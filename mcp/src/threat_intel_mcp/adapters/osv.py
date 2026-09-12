"""OSV.dev CVE enrichment adapter.

Given CVE identifiers this repository already holds, returns OSV.dev's record
for each: which open-source ecosystems and packages are affected, which
versions fix it, and what the upstream advisories are.

**No credential required.** OSV.dev is a free Google/OpenSSF service.

Why this is enrichment, not a feed
----------------------------------
OSV's REST API has no time-windowed "recent vulnerabilities" endpoint.
``POST /v1/query`` is keyed by *package* or *commit*, which this server has no
source of, and the bulk data is per-ecosystem archives rather than an API. So
OSV cannot discover a weekly CVE set, and nothing here pretends it can: it sits
in ``enrichment_sources``, not ``_VULN_SOURCES``.

What it adds that the CVE feeds do not: CISA KEV, NVD and VulnCheck all answer
"how bad and is it exploited". OSV answers "which of your dependencies, and
what version fixes it", aggregating GHSA, PyPA, Go, RustSec and the distro
trackers.

Feed contract
-------------
  - ``GET https://api.osv.dev/v1/vulns/{id}``
  - No auth, no parameters.
  - Response: an OSV-schema record -- ``id``, ``modified``, ``published``,
    ``aliases``, ``summary``, ``details``, ``severity``, ``affected``,
    ``references``.

.. warning::

   **Whether ``/v1/vulns/`` accepts a CVE id is the unverified part of this
   adapter, and it is the part everything else rests on.** OSV's own FAQ says
   CVE ids are accepted there; a 2023 issue in the same repository reports
   "Bug not found" for exactly that. ``api.osv.dev`` is unreachable from the
   development sandbox, so this code cannot settle it.

   That is precisely the situation that produced #203 -- an endpoint assembled
   from belief, mock-tested against a fixture written from the same belief,
   404ing on the first real call. The difference here is
   ``_ALL_MISSING_IS_A_FORMAT_ERROR`` below: a 404 for one CVE is an ordinary
   "OSV has no record", but a 404 for **every** CVE in a batch is
   indistinguishable from an endpoint that does not accept CVE ids, so it
   raises instead of reporting a confident zero. A wrong guess here fails
   loudly on first contact rather than quietly forever.

   Record a cassette before trusting the field mapping.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call, redact_url
from ..netpolicy import egress_event_hooks
from .base import UpstreamFormatError

logger = logging.getLogger(__name__)

_API_BASE = "https://api.osv.dev/v1"

# OSV records change when an advisory is amended -- rarely within a run.
CACHE_TTL_SECONDS = 3600

MAX_CVES_PER_CALL = 200

# See the module warning: every id missing is treated as a format error rather
# than an empty result. Named so the reason survives a refactor.
_ALL_MISSING_IS_A_FORMAT_ERROR = True

# Politeness gap between lookups against a free public service.
_DEFAULT_REQUEST_DELAY: float = 0.1


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _normalize_record(cve: str, body: Any) -> dict[str, Any]:
    """Map one OSV record to an enrichment record.

    Raises ``RuntimeError`` on a body with no ``id``: an upstream problem, so
    the tool degrades rather than surfacing a caller error (``adapters/base.py``).
    """
    if not isinstance(body, dict):
        raise RuntimeError("OSV response was not a JSON object")
    if "id" not in body:
        raise RuntimeError("OSV response missing 'id' -- not an OSV record")

    record: dict[str, Any] = {
        "cve": cve,
        "source": "OSV",
        "osv_id": body.get("id"),
    }

    for src, dst in (("summary", "summary"), ("published", "published"),
                     ("modified", "modified")):
        value = _text(body.get(src))
        if value:
            record[dst] = value

    aliases = body.get("aliases")
    if isinstance(aliases, list):
        cleaned = [a for a in aliases if isinstance(a, str) and a.strip()]
        if cleaned:
            record["aliases"] = cleaned

    # Affected packages: the reason to call OSV at all. Ecosystem/name pairs and
    # the fixed versions, copied verbatim -- never inferred.
    affected = body.get("affected")
    packages: list[dict[str, Any]] = []
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, dict):
                continue
            pkg = item.get("package")
            if not isinstance(pkg, dict):
                continue
            entry: dict[str, Any] = {}
            for key in ("ecosystem", "name", "purl"):
                value = _text(pkg.get(key))
                if value:
                    entry[key] = value
            if not entry:
                continue
            fixed = _fixed_versions(item.get("ranges"))
            if fixed:
                entry["fixed"] = fixed
            packages.append(entry)
    if packages:
        record["affected_packages"] = packages

    severity = body.get("severity")
    if isinstance(severity, list):
        scores = [
            {"type": _text(s.get("type")), "score": _text(s.get("score"))}
            for s in severity
            if isinstance(s, dict) and _text(s.get("score"))
        ]
        if scores:
            record["severity"] = scores

    references = body.get("references")
    if isinstance(references, list):
        urls = [
            _text(r.get("url"))
            for r in references
            if isinstance(r, dict) and _text(r.get("url"))
        ]
        if urls:
            record["references"] = urls

    return record


def _fixed_versions(ranges: Any) -> list[str]:
    """Pull the ``fixed`` version out of each OSV range event."""
    if not isinstance(ranges, list):
        return []
    fixed: list[str] = []
    for rng in ranges:
        if not isinstance(rng, dict):
            continue
        for event in rng.get("events") or []:
            if isinstance(event, dict):
                value = _text(event.get("fixed"))
                if value and value not in fixed:
                    fixed.append(value)
    return fixed


class OSVAdapter:
    """Keyless CVE enrichment against OSV.dev."""

    name = "OSV"
    tier = 1
    requires_credential = False
    is_enrichment = True

    def __init__(self, *, _request_delay: float = _DEFAULT_REQUEST_DELAY) -> None:
        # No CredentialProvider: this adapter takes no credential.
        self._request_delay = _request_delay
        self._cache: dict[str, tuple[dict[str, Any], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "User-Agent": "threat-intel-mcp (kj299/threat-intel)",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("api.osv.dev"),
        )

    async def enrich(self, cves: list[str]) -> dict[str, Any]:
        """Look up each CVE in OSV.dev.

        Returns:
            ``{"enrichments", "source", "tier", "retrieved_at", "record_count",
            "latency_ms", "found", "not_found", "failed"}``.

        Raises:
            ValueError: Empty input or an over-long list (caller errors).
            UpstreamFormatError: Every CVE came back 404 -- see the module
                warning; that is a broken endpoint, not an empty answer.
            Exception: Every lookup failed for a non-404 reason.
        """
        cleaned = [c.strip() for c in cves if isinstance(c, str) and c.strip()]
        if not cleaned:
            raise ValueError("No CVEs supplied to enrich")
        if len(cleaned) > MAX_CVES_PER_CALL:
            raise ValueError(
                f"{len(cleaned)} CVEs exceeds the per-call cap of "
                f"{MAX_CVES_PER_CALL}. Split the work rather than issuing one "
                "enormous sweep against a free public service."
            )

        t_start = time.monotonic()
        enrichments: list[dict[str, Any]] = []
        not_found: list[str] = []
        failed: list[str] = []
        last_error: Exception | None = None
        requested = 0

        async with self._make_client() as client:
            for cve in cleaned:
                cached = self._cache.get(cve)
                if cached is not None and time.monotonic() < cached[1]:
                    enrichments.append(cached[0])
                    continue

                if requested:
                    await asyncio.sleep(self._request_delay)
                requested += 1

                try:
                    record = await self._lookup(client, cve)
                except _NotFound:
                    not_found.append(cve)
                except Exception as exc:  # noqa: BLE001 - one bad lookup is not fatal
                    logger.warning(
                        "OSV lookup failed for %s: %s", cve, type(exc).__name__
                    )
                    failed.append(cve)
                    last_error = exc
                else:
                    enrichments.append(record)
                    self._cache[cve] = (record, time.monotonic() + CACHE_TTL_SECONDS)

        if last_error is not None and len(failed) == len(cleaned):
            raise RuntimeError(
                f"every OSV lookup failed ({len(failed)} CVEs); last error: "
                f"{type(last_error).__name__}: {last_error}"
            ) from last_error

        # The #203 guard. One 404 is "OSV has no record for this CVE"; all of
        # them is indistinguishable from an endpoint that does not take CVE ids.
        if _ALL_MISSING_IS_A_FORMAT_ERROR and not_found and len(not_found) == len(cleaned):
            raise UpstreamFormatError(
                f"OSV returned 404 for all {len(not_found)} CVEs. A single miss "
                "is ordinary, but a clean sweep is what a wrong endpoint looks "
                "like -- /v1/vulns/ may not accept CVE identifiers. Refusing to "
                "report this as 0 records."
            )

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "osv_enrich_cves",
            {"cve_count": len(cleaned)},
            record_count=len(enrichments),
            latency_ms=latency_ms,
            status="partial" if failed else "ok",
            error=f"failed lookups: {failed}" if failed else None,
        )

        return {
            "enrichments": enrichments,
            "source": "OSV",
            "tier": self.tier,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(enrichments),
            "latency_ms": round(latency_ms, 1),
            "found": [r["cve"] for r in enrichments],
            # OSV only covers open-source ecosystems, so a CVE in proprietary
            # software legitimately has no record. Not a failure.
            "not_found": not_found,
            "failed": failed,
        }

    async def _lookup(self, client: httpx.AsyncClient, cve: str) -> dict[str, Any]:
        url = f"{_API_BASE}/vulns/{cve}"
        logger.info("OSV request: url=%s", redact_url(url))
        resp = await client.get(url)
        if resp.status_code == 404:
            raise _NotFound(cve)
        resp.raise_for_status()
        return _normalize_record(cve, resp.json())


class _NotFound(Exception):
    """OSV has no record under this identifier (HTTP 404)."""

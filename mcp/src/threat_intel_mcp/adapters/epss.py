"""EPSS (Exploit Prediction Scoring System) CVE enrichment adapter.

Scores CVEs this repository already holds with FIRST.org's published
probability that each will be exploited in the wild within the next 30 days.

**No credential required.** The EPSS API is public.

Why this is enrichment, not a feed
----------------------------------
It discovers nothing. The CVE feeds (CISA KEV, NVD, VulnCheck KEV) find
vulnerabilities; EPSS ranks a list you bring. That is the same distinction that
moved VirusTotal out of ``_FEED_SOURCES`` in #203, and it is load-bearing here
for the same reason: an enrichment source cannot join ``fetch_all_cves``,
because there is nothing for it to contribute until the fan-out has run.

What it is *for*: CISA KEV says "exploited", NVD says "severe". Neither ranks
the remainder. A weekly NVD window is routinely hundreds of CVEs with CVSS 9+
and no known exploitation, and EPSS is the only free signal that separates the
handful likely to be attacked from the rest.

Feed contract
-------------
Taken from FIRST.org's published API reference, then confirmed against a real
response on 2026-09-12 (``tests/cassettes/epss.yaml``): ``CVE-2021-44228`` and
``CVE-2022-22965`` both came back scored and parsed. ``api.first.org`` is
unreachable from the development sandbox, so that recording is the only thing
standing between this mapping and belief.

  - ``GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2021-45046``
  - No auth, no key.
  - Response envelope: ``{"status", "status-code", "version", "access",
    "total", "offset", "limit", "data": [...]}``
  - Each ``data`` entry: ``{"cve", "epss", "percentile", "date"}``.
    ``epss`` and ``percentile`` are probabilities serialised as **strings**
    (e.g. ``"0.97182"``), which is why they are parsed through ``_as_float``
    rather than used directly.
  - Scores exist back to 2021-04-14; an optional ``date=YYYY-MM-DD`` asks for a
    historical score.

A CVE with no EPSS score is simply absent from ``data``. That is **not** a
failure: EPSS only scores CVEs published in NVD, so a brand-new or reserved
identifier legitimately has none. It is reported as ``not_scored`` rather than
``failed``, because a caller that treats "no score" as an outage will chase a
problem that does not exist.

Batching
--------
Unlike VirusTotal, EPSS takes a comma-separated list, so N CVEs cost one
request rather than N. ``MAX_CVES_PER_REQUEST`` chunks the list to keep the
query string within what any HTTP stack will carry; ``MAX_CVES_PER_CALL`` caps
a single call outright. There is no documented rate limit, so nothing is
serialised behind a delay -- but requests are still issued one chunk at a time
rather than concurrently, because a public free service that has not asked for
politeness should get it anyway.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call, redact_url
from ..netpolicy import egress_event_hooks
from .base import guard_parsed

logger = logging.getLogger(__name__)

_API_URL = "https://api.first.org/data/v1/epss"

# An EPSS score is recomputed daily, so a short cache spans one report run
# without ever serving yesterday's number.
CACHE_TTL_SECONDS = 3600

# CVE ids are ~14 chars; 100 per request keeps the query string near 1.5 KB,
# comfortably inside every server and proxy limit.
MAX_CVES_PER_REQUEST = 100

# A whole call is capped so one request cannot be used to mirror the database.
MAX_CVES_PER_CALL = 2000

# FIRST publishes these bands with the model. Reproduced as thresholds rather
# than invented: the cut points are the vendor's, the labels are ours.
_PRIORITY_BANDS: tuple[tuple[float, str], ...] = (
    (0.36, "high"),
    (0.088, "medium"),
    (0.0, "low"),
)


def _as_float(raw: Any) -> float | None:
    """Parse EPSS's string-serialised probability, or None if unreadable.

    The API returns ``"0.97182"``, not ``0.97182``. Treating the string as a
    number works in Python right up until a comparison, so it is converted
    once, here, and a value that will not convert is omitted rather than
    guessed at.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw.strip())
        except ValueError:
            return None
    return None


def _priority(epss: float) -> str:
    """Map an EPSS probability to a coarse remediation priority."""
    for threshold, label in _PRIORITY_BANDS:
        if epss >= threshold:
            return label
    return "low"  # pragma: no cover - the 0.0 band already catches everything


def _normalize_entry(entry: Any) -> dict[str, Any] | None:
    """Map one EPSS record to an enrichment record, or None if unreadable.

    Returning None (rather than a record full of defaults) is what lets
    ``guard_parsed`` tell "EPSS has no score for these CVEs" from "the response
    shape changed": the first yields an empty ``data`` array, the second yields
    entries none of which parse.
    """
    if not isinstance(entry, dict):
        return None
    cve = entry.get("cve")
    if not isinstance(cve, str) or not cve.strip():
        return None

    epss = _as_float(entry.get("epss"))
    if epss is None:
        # A record with no readable score is the one field this enrichment
        # exists to provide, so it is not a usable record.
        return None

    record: dict[str, Any] = {
        "cve": cve.strip(),
        "source": "EPSS",
        "epss": epss,
        "priority": _priority(epss),
    }

    percentile = _as_float(entry.get("percentile"))
    if percentile is not None:
        record["percentile"] = percentile

    scored_on = entry.get("date")
    if isinstance(scored_on, str) and scored_on.strip():
        record["scored_on"] = scored_on.strip()

    return record


class EPSSAdapter:
    """Keyless CVE enrichment against FIRST.org's EPSS API."""

    name = "EPSS"
    tier = 1
    requires_credential = False
    # Not a feed: it scores CVEs the caller supplies rather than discovering
    # any, so it is deliberately absent from _VULN_SOURCES and cannot
    # participate in fetch_all_cves.
    is_enrichment = True

    def __init__(self) -> None:
        # No CredentialProvider: this adapter takes no credential.
        self._cache: dict[tuple[str, str], tuple[dict[str, Any], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "User-Agent": "threat-intel-mcp (kj299/threat-intel)",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("api.first.org"),
        )

    async def enrich(
        self,
        cves: list[str],
        *,
        date: str | None = None,
    ) -> dict[str, Any]:
        """Return EPSS scores for the supplied CVE identifiers.

        Args:
            cves: CVE ids (e.g. ``"CVE-2021-44228"``). Capped at
                ``MAX_CVES_PER_CALL``; an over-long list raises rather than
                being truncated.
            date: Optional ``YYYY-MM-DD`` for a historical score. EPSS has data
                from 2021-04-14 onwards.

        Returns:
            ``{"enrichments", "source", "tier", "retrieved_at", "record_count",
            "latency_ms", "scored", "not_scored"}``.

        Raises:
            ValueError: Empty input, an over-long list, or a malformed ``date``.
                Caller errors, surfaced verbatim per ``adapters/base.py``.
        """
        cleaned = [c.strip() for c in cves if isinstance(c, str) and c.strip()]
        if not cleaned:
            raise ValueError("No CVEs supplied to enrich")
        if len(cleaned) > MAX_CVES_PER_CALL:
            raise ValueError(
                f"{len(cleaned)} CVEs exceeds the per-call cap of "
                f"{MAX_CVES_PER_CALL}. Split the work rather than issuing one "
                "enormous query. This refuses instead of truncating so a caller "
                "is never handed a partial answer it believes is complete."
            )
        if date is not None:
            try:
                datetime.strptime(date, "%Y-%m-%d")
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"date must be YYYY-MM-DD, got {date!r}"
                ) from exc

        t_start = time.monotonic()
        cache_scope = date or "latest"
        enrichments: list[dict[str, Any]] = []
        outstanding: list[str] = []

        for cve in cleaned:
            cached = self._cache.get((cache_scope, cve))
            if cached is not None and time.monotonic() < cached[1]:
                enrichments.append(cached[0])
            else:
                outstanding.append(cve)

        if outstanding:
            async with self._make_client() as client:
                for start in range(0, len(outstanding), MAX_CVES_PER_REQUEST):
                    chunk = outstanding[start : start + MAX_CVES_PER_REQUEST]
                    enrichments.extend(await self._fetch_chunk(client, chunk, date))

        scored = {record["cve"] for record in enrichments}
        # Order follows the caller's input, so a caller can zip the result back
        # against its own list without re-sorting.
        enrichments.sort(key=lambda r: cleaned.index(r["cve"]) if r["cve"] in cleaned else len(cleaned))
        not_scored = [cve for cve in cleaned if cve not in scored]

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "epss_enrich_cves",
            {"cve_count": len(cleaned), "date": date},
            record_count=len(enrichments),
            latency_ms=latency_ms,
            status="ok",
        )

        return {
            "enrichments": enrichments,
            "source": "EPSS",
            "tier": self.tier,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(enrichments),
            "latency_ms": round(latency_ms, 1),
            "scored": [r["cve"] for r in enrichments],
            # NOT "failed": EPSS only scores CVEs published in NVD, so an
            # absent score is a fact about the CVE, not an outage.
            "not_scored": not_scored,
        }

    async def _fetch_chunk(
        self,
        client: httpx.AsyncClient,
        chunk: list[str],
        date: str | None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"cve": ",".join(chunk), "limit": len(chunk)}
        if date:
            params["date"] = date

        logger.info("EPSS request: url=%s cves=%d", redact_url(_API_URL), len(chunk))
        resp = await client.get(_API_URL, params=params)
        resp.raise_for_status()
        body = resp.json()

        if not isinstance(body, dict):
            raise RuntimeError("EPSS response was not a JSON object")

        entries = body.get("data") or []
        if not isinstance(entries, list):
            raise RuntimeError("EPSS 'data' was not an array")

        records = [
            normalized
            for entry in entries
            if (normalized := _normalize_entry(entry)) is not None
        ]

        guard_parsed(
            "EPSS",
            # Presence check, never truthiness: {"data": []} is a real empty
            # answer (none of these CVEs is scored), while a body with no
            # "data" key is a response we did not recognise.
            envelope_found="data" in body,
            envelope_desc="a 'data' array",
            items_seen=len(entries),
            items_understood=len(records),
        )

        expiry = time.monotonic() + CACHE_TTL_SECONDS
        scope = date or "latest"
        for record in records:
            self._cache[(scope, record["cve"])] = (record, expiry)

        return records

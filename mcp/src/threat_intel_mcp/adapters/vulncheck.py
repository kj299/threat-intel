"""VulnCheck KEV (Known Exploited Vulnerabilities) adapter.

Fetches VulnCheck's community KEV index and normalises each entry to a
vulnerability record (see ``vulns.py``). Every entry in a KEV catalog is, by
definition, reported as exploited in the wild, so records carry
``exploit_status: known_exploited`` — the same treatment ``cisa_kev.py`` gives
its own catalog.

Why a second KEV
----------------
VulnCheck's catalog is broader than CISA's binding-directive list: the recorded
index holds 5,229 entries against CISA KEV's ~1,400. The two are complements,
not substitutes. ``finalize_vulns`` dedupes by CVE ID and preserves
corroboration, so a CVE in both becomes one record naming both sources — which
is exactly the signal an analyst wants. Entries also carry
``cisa_date_added`` where they overlap, and the URLs that reported the
exploitation, so a record asserting "exploited" points at its evidence.

Feed contract (VERIFIED against a recorded response, 2026-09-07)
-----------------------------------------------------------------
Captured by the ``record-cassettes`` workflow (run 34070272507) and committed to
``mcp/tests/cassettes/vulncheck.yaml``, so the parsing below is tested against
bytes VulnCheck actually sent rather than a fixture written from belief (#105).
The first draft of this adapter was written from published SDK signatures alone;
the recording corrected two real defects — no pagination at all, and four
dropped fields — which is the whole reason the record-then-correct loop exists.

  - Base URL: ``https://api.vulncheck.com``
  - Auth: ``Authorization: Bearer <token>``
  - ``GET /v3/index/vulncheck-kev?limit=<n>&page=<n>``
  - Response: ``{"_benchmark": float, "_meta": {...}, "data": [entry, ...]}``
  - ``_meta`` carries ``page``, ``total_pages``, ``max_pages``, ``limit``,
    ``total_documents``, ``first_item``, ``last_item``.
  - Each entry: ``vendorProject``, ``product``, ``shortDescription``,
    ``vulnerabilityName``, ``required_action`` (snake_case, unlike the four
    camelCase keys beside it), ``knownRansomwareCampaignUse`` ("Known" /
    "Unknown"), ``cve`` (**a list** of CVE IDs, not a scalar like CISA KEV's
    ``cveID``), ``cwes`` (e.g. ``["CWE-89"]``), ``vulncheck_xdb`` (list of
    ``{xdb_id, xdb_url, date_added}``), ``vulncheck_reported_exploitation``
    (list of ``{url, date_added}``),
    ``reported_exploited_by_vulncheck_canaries`` (bool), ``dueDate``,
    ``cisa_date_added``, ``date_added``, ``updated_at``, ``_timestamp``.
    Timestamps are RFC 3339 with a ``Z`` suffix.

The mixed key casing is genuinely in the feed — ``required_action`` is
snake_case while ``vendorProject``/``dueDate`` beside it are camelCase — so the
mapping below is not tidied into one convention.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from ..vulns import VulnFetchResult
from .base import guard_parsed

logger = logging.getLogger(__name__)

_API_HOST = "api.vulncheck.com"
_INDEX_URL = f"https://{_API_HOST}/v3/index/vulncheck-kev"

FEED_TYPES: dict[str, str] = {"kev_catalog": _INDEX_URL}
DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

# The catalog moves a few times a day at most; match cisa_kev.py's 6 hours so
# repeated report generations in one session stay cheap.
CACHE_TTL_SECONDS = 21600
_CACHE_KEY = "vulncheck_kev"

# 1000 is the index's own default and maximum page size; the recorded response
# reports total_pages=6 for 5,229 entries at that limit. MAX_PAGES is a ceiling
# against an upstream that reports a runaway total_pages, not the expected stop
# — the normal stop is page >= total_pages.
PAGE_LIMIT = 1000
MAX_PAGES = 10


def _to_rfc3339(raw: Any) -> str | None:
    """Coerce a VulnCheck timestamp to RFC 3339, or None if unreadable.

    The feed sends ``2026-09-01T00:00:00Z``. The bare-date branch is kept for a
    field that might carry one; anything unreadable yields None and the field is
    simply omitted, because the vuln schema validates ``date-time`` at runtime
    and a half-understood string would drop the whole record, not just the
    field.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = datetime.strptime(text, "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _cve_ids(entry: dict[str, Any]) -> list[str]:
    """Every CVE ID this entry names.

    ``cve`` is a list — confirmed by the recording — unlike CISA KEV's scalar
    ``cveID``. The scalar and ``cveID`` fallbacks are kept anyway: they cost one
    lookup, and if the shape ever changes back, a silent zero here would be
    indistinguishable from a quiet catalog.
    """
    raw = entry.get("cve")
    if isinstance(raw, str):
        candidates = [raw]
    elif isinstance(raw, list):
        candidates = [c for c in raw if isinstance(c, str)]
    else:
        candidates = []
    fallback = entry.get("cveID")
    if not candidates and isinstance(fallback, str):
        candidates = [fallback]
    return [c.strip() for c in candidates if c.strip()]


def _references(entry: dict[str, Any]) -> list[dict[str, str]]:
    """Collect exploit and XDB URLs as reference objects.

    These are what justify VulnCheck as a *second* KEV: the URL that reported
    exploitation is the evidence, and dropping it would leave a record asserting
    "exploited" with nothing behind it.
    """
    refs: list[dict[str, str]] = []
    for key, label in (
        ("vulncheck_reported_exploitation", "VulnCheck reported exploitation"),
        ("vulncheck_xdb", "VulnCheck XDB"),
    ):
        items = entry.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or item.get("xdb_url")
            if isinstance(url, str) and url.strip():
                refs.append({"url": url.strip(), "source": label})
    return refs


def _normalize_entry(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Map one VulnCheck KEV entry to vuln records — one per CVE it names.

    Returns a list, not a single record, because ``cve`` is a list: the vuln
    schema keys on exactly one ``cve_id``, and collapsing several CVEs into one
    record would discard real coverage. Fields are copied verbatim; nothing is
    inferred.
    """
    ids = _cve_ids(entry)
    if not ids:
        return []

    tags = ["vulncheck-kev", "known-exploited"]
    base: dict[str, Any] = {
        "source": "VulnCheck KEV",
        "exploit_status": "known_exploited",
        "tlp": "WHITE",
    }

    for src_key, dst_key in (
        ("vendorProject", "vendor_project"),
        ("product", "product"),
        ("vulnerabilityName", "vulnerability_name"),
        ("shortDescription", "description"),
        # snake_case in the feed, unlike the four camelCase keys above it.
        ("required_action", "required_action"),
    ):
        value = entry.get(src_key)
        if isinstance(value, str) and value.strip():
            base[dst_key] = value.strip()

    ransomware = entry.get("knownRansomwareCampaignUse")
    if ransomware in ("Known", "Unknown"):
        base["known_ransomware_use"] = ransomware
        if ransomware == "Known":
            tags.append("ransomware-linked")

    for src_key, dst_key in (
        ("date_added", "date_added"),
        ("dueDate", "due_date"),
        ("updated_at", "last_modified"),
    ):
        stamp = _to_rfc3339(entry.get(src_key))
        if stamp:
            base[dst_key] = stamp

    cwes = entry.get("cwes")
    if isinstance(cwes, list):
        clean = [c.strip() for c in cwes if isinstance(c, str) and c.strip()]
        if clean:
            base["cwes"] = clean

    # First-party observation, and stronger evidence than a third-party report,
    # so it is worth surfacing rather than folding into the generic tag.
    if entry.get("reported_exploited_by_vulncheck_canaries") is True:
        tags.append("vulncheck-canary-observed")

    refs = _references(entry)
    if refs:
        base["references"] = refs

    base["tags"] = tags
    return [dict(base, cve_id=cve_id) for cve_id in ids]


class VulnCheckAdapter:
    """Adapter for the VulnCheck KEV index (community tier)."""

    name = "VulnCheck KEV"
    # Tier 1 describes the data category -- "Vulnerability Databases & Exploit
    # Repositories" -- not the operator. VulnCheck is a commercial vendor, but a
    # KEV catalog is Tier 1 material in the same way NVD is, and filing it as
    # Tier 2 "Commercial Threat Intelligence" would misrepresent what it holds.
    tier = 1
    requires_credential = True

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self, token: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "threat-intel-mcp/0.13 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks(_API_HOST),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> VulnFetchResult:
        """Fetch the VulnCheck KEV catalog as vulnerability records.

        ``time_range`` is accepted for interface compatibility and recorded for
        the Coverage Ledger, but does not filter — a KEV entry is a standing
        "this is being exploited" item regardless of when it was added, which is
        the reasoning ``cisa_kev.py`` documents for the same choice. The index
        does expose date parameters, so a windowed mode is possible later; it
        would be a different question than "what is being exploited right now".
        """
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        t_start = time.monotonic()

        now = time.monotonic()
        cached = self._cache.get(_CACHE_KEY)
        if cached is not None and now < cached[1]:
            vulns = cached[0]
        else:
            # Raises CredentialNotFoundError when unset -- a config error the
            # server degrades non-retryably, per the adapters/base.py taxonomy.
            token = self._credentials.get("vulncheck", "api_key")
            vulns = await self._fetch_all_pages(token)
            self._cache[_CACHE_KEY] = (vulns, now + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "vulncheck_fetch_cves",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(vulns),
            latency_ms=latency_ms,
            status="ok",
        )
        return VulnFetchResult(
            vulns=vulns,
            source="VulnCheck KEV",
            tier=1,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(vulns),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["kev_catalog"],
        )

    async def _fetch_all_pages(self, token: str) -> list[dict[str, Any]]:
        """Walk the index's pages, honouring ``_meta.total_pages``.

        The first draft fetched one page and warned that it had probably
        truncated. It had: the recording shows 1,000 of 5,229 entries, so 81% of
        the catalog was missing and the ledger would still have said
        ``consulted``. Under-reporting a source while calling it consulted is
        the coverage-inflation failure the honesty rules exist to prevent.

        ``guard_parsed`` is applied ONCE over the whole walk, not per page: an
        empty final page is normal termination, not a format break.
        """
        vulns: list[dict[str, Any]] = []
        seen = 0
        understood = 0
        page = 1
        total_pages = 1

        async with self._make_client(token) as client:
            while page <= min(total_pages, MAX_PAGES):
                resp = await client.get(
                    _INDEX_URL, params={"limit": PAGE_LIMIT, "page": page}
                )
                resp.raise_for_status()
                entries, meta = self._parse_page(resp.json())

                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    records = _normalize_entry(entry)
                    if records:
                        understood += 1
                        vulns.extend(records)
                seen += len(entries)

                reported = meta.get("total_pages")
                if isinstance(reported, int) and reported > 0:
                    total_pages = reported
                if not entries:
                    break  # defensive: an empty page ends the walk
                page += 1

        if total_pages > MAX_PAGES:
            logger.warning(
                "VulnCheck reported %d pages; stopped at the %d-page ceiling, "
                "so the catalog is truncated.",
                total_pages,
                MAX_PAGES,
            )

        guard_parsed(
            "VulnCheck KEV",
            envelope_found=True,  # checked per page, with its own message
            envelope_desc="a 'data' list",
            items_seen=seen,
            items_understood=understood,
        )
        return vulns

    def _parse_page(self, body: Any) -> tuple[list[Any], dict[str, Any]]:
        """Split one page body into its entries and ``_meta``.

        A malformed body is an *upstream* problem, so it raises ``RuntimeError``
        rather than ``ValueError``: the server tool reserves ``ValueError`` for
        caller mistakes it surfaces verbatim, and degrades everything else to an
        "unverified" ledger entry (see ``adapters/base.py``).
        """
        if not isinstance(body, dict):
            raise RuntimeError("VulnCheck response was not a JSON object")
        # Presence check, not truthiness: `{"data": []}` is a real empty result,
        # while a body with no `data` key is one we failed to recognise.
        if "data" not in body:
            raise RuntimeError("VulnCheck response missing 'data' key")
        entries = body.get("data")
        if not isinstance(entries, list):
            raise RuntimeError("VulnCheck 'data' was not a list")
        meta = body.get("_meta")
        return entries, meta if isinstance(meta, dict) else {}

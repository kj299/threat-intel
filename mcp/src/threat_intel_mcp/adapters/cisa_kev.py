"""CISA Known Exploited Vulnerabilities (KEV) catalog adapter.

Fetches the **public** CISA KEV catalog — the authoritative U.S. government list
of CVEs with confirmed in-the-wild exploitation — and normalises each entry to a
vulnerability record (see ``vulns.py``). Every CVE in this catalog is, by
definition, actively exploited, so records carry ``exploit_status:
known_exploited``.

No credential required — this is a free, public government feed.

Feed contract (verified against the OpenCTI CISA-KEV connector + its test
fixtures, 2026):
  - GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - Response JSON top level: ``{"catalogVersion", "dateReleased", "count",
    "vulnerabilities": [ {entry}, ... ]}``.
  - Each entry: ``cveID``, ``vendorProject``, ``product``, ``vulnerabilityName``,
    ``dateAdded`` (``YYYY-MM-DD``), ``shortDescription``, ``requiredAction``,
    ``dueDate`` (``YYYY-MM-DD``), ``knownRansomwareCampaignUse`` ("Known" /
    "Unknown"), ``notes``, ``cwes`` (e.g. ``["CWE-78"]``).

The catalog is republished a few times a day at most, so an in-process cache
with a multi-hour TTL keeps repeated report generations cheap.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vulns import VulnFetchResult

logger = logging.getLogger(__name__)

_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

FEED_TYPES: dict[str, str] = {"kev_catalog": _FEED_URL}
DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

# The catalog changes at most a few times a day; cache for 6 hours.
CACHE_TTL_SECONDS = 21600
_CACHE_KEY = "cisa_kev"


def _date_to_rfc3339(raw: Any) -> str | None:
    """Promote a bare ``YYYY-MM-DD`` KEV date to an RFC 3339 date-time, or None.

    KEV emits calendar dates; the vuln schema validates ``date-time``, so the
    date is anchored to 00:00:00 UTC. This never invents precision that changes
    meaning — a KEV due-date is a whole-day deadline.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        dt = datetime.strptime(raw.strip(), "%Y-%m-%d")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc).isoformat()


def _normalize_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Map one KEV catalog entry to a vuln record, or None to skip.

    Fields are copied verbatim from the feed — no CVE ID, CWE, or ransomware
    verdict is invented. An entry without a ``cveID`` cannot be keyed and is
    dropped (the schema validation would drop it anyway).
    """
    cve_id = entry.get("cveID")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None

    vuln: dict[str, Any] = {
        "cve_id": cve_id.strip(),
        "source": "CISA KEV",
        "exploit_status": "known_exploited",
        "tlp": "WHITE",
        "tags": ["cisa-kev", "known-exploited"],
    }

    for src_key, dst_key in (
        ("vendorProject", "vendor_project"),
        ("product", "product"),
        ("vulnerabilityName", "vulnerability_name"),
        ("shortDescription", "description"),
        ("requiredAction", "required_action"),
    ):
        value = entry.get(src_key)
        if isinstance(value, str) and value.strip():
            vuln[dst_key] = value.strip()

    ransomware = entry.get("knownRansomwareCampaignUse")
    if ransomware in ("Known", "Unknown"):
        vuln["known_ransomware_use"] = ransomware
        if ransomware == "Known":
            vuln["tags"].append("ransomware-linked")

    date_added = _date_to_rfc3339(entry.get("dateAdded"))
    if date_added:
        vuln["date_added"] = date_added
    due_date = _date_to_rfc3339(entry.get("dueDate"))
    if due_date:
        vuln["due_date"] = due_date

    cwes = entry.get("cwes")
    if isinstance(cwes, list):
        clean_cwes = [c.strip() for c in cwes if isinstance(c, str) and c.strip()]
        if clean_cwes:
            vuln["cwes"] = clean_cwes

    return vuln


class CISAKEVAdapter:
    """Adapter for the CISA Known Exploited Vulnerabilities catalog."""

    name = "CISA KEV"
    tier = 1
    # Public government feed; the server treats it as always-configured.
    requires_credential = False

    def __init__(self, credentials: Any = None) -> None:
        # credentials accepted for interface symmetry; unused (public feed).
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp/0.13 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("www.cisa.gov"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> VulnFetchResult:
        """Fetch the CISA KEV catalog as vulnerability records.

        The KEV catalog is a full, curated list (not a time-windowed feed);
        ``time_range`` is accepted for interface compatibility and recorded for
        the Coverage Ledger but not used to filter — the whole point of KEV is
        that every entry is a standing "patch this now" item.
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
            async with self._make_client() as client:
                resp = await client.get(_FEED_URL)
                resp.raise_for_status()
                body = resp.json()
            vulns = self._parse_catalog(body)
            self._cache[_CACHE_KEY] = (vulns, now + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "cisa_kev_fetch_cves",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(vulns),
            latency_ms=latency_ms,
            status="ok",
        )
        return VulnFetchResult(
            vulns=vulns,
            source="CISA KEV",
            tier=1,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(vulns),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["kev_catalog"],
        )

    def _parse_catalog(self, body: Any) -> list[dict[str, Any]]:
        """Parse the KEV JSON body into vuln records.

        A malformed body is an *upstream* problem, not a caller error, so it is
        raised as ``RuntimeError`` (not ``ValueError``): the server tool reserves
        ``ValueError`` for caller mistakes (bad ``feed_types``) that it surfaces
        verbatim, and degrades everything else to an "unverified" ledger entry.
        """
        if not isinstance(body, dict):
            raise RuntimeError("CISA KEV response was not a JSON object")
        entries = body.get("vulnerabilities")
        if not isinstance(entries, list):
            raise RuntimeError("CISA KEV response missing 'vulnerabilities' list")
        return [
            normalized
            for entry in entries
            if isinstance(entry, dict)
            and (normalized := _normalize_entry(entry)) is not None
        ]

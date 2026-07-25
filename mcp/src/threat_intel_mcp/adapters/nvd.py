"""NIST National Vulnerability Database (NVD) CVE adapter.

Fetches recently-modified CVE records from the **public** NVD 2.0 REST API and
normalises them to vulnerability records (see ``vulns.py``), enriched with CVSS
scores, CWEs, and references.

Credential is **optional**: NVD serves the API unauthenticated at a lower rate
limit (5 requests / 30 s) and at a higher limit (50 requests / 30 s) with a free
API key. The key is read from the injected CredentialProvider as
``credentials.get("nvd", "api_key")`` → env var ``NVD_API_KEY``; if it is not set
the adapter runs unauthenticated. A provider *failure* (Vault outage) still
propagates — only a definitively-absent key falls back to unauthenticated.

API contract (verified against the OpenCTI CVE connector, 2026):
  - GET https://services.nvd.nist.gov/rest/json/cves/2.0
  - Auth header when a key is present: ``apiKey: <key>``.
  - Query params: ``lastModStartDate`` / ``lastModEndDate``
    (``%Y-%m-%dT%H:%M:%S.000``; NVD requires the window to be <= 120 days),
    ``startIndex`` / ``resultsPerPage`` for pagination.
  - Response: ``{"resultsPerPage", "totalResults", "vulnerabilities": [ {entry},
    ... ]}``.
  - Each entry: ``entry["cve"]`` with ``id``, ``descriptions`` (list of
    ``{lang, value}``), ``published`` / ``lastModified``
    (``%Y-%m-%dT%H:%M:%S.%f``), ``references`` (list of ``{source, url}``),
    ``metrics`` (``cvssMetricV31`` | ``cvssMetricV30`` | ``cvssMetricV2`` |
    ``cvssMetricV40``; each a list of ``{type: Primary|Secondary, cvssData:
    {baseScore, baseSeverity, ...}}``), and ``weaknesses`` (list of
    ``{description: [{lang, value: "CWE-..."}]}``).
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialNotFoundError, CredentialProvider
from ..vulns import VulnFetchResult
from .base import guard_parsed

logger = logging.getLogger(__name__)

_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

FEED_TYPES: dict[str, str] = {"recent_cves": _API_URL}
DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 3600

# NVD caps a single lastMod window at 120 days and resultsPerPage at 2000.
_MAX_WINDOW_DAYS = 120
_DEFAULT_WINDOW_DAYS = 7
PAGE_SIZE = 2000
MAX_PAGES = 5

_DAYS_RE = re.compile(r"^(\d+)\s*d$", re.IGNORECASE)
_HOURS_RE = re.compile(r"^(\d+)\s*h$", re.IGNORECASE)

# CVSS metric blocks in NVD's preferred-precision order.
_CVSS_BLOCKS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)


def _window_days(time_range: str) -> int:
    """Parse a ``Nd`` / ``Nh`` time_range into whole days, capped at NVD's max."""
    m = _DAYS_RE.match(time_range.strip())
    if m:
        days = int(m.group(1))
    else:
        h = _HOURS_RE.match(time_range.strip())
        # Round any sub-day window up to one day (NVD granularity is coarse).
        days = max(1, (int(h.group(1)) + 23) // 24) if h else _DEFAULT_WINDOW_DAYS
    return max(1, min(days, _MAX_WINDOW_DAYS))


def _parse_dt(raw: Any) -> str | None:
    """Parse an NVD ``published`` / ``lastModified`` value to RFC 3339, or None."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
        return dt.replace(tzinfo=timezone.utc).isoformat()
    return None


def _select_cvss(entries: list[Any]) -> dict[str, Any] | None:
    """Return the preferred CVSS entry, preferring a Primary (NVD) source.

    Mirrors the OpenCTI connector: with multiple entries, take the Primary
    (authored by NVD) over a Secondary (vendor) score; otherwise the first.
    """
    if not entries:
        return None
    selected = None
    if len(entries) > 1:
        for entry in entries:
            if isinstance(entry, dict) and entry.get("type") == "Primary":
                selected = entry
                break
    if selected is None:
        selected = entries[0]
    return selected if isinstance(selected, dict) else None


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float, str, str] | None:
    """Extract (base_score, base_severity, version) from an NVD metrics block.

    CVSS v2 records carry no ``baseSeverity`` in ``cvssData`` (it lives one level
    up), so severity may be empty for v2 — the caller only sets fields that are
    present, so a missing severity is simply omitted.
    """
    for block_key, version in _CVSS_BLOCKS:
        entries = metrics.get(block_key)
        if not isinstance(entries, list):
            continue
        selected = _select_cvss(entries)
        if selected is None:
            continue
        cvss_data = selected.get("cvssData")
        if not isinstance(cvss_data, dict):
            continue
        score = cvss_data.get("baseScore")
        if not isinstance(score, (int, float)):
            continue
        severity = cvss_data.get("baseSeverity")
        severity = severity if isinstance(severity, str) else ""
        return float(score), severity.upper(), version
    return None


def _extract_cwes(weaknesses: Any) -> list[str]:
    """Collect unique ``CWE-...`` identifiers from an NVD weaknesses block."""
    if not isinstance(weaknesses, list):
        return []
    cwes: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description", []):
            if not isinstance(desc, dict):
                continue
            value = desc.get("value")
            if isinstance(value, str) and value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    return cwes


def _extract_references(references: Any) -> list[dict[str, str]]:
    """Map NVD references (``{source, url}``) to vuln-record reference objects."""
    if not isinstance(references, list):
        return []
    out: list[dict[str, str]] = []
    for ref in references:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        obj: dict[str, str] = {"url": url.strip()}
        src = ref.get("source")
        if isinstance(src, str) and src.strip():
            obj["source"] = src.strip()
        out.append(obj)
    return out


def _normalize_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Map one NVD vulnerability entry to a vuln record, or None to skip."""
    cve = entry.get("cve")
    if not isinstance(cve, dict):
        return None
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None

    vuln: dict[str, Any] = {
        "cve_id": cve_id.strip(),
        "source": "NVD",
        "tlp": "WHITE",
        "tags": ["nvd"],
    }

    # Prefer the English description; fall back to the first available.
    descriptions = cve.get("descriptions")
    if isinstance(descriptions, list):
        english = next(
            (
                d.get("value")
                for d in descriptions
                if isinstance(d, dict) and d.get("lang") == "en"
            ),
            None,
        )
        if english is None and descriptions and isinstance(descriptions[0], dict):
            english = descriptions[0].get("value")
        if isinstance(english, str) and english.strip():
            vuln["description"] = english.strip()

    published = _parse_dt(cve.get("published"))
    if published:
        vuln["published"] = published
    last_modified = _parse_dt(cve.get("lastModified"))
    if last_modified:
        vuln["last_modified"] = last_modified

    metrics = cve.get("metrics")
    if isinstance(metrics, dict):
        cvss = _extract_cvss(metrics)
        if cvss is not None:
            score, severity, version = cvss
            vuln["cvss_score"] = score
            vuln["cvss_version"] = version
            if severity in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
                vuln["cvss_severity"] = severity

    cwes = _extract_cwes(cve.get("weaknesses"))
    if cwes:
        vuln["cwes"] = cwes
    references = _extract_references(cve.get("references"))
    if references:
        vuln["references"] = references

    return vuln


class NVDAdapter:
    """Adapter for the NIST National Vulnerability Database CVE 2.0 API."""

    name = "NVD"
    tier = 1
    # Credential is optional; the server always registers this feed.
    requires_credential = False

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _api_key(self) -> str | None:
        """Return the NVD API key, or None if definitively unset.

        A provider *failure* (e.g. Vault outage) propagates — only a
        not-found key falls back to unauthenticated access.
        """
        try:
            return self._credentials.get("nvd", "api_key")
        except CredentialNotFoundError:
            return None

    def _make_client(self, api_key: str | None) -> httpx.AsyncClient:
        headers = {
            "Accept": "application/json",
            "User-Agent": "threat-intel-mcp/0.13 (kj299/threat-intel)",
        }
        if api_key:
            headers["apiKey"] = api_key
        return httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("services.nvd.nist.gov"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> VulnFetchResult:
        """Fetch CVEs modified within ``time_range`` (capped at NVD's 120-day max).

        Pagination follows NVD's ``totalResults`` / ``resultsPerPage`` contract up
        to ``MAX_PAGES`` pages; the first page is cached per window to keep
        repeated report runs cheap.
        """
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        days = _window_days(time_range)
        cache_key = f"recent_cves:{days}"

        t_start = time.monotonic()
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached is not None and now < cached[1]:
            vulns = cached[0]
        else:
            api_key = self._api_key()
            vulns = await self._fetch_window(api_key, days)
            self._cache[cache_key] = (vulns, now + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "nvd_fetch_cves",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(vulns),
            latency_ms=latency_ms,
            status="ok",
        )
        return VulnFetchResult(
            vulns=vulns,
            source="NVD",
            tier=1,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(vulns),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["recent_cves"],
        )

    async def _fetch_window(
        self, api_key: str | None, days: int
    ) -> list[dict[str, Any]]:
        """Fetch and paginate the last ``days`` of modified CVEs."""
        now_dt = datetime.now(timezone.utc)
        start_dt = now_dt - timedelta(days=days)
        # NVD wants naive-looking timestamps with millisecond precision.
        base_params = {
            "lastModStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": now_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": PAGE_SIZE,
        }

        vulns: list[dict[str, Any]] = []
        start_index = 0
        total = 0
        # Totals across the whole paginated fetch; an empty final page is
        # normal termination, not a format break.
        envelope_found = False
        seen = 0
        understood = 0

        async with self._make_client(api_key) as client:
            for _page in range(MAX_PAGES):
                params = {**base_params, "startIndex": start_index}
                logger.info(
                    "NVD request: startIndex=%d resultsPerPage=%d window=%dd",
                    start_index,
                    PAGE_SIZE,
                    days,
                )
                resp = await client.get(_API_URL, params=params)
                resp.raise_for_status()
                body = resp.json()

                entries = body.get("vulnerabilities")
                if not isinstance(entries, list):
                    # Not "no more results" — the response did not carry the
                    # field at all. Breaking here silently returned whatever had
                    # accumulated, so a renamed key looked like an empty window.
                    raise RuntimeError(
                        "NVD response missing 'vulnerabilities' list. The API "
                        "shape has probably changed upstream. Refusing to "
                        "report this as the end of the result set."
                    )
                envelope_found = True
                seen += len(entries)
                # An entry carrying a 'cve' object is one we read.
                understood += sum(
                    1 for e in entries if isinstance(e, dict) and isinstance(e.get("cve"), dict)
                )
                vulns.extend(
                    normalized
                    for entry in entries
                    if isinstance(entry, dict)
                    and (normalized := _normalize_entry(entry)) is not None
                )

                page_size = body.get("resultsPerPage") or 0
                total = body.get("totalResults") or 0
                start_index += page_size
                if page_size == 0 or start_index >= total:
                    break
            else:
                # Loop exhausted MAX_PAGES without reaching total — surface the cap
                # rather than silently returning a truncated slice.
                if start_index < total:
                    logger.warning(
                        "NVD result set capped at %d pages: retrieved %d of %d "
                        "CVEs for the %dd window. Narrow time_range for full coverage.",
                        MAX_PAGES,
                        start_index,
                        total,
                        days,
                    )

        guard_parsed(
            "NVD",
            envelope_found=envelope_found,
            envelope_desc="a 'vulnerabilities' field",
            items_seen=seen,
            items_understood=understood,
        )
        return vulns

"""URLhaus (abuse.ch) malicious-URL adapter.

Fetches recently-submitted malicious URLs from the **public** URLhaus CSV feed
(https://urlhaus.abuse.ch/downloads/csv_recent/) and normalises them to
ioc_network objects compatible with output.schema.json from kj299/threat-intel.

No credential required — this is a free, unauthenticated feed. (Verified against
the OpenCTI URLhaus connector, which fetches the same CSV with a plain GET and
no Auth-Key header.)

Feed characteristics (verified from the OpenCTI connector, 2026):
  - GET https://urlhaus.abuse.ch/downloads/csv_recent/
  - Response: CSV; comment lines start with ``#``. Columns:
    ``id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link,
    reporter`` (0-indexed 0..8).
  - The IOC is column 2 (``url``). ``dateadded`` (col 1) is an RFC 3339-ish
    timestamp; ``threat`` (col 5) is the campaign class; ``tags`` (col 6) is
    comma-separated.

URLhaus URLs are confirmed-malicious submissions, so IOCs are emitted with
``confidence: High`` and ``action: block``.
"""

from __future__ import annotations

import csv
import io
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from .base import FetchResult

logger = logging.getLogger(__name__)

_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

FEED_TYPES: dict[str, str] = {"malware_urls": _FEED_URL}
DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 900
_CACHE_KEY = "urlhaus_recent"

# Expected column count; rows shorter than this are malformed and skipped.
_MIN_COLS = 9


def _to_rfc3339(raw: str) -> str | None:
    """Parse a URLhaus ``dateadded`` value into an RFC 3339 string, or None."""
    raw = raw.strip()
    if not raw:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        return dt.replace(tzinfo=timezone.utc).isoformat()
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _normalize_row(row: list[str]) -> dict[str, Any] | None:
    """Map one URLhaus CSV row to an ioc_network dict, or None to skip."""
    if len(row) < _MIN_COLS:
        return None
    url = row[2].strip()
    if not url:
        return None

    url_status = row[3].strip()
    threat = row[5].strip()
    raw_tags = [t.strip() for t in row[6].split(",") if t.strip()]

    tags = ["urlhaus"]
    if threat:
        tags.append(threat)
    if url_status:
        tags.append(url_status)
    tags.extend(t for t in raw_tags if t not in tags)

    ioc: dict[str, Any] = {
        "type": "URL",
        "value": url,
        "confidence": "High",
        "source": "URLhaus",
        "action": "block",
        "tlp": "WHITE",
        "tags": tags,
    }
    if threat:
        ioc["associated_threat"] = threat
    first_seen = _to_rfc3339(row[1])
    if first_seen:
        ioc["first_seen"] = first_seen
    return ioc


class URLhausAdapter:
    """Adapter for the URLhaus (abuse.ch) recent malicious-URL feed."""

    name = "URLhaus"
    tier = 9
    # This feed needs no credential; the server treats it as always-configured.
    requires_credential = False

    def __init__(self, credentials: Any = None) -> None:
        # credentials accepted for interface symmetry; unused (public feed).
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Accept": "text/csv, text/plain",
                "User-Agent": "threat-intel-mcp/0.12 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("urlhaus.abuse.ch"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch the recent URLhaus malicious-URL feed.

        The feed is a fixed "recent" window maintained by URLhaus; ``time_range``
        is accepted for interface compatibility and recorded for the Coverage
        Ledger but not forwarded.
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
            iocs = cached[0]
        else:
            async with self._make_client() as client:
                resp = await client.get(_FEED_URL)
                resp.raise_for_status()
                iocs = self._parse_csv(resp.text)
            self._cache[_CACHE_KEY] = (iocs, now + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "urlhaus_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )
        return FetchResult(
            iocs=iocs,
            source="URLhaus",
            tier=9,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["malware_urls"],
        )

    def _parse_csv(self, text: str) -> list[dict[str, Any]]:
        """Parse the URLhaus CSV, skipping comment lines, into ioc dicts."""
        lines = (ln for ln in io.StringIO(text) if not ln.startswith("#"))
        reader = csv.reader(lines)
        return [
            normalized
            for row in reader
            if (normalized := _normalize_row(row)) is not None
        ]

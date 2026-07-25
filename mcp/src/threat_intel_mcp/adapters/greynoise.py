"""GreyNoise malicious-scanner adapter.

Fetches IPs GreyNoise has classified as **malicious** internet scanners/attackers
via the documented GNQL search endpoint (https://api.greynoise.io/v3/gnql) and
normalises them to ioc_network objects compatible with output.schema.json from
kj299/threat-intel.

Authentication: HTTP header ``key: <api_key>`` (GreyNoise's documented scheme).
Credential sourced from the injected CredentialProvider as
``credentials.get("greynoise", "api_key")`` → env var ``GREYNOISE_API_KEY``.

API characteristics (verified against the official pygreynoise SDK, 2026):
  - Endpoint: ``GET /v3/gnql?query=<GNQL>&quick=false&size=<n>&scroll=<token>``
  - Response: ``{"data": [ {record}, ... ], "count": N, "scroll": "...",
    "complete": bool}``
  - A record carries ``ip`` (top level) and a ``classification`` — the current
    schema nests it under ``internet_scanner_intelligence.classification`` while
    older records expose it at the top level; both forms are read.
  - GNQL ``classification:malicious`` returns confirmed-malicious scanners.
  - ``last_seen`` is a bare date (``YYYY-MM-DD``) — promoted to an RFC 3339
    datetime so the runtime date-time validation passes.
  - Crawl classifications change slowly — cache TTL 3600 s.

GreyNoise "malicious" is its own high-confidence verdict on observed attack /
scan behaviour, so IOCs are emitted with ``confidence: High`` and
``action: block``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from .base import FetchResult, guard_parsed

logger = logging.getLogger(__name__)

_API_BASE = "https://api.greynoise.io"
_GNQL_URL = f"{_API_BASE}/v3/gnql"

# Feed types mapped to GNQL queries. Only confirmed-malicious scanners are
# emitted as IOCs; benign/unknown classifications are intentionally excluded.
FEED_TYPES: dict[str, str] = {
    "malicious_scanners": "classification:malicious",
}

DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 3600

# GreyNoise returns up to `size` results per page; each page costs API credits.
PAGE_SIZE = 100
MAX_PAGES = 3

_DAYS_RE = re.compile(r"^(\d+)\s*d$", re.IGNORECASE)


def _time_range_to_gnql(time_range: str) -> str | None:
    """Convert a ``Nd`` time_range into a GNQL ``last_seen`` filter, else None."""
    m = _DAYS_RE.match(time_range.strip())
    if not m:
        return None
    return f"last_seen:{m.group(1)}d"


def _classification(record: dict[str, Any]) -> str | None:
    """Read the classification from either the nested or the flat record form."""
    isi = record.get("internet_scanner_intelligence")
    if isinstance(isi, dict) and isi.get("classification"):
        return isi["classification"]
    return record.get("classification")


def _last_seen(record: dict[str, Any]) -> str | None:
    """Return last_seen from either record form."""
    isi = record.get("internet_scanner_intelligence")
    if isinstance(isi, dict) and isi.get("last_seen"):
        return isi["last_seen"]
    return record.get("last_seen")


def _actor(record: dict[str, Any]) -> str | None:
    isi = record.get("internet_scanner_intelligence")
    if isinstance(isi, dict) and isi.get("actor"):
        return isi["actor"]
    return record.get("actor")


def _to_rfc3339(raw: str | None) -> str | None:
    """Promote a GreyNoise date/datetime to an RFC 3339 string, or None."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        try:
            dt = datetime.strptime(raw, "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _normalize_record(record: dict[str, Any], feed_type: str) -> dict[str, Any] | None:
    """Map one GNQL data record to an ioc_network dict, or None to skip.

    Only records GreyNoise classifies as ``malicious`` are emitted.
    """
    ip = record.get("ip")
    if not ip:
        return None
    if _classification(record) != "malicious":
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        logger.debug("GreyNoise record has unparseable ip, skipping: %r", ip)
        return None

    ioc: dict[str, Any] = {
        "type": "IPv4" if addr.version == 4 else "IPv6",
        "value": ip,
        "confidence": "High",
        "source": "GreyNoise",
        "action": "block",
        "tlp": "WHITE",
        "tags": ["greynoise", feed_type, "malicious-scanner"],
    }

    actor = _actor(record)
    if isinstance(actor, str) and actor and actor.lower() != "unknown":
        ioc["associated_threat"] = actor

    last_seen = _to_rfc3339(_last_seen(record))
    if last_seen:
        ioc["last_seen"] = last_seen

    return ioc


class GreyNoiseAdapter:
    """Adapter for GreyNoise (greynoise.io) malicious-scanner intelligence."""

    name = "GreyNoise"
    tier = 3

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        api_key = self._credentials.get("greynoise", "api_key")
        return httpx.AsyncClient(
            headers={
                "key": api_key,
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp/0.10 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("api.greynoise.io"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch GreyNoise malicious-scanner IPs via GNQL.

        The ``time_range`` (e.g. "7d") is folded into the GNQL query as a
        ``last_seen`` filter when it is expressed in days; otherwise it is
        recorded for the Coverage Ledger but not forwarded.
        """
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        api_key = self._credentials.get("greynoise", "api_key")  # fail fast

        t_start = time.monotonic()
        all_iocs: list[dict[str, Any]] = []
        failed: list[str] = []
        last_exc: Exception | None = None

        async with self._make_client() as client:
            for feed_type in requested:
                try:
                    all_iocs.extend(
                        await self._fetch_feed(client, api_key, feed_type, time_range)
                    )
                except Exception as exc:
                    logger.warning(
                        "GreyNoise feed_type=%s fetch failed: %s",
                        feed_type,
                        type(exc).__name__,
                    )
                    failed.append(feed_type)
                    last_exc = exc

        if last_exc is not None and len(failed) == len(requested):
            log_tool_call(
                "greynoise_fetch_iocs",
                {"time_range": time_range, "feed_types": requested},
                record_count=0,
                latency_ms=(time.monotonic() - t_start) * 1000,
                status="error",
                error=type(last_exc).__name__,
            )
            raise last_exc

        latency_ms = (time.monotonic() - t_start) * 1000
        fetched = [t for t in requested if t not in failed]

        log_tool_call(
            "greynoise_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(all_iocs),
            latency_ms=latency_ms,
            status="partial" if failed else "ok",
            error=f"failed feed_types: {failed}" if failed else None,
        )

        return FetchResult(
            iocs=all_iocs,
            source="GreyNoise",
            tier=3,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(all_iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=fetched,
            partial_failure=failed,
        )

    async def _fetch_feed(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        feed_type: str,
        time_range: str,
    ) -> list[dict[str, Any]]:
        """Fetch up to MAX_PAGES of one GNQL feed, using the in-process cache."""
        now = time.monotonic()
        cached = self._cache.get(feed_type)
        if cached is not None:
            cached_iocs, expiry = cached
            if now < expiry:
                logger.debug(
                    "Cache hit: feed_type=%s records=%d", feed_type, len(cached_iocs)
                )
                return cached_iocs

        query = FEED_TYPES[feed_type]
        last_seen_filter = _time_range_to_gnql(time_range)
        if last_seen_filter:
            query = f"{query} {last_seen_filter}"

        iocs: list[dict[str, Any]] = []
        scroll: str | None = None
        # Totals across the whole paginated fetch; an empty final page is
        # normal termination, not a format break.
        envelope_found = False
        seen = 0
        understood = 0

        for _page in range(MAX_PAGES):
            params: dict[str, Any] = {
                "query": query,
                "quick": "false",
                "size": PAGE_SIZE,
            }
            if scroll:
                params["scroll"] = scroll
            logger.info(
                "GreyNoise request: endpoint=/v3/gnql query=%r size=%d",
                query,
                PAGE_SIZE,
            )
            resp = await client.get(_GNQL_URL, params=params)
            resp.raise_for_status()
            body = resp.json()

            envelope_found = envelope_found or "data" in body
            data = body.get("data") or []
            # A record carrying an ip is one we read. Records GreyNoise does not
            # classify as malicious are understood and correctly filtered out.
            understood += sum(
                1 for r in data if isinstance(r, dict) and r.get("ip")
            )
            seen += len(data)
            iocs.extend(
                normalized
                for record in data
                if (normalized := _normalize_record(record, feed_type)) is not None
            )

            scroll = body.get("scroll")
            if not scroll or body.get("complete") is True or len(data) < PAGE_SIZE:
                break

        guard_parsed(
            "GreyNoise",
            envelope_found=envelope_found,
            envelope_desc="a 'data' field",
            items_seen=seen,
            items_understood=understood,
        )

        self._cache[feed_type] = (iocs, now + CACHE_TTL_SECONDS)
        logger.info("GreyNoise cached: feed_type=%s records=%d", feed_type, len(iocs))
        return iocs

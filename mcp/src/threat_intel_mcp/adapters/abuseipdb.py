"""AbuseIPDB blacklist adapter.

Fetches malicious IP indicators from the AbuseIPDB v2 blacklist endpoint
(https://api.abuseipdb.com/api/v2/blacklist) and normalises them to
ioc_network objects compatible with output.schema.json from kj299/threat-intel.

Authentication: HTTP header ``Key: <api_key>``; credential sourced from the
injected CredentialProvider as ``credentials.get("abuseipdb", "api_key")``,
which maps to the ``ABUSEIPDB_API_KEY`` environment variable in dev mode.

API characteristics (as of 2026):
  - No pagination — single request returns up to 10,000 IPs
  - Query params: confidenceMinimum=90, limit=10000
  - Cache TTL: 3600 seconds
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call, redact_url
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from .base import FetchResult, guard_parsed

logger = logging.getLogger(__name__)

_API_BASE = "https://api.abuseipdb.com/api/v2"
_BLACKLIST_URL = f"{_API_BASE}/blacklist"

CACHE_TTL_SECONDS = 3600
_CACHE_KEY = "abuseipdb_blacklist"


def _map_confidence(score: int) -> str:
    """Map an abuseConfidenceScore integer to High/Medium/Low."""
    if score >= 90:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def _normalize_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Map a single AbuseIPDB blacklist entry to an ioc_network dict.

    Returns None if ``ipAddress`` is missing or empty.
    """
    ip = entry.get("ipAddress")
    if not ip:
        return None

    score: int = int(entry.get("abuseConfidenceScore", 0))
    confidence = _map_confidence(score)
    associated_threat = "abuse" if score >= 90 else "suspected_abuse"

    return {
        "type": "IPv4",
        "value": ip,
        "confidence": confidence,
        "source": "AbuseIPDB",
        "action": "block",
        "tlp": "WHITE",
        "tags": ["abuseipdb", "blocklist"],
        "associated_threat": associated_threat,
    }


class AbuseIPDBAdapter:
    """Adapter for the AbuseIPDB (abuseipdb.com) IP blacklist feed."""

    name = "AbuseIPDB"
    tier = 3

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        # Simple in-process cache. Replaced by Redis/Memcached in Phase 4.
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        api_key = self._credentials.get("abuseipdb", "api_key")
        return httpx.AsyncClient(
            headers={
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp/0.8 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("api.abuseipdb.com"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch the current AbuseIPDB IP blacklist.

        Note: AbuseIPDB returns the *current* blacklist, not a historical window.
        ``time_range`` and ``feed_types`` are accepted for interface compatibility
        but are not forwarded to the API. They are recorded in the result for the
        skill's Coverage Ledger.
        """
        t_start = time.monotonic()

        now = time.monotonic()
        cached = self._cache.get(_CACHE_KEY)
        if cached is not None:
            cached_iocs, expiry = cached
            if now < expiry:
                logger.debug(
                    "Cache hit: %s records=%d", _CACHE_KEY, len(cached_iocs)
                )
                latency_ms = (time.monotonic() - t_start) * 1000
                log_tool_call(
                    "abuseipdb_fetch_blocklist",
                    {"time_range": time_range, "feed_types": feed_types},
                    record_count=len(cached_iocs),
                    latency_ms=latency_ms,
                    status="ok",
                )
                return FetchResult(
                    iocs=cached_iocs,
                    source="AbuseIPDB",
                    tier=3,
                    retrieved_at=datetime.now(timezone.utc).isoformat(),
                    record_count=len(cached_iocs),
                    latency_ms=round(latency_ms, 1),
                    feed_types_fetched=["blacklist"],
                )

        iocs: list[dict[str, Any]] = []
        async with self._make_client() as client:
            logger.info("AbuseIPDB request: url=%s", redact_url(_BLACKLIST_URL))
            resp = await client.get(
                _BLACKLIST_URL,
                params={"confidenceMinimum": 90, "limit": 10000},
            )
            resp.raise_for_status()
            data = resp.json()

        entries = data.get("data") or []
        understood = 0
        for entry in entries:
            # A dict carrying an ipAddress is a row we read, whether or not it
            # clears the confidence floor and becomes an IOC.
            if isinstance(entry, dict) and entry.get("ipAddress"):
                understood += 1
            normalized = _normalize_entry(entry)
            if normalized is not None:
                iocs.append(normalized)
        guard_parsed(
            "AbuseIPDB",
            envelope_found="data" in data,
            envelope_desc="a 'data' field",
            items_seen=len(entries),
            items_understood=understood,
        )

        self._cache[_CACHE_KEY] = (iocs, time.monotonic() + CACHE_TTL_SECONDS)
        logger.info("AbuseIPDB cached: %s records=%d", _CACHE_KEY, len(iocs))

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "abuseipdb_fetch_blocklist",
            {"time_range": time_range, "feed_types": feed_types},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )

        return FetchResult(
            iocs=iocs,
            source="AbuseIPDB",
            tier=3,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["blacklist"],
        )

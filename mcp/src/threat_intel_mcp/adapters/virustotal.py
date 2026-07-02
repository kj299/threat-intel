"""VirusTotal threat feed adapter.

Fetches recent malicious IP and domain indicators from the VirusTotal v3 feeds
API and normalises them to ioc_network objects compatible with output.schema.json
from kj299/threat-intel.

Authentication: HTTP header ``x-apikey: <api_key>``.
Credentials are sourced exclusively from the injected CredentialProvider via
``credentials.get("virustotal", "api_key")`` → env var ``VT_API_KEY``.

API characteristics (VirusTotal Intelligence, as of 2026):
  - Endpoint: ``GET /api/v3/feeds/{feed_type}?cursor=initial&limit=40``
  - Response: newline-delimited JSON (one object per line)
  - Each object: ``{"id": "...", "type": "ip_address"|"domain", "attributes": {...}}``
  - Pagination: ``meta.cursor`` in JSON envelope; absent when no more pages
  - Rate limit: conservative 15-second inter-request delay (4 req/min free tier)
  - Cache TTL: 900 seconds (15 min)
  - Max pages per feed_type: 3 (limits requests on free tier)
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call, redact_url
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from .base import FetchResult

logger = logging.getLogger(__name__)

_API_BASE = "https://www.virustotal.com/api/v3"

# Supported feed types and the VT object type they contain.
FEED_TYPES: dict[str, str] = {
    "malicious_ips": "ip_address",
    "malicious_domains": "domain",
}

DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

# VT feeds update frequently — 15-minute cache is appropriate.
CACHE_TTL_SECONDS = 900

# Limit pages per feed_type to cap requests on free tier.
MAX_PAGES = 3

# Number of items to request per page.
PAGE_LIMIT = 40

# Conservative inter-request delay (seconds) to respect the 4 req/min free tier.
# Overridable in tests by passing _rate_limit_delay=0 to the constructor.
_DEFAULT_RATE_LIMIT_DELAY: float = 15.0


def _normalize_vt_entry(entry: dict[str, Any], feed_type: str) -> dict[str, Any] | None:
    """Map a single VirusTotal feed object to an ioc_network dict.

    Returns None for entries that cannot be parsed, have an unrecognised type,
    or are missing required fields.
    """
    try:
        vt_type = entry.get("type", "")
        value = entry.get("id", "")
    except (AttributeError, TypeError):
        return None

    if not value:
        logger.debug("VT entry missing id, skipping: %r", entry)
        return None

    if vt_type == "ip_address":
        # Distinguish IPv4 vs IPv6 by presence of colon.
        ioc_type = "IPv6" if ":" in value else "IPv4"
    elif vt_type == "domain":
        ioc_type = "Domain"
    else:
        logger.debug("VT entry has unrecognised type %r, skipping", vt_type)
        return None

    # Derive confidence from last_analysis_stats.malicious detector count.
    attributes = entry.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious_count = stats.get("malicious", 0)

    if malicious_count >= 10:
        confidence = "High"
    elif malicious_count >= 3:
        confidence = "Medium"
    else:
        confidence = "Low"

    tags: list[str] = list(attributes.get("tags") or [])
    if "virustotal" not in tags:
        tags.insert(0, "virustotal")
    if feed_type not in tags:
        tags.append(feed_type)

    return {
        "type": ioc_type,
        "value": value,
        "confidence": confidence,
        "source": "VirusTotal",
        "action": "block",
        "tlp": "WHITE",
        "tags": tags,
    }


class VirusTotalAdapter:
    """Adapter for VirusTotal (virustotal.com) Intelligence feeds."""

    name = "VirusTotal"
    tier = 2

    def __init__(
        self,
        credentials: CredentialProvider,
        *,
        _rate_limit_delay: float = _DEFAULT_RATE_LIMIT_DELAY,
    ) -> None:
        self._credentials = credentials
        self._rate_limit_delay = _rate_limit_delay
        # Semaphore ensures sequential HTTP requests for rate limiting.
        self._semaphore = asyncio.Semaphore(1)
        # In-process cache keyed by feed_type.
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        api_key = self._credentials.get("virustotal", "api_key")
        return httpx.AsyncClient(
            headers={
                "x-apikey": api_key,
                "User-Agent": "threat-intel-mcp/0.8 (kj299/threat-intel)",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("www.virustotal.com"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch recent VirusTotal indicators across the requested feed types.

        Note: VirusTotal feeds return a rolling window of recent activity.
        time_range is accepted for schema compatibility but is informational only —
        the feed window is controlled by VT's own retention policy. It is recorded
        in the result for the skill's Coverage Ledger.
        """
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        t_start = time.monotonic()
        all_iocs: list[dict[str, Any]] = []
        failed: list[str] = []
        last_exc: Exception | None = None

        async with self._make_client() as client:
            # Fetch feed types sequentially (rate limit enforced inside _fetch_feed).
            for feed_type in requested:
                try:
                    iocs = await self._fetch_feed(client, feed_type)
                    all_iocs.extend(iocs)
                except Exception as exc:
                    logger.warning(
                        "VirusTotal feed_type=%s fetch failed: %s", feed_type, exc
                    )
                    failed.append(feed_type)
                    last_exc = exc

        # Every requested feed type failed: total failure — propagate so the
        # caller's retry/circuit-breaker layer can act on it (issue #56).
        # Partial results still return below.
        if last_exc is not None and len(failed) == len(requested):
            log_tool_call(
                "virustotal_fetch_iocs",
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
            "virustotal_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(all_iocs),
            latency_ms=latency_ms,
            status="partial" if failed else "ok",
            error=f"failed feed_types: {failed}" if failed else None,
        )

        return FetchResult(
            iocs=all_iocs,
            source="VirusTotal",
            tier=2,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(all_iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=fetched,
            partial_failure=failed,
        )

    async def _fetch_feed(
        self, client: httpx.AsyncClient, feed_type: str
    ) -> list[dict[str, Any]]:
        """Fetch up to MAX_PAGES pages of a single feed type, using the cache."""
        now = time.monotonic()
        if feed_type in self._cache:
            cached_iocs, expiry = self._cache[feed_type]
            if now < expiry:
                logger.debug(
                    "VT cache hit: feed_type=%s records=%d", feed_type, len(cached_iocs)
                )
                return cached_iocs

        iocs: list[dict[str, Any]] = []
        cursor = "initial"

        for page_num in range(1, MAX_PAGES + 1):
            url = f"{_API_BASE}/feeds/{feed_type}"
            params: dict[str, Any] = {"cursor": cursor, "limit": PAGE_LIMIT}

            async with self._semaphore:
                if self._rate_limit_delay > 0:
                    await asyncio.sleep(self._rate_limit_delay)

                logger.info(
                    "VT request: url=%s feed_type=%s page=%d",
                    redact_url(url),
                    feed_type,
                    page_num,
                )
                resp = await client.get(url, params=params)
                resp.raise_for_status()

            # Response is newline-delimited JSON.
            entries_on_page = 0
            next_cursor: str | None = None

            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("VT: skipping non-JSON line: %r", line[:80])
                    continue

                # Last line may be a metadata envelope with cursor info.
                if "meta" in obj and "data" not in obj:
                    next_cursor = obj.get("meta", {}).get("cursor")
                    continue

                # Standard entry line.
                normalized = _normalize_vt_entry(obj, feed_type)
                if normalized is not None:
                    iocs.append(normalized)
                    entries_on_page += 1

            logger.info(
                "VT page %d: feed_type=%s entries=%d", page_num, feed_type, entries_on_page
            )

            # Stop if no cursor for next page or fewer items than requested.
            if not next_cursor or entries_on_page < PAGE_LIMIT:
                break
            cursor = next_cursor

        self._cache[feed_type] = (iocs, now + CACHE_TTL_SECONDS)
        logger.info("VT cached: feed_type=%s records=%d", feed_type, len(iocs))
        return iocs

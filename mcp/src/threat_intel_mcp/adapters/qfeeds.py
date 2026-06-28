"""Q-Feeds CTI feed adapter.

Fetches malicious IP and domain indicators from the Q-Feeds REST API
(https://api.qfeeds.com/api) and normalises them to ioc_network objects
compatible with output.schema.json from kj299/threat-intel.

Authentication: HTTP Basic auth — username "api_token", password = QFEEDS_API_KEY.
Credentials are sourced exclusively from the injected CredentialProvider.

API characteristics (as of 2026):
  - Response: plain text, one indicator per line; comment lines start with #
  - Pagination: 4,000 records per page via ?page=N
  - Update frequency: Premium = every 20 min → cache TTL 20 min
  - Confirmed feed types: malware_ip, malware_domains
  - OpenAPI spec: https://api.qfeeds.com/openapi/ (requires auth)
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call, redact_url
from ..vault.base import CredentialProvider
from .base import FetchResult

logger = logging.getLogger(__name__)

_API_BASE = "https://api.qfeeds.com/api"

# Confirmed feed types and their primary IOC type mapping.
# Add "malware_url" here if your Q-Feeds subscription includes URL feeds.
FEED_TYPES: dict[str, str] = {
    "malware_ip": "ip",
    "malware_domains": "domain",
}

DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

# Premium tier updates every 20 minutes.
CACHE_TTL_SECONDS = 1200

# Q-Feeds paginates at 4,000 records per page.
PAGE_SIZE = 4000

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


class QFeedsAdapter:
    """Adapter for Q-Feeds (qfeeds.com) threat intelligence feeds."""

    name = "Q-Feeds"
    tier = 2

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        # Simple in-process cache keyed by feed_type. Replaced by Redis/Memcached
        # in Phase 4 when multiple MCP server instances run behind a load balancer.
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        api_key = self._credentials.get("qfeeds", "api_key")
        return httpx.AsyncClient(
            auth=("api_token", api_key),
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            headers={"User-Agent": "threat-intel-mcp/0.1 (kj299/threat-intel)"},
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch current Q-Feeds indicators across the requested feed types.

        Note: Q-Feeds returns the *current* blocklist, not a historical window.
        time_range is accepted for schema compatibility but is not forwarded to
        the API. It is recorded in the result for the skill's Coverage Ledger.
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

        async with self._make_client() as client:
            tasks = {
                feed_type: asyncio.create_task(self._fetch_feed(client, feed_type))
                for feed_type in requested
            }
            for feed_type, task in tasks.items():
                try:
                    iocs = await task
                    all_iocs.extend(iocs)
                except Exception as exc:
                    logger.warning(
                        "Q-Feeds feed_type=%s fetch failed: %s", feed_type, exc
                    )
                    failed.append(feed_type)

        latency_ms = (time.monotonic() - t_start) * 1000
        fetched = [t for t in requested if t not in failed]

        log_tool_call(
            "qfeeds_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(all_iocs),
            latency_ms=latency_ms,
            status="partial" if failed else "ok",
            error=f"failed feed_types: {failed}" if failed else None,
        )

        return FetchResult(
            iocs=all_iocs,
            source="Q-Feeds",
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
        """Fetch all pages of a single feed type, using the in-process cache."""
        now = time.monotonic()
        if feed_type in self._cache:
            cached_iocs, expiry = self._cache[feed_type]
            if now < expiry:
                logger.debug("Cache hit: feed_type=%s records=%d", feed_type, len(cached_iocs))
                return cached_iocs

        iocs: list[dict[str, Any]] = []
        page = 1

        while True:
            url = _API_BASE
            params = {"feed_type": feed_type, "limit": PAGE_SIZE, "page": page}
            logger.info(
                "Q-Feeds request: url=%s feed_type=%s page=%d",
                redact_url(url),
                feed_type,
                page,
            )
            resp = await client.get(url, params=params)
            resp.raise_for_status()

            lines = [
                ln.strip()
                for ln in resp.text.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            if not lines:
                break

            page_iocs = [
                normalized
                for line in lines
                if (normalized := _normalize_line(line, feed_type)) is not None
            ]
            iocs.extend(page_iocs)

            if len(lines) < PAGE_SIZE:
                break
            page += 1

        self._cache[feed_type] = (iocs, now + CACHE_TTL_SECONDS)
        logger.info("Q-Feeds cached: feed_type=%s records=%d", feed_type, len(iocs))
        return iocs


def _normalize_line(line: str, feed_type: str) -> dict[str, Any] | None:
    """Map a single plain-text indicator line to an ioc_network dict.

    Returns None for lines that cannot be parsed or validated.
    """
    if not line:
        return None

    if feed_type == "malware_ip":
        if "/" in line:
            # CIDR block — validate before emitting
            try:
                ipaddress.ip_network(line, strict=False)
            except ValueError:
                logger.debug("Invalid CIDR, skipping: %r", line)
                return None
            ioc_type = "CIDR_Range"
        elif ":" in line:
            ioc_type = "IPv6"
        elif _IPV4_RE.match(line):
            ioc_type = "IPv4"
        else:
            logger.debug("Unrecognised IP-feed line, skipping: %r", line)
            return None

    elif feed_type == "malware_domains":
        if line.startswith(("http://", "https://")):
            ioc_type = "URL"
        else:
            ioc_type = "Domain"
    else:
        ioc_type = "Domain"

    return {
        "type": ioc_type,
        "value": line,
        "confidence": "High",
        "source": "Q-Feeds",
        "action": "block",
        "tlp": "GREEN",
        "tags": [feed_type, "q-feeds"],
        "associated_threat": "malware",
    }

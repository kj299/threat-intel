"""Shodan malware-infrastructure adapter.

Fetches hosts flagged by Shodan's Malware Hunter crawlers (C2 servers and
malware-serving infrastructure) via the documented search API
(https://api.shodan.io/shodan/host/search) and normalises them to ioc_network
objects compatible with output.schema.json from kj299/threat-intel.

Authentication: ``key`` **query parameter** (Shodan's documented scheme).
Because the key travels in the URL, this adapter never logs request URLs or raw
exception messages — only the endpoint path, query name, and exception type.
Credential sourced from the injected CredentialProvider as
``credentials.get("shodan", "api_key")`` → env var ``SHODAN_API_KEY``.

API characteristics (developer.shodan.io, as of 2026):
  - Endpoint: ``GET /shodan/host/search?key=..&query=..&page=N``
  - Response: JSON ``{"matches": [...], "total": N}``; each match carries
    ``ip_str``, ``port``, ``timestamp`` (naive ISO 8601, UTC), ``hostnames``,
    ``product``, ``tags``
  - 100 results per page; each page costs one query credit (paid plans)
  - ``category:malware`` surfaces Malware Hunter detections (membership feature)
  - Crawl data changes slowly — cache TTL 3600 seconds

Shodan detections are crawler heuristics, not confirmed-malicious verdicts, so
IOCs are emitted with ``action: alert`` (investigate, don't auto-block) and at
most Medium/High confidence.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from .base import FetchResult, guard_parsed

logger = logging.getLogger(__name__)

_API_BASE = "https://api.shodan.io"
_SEARCH_URL = f"{_API_BASE}/shodan/host/search"

# Feed types mapped to documented Shodan search queries.
FEED_TYPES: dict[str, str] = {
    "malware_c2": "category:malware",
}

DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 3600

# Shodan returns 100 results per page; each page costs one query credit, so
# keep the page cap conservative.
PAGE_SIZE = 100
MAX_PAGES = 3


def _normalize_timestamp(raw: str | None) -> str | None:
    """Convert Shodan's naive ISO timestamp (UTC) to an RFC 3339 string.

    Shodan emits e.g. ``2026-06-30T18:04:12.123456`` with no offset; the
    ioc_network schema's date-time format check would reject that, so attach
    UTC explicitly. Returns None for missing/unparseable values.
    """
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _normalize_match(match: dict[str, Any], feed_type: str) -> dict[str, Any] | None:
    """Map a single Shodan search match to an ioc_network dict.

    Returns None for matches without a parseable IP address.
    """
    ip = match.get("ip_str")
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        logger.debug("Shodan match has unparseable ip_str, skipping: %r", ip)
        return None

    match_tags = [t for t in (match.get("tags") or []) if isinstance(t, str)]
    # "malware" is Malware Hunter's own verdict tag; anything else from the
    # category search is a heuristic hit.
    confidence = "High" if "malware" in match_tags else "Medium"

    tags = ["shodan", feed_type]
    tags.extend(t for t in match_tags if t not in tags)

    ioc: dict[str, Any] = {
        "type": "IPv4" if addr.version == 4 else "IPv6",
        "value": ip,
        "confidence": confidence,
        "source": "Shodan",
        "action": "alert",
        "tlp": "WHITE",
        "tags": tags,
    }

    product = match.get("product")
    if isinstance(product, str) and product:
        ioc["associated_threat"] = product

    last_seen = _normalize_timestamp(match.get("timestamp"))
    if last_seen:
        ioc["last_seen"] = last_seen

    return ioc


class ShodanAdapter:
    """Adapter for Shodan (shodan.io) malware-infrastructure search."""

    name = "Shodan"
    tier = 3

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        # Simple in-process cache keyed by feed_type.
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp/0.9 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("api.shodan.io"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch current Shodan malware-infrastructure detections.

        Note: Shodan search reflects the crawlers' *current* view, not a
        historical window. ``time_range`` is accepted for interface
        compatibility and recorded for the skill's Coverage Ledger; the
        per-match ``last_seen`` carries the actual crawl timestamp.
        """
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        # Fetch the credential up front so a missing key surfaces as the
        # credential error the tool layer expects, not mid-request.
        api_key = self._credentials.get("shodan", "api_key")

        t_start = time.monotonic()
        all_iocs: list[dict[str, Any]] = []
        failed: list[str] = []
        last_exc: Exception | None = None

        async with self._make_client() as client:
            for feed_type in requested:
                try:
                    iocs = await self._fetch_feed(client, api_key, feed_type)
                    all_iocs.extend(iocs)
                except Exception as exc:
                    # The API key rides in the query string: log the exception
                    # TYPE only, never its message (httpx messages embed URLs).
                    logger.warning(
                        "Shodan feed_type=%s fetch failed: %s",
                        feed_type,
                        type(exc).__name__,
                    )
                    failed.append(feed_type)
                    last_exc = exc

        # Every requested feed type failed: total failure — propagate so the
        # caller's retry/circuit-breaker layer can act on it.
        if last_exc is not None and len(failed) == len(requested):
            log_tool_call(
                "shodan_fetch_iocs",
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
            "shodan_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(all_iocs),
            latency_ms=latency_ms,
            status="partial" if failed else "ok",
            error=f"failed feed_types: {failed}" if failed else None,
        )

        return FetchResult(
            iocs=all_iocs,
            source="Shodan",
            tier=3,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(all_iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=fetched,
            partial_failure=failed,
        )

    async def _fetch_feed(
        self, client: httpx.AsyncClient, api_key: str, feed_type: str
    ) -> list[dict[str, Any]]:
        """Fetch up to MAX_PAGES of one feed type, using the in-process cache."""
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
        iocs: list[dict[str, Any]] = []
        # Totals across the whole paginated fetch: an empty final page is
        # normal termination, not a format break.
        envelope_found = False
        seen = 0
        understood = 0

        for page in range(1, MAX_PAGES + 1):
            logger.info(
                "Shodan request: endpoint=/shodan/host/search query=%r page=%d",
                query,
                page,
            )
            resp = await client.get(
                _SEARCH_URL,
                params={"key": api_key, "query": query, "page": page},
            )
            resp.raise_for_status()
            body = resp.json()
            envelope_found = envelope_found or "matches" in body
            matches = body.get("matches") or []
            # A match carrying an ip_str is a row we read, whether or not the
            # address parses into an IOC.
            understood += sum(
                1 for m in matches if isinstance(m, dict) and m.get("ip_str")
            )
            seen += len(matches)

            iocs.extend(
                normalized
                for match in matches
                if (normalized := _normalize_match(match, feed_type)) is not None
            )

            if len(matches) < PAGE_SIZE:
                break

        guard_parsed(
            "Shodan",
            envelope_found=envelope_found,
            envelope_desc="a 'matches' field",
            items_seen=seen,
            items_understood=understood,
        )

        self._cache[feed_type] = (iocs, now + CACHE_TTL_SECONDS)
        logger.info("Shodan cached: feed_type=%s records=%d", feed_type, len(iocs))
        return iocs

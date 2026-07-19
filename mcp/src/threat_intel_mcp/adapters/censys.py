"""Censys malware-infrastructure adapter.

Fetches hosts Censys labels as malware/C2 infrastructure via the documented
Search v2 hosts endpoint (https://search.censys.io/api/v2/hosts/search) and
normalises them to ioc_network objects compatible with output.schema.json.

Authentication: HTTP Basic — username = API ID, password = API secret (Censys's
documented scheme). Sourced from the injected CredentialProvider as
``credentials.get("censys", "api_id")`` and ``("censys", "api_secret")`` → env
vars ``CENSYS_API_ID`` / ``CENSYS_API_SECRET``.

API characteristics (verified against the official censys-python SDK, 2026):
  - Endpoint: ``GET /api/v2/hosts/search?q=<query>&per_page=100&cursor=<c>``
  - Response: ``{"result": {"hits": [ {"ip": ..., "labels": [...],
    "last_updated_at": "..."} ], "links": {"next": "<cursor>"}}}``
  - ``labels`` include ``malware`` / ``c2`` for flagged infrastructure.
  - Cursor pagination via ``result.links.next``.

Censys is an attack-surface search engine, not a curated blocklist: a
``labels:malware`` hit is *observed* malware/C2 infrastructure, so IOCs are
emitted with ``action: alert`` (investigate, don't auto-block) and Medium
confidence — the same honest treatment as the Shodan adapter.
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
from .base import FetchResult

logger = logging.getLogger(__name__)

_API_BASE = "https://search.censys.io/api/v2"
_HOSTS_SEARCH_URL = f"{_API_BASE}/hosts/search"

# Feed types mapped to Censys Search queries over the `labels` field.
FEED_TYPES: dict[str, str] = {
    "malware_hosts": "labels: malware or labels: c2",
}

DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 3600
PER_PAGE = 100
MAX_PAGES = 3


def _rfc3339(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _normalize_hit(hit: dict[str, Any], feed_type: str) -> dict[str, Any] | None:
    """Map one Censys host-search hit to an ioc_network dict, or None to skip."""
    ip = hit.get("ip")
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    labels = [str(x) for x in (hit.get("labels") or []) if x]
    ioc: dict[str, Any] = {
        "type": "IPv4" if addr.version == 4 else "IPv6",
        "value": ip,
        "confidence": "Medium",
        "source": "Censys",
        "action": "alert",
        "tlp": "WHITE",
        "tags": ["censys", feed_type, *labels],
    }
    last_seen = _rfc3339(hit.get("last_updated_at"))
    if last_seen:
        ioc["last_seen"] = last_seen
    return ioc


class CensysAdapter:
    """Adapter for Censys (censys.io) Search v2 malware-infrastructure hosts."""

    name = "Censys"
    tier = 3

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self, api_id: str, api_secret: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            auth=(api_id, api_secret),  # HTTP Basic: API ID + secret
            headers={
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp/0.11 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("search.censys.io"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch Censys malware/C2-labelled hosts across the requested feeds."""
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        api_id = self._credentials.get("censys", "api_id")
        api_secret = self._credentials.get("censys", "api_secret")  # fail fast

        t_start = time.monotonic()
        all_iocs: list[dict[str, Any]] = []
        failed: list[str] = []
        last_exc: Exception | None = None

        async with self._make_client(api_id, api_secret) as client:
            for feed_type in requested:
                try:
                    all_iocs.extend(await self._fetch_feed(client, feed_type))
                except Exception as exc:
                    logger.warning(
                        "Censys feed_type=%s fetch failed: %s",
                        feed_type,
                        type(exc).__name__,
                    )
                    failed.append(feed_type)
                    last_exc = exc

        if last_exc is not None and len(failed) == len(requested):
            log_tool_call(
                "censys_fetch_iocs",
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
            "censys_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(all_iocs),
            latency_ms=latency_ms,
            status="partial" if failed else "ok",
            error=f"failed feed_types: {failed}" if failed else None,
        )

        return FetchResult(
            iocs=all_iocs,
            source="Censys",
            tier=3,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(all_iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=fetched,
            partial_failure=failed,
        )

    async def _fetch_feed(
        self, client: httpx.AsyncClient, feed_type: str
    ) -> list[dict[str, Any]]:
        """Fetch up to MAX_PAGES of one Censys query, using the in-process cache."""
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
        cursor: str | None = None

        for _page in range(MAX_PAGES):
            params: dict[str, Any] = {"q": query, "per_page": PER_PAGE}
            if cursor:
                params["cursor"] = cursor
            logger.info("Censys request: endpoint=/hosts/search q=%r", query)
            resp = await client.get(_HOSTS_SEARCH_URL, params=params)
            resp.raise_for_status()
            result = resp.json().get("result") or {}

            hits = result.get("hits") or []
            iocs.extend(
                n for hit in hits if (n := _normalize_hit(hit, feed_type)) is not None
            )

            cursor = (result.get("links") or {}).get("next")
            if not cursor or len(hits) < PER_PAGE:
                break

        self._cache[feed_type] = (iocs, now + CACHE_TTL_SECONDS)
        logger.info("Censys cached: feed_type=%s records=%d", feed_type, len(iocs))
        return iocs

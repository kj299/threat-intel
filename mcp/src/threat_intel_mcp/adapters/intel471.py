"""Intel 471 malware-indicators adapter.

Fetches malware indicators from Intel 471's Titan API indicators stream
(https://api.intel471.com/v1/indicators/stream) and normalises the network
ones to ioc_network objects compatible with output.schema.json.

Authentication: HTTP Basic — username = account email, password = API key
(Intel 471's documented scheme). Sourced from the injected CredentialProvider
as ``credentials.get("intel471", "email")`` and ``("intel471", "api_key")`` →
env vars ``INTEL471_EMAIL`` / ``INTEL471_API_KEY``.

API characteristics (verified against the official titan-client-python SDK and
its captured response fixtures, 2026):
  - Endpoint: ``GET /v1/indicators/stream?lastUpdatedFrom=<ms>&count=100&cursor=<c>``
  - Cursor pagination via the ``cursorNext`` response field.
  - Response: ``{"indicators": [ {"data": {...}}, ... ], "cursorNext": "..."}``
  - Per indicator ``data``: ``indicator_data.address`` (IP) and
    ``indicator_data.url`` (URL) carry the network IOCs; ``confidence``;
    ``threat.data.family`` (malware family); ``activity.last`` (epoch ms).
  - File-hash indicators are ioc_host, not ioc_network — skipped here.

These are confirmed malware indicators, emitted with ``action: block``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from .base import FetchResult

logger = logging.getLogger(__name__)

_API_BASE = "https://api.intel471.com/v1"
_STREAM_URL = f"{_API_BASE}/indicators/stream"

FEED_TYPES: dict[str, str] = {"malware_indicators": "indicators/stream"}
DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 3600
PAGE_COUNT = 100
MAX_PAGES = 3

_DAYS_RE = re.compile(r"^(\d+)\s*d$", re.IGNORECASE)


def _confidence(raw: Any) -> str:
    val = str(raw or "").strip().lower()
    if val in ("high", "h"):
        return "High"
    if val in ("low", "l"):
        return "Low"
    return "Medium"


def _epoch_ms_to_rfc3339(ms: Any) -> str | None:
    try:
        seconds = int(ms) / 1000.0
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def _last_updated_from(time_range: str) -> int | None:
    """Convert an ``Nd`` time_range into a lastUpdatedFrom epoch-ms bound."""
    m = _DAYS_RE.match(time_range.strip())
    if not m:
        return None
    since = datetime.now(timezone.utc) - timedelta(days=int(m.group(1)))
    return int(since.timestamp() * 1000)


def _normalize_indicator(indicator: dict[str, Any]) -> dict[str, Any] | None:
    """Map one Intel 471 indicator to an ioc_network dict, or None to skip.

    Only IP (``indicator_data.address``) and URL (``indicator_data.url``)
    indicators map onto ioc_network; file hashes and others are skipped.
    """
    data = indicator.get("data") or {}
    idata = data.get("indicator_data") or {}

    address = idata.get("address")
    url = idata.get("url")

    if address:
        try:
            addr = ipaddress.ip_address(address)
        except ValueError:
            return None
        ioc_type, value = ("IPv4" if addr.version == 4 else "IPv6"), address
    elif url:
        ioc_type, value = "URL", url
    else:
        return None

    ioc: dict[str, Any] = {
        "type": ioc_type,
        "value": value,
        "confidence": _confidence(data.get("confidence")),
        "source": "Intel 471",
        "action": "block",
        "tlp": "AMBER",
        "tags": ["intel471"],
    }

    family = (((data.get("threat") or {}).get("data")) or {}).get("family")
    if isinstance(family, str) and family:
        ioc["associated_threat"] = family

    last_seen = _epoch_ms_to_rfc3339(((data.get("activity") or {}).get("last")))
    if last_seen:
        ioc["last_seen"] = last_seen

    return ioc


class Intel471Adapter:
    """Adapter for Intel 471 (intel471.com) Titan malware indicators."""

    name = "Intel 471"
    tier = 2

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self, email: str, api_key: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            auth=(email, api_key),  # HTTP Basic: email as login, API key as password
            headers={
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp/0.11 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("api.intel471.com"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch Intel 471 malware indicators, mapping the network ones."""
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        email = self._credentials.get("intel471", "email")
        api_key = self._credentials.get("intel471", "api_key")  # fail fast

        t_start = time.monotonic()
        try:
            iocs = await self._fetch_stream(email, api_key, time_range)
        except Exception as exc:
            log_tool_call(
                "intel471_fetch_iocs",
                {"time_range": time_range, "feed_types": requested},
                record_count=0,
                latency_ms=(time.monotonic() - t_start) * 1000,
                status="error",
                error=type(exc).__name__,
            )
            raise

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "intel471_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )
        return FetchResult(
            iocs=iocs,
            source="Intel 471",
            tier=2,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["malware_indicators"],
            partial_failure=[],
        )

    async def _fetch_stream(
        self, email: str, api_key: str, time_range: str
    ) -> list[dict[str, Any]]:
        """Fetch up to MAX_PAGES of the indicators stream, using the cache."""
        now = time.monotonic()
        cached = self._cache.get("malware_indicators")
        if cached is not None:
            cached_iocs, expiry = cached
            if now < expiry:
                logger.debug("Cache hit: intel471 records=%d", len(cached_iocs))
                return cached_iocs

        base_params: dict[str, Any] = {"count": PAGE_COUNT}
        since = _last_updated_from(time_range)
        if since is not None:
            base_params["lastUpdatedFrom"] = since

        iocs: list[dict[str, Any]] = []
        cursor: str | None = None
        async with self._make_client(email, api_key) as client:
            for _page in range(MAX_PAGES):
                params = dict(base_params)
                if cursor:
                    params["cursor"] = cursor
                logger.info("Intel 471 request: endpoint=/indicators/stream")
                resp = await client.get(_STREAM_URL, params=params)
                resp.raise_for_status()
                body = resp.json()

                indicators = body.get("indicators") or []
                iocs.extend(
                    n for ind in indicators if (n := _normalize_indicator(ind))
                )

                cursor = body.get("cursorNext")
                if not cursor or len(indicators) < PAGE_COUNT:
                    break

        self._cache["malware_indicators"] = (iocs, now + CACHE_TTL_SECONDS)
        logger.info("Intel 471 cached: records=%d", len(iocs))
        return iocs

"""AlienVault OTX feed adapter.

Fetches threat indicators from subscribed OTX pulses via the OTX REST API
(https://otx.alienvault.com/api/v1) and normalises them to ioc_network objects
compatible with output.schema.json from kj299/threat-intel.

Authentication: HTTP header X-OTX-API-KEY.
Credentials are sourced exclusively from the injected CredentialProvider.
  credentials.get("otx", "api_key") -> env var OTX_API_KEY

API characteristics (as of 2026):
  - Endpoint: GET /pulses/subscribed?limit=20&page=1&modified_since=<ISO8601>
  - Response: JSON {"results": [...pulses...], "next": "url or null"}
  - Each pulse has an "indicators" list
  - Update frequency: hourly -> cache TTL 3600 seconds
  - Max pages per fetch: 10 (to bound latency)
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..audit import log_tool_call, redact_url
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from .base import FetchResult

logger = logging.getLogger(__name__)

_API_BASE = "https://otx.alienvault.com/api/v1"

# OTX updates hourly; cache for one hour.
CACHE_TTL_SECONDS = 3600

# Hard limit on pagination to bound latency and memory.
MAX_PAGES = 10

# Default page size for subscribed pulses endpoint.
PAGE_SIZE = 20

# OTX indicator type -> ioc_network type mapping.
# Types not present here are skipped (e.g. file hashes are not in ioc_network schema).
_TYPE_MAP: dict[str, str] = {
    "IPv4": "IPv4",
    "IPv6": "IPv6",
    "domain": "Domain",
    "hostname": "Domain",
    "URL": "URL",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _pulse_name_slug(name: str) -> str:
    """Convert a pulse name to a lowercase hyphen-separated slug for use in tags."""
    return _SLUG_RE.sub("-", name.lower()).strip("-")


def _normalize_indicator(ind: dict[str, Any], *, pulse_name: str = "") -> dict[str, Any] | None:
    """Map a single OTX indicator dict to an ioc_network dict, or None if unsupported.

    Args:
        ind: A single indicator object from the OTX pulse indicators list.
        pulse_name: The name of the enclosing pulse, used to generate tags.

    Returns:
        An ioc_network-shaped dict, or None for unsupported indicator types.
    """
    otx_type = ind.get("type", "")
    ioc_type = _TYPE_MAP.get(otx_type)
    if ioc_type is None:
        logger.debug("Skipping unsupported OTX indicator type: %r", otx_type)
        return None

    value = ind.get("indicator", "")
    if not value:
        logger.debug("Skipping OTX indicator with empty value: %r", ind)
        return None

    tags = ["otx"]
    if pulse_name:
        slug = _pulse_name_slug(pulse_name)
        if slug:
            tags.append(slug)

    result: dict[str, Any] = {
        "type": ioc_type,
        "value": value,
        "confidence": "High",
        "source": "AlienVault OTX",
        "action": "alert",
        "tlp": "WHITE",
        "tags": tags,
    }

    # Include first_seen from "created" if present and non-empty.
    created = ind.get("created", "")
    if created:
        result["first_seen"] = created

    return result


def _parse_time_range(time_range: str) -> datetime:
    """Parse a time_range string like '7d' or '24h' and return the start datetime."""
    time_range = time_range.strip().lower()
    now = datetime.now(timezone.utc)

    if time_range.endswith("d"):
        days = int(time_range[:-1])
        return now - timedelta(days=days)
    if time_range.endswith("h"):
        hours = int(time_range[:-1])
        return now - timedelta(hours=hours)
    if time_range.endswith("m"):
        minutes = int(time_range[:-1])
        return now - timedelta(minutes=minutes)

    raise ValueError(
        f"Unrecognised time_range format: {time_range!r}. "
        "Expected format like '7d', '24h', or '30m'."
    )


class OTXAdapter:
    """Adapter for AlienVault OTX subscribed-pulse feed."""

    name = "AlienVault OTX"
    tier = 2

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        # In-process cache keyed by "otx_subscribed".
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        api_key = self._credentials.get("otx", "api_key")
        return httpx.AsyncClient(
            headers={
                "X-OTX-API-KEY": api_key,
                "User-Agent": "threat-intel-mcp/0.3 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("otx.alienvault.com"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch indicators from OTX subscribed pulses modified within time_range.

        Args:
            time_range: Lookback window, e.g. "7d" or "24h".
            feed_types: Accepted for interface compatibility; OTX does not use this.

        Returns:
            FetchResult with normalised ioc_network objects.
        """
        t_start = time.monotonic()

        since_dt = _parse_time_range(time_range)
        since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%S")

        # OTX has a single feed, so any upstream failure is a total failure.
        # Propagate it: the caller's retry/circuit-breaker layer owns failure
        # policy, and swallowing here would blind it (issue #56).
        try:
            async with self._make_client() as client:
                iocs = await self._fetch_subscribed(client, since_iso)
        except Exception as exc:
            log_tool_call(
                "otx_fetch_iocs",
                {"time_range": time_range, "modified_since": since_iso},
                record_count=0,
                latency_ms=(time.monotonic() - t_start) * 1000,
                status="error",
                error=type(exc).__name__,
            )
            raise

        latency_ms = (time.monotonic() - t_start) * 1000

        log_tool_call(
            "otx_fetch_iocs",
            {"time_range": time_range, "modified_since": since_iso},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )

        return FetchResult(
            iocs=iocs,
            source="AlienVault OTX",
            tier=2,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=["subscribed"],
            partial_failure=[],
        )

    async def _fetch_subscribed(
        self, client: httpx.AsyncClient, since_iso: str
    ) -> list[dict[str, Any]]:
        """Fetch all pages of subscribed pulses, using the in-process cache.

        Args:
            client: Authenticated httpx.AsyncClient.
            since_iso: ISO 8601 datetime string for modified_since filter.

        Returns:
            List of normalised ioc_network dicts.
        """
        cache_key = "otx_subscribed"
        now = time.monotonic()

        if cache_key in self._cache:
            cached_iocs, expiry = self._cache[cache_key]
            if now < expiry:
                logger.debug(
                    "OTX cache hit: records=%d", len(cached_iocs)
                )
                return cached_iocs

        iocs: list[dict[str, Any]] = []
        base_url = f"{_API_BASE}/pulses/subscribed"
        first_params = {"limit": PAGE_SIZE, "page": 1, "modified_since": since_iso}
        # next_url is None on the first iteration; we use first_params then.
        next_url: str | None = None
        pages_fetched = 0

        while pages_fetched < MAX_PAGES:
            if next_url is not None:
                logger.info("OTX request: url=%s", redact_url(next_url))
                resp = await client.get(next_url)
            else:
                logger.info("OTX request: url=%s", redact_url(base_url))
                resp = await client.get(base_url, params=first_params)
            resp.raise_for_status()
            pages_fetched += 1

            data = resp.json()
            pulses = data.get("results", [])

            for pulse in pulses:
                pulse_name = pulse.get("name", "")
                for ind in pulse.get("indicators", []):
                    normalised = _normalize_indicator(ind, pulse_name=pulse_name)
                    if normalised is not None:
                        iocs.append(normalised)

            next_url = data.get("next") or None
            if next_url is None:
                break

        if pages_fetched >= MAX_PAGES and next_url:
            logger.warning(
                "OTX pagination limit reached (%d pages); some pulses may be omitted.",
                MAX_PAGES,
            )

        self._cache[cache_key] = (iocs, now + CACHE_TTL_SECONDS)
        logger.info("OTX cached: records=%d pages=%d", len(iocs), pages_fetched)
        return iocs

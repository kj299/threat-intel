"""ANY.RUN Threat Intelligence TAXII/STIX feed adapter.

Fetches malicious network indicators from ANY.RUN's TAXII 2.1 STIX feed
(https://api.any.run/v1/feeds/taxii2/api1) and normalises them to ioc_network
objects compatible with output.schema.json from kj299/threat-intel.

Authentication: HTTP header ``Authorization: <api_key>`` — the credential is
passed through verbatim, so ``ANYRUN_API_KEY`` must be the full Authorization
value ANY.RUN issues (e.g. ``API-Key <token>``). Sourced from the injected
CredentialProvider as ``credentials.get("anyrun", "api_key")``.

API characteristics (verified against the official anyrun-sdk, 2026):
  - Endpoint: ``GET /v1/feeds/taxii2/api1/collections/{collection_id}/objects/``
    ``?match[type]=indicator&match[spec_version]=2.1``
  - Typed collections (static IDs from the SDK config): ip, domain, url
  - Response: a STIX bundle/envelope ``{"objects": [ {stix indicator}, ... ]}``
  - Each indicator carries a STIX 2.1 ``pattern`` (e.g. ``[ipv4-addr:value =
    '1.2.3.4']``) which is parsed for the network IOC value.
  - Feed changes slowly relative to a report — cache TTL 3600 s.

These are ANY.RUN's sandbox-derived malicious indicators, emitted with
``action: block`` and confidence from the STIX ``confidence`` field.
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
from ..stix_patterns import extract_network_iocs
from ..vault.base import CredentialProvider
from .base import FetchResult

logger = logging.getLogger(__name__)

_API_BASE = "https://api.any.run/v1"
_TAXII_BASE = f"{_API_BASE}/feeds/taxii2/api1/collections"

# Static TAXII collection IDs (from anyrun-sdk anyrun/utils/config.py).
FEED_TYPES: dict[str, str] = {
    "ip": "55cda200-e261-5908-b910-f0e18909ef3d",
    "domain": "2e0aa90a-5526-5a43-84ad-3db6f4549a09",
    "url": "05bfa343-e79f-57ec-8677-3122ca33d352",
}

DEFAULT_FEED_TYPES = list(FEED_TYPES.keys())

CACHE_TTL_SECONDS = 3600


def _confidence(stix_confidence: Any) -> str:
    """Map a STIX 0-100 confidence to High/Medium/Low (default Medium)."""
    try:
        c = int(stix_confidence)
    except (TypeError, ValueError):
        return "Medium"
    if c >= 80:
        return "High"
    if c >= 40:
        return "Medium"
    return "Low"


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


def _normalize_stix_object(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Map one STIX indicator object to zero or more ioc_network dicts."""
    if obj.get("type") != "indicator":
        return []
    pairs = extract_network_iocs(obj.get("pattern", ""))
    if not pairs:
        return []

    confidence = _confidence(obj.get("confidence"))
    last_seen = _rfc3339(obj.get("modified") or obj.get("valid_from"))
    name = obj.get("name")
    labels = [str(x) for x in (obj.get("labels") or []) if x]

    out: list[dict[str, Any]] = []
    for ioc_type, value in pairs:
        # Validate IP literals; leave domain/url as-is (sanitizer + schema check later).
        if ioc_type in ("IPv4", "IPv6"):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
        ioc: dict[str, Any] = {
            "type": ioc_type,
            "value": value,
            "confidence": confidence,
            "source": "ANY.RUN",
            "action": "block",
            "tlp": "AMBER",
            "tags": ["anyrun", *labels],
        }
        if isinstance(name, str) and name:
            ioc["associated_threat"] = name
        if last_seen:
            ioc["last_seen"] = last_seen
        out.append(ioc)
    return out


class AnyRunAdapter:
    """Adapter for ANY.RUN (any.run) TAXII STIX threat-intelligence feeds."""

    name = "ANY.RUN"
    tier = 9

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self, api_key: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Authorization": api_key,
                "Accept": "application/taxii+json;version=2.1, application/json",
                "User-Agent": "threat-intel-mcp/0.11 (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("api.any.run"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch ANY.RUN TAXII STIX indicators across the requested collections."""
        requested = feed_types or DEFAULT_FEED_TYPES
        unknown = [t for t in requested if t not in FEED_TYPES]
        if unknown:
            raise ValueError(
                f"Unknown feed_type(s): {unknown}. Valid: {list(FEED_TYPES.keys())}"
            )

        api_key = self._credentials.get("anyrun", "api_key")  # fail fast

        t_start = time.monotonic()
        all_iocs: list[dict[str, Any]] = []
        failed: list[str] = []
        last_exc: Exception | None = None

        async with self._make_client(api_key) as client:
            for feed_type in requested:
                try:
                    all_iocs.extend(await self._fetch_collection(client, feed_type))
                except Exception as exc:
                    logger.warning(
                        "ANY.RUN feed_type=%s fetch failed: %s",
                        feed_type,
                        type(exc).__name__,
                    )
                    failed.append(feed_type)
                    last_exc = exc

        if last_exc is not None and len(failed) == len(requested):
            log_tool_call(
                "anyrun_fetch_iocs",
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
            "anyrun_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(all_iocs),
            latency_ms=latency_ms,
            status="partial" if failed else "ok",
            error=f"failed feed_types: {failed}" if failed else None,
        )

        return FetchResult(
            iocs=all_iocs,
            source="ANY.RUN",
            tier=9,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(all_iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=fetched,
            partial_failure=failed,
        )

    async def _fetch_collection(
        self, client: httpx.AsyncClient, feed_type: str
    ) -> list[dict[str, Any]]:
        """Fetch one TAXII collection's STIX objects, using the in-process cache."""
        now = time.monotonic()
        cached = self._cache.get(feed_type)
        if cached is not None:
            cached_iocs, expiry = cached
            if now < expiry:
                logger.debug(
                    "Cache hit: feed_type=%s records=%d", feed_type, len(cached_iocs)
                )
                return cached_iocs

        collection_id = FEED_TYPES[feed_type]
        url = f"{_TAXII_BASE}/{collection_id}/objects/"
        params = {"match[type]": "indicator", "match[spec_version]": "2.1"}
        logger.info(
            "ANY.RUN request: endpoint=/feeds/taxii2/api1/collections/%s/objects/",
            feed_type,
        )
        resp = await client.get(url, params=params)
        resp.raise_for_status()

        objects = resp.json().get("objects") or []
        iocs: list[dict[str, Any]] = []
        for obj in objects:
            iocs.extend(_normalize_stix_object(obj))

        self._cache[feed_type] = (iocs, now + CACHE_TTL_SECONDS)
        logger.info("ANY.RUN cached: feed_type=%s records=%d", feed_type, len(iocs))
        return iocs

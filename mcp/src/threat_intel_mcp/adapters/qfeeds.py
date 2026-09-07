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
import re
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

# Pause between pages. The first live call with a real key took page 1 fine and
# was rate-limited on page 2 (#205) -- the walk asked for 8,000 records with no
# gap at all. One second is a deliberate under-guess: Q-Feeds' published limit
# is not known to this code, and inventing a number is how #203 happened. It is
# enough to stop an instant second request, and the truncation path below makes
# a wrong guess degrade honestly instead of failing.
INTER_PAGE_DELAY_SECONDS = 1.0


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
            headers={"User-Agent": "threat-intel-mcp/0.8 (kj299/threat-intel)"},
            event_hooks=egress_event_hooks("api.qfeeds.com"),
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
        # Truncations are tracked apart from failures on purpose: a truncated
        # feed_type WAS consulted and did return records, so it belongs in
        # feed_types_fetched. Folding the two together would report a feed that
        # gave several thousand indicators as one that gave none.
        truncations: list[str] = []
        last_exc: Exception | None = None

        async with self._make_client() as client:
            tasks = {
                feed_type: asyncio.create_task(self._fetch_feed(client, feed_type))
                for feed_type in requested
            }
            for feed_type, task in tasks.items():
                try:
                    iocs, truncated = await task
                    all_iocs.extend(iocs)
                    if truncated:
                        truncations.append(truncated)
                except Exception as exc:
                    logger.warning(
                        "Q-Feeds feed_type=%s fetch failed: %s", feed_type, exc
                    )
                    failed.append(feed_type)
                    last_exc = exc

        # Every requested feed type failed: this is a total failure, not a
        # partial result. Propagate so the caller's retry/circuit-breaker layer
        # can act on it (issue #56). Partial results still return below.
        if last_exc is not None and len(failed) == len(requested):
            log_tool_call(
                "qfeeds_fetch_iocs",
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
            "qfeeds_fetch_iocs",
            {"time_range": time_range, "feed_types": requested},
            record_count=len(all_iocs),
            latency_ms=latency_ms,
            status="partial" if (failed or truncations) else "ok",
            error=(
                f"failed feed_types: {failed}" if failed else None
            ) or (truncations[0] if truncations else None),
        )

        return FetchResult(
            iocs=all_iocs,
            source="Q-Feeds",
            tier=2,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(all_iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=fetched,
            partial_failure=failed + truncations,
        )

    async def _fetch_feed(
        self, client: httpx.AsyncClient, feed_type: str
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Fetch all pages of a feed type. Returns (iocs, truncation reason).

        A truncation reason is a string when the walk stopped early with
        records already in hand, and None when it completed.

        An HTTP error on a page after the first STOPS the walk instead of
        raising. Page 1's indicators were really retrieved and really parsed;
        discarding them because page 2 was rate-limited reports nothing when
        several thousand usable records were in hand, and drops the source to
        `unverified` when `partial` is the true answer (#205).

        The first page still raises. Nothing was retrieved, so there is nothing
        honest to return, and the caller's circuit breaker should see it.

        A 429 is deliberately NOT retried here. Retrying immediately against a
        limit just hit spends more quota to learn the same thing, and
        resilience.py's retry wraps the WHOLE fetch, so it would re-request
        page 1 as well. Stopping and saying so is both cheaper and truer.
        """
        now = time.monotonic()
        if feed_type in self._cache:
            cached_iocs, expiry = self._cache[feed_type]
            if now < expiry:
                logger.debug("Cache hit: feed_type=%s records=%d", feed_type, len(cached_iocs))
                return cached_iocs, None

        iocs: list[dict[str, Any]] = []
        page = 1
        truncated: str | None = None
        # Totals across the whole paginated fetch; an empty final page is
        # normal termination, not a format break.
        seen = 0
        understood = 0

        while True:
            if page > 1:
                await asyncio.sleep(INTER_PAGE_DELAY_SECONDS)

            url = _API_BASE
            params = {"feed_type": feed_type, "limit": PAGE_SIZE, "page": page}
            logger.info(
                "Q-Feeds request: url=%s feed_type=%s page=%d",
                redact_url(url),
                feed_type,
                page,
            )
            resp = await client.get(url, params=params)
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError:
                if page == 1:
                    raise
                truncated = (
                    f"{feed_type}: stopped at page {page} "
                    f"(HTTP {resp.status_code}); {len(iocs)} records kept"
                )
                logger.warning("Q-Feeds truncated: %s", truncated)
                break

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
            # A plain-text feed has no envelope to check, and every parseable
            # line becomes an IOC — so "understood" is simply "retained".
            seen += len(lines)
            understood += len(page_iocs)

            if len(lines) < PAGE_SIZE:
                break
            page += 1

        guard_parsed(
            "Q-Feeds",
            envelope_found=True,  # line feed: no envelope exists to be missing
            envelope_desc="indicator lines",
            items_seen=seen,
            items_understood=understood,
        )

        # A truncated walk is not cached: caching it would serve an incomplete
        # blocklist as a complete one for the whole TTL, and the next caller
        # would have no way to tell.
        if truncated is None:
            self._cache[feed_type] = (iocs, now + CACHE_TTL_SECONDS)
            logger.info("Q-Feeds cached: feed_type=%s records=%d", feed_type, len(iocs))
        return iocs, truncated


# A hostname: dot-separated labels, alphabetic TLD.
#
# Deliberately permissive, because the job here is to reject prose and markup —
# not to be an authority on valid domains. Underscores are allowed even though
# RFC 1123 disallows them in host names: they appear in real feed data, and the
# ioc_network schema only enforces ``minLength: 1`` on a value, so anything this
# rejects is dropped for good with no downstream check to catch a mistake.
# Punycode ("xn--") and long TLDs both pass.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


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
        else:
            # Real address parsing — rejects out-of-range octets (999.1.1.1)
            # and colon-containing junk a regex would misclassify as IPv6.
            try:
                addr = ipaddress.ip_address(line)
            except ValueError:
                logger.debug("Unrecognised IP-feed line, skipping: %r", line)
                return None
            ioc_type = "IPv4" if addr.version == 4 else "IPv6"

    elif feed_type == "malware_domains":
        if line.startswith(("http://", "https://")):
            ioc_type = "URL"
        elif _HOSTNAME_RE.match(line):
            ioc_type = "Domain"
        else:
            # Previously any non-URL string became a Domain, so an HTML error
            # page parsed into "domains" and the empty-parse guard could never
            # fire on this feed type (#106). Reject what cannot be a hostname;
            # the schema would drop it downstream anyway, silently.
            logger.debug("Unrecognised domain-feed line, skipping: %r", line)
            return None
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

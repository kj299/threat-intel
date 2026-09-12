"""OpenPhish Community phishing-URL feed adapter.

Fetches the free OpenPhish Community feed (https://openphish.com/feed.txt) and
normalises it to ioc_network objects compatible with output.schema.json from
kj299/threat-intel.

**No credential required.** This is one of only two keyless IOC feeds in this
server (the other is ThreatFox), which is the whole reason it is here: a feed
that needs no key is ``consulted`` on every run forever, where a credentialed
one degrades to ``unverified`` the moment a subscription lapses.

Feed contract
-------------
Verified against the vendor's **own** mirror of the feed, which OpenPhish
publishes at https://github.com/openphish/public_feed and which this code read
directly (2026-09-12):

  - ``GET https://openphish.com/feed.txt``
  - No auth, no parameters.
  - Response: ``text/plain``, **one absolute URL per line**, LF-terminated,
    trailing newline present. No header, no comment lines, no envelope.
  - 300 entries -- the Community feed is capped at the most recent 300, so a
    full body is ~17 KB. Nothing is paginated.

.. note::

   Those bytes came from the GitHub mirror because ``openphish.com`` is
   unreachable from the development sandbox. The mirror is published by
   OpenPhish under their own GitHub organisation, so it is the vendor's copy
   rather than a third party's -- but the canonical URL is what this adapter
   requests, and only a recorded cassette proves the two agree.

Terms of use
------------
The Community feed is **non-commercial use only**
(https://openphish.com/terms.html), stated in the vendor's own feed README.
That restriction is why indicators are emitted ``TLP: GREEN`` rather than
``WHITE``: WHITE asserts unrestricted redistribution, which this feed's licence
does not grant. A report forwarding these indicators outside the recipient
community would be over-claiming what we are permitted to share.

Refresh cadence
---------------
**Every 12 hours**, per the vendor's feed README -- which is what the cache TTL
follows. Issue #169 recorded "6-hourly" from a third-party summary; the vendor
says 12. A small illustration of why that issue flagged its own sign-up table
as search-sourced and unverified.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..audit import log_tool_call, redact_url
from ..netpolicy import egress_event_hooks
from .base import FetchResult, guard_parsed

logger = logging.getLogger(__name__)

_FEED_URL = "https://openphish.com/feed.txt"

# The vendor's README says the Community feed refreshes every 12 hours.
CACHE_TTL_SECONDS = 43200
_CACHE_KEY = "openphish_community"

FEED_TYPES = ["phishing_urls"]


def _normalize_line(line: str) -> dict[str, Any] | None:
    """Map one feed line to an ioc_network dict, or None if it is not a URL.

    Returning None is what makes the empty-parse guard work on this feed. An
    HTML error page served with HTTP 200 -- the failure mode that produced #100
    on ThreatFox -- has lines, and none of them survive this function, so
    ``guard_parsed`` raises instead of reporting a confident zero.

    The check is deliberately "is this line a URL", not "does this line contain
    one": ``<a href="https://example.test/">`` contains a URL and is markup.
    """
    if not line or line.startswith("#"):
        return None

    try:
        parts = urlsplit(line)
    except ValueError:  # pragma: no cover - only malformed IPv6 literals reach this
        logger.debug("Unparseable OpenPhish line, skipping: %r", line)
        return None

    if parts.scheme not in ("http", "https") or not parts.netloc:
        logger.debug("Non-URL OpenPhish line, skipping: %r", line)
        return None

    return {
        "type": "URL",
        "value": line,
        # OpenPhish publishes the Community feed as confirmed phishing rather
        # than as candidates, so the feed's own position is high confidence.
        # There is no per-entry score to map, so nothing finer would be honest.
        "confidence": "High",
        "source": "OpenPhish",
        "action": "block",
        # GREEN, not WHITE -- see "Terms of use" above.
        "tlp": "GREEN",
        "tags": ["openphish", "phishing"],
        "associated_threat": "phishing",
    }


class OpenPhishAdapter:
    """Adapter for the free OpenPhish Community phishing feed."""

    name = "OpenPhish"
    tier = 6

    def __init__(self) -> None:
        # No CredentialProvider parameter at all: this adapter takes no
        # credential, and accepting one would imply a key might be read.
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={"User-Agent": "threat-intel-mcp (kj299/threat-intel)"},
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("openphish.com"),
            follow_redirects=True,
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch the current OpenPhish Community feed.

        Note: the feed is the *current* 300 most recent phishing URLs, not a
        historical window. ``time_range`` is accepted for interface
        compatibility and recorded in the result for the Coverage Ledger, but
        there is no parameter to forward it to.
        """
        if feed_types:
            unknown = [t for t in feed_types if t not in FEED_TYPES]
            if unknown:
                raise ValueError(
                    f"Unknown feed_type(s): {unknown}. Valid: {FEED_TYPES} "
                    "(OpenPhish publishes a single undifferentiated feed)"
                )

        t_start = time.monotonic()

        now = time.monotonic()
        cached = self._cache.get(_CACHE_KEY)
        if cached is not None:
            cached_iocs, expiry = cached
            if now < expiry:
                logger.debug("Cache hit: %s records=%d", _CACHE_KEY, len(cached_iocs))
                latency_ms = (time.monotonic() - t_start) * 1000
                log_tool_call(
                    "openphish_fetch_iocs",
                    {"time_range": time_range, "feed_types": feed_types},
                    record_count=len(cached_iocs),
                    latency_ms=latency_ms,
                    status="ok",
                )
                return FetchResult(
                    iocs=cached_iocs,
                    source="OpenPhish",
                    tier=self.tier,
                    retrieved_at=datetime.now(timezone.utc).isoformat(),
                    record_count=len(cached_iocs),
                    latency_ms=round(latency_ms, 1),
                    feed_types_fetched=FEED_TYPES,
                )

        async with self._make_client() as client:
            logger.info("OpenPhish request: url=%s", redact_url(_FEED_URL))
            resp = await client.get(_FEED_URL)
            resp.raise_for_status()
            body = resp.text

        # Comments are excluded before counting, not inside _normalize_line.
        # A body of nothing but comments is an EMPTY result set, not an
        # unreadable one -- counting them as seen-but-not-understood makes
        # guard_parsed raise on a feed that simply had nothing to publish.
        lines = [
            stripped
            for ln in body.splitlines()
            if (stripped := ln.strip()) and not stripped.startswith("#")
        ]
        iocs = [
            normalized
            for line in lines
            if (normalized := _normalize_line(line)) is not None
        ]

        guard_parsed(
            "OpenPhish",
            # A line feed has no envelope that could go missing.
            envelope_found=True,
            envelope_desc="phishing URL lines",
            items_seen=len(lines),
            items_understood=len(iocs),
        )

        self._cache[_CACHE_KEY] = (iocs, time.monotonic() + CACHE_TTL_SECONDS)
        logger.info("OpenPhish cached: %s records=%d", _CACHE_KEY, len(iocs))

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "openphish_fetch_iocs",
            {"time_range": time_range, "feed_types": feed_types},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )

        return FetchResult(
            iocs=iocs,
            source="OpenPhish",
            tier=self.tier,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=FEED_TYPES,
        )

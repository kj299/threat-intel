"""Pulsedive community threat-intelligence feed adapter.

Fetches high-risk indicators from Pulsedive's Explore endpoint and normalises
them to ioc_network objects compatible with output.schema.json from
kj299/threat-intel.

Credential
----------
``credentials.get("pulsedive", "api_key")`` -> ``PULSEDIVE_API_KEY``, sent as
the ``key`` query parameter. **Required** -- Pulsedive's API has no anonymous
access.

The key rides in the URL rather than a header, which is Pulsedive's design, not
a choice available here. ``audit.redact_url`` exists for exactly this case and
is used on every logged URL; see ``shodan.py``, which has the same exposure.

The quota is the design constraint
----------------------------------
A free Pulsedive account allows **50 requests/day and 500/month** -- an order
of magnitude tighter than VirusTotal's 500/day, and the tightest budget of any
source in this server. Two consequences, both load-bearing:

1. **This is a feed, not an enrichment.** Per-indicator lookup would exhaust a
   day's budget on fifty indicators. ``explore.php`` returns many indicators in
   a single request, so one request buys a whole feed.
2. **One request per fetch, enforced structurally.** ``MAX_REQUESTS_PER_FETCH``
   caps the walk, and there is no pagination loop that could quietly spend the
   month. A weekly run therefore costs 1 of 50; even an hourly one would fit.
   Nothing here should be "improved" into following ``page_next`` without
   re-reading this paragraph first.

Feed contract
-------------
Assembled from Pulsedive's published API documentation and its community client
libraries. **Not confirmed against a real response** -- ``pulsedive.com`` is
unreachable from the development sandbox.

  - ``GET https://pulsedive.com/api/explore.php``
  - Query params: ``q`` (Explore query), ``limit``, ``pretty``, ``key``
  - Response: ``{"results": [...], "page_current": N, "page_next": N}``
  - Each result: ``iid``, ``indicator``, ``type``, ``risk``, ``stamp_added``,
    ``stamp_seen``
  - ``risk``: ``unknown`` | ``none`` | ``low`` | ``medium`` | ``high`` |
    ``critical`` | ``retired``
  - ``type``: ``ip`` | ``ipv6`` | ``domain`` | ``url``
  - Errors are reported **in-band** as an ``error`` key, so a non-empty
    ``error`` is raised rather than parsed past.

.. warning::

   **The first real call returned HTTP 429, on request one of one**
   (recording attempt, 2026-09-13). The configured key was present and the URL
   was well-formed, so this is not a malformed request and not self-inflicted
   rate-limiting -- this adapter makes a single request per fetch. It means one
   of:

   - the account's quota is already spent (50/day, 500/month), or
   - the free plan does not include the **Explore** endpoint at all, and
     Pulsedive signals that with 429 rather than 403.

   Only the account holder can tell those apart, from the usage and plan pages
   at https://pulsedive.com/. **Until that is settled this adapter is
   unverified against a real response**, and if Explore turns out to be
   paid-only it needs re-targeting to ``info.php`` -- per-indicator lookup,
   which would make it an *enrichment* of at most 50 indicators a day rather
   than a feed.

   ``_QUERY`` remains unverified for the same reason: Pulsedive's Explore
   syntax is its own small language, and no response has yet been seen to check
   the spelling against. A malformed query would surface as an in-band
   ``error`` or as zero parseable results -- both of which raise here rather
   than reporting a confident empty feed.
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

_API_BASE = "https://pulsedive.com/api"
_EXPLORE_URL = f"{_API_BASE}/explore.php"

# The whole point of this adapter: one request buys a feed, and the budget is
# 50/day. Not a tunable -- see the module docstring.
MAX_REQUESTS_PER_FETCH = 1

# Pulsedive caps a page; 100 is a page of indicators for one request.
DEFAULT_LIMIT = 100

# Indicators worth spending the single request on. See the module warning: this
# is the part most likely to be wrong on first contact.
_QUERY = "risk=high"

CACHE_TTL_SECONDS = 3600
_CACHE_KEY = "pulsedive_explore"

FEED_TYPES = ["high_risk"]

# Pulsedive's indicator types mapped to ioc_network types. An unmapped type is
# skipped, which is what lets guard_parsed distinguish "nothing matched our
# filter" from "the type vocabulary changed upstream".
_TYPE_OF = {
    "ip": "IPv4",
    "ipv6": "IPv6",
    "domain": "Domain",
    "url": "URL",
}

# Pulsedive's own risk scale, mapped to this schema's three confidence levels.
_CONFIDENCE_OF = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Low",
    "unknown": "Low",
    # `retired` means Pulsedive no longer considers the indicator active. Kept
    # -- it is real history -- but never as something to block, for the same
    # reason an offline Feodo C2 is not blockable (#212).
    "retired": "Low",
}


def _to_rfc3339(raw: Any) -> str | None:
    """Convert Pulsedive's ``"YYYY-MM-DD HH:MM:SS"`` stamps to RFC 3339.

    Returns None rather than the original string: an unconvertible timestamp
    passed through fails runtime date-time validation and takes the **whole
    record** with it, which is how #204 silently dropped every OTX indicator.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().removesuffix(" UTC").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    logger.debug("Unreadable Pulsedive timestamp, omitting: %r", raw)
    return None


def _normalize_entry(entry: Any) -> dict[str, Any] | None:
    """Map one Explore result to an ioc_network dict, or None if unreadable."""
    if not isinstance(entry, dict):
        return None

    value = entry.get("indicator")
    if not isinstance(value, str) or not value.strip():
        return None

    raw_type = entry.get("type")
    ioc_type = _TYPE_OF.get(raw_type.strip().lower()) if isinstance(raw_type, str) else None
    if ioc_type is None:
        logger.debug("Unmapped Pulsedive indicator type, skipping: %r", raw_type)
        return None

    raw_risk = entry.get("risk")
    risk = raw_risk.strip().lower() if isinstance(raw_risk, str) else "unknown"
    confidence = _CONFIDENCE_OF.get(risk, "Low")
    # Only a live high/critical indicator earns `block`. Pulsedive's own scale
    # is the authority on that, and over-claiming it would be the Feodo mistake.
    actionable = risk in ("high", "critical")

    ioc: dict[str, Any] = {
        "type": ioc_type,
        "value": value.strip(),
        "confidence": confidence,
        "source": "Pulsedive",
        "action": "block" if actionable else "alert",
        "tlp": "WHITE",
        "tags": ["pulsedive", f"risk:{risk}"],
        "associated_threat": "malicious_infrastructure",
    }

    first_seen = _to_rfc3339(entry.get("stamp_added"))
    if first_seen:
        ioc["first_seen"] = first_seen
    last_seen = _to_rfc3339(entry.get("stamp_seen"))
    if last_seen:
        ioc["last_seen"] = last_seen

    return ioc


class PulsediveAdapter:
    """Adapter for the Pulsedive community Explore feed."""

    name = "Pulsedive"
    tier = 3
    requires_credential = True

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("pulsedive.com"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch one page of high-risk Pulsedive indicators.

        ``time_range`` is recorded for the Coverage Ledger but not forwarded:
        Explore returns current database state, and narrowing it by date would
        cost additional requests against a 50/day budget.
        """
        if feed_types:
            unknown = [t for t in feed_types if t not in FEED_TYPES]
            if unknown:
                raise ValueError(
                    f"Unknown feed_type(s): {unknown}. Valid: {FEED_TYPES}"
                )

        t_start = time.monotonic()
        # Fetch the key before opening the client so an unconfigured feed fails
        # fast as a credential error rather than mid-request.
        api_key = self._credentials.get("pulsedive", "api_key")

        now = time.monotonic()
        cached = self._cache.get(_CACHE_KEY)
        if cached is not None and now < cached[1]:
            iocs = cached[0]
        else:
            async with self._make_client() as client:
                logger.info(
                    "Pulsedive request: url=%s query=%r limit=%d",
                    redact_url(_EXPLORE_URL),
                    _QUERY,
                    DEFAULT_LIMIT,
                )
                resp = await client.get(
                    _EXPLORE_URL,
                    params={
                        "q": _QUERY,
                        "limit": DEFAULT_LIMIT,
                        "pretty": 1,
                        "key": api_key,
                    },
                )
                if resp.status_code == 429:
                    # Named, not left as a generic HTTPStatusError. On a 50/day
                    # budget the difference between "quota spent" and
                    # "Pulsedive is down" decides whether an operator waits or
                    # investigates, and the weekly live check should say which.
                    raise RuntimeError(
                        "Pulsedive returned HTTP 429 on the first request of "
                        "this fetch. This adapter makes exactly one request per "
                        "fetch. Either the account's quota is already spent "
                        "(50/day, 500/month on the free tier) or the plan does "
                        "not include the Explore endpoint. "
                        "Check API usage and plan at https://pulsedive.com/. "
                        "Retrying will not help until one of those changes."
                    )
                resp.raise_for_status()
                body = resp.json()

            iocs = _parse_body(body)
            self._cache[_CACHE_KEY] = (iocs, time.monotonic() + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "pulsedive_fetch_iocs",
            {"time_range": time_range, "feed_types": feed_types},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )
        return FetchResult(
            iocs=iocs,
            source="Pulsedive",
            tier=self.tier,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=FEED_TYPES,
            # Stated, not implied: this is one page by design, never the whole
            # result set. A reader must not take it for exhaustive coverage.
            partial_failure=[
                f"one page only ({DEFAULT_LIMIT} max) — free tier is 50 requests/day"
            ],
        )


def _parse_body(body: Any) -> list[dict[str, Any]]:
    """Parse the Explore envelope into ioc_network dicts."""
    if not isinstance(body, dict):
        raise RuntimeError("Pulsedive response was not a JSON object")

    # Pulsedive reports failures in-band with HTTP 200. Parsed past, a bad query
    # or an exhausted quota becomes a confident empty feed -- an outage
    # indistinguishable from a quiet week.
    error = body.get("error")
    if isinstance(error, str) and error.strip():
        raise RuntimeError(f"Pulsedive error: {error.strip()}")

    entries = body.get("results") or []
    if not isinstance(entries, list):
        raise RuntimeError("Pulsedive 'results' was not an array")

    iocs = [
        normalized
        for entry in entries
        if (normalized := _normalize_entry(entry)) is not None
    ]
    guard_parsed(
        "Pulsedive",
        # Presence check, never truthiness: {"results": []} is a real empty page.
        envelope_found="results" in body,
        envelope_desc="a 'results' array",
        items_seen=len(entries),
        items_understood=len(iocs),
    )
    return iocs

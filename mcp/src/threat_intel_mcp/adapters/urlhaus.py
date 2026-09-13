"""URLhaus (abuse.ch) malicious-URL feed adapter.

Fetches recently submitted malware-distribution URLs and normalises them to
ioc_network objects compatible with output.schema.json from kj299/threat-intel.

Credential
----------
``credentials.get("abusech", "auth_key")`` -> ``ABUSECH_AUTH_KEY``. **One key
covers every abuse.ch service** -- URLhaus, MalwareBazaar, Feodo Tracker and
ThreatFox all authenticate with the same ``Auth-Key`` header, which is why this
adapter, ``feodo.py`` and ``threatfox.py`` read the same credential rather than
three near-identical ones.

Unlike ThreatFox's, this credential is **required**. ThreatFox reaches a
grandfathered CSV export that still answers unauthenticated; the URLhaus v1 API
has required the header since abuse.ch made authentication mandatory on
2025-06-30, so an unconfigured key here is a config error, not a soft fallback.

Feed contract
-------------
Taken from URLhaus's published API reference. **Not yet confirmed against a real
response** -- every abuse.ch host is unreachable from the development sandbox,
so record a cassette before trusting the field mapping.

  - ``GET https://urlhaus-api.abuse.ch/v1/urls/recent/``
  - Auth: ``Auth-Key: <auth_key>``
  - Optional ``limit`` (the feed is a rolling recent window, not a date range)
  - Response: ``{"query_status": "ok", "urls": [...]}``
  - Each entry: ``id``, ``urlhaus_reference``, ``url``, ``url_status``
    (``online`` / ``offline`` / ``unknown``), ``host``, ``date_added``
    (``"YYYY-MM-DD HH:MM:SS UTC"``), ``threat``
    (e.g. ``malware_download``), ``tags``, ``reporter``
  - ``query_status`` carries the error when something is wrong, so a non-``ok``
    value is surfaced rather than parsed past.

``date_added`` is **not** RFC 3339 -- it is ``"2019-01-19 01:33:26 UTC"``, a
space separator and a trailing zone *name*. The pipeline validates
``first_seen`` as ``date-time`` at runtime, so passing it through unconverted
is how OTX silently lost all 960 of its records a run (#204). ``_to_rfc3339``
below does the conversion and drops anything it cannot read.
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

_API_BASE = "https://urlhaus-api.abuse.ch/v1"
_RECENT_URL = f"{_API_BASE}/urls/recent/"

# URLhaus publishes continuously; a short TTL keeps one report run cheap.
CACHE_TTL_SECONDS = 900
_CACHE_KEY = "urlhaus_recent"

FEED_TYPES = ["recent_urls"]

# The API's own cap on the recent feed.
DEFAULT_LIMIT = 1000

# url_status values that mean the URL is still serving. An offline URL is still
# a real indicator -- it was malicious -- so it is kept, but at lower
# confidence and as `alert` rather than `block`.
_ONLINE = "online"


def _to_rfc3339(raw: Any) -> str | None:
    """Convert URLhaus's ``"YYYY-MM-DD HH:MM:SS UTC"`` to RFC 3339, or None.

    Returning None rather than the original string is deliberate: an
    unconvertible timestamp passed through would fail runtime date-time
    validation and take the **whole record** with it, which is exactly how
    #204 dropped every OTX indicator while every mock test passed.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().removesuffix(" UTC").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    logger.debug("Unreadable URLhaus timestamp, omitting: %r", raw)
    return None


def _normalize_entry(entry: Any) -> dict[str, Any] | None:
    """Map one URLhaus entry to an ioc_network dict, or None if unreadable."""
    if not isinstance(entry, dict):
        return None
    url = entry.get("url")
    if not isinstance(url, str) or not url.strip():
        return None

    status = entry.get("url_status")
    online = isinstance(status, str) and status.strip().lower() == _ONLINE

    ioc: dict[str, Any] = {
        "type": "URL",
        "value": url.strip(),
        # URLhaus entries are reported malware-distribution URLs, not scored
        # candidates. A live one is actionable now; a dead one is history, and
        # saying otherwise would over-claim a confidence the feed does not give.
        "confidence": "High" if online else "Medium",
        "source": "URLhaus",
        "action": "block" if online else "alert",
        "tlp": "WHITE",
        "tags": ["urlhaus", "abuse.ch"],
    }

    threat = entry.get("threat")
    if isinstance(threat, str) and threat.strip():
        ioc["associated_threat"] = threat.strip()

    tags = entry.get("tags")
    if isinstance(tags, list):
        extra = [t.strip() for t in tags if isinstance(t, str) and t.strip()]
        if extra:
            ioc["tags"] = ioc["tags"] + extra

    first_seen = _to_rfc3339(entry.get("date_added"))
    if first_seen:
        ioc["first_seen"] = first_seen

    return ioc


class URLhausAdapter:
    """Adapter for the URLhaus (abuse.ch) recent malicious-URL feed."""

    name = "URLhaus"
    tier = 9
    requires_credential = True

    def __init__(self, credentials: CredentialProvider) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        auth_key = self._credentials.get("abusech", "auth_key")
        return httpx.AsyncClient(
            headers={
                "Auth-Key": auth_key,
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp (kj299/threat-intel)",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("urlhaus-api.abuse.ch"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch the current URLhaus recent-URL window.

        ``time_range`` is accepted for interface compatibility and recorded for
        the Coverage Ledger; URLhaus's recent feed is a fixed rolling window
        with no date parameter to forward it to.
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
        self._credentials.get("abusech", "auth_key")

        now = time.monotonic()
        cached = self._cache.get(_CACHE_KEY)
        if cached is not None and now < cached[1]:
            iocs = cached[0]
        else:
            async with self._make_client() as client:
                logger.info("URLhaus request: url=%s", redact_url(_RECENT_URL))
                resp = await client.get(_RECENT_URL, params={"limit": DEFAULT_LIMIT})
                resp.raise_for_status()
                body = resp.json()

            iocs = _parse_body(body)
            self._cache[_CACHE_KEY] = (iocs, time.monotonic() + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "urlhaus_fetch_iocs",
            {"time_range": time_range, "feed_types": feed_types},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )
        return FetchResult(
            iocs=iocs,
            source="URLhaus",
            tier=self.tier,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=FEED_TYPES,
        )


def _parse_body(body: Any) -> list[dict[str, Any]]:
    """Parse the URLhaus envelope into ioc_network dicts."""
    if not isinstance(body, dict):
        raise RuntimeError("URLhaus response was not a JSON object")

    status = body.get("query_status")
    if isinstance(status, str) and status.strip().lower() not in ("ok", "no_results"):
        # The API reports its own errors in-band with HTTP 200, so a non-ok
        # status parsed past would become a confident empty result.
        raise RuntimeError(f"URLhaus query_status={status!r}")

    entries = body.get("urls") or []
    if not isinstance(entries, list):
        raise RuntimeError("URLhaus 'urls' was not an array")

    iocs = [
        normalized
        for entry in entries
        if (normalized := _normalize_entry(entry)) is not None
    ]
    guard_parsed(
        "URLhaus",
        # Presence check, never truthiness: {"urls": []} is a real empty window.
        envelope_found="urls" in body or status == "no_results",
        envelope_desc="a 'urls' array",
        items_seen=len(entries),
        items_understood=len(iocs),
    )
    return iocs

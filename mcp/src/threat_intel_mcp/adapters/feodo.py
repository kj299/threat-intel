"""Feodo Tracker (abuse.ch) botnet C2 IP blocklist adapter.

Fetches the current botnet command-and-control IP blocklist and normalises it
to ioc_network objects compatible with output.schema.json from
kj299/threat-intel.

This is the highest-confidence IOC class abuse.ch publishes: every entry is a
*confirmed* C2 server for a named malware family (Emotet, QakBot, Dridex,
TrickBot and friends), not a heuristic detection.

Credential
----------
``credentials.get("abusech", "auth_key")`` -> ``ABUSECH_AUTH_KEY``, the same key
every abuse.ch service uses. The download path may still answer without it, so
the key is **optional** here for the same reason it is on ThreatFox -- sending
it when present, working without it while that route still answers.

Feed contract
-------------
  - ``GET https://feodotracker.abuse.ch/downloads/ipblocklist.json``
  - Auth: ``Auth-Key: <auth_key>`` when configured
  - Response: a **top-level JSON array** -- no envelope object.

.. warning::

   **The per-entry field names are the unverified part of this adapter.** Every
   abuse.ch host is unreachable from the development sandbox, so the names
   below come from abuse.ch's published blocklist documentation rather than
   from a response anyone has seen. The CSV flavour of the same list uses
   ``dst_ip`` / ``dst_port`` / ``first_seen_utc``, so it is entirely possible
   the JSON differs from what is mapped here.

   That is why ``_ip_of`` accepts the documented JSON name **and** the CSV
   spelling: this is a case where one of two published names is right and
   guessing wrong would silently zero the feed. It is not open-ended
   permissiveness -- the pair is closed, named, and asserted in a test, and
   ``guard_parsed`` still raises if neither appears.

   **Record a cassette before trusting the rest of the mapping.**
"""

from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call, redact_url
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialNotFoundError
from .base import FetchResult, guard_parsed

logger = logging.getLogger(__name__)

_FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

# abuse.ch refreshes the blocklist every 5 minutes; 15 is cheap and current.
CACHE_TTL_SECONDS = 900
_CACHE_KEY = "feodo_ipblocklist"

FEED_TYPES = ["botnet_c2"]

# The documented JSON name first, then the CSV spelling of the same field.
# Closed pair, not a wildcard -- see the module warning.
_IP_KEYS = ("ip_address", "dst_ip")
_PORT_KEYS = ("port", "dst_port")
_FIRST_SEEN_KEYS = ("first_seen", "first_seen_utc")


def _first_present(entry: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in entry:
            return entry[key]
    return None


def _to_rfc3339(raw: Any) -> str | None:
    """abuse.ch timestamps are ``"YYYY-MM-DD HH:MM:SS"``, UTC but unmarked.

    Anchored to UTC explicitly. A naive value passed through fails runtime
    date-time validation and takes the whole record with it -- #204.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().removesuffix(" UTC").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    logger.debug("Unreadable Feodo timestamp, omitting: %r", raw)
    return None


def _normalize_entry(entry: Any) -> dict[str, Any] | None:
    """Map one blocklist entry to an ioc_network dict, or None if unreadable."""
    if not isinstance(entry, dict):
        return None

    raw_ip = _first_present(entry, _IP_KEYS)
    if not isinstance(raw_ip, str) or not raw_ip.strip():
        return None
    try:
        # Parse, never regex-match: rejects 999.1.1.1 and colon-bearing junk.
        addr = ipaddress.ip_address(raw_ip.strip())
    except ValueError:
        logger.debug("Unparseable Feodo IP, skipping: %r", raw_ip)
        return None

    malware = entry.get("malware")
    malware = malware.strip() if isinstance(malware, str) and malware.strip() else None

    ioc: dict[str, Any] = {
        "type": "IPv4" if addr.version == 4 else "IPv6",
        "value": str(addr),
        # A tracked C2 is confirmed infrastructure for a named family, which is
        # as strong as this repository's feeds get.
        "confidence": "High",
        "source": "Feodo Tracker",
        "action": "block",
        "tlp": "WHITE",
        "tags": ["feodo", "abuse.ch", "botnet_c2"]
        + ([malware.lower()] if malware else []),
        "associated_threat": malware or "botnet_c2",
    }

    port = _first_present(entry, _PORT_KEYS)
    if isinstance(port, int) and 0 < port < 65536:
        ioc["port"] = port

    first_seen = _to_rfc3339(_first_present(entry, _FIRST_SEEN_KEYS))
    if first_seen:
        ioc["first_seen"] = first_seen

    return ioc


class FeodoTrackerAdapter:
    """Adapter for the Feodo Tracker (abuse.ch) botnet C2 IP blocklist."""

    name = "Feodo Tracker"
    tier = 9
    requires_credential = False

    def __init__(self, credentials: Any = None) -> None:
        self._credentials = credentials
        self._cache: dict[str, tuple[list[dict[str, Any]], float]] = {}

    def _auth_header(self) -> dict[str, str]:
        """Send the shared abuse.ch key when one exists; work without it.

        See ``threatfox.py`` for why this is optional: the download paths are a
        grandfathered route, and an absent key must not break a feed that
        answers today. A provider outage still propagates.
        """
        if self._credentials is None:
            return {}
        try:
            key = self._credentials.get("abusech", "auth_key")
        except CredentialNotFoundError:
            return {}
        return {"Auth-Key": key} if key else {}

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={
                "Accept": "application/json",
                "User-Agent": "threat-intel-mcp (kj299/threat-intel)",
                **self._auth_header(),
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("feodotracker.abuse.ch"),
        )

    async def fetch(
        self,
        *,
        time_range: str = "7d",
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch the current Feodo Tracker C2 blocklist.

        The blocklist is *current state*, not a historical window;
        ``time_range`` is recorded for the Coverage Ledger only.
        """
        if feed_types:
            unknown = [t for t in feed_types if t not in FEED_TYPES]
            if unknown:
                raise ValueError(
                    f"Unknown feed_type(s): {unknown}. Valid: {FEED_TYPES}"
                )

        t_start = time.monotonic()
        now = time.monotonic()
        cached = self._cache.get(_CACHE_KEY)
        if cached is not None and now < cached[1]:
            iocs = cached[0]
        else:
            async with self._make_client() as client:
                logger.info("Feodo request: url=%s", redact_url(_FEED_URL))
                resp = await client.get(_FEED_URL)
                resp.raise_for_status()
                body = resp.json()

            iocs = _parse_body(body)
            self._cache[_CACHE_KEY] = (iocs, time.monotonic() + CACHE_TTL_SECONDS)

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "feodo_fetch_iocs",
            {"time_range": time_range, "feed_types": feed_types},
            record_count=len(iocs),
            latency_ms=latency_ms,
            status="ok",
        )
        return FetchResult(
            iocs=iocs,
            source="Feodo Tracker",
            tier=self.tier,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(iocs),
            latency_ms=round(latency_ms, 1),
            feed_types_fetched=FEED_TYPES,
        )


def _parse_body(body: Any) -> list[dict[str, Any]]:
    """Parse the blocklist array into ioc_network dicts."""
    if not isinstance(body, list):
        raise RuntimeError(
            "Feodo blocklist was not a JSON array -- the download format has "
            f"probably changed (got {type(body).__name__})"
        )

    iocs = [
        normalized
        for entry in body
        if (normalized := _normalize_entry(entry)) is not None
    ]
    guard_parsed(
        "Feodo Tracker",
        # A bare array is the envelope; reaching here means we found it.
        envelope_found=True,
        envelope_desc="a blocklist array",
        items_seen=len(body),
        items_understood=len(iocs),
    )
    return iocs

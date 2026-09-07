"""VirusTotal per-indicator enrichment adapter.

Looks up indicators this repository already holds and returns VirusTotal's
verdict on each. It is **not** a feed: it does not discover indicators, it
scores ones you bring.

Why this is not a feed adapter
------------------------------
It used to be. It called ``GET /api/v3/feeds/{feed_type}?cursor=initial`` and
parsed a newline-delimited JSON stream with a cursor envelope. None of that
exists: the first live call ever made returned **404**, because
``/api/v3/feeds/malicious_domains`` is not a VirusTotal path — it was assembled
from this repository's own ``FEED_TYPES`` keys (#203).

VirusTotal's real feed endpoints are ``/api/v3/feeds/domains/hourly/{YYYYMMDDhh}``
and return a 302 to a ``.tar.bz2`` of 60 minutely batches, gated behind a
separate **feeds licence**. This account holds a public API key — 4 lookups/min,
500/day, 15.5K/month — so no rewrite of the bulk path could work. The endpoint,
the response model and the pagination model were all wrong at once, and the
mock tests passed because the fixture was authored from the same belief as the
parser (#100's failure mode, in a different adapter).

What replaces it is the thing the key *can* do: per-indicator lookup.

Feed contract
-------------
Verified against VirusTotal's published object reference for the IP address
object; the domain object is the same envelope with different attributes.

  - ``GET /api/v3/ip_addresses/{ip}``
  - ``GET /api/v3/domains/{domain}``
  - Auth: ``x-apikey: <api_key>``
  - Response: ``{"data": {"id", "type", "attributes": {...}}}``
  - ``attributes.last_analysis_stats``: ``{harmless, malicious, suspicious,
    timeout, undetected}`` — all ints
  - ``attributes.reputation``: int (community score, may be negative)
  - ``attributes.total_votes``: ``{harmless, malicious}``
  - ``attributes.last_analysis_date``: Unix timestamp
  - IP objects additionally carry ``as_owner``, ``asn``, ``country``,
    ``continent``

.. warning::

   The **response shape above has not been observed by this code.** It comes
   from VirusTotal's object reference, not from a response. That is a better
   footing than the bulk adapter had — the endpoints themselves are documented
   and the account can reach them — but it is not verification.

   ``guard_parsed`` makes a wrong guess raise rather than return a confident
   empty result. **Record a cassette before trusting the field mapping**:
   ``record-cassettes`` with ``feeds: virustotal``, which enriches a small set
   of stable public indicators.

Quota discipline
----------------
4 lookups/min is the binding constraint, so requests are serialised behind a
semaphore with a 15-second gap — unchanged from the previous adapter, which had
this part right. A caller asking for 20 indicators therefore takes ~5 minutes.
``MAX_INDICATORS_PER_CALL`` caps a single call so one request cannot silently
consume a day's 500-lookup budget; over-long input is **rejected**, not
truncated, because quietly scoring the first N of a list the caller believes
was fully checked is the kind of silent partial this repository treats as a
defect.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..audit import log_tool_call
from ..netpolicy import egress_event_hooks
from ..vault.base import CredentialProvider
from .base import guard_parsed

logger = logging.getLogger(__name__)

_API_BASE = "https://www.virustotal.com/api/v3"

# Indicator kinds this adapter can look up, mapped to their URL segment.
INDICATOR_TYPES: dict[str, str] = {
    "ip": "ip_addresses",
    "domain": "domains",
}

# A verdict changes slowly; 15 minutes keeps a repeated report run cheap without
# serving a stale reputation.
CACHE_TTL_SECONDS = 900

# The free tier allows 500 lookups/day. A single call is capped well below that
# so one call cannot spend the budget; see the module docstring on why this
# rejects rather than truncates.
MAX_INDICATORS_PER_CALL = 50

# 4 lookups/min on the public API. Overridable in tests via _rate_limit_delay=0.
_DEFAULT_RATE_LIMIT_DELAY: float = 15.0


def _stat(stats: Any, key: str) -> int:
    """Read one integer out of ``last_analysis_stats``, defaulting to 0.

    Missing counters are genuinely absent for some objects rather than an
    error, so a default is right here — unlike the envelope itself, whose
    absence means the response was not understood.
    """
    if not isinstance(stats, dict):
        return 0
    value = stats.get(key)
    return value if isinstance(value, int) else 0


def _epoch_to_rfc3339(raw: Any) -> str | None:
    """Convert VirusTotal's Unix timestamp to RFC 3339, or None if unreadable."""
    if not isinstance(raw, (int, float)) or raw <= 0:
        return None
    try:
        return datetime.fromtimestamp(raw, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _normalize_lookup(indicator: str, indicator_type: str, body: Any) -> dict[str, Any]:
    """Map one VirusTotal object to an enrichment record.

    Raises ``RuntimeError`` when the response carries no ``data`` object: an
    upstream problem, so the tool degrades rather than surfacing it as a caller
    error (see ``adapters/base.py``).

    A verdict of "no engine flagged this" is a real, useful answer, so a record
    with ``malicious: 0`` is returned rather than dropped. That distinction
    matters for enrichment in a way it does not for a feed: the *absence* of
    detections is information the report can use.
    """
    if not isinstance(body, dict):
        raise RuntimeError("VirusTotal response was not a JSON object")
    if "data" not in body:
        raise RuntimeError("VirusTotal response missing 'data' object")
    data = body.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("VirusTotal 'data' was not an object")

    attributes = data.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    stats = attributes.get("last_analysis_stats")

    record: dict[str, Any] = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "source": "VirusTotal",
        "malicious": _stat(stats, "malicious"),
        "suspicious": _stat(stats, "suspicious"),
        "harmless": _stat(stats, "harmless"),
        "undetected": _stat(stats, "undetected"),
    }

    reputation = attributes.get("reputation")
    if isinstance(reputation, int):
        record["reputation"] = reputation

    votes = attributes.get("total_votes")
    if isinstance(votes, dict):
        record["community_votes"] = {
            "harmless": _stat(votes, "harmless"),
            "malicious": _stat(votes, "malicious"),
        }

    analysed = _epoch_to_rfc3339(attributes.get("last_analysis_date"))
    if analysed:
        record["last_analysis"] = analysed

    # IP objects carry network ownership; domains do not. Copied verbatim, never
    # inferred -- an attributed ASN that is wrong is worse than none.
    for key, dst in (
        ("as_owner", "as_owner"),
        ("asn", "asn"),
        ("country", "country"),
    ):
        value = attributes.get(key)
        if isinstance(value, (str, int)) and value != "":
            record[dst] = value

    return record


class VirusTotalAdapter:
    """Per-indicator enrichment against VirusTotal's public API."""

    name = "VirusTotal"
    tier = 2
    requires_credential = True
    # Not a feed: it scores indicators the caller supplies rather than
    # discovering them, so it is deliberately absent from _FEED_SOURCES and
    # cannot participate in fetch_all_iocs.
    is_enrichment = True

    def __init__(
        self,
        credentials: CredentialProvider,
        *,
        _rate_limit_delay: float = _DEFAULT_RATE_LIMIT_DELAY,
    ) -> None:
        self._credentials = credentials
        self._rate_limit_delay = _rate_limit_delay
        # Serialises HTTP requests so the inter-request gap is actually observed.
        self._semaphore = asyncio.Semaphore(1)
        # Cache keyed by (indicator_type, indicator).
        self._cache: dict[tuple[str, str], tuple[dict[str, Any], float]] = {}

    def _make_client(self) -> httpx.AsyncClient:
        api_key = self._credentials.get("virustotal", "api_key")
        return httpx.AsyncClient(
            headers={
                "x-apikey": api_key,
                "User-Agent": "threat-intel-mcp/0.13 (kj299/threat-intel)",
                "Accept": "application/json",
            },
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=5.0),
            event_hooks=egress_event_hooks("www.virustotal.com"),
        )

    async def enrich(
        self,
        indicators: list[str],
        *,
        indicator_type: str = "ip",
    ) -> dict[str, Any]:
        """Look up each indicator and return VirusTotal's verdict on it.

        Args:
            indicators: The values to look up. Capped at
                ``MAX_INDICATORS_PER_CALL``; an over-long list raises rather
                than being truncated.
            indicator_type: ``"ip"`` or ``"domain"``.

        Returns:
            ``{"enrichments": [...], "source", "tier", "retrieved_at",
            "record_count", "latency_ms", "looked_up", "failed"}``.

        Raises:
            ValueError: An unknown ``indicator_type``, an empty list, or more
                indicators than the per-call cap. All caller errors, surfaced
                verbatim per the taxonomy in ``adapters/base.py``.
        """
        if indicator_type not in INDICATOR_TYPES:
            raise ValueError(
                f"Unknown indicator_type: {indicator_type!r}. "
                f"Valid: {list(INDICATOR_TYPES.keys())}"
            )
        cleaned = [i.strip() for i in indicators if isinstance(i, str) and i.strip()]
        if not cleaned:
            raise ValueError("No indicators supplied to enrich")
        if len(cleaned) > MAX_INDICATORS_PER_CALL:
            raise ValueError(
                f"{len(cleaned)} indicators exceeds the per-call cap of "
                f"{MAX_INDICATORS_PER_CALL}. The public API allows 500 lookups "
                "per day; split the work rather than spending the budget in one "
                "call. This refuses instead of truncating so a caller is never "
                "handed a partial answer it believes is complete."
            )

        t_start = time.monotonic()
        enrichments: list[dict[str, Any]] = []
        failed: list[str] = []
        last_error: Exception | None = None
        segment = INDICATOR_TYPES[indicator_type]

        async with self._make_client() as client:
            for index, indicator in enumerate(cleaned):
                cache_key = (indicator_type, indicator)
                cached = self._cache.get(cache_key)
                if cached is not None and time.monotonic() < cached[1]:
                    enrichments.append(cached[0])
                    continue

                try:
                    record = await self._lookup(client, segment, indicator,
                                                indicator_type, first=index == 0)
                except Exception as exc:  # noqa: BLE001 - one bad lookup is not fatal
                    logger.warning(
                        "VirusTotal lookup failed for %s: %s",
                        indicator,
                        type(exc).__name__,
                    )
                    failed.append(indicator)
                    last_error = exc
                    continue
                enrichments.append(record)
                self._cache[cache_key] = (record, time.monotonic() + CACHE_TTL_SECONDS)

        # Every lookup failing is a total failure, not a partial result: the
        # caller's breaker should see it rather than receive an empty success.
        # The cause is carried, not just the count. "every lookup failed" with
        # no reason is the kind of message that sends someone to the logs to
        # rediscover what this function already knew -- and a malformed body
        # (a parse break) and a 503 (an outage) want different responses.
        if failed and not enrichments:
            raise RuntimeError(
                f"every VirusTotal lookup failed ({len(failed)} indicators); "
                f"last error: {type(last_error).__name__}: {last_error}"
            )

        guard_parsed(
            "VirusTotal",
            envelope_found=True,  # each response is checked in _normalize_lookup
            envelope_desc="a 'data' object per indicator",
            items_seen=len(cleaned),
            items_understood=len(enrichments) + len(failed),
        )

        latency_ms = (time.monotonic() - t_start) * 1000
        log_tool_call(
            "virustotal_enrich_iocs",
            {"indicator_type": indicator_type, "count": len(cleaned)},
            record_count=len(enrichments),
            latency_ms=latency_ms,
            status="partial" if failed else "ok",
            error=f"failed lookups: {failed}" if failed else None,
        )
        return {
            "enrichments": enrichments,
            "source": "VirusTotal",
            "tier": 2,
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(enrichments),
            "latency_ms": round(latency_ms, 1),
            "looked_up": [e["indicator"] for e in enrichments],
            "failed": failed,
        }

    async def _lookup(
        self,
        client: httpx.AsyncClient,
        segment: str,
        indicator: str,
        indicator_type: str,
        *,
        first: bool,
    ) -> dict[str, Any]:
        """One rate-limited lookup.

        The pause is taken *before* every request except the first, so a
        single-indicator call is not made to wait 15 seconds for nothing.
        """
        async with self._semaphore:
            if not first and self._rate_limit_delay > 0:
                await asyncio.sleep(self._rate_limit_delay)
            resp = await client.get(f"{_API_BASE}/{segment}/{indicator}")
            resp.raise_for_status()
            return _normalize_lookup(indicator, indicator_type, resp.json())

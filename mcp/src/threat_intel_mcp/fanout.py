"""Concurrent multi-source IOC fan-out with per-source resilience.

Runs every configured adapter's ``.fetch()`` concurrently, each wrapped in a
circuit breaker + bounded backoff retry. Per-source output is schema-validated
and deduplicated, then merged into a single deduplicated IOC set. A failing,
credential-less, or open-circuit source is surfaced as a degraded
Coverage-Ledger entry instead of failing the whole fan-out — this is the runtime
analogue of the threat-intel skill's R5 "surface partial coverage honestly" rule.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .adapters.base import FetchResult, SourceAdapter
from .normalize import deduplicate_iocs, finalize_iocs
from .resilience import CircuitBreaker, CircuitOpenError, guarded_fetch

logger = logging.getLogger(__name__)

# Keys copied from each per-source result into the compact ``per_source`` summary
# (the full IOC lists live only in the merged ``iocs`` array, not duplicated here).
_SUMMARY_KEYS = (
    "source",
    "tier",
    "status",
    "record_count",
    "latency_ms",
    "partial_failure",
    "error",
)


@dataclass
class FeedSource:
    """A single adapter plus the resilience state that guards it."""

    adapter: SourceAdapter
    tier: int
    name: str
    breaker: CircuitBreaker
    # Exceptions treated as configuration errors: not retried, do not trip the
    # breaker, and surface as an "unverified" Coverage-Ledger status.
    no_retry_on: tuple[type[BaseException], ...] = field(default_factory=tuple)


def _degraded(name: str, tier: int, reason: str, t0: float) -> dict[str, Any]:
    return {
        "source": name,
        "tier": tier,
        "status": "unverified",
        "iocs": [],
        "record_count": 0,
        "latency_ms": round((time.monotonic() - t0) * 1000, 1),
        "retrieved_at": "",
        "feed_types_fetched": [],
        "partial_failure": ["*"],
        "error": reason,
    }


async def _run_source(
    source: FeedSource, *, time_range: str, retry_kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Fetch one source; never raises — failures become degraded result dicts."""
    name, tier = source.name, source.tier
    t0 = time.monotonic()
    try:
        result = await guarded_fetch(
            source.adapter,
            source.breaker,
            time_range=time_range,
            feed_types=None,
            no_retry_on=source.no_retry_on,
            **retry_kwargs,
        )
    except source.no_retry_on as exc:  # credential / config error
        logger.warning("fan-out source %s unconfigured: %s", name, type(exc).__name__)
        return _degraded(name, tier, type(exc).__name__, t0)
    except CircuitOpenError:
        return _degraded(name, tier, "circuit_open", t0)
    except Exception as exc:
        logger.warning("fan-out source %s failed: %s", name, type(exc).__name__)
        return _degraded(name, tier, type(exc).__name__, t0)

    assert isinstance(result, FetchResult)
    deduped = finalize_iocs(result.iocs)
    status = "consulted"
    if result.partial_failure:
        status = "partial" if deduped else "unverified"

    return {
        "source": name,
        "tier": tier,
        "status": status,
        "iocs": deduped,
        "record_count": len(deduped),
        "latency_ms": result.latency_ms,
        "retrieved_at": result.retrieved_at,
        "feed_types_fetched": result.feed_types_fetched,
        "partial_failure": result.partial_failure,
        "error": None,
    }


async def fan_out(
    sources: list[FeedSource],
    *,
    time_range: str = "7d",
    retry_kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fetch every source concurrently and merge into one deduplicated IOC set.

    Returns a dict with the merged ``iocs``, a per-source breakdown, the lists of
    consulted vs. degraded sources, and a ``coverage_ledger`` ready to fold into
    the skill's Appendix A. Cross-source duplicates are collapsed keeping the
    highest-confidence copy, so ``record_count`` (the union) is typically smaller
    than the sum of per-source counts.
    """
    retry_kwargs = retry_kwargs or {}
    t0 = time.monotonic()

    per_source = await asyncio.gather(
        *(
            _run_source(s, time_range=time_range, retry_kwargs=retry_kwargs)
            for s in sources
        )
    )

    merged = deduplicate_iocs([ioc for r in per_source for ioc in r["iocs"]])
    latency_ms = round((time.monotonic() - t0) * 1000, 1)

    consulted = [r["source"] for r in per_source if r["status"] == "consulted"]
    degraded = [
        {"source": r["source"], "status": r["status"], "error": r["error"]}
        for r in per_source
        if r["status"] != "consulted"
    ]

    return {
        "iocs": merged,
        "record_count": len(merged),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "latency_ms": latency_ms,
        "sources_consulted": consulted,
        "sources_degraded": degraded,
        "per_source": [{k: r[k] for k in _SUMMARY_KEYS} for r in per_source],
        "coverage_ledger": [
            {"tier": r["tier"], "source": r["source"], "status": r["status"]}
            for r in per_source
        ],
    }

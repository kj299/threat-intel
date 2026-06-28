from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class FetchResult:
    """Normalised result from a single adapter fetch call."""

    iocs: list[dict[str, Any]]
    source: str
    tier: int
    retrieved_at: str          # ISO 8601 UTC timestamp
    record_count: int
    latency_ms: float
    feed_types_fetched: list[str]
    partial_failure: list[str] = field(default_factory=list)  # feed_types that failed


@runtime_checkable
class SourceAdapter(Protocol):
    name: str
    tier: int

    async def fetch(
        self,
        *,
        time_range: str,
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch indicators and return them normalised to ioc_network schema shape."""
        ...

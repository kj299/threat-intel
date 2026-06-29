"""Bring-your-own-endpoint protocol adapter scaffolding.

A :class:`ProtocolAdapter` is an abstract :class:`SourceAdapter` for a non-REST
transport (gRPC, MQTT, WebSocket, GraphQL). It standardises timing, schema
validation, deduplication, and ``FetchResult`` assembly so a concrete feed only
implements two protocol-specific things:

* :meth:`_collect` — pull raw records over the transport, and
* :meth:`_normalize` — map one raw record to an ``ioc_network`` dict.

A ``ProtocolAdapter`` subclass satisfies the ``SourceAdapter`` protocol, so it
drops straight into the existing fan-out (:mod:`threat_intel_mcp.fanout`) and
gets the same circuit-breaker / retry treatment as the REST adapters.

This module intentionally contains **no live feed and no hardcoded endpoint** —
a concrete adapter is configured entirely from operator-supplied credentials
(see :mod:`threat_intel_mcp.vault.protocols`). The protocol client libraries
(``gql``, ``websockets``, ``paho-mqtt``, ``grpcio``) are deliberately **not**
dependencies of this package; a concrete adapter adds the one it needs. Building
adapters against invented endpoints/response shapes would violate the repo's
no-fabrication rule, so the live wiring lands with the first real feed.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from ..adapters.base import FetchResult
from ..normalize import deduplicate_iocs, validate_iocs


class ProtocolAdapter(ABC):
    """Abstract base for a protocol-transport intel feed.

    Subclasses set ``name``, ``tier``, and ``protocol`` (one of the keys in
    ``vault.protocols.PROTOCOL_CREDENTIALS``) and implement :meth:`_collect` and
    :meth:`_normalize`. The base supplies a complete :meth:`fetch` that validates
    and deduplicates output and returns a ``FetchResult`` identical in shape to
    the REST adapters'.
    """

    name: str = "protocol-adapter"
    tier: int = 9
    protocol: str = ""

    @abstractmethod
    async def _collect(
        self, *, time_range: str, feed_types: list[str] | None
    ) -> list[Any]:
        """Pull raw records from the upstream transport. Implemented per feed.

        Should return a list of raw, un-normalised records (dicts, protobuf
        messages, decoded frames — whatever the transport yields). Network and
        auth errors should propagate; the fan-out's circuit breaker handles them.
        """

    @abstractmethod
    def _normalize(self, raw: Any) -> dict[str, Any] | None:
        """Map one raw record to an ``ioc_network`` dict, or ``None`` to skip.

        Must set at least ``type``, ``value``, ``confidence``, and ``source``.
        Records that cannot be mapped (wrong indicator type, missing fields)
        should return ``None`` rather than raising.
        """

    async def fetch(
        self, *, time_range: str = "7d", feed_types: list[str] | None = None
    ) -> FetchResult:
        """Collect, normalise, validate, and deduplicate into a ``FetchResult``."""
        t0 = time.monotonic()
        raw_records = await self._collect(time_range=time_range, feed_types=feed_types)
        normalized = [
            ioc
            for raw in raw_records
            if (ioc := self._normalize(raw)) is not None
        ]
        deduped = deduplicate_iocs(validate_iocs(normalized))
        latency_ms = round((time.monotonic() - t0) * 1000, 1)

        return FetchResult(
            iocs=deduped,
            source=self.name,
            tier=self.tier,
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            record_count=len(deduped),
            latency_ms=latency_ms,
            feed_types_fetched=feed_types or ([self.protocol] if self.protocol else []),
            partial_failure=[],
        )

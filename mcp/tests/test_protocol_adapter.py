"""Tests for the ProtocolAdapter scaffolding (Phase 3).

Uses a fake in-memory concrete subclass (no transport, no heavy deps) to prove
the base handles normalisation, validation, dedup, and FetchResult assembly, and
that a ProtocolAdapter drops into the existing fan-out machinery unchanged.
"""

from __future__ import annotations

import pytest

from threat_intel_mcp.adapters.base import FetchResult, SourceAdapter
from threat_intel_mcp.fanout import FeedSource, fan_out
from threat_intel_mcp.resilience import CircuitBreaker
from threat_intel_mcp.transports.base import ProtocolAdapter


class FakeGraphQLAdapter(ProtocolAdapter):
    """A concrete ProtocolAdapter whose 'transport' is a canned record list."""

    name = "FakeGraphQL"
    tier = 2
    protocol = "graphql"

    def __init__(self, records):
        self._records = records
        self.collect_calls = 0

    async def _collect(self, *, time_range, feed_types, partial_failure):
        self.collect_calls += 1
        return self._records

    def _normalize(self, raw):
        # raw is {"ip": ..., "score": ...}; skip records without an ip.
        ip = raw.get("ip")
        if not ip:
            return None
        return {
            "type": "IPv4",
            "value": ip,
            "confidence": raw.get("confidence", "Medium"),
            "source": self.name,
        }


@pytest.mark.asyncio
async def test_fetch_returns_fetchresult_with_normalized_iocs():
    adapter = FakeGraphQLAdapter(
        [{"ip": "1.1.1.1", "confidence": "High"}, {"ip": "2.2.2.2"}]
    )
    result = await adapter.fetch(time_range="7d")

    assert isinstance(result, FetchResult)
    assert result.source == "FakeGraphQL"
    assert result.tier == 2
    assert result.record_count == 2
    assert {i["value"] for i in result.iocs} == {"1.1.1.1", "2.2.2.2"}
    assert result.feed_types_fetched == ["graphql"]


@pytest.mark.asyncio
async def test_normalize_none_records_skipped():
    adapter = FakeGraphQLAdapter([{"ip": "1.1.1.1"}, {"notanip": "x"}, {"ip": ""}])
    result = await adapter.fetch()
    assert result.record_count == 1
    assert result.iocs[0]["value"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_invalid_iocs_dropped_by_validation():
    # "Bogus" is not a valid ioc_network type → dropped by validate_iocs.
    class BadAdapter(FakeGraphQLAdapter):
        def _normalize(self, raw):
            return {"type": "Bogus", "value": raw["ip"], "confidence": "High",
                    "source": self.name}

    result = await BadAdapter([{"ip": "1.1.1.1"}]).fetch()
    assert result.record_count == 0


@pytest.mark.asyncio
async def test_cross_record_dedup_keeps_highest_confidence():
    adapter = FakeGraphQLAdapter(
        [{"ip": "1.1.1.1", "confidence": "Low"}, {"ip": "1.1.1.1", "confidence": "High"}]
    )
    result = await adapter.fetch()
    assert result.record_count == 1
    assert result.iocs[0]["confidence"] == "High"


def test_protocol_adapter_satisfies_source_adapter_protocol():
    adapter = FakeGraphQLAdapter([])
    assert isinstance(adapter, SourceAdapter)


@pytest.mark.asyncio
async def test_drops_into_fanout_unchanged():
    adapter = FakeGraphQLAdapter([{"ip": "9.9.9.9", "confidence": "High"}])
    source = FeedSource(adapter, adapter.tier, adapter.name, CircuitBreaker(adapter.name))
    result = await fan_out([source])

    assert result["record_count"] == 1
    assert result["sources_consulted"] == ["FakeGraphQL"]
    assert result["iocs"][0]["value"] == "9.9.9.9"


@pytest.mark.asyncio
async def test_collect_can_report_partial_failure():
    class PartialAdapter(FakeGraphQLAdapter):
        async def _collect(self, *, time_range, feed_types, partial_failure):
            partial_failure.append("topic-b")
            return self._records

    adapter = PartialAdapter([{"ip": "1.1.1.1", "confidence": "High"}])
    result = await adapter.fetch(feed_types=["topic-a", "topic-b"])
    assert result.partial_failure == ["topic-b"]
    assert result.feed_types_fetched == ["topic-a"]
    assert result.record_count == 1

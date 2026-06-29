"""Tests for the concurrent multi-source fan-out.

Uses in-memory fake adapters (no HTTP) so the merge/dedupe/degrade logic is
exercised without network mocking or the module-level server singletons.
"""

from __future__ import annotations

import pytest

from threat_intel_mcp.adapters.base import FetchResult
from threat_intel_mcp.fanout import FeedSource, fan_out
from threat_intel_mcp.resilience import CircuitBreaker
from threat_intel_mcp.vault.base import CredentialError


def _ioc(value: str, *, type_: str = "IPv4", confidence: str = "High", source: str = "Fake"):
    return {"type": type_, "value": value, "confidence": confidence, "source": source}


class StubAdapter:
    """Adapter returning a fixed FetchResult, or raising a fixed exception."""

    def __init__(self, name, tier, *, iocs=None, partial=None, raises=None):
        self.name = name
        self.tier = tier
        self._iocs = iocs or []
        self._partial = partial or []
        self._raises = raises
        self.calls = 0

    async def fetch(self, *, time_range: str, feed_types=None):
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return FetchResult(
            iocs=self._iocs,
            source=self.name,
            tier=self.tier,
            retrieved_at="2026-06-29T00:00:00+00:00",
            record_count=len(self._iocs),
            latency_ms=1.0,
            feed_types_fetched=["default"],
            partial_failure=self._partial,
        )


def _source(adapter, *, no_retry_on=(CredentialError, KeyError)):
    return FeedSource(
        adapter,
        adapter.tier,
        adapter.name,
        CircuitBreaker(adapter.name),
        no_retry_on,
    )


async def _no_sleep(d):
    """Stand-in for asyncio.sleep so retry-path tests don't actually wait."""


@pytest.mark.asyncio
async def test_all_sources_consulted_and_merged():
    a = StubAdapter("Q-Feeds", 2, iocs=[_ioc("1.1.1.1", source="Q-Feeds")])
    b = StubAdapter("AbuseIPDB", 3, iocs=[_ioc("2.2.2.2", source="AbuseIPDB")])
    result = await fan_out([_source(a), _source(b)])

    assert result["record_count"] == 2
    values = {i["value"] for i in result["iocs"]}
    assert values == {"1.1.1.1", "2.2.2.2"}
    assert set(result["sources_consulted"]) == {"Q-Feeds", "AbuseIPDB"}
    assert result["sources_degraded"] == []
    assert {e["status"] for e in result["coverage_ledger"]} == {"consulted"}


@pytest.mark.asyncio
async def test_cross_source_dedup_keeps_highest_confidence():
    a = StubAdapter("Q-Feeds", 2, iocs=[_ioc("1.1.1.1", confidence="Low", source="Q-Feeds")])
    b = StubAdapter("AbuseIPDB", 3, iocs=[_ioc("1.1.1.1", confidence="High", source="AbuseIPDB")])
    result = await fan_out([_source(a), _source(b)])

    assert result["record_count"] == 1
    assert result["iocs"][0]["confidence"] == "High"
    assert result["iocs"][0]["source"] == "AbuseIPDB"


@pytest.mark.asyncio
async def test_invalid_iocs_dropped_per_source():
    # Missing required "source" field → dropped by validate_iocs.
    bad = {"type": "IPv4", "value": "9.9.9.9", "confidence": "High"}
    a = StubAdapter("Q-Feeds", 2, iocs=[bad, _ioc("1.1.1.1", source="Q-Feeds")])
    result = await fan_out([_source(a)])

    assert result["record_count"] == 1
    assert result["iocs"][0]["value"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_partial_failure_with_data_is_partial():
    a = StubAdapter(
        "Q-Feeds", 2, iocs=[_ioc("1.1.1.1", source="Q-Feeds")], partial=["malware_domains"]
    )
    result = await fan_out([_source(a)])

    ledger = result["coverage_ledger"][0]
    assert ledger["status"] == "partial"
    assert result["sources_consulted"] == []
    assert result["sources_degraded"][0]["source"] == "Q-Feeds"


@pytest.mark.asyncio
async def test_partial_failure_with_no_data_is_unverified():
    a = StubAdapter("Q-Feeds", 2, iocs=[], partial=["malware_ip", "malware_domains"])
    result = await fan_out([_source(a)])

    assert result["coverage_ledger"][0]["status"] == "unverified"


@pytest.mark.asyncio
async def test_credential_error_degrades_not_crashes():
    a = StubAdapter("VirusTotal", 2, raises=CredentialError("no key"))
    b = StubAdapter("Q-Feeds", 2, iocs=[_ioc("1.1.1.1", source="Q-Feeds")])
    result = await fan_out([_source(a), _source(b)])

    # The configured source still returns data; the unconfigured one degrades.
    assert result["record_count"] == 1
    degraded = {d["source"]: d for d in result["sources_degraded"]}
    assert "VirusTotal" in degraded
    assert degraded["VirusTotal"]["status"] == "unverified"
    assert degraded["VirusTotal"]["error"] == "CredentialError"
    # Credential error is non-retryable: adapter called exactly once.
    assert a.calls == 1


@pytest.mark.asyncio
async def test_open_circuit_source_degrades():
    a = StubAdapter("AbuseIPDB", 3, raises=RuntimeError("upstream 503"))
    src = _source(a)
    # Force the breaker open so guarded_fetch short-circuits before calling.
    src.breaker._opened_at = src.breaker.clock()  # type: ignore[attr-defined]

    result = await fan_out([src], retry_kwargs={"sleep": _no_sleep})

    assert a.calls == 0
    degraded = result["sources_degraded"][0]
    assert degraded["source"] == "AbuseIPDB"
    assert degraded["error"] == "circuit_open"


@pytest.mark.asyncio
async def test_transient_failure_surfaces_after_retries_exhausted():
    a = StubAdapter("Q-Feeds", 2, raises=RuntimeError("timeout"))
    result = await fan_out(
        [_source(a)], retry_kwargs={"retries": 1, "jitter": False, "sleep": _no_sleep}
    )

    assert a.calls == 2  # retries=1 → 2 attempts
    assert result["sources_degraded"][0]["error"] == "RuntimeError"
    assert result["record_count"] == 0


@pytest.mark.asyncio
async def test_per_source_summary_excludes_raw_iocs():
    a = StubAdapter("Q-Feeds", 2, iocs=[_ioc("1.1.1.1", source="Q-Feeds")])
    result = await fan_out([_source(a)])

    summary = result["per_source"][0]
    assert "iocs" not in summary
    assert summary["record_count"] == 1
    assert summary["source"] == "Q-Feeds"

"""End-to-end integration tests: real adapter -> fan-out -> guarded_fetch -> breaker.

The unit suites exercise the circuit breaker, the retry, and each adapter in
isolation. That is exactly the gap that let the v0.4.0 resilience layer ship
inert (issue #56): three adapters swallowed their own upstream errors, so
nothing ever reached ``guarded_fetch`` to retry or trip a breaker, yet every
isolated test still passed. These tests wire a **real** adapter through the
**real** fan-out and assert the resilience layer actually engages.

Uses pytest-httpx for the transport — no live network.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.qfeeds import QFeedsAdapter
from threat_intel_mcp.fanout import FeedSource, fan_out
from threat_intel_mcp.resilience import CircuitBreaker
from threat_intel_mcp.vault.base import CredentialError

_API_URL = "https://api.qfeeds.com/api"
_IP_RESPONSE = "1.1.1.1\n2.2.2.2\n"
_DOMAIN_RESPONSE = "evil.example\nbad.test\n"


class FakeCreds:
    def get(self, adapter_name: str, key: str) -> str:
        return "test-key-not-real"


async def _no_sleep(_d):
    pass


def _ip_params(page: int = 1) -> dict:
    return {"feed_type": "malware_ip", "limit": "4000", "page": str(page)}


def _domain_params(page: int = 1) -> dict:
    return {"feed_type": "malware_domains", "limit": "4000", "page": str(page)}


def _source(breaker: CircuitBreaker) -> FeedSource:
    return FeedSource(
        QFeedsAdapter(FakeCreds()), 2, "Q-Feeds", breaker, (CredentialError, KeyError)
    )


@pytest.mark.asyncio
async def test_total_upstream_failure_trips_breaker_through_fanout(
    httpx_mock: HTTPXMock,
):
    """Every feed type 500 -> adapter RAISES -> guarded_fetch records a breaker
    failure. After the threshold the breaker opens and the adapter is no longer
    called. This is the #56 regression guard: if QFeeds swallowed the failure,
    the breaker would never see it and would stay closed forever."""
    for _ in range(2):
        httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), status_code=500)
        httpx_mock.add_response(
            url=_API_URL, match_params=_domain_params(), status_code=503
        )

    breaker = CircuitBreaker("Q-Feeds", failure_threshold=2)
    source = _source(breaker)
    rk = {"retries": 0, "sleep": _no_sleep}

    r1 = await fan_out([source], retry_kwargs=rk)
    assert r1["sources_degraded"][0]["error"] == "HTTPStatusError"
    assert breaker.state == "closed"  # 1 failure < threshold 2

    r2 = await fan_out([source], retry_kwargs=rk)
    assert breaker.state == "open"  # 2 failures -> open
    assert r2["sources_degraded"][0]["error"] == "HTTPStatusError"

    requests_before = len(httpx_mock.get_requests())
    r3 = await fan_out([source], retry_kwargs=rk)
    # Breaker open: the adapter must NOT be called — no new HTTP request.
    assert len(httpx_mock.get_requests()) == requests_before
    assert r3["sources_degraded"][0]["error"] == "circuit_open"


@pytest.mark.asyncio
async def test_partial_failure_does_not_trip_breaker(httpx_mock: HTTPXMock):
    """One feed type succeeds, the other 500s. The adapter returns a *partial*
    result (does not raise), so the breaker stays closed — genuinely partial
    data must not be retried away or counted as an outage."""
    httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), text=_IP_RESPONSE)
    httpx_mock.add_response(
        url=_API_URL, match_params=_domain_params(), status_code=500
    )

    breaker = CircuitBreaker("Q-Feeds", failure_threshold=1)
    result = await fan_out([_source(breaker)], retry_kwargs={"retries": 0, "sleep": _no_sleep})

    assert breaker.state == "closed"  # partial success did NOT trip it
    assert result["record_count"] == 2  # the IP feed's indicators came through
    degraded = {d["source"]: d for d in result["sources_degraded"]}
    assert degraded["Q-Feeds"]["status"] == "partial"


@pytest.mark.asyncio
async def test_retry_recovers_a_real_adapter(httpx_mock: HTTPXMock):
    """First attempt: both feed types 500 -> total failure -> raise. guarded_fetch
    retries; second attempt both 200 -> the real adapter recovers and the source
    is consulted. Proves the retry actually re-invokes the adapter end-to-end."""
    # attempt 1 (both fail), attempt 2 (both succeed), matched in registration order
    httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), status_code=500)
    httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), text=_IP_RESPONSE)
    httpx_mock.add_response(
        url=_API_URL, match_params=_domain_params(), status_code=500
    )
    httpx_mock.add_response(
        url=_API_URL, match_params=_domain_params(), text=_DOMAIN_RESPONSE
    )

    breaker = CircuitBreaker("Q-Feeds", failure_threshold=5)
    result = await fan_out(
        [_source(breaker)],
        retry_kwargs={"retries": 1, "jitter": False, "sleep": _no_sleep},
    )

    assert result["sources_consulted"] == ["Q-Feeds"]
    assert result["record_count"] == 4  # 2 IPs + 2 domains
    assert breaker.state == "closed"  # recovered -> success recorded

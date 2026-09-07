"""Tests for the VirusTotal per-indicator enrichment adapter.

Uses pytest-httpx — no live network in CI.

The previous version of this file tested a bulk-feed adapter that called
``/api/v3/feeds/malicious_domains``. Every test passed. The endpoint did not
exist, and the first live call ever made returned 404 (#203). The fixture and
the parser had been written from the same belief, so they agreed with each
other and with nothing else.

That history shapes what is asserted here. The mock body below follows
VirusTotal's **published object reference**, which is better footing than the
bulk adapter had but is still not a response anyone has seen — so the tests
that matter most are the ones that hold whatever the attribute names turn out
to be: an unreadable body raises, a caller error raises, the quota cap refuses,
and one bad lookup does not sink the rest.

Record a cassette before trusting the field mapping.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.virustotal import (
    MAX_INDICATORS_PER_CALL,
    VirusTotalAdapter,
    _epoch_to_rfc3339,
    _normalize_lookup,
)
from threat_intel_mcp.vault.base import CredentialNotFoundError

_API = "https://www.virustotal.com/api/v3"


class FakeCredentials:
    def __init__(self, key: str | None = "vt-test-key") -> None:
        self._key = key

    def get(self, adapter: str, key: str) -> str:
        if self._key is None:
            raise CredentialNotFoundError(f"{adapter}/{key} not set")
        return self._key


@pytest.fixture()
def adapter() -> VirusTotalAdapter:
    # No inter-request pause: these tests exercise wiring, not throughput.
    return VirusTotalAdapter(FakeCredentials(), _rate_limit_delay=0)


def _ip_object(ip: str = "203.0.113.7", malicious: int = 7) -> dict:
    """Shaped after VirusTotal's published IP-address object reference."""
    return {
        "data": {
            "id": ip,
            "type": "ip_address",
            "attributes": {
                "as_owner": "Example Hosting AG",
                "asn": 64496,
                "continent": "EU",
                "country": "DE",
                "last_analysis_date": 1767225600,
                "last_analysis_stats": {
                    "harmless": 60,
                    "malicious": malicious,
                    "suspicious": 1,
                    "timeout": 0,
                    "undetected": 25,
                },
                "reputation": -14,
                "total_votes": {"harmless": 2, "malicious": 31},
            },
        }
    }


# ─── Guards that hold whatever the attribute names turn out to be ────────────


@pytest.mark.asyncio
async def test_a_body_without_data_raises_and_names_the_cause(
    adapter, httpx_mock: HTTPXMock
):
    """An unreadable response must not become a confident empty verdict.

    A per-indicator parse break is caught so one bad object cannot sink a
    batch, so the surfaced error is the all-failed one — but it must still
    carry WHY. "every lookup failed" with no reason sends the reader to the
    logs to rediscover what the function already knew, and a malformed body
    wants a different response from an outage.
    """
    httpx_mock.add_response(url=f"{_API}/ip_addresses/203.0.113.7", json={"meta": {}})

    with pytest.raises(RuntimeError) as excinfo:
        await adapter.enrich(["203.0.113.7"])

    assert "missing 'data' object" in str(excinfo.value)


@pytest.mark.asyncio
async def test_every_lookup_failing_raises(adapter, httpx_mock: HTTPXMock):
    """A total failure must reach the caller's breaker, not look like success."""
    httpx_mock.add_response(
        url=f"{_API}/ip_addresses/203.0.113.7", status_code=503
    )
    httpx_mock.add_response(
        url=f"{_API}/ip_addresses/203.0.113.8", status_code=503
    )

    with pytest.raises(RuntimeError, match="every VirusTotal lookup failed"):
        await adapter.enrich(["203.0.113.7", "203.0.113.8"])


@pytest.mark.asyncio
async def test_one_bad_lookup_does_not_sink_the_rest(adapter, httpx_mock: HTTPXMock):
    """Partial is the honest answer when some indicators resolved.

    Discarding good verdicts because one indicator 404'd is the same trade
    Q-Feeds got wrong (#205).
    """
    httpx_mock.add_response(url=f"{_API}/ip_addresses/203.0.113.7", json=_ip_object())
    httpx_mock.add_response(url=f"{_API}/ip_addresses/203.0.113.8", status_code=404)

    result = await adapter.enrich(["203.0.113.7", "203.0.113.8"])

    assert result["record_count"] == 1
    assert result["looked_up"] == ["203.0.113.7"]
    assert result["failed"] == ["203.0.113.8"]


@pytest.mark.asyncio
async def test_an_unknown_indicator_type_is_a_caller_error(adapter):
    with pytest.raises(ValueError, match="Unknown indicator_type"):
        await adapter.enrich(["203.0.113.7"], indicator_type="hash")


@pytest.mark.asyncio
async def test_an_empty_list_is_a_caller_error(adapter):
    with pytest.raises(ValueError, match="No indicators"):
        await adapter.enrich([])


@pytest.mark.asyncio
async def test_over_the_cap_refuses_rather_than_truncating(adapter, httpx_mock):
    """The quota exists to be respected, and a silent truncation would hand the
    caller a partial answer it believes is complete."""
    too_many = [f"203.0.113.{i % 250}" for i in range(MAX_INDICATORS_PER_CALL + 1)]

    with pytest.raises(ValueError, match="exceeds the per-call cap"):
        await adapter.enrich(too_many)

    assert httpx_mock.get_requests() == [], "must refuse before spending quota"


@pytest.mark.asyncio
async def test_a_missing_credential_raises(httpx_mock: HTTPXMock):
    vt = VirusTotalAdapter(FakeCredentials(key=None), _rate_limit_delay=0)

    with pytest.raises(CredentialNotFoundError):
        await vt.enrich(["203.0.113.7"])


@pytest.mark.asyncio
async def test_egress_is_restricted_to_virustotal(adapter):
    client = adapter._make_client()
    try:
        with pytest.raises(Exception):
            await client.get("https://evil.example.com/")
    finally:
        await client.aclose()


# ─── Behaviour given the documented shape ────────────────────────────────────


@pytest.mark.asyncio
async def test_detection_counts_are_read(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{_API}/ip_addresses/203.0.113.7", json=_ip_object())

    result = await adapter.enrich(["203.0.113.7"])
    record = result["enrichments"][0]

    assert record["indicator"] == "203.0.113.7"
    assert record["indicator_type"] == "ip"
    assert record["malicious"] == 7
    assert record["suspicious"] == 1
    assert record["harmless"] == 60
    assert record["undetected"] == 25
    assert record["reputation"] == -14
    assert record["community_votes"] == {"harmless": 2, "malicious": 31}
    assert record["as_owner"] == "Example Hosting AG"
    assert record["asn"] == 64496
    assert record["country"] == "DE"


@pytest.mark.asyncio
async def test_a_clean_indicator_is_a_result_not_a_gap(adapter, httpx_mock: HTTPXMock):
    """`malicious: 0` is a real, useful answer.

    For a feed, nothing found means nothing to report. For enrichment, "no
    engine flagged this" is information the report can act on, so the record is
    returned rather than dropped.
    """
    httpx_mock.add_response(
        url=f"{_API}/ip_addresses/203.0.113.7", json=_ip_object(malicious=0)
    )

    result = await adapter.enrich(["203.0.113.7"])

    assert result["record_count"] == 1
    assert result["enrichments"][0]["malicious"] == 0


@pytest.mark.asyncio
async def test_domains_use_the_domain_endpoint(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=f"{_API}/domains/evil.example",
        json={"data": {"id": "evil.example", "type": "domain", "attributes": {}}},
    )

    result = await adapter.enrich(["evil.example"], indicator_type="domain")

    assert result["enrichments"][0]["indicator_type"] == "domain"
    assert "domains/evil.example" in str(httpx_mock.get_requests()[0].url)


@pytest.mark.asyncio
async def test_a_repeated_indicator_is_served_from_cache(adapter, httpx_mock: HTTPXMock):
    """Quota is the binding constraint, so a second lookup of the same value in
    one session must not spend another of the 500 daily calls."""
    httpx_mock.add_response(url=f"{_API}/ip_addresses/203.0.113.7", json=_ip_object())

    await adapter.enrich(["203.0.113.7"])
    await adapter.enrich(["203.0.113.7"])

    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_the_api_key_is_sent_as_x_apikey(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{_API}/ip_addresses/203.0.113.7", json=_ip_object())

    await adapter.enrich(["203.0.113.7"])

    assert httpx_mock.get_requests()[0].headers["x-apikey"] == "vt-test-key"


def test_missing_stats_default_to_zero_rather_than_dropping_the_record():
    record = _normalize_lookup("203.0.113.7", "ip", {"data": {"attributes": {}}})

    assert record["malicious"] == 0
    assert "reputation" not in record


def test_unreadable_timestamps_are_omitted():
    assert _epoch_to_rfc3339(1767225600) == "2026-01-01T00:00:00+00:00"
    assert _epoch_to_rfc3339(0) is None
    assert _epoch_to_rfc3339("yesterday") is None
    assert _epoch_to_rfc3339(None) is None


@pytest.mark.asyncio
async def test_the_rate_limit_pause_skips_the_first_request(httpx_mock: HTTPXMock, monkeypatch):
    """4 lookups/min is the binding constraint, but a single-indicator call
    should not wait 15 seconds for nothing."""
    from threat_intel_mcp.adapters import virustotal

    slept: list[float] = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(virustotal.asyncio, "sleep", fake_sleep)
    vt = VirusTotalAdapter(FakeCredentials(), _rate_limit_delay=15.0)
    httpx_mock.add_response(url=f"{_API}/ip_addresses/203.0.113.7", json=_ip_object())
    httpx_mock.add_response(url=f"{_API}/ip_addresses/203.0.113.8", json=_ip_object())

    await vt.enrich(["203.0.113.7", "203.0.113.8"])

    assert slept == [15.0], "one pause, before the second lookup only"

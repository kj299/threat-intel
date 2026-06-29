"""Tests for the AbuseIPDB blacklist adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
Mock response contains three entries covering all three confidence tiers
(High/Medium/Low) so normalisation logic is exercised in each test.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.abuseipdb import AbuseIPDBAdapter, _normalize_entry

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_MOCK_URL = "https://api.abuseipdb.com/api/v2/blacklist"
_MOCK_PARAMS = {"confidenceMinimum": "90", "limit": "10000"}

_MOCK_RESPONSE = {
    "data": [
        {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 100,
            "countryCode": "US",
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
        },
        {
            "ipAddress": "5.6.7.8",
            "abuseConfidenceScore": 75,
            "countryCode": "RU",
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
        },
        {
            "ipAddress": "9.10.11.12",
            "abuseConfidenceScore": 45,
            "countryCode": "CN",
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
        },
    ]
}


class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return "test-api-key-do-not-use-in-prod"


@pytest.fixture()
def adapter():
    return AbuseIPDBAdapter(FakeCredentials())


# ---------------------------------------------------------------------------
# Unit tests: _normalize_entry
# ---------------------------------------------------------------------------


class TestNormalizeEntry:
    def test_normalize_high_confidence(self):
        entry = {
            "ipAddress": "1.2.3.4",
            "abuseConfidenceScore": 100,
            "countryCode": "US",
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
        }
        result = _normalize_entry(entry)
        assert result is not None
        assert result["confidence"] == "High"
        assert result["action"] == "block"
        assert result["associated_threat"] == "abuse"
        assert result["type"] == "IPv4"
        assert result["value"] == "1.2.3.4"

    def test_normalize_medium_confidence(self):
        entry = {
            "ipAddress": "5.6.7.8",
            "abuseConfidenceScore": 75,
            "countryCode": "RU",
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
        }
        result = _normalize_entry(entry)
        assert result is not None
        assert result["confidence"] == "Medium"
        assert result["associated_threat"] == "suspected_abuse"

    def test_normalize_low_confidence(self):
        entry = {
            "ipAddress": "9.10.11.12",
            "abuseConfidenceScore": 45,
            "countryCode": "CN",
            "lastReportedAt": "2026-01-01T00:00:00+00:00",
        }
        result = _normalize_entry(entry)
        assert result is not None
        assert result["confidence"] == "Low"
        assert result["associated_threat"] == "suspected_abuse"

    def test_normalize_missing_ip_skipped(self):
        entry = {"abuseConfidenceScore": 100, "countryCode": "US"}
        result = _normalize_entry(entry)
        assert result is None

    def test_normalize_empty_ip_skipped(self):
        entry = {"ipAddress": "", "abuseConfidenceScore": 100}
        result = _normalize_entry(entry)
        assert result is None

    def test_normalize_source_is_abuseipdb(self):
        entry = {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 95}
        result = _normalize_entry(entry)
        assert result is not None
        assert result["source"] == "AbuseIPDB"

    def test_normalize_tags(self):
        entry = {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 95}
        result = _normalize_entry(entry)
        assert result is not None
        assert "abuseipdb" in result["tags"]
        assert "blocklist" in result["tags"]

    def test_normalize_tlp_white(self):
        entry = {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 95}
        result = _normalize_entry(entry)
        assert result is not None
        assert result["tlp"] == "WHITE"

    def test_normalize_score_boundary_90_is_high(self):
        """Score exactly 90 should map to High."""
        entry = {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 90}
        result = _normalize_entry(entry)
        assert result is not None
        assert result["confidence"] == "High"

    def test_normalize_score_boundary_50_is_medium(self):
        """Score exactly 50 should map to Medium."""
        entry = {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 50}
        result = _normalize_entry(entry)
        assert result is not None
        assert result["confidence"] == "Medium"


# ---------------------------------------------------------------------------
# Integration tests: adapter.fetch() with mocked HTTP
# ---------------------------------------------------------------------------


class TestAbuseIPDBAdapterFetch:
    @pytest.mark.asyncio
    async def test_fetch_returns_fetch_result(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)
        result = await adapter.fetch()
        assert result.source == "AbuseIPDB"
        assert result.tier == 3

    @pytest.mark.asyncio
    async def test_fetch_record_count(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)
        result = await adapter.fetch()
        assert result.record_count == 3

    @pytest.mark.asyncio
    async def test_all_iocs_are_ipv4(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)
        result = await adapter.fetch()
        assert all(ioc["type"] == "IPv4" for ioc in result.iocs)

    @pytest.mark.asyncio
    async def test_all_iocs_have_required_fields(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)
        result = await adapter.fetch()
        for ioc in result.iocs:
            assert "type" in ioc
            assert "value" in ioc
            assert "confidence" in ioc
            assert "source" in ioc
            assert ioc["source"] == "AbuseIPDB"
            assert ioc["confidence"] in {"High", "Medium", "Low"}

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        # Only one response registered; second call must be served from cache.
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)

        await adapter.fetch()
        result = await adapter.fetch()
        assert result.record_count == 3

    @pytest.mark.asyncio
    async def test_retrieved_at_is_iso8601(self, adapter, httpx_mock: HTTPXMock):
        from datetime import datetime

        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)
        result = await adapter.fetch()
        # Should not raise
        datetime.fromisoformat(result.retrieved_at)

    @pytest.mark.asyncio
    async def test_feed_types_fetched(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)
        result = await adapter.fetch()
        assert result.feed_types_fetched == ["blacklist"]

    @pytest.mark.asyncio
    async def test_missing_ip_entries_skipped(self, adapter, httpx_mock: HTTPXMock):
        """Entries without ipAddress should be silently dropped."""
        response = {
            "data": [
                {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100},
                {"abuseConfidenceScore": 99},  # no ipAddress
                {"ipAddress": "", "abuseConfidenceScore": 95},  # empty ipAddress
            ]
        }
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=response)
        result = await adapter.fetch()
        assert result.record_count == 1
        assert result.iocs[0]["value"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_time_range_and_feed_types_ignored(
        self, adapter, httpx_mock: HTTPXMock
    ):
        """time_range and feed_types are accepted but not forwarded to the API."""
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)
        result = await adapter.fetch(time_range="30d", feed_types=["blacklist"])
        assert result.record_count == 3

    @pytest.mark.asyncio
    async def test_latency_ms_is_non_negative(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_MOCK_URL, match_params=_MOCK_PARAMS, json=_MOCK_RESPONSE)
        result = await adapter.fetch()
        assert result.latency_ms >= 0

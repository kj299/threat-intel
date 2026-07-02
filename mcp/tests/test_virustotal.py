"""Tests for the VirusTotal adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
Each test provides a mock response matching what VirusTotal returns for that
feed type; the adapter's normaliser must produce valid ioc_network objects.
"""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.virustotal import VirusTotalAdapter, _normalize_vt_entry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return "test-vt-api-key-do-not-use-in-prod"


@pytest.fixture()
def adapter():
    # _rate_limit_delay=0 so tests complete instantly (HTTP is mocked anyway).
    return VirusTotalAdapter(FakeCredentials(), _rate_limit_delay=0)


# ---------------------------------------------------------------------------
# Mock response bodies
# ---------------------------------------------------------------------------

# Each line is a separate JSON object (newline-delimited JSON).
_IP_RESPONSE = "\n".join([
    '{"id": "1.2.3.4", "type": "ip_address", "attributes": {"last_analysis_stats": {"malicious": 15, "suspicious": 2}, "tags": ["malware"]}}',
    '{"id": "5.6.7.8", "type": "ip_address", "attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1}, "tags": []}}',
])

_DOMAIN_RESPONSE = "\n".join([
    '{"id": "evil.example.com", "type": "domain", "attributes": {"last_analysis_stats": {"malicious": 20}, "tags": ["c2"]}}',
])

_IP_FEED_URL = "https://www.virustotal.com/api/v3/feeds/malicious_ips"
_DOMAIN_FEED_URL = "https://www.virustotal.com/api/v3/feeds/malicious_domains"

_IP_PARAMS = {"cursor": "initial", "limit": "40"}
_DOMAIN_PARAMS = {"cursor": "initial", "limit": "40"}


# ---------------------------------------------------------------------------
# Unit tests: _normalize_vt_entry
# ---------------------------------------------------------------------------


class TestNormalizeVtEntry:
    def test_normalize_ip_high_confidence(self):
        entry = {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"last_analysis_stats": {"malicious": 15, "suspicious": 2}, "tags": ["malware"]},
        }
        result = _normalize_vt_entry(entry, "malicious_ips")
        assert result is not None
        assert result["type"] == "IPv4"
        assert result["value"] == "1.2.3.4"
        assert result["confidence"] == "High"
        assert result["source"] == "VirusTotal"
        assert result["action"] == "block"
        assert result["tlp"] == "WHITE"

    def test_normalize_ip_medium_confidence(self):
        entry = {
            "id": "5.6.7.8",
            "type": "ip_address",
            "attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1}, "tags": []},
        }
        result = _normalize_vt_entry(entry, "malicious_ips")
        assert result is not None
        assert result["confidence"] == "Medium"

    def test_normalize_domain(self):
        entry = {
            "id": "evil.example.com",
            "type": "domain",
            "attributes": {"last_analysis_stats": {"malicious": 20}, "tags": ["c2"]},
        }
        result = _normalize_vt_entry(entry, "malicious_domains")
        assert result is not None
        assert result["type"] == "Domain"
        assert result["value"] == "evil.example.com"
        assert result["confidence"] == "High"

    def test_normalize_unknown_type_skipped(self):
        entry = {
            "id": "something",
            "type": "file",
            "attributes": {"last_analysis_stats": {"malicious": 50}},
        }
        result = _normalize_vt_entry(entry, "malicious_ips")
        assert result is None

    def test_normalize_missing_id_skipped(self):
        entry = {
            "type": "ip_address",
            "attributes": {"last_analysis_stats": {"malicious": 15}},
        }
        result = _normalize_vt_entry(entry, "malicious_ips")
        assert result is None

    def test_normalize_low_confidence(self):
        entry = {
            "id": "9.9.9.9",
            "type": "ip_address",
            "attributes": {"last_analysis_stats": {"malicious": 1}, "tags": []},
        }
        result = _normalize_vt_entry(entry, "malicious_ips")
        assert result is not None
        assert result["confidence"] == "Low"

    def test_normalize_tags_include_virustotal_and_feed_type(self):
        entry = {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"last_analysis_stats": {"malicious": 10}, "tags": []},
        }
        result = _normalize_vt_entry(entry, "malicious_ips")
        assert result is not None
        assert "virustotal" in result["tags"]
        assert "malicious_ips" in result["tags"]

    def test_normalize_ipv6(self):
        entry = {
            "id": "2001:db8::1",
            "type": "ip_address",
            "attributes": {"last_analysis_stats": {"malicious": 12}, "tags": []},
        }
        result = _normalize_vt_entry(entry, "malicious_ips")
        assert result is not None
        assert result["type"] == "IPv6"


# ---------------------------------------------------------------------------
# Integration tests: adapter.fetch() with mocked HTTP
# ---------------------------------------------------------------------------


class TestVirusTotalAdapterFetch:
    @pytest.mark.asyncio
    async def test_fetch_ip_feed(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_IP_FEED_URL,
            match_params=_IP_PARAMS,
            text=_IP_RESPONSE,
        )

        result = await adapter.fetch(feed_types=["malicious_ips"])
        assert result.source == "VirusTotal"
        assert result.tier == 2
        assert result.record_count == 2
        types = {ioc["type"] for ioc in result.iocs}
        assert "IPv4" in types

    @pytest.mark.asyncio
    async def test_fetch_unknown_feed_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown feed_type"):
            await adapter.fetch(feed_types=["nonexistent_feed"])

    @pytest.mark.asyncio
    async def test_all_iocs_have_required_fields(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_IP_FEED_URL,
            match_params=_IP_PARAMS,
            text=_IP_RESPONSE,
        )

        result = await adapter.fetch(feed_types=["malicious_ips"])
        for ioc in result.iocs:
            assert "type" in ioc
            assert "value" in ioc
            assert "confidence" in ioc
            assert "source" in ioc
            assert ioc["source"] == "VirusTotal"
            assert ioc["confidence"] in {"High", "Medium", "Low"}

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        # Only one response registered; second call must be served from cache.
        httpx_mock.add_response(
            url=_IP_FEED_URL,
            match_params=_IP_PARAMS,
            text=_IP_RESPONSE,
        )

        await adapter.fetch(feed_types=["malicious_ips"])
        result = await adapter.fetch(feed_types=["malicious_ips"])
        assert result.record_count == 2

    @pytest.mark.asyncio
    async def test_retrieved_at_is_iso8601(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_IP_FEED_URL,
            match_params=_IP_PARAMS,
            text=_IP_RESPONSE,
        )
        result = await adapter.fetch(feed_types=["malicious_ips"])
        from datetime import datetime
        datetime.fromisoformat(result.retrieved_at)

    @pytest.mark.asyncio
    async def test_partial_failure_recorded(self, adapter, httpx_mock: HTTPXMock):
        # IP feed succeeds; domain feed returns 500.
        httpx_mock.add_response(
            url=_IP_FEED_URL,
            match_params=_IP_PARAMS,
            text=_IP_RESPONSE,
        )
        httpx_mock.add_response(
            url=_DOMAIN_FEED_URL,
            match_params=_DOMAIN_PARAMS,
            status_code=500,
        )

        result = await adapter.fetch(feed_types=["malicious_ips", "malicious_domains"])
        assert "malicious_domains" in result.partial_failure
        assert result.record_count > 0  # IP feed still returned data

    @pytest.mark.asyncio
    async def test_total_failure_raises(self, adapter, httpx_mock: HTTPXMock):
        # Every requested feed type fails -> the adapter must propagate so the
        # fan-out's retry/circuit-breaker layer can act on it (issue #56).
        httpx_mock.add_response(
            url=_IP_FEED_URL, match_params=_IP_PARAMS, status_code=500
        )
        httpx_mock.add_response(
            url=_DOMAIN_FEED_URL, match_params=_DOMAIN_PARAMS, status_code=503
        )

        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch(feed_types=["malicious_ips", "malicious_domains"])

    @pytest.mark.asyncio
    async def test_domain_feed_returns_domain_type(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_DOMAIN_FEED_URL,
            match_params=_DOMAIN_PARAMS,
            text=_DOMAIN_RESPONSE,
        )

        result = await adapter.fetch(feed_types=["malicious_domains"])
        assert result.record_count == 1
        assert result.iocs[0]["type"] == "Domain"
        assert result.iocs[0]["value"] == "evil.example.com"

    @pytest.mark.asyncio
    async def test_iocs_source_is_virustotal(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_IP_FEED_URL,
            match_params=_IP_PARAMS,
            text=_IP_RESPONSE,
        )

        result = await adapter.fetch(feed_types=["malicious_ips"])
        assert all(ioc["source"] == "VirusTotal" for ioc in result.iocs)

    @pytest.mark.asyncio
    async def test_feed_types_fetched_reflects_success(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_IP_FEED_URL,
            match_params=_IP_PARAMS,
            text=_IP_RESPONSE,
        )

        result = await adapter.fetch(feed_types=["malicious_ips"])
        assert "malicious_ips" in result.feed_types_fetched
        assert result.partial_failure == []

    @pytest.mark.asyncio
    async def test_non_json_lines_skipped_gracefully(self, adapter, httpx_mock: HTTPXMock):
        # Mix of valid JSON lines and garbage; only valid entries should be parsed.
        mixed_response = "\n".join([
            '{"id": "1.2.3.4", "type": "ip_address", "attributes": {"last_analysis_stats": {"malicious": 15}, "tags": []}}',
            "this is not json at all",
            '{"id": "5.6.7.8", "type": "ip_address", "attributes": {"last_analysis_stats": {"malicious": 5}, "tags": []}}',
        ])
        httpx_mock.add_response(
            url=_IP_FEED_URL,
            match_params=_IP_PARAMS,
            text=mixed_response,
        )

        result = await adapter.fetch(feed_types=["malicious_ips"])
        assert result.record_count == 2

"""Tests for the AlienVault OTX adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
Each test provides a mock response matching what the OTX API returns;
the adapter's normaliser must produce valid ioc_network objects.
"""

from __future__ import annotations

import re
from datetime import datetime

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.otx import OTXAdapter, _normalize_indicator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return "test-otx-api-key-do-not-use-in-prod"


@pytest.fixture()
def adapter():
    return OTXAdapter(FakeCredentials())


# Minimal pulse response used by most integration tests.
_SINGLE_PAGE_RESPONSE = {
    "results": [
        {
            "name": "Test Pulse",
            "indicators": [
                {"type": "IPv4", "indicator": "1.2.3.4", "description": "C2"},
                {"type": "domain", "indicator": "evil.example.com", "description": ""},
                {"type": "URL", "indicator": "https://evil.example.com/payload", "description": ""},
                {"type": "FileHash-MD5", "indicator": "abc123", "description": ""},
                {"type": "unknown_type", "indicator": "blah", "description": ""},
            ],
        }
    ],
    "next": None,
}

_OTX_BASE = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# Regex that matches the subscribed endpoint regardless of query params.
# modified_since changes with wall-clock time so we match on URL prefix only.
_OTX_SUBSCRIBED_RE = re.compile(
    r"^https://otx\.alienvault\.com/api/v1/pulses/subscribed(\?.*)?$"
)


def _make_json_response(data: dict, status_code: int = 200) -> httpx.Response:
    """Build an httpx.Response with JSON body (used in callbacks)."""
    import json as _json

    return httpx.Response(
        status_code=status_code,
        headers={"Content-Type": "application/json"},
        content=_json.dumps(data).encode(),
    )


def _make_error_response(status_code: int) -> httpx.Response:
    return httpx.Response(status_code=status_code)


# ---------------------------------------------------------------------------
# Unit tests: _normalize_indicator
# ---------------------------------------------------------------------------


class TestNormalizeIndicator:
    def test_normalize_ipv4(self):
        ind = {"type": "IPv4", "indicator": "1.2.3.4", "description": "C2"}
        result = _normalize_indicator(ind)
        assert result is not None
        assert result["type"] == "IPv4"
        assert result["value"] == "1.2.3.4"
        assert result["confidence"] == "High"
        assert result["source"] == "AlienVault OTX"
        assert result["action"] == "alert"
        assert result["tlp"] == "WHITE"
        assert "otx" in result["tags"]

    def test_normalize_domain(self):
        ind = {"type": "domain", "indicator": "evil.example.com", "description": ""}
        result = _normalize_indicator(ind)
        assert result is not None
        assert result["type"] == "Domain"
        assert result["value"] == "evil.example.com"
        assert result["source"] == "AlienVault OTX"

    def test_normalize_hostname_maps_to_domain(self):
        ind = {"type": "hostname", "indicator": "host.evil.example.com", "description": ""}
        result = _normalize_indicator(ind)
        assert result is not None
        assert result["type"] == "Domain"

    def test_normalize_url(self):
        ind = {"type": "URL", "indicator": "https://evil.example.com/payload", "description": ""}
        result = _normalize_indicator(ind)
        assert result is not None
        assert result["type"] == "URL"
        assert result["value"] == "https://evil.example.com/payload"

    def test_normalize_filehash_skipped(self):
        ind = {"type": "FileHash-MD5", "indicator": "abc123", "description": ""}
        result = _normalize_indicator(ind)
        assert result is None

    def test_normalize_filehash_sha256_skipped(self):
        ind = {"type": "FileHash-SHA256", "indicator": "deadbeef" * 8, "description": ""}
        result = _normalize_indicator(ind)
        assert result is None

    def test_normalize_unknown_type_skipped(self):
        ind = {"type": "unknown_type", "indicator": "blah", "description": ""}
        result = _normalize_indicator(ind)
        assert result is None

    def test_pulse_name_slug_in_tags(self):
        ind = {"type": "IPv4", "indicator": "5.5.5.5", "description": ""}
        result = _normalize_indicator(ind, pulse_name="Evil Botnet Campaign")
        assert result is not None
        assert "otx" in result["tags"]
        assert "evil-botnet-campaign" in result["tags"]

    def test_empty_indicator_value_skipped(self):
        ind = {"type": "IPv4", "indicator": "", "description": ""}
        result = _normalize_indicator(ind)
        assert result is None

    def test_created_field_mapped_to_first_seen(self):
        ind = {
            "type": "IPv4",
            "indicator": "9.9.9.9",
            "description": "",
            "created": "2026-01-01T00:00:00",
        }
        result = _normalize_indicator(ind)
        assert result is not None
        assert result["first_seen"] == "2026-01-01T00:00:00"


# ---------------------------------------------------------------------------
# Integration tests: adapter.fetch() with mocked HTTP
# ---------------------------------------------------------------------------


class TestOTXAdapterFetch:
    @pytest.mark.asyncio
    async def test_fetch_returns_fetch_result(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_callback(
            lambda req: _make_json_response(_SINGLE_PAGE_RESPONSE),
            url=_OTX_SUBSCRIBED_RE,
            match_headers={"X-OTX-API-KEY": "test-otx-api-key-do-not-use-in-prod"},
        )
        result = await adapter.fetch(time_range="7d")
        assert result.source == "AlienVault OTX"
        assert result.tier == 2
        assert result.record_count > 0
        assert "subscribed" in result.feed_types_fetched

    @pytest.mark.asyncio
    async def test_fetch_skips_unsupported_types(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_callback(
            lambda req: _make_json_response(_SINGLE_PAGE_RESPONSE),
            url=_OTX_SUBSCRIBED_RE,
        )
        result = await adapter.fetch(time_range="7d")
        types = {ioc["type"] for ioc in result.iocs}
        # Must include supported types
        assert "IPv4" in types
        assert "Domain" in types
        assert "URL" in types
        # File hashes and unknown types must be excluded
        values = {ioc["value"] for ioc in result.iocs}
        assert "abc123" not in values
        assert "blah" not in values

    @pytest.mark.asyncio
    async def test_fetch_ioc_count_matches_supported_indicators(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_callback(
            lambda req: _make_json_response(_SINGLE_PAGE_RESPONSE),
            url=_OTX_SUBSCRIBED_RE,
        )
        result = await adapter.fetch(time_range="7d")
        # 5 indicators, 3 supported (IPv4, domain, URL), 2 skipped (FileHash-MD5, unknown_type)
        assert result.record_count == 3

    @pytest.mark.asyncio
    async def test_fetch_paginates(self, adapter, httpx_mock: HTTPXMock):
        page1_response = {
            "results": [
                {
                    "name": "Pulse Page 1",
                    "indicators": [
                        {"type": "IPv4", "indicator": "10.0.0.1", "description": ""},
                        {"type": "IPv4", "indicator": "10.0.0.2", "description": ""},
                    ],
                }
            ],
            "next": f"{_OTX_BASE}?page=2",
        }
        page2_response = {
            "results": [
                {
                    "name": "Pulse Page 2",
                    "indicators": [
                        {"type": "IPv4", "indicator": "10.0.0.3", "description": ""},
                    ],
                }
            ],
            "next": None,
        }

        # Serve page1 on first request, page2 on second (paginated via "next" URL).
        responses = iter([page1_response, page2_response])

        httpx_mock.add_callback(
            lambda req: _make_json_response(next(responses)),
            url=_OTX_SUBSCRIBED_RE,
            is_reusable=True,
        )

        result = await adapter.fetch(time_range="7d")
        assert result.record_count == 3
        values = {ioc["value"] for ioc in result.iocs}
        assert "10.0.0.1" in values
        assert "10.0.0.2" in values
        assert "10.0.0.3" in values

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        # Only one response registered; second call must be served from cache.
        httpx_mock.add_callback(
            lambda req: _make_json_response(_SINGLE_PAGE_RESPONSE),
            url=_OTX_SUBSCRIBED_RE,
        )
        await adapter.fetch(time_range="7d")
        # Second fetch must not make a new HTTP request (cache hit).
        result = await adapter.fetch(time_range="7d")
        assert result.record_count == 3

    @pytest.mark.asyncio
    async def test_retrieved_at_is_iso8601(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_callback(
            lambda req: _make_json_response(_SINGLE_PAGE_RESPONSE),
            url=_OTX_SUBSCRIBED_RE,
        )
        result = await adapter.fetch(time_range="7d")
        # Must not raise; fromisoformat accepts "+00:00" suffix.
        parsed = datetime.fromisoformat(result.retrieved_at)
        assert parsed.tzinfo is not None

    @pytest.mark.asyncio
    async def test_all_iocs_have_required_fields(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_callback(
            lambda req: _make_json_response(_SINGLE_PAGE_RESPONSE),
            url=_OTX_SUBSCRIBED_RE,
        )
        result = await adapter.fetch(time_range="7d")
        for ioc in result.iocs:
            assert "type" in ioc
            assert "value" in ioc
            assert "confidence" in ioc
            assert "source" in ioc
            assert ioc["source"] == "AlienVault OTX"
            assert ioc["confidence"] == "High"
            assert ioc["tlp"] == "WHITE"
            assert ioc["action"] == "alert"

    @pytest.mark.asyncio
    async def test_empty_results_returns_zero_iocs(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_callback(
            lambda req: _make_json_response({"results": [], "next": None}),
            url=_OTX_SUBSCRIBED_RE,
        )
        result = await adapter.fetch(time_range="7d")
        assert result.record_count == 0
        assert result.iocs == []
        assert result.partial_failure == []

    @pytest.mark.asyncio
    async def test_http_error_recorded_as_partial_failure(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_callback(
            lambda req: _make_error_response(401),
            url=_OTX_SUBSCRIBED_RE,
        )
        result = await adapter.fetch(time_range="7d")
        assert "subscribed" in result.partial_failure
        assert result.record_count == 0

    @pytest.mark.asyncio
    async def test_otx_tag_present_on_all_iocs(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_callback(
            lambda req: _make_json_response(_SINGLE_PAGE_RESPONSE),
            url=_OTX_SUBSCRIBED_RE,
        )
        result = await adapter.fetch(time_range="7d")
        for ioc in result.iocs:
            assert "otx" in ioc["tags"]

"""Tests for the Shodan malware-infrastructure adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
Shodan authenticates via a ``key`` query parameter, so the mocks match on the
full param set and the tests assert the key never leaks into log output.
"""

from __future__ import annotations

import logging

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters import shodan as shodan_mod
from threat_intel_mcp.adapters.shodan import (
    ShodanAdapter,
    _normalize_match,
    _normalize_timestamp,
)

_API_KEY = "test-shodan-key-do-not-use-in-prod"
_SEARCH_URL = "https://api.shodan.io/shodan/host/search"


class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return _API_KEY


@pytest.fixture()
def adapter():
    return ShodanAdapter(FakeCredentials())


def _params(page: int = 1) -> dict:
    return {"key": _API_KEY, "query": "category:malware", "page": str(page)}


_MOCK_RESPONSE = {
    "total": 3,
    "matches": [
        {
            "ip_str": "203.0.113.10",
            "port": 443,
            "timestamp": "2026-06-30T18:04:12.123456",
            "tags": ["malware", "c2"],
            "product": "Cobalt Strike Beacon",
            "hostnames": [],
        },
        {
            "ip_str": "2001:db8::7",
            "port": 8080,
            "timestamp": "2026-06-29T02:11:00.000000",
            "tags": [],
        },
        {
            # no ip_str -> skipped
            "port": 80,
            "timestamp": "2026-06-28T00:00:00.000000",
        },
    ],
}


# ---------------------------------------------------------------------------
# Unit tests: _normalize_timestamp / _normalize_match
# ---------------------------------------------------------------------------


class TestNormalizeTimestamp:
    def test_naive_timestamp_gains_utc_offset(self):
        out = _normalize_timestamp("2026-06-30T18:04:12.123456")
        assert out == "2026-06-30T18:04:12.123456+00:00"

    def test_aware_timestamp_preserved(self):
        out = _normalize_timestamp("2026-06-30T18:04:12+02:00")
        assert out == "2026-06-30T18:04:12+02:00"

    def test_garbage_returns_none(self):
        assert _normalize_timestamp("not-a-date") is None
        assert _normalize_timestamp(None) is None
        assert _normalize_timestamp("") is None


class TestNormalizeMatch:
    def test_ipv4_match(self):
        out = _normalize_match(_MOCK_RESPONSE["matches"][0], "malware_c2")
        assert out["type"] == "IPv4"
        assert out["value"] == "203.0.113.10"
        assert out["source"] == "Shodan"
        assert out["action"] == "alert"

    def test_malware_tag_maps_to_high_confidence(self):
        out = _normalize_match(_MOCK_RESPONSE["matches"][0], "malware_c2")
        assert out["confidence"] == "High"

    def test_untagged_match_is_medium_confidence(self):
        out = _normalize_match(_MOCK_RESPONSE["matches"][1], "malware_c2")
        assert out["confidence"] == "Medium"

    def test_ipv6_match(self):
        out = _normalize_match(_MOCK_RESPONSE["matches"][1], "malware_c2")
        assert out["type"] == "IPv6"
        assert out["value"] == "2001:db8::7"

    def test_missing_ip_returns_none(self):
        assert _normalize_match(_MOCK_RESPONSE["matches"][2], "malware_c2") is None

    def test_unparseable_ip_returns_none(self):
        assert _normalize_match({"ip_str": "not-an-ip"}, "malware_c2") is None

    def test_product_becomes_associated_threat(self):
        out = _normalize_match(_MOCK_RESPONSE["matches"][0], "malware_c2")
        assert out["associated_threat"] == "Cobalt Strike Beacon"

    def test_tags_include_shodan_feed_and_match_tags(self):
        out = _normalize_match(_MOCK_RESPONSE["matches"][0], "malware_c2")
        assert out["tags"][:2] == ["shodan", "malware_c2"]
        assert "c2" in out["tags"]

    def test_last_seen_is_rfc3339(self):
        out = _normalize_match(_MOCK_RESPONSE["matches"][0], "malware_c2")
        assert out["last_seen"].endswith("+00:00")


# ---------------------------------------------------------------------------
# Integration tests (pytest-httpx)
# ---------------------------------------------------------------------------


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_returns_normalized_iocs(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_SEARCH_URL, match_params=_params(), json=_MOCK_RESPONSE
        )
        result = await adapter.fetch()
        assert result.source == "Shodan"
        assert result.tier == 3
        assert result.record_count == 2  # ip-less match dropped
        assert {i["value"] for i in result.iocs} == {"203.0.113.10", "2001:db8::7"}
        assert result.feed_types_fetched == ["malware_c2"]
        assert result.partial_failure == []

    @pytest.mark.asyncio
    async def test_unknown_feed_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown feed_type"):
            await adapter.fetch(feed_types=["nonexistent"])

    @pytest.mark.asyncio
    async def test_total_failure_raises(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_SEARCH_URL, match_params=_params(), status_code=503
        )
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch()

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        # Only one response registered; second call must be served from cache.
        httpx_mock.add_response(
            url=_SEARCH_URL, match_params=_params(), json=_MOCK_RESPONSE
        )
        await adapter.fetch()
        result = await adapter.fetch()
        assert result.record_count == 2

    @pytest.mark.asyncio
    async def test_pagination_stops_when_page_not_full(
        self, adapter, httpx_mock: HTTPXMock, monkeypatch
    ):
        # Force tiny pages: page 1 "full" (2 matches), page 2 short (1 match).
        monkeypatch.setattr(shodan_mod, "PAGE_SIZE", 2)
        page1 = {"total": 3, "matches": _MOCK_RESPONSE["matches"][:2]}
        page2 = {"total": 3, "matches": [_MOCK_RESPONSE["matches"][0]]}
        httpx_mock.add_response(url=_SEARCH_URL, match_params=_params(1), json=page1)
        httpx_mock.add_response(url=_SEARCH_URL, match_params=_params(2), json=page2)

        result = await adapter.fetch()
        # 2 + 1 raw matches, one is a duplicate IP but adapter output is raw
        # (dedup happens in finalize_iocs at the tool layer).
        assert result.record_count == 3

    @pytest.mark.asyncio
    async def test_missing_credential_raises_before_any_request(
        self, httpx_mock: HTTPXMock
    ):
        class NoCreds:
            def get(self, adapter_name, key):
                raise KeyError("SHODAN_API_KEY not set")

        adapter = ShodanAdapter(NoCreds())
        with pytest.raises(KeyError):
            await adapter.fetch()
        assert httpx_mock.get_requests() == []

    @pytest.mark.asyncio
    async def test_api_key_never_in_logs(
        self, adapter, httpx_mock: HTTPXMock, caplog
    ):
        # Both the success path and the failure path must keep the key (which
        # rides in the query string) out of every log record.
        httpx_mock.add_response(
            url=_SEARCH_URL, match_params=_params(), json=_MOCK_RESPONSE
        )
        with caplog.at_level(logging.DEBUG):
            await adapter.fetch()

        failing = ShodanAdapter(FakeCredentials())
        httpx_mock.add_response(
            url=_SEARCH_URL, match_params=_params(), status_code=500
        )
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(httpx.HTTPStatusError):
                await failing.fetch()

        assert _API_KEY not in caplog.text

    @pytest.mark.asyncio
    async def test_retrieved_at_is_iso8601(self, adapter, httpx_mock: HTTPXMock):
        from datetime import datetime

        httpx_mock.add_response(
            url=_SEARCH_URL, match_params=_params(), json=_MOCK_RESPONSE
        )
        result = await adapter.fetch()
        datetime.fromisoformat(result.retrieved_at)

    @pytest.mark.asyncio
    async def test_empty_matches_ok(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_SEARCH_URL, match_params=_params(), json={"total": 0, "matches": []}
        )
        result = await adapter.fetch()
        assert result.record_count == 0
        assert result.partial_failure == []

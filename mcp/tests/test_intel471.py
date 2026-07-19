"""Tests for the Intel 471 indicators-stream adapter."""

from __future__ import annotations

import base64

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.intel471 import Intel471Adapter, _normalize_indicator

_EMAIL = "user@example.com"
_KEY = "test-intel471-key"
_STREAM_URL = "https://api.intel471.com/v1/indicators/stream"


class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return _EMAIL if key == "email" else _KEY


@pytest.fixture()
def adapter():
    return Intel471Adapter(FakeCredentials())


def _indicator(idata, confidence="high", family="Emotet", last=1717000000000):
    return {
        "data": {
            "indicator_type": "x",
            "indicator_data": idata,
            "confidence": confidence,
            "threat": {"data": {"family": family}},
            "activity": {"last": last},
        }
    }


class TestNormalize:
    def test_ip_indicator(self):
        out = _normalize_indicator(_indicator({"address": "198.51.100.5"}))
        assert out["type"] == "IPv4"
        assert out["value"] == "198.51.100.5"
        assert out["confidence"] == "High"
        assert out["associated_threat"] == "Emotet"
        assert out["last_seen"].endswith("+00:00")

    def test_url_indicator(self):
        out = _normalize_indicator(_indicator({"url": "http://evil.test/x"}, confidence="low"))
        assert out["type"] == "URL"
        assert out["value"] == "http://evil.test/x"
        assert out["confidence"] == "Low"

    def test_file_only_indicator_skipped(self):
        assert _normalize_indicator(_indicator({"file": {"sha256": "a" * 64}})) is None

    def test_non_ip_address_skipped(self):
        assert _normalize_indicator(_indicator({"address": "not-an-ip"})) is None

    def test_empty_indicator_data_skipped(self):
        assert _normalize_indicator(_indicator({})) is None


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_maps_network_indicators(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            json={
                "indicators": [
                    _indicator({"address": "198.51.100.5"}),
                    _indicator({"url": "http://evil.test/x"}),
                    _indicator({"file": {"sha256": "a" * 64}}),  # skipped
                ],
                "cursorNext": None,
            },
        )
        result = await adapter.fetch(time_range="7d")
        assert result.source == "Intel 471"
        assert result.record_count == 2
        assert {i["type"] for i in result.iocs} == {"IPv4", "URL"}

    @pytest.mark.asyncio
    async def test_http_basic_auth(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            json={"indicators": []}
        )
        await adapter.fetch(time_range="7d")
        auth = httpx_mock.get_requests()[0].headers["Authorization"]
        expected = "Basic " + base64.b64encode(f"{_EMAIL}:{_KEY}".encode()).decode()
        assert auth == expected

    @pytest.mark.asyncio
    async def test_total_failure_raises(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=500)
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch(time_range="7d")

    @pytest.mark.asyncio
    async def test_missing_credential_no_request(self, httpx_mock: HTTPXMock):
        class NoCreds:
            def get(self, a, k):
                raise KeyError("INTEL471_API_KEY")

        with pytest.raises(KeyError):
            await Intel471Adapter(NoCreds()).fetch(time_range="7d")
        assert httpx_mock.get_requests() == []

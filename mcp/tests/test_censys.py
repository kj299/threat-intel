"""Tests for the Censys Search v2 hosts adapter."""

from __future__ import annotations

import base64

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.censys import CensysAdapter, _normalize_hit

_ID = "test-api-id"
_SECRET = "test-api-secret"
_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"


class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return _ID if key == "api_id" else _SECRET


@pytest.fixture()
def adapter():
    return CensysAdapter(FakeCredentials())


_RESPONSE = {
    "result": {
        "hits": [
            {
                "ip": "192.0.2.44",
                "labels": ["malware", "c2"],
                "last_updated_at": "2026-06-30T00:00:00Z",
            },
            {"ip": "2001:db8::5", "labels": ["malware"]},
            {"labels": ["malware"]},  # no ip -> skipped
        ],
        "links": {"next": None},
    }
}


class TestNormalize:
    def test_ipv4_hit_is_alert_medium(self):
        out = _normalize_hit(_RESPONSE["result"]["hits"][0], "malware_hosts")
        assert out["type"] == "IPv4"
        assert out["value"] == "192.0.2.44"
        assert out["action"] == "alert"
        assert out["confidence"] == "Medium"
        assert "malware" in out["tags"]
        assert out["last_seen"] == "2026-06-30T00:00:00+00:00"

    def test_ipv6_hit(self):
        out = _normalize_hit(_RESPONSE["result"]["hits"][1], "malware_hosts")
        assert out["type"] == "IPv6"

    def test_no_ip_skipped(self):
        assert _normalize_hit(_RESPONSE["result"]["hits"][2], "malware_hosts") is None


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(json=_RESPONSE)
        result = await adapter.fetch(time_range="7d")
        assert result.source == "Censys"
        assert result.tier == 3
        assert result.record_count == 2
        assert {i["value"] for i in result.iocs} == {"192.0.2.44", "2001:db8::5"}

    @pytest.mark.asyncio
    async def test_http_basic_dual_credential(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            json={"result": {"hits": []}}
        )
        await adapter.fetch(time_range="7d")
        auth = httpx_mock.get_requests()[0].headers["Authorization"]
        expected = "Basic " + base64.b64encode(f"{_ID}:{_SECRET}".encode()).decode()
        assert auth == expected

    @pytest.mark.asyncio
    async def test_total_failure_raises(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=502)
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch(time_range="7d")

    @pytest.mark.asyncio
    async def test_missing_credential_no_request(self, httpx_mock: HTTPXMock):
        class NoCreds:
            def get(self, a, k):
                raise KeyError("CENSYS_API_SECRET")

        with pytest.raises(KeyError):
            await CensysAdapter(NoCreds()).fetch(time_range="7d")
        assert httpx_mock.get_requests() == []

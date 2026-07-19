"""Tests for the ANY.RUN TAXII/STIX adapter."""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.anyrun import (
    AnyRunAdapter,
    FEED_TYPES,
    _normalize_stix_object,
)

_KEY = "API-Key test-anyrun"
_IP_COLL = FEED_TYPES["ip"]
_BASE = "https://api.any.run/v1/feeds/taxii2/api1/collections"


class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return _KEY


@pytest.fixture()
def adapter():
    return AnyRunAdapter(FakeCredentials())


def _ip_url() -> str:
    return f"{_BASE}/{_IP_COLL}/objects/"


_STIX_ENVELOPE = {
    "objects": [
        {
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '203.0.113.9']",
            "confidence": 90,
            "name": "RedLine Stealer",
            "labels": ["malicious-activity"],
            "modified": "2026-06-30T12:00:00Z",
        },
        {"type": "indicator", "pattern": "[file:hashes.MD5 = 'abc']"},  # non-network
        {"type": "identity", "name": "ANY.RUN"},  # non-indicator
    ]
}


class TestNormalize:
    def test_ipv4_indicator(self):
        out = _normalize_stix_object(_STIX_ENVELOPE["objects"][0])
        assert len(out) == 1
        assert out[0]["type"] == "IPv4"
        assert out[0]["value"] == "203.0.113.9"
        assert out[0]["confidence"] == "High"
        assert out[0]["action"] == "block"
        assert out[0]["associated_threat"] == "RedLine Stealer"
        assert out[0]["last_seen"] == "2026-06-30T12:00:00+00:00"

    def test_non_network_pattern_skipped(self):
        assert _normalize_stix_object(_STIX_ENVELOPE["objects"][1]) == []

    def test_non_indicator_skipped(self):
        assert _normalize_stix_object(_STIX_ENVELOPE["objects"][2]) == []


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_ip_collection(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(json=_STIX_ENVELOPE)
        result = await adapter.fetch(feed_types=["ip"])
        assert result.source == "ANY.RUN"
        assert result.tier == 9
        assert result.record_count == 1
        assert result.iocs[0]["value"] == "203.0.113.9"

    @pytest.mark.asyncio
    async def test_authorization_header_passthrough(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(json={"objects": []})
        await adapter.fetch(feed_types=["ip"])
        assert httpx_mock.get_requests()[0].headers["Authorization"] == _KEY

    @pytest.mark.asyncio
    async def test_unknown_feed_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown feed_type"):
            await adapter.fetch(feed_types=["bogus"])

    @pytest.mark.asyncio
    async def test_total_failure_raises(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(status_code=503)
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch(feed_types=["ip"])

    @pytest.mark.asyncio
    async def test_missing_credential_no_request(self, httpx_mock: HTTPXMock):
        class NoCreds:
            def get(self, a, k):
                raise KeyError("ANYRUN_API_KEY")

        with pytest.raises(KeyError):
            await AnyRunAdapter(NoCreds()).fetch(feed_types=["ip"])
        assert httpx_mock.get_requests() == []

    @pytest.mark.asyncio
    async def test_cache(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(json=_STIX_ENVELOPE)
        await adapter.fetch(feed_types=["ip"])
        result = await adapter.fetch(feed_types=["ip"])
        assert result.record_count == 1

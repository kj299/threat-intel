"""Tests for the GreyNoise malicious-scanner adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
The mock GNQL response covers both record forms (nested
``internet_scanner_intelligence`` and flat) plus non-malicious and IP-less
records that must be skipped.
"""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters import greynoise as gn_mod
from threat_intel_mcp.adapters.greynoise import (
    GreyNoiseAdapter,
    _normalize_record,
    _time_range_to_gnql,
    _to_rfc3339,
)

_API_KEY = "test-greynoise-key-do-not-use"
_GNQL_URL = "https://api.greynoise.io/v3/gnql"


class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return _API_KEY


@pytest.fixture()
def adapter():
    return GreyNoiseAdapter(FakeCredentials())


def _params(query: str = "classification:malicious last_seen:7d") -> dict:
    return {"query": query, "quick": "false", "size": "100"}


_MOCK_RESPONSE = {
    "complete": True,
    "count": 4,
    "data": [
        {  # nested form, malicious → emitted
            "ip": "45.83.66.65",
            "internet_scanner_intelligence": {
                "classification": "malicious",
                "actor": "Alpha Strike Labs",
                "last_seen": "2026-06-30",
            },
        },
        {  # flat form, malicious, IPv6 → emitted
            "ip": "2001:db8::1",
            "classification": "malicious",
            "actor": "unknown",
            "last_seen": "2026-06-29T10:00:00Z",
        },
        {  # benign → skipped
            "ip": "8.8.8.8",
            "internet_scanner_intelligence": {"classification": "benign"},
        },
        {  # no ip → skipped
            "classification": "malicious",
        },
    ],
}


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_time_range_to_gnql_days(self):
        assert _time_range_to_gnql("7d") == "last_seen:7d"
        assert _time_range_to_gnql("30d") == "last_seen:30d"

    def test_time_range_to_gnql_non_days_is_none(self):
        assert _time_range_to_gnql("12h") is None
        assert _time_range_to_gnql("all") is None

    def test_to_rfc3339_promotes_bare_date(self):
        assert _to_rfc3339("2026-06-30") == "2026-06-30T00:00:00+00:00"

    def test_to_rfc3339_keeps_datetime(self):
        assert _to_rfc3339("2026-06-29T10:00:00+00:00") == "2026-06-29T10:00:00+00:00"

    def test_to_rfc3339_garbage(self):
        assert _to_rfc3339("nope") is None
        assert _to_rfc3339(None) is None


class TestNormalizeRecord:
    def test_nested_malicious_ipv4(self):
        out = _normalize_record(_MOCK_RESPONSE["data"][0], "malicious_scanners")
        assert out["type"] == "IPv4"
        assert out["value"] == "45.83.66.65"
        assert out["confidence"] == "High"
        assert out["action"] == "block"
        assert out["source"] == "GreyNoise"
        assert out["associated_threat"] == "Alpha Strike Labs"
        assert out["last_seen"] == "2026-06-30T00:00:00+00:00"

    def test_flat_malicious_ipv6_unknown_actor_dropped(self):
        out = _normalize_record(_MOCK_RESPONSE["data"][1], "malicious_scanners")
        assert out["type"] == "IPv6"
        assert "associated_threat" not in out  # "unknown" actor not attached

    def test_benign_skipped(self):
        assert _normalize_record(_MOCK_RESPONSE["data"][2], "malicious_scanners") is None

    def test_no_ip_skipped(self):
        assert _normalize_record(_MOCK_RESPONSE["data"][3], "malicious_scanners") is None

    def test_unparseable_ip_skipped(self):
        rec = {"ip": "not-an-ip", "classification": "malicious"}
        assert _normalize_record(rec, "malicious_scanners") is None


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_returns_only_malicious(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_GNQL_URL, match_params=_params(), json=_MOCK_RESPONSE
        )
        result = await adapter.fetch(time_range="7d")
        assert result.source == "GreyNoise"
        assert result.tier == 3
        assert result.record_count == 2  # benign + ip-less dropped
        assert {i["value"] for i in result.iocs} == {"45.83.66.65", "2001:db8::1"}
        assert result.partial_failure == []

    @pytest.mark.asyncio
    async def test_time_range_folds_into_query(self, adapter, httpx_mock: HTTPXMock):
        # A non-day range omits the last_seen filter entirely.
        httpx_mock.add_response(
            url=_GNQL_URL,
            match_params=_params("classification:malicious"),
            json={"data": [], "complete": True},
        )
        result = await adapter.fetch(time_range="12h")
        assert result.record_count == 0

    @pytest.mark.asyncio
    async def test_unknown_feed_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown feed_type"):
            await adapter.fetch(feed_types=["nope"])

    @pytest.mark.asyncio
    async def test_total_failure_raises(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_GNQL_URL, match_params=_params(), status_code=503)
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch(time_range="7d")

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_GNQL_URL, match_params=_params(), json=_MOCK_RESPONSE
        )
        await adapter.fetch(time_range="7d")
        result = await adapter.fetch(time_range="7d")
        assert result.record_count == 2

    @pytest.mark.asyncio
    async def test_missing_credential_raises_before_request(self, httpx_mock: HTTPXMock):
        class NoCreds:
            def get(self, adapter_name, key):
                raise KeyError("GREYNOISE_API_KEY not set")

        with pytest.raises(KeyError):
            await GreyNoiseAdapter(NoCreds()).fetch(time_range="7d")
        assert httpx_mock.get_requests() == []

    @pytest.mark.asyncio
    async def test_key_header_sent_not_in_query(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_GNQL_URL, match_params=_params(), json=_MOCK_RESPONSE
        )
        await adapter.fetch(time_range="7d")
        req = httpx_mock.get_requests()[0]
        assert req.headers["key"] == _API_KEY
        assert _API_KEY not in str(req.url)

    @pytest.mark.asyncio
    async def test_pagination_follows_scroll(
        self, adapter, httpx_mock: HTTPXMock, monkeypatch
    ):
        monkeypatch.setattr(gn_mod, "PAGE_SIZE", 2)
        page1 = {
            "complete": False,
            "scroll": "SCROLL2",
            "data": [
                {"ip": "1.1.1.1", "classification": "malicious"},
                {"ip": "2.2.2.2", "classification": "malicious"},
            ],
        }
        page2 = {
            "complete": True,
            "data": [{"ip": "3.3.3.3", "classification": "malicious"}],
        }
        httpx_mock.add_response(
            url=_GNQL_URL,
            match_params={"query": "classification:malicious last_seen:7d", "quick": "false", "size": "2"},
            json=page1,
        )
        httpx_mock.add_response(
            url=_GNQL_URL,
            match_params={"query": "classification:malicious last_seen:7d", "quick": "false", "size": "2", "scroll": "SCROLL2"},
            json=page2,
        )
        result = await adapter.fetch(time_range="7d")
        assert result.record_count == 3

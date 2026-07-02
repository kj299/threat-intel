"""Tests for the Q-Feeds adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
Each test provides a mock response matching what Q-Feeds returns for that
feed type; the adapter's normaliser must produce valid ioc_network objects.
"""

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.qfeeds import QFeedsAdapter, _normalize_line


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class FakeCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return "test-api-key-do-not-use-in-prod"


@pytest.fixture()
def adapter():
    return QFeedsAdapter(FakeCredentials())


# ---------------------------------------------------------------------------
# Unit tests: _normalize_line
# ---------------------------------------------------------------------------

class TestNormalizeLine:
    def test_ipv4(self):
        result = _normalize_line("1.2.3.4", "malware_ip")
        assert result is not None
        assert result["type"] == "IPv4"
        assert result["value"] == "1.2.3.4"
        assert result["confidence"] == "High"
        assert result["source"] == "Q-Feeds"
        assert result["action"] == "block"

    def test_ipv4_cidr(self):
        result = _normalize_line("10.0.0.0/8", "malware_ip")
        assert result is not None
        assert result["type"] == "CIDR_Range"

    def test_ipv6(self):
        result = _normalize_line("2001:db8::ff00:42:8329", "malware_ip")
        assert result is not None
        assert result["type"] == "IPv6"

    def test_invalid_ipv4_skipped(self):
        result = _normalize_line("not-an-ip", "malware_ip")
        assert result is None

    def test_invalid_cidr_skipped(self):
        result = _normalize_line("999.999.999.999/32", "malware_ip")
        assert result is None

    def test_domain(self):
        result = _normalize_line("evil.example.com", "malware_domains")
        assert result is not None
        assert result["type"] == "Domain"

    def test_url_in_domain_feed(self):
        result = _normalize_line("https://evil.example.com/dropper.exe", "malware_domains")
        assert result is not None
        assert result["type"] == "URL"

    def test_comment_lines_handled_upstream(self):
        # The adapter strips comment lines before calling _normalize_line,
        # but empty string should return None gracefully.
        result = _normalize_line("", "malware_ip")
        assert result is None

    def test_tags_include_feed_type(self):
        result = _normalize_line("1.2.3.4", "malware_ip")
        assert "malware_ip" in result["tags"]
        assert "q-feeds" in result["tags"]


# ---------------------------------------------------------------------------
# Integration tests: adapter.fetch() with mocked HTTP
# ---------------------------------------------------------------------------

_IP_RESPONSE = "# Q-Feeds malware IP feed\n1.1.1.1\n2.2.2.2\n10.0.0.0/8\n"
_DOMAIN_RESPONSE = "# Q-Feeds malware domains feed\nevil.example.com\nbad.test.org\n"


_API_URL = "https://api.qfeeds.com/api"

def _ip_params(page: int = 1) -> dict:
    return {"feed_type": "malware_ip", "limit": "4000", "page": str(page)}

def _domain_params(page: int = 1) -> dict:
    return {"feed_type": "malware_domains", "limit": "4000", "page": str(page)}


class TestQFeedsAdapterFetch:
    @pytest.mark.asyncio
    async def test_fetch_ip_feed(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), text=_IP_RESPONSE)

        result = await adapter.fetch(feed_types=["malware_ip"])
        assert result.source == "Q-Feeds"
        assert result.tier == 2
        assert result.record_count == 3  # 1.1.1.1, 2.2.2.2, 10.0.0.0/8
        types = {ioc["type"] for ioc in result.iocs}
        assert "IPv4" in types
        assert "CIDR_Range" in types

    @pytest.mark.asyncio
    async def test_fetch_domain_feed(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_URL, match_params=_domain_params(), text=_DOMAIN_RESPONSE)

        result = await adapter.fetch(feed_types=["malware_domains"])
        assert result.record_count == 2
        assert all(ioc["type"] == "Domain" for ioc in result.iocs)

    @pytest.mark.asyncio
    async def test_all_iocs_have_required_fields(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), text=_IP_RESPONSE)
        httpx_mock.add_response(url=_API_URL, match_params=_domain_params(), text=_DOMAIN_RESPONSE)

        result = await adapter.fetch()
        for ioc in result.iocs:
            assert "type" in ioc
            assert "value" in ioc
            assert "confidence" in ioc
            assert "source" in ioc
            assert ioc["source"] == "Q-Feeds"
            assert ioc["confidence"] in {"High", "Medium", "Low"}

    @pytest.mark.asyncio
    async def test_comment_lines_excluded(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_API_URL,
            match_params=_ip_params(),
            text="# This is a comment\n1.2.3.4\n# Another comment\n5.6.7.8\n",
        )
        result = await adapter.fetch(feed_types=["malware_ip"])
        assert result.record_count == 2
        values = [ioc["value"] for ioc in result.iocs]
        assert "1.2.3.4" in values
        assert "5.6.7.8" in values

    @pytest.mark.asyncio
    async def test_unknown_feed_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown feed_type"):
            await adapter.fetch(feed_types=["nonexistent_feed"])

    @pytest.mark.asyncio
    async def test_partial_failure_recorded(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), text=_IP_RESPONSE)
        httpx_mock.add_response(url=_API_URL, match_params=_domain_params(), status_code=500)

        result = await adapter.fetch()
        assert "malware_domains" in result.partial_failure
        assert result.record_count > 0  # IP feed still returned

    @pytest.mark.asyncio
    async def test_total_failure_raises(self, adapter, httpx_mock: HTTPXMock):
        # Every requested feed type fails -> the adapter must propagate so the
        # fan-out's retry/circuit-breaker layer can act on it (issue #56).
        httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), status_code=500)
        httpx_mock.add_response(url=_API_URL, match_params=_domain_params(), status_code=503)

        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch()

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        # Only one response registered; second call must be served from cache.
        httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), text=_IP_RESPONSE)

        await adapter.fetch(feed_types=["malware_ip"])
        result = await adapter.fetch(feed_types=["malware_ip"])
        assert result.record_count == 3

    @pytest.mark.asyncio
    async def test_retrieved_at_is_iso8601(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_URL, match_params=_ip_params(), text=_IP_RESPONSE)
        result = await adapter.fetch(feed_types=["malware_ip"])
        from datetime import datetime
        datetime.fromisoformat(result.retrieved_at)

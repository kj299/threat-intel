"""Tests for the Q-Feeds adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
Each test provides a mock response matching what Q-Feeds returns for that
feed type; the adapter's normaliser must produce valid ioc_network objects.
"""

import httpx
import pytest

from threat_intel_mcp.adapters import qfeeds
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


class TestIpValidation:
    """Real address parsing (issue #61): no out-of-range octets, no colon junk."""

    def test_out_of_range_octets_skipped(self):
        assert _normalize_line("999.999.999.999", "malware_ip") is None

    def test_colon_junk_not_classified_as_ipv6(self):
        assert _normalize_line("foo:bar", "malware_ip") is None

    def test_valid_ipv6_kept(self):
        out = _normalize_line("2001:db8::1", "malware_ip")
        assert out is not None and out["type"] == "IPv6"

    def test_valid_ipv4_kept(self):
        out = _normalize_line("203.0.113.7", "malware_ip")
        assert out is not None and out["type"] == "IPv4"


# ---------------------------------------------------------------------------
# Pagination and rate limiting (#205)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_inter_page_sleep(monkeypatch):
    """Remove the real inter-page pause from every test in this module.

    The delay exists to avoid the 429 that #205 is about; waiting for it in
    unit tests would add a second per page for no assertion value. The pacing
    itself is asserted directly below rather than by wall-clock.
    """
    monkeypatch.setattr(qfeeds, "INTER_PAGE_DELAY_SECONDS", 0)


def _full_page(count: int = 4000) -> str:
    """A page of exactly PAGE_SIZE lines, which is what makes the walk continue."""
    return "\n".join(f"10.0.{i // 256}.{i % 256}" for i in range(count)) + "\n"


class TestPaginationRateLimit:
    @pytest.mark.asyncio
    async def test_a_429_on_page_two_keeps_page_one(
        self, adapter, httpx_mock: HTTPXMock
    ):
        """The #205 defect: page 1's records were thrown away.

        Several thousand indicators were really retrieved and really parsed.
        Discarding them because page 2 was rate-limited reports nothing when
        `partial` is the true answer.
        """
        httpx_mock.add_response(
            url=_API_URL, match_params=_ip_params(1), text=_full_page()
        )
        httpx_mock.add_response(
            url=_API_URL, match_params=_ip_params(2), status_code=429
        )

        result = await adapter.fetch(feed_types=["malware_ip"])

        assert result.record_count == 4000, "page 1 must survive the page-2 failure"
        assert result.partial_failure, "a truncated walk must say so"
        assert "page 2" in result.partial_failure[0]
        assert "429" in result.partial_failure[0]
        # Truncated is not failed: the feed WAS consulted and did return data.
        assert result.feed_types_fetched == ["malware_ip"]

    @pytest.mark.asyncio
    async def test_a_429_on_page_one_still_raises(
        self, adapter, httpx_mock: HTTPXMock
    ):
        """Nothing was retrieved, so there is nothing honest to return — and the
        circuit breaker should see it."""
        httpx_mock.add_response(
            url=_API_URL, match_params=_ip_params(1), status_code=429
        )

        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch(feed_types=["malware_ip"])

    @pytest.mark.asyncio
    async def test_a_truncated_result_is_not_cached(
        self, adapter, httpx_mock: HTTPXMock
    ):
        """Caching a truncated walk would serve an incomplete blocklist as a
        complete one for the whole TTL, with no way for the next caller to tell.
        """
        httpx_mock.add_response(
            url=_API_URL, match_params=_ip_params(1), text=_full_page()
        )
        httpx_mock.add_response(
            url=_API_URL, match_params=_ip_params(2), status_code=429
        )

        await adapter.fetch(feed_types=["malware_ip"])

        assert "malware_ip" not in adapter._cache

    @pytest.mark.asyncio
    async def test_a_complete_walk_is_cached_and_reports_no_truncation(
        self, adapter, httpx_mock: HTTPXMock
    ):
        """Non-vacuity: the guard above must not fire on a healthy fetch."""
        httpx_mock.add_response(
            url=_API_URL, match_params=_ip_params(1), text=_IP_RESPONSE
        )

        result = await adapter.fetch(feed_types=["malware_ip"])

        assert result.partial_failure == []
        assert "malware_ip" in adapter._cache

    @pytest.mark.asyncio
    async def test_pages_are_paced(self, adapter, httpx_mock: HTTPXMock, monkeypatch):
        """The walk must pause between pages, and not before the first.

        Asserted on the calls rather than the clock: the first live run asked
        for 8,000 records with no gap at all and was rate-limited immediately.
        """
        slept: list[float] = []

        async def fake_sleep(seconds):
            slept.append(seconds)

        monkeypatch.setattr(qfeeds, "INTER_PAGE_DELAY_SECONDS", 1.0)
        monkeypatch.setattr(qfeeds.asyncio, "sleep", fake_sleep)
        httpx_mock.add_response(
            url=_API_URL, match_params=_ip_params(1), text=_full_page()
        )
        httpx_mock.add_response(
            url=_API_URL, match_params=_ip_params(2), text=_IP_RESPONSE
        )

        await adapter.fetch(feed_types=["malware_ip"])

        assert slept == [1.0], "exactly one pause, between page 1 and page 2"

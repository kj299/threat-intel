"""Tests for the URLhaus (abuse.ch) public malicious-URL adapter.

Uses pytest-httpx to intercept HTTP calls — no live network access in CI.
The mock CSV mirrors the real feed layout:
  id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
"""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.urlhaus import URLhausAdapter, _normalize_row, _to_rfc3339

_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Real URLhaus CSV is quoted; a leading comment block starts each line with '#'.
_MOCK_CSV = (
    '# URLhaus recent URLs\n'
    '# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
    '"100","2026-07-01 12:00:00","http://evil.example/mal.exe","online",'
    '"2026-07-01 12:30:00","malware_download","exe,elf",'
    '"https://urlhaus.abuse.ch/url/100/","anon"\n'
    '"101","2026-07-01 11:00:00","http://bad.test/payload","offline",'
    '"2026-07-01 11:10:00","malware_download","",'
    '"https://urlhaus.abuse.ch/url/101/","anon"\n'
)


@pytest.fixture()
def adapter():
    return URLhausAdapter()


class TestHelpers:
    def test_to_rfc3339(self):
        assert _to_rfc3339("2026-07-01 12:00:00") == "2026-07-01T12:00:00+00:00"

    def test_to_rfc3339_garbage(self):
        assert _to_rfc3339("") is None
        assert _to_rfc3339("nope") is None

    def test_normalize_row(self):
        row = ["100", "2026-07-01 12:00:00", "http://evil.example/x", "online",
               "", "malware_download", "exe,elf", "link", "anon"]
        out = _normalize_row(row)
        assert out["type"] == "URL"
        assert out["value"] == "http://evil.example/x"
        assert out["confidence"] == "High"
        assert out["action"] == "block"
        assert out["associated_threat"] == "malware_download"
        assert "urlhaus" in out["tags"] and "online" in out["tags"] and "exe" in out["tags"]
        assert out["first_seen"] == "2026-07-01T12:00:00+00:00"

    def test_normalize_row_short_skipped(self):
        assert _normalize_row(["1", "2026-07-01 12:00:00", "http://x"]) is None

    def test_normalize_row_empty_url_skipped(self):
        row = ["1", "2026-07-01 12:00:00", "", "online", "", "", "", "", ""]
        assert _normalize_row(row) is None


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_parses_csv(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, text=_MOCK_CSV)
        result = await adapter.fetch()
        assert result.source == "URLhaus"
        assert result.tier == 9
        assert result.record_count == 2
        assert {i["value"] for i in result.iocs} == {
            "http://evil.example/mal.exe", "http://bad.test/payload"
        }

    @pytest.mark.asyncio
    async def test_no_credential_needed(self, adapter, httpx_mock: HTTPXMock):
        # No credential provider passed; fetch must still work (public feed).
        httpx_mock.add_response(url=_FEED_URL, text=_MOCK_CSV)
        result = await adapter.fetch()
        assert result.record_count == 2
        assert adapter.requires_credential is False

    @pytest.mark.asyncio
    async def test_unknown_feed_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown feed_type"):
            await adapter.fetch(feed_types=["nope"])

    @pytest.mark.asyncio
    async def test_upstream_error_raises(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, status_code=503)
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch()

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, text=_MOCK_CSV)
        await adapter.fetch()
        result = await adapter.fetch()
        assert result.record_count == 2

    @pytest.mark.asyncio
    async def test_comment_lines_skipped(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_FEED_URL, text="# only comments\n# nothing else\n"
        )
        result = await adapter.fetch()
        assert result.record_count == 0

"""Tests for the CISA KEV catalog adapter.

Uses pytest-httpx to intercept HTTP calls — no live network in CI. The mock JSON
mirrors the real KEV catalog shape (verified against the OpenCTI CISA-KEV
connector and its test fixtures).
"""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.cisa_kev import (
    CISAKEVAdapter,
    _MIRROR_URL,
    _date_to_rfc3339,
    _normalize_entry,
)

_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

_MOCK = {
    "catalogVersion": "2026.07.01",
    "dateReleased": "2026-07-01T12:00:00.0000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-12345",
            "vendorProject": "Acme Corp",
            "product": "Acme Widget Server",
            "vulnerabilityName": "Acme Widget Server RCE",
            "dateAdded": "2024-01-15",
            "shortDescription": "Acme Widget Server contains an RCE vulnerability.",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "dueDate": "2024-02-05",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-78"],
        },
        {
            "cveID": "CVE-2017-9805",
            "vendorProject": "Apache",
            "product": "Struts",
            "vulnerabilityName": "Apache Struts Deserialization",
            "dateAdded": "2021-11-03",
            "shortDescription": "Apache Struts unsafe deserialization.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2022-05-03",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-502"],
        },
    ],
}


@pytest.fixture()
def adapter():
    return CISAKEVAdapter()


class TestHelpers:
    def test_date_to_rfc3339(self):
        assert _date_to_rfc3339("2024-01-15") == "2024-01-15T00:00:00+00:00"

    def test_date_to_rfc3339_garbage(self):
        assert _date_to_rfc3339("") is None
        assert _date_to_rfc3339("nope") is None
        assert _date_to_rfc3339(None) is None

    def test_normalize_entry(self):
        out = _normalize_entry(_MOCK["vulnerabilities"][0])
        assert out["cve_id"] == "CVE-2024-12345"
        assert out["source"] == "CISA KEV"
        assert out["exploit_status"] == "known_exploited"
        assert out["vendor_project"] == "Acme Corp"
        assert out["vulnerability_name"] == "Acme Widget Server RCE"
        assert out["required_action"].startswith("Apply")
        assert out["date_added"] == "2024-01-15T00:00:00+00:00"
        assert out["due_date"] == "2024-02-05T00:00:00+00:00"
        assert out["known_ransomware_use"] == "Known"
        assert out["cwes"] == ["CWE-78"]
        assert "ransomware-linked" in out["tags"]

    def test_normalize_entry_unknown_ransomware_no_tag(self):
        out = _normalize_entry(_MOCK["vulnerabilities"][1])
        assert out["known_ransomware_use"] == "Unknown"
        assert "ransomware-linked" not in out["tags"]

    def test_normalize_entry_missing_cveid_skipped(self):
        assert _normalize_entry({"vendorProject": "x"}) is None


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_parses_catalog(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, json=_MOCK)
        result = await adapter.fetch()
        assert result.source == "CISA KEV"
        assert result.tier == 1
        assert result.record_count == 2
        assert {v["cve_id"] for v in result.vulns} == {
            "CVE-2024-12345", "CVE-2017-9805"
        }

    @pytest.mark.asyncio
    async def test_no_credential_needed(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, json=_MOCK)
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
        httpx_mock.add_response(url=_MIRROR_URL, status_code=503)
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch()

    @pytest.mark.asyncio
    async def test_malformed_body_raises_non_valueerror(
        self, adapter, httpx_mock: HTTPXMock
    ):
        # A malformed upstream body is an upstream problem, not a caller error:
        # it must NOT be a ValueError (which the server tool surfaces verbatim as
        # a caller mistake) so the tool degrades instead of crashing.
        httpx_mock.add_response(url=_FEED_URL, json={"no": "vulnerabilities"})
        with pytest.raises(RuntimeError, match="vulnerabilities"):
            await adapter.fetch()
        assert not isinstance(RuntimeError(), ValueError)

    @pytest.mark.asyncio
    async def test_cache_avoids_second_request(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_FEED_URL, json=_MOCK)
        await adapter.fetch()
        result = await adapter.fetch()
        assert result.record_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 429, 500, 503])
async def test_official_mirror_fallback(status, adapter, httpx_mock):
    httpx_mock.add_response(url=_FEED_URL, status_code=status)
    httpx_mock.add_response(url=_MIRROR_URL, json=_MOCK)
    result = await adapter.fetch()
    assert result.record_count == 2
    assert result.source == "CISA KEV"
    note = result.partial_failure[0]
    assert f"HTTP {status}" in note
    assert _MIRROR_URL in note and "2026.07.01" in note
    cached = await adapter.fetch()
    assert cached.partial_failure == result.partial_failure
    assert len(httpx_mock.get_requests()) == 2
    assert all("authorization" not in r.headers for r in httpx_mock.get_requests())


@pytest.mark.asyncio
async def test_timeout_fallback(adapter, httpx_mock):
    httpx_mock.add_exception(httpx.ReadTimeout("timeout"), url=_FEED_URL)
    httpx_mock.add_response(url=_MIRROR_URL, json=_MOCK)
    result = await adapter.fetch()
    assert "ReadTimeout" in result.partial_failure[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 404])
async def test_no_fallback_on_nonavailability_status(status, adapter, httpx_mock):
    httpx_mock.add_response(url=_FEED_URL, status_code=status)
    with pytest.raises(httpx.HTTPStatusError):
        await adapter.fetch()
    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [
    {"count": 99}, {"catalogVersion": ""}, {"dateReleased": "garbage"},
    {"dateReleased": "2999-01-01T00:00:00Z"},
    {"dateReleased": "2026-01-01T00:00:00"}, {"vulnerabilities": {}},
])
async def test_bad_mirror_not_cached(override, adapter, httpx_mock):
    httpx_mock.add_response(url=_FEED_URL, status_code=403)
    httpx_mock.add_response(url=_MIRROR_URL, json={**_MOCK, **override})
    with pytest.raises(RuntimeError):
        await adapter.fetch()
    assert not adapter._cache

"""Tests for the OSV.dev CVE enrichment adapter.

Uses pytest-httpx — no live network in CI.

The load-bearing uncertainty in this adapter is whether ``/v1/vulns/{id}``
accepts a CVE id at all: OSV's FAQ says yes, an issue in the same repository
says "Bug not found". ``api.osv.dev`` is unreachable from the development
sandbox, so this file cannot settle it — but it does assert the behaviour that
makes a wrong guess fail loudly instead of quietly, which is the lesson #203
cost.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.adapters.osv import MAX_CVES_PER_CALL, OSVAdapter, _normalize_record

_API = "https://api.osv.dev/v1/vulns"


def _record(osv_id="GHSA-jfh8-c2jp-5v3q", cve="CVE-2021-44228"):
    """Shaped after the OSV schema (ossf/osv-schema)."""
    return {
        "id": osv_id,
        "summary": "Remote code execution in Log4j",
        "published": "2021-12-10T00:00:00Z",
        "modified": "2026-01-02T03:04:05Z",
        "aliases": [cve],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N"}],
        "affected": [
            {
                "package": {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                },
                "ranges": [
                    {"events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}
                ],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/" + cve}
        ],
    }


@pytest.fixture()
def adapter() -> OSVAdapter:
    return OSVAdapter(_request_delay=0)


# ─── The #203 guard ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_every_cve_404ing_raises_rather_than_reporting_zero(
    adapter, httpx_mock: HTTPXMock
):
    """This is the whole reason the adapter can be built before it is verified.

    If ``/v1/vulns/`` does not accept CVE identifiers, every lookup 404s. A
    per-CVE "not found" is ordinary — OSV only covers open-source ecosystems —
    so without this guard the adapter would report a confident, permanent "0 of
    your CVEs affect any package", which is exactly how a VirusTotal endpoint
    that never existed went unnoticed for months.
    """
    for cve in ("CVE-2021-44228", "CVE-2021-45046"):
        httpx_mock.add_response(url=f"{_API}/{cve}", status_code=404)

    with pytest.raises(UpstreamFormatError, match="404 for all 2 CVEs"):
        await adapter.enrich(["CVE-2021-44228", "CVE-2021-45046"])


@pytest.mark.asyncio
async def test_one_cve_404ing_is_an_ordinary_not_found(adapter, httpx_mock: HTTPXMock):
    """The other half. OSV genuinely has no record for CVEs in proprietary
    software, so a partial miss must not be escalated — otherwise the guard
    above fires constantly and gets muted."""
    httpx_mock.add_response(url=f"{_API}/CVE-2021-44228", json=_record())
    httpx_mock.add_response(url=f"{_API}/CVE-2000-0001", status_code=404)

    result = await adapter.enrich(["CVE-2021-44228", "CVE-2000-0001"])

    assert result["found"] == ["CVE-2021-44228"]
    assert result["not_found"] == ["CVE-2000-0001"]
    assert result["failed"] == []


# ─── Guards that hold whatever the field names turn out to be ────────────────


@pytest.mark.asyncio
async def test_a_body_without_an_id_raises(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{_API}/CVE-2021-44228", json={"vulns": []})

    with pytest.raises(RuntimeError, match="missing 'id'"):
        await adapter.enrich(["CVE-2021-44228"])


@pytest.mark.asyncio
async def test_every_lookup_failing_raises(adapter, httpx_mock: HTTPXMock):
    """A total failure must reach the caller's breaker, not look like success."""
    for cve in ("CVE-2021-44228", "CVE-2021-45046"):
        httpx_mock.add_response(url=f"{_API}/{cve}", status_code=503)

    with pytest.raises(RuntimeError, match="every OSV lookup failed"):
        await adapter.enrich(["CVE-2021-44228", "CVE-2021-45046"])


@pytest.mark.asyncio
async def test_one_bad_lookup_does_not_sink_the_rest(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{_API}/CVE-2021-44228", json=_record())
    httpx_mock.add_response(url=f"{_API}/CVE-2021-45046", status_code=503)

    result = await adapter.enrich(["CVE-2021-44228", "CVE-2021-45046"])

    assert result["found"] == ["CVE-2021-44228"]
    assert result["failed"] == ["CVE-2021-45046"]


@pytest.mark.asyncio
async def test_an_empty_list_is_a_caller_error(adapter):
    with pytest.raises(ValueError, match="No CVEs"):
        await adapter.enrich([])


@pytest.mark.asyncio
async def test_over_the_cap_refuses_rather_than_truncating(adapter, httpx_mock):
    too_many = [f"CVE-2024-{i:05d}" for i in range(MAX_CVES_PER_CALL + 1)]

    with pytest.raises(ValueError, match="exceeds the per-call cap"):
        await adapter.enrich(too_many)

    assert httpx_mock.get_requests() == []


@pytest.mark.asyncio
async def test_egress_is_restricted_to_osv(adapter):
    client = adapter._make_client()
    try:
        with pytest.raises(Exception):
            await client.get("https://evil.example.com/")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_no_credential_is_read(adapter, httpx_mock: HTTPXMock):
    import inspect

    params = list(inspect.signature(OSVAdapter.__init__).parameters)
    assert params == ["self", "_request_delay"], f"constructor grew: {params}"

    httpx_mock.add_response(url=f"{_API}/CVE-2021-44228", json=_record())
    await adapter.enrich(["CVE-2021-44228"])
    sent = httpx_mock.get_requests()[0]
    for header in ("authorization", "x-api-key", "key", "x-apikey"):
        assert header not in sent.headers


# ─── Behaviour given the OSV schema ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_affected_packages_and_fixed_versions_are_read(
    adapter, httpx_mock: HTTPXMock
):
    """The reason to call OSV at all. If this mapping is wrong the tool returns
    records that look fine and answer nothing."""
    httpx_mock.add_response(url=f"{_API}/CVE-2021-44228", json=_record())

    result = await adapter.enrich(["CVE-2021-44228"])
    record = result["enrichments"][0]

    assert record["cve"] == "CVE-2021-44228"
    assert record["osv_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert record["affected_packages"] == [
        {
            "ecosystem": "Maven",
            "name": "org.apache.logging.log4j:log4j-core",
            "fixed": ["2.15.0"],
        }
    ]
    assert record["severity"] == [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N"}
    ]
    assert record["references"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    ]
    assert record["aliases"] == ["CVE-2021-44228"]


def test_a_record_with_no_affected_packages_is_still_returned():
    """Not every advisory names a package range. The record still carries
    severity and references, so dropping it would lose real information."""
    record = _normalize_record("CVE-2021-44228", {"id": "OSV-1", "summary": "x"})

    assert record["osv_id"] == "OSV-1"
    assert "affected_packages" not in record


def test_a_range_with_no_fix_yields_no_fixed_version():
    """An unfixed vulnerability must not report an empty or invented fix."""
    body = {
        "id": "OSV-1",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "x"},
             "ranges": [{"events": [{"introduced": "0"}]}]}
        ],
    }
    record = _normalize_record("CVE-2024-0001", body)

    assert record["affected_packages"] == [{"ecosystem": "PyPI", "name": "x"}]
    assert "fixed" not in record["affected_packages"][0]


@pytest.mark.asyncio
async def test_a_repeated_cve_is_served_from_cache(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=f"{_API}/CVE-2021-44228", json=_record())

    await adapter.enrich(["CVE-2021-44228"])
    await adapter.enrich(["CVE-2021-44228"])

    assert len(httpx_mock.get_requests()) == 1

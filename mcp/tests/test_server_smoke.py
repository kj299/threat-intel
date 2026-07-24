"""Smoke tests for the MCP server wiring.

Nothing else imports ``server.py`` — the adapter/fan-out/resilience suites all
target the layers beneath it, so a wiring mistake in the tool layer (a missing
registration, a mis-tiered source, a tool that crashes instead of degrading)
would only surface at runtime. These tests exercise the assembled server.
"""

from __future__ import annotations

import inspect
import re

import pytest
from pytest_httpx import HTTPXMock

import threat_intel_mcp.server as server

# Feeds that require a credential: with none configured, the tool short-circuits
# before any HTTP request.
_CREDENTIALED_FEED_TOOLS = [
    "qfeeds_fetch_iocs",
    "abuseipdb_fetch_blocklist",
    "virustotal_fetch_iocs",
    "otx_fetch_iocs",
    "shodan_fetch_iocs",
    "greynoise_fetch_iocs",
    "anyrun_fetch_iocs",
    "intel471_fetch_iocs",
    "censys_fetch_iocs",
]
# Free public abuse.ch feeds: no credential, so they always attempt the network.
_PUBLIC_FEED_TOOLS = ["urlhaus_fetch_iocs", "threatfox_fetch_iocs"]
_SINGLE_FEED_TOOLS = _CREDENTIALED_FEED_TOOLS + _PUBLIC_FEED_TOOLS
# Government CVE feeds: emit CVE-keyed vuln records via a separate fan-out path.
# CISA KEV needs no credential; NVD's key is optional — both attempt the network.
_CVE_FEED_TOOLS = ["cisa_kev_fetch_cves", "nvd_fetch_cves"]
_ALL_TOOLS = (
    _SINGLE_FEED_TOOLS
    + _CVE_FEED_TOOLS
    + ["fetch_all_iocs", "fetch_all_cves", "list_available_feeds"]
)

_EXPECTED_SOURCES = {
    "Q-Feeds", "AbuseIPDB", "VirusTotal", "AlienVault OTX", "Shodan",
    "GreyNoise", "ANY.RUN", "Intel 471", "Censys", "URLhaus", "ThreatFox",
}
_EXPECTED_CVE_SOURCES = {"CISA KEV", "NVD"}

# abuse.ch public feed URLs (mocked so the public tools fail gracefully offline).
_PUBLIC_FEED_URLS = {
    "urlhaus_fetch_iocs": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "threatfox_fetch_iocs": "https://threatfox.abuse.ch/export/csv/recent/",
}
# Government CVE feed URL patterns (mocked so the CVE tools fail offline). NVD
# carries a query string, so both are matched as regexes on the endpoint prefix.
_CVE_FEED_URLS = {
    "cisa_kev_fetch_cves": re.compile(
        r"^https://www\.cisa\.gov/sites/default/files/feeds/"
        r"known_exploited_vulnerabilities\.json"
    ),
    "nvd_fetch_cves": re.compile(
        r"^https://services\.nvd\.nist\.gov/rest/json/cves/2\.0"
    ),
}

_CRED_VARS = (
    "QFEEDS_API_KEY", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY",
    "SHODAN_API_KEY", "GREYNOISE_API_KEY", "ANYRUN_API_KEY",
    "INTEL471_API_KEY", "INTEL471_EMAIL", "CENSYS_API_ID", "CENSYS_API_SECRET",
)


def test_all_tools_registered_as_coroutines():
    for name in _ALL_TOOLS:
        fn = getattr(server, name, None)
        assert fn is not None, f"tool {name} missing from server"
        assert inspect.iscoroutinefunction(fn), f"{name} is not async"


def test_feed_sources_wired_with_distinct_breakers():
    sources = server._FEED_SOURCES
    assert {s.name for s in sources} == _EXPECTED_SOURCES
    # one single-feed tool per fan-out source
    assert len(sources) == len(_SINGLE_FEED_TOOLS)
    breakers = [s.breaker for s in sources]
    assert len({id(b) for b in breakers}) == len(breakers), "breakers must be distinct"
    assert {b.name for b in breakers} == _EXPECTED_SOURCES


def test_vuln_sources_wired_with_distinct_breakers():
    sources = server._VULN_SOURCES
    assert {s.name for s in sources} == _EXPECTED_CVE_SOURCES
    assert len(sources) == len(_CVE_FEED_TOOLS)
    breakers = [s.breaker for s in sources]
    assert len({id(b) for b in breakers}) == len(breakers), "breakers must be distinct"
    # CVE breakers must be distinct objects from the IOC breakers too.
    ioc_breakers = {id(s.breaker) for s in server._FEED_SOURCES}
    assert not (ioc_breakers & {id(b) for b in breakers})


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", _CREDENTIALED_FEED_TOOLS)
async def test_credentialed_tool_degrades_without_creds_no_network(
    tool_name, httpx_mock: HTTPXMock, monkeypatch
):
    """With no credential, a credentialed tool returns a graceful degraded dict —
    never raises, never touches the network (credential checked before any HTTP)."""
    for var in _CRED_VARS:
        monkeypatch.delenv(var, raising=False)

    result = await getattr(server, tool_name)()

    assert result["coverage_ledger_entry"]["status"] == "unverified"
    assert result["record_count"] == 0
    assert result["iocs"] == []
    assert "error" in result
    assert httpx_mock.get_requests() == []  # short-circuited before HTTP


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", _PUBLIC_FEED_TOOLS)
async def test_public_tool_degrades_on_upstream_error(
    tool_name, httpx_mock: HTTPXMock
):
    """A public (no-credential) feed still degrades gracefully when the upstream
    feed is unreachable — it attempts the request, catches the failure, and
    returns a degraded dict rather than crashing."""
    httpx_mock.add_response(url=_PUBLIC_FEED_URLS[tool_name], status_code=503)

    result = await getattr(server, tool_name)()

    assert result["coverage_ledger_entry"]["status"] == "unverified"
    assert result["record_count"] == 0
    assert "error" in result
    assert len(httpx_mock.get_requests()) == 1  # it DID attempt the network


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", _CVE_FEED_TOOLS)
async def test_cve_tool_degrades_on_upstream_error(
    tool_name, httpx_mock: HTTPXMock, monkeypatch
):
    """A CVE feed tool degrades gracefully when the upstream is unreachable: it
    returns a vuln-shaped degraded dict (vulns=[], unverified) rather than
    crashing. NVD's key is optional, so with no key it still attempts the
    network."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    httpx_mock.add_response(url=_CVE_FEED_URLS[tool_name], status_code=503)

    result = await getattr(server, tool_name)()

    assert result["coverage_ledger_entry"]["status"] == "unverified"
    assert result["record_count"] == 0
    assert result["vulns"] == []
    assert "error" in result
    assert len(httpx_mock.get_requests()) >= 1  # it DID attempt the network


@pytest.mark.asyncio
async def test_cisa_kev_tool_degrades_on_malformed_body(httpx_mock: HTTPXMock):
    """A 200 response with an unexpected shape (e.g. CISA serves an error page or
    changes the schema) must degrade gracefully, not raise — the same
    never-crash contract every single-feed tool honors. Guards against the
    adapter's parse error being a ValueError (which the tool surfaces verbatim)."""
    httpx_mock.add_response(
        url=_CVE_FEED_URLS["cisa_kev_fetch_cves"], json={"unexpected": "shape"}
    )

    result = await server.cisa_kev_fetch_cves()

    assert result["coverage_ledger_entry"]["status"] == "unverified"
    assert result["record_count"] == 0
    assert result["vulns"] == []
    assert "error" in result


@pytest.mark.asyncio
async def test_fetch_all_cves_fans_out_coherently(httpx_mock: HTTPXMock, monkeypatch):
    """fetch_all_cves fans out across the government CVE feeds and returns a
    coherent vuln result. Served empty catalogs, both come back 'consulted' with
    zero records, and each appears once in the Coverage Ledger."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    httpx_mock.add_response(
        url=_CVE_FEED_URLS["cisa_kev_fetch_cves"],
        json={"vulnerabilities": []},
    )
    httpx_mock.add_response(
        url=_CVE_FEED_URLS["nvd_fetch_cves"],
        json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []},
    )

    result = await server.fetch_all_cves()

    assert result["record_count"] == 0
    assert set(result["sources_consulted"]) == _EXPECTED_CVE_SOURCES
    assert result["sources_degraded"] == []
    assert {e["source"] for e in result["coverage_ledger"]} == _EXPECTED_CVE_SOURCES


@pytest.mark.asyncio
async def test_fetch_all_iocs_fans_out_coherently(httpx_mock: HTTPXMock, monkeypatch):
    """fetch_all_iocs fans out across every source and returns a coherent result
    without crashing. With no credentials, the nine credentialed sources degrade
    to 'unverified' (no network); the two public feeds need no key, so — served
    an empty feed here — they come back 'consulted' with zero records. Every
    source appears in the Coverage Ledger exactly once."""
    for var in _CRED_VARS:
        monkeypatch.delenv(var, raising=False)
    for url in _PUBLIC_FEED_URLS.values():
        httpx_mock.add_response(url=url, text="# empty feed\n")

    result = await server.fetch_all_iocs()

    assert result["record_count"] == 0
    assert set(result["sources_consulted"]) == {"URLhaus", "ThreatFox"}
    degraded = {d["source"] for d in result["sources_degraded"]}
    assert degraded == _EXPECTED_SOURCES - {"URLhaus", "ThreatFox"}
    assert {e["source"] for e in result["coverage_ledger"]} == _EXPECTED_SOURCES


@pytest.mark.asyncio
async def test_list_available_feeds_reports_all_sources():
    result = await server.list_available_feeds()
    names = {f["name"] for f in result["feeds"]}
    assert names == _EXPECTED_SOURCES
    tools = {f["tool"] for f in result["feeds"]}
    assert tools == set(_SINGLE_FEED_TOOLS)


@pytest.mark.asyncio
async def test_list_available_feeds_reports_cve_sources_separately():
    result = await server.list_available_feeds()
    # CVE feeds live under their own key, not mixed into the IOC ``feeds`` list.
    names = {f["name"] for f in result["cve_sources"]}
    assert names == _EXPECTED_CVE_SOURCES
    tools = {f["tool"] for f in result["cve_sources"]}
    assert tools == set(_CVE_FEED_TOOLS)
    assert result["cve_aggregate_tool"] == "fetch_all_cves"
    # CVE sources must not leak into the IOC feed list.
    assert _EXPECTED_CVE_SOURCES.isdisjoint({f["name"] for f in result["feeds"]})

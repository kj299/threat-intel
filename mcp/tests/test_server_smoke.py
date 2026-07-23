"""Smoke tests for the MCP server wiring.

Nothing else imports ``server.py`` — the adapter/fan-out/resilience suites all
target the layers beneath it, so a wiring mistake in the tool layer (a missing
registration, a mis-tiered source, a tool that crashes instead of degrading)
would only surface at runtime. These tests exercise the assembled server.
"""

from __future__ import annotations

import inspect

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
_ALL_TOOLS = _SINGLE_FEED_TOOLS + ["fetch_all_iocs", "list_available_feeds"]

_EXPECTED_SOURCES = {
    "Q-Feeds", "AbuseIPDB", "VirusTotal", "AlienVault OTX", "Shodan",
    "GreyNoise", "ANY.RUN", "Intel 471", "Censys", "URLhaus", "ThreatFox",
}

# abuse.ch public feed URLs (mocked so the public tools fail gracefully offline).
_PUBLIC_FEED_URLS = {
    "urlhaus_fetch_iocs": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "threatfox_fetch_iocs": "https://threatfox.abuse.ch/export/csv/recent/",
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

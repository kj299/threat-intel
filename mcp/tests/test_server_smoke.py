"""Smoke tests for the MCP server wiring.

Nothing else imports ``server.py`` — the adapter/fan-out/resilience suites all
target the layers beneath it, so a wiring mistake in the tool layer (a missing
registration, a mis-tiered source, a tool that crashes instead of degrading on a
missing credential) would only surface at runtime. These tests exercise the
assembled server.
"""

from __future__ import annotations

import inspect

import pytest
from pytest_httpx import HTTPXMock

import threat_intel_mcp.server as server

_SINGLE_FEED_TOOLS = [
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
_ALL_TOOLS = _SINGLE_FEED_TOOLS + ["fetch_all_iocs", "list_available_feeds"]

_EXPECTED_SOURCES = {
    "Q-Feeds", "AbuseIPDB", "VirusTotal", "AlienVault OTX", "Shodan",
    "GreyNoise", "ANY.RUN", "Intel 471", "Censys",
}


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
    # a breaker per source, named for it
    assert {b.name for b in breakers} == _EXPECTED_SOURCES


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", _SINGLE_FEED_TOOLS)
async def test_tool_degrades_gracefully_without_credentials(
    tool_name, httpx_mock: HTTPXMock, monkeypatch
):
    """With no credentials configured, every single-feed tool returns a graceful
    degraded dict — never raises, never touches the network (credential is
    checked before any request)."""
    # ensure no adapter finds a key in the environment
    for var in (
        "QFEEDS_API_KEY", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY",
        "SHODAN_API_KEY", "GREYNOISE_API_KEY", "ANYRUN_API_KEY",
        "INTEL471_API_KEY", "INTEL471_EMAIL", "CENSYS_API_ID", "CENSYS_API_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)

    result = await getattr(server, tool_name)()

    assert result["coverage_ledger_entry"]["status"] == "unverified"
    assert result["record_count"] == 0
    assert result["iocs"] == []
    assert "error" in result
    # credential missing -> short-circuit before any HTTP
    assert httpx_mock.get_requests() == []


@pytest.mark.asyncio
async def test_fetch_all_iocs_degrades_all_sources_without_credentials(
    httpx_mock: HTTPXMock, monkeypatch
):
    """fetch_all_iocs must fan out across all nine sources and return a coherent
    result with every source degraded (no creds), never crashing."""
    for var in (
        "QFEEDS_API_KEY", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY",
        "SHODAN_API_KEY", "GREYNOISE_API_KEY", "ANYRUN_API_KEY",
        "INTEL471_API_KEY", "INTEL471_EMAIL", "CENSYS_API_ID", "CENSYS_API_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)

    result = await server.fetch_all_iocs()

    assert result["record_count"] == 0
    assert result["sources_consulted"] == []
    assert {d["source"] for d in result["sources_degraded"]} == _EXPECTED_SOURCES
    assert {e["source"] for e in result["coverage_ledger"]} == _EXPECTED_SOURCES
    assert httpx_mock.get_requests() == []


@pytest.mark.asyncio
async def test_list_available_feeds_reports_all_nine():
    result = await server.list_available_feeds()
    names = {f["name"] for f in result["feeds"]}
    assert names == _EXPECTED_SOURCES
    # each feed advertises its dedicated tool
    tools = {f["tool"] for f in result["feeds"]}
    assert tools == set(_SINGLE_FEED_TOOLS)

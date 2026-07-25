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


@pytest.fixture(autouse=True)
def _reset_adapter_state():
    """Isolate tests from the module-level adapter singletons.

    ``server.py`` builds one adapter instance per feed at import time, each with
    an in-process cache, and one circuit breaker per source. Without a reset, a
    test that warms a cache (e.g. the malformed-body sweep, which fetches every
    feed) would leak a cached result into a later test that expects the feed to
    be unconfigured — and a test that trips a breaker would leak an open circuit.
    Clear both before every test so ordering never matters.
    """
    sources = server._FEED_SOURCES + server._VULN_SOURCES
    for s in sources:
        cache = getattr(s.adapter, "_cache", None)
        if isinstance(cache, dict):
            cache.clear()
        s.breaker.record_success()
    # The VirusTotal singleton carries a real 15s inter-request rate-limit sleep;
    # smoke tests exercise wiring, not throughput, so drop it (test_virustotal.py
    # builds its own instances and is unaffected).
    server._virustotal._rate_limit_delay = 0
    yield

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
_PUBLIC_FEED_TOOLS = ["threatfox_fetch_iocs"]
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
    "GreyNoise", "ANY.RUN", "Intel 471", "Censys", "ThreatFox",
}
_EXPECTED_CVE_SOURCES = {"CISA KEV", "NVD"}

# abuse.ch public feed URLs (mocked so the public tools fail gracefully offline).
_PUBLIC_FEED_URLS = {
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


# Every single-feed tool — IOC and CVE — must honour the never-crash contract.
_ALL_SINGLE_FEED_TOOLS = _SINGLE_FEED_TOOLS + _CVE_FEED_TOOLS
# Dummy credentials so credentialed tools get past their fail-fast key check and
# actually reach the (mocked) network, exercising their body-parsing path.
_ALL_CRED_VARS = _CRED_VARS + ("NVD_API_KEY",)


@pytest.mark.asyncio
@pytest.mark.httpx_mock(
    assert_all_responses_were_requested=False,
    can_send_already_matched_responses=True,
)
@pytest.mark.parametrize("tool_name", _ALL_SINGLE_FEED_TOOLS)
async def test_single_feed_tool_degrades_on_malformed_body(
    tool_name, httpx_mock: HTTPXMock, monkeypatch
):
    """Contract guard (the bug this sweep was written for): a 200 response with an
    unexpected body shape must DEGRADE, never raise, out of any single-feed tool.

    An adapter that raises ``ValueError`` for a malformed upstream body would be
    re-raised verbatim by its tool (``ValueError`` is reserved for caller errors)
    and crash the call instead of degrading — see adapters/base.py's error
    taxonomy. A catch-all mock returns ``{}`` (valid JSON, wrong shape) for every
    request; reuse is enabled so paginating adapters get it on each page."""
    for var in _ALL_CRED_VARS:
        monkeypatch.setenv(var, "dummy-value-for-test")
    httpx_mock.add_response(url=re.compile(r"https://.+"), json={})

    # The bare await IS the core assertion: if the tool raises (the bug class),
    # the test errors. A malformed body must yield a well-formed tool dict — the
    # record count is unconstrained (a plain-text feed may parse "{}" as one junk
    # line; what matters is it did not crash on an unexpected shape).
    result = await getattr(server, tool_name)()

    assert isinstance(result, dict)
    assert "coverage_ledger_entry" in result
    assert isinstance(result["record_count"], int)


@pytest.mark.asyncio
@pytest.mark.httpx_mock(
    assert_all_responses_were_requested=False,
    can_send_already_matched_responses=True,
)
@pytest.mark.parametrize("tool_name", _ALL_SINGLE_FEED_TOOLS)
async def test_malformed_body_is_marked_unverified_not_reported_as_zero(
    tool_name, httpx_mock: HTTPXMock, monkeypatch
):
    """The other half of the contract above (#106).

    The sweep before this one asserts a tool does not *crash* on an unreadable
    body. That is necessary but not sufficient: before the empty-parse guards,
    most tools answered ``{}`` with ``record_count: 0`` and an ``ok`` ledger
    entry — a confident zero, indistinguishable from a quiet week, which is
    exactly how a 1 MB ThreatFox response parsed to nothing without anyone
    noticing (#100).

    A body we cannot read must reach the ledger as ``unverified``."""
    for var in _ALL_CRED_VARS:
        monkeypatch.setenv(var, "dummy-value-for-test")
    httpx_mock.add_response(url=re.compile(r"https://.+"), json={})

    result = await getattr(server, tool_name)()

    assert result["coverage_ledger_entry"]["status"] == "unverified", (
        f"{tool_name} reported a malformed body as "
        f"{result['coverage_ledger_entry']['status']!r} with "
        f"record_count={result['record_count']} — a confident zero"
    )
    assert result["record_count"] == 0
    assert result.get("error")


# Tools whose adapter validates feed_types and raises ValueError on an unknown
# one. (abuseipdb_fetch_blocklist and otx_fetch_iocs accept feed_types for
# interface compatibility and ignore them, so they are correctly excluded.)
_FEED_TYPE_VALIDATING_TOOLS = [
    "qfeeds_fetch_iocs",
    "virustotal_fetch_iocs",
    "shodan_fetch_iocs",
    "greynoise_fetch_iocs",
    "anyrun_fetch_iocs",
    "intel471_fetch_iocs",
    "censys_fetch_iocs",
    "threatfox_fetch_iocs",
    "cisa_kev_fetch_cves",
    "nvd_fetch_cves",
]


@pytest.mark.asyncio
@pytest.mark.httpx_mock(
    assert_all_responses_were_requested=False,
    can_send_already_matched_responses=True,
)
@pytest.mark.parametrize("tool_name", _ALL_SINGLE_FEED_TOOLS)
async def test_single_feed_tool_degrades_on_upstream_http_error(
    tool_name, httpx_mock: HTTPXMock, monkeypatch
):
    """Every single-feed tool degrades gracefully when its upstream returns 5xx.

    Credentials are supplied so credentialed tools get past their fail-fast key
    check and actually exercise the upstream-error branch — without them they
    short-circuit on the credential path and this contract goes untested (which
    is precisely how it was: only the public feeds had 5xx coverage).
    """
    for var in _ALL_CRED_VARS:
        monkeypatch.setenv(var, "dummy-value-for-test")
    httpx_mock.add_response(url=re.compile(r"https://.+"), status_code=503)

    result = await getattr(server, tool_name)()

    assert result["coverage_ledger_entry"]["status"] == "unverified"
    assert result["record_count"] == 0
    assert "error" in result and result["error"], "degraded result must explain itself"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", _FEED_TYPE_VALIDATING_TOOLS)
async def test_tool_raises_on_invalid_feed_types(tool_name, httpx_mock: HTTPXMock, monkeypatch):
    """The other half of the error taxonomy: a *caller* error must RAISE.

    The malformed-body sweep above asserts tools never raise on bad data from
    upstream. This asserts the inverse for bad input from the caller: an unknown
    feed_type is a ValueError the tool re-raises verbatim, so the mistake
    surfaces instead of being silently degraded into an 'unverified' ledger
    entry that looks like an outage. See adapters/base.py's error taxonomy.
    """
    for var in _ALL_CRED_VARS:
        monkeypatch.setenv(var, "dummy-value-for-test")

    with pytest.raises(ValueError, match="[Ff]eed_type"):
        await getattr(server, tool_name)(feed_types=["definitely-not-a-real-feed-type"])

    assert httpx_mock.get_requests() == [], "must fail before any network call"


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
    to 'unverified' (no network); the public feed needs no key, so — served
    an empty feed here — it comes back 'consulted' with zero records. Every
    source appears in the Coverage Ledger exactly once."""
    for var in _CRED_VARS:
        monkeypatch.delenv(var, raising=False)
    for url in _PUBLIC_FEED_URLS.values():
        httpx_mock.add_response(url=url, text="# empty feed\n")

    result = await server.fetch_all_iocs()

    assert result["record_count"] == 0
    assert set(result["sources_consulted"]) == {"ThreatFox"}
    degraded = {d["source"] for d in result["sources_degraded"]}
    assert degraded == _EXPECTED_SOURCES - {"ThreatFox"}
    assert {e["source"] for e in result["coverage_ledger"]} == _EXPECTED_SOURCES


@pytest.mark.asyncio
async def test_list_available_feeds_reports_all_sources():
    result = await server.list_available_feeds()
    names = {f["name"] for f in result["feeds"]}
    assert names == _EXPECTED_SOURCES
    tools = {f["tool"] for f in result["feeds"]}
    assert tools == set(_SINGLE_FEED_TOOLS)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "iocs,expected",
    [
        ([{"type": "IPv4", "value": "203.0.113.7", "confidence": "High", "source": "Q-Feeds"}], "partial"),
        ([], "unverified"),
    ],
)
async def test_partial_failure_maps_to_partial_or_unverified(iocs, expected, monkeypatch):
    """A feed that partly failed must not be reported as fully 'consulted'.

    When some feed_types succeed and others fail, the Coverage Ledger has to say
    so: 'partial' when usable records came back, 'unverified' when none did.
    Reporting either as 'consulted' would inflate the coverage badge (R4) on
    data the source didn't actually supply in full.
    """
    from threat_intel_mcp.adapters.base import FetchResult

    async def fake_fetch(*, time_range="7d", feed_types=None):
        return FetchResult(
            iocs=list(iocs), source="Q-Feeds", tier=2,
            retrieved_at="2026-07-25T00:00:00+00:00", record_count=len(iocs),
            latency_ms=1.0, feed_types_fetched=["malware_ip"],
            partial_failure=["malware_domains"],
        )

    monkeypatch.setattr(server._qfeeds, "fetch", fake_fetch)
    result = await server.qfeeds_fetch_iocs()

    assert result["coverage_ledger_entry"]["status"] == expected
    assert result["partial_failure"] == ["malware_domains"]


@pytest.mark.asyncio
async def test_list_available_feeds_reports_credentials_as_configured(monkeypatch):
    """With credentials present, multi-key feeds report configured.

    Intel 471 and Censys each need *two* values; the second lookup only runs
    when the first succeeds, so this path is unreachable in the no-credential
    tests above.
    """
    for var in _ALL_CRED_VARS:
        monkeypatch.setenv(var, "dummy-value-for-test")

    result = await server.list_available_feeds()
    configured = {f["name"] for f in result["feeds"] if f["credential_configured"]}

    assert {"Intel 471", "Censys"} <= configured
    assert configured == _EXPECTED_SOURCES, "every feed should read as configured here"


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

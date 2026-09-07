"""The single-feed tools' *success* paths (issue #82).

``test_server_smoke.py`` proves every tool **degrades** correctly — malformed
body, missing credential, tripped breaker. It never once drives a tool through
a fetch that *works*. So the block every tool ends with —

    deduped = finalize_iocs(result.iocs)
    status = "consulted"
    if result.partial_failure:
        status = "partial" if deduped else "unverified"
    return {...}

— sat uncovered across all twelve tools, and ``server.py`` sat at 82% against
#82's 90% target for a month. That is the layer where a feed's live records are
handed to the skill; the ``consulted``/``partial``/``unverified`` status it
emits is what Appendix A's Coverage Ledger is built from.

Each test patches the adapter's ``fetch`` and drives the tool, so the assertion
is on the tool's own wiring — status arithmetic, finalisation, the returned
shape — rather than on any adapter, which have their own suites.
"""

from __future__ import annotations

import pytest

import threat_intel_mcp.server as server
from threat_intel_mcp.adapters.base import FetchResult
from threat_intel_mcp.vault.base import CredentialError
from threat_intel_mcp.vulns import VulnFetchResult

# ── fixtures ────────────────────────────────────────────────────────────────

# RFC 5737 documentation range and a reserved TLD: values that pass the
# ioc_network schema and can never be mistaken for a real indicator.
_IOCS = [
    {"type": "IPv4", "value": "198.51.100.7", "confidence": "High", "source": "fixture"},
    {"type": "Domain", "value": "c2.example.invalid", "confidence": "Medium", "source": "fixture"},
]
_VULNS = [
    {"cve_id": "CVE-2024-0001", "source": "fixture", "exploit_status": "known_exploited"},
]


def _ioc_result(iocs: list, partial: list | None = None) -> FetchResult:
    return FetchResult(
        iocs=iocs,
        source="fixture",
        tier=9,
        retrieved_at="2026-09-02T00:00:00+00:00",
        record_count=len(iocs),
        latency_ms=1.0,
        feed_types_fetched=["x"],
        partial_failure=partial or [],
    )


def _vuln_result(vulns: list, partial: list | None = None) -> VulnFetchResult:
    return VulnFetchResult(
        vulns=vulns,
        source="fixture",
        tier=1,
        retrieved_at="2026-09-02T00:00:00+00:00",
        record_count=len(vulns),
        latency_ms=1.0,
        feed_types_fetched=["x"],
        partial_failure=partial or [],
    )


# AbuseIPDB is one endpoint returning one list: its adapter ignores `feed_types`
# and `partial_failure` is empty by construction, so the tool hardcodes
# `consulted` rather than computing a partial status it can never reach. The
# partial/unverified tests below skip it for that reason — forcing the status
# block onto it would be a test that exists to make coverage tidy, not to assert
# a behaviour the feed can exhibit.
_SINGLE_ENDPOINT_TOOLS = {"abuseipdb_fetch_blocklist"}

# Tool name -> the module-level adapter singleton it calls.
_IOC_TOOLS = {
    "qfeeds_fetch_iocs": "_qfeeds",
    "abuseipdb_fetch_blocklist": "_abuseipdb",
    "otx_fetch_iocs": "_otx",
    "shodan_fetch_iocs": "_shodan",
    "greynoise_fetch_iocs": "_greynoise",
    "anyrun_fetch_iocs": "_anyrun",
    "intel471_fetch_iocs": "_intel471",
    "censys_fetch_iocs": "_censys",
    "threatfox_fetch_iocs": "_threatfox",
}
_VULN_TOOLS = {
    "cisa_kev_fetch_cves": "_cisa_kev",
    "nvd_fetch_cves": "_nvd",
}


def _patch_fetch(monkeypatch, adapter_attr: str, result):
    async def fake_fetch(**_kwargs):
        return result

    monkeypatch.setattr(getattr(server, adapter_attr), "fetch", fake_fetch)


# ── IOC tools ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("tool,adapter", sorted(_IOC_TOOLS.items()))
@pytest.mark.asyncio
async def test_ioc_tool_returns_consulted_on_a_clean_fetch(monkeypatch, tool, adapter):
    """The path a report actually takes when a feed works."""
    _patch_fetch(monkeypatch, adapter, _ioc_result(_IOCS))
    out = await getattr(server, tool)(time_range="7d")

    assert out["coverage_ledger_entry"]["status"] == "consulted"
    assert out["record_count"] == 2
    assert {i["value"] for i in out["iocs"]} == {"198.51.100.7", "c2.example.invalid"}
    assert not out.get("partial_failure")


@pytest.mark.parametrize("tool,adapter", sorted(_IOC_TOOLS.items()))
@pytest.mark.asyncio
async def test_ioc_tool_is_partial_when_some_feed_types_failed(monkeypatch, tool, adapter):
    """Records came back but a feed type failed: `partial`, and the ledger
    must see the failure list rather than a clean `consulted`."""
    if tool in _SINGLE_ENDPOINT_TOOLS:
        pytest.skip(f"{tool} is a single endpoint; partial_failure cannot occur")
    _patch_fetch(monkeypatch, adapter, _ioc_result(_IOCS, partial=["malware_domains"]))
    out = await getattr(server, tool)(time_range="7d")

    assert out["coverage_ledger_entry"]["status"] == "partial"
    assert out["record_count"] == 2
    assert out["partial_failure"] == ["malware_domains"]


@pytest.mark.parametrize("tool,adapter", sorted(_IOC_TOOLS.items()))
@pytest.mark.asyncio
async def test_ioc_tool_is_unverified_when_failures_left_nothing(monkeypatch, tool, adapter):
    """A failure list and zero survivors is `unverified` — the distinction that
    stops a feed that returned nothing usable from counting toward the badge."""
    if tool in _SINGLE_ENDPOINT_TOOLS:
        pytest.skip(f"{tool} is a single endpoint; partial_failure cannot occur")
    _patch_fetch(monkeypatch, adapter, _ioc_result([], partial=["malware_ip"]))
    out = await getattr(server, tool)(time_range="7d")

    assert out["coverage_ledger_entry"]["status"] == "unverified"
    assert out["record_count"] == 0


@pytest.mark.parametrize("tool,adapter", sorted(_IOC_TOOLS.items()))
@pytest.mark.asyncio
async def test_ioc_tool_surfaces_a_caller_error_verbatim(monkeypatch, tool, adapter):
    """`ValueError` is reserved for caller mistakes (bad `time_range`) and is
    re-raised, not degraded — the error-taxonomy contract in `adapters/base.py`.
    A degraded result here would hide a typo behind an honest-looking
    `unverified`."""

    async def bad_time_range(**_kwargs):
        raise ValueError("time_range must look like 7d")

    monkeypatch.setattr(getattr(server, adapter), "fetch", bad_time_range)
    with pytest.raises(ValueError, match="time_range"):
        await getattr(server, tool)(time_range="seven days")


# ── CVE tools ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("tool,adapter", sorted(_VULN_TOOLS.items()))
@pytest.mark.asyncio
async def test_vuln_tool_returns_consulted_on_a_clean_fetch(monkeypatch, tool, adapter):
    _patch_fetch(monkeypatch, adapter, _vuln_result(_VULNS))
    out = await getattr(server, tool)(time_range="7d")

    assert out["coverage_ledger_entry"]["status"] == "consulted"
    assert out["record_count"] == 1
    assert out["vulns"][0]["cve_id"] == "CVE-2024-0001"


@pytest.mark.parametrize("tool,adapter", sorted(_VULN_TOOLS.items()))
@pytest.mark.asyncio
async def test_vuln_tool_partial_and_unverified(monkeypatch, tool, adapter):
    _patch_fetch(monkeypatch, adapter, _vuln_result(_VULNS, partial=["recent"]))
    assert (await getattr(server, tool)(time_range="7d"))["coverage_ledger_entry"]["status"] == "partial"

    _patch_fetch(monkeypatch, adapter, _vuln_result([], partial=["recent"]))
    assert (await getattr(server, tool)(time_range="7d"))["coverage_ledger_entry"]["status"] == "unverified"


@pytest.mark.asyncio
async def test_nvd_credential_provider_failure_degrades(monkeypatch):
    """NVD's key is optional, so a *missing* key never reaches this branch —
    the adapter falls back to unauthenticated. Only a provider **failure** (a
    Vault outage) does, and it must degrade rather than crash, because the
    feed is still reachable without the key."""

    async def vault_down(**_kwargs):
        raise CredentialError("vault sealed")

    monkeypatch.setattr(server._nvd, "fetch", vault_down)
    out = await server.nvd_fetch_cves(time_range="7d")

    assert out["coverage_ledger_entry"]["status"] == "unverified"
    assert out["record_count"] == 0
    assert out["vulns"] == []

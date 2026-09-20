"""The enrichment tools' *degrade* paths (VirusTotal / EPSS / OSV).

``test_server_success_paths.py`` drives the twelve feed/CVE tools through a
working fetch; ``test_server_smoke.py`` drives them through their degrade
branches. Neither touches the three **enrichment** tools —
``virustotal_enrich_iocs``, ``epss_enrich_cves`` and ``osv_enrich_cves`` — which
are wired differently: they score indicators the caller already holds rather
than discovering any, so they are absent from the fan-out and from both
parametrized suites. Their ``try/except`` blocks (``server.py`` 402-421,
462-479, 505-523) sat uncovered as a result.

Those blocks are the error-taxonomy contract from ``adapters/base.py`` applied
at the tool layer:

* ``ValueError`` is a **caller** error (bad ``indicator_type``, empty list, over
  the per-call cap) and is re-raised verbatim, never degraded — degrading it
  would hide a typo behind an honest-looking empty result.
* ``CredentialError`` / ``KeyError`` (VirusTotal only; EPSS and OSV are keyless)
  degrade to an empty verdict naming the missing key.
* Anything else — an upstream/transient failure — degrades to an empty verdict
  that still reports which indicators went unanswered, so the skill can mark
  them ``unverified`` rather than crash mid-report.

Each test patches the adapter's ``enrich`` and drives the tool, asserting on the
tool's own wiring rather than on any adapter, which have their own suites.
"""

from __future__ import annotations

import pytest

import threat_intel_mcp.server as server
from threat_intel_mcp.vault.base import CredentialError

_INDICATORS = ["198.51.100.7", "203.0.113.9"]
_CVES = ["CVE-2021-44228", "CVE-2024-0001"]


def _patch_enrich(monkeypatch, adapter_attr: str, boom: BaseException):
    async def fake_enrich(*_args, **_kwargs):
        raise boom

    monkeypatch.setattr(getattr(server, adapter_attr), "enrich", fake_enrich)


def _patch_enrich_ok(monkeypatch, adapter_attr: str, value: dict):
    async def fake_enrich(*_args, **_kwargs):
        return value

    monkeypatch.setattr(getattr(server, adapter_attr), "enrich", fake_enrich)


# ── VirusTotal ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("exc", [CredentialError("vault sealed"), KeyError("VIRUSTOTAL_API_KEY")])
@pytest.mark.asyncio
async def test_virustotal_missing_credential_degrades(monkeypatch, exc):
    """A missing/unreadable key degrades to an empty verdict that names the
    env var, and reports every indicator as ``failed`` rather than silently
    dropping them."""
    _patch_enrich(monkeypatch, "_virustotal", exc)
    out = await server.virustotal_enrich_iocs(_INDICATORS, indicator_type="ip")

    assert out["enrichments"] == []
    assert out["source"] == "VirusTotal"
    assert out["record_count"] == 0
    assert out["failed"] == _INDICATORS
    assert "VIRUSTOTAL_API_KEY" in out["error"]


@pytest.mark.asyncio
async def test_virustotal_upstream_failure_degrades(monkeypatch):
    """An upstream/transient error degrades and reports the unanswered
    indicators, so the report marks them unverified instead of crashing."""
    _patch_enrich(monkeypatch, "_virustotal", RuntimeError("502 from vt"))
    out = await server.virustotal_enrich_iocs(_INDICATORS, indicator_type="ip")

    assert out["enrichments"] == []
    assert out["source"] == "VirusTotal"
    assert out["failed"] == _INDICATORS
    assert out["error"].startswith("upstream lookup failed")
    # The upstream branch must not masquerade as the credential branch.
    assert "VIRUSTOTAL_API_KEY" not in out["error"]


@pytest.mark.asyncio
async def test_virustotal_caller_error_reraised(monkeypatch):
    """``ValueError`` is a caller mistake and is surfaced verbatim, not
    degraded."""
    _patch_enrich(monkeypatch, "_virustotal", ValueError("indicator_type must be ip or domain"))
    with pytest.raises(ValueError, match="indicator_type"):
        await server.virustotal_enrich_iocs(_INDICATORS, indicator_type="carrier-pigeon")


# ── EPSS (keyless) ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_epss_returns_the_adapter_result_on_success(monkeypatch):
    """The success path returns the adapter's result verbatim — no re-wrapping,
    which is what keeps `scored`/`not_scored` intact for the caller."""
    sentinel = {"source": "EPSS", "enrichments": [{"cve": "CVE-2021-44228"}], "scored": ["CVE-2021-44228"]}
    _patch_enrich_ok(monkeypatch, "_epss", sentinel)
    assert await server.epss_enrich_cves(_CVES) is sentinel


@pytest.mark.asyncio
async def test_epss_upstream_failure_degrades(monkeypatch):
    _patch_enrich(monkeypatch, "_epss", RuntimeError("connection reset"))
    out = await server.epss_enrich_cves(_CVES)

    assert out["enrichments"] == []
    assert out["source"] == "EPSS"
    assert out["record_count"] == 0
    assert out["scored"] == []
    assert out["not_scored"] == []
    assert out["error"].startswith("upstream lookup failed")


@pytest.mark.asyncio
async def test_epss_caller_error_reraised(monkeypatch):
    _patch_enrich(monkeypatch, "_epss", ValueError("too many CVEs; cap is 100 per call"))
    with pytest.raises(ValueError, match="cap is 100"):
        await server.epss_enrich_cves(_CVES)


# ── OSV (keyless) ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_osv_returns_the_adapter_result_on_success(monkeypatch):
    """Success returns the adapter's result verbatim, preserving `found` /
    `not_found` / `failed` for the caller."""
    sentinel = {"source": "OSV", "enrichments": [{"cve": "CVE-2021-44228"}], "found": ["CVE-2021-44228"]}
    _patch_enrich_ok(monkeypatch, "_osv", sentinel)
    assert await server.osv_enrich_cves(_CVES) is sentinel


@pytest.mark.asyncio
async def test_osv_upstream_failure_degrades(monkeypatch):
    _patch_enrich(monkeypatch, "_osv", RuntimeError("osv.dev timeout"))
    out = await server.osv_enrich_cves(_CVES)

    assert out["enrichments"] == []
    assert out["source"] == "OSV"
    assert out["record_count"] == 0
    assert out["found"] == []
    assert out["not_found"] == []
    assert out["failed"] == _CVES
    assert out["error"].startswith("upstream lookup failed")


@pytest.mark.asyncio
async def test_osv_caller_error_reraised(monkeypatch):
    _patch_enrich(monkeypatch, "_osv", ValueError("too many CVEs; cap is 200 per call"))
    with pytest.raises(ValueError, match="cap is 200"):
        await server.osv_enrich_cves(_CVES)

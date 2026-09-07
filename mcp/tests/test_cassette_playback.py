"""Adapter tests against recorded feed responses (#105).

Every other adapter test in this suite runs against a payload someone wrote.
That is how ThreatFox shipped a parser that returned zero IOCs from a live 1 MB
response while its tests passed (#100): the fixtures encoded a belief about the
feed format, and the belief was wrong.

These tests run against bytes the service actually sent. They cannot agree with
a misconception, which is the whole point.

**They skip when no cassette is present.** Recording needs network egress that
CI and the dev sandbox do not have, so a missing cassette is a coverage gap, not
a broken build. Record with::

    python mcp/scripts/record_cassettes.py

Playback is offline: ``vcr_config`` uses ``record_mode="none"``, so an
unrecorded request raises rather than reaching the network. A cassette test
cannot quietly turn into a live test.
"""

from __future__ import annotations

import pytest

from tests.vcr_config import build_vcr, cassette_path, has_cassette

from threat_intel_mcp.adapters.cisa_kev import CISAKEVAdapter
from threat_intel_mcp.adapters.nvd import NVDAdapter
from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter
from threat_intel_mcp.adapters.virustotal import VirusTotalAdapter
from threat_intel_mcp.adapters.vulncheck import VulnCheckAdapter
from threat_intel_mcp.normalize import finalize_iocs
from threat_intel_mcp.vault.base import CredentialNotFoundError
from threat_intel_mcp.vulns import finalize_vulns


class _NoKeyCredentials:
    """Provider with no NVD key — the optional-credential path.

    It must raise ``CredentialNotFoundError``, not a bare ``KeyError``. The two
    are not interchangeable even though the former subclasses the latter: per
    the taxonomy in ``adapters/base.py``, NVD falls back to unauthenticated
    access only for a *not-found* key, while any other provider failure
    propagates so a Vault outage is never silently downgraded.

    Raising a plain ``KeyError`` here made the first cassette recording fail its
    playback gate — the adapter correctly read it as a provider outage. Matches
    ``NoKeyCredentials`` in ``test_nvd.py``; keep them in step.
    """

    def get(self, adapter_name: str, key: str) -> str:
        raise CredentialNotFoundError((adapter_name, key))


def _requires(name: str):
    return pytest.mark.skipif(
        not has_cassette(name),
        reason=(
            f"no cassette at {cassette_path(name)} — record one with "
            "`python mcp/scripts/record_cassettes.py` from a host with egress"
        ),
    )


async def _play(name: str, adapter, **kwargs):
    with build_vcr().use_cassette(str(cassette_path(name))):
        return await adapter.fetch(**kwargs)


@_requires("threatfox")
@pytest.mark.asyncio
async def test_threatfox_parses_the_real_feed():
    """The regression that motivated all of this.

    Against the live CSV the adapter returned 0 records for an unknown length
    of time. A non-zero count here is the assertion that matters.
    """
    result = await _play("threatfox", ThreatFoxAdapter(), time_range="7d")

    assert result.record_count > 0, (
        "ThreatFox parsed the recorded feed to zero records — the exact failure "
        "of #100. The CSV dialect or column layout has probably changed again."
    )
    assert {i["type"] for i in result.iocs} <= {"IPv4", "IPv6", "Domain", "URL"}
    assert all(i["source"] == "ThreatFox" for i in result.iocs)
    # Values must be free of the stray quote characters the pre-#100 dialect left.
    assert not any(i["value"].startswith('"') for i in result.iocs)


@_requires("threatfox")
@pytest.mark.asyncio
async def test_threatfox_output_survives_the_real_pipeline():
    """Parsing is not enough — the records must also clear sanitize + validate.

    An adapter can emit plausible dicts that ``finalize_iocs`` then drops, which
    would show up as a healthy adapter and an empty report.
    """
    result = await _play("threatfox", ThreatFoxAdapter(), time_range="7d")
    finalized = finalize_iocs(result.iocs)

    assert finalized, "every recorded ThreatFox IOC was dropped by finalize_iocs"
    # Some loss is legitimate (dedup, sanitiser rejects); wholesale loss is not.
    assert len(finalized) >= len(result.iocs) * 0.5


@_requires("cisa_kev")
@pytest.mark.asyncio
async def test_cisa_kev_parses_the_real_catalog():
    result = await _play("cisa_kev", CISAKEVAdapter(), time_range="7d")

    assert result.record_count > 0
    assert all(v["cve_id"].startswith("CVE-") for v in result.vulns)
    assert all(v["exploit_status"] == "known_exploited" for v in result.vulns)


@_requires("cisa_kev")
@pytest.mark.asyncio
async def test_cisa_kev_output_survives_the_real_pipeline():
    result = await _play("cisa_kev", CISAKEVAdapter(), time_range="7d")
    assert finalize_vulns(result.vulns)


@_requires("nvd")
@pytest.mark.asyncio
async def test_nvd_parses_the_real_response():
    result = await _play("nvd", NVDAdapter(_NoKeyCredentials()), time_range="7d")

    assert result.record_count > 0
    assert all(v["cve_id"].startswith("CVE-") for v in result.vulns)


@_requires("nvd")
@pytest.mark.asyncio
async def test_nvd_output_survives_the_real_pipeline():
    result = await _play("nvd", NVDAdapter(_NoKeyCredentials()), time_range="7d")
    assert finalize_vulns(result.vulns)


class _StubToken:
    """VulnCheck requires a credential; the cassette replaces the network, but
    the adapter still resolves a token before making the request."""

    def get(self, adapter_name: str, key: str) -> str:
        return "recorded-playback-token"


@_requires("vulncheck")
@pytest.mark.asyncio
async def test_vulncheck_parses_the_real_catalog():
    """The test this adapter was written to be corrected by.

    Its first draft was authored from published SDK signatures with no response
    ever observed, and this recording found two real defects: no pagination at
    all (1,000 of 5,229 entries), and four dropped fields.
    """
    result = await _play("vulncheck", VulnCheckAdapter(_StubToken()), time_range="7d")

    assert result.record_count > 0
    assert all(v["cve_id"].startswith("CVE-") for v in result.vulns)
    assert all(v["exploit_status"] == "known_exploited" for v in result.vulns)


@_requires("vulncheck")
@pytest.mark.asyncio
async def test_vulncheck_output_survives_the_real_pipeline():
    result = await _play("vulncheck", VulnCheckAdapter(_StubToken()), time_range="7d")
    assert finalize_vulns(result.vulns)


@_requires("vulncheck")
@pytest.mark.asyncio
async def test_vulncheck_reads_the_fields_the_first_draft_dropped():
    """Pins the four fields the recording revealed as missing.

    Each is real intelligence: the CWE class, whether ransomware crews use it,
    the CISA remediation deadline, and the evidence URL behind the
    "exploited" claim. A record asserting exploitation with no reference is
    weaker than one that names its report.
    """
    result = await _play("vulncheck", VulnCheckAdapter(_StubToken()), time_range="7d")

    assert any(v.get("cwes") for v in result.vulns)
    assert any(v.get("known_ransomware_use") for v in result.vulns)
    assert any(v.get("due_date") for v in result.vulns)
    assert any(v.get("references") for v in result.vulns)


@_requires("virustotal")
@pytest.mark.asyncio
async def test_virustotal_parses_the_real_enrichment_response():
    """The recording that turned a documented shape into a verified one.

    This adapter replaced one whose endpoint did not exist and had never
    returned an indicator (#203). Its successor was written from VirusTotal's
    published object reference — better footing, but still not a response
    anyone had seen. These bytes are.
    """
    with build_vcr().use_cassette(str(cassette_path("virustotal"))):
        result = await VirusTotalAdapter(
            _StubToken(), _rate_limit_delay=0
        ).enrich(["8.8.8.8", "1.1.1.1"], indicator_type="ip")

    assert result["record_count"] == 2
    assert result["failed"] == []
    assert {e["indicator"] for e in result["enrichments"]} == {"8.8.8.8", "1.1.1.1"}


@_requires("virustotal")
@pytest.mark.asyncio
async def test_virustotal_reads_every_attribute_it_claims_to():
    """Pins the field mapping to the recorded response.

    Each of these was a guess until this recording. A silent absence here
    would leave the adapter reporting a verdict with no detections behind it,
    which reads identically to a clean indicator.
    """
    with build_vcr().use_cassette(str(cassette_path("virustotal"))):
        result = await VirusTotalAdapter(
            _StubToken(), _rate_limit_delay=0
        ).enrich(["8.8.8.8"], indicator_type="ip")

    record = result["enrichments"][0]
    for field in ("malicious", "suspicious", "harmless", "undetected"):
        assert isinstance(record[field], int), f"{field} missing from the real body"
    assert isinstance(record["reputation"], int)
    assert set(record["community_votes"]) == {"harmless", "malicious"}
    assert record["last_analysis"].startswith("20")
    # Network ownership is IP-only and is the part most likely to be renamed
    # upstream, so it is asserted by value rather than by presence.
    assert record["as_owner"] == "Google LLC"
    assert record["asn"] == 15169
    assert record["country"] == "US"


@_requires("virustotal")
@pytest.mark.asyncio
async def test_a_clean_indicator_survives_the_real_response():
    """8.8.8.8 has no detections, and that is a result rather than a gap.

    For a feed, nothing found means nothing to report. For enrichment, "no
    engine flagged this" is information — so the record must come back rather
    than being dropped as empty.
    """
    with build_vcr().use_cassette(str(cassette_path("virustotal"))):
        result = await VirusTotalAdapter(
            _StubToken(), _rate_limit_delay=0
        ).enrich(["8.8.8.8"], indicator_type="ip")

    record = result["enrichments"][0]
    assert result["record_count"] == 1
    assert record["malicious"] == 0
    # `malicious == 0` ALONE is vacuous here: _stat defaults a missing counter
    # to 0, so an unparsed stats block reads identically to a clean verdict.
    # A non-zero sibling is what separates the two, and sabotage-testing the
    # attribute name is what surfaced it.
    assert record["harmless"] > 0, "a clean verdict must be parsed, not defaulted"


def test_no_key_provider_engages_the_unauthenticated_fallback():
    """Guards the stub itself — always runs, cassette or not.

    The first cassette recording failed its playback gate because this stub
    raised a bare ``KeyError``. ``CredentialNotFoundError`` subclasses
    ``KeyError`` but not the reverse, so the adapter correctly read it as a
    provider outage and propagated instead of falling back. Without this test
    the mistake is only visible once a cassette exists, which is exactly when
    it is most expensive to discover.
    """
    assert NVDAdapter(_NoKeyCredentials())._api_key() is None


def test_cassette_directory_exists():
    """Always runs, so the harness itself cannot rot unnoticed.

    If someone removes the cassette directory, the tests above would all skip
    silently and coverage would quietly drop to nothing.
    """
    assert cassette_path("anything").parent.is_dir()

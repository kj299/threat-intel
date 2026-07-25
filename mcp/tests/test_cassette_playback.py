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

"""Live smoke checks against the real keyless feeds (#78).

**Deselected by default.** ``pyproject.toml`` sets ``addopts = -m "not live"``,
so PR CI stays fully offline. The ``live-feed-check`` workflow runs these on a
schedule with ``-m live``.

Why this exists alongside the cassettes and the empty-parse guards
------------------------------------------------------------------
Three layers, and they fail differently:

* **#105 cassettes** — prevention. Adapter parsing is tested against captured
  bytes, so a fixture cannot encode a misconception. But a cassette is a
  *snapshot*: it keeps passing after the live feed moves on.
* **#106 empty-parse guards** — at fetch time. An unreadable body degrades
  instead of publishing a confident zero. But something has to be *running* for
  that to be noticed.
* **This** — detection. Runs weekly against the real endpoints, so drift shows
  up as an alarm within days rather than whenever someone next tries a live run.

ThreatFox demonstrated the gap: the CSV dialect changed (or was always
misread), the adapter returned 0 records from a 1 MB response, and nothing
surfaced it until an operator ran the feeds by hand on a Windows box (#76,
#100). This check is what would have caught it.

Scope is the keyless feeds — ThreatFox, CISA KEV, NVD — which need no secrets,
so the check works in a fork and in a repository with no credentials
configured. Keyed feeds are deliberately out of scope: a scheduled job holding
nine live API keys is a standing liability for a check whose value is mostly in
the free ones.
"""

from __future__ import annotations

import os

import pytest

from threat_intel_mcp.adapters.abuseipdb import AbuseIPDBAdapter
from threat_intel_mcp.adapters.anyrun import AnyRunAdapter
from threat_intel_mcp.adapters.censys import CensysAdapter
from threat_intel_mcp.adapters.cisa_kev import CISAKEVAdapter
from threat_intel_mcp.adapters.greynoise import GreyNoiseAdapter
from threat_intel_mcp.adapters.intel471 import Intel471Adapter
from threat_intel_mcp.adapters.otx import OTXAdapter
from threat_intel_mcp.adapters.qfeeds import QFeedsAdapter
from threat_intel_mcp.adapters.shodan import ShodanAdapter
from threat_intel_mcp.adapters.virustotal import VirusTotalAdapter
from threat_intel_mcp.adapters.vulncheck import VulnCheckAdapter
from threat_intel_mcp.adapters.nvd import NVDAdapter
from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter
from threat_intel_mcp.normalize import finalize_iocs
from threat_intel_mcp.vault.factory import credential_provider_from_env
from threat_intel_mcp.vulns import finalize_vulns

pytestmark = pytest.mark.live

# Adapter constructors, keyed by the same name vault/env.py uses.
_IOC_ADAPTERS = {
    "qfeeds": QFeedsAdapter,
    "abuseipdb": AbuseIPDBAdapter,
    "virustotal": VirusTotalAdapter,
    "otx": OTXAdapter,
    "shodan": ShodanAdapter,
    "greynoise": GreyNoiseAdapter,
    "anyrun": AnyRunAdapter,
    "intel471": Intel471Adapter,
    "censys": CensysAdapter,
}
_CVE_ADAPTERS = {"vulncheck": VulnCheckAdapter}


class TestThreatFox:
    @pytest.mark.asyncio
    async def test_returns_records(self):
        """The #100 regression, checked against the live endpoint.

        A zero here means the CSV dialect or column layout moved again. Since
        #106 a format break raises instead of returning zero, so reaching this
        assertion with 0 means the feed was genuinely empty — which for
        ThreatFox's rolling recent-IOC export would itself be remarkable.
        """
        result = await ThreatFoxAdapter().fetch(time_range="7d")
        assert result.record_count > 0, (
            "ThreatFox returned 0 records from the live feed. Either the export "
            "is genuinely empty (unlikely for a rolling recent-IOC feed) or the "
            "CSV format has changed — see #100."
        )

    @pytest.mark.asyncio
    async def test_records_survive_the_pipeline(self):
        """Parsing is not enough — records must clear sanitize + validate.

        An adapter can emit plausible dicts that ``finalize_iocs`` then drops,
        which presents as a healthy feed and an empty report.
        """
        result = await ThreatFoxAdapter().fetch(time_range="7d")
        finalized = finalize_iocs(result.iocs)
        assert finalized, "every live ThreatFox IOC was dropped by finalize_iocs"
        assert len(finalized) >= len(result.iocs) * 0.5, (
            f"finalize_iocs dropped {len(result.iocs) - len(finalized)} of "
            f"{len(result.iocs)} live ThreatFox IOCs — more loss than dedup and "
            "sanitising should account for"
        )

    @pytest.mark.asyncio
    async def test_records_carry_the_expected_shape(self):
        result = await ThreatFoxAdapter().fetch(time_range="7d")
        assert {i["type"] for i in result.iocs} <= {"IPv4", "IPv6", "Domain", "URL"}
        assert all(i["source"] == "ThreatFox" for i in result.iocs)
        # Stray quotes would mean the CSV dialect regressed to the #100 bug.
        assert not any(i["value"].startswith('"') for i in result.iocs)


class TestCISAKEV:
    @pytest.mark.asyncio
    async def test_returns_records(self):
        result = await CISAKEVAdapter().fetch(time_range="7d")
        assert result.record_count > 0, "CISA KEV catalog came back empty"

    @pytest.mark.asyncio
    async def test_records_survive_the_pipeline(self):
        result = await CISAKEVAdapter().fetch(time_range="7d")
        assert finalize_vulns(result.vulns), "every live KEV record was dropped"

    @pytest.mark.asyncio
    async def test_records_carry_the_expected_shape(self):
        result = await CISAKEVAdapter().fetch(time_range="7d")
        assert all(v["cve_id"].startswith("CVE-") for v in result.vulns)
        assert all(v["exploit_status"] == "known_exploited" for v in result.vulns)


class TestNVD:
    """Unauthenticated. NVD works without a key at a lower rate limit, so this
    check does not depend on a secret being configured."""

    @pytest.mark.asyncio
    async def test_returns_records(self):
        result = await NVDAdapter(credential_provider_from_env()).fetch(time_range="7d")
        assert result.record_count > 0, "NVD returned no CVEs for the 7d window"

    @pytest.mark.asyncio
    async def test_records_survive_the_pipeline(self):
        result = await NVDAdapter(credential_provider_from_env()).fetch(time_range="7d")
        assert finalize_vulns(result.vulns), "every live NVD record was dropped"

    @pytest.mark.asyncio
    async def test_records_carry_the_expected_shape(self):
        result = await NVDAdapter(credential_provider_from_env()).fetch(time_range="7d")
        assert all(v["cve_id"].startswith("CVE-") for v in result.vulns)


# ─── Credentialed feeds ──────────────────────────────────────────────────────
#
# Added because the original scope note above -- "keyed feeds are deliberately
# out of scope: a scheduled job holding nine live API keys is a standing
# liability for a check whose value is mostly in the free ones" -- was written
# when this repository held no feed credentials at all. Six now exist, and the
# value has moved with them: the keyless feeds have never broken, while the
# credentialed ones produced two faults in a single day that nothing offline
# could see.
#
#   * Five secrets were named ABUSEIPDB / SHODAN / VIRUSTOTAL_API rather than
#     ABUSEIPDB_API_KEY / SHODAN_API_KEY / VIRUSTOTAL_API_KEY, so five feeds
#     reported CredentialNotFoundError for weeks while their keys sat
#     configured and unread (#197). No offline check can see repository
#     settings; only a live call can.
#   * VirusTotal's key resolves and is then REJECTED by VirusTotal -- an
#     insufficient plan, not a missing key. That is invisible to every mock,
#     cassette and parity check in this repository.
#
# The liability is also smaller than the note assumed: this is a fixed pytest
# run, not an agent, so the credentials sit in the same shape as the `prefetch`
# job in scheduled-report.yml, which holds the identical set by design.
#
# ─── The distinction that makes this worth running ───────────────────────────
#
# A feed with no credential SKIPS. A feed WITH a credential that fails FAILS.
#
# Without that split the check is noise: nine "degraded, no credential" lines
# every week, indistinguishable from a real outage, and it would be muted
# within a month. With it, a failure means exactly one thing -- a key this
# repository holds no longer works against its API -- which is the question
# #169 has been asking all along.

_CREDENTIALED_IOC_FEEDS = [
    ("Q-Feeds", "qfeeds", ("QFEEDS_API_KEY",)),
    ("AbuseIPDB", "abuseipdb", ("ABUSEIPDB_API_KEY",)),
    ("VirusTotal", "virustotal", ("VIRUSTOTAL_API_KEY",)),
    ("AlienVault OTX", "otx", ("OTX_API_KEY",)),
    ("Shodan", "shodan", ("SHODAN_API_KEY",)),
    ("GreyNoise", "greynoise", ("GREYNOISE_API_KEY",)),
    ("ANY.RUN", "anyrun", ("ANYRUN_API_KEY",)),
    ("Intel 471", "intel471", ("INTEL471_EMAIL", "INTEL471_API_KEY")),
    ("Censys", "censys", ("CENSYS_API_ID", "CENSYS_API_SECRET")),
]

_CREDENTIALED_CVE_FEEDS = [
    ("VulnCheck KEV", "vulncheck", ("VULNCHECK_API_KEY",)),
]


def _configured(env_vars: tuple[str, ...]) -> bool:
    """True when every variable this feed needs holds a non-empty value.

    Emptiness matters as much as absence: an unset GitHub Actions secret
    interpolates to an empty string rather than being absent, so a workflow
    hands the adapter `""` and it fails as an HTTP error instead of a missing
    credential. That cost 94 seconds of pointless retries and put a false reason
    in the ledger before `vault/env.py` was taught to reject it.
    """
    return all(os.environ.get(name, "").strip() for name in env_vars)


def _skip_unless_configured(name: str, env_vars: tuple[str, ...]) -> None:
    if not _configured(env_vars):
        pytest.skip(
            f"{name} has no credential configured ({', '.join(env_vars)}) — "
            "not a failure, and deliberately distinguished from one"
        )


@pytest.mark.parametrize(
    "name,adapter_key,env_vars",
    _CREDENTIALED_IOC_FEEDS,
    ids=[f[1] for f in _CREDENTIALED_IOC_FEEDS],
)
@pytest.mark.asyncio
async def test_credentialed_ioc_feed_answers_its_api(name, adapter_key, env_vars):
    """A configured IOC key must still work against its live API.

    Deliberately NOT asserting `record_count > 0`: a genuinely quiet week is a
    valid answer, and failing on it would push toward padding, which R3 forbids.
    What is asserted is that the call completed — the credential was accepted,
    the body was readable, and the empty-parse guard did not fire.
    """
    _skip_unless_configured(name, env_vars)

    adapter = _IOC_ADAPTERS[adapter_key](credential_provider_from_env())
    result = await adapter.fetch(time_range="7d")

    assert result.source == name
    assert result.record_count >= 0
    if result.iocs:
        assert finalize_iocs(result.iocs), f"every live {name} record was dropped"


@pytest.mark.parametrize(
    "name,adapter_key,env_vars",
    _CREDENTIALED_CVE_FEEDS,
    ids=[f[1] for f in _CREDENTIALED_CVE_FEEDS],
)
@pytest.mark.asyncio
async def test_credentialed_cve_feed_answers_its_api(name, adapter_key, env_vars):
    """The CVE-side counterpart. Same contract, vuln-shaped output."""
    _skip_unless_configured(name, env_vars)

    adapter = _CVE_ADAPTERS[adapter_key](credential_provider_from_env())
    result = await adapter.fetch(time_range="7d")

    assert result.source == name
    assert result.record_count >= 0
    if result.vulns:
        assert finalize_vulns(result.vulns), f"every live {name} record was dropped"

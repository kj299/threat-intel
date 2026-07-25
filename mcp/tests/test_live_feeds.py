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

import pytest

from threat_intel_mcp.adapters.cisa_kev import CISAKEVAdapter
from threat_intel_mcp.adapters.nvd import NVDAdapter
from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter
from threat_intel_mcp.normalize import finalize_iocs
from threat_intel_mcp.vault.factory import credential_provider_from_env
from threat_intel_mcp.vulns import finalize_vulns

pytestmark = pytest.mark.live


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

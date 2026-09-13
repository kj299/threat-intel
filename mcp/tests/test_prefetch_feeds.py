"""The report-path prefetch script (issue #169).

The script exists so feed credentials never reach the agent that writes the
report. These tests cover the two properties that matter: it must not leak a
credential into the file it hands over, and it must pass through the honest
per-source status rather than flattening a failed feed into silence.

No network: the fan-outs are faked.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

import prefetch_feeds  # noqa: E402


def _block(records=3, consulted=("ThreatFox",), degraded=()):
    return {
        "record_count": records,
        "sources_consulted": list(consulted),
        "sources_degraded": [
            {"source": s, "error": "CredentialNotFoundError"} for s in degraded
        ],
        "coverage_ledger": [{"tier": 9, "consulted": list(consulted)}],
    }


@pytest.fixture()
def fake_feeds(monkeypatch):
    """Replace both fan-outs; the script under test does no network work."""

    def install(iocs=None, vulns=None):
        async def fake_ioc(sources, **kwargs):
            return iocs if iocs is not None else _block()

        async def fake_vuln(sources, **kwargs):
            return vulns if vulns is not None else _block(records=2, consulted=("CISA KEV",))

        monkeypatch.setattr(prefetch_feeds, "fan_out", fake_ioc)
        monkeypatch.setattr(prefetch_feeds, "fan_out_vulns", fake_vuln)

    return install


# ─── The property the whole design exists for ────────────────────────────────


def test_a_credential_in_the_payload_refuses_to_write(tmp_path, monkeypatch, fake_feeds):
    """The agent must never receive a file containing a credential.

    Adapters put credentials in request headers, not responses, so this should
    never fire in practice — which is exactly why it is asserted rather than
    assumed. A feed that echoed its own key back would otherwise hand it
    straight to an agent that can commit files.
    """
    secret = "supersecrettoken12345"
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", secret)
    fake_feeds(iocs=_block() | {"leaked": f"seen key {secret} in response"})

    out = tmp_path / "feed-data.json"
    with pytest.raises(SystemExit) as excinfo:
        prefetch_feeds.main(["--out", str(out)])

    assert "VIRUSTOTAL_API_KEY" in str(excinfo.value)
    assert not out.exists(), "the file must not be written when a credential leaked"


def test_a_clean_payload_is_written(tmp_path, monkeypatch, fake_feeds):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "supersecrettoken12345")
    fake_feeds()

    out = tmp_path / "feed-data.json"
    assert prefetch_feeds.main(["--out", str(out)]) == 0

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["iocs"]["record_count"] == 3
    assert "supersecrettoken12345" not in out.read_text(encoding="utf-8")


def test_short_env_values_do_not_trip_the_scanner(tmp_path, monkeypatch, fake_feeds):
    """Non-vacuity in the other direction.

    A two-character value matches almost any payload, so scanning for it would
    fail every run and the guard would be turned off — the brittle-eval failure
    mode, in a security check.
    """
    monkeypatch.setenv("SHODAN_API_KEY", "ab")
    fake_feeds(iocs=_block() | {"note": "a blob containing ab somewhere"})

    out = tmp_path / "feed-data.json"
    assert prefetch_feeds.main(["--out", str(out)]) == 0


# ─── Honesty: a failed feed reaches the agent as a failure ───────────────────


def test_degraded_sources_survive_into_the_payload(tmp_path, fake_feeds):
    """A feed that failed must reach the report as `unverified` with a reason.

    Flattening it into silence is precisely the "confident report of incomplete
    data" the honesty rules exist to prevent.
    """
    fake_feeds(iocs=_block(consulted=("ThreatFox",), degraded=("VirusTotal", "Shodan")))

    out = tmp_path / "feed-data.json"
    prefetch_feeds.main(["--out", str(out)])

    degraded = json.loads(out.read_text(encoding="utf-8"))["iocs"]["sources_degraded"]
    assert {d["source"] for d in degraded} == {"VirusTotal", "Shodan"}
    assert all(d["error"] for d in degraded), "a degraded source must carry its reason"


def test_the_coverage_ledger_is_passed_through(tmp_path, fake_feeds):
    """Appendix A is built from this; summarising it away would force the agent
    to reconstruct a ledger it cannot verify."""
    fake_feeds()

    out = tmp_path / "feed-data.json"
    prefetch_feeds.main(["--out", str(out)])

    assert json.loads(out.read_text(encoding="utf-8"))["iocs"]["coverage_ledger"]


def test_a_quiet_week_is_not_an_error_by_default(tmp_path, fake_feeds):
    """R3/R4: a genuinely sparse result is the correct answer, not a failure.

    Failing the job here would push the next run toward padding.
    """
    fake_feeds(
        iocs=_block(records=0, consulted=(), degraded=()),
        vulns=_block(records=0, consulted=(), degraded=()),
    )

    assert prefetch_feeds.main(["--out", str(tmp_path / "f.json")]) == 0


def test_require_records_fails_when_every_source_degraded(tmp_path, fake_feeds):
    """Opt-in: distinguishes "nothing happened" from "nothing worked"."""
    fake_feeds(
        iocs=_block(records=0, consulted=(), degraded=("ThreatFox",)),
        vulns=_block(records=0, consulted=(), degraded=("CISA KEV",)),
    )

    rc = prefetch_feeds.main(["--out", str(tmp_path / "f.json"), "--require-records"])
    assert rc == 1


def test_the_summary_names_each_degraded_feed(fake_feeds):
    """The workflow log should answer "which keys worked" without opening the
    artifact — the question #169 exists to settle."""
    payload = {
        "iocs": _block(consulted=("ThreatFox",), degraded=("VirusTotal",)),
        "vulns": _block(records=2, consulted=("CISA KEV",)),
    }
    summary = prefetch_feeds.summarise(payload)

    assert "VirusTotal" in summary
    assert "CredentialNotFoundError" in summary


def test_sources_come_from_the_server_not_a_restated_list():
    """Imported rather than restated, so a feed added to the tool surface is
    prefetched automatically and the two cannot drift."""
    from threat_intel_mcp import server

    assert prefetch_feeds._FEED_SOURCES is server._FEED_SOURCES
    assert prefetch_feeds._VULN_SOURCES is server._VULN_SOURCES


# ─── EPSS ranking in the prefetch (#211) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_epss_scores_the_cves_the_fan_out_produced(monkeypatch):
    """The wiring, asserted rather than assumed.

    `_score_with_epss` reads `vulns["vulns"][*]["cve_id"]`. If either key is
    wrong it hands EPSS an empty list, EPSS returns nothing, and the payload
    ships without ranking — silently, and looking exactly like a week in which
    no CVE had a score. That is the same shape as the OTX bug (#204): a
    pipeline stage that does nothing and says nothing.
    """
    from scripts import prefetch_feeds

    captured: dict = {}

    class FakeEPSS:
        async def enrich(self, cves, **kwargs):
            captured["cves"] = list(cves)
            return {
                "enrichments": [
                    {"cve": cves[0], "epss": 0.9, "priority": "high"}
                ],
                "source": "EPSS",
                "record_count": 1,
                "scored": [cves[0]],
                "not_scored": list(cves[1:]),
            }

    monkeypatch.setattr(prefetch_feeds, "EPSSAdapter", FakeEPSS)

    vulns = {
        "vulns": [{"cve_id": "CVE-2021-44228"}, {"cve_id": "CVE-2022-22965"}],
        "record_count": 2,
    }
    result = await prefetch_feeds._score_with_epss(vulns)

    assert captured["cves"] == ["CVE-2021-44228", "CVE-2022-22965"], (
        "the CVE ids never reached EPSS — check the key names in _score_with_epss"
    )
    assert result["record_count"] == 1


@pytest.mark.asyncio
async def test_no_cves_means_no_epss_call(monkeypatch):
    """A quiet CVE week must not produce a pointless request, and must not
    produce an `epss` block implying zero scores were a finding."""
    from scripts import prefetch_feeds

    class ExplodingEPSS:
        async def enrich(self, cves, **kwargs):  # pragma: no cover
            raise AssertionError("EPSS must not be called with no CVEs")

    monkeypatch.setattr(prefetch_feeds, "EPSSAdapter", ExplodingEPSS)

    assert await prefetch_feeds._score_with_epss({"vulns": []}) is None


@pytest.mark.asyncio
async def test_an_epss_outage_degrades_rather_than_losing_the_cves(monkeypatch):
    """The CVE records are already in hand. Failing the prefetch because the
    ranking step broke would throw away the feeds that did work."""
    from scripts import prefetch_feeds

    class BrokenEPSS:
        async def enrich(self, cves, **kwargs):
            raise RuntimeError("upstream is down")

    monkeypatch.setattr(prefetch_feeds, "EPSSAdapter", BrokenEPSS)

    result = await prefetch_feeds._score_with_epss({"vulns": [{"cve_id": "CVE-2021-44228"}]})

    assert result["record_count"] == 0
    assert "upstream is down" in result["error"]


@pytest.mark.asyncio
async def test_the_per_run_cve_cap_is_enforced(monkeypatch):
    from scripts import prefetch_feeds

    captured: dict = {}

    class CountingEPSS:
        async def enrich(self, cves, **kwargs):
            captured["n"] = len(cves)
            return {"enrichments": [], "source": "EPSS", "record_count": 0,
                    "scored": [], "not_scored": []}

    monkeypatch.setattr(prefetch_feeds, "EPSSAdapter", CountingEPSS)
    vulns = {"vulns": [{"cve_id": f"CVE-2024-{i:05d}"} for i in range(600)]}

    await prefetch_feeds._score_with_epss(vulns)

    assert captured["n"] == prefetch_feeds._MAX_CVES_TO_SCORE


# ─── VirusTotal enrichment in the prefetch (#214) ────────────────────────────


def _ioc(value, type_="IPv4", confidence="High", corroborated=False):
    tags = ["feed"] + (["corroborated-by:ThreatFox"] if corroborated else [])
    return {"type": type_, "value": value, "confidence": confidence, "tags": tags}


def test_unsupported_indicator_types_are_never_selected():
    """VirusTotal's per-indicator endpoints cover IPs and domains only.

    Selecting a URL or a CIDR range spends one of 500 daily lookups, and 15
    seconds, on a request that cannot succeed. The adapter would reject it, so
    the cost is pure waste.
    """
    from scripts.prefetch_feeds import _select_for_enrichment

    iocs = [
        _ioc("http://evil.test/a", type_="URL"),
        _ioc("10.0.0.0/8", type_="CIDR_Range"),
        _ioc("203.0.113.1"),
        _ioc("evil.test", type_="Domain"),
    ]

    selected = _select_for_enrichment(iocs, 10)

    assert selected == {"ip": ["203.0.113.1"], "domain": ["evil.test"]}


def test_corroborated_indicators_are_selected_first():
    """The selection rule, and the reason this is not "the first N".

    At 15 seconds each there is room for tens of indicators out of thousands.
    Taking them in list order means the choice is made by whichever feed sorted
    first. An indicator two independent feeds both reported is the one a report
    foregrounds, and a verdict is worth most where a claim is about to be made.
    """
    from scripts.prefetch_feeds import _select_for_enrichment

    iocs = [_ioc(f"203.0.113.{i}", confidence="Low") for i in range(20)]
    iocs.append(_ioc("198.51.100.1", confidence="Low", corroborated=True))

    selected = _select_for_enrichment(iocs, 3)

    assert selected["ip"][0] == "198.51.100.1", (
        "the corroborated indicator was not picked first — selection fell back "
        "to list order"
    )


def test_confidence_breaks_ties_among_uncorroborated():
    from scripts.prefetch_feeds import _select_for_enrichment

    iocs = [
        _ioc("203.0.113.1", confidence="Low"),
        _ioc("203.0.113.2", confidence="Medium"),
        _ioc("203.0.113.3", confidence="High"),
    ]

    selected = _select_for_enrichment(iocs, 2)

    assert selected["ip"] == ["203.0.113.3", "203.0.113.2"]


def test_the_total_limit_is_respected_across_both_types():
    from scripts.prefetch_feeds import _select_for_enrichment

    iocs = [_ioc(f"203.0.113.{i}") for i in range(50)]
    iocs += [_ioc(f"d{i}.test", type_="Domain") for i in range(50)]

    selected = _select_for_enrichment(iocs, 7)

    assert sum(len(v) for v in selected.values()) == 7


def test_a_type_never_exceeds_the_adapters_per_call_cap():
    """The adapter REJECTS an over-long list rather than truncating it, so a
    selection larger than the cap would raise and lose the whole type."""
    from threat_intel_mcp.adapters.virustotal import MAX_INDICATORS_PER_CALL

    from scripts.prefetch_feeds import _select_for_enrichment

    iocs = [_ioc(f"203.0.113.{i // 256}.{i % 256}") for i in range(500)]
    for i, ioc in enumerate(iocs):
        ioc["value"] = f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}"

    selected = _select_for_enrichment(iocs, 10_000)

    assert len(selected["ip"]) <= MAX_INDICATORS_PER_CALL


def test_duplicate_values_are_not_looked_up_twice():
    from scripts.prefetch_feeds import _select_for_enrichment

    iocs = [_ioc("203.0.113.1"), _ioc("203.0.113.1"), _ioc("203.0.113.2")]

    selected = _select_for_enrichment(iocs, 10)

    assert selected["ip"] == ["203.0.113.1", "203.0.113.2"]


def test_selection_is_deterministic():
    """The same payload must pick the same indicators, or two runs of the same
    week's data quietly spend quota on different samples."""
    from scripts.prefetch_feeds import _select_for_enrichment

    iocs = [_ioc(f"203.0.113.{i}", confidence="Medium") for i in range(30)]
    iocs.append(_ioc("198.51.100.9", corroborated=True))

    assert _select_for_enrichment(iocs, 5) == _select_for_enrichment(iocs, 5)


@pytest.mark.asyncio
async def test_a_zero_limit_disables_it_without_touching_the_api(monkeypatch):
    """VirusTotal costs quota, so "off" has to mean no request at all.

    This pins the *behaviour*, not a particular guard: the limit is enforced
    both by an early return and by the budget check in the selection loop, so
    removing either alone still yields nothing. That redundancy is deliberate
    (see the comment on `_select_for_enrichment`), and it means this test does
    not fail on a single-line edit — the off-by-one that would actually let a
    disabled run spend a lookup is caught by
    `test_the_result_says_it_is_a_sample_not_coverage`.
    """
    from scripts import prefetch_feeds

    class ExplodingVT:
        def __init__(self, *a, **k):
            raise AssertionError("must not construct the adapter when disabled")

    monkeypatch.setattr(prefetch_feeds, "VirusTotalAdapter", ExplodingVT)

    result = await prefetch_feeds._enrich_with_virustotal(
        {"iocs": [_ioc("203.0.113.1")]}, 0
    )

    assert result is None
    # A negative limit is nonsense input, not a licence to spend the budget.
    assert prefetch_feeds._select_for_enrichment([_ioc("203.0.113.1")], -1) == {}


@pytest.mark.asyncio
async def test_the_result_says_it_is_a_sample_not_coverage(monkeypatch):
    """R4: recording VirusTotal as covering the feed set would inflate the
    badge. `selected_from` is what stops a reader — or the agent — reading 40
    enriched indicators as 40 being all there were."""
    from scripts import prefetch_feeds

    class FakeVT:
        def __init__(self, *a, **k):
            pass

        async def enrich(self, values, *, indicator_type="ip"):
            return {
                "enrichments": [{"indicator": v, "malicious": 1} for v in values],
                "looked_up": list(values),
            }

    monkeypatch.setattr(prefetch_feeds, "VirusTotalAdapter", FakeVT)
    monkeypatch.setattr(prefetch_feeds, "credential_provider_from_env", lambda: None)

    iocs = {"iocs": [_ioc(f"203.0.113.{i}") for i in range(100)]}
    result = await prefetch_feeds._enrich_with_virustotal(iocs, 5)

    assert result["record_count"] == 5
    assert result["selected_from"] == 100, (
        "selected_from must report the candidate pool, not the sample size"
    )
    assert "corroborated" in result["selection"]


@pytest.mark.asyncio
async def test_one_type_failing_keeps_the_other(monkeypatch):
    """The indicators are already in hand. Losing the domain verdicts because
    the IP lookups rate-limited would throw away work that succeeded."""
    from scripts import prefetch_feeds

    class HalfBrokenVT:
        def __init__(self, *a, **k):
            pass

        async def enrich(self, values, *, indicator_type="ip"):
            if indicator_type == "ip":
                raise RuntimeError("rate limited")
            return {
                "enrichments": [{"indicator": v} for v in values],
                "looked_up": list(values),
            }

    monkeypatch.setattr(prefetch_feeds, "VirusTotalAdapter", HalfBrokenVT)
    monkeypatch.setattr(prefetch_feeds, "credential_provider_from_env", lambda: None)

    iocs = {"iocs": [_ioc("203.0.113.1"), _ioc("evil.test", type_="Domain")]}
    result = await prefetch_feeds._enrich_with_virustotal(iocs, 10)

    assert result["record_count"] == 1
    assert result["looked_up"] == ["evil.test"]
    assert "ip: RuntimeError" in result["error"]


@pytest.mark.asyncio
async def test_no_eligible_indicators_means_no_enrichment_block(monkeypatch):
    """A week of nothing but URLs must not produce an empty block implying
    VirusTotal was consulted and found nothing."""
    from scripts import prefetch_feeds

    result = await prefetch_feeds._enrich_with_virustotal(
        {"iocs": [_ioc("http://x.test/", type_="URL")]}, 40
    )

    assert result is None

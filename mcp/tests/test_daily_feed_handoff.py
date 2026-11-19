"""Offline contract tests: no claim of authenticated live collection."""

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "mcp/scripts"))
import consume_daily_feeds as consumer  # noqa: E402
import daily_source_roster  # noqa: E402
import prefetch_daily_feeds as producer  # noqa: E402


@pytest.fixture
def inputs():
    payload = {
        "generated_at": "2026-11-19T11:45:00Z", "time_range": "24h",
        "daily_contract": {"version": 1, "registry": deepcopy(consumer.REGISTRY),
                           "collection_started_at": "2026-11-19T11:30:01Z"},
    }
    for section, names in consumer.REGISTRY.items():
        payload[section] = {
            "retrieved_at": "2026-11-19T11:35:00Z", "record_count": 0, section: [],
            "per_source": [{"source": n, "status": "consulted", "record_count": 0,
                            "partial_failure": [], "error": None} for n in names],
        }
    run = {"repository": {"full_name": "kj299/threat-intel"},
           "path": ".github/workflows/daily-feeds-prefetch.yml",
           "head_branch": "main", "head_sha": "abc", "event": "workflow_dispatch",
           "status": "completed", "conclusion": "success", "id": 42,
           "html_url": "https://github.com/kj299/threat-intel/actions/runs/42"}
    artifact = {"name": "daily-feed-data", "expired": False,
                "workflow_run": {"id": 42}, "id": 7, "size_in_bytes": 100}
    jobs = {"jobs": [{"name": "Fetch daily feeds (holds credentials; no agent)",
                      "conclusion": "success", "run_id": 42,
                      "started_at": "2026-11-19T11:30:00Z",
                      "completed_at": "2026-11-19T11:46:00Z"}]}
    return payload, run, artifact, jobs


def consume(inputs):
    return consumer.consume(*inputs, expected_sha="abc",
                            report_end=datetime(2026, 11, 19, 12, tzinfo=timezone.utc))


def test_empty_failed_partial_are_not_silence(inputs):
    rows = inputs[0]["iocs"]["per_source"]
    rows[0].update(status="unverified", error="CredentialNotFoundError")
    rows[1].update(status="partial", partial_failure=["one page only"])
    result = consume(inputs)
    assert result["status"] == "partial"
    assert len(result["coverage"]) == 16
    assert result["coverage"][0]["outcome"] == "unavailable"
    assert result["coverage"][1]["status"] == "partial"
    assert result["coverage"][1]["partial_failure"] == ["one page only"]
    assert result["coverage"][2]["outcome"] == "zero_records"
    assert result["candidate_data"] == inputs[0]
    assert result["threatfox"]["status"] == "partial"


@pytest.mark.parametrize("target,key,value", [
    (1, "head_sha", "wrong"), (1, "head_branch", "feature"),
    (1, "event", "schedule"), (1, "conclusion", "failure"),
    (1, "path", ".github/workflows/scheduled-report.yml"),
    (2, "expired", True), (2, "workflow_run", {"id": 43}),
    (2, "size_in_bytes", 129 * 1024 * 1024), (2, "name", "feed-data"),
    (0, "generated_at", "2026-11-19T12:01:00Z"),
    (0, "generated_at", "bad timestamp"), (0, "time_range", "7d"),
])
def test_reject_provenance(inputs, target, key, value):
    inputs[target][key] = value
    assert consume(inputs)["candidate_data"] is None


@pytest.mark.parametrize("field,value", [
    ("started_at", "2026-11-19T09:59:00Z"),
    ("completed_at", "2026-11-19T11:32:00Z"),
    ("conclusion", "failure"), ("run_id", 43),
])
def test_reject_job_bounds(inputs, field, value):
    inputs[3]["jobs"][0][field] = value
    assert consume(inputs)["status"] == "unverified"


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "count", "status", "time"])
def test_reject_incomplete_receipts(inputs, mutation):
    block = inputs[0]["iocs"]
    if mutation == "missing":
        block["per_source"].pop()
    elif mutation == "duplicate":
        block["per_source"][0] = block["per_source"][1]
    elif mutation == "count":
        block["record_count"] = 1
    elif mutation == "status":
        block["per_source"][0]["status"] = "full"
    else:
        block["retrieved_at"] = "2026-11-19T11:50:00Z"
    assert consume(inputs)["status"] == "unverified"


def test_threatfox_uses_own_first_seen(inputs):
    block = inputs[0]["iocs"]
    block["iocs"] = [{"type": "IPv4", "value": "192.0.2.1", "source": "Q-Feeds",
                      "first_seen": "2026-11-19T11:00:00Z", "source_evidence": [
                          {"source": "ThreatFox", "first_seen": "2020-01-01T00:00:00Z"}]}]
    block["record_count"] = 1
    assert consume(inputs)["threatfox"]["record_count"] == 0
    block["iocs"][0]["source_evidence"][0]["first_seen"] = "2026-11-19T11:00:00Z"
    assert consume(inputs)["threatfox"]["record_count"] == 1


def test_collection_reuses_registry_and_fixed_budget(monkeypatch):
    calls = []

    async def collect(time_range, virustotal_limit):
        calls.append((time_range, virustotal_limit))
        return {"iocs": {}, "vulns": {}}

    monkeypatch.setattr(producer.prefetch_feeds, "collect", collect)
    result = asyncio.run(producer.collect())
    assert calls == [("24h", 8)]
    assert result["daily_contract"]["registry"] == consumer.REGISTRY
    assert result["daily_contract"]["enrichment_limits"] == {"epss": 1000, "osv": 100, "virustotal": 8}


@pytest.mark.parametrize("secret", ["synthetic-secret-012345", 'secret-with-"quotes\\end'])
def test_scanner_rejects_literal_and_escaped(monkeypatch, secret):
    monkeypatch.setattr(producer.prefetch_feeds, "_credential_values", lambda: {"TEST_API_KEY": secret})
    with pytest.raises(ValueError, match="Credential"):
        producer.encode({"response": secret})


def test_oversize_not_silently_sampled(monkeypatch):
    monkeypatch.setattr(producer, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="128 MiB"):
        producer.encode({"response": "long content"})


def test_timeout_does_not_write_or_log_response(monkeypatch, tmp_path, capsys):
    async def fail():
        print("synthetic-sensitive-response")
        raise TimeoutError("synthetic-sensitive-response")

    monkeypatch.setattr(producer, "collect", fail)
    output = tmp_path / "feed-data.json"
    assert producer.main(["--out", str(output)]) == 1
    assert not output.exists()
    assert "synthetic-sensitive-response" not in capsys.readouterr().out


def test_workflow_isolation_alias_parity():
    new = yaml.safe_load((ROOT / ".github/workflows/daily-feeds-prefetch.yml").read_text())
    weekly = yaml.safe_load((ROOT / ".github/workflows/scheduled-report.yml").read_text())
    assert new[True] == {"workflow_dispatch": None}
    assert new["permissions"] == {"contents": "read"}
    assert list(new["jobs"]) == ["prefetch"]
    steps = new["jobs"]["prefetch"]["steps"]
    env = next(s["env"] for s in steps if "env" in s)
    old = next(s["env"] for s in weekly["jobs"]["prefetch"]["steps"] if "env" in s)
    assert env == old
    assert all(len(s["uses"].split("@")[1]) == 40 for s in steps if "uses" in s)
    assert steps[0]["with"]["persist-credentials"] is False
    assert new["jobs"]["prefetch"]["timeout-minutes"] == 25


def test_roster_every_named_matrix_entry():
    matrix = (ROOT / "skills/cyber-threat-intel/references/source-matrix.md").read_text()
    rows = daily_source_roster.roster(matrix)
    named = [line for line in matrix.splitlines() if line.startswith("- ")
             and ("[MUST]" in line or "[SHOULD]" in line)]
    assert len({r["matrix_entry_id"] for r in rows}) == len(named)
    assert {r["matrix_entry"] for r in rows} == {line[2:] for line in named}
    assert len({r["source_id"] for r in rows}) == len(rows)
    assert {r["tier"] for r in rows} == set(range(1, 10))
    assert all(r["outcome"] == "not_attempted" and not r["attempts"] for r in rows)
    assert any("CERT-EU" in r["source"] for r in rows)
    json.dumps(rows)


def test_total_outage_remains_unverified_with_receipts(inputs):
    for section in consumer.REGISTRY:
        for row in inputs[0][section]["per_source"]:
            row.update(status="unverified", error="unavailable")
    result = consume(inputs)
    assert result["status"] == "unverified"
    assert len(result["coverage"]) == 16
    assert all(r["outcome"] == "unavailable" for r in result["coverage"])


def test_cli_writes_provenance_and_preserves_enrichment_sample(inputs, tmp_path, monkeypatch):
    inputs[0]["ioc_enrichment"] = {"virustotal": {
        "record_count": 0, "selected_from": 100, "selection": "corroborated first",
        "error": "unavailable", "enrichments": [],
    }}
    argv = ["consumer", "--expected-sha", "abc", "--report-end", "2026-11-19T12:00:00Z"]
    for name, value in zip(("payload", "run", "artifact", "jobs"), inputs, strict=True):
        path = tmp_path / (name + ".json")
        path.write_text(json.dumps(value))
        argv += ["--" + name, str(path)]
    out = tmp_path / "result.json"
    monkeypatch.setattr(sys, "argv", argv + ["--out", str(out)])
    consumer.main()
    result = json.loads(out.read_text())
    assert len(result["source_payload_sha256"]) == 64
    assert result["candidate_data"]["ioc_enrichment"] == inputs[0]["ioc_enrichment"]
    (tmp_path / "payload.json").unlink()
    consumer.main()
    assert json.loads(out.read_text())["status"] == "unverified"


@pytest.mark.parametrize("first,others", [
    ("Flashpoint", ["Intel 471", "DarkOwl", "Kela", "Cybersixgill", "SOCRadar",
                    "ReliaQuest", "ZeroFox", "Searchlight Cyber"]),
    ("infosec.exchange", ["ioc.exchange"]),
    ("FBI IC3", ["FBI Flash Alerts"]),
    ("SWIFT CSCF", ["SWIFT Security Updates"]),
    ("r/netsec", ["r/cybersecurity", "r/blueteamsec", "r/redteamsec", "r/ExploitDev",
                  "r/bugbounty", "r/ReverseEngineering", "r/malware"]),
    ("r/hacking", ["r/hackernews", "r/hackers", "r/masterhacker", "r/Hacking_Tutorials",
                   "r/AskNetsec", "r/Pentesting", "r/sysadmin", "r/homesecurity",
                   "r/crypto", "r/privacy", "r/computerforensics"]),
    ("Twitter/X #infosec", ["Twitter/X #threatintel", "Twitter/X #malware",
                            "Twitter/X #APT", "Twitter/X #CVE",
                            "Twitter/X security researcher accounts (unspecified scope)"]),
])
def test_group_member_consultation_never_covers_siblings(first, others):
    matrix = (ROOT / "skills/cyber-threat-intel/references/source-matrix.md").read_text()
    by_name = {r["source"]: r for r in daily_source_roster.roster(matrix)}
    consulted = by_name[first]
    consulted["outcome"] = "content_consulted"
    consulted["attempts"].append({"outcome": "content_consulted", "evidence": "test only"})
    siblings = [by_name[name] for name in others]
    assert all(r["matrix_entry_id"] == consulted["matrix_entry_id"] for r in siblings)
    assert all(r["matrix_entry"] == consulted["matrix_entry"] for r in siblings)
    assert all(r["source_id"] != consulted["source_id"] for r in siblings)
    assert all(r["outcome"] == "not_attempted" and r["attempts"] == [] for r in siblings)


def test_member_identity_stable_on_reorder_and_description_change():
    matrix = (ROOT / "skills/cyber-threat-intel/references/source-matrix.md").read_text()
    before = {r["source"]: (r["source_id"], r["matrix_entry_id"])
              for r in daily_source_roster.roster(matrix)}
    matrix = matrix.replace("infosec.exchange, ioc.exchange", "ioc.exchange, infosec.exchange")
    matrix = matrix.replace("CISA Advisories — cisa.gov [MUST]",
                            "CISA Advisories — cisa.gov — amended description [SHOULD]")
    after = {r["source"]: (r["source_id"], r["matrix_entry_id"])
             for r in daily_source_roster.roster(matrix)}
    assert before == after
    assert daily_source_roster.members("Mandiant / Google TI") == ["Mandiant / Google TI"]
    assert daily_source_roster.members("Organization (one, two)") == ["Organization (one, two)"]

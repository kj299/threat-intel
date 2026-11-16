"""Freshness and attribution gates for credential-free report ingestion."""

import copy
from datetime import datetime, timezone
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "consume_threatfox", Path(__file__).parents[2] / "scripts/consume_threatfox.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def inputs():
    run = {
        "id": 1,
        "repository": {"full_name": "kj299/threat-intel"},
        "path": ".github/workflows/scheduled-report.yml",
        "head_branch": "main",
        "head_sha": "abc",
        "event": "workflow_dispatch",
        "html_url": "https://github.com/kj299/threat-intel/actions/runs/1",
    }
    artifact = {
        "id": 2,
        "name": "feed-data",
        "expired": False,
        "workflow_run": {"id": 1},
        "size_in_bytes": 100,
    }
    jobs = {
        "jobs": [
            {
                "name": "Fetch feeds (holds credentials; no agent)",
                "conclusion": "success",
                "started_at": "2026-11-16T11:00:00Z",
            }
        ]
    }
    payload = {
        "time_range": "24h",
        "generated_at": "2026-11-16T11:20:00Z",
        "iocs": {
            "retrieved_at": "2026-11-16T11:02:00Z",
            "per_source": [{"source": "ThreatFox", "status": "consulted"}],
            "iocs": [
                {
                    "source": "Other",
                    "type": "Domain",
                    "value": "test.example",
                    "tlp": "AMBER",
                    "first_seen": "2026-11-16T10:00:00Z",
                    "source_evidence": [
                        {
                            "source": "ThreatFox",
                            "first_seen": "2026-11-16T09:00:00Z",
                            "confidence": "High",
                        }
                    ],
                }
            ],
        },
    }
    return payload, run, artifact, jobs


def check(inputs):
    return module.consume(
        *inputs,
        report_end=datetime(2026, 11, 16, 12, tzinfo=timezone.utc),
        expected_sha="abc",
    )


def test_live_artifact_contract_preserves_source_evidence_and_gap(inputs):
    result = check(inputs)
    assert result["status"] == "partial"
    assert result["iocs"][0]["first_seen"] == "2026-11-16T09:00:00+00:00"
    assert result["iocs"][0]["tlp"] == "AMBER"
    assert result["artifact_id"] == 2
    assert result["acquisition_between"] == [
        "2026-11-16T11:00:00+00:00",
        "2026-11-16T11:02:00+00:00",
    ]


@pytest.mark.parametrize(
    "case",
    [
        "stale",
        "future",
        "weekly",
        "expired",
        "wrong_run",
        "wrong_sha",
        "failed_job",
        "missing_source",
        "invalid_date",
    ],
)
def test_bad_inputs_degrade_without_stopping_report(inputs, case):
    p, r, a, j = copy.deepcopy(inputs)
    if case == "stale":
        j["jobs"][0]["started_at"] = "2026-11-16T08:00:00Z"
    if case == "future":
        p["generated_at"] = "2026-11-17T00:00:00Z"
    if case == "weekly":
        p["time_range"] = "7d"
    if case == "expired":
        a["expired"] = True
    if case == "wrong_run":
        a["workflow_run"]["id"] = 9
    if case == "wrong_sha":
        r["head_sha"] = "other"
    if case == "failed_job":
        j["jobs"][0]["conclusion"] = "failure"
    if case == "missing_source":
        p["iocs"]["per_source"] = []
    if case == "invalid_date":
        p["iocs"]["iocs"][0]["source_evidence"][0]["first_seen"] = "not a date"
    result = check((p, r, a, j))
    assert result["status"] == "unverified" and result["iocs"] == []


def test_other_source_timestamp_cannot_make_old_threatfox_record_current(inputs):
    inputs[0]["iocs"]["iocs"][0]["source_evidence"][0]["first_seen"] = (
        "2026-11-01T00:00:00Z"
    )
    assert check(inputs)["iocs"] == []


def test_upstream_partial_is_not_upgraded(inputs):
    inputs[0]["iocs"]["per_source"][0].update(
        status="partial", partial_failure=["capped"]
    )
    result = check(inputs)
    assert result["status"] == "partial"
    assert result["upstream_status"] == "partial"
    assert result["upstream_partial_failure"] == ["capped"]


def test_compact_export_preserves_records(inputs):
    import json

    result = check(inputs)
    assert json.loads(module.encode_compact(result)) == result


def test_oversized_compact_export_fails_closed():
    import json

    result = json.loads(
        module.encode_compact({"status": "partial", "iocs": ["x" * (1024 * 1024)]})
    )
    assert result["status"] == "unverified" and result["iocs"] == []
    assert result["record_count"] == 0


def archive(tmp_path, names, *, mode=0o100644, body=b"{}"):
    import zipfile

    path = tmp_path / "feed.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for name in names:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(info, body)
    return path


def test_archive_reads_exact_regular_member(tmp_path):
    assert (
        module.read_payload(archive(tmp_path, ["feed-data.json"]), archive=True)
        == b"{}"
    )


@pytest.mark.parametrize(
    "names",
    [["../feed-data.json"], ["/feed-data.json"], ["feed-data.json", "extra.json"]],
)
def test_archive_rejects_unexpected_paths_and_extra_members(tmp_path, names):
    with pytest.raises(module.ArtifactInputError):
        module.read_payload(archive(tmp_path, names), archive=True)


def test_archive_rejects_symlink(tmp_path):
    with pytest.raises(module.ArtifactInputError):
        module.read_payload(
            archive(tmp_path, ["feed-data.json"], mode=0o120777), archive=True
        )


def test_archive_checks_expansion_before_reading(tmp_path, monkeypatch):
    path = archive(tmp_path, ["feed-data.json"], body=b"x" * 10000)
    monkeypatch.setattr(module, "MAX_ARTIFACT_BYTES", 512)
    assert path.stat().st_size < 512
    with pytest.raises(module.ArtifactInputError, match="Uncompressed"):
        module.read_payload(path, archive=True)


def test_raw_payload_size_limit(tmp_path, monkeypatch):
    path = tmp_path / "feed-data.json"
    path.write_bytes(b"x" * 20)
    monkeypatch.setattr(module, "MAX_ARTIFACT_BYTES", 10)
    with pytest.raises(module.ArtifactInputError):
        module.read_payload(path)

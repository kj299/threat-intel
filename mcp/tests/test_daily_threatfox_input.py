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


def test_scheduled_source_only_artifact_is_readable_without_dispatch(inputs):
    p, r, a, j = inputs
    r.update(path=".github/workflows/threatfox-prefetch.yml", event="schedule")
    a["name"] = "threatfox-feed-data"
    j["jobs"][0]["name"] = "Fetch ThreatFox (holds credential; no agent)"
    p["iocs"]["per_source"][0].update(
        collection_started_at="2026-11-16T11:01:00Z",
        collection_completed_at="2026-11-16T11:01:03Z",
    )
    result = check(inputs)
    assert result["status"] == "partial" and result["record_count"] == 1
    assert result["acquisition_between"] == [
        "2026-11-16T11:01:00+00:00",
        "2026-11-16T11:01:03+00:00",
    ]


def test_invalid_source_bounds_degrade(inputs):
    inputs[0]["iocs"]["per_source"][0]["collection_started_at"] = "2026-11-17T00:00:00Z"
    assert check(inputs)["status"] == "unverified"


@pytest.fixture
def producer():
    path = Path(__file__).parents[1] / "scripts/prefetch_threatfox.py"
    producer_spec = importlib.util.spec_from_file_location("prefetch_threatfox", path)
    loaded = importlib.util.module_from_spec(producer_spec)
    producer_spec.loader.exec_module(loaded)
    return loaded


@pytest.mark.asyncio
async def test_producer_one_read_validated_and_bounded(producer):
    from threat_intel_mcp.adapters.base import FetchResult
    import json

    calls = []

    class Adapter:
        async def fetch(self, **kwargs):
            calls.append(kwargs)
            records = [
                {
                    "source": "ThreatFox",
                    "type": "Domain",
                    "value": "example.com",
                    "confidence": "High",
                    "action": "block",
                    "tlp": "WHITE",
                    "first_seen": "2026-11-16T09:00:00+00:00",
                }
            ]
            return FetchResult(
                records, "ThreatFox", 9, producer.now(), 1, 1, ["recent_iocs"]
            )

    payload = await producer.collect(Adapter())
    assert calls == [{"time_range": "24h"}]
    encoded = producer.encode(payload, "synthetic-key-not-in-data")
    assert len(encoded.encode()) < 1024 * 1024
    summary = json.loads(encoded)["iocs"]["per_source"][0]
    assert summary["status"] == "consulted" and summary["record_count"] == 1
    assert (
        summary["collection_started_at"]
        <= summary["retrieved_at"]
        <= summary["collection_completed_at"]
    )


@pytest.mark.asyncio
async def test_producer_error_is_unverified_without_exception_payload(producer):
    secret = "synthetic-secret-in-exception"

    class Broken:
        async def fetch(self, **kwargs):
            raise RuntimeError(secret)

    payload = await producer.collect(Broken())
    encoded = producer.encode(payload, secret)
    assert secret not in encoded
    assert payload["iocs"]["per_source"][0]["status"] == "unverified"
    assert payload["iocs"]["iocs"] == []


@pytest.mark.parametrize("key", ["synthetic-secret-echo", 'synthetic-"quoted-secret'])
def test_producer_refuses_literal_secret(producer, key):
    with pytest.raises(RuntimeError, match="Credential material"):
        producer.encode({"value": key}, key)


@pytest.mark.asyncio
async def test_producer_oversize_becomes_unverified(producer, monkeypatch):
    class Broken:
        async def fetch(self, **kwargs):
            raise RuntimeError("upstream failure")

    payload = await producer.collect(Broken())
    payload["iocs"]["iocs"] = ["x" * 10000]
    monkeypatch.setattr(producer, "MAX_OUTPUT_BYTES", 2000)
    import json

    result = json.loads(producer.encode(payload, ""))
    assert result["iocs"]["iocs"] == []
    assert result["iocs"]["per_source"][0]["status"] == "unverified"


def test_proposed_workflow_is_credential_isolated_read_only():
    import yaml

    path = Path(__file__).parents[2] / ".github/workflows/threatfox-prefetch.yml"
    workflow = yaml.safe_load(path.read_text())
    trigger = workflow.get("on", workflow.get(True))
    assert set(trigger) == {"schedule", "workflow_dispatch"}
    assert trigger["schedule"] == [
        {"cron": "40 6 * * *", "timezone": "America/New_York"}
    ]
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["prefetch"]
    assert job["timeout-minutes"] == 5
    credential_steps = [s for s in job["steps"] if "env" in s]
    assert len(credential_steps) == 1
    assert credential_steps[0]["env"] == {
        "ABUSECH_AUTH_KEY": "${{ secrets.ABUSECH_AUTH_KEY }}"
    }
    assert not any("claude" in s.get("uses", "") for s in job["steps"])
    assert job["steps"][-1]["with"]["name"] == "threatfox-feed-data"


@pytest.fixture
def refresher():
    spec = importlib.util.spec_from_file_location(
        "refresh_threatfox", Path(__file__).parents[2] / "scripts/refresh_threatfox.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    "case", ["success", "ambiguous", "failed", "changed_main", "expired"]
)
def test_independent_refresh_dispatches_once_and_does_not_claim_ingestion(
    refresher, case
):
    dispatched = []
    state = {"main_reads": 0}

    def api(path, *, dispatch=False):
        if dispatch:
            dispatched.append(path)
            return {}
        if path == "commits/main":
            state["main_reads"] += 1
            return {
                "sha": "changed"
                if case == "changed_main" and state["main_reads"] > 1
                else "abc"
            }
        if path.endswith("/artifacts"):
            return {
                "artifacts": [
                    {
                        "id": 9,
                        "name": "threatfox-feed-data",
                        "expired": case == "expired",
                        "size_in_bytes": 100,
                    }
                ]
            }
        run = {
            "id": 2,
            "head_sha": "abc",
            "head_branch": "main",
            "event": "workflow_dispatch",
            "created_at": "2099-01-01T00:00:00Z",
            "status": "completed",
            "conclusion": "failure" if case == "failed" else "success",
        }
        return {
            "workflow_runs": []
            if not dispatched
            else [run, {**run, "id": 3}]
            if case == "ambiguous"
            else [run]
        }

    if case == "success":
        result = refresher.refresh(call=api)
        assert result["status"] == "artifact_available_not_ingested"
        assert result["artifact_id"] == 9
    else:
        with pytest.raises(refresher.RefreshError):
            refresher.refresh(call=api)
    assert len(dispatched) == 1


def test_refresh_timeout_does_not_retry_dispatch(refresher):
    calls = []
    tick = iter([0, 301])

    def api(path, *, dispatch=False):
        calls.append((path, dispatch))
        return {"sha": "abc"} if path == "commits/main" else {"workflow_runs": []}

    with pytest.raises(refresher.RefreshError, match="expired"):
        refresher.refresh(call=api, clock=lambda: next(tick))
    assert sum(dispatch for _, dispatch in calls) == 1


def test_refresh_gh_failure_withholds_signed_urls(refresher, monkeypatch):
    def fail(*args, **kwargs):
        raise refresher.subprocess.CalledProcessError(
            1, ["gh"], stderr="secret signed URL"
        )

    monkeypatch.setattr(refresher.subprocess, "run", fail)
    with pytest.raises(refresher.RefreshError) as exc:
        refresher.api("commits/main")
    assert "secret" not in str(exc.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("body,expected_count", [
    ({"query_status": "no_result"}, 0),
    ({"query_status": "ok", "data": [{"ioc": "192.0.2.1:443", "ioc_type": "ip:port",
       "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
       "confidence_level": 90, "threat_type": "botnet_cc"}]}, 1),
])
async def test_protocol_retry_then_success(producer, httpx_mock, body, expected_count, caplog):
    import httpx
    import json
    from tests.test_abusech import FakeCredentials
    from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter

    secret = "synthetic-protocol-exception-secret"
    httpx_mock.add_exception(httpx.RemoteProtocolError(secret))
    httpx_mock.add_response(json=body)
    payload = await producer.collect(ThreatFoxAdapter(FakeCredentials("test-key")))
    summary = payload["iocs"]["per_source"][0]
    requests = httpx_mock.get_requests()
    assert len(requests) == 2
    assert all(r.method == "POST" and json.loads(r.content) == {"query": "get_iocs", "days": 1}
               for r in requests)
    assert summary["attempt_count"] == 2
    assert summary["status"] == "consulted" and summary["record_count"] == expected_count
    assert summary["collection_started_at"] <= summary["retrieved_at"] <= summary["collection_completed_at"]
    assert secret not in caplog.text + producer.encode(payload, secret)


@pytest.mark.asyncio
async def test_protocol_failure_twice_stops_unverified(producer, httpx_mock):
    import httpx
    from tests.test_abusech import FakeCredentials
    from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter

    for _ in range(2):
        httpx_mock.add_exception(httpx.RemoteProtocolError("synthetic-sensitive-text"))
    payload = await producer.collect(ThreatFoxAdapter(FakeCredentials("test-key")))
    summary = payload["iocs"]["per_source"][0]
    assert len(httpx_mock.get_requests()) == summary["attempt_count"] == 2
    assert summary["status"] == "unverified" and summary["record_count"] == 0
    assert "RemoteProtocolError" in summary["error"]
    assert "synthetic-sensitive-text" not in producer.encode(payload, "")


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    {"status_code": 401}, {"status_code": 403}, {"status_code": 429}, {"status_code": 503},
    {"json": {"query_status": "ok", "data": [{"ioc_type": "unknown"}]}},
    {"content": b"not json"},
])
async def test_http_and_schema_failures_not_retried(producer, httpx_mock, response):
    from tests.test_abusech import FakeCredentials
    from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter

    httpx_mock.add_response(**response)
    payload = await producer.collect(ThreatFoxAdapter(FakeCredentials("test-key")))
    summary = payload["iocs"]["per_source"][0]
    assert len(httpx_mock.get_requests()) == summary["attempt_count"] == 1
    assert summary["status"] == "unverified"


@pytest.mark.asyncio
async def test_retry_delay_shares_original_deadline(producer, monkeypatch):
    import asyncio
    import httpx

    wait_for = asyncio.wait_for
    budgets = []

    async def shortened(awaitable, *, timeout):
        budgets.append(timeout)
        return await wait_for(awaitable, timeout=0.01)

    class Broken:
        async def fetch(self, **kwargs):
            raise httpx.RemoteProtocolError("synthetic")

    monkeypatch.setattr(producer.asyncio, "wait_for", shortened)
    payload = await producer.collect(Broken())
    summary = payload["iocs"]["per_source"][0]
    assert budgets == [90]
    assert summary["attempt_count"] == 1  # Cancelled during the retry delay.
    assert summary["status"] == "unverified" and "TimeoutError" in summary["error"]


@pytest.mark.asyncio
async def test_partial_survives_protocol_retry(producer):
    import httpx
    from threat_intel_mcp.adapters.base import FetchResult

    class Adapter:
        calls = 0

        async def fetch(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise httpx.RemoteProtocolError("synthetic")
            return FetchResult([], "ThreatFox", 9, producer.now(), 1, 0,
                               ["recent_iocs"], partial_failure=["test coverage limitation"])

    result = await producer.collect(Adapter())
    summary = result["iocs"]["per_source"][0]
    assert summary["status"] == "partial" and summary["attempt_count"] == 2
    assert summary["partial_failure"] == ["test coverage limitation"]
    assert result["iocs"]["sources_consulted"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["ReadTimeout", "LocalProtocolError", "CredentialNotFoundError"])
async def test_other_errors_do_not_retry(producer, kind):
    import httpx
    from threat_intel_mcp.vault.base import CredentialNotFoundError

    error = CredentialNotFoundError if kind == "CredentialNotFoundError" else getattr(httpx, kind)

    class Broken:
        async def fetch(self, **kwargs):
            raise error("synthetic-sensitive-text")

    result = await producer.collect(Broken())
    summary = result["iocs"]["per_source"][0]
    assert summary["attempt_count"] == 1 and summary["status"] == "unverified"
    assert kind in summary["error"]
    assert "synthetic-sensitive-text" not in producer.encode(result, "")

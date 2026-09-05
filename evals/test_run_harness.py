"""The scenario harness keeps what it judged (issue #185).

`injection_resistance` passed on 2026-09-04 — the first scenario ever executed
here — and left nothing behind but two lines of PASS. For a security property
that is a thin record: it says the badge was not upgraded, but not *how* the
model handled the planted instruction, and it cannot be re-read or compared.

These tests need no model call: the subprocess is faked, so what is under test
is the harness's own bookkeeping rather than the skill.
"""

from __future__ import annotations

import json
import subprocess
import types

import pytest

import run as harness
from scenarios import INJECTION_PAYLOAD


def _stream(*messages: str) -> str:
    """A `stream-json` transcript carrying one assistant message per argument.

    The harness now invokes the CLI with `--output-format stream-json`, so the
    fake has to speak that shape or it would be testing a code path that no
    longer exists.
    """
    lines = [json.dumps({"type": "system", "subtype": "init"})]
    for text in messages:
        lines.append(
            json.dumps(
                {"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}}
            )
        )
    lines.append(json.dumps({"type": "result", "subtype": "success"}))
    return "\n".join(lines) + "\n"


def _fake_completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    """`stdout` is the report text; it is wrapped as a one-message transcript."""
    return types.SimpleNamespace(
        stdout=_stream(stdout) if stdout else "", stderr=stderr, returncode=returncode
    )


def _fake_raw(stdout: str, stderr: str = "", returncode: int = 0):
    """For tests that need to control the transcript bytes exactly."""
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


@pytest.fixture()
def runs_dir(tmp_path, monkeypatch):
    """Never write into the real evals/runs/ from a test."""
    monkeypatch.setattr(harness, "_RUNS", tmp_path)
    return tmp_path


def _run(monkeypatch, key: str, completed) -> int:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed)
    return harness.run_scenario(key)


def test_a_scenario_run_leaves_its_output_on_disk(runs_dir, monkeypatch):
    """The acceptance criterion: the text judged is recoverable afterwards."""
    _run(monkeypatch, "sparse_honesty", _fake_completed(stdout="COVERAGE: MINIMAL\nquiet week"))

    written = list(runs_dir.glob("sparse_honesty-*.md"))
    assert len(written) == 1, f"expected one artifact, got {written}"
    body = written[0].read_text(encoding="utf-8")
    assert "COVERAGE: MINIMAL" in body and "quiet week" in body


def test_the_artifact_records_the_prompt_including_the_planted_payload(runs_dir, monkeypatch):
    """Without the prompt, a passed R6 run cannot be reproduced or compared."""
    _run(monkeypatch, "injection_resistance", _fake_completed(stdout="COVERAGE: MINIMAL"))

    body = next(runs_dir.glob("injection_resistance-*.md")).read_text(encoding="utf-8")
    assert INJECTION_PAYLOAD in body


def test_output_is_kept_even_when_the_invocation_fails(runs_dir, monkeypatch):
    """A scenario-0 failure is exactly when the full stderr is worth having —
    the harness only prints its last 2000 characters."""
    rc = _run(monkeypatch, "sparse_honesty", _fake_completed(stderr="boom" * 900, returncode=1))

    assert rc == 1
    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    assert body.count("boom") == 900, "stderr was truncated in the artifact"


def test_the_verdict_is_recorded_next_to_the_output(runs_dir, monkeypatch):
    _run(monkeypatch, "sparse_honesty", _fake_completed(stdout="nothing honest here"))

    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    assert "## Verdict" in body


def test_a_report_containing_fenced_blocks_survives_verbatim(runs_dir, monkeypatch):
    """Real reports carry fenced YARA/Sigma blocks. Wrapping the output in a
    fence of its own would break at the first one, so it is written raw."""
    report = "## Detection Rules\n\n```yara\nrule X { condition: true }\n```\n"
    _run(monkeypatch, "sparse_honesty", _fake_completed(stdout=report))

    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")

    # `report in body` is NOT enough here and was the first version of this
    # test: wrapping the output in a fence leaves the inner text untouched, so
    # the substring still matches and the assertion passes while the property
    # it names is broken. Assert the structure instead — the output section
    # must begin with the report itself, not with a fence.
    section = body.split("## Model output\n\n", 1)[1]
    assert section.startswith(report), "model output must not be wrapped in a fence"


def test_a_scenario_run_never_writes_into_the_frozen_corpus(runs_dir, monkeypatch):
    """reports/ is pinned at 11 by CI (#183); a scenario must not touch it."""
    before = sorted(p.name for p in harness._REPORTS.glob("*.md"))
    _run(monkeypatch, "sparse_honesty", _fake_completed(stdout="COVERAGE: MINIMAL"))
    assert sorted(p.name for p in harness._REPORTS.glob("*.md")) == before


# ─── The capture defect (2026-09-05) ─────────────────────────────────────────


def test_a_report_split_across_messages_is_captured_whole(runs_dir, monkeypatch):
    """The defect itself.

    `claude -p` in text mode prints only the FINAL assistant message. Two of the
    six scenario runs on 2026-09-05 composed their report across turns and
    signed off with a short note, so the harness asserted over the sign-off and
    reported hard failures against a few sentences of prose.
    """
    completed = _fake_raw(
        _stream(
            "## Appendix A: Source Coverage Ledger\n\nCOVERAGE: MINIMAL",
            "**Fabrication check:** `PASS` — nothing was invented.",
            "Note: I didn't commit this to reports/ — that corpus is frozen.",
        )
    )
    _run(monkeypatch, "sparse_honesty", completed)

    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    section = body.split("## Model output\n\n", 1)[1]
    for fragment in ("Source Coverage Ledger", "Fabrication check", "didn't commit"):
        assert fragment in section, f"lost {fragment!r} from the transcript"
    assert "assistant messages merged**: 3" in body


def test_only_the_last_message_would_have_lost_the_report(runs_dir, monkeypatch):
    """Non-vacuity for the test above.

    Asserting that the whole transcript survives proves nothing unless the old
    behaviour would actually have failed it. Reduce the same transcript the way
    text mode did — final message only — and the ledger is gone.
    """
    messages = (
        "## Appendix A: Source Coverage Ledger\n\nCOVERAGE: MINIMAL",
        "Note: I didn't commit this to reports/.",
    )
    whole, count = harness.collect_report_text(_stream(*messages))
    assert count == 2
    assert "Source Coverage Ledger" in whole
    assert "Source Coverage Ledger" not in messages[-1], (
        "the fixture must reproduce the real shape: report early, sign-off last"
    )


def test_tool_use_blocks_are_not_part_of_the_report(runs_dir, monkeypatch):
    """How the report was gathered is not the report."""
    stream = "\n".join(
        [
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "tool_use", "name": "fetch_all_iocs", "input": {}},
                            {"type": "text", "text": "COVERAGE: MINIMAL"},
                        ]
                    },
                }
            )
        ]
    )
    text, count = harness.collect_report_text(stream)
    assert text == "COVERAGE: MINIMAL"
    assert "fetch_all_iocs" not in text
    assert count == 1


def test_non_json_lines_are_skipped_not_fatal():
    """The CLI may emit diagnostics the harness has no contract with."""
    stream = "warning: something\n" + _stream("COVERAGE: MINIMAL")
    text, count = harness.collect_report_text(stream)
    assert text == "COVERAGE: MINIMAL"
    assert count == 1


def test_assistant_messages_with_no_text_refuse_to_assert(runs_dir, monkeypatch):
    """An empty reconstruction must be loud, never a silent pass-through.

    The adapters forbid a confident `0 records` from a body that could not be
    read (`guard_parsed`); handing the invariants an empty string would
    reintroduce that exact shape one layer up, as honest-looking hard failures
    about text nobody ever saw.
    """
    stream = json.dumps(
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "X"}]}}
    )
    with pytest.raises(harness.TranscriptError):
        harness.collect_report_text(stream)

    rc = _run(monkeypatch, "sparse_honesty", _fake_raw(stream))
    assert rc == 1, "an unreadable transcript must fail the run"
    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    assert "tool_use" in body, "the raw stream must survive for debugging"


def test_an_empty_transcript_is_not_an_error():
    """No assistant messages at all is a different thing from unreadable ones —
    a crashed invocation, which scenario 0 reports through the exit code."""
    assert harness.collect_report_text("") == ("", 0)


def test_the_artifact_records_what_was_asserted(runs_dir, monkeypatch):
    """The artifact and the verdict must never describe different text."""
    _run(monkeypatch, "sparse_honesty", _fake_completed(stdout="COVERAGE: MINIMAL"))
    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    section = body.split("## Model output\n\n", 1)[1]
    assert section.startswith("COVERAGE: MINIMAL")
    assert '"type": "assistant"' not in section, "raw transcript leaked into the artifact"

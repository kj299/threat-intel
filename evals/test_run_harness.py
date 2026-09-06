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
import pathlib
import re
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


def _out_path_from(prompt: str) -> str:
    """Recover the destination the harness named, the way the model would."""
    m = re.search(r"exact path: (\S+)", prompt)
    assert m, f"prompt names no output path:\n{prompt}"
    return m.group(1)


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


# ─── The report is written, not spoken (2026-09-05, second finding) ──────────


def test_the_prompt_names_an_output_path():
    """Capturing the transcript was necessary and not sufficient.

    The re-run of `ledger_consistency` with full transcript capture merged 43
    assistant messages into 2,479 characters of narration -- "Report generated
    and saved. Sending it to you now." -- while the real 462-line report went to
    a scratch file the harness had never been told about. The model composes a
    report by writing it, so the harness has to say where.
    """
    prompt = harness._build_prompt(
        harness.by_key("sparse_honesty"), pathlib.Path("/tmp/x/report.md")
    )
    assert "/tmp/x/report.md" in prompt
    assert "reports/" in prompt, "must warn off the frozen corpus"
    # Load-bearing: under `-p` the invoked session has no tool permissions, so
    # Write is denied. The 19:02 run spent 25 messages arguing with the
    # permission system and ended by asking whether to retry, because the
    # prompt named a path and never said what to do when it was refused.
    assert "output the complete report as your reply" in prompt


def test_the_written_file_wins_over_the_narration(runs_dir, monkeypatch, tmp_path):
    """The exact shape of the real failure: narration in the transcript, report
    on disk. Asserting over the transcript would judge the sign-off."""
    report = "## Appendix A: Source Coverage Ledger\n\nCOVERAGE: MINIMAL\n"

    def fake_run(cmd, **kwargs):
        # The model writes the file it was told to write.
        out = pathlib.Path(_out_path_from(cmd[-1]))
        out.write_text(report, encoding="utf-8")
        return _fake_raw(_stream("Report generated and saved. Sending it to you now."))

    monkeypatch.setattr(subprocess, "run", fake_run)
    harness.run_scenario("sparse_honesty")

    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    assert "Source Coverage Ledger" in body, "the written report was not read back"
    assert "asserted over**: the report file" in body


def test_the_transcript_is_the_fallback_when_no_file_is_written(runs_dir, monkeypatch):
    """A run that narrates its report instead of writing one still works."""
    _run(monkeypatch, "sparse_honesty", _fake_completed(stdout="COVERAGE: MINIMAL"))

    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    assert "COVERAGE: MINIMAL" in body
    assert "asserted over**: 1 assistant message(s)" in body


def test_an_empty_written_file_falls_back_rather_than_asserting_over_nothing(
    runs_dir, monkeypatch
):
    """A touched-but-empty file must not silently replace a real transcript."""

    def fake_run(cmd, **kwargs):
        out = pathlib.Path(_out_path_from(cmd[-1]))
        out.write_text("   \n", encoding="utf-8")
        return _fake_raw(_stream("COVERAGE: MINIMAL"))

    monkeypatch.setattr(subprocess, "run", fake_run)
    harness.run_scenario("sparse_honesty")

    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    assert "COVERAGE: MINIMAL" in body
    assert "asserted over**: 1 assistant message(s)" in body


# ─── Scenario 6 asserts a relation, not a document ───────────────────────────

_PAIRED = "overview_agrees_with_report"


def test_only_the_separate_mode_is_paired():
    """Derived from the skill input so the two cannot disagree. `attached`
    prepends the overview and yields one document; only `separate` yields the
    pair the relation holds between."""
    assert harness.is_paired(harness.by_key(_PAIRED))
    assert not harness.is_paired(harness.by_key("sparse_honesty"))


def test_the_paired_prompt_names_both_artifacts_and_both_markers():
    prompt = harness._build_prompt(
        harness.by_key(_PAIRED),
        pathlib.Path("/x/report.md"),
        pathlib.Path("/x/overview.html"),
    )
    assert "/x/report.md" in prompt and "/x/overview.html" in prompt
    assert harness._PAIR_REPORT_MARKER in prompt
    assert harness._PAIR_OVERVIEW_MARKER in prompt


def test_split_paired_recovers_both_halves():
    text = (
        "here you go\n"
        f"{harness._PAIR_REPORT_MARKER}\n## Technical\nCOVERAGE: MINIMAL\n"
        f"{harness._PAIR_OVERVIEW_MARKER}\n<html>dashboard</html>\n"
    )
    report, overview = harness.split_paired(text)
    assert report.startswith("## Technical")
    assert "COVERAGE: MINIMAL" in report
    assert overview == "<html>dashboard</html>"
    assert harness._PAIR_OVERVIEW_MARKER not in report, "marker leaked into the report"


@pytest.mark.parametrize(
    "text",
    [
        "no markers at all",
        f"{harness._PAIR_REPORT_MARKER}\nreport only",
        f"{harness._PAIR_OVERVIEW_MARKER}\noverview only",
        f"{harness._PAIR_REPORT_MARKER}\n\n{harness._PAIR_OVERVIEW_MARKER}\noverview",
        f"{harness._PAIR_REPORT_MARKER}\nreport\n{harness._PAIR_OVERVIEW_MARKER}\n   ",
    ],
)
def test_an_unrecoverable_pair_raises_rather_than_returning_half(text: str):
    """A vacuous pass is the failure to avoid here.

    Every pair invariant tolerates a missing field on one side, so
    check_paired_artifacts over an empty overview passes all seven while
    asserting nothing.
    """
    with pytest.raises(harness.PairError):
        harness.split_paired(text)


# A standalone report that PASSES check_report on its own. Load-bearing: the
# first version of the test below used markerless junk, which check_report
# rejected for three unrelated reasons, so the run failed whether or not the
# pair guard existed. Removing the guard left every test green. The text has to
# be good enough that degrading to check_report would PASS, or the test proves
# nothing about the guard.
_STANDALONE_OK = (
    "Report ID: r-1\nGenerated: 2026-09-05T00:00:00Z\nCoverage: MINIMAL\n\n"
    "This week was genuinely quiet and coverage is limited; little was retrievable.\n\n"
    "## Appendix A: Source Coverage Ledger\nSources consulted: 3\n"
    "**Fabrication check:** `PASS` — nothing was invented.\n"
)


def test_the_standalone_fixture_really_would_pass_alone():
    """Guards the guard: if this ever stops passing, the test below silently
    goes vacuous again."""
    from invariants import check_report

    assert check_report(_STANDALONE_OK, "fixture").ok


def test_a_paired_run_that_cannot_be_split_fails_instead_of_checking_one_half(
    runs_dir, monkeypatch, capsys
):
    """The defect this closes: run_scenario called check_report over whichever
    text it had, so scenario 6 reported a verdict about a different property
    than the one on its label.

    The report here is a perfectly good report. Judged as one it passes; judged
    as half of a missing pair it must fail.

    The assertion is on the DIAGNOSIS, not just the exit code, and that is not a
    weaker test — it is the only honest one. Measured: without the guard the run
    still fails, because `pair_overview_names_report` rejects an empty overview.
    Asserting `rc == 1` therefore passes with the guard removed, which is how
    the first version of this test went green against a sabotaged runner.
    """
    rc = _run(monkeypatch, _PAIRED, _fake_completed(stdout=_STANDALONE_OK))
    out = capsys.readouterr().out

    assert rc == 1, "a paired scenario must not pass on the report alone"
    assert "could not recover the artifact pair" in out, (
        "the run must say the pair was unrecoverable, not blame the overview "
        "for failing an invariant it never had a chance to satisfy; got:\n" + out
    )
    body = next(runs_dir.glob(f"{_PAIRED}-*.md")).read_text(encoding="utf-8")
    assert "## Verdict\n\nFAIL" in body


def test_a_paired_run_asserts_the_relation(runs_dir, monkeypatch, capsys):
    """The overview names a CVE the report does not — invisible in either
    document alone, which is the whole point of the pair check."""
    text = (
        f"{harness._PAIR_REPORT_MARKER}\n"
        "Report ID: r-1\nGenerated: 2026-09-05T00:00:00Z\n"
        "Coverage: MINIMAL\n\n## Appendix A: Source Coverage Ledger\n"
        "Sources consulted: 3\n**Fabrication check:** `PASS` — nothing was invented.\n"
        f"{harness._PAIR_OVERVIEW_MARKER}\n"
        "<html>Report ID: r-1 Coverage: MINIMAL CVE-2099-9999 "
        "see the technical report</html>\n"
    )
    _run(monkeypatch, _PAIRED, _fake_completed(stdout=text))

    out = capsys.readouterr().out
    assert "pair_no_cve_only_in_overview" in out, (
        "the relation was not asserted; output was:\n" + out
    )


def test_the_overview_file_is_read_when_the_run_can_write(runs_dir, monkeypatch):
    """Both artifacts on disk is the path a permissioned run takes."""

    def fake_run(cmd, **kwargs):
        prompt = cmd[-1]
        report_p = pathlib.Path(_out_path_from(prompt))
        overview_p = report_p.parent / "overview.html"
        report_p.write_text("Coverage: MINIMAL\n## Appendix A: Source Coverage Ledger\n", encoding="utf-8")
        overview_p.write_text("<html>MINIMAL</html>", encoding="utf-8")
        return _fake_raw(_stream("Both files written."))

    monkeypatch.setattr(subprocess, "run", fake_run)
    harness.run_scenario(_PAIRED)

    body = next(runs_dir.glob(f"{_PAIRED}-*.md")).read_text(encoding="utf-8")
    assert "the overview file" in body, "the overview file was not picked up"


def test_a_paired_artifact_keeps_both_halves(runs_dir, monkeypatch):
    """A pair verdict is about a relation, so an artifact holding one document
    cannot support it.

    The first real paired run failed `pair_same_badge` and the overview it was
    judged against had already been discarded — the finding could not be
    checked at all. That is the same "keep what you judged" failure #185 fixed
    for the report, reappearing on the other half.
    """
    text = (
        f"{harness._PAIR_REPORT_MARKER}\nCoverage: MINIMAL\n"
        "## Appendix A: Source Coverage Ledger\n"
        f"{harness._PAIR_OVERVIEW_MARKER}\n<html>DASHBOARD-MARKER Coverage: FULL</html>\n"
    )
    _run(monkeypatch, _PAIRED, _fake_completed(stdout=text))

    body = next(runs_dir.glob(f"{_PAIRED}-*.md")).read_text(encoding="utf-8")
    assert "DASHBOARD-MARKER" in body, "the overview was judged but not kept"
    assert "## Executive overview" in body


def test_an_unpaired_artifact_has_no_overview_section(runs_dir, monkeypatch):
    """Non-vacuity: the section appears because there is a second document,
    not unconditionally."""
    _run(monkeypatch, "sparse_honesty", _fake_completed(stdout="COVERAGE: MINIMAL"))

    body = next(runs_dir.glob("sparse_honesty-*.md")).read_text(encoding="utf-8")
    assert "## Executive overview" not in body

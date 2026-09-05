"""The scenario harness keeps what it judged (issue #185).

`injection_resistance` passed on 2026-09-04 — the first scenario ever executed
here — and left nothing behind but two lines of PASS. For a security property
that is a thin record: it says the badge was not upgraded, but not *how* the
model handled the planted instruction, and it cannot be re-read or compared.

These tests need no model call: the subprocess is faked, so what is under test
is the harness's own bookkeeping rather than the skill.
"""

from __future__ import annotations

import subprocess
import types

import pytest

import run as harness
from scenarios import INJECTION_PAYLOAD


def _fake_completed(stdout: str = "", stderr: str = "", returncode: int = 0):
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

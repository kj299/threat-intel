"""Structural guards on ``scheduled-report.yml``'s total-outage rule.

On 2026-10-26 the weekly report produced nothing. ThreatFox's CSV export had
started answering ``410 Gone``, and the ``generate`` job opened with a step that
re-fetched ThreatFox and CISA KEV from its own runner and failed the run if
either was unhealthy. One retired feed aborted the whole report before the agent
ran -- the opposite of what the honesty rules ask for, where a source that cannot
be reached is recorded ``unverified`` and the report goes ahead.

That step had two defects, and each is guarded here:

* It **re-fetched in the agent's job**, which the workflow's own comments
  forbid: the credential-free runner would produce "a strictly worse second
  picture" that can contradict the prefetch's file. The only picture of the feeds
  the agent may use is the one ``prefetch`` wrote.
* It was the **only** thing standing between a total outage and a silent
  no-live-data report, because ``prefetch_feeds.py --require-records`` -- the
  script's own total-outage rule -- was never switched on in the workflow. The
  rule now lives where the data does: ``prefetch`` fails (so ``generate`` never
  starts) when *every* source degraded, and not otherwise.

The workflow is parsed, not grepped, and the shell command is tokenised rather
than searched as text. That matters: inside a ``run: |`` block a ``# --flag``
line is just characters in a YAML string, so a substring check passes whether
the flag is passed or merely mentioned in a comment. (The first draft of this
test did exactly that, and survived the flag being commented out.)
"""

from __future__ import annotations

import pathlib
import shlex

import pytest
import yaml

_WORKFLOW = (
    pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "scheduled-report.yml"
)


@pytest.fixture(scope="module")
def jobs() -> dict:
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _runs(job: dict) -> list[str]:
    return [step["run"] for step in job.get("steps", []) if "run" in step]


def _argv(run: str) -> list[str]:
    """The shell words the script would actually execute: comments dropped,
    ``\\``-continuations joined. Raises on a script shlex cannot read -- for the
    one plain command this is used on, that is itself a finding."""
    return shlex.split(run, comments=True)


def _agent_job(jobs: dict) -> tuple[str, dict]:
    found = [
        (name, job)
        for name, job in jobs.items()
        if any("claude-code-action" in str(step.get("uses", "")) for step in job.get("steps", []))
    ]
    assert len(found) == 1, f"expected exactly one job running the agent, found {[n for n, _ in found]}"
    return found[0]


def test_prefetch_fails_the_run_only_on_a_total_outage(jobs):
    prefetch = [_argv(r) for r in _runs(jobs["prefetch"]) if "prefetch_feeds.py" in r]
    assert len(prefetch) == 1, "expected exactly one step running prefetch_feeds.py"
    assert "--require-records" in prefetch[0], (
        "prefetch_feeds.py is run without --require-records, so a total outage "
        "(every source degraded) would produce a silent no-live-data report"
    )


def test_the_agent_job_never_refetches_feeds(jobs):
    name, job = _agent_job(jobs)

    def code(run: str) -> str:
        # Comments out when the script is plain shell; the raw text when it is
        # not (a heredoc of Python is not shell words) -- over-matching there
        # fails closed, which is the right direction for a guard.
        try:
            return " ".join(_argv(run))
        except ValueError:
            return run

    offenders = [
        run.strip().splitlines()[0]
        for run in _runs(job)
        if any(
            marker in code(run)
            for marker in ("threat_intel_mcp.adapters", ".fetch(", "prefetch_feeds", "fan_out")
        )
    ]
    assert not offenders, (
        f"job {name!r} runs the agent but also fetches feeds itself: {offenders}. "
        "It must read only the file the prefetch job wrote; a re-fetch from a "
        "credential-free runner can contradict that file, and one retired feed "
        "must never be able to abort the report (2026-10-26)."
    )


def test_the_agent_job_depends_on_prefetch(jobs):
    _, job = _agent_job(jobs)
    needs = job.get("needs")
    assert "prefetch" in ([needs] if isinstance(needs, str) else needs or []), (
        "the agent job must declare needs: prefetch, or --require-records "
        "protects nothing: generate would start regardless of the prefetch's verdict"
    )

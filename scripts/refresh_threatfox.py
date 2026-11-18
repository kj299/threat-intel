"""One authenticated maintainer dispatch; return a pointer, never claim ingestion.

Run from an independently scheduled, already authenticated maintenance environment.
Never install this in the unprivileged report runtime or pass a feed credential.
"""

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone

REPO = "repos/kj299/threat-intel"
WORKFLOW = "threatfox-prefetch.yml"


class RefreshError(RuntimeError):
    pass


def api(path, *, dispatch=False):
    command = ["gh", "api", f"{REPO}/{path}"]
    if dispatch:
        command += ["--method", "POST", "--field", "ref=main"]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=30, check=True)
        return json.loads(completed.stdout) if completed.stdout else {}
    except (subprocess.SubprocessError, OSError, ValueError):
        # gh errors can contain signed URLs; never print its output or exception.
        raise RefreshError(
            "GitHub request failed; outcome may be uncertain; inspect runs before retry"
        ) from None


def candidates(runs, prior_ids, sha, since):
    return [
        r
        for r in runs
        if r["id"] not in prior_ids
        and r["head_sha"] == sha
        and r["head_branch"] == "main"
        and r["event"] == "workflow_dispatch"
        and r["created_at"] >= since
    ]


def refresh(call=api, sleep=time.sleep, clock=time.monotonic, timeout=300):
    sha = call("commits/main")["sha"]
    path = f"actions/workflows/{WORKFLOW}/runs?event=workflow_dispatch&per_page=100"
    prior = {r["id"] for r in call(path)["workflow_runs"]}
    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    deadline = clock() + timeout
    call(f"actions/workflows/{WORKFLOW}/dispatches", dispatch=True)
    # Exactly one dispatch. Timeouts and ambiguous outcomes never cause retries.
    while clock() < deadline:
        found = candidates(call(path)["workflow_runs"], prior, sha, since)
        if len(found) > 1:
            raise RefreshError(
                "Concurrent matching dispatches; cannot identify owned run"
            )
        if found:
            run = found[0]
            if run["status"] == "completed":
                if run["conclusion"] != "success":
                    raise RefreshError(
                        "Producer run failed; preserve report with source unverified"
                    )
                if call("commits/main")["sha"] != sha:
                    raise RefreshError(
                        "Main changed during refresh; do not bypass consumer SHA gate"
                    )
                artifacts = call(f"actions/runs/{run['id']}/artifacts")["artifacts"]
                matches = [
                    a
                    for a in artifacts
                    if a["name"] == "threatfox-feed-data"
                    and not a["expired"]
                    and 0 < a["size_in_bytes"] <= 128 * 1024 * 1024
                ]
                if len(matches) != 1:
                    raise RefreshError("Missing or ambiguous bounded artifact")
                return {
                    "status": "artifact_available_not_ingested",
                    "run_id": run["id"],
                    "artifact_id": matches[0]["id"],
                    "sha": sha,
                    "next_step": "Download exact artifact through authorized connector; validate bytes, source status and freshness using consume_threatfox.py",
                }
        sleep(min(10, max(0, deadline - clock())))
    raise RefreshError(
        "Refresh wait expired; inspect runs before retry; continue report"
    )


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        print(json.dumps(refresh()))
    except (RefreshError, KeyError, TypeError) as error:
        reason = (
            str(error)
            if isinstance(error, RefreshError)
            else "Unexpected GitHub metadata"
        )
        print(json.dumps({"status": "unverified", "reason": reason}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

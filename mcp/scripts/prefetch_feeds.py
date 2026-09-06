#!/usr/bin/env python3
"""Fetch every configured feed and write the result to a file (issue #169).

Why this exists
---------------
`scheduled-report.yml` runs an LLM agent whose job is ingesting untrusted
content -- threat feeds, vendor blogs, leak-site aggregators -- with `contents:
write` and the ability to open a PR. Any feed credential in that agent's
environment is reachable by a prompt injection and can leave in a committed
file, which log masking does not cover. So the agent never gets one.

This script is the other half of that arrangement: a fixed program, no model in
the loop, that holds the credentials, fetches, and writes **data only**. The
agent then reads a file. It is the shape `record-cassettes.yml` already uses and
that `docs/report-runbook.md` prescribes.

The isolation is by JOB, not by step. Steps share a runner; jobs get separate
machines, so the agent's runner never holds the credential in any form at any
moment -- not in an environment block, not in a file, not in the process table.

What it writes
--------------
`fan_out` and `fan_out_vulns` already return a per-source breakdown and a
`coverage_ledger` ready for Appendix A, including which sources were consulted
and which degraded and why. That is exactly what an honest report needs, so this
script passes it through rather than summarising it: a feed that failed must
reach the agent as `unverified` with its reason, never as silence.

Usage:
    python scripts/prefetch_feeds.py --out feed-data.json --time-range 7d
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import pathlib
import sys

# The server's own source lists, imported rather than restated: a feed added to
# the tool surface is then prefetched automatically, and the two cannot drift.
from threat_intel_mcp.fanout import fan_out
from threat_intel_mcp.server import _FEED_SOURCES, _VULN_SOURCES
from threat_intel_mcp.vulns import fan_out_vulns

# Credentials are read by the adapters via EnvCredentialProvider; this script
# never touches their values. The names are needed only to prove none of them
# reached the output file.
_CREDENTIAL_ENV_SUFFIXES = ("_API_KEY", "_API_ID", "_API_SECRET", "_EMAIL", "_TOKEN")


def _credential_values() -> dict[str, str]:
    """Every credential-shaped environment value present in this process."""
    return {
        name: value
        for name, value in os.environ.items()
        if value and any(name.endswith(sfx) for sfx in _CREDENTIAL_ENV_SUFFIXES)
    }


def assert_no_credentials(payload: str) -> None:
    """Refuse to write a file containing any credential this process holds.

    Belt and braces before bytes derived from an authenticated session are
    handed to an agent that can commit files. The adapters put credentials in
    request headers, not responses, so this should never fire -- which is
    exactly why it is worth asserting rather than assuming.

    Short values are skipped: a two-character secret would match everywhere and
    make the check useless noise rather than a guard.
    """
    leaked = sorted(
        name
        for name, value in _credential_values().items()
        if len(value) >= 8 and value in payload
    )
    if leaked:
        raise SystemExit(
            "REFUSING TO WRITE: the fetched payload contains the value of "
            f"{', '.join(leaked)}. A credential must never reach the agent."
        )


async def collect(time_range: str) -> dict:
    """Fetch IOC and CVE feeds concurrently and return one combined payload."""
    iocs, vulns = await asyncio.gather(
        fan_out(_FEED_SOURCES, time_range=time_range),
        fan_out_vulns(_VULN_SOURCES, time_range=time_range),
    )
    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "time_range": time_range,
        "iocs": iocs,
        "vulns": vulns,
    }


def summarise(payload: dict) -> str:
    """A human-readable line per feed, for the workflow log.

    Printed so a run's log answers "which keys actually worked" without opening
    the artifact -- the question issue #169 exists to settle.
    """
    lines = []
    for section in ("iocs", "vulns"):
        block = payload[section]
        lines.append(
            f"{section}: {block['record_count']} records, "
            f"{len(block['sources_consulted'])} consulted, "
            f"{len(block['sources_degraded'])} degraded"
        )
        for degraded in block["sources_degraded"]:
            lines.append(f"  degraded: {degraded['source']} — {degraded.get('error', '?')}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Path to write the JSON payload to")
    parser.add_argument("--time-range", default="7d", help="Lookback window (e.g. 7d)")
    parser.add_argument(
        "--require-records",
        action="store_true",
        help=(
            "Exit non-zero if every source degraded. Off by default: a genuinely "
            "quiet week is a valid result, and failing on it would push the run "
            "toward padding, which R3 forbids."
        ),
    )
    args = parser.parse_args(argv)

    payload = asyncio.run(collect(args.time_range))
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    assert_no_credentials(text)

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")

    print(summarise(payload))
    print(f"\nwrote {out} ({len(text)} bytes)")

    if args.require_records:
        consulted = sum(
            len(payload[s]["sources_consulted"]) for s in ("iocs", "vulns")
        )
        if consulted == 0:
            print("::error::every source degraded — no feed data to report on")
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

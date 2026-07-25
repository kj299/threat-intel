#!/usr/bin/env python3
"""Record real feed responses as vcrpy cassettes (#105).

Run this from an environment with network egress to the feed hosts. It cannot
run in the default cloud dev sandbox, where every feed host returns
``CONNECT tunnel failed, response 403`` — which is exactly why adapter fixtures
were authored from belief rather than captured, and why ThreatFox parsed a 1 MB
response to zero records before anyone noticed (#100).

Usage::

    python mcp/scripts/record_cassettes.py                 # keyless feeds only
    python mcp/scripts/record_cassettes.py --all           # include keyed feeds
    python mcp/scripts/record_cassettes.py --only threatfox

Keyed feeds are opt-in because recording one requires a live credential in the
environment. The scrubbing in ``tests/vcr_config.py`` removes credentials from
what is written, and ``--verify-scrubbed`` (on by default) greps the output for
anything that looks like a leaked secret before you can commit it.

Cassettes land in ``mcp/tests/cassettes/`` and are meant to be committed.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tests.vcr_config import CASSETTE_DIR, build_vcr  # noqa: E402

from threat_intel_mcp.adapters.abuseipdb import AbuseIPDBAdapter  # noqa: E402
from threat_intel_mcp.adapters.anyrun import AnyRunAdapter  # noqa: E402
from threat_intel_mcp.adapters.censys import CensysAdapter  # noqa: E402
from threat_intel_mcp.adapters.cisa_kev import CISAKEVAdapter  # noqa: E402
from threat_intel_mcp.adapters.greynoise import GreyNoiseAdapter  # noqa: E402
from threat_intel_mcp.adapters.intel471 import Intel471Adapter  # noqa: E402
from threat_intel_mcp.adapters.nvd import NVDAdapter  # noqa: E402
from threat_intel_mcp.adapters.otx import OTXAdapter  # noqa: E402
from threat_intel_mcp.adapters.qfeeds import QFeedsAdapter  # noqa: E402
from threat_intel_mcp.adapters.shodan import ShodanAdapter  # noqa: E402
from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter  # noqa: E402
from threat_intel_mcp.adapters.virustotal import VirusTotalAdapter  # noqa: E402
from threat_intel_mcp.vault.factory import credential_provider_from_env  # noqa: E402

# name -> (adapter factory, needs a credential)
FEEDS = {
    # Keyless — recordable by anyone, no secrets involved.
    "threatfox": (lambda c: ThreatFoxAdapter(), False),
    "cisa_kev": (lambda c: CISAKEVAdapter(), False),
    "nvd": (lambda c: NVDAdapter(c), False),  # key optional; works unauthenticated
    # Keyed — opt in with --all, and only with credentials in the environment.
    "qfeeds": (lambda c: QFeedsAdapter(c), True),
    "abuseipdb": (lambda c: AbuseIPDBAdapter(c), True),
    "virustotal": (lambda c: VirusTotalAdapter(c, _rate_limit_delay=0), True),
    "otx": (lambda c: OTXAdapter(c), True),
    "shodan": (lambda c: ShodanAdapter(c), True),
    "greynoise": (lambda c: GreyNoiseAdapter(c), True),
    "anyrun": (lambda c: AnyRunAdapter(c), True),
    "intel471": (lambda c: Intel471Adapter(c), True),
    "censys": (lambda c: CensysAdapter(c), True),
}

# Anything in a committed cassette matching these is a scrubbing failure. Kept
# deliberately broad — a false positive costs a second look, a false negative
# costs a leaked credential.
_SUSPICIOUS = (
    "api_key",
    "apikey",
    "authorization: ",
    "bearer ",
    "basic ",
    "secret",
    "password",
)


async def record_one(name: str, creds, time_range: str) -> tuple[str, int | None, str]:
    factory, _ = FEEDS[name]
    cassette = CASSETTE_DIR / f"{name}.yaml"
    recorder = build_vcr(record_mode="all")
    try:
        with recorder.use_cassette(str(cassette)):
            result = await factory(creds).fetch(time_range=time_range)
        count = result.record_count
        # A cassette of an empty response teaches nothing and would make the
        # cassette test assert against a quiet day forever.
        note = "" if count else "  (WARNING: recorded an empty response)"
        return name, count, f"recorded {cassette.name}{note}"
    except Exception as exc:  # noqa: BLE001 - report, do not abort the batch
        if cassette.exists() and cassette.stat().st_size == 0:
            cassette.unlink()
        return name, None, f"FAILED {type(exc).__name__}: {exc}"


def verify_scrubbed(names: list[str]) -> list[str]:
    """Grep the written cassettes for anything credential-shaped."""
    problems = []
    for name in names:
        path = CASSETTE_DIR / f"{name}.yaml"
        if not path.is_file():
            continue
        lowered = path.read_text(encoding="utf-8", errors="replace").lower()
        for needle in _SUSPICIOUS:
            for line_no, line in enumerate(lowered.splitlines(), 1):
                if needle in line and "[redacted]" not in line:
                    problems.append(f"{path.name}:{line_no}: contains {needle!r}")
    return problems


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="include keyed feeds")
    parser.add_argument("--only", nargs="*", help="record only these feeds")
    parser.add_argument("--time-range", default="7d")
    parser.add_argument(
        "--skip-verify", action="store_true", help="skip the leaked-secret scan"
    )
    args = parser.parse_args()

    if args.only:
        unknown = [n for n in args.only if n not in FEEDS]
        if unknown:
            print(f"Unknown feed(s): {unknown}. Known: {sorted(FEEDS)}")
            return 2
        selected = args.only
    else:
        selected = [n for n, (_, keyed) in FEEDS.items() if args.all or not keyed]

    CASSETTE_DIR.mkdir(parents=True, exist_ok=True)
    creds = credential_provider_from_env()

    print(f"Recording {len(selected)} feed(s) into {CASSETTE_DIR}\n")
    results = [await record_one(n, creds, args.time_range) for n in selected]

    failures = []
    for name, count, message in results:
        marker = "  ok  " if count is not None else " FAIL "
        shown = f"{count} records" if count is not None else ""
        print(f"[{marker}] {name:<12} {shown:<14} {message}")
        if count is None:
            failures.append(name)

    recorded = [n for n, c, _ in results if c is not None]
    if not args.skip_verify:
        print()
        if not recorded:
            # Saying "scrubbing passed" after recording nothing would be a
            # reassuring message with nothing behind it.
            print("Nothing was recorded, so there was nothing to scrub-check.")
        else:
            problems = verify_scrubbed(recorded)
            if problems:
                print("SCRUBBING CHECK FAILED — do not commit these cassettes:")
                for p in problems:
                    print(f"  {p}")
                return 1
            print(
                f"Scrubbing check passed over {len(recorded)} cassette(s): "
                "no credential-shaped strings in the output."
            )

    if failures:
        print(f"\n{len(failures)} feed(s) failed to record: {failures}")
        if os.environ.get("CI"):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

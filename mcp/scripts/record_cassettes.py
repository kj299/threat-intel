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
import json
import os
import pathlib
import sys

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tests.vcr_config import CASSETTE_DIR, build_vcr, fresh_recording  # noqa: E402

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
from threat_intel_mcp.adapters.vulncheck import VulnCheckAdapter  # noqa: E402
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
    # Keyed, and the reason this recorder matters most right now: the VulnCheck
    # adapter's field mapping was written from published SDK signatures, not
    # from a response anyone has seen. This recording is what turns it from
    # belief into verified -- see the warning in adapters/vulncheck.py.
    "vulncheck": (lambda c: VulnCheckAdapter(c), True),
}

# Credential-bearing header names and query parameters. These are checked
# STRUCTURALLY -- against request headers, the request URI, and response headers
# -- never against a response body.
#
# The first version of this check grepped whole cassettes for words like
# "password" and "secret". That failed on the very first real recording: NVD CVE
# descriptions say "password" thousands of times ("allows an attacker to reset
# the password"), because it is a vulnerability feed. A check that fires on every
# NVD recording is not a cautious check, it is a broken one -- it blocks the
# feature and teaches people to pass --skip-verify.
#
# Response bodies are public threat data and are the entire point of a cassette.
# Credentials live in headers and query strings, so that is where we look.
_SECRET_HEADER_NAMES = (
    "authorization",
    "x-apikey",
    "x-otx-api-key",
    "x-api-key",
    "x-auth-token",
    "apikey",
    "key",
    "cookie",
    "set-cookie",
    "proxy-authorization",
)
_SECRET_QUERY_PARAMS = ("key", "apikey", "api_key", "token", "auth", "password", "secret")

# Every credential env var the adapters read. Any value actually configured is
# checked as a literal against the whole cassette -- the strongest form of this
# check, with no false positives: if the real key is in the file, it leaked,
# wherever it ended up.
_CREDENTIAL_ENV_VARS = (
    "QFEEDS_API_KEY", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "OTX_API_KEY",
    "SHODAN_API_KEY", "GREYNOISE_API_KEY", "ANYRUN_API_KEY", "INTEL471_EMAIL",
    "INTEL471_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET", "NVD_API_KEY",
    "VULNCHECK_API_KEY",
)

_REDACTED = "[REDACTED]"


# ─── Size ────────────────────────────────────────────────────────────────────
#
# A 7-day NVD window is ~36 MB across four pages, and every re-recording adds
# that again to git history forever. Issue #105 anticipated this: "Truncate to a
# representative slice rather than committing megabytes per adapter, but keep
# enough rows to exercise every branch."
#
# Only the `vulnerabilities` array is trimmed. `resultsPerPage` and
# `totalResults` are left exactly as NVD sent them, and that is load-bearing
# rather than tidiness: the adapter advances with `start_index += resultsPerPage`
# and stops at `start_index >= totalResults`, so those two fields alone decide
# the request sequence. Leaving them untouched means the recorded four-page walk
# replays identically -- pagination stays covered, which matters because no mock
# test covers it.
_MAX_ENTRIES_PER_PAGE = 25

# One entry carrying each CVSS block is kept even if it falls outside the first
# N, so trimming cannot quietly drop the branch that parses v2 or v4.0 scores.
_CVSS_BLOCKS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


def _representative(entries: list) -> list:
    """The first N entries, plus one exercising each CVSS block and one with none."""
    kept = list(entries[:_MAX_ENTRIES_PER_PAGE])
    kept_ids = {id(e) for e in kept}

    def _metrics(entry):
        cve = entry.get("cve") if isinstance(entry, dict) else None
        return (cve or {}).get("metrics") or {} if isinstance(cve, dict) else {}

    for block in _CVSS_BLOCKS:
        if any(_metrics(e).get(block) for e in kept):
            continue
        for entry in entries:
            if _metrics(entry).get(block) and id(entry) not in kept_ids:
                kept.append(entry)
                kept_ids.add(id(entry))
                break
    if not any(not _metrics(e) for e in kept):
        for entry in entries:
            if not _metrics(entry) and id(entry) not in kept_ids:
                kept.append(entry)
                break
    return kept


def shrink_nvd_cassette(path: pathlib.Path) -> tuple[int, int]:
    """Trim NVD response bodies in place. Returns (bytes_before, bytes_after)."""
    before = path.stat().st_size
    data = yaml.safe_load(path.read_text())
    for interaction in data.get("interactions", []):
        body = interaction.get("response", {}).get("body", {})
        raw = body.get("string")
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue  # not JSON; leave it exactly as recorded
        entries = parsed.get("vulnerabilities")
        if not isinstance(entries, list):
            continue
        parsed["vulnerabilities"] = _representative(entries)
        # resultsPerPage / totalResults deliberately untouched -- see above.
        body["string"] = json.dumps(parsed)
    path.write_text(yaml.safe_dump(data, default_flow_style=False, allow_unicode=True))
    return before, path.stat().st_size


# Feeds whose recordings are trimmed. ThreatFox (~1 MB) and CISA KEV (~1.6 MB)
# are committed whole: they are single responses of a size git handles fine, and
# an untrimmed cassette is the stronger artefact where it is affordable.
# A few VulnCheck entries carry enormous evidence lists -- the largest observed
# is 215 KB against a 1-6 KB median, and six of those alone took a trimmed
# recording to 3.35 MB against the 4 MB ceiling. Capping the lists keeps every
# parser branch exercised (the field is still present and non-empty) while
# removing bulk that tests nothing: the hundredth XDB URL exercises the same
# code as the first.
_MAX_EVIDENCE_ITEMS = 3
_EVIDENCE_LIST_KEYS = ("vulncheck_xdb", "vulncheck_reported_exploitation")


def _cap_evidence_lists(entry: dict) -> dict:
    """Return the entry with its evidence lists capped, others untouched."""
    if not isinstance(entry, dict):
        return entry
    trimmed = dict(entry)
    for key in _EVIDENCE_LIST_KEYS:
        value = trimmed.get(key)
        if isinstance(value, list) and len(value) > _MAX_EVIDENCE_ITEMS:
            trimmed[key] = value[:_MAX_EVIDENCE_ITEMS]
    return trimmed


def shrink_vulncheck_cassette(path: pathlib.Path) -> tuple[int, int]:
    """Trim VulnCheck response bodies in place. Returns (bytes_before, after).

    One page of vulncheck-kev is ~7.8 MB, over the 4 MB ceiling
    tests/test_vcr_harness.py enforces, so the `data` array is trimmed to a
    representative slice.

    `_meta` is left EXACTLY as sent, and that is load-bearing rather than
    tidiness -- the adapter paginates on `_meta.page` / `_meta.total_pages`, so
    those two fields alone decide the request sequence. It is the same reasoning
    that keeps NVD's resultsPerPage / totalResults untouched above.

    The kept slice is the first N entries plus one exercising each optional
    branch the parser has (a populated vulncheck_xdb, a cwes list, a canary
    report), so trimming cannot silently drop the branch that parses one of
    them and leave a green test asserting nothing about it.
    """
    before = path.stat().st_size
    data = yaml.safe_load(path.read_text())
    for interaction in data.get("interactions", []):
        body = interaction.get("response", {}).get("body", {})
        raw = body.get("string")
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue  # not JSON; leave it exactly as recorded
        entries = parsed.get("data")
        if not isinstance(entries, list):
            continue

        kept = list(entries[:_MAX_ENTRIES_PER_PAGE])
        kept_ids = {id(e) for e in kept}

        def _has(entry, key):
            return isinstance(entry, dict) and bool(entry.get(key))

        for key in ("vulncheck_xdb", "cwes", "vulncheck_reported_exploitation"):
            if not any(_has(e, key) for e in kept):
                extra = next((e for e in entries if _has(e, key)), None)
                if extra is not None and id(extra) not in kept_ids:
                    kept.append(extra)
                    kept_ids.add(id(extra))
        # The canary flag is a bool, so truthiness is the right test here.
        if not any(
            isinstance(e, dict) and e.get("reported_exploited_by_vulncheck_canaries")
            for e in kept
        ):
            extra = next(
                (
                    e
                    for e in entries
                    if isinstance(e, dict)
                    and e.get("reported_exploited_by_vulncheck_canaries")
                ),
                None,
            )
            if extra is not None and id(extra) not in kept_ids:
                kept.append(extra)

        parsed["data"] = [_cap_evidence_lists(e) for e in kept]
        # _meta deliberately untouched -- see above.
        body["string"] = json.dumps(parsed)
    path.write_text(yaml.safe_dump(data, default_flow_style=False, allow_unicode=True))
    return before, path.stat().st_size


_SHRINK = {"nvd": shrink_nvd_cassette, "vulncheck": shrink_vulncheck_cassette}


# Adapters whose recording entry point is not `fetch(time_range=...)`.
# VirusTotal is enrichment: it scores indicators the caller supplies, so a
# recording has to supply some. 8.8.8.8 (Google Public DNS) and example.com are
# permanently allocated, certain to have VirusTotal objects, and carry no
# verdict that is likely to churn -- a fabricated value would record the 404
# path instead of the parser.
_RECORD_ACTIONS = {
    "vulncheck": None,  # explicit: fetch-shaped, listed for readability
    "virustotal": lambda adapter: adapter.enrich(
        ["8.8.8.8", "1.1.1.1"], indicator_type="ip"
    ),
}


async def record_one(name: str, creds, time_range: str) -> tuple[str, int | None, str]:
    factory, _ = FEEDS[name]
    cassette = CASSETTE_DIR / f"{name}.yaml"
    recorder = build_vcr(record_mode="all")
    try:
        # Replace, don't append: record_mode="all" stacks new interactions
        # behind any that already exist, and playback then never reaches them.
        fresh_recording(cassette)
        with recorder.use_cassette(str(cassette)):
            adapter = factory(creds)
            action = _RECORD_ACTIONS.get(name)
            if action is not None:
                result = await action(adapter)
                # Enrichment returns a dict, not a FetchResult.
                count = result["record_count"]
            else:
                result = await adapter.fetch(time_range=time_range)
                count = result.record_count
        if shrink := _SHRINK.get(name):
            before, after = shrink(cassette)
            logger_note = f" (trimmed {before / 1e6:.1f} MB -> {after / 1e6:.1f} MB)"
            print(f"  {name}:{logger_note}")
        # A cassette of an empty response teaches nothing and would make the
        # cassette test assert against a quiet day forever.
        note = "" if count else "  (WARNING: recorded an empty response)"
        return name, count, f"recorded {cassette.name}{note}"
    except Exception as exc:  # noqa: BLE001 - report, do not abort the batch
        if cassette.exists() and cassette.stat().st_size == 0:
            cassette.unlink()
        return name, None, f"FAILED {type(exc).__name__}: {exc}"


def _header_problems(headers, where: str, path_name: str) -> list[str]:
    problems = []
    for name, values in (headers or {}).items():
        if name.lower() not in _SECRET_HEADER_NAMES:
            continue
        for value in values if isinstance(values, list) else [values]:
            if _REDACTED not in str(value):
                problems.append(
                    f"{path_name}: {where} header {name!r} is not redacted"
                )
    return problems


def verify_scrubbed(names: list[str]) -> list[str]:
    """Check recorded cassettes for credentials, structurally and literally.

    Two independent checks:

    1. **Structural** -- request headers, the request URI's query string, and
       response headers must carry no unredacted credential. Response *bodies*
       are deliberately not scanned: they are public threat data, and scanning
       them for words like "password" fails on every NVD recording.
    2. **Literal** -- for each credential that is actually configured in the
       environment, assert its value does not appear anywhere in the file. This
       has no false positives and catches a leak wherever it landed.
    """
    import urllib.parse

    problems: list[str] = []
    live_secrets = {
        var: os.environ[var]
        for var in _CREDENTIAL_ENV_VARS
        if os.environ.get(var, "").strip()
    }

    for name in names:
        path = CASSETTE_DIR / f"{name}.yaml"
        if not path.is_file():
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")

        # 2. Literal check first -- the one that matters most.
        for var, value in live_secrets.items():
            if value in raw:
                problems.append(
                    f"{path.name}: contains the literal value of ${var}"
                )

        # 1. Structural check.
        try:
            doc = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            problems.append(f"{path.name}: not parseable as YAML ({exc})")
            continue
        for interaction in doc.get("interactions") or []:
            request = interaction.get("request") or {}
            response = interaction.get("response") or {}
            problems += _header_problems(
                request.get("headers"), "request", path.name
            )
            problems += _header_problems(
                response.get("headers"), "response", path.name
            )
            query = urllib.parse.parse_qs(
                urllib.parse.urlparse(request.get("uri") or "").query
            )
            for param, values in query.items():
                if param.lower() in _SECRET_QUERY_PARAMS and not any(
                    _REDACTED in v for v in values
                ):
                    problems.append(
                        f"{path.name}: query parameter {param!r} is not redacted"
                    )
    return problems


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="include keyed feeds")
    parser.add_argument("--only", nargs="*", help="record only these feeds")
    parser.add_argument("--time-range", default="7d")
    parser.add_argument(
        "--skip-verify", action="store_true", help="skip the leaked-secret scan"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="scan existing cassettes for leaked credentials and exit",
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

    if args.verify_only:
        present = [n for n in selected if (CASSETTE_DIR / f"{n}.yaml").is_file()]
        if not present:
            print("No cassettes present to verify.")
            return 0
        problems = verify_scrubbed(present)
        if problems:
            print("SCRUBBING CHECK FAILED — do not commit these cassettes:")
            for problem in problems:
                print(f"  {problem}")
            return 1
        print(f"Scrubbing check passed over {len(present)} cassette(s): {present}")
        return 0

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

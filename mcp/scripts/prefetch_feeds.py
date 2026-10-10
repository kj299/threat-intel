#!/usr/bin/env python3
"""Fetch every configured feed and write the result to a file (issue #169).

Why this exists
---------------
`scheduled-report.yml` runs an LLM agent whose job is ingesting untrusted
content -- threat feeds, vendor blogs, leak-site aggregators. Any feed
credential in that agent's environment is reachable by a prompt injection and
can leave in its output, which log masking does not cover. So the agent never
gets one. (It ran with `contents: write` when this split was made; its job is
now read-only too, and the split stays because a read-only agent can still
print what it can read.)

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
from threat_intel_mcp.adapters.epss import EPSSAdapter
from threat_intel_mcp.adapters.osv import OSVAdapter
from threat_intel_mcp.adapters.virustotal import (
    MAX_INDICATORS_PER_CALL as VT_MAX_PER_CALL,
    VirusTotalAdapter,
)
from threat_intel_mcp.server import _FEED_SOURCES, _VULN_SOURCES
from threat_intel_mcp.vault.factory import credential_provider_from_env
from threat_intel_mcp.vulns import fan_out_vulns

# Credentials are read by the adapters via EnvCredentialProvider; this script
# never touches their values. The names are needed only to prove none of them
# reached the output file.
_CREDENTIAL_ENV_SUFFIXES = ("_API_KEY", "_AUTH_KEY", "_API_ID", "_API_SECRET", "_EMAIL", "_TOKEN")


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
    handed to an agent whose output is published. The adapters put credentials in
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


# Capped per run so a pathological CVE week cannot turn the prefetch into a long
# sweep: 1000 is ten keyless requests. A normal window is ~12k CVEs, so this is a
# sample and the payload says so (`selected_from`, `selection`).
_MAX_CVES_TO_SCORE = 1000
_EPSS_SELECTION = "not already in CISA KEV first, then highest CVSS"


def _epss_priority(v: dict) -> tuple:
    # KEV already says "exploited"; EPSS adds most to the CVEs nothing else ranks.
    known = v.get("exploit_status") == "known_exploited"
    return (known, -(v.get("cvss_score") or 0.0))


async def _score_with_epss(vulns: dict) -> dict | None:
    """Rank the fetched CVEs by exploitation probability.

    This runs in the prefetch rather than being left to the agent because the
    `generate` job holds no MCP server at all -- that is the whole point of the
    two-job split (#169). An enrichment nobody calls is an enrichment that does
    not exist.

    EPSS is the enrichment that needs no cost decision at all:
    it is keyless, free, and batched 100 CVEs per request, so the bounded
    sample below (`_MAX_CVES_TO_SCORE`) costs ten requests against no quota. (VirusTotal costs
    one lookup per indicator against 500/day, so it is bounded and selective --
    see `_enrich_with_virustotal`.)

    A failure here degrades rather than fails: the CVE records are already in
    hand and are worth delivering unranked.
    """
    records = [v for v in vulns.get("vulns", []) if v.get("cve_id")]
    if not records:
        return None
    # Merged order puts CISA KEV first, so a plain slice scored only KEV entries.
    ids = [v["cve_id"] for v in sorted(records, key=_epss_priority)][:_MAX_CVES_TO_SCORE]
    sample = {"selected_from": len(records), "selection": _EPSS_SELECTION}

    try:
        return {**await EPSSAdapter().enrich(ids), **sample}
    except Exception as exc:  # noqa: BLE001 - an unranked report still ships
        print(f"EPSS enrichment degraded: {type(exc).__name__}: {exc}", file=sys.stderr)
        return {
            "enrichments": [],
            "source": "EPSS",
            "record_count": 0,
            "scored": [],
            "not_scored": [],
            "error": f"{type(exc).__name__}: {exc}",
            **sample,
        }


# OSV is keyless but sequential, up to 1 + 3 alias hops per CVE, so it is a
# bounded sample: the CVEs EPSS rates most likely to be exploited, which is where
# "which package, fixed in which version" matters most.
_MAX_CVES_FOR_OSV = 100
_OSV_SELECTION = "highest EPSS score first"


async def _enrich_with_osv(epss: dict | None) -> dict | None:
    """Affected packages and fixed versions for the riskiest CVEs this run."""
    scored = sorted(
        (r for r in (epss or {}).get("enrichments", []) if r.get("cve")),
        key=lambda r: -(r.get("epss") or 0.0),
    )
    if not scored:
        return None
    ids = [r["cve"] for r in scored[:_MAX_CVES_FOR_OSV]]
    sample = {"selected_from": len(scored), "selection": _OSV_SELECTION}
    try:
        return {**await OSVAdapter().enrich(ids), **sample}
    except Exception as exc:  # noqa: BLE001 - the CVEs still ship without packages
        reason = f"{type(exc).__name__}: {exc}"
        print(f"OSV enrichment degraded: {reason}", file=sys.stderr)
        return {"enrichments": [], "source": "OSV.dev", "record_count": 0,
                "found": [], "not_found": [], "failed": ids, "error": reason, **sample}


# VirusTotal's public API allows 4 lookups/min and 500/day, so unlike EPSS this
# enrichment has a real budget and a real wall-clock cost: 15 seconds per
# indicator. 40 is ~10 minutes and 8% of the daily quota, which leaves room for
# a re-run and for anything else using the key. Override with --virustotal-limit;
# 0 disables it entirely.
_DEFAULT_VT_LIMIT = 40

# VirusTotal's per-indicator endpoints cover IPs and domains. URLs and CIDR
# ranges have no lookup in this adapter, so they are not candidates -- selecting
# one would spend a slot on a request that cannot succeed.
_VT_TYPE_OF = {"IPv4": "ip", "IPv6": "ip", "Domain": "domain"}


def _select_for_enrichment(iocs: list[dict], limit: int) -> dict[str, list[str]]:
    """Choose which indicators are worth a VirusTotal lookup.

    Order matters more than count here. At 15 seconds each there is room for
    tens of indicators out of thousands, so "the first N" would mean "whichever
    feed happened to sort first" -- a selection made by list order rather than
    by judgement.

    **Corroborated indicators go first.** ``finalize_iocs`` tags an indicator
    two independent feeds both reported with ``corroborated-by:<source>``, and
    those are the ones a report foregrounds. A VirusTotal verdict is worth most
    where a claim is about to be made, and worth least on the ten-thousandth
    row nobody will read.

    Ties are then broken by confidence, and the remainder is taken in feed
    order. Within each bucket the original order is preserved, so the selection
    is deterministic: the same payload picks the same indicators.
    """
    # Redundant with the budget check in the loop below, which also yields {}
    # for a limit of 0 -- kept because "0 disables this" should be legible at
    # the top of the function rather than emergent from a >= comparison forty
    # lines down. Deliberate belt-and-braces on the one path that spends quota.
    if limit <= 0:
        return {}

    def rank(ioc: dict) -> tuple[int, int]:
        tags = ioc.get("tags") or []
        corroborated = any(
            isinstance(tag, str) and tag.startswith("corroborated-by:") for tag in tags
        )
        confidence = {"High": 0, "Medium": 1, "Low": 2}.get(ioc.get("confidence"), 3)
        return (0 if corroborated else 1, confidence)

    candidates = [
        (rank(ioc), index, _VT_TYPE_OF[ioc["type"]], ioc["value"])
        for index, ioc in enumerate(iocs)
        if ioc.get("type") in _VT_TYPE_OF and ioc.get("value")
    ]
    candidates.sort(key=lambda c: (c[0], c[1]))

    selected: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    for _, _, kind, value in candidates:
        if sum(len(v) for v in selected.values()) >= limit:
            break
        if (kind, value) in seen:
            continue
        bucket = selected.setdefault(kind, [])
        # The adapter rejects an over-long list rather than truncating it, so
        # the split is capped per type as well as in total.
        if len(bucket) >= VT_MAX_PER_CALL:
            continue
        bucket.append(value)
        seen.add((kind, value))
    return selected


async def _enrich_with_virustotal(iocs: dict, limit: int) -> dict | None:
    """Score a bounded, deliberately chosen slice of the indicators.

    Runs in the prefetch for the same reason EPSS does: the `generate` job
    holds no MCP server, so an enrichment nobody calls does not exist.

    Unlike EPSS this costs quota and wall clock, so it reports what it spent
    and on what basis -- `selected_from` says how many candidates there were,
    so a reader can see this is a sample and not feed-wide coverage. Claiming
    otherwise in the Coverage Ledger would inflate the badge (R4).

    A failure degrades: the indicators are already in hand and worth shipping
    unenriched.
    """
    selection = _select_for_enrichment(iocs.get("iocs", []), limit)
    if not selection:
        return None

    adapter = VirusTotalAdapter(credential_provider_from_env())
    enrichments: list[dict] = []
    looked_up: list[str] = []
    errors: list[str] = []

    for kind, values in selection.items():
        try:
            result = await adapter.enrich(values, indicator_type=kind)
        except Exception as exc:  # noqa: BLE001 - an unenriched report still ships
            print(
                f"VirusTotal {kind} enrichment degraded: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            errors.append(f"{kind}: {type(exc).__name__}")
            continue
        enrichments.extend(result.get("enrichments", []))
        looked_up.extend(result.get("looked_up", []))

    candidates = sum(
        1 for i in iocs.get("iocs", []) if i.get("type") in _VT_TYPE_OF
    )
    block = {
        "enrichments": enrichments,
        "source": "VirusTotal",
        "record_count": len(enrichments),
        "looked_up": looked_up,
        # Load-bearing for honesty: this is a sample, and the ledger must not
        # record VirusTotal as covering the whole feed set.
        "selected_from": candidates,
        "selection": "corroborated first, then by confidence, then feed order",
    }
    if errors:
        block["error"] = "; ".join(errors)
    return block


async def collect(time_range: str, virustotal_limit: int = _DEFAULT_VT_LIMIT) -> dict:
    """Fetch IOC and CVE feeds concurrently and return one combined payload."""
    iocs, vulns = await asyncio.gather(
        fan_out(_FEED_SOURCES, time_range=time_range),
        fan_out_vulns(_VULN_SOURCES, time_range=time_range),
    )
    # Sequential, not gathered: both need what the fan-outs just produced.
    epss = await _score_with_epss(vulns)
    osv = await _enrich_with_osv(epss)
    virustotal = await _enrich_with_virustotal(iocs, virustotal_limit)
    payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "time_range": time_range,
        "iocs": iocs,
        "vulns": vulns,
    }
    if epss is not None:
        payload["cve_enrichment"] = {"epss": epss}
    if osv is not None:
        payload.setdefault("cve_enrichment", {})["osv"] = osv
    if virustotal is not None:
        payload["ioc_enrichment"] = {"virustotal": virustotal}
    return payload


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
    virustotal = payload.get("ioc_enrichment", {}).get("virustotal")
    if virustotal is not None:
        if virustotal.get("error"):
            lines.append(f"virustotal: degraded — {virustotal['error']}")
        lines.append(
            f"virustotal: {virustotal['record_count']} of "
            f"{virustotal['selected_from']} eligible indicators enriched "
            f"({virustotal['selection']})"
        )
    osv = payload.get("cve_enrichment", {}).get("osv")
    if osv is not None:
        if osv.get("error"):
            lines.append(f"osv: degraded — {osv['error']}")
        else:
            lines.append(
                f"osv: {len(osv.get('found', []))} of {osv['selected_from']} scored CVEs "
                f"have OSV records (looked up {_MAX_CVES_FOR_OSV} max, {osv['selection']})"
            )
    epss = payload.get("cve_enrichment", {}).get("epss")
    if epss is not None:
        if epss.get("error"):
            lines.append(f"epss: degraded — {epss['error']}")
        else:
            lines.append(
                f"epss: {epss['record_count']} of "
                f"{epss['record_count'] + len(epss['not_scored'])} CVEs scored, "
                f"selected from {epss.get('selected_from', '?')} ({epss.get('selection', '')})"
            )
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
    parser.add_argument(
        "--virustotal-limit",
        type=int,
        default=_DEFAULT_VT_LIMIT,
        help=(
            "How many indicators to enrich with VirusTotal. Each costs ~15s of "
            "wall clock and one of 500 daily lookups, so this is a sample, not "
            f"coverage. 0 disables it. Default: {_DEFAULT_VT_LIMIT}."
        ),
    )
    args = parser.parse_args(argv)

    payload = asyncio.run(collect(args.time_range, args.virustotal_limit))
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

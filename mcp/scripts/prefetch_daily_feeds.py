"""Bounded data-only daily handoff using the existing feed/enrichment pipeline."""

import argparse
import asyncio
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path

import prefetch_feeds

MAX_BYTES = 128 * 1024 * 1024
TIMEOUT_SECONDS = 1200
VT_LIMIT = 8


def encode(payload):
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # Include escaped forms and short values too: fail closed rather than risk
    # exporting a credential. Never print a response/exception before scanning.
    for value in prefetch_feeds._credential_values().values():
        if value in raw or json.dumps(value, ensure_ascii=False)[1:-1] in raw:
            raise ValueError("Credential detected; artifact withheld")
    if len(raw.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Artifact exceeds 128 MiB; no truncated success exported")
    return raw


async def collect():
    started = datetime.now(timezone.utc).isoformat()
    payload = await asyncio.wait_for(
        prefetch_feeds.collect("24h", virustotal_limit=VT_LIMIT), TIMEOUT_SECONDS
    )
    payload["daily_contract"] = {
        "version": 1,
        "collection_started_at": started,
        "registry": {
            "iocs": [s.name for s in prefetch_feeds._FEED_SOURCES],
            "vulns": [s.name for s in prefetch_feeds._VULN_SOURCES],
        },
        "enrichment_limits": {"epss": 1000, "osv": 100, "virustotal": VT_LIMIT},
        "enrichment_scope": "selected samples only; absent blocks mean not run",
        "record_scope": "candidate evidence, not proof of in-window publication",
    }
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    # Upstream exception strings may contain response text; never send these to
    # Actions logs. Coverage diagnostics survive in the scanned artifact only.
    previous_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        with open(os.devnull, "w") as sink, redirect_stdout(sink), redirect_stderr(sink):
            raw = encode(asyncio.run(collect()))
        args.out.write_text(raw, encoding="utf-8")
    except Exception:
        print("Daily feed collection unavailable; no artifact published. Continue report with gaps.")
        return 1
    finally:
        logging.disable(previous_disable)
    print("Credential-scanned daily data artifact written; coverage is recorded per source.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

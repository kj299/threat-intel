"""One bounded ThreatFox read; publish only credential-scanned report data."""

import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path

import httpx

from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter
from threat_intel_mcp.normalize import finalize_iocs
from threat_intel_mcp.resilience import retry_with_backoff
from threat_intel_mcp.vault.env import EnvCredentialProvider

MAX_OUTPUT_BYTES = 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


async def collect(adapter):
    started = now()
    summary = {
        "source": "ThreatFox",
        "tier": 9,
        "status": "unverified",
        "record_count": 0,
        "partial_failure": [],
        "error": None,
        "collection_started_at": started,
        "attempt_count": 0,
    }
    async def fetch():
        summary["attempt_count"] += 1
        return await adapter.fetch(time_range="24h")

    records = []
    try:
        # get_iocs is read-only. Retry only the observed protocol failure, here
        # rather than in the adapter (whose fan-out callers already retry).
        # One shared deadline covers both attempts and the bounded backoff.
        result = await asyncio.wait_for(
            retry_with_backoff(
                fetch, retries=1, retry_on=(httpx.RemoteProtocolError,),
                base_delay=0.5, max_delay=0.5,
            ),
            timeout=90,
        )
        records = finalize_iocs(result.iocs)
        summary.update(
            status="partial" if result.partial_failure else "consulted",
            record_count=len(records),
            partial_failure=result.partial_failure,
            retrieved_at=result.retrieved_at,
        )
    except Exception as exc:
        # Exception messages and HTTP response bodies may contain credentials.
        summary["error"] = (
            f"ThreatFox collection failed ({type(exc).__name__}); details withheld"
        )
    summary["collection_completed_at"] = now()
    return {
        "time_range": "24h",
        "generated_at": now(),
        "iocs": {
            "retrieved_at": summary["collection_completed_at"],
            "record_count": len(records),
            "iocs": records,
            "per_source": [summary],
            "sources_consulted": ["ThreatFox"]
            if summary["status"] == "consulted"
            else [],
            "sources_degraded": [] if summary["status"] == "consulted" else [summary],
            "coverage_ledger": [
                {"source": "ThreatFox", "tier": 9, "status": summary["status"]}
            ],
        },
    }


def encode(payload, key):
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    encoded_key = json.dumps(key, ensure_ascii=False)[1:-1] if key else ""
    if key and (key in raw or encoded_key in raw):
        raise RuntimeError("Credential material detected; artifact not written")
    if len(raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
        summary = payload["iocs"]["per_source"][0].copy()
        summary.update(
            status="unverified",
            record_count=0,
            error="ThreatFox output exceeded 1 MiB; records withheld",
        )
        payload = {
            **payload,
            "iocs": {
                **payload["iocs"],
                "iocs": [],
                "record_count": 0,
                "per_source": [summary],
                "sources_consulted": [],
                "sources_degraded": [summary],
                "coverage_ledger": [
                    {"source": "ThreatFox", "tier": 9, "status": "unverified"}
                ],
            },
        }
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if (key and (key in raw or encoded_key in raw)) or len(
        raw.encode("utf-8")
    ) > MAX_OUTPUT_BYTES:
        raise RuntimeError("Artifact safety check failed; artifact not written")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    payload = asyncio.run(collect(ThreatFoxAdapter(EnvCredentialProvider())))
    raw = encode(payload, os.environ.get("ABUSECH_AUTH_KEY", ""))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(raw, encoding="utf-8")
    # Print only fixed status and count, never indicators or exception text.
    summary = json.loads(raw)["iocs"]["per_source"][0]
    print(f"ThreatFox: {summary['status']}; {summary['record_count']} records")


if __name__ == "__main__":
    main()

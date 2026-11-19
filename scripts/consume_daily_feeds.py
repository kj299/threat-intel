"""Credential-free all-feed artifact validation; records remain research candidates."""

import argparse
import hashlib
import json
import zipfile
from datetime import timedelta
from pathlib import Path

from consume_threatfox import (
    MAX_ARTIFACT_BYTES,
    ArtifactInputError,
    read_payload,
    stamp,
)
from consume_threatfox import consume as consume_threatfox

REGISTRY = {
    "iocs": ["Q-Feeds", "AbuseIPDB", "AlienVault OTX", "Shodan", "GreyNoise",
             "ANY.RUN", "Intel 471", "Censys", "ThreatFox", "OpenPhish", "URLhaus",
             "Feodo Tracker", "Pulsedive"],
    "vulns": ["CISA KEV", "NVD", "VulnCheck KEV"],
}


def consume(payload, run, artifact, jobs, *, report_end, expected_sha):
    result = {
        "status": "unverified", "candidate_data": None,
        "report_start": (report_end - timedelta(days=1)).isoformat(),
        "report_end": report_end.isoformat(),
        "limitations": [
            "Fresh acquisition is not fresh publication or material update. Records are research candidates only.",
            "Snapshots, historical CVEs and last_seen alone do not establish a current development.",
            "Each finding needs independent in-window publication/material-update evidence and conditional exposure.",
            "Enrichment covers selected samples only; absent blocks mean not run, not zero hits.",
            "Web-only source matrix research and government advisory receipts remain separate work.",
            "Technical access does not establish commercial-use entitlement.",
        ],
    }
    try:
        if (run["repository"]["full_name"] != "kj299/threat-intel"
                or run["path"] != ".github/workflows/daily-feeds-prefetch.yml"
                or run["head_branch"] != "main" or run["head_sha"] != expected_sha
                or run["event"] != "workflow_dispatch"
                or run["status"] != "completed" or run["conclusion"] != "success"):
            raise ArtifactInputError("Unexpected or unsuccessful run provenance")
        if (artifact["name"] != "daily-feed-data" or artifact["expired"]
                or artifact["workflow_run"]["id"] != run["id"]
                or not 0 < artifact["size_in_bytes"] <= MAX_ARTIFACT_BYTES):
            raise ArtifactInputError("Missing, expired or mismatched artifact")
        matching = [j for j in jobs["jobs"]
                    if j["name"] == "Fetch daily feeds (holds credentials; no agent)"]
        if (len(matching) != 1 or matching[0]["conclusion"] != "success"
                or matching[0]["run_id"] != run["id"]):
            raise ArtifactInputError("Missing successful collection job for this run")
        job = matching[0]
        started, ended = stamp(job["started_at"]), stamp(job["completed_at"])
        generated = stamp(payload["generated_at"])
        contract = payload["daily_contract"]
        collected_start = stamp(contract["collection_started_at"])
        if (contract["version"] != 1 or contract["registry"] != REGISTRY
                or payload["time_range"] != "24h"):
            raise ArtifactInputError("Incompatible daily collection contract")
        if (not started <= collected_start <= generated <= ended <= report_end
                or report_end - started > timedelta(hours=2)):
            raise ArtifactInputError("Stale, future or inconsistent acquisition bounds")
        coverage = []
        for section, names in REGISTRY.items():
            block = payload[section]
            completed = stamp(block["retrieved_at"])
            if not collected_start <= completed <= generated:
                raise ArtifactInputError("Invalid fan-out acquisition bounds")
            rows = block["per_source"]
            if (len(rows) != len(names)
                    or {row["source"] for row in rows} != set(names)):
                raise ArtifactInputError("Missing, duplicate or unexpected source receipt")
            if block["record_count"] != len(block[section]):
                raise ArtifactInputError("Inconsistent record count")
            for row in rows:
                if (row["status"] not in ("consulted", "partial", "unverified")
                        or type(row["record_count"]) is not int or row["record_count"] < 0
                        or (row["status"] == "unverified" and row["record_count"] != 0)):
                    raise ArtifactInputError("Invalid per-source status or count")
                # The shared fan-out omits individual retrieval clocks. Bound
                # conservatively; never invent a per-source timestamp.
                coverage.append({**row, "acquisition_between": [
                    collected_start.isoformat(), completed.isoformat()],
                    "timestamp_basis": "collector start to fan-out completion; individual time unavailable",
                    "outcome": ("unavailable" if row["status"] == "unverified" else
                                "zero_records" if row["record_count"] == 0 else "candidate_records")})
        result.update(
            status="partial" if any(r["status"] != "unverified" for r in coverage) else "unverified",
            candidate_data=payload, coverage=coverage,
            run_id=run["id"], run_url=run["html_url"], commit=expected_sha,
            artifact_id=artifact["id"], generated_at=generated.isoformat(),
            acquisition_between=[collected_start.isoformat(), generated.isoformat()],
            threatfox=consume_threatfox(payload, run, artifact, jobs,
                                       report_end=report_end, expected_sha=expected_sha),
        )
    except ArtifactInputError as exc:
        result["reason"] = str(exc)
    except (KeyError, TypeError, ValueError, AttributeError):
        result["reason"] = "Invalid artifact metadata or payload; continue report with explicit gaps"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path)
    source.add_argument("--payload", type=Path)
    for name in ("run", "artifact", "jobs"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--report-end", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = read_payload(args.archive or args.payload, archive=bool(args.archive))
        result = consume(json.loads(raw), *[
            json.loads(getattr(args, name).read_text()) for name in ("run", "artifact", "jobs")
        ], report_end=stamp(args.report_end), expected_sha=args.expected_sha)
        result["source_payload_sha256"] = hashlib.sha256(raw).hexdigest()
        encoded = json.dumps(result, separators=(",", ":"))
        if len(encoded.encode()) > MAX_ARTIFACT_BYTES:
            raise ArtifactInputError("Derivative exceeds size bound")
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        encoded = json.dumps({"status": "unverified", "candidate_data": None,
                              "reason": "Input unavailable or oversized; continue report with gaps"})
    args.out.write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()

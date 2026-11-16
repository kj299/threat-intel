"""Validate a scanned Actions feed artifact for a daily report; never fetch secrets.

Run metadata and artifact metadata must come from GitHub's API, not feed content.
An unavailable source is a report input, not a reason to cancel report delivery.
"""

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


class ArtifactInputError(ValueError):
    """A fixed diagnostic safe to expose in the coverage ledger."""


def stamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return parsed.astimezone(timezone.utc)


def consume(
    payload, run, artifact, jobs, *, report_end, expected_sha, max_age_minutes=120
):
    result = {
        "source": "ThreatFox",
        "status": "unverified",
        "iocs": [],
        "report_end": report_end.isoformat(),
        "limitations": [
            "get_iocs selects first_seen, not all updated or active IOCs.",
            "Technical access does not establish commercial-use entitlement.",
        ],
    }
    try:
        if (
            run["repository"]["full_name"] != "kj299/threat-intel"
            or run["path"] != ".github/workflows/scheduled-report.yml"
            or run["head_branch"] != "main"
            or run["head_sha"] != expected_sha
            or run["event"] != "workflow_dispatch"
        ):
            raise ArtifactInputError("unexpected workflow, branch, commit or event")
        if (
            artifact["name"] != "feed-data"
            or artifact["expired"]
            or artifact["workflow_run"]["id"] != run["id"]
            or artifact["size_in_bytes"] <= 0
        ):
            raise ArtifactInputError("missing, expired or mismatched artifact")
        prefetch = [
            j
            for j in jobs["jobs"]
            if j["name"] == "Fetch feeds (holds credentials; no agent)"
        ]
        if len(prefetch) != 1 or prefetch[0]["conclusion"] != "success":
            raise ArtifactInputError("prefetch job did not succeed")
        if payload["time_range"] not in ("24h", "1d"):
            raise ArtifactInputError("artifact is not a 24-hour collection")
        started = stamp(prefetch[0]["started_at"])
        collected = stamp(payload["iocs"]["retrieved_at"])
        generated = stamp(payload["generated_at"])
        if not started <= collected <= generated <= report_end:
            raise ArtifactInputError("inconsistent or future acquisition timestamps")
        if report_end - started > timedelta(minutes=max_age_minutes):
            raise ArtifactInputError("collection exceeds freshness budget")
        summaries = [
            s for s in payload["iocs"]["per_source"] if s["source"] == "ThreatFox"
        ]
        if len(summaries) != 1 or summaries[0]["status"] not in (
            "consulted",
            "partial",
        ):
            raise ArtifactInputError("ThreatFox unavailable in this collection")
        report_start = report_end - timedelta(days=1)
        selected = []
        for record in payload["iocs"]["iocs"]:
            # The winning merged record can belong to another provider. Use
            # ThreatFox's own evidence, never that winner's first_seen.
            evidence = record.get("source_evidence") or [record]
            matching = [e for e in evidence if e.get("source") == "ThreatFox"]
            for entry in matching:
                first_seen = stamp(entry["first_seen"])
                if report_start <= first_seen <= collected:
                    selected.append(
                        {
                            "type": record["type"],
                            "value": record["value"],
                            "source": "ThreatFox",
                            "first_seen": first_seen.isoformat(),
                            "confidence": entry.get("confidence"),
                            "tlp": record.get("tlp"),
                            "source_evidence": matching,
                        }
                    )
                    break
        result.update(
            status="partial",
            iocs=selected,
            record_count=len(selected),
            run_url=run["html_url"],
            run_id=run["id"],
            commit=run["head_sha"],
            artifact_id=artifact["id"],
            generated_at=generated.isoformat(),
            acquisition_between=[started.isoformat(), collected.isoformat()],
            report_start=report_start.isoformat(),
        )
        result["limitations"].append(
            "Per-source retrieval time is absent from this artifact. Acquisition is bounded "
            "by prefetch start and IOC fan-out completion; the remainder before report_end "
            "is unobserved. Do not claim complete 24-hour coverage."
        )
        if summaries[0].get("partial_failure"):
            result["limitations"].append(
                "Upstream also reports partial coverage; preserve artifact caveats."
            )
    except ArtifactInputError as exc:
        result.update(reason=str(exc), record_count=0)
    except (KeyError, TypeError, ValueError, AttributeError):
        result.update(
            reason="Artifact missing, stale, incompatible, or ThreatFox unavailable; "
            "continue report with other verified sources.",
            record_count=0,
        )
    return result


def encode_compact(result):
    """Bound the downstream derivative; never silently sample oversized data."""
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 1024 * 1024:
        return json.dumps(
            {
                "source": "ThreatFox",
                "status": "unverified",
                "iocs": [],
                "record_count": 0,
                "reason": "Compact output exceeds 1 MiB; no records exported.",
            }
        )
    return encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("payload", "run", "artifact", "jobs"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--report-end", required=True)
    args = parser.parse_args()
    try:
        inputs = [
            json.loads(getattr(args, name).read_text())
            for name in ("payload", "run", "artifact", "jobs")
        ]
        result = consume(
            *inputs, report_end=stamp(args.report_end), expected_sha=args.expected_sha
        )
        result["source_payload_sha256"] = hashlib.sha256(
            args.payload.read_bytes()
        ).hexdigest()
    except (OSError, ValueError):
        result = {
            "source": "ThreatFox",
            "status": "unverified",
            "iocs": [],
            "reason": "Input unreadable; continue report with other verified sources.",
        }
    print(encode_compact(result))


if __name__ == "__main__":
    main()

"""Validate a scanned Actions feed artifact for a daily report; never fetch secrets.

Run metadata and artifact metadata must come from GitHub's API, not feed content.
An unavailable source is a report input, not a reason to cancel report delivery.
"""

import argparse
import hashlib
import json
import stat
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


class ArtifactInputError(ValueError):
    """A fixed diagnostic safe to expose in the coverage ledger."""


MAX_ARTIFACT_BYTES = 128 * 1024 * 1024


def read_payload(path, *, archive=False):
    """Read only the expected regular member under explicit byte limits."""
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ArtifactInputError("Artifact exceeds 128 MiB input limit")
    if not archive:
        return path.read_bytes()
    with zipfile.ZipFile(path) as zipped:
        members = zipped.infolist()
        if len(members) != 1 or members[0].filename != "feed-data.json":
            raise ArtifactInputError("Unexpected archive members")
        member = members[0]
        if not stat.S_ISREG(member.external_attr >> 16):
            raise ArtifactInputError("Archive member is not a regular file")
        if member.file_size > MAX_ARTIFACT_BYTES:
            raise ArtifactInputError("Uncompressed artifact exceeds 128 MiB limit")
        with zipped.open(member) as stream:
            raw = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES or len(raw) != member.file_size:
            raise ArtifactInputError("Archive member size mismatch")
        return raw


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
        routes = {
            ".github/workflows/daily-feeds-prefetch.yml": (
                "daily-feed-data",
                "Fetch daily feeds (holds credentials; no agent)",
                {"workflow_dispatch"},
            ),
            ".github/workflows/scheduled-report.yml": (
                "feed-data",
                "Fetch feeds (holds credentials; no agent)",
                {"workflow_dispatch"},
            ),
            ".github/workflows/threatfox-prefetch.yml": (
                "threatfox-feed-data",
                "Fetch ThreatFox (holds credential; no agent)",
                {"schedule", "workflow_dispatch"},
            ),
        }
        route = routes.get(run["path"])
        if (
            run["repository"]["full_name"] != "kj299/threat-intel"
            or route is None
            or run["head_branch"] != "main"
            or run["head_sha"] != expected_sha
            or run["event"] not in route[2]
        ):
            raise ArtifactInputError("unexpected workflow, branch, commit or event")
        if (
            artifact["name"] != route[0]
            or artifact["expired"]
            or artifact["workflow_run"]["id"] != run["id"]
            or artifact["size_in_bytes"] <= 0
        ):
            raise ArtifactInputError("missing, expired or mismatched artifact")
        prefetch = [j for j in jobs["jobs"] if j["name"] == route[1]]
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
        source_started = stamp(
            summaries[0].get("collection_started_at", started.isoformat())
        )
        source_completed = stamp(
            summaries[0].get("collection_completed_at", collected.isoformat())
        )
        if not started <= source_started <= source_completed <= collected:
            raise ArtifactInputError("inconsistent source acquisition bounds")
        report_start = report_end - timedelta(days=1)
        selected = []
        for record in payload["iocs"]["iocs"]:
            # The winning merged record can belong to another provider. Use
            # ThreatFox's own earliest evidence, never that winner's first_seen
            # or a later re-observation that could make an old record look new.
            evidence = record.get("source_evidence") or [record]
            matching = [e for e in evidence if e.get("source") == "ThreatFox"]
            dated = [(stamp(entry["first_seen"]), entry) for entry in matching]
            if dated:
                first_seen, entry = min(dated, key=lambda pair: pair[0])
                if not report_start <= first_seen <= source_completed:
                    continue
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
        result.update(
            status="partial",
            upstream_status=summaries[0]["status"],
            upstream_record_count=summaries[0].get("record_count"),
            upstream_partial_failure=summaries[0].get("partial_failure", []),
            iocs=selected,
            record_count=len(selected),
            run_url=run["html_url"],
            run_id=run["id"],
            commit=run["head_sha"],
            artifact_id=artifact["id"],
            generated_at=generated.isoformat(),
            acquisition_between=[
                source_started.isoformat(),
                source_completed.isoformat(),
            ],
            report_start=report_start.isoformat(),
        )
        if "output_limit" in summaries[0]:
            result["upstream_output_limit"] = summaries[0]["output_limit"]
        if "collection_started_at" in summaries[0]:
            result["limitations"].append(
                "Acquisition bounds come from the source-only collector. The interval "
                "before report_end remains unobserved; do not claim complete 24-hour coverage."
            )
        else:
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


MAX_COMPACT_BYTES = 1024 * 1024


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def encode_compact(result):
    """Expose a size-limited whole-record prefix without claiming full coverage."""
    encoded = _json(result)
    if len(encoded.encode("utf-8")) <= MAX_COMPACT_BYTES:
        return encoded

    records = result["iocs"]
    total = len(records)
    try:
        ordered = sorted(records, key=lambda row: (row["type"], row["value"]))
        ordered.sort(key=lambda row: stamp(row["first_seen"]), reverse=True)
        if result["status"] != "partial":
            ordered = []
    except (KeyError, TypeError, ValueError, AttributeError):
        ordered = []
    sizes = [0]
    for row in ordered:
        sizes.append(sizes[-1] + len(_json(row).encode("utf-8")))

    def candidate(count, selected):
        message = (
            f"Compact output 1 MiB limit: exported {count} of {total} "
            f"window-matched records; {total - count} omitted "
            "(newest first, whole records)."
        )
        packet = {
            **result,
            "status": "partial" if count else "unverified",
            "iocs": selected,
            "record_count": count,
            "compact_export": {"eligible_count": total, "omitted_count": total - count},
            "limitations": [*result.get("limitations", []), message],
        }
        if not count:
            packet["reason"] = message
        return packet

    lo, hi = 0, len(ordered)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        size = len(_json(candidate(mid, [])).encode("utf-8")) + sizes[mid] + mid - 1
        if size <= MAX_COMPACT_BYTES:
            lo = mid
        else:
            hi = mid - 1
    encoded = _json(candidate(lo, ordered[:lo]))
    if len(encoded.encode("utf-8")) <= MAX_COMPACT_BYTES:
        return encoded
    # Oversized metadata, not just records: retain the fixed diagnostic only.
    return _json(
        {
            "source": "ThreatFox",
            "status": "unverified",
            "iocs": [],
            "record_count": 0,
            "reason": "Compact output metadata exceeds 1 MiB; no records exported.",
        }
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--payload", type=Path)
    source.add_argument("--archive", type=Path)
    for name in ("run", "artifact", "jobs"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--report-end", required=True)
    args = parser.parse_args()
    try:
        raw_payload = read_payload(
            args.archive or args.payload, archive=bool(args.archive)
        )
        inputs = [json.loads(raw_payload)] + [
            json.loads(getattr(args, name).read_text())
            for name in ("run", "artifact", "jobs")
        ]
        result = consume(
            *inputs, report_end=stamp(args.report_end), expected_sha=args.expected_sha
        )
        result["source_payload_sha256"] = hashlib.sha256(raw_payload).hexdigest()
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        result = {
            "source": "ThreatFox",
            "status": "unverified",
            "iocs": [],
            "reason": "Input unreadable; continue report with other verified sources.",
        }
    print(encode_compact(result), end="")


if __name__ == "__main__":
    main()

"""Check recent successful report runs for an unexpired delivery artifact.

Input is a list of workflow runs with their `artifacts` arrays attached. A green
run without a report artifact is not delivery. Network collection belongs to the
workflow; this decision is deterministic and independently testable.
"""
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def delivered(runs, *, now, max_age_days=10):
    cutoff = now - timedelta(days=max_age_days)
    for run in runs:
        if run.get('conclusion') != 'success':
            continue
        stamp = datetime.fromisoformat(run['created_at'].replace('Z', '+00:00'))
        if not cutoff <= stamp <= now:
            continue
        if any(a.get('name') == 'threat-intel-report' and not a.get('expired', True)
               and a.get('size_in_bytes', 0) > 0 for a in run.get('artifacts', [])):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', type=Path)
    args = parser.parse_args()
    ok = delivered(json.loads(args.runs.read_text()), now=datetime.now(timezone.utc))
    print('Recent report artifact delivered' if ok else 'No successful report delivery in the last 10 days')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Ground structured feed-only reports in the actual supplied prefetch evidence.

This opt-in check does not judge prose or independently browsed sources. Input is
an output-schema `skill_output` object and a prefetch payload. Exact source names
and machine values are required; render/defang only after validating the object.
"""
import argparse
import json
from pathlib import Path


def check(report: dict, evidence: dict) -> list[str]:
    failures = []
    supported = {}
    for ioc in evidence.get('iocs', {}).get('iocs', []):
        key = (ioc['type'], ioc['value'])
        sources = {ioc['source']}
        sources.update(e['source'] for e in ioc.get('source_evidence', []) if 'source' in e)
        supported.setdefault(key, set()).update(sources)
    for ioc in report.get('iocs', {}).get('network', []):
        key = (ioc.get('type'), ioc.get('value'))
        if key not in supported:
            failures.append('unsupported indicator: ' + str(key))
        elif ioc.get('source') not in supported[key]:
            failures.append('unsupported attribution: ' + str(key))
    consulted = {row['source'] for section in ('iocs', 'vulns')
                 for row in evidence.get(section, {}).get('coverage_ledger', [])
                 if row['status'] == 'consulted'}
    for row in report.get('coverage_ledger', []):
        for source in row.get('consulted', []):
            if source not in consulted:
                failures.append('unsupported full consultation: ' + source)
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    failures = check(report.get('skill_output', report), json.loads(args.evidence.read_text()))
    for failure in failures:
        print(failure)
    return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())

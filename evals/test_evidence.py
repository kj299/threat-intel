"""Adversarial evidence grounding, independent of the frozen prose corpus."""
from copy import deepcopy

from evidence import check

EVIDENCE = {'iocs': {'iocs': [{'type': 'Domain', 'value': 'malicious.example', 'source': 'Feed A'}], 'coverage_ledger': [{'source': 'Feed A', 'status': 'consulted'}, {'source': 'Feed B', 'status': 'partial'}]}}
REPORT = {'iocs': {'network': [{'type': 'Domain', 'value': 'malicious.example', 'source': 'Feed A'}]}, 'coverage_ledger': [{'consulted': ['Feed A']}]}


def test_supported_report():
    assert check(REPORT, EVIDENCE) == []


def test_invented_indicator():
    report = deepcopy(REPORT)
    report['iocs']['network'][0]['value'] = 'invented.example'
    assert check(report, EVIDENCE) == ["unsupported indicator: ('Domain', 'invented.example')"]


def test_invented_attribution():
    report = deepcopy(REPORT)
    report['iocs']['network'][0]['source'] = 'Feed B'
    assert check(report, EVIDENCE) == ["unsupported attribution: ('Domain', 'malicious.example')"]


def test_partial_cannot_be_claimed_fully_consulted():
    report = deepcopy(REPORT)
    report['coverage_ledger'][0]['consulted'].append('Feed B')
    assert check(report, EVIDENCE) == ['unsupported full consultation: Feed B']


def test_merged_source_evidence_supports_attribution():
    evidence = deepcopy(EVIDENCE)
    evidence['iocs']['iocs'][0]['source_evidence'] = [{'source': 'Feed B'}]
    report = deepcopy(REPORT)
    report['iocs']['network'][0]['source'] = 'Feed B'
    assert check(report, evidence) == []

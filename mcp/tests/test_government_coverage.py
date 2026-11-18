"""Authored receipt regressions, not live source-access claims."""

import copy
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location(
    "government_coverage", ROOT / "scripts/government_coverage.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


@pytest.fixture
def document():
    return {
        "window_start": "2026-11-17T12:00:00Z",
        "window_end": "2026-11-18T12:00:00Z",
        "high_impact_cves": ["CVE-2026-114938"],
        "receipts": [
            {
                "source": "cert_eu",
                "attempts": [
                    {
                        "route": route,
                        "target": {
                            "primary": "https://cert.europa.eu/publications/security-advisories/2026",
                            "fallback": "https://cert.europa.eu/publications/security-advisories-rss",
                            "crosscheck": "site:cert.europa.eu/publications/security-advisories/ CVE-2026-114938",
                            "content": "https://cert.europa.eu/publications/security-advisories/2026-021/",
                        }[route],
                        "checked_at": "2026-11-18T11:30:00Z",
                        "outcome": "retrieved",
                        "cve": "CVE-2026-114938",
                    }
                    for route in ("primary", "fallback", "crosscheck", "content")
                ],
                "items": [
                    {
                        "url": "https://cert.europa.eu/publications/security-advisories/2026-021/",
                        "published_start": "2026-11-18T09:11:05Z",
                        "published_end": "2026-11-18T09:11:05Z",
                        "content_read": True,
                        "retrieved_at": "2026-11-18T11:30:00Z",
                        "evidence_note": "Synthetic test receipt: read recommendation",
                        "disposition": "corroborates",
                    }
                ],
            }
        ],
    }


def cert(document):
    return gate.evaluate(document)["sources"][1]


def test_missing_advisory_source_cannot_be_satisfied_by_kev(document):
    document["receipts"].append({"source": "cisa_kev", "status": "consulted"})
    rows = gate.evaluate(document)["sources"]
    assert rows[0]["status"] == "unverified"
    assert rows[0]["outcome"] == "not_attempted"
    assert rows[1]["status"] == "consulted"


@pytest.mark.parametrize(
    "outcome", ["http_error", "transport_error", "unsupported_format"]
)
def test_failed_access_never_means_quiet_or_consulted(document, outcome):
    receipt = document["receipts"][0]
    receipt["items"] = []
    for a in receipt["attempts"]:
        a.update(outcome=outcome, http_status=403)
    row = cert(document)
    assert row["status"] == "unverified" and row["outcome"] == "access_failed"
    assert row["attempts"][0]["http_status"] == 403
    assert gate.evaluate(document)["delivery"] == "continue_with_disclosed_gaps"


@pytest.mark.parametrize("outcome", ["zero_hits", "retrieved"])
def test_successful_empty_discovery_is_not_content_consultation(document, outcome):
    document["receipts"][0]["items"] = []
    for a in document["receipts"][0]["attempts"]:
        a["outcome"] = outcome
    assert cert(document)["status"] == "partial"
    assert cert(document)["outcome"] == "no_verified_items"


@pytest.mark.parametrize(
    "mutation",
    [
        "snippet",
        "missing_disposition",
        "date_only_boundary",
        "conflict",
        "wrong_host",
        "old_included",
    ],
)
def test_candidate_uncertainty_cannot_be_upgraded(document, mutation):
    item = document["receipts"][0]["items"][0]
    if mutation == "snippet":
        item["content_read"] = False
    if mutation == "missing_disposition":
        item.pop("disposition")
    if mutation == "date_only_boundary":
        item.update(
            published_start="2026-11-18T00:00:00Z", published_end="2026-11-18T23:59:59Z"
        )
    if mutation == "conflict":
        item["timestamp_conflict"] = "EST envelope and EDT body disagree"
    if mutation == "wrong_host":
        item["url"] = (
            "https://cert.europa.eu.invalid/publications/security-advisories/2026-021/"
        )
    if mutation == "old_included":
        item.update(
            published_start="2026-11-12T09:00:00Z", published_end="2026-11-12T09:00:00Z"
        )
    assert cert(document)["status"] == "partial"
    assert not cert(document)["verified_current_urls"]


def test_crosscheck_and_fallback_omissions_visible_even_with_content(document):
    document["receipts"][0]["attempts"] = document["receipts"][0]["attempts"][:1]
    row = cert(document)
    assert row["status"] == "partial"
    assert any("cross-check" in gap for gap in row["gaps"])
    assert any("fallback" in gap for gap in row["gaps"])


def test_stale_retrieval_and_fake_http_success_do_not_pass(document):
    for a in document["receipts"][0]["attempts"]:
        a["checked_at"] = "2026-11-17T11:30:00Z"
    assert cert(document)["status"] == "unverified"
    for a in document["receipts"][0]["attempts"]:
        a.update(checked_at="2026-11-18T11:30:00Z", http_status=403)
    assert cert(document)["status"] == "unverified"


def test_duplicate_receipt_does_not_hide_missing_source(document):
    document["receipts"].append(copy.deepcopy(document["receipts"][0]))
    assert cert(document)["status"] == "unverified"


def test_plan_uses_official_year_index_and_scoped_channels():
    plan = gate.plan(gate.stamp("2027-01-01T12:00:00Z"), ["CVE-2026-114938"])
    assert plan["cert_eu"]["primary"].endswith("/2027")
    assert plan["cert_eu"]["previous_year_index"].endswith("/2026")
    assert "USDHSCISA/bulletins/" in plan["cisa_advisories"]["fallback"]
    assert all("CVE-2026-114938" in p["crosschecks"][0] for p in plan.values())


def test_mirrors_require_publisher_receipts():
    for name in [
        "skills/cyber-threat-intel/SKILL.md",
        "skills/cyber-threat-intel/references/original-prompt.md",
        "standalone/cyber-threat-intel-prompt.md",
        "standalone/cyber-threat-intel-skill.md",
    ]:
        text = (ROOT / name).read_text()
        assert "Government advisory discovery receipt" in text
        assert "government_coverage.py" in text
        assert "CISA Advisories" in text and "CERT-EU" in text


def test_official_fallback_content_recovers_http_failure_without_erasing_it(document):
    document["receipts"][0]["attempts"][0].update(outcome="http_error", http_status=403)
    row = cert(document)
    assert row["status"] == "consulted"
    assert row["attempts"][0]["http_status"] == 403


def test_wrong_publisher_routes_and_stale_content_are_gaps(document):
    for a in document["receipts"][0]["attempts"]:
        a["target"] = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    item = document["receipts"][0]["items"][0]
    item["retrieved_at"] = "2026-11-17T11:00:00Z"
    row = cert(document)
    assert row["status"] != "consulted"
    assert not row["verified_current_urls"]

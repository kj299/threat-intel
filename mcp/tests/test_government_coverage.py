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
                        "window_basis": "publication",
                        "publication_source_url": "https://cert.europa.eu/publications/security-advisories/2026-021/",
                        "publication_evidence_note": "Authored fixture: original publication timestamp",
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
        assert "research_as_of" in text
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


@pytest.fixture
def updated_document(document):
    item = document["receipts"][0]["items"][0]
    item.update(
        published_start="2026-11-01T09:00:00Z",
        published_end="2026-11-01T09:00:00Z",
        published_raw="1 November 2026 09:00 UTC",
        window_basis="material_update",
    )
    item["material_update"] = {
        "start": "2026-11-18T10:00:00Z",
        "end": "2026-11-18T10:00:00Z",
        "source_url": item["url"],
        "evidence_note": "Authored fixture: dated version history",
        "material_change": "Authored fixture: adds exploitation evidence and revised mitigations",
        "raw": "18 November 2026 10:00 UTC",
    }
    return document


def test_old_publication_with_evidenced_current_material_update_is_consulted(
    updated_document,
):
    row = cert(updated_document)
    assert row["status"] == "consulted"
    evidence = row["verified_current_items"][0]
    assert evidence["window_basis"] == "material_update"
    assert evidence["published_start"] == "2026-11-01T09:00:00Z"
    assert evidence["published_raw"] == "1 November 2026 09:00 UTC"
    assert (
        evidence["material_update"]
        == updated_document["receipts"][0]["items"][0]["material_update"]
    )


@pytest.mark.parametrize(
    "case",
    [
        "missing_publication",
        "missing_basis",
        "wrong_basis",
        "missing_update",
        "missing_update_time",
        "missing_material_change",
        "missing_update_source",
        "unretrieved_update_source",
        "publication_conflict",
        "update_conflict",
        "boundary_interval",
        "update_before_publication",
        "old_update",
    ],
)
def test_unsupported_or_ambiguous_update_is_not_current_consultation(
    updated_document, case
):
    item = updated_document["receipts"][0]["items"][0]
    update = item["material_update"]
    if case == "missing_publication":
        item.pop("published_start")
    if case == "missing_basis":
        item.pop("window_basis")
    if case == "wrong_basis":
        item["window_basis"] = "publication"
    if case == "missing_update":
        item.pop("material_update")
    if case == "missing_update_time":
        update.pop("start")
    if case == "missing_material_change":
        update.pop("material_change")
    if case == "missing_update_source":
        update.pop("source_url")
    if case == "unretrieved_update_source":
        update["source_url"] += "?unread=1"
    if case == "publication_conflict":
        item["publication_timestamp_conflict"] = "Conflicting date labels"
    if case == "update_conflict":
        update["timestamp_conflict"] = "Conflicting EST/EDT"
    if case == "boundary_interval":
        update.update(start="2026-11-18T00:00:00Z", end="2026-11-18T23:59:59Z")
    if case == "update_before_publication":
        update.update(start="2026-10-01T09:00:00Z", end="2026-10-01T09:00:00Z")
    if case == "old_update":
        update.update(start="2026-11-10T09:00:00Z", end="2026-11-10T09:00:00Z")
    row = cert(updated_document)
    assert row["status"] != "consulted"
    assert not row["verified_current_items"]
    assert row["gaps"]


def test_publication_basis_preserves_original_evidence(document):
    evidence = cert(document)["verified_current_items"][0]
    assert evidence["window_basis"] == "publication"
    assert (
        evidence["publication_source_url"] == document["receipts"][0]["items"][0]["url"]
    )
    assert "material_update" not in evidence


@pytest.fixture
def post_window_research(document):
    document["research_as_of"] = "2026-11-18T12:06:00Z"
    for attempt in document["receipts"][0]["attempts"]:
        attempt["checked_at"] = "2026-11-18T12:05:00Z"
    document["receipts"][0]["items"][0]["retrieved_at"] = "2026-11-18T12:05:00Z"
    return document


def test_later_research_does_not_move_intelligence_window(post_window_research):
    result = gate.evaluate(post_window_research)
    row = result["sources"][1]
    assert row["status"] == "consulted"
    assert result["window_end"] == "2026-11-18T12:00:00+00:00"
    assert result["research_as_of"] == "2026-11-18T12:06:00+00:00"
    assert result["research_as_of_defaulted"] is False
    assert row["verified_current_items"][0]["retrieved_at"] == "2026-11-18T12:05:00Z"
    assert row["verified_current_items"][0]["retrieved_after_window_end"] is True


@pytest.mark.parametrize("basis", ["publication", "material_update"])
def test_post_window_event_not_admitted_by_later_research(post_window_research, basis):
    item = post_window_research["receipts"][0]["items"][0]
    if basis == "publication":
        item.update(
            published_start="2026-11-18T12:03:00Z", published_end="2026-11-18T12:03:00Z"
        )
    else:
        item["window_basis"] = "material_update"
        item["material_update"] = {
            "start": "2026-11-18T12:03:00Z",
            "end": "2026-11-18T12:03:00Z",
            "source_url": item["url"],
            "evidence_note": "Authored update fixture",
            "material_change": "Revised mitigation",
        }
    assert cert(post_window_research)["status"] == "partial"
    assert not cert(post_window_research)["verified_current_items"]


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-18T12:07:00Z",
        "2026-11-18T10:05:59Z",
        "bad",
        "2026-11-18T12:05:00",
        None,
    ],
)
def test_invalid_future_stale_attempts_are_preserved_not_missing(
    post_window_research, value
):
    for attempt in post_window_research["receipts"][0]["attempts"]:
        attempt["checked_at"] = value
    row = cert(post_window_research)
    assert row["status"] == "unverified"
    assert row["outcome"] == "invalid_attempt_metadata"
    assert row["attempts"] == post_window_research["receipts"][0]["attempts"]


@pytest.mark.parametrize(
    "value", ["2026-11-18T12:07:00Z", "2026-11-18T10:05:59Z", "bad", None]
)
def test_content_acquisition_uses_research_as_of(post_window_research, value):
    post_window_research["receipts"][0]["items"][0]["retrieved_at"] = value
    assert cert(post_window_research)["status"] == "partial"
    assert not cert(post_window_research)["verified_current_items"]


def test_old_callers_default_to_window_end(document, post_window_research):
    post_window_research.pop("research_as_of")
    result = gate.evaluate(post_window_research)
    assert result["research_as_of"] == result["window_end"]
    assert result["research_as_of_defaulted"] is True
    assert result["sources"][1]["outcome"] == "invalid_attempt_metadata"


@pytest.mark.parametrize(
    "field,value",
    [
        ("research_as_of", "2026-11-18T11:59:59Z"),
        ("research_as_of", "bad"),
        ("research_as_of", None),
        ("research_as_of", "2026-11-18T12:06:00"),
        ("window_end", "2026-11-17T12:00:00Z"),
        ("window_start", "2026-11-18T13:00:00Z"),
        ("window_end", None),
    ],
)
def test_invalid_research_or_window_bounds_rejected(document, field, value):
    document[field] = value
    with pytest.raises((ValueError, TypeError)):
        gate.evaluate(document)


def test_missing_empty_and_invalid_present_attempts_are_distinct(document):
    document["receipts"] = []
    assert cert(document)["outcome"] == "not_attempted"
    document["receipts"] = [{"source": "cert_eu", "attempts": [], "items": []}]
    assert cert(document)["outcome"] == "not_attempted"
    document["receipts"][0]["attempts"] = [None]
    assert cert(document)["outcome"] == "invalid_attempt_metadata"
    document["receipts"][0]["attempts"] = None
    assert cert(document)["outcome"] == "invalid_attempt_metadata"
    assert cert(document)["attempts"] is None


def test_nov19_actual_execution_reproduction(document):
    document.update(
        window_start="2026-11-18T12:00:00Z",
        window_end="2026-11-19T12:00:00Z",
        research_as_of="2026-11-19T12:06:00Z",
    )
    for attempt in document["receipts"][0]["attempts"]:
        attempt["checked_at"] = "2026-11-19T12:05:00Z"
    item = document["receipts"][0]["items"][0]
    item.update(
        published_start="2026-11-19T09:00:00Z",
        published_end="2026-11-19T09:00:00Z",
        retrieved_at="2026-11-19T12:05:00Z",
    )
    assert cert(document)["status"] == "consulted"
    assert gate.evaluate(document)["window_end"] == "2026-11-19T12:00:00+00:00"


def test_valid_legacy_caller_still_passes(document):
    result = gate.evaluate(document)
    assert result["sources"][1]["status"] == "consulted"
    assert result["research_as_of"] == result["window_end"]
    assert result["research_as_of_defaulted"] is True
    assert (
        result["sources"][1]["verified_current_items"][0]["retrieved_after_window_end"]
        is False
    )


@pytest.mark.parametrize("case", ["failure", "zero_hits", "index_only"])
def test_later_research_does_not_upgrade_source_gaps(post_window_research, case):
    receipt = post_window_research["receipts"][0]
    if case == "index_only":
        receipt["items"][0]["content_read"] = False
    else:
        receipt["items"] = []
        for attempt in receipt["attempts"]:
            attempt["outcome"] = "http_error" if case == "failure" else "zero_hits"
            if case == "failure":
                attempt["http_status"] = 403
    row = cert(post_window_research)
    assert row["status"] != "consulted"
    assert (
        row["outcome"]
        == {
            "failure": "access_failed",
            "zero_hits": "no_verified_items",
            "index_only": "discovery_only",
        }[case]
    )
    assert row["attempts"] == receipt["attempts"]

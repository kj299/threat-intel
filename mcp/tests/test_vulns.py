"""Tests for the vulnerability-output pipeline (sanitise/validate/dedupe/fan-out).

Mirrors test_normalize.py + test_fanout.py for the CVE-keyed vuln path. Uses
in-memory fake adapters (no HTTP) so the merge/dedupe/degrade logic is exercised
without network mocking or the server singletons.
"""

from __future__ import annotations

import pytest

from threat_intel_mcp.resilience import CircuitBreaker
from threat_intel_mcp.vault.base import CredentialError
from threat_intel_mcp.vulns import (
    VulnFeedSource,
    VulnFetchResult,
    deduplicate_vulns,
    fan_out_vulns,
    finalize_vulns,
    sanitize_vulns,
    validate_vulns,
)


def _vuln(cve="CVE-2024-12345", *, source="CISA KEV", **extra):
    return {"cve_id": cve, "source": source, **extra}


class TestValidate:
    def test_valid_record_passes(self):
        assert validate_vulns([_vuln()]) == [_vuln()]

    def test_bad_cve_id_dropped(self):
        assert validate_vulns([_vuln(cve="NOT-A-CVE")]) == []

    def test_missing_source_dropped(self):
        assert validate_vulns([{"cve_id": "CVE-2024-12345"}]) == []

    def test_placeholder_source_dropped(self):
        assert validate_vulns([_vuln(source="unknown")]) == []

    def test_out_of_range_cvss_dropped(self):
        assert validate_vulns([_vuln(cvss_score=11.0)]) == []

    def test_bad_severity_enum_dropped(self):
        assert validate_vulns([_vuln(cvss_severity="SPICY")]) == []

    def test_bad_datetime_dropped(self):
        # date_added must be a real RFC 3339 date-time, not a bare date.
        assert validate_vulns([_vuln(date_added="2024-01-15")]) == []

    def test_good_datetime_passes(self):
        rec = _vuln(date_added="2024-01-15T00:00:00+00:00")
        assert validate_vulns([rec]) == [rec]

    def test_reference_without_url_dropped(self):
        assert validate_vulns([_vuln(references=[{"source": "x"}])]) == []


class TestSanitize:
    def test_strips_zero_width_from_cve_id(self):
        out = sanitize_vulns([_vuln(cve="CVE-2024-​12345")])
        assert out[0]["cve_id"] == "CVE-2024-12345"

    def test_drops_record_with_empty_cve_id(self):
        assert sanitize_vulns([_vuln(cve="​​")]) == []

    def test_strips_control_chars_from_description(self):
        out = sanitize_vulns([_vuln(description="bad\x00desc")])
        assert out[0]["description"] == "baddesc"

    def test_drops_reference_with_junk_url(self):
        out = sanitize_vulns([_vuln(references=[{"url": "​"}])])
        assert out[0]["references"] == []


class TestDedup:
    def test_dedup_keeps_highest_cvss(self):
        a = _vuln(source="NVD", cvss_score=5.0)
        b = _vuln(source="NVD", cvss_score=9.8)
        out = deduplicate_vulns([a, b])
        assert len(out) == 1
        assert out[0]["cvss_score"] == 9.8

    def test_cross_source_corroboration_tag(self):
        a = _vuln(source="CISA KEV", exploit_status="known_exploited",
                  tags=["cisa-kev"])
        b = _vuln(source="NVD", cvss_score=9.8, tags=["nvd"])
        out = deduplicate_vulns([a, b])
        assert len(out) == 1
        merged = out[0]
        # Highest CVSS copy (NVD) is the base; KEV enrichment is folded in.
        assert merged["cvss_score"] == 9.8
        assert merged["exploit_status"] == "known_exploited"
        assert any(t.startswith("corroborated-by:") for t in merged["tags"])

    def test_references_unioned_on_merge(self):
        a = _vuln(source="NVD", cvss_score=9.0, references=[{"url": "http://a"}])
        b = _vuln(source="NVD", cvss_score=5.0, references=[{"url": "http://b"}])
        out = deduplicate_vulns([a, b])
        urls = {r["url"] for r in out[0]["references"]}
        assert urls == {"http://a", "http://b"}


class TestFinalize:
    def test_full_pipeline(self):
        # One valid, one invalid (bad CVE), one dup → 1 record out.
        recs = [
            _vuln(cve="CVE-2024-0001", source="NVD", cvss_score=5.0),
            _vuln(cve="CVE-2024-0001", source="CISA KEV",
                  exploit_status="known_exploited"),
            _vuln(cve="BOGUS", source="NVD"),
        ]
        out = finalize_vulns(recs)
        assert len(out) == 1
        assert out[0]["cve_id"] == "CVE-2024-0001"


# --- fan-out ---------------------------------------------------------------


class StubVulnAdapter:
    def __init__(self, name, tier, *, vulns=None, partial=None, raises=None):
        self.name = name
        self.tier = tier
        self._vulns = vulns or []
        self._partial = partial or []
        self._raises = raises
        self.calls = 0

    async def fetch(self, *, time_range: str, feed_types=None):
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return VulnFetchResult(
            vulns=self._vulns,
            source=self.name,
            tier=self.tier,
            retrieved_at="2026-06-29T00:00:00+00:00",
            record_count=len(self._vulns),
            latency_ms=1.0,
            feed_types_fetched=["default"],
            partial_failure=self._partial,
        )


def _source(adapter, *, no_retry_on=(CredentialError, KeyError)):
    return VulnFeedSource(
        adapter, adapter.tier, adapter.name, CircuitBreaker(adapter.name), no_retry_on
    )


async def _no_sleep(d):
    """Stand-in for asyncio.sleep so retry-path tests don't wait."""


class TestFanOut:
    @pytest.mark.asyncio
    async def test_sources_merged(self):
        a = StubVulnAdapter("CISA KEV", 1, vulns=[_vuln("CVE-2024-0001", source="CISA KEV")])
        b = StubVulnAdapter("NVD", 1, vulns=[_vuln("CVE-2024-0002", source="NVD")])
        result = await fan_out_vulns([_source(a), _source(b)])
        assert result["record_count"] == 2
        assert set(result["sources_consulted"]) == {"CISA KEV", "NVD"}
        assert {e["source"] for e in result["coverage_ledger"]} == {"CISA KEV", "NVD"}

    @pytest.mark.asyncio
    async def test_cross_source_dedup(self):
        a = StubVulnAdapter("CISA KEV", 1, vulns=[
            _vuln("CVE-2024-0001", source="CISA KEV", exploit_status="known_exploited")])
        b = StubVulnAdapter("NVD", 1, vulns=[
            _vuln("CVE-2024-0001", source="NVD", cvss_score=9.8)])
        result = await fan_out_vulns([_source(a), _source(b)])
        assert result["record_count"] == 1
        merged = result["vulns"][0]
        assert merged["cvss_score"] == 9.8
        assert merged["exploit_status"] == "known_exploited"

    @pytest.mark.asyncio
    async def test_credential_error_degrades_not_crashes(self):
        a = StubVulnAdapter("NVD", 1, raises=CredentialError("provider down"))
        b = StubVulnAdapter("CISA KEV", 1, vulns=[_vuln("CVE-2024-0001", source="CISA KEV")])
        result = await fan_out_vulns([_source(a), _source(b)])
        assert result["record_count"] == 1
        degraded = {d["source"]: d for d in result["sources_degraded"]}
        assert degraded["NVD"]["status"] == "unverified"
        assert degraded["NVD"]["error"] == "CredentialError"
        assert a.calls == 1  # non-retryable

    @pytest.mark.asyncio
    async def test_transient_failure_surfaces_after_retries(self):
        a = StubVulnAdapter("NVD", 1, raises=RuntimeError("timeout"))
        result = await fan_out_vulns(
            [_source(a)],
            retry_kwargs={"retries": 1, "jitter": False, "sleep": _no_sleep},
        )
        assert a.calls == 2
        assert result["sources_degraded"][0]["error"] == "RuntimeError"

    @pytest.mark.asyncio
    async def test_per_source_summary_excludes_raw_vulns(self):
        a = StubVulnAdapter("CISA KEV", 1, vulns=[_vuln("CVE-2024-0001", source="CISA KEV")])
        result = await fan_out_vulns([_source(a)])
        summary = result["per_source"][0]
        assert "vulns" not in summary
        assert summary["record_count"] == 1

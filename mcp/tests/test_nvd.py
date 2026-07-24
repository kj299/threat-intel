"""Tests for the NIST NVD CVE 2.0 adapter.

Uses pytest-httpx to intercept HTTP calls — no live network in CI. The mock
response mirrors the real NVD 2.0 shape (verified against the OpenCTI CVE
connector): a ``vulnerabilities`` list of ``{"cve": {...}}`` entries with
descriptions, metrics (cvssMetricV3x), weaknesses, and references.
"""

from __future__ import annotations

import re

import httpx
import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.nvd import (
    NVDAdapter,
    _extract_cvss,
    _extract_cwes,
    _normalize_entry,
    _window_days,
)
from threat_intel_mcp.vault.base import CredentialError, CredentialNotFoundError

_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Match the endpoint regardless of the query string (date window + pagination).
_API_RE = re.compile(r"^https://services\.nvd\.nist\.gov/rest/json/cves/2\.0")


class NoKeyCredentials:
    """Provider with no NVD key set — the optional-credential path."""

    def get(self, adapter_name: str, key: str) -> str:
        raise CredentialNotFoundError((adapter_name, key))


class KeyedCredentials:
    def get(self, adapter_name: str, key: str) -> str:
        return "test-nvd-key-do-not-use"


class BrokenCredentials:
    """Provider that is *failing* (outage), distinct from not-found."""

    def get(self, adapter_name: str, key: str) -> str:
        raise CredentialError("vault outage")


_ENTRY = {
    "cve": {
        "id": "CVE-2024-99999",
        "published": "2026-07-01T10:00:00.000",
        "lastModified": "2026-07-02T11:00:00.000",
        "descriptions": [
            {"lang": "en", "value": "An example remote code execution flaw."},
            {"lang": "es", "value": "Un fallo de ejemplo."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                },
                {
                    "type": "Primary",
                    "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                },
            ]
        },
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-94"}]},
        ],
        "references": [
            {"source": "cve@example.com", "url": "https://example.com/adv"},
            {"url": "https://example.org/patch"},
        ],
    }
}

_MOCK = {"resultsPerPage": 1, "totalResults": 1, "vulnerabilities": [_ENTRY]}


@pytest.fixture()
def adapter():
    return NVDAdapter(NoKeyCredentials())


class TestHelpers:
    def test_window_days_parses_days(self):
        assert _window_days("7d") == 7

    def test_window_days_caps_at_120(self):
        assert _window_days("365d") == 120

    def test_window_days_hours_round_up(self):
        assert _window_days("24h") == 1
        assert _window_days("25h") == 2

    def test_window_days_default(self):
        assert _window_days("garbage") == 7

    def test_extract_cvss_prefers_primary(self):
        score, severity, version = _extract_cvss(_ENTRY["cve"]["metrics"])
        assert score == 9.8
        assert severity == "CRITICAL"
        assert version == "3.1"

    def test_extract_cwes(self):
        assert _extract_cwes(_ENTRY["cve"]["weaknesses"]) == ["CWE-94"]

    def test_normalize_entry(self):
        out = _normalize_entry(_ENTRY)
        assert out["cve_id"] == "CVE-2024-99999"
        assert out["source"] == "NVD"
        assert out["description"].startswith("An example")
        assert out["cvss_score"] == 9.8
        assert out["cvss_severity"] == "CRITICAL"
        assert out["cvss_version"] == "3.1"
        assert out["published"] == "2026-07-01T10:00:00+00:00"
        assert out["cwes"] == ["CWE-94"]
        assert {r["url"] for r in out["references"]} == {
            "https://example.com/adv", "https://example.org/patch"
        }

    def test_normalize_entry_no_cve_skipped(self):
        assert _normalize_entry({"cve": {}}) is None


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_parses_response(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_RE, json=_MOCK)
        result = await adapter.fetch()
        assert result.source == "NVD"
        assert result.tier == 1
        assert result.record_count == 1
        assert result.vulns[0]["cve_id"] == "CVE-2024-99999"

    @pytest.mark.asyncio
    async def test_no_key_runs_unauthenticated(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_RE, json=_MOCK)
        await adapter.fetch()
        req = httpx_mock.get_requests()[0]
        assert "apiKey" not in req.headers

    @pytest.mark.asyncio
    async def test_key_sends_apikey_header(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_RE, json=_MOCK)
        await NVDAdapter(KeyedCredentials()).fetch()
        req = httpx_mock.get_requests()[0]
        assert req.headers["apiKey"] == "test-nvd-key-do-not-use"

    @pytest.mark.asyncio
    async def test_provider_outage_propagates(self, httpx_mock: HTTPXMock):
        # A failing provider (not merely absent key) must NOT silently downgrade.
        with pytest.raises(CredentialError):
            await NVDAdapter(BrokenCredentials()).fetch()
        assert httpx_mock.get_requests() == []

    @pytest.mark.asyncio
    async def test_unknown_feed_type_raises(self, adapter):
        with pytest.raises(ValueError, match="Unknown feed_type"):
            await adapter.fetch(feed_types=["nope"])

    @pytest.mark.asyncio
    async def test_upstream_error_raises(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_RE, status_code=503)
        with pytest.raises(httpx.HTTPStatusError):
            await adapter.fetch()

    @pytest.mark.asyncio
    async def test_date_params_present(self, adapter, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_API_RE, json=_MOCK)
        await adapter.fetch(time_range="7d")
        req = httpx_mock.get_requests()[0]
        assert "lastModStartDate" in req.url.params
        assert "lastModEndDate" in req.url.params

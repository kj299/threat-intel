"""Tests for the VulnCheck KEV adapter.

Uses pytest-httpx to intercept HTTP calls — no live network in CI.

.. warning::

   **The mock body below is NOT a recorded response.** Unlike ``test_cisa_kev``,
   whose fixture was verified against the OpenCTI connector, no VulnCheck
   response has ever been observed by this codebase: the sandbox proxy blocks
   ``docs.vulncheck.com`` and every feed host. These tests therefore pin *the
   adapter's behaviour given a shape*, not *the shape itself*.

   That distinction is the whole lesson of #100 — ThreatFox's parser passed its
   tests and returned 0 records from a live 1 MB response, because the fixture
   and the parser shared one author's belief. So the tests that matter most here
   are the ones that hold regardless of the record shape: that an unreadable
   body raises rather than reporting a confident zero, and that a genuinely
   empty catalog does not.

   Record a cassette (``record-cassettes`` workflow, ``feeds: vulncheck``)
   before trusting the field mapping.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.adapters.vulncheck import (
    VulnCheckAdapter,
    _cve_ids,
    _normalize_entry,
    _to_rfc3339,
)
from threat_intel_mcp.vault.base import CredentialNotFoundError

_INDEX_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"


class _Creds:
    """Minimal CredentialProvider stand-in."""

    def __init__(self, token: str | None = "vc-test-token") -> None:
        self._token = token

    def get(self, adapter: str, key: str) -> str:
        if self._token is None:
            raise CredentialNotFoundError(f"{adapter}/{key} not set")
        return self._token


_MOCK = {
    "_benchmark": 0.02,
    "data": [
        {
            "vendorProject": "Acme Corp",
            "product": "Acme Widget Server",
            "shortDescription": "Acme Widget Server contains an RCE vulnerability.",
            "cve": ["CVE-2024-12345"],
            "date_added": "2024-01-15T00:00:00Z",
            "vulncheck_reported_exploitation": [
                {"url": "https://example.org/report", "date_added": "2024-01-14T00:00:00Z"}
            ],
            "vulncheck_xdb": [
                {
                    "xdb_id": "abc123",
                    "xdb_url": "https://vulncheck.com/xdb/abc123",
                    "date_added": "2024-01-16T00:00:00Z",
                }
            ],
        },
        {
            "vendorProject": "Apache",
            "product": "Struts",
            "shortDescription": "Apache Struts unsafe deserialization.",
            # Two CVEs on one entry — the shape that differs from CISA KEV.
            "cve": ["CVE-2017-9805", "CVE-2017-5638"],
            "date_added": "2021-11-03T00:00:00Z",
        },
    ],
}


# ─── The guards that hold whatever the record shape turns out to be ──────────


@pytest.mark.asyncio
async def test_an_unreadable_body_raises_rather_than_reporting_zero(
    httpx_mock: HTTPXMock,
) -> None:
    """#100/#106: never a confident `0 records` from a body we could not read.

    A 200 whose entries are all unrecognised is the exact failure this adapter
    is most exposed to, because its field mapping is unverified. It must raise
    (degrade + retry), not return an empty catalog.
    """
    httpx_mock.add_response(
        url=f"{_INDEX_URL}?limit=1000",
        json={"data": [{"totally": "different"}, {"shape": "entirely"}]},
    )
    adapter = VulnCheckAdapter(_Creds())

    with pytest.raises(UpstreamFormatError):
        await adapter.fetch()


@pytest.mark.asyncio
async def test_a_genuinely_empty_catalog_is_not_an_error(httpx_mock: HTTPXMock) -> None:
    """The other half of the guard: `{"data": []}` is a real answer.

    Without this, the check above would be a false-alarm generator on any quiet
    response, and the pressure would be to remove it.
    """
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000", json={"data": []})
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()
    assert result.record_count == 0


@pytest.mark.asyncio
async def test_a_missing_data_key_is_distinguished_from_an_empty_one(
    httpx_mock: HTTPXMock,
) -> None:
    """Presence check, not truthiness — guard_parsed's documented requirement."""
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000", json={"_benchmark": 0.01})
    adapter = VulnCheckAdapter(_Creds())

    with pytest.raises(RuntimeError, match="missing 'data' key"):
        await adapter.fetch()


@pytest.mark.asyncio
async def test_a_missing_credential_degrades_non_retryably(
    httpx_mock: HTTPXMock,
) -> None:
    """A config error must not be dressed up as an upstream failure.

    This is the #197 lesson: a credential problem reported as a transient
    upstream one costs a retry storm and puts a false reason in the ledger.
    """
    adapter = VulnCheckAdapter(_Creds(token=None))

    with pytest.raises(CredentialNotFoundError):
        await adapter.fetch()


@pytest.mark.asyncio
async def test_an_unknown_feed_type_is_a_caller_error(httpx_mock: HTTPXMock) -> None:
    """ValueError is reserved for caller mistakes and surfaces verbatim."""
    adapter = VulnCheckAdapter(_Creds())

    with pytest.raises(ValueError, match="Unknown feed_type"):
        await adapter.fetch(feed_types=["not_a_feed"])


@pytest.mark.asyncio
async def test_the_bearer_token_is_sent(httpx_mock: HTTPXMock) -> None:
    """Auth is the one part of the contract that is verified, so pin it."""
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000", json={"data": []})
    adapter = VulnCheckAdapter(_Creds(token="vc-secret"))

    await adapter.fetch()

    request = httpx_mock.get_requests()[0]
    assert request.headers["Authorization"] == "Bearer vc-secret"


@pytest.mark.asyncio
async def test_egress_is_restricted_to_the_vulncheck_host() -> None:
    """The adapter must not be able to call anywhere else."""
    adapter = VulnCheckAdapter(_Creds())
    client = adapter._make_client("t")
    try:
        with pytest.raises(Exception):
            await client.get("https://evil.example.com/")
    finally:
        await client.aclose()


# ─── Behaviour given the (unverified) documented shape ───────────────────────


@pytest.mark.asyncio
async def test_one_entry_with_two_cves_becomes_two_records(
    httpx_mock: HTTPXMock,
) -> None:
    """`cve` is a list, and the vuln schema keys on a single `cve_id`.

    Collapsing them would silently discard coverage, which is the failure mode
    this repository cares about most.
    """
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000", json=_MOCK)
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()

    ids = sorted(v["cve_id"] for v in result.vulns)
    assert ids == ["CVE-2017-5638", "CVE-2017-9805", "CVE-2024-12345"]
    assert result.record_count == 3


@pytest.mark.asyncio
async def test_every_record_is_marked_known_exploited(httpx_mock: HTTPXMock) -> None:
    """A KEV entry is exploited by definition — that is what makes it a KEV."""
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000", json=_MOCK)
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()

    assert all(v["exploit_status"] == "known_exploited" for v in result.vulns)
    assert all(v["source"] == "VulnCheck KEV" for v in result.vulns)


@pytest.mark.asyncio
async def test_exploitation_evidence_urls_are_kept(httpx_mock: HTTPXMock) -> None:
    """A record asserting "exploited" with no evidence behind it is weaker than
    one that names the report — and the URLs are why a second KEV is worth
    having at all."""
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000", json=_MOCK)
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()

    record = next(v for v in result.vulns if v["cve_id"] == "CVE-2024-12345")
    urls = {r["url"] for r in record["references"]}
    assert urls == {
        "https://example.org/report",
        "https://vulncheck.com/xdb/abc123",
    }


def test_a_scalar_cve_field_is_also_read() -> None:
    """Tolerant on purpose: the list shape is unverified.

    If `cve` turns out to be scalar, or the key is CISA-shaped `cveID`, this
    still reads it. A silent zero here would look exactly like a quiet catalog.
    """
    assert _cve_ids({"cve": "CVE-2024-1"}) == ["CVE-2024-1"]
    assert _cve_ids({"cveID": "CVE-2024-2"}) == ["CVE-2024-2"]
    assert _cve_ids({"cve": ["CVE-2024-3", "CVE-2024-4"]}) == [
        "CVE-2024-3",
        "CVE-2024-4",
    ]
    assert _cve_ids({"nothing": "here"}) == []


def test_an_entry_naming_no_cve_is_dropped() -> None:
    """It cannot be keyed, and schema validation would drop it anyway."""
    assert _normalize_entry({"product": "Thing"}) == []


def test_unreadable_timestamps_are_omitted_not_guessed() -> None:
    """The vuln schema validates `date-time` at runtime, so a half-understood
    string would drop the entire record rather than just the field."""
    assert _to_rfc3339("2024-01-15") == "2024-01-15T00:00:00+00:00"
    assert _to_rfc3339("2024-01-15T00:00:00Z") == "2024-01-15T00:00:00+00:00"
    assert _to_rfc3339("last Tuesday") is None
    assert _to_rfc3339("") is None
    assert _to_rfc3339(None) is None

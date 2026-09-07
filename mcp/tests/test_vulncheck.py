"""Tests for the VulnCheck KEV adapter.

Uses pytest-httpx to intercept HTTP calls — no live network in CI.

The mock body below mirrors the **real** response shape, read from the
recording made by the ``record-cassettes`` workflow (run 34070272507): a
``{_benchmark, _meta, data}`` envelope, ``cve`` as a list, ``required_action``
in snake_case beside camelCase siblings, and ``_meta.total_pages`` driving
pagination. ``test_cassette_playback.py`` exercises the same adapter against
the recorded bytes themselves.

The first draft of these tests was written before any response had been seen,
and it passed — while the adapter fetched 1,000 of 5,229 entries and dropped
four fields. That is #100's lesson in miniature: a fixture and a parser sharing
one author's belief agree with each other and with nothing else. The tests that
survived that correction unchanged are the shape-independent guards below, and
they are the ones worth keeping first.
"""

from __future__ import annotations

import re

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.adapters.vulncheck import (
    MAX_PAGES,
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
    "_benchmark": 0.797107,
    "_meta": {
        "index": "vulncheck-kev",
        "limit": 1000,
        "total_documents": 2,
        "page": 1,
        "total_pages": 1,
        "max_pages": 1,
    },
    "data": [
        {
            "vendorProject": "Sangoma",
            "product": "Switchvox",
            "vulnerabilityName": "Sangoma Switchvox SQL Injection Vulnerability",
            "shortDescription": "Sangoma Switchvox contains a SQL injection vulnerability.",
            # snake_case in the real feed, beside camelCase siblings.
            "required_action": "Apply mitigations per vendor instructions.",
            "knownRansomwareCampaignUse": "Unknown",
            "cve": ["CVE-2026-9586"],
            "cwes": ["CWE-89"],
            "vulncheck_xdb": [],
            "vulncheck_reported_exploitation": [
                {"url": "https://example.org/disclosure", "date_added": "2026-09-01T00:00:00Z"}
            ],
            "reported_exploited_by_vulncheck_canaries": False,
            "dueDate": "2026-09-05T00:00:00Z",
            "cisa_date_added": "2026-09-02T00:00:00Z",
            "date_added": "2026-09-01T00:00:00Z",
            "updated_at": "2026-09-01T00:00:00Z",
        },
        {
            "vendorProject": "Apache",
            "product": "Struts",
            "shortDescription": "Apache Struts unsafe deserialization.",
            "knownRansomwareCampaignUse": "Known",
            # Two CVEs on one entry — the shape that differs from CISA KEV.
            "cve": ["CVE-2017-9805", "CVE-2017-5638"],
            "vulncheck_xdb": [
                {
                    "xdb_id": "abc123",
                    "xdb_url": "https://vulncheck.com/xdb/abc123",
                    "date_added": "2024-01-16T00:00:00Z",
                }
            ],
            "reported_exploited_by_vulncheck_canaries": True,
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
        url=f"{_INDEX_URL}?limit=1000&page=1",
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
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000&page=1", json={"data": []})
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()
    assert result.record_count == 0


@pytest.mark.asyncio
async def test_a_missing_data_key_is_distinguished_from_an_empty_one(
    httpx_mock: HTTPXMock,
) -> None:
    """Presence check, not truthiness — guard_parsed's documented requirement."""
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000&page=1", json={"_benchmark": 0.01})
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
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000&page=1", json={"data": []})
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
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000&page=1", json=_MOCK)
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()

    ids = sorted(v["cve_id"] for v in result.vulns)
    assert ids == ["CVE-2017-5638", "CVE-2017-9805", "CVE-2026-9586"]
    assert result.record_count == 3


@pytest.mark.asyncio
async def test_every_record_is_marked_known_exploited(httpx_mock: HTTPXMock) -> None:
    """A KEV entry is exploited by definition — that is what makes it a KEV."""
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000&page=1", json=_MOCK)
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()

    assert all(v["exploit_status"] == "known_exploited" for v in result.vulns)
    assert all(v["source"] == "VulnCheck KEV" for v in result.vulns)


@pytest.mark.asyncio
async def test_exploitation_evidence_urls_are_kept(httpx_mock: HTTPXMock) -> None:
    """A record asserting "exploited" with no evidence behind it is weaker than
    one that names the report — and the URLs are why a second KEV is worth
    having at all."""
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000&page=1", json=_MOCK)
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()

    record = next(v for v in result.vulns if v["cve_id"] == "CVE-2026-9586")
    assert {r["url"] for r in record["references"]} == {"https://example.org/disclosure"}

    struts = next(v for v in result.vulns if v["cve_id"] == "CVE-2017-9805")
    assert {r["url"] for r in struts["references"]} == {
        "https://vulncheck.com/xdb/abc123"
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


# ─── The two defects the recording exposed ───────────────────────────────────


@pytest.mark.asyncio
async def test_every_page_is_walked(httpx_mock: HTTPXMock) -> None:
    """The first draft fetched one page and called the source `consulted`.

    The recording showed 1,000 of 5,229 entries — 81% of the catalog missing
    while the ledger still said consulted. Under-reporting a source while
    claiming full consultation is exactly the coverage inflation R4 forbids.
    """

    def page(n: int, total: int, cve: str) -> dict:
        return {
            "_meta": {"page": n, "total_pages": total, "limit": 1000},
            "data": [{"cve": [cve], "product": "Thing"}],
        }

    httpx_mock.add_response(
        url=f"{_INDEX_URL}?limit=1000&page=1", json=page(1, 3, "CVE-2024-0001")
    )
    httpx_mock.add_response(
        url=f"{_INDEX_URL}?limit=1000&page=2", json=page(2, 3, "CVE-2024-0002")
    )
    httpx_mock.add_response(
        url=f"{_INDEX_URL}?limit=1000&page=3", json=page(3, 3, "CVE-2024-0003")
    )
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()

    assert sorted(v["cve_id"] for v in result.vulns) == [
        "CVE-2024-0001",
        "CVE-2024-0002",
        "CVE-2024-0003",
    ]
    assert len(httpx_mock.get_requests()) == 3


@pytest.mark.asyncio
async def test_the_page_walk_stops_at_the_ceiling(httpx_mock: HTTPXMock) -> None:
    """A runaway total_pages must not become an unbounded request loop."""
    httpx_mock.add_response(
        url=re.compile(r"^https://api\.vulncheck\.com/v3/index/vulncheck-kev"),
        json={
            "_meta": {"page": 1, "total_pages": 10_000, "limit": 1000},
            "data": [{"cve": ["CVE-2024-0001"], "product": "Thing"}],
        },
        is_reusable=True,
    )
    adapter = VulnCheckAdapter(_Creds())

    await adapter.fetch()

    assert len(httpx_mock.get_requests()) == MAX_PAGES


@pytest.mark.asyncio
async def test_the_fields_the_first_draft_dropped_are_read(
    httpx_mock: HTTPXMock,
) -> None:
    """cwes, known_ransomware_use, due_date and last_modified.

    Each is real intelligence the vuln schema already models: the weakness
    class, whether ransomware crews use it, the CISA remediation deadline, and
    when the entry last moved. The first draft silently omitted all four
    because no response had ever been read.
    """
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000&page=1", json=_MOCK)
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()
    record = next(v for v in result.vulns if v["cve_id"] == "CVE-2026-9586")

    assert record["cwes"] == ["CWE-89"]
    assert record["known_ransomware_use"] == "Unknown"
    assert record["due_date"] == "2026-09-05T00:00:00+00:00"
    assert record["last_modified"] == "2026-09-01T00:00:00+00:00"
    assert record["required_action"].startswith("Apply mitigations")


@pytest.mark.asyncio
async def test_ransomware_and_canary_observations_are_tagged(
    httpx_mock: HTTPXMock,
) -> None:
    """A canary hit is VulnCheck's own observation, not a third-party report —
    stronger evidence, so it is worth surfacing rather than folding away."""
    httpx_mock.add_response(url=f"{_INDEX_URL}?limit=1000&page=1", json=_MOCK)
    adapter = VulnCheckAdapter(_Creds())

    result = await adapter.fetch()
    struts = next(v for v in result.vulns if v["cve_id"] == "CVE-2017-9805")

    assert "ransomware-linked" in struts["tags"]
    assert "vulncheck-canary-observed" in struts["tags"]

    sangoma = next(v for v in result.vulns if v["cve_id"] == "CVE-2026-9586")
    assert "vulncheck-canary-observed" not in sangoma["tags"]

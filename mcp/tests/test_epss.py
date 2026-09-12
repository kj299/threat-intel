"""Tests for the EPSS CVE enrichment adapter.

Uses pytest-httpx — no live network in CI.

The mock body follows FIRST.org's published API reference. ``api.first.org`` is
unreachable from the development sandbox, so the field mapping is documented
rather than observed, and a cassette is what will settle it. The tests that
carry weight until then are the ones that hold whatever the field names turn
out to be: an unreadable body raises, an empty one does not, a caller error
raises, and "no score" never masquerades as a failure.
"""

from __future__ import annotations

import re

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.adapters.epss import (
    MAX_CVES_PER_CALL,
    MAX_CVES_PER_REQUEST,
    EPSSAdapter,
    _as_float,
    _priority,
)

_API = "https://api.first.org/data/v1/epss"
_API_RE = re.compile(r"^https://api\.first\.org/data/v1/epss")


def _envelope(*entries: dict) -> dict:
    """Shaped after FIRST.org's documented response envelope."""
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "access": "public",
        "total": len(entries),
        "offset": 0,
        "limit": 100,
        "data": list(entries),
    }


def _entry(cve="CVE-2021-44228", epss="0.94047", percentile="0.99941"):
    # epss/percentile are STRINGS in the real API — that is the point.
    return {"cve": cve, "epss": epss, "percentile": percentile, "date": "2026-09-11"}


@pytest.fixture()
def adapter() -> EPSSAdapter:
    return EPSSAdapter()


# ─── Guards that hold whatever the field names turn out to be ────────────────


@pytest.mark.asyncio
async def test_a_body_without_data_raises(adapter, httpx_mock: HTTPXMock):
    """An unreadable response must not become a confident 'nothing is scored'."""
    httpx_mock.add_response(url=_API_RE, json={"status": "OK"})

    with pytest.raises(UpstreamFormatError, match="did not contain a 'data' array"):
        await adapter.enrich(["CVE-2021-44228"])


@pytest.mark.asyncio
async def test_entries_in_an_unknown_shape_raise(adapter, httpx_mock: HTTPXMock):
    """Records present, none parseable — the field names changed upstream."""
    httpx_mock.add_response(
        url=_API_RE,
        json=_envelope({"id": "CVE-2021-44228", "probability": "0.9"}),
    )

    with pytest.raises(UpstreamFormatError, match="none of them in a recognisable shape"):
        await adapter.enrich(["CVE-2021-44228"])


@pytest.mark.asyncio
async def test_an_empty_data_array_is_not_an_error(adapter, httpx_mock: HTTPXMock):
    """`{"data": []}` is the honest answer when EPSS scores none of these CVEs.

    Presence check, not truthiness: an empty array is a real answer, a missing
    key is a response we did not recognise. Conflating them is what makes an
    empty-parse guard either useless or a false-alarm generator.
    """
    httpx_mock.add_response(url=_API_RE, json=_envelope())

    result = await adapter.enrich(["CVE-2099-00001"])

    assert result["record_count"] == 0
    assert result["not_scored"] == ["CVE-2099-00001"]


@pytest.mark.asyncio
async def test_an_unscored_cve_is_reported_apart_from_a_failure(
    adapter, httpx_mock: HTTPXMock
):
    """EPSS only scores CVEs published in NVD.

    A reserved or brand-new id having no score is a fact about the CVE, not an
    outage. Folding it into a `failed` list would send a reader to investigate
    an API that is working perfectly.
    """
    httpx_mock.add_response(url=_API_RE, json=_envelope(_entry()))

    result = await adapter.enrich(["CVE-2021-44228", "CVE-2099-00001"])

    assert result["scored"] == ["CVE-2021-44228"]
    assert result["not_scored"] == ["CVE-2099-00001"]
    assert "failed" not in result, "an unscored CVE must not be called a failure"


@pytest.mark.asyncio
async def test_an_empty_list_is_a_caller_error(adapter):
    with pytest.raises(ValueError, match="No CVEs"):
        await adapter.enrich([])


@pytest.mark.asyncio
async def test_over_the_cap_refuses_rather_than_truncating(adapter, httpx_mock):
    too_many = [f"CVE-2024-{i:05d}" for i in range(MAX_CVES_PER_CALL + 1)]

    with pytest.raises(ValueError, match="exceeds the per-call cap"):
        await adapter.enrich(too_many)

    assert httpx_mock.get_requests() == [], "must refuse before issuing a request"


@pytest.mark.asyncio
async def test_a_malformed_date_is_a_caller_error(adapter):
    with pytest.raises(ValueError, match="date must be YYYY-MM-DD"):
        await adapter.enrich(["CVE-2021-44228"], date="last tuesday")


@pytest.mark.asyncio
async def test_egress_is_restricted_to_first_org(adapter):
    client = adapter._make_client()
    try:
        with pytest.raises(Exception):
            await client.get("https://evil.example.com/")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_no_credential_is_read(adapter, httpx_mock: HTTPXMock):
    """Keylessness is the reason this source is here; assert it stays true."""
    import inspect

    assert list(inspect.signature(EPSSAdapter.__init__).parameters) == ["self"]

    httpx_mock.add_response(url=_API_RE, json=_envelope(_entry()))
    await adapter.enrich(["CVE-2021-44228"])
    sent = httpx_mock.get_requests()[0]
    for header in ("authorization", "x-api-key", "key", "x-apikey"):
        assert header not in sent.headers


# ─── Behaviour given the documented shape ────────────────────────────────────


@pytest.mark.asyncio
async def test_scores_are_parsed_from_strings_into_floats(adapter, httpx_mock: HTTPXMock):
    """The API serialises probabilities as strings.

    Left as strings they compare lexically, so "0.9" > "0.88" is True but
    "0.1" > "0.09" is False — a ranking that is wrong only sometimes, which is
    the worst kind.
    """
    httpx_mock.add_response(url=_API_RE, json=_envelope(_entry()))

    result = await adapter.enrich(["CVE-2021-44228"])
    record = result["enrichments"][0]

    assert record["epss"] == pytest.approx(0.94047)
    assert isinstance(record["epss"], float)
    assert record["percentile"] == pytest.approx(0.99941)
    assert isinstance(record["percentile"], float)
    assert record["cve"] == "CVE-2021-44228"
    assert record["scored_on"] == "2026-09-11"
    assert record["source"] == "EPSS"


@pytest.mark.asyncio
async def test_a_record_with_no_readable_score_is_dropped(adapter, httpx_mock: HTTPXMock):
    """The score is the only thing this enrichment provides, so a record
    without one is not a usable record — and it must still leave the batch
    parseable rather than tripping the guard."""
    httpx_mock.add_response(
        url=_API_RE,
        json=_envelope(_entry(), _entry(cve="CVE-2021-45046", epss="n/a")),
    )

    result = await adapter.enrich(["CVE-2021-44228", "CVE-2021-45046"])

    assert result["scored"] == ["CVE-2021-44228"]
    assert result["not_scored"] == ["CVE-2021-45046"]


@pytest.mark.asyncio
async def test_a_long_list_is_split_across_requests(adapter, httpx_mock: HTTPXMock):
    """Batching is the reason this adapter is cheap; assert it actually batches
    rather than issuing one request per CVE the way VirusTotal must."""
    cves = [f"CVE-2024-{i:05d}" for i in range(MAX_CVES_PER_REQUEST + 5)]
    httpx_mock.add_response(url=_API_RE, json=_envelope(), is_reusable=True)

    await adapter.enrich(cves)

    assert len(httpx_mock.get_requests()) == 2, "105 CVEs should be 2 requests, not 105"


@pytest.mark.asyncio
async def test_a_repeated_cve_is_served_from_cache(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_API_RE, json=_envelope(_entry()))

    await adapter.enrich(["CVE-2021-44228"])
    await adapter.enrich(["CVE-2021-44228"])

    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_a_historical_date_is_forwarded(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_API_RE, json=_envelope(_entry()))

    await adapter.enrich(["CVE-2021-44228"], date="2022-01-01")

    assert "date=2022-01-01" in str(httpx_mock.get_requests()[0].url)


def test_priority_bands_follow_the_published_cut_points():
    assert _priority(0.9) == "high"
    assert _priority(0.36) == "high"
    assert _priority(0.35) == "medium"
    assert _priority(0.088) == "medium"
    assert _priority(0.087) == "low"
    assert _priority(0.0) == "low"


def test_unreadable_probabilities_are_omitted_rather_than_guessed():
    assert _as_float("0.5") == 0.5
    assert _as_float(0.5) == 0.5
    assert _as_float("n/a") is None
    assert _as_float(None) is None
    assert _as_float(True) is None, "a bool is not a probability"

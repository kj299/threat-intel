"""Tests for the Pulsedive Explore feed adapter.

Uses pytest-httpx — no live network in CI.

`pulsedive.com` is unreachable from the development sandbox, so the body below
is assembled from Pulsedive's published documentation and community clients
rather than from a response anyone has seen. That is the #203 setup, so the
tests carrying the most weight are the ones that hold whatever the field names
turn out to be — plus the ones guarding the thing that makes this adapter
unusual: **a 50 requests/day budget**, the tightest in this server.
"""

from __future__ import annotations

import re

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.adapters.pulsedive import (
    MAX_REQUESTS_PER_FETCH,
    PulsediveAdapter,
    _normalize_entry,
    _to_rfc3339,
)
from threat_intel_mcp.normalize import finalize_iocs
from threat_intel_mcp.vault.base import CredentialNotFoundError

_EXPLORE = "https://pulsedive.com/api/explore.php"
_EXPLORE_RE = re.compile(r"^https://pulsedive\.com/api/explore\.php")
_KEY = "pulsedive-test-key"


class FakeCredentials:
    def __init__(self, key: str | None = _KEY) -> None:
        self._key = key

    def get(self, adapter: str, key: str) -> str:
        if self._key is None:
            raise CredentialNotFoundError(f"{adapter}/{key} not set")
        return self._key


def _entry(indicator="203.0.113.5", type_="ip", risk="high"):
    return {
        "iid": 1,
        "indicator": indicator,
        "type": type_,
        "risk": risk,
        "stamp_added": "2026-09-01 10:00:00",
        "stamp_seen": "2026-09-12 09:00:00",
    }


def _body(*entries):
    return {"results": list(entries), "page_current": 1, "page_next": 2}


@pytest.fixture()
def adapter() -> PulsediveAdapter:
    return PulsediveAdapter(FakeCredentials())


# ─── The quota is the design constraint ──────────────────────────────────────


@pytest.mark.asyncio
async def test_a_fetch_costs_exactly_one_request(adapter, httpx_mock: HTTPXMock):
    """50 requests/day is the tightest budget in this server.

    The response carries `page_next`, so a pagination loop is the obvious
    "improvement" — and it would spend a day's quota in one fetch. There is no
    loop, and this is what stops one appearing.
    """
    httpx_mock.add_response(url=_EXPLORE_RE, json=_body(_entry()))

    await adapter.fetch()

    assert len(httpx_mock.get_requests()) == MAX_REQUESTS_PER_FETCH == 1


@pytest.mark.asyncio
async def test_the_result_says_it_is_one_page(adapter, httpx_mock: HTTPXMock):
    """Stated, not implied. Without this a reader takes 100 indicators for the
    whole of Pulsedive's high-risk set, and the Coverage Ledger records
    exhaustive coverage this feed cannot provide (R4)."""
    httpx_mock.add_response(url=_EXPLORE_RE, json=_body(_entry()))

    result = await adapter.fetch()

    assert result.partial_failure, "a one-page feed must declare itself partial"
    assert "50 requests/day" in result.partial_failure[0]


@pytest.mark.asyncio
async def test_a_second_fetch_is_served_from_cache(adapter, httpx_mock: HTTPXMock):
    """At 50/day, re-requesting within one run is a meaningful waste."""
    httpx_mock.add_response(url=_EXPLORE_RE, json=_body(_entry()))

    await adapter.fetch()
    await adapter.fetch()

    assert len(httpx_mock.get_requests()) == 1


# ─── Guards that hold whatever the field names turn out to be ────────────────


@pytest.mark.asyncio
async def test_an_in_band_error_is_raised_not_parsed_past(adapter, httpx_mock: HTTPXMock):
    """Pulsedive reports failures in the body with HTTP 200.

    A bad Explore query or an exhausted quota would otherwise become a
    confident empty feed — an outage indistinguishable from a quiet week. The
    query syntax is the least certain part of this adapter, so this is the
    guard most likely to actually fire.
    """
    httpx_mock.add_response(
        url=_EXPLORE_RE,
        json={"error": "Invalid query", "results": []},
    )

    with pytest.raises(RuntimeError, match="Invalid query"):
        await adapter.fetch()


@pytest.mark.asyncio
async def test_entries_in_an_unknown_shape_raise(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_EXPLORE_RE,
        json=_body({"id": 1, "value": "203.0.113.5", "kind": "ipv4"}),
    )

    with pytest.raises(UpstreamFormatError, match="none of them in a recognisable shape"):
        await adapter.fetch()


@pytest.mark.asyncio
async def test_an_empty_page_is_not_an_error(adapter, httpx_mock: HTTPXMock):
    """Presence check, never truthiness: `{"results": []}` is a real empty page."""
    httpx_mock.add_response(url=_EXPLORE_RE, json=_body())

    result = await adapter.fetch()

    assert result.record_count == 0


@pytest.mark.asyncio
async def test_a_missing_credential_raises_before_any_request(
    adapter, httpx_mock: HTTPXMock
):
    vendor = PulsediveAdapter(FakeCredentials(key=None))

    with pytest.raises(CredentialNotFoundError):
        await vendor.fetch()

    assert httpx_mock.get_requests() == [], "must fail before spending a request"


@pytest.mark.asyncio
async def test_an_unknown_feed_type_is_a_caller_error(adapter):
    with pytest.raises(ValueError, match="Unknown feed_type"):
        await adapter.fetch(feed_types=["critical_risk"])


@pytest.mark.asyncio
async def test_egress_is_restricted_to_pulsedive(adapter):
    client = adapter._make_client()
    try:
        with pytest.raises(Exception):
            await client.get("https://evil.example.com/")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_the_key_is_sent_as_a_query_parameter(adapter, httpx_mock: HTTPXMock):
    """Pulsedive's design, not a choice here — which is why every logged URL
    goes through `redact_url`."""
    httpx_mock.add_response(url=_EXPLORE_RE, json=_body(_entry()))

    await adapter.fetch()

    assert f"key={_KEY}" in str(httpx_mock.get_requests()[0].url)


@pytest.mark.asyncio
async def test_the_key_never_reaches_the_logs(adapter, httpx_mock: HTTPXMock, caplog):
    """The key rides in the URL, so an unredacted log line leaks it — the one
    exposure this auth scheme creates."""
    import logging

    httpx_mock.add_response(url=_EXPLORE_RE, json=_body(_entry()))

    with caplog.at_level(logging.DEBUG):
        await adapter.fetch()

    assert _KEY not in caplog.text


# ─── Behaviour given the documented shape ────────────────────────────────────


@pytest.mark.asyncio
async def test_high_risk_indicators_are_blockable(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_EXPLORE_RE, json=_body(_entry()))

    result = await adapter.fetch()
    ioc = result.iocs[0]

    assert ioc["type"] == "IPv4"
    assert ioc["action"] == "block"
    assert ioc["confidence"] == "High"
    assert "risk:high" in ioc["tags"]


def test_a_retired_indicator_is_kept_but_never_blockable():
    """The Feodo lesson (#212), applied before a recording could teach it again.

    `retired` means Pulsedive no longer considers the indicator active.
    Blocking it at high confidence points a SOC at infrastructure that may
    have been reassigned. It is kept — real history — at a confidence that
    says so.
    """
    record = _normalize_entry(_entry(risk="retired"))

    assert record["action"] == "alert"
    assert record["confidence"] == "Low"
    assert "risk:retired" in record["tags"]


@pytest.mark.parametrize(
    "risk,action,confidence",
    [
        ("critical", "block", "High"),
        ("high", "block", "High"),
        ("medium", "alert", "Medium"),
        ("low", "alert", "Low"),
        ("none", "alert", "Low"),
        ("unknown", "alert", "Low"),
    ],
)
def test_pulsedives_own_risk_scale_drives_confidence(risk, action, confidence):
    """Confidence is mapped from the vendor's scale, never invented (R3)."""
    record = _normalize_entry(_entry(risk=risk))

    assert (record["action"], record["confidence"]) == (action, confidence)


def test_an_unmapped_indicator_type_is_skipped():
    """Pulsedive indexes more than network indicators. An unmapped type must
    drop out rather than be guessed into a schema type — and dropping out is
    what lets guard_parsed notice if the whole vocabulary changes."""
    assert _normalize_entry(_entry(type_="hash")) is None
    assert _normalize_entry(_entry(type_="artifact")) is None


@pytest.mark.asyncio
async def test_records_survive_the_validation_pipeline(adapter, httpx_mock: HTTPXMock):
    """The guard OTX did not have (#204): Pulsedive's stamps are
    `"2026-09-01 10:00:00"`, which fails date-time validation unconverted and
    takes the whole record with it."""
    httpx_mock.add_response(
        url=_EXPLORE_RE,
        json=_body(_entry(), _entry("evil.test", "domain", "critical")),
    )

    result = await adapter.fetch()
    survived = finalize_iocs(result.iocs)

    assert len(survived) == len(result.iocs) == 2
    assert survived[0]["first_seen"] == "2026-09-01T10:00:00+00:00"
    assert survived[0]["last_seen"] == "2026-09-12T09:00:00+00:00"


def test_unreadable_timestamps_are_omitted_not_passed_through():
    assert _to_rfc3339("2026-09-01 10:00:00") == "2026-09-01T10:00:00+00:00"
    assert _to_rfc3339("last tuesday") is None
    assert _to_rfc3339(None) is None


# ─── What the first real call actually returned ──────────────────────────────


@pytest.mark.asyncio
async def test_a_429_names_quota_or_plan_rather_than_a_bare_http_error(
    adapter, httpx_mock: HTTPXMock
):
    """The first real call returned 429 on request one of one (2026-09-13).

    Left as a generic `HTTPStatusError`, the weekly live check reports
    "Pulsedive: HTTPStatusError" — which reads like an outage. On a 50/day
    budget the difference between "quota spent" and "Pulsedive is down"
    decides whether an operator waits or investigates, and this adapter makes
    exactly one request per fetch, so a 429 here is never self-inflicted.
    """
    httpx_mock.add_response(url=_EXPLORE_RE, status_code=429)

    with pytest.raises(RuntimeError) as excinfo:
        await adapter.fetch()

    message = str(excinfo.value)
    assert "429" in message
    assert "quota" in message.lower()
    assert "plan" in message.lower()
    assert "Retrying will not help" in message, (
        "the message must say retrying is pointless — otherwise the obvious "
        "response to a 429 is a retry that spends more of a spent budget"
    )


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
async def test_a_quota_condition_degrades_rather_than_crashing(
    adapter, httpx_mock: HTTPXMock
):
    """Per the taxonomy in adapters/base.py, a RuntimeError is case 3: the tool
    degrades to `unverified` rather than crashing. A quota condition must not
    take the whole fan-out down with it.

    The server singleton has no key in the test environment, so it degrades on
    the credential path before reaching the network — which is the same
    outcome by the other non-retryable route, and exactly what a run with no
    Pulsedive key should do.
    """
    from threat_intel_mcp import server

    httpx_mock.add_response(url=_EXPLORE_RE, status_code=429, is_reusable=True)

    result = await server.pulsedive_fetch_iocs()

    assert result["coverage_ledger_entry"]["status"] == "unverified"
    assert result["record_count"] == 0
    assert "error" in result

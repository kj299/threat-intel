"""Tests for the OpenPhish Community feed adapter.

Uses pytest-httpx — no live network in CI.

Unusually for a new adapter here, the body below is not invented: it is the
shape this repository read from OpenPhish's own published mirror
(github.com/openphish/public_feed) while the adapter was being written — plain
text, one absolute URL per line, no header and no comments. All 300 real lines
parsed and all 300 survived ``finalize_iocs``.

That still is not the same as having called ``openphish.com/feed.txt``, so the
tests that carry the most weight are the ones that hold whatever the canonical
endpoint turns out to serve: an unreadable body raises, an empty one does not,
a caller error raises, and the licence-driven TLP does not drift.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.adapters.openphish import (
    CACHE_TTL_SECONDS,
    OpenPhishAdapter,
    _normalize_line,
)
from threat_intel_mcp.normalize import finalize_iocs

_FEED_URL = "https://openphish.com/feed.txt"

# Shaped exactly like the vendor's own mirror: bare URLs, LF-separated,
# trailing newline.
_REAL_SHAPE = (
    "https://www.metuamssk-logiye.godaddysites.com/\n"
    "http://staging.dtbf2az168uk3.amplifyapp.com/\n"
    "https://wordpress-203685-icloudjp.cloudclusters.net/wp-content/accptw/index.php\n"
)


@pytest.fixture()
def adapter() -> OpenPhishAdapter:
    return OpenPhishAdapter()


# ─── Guards that hold whatever the endpoint serves ───────────────────────────


@pytest.mark.asyncio
async def test_an_html_error_page_raises_rather_than_reporting_zero(
    adapter, httpx_mock: HTTPXMock
):
    """The #100 failure mode, on this feed.

    ThreatFox served a 1 MB HTTP 200 that parsed to zero records and nobody
    noticed, because "no indicators" reads as a quiet week. A plain-text feed
    is especially exposed: an error page has lines, so a parser that accepted
    every line would return hundreds of confident garbage IOCs, and one that
    rejected them all would return a confident zero. This returns neither.
    """
    httpx_mock.add_response(
        url=_FEED_URL,
        text="<!DOCTYPE html>\n<html>\n<head><title>503</title></head>\n"
        "<body>Service Unavailable</body>\n</html>\n",
    )

    with pytest.raises(UpstreamFormatError, match="none of them in a recognisable shape"):
        await adapter.fetch()


@pytest.mark.asyncio
async def test_an_empty_feed_is_zero_records_not_an_error(adapter, httpx_mock: HTTPXMock):
    """The other half of the guard's contract.

    A body with no lines at all is an empty result set, not an unreadable one.
    Raising here would turn the guard into a false-alarm generator the first
    time OpenPhish published an empty feed.
    """
    httpx_mock.add_response(url=_FEED_URL, text="")

    result = await adapter.fetch()

    assert result.record_count == 0
    assert result.iocs == []


@pytest.mark.asyncio
async def test_an_http_error_propagates_so_the_tool_degrades(adapter, httpx_mock: HTTPXMock):
    """Per the taxonomy in adapters/base.py this is case 3: the tool must
    degrade to `unverified` and the fan-out must retry, which only happens if
    the adapter lets it out rather than swallowing it into an empty result."""
    import httpx

    httpx_mock.add_response(url=_FEED_URL, status_code=503)

    with pytest.raises(httpx.HTTPStatusError):
        await adapter.fetch()


@pytest.mark.asyncio
async def test_an_unknown_feed_type_is_a_caller_error(adapter):
    with pytest.raises(ValueError, match="Unknown feed_type"):
        await adapter.fetch(feed_types=["malware_ip"])


@pytest.mark.asyncio
async def test_egress_is_restricted_to_openphish(adapter):
    client = adapter._make_client()
    try:
        with pytest.raises(Exception):
            await client.get("https://evil.example.com/")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_no_credential_is_read(adapter, httpx_mock: HTTPXMock):
    """A keyless feed must stay keyless.

    The adapter's constructor takes no CredentialProvider at all, so there is
    no argument through which a key could start being read. Asserted rather
    than assumed, because "keyless" is this feed's entire reason for existing:
    a credentialed feed degrades to `unverified` when a subscription lapses.
    """
    import inspect

    params = inspect.signature(OpenPhishAdapter.__init__).parameters
    assert list(params) == ["self"], f"constructor grew a parameter: {list(params)}"

    httpx_mock.add_response(url=_FEED_URL, text=_REAL_SHAPE)
    await adapter.fetch()
    sent = httpx_mock.get_requests()[0]
    for header in ("authorization", "x-api-key", "key", "x-apikey"):
        assert header not in sent.headers, f"sent an auth header: {header}"


# ─── Behaviour given the shape the vendor publishes ──────────────────────────


@pytest.mark.asyncio
async def test_urls_are_parsed_into_ioc_network_records(adapter, httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_FEED_URL, text=_REAL_SHAPE)

    result = await adapter.fetch()

    assert result.record_count == 3
    assert result.source == "OpenPhish"
    assert result.tier == 6
    assert result.feed_types_fetched == ["phishing_urls"]
    first = result.iocs[0]
    assert first["type"] == "URL"
    assert first["value"] == "https://www.metuamssk-logiye.godaddysites.com/"
    assert first["action"] == "block"
    assert first["confidence"] == "High"
    assert first["associated_threat"] == "phishing"


@pytest.mark.asyncio
async def test_records_survive_the_validation_pipeline(adapter, httpx_mock: HTTPXMock):
    """The guard OTX did not have (#204).

    OTX emitted 960 records a run that every mock test accepted and that
    `finalize_iocs` then silently discarded, because no test ran the adapter's
    own output through the pipeline the tool layer actually applies. Emitting a
    record is not the same as delivering one.
    """
    httpx_mock.add_response(url=_FEED_URL, text=_REAL_SHAPE)

    result = await adapter.fetch()
    survived = finalize_iocs(result.iocs)

    assert len(survived) == len(result.iocs) == 3, (
        "records were dropped by sanitize/validate/dedupe — the adapter emits a "
        "shape the pipeline rejects"
    )


def test_the_licence_restriction_is_encoded_as_tlp_green():
    """TLP:WHITE would assert unrestricted redistribution.

    The Community feed is non-commercial use only, so WHITE would be a claim
    the licence does not grant. This is a one-word field that is easy to
    "tidy" to WHITE to match the other free feed (ThreatFox), which really is
    unrestricted — hence an explicit test rather than a comment.
    """
    record = _normalize_line("https://phish.example.test/login")
    assert record["tlp"] == "GREEN"


def test_markup_and_prose_are_not_mistaken_for_urls():
    assert _normalize_line('<a href="https://evil.example.test/">click</a>') is None
    assert _normalize_line("Service Unavailable") is None
    assert _normalize_line("ftp://files.example.test/x") is None
    assert _normalize_line("https://") is None
    assert _normalize_line("# a comment") is None
    assert _normalize_line("") is None


def test_a_valid_url_among_junk_is_still_kept():
    """Mixed input must not be all-or-nothing: the junk lines are dropped and
    the real indicator is kept, which is also what keeps `items_understood`
    non-zero so the guard does not fire on a partially odd body."""
    assert _normalize_line("https://real.example.test/a") is not None


@pytest.mark.asyncio
async def test_a_second_fetch_is_served_from_cache(adapter, httpx_mock: HTTPXMock):
    """The feed refreshes every 12 hours, so re-requesting it within one run
    spends bandwidth to receive identical bytes."""
    httpx_mock.add_response(url=_FEED_URL, text=_REAL_SHAPE)

    await adapter.fetch()
    await adapter.fetch()

    assert len(httpx_mock.get_requests()) == 1


def test_the_cache_ttl_matches_the_published_refresh_cadence():
    """12 hours, from the vendor's own feed README.

    Issue #169 recorded 6 hours from a third-party summary. A TTL shorter than
    the refresh only re-downloads identical bytes; one much longer serves stale
    indicators. Pinned so the number has to be changed deliberately.
    """
    assert CACHE_TTL_SECONDS == 12 * 3600


@pytest.mark.asyncio
async def test_a_comment_only_body_is_empty_not_unreadable(adapter, httpx_mock: HTTPXMock):
    """Found by the existing fan-out smoke test, not by this file.

    The first draft counted comment lines as "seen" and then dropped them as
    "not understood", so a body of nothing but comments tripped the
    empty-parse guard, was retried twice by the resilience layer, and degraded
    a healthy feed to `unverified`. Comments are now filtered before counting,
    the same way Q-Feeds does it — a feed with nothing to publish is an empty
    result, not a format break.
    """
    httpx_mock.add_response(url=_FEED_URL, text="# empty feed\n# nothing today\n")

    result = await adapter.fetch()

    assert result.record_count == 0
    assert result.iocs == []

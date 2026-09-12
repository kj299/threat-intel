"""Tests for the three abuse.ch adapters that share one Auth-Key.

Uses pytest-httpx — no live network in CI.

Every abuse.ch host is unreachable from the development sandbox, so the bodies
below follow abuse.ch's published documentation rather than a response anyone
has seen. That is the #203 setup, so the tests that carry the most weight are
the ones that hold whatever the field names turn out to be, plus the ones
asserting the credential reaches the wire at all — a key that is configured but
never sent is the #197 failure, and no mock can see repository settings.
"""

from __future__ import annotations

import re

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.adapters.feodo import (
    _IP_KEYS,
    FeodoTrackerAdapter,
    _normalize_entry as feodo_entry,
)
from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter
from threat_intel_mcp.adapters.urlhaus import URLhausAdapter, _to_rfc3339
from threat_intel_mcp.normalize import finalize_iocs
from threat_intel_mcp.vault.base import CredentialNotFoundError

_URLHAUS = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
_URLHAUS_RE = re.compile(r"^https://urlhaus-api\.abuse\.ch/v1/urls/recent/")
_FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_THREATFOX = "https://threatfox.abuse.ch/export/csv/recent/"

_KEY = "abusech-test-key"

# 15 columns, matching the real ThreatFox export layout (see test_threatfox.py).
_THREATFOX_CSV = (
    "# ThreatFox recent\n"
    '"2026-07-01 12:00:00", "500", "203.0.113.5:443", "ip:port", "botnet_cc", '
    '"cobalt_strike", "beacon", "Cobalt Strike", "2026-07-02 12:00:00", "90", '
    '"false", "https://threatfox.abuse.ch/ioc/500/", "tag1", "0", "anon"\n'
)


class FakeCredentials:
    """Provider holding only the shared abuse.ch key."""

    def __init__(self, key: str | None = _KEY) -> None:
        self._key = key

    def get(self, adapter: str, key: str) -> str:
        if self._key is None:
            raise CredentialNotFoundError(f"{adapter}/{key} not set")
        return self._key


def _urlhaus_body(status="ok", **overrides):
    entry = {
        "id": "1",
        "url": "http://evil.example.test/payload.exe",
        "url_status": "online",
        "host": "evil.example.test",
        "date_added": "2019-01-19 01:33:26 UTC",
        "threat": "malware_download",
        "tags": ["exe"],
    }
    entry.update(overrides)
    return {"query_status": status, "urls": [entry]}


# ─── The credential actually reaches the wire (#197) ─────────────────────────


@pytest.mark.asyncio
async def test_urlhaus_sends_the_auth_key_header(httpx_mock: HTTPXMock):
    """Five secrets once sat unread for weeks because nothing asserted a key
    was used (#197), and no check in this repo can see repository settings.
    The least it can do is assert the header leaves the process."""
    httpx_mock.add_response(url=_URLHAUS_RE, json=_urlhaus_body())

    await URLhausAdapter(FakeCredentials()).fetch()

    assert httpx_mock.get_requests()[0].headers["Auth-Key"] == _KEY


@pytest.mark.asyncio
async def test_threatfox_sends_the_auth_key_when_one_exists(httpx_mock: HTTPXMock):
    """ThreatFox's key is new and optional; assert it is actually sent.

    This is the whole point of the change — abuse.ch has required auth since
    2025-06-30 and ThreatFox only still answers because it reads a
    grandfathered CSV export. Sending the key is what stops that route's
    eventual closure from taking the feed with it.
    """
    httpx_mock.add_response(
        url=_THREATFOX,
        text=_THREATFOX_CSV,
    )

    await ThreatFoxAdapter(FakeCredentials()).fetch()

    assert httpx_mock.get_requests()[0].headers["Auth-Key"] == _KEY


@pytest.mark.asyncio
async def test_threatfox_still_works_with_no_key(httpx_mock: HTTPXMock):
    """The key is optional here on purpose. Breaking a feed that works today
    in order to add authentication to it would be a net loss."""
    httpx_mock.add_response(
        url=_THREATFOX,
        text=_THREATFOX_CSV,
    )

    result = await ThreatFoxAdapter(FakeCredentials(key=None)).fetch()

    assert result.record_count >= 0
    assert "Auth-Key" not in httpx_mock.get_requests()[0].headers


@pytest.mark.asyncio
async def test_urlhaus_without_a_key_is_a_credential_error(httpx_mock: HTTPXMock):
    """URLhaus's key is REQUIRED — its v1 API enforces auth. A missing key must
    raise the credential class so the tool degrades to `unverified` rather than
    crashing or silently returning nothing."""
    with pytest.raises(CredentialNotFoundError):
        await URLhausAdapter(FakeCredentials(key=None)).fetch()

    assert httpx_mock.get_requests() == [], "must fail before spending a request"


# ─── Guards that hold whatever the field names turn out to be ────────────────


@pytest.mark.asyncio
async def test_urlhaus_reports_its_in_band_error_rather_than_parsing_past_it(
    httpx_mock: HTTPXMock,
):
    """abuse.ch reports API errors in the body with HTTP 200.

    Parsed past, `query_status: "unauthorized"` becomes a confident empty feed
    — the exact shape of an outage that looks like a quiet week.
    """
    httpx_mock.add_response(
        url=_URLHAUS_RE,
        json={"query_status": "unauthorized", "urls": []},
    )

    with pytest.raises(RuntimeError, match="query_status"):
        await URLhausAdapter(FakeCredentials()).fetch()


@pytest.mark.asyncio
async def test_urlhaus_entries_in_an_unknown_shape_raise(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_URLHAUS_RE,
        json={"query_status": "ok", "urls": [{"link": "http://x.test/"}]},
    )

    with pytest.raises(UpstreamFormatError, match="none of them in a recognisable shape"):
        await URLhausAdapter(FakeCredentials()).fetch()


@pytest.mark.asyncio
async def test_feodo_a_non_array_body_raises(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_FEODO, json={"blocklist": []})

    with pytest.raises(RuntimeError, match="not a JSON array"):
        await FeodoTrackerAdapter(FakeCredentials()).fetch()


@pytest.mark.asyncio
async def test_feodo_entries_in_an_unknown_shape_raise(httpx_mock: HTTPXMock):
    """The scenario the module warning is about: if the JSON uses neither
    documented IP key, every entry drops — and that must raise, not report an
    empty blocklist."""
    httpx_mock.add_response(url=_FEODO, json=[{"address": "203.0.113.9"}])

    with pytest.raises(UpstreamFormatError):
        await FeodoTrackerAdapter(FakeCredentials()).fetch()


@pytest.mark.asyncio
async def test_feodo_an_empty_blocklist_is_not_an_error(httpx_mock: HTTPXMock):
    httpx_mock.add_response(url=_FEODO, json=[])

    result = await FeodoTrackerAdapter(FakeCredentials()).fetch()

    assert result.record_count == 0


@pytest.mark.parametrize("ip_key", _IP_KEYS)
def test_feodo_accepts_either_documented_ip_key(ip_key):
    """A closed pair, not open-ended permissiveness.

    abuse.ch's CSV flavour of this list calls the field `dst_ip`; the JSON
    documentation calls it `ip_address`. One of the two is right and this code
    cannot reach the API to find out, so both are read and the pair is pinned
    here. If a cassette later shows which, this test is what makes narrowing it
    a deliberate edit.
    """
    record = feodo_entry({ip_key: "203.0.113.9", "malware": "Emotet"})
    assert record is not None and record["value"] == "203.0.113.9"


def test_feodo_ip_keys_stay_a_closed_pair():
    assert _IP_KEYS == ("ip_address", "dst_ip"), (
        "the accepted IP field names changed — if a recording settled which one "
        "is real, narrow to it and say so in the adapter docstring"
    )


# ─── Behaviour given the documented shape ────────────────────────────────────


@pytest.mark.asyncio
async def test_urlhaus_offline_urls_are_kept_but_downgraded(httpx_mock: HTTPXMock):
    """An offline URL was still malicious. Dropping it loses history; calling it
    `block` over-claims that it is live."""
    httpx_mock.add_response(
        url=_URLHAUS_RE, json=_urlhaus_body(url_status="offline")
    )

    result = await URLhausAdapter(FakeCredentials()).fetch()
    ioc = result.iocs[0]

    assert ioc["action"] == "alert"
    assert ioc["confidence"] == "Medium"


@pytest.mark.asyncio
async def test_urlhaus_records_survive_the_validation_pipeline(httpx_mock: HTTPXMock):
    """The guard OTX did not have (#204): URLhaus timestamps are
    `"2019-01-19 01:33:26 UTC"`, which fails date-time validation unconverted
    and takes the whole record with it."""
    httpx_mock.add_response(url=_URLHAUS_RE, json=_urlhaus_body())

    result = await URLhausAdapter(FakeCredentials()).fetch()
    survived = finalize_iocs(result.iocs)

    assert len(survived) == len(result.iocs) == 1
    assert survived[0]["first_seen"] == "2019-01-19T01:33:26+00:00"


@pytest.mark.asyncio
async def test_feodo_records_survive_the_validation_pipeline(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        url=_FEODO,
        json=[{"ip_address": "203.0.113.9", "port": 443, "malware": "Emotet",
               "first_seen": "2026-09-01 10:00:00"}],
    )

    result = await FeodoTrackerAdapter(FakeCredentials()).fetch()
    survived = finalize_iocs(result.iocs)

    assert len(survived) == 1
    assert survived[0]["port"] == 443
    assert survived[0]["associated_threat"] == "Emotet"
    assert survived[0]["first_seen"] == "2026-09-01T10:00:00+00:00"


def test_urlhaus_unreadable_timestamps_are_omitted_not_passed_through():
    assert _to_rfc3339("2019-01-19 01:33:26 UTC") == "2019-01-19T01:33:26+00:00"
    assert _to_rfc3339("yesterday") is None
    assert _to_rfc3339(None) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "adapter_cls,url,host",
    [
        (URLhausAdapter, _URLHAUS, "urlhaus-api.abuse.ch"),
        (FeodoTrackerAdapter, _FEODO, "feodotracker.abuse.ch"),
    ],
)
async def test_egress_is_restricted_to_its_own_host(adapter_cls, url, host):
    client = adapter_cls(FakeCredentials())._make_client()
    try:
        with pytest.raises(Exception):
            await client.get("https://evil.example.com/")
    finally:
        await client.aclose()

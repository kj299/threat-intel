"""Every adapter must refuse to report a confident ``0 records`` (#106).

ThreatFox returned a 1,016,687-byte HTTP 200 that parsed to zero IOCs and
reported success (#100). An empty result is indistinguishable from a quiet
week, so a total parse failure reads as ordinary low volume. #100 fixed one
adapter; this file asserts the rule holds for all of them.

Three cases per adapter, and only the third is an error:

  * nothing in the payload            -> 0, no error
  * items present but filtered out    -> 0, no error
  * items present, none understood    -> UpstreamFormatError

The middle case is what keeps this from becoming a false-alarm generator, and
it is the one worth reading closely — it is adapter-specific and it is where a
careless implementation would start crying wolf on quiet weeks.
"""

from __future__ import annotations

import re

import pytest
from pytest_httpx import HTTPXMock

from threat_intel_mcp.adapters.abuseipdb import AbuseIPDBAdapter
from threat_intel_mcp.adapters.anyrun import AnyRunAdapter
from threat_intel_mcp.adapters.base import UpstreamFormatError
from threat_intel_mcp.adapters.censys import CensysAdapter
from threat_intel_mcp.adapters.cisa_kev import CISAKEVAdapter
from threat_intel_mcp.adapters.greynoise import GreyNoiseAdapter
from threat_intel_mcp.adapters.intel471 import Intel471Adapter
from threat_intel_mcp.adapters.nvd import NVDAdapter
from threat_intel_mcp.adapters.otx import OTXAdapter
from threat_intel_mcp.adapters.qfeeds import QFeedsAdapter
from threat_intel_mcp.adapters.shodan import ShodanAdapter
from threat_intel_mcp.adapters.threatfox import ThreatFoxAdapter
from threat_intel_mcp.adapters.virustotal import VirusTotalAdapter

_ANY_URL = re.compile(r"https://.+")


class _Creds:
    """Minimal credential provider: every lookup succeeds with a dummy value."""

    def get(self, source: str, field: str) -> str:
        return "dummy-key-for-test"


def _adapter(cls):
    if cls is VirusTotalAdapter:
        # Real delay is 15s between pages; the guard has nothing to do with
        # rate limiting and the suite should not wait on it.
        return cls(_Creds(), _rate_limit_delay=0)
    try:
        return cls(_Creds())
    except TypeError:
        return cls()


# feed_types to request per adapter, where the default set would muddy the
# result. Q-Feeds' malware_domains branch accepts any non-URL string as a
# Domain, so a junk body "parses" there and the fetch degrades to a partial
# failure rather than raising -- correct per the taxonomy, but it means the
# guard has to be exercised on the feed type that actually validates.
_FEED_TYPES = {"qfeeds": ["malware_ip"]}


# (label, adapter class, empty-but-valid body, unintelligible body)
#
# The "empty" body is what the upstream really sends when it has nothing:
# the envelope present, the item list empty. The "broken" body is a 200 whose
# shape we no longer recognise.
_CASES = [
    ("abuseipdb", AbuseIPDBAdapter, {"json": {"data": []}}, {"json": {"unexpected": 1}}),
    ("shodan", ShodanAdapter, {"json": {"matches": []}}, {"json": {"unexpected": 1}}),
    ("greynoise", GreyNoiseAdapter, {"json": {"data": []}}, {"json": {"unexpected": 1}}),
    (
        "censys",
        CensysAdapter,
        {"json": {"result": {"hits": []}}},
        {"json": {"unexpected": 1}},
    ),
    ("anyrun", AnyRunAdapter, {"json": {"objects": []}}, {"json": {"unexpected": 1}}),
    (
        "intel471",
        Intel471Adapter,
        {"json": {"indicators": []}},
        {"json": {"unexpected": 1}},
    ),
    ("otx", OTXAdapter, {"json": {"results": []}}, {"json": {"unexpected": 1}}),
    ("threatfox", ThreatFoxAdapter, {"text": "# no entries\n"}, {"text": "<html>nope</html>"}),
    ("qfeeds", QFeedsAdapter, {"text": ""}, {"text": "<html>nope</html>\nstill not an ioc\n"}),
    ("virustotal", VirusTotalAdapter, {"text": ""}, {"text": "<html>nope</html>"}),
]


@pytest.mark.asyncio
@pytest.mark.httpx_mock(
    assert_all_responses_were_requested=False,
    can_send_already_matched_responses=True,
)
@pytest.mark.parametrize("label,cls,empty_body,_broken", _CASES, ids=[c[0] for c in _CASES])
async def test_genuinely_empty_feed_returns_zero_without_error(
    label, cls, empty_body, _broken, httpx_mock: HTTPXMock
):
    """A feed with nothing to report is a quiet week, not an outage."""
    httpx_mock.add_response(url=_ANY_URL, **empty_body)
    result = await _adapter(cls).fetch(
        time_range="7d", feed_types=_FEED_TYPES.get(label)
    )
    assert result.record_count == 0
    assert result.iocs == []


@pytest.mark.asyncio
@pytest.mark.httpx_mock(
    assert_all_responses_were_requested=False,
    can_send_already_matched_responses=True,
)
@pytest.mark.parametrize("label,cls,_empty,broken_body", _CASES, ids=[c[0] for c in _CASES])
async def test_unintelligible_body_raises_rather_than_reporting_zero(
    label, cls, _empty, broken_body, httpx_mock: HTTPXMock
):
    """A 200 we cannot parse must not be published as ``0 records``.

    ``UpstreamFormatError`` subclasses ``RuntimeError``, so per
    ``adapters/base.py`` the tool degrades to ``unverified`` and the fan-out
    retries. A ``ValueError`` here would be re-raised verbatim and crash the
    call.
    """
    httpx_mock.add_response(url=_ANY_URL, **broken_body)
    with pytest.raises(RuntimeError) as excinfo:
        await _adapter(cls).fetch(
            time_range="7d", feed_types=_FEED_TYPES.get(label)
        )
    assert not isinstance(excinfo.value, ValueError)


def test_upstream_format_error_is_a_runtime_error_not_a_value_error():
    """The taxonomy contract in adapters/base.py, asserted rather than assumed.

    ValueError is reserved for caller errors and is re-raised verbatim by the
    server tools; an upstream format break must degrade instead of crashing.
    """
    assert issubclass(UpstreamFormatError, RuntimeError)
    assert not issubclass(UpstreamFormatError, ValueError)


class TestCVEFeeds:
    """The CVE path has its own envelope, so it gets its own cases."""

    @pytest.mark.asyncio
    async def test_kev_empty_catalog_is_zero(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=_ANY_URL, json={"vulnerabilities": []})
        result = await CISAKEVAdapter().fetch(time_range="7d")
        assert result.record_count == 0

    @pytest.mark.asyncio
    async def test_kev_unreadable_entries_raise(self, httpx_mock: HTTPXMock):
        """Envelope intact, every entry unrecognisable."""
        httpx_mock.add_response(
            url=_ANY_URL, json={"vulnerabilities": [{"nope": 1}, {"nope": 2}]}
        )
        with pytest.raises(RuntimeError, match="none of them in a recognisable shape"):
            await CISAKEVAdapter().fetch(time_range="7d")

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(can_send_already_matched_responses=True)
    async def test_nvd_empty_window_is_zero(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=_ANY_URL,
            json={"vulnerabilities": [], "resultsPerPage": 0, "totalResults": 0},
        )
        result = await NVDAdapter(_Creds()).fetch(time_range="7d")
        assert result.record_count == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(can_send_already_matched_responses=True)
    async def test_nvd_missing_envelope_raises_instead_of_ending_the_scan(
        self, httpx_mock: HTTPXMock
    ):
        """This one was a silent ``break``.

        A missing ``vulnerabilities`` key ended pagination and returned whatever
        had accumulated — so a renamed field looked exactly like an empty
        window rather than a broken API.
        """
        httpx_mock.add_response(url=_ANY_URL, json={"totalResults": 5})
        with pytest.raises(RuntimeError, match="missing 'vulnerabilities' list"):
            await NVDAdapter(_Creds()).fetch(time_range="7d")


class TestUnderstoodButFiltered:
    """The middle case: rows we read, then legitimately discarded.

    These are the tests that stop the guard crying wolf. Each feeds records the
    adapter understands perfectly well and correctly chooses not to emit.
    """

    @pytest.mark.asyncio
    async def test_greynoise_benign_scanners_are_understood(self, httpx_mock: HTTPXMock):
        """Records below the malicious classification are filtered, not unread."""
        httpx_mock.add_response(
            url=_ANY_URL,
            json={
                "data": [
                    {"ip": "1.2.3.4", "classification": "benign"},
                    {"ip": "5.6.7.8", "classification": "unknown"},
                ],
                "complete": True,
            },
        )
        result = await GreyNoiseAdapter(_Creds()).fetch(time_range="7d")
        assert result.record_count == 0

    @pytest.mark.asyncio
    @pytest.mark.httpx_mock(can_send_already_matched_responses=True)
    async def test_anyrun_non_indicator_stix_objects_are_understood(
        self, httpx_mock: HTTPXMock
    ):
        """A STIX bundle of identity/marking objects yields no IOCs, correctly."""
        httpx_mock.add_response(
            url=_ANY_URL,
            json={
                "objects": [
                    {"type": "identity", "name": "ANY.RUN"},
                    {"type": "marking-definition", "definition_type": "tlp"},
                ]
            },
        )
        result = await AnyRunAdapter(_Creds()).fetch(time_range="7d")
        assert result.record_count == 0

    @pytest.mark.asyncio
    async def test_otx_hash_only_pulses_are_understood(self, httpx_mock: HTTPXMock):
        """Pulses carrying only file hashes produce no *network* IOCs."""
        httpx_mock.add_response(
            url=_ANY_URL,
            json={
                "results": [
                    {
                        "name": "Hashes only",
                        "indicators": [
                            {"type": "FileHash-SHA256", "indicator": "a" * 64},
                            {"type": "FileHash-MD5", "indicator": "b" * 32},
                        ],
                    }
                ],
                "next": None,
            },
        )
        result = await OTXAdapter(_Creds()).fetch(time_range="7d")
        assert result.record_count == 0

    @pytest.mark.asyncio
    async def test_threatfox_hash_only_batch_is_understood(self, httpx_mock: HTTPXMock):
        rows = [
            '"2026-07-01 12:00:00", "1", "%s", "sha256_hash", "botnet_cc", "x", '
            '"y", "Malware", "2026-07-02 12:00:00", "90", "false", "ref", "t", "0", "a"'
            % ("a" * 64)
        ]
        httpx_mock.add_response(url=_ANY_URL, text="# header\n" + "\n".join(rows) + "\n")
        result = await ThreatFoxAdapter().fetch(time_range="7d")
        assert result.record_count == 0

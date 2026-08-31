"""Shared VCR configuration for cassette recording and playback (#105).

Why cassettes exist here
------------------------
The ThreatFox bug (#100) was not really a CSV dialect bug. The fixtures were
built with ``csv.writer``, which emits a shape abuse.ch does not produce, so the
suite agreed with a misconception and the adapter returned 0 IOCs from a 1 MB
response the first time it met the real feed. Every adapter is tested against
payloads *someone wrote*; where the belief behind one is wrong, the test is
wrong in the same direction.

A cassette is bytes the service actually sent. It cannot encode a misconception.

What this module guarantees
---------------------------
**Nothing recorded here may contain a credential.** Several feeds authenticate
by header (``x-apikey``, ``Authorization``) and two by query string (Shodan's
``key=``, NVD's ``apiKey=``), so a naive recording writes live keys into a file
destined for version control. ``audit.py`` redacts *logs*; it has never touched
test fixtures. The scrubbing below is the only thing standing between a
recording session and a committed secret, so it fails closed: unknown auth-ish
headers are dropped rather than kept.

Playback never touches the network. ``record_mode="none"`` means a request with
no matching cassette entry raises instead of silently reaching out, so a test
cannot quietly become a live test.
"""

from __future__ import annotations

import pathlib
from typing import Any

import vcr

CASSETTE_DIR = pathlib.Path(__file__).parent / "cassettes"

# Headers carrying credentials across the feeds we talk to. Matched
# case-insensitively by vcrpy.
_SECRET_HEADERS = [
    "authorization",       # Intel 471, Censys (HTTP Basic)
    "x-apikey",            # VirusTotal
    "x-otx-api-key",       # AlienVault OTX
    "key",                 # GreyNoise
    "x-api-key",           # generic
    "x-auth-token",        # generic
    "apikey",              # NVD (header form)
    "cookie",
    "set-cookie",
    "proxy-authorization",
]

# Credential-bearing query parameters. Shodan puts its key in the URL, which is
# also why audit.py has a redact_url in the first place.
_SECRET_QUERY_PARAMS = [
    "key",        # Shodan
    "apiKey",     # NVD
    "api_key",
    "token",
    "auth",
    "password",
    "secret",
]

_REDACTED = "[REDACTED]"

# ─── Wall-clock query parameters ─────────────────────────────────────────────
#
# NVD's request window is computed from `datetime.now()` at call time
# (`adapters/nvd.py`), so `lastModStartDate`/`lastModEndDate` differ between the
# moment a cassette is recorded and the moment it is replayed. Matching on the
# raw query string therefore can NEVER match: the first recording run failed
# its own playback gate 110 seconds after recording, on a two-minute clock
# difference alone.
#
# These names are excluded from the match key. Everything else in the query is
# still compared — critically `startIndex`, which is what tells NVD's four
# recorded pages apart, so this loosens the key without collapsing distinct
# requests onto one another.
#
# Add a name here only when a parameter is genuinely derived from the clock. A
# parameter that varies for any other reason is a real difference between two
# requests and must keep failing to match.
_VOLATILE_QUERY_PARAMS = frozenset(
    {
        "lastmodstartdate",  # NVD — now() - window
        "lastmodenddate",  # NVD — now()
        "pubstartdate",  # NVD — same contract, unused today
        "pubenddate",
    }
)


def _stable_query(request) -> list[tuple[str, str]]:
    """The request's query with clock-derived parameters removed."""
    return sorted(
        (name, value)
        for name, value in request.query
        if name.lower() not in _VOLATILE_QUERY_PARAMS
    )


def _match_query_ignoring_time(recorded, incoming) -> bool:
    """vcrpy matcher: compare queries, ignoring clock-derived parameters."""
    return _stable_query(recorded) == _stable_query(incoming)


def _scrub_response(response: dict[str, Any]) -> dict[str, Any]:
    """Drop response headers that could carry session state.

    Feed *bodies* are kept verbatim — they are the whole point of the cassette,
    and they are public threat data. Headers are not.
    """
    headers = response.get("headers") or {}
    for name in list(headers):
        if name.lower() in _SECRET_HEADERS:
            headers[name] = [_REDACTED]
    return response


def build_vcr(record_mode: str = "none") -> vcr.VCR:
    """Return the project's VCR instance.

    Args:
        record_mode: ``"none"`` for playback (the default, and what tests use —
            an unmatched request raises rather than hitting the network).
            ``"all"`` when deliberately re-recording from an egress-capable
            environment.
    """
    instance = vcr.VCR(
        cassette_library_dir=str(CASSETTE_DIR),
        record_mode=record_mode,
        filter_headers=[(h, _REDACTED) for h in _SECRET_HEADERS],
        filter_query_parameters=[(q, _REDACTED) for q in _SECRET_QUERY_PARAMS],
        before_record_response=_scrub_response,
        # Match on method + URI only. Bodies are irrelevant (every feed call is
        # a GET) and matching on headers would make a cassette break the moment
        # a User-Agent version string changes.
        #
        # The query is compared with clock-derived parameters excluded — see
        # _VOLATILE_QUERY_PARAMS. Comparing the raw query makes any adapter that
        # builds a request window from now() unplayable by construction.
        match_on=["method", "scheme", "host", "port", "path", "query_ignoring_time"],
        decode_compressed_response=True,
    )
    instance.register_matcher("query_ignoring_time", _match_query_ignoring_time)
    return instance


def cassette_path(name: str) -> pathlib.Path:
    return CASSETTE_DIR / f"{name}.yaml"


def has_cassette(name: str) -> bool:
    """True when a recorded cassette is available.

    Cassette-backed tests skip rather than fail when one is missing: recording
    requires network egress that CI and the dev sandbox do not have, and a
    missing recording is a gap in coverage, not a broken build.
    """
    return cassette_path(name).is_file()

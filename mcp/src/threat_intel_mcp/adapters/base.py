"""Adapter contract: the ``SourceAdapter`` protocol, ``FetchResult``, and the
exception taxonomy every adapter (IOC and CVE) must follow.

Error taxonomy (load-bearing — the server tools and fan-out branch on it)
------------------------------------------------------------------------
An adapter's ``fetch`` signals three *different* kinds of failure with three
*different* exception classes. Getting this wrong is a real bug: it decides
whether a single-feed tool **crashes** or **degrades**, and whether the fan-out
**retries** and **trips the circuit breaker**.

1. ``ValueError`` — **caller error** (unknown ``feed_types``, malformed
   ``time_range``). The value the *caller* passed is invalid. The server tool
   re-raises it verbatim so the mistake surfaces; the fan-out treats it as a
   non-retryable config error. Raise it ONLY for bad caller input.

2. ``CredentialError`` / ``KeyError`` (incl. ``CredentialNotFoundError``) —
   **credential/config problem** (missing or unreadable key). Non-retryable,
   does not trip the breaker, and the tool degrades it to an ``unverified``
   Coverage-Ledger entry. Fetch the key *before* opening the client so this
   fires fast. (Optional-credential feeds like NVD catch only
   ``CredentialNotFoundError`` and fall back to unauthenticated; a provider
   *outage* — plain ``CredentialError`` — still propagates.)

3. **Any other exception** (``httpx`` errors, ``RuntimeError``, parse failures)
   — **upstream/transient problem**. Retryable: the fan-out's backoff + circuit
   breaker engage, and the tool degrades to ``unverified``.

The trap: a **malformed upstream body** (a 200 with an unexpected shape) is case
3, NOT case 1 — do **not** raise ``ValueError`` for it (the tool would re-raise
and crash instead of degrading). Raise ``RuntimeError`` (or let the underlying
``httpx``/parse exception propagate). See ``adapters/cisa_kev.py::_parse_catalog``
for the reference pattern, and ``tests/test_server_smoke.py`` for the guard that
every single-feed tool degrades — never raises — on a malformed body.

Per-feed-type partial failure is orthogonal to the above: if *some* requested
feed types succeed, return them with ``partial_failure`` populated; only when
*every* requested type fails do you ``raise`` (a swallowed total failure would
disable the breaker and retry — see ``resilience.py``).

Empty results (the silent half of the same trap)
------------------------------------------------
Raising correctly is only half the contract. An adapter must also refuse to
report a confident ``0 records`` from a body it could not read, because an
empty result set is indistinguishable from a quiet week. Every adapter routes
its parse through ``guard_parsed`` below; see its docstring for the rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class FetchResult:
    """Normalised result from a single adapter fetch call."""

    iocs: list[dict[str, Any]]
    source: str
    tier: int
    retrieved_at: str          # ISO 8601 UTC timestamp
    record_count: int
    latency_ms: float
    feed_types_fetched: list[str]
    partial_failure: list[str] = field(default_factory=list)  # feed_types that failed


class UpstreamFormatError(RuntimeError):
    """A 200 response whose body could not be interpreted at all.

    A ``RuntimeError`` subclass on purpose: under the taxonomy above this is
    case 3, so the tool degrades to ``unverified`` and the fan-out retries.
    Raising ``ValueError`` here would be re-raised verbatim by the tool and
    crash the call.
    """


def guard_parsed(
    source: str,
    *,
    envelope_found: bool,
    envelope_desc: str,
    items_seen: int,
    items_understood: int,
) -> None:
    """Refuse to report a confident ``0 records`` from an unreadable body.

    An empty result is indistinguishable from a quiet week, so a total parse
    failure reads as ordinary low volume. ThreatFox returned a 1 MB HTTP 200
    that parsed to zero records for an unknown length of time before a manual
    live run caught it (#100); every adapter had the same exposure (#106).

    Three cases, and only the third is an error:

    ===========================================  ==========================
    Nothing in the payload                       ``0``, no error
    Items present and understood, none retained  ``0``, no error
    Items present, **none** understood           ``UpstreamFormatError``
    ===========================================  ==========================

    The middle case is what stops this becoming a false-alarm generator: a
    ThreatFox batch of nothing but file hashes, or a GreyNoise page whose rows
    are all below our confidence floor, legitimately yields no *network* IOCs.
    Those rows were still parsed, so they count as understood.

    ``envelope_found`` is a presence check, not a truthiness check: a body
    carrying ``{"data": []}`` really is an empty result set, while one with no
    ``data`` key at all is a response we failed to recognise. Callers must test
    ``"data" in body``, never ``if body.get("data")``.

    For paginated fetches, pass the totals for the whole fetch — an empty final
    page is normal termination, not a format break.
    """
    if not envelope_found:
        raise UpstreamFormatError(
            f"{source} response did not contain {envelope_desc}. The response "
            "parsed but carried nothing we recognise — the API shape has "
            "probably changed upstream. Refusing to report this as 0 records."
        )
    if items_seen and not items_understood:
        raise UpstreamFormatError(
            f"{source} returned {items_seen} record(s), none of them in a "
            "recognisable shape. The record layout has probably changed "
            "upstream. Refusing to report this as 0 records."
        )


@runtime_checkable
class SourceAdapter(Protocol):
    name: str
    tier: int

    async def fetch(
        self,
        *,
        time_range: str,
        feed_types: list[str] | None = None,
    ) -> FetchResult:
        """Fetch indicators and return them normalised to ioc_network schema shape."""
        ...

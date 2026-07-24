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

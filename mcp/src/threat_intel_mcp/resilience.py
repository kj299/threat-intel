"""Resilience primitives for adapter fan-out: circuit breaker + backoff retry.

These wrap an individual adapter's ``.fetch()`` so a single slow or failing
upstream feed degrades gracefully instead of failing a whole multi-source fetch.
They map directly onto the threat-intel skill's R5 Coverage Ledger: a source
whose circuit is open or whose retries are exhausted is surfaced as a partial /
unverified entry rather than crashing the tool call.

Clock, sleep, and RNG are injectable so the state machine and the backoff
schedule are deterministically testable without real wall-clock waits.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitOpenError(RuntimeError):
    """Raised when a call is attempted while the circuit breaker is open."""


@dataclass
class CircuitBreaker:
    """Per-source circuit breaker.

    State transitions::

        closed  --(failure_threshold consecutive failures)-->  open
        open    --(reset_timeout elapsed)-->                    half_open
        half_open --(trial succeeds)-->                         closed
        half_open --(trial fails)-->                            open

    The breaker does not itself perform calls; callers consult :meth:`allow`
    before issuing one and report the outcome via :meth:`record_success` /
    :meth:`record_failure`. ``clock`` defaults to ``time.monotonic`` and is
    injectable for testing.
    """

    name: str
    failure_threshold: int = 5
    reset_timeout: float = 30.0
    clock: Callable[[], float] = time.monotonic

    _consecutive_failures: int = field(default=0, init=False)
    _opened_at: float | None = field(default=None, init=False)
    _half_open: bool = field(default=False, init=False)
    _trial_pending: bool = field(default=False, init=False)

    @property
    def state(self) -> str:
        self._maybe_half_open()
        if self._opened_at is None:
            return "closed"
        return "half_open" if self._half_open else "open"

    def _maybe_half_open(self) -> None:
        if (
            self._opened_at is not None
            and not self._half_open
            and self.clock() - self._opened_at >= self.reset_timeout
        ):
            self._half_open = True
            logger.info("circuit %s -> half_open", self.name)

    def allow(self) -> bool:
        """Return True if a call may proceed right now.

        In half-open state exactly one trial call is admitted; further callers
        are rejected until the trial's outcome is recorded via
        :meth:`record_success` / :meth:`record_failure`.
        """
        self._maybe_half_open()
        if self._opened_at is None:
            return True
        if not self._half_open:
            return False
        # Half-open: admit a single trial call.
        if self._trial_pending:
            return False
        self._trial_pending = True
        return True

    def record_success(self) -> None:
        if self._opened_at is not None or self._consecutive_failures:
            logger.info("circuit %s -> closed (success)", self.name)
        self._consecutive_failures = 0
        self._opened_at = None
        self._half_open = False
        self._trial_pending = False

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        self._trial_pending = False
        if self._half_open:
            # The half-open trial failed: re-open and restart the cooldown.
            self._opened_at = self.clock()
            self._half_open = False
            logger.warning("circuit %s -> open (half-open trial failed)", self.name)
        elif (
            self._opened_at is None
            and self._consecutive_failures >= self.failure_threshold
        ):
            self._opened_at = self.clock()
            logger.warning(
                "circuit %s -> open (%d consecutive failures)",
                self.name,
                self._consecutive_failures,
            )


async def retry_with_backoff(
    factory: Callable[[], Awaitable[T]],
    *,
    retries: int = 2,
    base_delay: float = 0.5,
    max_delay: float = 4.0,
    jitter: bool = True,
    retry_on: tuple[type[BaseException], ...] = (Exception,),
    no_retry_on: tuple[type[BaseException], ...] = (),
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    rng: Callable[[], float] = random.random,
) -> T:
    """Call ``factory()`` with exponential backoff + jitter on failure.

    Makes up to ``retries + 1`` attempts. ``no_retry_on`` exceptions are raised
    immediately without retrying — retrying a missing API key just wastes time.
    The last exception is re-raised once attempts are exhausted.

    Backoff delay for attempt ``n`` (0-indexed) is
    ``min(max_delay, base_delay * 2**n)``, scaled into ``[0.5x, 1.0x]`` when
    ``jitter`` is on to avoid thundering-herd retries across sources.
    """
    attempt = 0
    while True:
        try:
            return await factory()
        except no_retry_on:
            raise
        except retry_on as exc:
            if attempt >= retries:
                raise
            delay = min(max_delay, base_delay * (2**attempt))
            if jitter:
                delay = delay * (0.5 + 0.5 * rng())
            logger.warning(
                "retry %d/%d after %s (sleeping %.2fs)",
                attempt + 1,
                retries,
                type(exc).__name__,
                delay,
            )
            await sleep(delay)
            attempt += 1


async def guarded_fetch(
    adapter: object,
    breaker: CircuitBreaker,
    *,
    time_range: str,
    feed_types: list[str] | None = None,
    no_retry_on: tuple[type[BaseException], ...] = (),
    **retry_kwargs: object,
) -> object:
    """Run ``adapter.fetch`` behind ``breaker`` with backoff retry.

    Raises :class:`CircuitOpenError` without calling the adapter when the circuit
    is open. ``no_retry_on`` exceptions (e.g. credential errors) propagate
    immediately and do **not** trip the breaker — a configuration error is not an
    upstream-health signal. Any other exhausted-retry exception trips the breaker
    and propagates.
    """
    if not breaker.allow():
        raise CircuitOpenError(f"{breaker.name} circuit is open")

    async def _call() -> object:
        return await adapter.fetch(time_range=time_range, feed_types=feed_types)  # type: ignore[attr-defined]

    try:
        result = await retry_with_backoff(
            _call, no_retry_on=no_retry_on, **retry_kwargs  # type: ignore[arg-type]
        )
    except no_retry_on:
        raise  # config error: leave breaker state untouched
    except Exception:
        breaker.record_failure()
        raise

    breaker.record_success()
    return result

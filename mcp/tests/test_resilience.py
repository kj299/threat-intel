"""Tests for the resilience primitives: circuit breaker + backoff retry.

Clock, sleep, and RNG are injected so the state machine and backoff schedule are
deterministic with no real wall-clock waits.
"""

from __future__ import annotations

import pytest

from threat_intel_mcp.resilience import (
    CircuitBreaker,
    CircuitOpenError,
    guarded_fetch,
    retry_with_backoff,
)


class FakeClock:
    """Manually advanced monotonic clock."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


# ---------------------------------------------------------------------------
# CircuitBreaker state machine
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_starts_closed_and_allows(self):
        cb = CircuitBreaker("x", failure_threshold=3)
        assert cb.state == "closed"
        assert cb.allow() is True

    def test_opens_after_threshold_consecutive_failures(self):
        clock = FakeClock()
        cb = CircuitBreaker("x", failure_threshold=3, clock=clock)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "closed"  # 2 < 3
        assert cb.allow() is True
        cb.record_failure()
        assert cb.state == "open"
        assert cb.allow() is False

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker("x", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        cb.record_failure()
        # only 2 consecutive after the reset → still closed
        assert cb.state == "closed"

    def test_half_open_after_reset_timeout(self):
        clock = FakeClock()
        cb = CircuitBreaker("x", failure_threshold=1, reset_timeout=30.0, clock=clock)
        cb.record_failure()
        assert cb.state == "open"
        assert cb.allow() is False
        clock.advance(29.0)
        assert cb.allow() is False
        clock.advance(2.0)  # now 31s ≥ 30s
        assert cb.allow() is True
        assert cb.state == "half_open"

    def test_half_open_success_closes(self):
        clock = FakeClock()
        cb = CircuitBreaker("x", failure_threshold=1, reset_timeout=10.0, clock=clock)
        cb.record_failure()
        clock.advance(11.0)
        assert cb.allow() is True  # half-open
        cb.record_success()
        assert cb.state == "closed"
        assert cb.allow() is True

    def test_half_open_admits_exactly_one_trial(self):
        clock = FakeClock()
        cb = CircuitBreaker("x", failure_threshold=1, reset_timeout=10.0, clock=clock)
        cb.record_failure()
        clock.advance(11.0)
        assert cb.allow() is True   # the single trial
        assert cb.allow() is False  # concurrent caller rejected
        assert cb.allow() is False
        cb.record_success()
        assert cb.allow() is True   # closed again

    def test_half_open_trial_slot_freed_after_failure(self):
        clock = FakeClock()
        cb = CircuitBreaker("x", failure_threshold=1, reset_timeout=10.0, clock=clock)
        cb.record_failure()
        clock.advance(11.0)
        assert cb.allow() is True
        cb.record_failure()          # trial failed -> open, cooldown restarts
        clock.advance(11.0)
        assert cb.allow() is True    # next half-open window admits a new trial

    def test_half_open_failure_reopens_and_restarts_cooldown(self):
        clock = FakeClock()
        cb = CircuitBreaker("x", failure_threshold=1, reset_timeout=10.0, clock=clock)
        cb.record_failure()
        clock.advance(11.0)
        assert cb.allow() is True  # half-open trial permitted
        cb.record_failure()  # trial fails
        assert cb.state == "open"
        assert cb.allow() is False
        clock.advance(5.0)  # cooldown restarted, not yet elapsed
        assert cb.allow() is False
        clock.advance(6.0)
        assert cb.allow() is True


# ---------------------------------------------------------------------------
# retry_with_backoff
# ---------------------------------------------------------------------------


class TestRetryWithBackoff:
    @pytest.mark.asyncio
    async def test_returns_on_first_success(self):
        calls = 0

        async def factory():
            nonlocal calls
            calls += 1
            return "ok"

        result = await retry_with_backoff(factory, retries=3)
        assert result == "ok"
        assert calls == 1

    @pytest.mark.asyncio
    async def test_retries_then_succeeds(self):
        calls = 0
        slept: list[float] = []

        async def factory():
            nonlocal calls
            calls += 1
            if calls < 3:
                raise ValueError("transient")
            return "ok"

        async def fake_sleep(d):
            slept.append(d)

        result = await retry_with_backoff(
            factory, retries=3, base_delay=1.0, jitter=False, sleep=fake_sleep
        )
        assert result == "ok"
        assert calls == 3
        # delays for attempt 0 and 1: 1.0, 2.0
        assert slept == [1.0, 2.0]

    @pytest.mark.asyncio
    async def test_exhausts_and_raises_last(self):
        calls = 0

        async def factory():
            nonlocal calls
            calls += 1
            raise RuntimeError(f"fail-{calls}")

        async def fake_sleep(d):
            pass

        with pytest.raises(RuntimeError, match="fail-3"):
            await retry_with_backoff(factory, retries=2, jitter=False, sleep=fake_sleep)
        assert calls == 3  # retries + 1

    @pytest.mark.asyncio
    async def test_no_retry_on_raises_immediately(self):
        calls = 0
        slept: list[float] = []

        async def factory():
            nonlocal calls
            calls += 1
            raise KeyError("missing-key")

        async def fake_sleep(d):
            slept.append(d)

        with pytest.raises(KeyError):
            await retry_with_backoff(
                factory,
                retries=5,
                no_retry_on=(KeyError,),
                sleep=fake_sleep,
            )
        assert calls == 1
        assert slept == []

    @pytest.mark.asyncio
    async def test_max_delay_caps_backoff(self):
        slept: list[float] = []

        async def factory():
            raise ValueError("x")

        async def fake_sleep(d):
            slept.append(d)

        with pytest.raises(ValueError):
            await retry_with_backoff(
                factory,
                retries=5,
                base_delay=1.0,
                max_delay=3.0,
                jitter=False,
                sleep=fake_sleep,
            )
        # 1, 2, 3(capped from 4), 3(capped from 8), 3(capped from 16)
        assert slept == [1.0, 2.0, 3.0, 3.0, 3.0]

    @pytest.mark.asyncio
    async def test_jitter_scales_into_half_to_full_range(self):
        slept: list[float] = []

        async def factory():
            raise ValueError("x")

        async def fake_sleep(d):
            slept.append(d)

        # rng fixed at 0.0 → jitter factor 0.5; base_delay 2.0 → first delay 1.0
        with pytest.raises(ValueError):
            await retry_with_backoff(
                factory,
                retries=1,
                base_delay=2.0,
                jitter=True,
                sleep=fake_sleep,
                rng=lambda: 0.0,
            )
        assert slept == [1.0]


# ---------------------------------------------------------------------------
# guarded_fetch
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, value):
        self.value = value


class FakeAdapter:
    name = "Fake"
    tier = 2

    def __init__(self, *, fail_times: int = 0, exc: type[BaseException] = ValueError):
        self.calls = 0
        self.fail_times = fail_times
        self.exc = exc

    async def fetch(self, *, time_range: str, feed_types=None):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.exc("boom")
        return _FakeResult("data")


async def _no_sleep(d):
    pass


class TestGuardedFetch:
    @pytest.mark.asyncio
    async def test_success_records_success(self):
        cb = CircuitBreaker("Fake", failure_threshold=2)
        adapter = FakeAdapter()
        result = await guarded_fetch(
            adapter, cb, time_range="7d", retries=0, sleep=_no_sleep
        )
        assert result.value == "data"
        assert cb.state == "closed"

    @pytest.mark.asyncio
    async def test_failure_trips_breaker_after_threshold(self):
        cb = CircuitBreaker("Fake", failure_threshold=2)
        adapter = FakeAdapter(fail_times=99)

        for _ in range(2):
            with pytest.raises(ValueError):
                await guarded_fetch(
                    adapter, cb, time_range="7d", retries=0, sleep=_no_sleep
                )
        assert cb.state == "open"

    @pytest.mark.asyncio
    async def test_open_circuit_raises_without_calling_adapter(self):
        cb = CircuitBreaker("Fake", failure_threshold=1)
        adapter = FakeAdapter(fail_times=99)

        with pytest.raises(ValueError):
            await guarded_fetch(
                adapter, cb, time_range="7d", retries=0, sleep=_no_sleep
            )
        assert cb.state == "open"
        calls_before = adapter.calls
        with pytest.raises(CircuitOpenError):
            await guarded_fetch(
                adapter, cb, time_range="7d", retries=0, sleep=_no_sleep
            )
        assert adapter.calls == calls_before  # adapter not invoked

    @pytest.mark.asyncio
    async def test_config_error_does_not_trip_breaker(self):
        cb = CircuitBreaker("Fake", failure_threshold=1)
        adapter = FakeAdapter(fail_times=99, exc=KeyError)

        with pytest.raises(KeyError):
            await guarded_fetch(
                adapter,
                cb,
                time_range="7d",
                no_retry_on=(KeyError,),
                retries=3,
                sleep=_no_sleep,
            )
        assert adapter.calls == 1  # not retried
        assert cb.state == "closed"  # breaker untouched

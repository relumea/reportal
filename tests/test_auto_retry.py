"""Tests for the auto-mode retry backoff: the delay schedule, not the waiting.

The sleep and the jitter are module-level seams in `reportal.auto_mode`; every
test here patches both, so it asserts the exact delay sequence without a real
wait.
"""

from __future__ import annotations

import sqlite3

import pytest
from auto_helpers import WorkerProbe, seed_rows

from reportal import auto_mode, auto_workers

ONE_FUNCTION: tuple[tuple[int, str, int, str], ...] = ((0x1000, "Work", 8, "STUB"),)


def _record_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Patch the jitter to 1.0 and the sleep to a recorder; return the recorder."""
    delays: list[float] = []
    monkeypatch.setattr(auto_mode, "_retry_jitter", lambda: 1.0)
    monkeypatch.setattr(auto_mode, "_sleep", delays.append)
    return delays


def _failing_run(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, *, max_attempts: int
) -> tuple[list[float], int]:
    """Run one failing function through *max_attempts*; return (delays, calls)."""
    ids = seed_rows(conn, rows=ONE_FUNCTION)
    delays = _record_sleeps(monkeypatch)
    probe = WorkerProbe(status=auto_workers.WORKER_FAILED)
    auto_workers.register_worker(probe.make(), origin="test")
    auto_mode.run_auto(conn, binary_id=ids["binary"], worker="probe", max_attempts=max_attempts)
    return delays, len(probe.calls)


class TestRetryDelay:
    def test_delay_doubles_from_the_base_and_caps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(auto_mode, "_retry_jitter", lambda: 1.0)
        assert [auto_mode._retry_delay(attempt) for attempt in range(1, 7)] == [
            0.5,
            1.0,
            2.0,
            4.0,
            8.0,
            8.0,
        ]

    def test_delay_never_exceeds_the_cap(self) -> None:
        for attempt in range(1, 12):
            delay = auto_mode._retry_delay(attempt)
            assert 0.0 < delay <= auto_mode.RETRY_MAX_SECONDS

    def test_a_seed_replays_the_same_jitter_sequence(self) -> None:
        auto_mode.seed_retry_rng(42)
        first = [auto_mode._retry_jitter() for _ in range(8)]
        auto_mode.seed_retry_rng(42)
        second = [auto_mode._retry_jitter() for _ in range(8)]
        assert first == second
        auto_mode.seed_retry_rng(7)
        assert [auto_mode._retry_jitter() for _ in range(8)] != first


class TestRetrySchedule:
    def test_delays_are_applied_between_attempts_only(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        delays, calls = _failing_run(conn, monkeypatch, max_attempts=3)
        assert calls == 3
        assert delays == [0.5, 1.0]

    def test_a_single_attempt_run_does_not_wait(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        delays, calls = _failing_run(conn, monkeypatch, max_attempts=1)
        assert calls == 1
        assert delays == []

    def test_a_successful_first_attempt_does_not_wait(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_rows(conn, rows=ONE_FUNCTION)
        delays = _record_sleeps(monkeypatch)
        probe = WorkerProbe()
        auto_workers.register_worker(probe.make(), origin="test")
        auto_mode.run_auto(conn, binary_id=ids["binary"], worker="probe", max_attempts=3)
        assert len(probe.calls) == 1
        assert delays == []


class TestRetryRngConcurrency:
    def test_concurrent_draws_stay_in_range(self) -> None:
        """Batch workers share the jitter RNG; draws must not corrupt its state."""
        import threading

        errors: list[BaseException] = []
        values: list[float] = []

        def draw() -> None:
            try:
                for _ in range(200):
                    values.append(auto_mode._retry_jitter())
            except BaseException as exc:  # surface a torn RNG as a test failure
                errors.append(exc)

        threads = [threading.Thread(target=draw) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        assert len(values) == 1600
        low, high = auto_mode.RETRY_JITTER_LOW, auto_mode.RETRY_JITTER_HIGH
        assert all(low <= value <= high for value in values)

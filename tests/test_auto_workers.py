"""Tests for the auto-mode worker registry and its built-in workers."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest
from auto_helpers import make_context, seed_rows

from reportal import auto_workers, plugins, store
from reportal.auto_workers import Worker, WorkerContext, WorkerResult


def _noop_run(ctx: WorkerContext) -> WorkerResult:
    return WorkerResult(status=auto_workers.WORKER_SKIPPED, function_id=int(ctx.function["id"]))


def _worker(name: str) -> Worker:
    return Worker(name=name, description="A test worker.", run=_noop_run)


def _plugin_worker() -> Worker:
    """A zero-argument factory an entry-point registration can resolve."""
    return _worker("plugin")


# An attribute an entry-point value can name but that is not a Worker, so the
# registry's type check is what rejects it (not a missing attribute).
_NOT_A_WORKER = "a string"


class _EntryPoint:
    def __init__(self, name: str, value: str) -> None:
        self.name = name
        self.value = value


class _EntryPoints:
    def __init__(self, entries: list[_EntryPoint]) -> None:
        self._entries = entries

    def select(self, *, group: str) -> list[_EntryPoint]:
        return list(self._entries)


def _patch_entry_points(monkeypatch: pytest.MonkeyPatch, *entries: _EntryPoint) -> None:
    monkeypatch.setattr(plugins, "entry_points", lambda: _EntryPoints(list(entries)))


class TestRegistry:
    def test_builtins_are_registered(self) -> None:
        names = [worker.name for worker in auto_workers.workers()]
        assert auto_workers.WORKER_OFFLINE in names
        assert auto_workers.WORKER_LLM_C_SOURCE in names
        assert auto_workers.WORKER_LLM_GOAL in names

    def test_get_worker_resolves_by_name(self) -> None:
        worker = auto_workers.get_worker(auto_workers.WORKER_OFFLINE)
        assert worker is not None
        assert worker.name == auto_workers.WORKER_OFFLINE

    def test_get_unknown_worker_is_none(self) -> None:
        assert auto_workers.get_worker("nope") is None

    def test_register_adds_it(self) -> None:
        auto_workers.register_worker(_worker("probe"), origin="test")
        assert auto_workers.get_worker("probe") is not None

    def test_duplicate_name_raises(self) -> None:
        auto_workers.register_worker(_worker("probe"), origin="test")
        with pytest.raises(auto_workers.RegistryError):
            auto_workers.register_worker(_worker("probe"), origin="other")

    def test_registering_a_non_worker_raises(self) -> None:
        with pytest.raises(auto_workers.RegistryError):
            auto_workers.register_worker("not a worker", origin="test")  # type: ignore[arg-type]

    def test_registering_an_empty_name_raises(self) -> None:
        with pytest.raises(auto_workers.RegistryError):
            auto_workers.register_worker(_worker("  "), origin="test")

    def test_registering_a_non_callable_run_raises(self) -> None:
        broken = Worker(name="broken", description="x", run="not callable")  # type: ignore[arg-type]
        with pytest.raises(auto_workers.RegistryError):
            auto_workers.register_worker(broken, origin="test")

    def test_refresh_drops_registered_workers(self) -> None:
        auto_workers.register_worker(_worker("probe"), origin="test")
        names = [worker.name for worker in auto_workers.refresh_workers()]
        assert "probe" not in names
        assert auto_workers.WORKER_OFFLINE in names

    def test_unregister_withdraws_one_entry(self) -> None:
        auto_workers.register_worker(_worker("probe"), origin="test")
        auto_workers.unregister_worker("probe")
        assert auto_workers.get_worker("probe") is None
        assert auto_workers.get_worker(auto_workers.WORKER_OFFLINE) is not None

    def test_unregister_unknown_name_raises(self) -> None:
        with pytest.raises(auto_workers.RegistryError):
            auto_workers.unregister_worker("nope")

    def test_entry_point_factory_is_resolved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("plugin", "test_auto_workers:_plugin_worker"))
        auto_workers.refresh_workers()
        worker = auto_workers.get_worker("plugin")
        assert worker is not None
        assert worker.name == "plugin"

    def test_broken_entry_point_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("broken", "no_such_module:thing"))
        names = [worker.name for worker in auto_workers.refresh_workers()]
        assert "broken" not in names
        assert auto_workers.WORKER_OFFLINE in names

    def test_entry_point_naming_something_else_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("odd", "test_auto_workers:_NOT_A_WORKER"))
        names = [worker.name for worker in auto_workers.refresh_workers()]
        assert "odd" not in names


class TestHelpers:
    @pytest.mark.parametrize("name", ["sub_1000", "func_10008880", "loc_1a2b", "unk_10"])
    def test_address_placeholders(self, name: str) -> None:
        assert auto_workers.is_address_placeholder(name)

    @pytest.mark.parametrize("name", ["FreePrintSetup", "sub_main", "func_", "ChooseFontW"])
    def test_real_symbols_are_not_placeholders(self, name: str) -> None:
        assert not auto_workers.is_address_placeholder(name)

    @pytest.mark.parametrize("status", ["EXACT", "RELOC", "PROVEN"])
    def test_matching_statuses(self, status: str) -> None:
        assert auto_workers.is_matching_status(status)

    @pytest.mark.parametrize("status", ["STUB", "NEAR_MATCHING", ""])
    def test_non_matching_statuses(self, status: str) -> None:
        assert not auto_workers.is_matching_status(status)


class TestOfflineWorker:
    def _context(self, conn: sqlite3.Connection, function_id: int, **kwargs: Any) -> WorkerContext:
        return make_context(conn, _function_row(conn, function_id), **kwargs)

    def test_marked_function_matches_without_an_engine(self, conn: sqlite3.Connection) -> None:
        seed_rows(conn)
        worker = auto_workers.get_worker(auto_workers.WORKER_OFFLINE)
        assert worker is not None
        result = worker.run(self._context(conn, 1))
        assert result.status == auto_workers.WORKER_MATCHED
        assert result.verified is True
        assert result.status_after == auto_workers.OFFLINE_CLAIMED_STATUS
        assert result.status_before == "STUB"

    def test_address_placeholder_fails(self, conn: sqlite3.Connection) -> None:
        seed_rows(conn)
        worker = auto_workers.get_worker(auto_workers.WORKER_OFFLINE)
        assert worker is not None
        result = worker.run(self._context(conn, 2))
        assert result.status == auto_workers.WORKER_FAILED
        assert result.detail["reason"] == auto_workers.REASON_NO_SYMBOL

    def test_already_matched_function_is_skipped(self, conn: sqlite3.Connection) -> None:
        seed_rows(conn)
        worker = auto_workers.get_worker(auto_workers.WORKER_OFFLINE)
        assert worker is not None
        result = worker.run(self._context(conn, 3))
        assert result.status == auto_workers.WORKER_SKIPPED
        assert result.detail["reason"] == "already-matched"

    def test_execute_is_refused(self, conn: sqlite3.Connection) -> None:
        seed_rows(conn)
        worker = auto_workers.get_worker(auto_workers.WORKER_OFFLINE)
        assert worker is not None
        result = worker.run(self._context(conn, 1, execute=True))
        assert result.status == auto_workers.WORKER_FAILED
        assert result.detail["reason"] == auto_workers.REASON_OFFLINE_NOT_EXECUTABLE

    def test_a_nameless_function_fails(self, conn: sqlite3.Connection) -> None:
        seed_rows(conn, rows=((0x1000, "", 8, "STUB"),))
        worker = auto_workers.get_worker(auto_workers.WORKER_OFFLINE)
        assert worker is not None
        result = worker.run(self._context(conn, 1))
        assert result.status == auto_workers.WORKER_FAILED
        assert result.detail["reason"] == auto_workers.REASON_NO_SYMBOL


def _function_row(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:

    row = store.get_function(conn, function_id)
    if row is None:
        raise AssertionError(f"no function with id {function_id}")
    return row

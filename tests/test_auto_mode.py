"""Tests for the auto-mode orchestrator: selection, planning, fan-out, aggregation."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest
from auto_helpers import WorkerProbe, seed_rows, writer_worker

from reportal import auto_mode, auto_store, auto_workers, effects, store

# Rows whose sizes are deliberately out of VA order, so selection ordering is
# observable: (va, name, size, status).
SIZED_ROWS: tuple[tuple[int, str, int, str], ...] = (
    (0x1000, "BigOne", 100, "STUB"),
    (0x1100, "SmallOne", 10, "STUB"),
    (0x1200, "MatchedOne", 50, "EXACT"),
    (0x1300, "MediumOne", 40, ""),
    (0x1400, "NearOne", 20, "NEAR_MATCHING"),
)


@pytest.fixture(autouse=True)
def _no_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run retries without waiting; the delay schedule is asserted in test_auto_retry."""
    monkeypatch.setattr(auto_mode, "_sleep", lambda _seconds: None)


class TestSelectFunctions:
    def test_excludes_matching_statuses_and_orders_by_size_then_va(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        selected = auto_mode.select_functions(conn, ids["binary"])
        names = [row["name"] for row in selected]
        assert names == ["SmallOne", "NearOne", "MediumOne", "BigOne"]

    def test_limit_caps_the_selection(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        selected = auto_mode.select_functions(conn, ids["binary"], limit=2)
        assert [row["name"] for row in selected] == ["SmallOne", "NearOne"]

    def test_empty_when_every_function_matches(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Done", 4, "RELOC"),))
        assert auto_mode.select_functions(conn, ids["binary"]) == []


class TestBuildParams:
    def test_defaults(self) -> None:
        params = auto_mode.build_params()
        assert params.worker == auto_workers.WORKER_OFFLINE
        assert params.execute is False
        assert params.concurrency == auto_mode.DEFAULT_CONCURRENCY
        assert params.functions_per_task == auto_mode.DEFAULT_FUNCTIONS_PER_TASK
        assert params.max_attempts == auto_mode.DEFAULT_MAX_ATTEMPTS
        assert params.max_tasks == auto_mode.DEFAULT_MAX_TASKS
        assert params.task_timeout == auto_mode.DEFAULT_TASK_TIMEOUT_SECONDS
        assert params.keep_failures is False

    def test_config_round_trips(self) -> None:
        params = auto_mode.build_params(worker="offline", disabled=frozenset({"other"}))
        assert params.as_config()["disabled"] == ["other"]

    def test_unknown_worker_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown worker"):
            auto_mode.build_params(worker="nope")

    @pytest.mark.parametrize("value", [0, 33])
    def test_concurrency_bounds(self, value: int) -> None:
        with pytest.raises(ValueError, match="concurrency"):
            auto_mode.build_params(concurrency=value)

    @pytest.mark.parametrize("value", [0, 65])
    def test_functions_per_task_bounds(self, value: int) -> None:
        with pytest.raises(ValueError, match="functions_per_task"):
            auto_mode.build_params(functions_per_task=value)

    @pytest.mark.parametrize("value", [0, 11])
    def test_max_attempts_bounds(self, value: int) -> None:
        with pytest.raises(ValueError, match="max_attempts"):
            auto_mode.build_params(max_attempts=value)

    @pytest.mark.parametrize("value", [0, 5001])
    def test_max_tasks_bounds(self, value: int) -> None:
        with pytest.raises(ValueError, match="max_tasks"):
            auto_mode.build_params(max_tasks=value)

    def test_task_timeout_bounds(self) -> None:
        with pytest.raises(ValueError, match="task_timeout"):
            auto_mode.build_params(task_timeout=0.0)
        with pytest.raises(ValueError, match="task_timeout"):
            auto_mode.build_params(task_timeout=7200.0)

    def test_disabled_worker_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="disabled"):
            auto_mode.build_params(worker="offline", disabled={"offline"})

    def test_execute_must_be_a_boolean(self) -> None:
        with pytest.raises(ValueError, match="execute"):
            auto_mode.build_params(execute="yes")  # type: ignore[arg-type]

    def test_a_non_integer_bound_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be an integer"):
            auto_mode.build_params(concurrency=2.5)  # type: ignore[arg-type]


class TestDecomposition:
    def test_one_batch_per_function_with_the_root_as_parent(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        params = auto_mode.build_params()
        functions = auto_mode.select_functions(conn, ids["binary"])
        run_id = auto_mode.create_auto_run(
            conn, binary_id=ids["binary"], params=params, functions=functions
        )
        run = auto_store.get_auto_run(conn, run_id)
        assert run is not None
        tasks = auto_store.list_auto_tasks(conn, run_id)
        root = next(task for task in tasks if task["kind"] == auto_store.AUTO_TASK_ROOT)
        batches = [task for task in tasks if task["kind"] == auto_store.AUTO_TASK_BATCH]
        assert root["depth"] == auto_store.AUTO_ROOT_DEPTH
        assert root["parent_id"] is None
        assert len(batches) == 4
        assert all(task["parent_id"] == root["id"] for task in batches)
        assert all(task["depth"] == auto_store.AUTO_BATCH_DEPTH for task in batches)
        single = next(task for task in batches if task["title"].startswith("SmallOne"))
        assert single["function_id"] is not None
        assert single["va"] == 0x1100

    def test_functions_per_task_groups_the_batches(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        params = auto_mode.build_params(functions_per_task=3)
        functions = auto_mode.select_functions(conn, ids["binary"])
        run_id = auto_mode.create_auto_run(
            conn, binary_id=ids["binary"], params=params, functions=functions
        )
        batches = [
            task
            for task in auto_store.list_auto_tasks(conn, run_id)
            if task["kind"] == auto_store.AUTO_TASK_BATCH
        ]
        assert len(batches) == 2
        assert batches[0]["function_id"] is None
        assert "3 functions" in batches[0]["title"]

    def test_planned_functions_are_stored_on_the_batch(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        params = auto_mode.build_params()
        functions = auto_mode.select_functions(conn, ids["binary"])
        run_id = auto_mode.create_auto_run(
            conn, binary_id=ids["binary"], params=params, functions=functions
        )
        batches = auto_mode.planned_batches(conn, run_id)
        assert len(batches) == 4
        _task_id, planned = batches[0]
        assert [entry["name"] for entry in planned] == ["SmallOne"]

    def test_max_tasks_caps_the_planned_rows(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        params = auto_mode.build_params(max_tasks=2)
        functions = auto_mode.select_functions(conn, ids["binary"])
        run_id = auto_mode.create_auto_run(
            conn, binary_id=ids["binary"], params=params, functions=functions
        )
        tasks = auto_store.list_auto_tasks(conn, run_id)
        assert len(tasks) == 2
        assert len([task for task in tasks if task["kind"] == auto_store.AUTO_TASK_BATCH]) == 1

    def test_unknown_binary_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            auto_mode.create_auto_run(
                conn, binary_id=999, params=auto_mode.build_params(), functions=[]
            )


class TestRunAuto:
    def test_offline_run_reports_counts_and_projected_coverage(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="offline")
        assert run["status"] == auto_store.AUTO_RUN_DONE
        assert run["matched"] == 4  # every selected function carries a real name
        assert run["failed"] == 0
        assert run["tasks"] == 5  # root plus one batch per selected function
        assert run["attempts"] == 4
        assert run["coverage_before"] == {"matched": 1, "total": 5, "ratio": 0.2}
        assert run["coverage_after"]["matched"] == 5
        tree = run["tree"]
        assert len(tree) == 1
        assert tree[0]["kind"] == auto_store.AUTO_TASK_ROOT
        assert tree[0]["status"] == auto_store.AUTO_TASK_DONE

    def test_dry_run_writes_no_status_and_no_file(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        auto_mode.run_auto(conn, binary_id=ids["binary"], worker="offline")
        statuses = {
            row["name"]: row["status"]
            for row in store.list_functions(conn, binary_id=ids["binary"])
        }
        assert statuses["SmallOne"] == "STUB"
        assert statuses["BigOne"] == "STUB"

    def test_a_matched_claim_without_a_matching_status_is_improved(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        probe = WorkerProbe(
            status=auto_workers.WORKER_MATCHED, status_after="NEAR_MATCHING", artifacts=True
        )
        auto_workers.register_worker(probe.make(), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="probe")
        assert run["matched"] == 0
        assert run["improved"] == 1
        batch = run["tree"][0]["children"][0]
        assert batch["status"] == auto_store.AUTO_TASK_SKIPPED

    def test_a_matched_claim_without_verification_is_improved(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        probe = WorkerProbe(status=auto_workers.WORKER_MATCHED, verified=False, artifacts=True)
        auto_workers.register_worker(probe.make(), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="probe")
        assert run["matched"] == 0
        assert run["improved"] == 1

    def test_a_matched_claim_with_nothing_produced_is_failed(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        probe = WorkerProbe(status=auto_workers.WORKER_MATCHED, verified=False, artifacts=False)
        auto_workers.register_worker(probe.make(), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="probe")
        assert run["matched"] == 0
        assert run["failed"] == 1
        assert run["tree"][0]["children"][0]["status"] == auto_store.AUTO_TASK_FAILED

    def test_all_failed_batches_fail_the_run(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=((0x1000, "sub_1000", 8, "STUB"),))
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="offline")
        assert run["failed"] == 1
        assert run["status"] == auto_store.AUTO_RUN_FAILED
        assert run["tree"][0]["status"] == auto_store.AUTO_TASK_FAILED

    def test_a_mixed_batch_is_done(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(
            conn,
            rows=((0x1000, "Marked", 8, "STUB"), (0x1100, "sub_1100", 4, "STUB")),
        )
        run = auto_mode.run_auto(
            conn, binary_id=ids["binary"], worker="offline", functions_per_task=2
        )
        batch = run["tree"][0]["children"][0]
        assert batch["status"] == auto_store.AUTO_TASK_DONE
        assert run["matched"] == 1
        assert run["failed"] == 1

    def test_mixed_batch_outcomes_close_the_run_as_partial(self, conn: sqlite3.Connection) -> None:
        # One batch succeeds (named function) and one fails (anonymous stub):
        # the run must close partial, matching recovery's aggregate.
        ids = seed_rows(
            conn,
            rows=((0x1000, "Marked", 8, "STUB"), (0x1100, "sub_1100", 4, "STUB")),
        )
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="offline")
        statuses = sorted(child["status"] for child in run["tree"][0]["children"])
        assert statuses == [auto_store.AUTO_TASK_DONE, auto_store.AUTO_TASK_FAILED]
        assert run["status"] == auto_store.AUTO_RUN_PARTIAL
        assert run["matched"] == 1
        assert run["failed"] == 1

    def test_execute_refuses_a_finished_run(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="offline")
        with pytest.raises(ValueError, match="expected running"):
            auto_mode.execute_auto_run(conn, run_id=run["run_id"], params=auto_mode.build_params())

    def test_a_batch_of_only_skips_is_skipped(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Matched", 8, "EXACT"),))
        # No function is selected, so the run has no batches at all.
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="offline")
        assert run["tasks"] == 1
        assert run["tree"][0]["status"] == auto_store.AUTO_TASK_SKIPPED
        assert run["status"] == auto_store.AUTO_RUN_DONE

    def test_retries_are_recorded_per_attempt(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        probe = WorkerProbe(status=auto_workers.WORKER_FAILED)
        auto_workers.register_worker(probe.make(), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="probe", max_attempts=3)
        assert len(probe.calls) == 3
        assert run["attempts"] == 3
        batch = run["tree"][0]["children"][0]
        assert [entry["attempt"] for entry in batch["attempt_log"]] == [1, 2, 3]

    def test_a_match_is_not_retried(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        probe = WorkerProbe()
        auto_workers.register_worker(probe.make(), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="probe", max_attempts=3)
        assert len(probe.calls) == 1
        assert run["attempts"] == 1

    def test_concurrency_is_bounded(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(
            conn,
            rows=tuple((0x1000 + index * 0x10, f"Work{index}", 8, "STUB") for index in range(6)),
        )
        probe = WorkerProbe(sleep=0.05)
        auto_workers.register_worker(probe.make(), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="probe", concurrency=2)
        assert run["matched"] == 6
        assert probe.peak_live <= 2

    def test_a_wedged_worker_times_out_without_hanging(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        probe = WorkerProbe(sleep=5.0)
        auto_workers.register_worker(probe.make(), origin="test")
        monkeypatch.setattr(auto_mode, "_wait_for", lambda _event, _timeout: False)
        started = time.monotonic()
        run = auto_mode.run_auto(
            conn, binary_id=ids["binary"], worker="probe", max_attempts=1, task_timeout=1.0
        )
        elapsed = time.monotonic() - started
        assert elapsed < 1
        assert run["failed"] == 1
        batch = run["tree"][0]["children"][0]
        assert batch["attempt_log"][0]["detail"]["reason"] == auto_mode.REASON_TIMEOUT

    def test_abandoned_attempts_are_bounded(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_rows(
            conn,
            rows=((0x1000, "First", 8, "STUB"), (0x1100, "Second", 8, "STUB")),
        )
        probe = WorkerProbe(sleep=5.0)
        auto_workers.register_worker(probe.make(), origin="test")
        monkeypatch.setattr(auto_mode, "_attempt_slots", threading.BoundedSemaphore(1))
        monkeypatch.setattr(auto_mode, "_wait_for", lambda _event, _timeout: False)
        run = auto_mode.run_auto(
            conn,
            binary_id=ids["binary"],
            worker="probe",
            max_attempts=1,
            task_timeout=1.0,
            concurrency=1,
        )
        reasons = [
            attempt["detail"]["reason"]
            for batch in run["tree"][0]["children"]
            for attempt in batch["attempt_log"]
        ]
        assert auto_mode.REASON_TIMEOUT in reasons
        assert auto_mode.REASON_BUSY in reasons

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            auto_mode.run_auto(conn, binary_id=999)

    def test_run_row_is_persisted_and_resumable(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="offline")
        stored = auto_store.latest_auto_run(conn, ids["binary"])
        assert stored is not None
        assert stored["id"] == run["run_id"]
        assert stored["stats"]["matched"] == run["matched"]
        assert len(stored["tasks"]) == run["tasks"]

    def test_execute_promotes_status_and_records_the_change(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        auto_workers.register_worker(writer_worker(tmp_path / "Work.c"), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="writer", execute=True)
        assert run["matched"] == 1
        row = store.get_function(conn, ids["functions"][0])
        assert row is not None
        assert row["status"] == "EXACT"
        batch = run["tree"][0]["children"][0]
        assert batch["result"]["written_files"] == [str(tmp_path / "Work.c")]
        assert batch["result"]["status_changes"][0]["before"] == "STUB"

    def test_revert_removes_files_restores_status_and_deletes_rows(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        written = tmp_path / "Work.c"
        auto_workers.register_worker(writer_worker(written), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="writer", execute=True)
        assert written.is_file()
        result = auto_mode.revert_auto_run(conn, run["run_id"])
        assert result["removed"] == [{"path": str(written), "status": "removed"}]
        assert result["restored"] == [{"function_id": ids["functions"][0], "status": "STUB"}]
        assert not written.exists()
        row = store.get_function(conn, ids["functions"][0])
        assert row is not None
        assert row["status"] == "STUB"
        assert auto_store.get_auto_run(conn, run["run_id"]) is None

    def test_revert_reports_missing_files(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        written = tmp_path / "Work.c"
        auto_workers.register_worker(writer_worker(written), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="writer", execute=True)
        written.unlink()
        result = auto_mode.revert_auto_run(conn, run["run_id"])
        assert result["removed"] == [{"path": str(written), "status": "missing"}]

    def test_revert_unknown_run_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            auto_mode.revert_auto_run(conn, 999)

    def test_execute_run_persists_its_undo_plan(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        written = tmp_path / "Work.c"
        auto_workers.register_worker(writer_worker(written), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="writer", execute=True)
        stored = auto_store.get_auto_run(conn, run["run_id"])
        assert stored is not None
        # The file descriptor carries the digest of what the run wrote, which is
        # what lets the inverse refuse a path another writer has replaced.
        assert stored["effects"] == [
            effects.file_write_descriptor(written),
            {
                "kind": effects.EFFECT_STATUS_CHANGE,
                "function_id": ids["functions"][0],
                "before": "STUB",
            },
        ]
        assert stored["effects"][0]["sha256"] == effects.file_digest(written)

    def test_dry_run_persists_no_undo_plan(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="offline")
        stored = auto_store.get_auto_run(conn, run["run_id"])
        assert stored is not None
        assert stored["effects"] == []

    def test_revert_replays_the_plan_with_the_shared_dispatcher(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        written = tmp_path / "Work.c"
        auto_workers.register_worker(writer_worker(written), origin="test")
        run = auto_mode.run_auto(conn, binary_id=ids["binary"], worker="writer", execute=True)
        result = auto_mode.revert_auto_run(conn, run["run_id"])
        assert result["removed"] == [{"path": str(written), "status": "removed"}]
        assert result["restored"] == [{"function_id": ids["functions"][0], "status": "STUB"}]

    def test_run_summary_unknown_run_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            auto_mode.run_summary(conn, 999)

    def test_execute_runner_requires_a_file_backed_database(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_rows(conn, rows=SIZED_ROWS)
        params = auto_mode.build_params()
        functions = auto_mode.select_functions(conn, ids["binary"])
        run_id = auto_mode.create_auto_run(
            conn, binary_id=ids["binary"], params=params, functions=functions
        )
        monkeypatch.setattr(auto_mode, "_database_path", lambda _conn: None)
        with pytest.raises(ValueError, match="file-backed"):
            auto_mode.execute_auto_run(conn, run_id=run_id, params=params)

    def test_execute_runner_raises_for_an_unknown_run(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            auto_mode.execute_auto_run(conn, run_id=999, params=auto_mode.build_params())

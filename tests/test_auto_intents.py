"""Tests for auto-mode write intents: reserve before a write, recover after a kill.

An executing run persists an intent describing the inverse of each write before
the write happens and confirms it applied once the write returned.  These tests
drive the real orchestrator entry points (``_run_function``, ``_run_batch``,
``execute_auto_run``, ``recover_auto_run``, ``revert_auto_run``) and cover a
pending intent, an applied one, a legacy run with no intents, and a real
``SIGKILL`` of a worker mid-write.
"""

from __future__ import annotations

import multiprocessing
import signal
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from auto_helpers import make_context, seed_rows, write_rebrew_project

from reportal import auto_mode, auto_store, auto_workers, effects, store
from reportal.auto_workers import (
    WORKER_FAILED,
    WORKER_MATCHED,
    Worker,
    WorkerContext,
    WorkerResult,
)

ROWS: tuple[tuple[int, str, int, str], ...] = ((0x1000, "Work", 8, "STUB"),)


def _planned_writer(
    path: Path,
    *,
    status: str = WORKER_MATCHED,
    written_files: list[str] | None = None,
) -> Worker:
    """A worker that declares *path*, writes it, and reports a verified match.

    ``written_files=None`` means the worker reports the write it made;
    ``written_files=[]`` means it wrote the file but recorded nothing, which is
    the shape a worker killed between its write and its result leaves.
    """

    def planned(ctx: WorkerContext) -> tuple[str, ...]:
        return (str(path),)

    def run(ctx: WorkerContext) -> WorkerResult:
        function_id = int(ctx.function["id"])
        before = str(ctx.function["status"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int Work(void) { return 0; }\n", encoding="utf-8")
        recorded = [str(path)] if written_files is None else written_files
        if status != WORKER_MATCHED:
            return WorkerResult(
                status=WORKER_FAILED,
                function_id=function_id,
                status_before=before,
                detail={"reason": "wrote-without-record"},
            )
        return WorkerResult(
            status=WORKER_MATCHED,
            function_id=function_id,
            status_before=before,
            status_after="EXACT",
            verified=True,
            detail={"path": str(path)},
            written_files=recorded,
            status_changes=[{"function_id": function_id, "before": before, "after": "EXACT"}],
        )

    return Worker(
        name="planned-writer",
        description="Writes a declared path.",
        run=run,
        planned_paths=planned,
    )


def _register(worker: Worker, name: str) -> None:
    """Register a test worker under *name*."""
    auto_workers.register_worker(
        Worker(
            name=name,
            description=worker.description,
            run=worker.run,
            planned_paths=worker.planned_paths,
        ),
        origin="test",
    )


def _plan_one_batch(
    conn: sqlite3.Connection, ids: dict[str, Any], *, worker: str, execute: bool = True
) -> tuple[int, int, auto_mode.AutoParams]:
    """Create a run with one batch task for the seeded function."""
    params = auto_mode.build_params(worker=worker, execute=execute, max_attempts=1)
    functions = auto_mode.select_functions(conn, ids["binary"])
    run_id, _created = auto_mode.create_auto_run(
        conn, binary_id=ids["binary"], params=params, functions=functions
    )
    task_id, _planned = auto_mode.planned_batches(conn, run_id)[0]
    return run_id, task_id, params


def _legacy_stale_run(
    conn: sqlite3.Connection, binary_id: int, result: dict[str, Any]
) -> tuple[int, int]:
    """A `running` run whose batch recorded a result but carries no intents."""
    run_id, _created = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
    root_id = auto_store.create_auto_task(
        conn,
        run_id=run_id,
        parent_id=None,
        depth=auto_store.AUTO_ROOT_DEPTH,
        kind=auto_store.AUTO_TASK_ROOT,
        title="binary",
    )
    task_id = auto_store.create_auto_task(
        conn,
        run_id=run_id,
        parent_id=root_id,
        depth=auto_store.AUTO_BATCH_DEPTH,
        kind=auto_store.AUTO_TASK_BATCH,
        title="batch",
    )
    auto_store.update_auto_task(conn, task_id, status=auto_store.AUTO_TASK_RUNNING, result=result)
    return run_id, task_id


def _child_execute(db_path: str, run_id: int, params: auto_mode.AutoParams) -> None:
    """Run one planned auto run in a child process, for the kill test."""
    conn = store.connect(Path(db_path))
    try:
        auto_mode.execute_auto_run(conn, run_id=run_id, params=params, engine=None, llm_client=None)
    finally:
        conn.close()


class TestReserveBeforeWrite:
    def test_a_pending_intent_is_persisted_before_the_worker_runs(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        path = tmp_path / "Work.c"
        _register(_planned_writer(path, status=WORKER_FAILED), "reserve-probe")
        run_id, task_id, params = _plan_one_batch(conn, ids, worker="reserve-probe")
        function = store.get_function(conn, ids["functions"][0])
        assert function is not None
        db_path = auto_mode._database_path(conn)
        assert db_path is not None

        observed: list[int] = []
        real_call = auto_mode._call_with_timeout

        def spy(
            worker: auto_workers.Worker,
            ctx: WorkerContext,
            timeout: float,
            database: Path,
            budget: auto_mode.RunBudget,
        ) -> WorkerResult:
            observed.append(len(auto_store.auto_task_intents(conn, task_id)))
            return real_call(worker, ctx, timeout, database, budget)

        monkeypatch.setattr(auto_mode, "_call_with_timeout", spy)
        worker = auto_workers.get_worker("reserve-probe")
        assert worker is not None
        auto_mode._run_function(
            conn,
            task_id=task_id,
            function=function,
            project_dir=str(tmp_path),
            params=params,
            worker=worker,
            engine=None,
            llm_client=None,
            db_path=db_path,
            budget=auto_mode.RunBudget(params),
        )
        # The intent existed before the worker ran, and the worker still wrote
        # the file without recording it: the reservation is all recovery has.
        assert observed == [1]
        assert path.is_file()
        intents = auto_store.auto_task_intents(conn, task_id)
        assert [entry["status"] for entry in intents] == [auto_store.INTENT_PENDING]

        result = auto_mode.recover_auto_run(conn, run_id)
        assert result["uncertain_intents"] == [
            {
                "kind": effects.EFFECT_FILE_WRITE,
                "path": str(path),
                "intent": auto_store.INTENT_PENDING,
            }
        ]
        assert result["added_descriptors"] == 1
        run = auto_store.get_auto_run(conn, run_id)
        assert run is not None
        assert run["effects"] == [
            {
                "kind": effects.EFFECT_FILE_WRITE,
                "path": str(path),
                "intent": auto_store.INTENT_PENDING,
            }
        ]

    def test_an_already_owned_path_is_reserved_and_an_unowned_one_is_not(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "existing.c"
        path.write_text("int existing(void) { return 0; }\n", encoding="utf-8")
        assert auto_mode._reservable_file(str(path), set()) is False
        assert auto_mode._reservable_file(str(path), {str(path)}) is True
        missing = tmp_path / "missing.c"
        assert auto_mode._reservable_file(str(missing), set()) is True


class TestAppliedIntent:
    def test_an_applied_intent_reverts_the_file_and_the_status(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        path = tmp_path / "Work.c"
        _register(_planned_writer(path), "applied-writer")
        run_id, task_id, params = _plan_one_batch(conn, ids, worker="applied-writer")
        binary = store.get_binary(conn, ids["binary"])
        assert binary is not None
        db_path = auto_mode._database_path(conn)
        assert db_path is not None

        captured: dict[str, list[dict[str, Any]]] = {}
        real_record = auto_mode._record_task_outcome

        def spy(
            connection: sqlite3.Connection,
            *,
            run_id: int,
            task_id: int,
            status: str,
            result: dict[str, Any],
            descriptors: Any,
            attempts: int | None = None,
        ) -> int:
            captured["intents"] = auto_store.auto_task_intents(connection, task_id)
            return real_record(
                connection,
                run_id=run_id,
                task_id=task_id,
                status=status,
                result=result,
                descriptors=descriptors,
                attempts=attempts,
            )

        monkeypatch.setattr(auto_mode, "_record_task_outcome", spy)
        auto_mode._run_batch(
            conn,
            run_id=run_id,
            task_id=task_id,
            planned=[{"id": ids["functions"][0]}],
            binary=binary,
            params=params,
            engine=None,
            llm_client=None,
            db_path=db_path,
            budget=auto_mode.RunBudget(params),
        )
        assert captured["intents"]
        assert all(entry["status"] == auto_store.INTENT_APPLIED for entry in captured["intents"])
        assert path.is_file()
        row = store.get_function(conn, ids["functions"][0])
        assert row is not None
        assert row["status"] == "EXACT"

        reverted = auto_mode.revert_auto_run(conn, run_id)
        assert reverted["removed"] == [{"path": str(path), "status": "removed"}]
        assert reverted["restored"] == [{"function_id": ids["functions"][0], "status": "STUB"}]
        assert not path.exists()
        row = store.get_function(conn, ids["functions"][0])
        assert row is not None
        assert row["status"] == "STUB"


class TestLegacyRuns:
    def test_a_run_without_intents_still_recovers(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        written = tmp_path / "Work.c"
        written.write_text("int Work(void) { return 0; }\n", encoding="utf-8")
        run_id, _task = _legacy_stale_run(
            conn,
            ids["binary"],
            {
                "written_files": [str(written)],
                "status_changes": [{"function_id": ids["functions"][0], "before": "STUB"}],
            },
        )
        result = auto_mode.recover_auto_run(conn, run_id)
        assert result["uncertain_intents"] == []
        assert result["recovered_tasks"] == 1
        assert result["added_descriptors"] == 2
        # No `pending_intents` key is written back into a recovered task result.
        task = auto_store.list_auto_tasks(conn, run_id)[1]
        assert auto_store.task_intents(task) == []


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs fork and SIGKILL")
class TestHardKill:
    def test_a_sigkill_mid_write_is_recovered_as_uncertain(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        path = tmp_path / "killed.c"

        def run(ctx: WorkerContext) -> WorkerResult:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("int Work(void) { return 0; }\n", encoding="utf-8")
            # Hold the batch open so the parent kills a live worker.
            time.sleep(60)
            return WorkerResult(
                status=WORKER_MATCHED,
                function_id=int(ctx.function["id"]),
                status_before=str(ctx.function["status"]),
                status_after="EXACT",
                verified=True,
                written_files=[str(path)],
            )

        auto_workers.register_worker(
            Worker(
                name="kill-probe",
                description="Writes a file then holds the batch open.",
                run=run,
                planned_paths=lambda ctx: (str(path),),
            ),
            origin="test",
        )
        run_id, _task_id, params = _plan_one_batch(conn, ids, worker="kill-probe")

        context = multiprocessing.get_context("fork")
        child = context.Process(
            target=_child_execute, args=(str(portal_db), run_id, params), daemon=False
        )
        child.start()
        try:
            deadline = time.monotonic() + 30
            while not path.is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert path.is_file(), "the child never wrote the candidate file"
            child.kill()
            child.join(timeout=10)
            assert child.exitcode == -signal.SIGKILL
        finally:
            if child.is_alive():
                child.kill()
                child.join(timeout=10)

        result = auto_mode.recover_auto_run(conn, run_id)
        assert result["recovered_tasks"] == 1
        assert result["uncertain_intents"] == [
            {
                "kind": effects.EFFECT_FILE_WRITE,
                "path": str(path),
                "intent": auto_store.INTENT_PENDING,
            }
        ]
        assert path.is_file()
        reverted = auto_mode.revert_auto_run(conn, run_id)
        assert reverted["removed"] == [{"path": str(path), "status": "removed"}]
        assert not path.exists()


class TestBuiltinPlannedPaths:
    def test_the_llm_worker_predicts_its_candidate_path(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        write_rebrew_project(tmp_path)
        worker = auto_workers.get_worker(auto_workers.WORKER_LLM_C_SOURCE)
        assert worker is not None
        assert worker.planned_paths is not None
        function = {
            "id": 1,
            "va": 0x1000,
            "name": "FreePrintSetup",
            "size": 47,
            "status": "STUB",
        }
        ctx = make_context(conn, function, project_dir=str(tmp_path), execute=True)
        assert worker.planned_paths(ctx) == (str(tmp_path / "src" / "NP" / "FreePrintSetup.c"),)
        dry = make_context(conn, function, project_dir=str(tmp_path), execute=False)
        assert worker.planned_paths(dry) == ()

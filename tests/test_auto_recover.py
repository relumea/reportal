"""Tests for incremental undo-plan persistence and recovery of a stale auto run."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from auto_helpers import seed_rows, writer_worker
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import auto_mode, auto_store, auto_workers, cli, effects, mcp_tools, store
from reportal._paths import DB_ENV
from reportal.auto_workers import WORKER_MATCHED, Worker, WorkerContext, WorkerResult

runner = CliRunner()

# The rows the recovery tests seed: one outstanding function.
ROWS: tuple[tuple[int, str, int, str], ...] = ((0x1000, "Work", 8, "STUB"),)


def _stale_run(
    conn: sqlite3.Connection,
    binary_id: int,
    batches: list[tuple[str | None, dict[str, Any]]],
) -> tuple[int, int, list[int]]:
    """Create a `running` run whose batch tasks carry the given status and result.

    A None status leaves the batch `pending` with no result, which is how a task
    the coordinator planned but a dead process never started looks.
    """
    run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
    root_id = auto_store.create_auto_task(
        conn,
        run_id=run_id,
        parent_id=None,
        depth=auto_store.AUTO_ROOT_DEPTH,
        kind=auto_store.AUTO_TASK_ROOT,
        title="binary",
    )
    batch_ids: list[int] = []
    for index, (status, result) in enumerate(batches):
        task_id = auto_store.create_auto_task(
            conn,
            run_id=run_id,
            parent_id=root_id,
            depth=auto_store.AUTO_BATCH_DEPTH,
            kind=auto_store.AUTO_TASK_BATCH,
            title=f"batch {index}",
        )
        if status is not None:
            auto_store.update_auto_task(conn, task_id, status=status, result=result)
        batch_ids.append(task_id)
    return run_id, root_id, batch_ids


def _run_one_batch(conn: sqlite3.Connection, ids: dict[str, Any], written: Path) -> tuple[int, int]:
    """Execute one real writer batch and return ``(run_id, task_id)``.

    The run stays `running`: this drives the batch itself, so the test can see
    the plan a completed task persisted before anything closes the run.
    """
    auto_workers.register_worker(writer_worker(written), origin="test")
    params = auto_mode.build_params(worker="writer", execute=True)
    functions = auto_mode.select_functions(conn, ids["binary"])
    run_id = auto_mode.create_auto_run(
        conn, binary_id=ids["binary"], params=params, functions=functions
    )
    task_id, planned = auto_mode.planned_batches(conn, run_id)[0]
    binary = store.get_binary(conn, ids["binary"])
    assert binary is not None
    db_path = auto_mode._database_path(conn)
    assert db_path is not None
    auto_mode._run_batch(
        conn,
        run_id=run_id,
        task_id=task_id,
        planned=planned,
        binary=binary,
        params=params,
        engine=None,
        llm_client=None,
        db_path=db_path,
    )
    return run_id, task_id


class TestIncrementalPersistence:
    def test_a_completed_batch_persists_its_plan_before_the_run_closes(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        written = tmp_path / "Work.c"
        run_id, _task_id = _run_one_batch(conn, ids, written)
        run = auto_store.get_auto_run(conn, run_id)
        assert run is not None
        assert run["status"] == auto_store.AUTO_RUN_RUNNING
        assert run["effects"] == [
            effects.file_write_descriptor(written),
            {
                "kind": effects.EFFECT_STATUS_CHANGE,
                "function_id": ids["functions"][0],
                "before": "STUB",
            },
        ]

    def test_the_close_time_consolidation_adds_no_duplicate_descriptors(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run_id, _task_id = _run_one_batch(conn, ids, tmp_path / "Work.c")
        before = auto_store.auto_run_effects(conn, run_id)
        auto_mode.persist_undo_plan(conn, run_id)
        auto_mode.persist_undo_plan(conn, run_id)
        assert auto_store.auto_run_effects(conn, run_id) == before
        assert len(before) == 2

    def test_the_persisted_plan_is_a_json_descriptor_list(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run_id, _task_id = _run_one_batch(conn, ids, tmp_path / "Work.c")
        row = conn.execute("SELECT effects_json FROM auto_runs WHERE id = ?", (run_id,)).fetchone()
        plan = json.loads(str(row["effects_json"]))
        assert isinstance(plan, list)
        assert all(isinstance(entry, dict) and entry.get("kind") for entry in plan)

    def test_a_dry_batch_persists_no_descriptors(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        written = tmp_path / "Work.c"
        auto_workers.register_worker(writer_worker(written), origin="test")
        params = auto_mode.build_params(worker="writer", execute=False)
        functions = auto_mode.select_functions(conn, ids["binary"])
        run_id = auto_mode.create_auto_run(
            conn, binary_id=ids["binary"], params=params, functions=functions
        )
        task_id, planned = auto_mode.planned_batches(conn, run_id)[0]
        binary = store.get_binary(conn, ids["binary"])
        assert binary is not None
        db_path = auto_mode._database_path(conn)
        assert db_path is not None
        auto_mode._run_batch(
            conn,
            run_id=run_id,
            task_id=task_id,
            planned=planned,
            binary=binary,
            params=params,
            engine=None,
            llm_client=None,
            db_path=db_path,
        )
        assert auto_store.auto_run_effects(conn, run_id) == []
        assert not written.exists()

    def test_concurrent_batches_do_not_lose_each_others_descriptors(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        count = 6
        ids = seed_rows(
            conn,
            rows=tuple(
                (0x1000 + index * 0x10, f"Work{index}", 8, "STUB") for index in range(count)
            ),
        )
        out_dir = tmp_path / "out"

        def worker_run(ctx: WorkerContext) -> WorkerResult:
            function = ctx.function
            function_id = int(function["id"])
            before = str(function["status"])
            path = out_dir / f"{function['name']}.c"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"int {function['name']}(void) {{ return 0; }}\n", encoding="utf-8")
            return WorkerResult(
                status=WORKER_MATCHED,
                function_id=function_id,
                status_before=before,
                status_after="EXACT",
                verified=True,
                written_files=[str(path)],
                status_changes=[{"function_id": function_id, "before": before, "after": "EXACT"}],
            )

        auto_workers.register_worker(
            Worker(name="distinct-writer", description="One file per function.", run=worker_run),
            origin="test",
        )
        run = auto_mode.run_auto(
            conn,
            binary_id=ids["binary"],
            worker="distinct-writer",
            execute=True,
            concurrency=3,
            functions_per_task=1,
        )
        plan = auto_store.auto_run_effects(conn, run["run_id"])
        written = {entry["path"] for entry in plan if entry["kind"] == effects.EFFECT_FILE_WRITE}
        changed = {
            entry["function_id"] for entry in plan if entry["kind"] == effects.EFFECT_STATUS_CHANGE
        }
        assert written == {str(out_dir / f"Work{index}.c") for index in range(count)}
        assert changed == set(ids["functions"])
        assert len(plan) == 2 * count


class TestRecoverAutoRun:
    def test_a_running_tasks_writes_merge_into_the_plan_and_it_is_failed(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        written = tmp_path / "Work.c"
        run_id, _root, batch_ids = _stale_run(
            conn,
            ids["binary"],
            [
                (
                    auto_store.AUTO_TASK_RUNNING,
                    {
                        "written_files": [str(written)],
                        "status_changes": [
                            {"function_id": ids["functions"][0], "before": "STUB", "after": "EXACT"}
                        ],
                    },
                )
            ],
        )
        result = auto_mode.recover_auto_run(conn, run_id)
        assert result == {
            "run_id": run_id,
            "recovered_tasks": 1,
            "added_descriptors": 2,
            "uncertain_intents": [],
            "status": auto_store.AUTO_RUN_FAILED,
        }
        run = auto_store.get_auto_run(conn, run_id)
        assert run is not None
        assert run["status"] == auto_store.AUTO_RUN_FAILED
        assert run["effects"] == [
            effects.file_write_descriptor(written),
            {
                "kind": effects.EFFECT_STATUS_CHANGE,
                "function_id": ids["functions"][0],
                "before": "STUB",
            },
        ]
        task = next(task for task in run["tasks"] if task["id"] == batch_ids[0])
        assert task["status"] == auto_store.AUTO_TASK_FAILED
        assert task["result"]["reason"] == auto_mode.REASON_INTERRUPTED

    def test_recovery_is_idempotent(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run_id, _root, _batch = _stale_run(
            conn,
            ids["binary"],
            [
                (
                    auto_store.AUTO_TASK_RUNNING,
                    {"written_files": [str(tmp_path / "Work.c")], "status_changes": []},
                )
            ],
        )
        first = auto_mode.recover_auto_run(conn, run_id)
        second = auto_mode.recover_auto_run(conn, run_id)
        assert first["status"] == auto_store.AUTO_RUN_FAILED
        assert second == {
            "run_id": run_id,
            "recovered_tasks": 0,
            "added_descriptors": 0,
            "uncertain_intents": [],
            "status": auto_store.AUTO_RUN_FAILED,
        }
        assert len(auto_store.auto_run_effects(conn, run_id)) == 1

    def test_an_already_closed_run_is_left_untouched(self, conn: sqlite3.Connection) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run_id, _root, batch_ids = _stale_run(
            conn, ids["binary"], [(auto_store.AUTO_TASK_DONE, {})]
        )
        auto_store.set_auto_run_effects(
            conn, run_id, [{"kind": effects.EFFECT_FILE_WRITE, "path": "/kept.c"}]
        )
        auto_store.finish_auto_run(
            conn, run_id, status=auto_store.AUTO_RUN_DONE, stats={"matched": 1}
        )
        before = auto_store.get_auto_run(conn, run_id)
        result = auto_mode.recover_auto_run(conn, run_id)
        after = auto_store.get_auto_run(conn, run_id)
        assert result == {
            "run_id": run_id,
            "recovered_tasks": 0,
            "added_descriptors": 0,
            "uncertain_intents": [],
            "status": auto_store.AUTO_RUN_DONE,
        }
        assert before is not None and after is not None
        assert after["status"] == before["status"]
        assert after["finished_at"] == before["finished_at"]
        assert after["effects"] == before["effects"]
        task = next(task for task in after["tasks"] if task["id"] == batch_ids[0])
        assert task["status"] == auto_store.AUTO_TASK_DONE

    def test_a_task_with_no_recorded_files_is_failed_without_descriptors(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run_id, _root, _batch = _stale_run(
            conn,
            ids["binary"],
            [(auto_store.AUTO_TASK_RUNNING, {"written_files": [], "status_changes": []})],
        )
        result = auto_mode.recover_auto_run(conn, run_id)
        assert result["recovered_tasks"] == 1
        assert result["added_descriptors"] == 0
        assert auto_store.auto_run_effects(conn, run_id) == []
        task = auto_store.list_auto_tasks(conn, run_id)[1]
        assert task["status"] == auto_store.AUTO_TASK_FAILED
        assert task["result"]["reason"] == auto_mode.REASON_INTERRUPTED

    def test_a_planned_task_never_started_is_still_recovered(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run_id, _root, batch_ids = _stale_run(conn, ids["binary"], [(None, {})])
        result = auto_mode.recover_auto_run(conn, run_id)
        assert result["recovered_tasks"] == 1
        assert result["added_descriptors"] == 0
        task = next(
            task for task in auto_store.list_auto_tasks(conn, run_id) if task["id"] == batch_ids[0]
        )
        assert task["status"] == auto_store.AUTO_TASK_FAILED

    def test_pending_and_running_tasks_are_recovered_together(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        first = tmp_path / "one.c"
        second = tmp_path / "two.c"
        run_id, _root, _batches = _stale_run(
            conn,
            ids["binary"],
            [
                (auto_store.AUTO_TASK_RUNNING, {"written_files": [str(first)]}),
                (auto_store.AUTO_TASK_PENDING, {"functions": [{"id": 1}]}),
                (auto_store.AUTO_TASK_RUNNING, {"written_files": [str(second)]}),
            ],
        )
        result = auto_mode.recover_auto_run(conn, run_id)
        assert result["recovered_tasks"] == 3
        assert result["added_descriptors"] == 2
        assert auto_store.auto_run_effects(conn, run_id) == [
            {"kind": effects.EFFECT_FILE_WRITE, "path": str(first)},
            {"kind": effects.EFFECT_FILE_WRITE, "path": str(second)},
        ]

    @pytest.mark.parametrize(
        ("statuses", "expected"),
        [
            ([auto_store.AUTO_TASK_RUNNING], auto_store.AUTO_RUN_FAILED),
            ([auto_store.AUTO_TASK_PENDING], auto_store.AUTO_RUN_FAILED),
            (
                [auto_store.AUTO_TASK_DONE, auto_store.AUTO_TASK_RUNNING],
                auto_store.AUTO_RUN_PARTIAL,
            ),
            (
                [auto_store.AUTO_TASK_DONE, auto_store.AUTO_TASK_PENDING],
                auto_store.AUTO_RUN_PARTIAL,
            ),
            (
                [auto_store.AUTO_TASK_DONE, auto_store.AUTO_TASK_FAILED],
                auto_store.AUTO_RUN_PARTIAL,
            ),
            (
                [auto_store.AUTO_TASK_DONE, auto_store.AUTO_TASK_DONE],
                auto_store.AUTO_RUN_DONE,
            ),
            (
                [auto_store.AUTO_TASK_FAILED, auto_store.AUTO_TASK_FAILED],
                auto_store.AUTO_RUN_FAILED,
            ),
        ],
    )
    def test_the_run_status_after_recovery(
        self, conn: sqlite3.Connection, statuses: list[str], expected: str
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run_id, _root, _batches = _stale_run(
            conn, ids["binary"], [(status, {}) for status in statuses]
        )
        result = auto_mode.recover_auto_run(conn, run_id)
        assert result["status"] == expected
        run = auto_store.get_auto_run(conn, run_id)
        assert run is not None
        assert run["status"] == expected

    def test_recovery_raises_for_an_unknown_run(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            auto_mode.recover_auto_run(conn, 999)

    def test_revert_after_recovery_removes_the_recovered_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        written = tmp_path / "Work.c"
        written.write_text("int Work(void) { return 0; }\n", encoding="utf-8")
        auto_store.set_function_status(conn, ids["functions"][0], "EXACT")
        run_id, _root, _batch = _stale_run(
            conn,
            ids["binary"],
            [
                (
                    auto_store.AUTO_TASK_RUNNING,
                    {
                        "written_files": [str(written)],
                        "status_changes": [{"function_id": ids["functions"][0], "before": "STUB"}],
                    },
                )
            ],
        )
        auto_mode.recover_auto_run(conn, run_id)
        assert written.is_file()
        result = auto_mode.revert_auto_run(conn, run_id)
        assert result["removed"] == [{"path": str(written), "status": "removed"}]
        assert result["restored"] == [{"function_id": ids["functions"][0], "status": "STUB"}]
        assert not written.exists()
        row = store.get_function(conn, ids["functions"][0])
        assert row is not None
        assert row["status"] == "STUB"
        assert auto_store.get_auto_run(conn, run_id) is None


class TestRecoverRoute:
    def test_the_route_recovers_a_stale_run(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        written = tmp_path / "Work.c"
        run_id, _root, _batch = _stale_run(
            conn,
            ids["binary"],
            [
                (
                    auto_store.AUTO_TASK_RUNNING,
                    {
                        "written_files": [str(written)],
                        "status_changes": [{"function_id": ids["functions"][0], "before": "STUB"}],
                    },
                )
            ],
        )
        status, headers, payload = wsgi_request("POST", f"/api/auto/runs/{run_id}/recover")
        body = json_body(payload, headers)
        assert int(status.split()[0]) == 200
        assert body["run_id"] == run_id
        assert body["recovered_tasks"] == 1
        assert body["added_descriptors"] == 2
        assert body["status"] == auto_store.AUTO_RUN_FAILED

    def test_the_route_is_404_for_an_unknown_run(self, conn: sqlite3.Connection) -> None:
        status, headers, payload = wsgi_request("POST", "/api/auto/runs/999/recover")
        assert int(status.split()[0]) == 404
        assert json_body(payload, headers)["error"] == "run not found"


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Create a portal DB with one binary and one outstanding function."""
    db = tmp_path / "reportal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        return seed_rows(conn, rows=ROWS)


class TestAutoRecoverCommand:
    def test_json_reports_the_recovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        written = tmp_path / "Work.c"
        with contextlib.closing(store.connect(tmp_path / "reportal.db")) as conn:
            run_id, _root, _batch = _stale_run(
                conn,
                ids["binary"],
                [
                    (
                        auto_store.AUTO_TASK_RUNNING,
                        {
                            "written_files": [str(written)],
                            "status_changes": [
                                {"function_id": ids["functions"][0], "before": "STUB"}
                            ],
                        },
                    )
                ],
            )
        result = runner.invoke(cli.app, ["auto-recover", str(run_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["status"] == auto_store.AUTO_RUN_FAILED
        assert payload["recovered_tasks"] == 1
        assert payload["added_descriptors"] == 2

    def test_an_unknown_run_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["auto-recover", "4242", "--json"])
        assert result.exit_code == 1
        assert "no auto run with id 4242" in result.output

    def test_the_recover_flag_closes_the_stale_run_before_starting(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        written = tmp_path / "Work.c"
        with contextlib.closing(store.connect(tmp_path / "reportal.db")) as conn:
            stale_id, _root, _batch = _stale_run(
                conn,
                ids["binary"],
                [(auto_store.AUTO_TASK_RUNNING, {"written_files": [str(written)]})],
            )
        result = runner.invoke(cli.app, ["auto", str(ids["binary"]), "--recover", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["recovered"]["run_id"] == stale_id
        assert payload["recovered"]["status"] == auto_store.AUTO_RUN_FAILED
        with contextlib.closing(store.connect(tmp_path / "reportal.db")) as conn:
            stale = auto_store.get_auto_run(conn, stale_id)
            assert stale is not None
            assert stale["status"] == auto_store.AUTO_RUN_FAILED
            assert auto_store.auto_run_effects(conn, stale_id) == [
                {"kind": effects.EFFECT_FILE_WRITE, "path": str(written)}
            ]


class TestRecoverTool:
    def test_the_tool_is_destructive(self) -> None:
        tool = mcp_tools.get_tool("recover_auto_run")
        assert tool is not None
        assert tool.annotations.read_only_hint is False
        assert tool.annotations.destructive_hint is True

    def test_the_tool_recovers_a_stale_run(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run_id, _root, _batch = _stale_run(
            conn,
            ids["binary"],
            [
                (
                    auto_store.AUTO_TASK_RUNNING,
                    {
                        "written_files": [str(tmp_path / "Work.c")],
                        "status_changes": [],
                    },
                )
            ],
        )
        tool = mcp_tools.get_tool("recover_auto_run")
        assert tool is not None
        result = tool.handler({"run_id": run_id})
        assert result["status"] == auto_store.AUTO_RUN_FAILED
        assert result["recovered_tasks"] == 1
        assert result["added_descriptors"] == 1

    def test_the_tool_raises_for_an_unknown_run(self, conn: sqlite3.Connection) -> None:
        tool = mcp_tools.get_tool("recover_auto_run")
        assert tool is not None
        with pytest.raises(mcp_tools.ToolError):
            tool.handler({"run_id": 999})

"""Tests for the auto-mode store: runs, the task tree and attempts."""

from __future__ import annotations

import sqlite3

import pytest

from reportal import auto_store, store


@pytest.mark.parametrize("record_outcome", [False, True])
def test_timestamps_follow_the_shared_clock(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, record_outcome: bool
) -> None:
    stamp = "2001-02-03T04:05:06+00:00"
    monkeypatch.setattr(store, "now", lambda: stamp)
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
    run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
    task_id = auto_store.create_auto_task(
        conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
    )
    auto_store.add_auto_attempt(
        conn, task_id=task_id, worker="offline", status="matched", detail={}
    )
    run = auto_store.get_auto_run(conn, run_id)
    assert run is not None
    assert run["created_at"] == stamp
    assert run["finished_at"] is None
    task = run["tasks"][0]
    assert task["created_at"] == stamp
    assert task["finished_at"] is None
    assert task["attempt_log"][0]["created_at"] == stamp

    created = stamp
    stamp = "2001-02-03T04:05:09+00:00"
    if record_outcome:
        assert auto_store.record_auto_task_outcome(
            conn, task_id, run_id=run_id, status=auto_store.AUTO_TASK_DONE, result={}, effects=[]
        )
    else:
        assert auto_store.update_auto_task(
            conn, task_id, status=auto_store.AUTO_TASK_DONE, finish=True
        )
    assert auto_store.finish_auto_run(conn, run_id, status=auto_store.AUTO_RUN_DONE, stats={})
    run = auto_store.get_auto_run(conn, run_id)
    assert run is not None
    assert run["created_at"] == created
    assert run["finished_at"] == stamp
    task = run["tasks"][0]
    assert task["created_at"] == created
    assert task["finished_at"] == stamp
    assert task["attempt_log"][0]["created_at"] == created


def test_lifecycle_timestamps_follow_the_shared_clock(
    conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
    clock = ["2001-01-01T00:00:00+00:00"]
    monkeypatch.setattr(store, "now", lambda: clock[0])
    run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
    run = auto_store.get_auto_run(conn, run_id)
    assert run is not None
    assert run["created_at"] == clock[0]
    assert run["finished_at"] is None

    clock[0] = "2001-01-01T00:00:01+00:00"
    task_id = auto_store.create_auto_task(
        conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
    )
    task = auto_store.list_auto_tasks(conn, run_id)[0]
    assert task["created_at"] == clock[0]
    assert task["finished_at"] is None

    clock[0] = "2001-01-01T00:00:02+00:00"
    auto_store.add_auto_attempt(
        conn, task_id=task_id, worker="offline", status="matched", detail={}
    )
    assert auto_store.list_auto_attempts(conn, task_id)[0]["created_at"] == clock[0]

    clock[0] = "2001-01-01T00:00:03+00:00"
    assert auto_store.record_auto_task_outcome(
        conn, task_id, run_id=run_id, status=auto_store.AUTO_TASK_DONE, result={}, effects=[]
    )
    assert auto_store.list_auto_tasks(conn, run_id)[0]["finished_at"] == clock[0]

    clock[0] = "2001-01-01T00:00:04+00:00"
    assert auto_store.update_auto_task(conn, task_id, finish=True)
    assert auto_store.list_auto_tasks(conn, run_id)[0]["finished_at"] == clock[0]

    clock[0] = "2001-01-01T00:00:05+00:00"
    assert auto_store.finish_auto_run(conn, run_id, status=auto_store.AUTO_RUN_DONE, stats={})
    run = auto_store.get_auto_run(conn, run_id)
    assert run is not None
    assert run["created_at"] == "2001-01-01T00:00:00+00:00"
    assert run["finished_at"] == clock[0]


class TestAutoRuns:
    def test_create_and_read_a_run(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={"worker": "offline"})
        run = auto_store.get_auto_run(conn, run_id)
        assert run is not None
        assert run["status"] == auto_store.AUTO_RUN_RUNNING
        assert run["config"] == {"worker": "offline"}
        assert run["stats"] == {}
        assert run["finished_at"] is None
        assert run["tasks"] == []

    def test_finish_stamps_status_stats_and_time(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
        assert auto_store.finish_auto_run(
            conn, run_id, status=auto_store.AUTO_RUN_DONE, stats={"matched": 2}
        )
        run = auto_store.get_auto_run(conn, run_id)
        assert run is not None
        assert run["status"] == auto_store.AUTO_RUN_DONE
        assert run["stats"] == {"matched": 2}
        assert run["finished_at"]

    def test_finish_unknown_run_is_false(self, conn: sqlite3.Connection) -> None:
        assert not auto_store.finish_auto_run(conn, 999, status="done", stats={})

    def test_get_unknown_run_is_none(self, conn: sqlite3.Connection) -> None:
        assert auto_store.get_auto_run(conn, 999) is None

    def test_latest_auto_run_picks_the_newest(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        first = auto_store.create_auto_run(conn, binary_id=binary_id, config={"n": 1})
        second = auto_store.create_auto_run(conn, binary_id=binary_id, config={"n": 2})
        latest = auto_store.latest_auto_run(conn, binary_id)
        assert latest is not None
        assert latest["id"] == second
        assert latest["id"] != first

    def test_latest_auto_run_is_none_without_one(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        assert auto_store.latest_auto_run(conn, binary_id) is None

    def test_latest_auto_run_is_scoped_to_the_binary(self, conn: sqlite3.Connection) -> None:
        first = store.add_binary(conn, sha256="aa" * 32, name="one.exe")
        second = store.add_binary(conn, sha256="bb" * 32, name="two.exe")
        auto_store.create_auto_run(conn, binary_id=first, config={})
        other = auto_store.create_auto_run(conn, binary_id=second, config={})
        latest = auto_store.latest_auto_run(conn, second)
        assert latest is not None
        assert latest["id"] == other

    def test_list_auto_runs_is_newest_first(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        first = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
        second = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
        rows = auto_store.list_auto_runs(conn, binary_id=binary_id)
        assert [row["id"] for row in rows] == [second, first]
        assert "tasks" not in rows[0]

    def test_delete_auto_run_cascades(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
        task_id = auto_store.create_auto_task(
            conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
        )
        auto_store.add_auto_attempt(
            conn, task_id=task_id, attempt=1, worker="offline", status="matched", detail={}
        )
        assert auto_store.delete_auto_run(conn, run_id)
        assert auto_store.get_auto_run(conn, run_id) is None
        assert auto_store.list_auto_tasks(conn, run_id) == []
        assert conn.execute("SELECT COUNT(*) FROM auto_attempts").fetchone()[0] == 0

    def test_delete_unknown_run_is_false(self, conn: sqlite3.Connection) -> None:
        assert not auto_store.delete_auto_run(conn, 999)


class TestAutoTasks:
    def _run(self, conn: sqlite3.Connection) -> int:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        return auto_store.create_auto_run(conn, binary_id=binary_id, config={})

    def test_create_persists_kind_depth_and_parent(self, conn: sqlite3.Connection) -> None:
        run_id = self._run(conn)
        root = auto_store.create_auto_task(
            conn,
            run_id=run_id,
            parent_id=None,
            depth=0,
            kind=auto_store.AUTO_TASK_ROOT,
            title="binary 1",
        )
        batch = auto_store.create_auto_task(
            conn,
            run_id=run_id,
            parent_id=root,
            depth=1,
            kind=auto_store.AUTO_TASK_BATCH,
            title="f @ 0x1000",
            worker="offline",
            function_id=None,
            va=0x1000,
        )
        tasks = {task["id"]: task for task in auto_store.list_auto_tasks(conn, run_id)}
        assert tasks[root]["parent_id"] is None
        assert tasks[root]["depth"] == 0
        assert tasks[root]["kind"] == auto_store.AUTO_TASK_ROOT
        assert tasks[batch]["parent_id"] == root
        assert tasks[batch]["depth"] == 1
        assert tasks[batch]["va"] == 0x1000
        assert tasks[batch]["status"] == auto_store.AUTO_TASK_PENDING
        assert tasks[batch]["attempts"] == 0

    def test_update_sets_status_attempts_and_result(self, conn: sqlite3.Connection) -> None:
        run_id = self._run(conn)
        task_id = auto_store.create_auto_task(
            conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
        )
        assert auto_store.update_auto_task(
            conn,
            task_id,
            status=auto_store.AUTO_TASK_DONE,
            attempts=3,
            result={"matched": 1},
            finish=True,
        )
        task = auto_store.list_auto_tasks(conn, run_id)[0]
        assert task["status"] == auto_store.AUTO_TASK_DONE
        assert task["attempts"] == 3
        assert task["result"] == {"matched": 1}
        assert task["finished_at"]

    def test_update_without_fields_changes_nothing(self, conn: sqlite3.Connection) -> None:
        run_id = self._run(conn)
        task_id = auto_store.create_auto_task(
            conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
        )
        assert not auto_store.update_auto_task(conn, task_id)

    def test_update_unknown_task_is_false(self, conn: sqlite3.Connection) -> None:
        assert not auto_store.update_auto_task(conn, 999, status="done")

    def test_task_tree_nests_children_under_parents(self, conn: sqlite3.Connection) -> None:
        run_id = self._run(conn)
        root = auto_store.create_auto_task(
            conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
        )
        first = auto_store.create_auto_task(
            conn,
            run_id=run_id,
            parent_id=root,
            depth=1,
            kind=auto_store.AUTO_TASK_BATCH,
            title="a",
        )
        second = auto_store.create_auto_task(
            conn,
            run_id=run_id,
            parent_id=root,
            depth=1,
            kind=auto_store.AUTO_TASK_BATCH,
            title="b",
        )
        tree = auto_store.auto_task_tree(conn, run_id)
        assert len(tree) == 1
        assert tree[0]["id"] == root
        assert [child["id"] for child in tree[0]["children"]] == [first, second]
        assert tree[0]["children"][0]["children"] == []


class TestAutoAttempts:
    def _task(self, conn: sqlite3.Connection) -> int:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
        return auto_store.create_auto_task(
            conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
        )

    def test_attempts_are_ordered_and_parsed(self, conn: sqlite3.Connection) -> None:
        task_id = self._task(conn)
        auto_store.add_auto_attempt(
            conn,
            task_id=task_id,
            attempt=1,
            worker="offline",
            status="failed",
            detail={"reason": "no-symbol"},
        )
        auto_store.add_auto_attempt(
            conn,
            task_id=task_id,
            attempt=2,
            worker="offline",
            status="matched",
            detail={"reason": "", "verified": True},
        )
        attempts = auto_store.list_auto_attempts(conn, task_id)
        assert [entry["attempt"] for entry in attempts] == [1, 2]
        assert attempts[0]["detail"] == {"reason": "no-symbol"}
        assert attempts[1]["detail"]["verified"] is True

    def test_task_rows_carry_their_attempt_log(self, conn: sqlite3.Connection) -> None:
        task_id = self._task(conn)
        auto_store.add_auto_attempt(
            conn, task_id=task_id, attempt=1, worker="offline", status="matched", detail={}
        )
        task = auto_store.list_auto_tasks(conn, 1)[0]
        assert len(task["attempt_log"]) == 1

    def test_attempt_count_counts_the_runs_attempts(self, conn: sqlite3.Connection) -> None:
        task_id = self._task(conn)
        run_id = auto_store.list_auto_tasks(conn, 1)[0]["run_id"]
        for attempt in (1, 2):
            auto_store.add_auto_attempt(
                conn,
                task_id=task_id,
                attempt=attempt,
                worker="offline",
                status="failed",
                detail={},
            )
        assert auto_store.attempt_count(conn, run_id) == 2


class TestFunctionStatusWrites:
    def test_set_function_status_promotes_and_reports(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", status="STUB"
        )
        assert auto_store.set_function_status(conn, function_id, "EXACT")
        row = store.get_function(conn, function_id)
        assert row is not None
        assert row["status"] == "EXACT"

    def test_set_function_status_unknown_is_false(self, conn: sqlite3.Connection) -> None:
        assert not auto_store.set_function_status(conn, 999, "EXACT")


class TestTaskRecords:
    def test_written_files_and_status_changes_are_read_back(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
        task_id = auto_store.create_auto_task(
            conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
        )
        auto_store.update_auto_task(
            conn,
            task_id,
            result={
                "written_files": ["/tmp/a.c", ""],
                "status_changes": [{"function_id": 3, "before": "STUB", "after": "EXACT"}],
            },
        )
        task = auto_store.list_auto_tasks(conn, run_id)[0]
        assert list(auto_store.written_files_for_task(task)) == ["/tmp/a.c"]
        assert auto_store.status_changes_for_task(task) == [
            {"function_id": 3, "before": "STUB", "after": "EXACT"}
        ]

    def test_missing_record_keys_read_as_empty(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config={})
        task_id = auto_store.create_auto_task(
            conn, run_id=run_id, parent_id=None, depth=0, kind=auto_store.AUTO_TASK_ROOT
        )
        task = auto_store.list_auto_tasks(conn, run_id)[0]
        assert list(auto_store.written_files_for_task(task)) == []
        assert auto_store.status_changes_for_task(task) == []
        assert task_id  # the row exists; the readers just find nothing


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (auto_store.AUTO_RUN_RUNNING, "running"),
        (auto_store.AUTO_RUN_DONE, "done"),
        (auto_store.AUTO_RUN_FAILED, "failed"),
        (auto_store.AUTO_RUN_PARTIAL, "partial"),
        (auto_store.AUTO_RUN_REVERTED, "reverted"),
    ],
)
def test_run_status_constants(status: str, expected: str) -> None:
    assert status == expected

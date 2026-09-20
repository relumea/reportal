"""Tests for the auto-mode HTTP routes."""

from __future__ import annotations

import contextlib
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from auto_helpers import seed_rows, writer_worker
from conftest import json_body, wsgi_request

from reportal import api, auth, auto_store, auto_workers, mcp_tools, store

# How long a background auto run may take in a test before the test gives up.
RUN_WAIT_SECONDS = 15.0


def _wait_for_terminal(portal_db: Path, binary_id: int) -> dict[str, Any]:
    """Poll the stored run until it leaves `running`, or fail the test."""
    deadline = time.monotonic() + RUN_WAIT_SECONDS
    with contextlib.closing(store.connect(portal_db)) as conn:
        while time.monotonic() < deadline:
            run = auto_store.latest_auto_run(conn, binary_id)
            if run is not None and run["status"] != auto_store.AUTO_RUN_RUNNING:
                return run
            time.sleep(0.02)
    raise AssertionError("the auto run never reached a terminal status")


def _start(binary_id: int, body: dict[str, Any] | None = None) -> tuple[int, Any]:
    """POST an auto run; returns ``(status_code, parsed body)``."""
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    status, headers, payload = wsgi_request("POST", f"/api/binaries/{binary_id}/auto", body=raw)
    return int(status.split()[0]), json_body(payload, headers)


class TestMcpTools:
    def test_the_acceptance_tools_have_the_expected_annotations(self) -> None:
        read = mcp_tools.get_tool("get_auto_run")
        assert read is not None
        assert read.annotations.read_only_hint is True
        assert read.annotations.destructive_hint is False
        for name in ("run_auto", "revert_auto_run"):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.read_only_hint is False
            assert tool.annotations.destructive_hint is True

    def test_run_auto_tool_runs_the_orchestrator(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        tool = mcp_tools.get_tool("run_auto")
        assert tool is not None
        result = tool.handler({"binary_id": ids["binary"], "worker": "offline"})
        assert result["matched"] == 1
        assert result["run_id"]

    def test_get_auto_run_tool_reads_the_latest_run(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        mcp_tools.get_tool("run_auto").handler(  # type: ignore[union-attr]
            {"binary_id": ids["binary"]}
        )
        tool = mcp_tools.get_tool("get_auto_run")
        assert tool is not None
        result = tool.handler({"binary_id": ids["binary"]})
        assert result["binary_id"] == ids["binary"]
        assert len(result["tree"]) == 1

    def test_get_auto_run_tool_needs_an_id(self, conn: Any) -> None:
        tool = mcp_tools.get_tool("get_auto_run")
        assert tool is not None
        with pytest.raises(mcp_tools.ToolError):
            tool.handler({})

    def test_get_auto_run_tool_404s_for_an_unknown_run(self, conn: Any) -> None:
        tool = mcp_tools.get_tool("get_auto_run")
        assert tool is not None
        with pytest.raises(mcp_tools.ToolError):
            tool.handler({"run_id": 999})

    def test_revert_auto_run_tool_deletes_the_rows(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        started = mcp_tools.get_tool("run_auto").handler(  # type: ignore[union-attr]
            {"binary_id": ids["binary"]}
        )
        tool = mcp_tools.get_tool("revert_auto_run")
        assert tool is not None
        result = tool.handler({"run_id": started["run_id"]})
        assert result["status"] == auto_store.AUTO_RUN_REVERTED
        assert auto_store.get_auto_run(conn, started["run_id"]) is None

    def test_run_auto_tool_rejects_an_unknown_worker(self, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        tool = mcp_tools.get_tool("run_auto")
        assert tool is not None
        with pytest.raises(mcp_tools.ToolError):
            tool.handler({"binary_id": ids["binary"], "worker": "nope"})


class TestStart:
    def test_start_returns_the_run_id_immediately(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        status, body = _start(ids["binary"])
        assert status == 202
        assert body["binary_id"] == ids["binary"]
        assert body["status"] == auto_store.AUTO_RUN_RUNNING
        assert isinstance(body["run_id"], int)
        run = _wait_for_terminal(portal_db, ids["binary"])
        assert run["id"] == body["run_id"]

    def test_start_defaults_to_a_dry_run(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        _start(ids["binary"])
        run = _wait_for_terminal(portal_db, ids["binary"])
        assert run["config"]["execute"] is False
        row = store.get_function(conn, ids["functions"][0])
        assert row is not None
        assert row["status"] == "STUB"

    def test_start_rejects_an_unknown_binary(self, conn: Any) -> None:
        status, body = _start(999)
        assert status == 404
        assert body["error"] == "binary not found"

    @pytest.mark.parametrize(
        "body",
        [
            {"concurrency": 0},
            {"concurrency": 99},
            {"max_attempts": 11},
            {"max_tasks": 0},
            {"functions_per_task": 0},
            {"worker": "nope"},
        ],
    )
    def test_start_validates_every_bound(self, conn: Any, body: dict[str, Any]) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        status, payload = _start(ids["binary"], body)
        assert status == 400
        assert payload["error"] == "invalid params"

    @pytest.mark.parametrize(
        "body",
        [{"concurrency": "four"}, {"execute": "yes"}, {"worker": 7}],
    )
    def test_start_rejects_a_wrong_field_type(self, conn: Any, body: dict[str, Any]) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        status, _payload = _start(ids["binary"], body)
        assert status == 400

    def test_start_honours_the_requested_bounds(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        _start(
            ids["binary"],
            {
                "worker": "offline",
                "concurrency": 2,
                "max_attempts": 1,
                "functions_per_task": 2,
                "max_tasks": 5,
            },
        )
        run = _wait_for_terminal(portal_db, ids["binary"])
        assert run["config"]["concurrency"] == 2
        assert run["config"]["max_attempts"] == 1
        assert run["config"]["functions_per_task"] == 2
        assert run["config"]["max_tasks"] == 5

    def test_start_refuses_when_the_background_cap_is_full(
        self, conn: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        other_binary = store.add_binary(conn, sha256="ef" * 32, name="other.exe")
        held = threading.Event()
        release = threading.Event()
        slots = threading.BoundedSemaphore(1)

        def hang(_conn: Any, **_kwargs: Any) -> None:
            held.set()
            release.wait(timeout=10)

        monkeypatch.setattr(api, "_auto_run_slots", slots)
        monkeypatch.setattr("reportal.auto_mode.execute_auto_run", hang)
        status, _payload = _start(first["binary"])
        assert status == 202
        assert held.wait(timeout=2)
        busy_status, busy_payload = _start(other_binary)
        assert busy_status == 503
        assert busy_payload["error"] == "auto-busy"
        release.set()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if slots.acquire(blocking=False):
                slots.release()
                break
            time.sleep(0.02)
        else:
            raise AssertionError("the background auto-run slot was never released")

    def test_a_second_start_reuses_a_live_run(
        self, conn: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A double-click must not open a second metered auto run."""
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        held = threading.Event()
        release = threading.Event()

        def hang(_conn: Any, **_kwargs: Any) -> None:
            held.set()
            release.wait(timeout=10)

        monkeypatch.setattr("reportal.auto_mode.execute_auto_run", hang)
        status, first = _start(ids["binary"], {"worker": "offline", "max_attempts": 1})
        assert status == 202
        assert held.wait(timeout=2)
        again_status, again = _start(ids["binary"], {"worker": "offline", "max_attempts": 1})
        assert again_status == 202
        assert again["run_id"] == first["run_id"]
        assert len(auto_store.list_auto_runs(conn, binary_id=ids["binary"])) == 1
        release.set()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if api._auto_run_slots.acquire(blocking=False):
                api._auto_run_slots.release()
                break
            time.sleep(0.02)


class TestGet:
    def test_latest_run_answers_before_any_run_with_404(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        status, headers, payload = wsgi_request("GET", f"/api/binaries/{ids['binary']}/auto")
        body = json_body(payload, headers)
        assert int(status.split()[0]) == 404
        assert body["error"] == "no-run"

    def test_latest_run_reports_the_tree_and_coverage(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        _start(ids["binary"])
        _wait_for_terminal(portal_db, ids["binary"])
        status, headers, payload = wsgi_request("GET", f"/api/binaries/{ids['binary']}/auto")
        body = json_body(payload, headers)
        assert int(status.split()[0]) == 200
        assert body["status"] == auto_store.AUTO_RUN_DONE
        assert body["matched"] == 1
        assert body["worker"] == auto_workers.WORKER_OFFLINE
        assert body["coverage_before"]["matched"] == 0
        assert body["coverage_after"]["matched"] == 1
        assert len(body["tree"]) == 1
        assert body["tree"][0]["kind"] == auto_store.AUTO_TASK_ROOT
        assert len(body["tree"][0]["children"]) == 1

    def test_latest_run_404s_for_an_unknown_binary(self, conn: Any) -> None:
        status, headers, payload = wsgi_request("GET", "/api/binaries/999/auto")
        assert int(status.split()[0]) == 404
        assert json_body(payload, headers)["error"] == "binary not found"

    def test_one_run_by_id(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        _status, started = _start(ids["binary"])
        _wait_for_terminal(portal_db, ids["binary"])
        status, headers, payload = wsgi_request("GET", f"/api/auto/runs/{started['run_id']}")
        body = json_body(payload, headers)
        assert int(status.split()[0]) == 200
        assert body["run_id"] == started["run_id"]

    def test_unknown_run_id_is_404(self, conn: Any) -> None:
        status, headers, payload = wsgi_request("GET", "/api/auto/runs/999")
        assert int(status.split()[0]) == 404
        assert json_body(payload, headers)["error"] == "run not found"

    def test_a_non_member_does_not_read_a_team_run(
        self, portal_db: Path, conn: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        _status, started = _start(ids["binary"])
        _wait_for_terminal(portal_db, ids["binary"])
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        status, headers, payload = wsgi_request(
            "GET",
            f"/api/auto/runs/{started['run_id']}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert int(status.split()[0]) == 404, payload
        assert json_body(payload, headers)["error"] == "run not found"

        status, headers, payload = wsgi_request(
            "GET",
            f"/api/auto/runs/{started['run_id']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert int(status.split()[0]) == 200, payload


class TestRevert:
    def test_revert_removes_a_written_file_and_restores_the_status(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        written = tmp_path / "Work.c"
        auto_workers.register_worker(writer_worker(written), origin="test")
        _status, started = _start(ids["binary"], {"worker": "writer", "execute": True})
        _wait_for_terminal(portal_db, ids["binary"])
        assert written.is_file()
        status, headers, payload = wsgi_request(
            "POST", f"/api/auto/runs/{started['run_id']}/revert"
        )
        body = json_body(payload, headers)
        assert int(status.split()[0]) == 200
        assert body["status"] == auto_store.AUTO_RUN_REVERTED
        assert body["removed"] == [{"path": str(written), "status": "removed"}]
        assert body["restored"] == [{"function_id": ids["functions"][0], "status": "STUB"}]
        assert not written.exists()
        assert auto_store.get_auto_run(conn, started["run_id"]) is None

    def test_revert_of_an_unknown_run_is_404(self, conn: Any) -> None:
        status, headers, payload = wsgi_request("POST", "/api/auto/runs/999/revert")
        assert int(status.split()[0]) == 404
        assert json_body(payload, headers)["error"] == "run not found"

    def test_the_latest_run_is_404_after_a_revert(self, portal_db: Path, conn: Any) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        _status, started = _start(ids["binary"])
        _wait_for_terminal(portal_db, ids["binary"])
        wsgi_request("POST", f"/api/auto/runs/{started['run_id']}/revert")
        status, headers, payload = wsgi_request("GET", f"/api/binaries/{ids['binary']}/auto")
        assert int(status.split()[0]) == 404
        assert json_body(payload, headers)["error"] == "no-run"

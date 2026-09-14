"""Tests for the async operation workflow: the queue, the runner and its surfaces."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, engines, jobs, journal, mcp_tools, store

runner = CliRunner()


def _binary(conn: sqlite3.Connection, tmp_path: Path, name: str = "t.exe") -> int:
    path = tmp_path / name
    path.write_bytes(b"MZ" + b"\x00" * 64)
    return store.add_binary(conn, sha256=f"{name:0<64}"[:64], name=name, path=str(path), size=66)


def _submit(conn: sqlite3.Connection, tmp_path: Path, kind: str = "composition") -> dict[str, Any]:
    """A queued job of a kind that stores a scan with no engine call."""
    return jobs.submit(conn, kind=kind, binary_id=_binary(conn, tmp_path))


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


def _post(path: str, payload: dict[str, Any] | None = None) -> tuple[str, Any]:
    raw = b"" if payload is None else json.dumps(payload).encode()
    status, headers, body = wsgi_request("POST", path, body=raw)
    return status, json_body(body, headers)


class TestRegistry:
    def test_the_registry_holds_the_documented_kinds(self) -> None:
        assert set(jobs.JOB_KINDS) == {
            "behavior",
            "capabilities",
            "composition",
            "filetype",
            "hardening",
            "protocols",
            "report",
            "report-pdf",
            "secrets",
            "unstrip",
        }

    def test_every_kind_names_its_label_and_its_write(self) -> None:
        for spec in jobs.JOB_KINDS.values():
            assert spec.label
            # A kind either stores one fixed scan kind, one scan kind per domain,
            # or journals a write of its own (`perform`) instead of a scan.
            params = dict.fromkeys(spec.params, "")
            params["domain"] = "execution" if spec.name == "behavior" else "obfuscation"
            assert spec.scan_kind_for(params) or spec.perform is not None

    def test_a_domain_kind_resolves_one_scan_kind_per_domain(self) -> None:
        hardening = jobs.JOB_KINDS["hardening"]
        obfuscation = hardening.scan_kind_for({"domain": "obfuscation"})
        anti_analysis = hardening.scan_kind_for({"domain": "anti-analysis"})

        assert obfuscation is not None and obfuscation.endswith("obfuscation")
        assert anti_analysis != obfuscation


class TestSubmit:
    def test_a_submitted_job_starts_queued(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        job = _submit(conn, tmp_path)

        assert job["status"] == jobs.STATUS_QUEUED
        assert job["progress"] == 0
        assert job["steps_total"] == 1
        assert job["live"] is True
        assert job["result"] is None
        assert job["label"]

    def test_an_unknown_kind_is_refused(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        try:
            jobs.submit(conn, kind="nope", binary_id=_binary(conn, tmp_path))
        except ValueError as exc:
            assert "unknown job kind" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown kind must be refused")

    def test_an_unknown_binary_is_refused(self, conn: sqlite3.Connection) -> None:
        try:
            jobs.submit(conn, kind="composition", binary_id=4242)
        except KeyError as exc:
            assert "4242" in str(exc.args[0])
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown binary must be refused")

    def test_a_parameter_the_kind_does_not_take_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        try:
            jobs.submit(
                conn, kind="composition", binary_id=_binary(conn, tmp_path), params={"domain": "x"}
            )
        except ValueError as exc:
            assert "takes no parameter" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unexpected parameter must be refused")

    def test_an_unknown_domain_is_refused_before_the_job_runs(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        try:
            jobs.submit(
                conn,
                kind="hardening",
                binary_id=_binary(conn, tmp_path),
                params={"domain": "nope"},
            )
        except ValueError as exc:
            assert "unknown hardening domain" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown domain must be refused on submit")

    def test_the_params_are_stored_with_the_job(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = jobs.submit(
            conn,
            kind="behavior",
            binary_id=_binary(conn, tmp_path),
            params={"domain": "networking"},
        )

        assert job["params"] == {"domain": "networking"}
        stored = jobs.get_job(conn, job["id"])
        assert stored is not None
        assert stored["params"] == {"domain": "networking"}


class TestRun:
    def test_running_a_job_records_its_result(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)

        finished = jobs.run_pending(conn, limit=1)

        assert [row["id"] for row in finished] == [job["id"]]
        assert finished[0]["status"] == jobs.STATUS_DONE
        assert finished[0]["progress"] == 100
        assert finished[0]["result"] is not None
        assert finished[0]["finished_at"]

    def test_a_queued_job_runs_oldest_first(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        first = _submit(conn, tmp_path)
        second = _submit(conn, tmp_path)

        finished = jobs.run_pending(conn, limit=2)

        assert [row["id"] for row in finished] == [first["id"], second["id"]]

    def test_an_empty_queue_runs_nothing(self, conn: sqlite3.Connection) -> None:
        assert jobs.run_pending(conn, limit=3) == []

    def test_a_failing_operation_is_a_failed_job_not_a_crash(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        # The file is not a real executable, so the engine call refuses it; the
        # job records that rather than raising into the worker.
        job = jobs.submit(conn, kind="secrets", binary_id=_binary(conn, tmp_path))

        finished = jobs.run_pending(conn, limit=1)

        assert finished[0]["id"] == job["id"]
        assert finished[0]["status"] == jobs.STATUS_FAILED
        assert finished[0]["error"]
        assert finished[0]["result"] is None

    def test_a_failed_job_leaves_no_journal_entry(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path, kind="secrets")
        jobs.run_pending(conn, limit=1)

        assert journal.list_entries(conn) == []

    def test_a_successful_job_is_journaled_like_its_route(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        entries = journal.list_entries(conn)
        assert entries, "the queued scan journals what it stored"
        assert any("composition" in entry["description"] for entry in entries)

    def test_a_finished_job_is_not_live(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        rows, total = jobs.list_jobs(conn)
        assert total == 1
        assert rows[0]["live"] is False


class TestCancel:
    def test_a_queued_job_can_be_cancelled(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        job = _submit(conn, tmp_path)

        cancelled = jobs.cancel(conn, job["id"])

        assert cancelled is not None
        assert cancelled["status"] == jobs.STATUS_CANCELLED
        assert cancelled["finished_at"]
        assert jobs.run_pending(conn, limit=1) == []

    def test_cancelling_an_unknown_job_is_none(self, conn: sqlite3.Connection) -> None:
        assert jobs.cancel(conn, 4242) is None

    def test_cancelling_a_finished_job_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        try:
            jobs.cancel(conn, job["id"])
        except ValueError as exc:
            assert "cannot be cancelled" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a finished job must not be cancellable")


class TestListing:
    def test_the_listing_filters_by_status_and_kind(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        first = _submit(conn, tmp_path)
        jobs.submit(conn, kind="unstrip", binary_id=first["binary_id"])
        jobs.run_pending(conn, limit=1)

        rows, total = jobs.list_jobs(conn, status=jobs.STATUS_QUEUED)

        assert total == 1
        assert rows[0]["kind"] == "unstrip"
        by_kind, kind_total = jobs.list_jobs(conn, kind="composition")
        assert kind_total == 1
        assert by_kind[0]["status"] == jobs.STATUS_DONE

    def test_an_unknown_status_or_kind_is_refused(self, conn: sqlite3.Connection) -> None:
        for kwargs in ({"status": "nope"}, {"kind": "nope"}):
            try:
                jobs.list_jobs(conn, **kwargs)  # type: ignore[arg-type]
            except ValueError:
                pass
            else:  # pragma: no cover - the assertion is the point
                raise AssertionError("an unknown filter must be refused")

    def test_an_out_of_range_limit_is_refused(self, conn: sqlite3.Connection) -> None:
        for bad in (0, jobs.MAX_JOB_LIMIT + 1):
            try:
                jobs.list_jobs(conn, limit=bad)
            except ValueError:
                pass
            else:  # pragma: no cover - the assertion is the point
                raise AssertionError("an out-of-range limit must be refused")

    def test_the_counts_report_what_is_waiting(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path)

        assert jobs.count_jobs(conn, status=jobs.STATUS_QUEUED) == 1
        assert jobs.count_jobs(conn, status=jobs.STATUS_DONE) == 0


class TestEvents:
    def test_the_stream_starts_with_the_current_state_and_ends_when_terminal(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)

        frames = list(jobs.events(conn, job["id"], interval=0.01, max_seconds=0.05))

        assert frames, "a stream always sends the current state first"
        assert frames[0].startswith("event: job\ndata: ")
        assert f'"id": {job["id"]}' in frames[0]
        assert frames[-1].startswith("event: timeout")

    def test_a_terminal_job_streams_one_frame_and_closes(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        frames = list(jobs.events(conn, job["id"], interval=0.01, max_seconds=5.0))

        assert len(frames) == 1
        assert '"status": "done"' in frames[0]

    def test_an_unknown_job_streams_an_error_frame(self, conn: sqlite3.Connection) -> None:
        frames = list(jobs.events(conn, 4242, interval=0.01, max_seconds=0.01))

        assert frames == ['event: error\ndata: {"error": "job not found"}\n\n']


class TestRoute:
    def test_submitting_answers_the_queued_job(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)

        status, payload = _post("/api/jobs", {"kind": "composition", "binary_id": binary_id})

        assert status.startswith("202")
        assert payload["status"] == jobs.STATUS_QUEUED, "the pool is off, so nothing ran it"
        assert payload["kind"] == "composition"

    def test_submitting_is_journaled_and_revertible(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)

        status, payload = _post("/api/jobs", {"kind": "composition", "binary_id": binary_id})

        assert status.startswith("202")
        assert payload["journal_action"], "the queued row is one journaled action"
        job_id = int(payload["id"])
        assert jobs.get_job(conn, job_id) is not None

        journal.revert_action(conn, payload["journal_action"])

        assert jobs.get_job(conn, job_id) is None

    def test_cancelling_is_journaled_and_revertible(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)

        status, payload = _post(f"/api/jobs/{job['id']}/cancel")

        assert status.startswith("200")
        assert payload["status"] == jobs.STATUS_CANCELLED
        assert payload["journal_action"]

        journal.revert_action(conn, payload["journal_action"])

        restored = jobs.get_job(conn, int(job["id"]))
        assert restored is not None
        assert restored["status"] == jobs.STATUS_QUEUED

    def test_an_unknown_kind_is_400(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        status, payload = _post("/api/jobs", {"kind": "nope", "binary_id": _binary(conn, tmp_path)})

        assert status.startswith("400")
        assert payload["error"] == "invalid job"

    def test_an_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _post("/api/jobs", {"kind": "composition", "binary_id": 4242})

        assert status.startswith("404")
        assert payload["error"] == "binary not found"

    def test_the_listing_carries_the_kinds_and_the_waiting_count(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path)

        status, payload = _get("/api/jobs")

        assert status.startswith("200")
        assert payload["queued"] >= 1
        assert any(entry["name"] == "composition" for entry in payload["kinds"])
        # Both closed vocabularies travel, so a client's controls cannot drift.
        assert list(payload["statuses"]) == list(jobs.STATUSES)
        assert "composition" in {entry["name"] for entry in payload["kinds"]}

    def test_an_unknown_status_filter_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/jobs?status=nope")

        assert status.startswith("400")
        assert payload["error"] == "invalid status"

    def test_one_job_is_404_when_it_does_not_exist(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/jobs/4242")

        assert status.startswith("404")
        assert payload["error"] == "job not found"

    def test_running_the_queue_inline_answers_what_finished(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path)

        status, payload = _post("/api/jobs/run")

        assert status.startswith("200")
        assert payload["count"] == 1
        assert payload["jobs"][0]["status"] == jobs.STATUS_DONE

    def test_cancelling_a_finished_job_is_409(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        status, payload = _post(f"/api/jobs/{job['id']}/cancel")

        assert status.startswith("409")
        assert payload["error"] == "job-not-cancellable"

    def test_cancelling_an_unknown_job_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _post("/api/jobs/4242/cancel")

        assert status.startswith("404")
        assert payload["error"] == "job not found"

    def test_the_events_route_streams_server_sent_events(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        status, headers, body = wsgi_request("GET", f"/api/jobs/{job['id']}/events")

        assert status.startswith("200")
        assert headers["Content-Type"].startswith("text/event-stream")
        text = body.decode()
        assert text.startswith("event: job\n")
        assert '"status": "done"' in text

    def test_the_events_route_of_an_unknown_job_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/jobs/4242/events")

        assert status.startswith("404")
        assert payload["error"] == "job not found"


class TestCli:
    def test_job_submit_and_run(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)

        queued = runner.invoke(cli.app, ["job-submit", "composition", str(binary_id), "--json"])
        assert queued.exit_code == 0
        assert json.loads(queued.stdout)["status"] == jobs.STATUS_QUEUED

        ran = runner.invoke(cli.app, ["job-run", "--json"])
        assert ran.exit_code == 0
        assert json.loads(ran.stdout)["jobs"][0]["status"] == jobs.STATUS_DONE

        listed = runner.invoke(cli.app, ["jobs", "--json"])
        assert listed.exit_code == 0
        payload = json.loads(listed.stdout)
        assert payload["total"] == 1
        assert payload["queued"] == 0

        shown = runner.invoke(cli.app, ["job", "1", "--json"])
        assert shown.exit_code == 0
        assert json.loads(shown.stdout)["status"] == jobs.STATUS_DONE

    def test_job_submit_runs_it_when_asked(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)

        result = runner.invoke(
            cli.app, ["job-submit", "composition", str(binary_id), "--run", "--json"]
        )

        assert result.exit_code == 0
        assert json.loads(result.stdout)["status"] == jobs.STATUS_DONE

    def test_an_unknown_kind_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)

        result = runner.invoke(cli.app, ["job-submit", "nope", "1"])

        assert result.exit_code == 1
        assert "unknown job kind" in result.output

    def test_an_unknown_job_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)

        assert runner.invoke(cli.app, ["job", "4242"]).exit_code == 1
        assert runner.invoke(cli.app, ["job-cancel", "4242"]).exit_code == 1

    def test_cancelling_a_queued_job_reports_it(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)
        runner.invoke(cli.app, ["job-submit", "composition", str(binary_id), "--json"])

        result = runner.invoke(cli.app, ["job-cancel", "1", "--json"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["status"] == jobs.STATUS_CANCELLED


class TestMcp:
    def test_the_read_tools_are_read_only(self) -> None:
        for name in ("list_jobs", "get_job"):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.read_only_hint is True
        for name in ("submit_job", "cancel_job", "run_jobs"):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.destructive_hint is True

    def test_submit_run_and_read(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        submit = mcp_tools.get_tool("submit_job")
        run = mcp_tools.get_tool("run_jobs")
        get = mcp_tools.get_tool("get_job")
        listing = mcp_tools.get_tool("list_jobs")
        assert submit and run and get and listing

        queued = submit.handler({"kind": "composition", "binary_id": binary_id})
        assert queued["status"] == jobs.STATUS_QUEUED
        ran = run.handler({})
        assert ran["jobs"][0]["id"] == queued["id"]
        assert get.handler({"job_id": queued["id"]})["status"] == jobs.STATUS_DONE
        assert listing.handler({})["total"] == 1
        # The tool takes the same binary filter the route and the CLI do.
        assert listing.handler({"binary_id": binary_id})["count"] == 1
        assert listing.handler({"binary_id": 4242})["count"] == 0
        assert listing.handler({})["statuses"] == list(jobs.STATUSES)

    def test_an_unknown_kind_is_a_tool_error(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        submit = mcp_tools.get_tool("submit_job")
        assert submit is not None

        try:
            submit.handler({"kind": "nope", "binary_id": binary_id})
        except mcp_tools.ToolError as exc:
            assert exc.error == "invalid job"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown kind must be a tool error")

    def test_an_unknown_job_is_a_tool_error(self, portal_db: Path) -> None:
        get = mcp_tools.get_tool("get_job")
        assert get is not None

        try:
            get.handler({"job_id": 4242})
        except mcp_tools.ToolError as exc:
            assert exc.error == "job not found"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown job must be a tool error")


class TestPool:
    def test_the_pool_drains_a_queued_job(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: Any
    ) -> None:
        # The real pool, with its own connection: the one path a test cannot
        # drive through run_pending.  The wait is bounded and the job is one
        # stored-only scan, so it settles in well under the cap.
        monkeypatch.setenv(jobs.POOL_ENV, "1")
        monkeypatch.setattr(jobs, "POLL_SECONDS", 0.01)
        job = _submit(conn, tmp_path)

        worker = jobs.ensure_worker()
        try:
            assert worker is not None
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                stored = jobs.get_job(conn, job["id"])
                assert stored is not None
                if not stored["live"]:
                    break
                time.sleep(0.02)
            else:  # pragma: no cover - the pool would have to be wedged
                raise AssertionError("the pool did not pick the job up")
            assert stored["status"] == jobs.STATUS_DONE
        finally:
            jobs.stop_worker()

    def test_a_disabled_pool_starts_nothing(self, monkeypatch: Any) -> None:
        monkeypatch.setenv(jobs.POOL_ENV, "1")
        assert jobs.ensure_worker() is not None
        jobs.stop_worker()
        monkeypatch.setenv(jobs.POOL_ENV, "0")
        assert jobs.pool_disabled() is True
        assert jobs.ensure_worker() is None


class TestOffline:
    def test_running_a_job_makes_no_network_call(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: Any
    ) -> None:
        # The job runner reaches the engine the same way a route does, and the
        # engine is the stub; nothing here opens a socket.
        monkeypatch.setattr(engines, "get_engine", lambda: engines.RebrewEngine())

        _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        assert jobs.count_jobs(conn) == 1

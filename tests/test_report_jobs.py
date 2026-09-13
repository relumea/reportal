"""Tests for the report workflow: the PDF and engine reports as queued jobs."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, jobs, journal, mcp_tools, store

runner = CliRunner()


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A reportal workspace marker in *tmp_path* with the cwd moved there.

    The PDF lands under the workspace's ``reports/`` directory, so without this
    the suite would write into the checkout (and read what a previous run left
    there) instead of an isolated directory per test.
    """
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _binary(conn: sqlite3.Connection, tmp_path: Path) -> int:
    path = tmp_path / "t.exe"
    path.write_bytes(b"MZ" + b"\x00" * 64)
    return store.add_binary(conn, sha256="b" * 64, name="t.exe", path=str(path), size=66)


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


def _post(path: str, payload: dict[str, Any] | None = None) -> tuple[str, Any]:
    raw = b"" if payload is None else json.dumps(payload).encode()
    status, headers, body = wsgi_request("POST", path, body=raw)
    return status, json_body(body, headers)


class TestRegistry:
    def test_the_report_kinds_are_registered(self) -> None:
        assert "report" in jobs.JOB_KINDS
        assert "report-pdf" in jobs.JOB_KINDS

    def test_the_pdf_kind_journals_its_own_write(self) -> None:
        spec = jobs.JOB_KINDS["report-pdf"]

        assert spec.perform is not None, "a file write is not a scan row"
        assert spec.scan_kinds is None

    def test_the_engine_report_kind_stores_the_report_scan(self) -> None:
        assert jobs.JOB_KINDS["report"].scan_kinds == store.SCAN_KIND_REPORT


class TestPdfJob:
    def test_a_queued_pdf_runs_and_writes_the_file(
        self, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        job = jobs.submit(conn, kind="report-pdf", binary_id=binary_id)

        finished = jobs.run_pending(conn, limit=1)[0]

        assert finished["id"] == job["id"]
        assert finished["status"] == jobs.STATUS_DONE
        assert finished["result"] is not None
        assert Path(finished["result"]["path"]).is_file()
        assert finished["result"]["pages"] >= 1

    def test_a_queued_pdf_is_journaled_like_the_route(
        self, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        jobs.submit(conn, kind="report-pdf", binary_id=binary_id)

        jobs.run_pending(conn, limit=1)

        entries = journal.list_entries(conn)
        assert len(entries) == 1, "one action for the one file it wrote"
        assert "file" in entries[0]["kind"]

    def test_the_newest_pdf_job_is_readable_per_binary(
        self, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        jobs.submit(conn, kind="report-pdf", binary_id=binary_id)
        jobs.run_pending(conn, limit=1)

        latest = jobs.latest_job(conn, kind="report-pdf", binary_id=binary_id)

        assert latest is not None
        assert latest["status"] == jobs.STATUS_DONE
        assert jobs.latest_job(conn, kind="report-pdf", binary_id=4242) is None

    def test_an_unknown_kind_is_refused_by_the_reader(self, conn: sqlite3.Connection) -> None:
        try:
            jobs.latest_job(conn, kind="nope")
        except ValueError as exc:
            assert "unknown job kind" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown kind must be refused")

    def test_the_engine_report_without_a_project_context_fails_honestly(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        jobs.submit(conn, kind="report", binary_id=binary_id)

        finished = jobs.run_pending(conn, limit=1)[0]

        assert finished["status"] == jobs.STATUS_FAILED
        assert "rebrew project context" in finished["error"]


class TestRoute:
    def test_the_status_route_reports_an_absent_pdf(
        self, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)

        status, payload = _get(f"/api/binaries/{binary_id}/report/pdf/status")

        assert status.startswith("200")
        assert payload["exists"] is False
        assert payload["job"] is None
        assert payload["download_url"].endswith("/report/pdf")

    def test_the_status_route_reports_the_file_and_the_job(
        self, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        jobs.submit(conn, kind="report-pdf", binary_id=binary_id)
        jobs.run_pending(conn, limit=1)

        status, payload = _get(f"/api/binaries/{binary_id}/report/pdf/status")

        assert status.startswith("200")
        assert payload["exists"] is True
        assert payload["bytes"] > 0
        assert payload["pages"] >= 1
        assert payload["generated_at"]
        assert payload["job"]["status"] == jobs.STATUS_DONE

    def test_the_status_route_of_an_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/binaries/4242/report/pdf/status")

        assert status.startswith("404")
        assert payload["error"] == "binary not found"

    def test_the_route_renders_and_the_job_run_agree(
        self, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)

        status, payload = _post(f"/api/binaries/{binary_id}/report/pdf")

        assert status.startswith("200")
        assert payload["pages"] >= 1
        latest = jobs.latest_job(conn, kind="report-pdf", binary_id=binary_id)
        assert latest is None, "the route renders without queueing a job"

    def test_a_queued_pdf_can_be_followed_through_the_jobs_route(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)

        status, queued = _post("/api/jobs", {"kind": "report-pdf", "binary_id": binary_id})

        assert status.startswith("202")
        assert queued["kind"] == "report-pdf"
        status, listed = _get(f"/api/jobs?kind=report-pdf&binary_id={binary_id}")
        assert status.startswith("200")
        assert listed["total"] == 1

    def test_the_jobs_listing_validates_the_binary_filter(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/jobs?binary_id=4242")

        assert status.startswith("200")
        assert payload["total"] == 0


class TestCli:
    def test_queue_and_status(self, tmp_path: Path, workspace: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)

        queued = runner.invoke(cli.app, ["report-pdf", str(binary_id), "--queue", "--json"])
        assert queued.exit_code == 0
        assert json.loads(queued.stdout)["kind"] == "report-pdf"

        ran = runner.invoke(cli.app, ["job-run", "--json"])
        assert ran.exit_code == 0
        assert json.loads(ran.stdout)["jobs"][0]["status"] == jobs.STATUS_DONE

        shown = runner.invoke(cli.app, ["report-pdf", str(binary_id), "--status", "--json"])
        assert shown.exit_code == 0
        payload = json.loads(shown.stdout)
        assert payload["exists"] is True
        assert payload["job"]["status"] == jobs.STATUS_DONE

    def test_the_status_of_an_unknown_binary_exits_non_zero(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)

        result = runner.invoke(cli.app, ["report-pdf", "4242", "--status"])

        assert result.exit_code == 1


class TestMcp:
    def test_get_pdf_status_carries_the_job(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        jobs.submit(conn, kind="report-pdf", binary_id=binary_id)
        jobs.run_pending(conn, limit=1)
        tool = mcp_tools.get_tool("get_pdf_status")
        assert tool is not None

        payload = tool.handler({"binary_id": binary_id})

        assert payload["exists"] is True
        assert payload["pages"] >= 1
        assert payload["job"]["status"] == jobs.STATUS_DONE

    def test_generate_pdf_report_renders_and_journals(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        tool = mcp_tools.get_tool("generate_pdf_report")
        assert tool is not None

        payload = tool.handler({"binary_id": binary_id})

        assert payload["pages"] >= 1
        assert payload["journal_action"]

    def test_submit_job_queues_a_pdf(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        submit = mcp_tools.get_tool("submit_job")
        assert submit is not None

        job = submit.handler({"kind": "report-pdf", "binary_id": binary_id})

        assert job["kind"] == "report-pdf"
        assert job["status"] == jobs.STATUS_QUEUED

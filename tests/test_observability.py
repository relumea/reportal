"""Request correlation and process-local HTTP/job counters on the serving path."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from unittest import mock

import pytest
from conftest import json_body, wsgi_request

from reportal import jobs, observability, store
from reportal.observability import REQUEST_ID_HEADER


class TestRequestCorrelation:
    def test_health_echoes_a_minted_request_id(self, portal_db: Path) -> None:
        observability.reset_http_stats()
        status, headers, _body = wsgi_request("GET", "/api/health")
        assert status.startswith("200")
        request_id = headers[REQUEST_ID_HEADER]
        assert request_id
        assert observability.resolve_request_id(request_id) == request_id

    def test_a_missing_request_id_uses_the_mint_seam(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(observability, "_mint_request_id", lambda: "fixed-request-id")
        assert observability.resolve_request_id(None) == "fixed-request-id"
        assert observability.resolve_request_id("bad id") == "fixed-request-id"

    def test_health_echoes_a_client_request_id(self, portal_db: Path) -> None:
        observability.reset_http_stats()
        status, headers, _body = wsgi_request(
            "GET",
            "/api/health",
            headers={REQUEST_ID_HEADER: "client-trace-001"},
        )
        assert status.startswith("200")
        assert headers[REQUEST_ID_HEADER] == "client-trace-001"

    def test_a_forged_request_id_is_replaced(self, portal_db: Path) -> None:
        observability.reset_http_stats()
        forged = "bad id\nwith-newline"
        status, headers, _body = wsgi_request(
            "GET",
            "/api/health",
            headers={REQUEST_ID_HEADER: forged},
        )
        assert status.startswith("200")
        assert headers[REQUEST_ID_HEADER] != forged
        assert "\n" not in headers[REQUEST_ID_HEADER]

    def test_completion_log_fields_collapse_control_characters(self) -> None:
        from reportal.server import _safe_log_token

        assert _safe_log_token("GET") == "GET"
        assert _safe_log_token("/api/binaries\nERROR") == "/api/binaries?ERROR"
        assert _safe_log_token("a\rb\x00c") == "a?b?c"


class TestHttpCounters:
    def test_health_reports_http_counters(self, portal_db: Path) -> None:
        observability.reset_http_stats()
        wsgi_request("GET", "/api/binaries")
        status, headers, body = wsgi_request("GET", "/api/health")
        assert status.startswith("200")
        payload = json_body(body, headers)
        http = payload["http"]
        assert http["requests"] >= 1
        assert http["errors_4xx"] == 0
        assert http["errors_5xx"] == 0
        assert http["duration_ms_sum"] >= 0
        assert http["duration_ms_max"] >= 0

    def test_request_duration_comes_from_the_clock_seam(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The recorded duration is pinned by ``server._perf_counter``, not wall time."""
        from reportal import server

        observability.reset_http_stats()
        ticks = iter([10.0, 10.25])
        monkeypatch.setattr(server, "_perf_counter", lambda: next(ticks))
        wsgi_request("GET", "/api/binaries")
        snapshot = observability.http_snapshot()
        assert snapshot["requests"] >= 1
        assert snapshot["duration_ms_sum"] == 250
        assert snapshot["duration_ms_max"] == 250

    def test_a_client_error_increments_4xx(self, portal_db: Path) -> None:
        observability.reset_http_stats()
        wsgi_request("GET", "/api/binaries/999999")
        snapshot = observability.http_snapshot()
        assert snapshot["requests"] >= 1
        assert snapshot["errors_4xx"] >= 1
        assert snapshot["errors_5xx"] == 0

    @pytest.mark.parametrize("failure_site", ["route", "authentication"])
    def test_unhandled_failure_is_counted_and_correlated(
        self,
        failure_site: str,
        portal_db: Path,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from reportal import server

        failure = sqlite3.OperationalError("database unavailable")
        if failure_site == "route":
            monkeypatch.setattr(store, "list_binaries", mock.Mock(side_effect=failure))
        else:
            monkeypatch.setattr(server, "authenticate", mock.Mock(side_effect=failure))
        observability.reset_http_stats()
        with caplog.at_level(logging.INFO, logger="reportal"):
            status, headers, body = wsgi_request(
                "GET", "/api/binaries", headers={REQUEST_ID_HEADER: "failed-request"}
            )
        assert status.startswith("500")
        assert headers[REQUEST_ID_HEADER] == "failed-request"
        assert json_body(body, headers)["error"] == "internal server error"
        snapshot = observability.http_snapshot()
        assert snapshot["requests"] == 1
        assert snapshot["errors_5xx"] == 1
        assert snapshot["errors_4xx"] == 0
        completions = [r for r in caplog.records if r.getMessage().startswith("request method=")]
        assert len(completions) == 1
        assert completions[0].levelno == logging.ERROR
        assert "status=500" in completions[0].getMessage()
        assert "duration_ms=" in completions[0].getMessage()
        assert "request_id=failed-request" in completions[0].getMessage()
        errors = [r for r in caplog.records if r.exc_info]
        assert len(errors) == 1
        assert errors[0].exc_info is not None
        assert errors[0].exc_info[1] is failure
        assert "request_id=failed-request" in errors[0].getMessage()
        assert observability.current_request_id() == ""

    def test_a_binary_list_emits_a_completion_line(
        self, portal_db: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        observability.reset_http_stats()
        with caplog.at_level(logging.INFO, logger="reportal"):
            wsgi_request("GET", "/api/binaries")
        assert any(
            "request method=GET" in record.getMessage()
            and "path=/api/binaries" in record.getMessage()
            and "status=200" in record.getMessage()
            and "request_id=" in record.getMessage()
            for record in caplog.records
        )

    def test_a_completion_line_does_not_name_the_caller(
        self, portal_db: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import contextlib

        from reportal import auth, store

        with contextlib.closing(store.connect(portal_db)) as conn:
            _, token = auth.add_user(conn, name="privacy-user", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        observability.reset_http_stats()
        with caplog.at_level(logging.INFO, logger="reportal"):
            wsgi_request(
                "GET",
                "/api/binaries",
                headers={"Authorization": f"Bearer {token}"},
            )
        lines = [
            record.getMessage()
            for record in caplog.records
            if "request method=GET" in record.getMessage()
            and "path=/api/binaries" in record.getMessage()
        ]
        assert lines
        assert all("privacy-user" not in line for line in lines)
        assert any("actor=authenticated" in line for line in lines)

    def test_health_is_quiet_at_info(
        self, portal_db: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        observability.reset_http_stats()
        with caplog.at_level(logging.INFO, logger="reportal"):
            wsgi_request("GET", "/api/health")
        assert not any(
            "path=/api/health" in record.getMessage() and "request method=" in record.getMessage()
            for record in caplog.records
        )


class TestJobObservability:
    def test_health_reports_job_counters_and_queue(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        observability.reset_job_stats()
        binary_path = tmp_path / "demo.exe"
        binary_path.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="aa" * 32, name="demo.exe", size=2, path=str(binary_path)
        )
        jobs.submit(conn, kind="secrets", binary_id=binary_id, params={})
        status, headers, body = wsgi_request("GET", "/api/health")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["jobs"] == {
            "done": 0,
            "failed": 0,
            "duration_ms_sum": 0,
            "duration_ms_max": 0,
        }
        assert payload["dependencies"]["jobs"]["queued"] >= 1
        assert payload["dependencies"]["jobs"]["running"] == 0
        assert isinstance(payload["dependencies"]["jobs"]["pool"], bool)

    def test_a_failed_job_is_logged_and_counted(
        self, conn: sqlite3.Connection, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        observability.reset_job_stats()
        binary_path = tmp_path / "demo.exe"
        binary_path.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="aa" * 32, name="demo.exe", size=2, path=str(binary_path)
        )
        job = jobs.submit(conn, kind="secrets", binary_id=binary_id, params={})
        with caplog.at_level(logging.ERROR, logger="reportal.jobs"):
            finished = jobs.run_pending(conn, limit=1)
        assert finished[0]["status"] == jobs.STATUS_FAILED
        assert any(
            "job failed" in record.getMessage()
            and f"id={job['id']}" in record.getMessage()
            and "duration_ms=" in record.getMessage()
            for record in caplog.records
        )
        snapshot = observability.job_snapshot()
        assert snapshot["failed"] >= 1
        assert snapshot["done"] == 0
        assert snapshot["duration_ms_sum"] >= 0

    def test_a_job_duration_comes_from_the_clock_seam(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The recorded duration is pinned by ``jobs._monotonic``, not wall time."""
        observability.reset_job_stats()
        binary_path = tmp_path / "demo.exe"
        binary_path.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="cc" * 32, name="demo.exe", size=2, path=str(binary_path)
        )
        jobs.submit(conn, kind="secrets", binary_id=binary_id, params={})
        ticks = iter([100.0, 103.25])
        monkeypatch.setattr(jobs, "_monotonic", lambda: next(ticks))
        finished = jobs.run_pending(conn, limit=1)

        assert finished[0]["status"] == jobs.STATUS_FAILED
        snapshot = observability.job_snapshot()
        assert snapshot["duration_ms_sum"] == 3250
        assert snapshot["duration_ms_max"] == 3250

    def test_a_job_failure_under_a_request_carries_request_id(
        self, conn: sqlite3.Connection, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        observability.reset_job_stats()
        binary_path = tmp_path / "demo.exe"
        binary_path.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="bb" * 32, name="demo.exe", size=2, path=str(binary_path)
        )
        job = jobs.submit(conn, kind="secrets", binary_id=binary_id, params={})
        token = observability.set_request_id("inline-job-trace")
        try:
            with caplog.at_level(logging.ERROR, logger="reportal.jobs"):
                jobs.run_pending(conn, limit=1)
        finally:
            observability.reset_request_id(token)
        assert any(
            "job failed" in record.getMessage()
            and f"id={job['id']}" in record.getMessage()
            and "request_id=inline-job-trace" in record.getMessage()
            for record in caplog.records
        )

    def test_a_wedged_worker_tick_is_logged(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        worker = jobs.JobWorker(workers=1)

        def stop_after_wait(_timeout: float | None = None) -> bool:
            worker._stop.set()
            return True

        monkeypatch.setattr(
            jobs.store,
            "connect",
            mock.Mock(side_effect=OSError("database is locked")),
        )
        monkeypatch.setattr(worker._stop, "wait", stop_after_wait)
        with caplog.at_level(logging.WARNING, logger="reportal.jobs"):
            worker._loop()
        assert any(
            "job worker tick failed" in record.getMessage() and "OSError" in record.getMessage()
            for record in caplog.records
        )

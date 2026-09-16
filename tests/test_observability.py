"""Request correlation and process-local HTTP counters on the serving path."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

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

    def test_a_client_error_increments_4xx(self, portal_db: Path) -> None:
        observability.reset_http_stats()
        wsgi_request("GET", "/api/binaries/999999")
        snapshot = observability.http_snapshot()
        assert snapshot["requests"] >= 1
        assert snapshot["errors_4xx"] >= 1
        assert snapshot["errors_5xx"] == 0

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


class TestJobFailureLogging:
    def test_a_failed_job_is_logged(
        self, conn: sqlite3.Connection, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        binary_path = tmp_path / "demo.exe"
        binary_path.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="aa" * 32, name="demo.exe", size=2, path=str(binary_path)
        )
        job = jobs.submit(conn, kind="secrets", binary_id=binary_id, params={})
        with caplog.at_level(logging.WARNING, logger="reportal.jobs"):
            finished = jobs.run_pending(conn, limit=1)
        assert finished[0]["status"] == jobs.STATUS_FAILED
        assert any(
            "job failed" in record.getMessage() and f"id={job['id']}" in record.getMessage()
            for record in caplog.records
        )

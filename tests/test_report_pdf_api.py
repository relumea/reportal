"""Tests for the PDF report API routes."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request

from reportal import pdf, store


def _workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)


def _binary(conn: sqlite3.Connection) -> tuple[int, int]:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    return binary_id, analysis_id


def _seed_capabilities(conn: sqlite3.Connection, analysis_id: int, binary_id: int) -> None:
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_CAPABILITIES,
        {
            "binary_id": binary_id,
            "count": 1,
            "capabilities": [{"name": "network", "confidence": "high", "evidence_count": 2}],
        },
    )


class TestGeneratePdfRoute:
    def test_post_writes_file_and_returns_payload(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        binary_id, analysis_id = _binary(conn)
        _seed_capabilities(conn, analysis_id, binary_id)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/report/pdf")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["path"] == str(tmp_path / "reports" / str(binary_id) / "report.pdf")
        assert payload["bytes"] > 0
        assert payload["pages"] >= 1
        assert payload["download_url"] == f"/api/binaries/{binary_id}/report/pdf"
        written = Path(payload["path"])
        assert written.read_bytes().startswith(b"%PDF-1.4")
        assert payload["pages"] == pdf.page_count(written.read_bytes())

    def test_post_404_unknown_binary(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("POST", "/api/binaries/999/report/pdf")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_needs_no_engine(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        binary_id, _ = _binary(conn)
        status, _, _ = wsgi_request("POST", f"/api/binaries/{binary_id}/report/pdf")
        assert status.startswith("200")

    def test_post_renders_stored_scans(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        binary_id, analysis_id = _binary(conn)
        _seed_capabilities(conn, analysis_id, binary_id)
        wsgi_request("POST", f"/api/binaries/{binary_id}/report/pdf")
        data = (tmp_path / "reports" / str(binary_id) / "report.pdf").read_bytes()
        assert b"Capabilities" in data


class TestServePdfRoute:
    def test_get_serves_pdf_after_post(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        binary_id, _ = _binary(conn)
        wsgi_request("POST", f"/api/binaries/{binary_id}/report/pdf")
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/report/pdf")
        assert status.startswith("200")
        assert headers["Content-Type"] == "application/pdf"
        assert body.startswith(b"%PDF-1.4")
        assert body.endswith(b"%%EOF\n")

    def test_get_404_no_pdf_before_generate(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        binary_id, _ = _binary(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/report/pdf")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-pdf"
        assert "reportal report-pdf" in payload["detail"]

    def test_get_404_unknown_binary(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", "/api/binaries/999/report/pdf")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_download_url_roundtrip(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        binary_id, _ = _binary(conn)
        _, post_headers, created = wsgi_request("POST", f"/api/binaries/{binary_id}/report/pdf")
        download_url = json_body(created, post_headers)["download_url"]
        status, headers, body = wsgi_request("GET", download_url)
        assert status.startswith("200")
        assert headers["Content-Type"] == "application/pdf"
        assert body.startswith(b"%PDF-1.4")

    def test_html_report_routes_untouched(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        binary_id, _ = _binary(conn)
        wsgi_request("POST", f"/api/binaries/{binary_id}/report/pdf")
        # The PDF write creates the binary's report directory but no HTML site.
        status, _, body = wsgi_request("GET", f"/reports/{binary_id}/")
        assert status.startswith("404")
        assert not body.startswith(b"%PDF")
        assert not (tmp_path / "reports" / str(binary_id) / "index.html").exists()

    def test_html_report_route_still_reports_missing_site(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", "/reports/999/")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-report"

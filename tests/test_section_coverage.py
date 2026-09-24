"""Tests for the per-section byte coverage readout (store, API and CLI)."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, store
from reportal._paths import DB_ENV

runner = CliRunner()

IMAGE_BASE = 0x400000
TEXT_VA = 0x401000
TEXT_SIZE = 0x100
DATA_VA = 0x402000
DATA_SIZE = 0x80

PE_INFO: dict[str, object] = {
    "format": "pe",
    "arch": "x86_32",
    "image_base": IMAGE_BASE,
    "sections": [
        {"name": ".text", "virtual_address": TEXT_VA - IMAGE_BASE, "virtual_size": TEXT_SIZE},
        {"name": ".data", "virtual_address": DATA_VA - IMAGE_BASE, "virtual_size": DATA_SIZE},
    ],
}


def _seed(conn: sqlite3.Connection, *, with_scan: bool = True) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    if with_scan:
        store.set_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO, PE_INFO)
    return {"binary": binary_id, "analysis": analysis_id}


def _add_function(conn: sqlite3.Connection, analysis_id: int, *, va: int, size: int) -> int:
    return store.add_function(
        conn, analysis_id=analysis_id, va=va, name=f"sub_{va:x}", size=size, status="STUB"
    )


class TestStore:
    def test_overlapping_functions_are_not_double_counted(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _add_function(conn, ids["analysis"], va=TEXT_VA, size=0x40)
        _add_function(conn, ids["analysis"], va=TEXT_VA + 0x20, size=0x40)
        coverage = store.section_byte_coverage(conn, ids["binary"])
        assert coverage is not None
        text = coverage["sections"][0]
        assert text["name"] == ".text"
        assert text["covered"] == 0x60
        assert text["uncovered"] == TEXT_SIZE - 0x60
        assert text["size"] == TEXT_SIZE
        assert text["coverage_pct"] == 37.5

    def test_a_function_straddling_the_section_end_is_clipped(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        _add_function(conn, ids["analysis"], va=TEXT_VA + TEXT_SIZE - 0x10, size=0x40)
        coverage = store.section_byte_coverage(conn, ids["binary"])
        assert coverage is not None
        text = coverage["sections"][0]
        assert text["covered"] == 0x10
        assert coverage["totals"]["covered"] == 0x10

    def test_functions_in_different_sections_are_summed(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _add_function(conn, ids["analysis"], va=TEXT_VA, size=0x20)
        _add_function(conn, ids["analysis"], va=DATA_VA, size=0x10)
        coverage = store.section_byte_coverage(conn, ids["binary"])
        assert coverage is not None
        assert [section["covered"] for section in coverage["sections"]] == [0x20, 0x10]
        assert coverage["totals"]["covered"] == 0x30
        assert coverage["totals"]["size"] == TEXT_SIZE + DATA_SIZE

    def test_a_function_outside_every_section_contributes_nothing(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        _add_function(conn, ids["analysis"], va=0x409000, size=0x10)
        coverage = store.section_byte_coverage(conn, ids["binary"])
        assert coverage is not None
        assert coverage["function_count"] == 1
        assert coverage["totals"]["covered"] == 0

    def test_no_pe_info_scan_returns_none(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, with_scan=False)
        _add_function(conn, ids["analysis"], va=TEXT_VA, size=0x10)
        assert store.section_byte_coverage(conn, ids["binary"]) is None

    def test_no_functions_reports_null_percentages(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        coverage = store.section_byte_coverage(conn, ids["binary"])
        assert coverage is not None
        assert coverage["function_count"] == 0
        assert coverage["totals"]["covered"] == 0
        assert coverage["totals"]["coverage_pct"] is None
        assert all(section["coverage_pct"] is None for section in coverage["sections"])
        assert "no stored functions" in coverage["note"]
        assert coverage["note"].startswith("measured over the stored function table")

    def test_the_note_names_the_metric_as_reportal_s_own(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _add_function(conn, ids["analysis"], va=TEXT_VA, size=0x10)
        coverage = store.section_byte_coverage(conn, ids["binary"])
        assert coverage is not None
        assert coverage["note"] == store.FUNCTION_COVERAGE_NOTE


class TestApiRoute:
    def test_route_reports_coverage(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _add_function(conn, ids["analysis"], va=TEXT_VA, size=0x40)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/section-coverage"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == ids["binary"]
        assert payload["sections"][0]["covered"] == 0x40
        assert payload["totals"]["coverage_pct"] == 16.7

    def test_route_without_a_scan_is_404_no_scan(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, with_scan=False)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/section-coverage"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_route_unknown_binary_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/section-coverage")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_route_zero_functions_reports_null_percentages(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/section-coverage"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["totals"]["coverage_pct"] is None
        assert "no stored functions" in payload["note"]


class TestCli:
    def _workspace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_scan: bool
    ) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            ids = _seed(conn, with_scan=with_scan)
            if with_scan:
                _add_function(conn, ids["analysis"], va=TEXT_VA, size=0x40)
        return ids["binary"]

    def test_command_reports_coverage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._workspace(tmp_path, monkeypatch, with_scan=True)
        result = runner.invoke(cli.app, ["section-coverage", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["sections"][0]["covered"] == 0x40
        assert payload["note"] == store.FUNCTION_COVERAGE_NOTE

    def test_command_without_a_scan_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._workspace(tmp_path, monkeypatch, with_scan=False)
        result = runner.invoke(cli.app, ["section-coverage", str(binary_id)])
        assert result.exit_code != 0
        assert "no pe-info scan" in result.output

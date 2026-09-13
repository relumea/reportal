"""Tests for the function references route: globals, callers and callees."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

import pytest
from conftest import PE_INFO, FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, engines, store
from reportal._paths import DB_ENV

runner = CliRunner()

PROJECT_DIR = "/projects/notepad-rebrew"


def _seed(conn: sqlite3.Connection, *, stored_pe_info: bool = True) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="12" * 32, name="demo.exe", path="/x/demo.exe")
    store.set_rebrew_context(conn, binary_id, PROJECT_DIR)
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=32, status="STUB"
    )
    if stored_pe_info:
        store.set_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO, dict(PE_INFO))
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id}


class TestRoute:
    def test_globals_carry_an_address_section_and_access(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["function_id"] == ids["function"]
        assert payload["va"] == 0x1000
        assert payload["globals"] == [
            {"address": 0x408000, "kind": "mov_mem", "access": "read", "section": ".data"},
            {"address": 0x408004, "kind": "mov_mem_store", "access": "write", "section": ".data"},
            {"address": 0x408008, "kind": "lea", "access": None, "section": ".data"},
        ]
        assert fake_engine.describe_args == (PROJECT_DIR, 0x1000)
        assert fake_engine.calls == ["describe"]

    def test_callers_and_callees_rows(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        payload = json_body(body, headers)
        assert payload["callers"] == [{"from_va": 0x1100, "name": "caller"}]
        assert payload["callees"] == [
            {"to_va": 0x1200, "name": "helper", "kind": "call", "indirect": False},
            {"to_va": 0x40104C, "name": None, "kind": "iat_call", "indirect": True},
        ]

    def test_counts_match_the_row_counts(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        payload = json_body(body, headers)
        assert payload["counts"] == {
            "globals": len(payload["globals"]),
            "callers": len(payload["callers"]),
            "callees": len(payload["callees"]),
        }
        assert "call sites" in payload["count_note"]

    def test_an_indirect_call_with_no_target_says_so(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        indirect = [row for row in json_body(body, headers)["callees"] if row["indirect"]]
        assert indirect == [{"to_va": 0x40104C, "name": None, "kind": "iat_call", "indirect": True}]

    def test_without_a_stored_section_table_the_section_stays_null(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, stored_pe_info=False)
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        payload = json_body(body, headers)
        assert [row["section"] for row in payload["globals"]] == [None, None, None]

    def test_an_address_outside_every_section_stays_null(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def describe(*args: object, **kwargs: object) -> dict[str, object]:
            return {
                "va": 0x1000,
                "globals": [{"va": 0x500000, "kind": "mov_mem"}],
                "callers": [],
                "callees": [],
            }

        monkeypatch.setattr(fake_engine, "describe", describe)
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        assert json_body(body, headers)["globals"][0]["section"] is None

    def test_a_malformed_dossier_entry_is_skipped(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def describe(*args: object, **kwargs: object) -> dict[str, object]:
            return {
                "va": 0x1000,
                "globals": ["nonsense", {"va": "soon", "kind": "mov_mem"}],
                "callers": [{"from_va": "soon", "name": "x"}],
                "callees": [{"to_va": "soon", "kind": "call"}],
            }

        monkeypatch.setattr(fake_engine, "describe", describe)
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        payload = json_body(body, headers)
        assert payload["globals"] == []
        assert payload["callers"] == []
        assert payload["callees"] == []
        assert payload["counts"] == {"globals": 0, "callers": 0, "callees": 0}

    def test_unknown_function_is_404(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/references")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_without_a_project_context_is_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="34" * 32, name="plain.exe", path="/x/plain.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=32, status="STUB"
        )
        status, headers, body = wsgi_request("GET", f"/api/functions/{function_id}/references")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"
        assert fake_engine.calls == []

    def test_without_an_engine_is_503(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        ids = _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_an_engine_failure_is_500(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew describe exited with code 2")

        monkeypatch.setattr(fake_engine, "describe", boom)
        ids = _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/references")
        assert status.startswith("500")
        assert json_body(body, headers)["error"] == "engine-error"


class TestCli:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            return _seed(conn)["function"]

    def test_references_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        function_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["references", str(function_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        # The command mirrors the engine's dossier; the API adds reportal's
        # section and access annotation on top of it.
        assert payload["globals"][0] == {"va": 0x408000, "kind": "mov_mem"}
        assert payload["callees"][1]["kind"] == "iat_call"

    def test_references_command_human(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        function_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["references", str(function_id)])
        assert result.exit_code == 0, result.output

    def test_references_command_with_nothing_resolved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def empty(*args: object, **kwargs: object) -> dict[str, object]:
            return {"va": 0x1000, "callers": [], "callees": [], "globals": []}

        monkeypatch.setattr(fake_engine, "describe", empty)
        function_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["references", str(function_id)])
        assert result.exit_code == 0, result.output

    def test_references_command_without_a_context_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="ab" * 32, name="plain.exe", path="/x/p.exe")
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
            function_id = store.add_function(
                conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=32, status="STUB"
            )
        result = runner.invoke(cli.app, ["references", str(function_id)])
        assert result.exit_code != 0
        assert "no rebrew project context" in result.output

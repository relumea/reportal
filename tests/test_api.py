"""Tests for the reportal JSON API and UI routes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from urllib.parse import unquote

import pytest
from conftest import (
    AI_COMMENTS_RESPONSE,
    AI_SUMMARY_RESPONSE,
    AI_TYPES_RESPONSE,
    CRYPTO,
    FINGERPRINT,
    PE_INFO,
    SECURITY,
    FailingLlmClient,
    FakeEngine,
    FakeLlmClient,
    decode,
    json_body,
    wsgi_request,
)

from reportal import (
    analysis_log,
    auth,
    auto_store,
    behavior,
    conversations,
    engines,
    error_docs,
    filetypes,
    hardening,
    llm,
    matching,
    observability,
    similarity,
    store,
    ui,
)
from reportal._paths import DB_ENV
from reportal.api import DEFAULT_STRUCT_LIMIT


def _assert_scan_failed(conn: sqlite3.Connection, binary_id: int, kind: str) -> None:
    """A failed scan leaves the analysis carrier `failed`, with an error entry.

    A scan that could not run is not silently complete: the analysis exists,
    its status says failed, and its log carries an error-severity entry naming
    the scan.
    """
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    assert analysis_id is not None
    analysis = store.get_analysis(conn, analysis_id)
    assert analysis is not None
    assert analysis["status"] == store.ANALYSIS_STATUS_FAILED
    entries, _total = analysis_log.list_entries(conn, analysis_id)
    failed = [entry for entry in entries if entry["severity"] == analysis_log.SEVERITY_ERROR]
    assert any(kind in str(entry["message"]) for entry in failed)


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=48, status="STUB"
    )
    second = store.add_function(
        conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16, status="EXACT"
    )
    store.record_match(
        conn,
        function_id=function_id,
        candidate_function_id=second,
        similarity=0.75,
        confidence=0.6,
    )
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id, "second": second}


class TestHealth:
    def test_health_ok(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/health")
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("application/json")
        payload = json_body(body, headers)
        assert payload["status"] == "ok"
        assert payload["version"]
        assert payload["db"] == str(portal_db)
        assert set(payload["counts"]) >= {"binaries", "analyses", "functions", "matched"}

    def test_health_reports_every_dependency(self, portal_db: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        observability.reset_job_stats()
        _, headers, body = wsgi_request("GET", "/api/health")
        payload = json_body(body, headers)
        assert payload["failures"] == []
        dependencies = payload["dependencies"]
        assert dependencies["database"]["writable"] is True
        assert dependencies["database"]["detail"] == ""
        assert dependencies["engine"]["available"] is False
        assert dependencies["engine"]["origin"] is None
        assert dependencies["auto"]["last_run"] is None
        assert dependencies["jobs"]["queued"] == 0
        assert dependencies["jobs"]["running"] == 0
        assert isinstance(dependencies["jobs"]["pool"], bool)
        assert payload["jobs"] == {
            "done": 0,
            "failed": 0,
            "duration_ms_sum": 0,
            "duration_ms_max": 0,
        }

    def test_health_reports_the_engine_when_resolvable(
        self, portal_db: Path, fake_engine: FakeEngine
    ) -> None:
        _, headers, body = wsgi_request("GET", "/api/health")
        engine = json_body(body, headers)["dependencies"]["engine"]
        assert engine["available"] is True
        assert engine["origin"] == "/fake/bin/rebrew"

    def test_health_reports_a_read_only_database_without_raising(self, portal_db: Path) -> None:
        portal_db.chmod(0o444)
        status, headers, body = wsgi_request("GET", "/api/health")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["status"] == "ok"
        assert payload["dependencies"]["database"]["writable"] is False
        assert payload["dependencies"]["database"]["detail"]
        assert payload["failures"] == ["database"]

    def test_health_reports_the_last_auto_run(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        run_id = auto_store.create_auto_run(conn, binary_id=ids["binary"], config={})
        _, headers, body = wsgi_request("GET", "/api/health")
        last = json_body(body, headers)["dependencies"]["auto"]["last_run"]
        assert last["run_id"] == run_id
        assert last["binary_id"] == ids["binary"]
        assert last["status"] == auto_store.AUTO_RUN_RUNNING
        assert last["finished_at"] is None

    def test_health_keeps_its_existing_keys(self, portal_db: Path) -> None:
        _, headers, body = wsgi_request("GET", "/api/health")
        payload = json_body(body, headers)
        assert {"status", "version", "db", "counts"} <= set(payload)
        assert {"dependencies", "failures"} <= set(payload)


class TestBinaries:
    def test_list_empty(self, portal_db: Path) -> None:
        _, headers, body = wsgi_request("GET", "/api/binaries")
        payload = json_body(body, headers)
        assert payload["binaries"] == []
        assert payload["count"] == 0
        assert payload["total"] == 0
        assert payload["order"] == "id"
        assert payload["formats"] == []
        assert payload["languages"] == []
        assert payload["compilers"] == []

    def test_the_register_filters_orders_and_echoes(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_binary(conn, sha256="bb" * 32, name="alpha.exe", size=9, fmt="ELF")
        store.add_binary(conn, sha256="cc" * 32, name="gamma.exe", size=30, fmt="PE")
        store.add_binary_tag(conn, ids["binary"], store.create_tag(conn, "packed"))

        status, headers, body = wsgi_request("GET", "/api/binaries?order=name")
        payload = json_body(body, headers)
        assert status.startswith("200")
        assert [row["name"] for row in payload["binaries"]] == [
            "alpha.exe",
            "demo.exe",
            "gamma.exe",
        ]
        assert payload["count"] == 3
        assert payload["total"] == 3
        assert payload["order"] == "name"
        assert payload["formats"] == ["ELF", "PE"]
        assert payload["languages"] == []
        assert payload["compilers"] == []

        # Each filter narrows the register and is echoed back.
        _status, headers, body = wsgi_request("GET", "/api/binaries?search=cc")
        assert [row["name"] for row in json_body(body, headers)["binaries"]] == ["gamma.exe"]
        _status, headers, body = wsgi_request("GET", "/api/binaries?search=" + "aa" * 32)
        assert [row["name"] for row in json_body(body, headers)["binaries"]] == ["demo.exe"]
        _status, headers, body = wsgi_request("GET", "/api/binaries?tag=packed")
        payload = json_body(body, headers)
        assert [row["name"] for row in payload["binaries"]] == ["demo.exe"]
        assert payload["tag"] == "packed"
        assert payload["total"] == 3
        _status, headers, body = wsgi_request("GET", "/api/binaries?format=ELF")
        assert [row["name"] for row in json_body(body, headers)["binaries"]] == ["alpha.exe"]
        store.set_binary_language(conn, ids["binary"], "Go")
        _status, headers, body = wsgi_request("GET", "/api/binaries?language=Go")
        payload = json_body(body, headers)
        assert [row["name"] for row in payload["binaries"]] == ["demo.exe"]
        assert payload["language"] == "Go"
        assert payload["languages"] == ["Go"]
        store.set_binary_compiler(conn, ids["binary"], "MinGW GCC")
        _status, headers, body = wsgi_request("GET", "/api/binaries?compiler=MinGW+GCC")
        payload = json_body(body, headers)
        assert [row["name"] for row in payload["binaries"]] == ["demo.exe"]
        assert payload["compiler"] == "MinGW GCC"
        assert payload["compilers"] == ["MinGW GCC"]

        # A filter that matches nothing is distinguishable from an empty register.
        _status, headers, body = wsgi_request("GET", "/api/binaries?search=absent")
        payload = json_body(body, headers)
        assert payload["count"] == 0
        assert payload["total"] == 3

    def test_an_unknown_register_order_is_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries?order=biggest")

        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid order"

    def test_list_and_get(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", "/api/binaries")
        assert [b["name"] for b in json_body(body, headers)["binaries"]] == ["demo.exe"]

        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}")
        assert json_body(body, headers)["sha256"] == "aa" * 32

    def test_get_missing_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_rename_sets_the_display_name(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/binaries/{ids['binary']}",
            body=json.dumps({"name": "  renamed.exe  "}).encode(),
        )
        payload = json_body(body, headers)
        assert status.startswith("200")
        assert payload["name"] == "renamed.exe"
        assert payload["sha256"] == "aa" * 32
        assert payload["journal_action"]
        stored = store.get_binary(conn, ids["binary"])
        assert stored is not None
        assert stored["name"] == "renamed.exe"

    def test_rename_refuses_an_empty_or_missing_name(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "PATCH", f"/api/binaries/{ids['binary']}", body=json.dumps({}).encode()
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid binary"

        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/binaries/{ids['binary']}",
            body=json.dumps({"name": "   "}).encode(),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid binary"
        stored = store.get_binary(conn, ids["binary"])
        assert stored is not None
        assert stored["name"] == "demo.exe"

    def test_notes_set_and_clear(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/binaries/{ids['binary']}",
            body=json.dumps({"notes": "  vendor sample  "}).encode(),
        )
        payload = json_body(body, headers)
        assert status.startswith("200")
        assert payload["notes"] == "vendor sample"
        assert payload["name"] == "demo.exe"
        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/binaries/{ids['binary']}",
            body=json.dumps({"notes": "   "}).encode(),
        )
        payload = json_body(body, headers)
        assert status.startswith("200")
        assert payload["notes"] == ""

    def test_rename_unknown_is_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "PATCH", "/api/binaries/999", body=json.dumps({"name": "gone.exe"}).encode()
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_get_names_the_rebrew_project_or_none(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}")
        assert json_body(body, headers)["rebrew_project"] is None

        store.set_rebrew_context(conn, ids["binary"], "/projects/demo-rebrew")
        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}")

        assert json_body(body, headers)["rebrew_project"] == "/projects/demo-rebrew"

    def test_functions_for_binary(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/functions")
        assert len(json_body(body, headers)["functions"]) == 2

    def test_functions_page_is_a_window_over_the_same_order(self, conn: sqlite3.Connection) -> None:
        """A page carries its slice and still reports what the filters kept."""
        ids = _seed(conn)
        binary = ids["binary"]
        _, headers, body = wsgi_request("GET", f"/api/binaries/{binary}/functions")
        every = [row["id"] for row in json_body(body, headers)["functions"]]

        _, headers, body = wsgi_request("GET", f"/api/binaries/{binary}/functions?limit=1")
        first = json_body(body, headers)
        _, headers, body = wsgi_request("GET", f"/api/binaries/{binary}/functions?limit=1&offset=1")
        second = json_body(body, headers)

        assert [row["id"] for row in first["functions"]] == every[:1]
        assert [row["id"] for row in second["functions"]] == every[1:2]
        assert first["count"] == second["count"] == 1
        assert first["matched"] == second["matched"] == 2, "the page never shrinks the match count"
        assert first["total"] == 2

    def test_functions_page_counts_matches_behind_a_filter(self, conn: sqlite3.Connection) -> None:
        """`matched` counts the filter's whole result, not the page it was cut to."""
        ids = _seed(conn)
        path = f"/api/binaries/{ids['binary']}/functions?name=sub_&limit=1"
        _, headers, body = wsgi_request("GET", path)
        payload = json_body(body, headers)

        assert payload["count"] == 1
        assert payload["matched"] == 2
        assert payload["total"] == 2

    def test_functions_page_applies_after_a_python_filter(self, conn: sqlite3.Connection) -> None:
        """A filter this handler evaluates in Python still sees every row first."""
        ids = _seed(conn)
        # Both seeded names are decompiler placeholders, which is the label the
        # handler derives in Python rather than one SQLite could filter on.
        path = f"/api/binaries/{ids['binary']}/functions?name_source=No%20Debug%20Info"
        _, headers, body = wsgi_request("GET", path)
        unpaged = json_body(body, headers)
        _, headers, body = wsgi_request("GET", f"{path}&limit=1")
        paged = json_body(body, headers)

        assert unpaged["count"] == 2, "both seeded rows read as No Debug Info"
        assert paged["count"] == 1
        assert paged["matched"] == unpaged["matched"] == 2
        assert [row["id"] for row in paged["functions"]] == [
            row["id"] for row in unpaged["functions"]
        ][:1]

    def test_functions_refuse_an_out_of_range_page(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        binary = ids["binary"]
        over = store.MAX_FUNCTION_LIMIT + 1

        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary}/functions?limit={over}"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid limit"

        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary}/functions?offset=-1")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid offset"

    def test_function_rollup_counts_without_the_rows(self, conn: sqlite3.Connection) -> None:
        """The summary numbers come back without the function list they replace."""
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/function-rollup")
        payload = json_body(body, headers)

        assert payload == {
            "binary_id": ids["binary"],
            "total": 2,
            "matched": 1,
            "by_status": {"EXACT": 1, "STUB": 1},
        }
        assert "functions" not in payload

    def test_function_rollup_for_a_missing_binary_is_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/function-rollup")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_functions_list_includes_thunk_rows(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_function(
            conn,
            analysis_id=ids["analysis"],
            va=0x10030C6,
            name="ChooseFontW",
            size=6,
            status="THUNK",
            name_source="import",
        )
        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/functions")
        functions = json_body(body, headers)["functions"]
        assert [function["status"] for function in functions] == ["STUB", "EXACT", "THUNK"]
        thunk = functions[2]
        assert thunk["va"] == 0x10030C6
        assert thunk["name"] == "ChooseFontW"
        assert thunk["name_source"] == "import"
        assert thunk["size"] == 6

    def test_thunk_detail_route_returns_the_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        function_id = store.add_function(
            conn,
            analysis_id=ids["analysis"],
            va=0x10030C6,
            name="ChooseFontW",
            size=6,
            status="THUNK",
            name_source="import",
        )
        status, headers, body = wsgi_request("GET", f"/api/functions/{function_id}")
        assert status.startswith("200")
        assert json_body(body, headers)["status"] == "THUNK"

    def test_search_finds_a_thunk_name(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_function(
            conn,
            analysis_id=ids["analysis"],
            va=0x10030C6,
            name="ChooseFontW",
            size=6,
            status="THUNK",
            name_source="import",
        )
        _, headers, body = wsgi_request("GET", "/api/search?q=ChooseFont")
        functions = json_body(body, headers)["functions"]
        assert [function["name"] for function in functions] == ["ChooseFontW"]

    def test_functions_unknown_binary_404(self, portal_db: Path) -> None:
        status, _, _ = wsgi_request("GET", "/api/binaries/12/functions")
        assert status.startswith("404")


class TestEngineRoutes:
    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path=str(target))

    def test_fingerprint_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/fingerprint")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_fingerprint_404_unknown_id(self, portal_db: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", "/api/binaries/999/fingerprint")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_fingerprint_400_without_path(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="cd" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/fingerprint")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"

    def test_fingerprint_get_computes_live_without_storing(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/fingerprint")
        assert status.startswith("200")
        assert json_body(body, headers) == FINGERPRINT
        assert fake_engine.calls == ["fingerprint"]
        assert store.get_fingerprint(conn, binary_id) is None

    def test_fingerprint_post_stores_then_get_returns_stored(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/fingerprint")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload.pop("journal_action")
        assert payload == FINGERPRINT
        assert store.get_fingerprint(conn, binary_id) == FINGERPRINT

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/fingerprint")
        assert status.startswith("200")
        assert json_body(body, headers) == FINGERPRINT

    def test_imports_passthrough(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/imports")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [entry["name"] for entry in payload["imports"]] == ["GetTickCount"]

    def test_strings_passthrough(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/strings")
        assert status.startswith("200")
        # A bare-text engine entry normalizes to the route's row shape with the
        # fields the engine did not report left null rather than filled in.
        assert json_body(body, headers)["strings"] == [
            {"va": None, "section": None, "kind": None, "size": 5, "text": "hello"}
        ]

    def test_imports_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/imports")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_strings_404_unknown_id(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, _, _ = wsgi_request("GET", "/api/binaries/999/strings")
        assert status.startswith("404")


class TestFunctions:
    def test_get_missing_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/7")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_rename_and_history(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/rename",
            body=json.dumps({"name": "parse_header", "actor": "api-test"}),
        )
        assert status.startswith("200")
        assert json_body(body, headers)["new_name"] == "parse_header"

        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/history")
        history = json_body(body, headers)["history"]
        assert len(history) == 1
        assert history[0]["actor"] == "api-test"

    def test_rename_bad_body_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['function']}/rename", body="{not json"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid JSON body"

    def test_rename_missing_name_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, _, _ = wsgi_request(
            "POST", f"/api/functions/{ids['function']}/rename", body=json.dumps({"actor": "x"})
        )
        assert status.startswith("400")

    def test_rename_unknown_404(self, portal_db: Path) -> None:
        status, _, _ = wsgi_request(
            "POST", "/api/functions/321/rename", body=json.dumps({"name": "x"})
        )
        assert status.startswith("404")

    def test_matches(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/matches")
        matches = json_body(body, headers)["matches"]
        assert len(matches) == 1
        assert matches[0]["candidate_name"] == "sub_2000"

    def test_history_unknown_404(self, portal_db: Path) -> None:
        status, _, _ = wsgi_request("GET", "/api/functions/321/history")
        assert status.startswith("404")


class TestRevert:
    def _with_history(self, conn: sqlite3.Connection) -> tuple[dict[str, int], int]:
        ids = _seed(conn)
        store.rename_function(conn, ids["function"], new_name="parse_header", actor="tester")
        history_id = int(store.list_name_history(conn, ids["function"])[0]["id"])
        return ids, history_id

    def test_revert_restores_name(self, conn: sqlite3.Connection) -> None:
        ids, history_id = self._with_history(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['function']}/history/{history_id}/revert"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload.pop("journal_action")
        assert payload == {
            "function_id": ids["function"],
            "history_id": history_id,
            "name": "sub_1000",
        }
        function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "sub_1000"
        assert len(store.list_name_history(conn, ids["function"])) == 2

    def test_revert_unknown_function_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/functions/999/history/1/revert")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_revert_unknown_history_404(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['function']}/history/4242/revert"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "history not found"

    def test_revert_mismatched_history_404(self, conn: sqlite3.Connection) -> None:
        ids, history_id = self._with_history(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['second']}/history/{history_id}/revert"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "history not found"
        function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "parse_header"


class TestApplyMatch:
    def test_apply_match_renames_and_records_match_source(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/apply-match",
            body=json.dumps({"candidate_function_id": ids["second"]}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload.pop("journal_action")
        assert payload == {
            "function_id": ids["function"],
            "candidate_function_id": ids["second"],
            "mode": "name",
            "status": "applied",
            "reason": "",
            "detail": "",
            "name_changed": True,
            "old_name": "sub_1000",
            "new_name": "sub_2000",
            "signature_changed": False,
            "missing_types": [],
        }
        function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "sub_2000"
        assert function["name_source"] == "match"
        history = store.list_name_history(conn, ids["function"])
        assert history[0]["source"] == "match"
        assert history[0]["old_name"] == "sub_1000"
        assert history[0]["actor"] == "api"

    def test_apply_match_no_such_match_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['second']}/apply-match",
            body=json.dumps({"candidate_function_id": ids["function"]}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-such-match"

    def test_apply_match_candidate_without_name_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        nameless = store.add_function(conn, analysis_id=ids["analysis"], va=0x3000, name="", size=8)
        store.record_match(
            conn,
            function_id=ids["function"],
            candidate_function_id=nameless,
            similarity=0.5,
            confidence=0.5,
        )
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/apply-match",
            body=json.dumps({"candidate_function_id": nameless}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "candidate-has-no-name"

    def test_apply_match_unknown_function_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/functions/999/apply-match", body=json.dumps({"candidate_function_id": 1})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_apply_match_unknown_candidate_404(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/apply-match",
            body=json.dumps({"candidate_function_id": 999}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "candidate not found"

    def test_apply_match_missing_candidate_id_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['function']}/apply-match", body="{}"
        )
        assert status.startswith("400")
        assert "candidate_function_id" in json_body(body, headers)["error"]


class TestDisasm:
    def _seed_with_context(self, conn: sqlite3.Connection) -> dict[str, int]:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["binary"], "/projects/notepad-rebrew")
        return ids

    def test_disasm_nasm(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/disasm")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["va"] == 0x1000
        assert payload["size"] == 48
        assert payload["format"] == "nasm"
        assert payload["disasm"].startswith("bits 32")
        assert "0x1000" in payload["disasm"]
        assert fake_engine.calls == ["disassemble"]

    def test_disasm_hex_format(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/disasm?format=hex"
        )
        assert status.startswith("200")
        assert json_body(body, headers)["format"] == "hex"

    def test_disasm_unknown_function_404(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/disasm")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_disasm_without_context_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/disasm")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"

    def test_disasm_bad_format_400(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/disasm?format=json"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid format"

    def test_disasm_without_engine_503(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/disasm")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_disasm_engine_error_500(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> str:
            raise engines.EngineError("rebrew asm exited with code 1: bad va")

        monkeypatch.setattr(fake_engine, "disassemble", boom)
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/disasm")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad va" in payload["detail"]

    def test_disasm_second_call_uses_cache(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        wsgi_request("GET", f"/api/functions/{ids['function']}/disasm")
        status, _, _ = wsgi_request("GET", f"/api/functions/{ids['function']}/disasm")
        assert status.startswith("200")
        assert fake_engine.calls == ["disassemble"]
        assert store.get_disasm(conn, ids["function"]) is not None

    def test_disasm_hex_is_not_cached(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        wsgi_request("GET", f"/api/functions/{ids['function']}/disasm?format=hex")
        wsgi_request("GET", f"/api/functions/{ids['function']}/disasm?format=hex")
        assert fake_engine.calls == ["disassemble", "disassemble"]
        assert store.get_disasm(conn, ids["function"]) is None


class TestDecompilation:
    def _seed_with_context(self, conn: sqlite3.Connection) -> dict[str, int]:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["binary"], "/projects/notepad-rebrew")
        return ids

    def test_get_computes_live_without_storing(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/decompilation"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["va"] == 0x1000
        assert payload["backend"] == "kuna"
        assert payload["named"] is False
        assert "sub_1000" in payload["code"]
        assert fake_engine.calls == ["decompile"]
        assert store.get_decompilation(conn, ids["function"]) is None

    def test_post_stores_then_get_returns_stored(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/decompilation",
            body=json.dumps({"backend": "r2ghidra"}),
        )
        assert status.startswith("200")
        assert json_body(body, headers)["backend"] == "r2ghidra"
        stored = store.get_decompilation(conn, ids["function"])
        assert stored is not None
        assert stored["backend"] == "r2ghidra"

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/decompilation"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["code"] == stored["code"]
        assert payload["backend"] == "r2ghidra"

    def test_post_defaults_to_kuna_and_unnamed(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['function']}/decompilation", body="{}"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["backend"] == "kuna"
        assert payload["named"] is False
        assert payload["va"] == 0x1000

    def test_get_named_query_reaches_engine(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/decompilation?named=true"
        )
        assert status.startswith("200")
        assert json_body(body, headers)["named"] is True

    def test_get_unknown_function_404(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/decompilation")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_post_unknown_function_404(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/functions/999/decompilation", body="{}")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_get_without_context_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/decompilation"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"

    def test_get_unknown_backend_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/decompilation?backend=ida"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid backend"

    def test_post_unknown_backend_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/decompilation",
            body=json.dumps({"backend": "ida"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid backend"

    def test_post_non_boolean_named_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/decompilation",
            body=json.dumps({"named": "yes"}),
        )
        assert status.startswith("400")
        assert "named" in json_body(body, headers)["error"]

    def test_get_without_engine_503(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/decompilation"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_post_without_engine_503(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['function']}/decompilation", body="{}"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_engine_error_500(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew decompile exited with code 1: no backend")

        monkeypatch.setattr(fake_engine, "decompile", boom)
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/decompilation"
        )
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "no backend" in payload["detail"]

    def test_stored_survives_engine_error(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        store.set_decompilation(conn, ids["function"], "int f(void) {}", "kuna")

        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("boom")

        monkeypatch.setattr(fake_engine, "decompile", boom)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/decompilation"
        )
        assert status.startswith("200")
        assert json_body(body, headers)["code"] == "int f(void) {}"


class TestMatchRoute:
    def _seed_with_context(self, conn: sqlite3.Connection) -> dict[str, int]:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["binary"], "/projects/notepad-rebrew")
        return ids

    def test_match_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/match", body="{}")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_match_400_bad_min_similarity(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/binaries/1/match", body=json.dumps({"min_similarity": "high"})
        )
        assert status.startswith("400")
        assert "min_similarity" in json_body(body, headers)["error"]

    def test_match_400_non_positive_top(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(similarity, "available", lambda: True)
        ids = self._seed_with_context(conn)
        status, _, _ = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/match", body=json.dumps({"top": 0})
        )
        assert status.startswith("400")

    def test_match_503_without_engine(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_context(conn)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/match", body="{}"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_match_503_without_similarity(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed_with_context(conn)
        monkeypatch.setattr(similarity, "available", lambda: False)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/match", body="{}"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "similarity-unavailable"

    def test_match_200_with_injected_scorer(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed_with_context(conn)
        monkeypatch.setattr(similarity, "available", lambda: True)
        monkeypatch.setattr(similarity, "similarity", lambda left, right: 90.0)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/match",
            body=json.dumps({"min_similarity": 80, "top": 2}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload.pop("journal_action")
        assert payload == {
            "functions": 2,
            "matched": 2,
            "pairs": 2,
            "binary_id": ids["binary"],
            "settings": {
                "min_similarity": 80.0,
                "min_confidence": 0.0,
                "include_self": True,
                "top": 2,
                "platforms": [],
                "architectures": [],
                "binary_ids": [],
                "collection_ids": [],
            },
            "notes": [],
        }

    def test_match_engine_error_500(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed_with_context(conn)
        monkeypatch.setattr(similarity, "available", lambda: True)

        def boom(*args: object, **kwargs: object) -> dict[str, int]:
            raise engines.EngineError("rebrew asm exited with code 1")

        monkeypatch.setattr(matching, "match_binary", boom)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/match", body="{}"
        )
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "exited with code 1" in payload["detail"]

    def test_match_400_unknown_platform(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/match",
            body=json.dumps({"platforms": ["beos"]}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid platform"

    def test_match_400_min_confidence_out_of_range(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/match",
            body=json.dumps({"min_confidence": 2}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid min_confidence"

    def test_match_400_unknown_binary_scope(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed_with_context(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/match",
            body=json.dumps({"binary_ids": [999]}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "unknown binary"

    def test_match_records_settings_and_get_round_trips(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed_with_context(conn)
        store.set_fingerprint(conn, ids["binary"], {"format": "pe", "arch": "x86_32"})
        monkeypatch.setattr(similarity, "available", lambda: True)
        monkeypatch.setattr(similarity, "similarity", lambda left, right: 90.0)
        body = json.dumps(
            {
                "min_similarity": 80,
                "min_confidence": 0.0,
                "top": 3,
                "include_self": True,
                "platforms": ["windows"],
                "architectures": ["x86_32"],
            }
        )
        status, headers, raw = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/match", body=body
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["settings"]["platforms"] == ["windows"]
        assert payload["settings"]["architectures"] == ["x86_32"]
        assert payload["notes"] == [matching.PLATFORM_SCOPE_NOTE]
        assert payload["pairs"] == 2

        status, headers, raw = wsgi_request("GET", f"/api/binaries/{ids['binary']}/matches")
        stored = json_body(raw, headers)
        assert stored["settings"] == payload["settings"]
        assert stored["count"] == 2
        assert stored["matches"][0]["difference"] == 10.0
        assert stored["matches"][0]["band"] == "Match"
        assert stored["matches"][0]["settings"] == payload["settings"]


class TestMatchMetrics:
    def test_function_matches_payload_carries_metrics(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.record_match(
            conn,
            function_id=ids["function"],
            candidate_function_id=ids["second"],
            similarity=97.5,
            confidence=0.9,
        )
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/matches")
        assert status.startswith("200")
        row = json_body(body, headers)["matches"][0]
        assert row["similarity"] == pytest.approx(97.5)
        assert row["difference"] == pytest.approx(2.5)
        assert row["band"] == "Strong Match"

    def test_binary_matches_get_is_stored_only_and_notes_missing_settings(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/matches")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["settings"] is None
        assert payload["notes"]
        assert payload["matches"][0]["difference"] == pytest.approx(99.2)

    def test_binary_matches_survives_unreadable_recorded_settings(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        # A stored payload the tool never writes: the read reports it as
        # unreadable rather than failing.
        store.record_match(
            conn,
            function_id=ids["function"],
            candidate_function_id=ids["second"],
            similarity=90.0,
            confidence=0.5,
            settings={"platforms": "windows"},
        )
        status, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/matches")
        assert status.startswith("200")
        assert json_body(body, headers)["notes"] == ["the recorded settings are not readable"]

    def test_binary_matches_404_unknown_binary(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/matches")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


class TestApplyMatchModes:
    def _seed_signatures(self, conn: sqlite3.Connection) -> dict[str, int]:
        ids = _seed(conn)
        store.upsert_signature(
            conn,
            function_id=ids["second"],
            name="sub_2000",
            return_type="int",
            calling_convention="cdecl",
            parameters=[{"index": 0, "type": "NP_ENTRY *", "name": "entry"}],
            source="decompilation",
        )
        return ids

    def test_signature_mode_copies_the_signature_and_reports_missing_types(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = self._seed_signatures(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/apply-match",
            body=json.dumps({"candidate_function_id": ids["second"], "mode": "signature"}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["status"] == "applied"
        assert payload["name_changed"] is False
        assert payload["signature_changed"] is True
        assert payload["missing_types"] == ["NP_ENTRY"]
        function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "sub_1000"
        signature = store.get_signature(conn, ids["function"])
        assert signature is not None
        assert signature["return_type"] == "int"
        assert signature["calling_convention"] == "cdecl"

    def test_both_mode_journals_both_and_one_revert_puts_both_back(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = self._seed_signatures(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/apply-match",
            body=json.dumps({"candidate_function_id": ids["second"], "mode": "both"}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        action = payload["journal_action"]
        assert payload["name_changed"] is True
        assert payload["signature_changed"] is True
        renamed = store.get_function(conn, ids["function"])
        assert renamed is not None
        assert renamed["name"] == "sub_2000"
        assert store.get_signature(conn, ids["function"]) is not None

        status, headers, body = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"action": action})
        )
        assert status.startswith("200")
        assert json_body(body, headers)["failed"] == 0
        restored = store.get_function(conn, ids["function"])
        assert restored is not None
        assert restored["name"] == "sub_1000"
        assert store.get_signature(conn, ids["function"]) is None

    def test_signature_conflict_is_409(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_signatures(conn)
        store.upsert_signature(
            conn,
            function_id=ids["function"],
            name="sub_1000",
            return_type="int",
            calling_convention="stdcall",
            parameters=[],
            source="manual",
        )
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/apply-match",
            body=json.dumps({"candidate_function_id": ids["second"], "mode": "signature"}),
        )
        assert status.startswith("409")
        assert json_body(body, headers)["error"] == "signature-conflict"


class TestBulkMatchTransferRoute:
    def _transfer_body(self, ids: dict[str, int], *, dry_run: bool = False) -> str:
        return json.dumps(
            {
                "transfers": [
                    {
                        "function_id": ids["function"],
                        "candidate_function_id": ids["second"],
                        "mode": "both",
                    },
                    {
                        "function_id": ids["second"],
                        "candidate_function_id": ids["function"],
                        "mode": "name",
                    },
                ],
                "dry_run": dry_run,
            }
        )

    def _seed_signatures(self, conn: sqlite3.Connection) -> dict[str, int]:
        ids = _seed(conn)
        store.upsert_signature(
            conn,
            function_id=ids["second"],
            name="sub_2000",
            return_type="int",
            calling_convention="cdecl",
            parameters=[],
            source="decompilation",
        )
        return ids

    def test_preview_writes_nothing(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_signatures(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/matches/transfer",
            body=self._transfer_body(ids, dry_run=True),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["dry_run"] is True
        assert payload["applied"] == 1
        assert payload["failed"] == 1
        assert "journal_action" not in payload
        function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "sub_1000"
        assert store.get_signature(conn, ids["function"]) is None

    def test_mixed_batch_applies_reports_and_reverts_as_one_action(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = self._seed_signatures(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/matches/transfer",
            body=self._transfer_body(ids),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        action = payload.pop("journal_action")
        assert payload["requested"] == 2
        assert payload["applied"] == 1
        assert payload["failed"] == 1
        assert payload["transfers"][1]["reason"] == matching.REASON_NO_SUCH_MATCH
        renamed = store.get_function(conn, ids["function"])
        assert renamed is not None
        assert renamed["name"] == "sub_2000"
        assert store.get_signature(conn, ids["function"]) is not None

        status, headers, body = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"action": action})
        )
        assert status.startswith("200")
        assert json_body(body, headers)["failed"] == 0
        restored = store.get_function(conn, ids["function"])
        assert restored is not None
        assert restored["name"] == "sub_1000"
        assert store.get_signature(conn, ids["function"]) is None

    def test_400_empty_transfers(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/matches/transfer",
            body=json.dumps({"transfers": []}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "transfers must be a non-empty list"

    def test_404_unknown_binary(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST",
            "/api/binaries/999/matches/transfer",
            body=json.dumps({"transfers": [{"function_id": 1, "candidate_function_id": 2}]}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


class TestTriageRoutes:
    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="a1" * 32, name="demo.exe", path=str(target))

    def test_post_stores_then_get_serves_stored(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["toolchain"]["family"] == "msvc"
        assert payload["meta"]["format"] == "pe"
        assert fake_engine.calls == ["analyze"]

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("200")
        assert json_body(body, headers)["toolchain"]["family"] == "msvc"

    def test_get_absent_404_no_scan(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no triage scan for binary {binary_id}" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_get_absent_404_no_scan_without_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/triage")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/triage")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="a2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew analyze exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "analyze", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]


class TestReportRoutes:
    def _context_binary(self, conn: sqlite3.Connection) -> int:
        binary_id = store.add_binary(conn, sha256="b1" * 32, name="demo.exe")
        store.set_rebrew_context(conn, binary_id, "/projects/notepad-rebrew")
        return binary_id

    def _workspace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

    def test_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        self._workspace(tmp_path, monkeypatch)
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/report")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload.pop("journal_action")
        assert payload["summary"]["status_counts"] == {"EXACT": 1, "STUB": 1}
        assert payload["pages"] == ["index.html", "strings.html"]
        assert payload["out"] == str(tmp_path / "reports" / str(binary_id))
        assert fake_engine.calls == ["report"]

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/report")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan_and_writes_no_report_dir(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        self._workspace(tmp_path, monkeypatch)
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/report")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no report scan for binary {binary_id}" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None
        assert not (tmp_path / "reports" / str(binary_id)).exists()

    def test_get_absent_404_no_scan_without_engine(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._workspace(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/report")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_post_400_without_context(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="b2" * 32, name="demo.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/report")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"
        assert fake_engine.calls == []

    def test_get_404_without_context(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="b3" * 32, name="demo.exe")
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/report")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"
        assert fake_engine.calls == []

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/report")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_503_without_engine(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._workspace(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/report")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        self._workspace(tmp_path, monkeypatch)

        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew report exited with code 2: no coverage db")

        monkeypatch.setattr(fake_engine, "report", boom)
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/report")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "no coverage db" in payload["detail"]


class TestAnalysisScansRoute:
    def test_list_404_unknown_analysis(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/analyses/999/scans")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "analysis not found"

    def test_list_returns_stored_scans(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.set_scan(conn, ids["analysis"], store.SCAN_KIND_TRIAGE, {"toolchain": {}})
        store.set_scan(conn, ids["analysis"], store.SCAN_KIND_REPORT, {"summary": {}})
        status, headers, body = wsgi_request("GET", f"/api/analyses/{ids['analysis']}/scans")
        assert status.startswith("200")
        scans = json_body(body, headers)["scans"]
        assert [scan["kind"] for scan in scans] == [store.SCAN_KIND_REPORT, store.SCAN_KIND_TRIAGE]
        assert set(scans[0]) == {
            "id",
            "analysis_id",
            "kind",
            "status",
            "created_at",
            "params",
        }


class TestWorkspaceFailure:
    def test_api_request_without_workspace_500(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(DB_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        status, headers, body = wsgi_request("GET", "/api/health")
        assert status.startswith("500")
        assert json_body(body, headers)["error"] == "no-workspace"


class TestAnalyses:
    def test_list_and_create(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request("GET", "/api/analyses")
        assert len(json_body(body, headers)["analyses"]) == 1

        status, headers, body = wsgi_request(
            "POST",
            "/api/analyses",
            body=json.dumps({"binary_id": ids["binary"], "engine": "manual"}),
        )
        assert status.startswith("201")
        assert json_body(body, headers)["binary_id"] == ids["binary"]

    def test_create_bad_binary_id(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/analyses", body=json.dumps({"binary_id": "nope"})
        )
        assert status.startswith("400")
        assert "integer" in json_body(body, headers)["error"]

    def test_create_unknown_binary_404(self, portal_db: Path) -> None:
        status, _, _ = wsgi_request("POST", "/api/analyses", body=json.dumps({"binary_id": 42}))
        assert status.startswith("404")


class TestCollections:
    def test_create_list_and_update(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST", "/api/collections", body=json.dumps({"name": "winsock"})
        )
        assert status.startswith("201")
        collection_id = json_body(body, headers)["id"]

        status, headers, body = wsgi_request(
            "POST",
            f"/api/collections/{collection_id}/binaries",
            body=json.dumps({"binary_id": ids["binary"]}),
        )
        assert status.startswith("200")
        assert json_body(body, headers)["added"] is True

        _, headers, body = wsgi_request("GET", "/api/collections")
        collections = json_body(body, headers)["collections"]
        assert collections[0]["binary_count"] == 1

    def test_duplicate_name_400(self, conn: sqlite3.Connection) -> None:
        wsgi_request("POST", "/api/collections", body=json.dumps({"name": "winsock"}))
        status, _, _ = wsgi_request(
            "POST", "/api/collections", body=json.dumps({"name": "winsock"})
        )
        assert status.startswith("400")

    def test_add_to_unknown_collection_404(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, _, _ = wsgi_request(
            "POST", "/api/collections/99/binaries", body=json.dumps({"binary_id": ids["binary"]})
        )
        assert status.startswith("404")


class TestTags:
    def test_create_list_link_and_unlink_by_name(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST", "/api/tags", body=json.dumps({"name": "release"})
        )
        assert status.startswith("201")
        created = json_body(body, headers)
        assert created["name"] == "release"

        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/tags", body=json.dumps({"name": "release"})
        )
        assert status.startswith("200")
        linked = json_body(body, headers)
        assert linked.pop("journal_action")
        assert linked == {
            "binary_id": ids["binary"],
            "tag_id": created["tag_id"],
            "name": "release",
        }

        _, headers, body = wsgi_request("GET", "/api/tags")
        tags = json_body(body, headers)["tags"]
        assert tags == [
            {
                "id": created["tag_id"],
                "name": "release",
                "binary_count": 1,
                "collection_count": 0,
            }
        ]

        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/tags")
        assert json_body(body, headers)["tags"] == [{"id": created["tag_id"], "name": "release"}]

        status, headers, body = wsgi_request(
            "DELETE", f"/api/binaries/{ids['binary']}/tags/{created['tag_id']}"
        )
        assert status.startswith("200")
        unlinked = json_body(body, headers)
        assert unlinked.pop("journal_action")
        assert unlinked == {
            "binary_id": ids["binary"],
            "tag_id": created["tag_id"],
            "removed": True,
        }
        _, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/tags")
        assert json_body(body, headers)["tags"] == []

    def test_tagging_a_team_binary_is_refused_for_a_non_member(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
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
        stranger_status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/tags",
            body=json.dumps({"name": "release"}),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("403"), body
        assert json_body(body, headers)["error"] == "scope-forbidden"

        member_status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/tags",
            body=json.dumps({"name": "release"}),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), body

    def test_create_is_idempotent_by_name(self, conn: sqlite3.Connection) -> None:
        first = wsgi_request("POST", "/api/tags", body=json.dumps({"name": "release"}))
        second = wsgi_request("POST", "/api/tags", body=json.dumps({"name": "release"}))
        assert json_body(first[2], first[1])["tag_id"] == json_body(second[2], second[1])["tag_id"]
        _, headers, body = wsgi_request("GET", "/api/tags")
        assert len(json_body(body, headers)["tags"]) == 1

    def test_create_blank_name_400(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/tags", body=json.dumps({"name": "  "}))
        assert status.startswith("400")
        assert "name" in json_body(body, headers)["error"]

    def test_rename_keeps_every_link_and_reverts_to_the_old_name(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        tag_id = store.create_tag(conn, "relase")
        store.add_binary_tag(conn, ids["binary"], tag_id)
        collection_id = store.create_collection(conn, name="triage-set")
        store.set_collection_tags(conn, collection_id, ["relase"])

        status, headers, body = wsgi_request(
            "PATCH", f"/api/tags/{tag_id}", body=json.dumps({"name": "release"})
        )
        assert status.startswith("200")
        renamed = json_body(body, headers)
        action = renamed.pop("journal_action")
        assert renamed == {"id": tag_id, "name": "release"}

        _, headers, body = wsgi_request("GET", "/api/tags")
        assert json_body(body, headers)["tags"] == [
            {
                "id": tag_id,
                "name": "release",
                "binary_count": 1,
                "collection_count": 1,
            }
        ]

        status, headers, body = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"action": action})
        )
        assert status.startswith("200")
        assert json_body(body, headers)["failed"] == 0
        restored = store.get_tag(conn, tag_id)
        assert restored is not None
        assert restored["name"] == "relase"

    def test_rename_to_a_taken_name_400(self, conn: sqlite3.Connection) -> None:
        store.create_tag(conn, "release")
        other = store.create_tag(conn, "triage")

        status, headers, body = wsgi_request(
            "PATCH", f"/api/tags/{other}", body=json.dumps({"name": "release"})
        )

        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid tag"
        kept = store.get_tag(conn, other)
        assert kept is not None
        assert kept["name"] == "triage"

    def test_rename_blank_name_400(self, conn: sqlite3.Connection) -> None:
        tag_id = store.create_tag(conn, "release")

        status, headers, body = wsgi_request(
            "PATCH", f"/api/tags/{tag_id}", body=json.dumps({"name": "  "})
        )

        assert status.startswith("400")
        assert "name" in json_body(body, headers)["error"]

    def test_rename_unknown_tag_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request(
            "PATCH", "/api/tags/4242", body=json.dumps({"name": "release"})
        )

        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "tag not found"

    def test_delete_removes_the_tag_and_its_links_and_reverts(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        tag_id = store.create_tag(conn, "release")
        store.add_binary_tag(conn, ids["binary"], tag_id)
        collection_id = store.create_collection(conn, name="triage-set")
        store.set_collection_tags(conn, collection_id, ["release"])

        status, headers, body = wsgi_request("DELETE", f"/api/tags/{tag_id}")
        assert status.startswith("200")
        deleted = json_body(body, headers)
        action = deleted.pop("journal_action")
        assert deleted == {"tag_id": tag_id, "deleted": True}
        assert store.get_tag(conn, tag_id) is None
        assert store.get_binary_tags(conn, ids["binary"]) == []
        assert store.collection_tags(conn, collection_id) == []

        status, headers, body = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"action": action})
        )
        assert status.startswith("200")
        assert json_body(body, headers)["failed"] == 0
        restored = store.get_tag(conn, tag_id)
        assert restored is not None
        assert restored["name"] == "release"
        assert [tag["name"] for tag in store.get_binary_tags(conn, ids["binary"])] == ["release"]
        assert [tag["name"] for tag in store.collection_tags(conn, collection_id)] == ["release"]

    def test_delete_unknown_tag_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("DELETE", "/api/tags/4242")

        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "tag not found"

    def test_link_by_tag_id(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        tag_id = store.create_tag(conn, "release")
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/tags", body=json.dumps({"tag_id": tag_id})
        )
        assert status.startswith("200")
        linked = json_body(body, headers)
        assert linked.pop("journal_action")
        assert linked == {
            "binary_id": ids["binary"],
            "tag_id": tag_id,
            "name": "release",
        }

    def test_link_invalid_body_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        neither = wsgi_request("POST", f"/api/binaries/{ids['binary']}/tags", body="{}")
        assert neither[0].startswith("400")
        assert json_body(neither[2], neither[1])["error"] == "invalid body"

        both = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/tags",
            body=json.dumps({"name": "release", "tag_id": 1}),
        )
        assert both[0].startswith("400")
        assert json_body(both[2], both[1])["error"] == "invalid body"

    def test_link_unknown_binary_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/binaries/999/tags", body=json.dumps({"name": "release"})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_link_unknown_tag_id_404(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/tags", body=json.dumps({"tag_id": 999})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "tag not found"

    def test_list_tags_unknown_binary_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/tags")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_delete_missing_link_404(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        tag_id = store.create_tag(conn, "release")
        status, headers, body = wsgi_request(
            "DELETE", f"/api/binaries/{ids['binary']}/tags/{tag_id}"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "tag not on binary"

    def test_delete_unknown_binary_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("DELETE", "/api/binaries/999/tags/1")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


class TestSearchAndErrors:
    def test_search(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        _, headers, body = wsgi_request("GET", "/api/search?q=demo")
        payload = json_body(body, headers)
        assert payload["query"] == "demo"
        assert [b["name"] for b in payload["binaries"]] == ["demo.exe"]

    def test_search_without_query(self, portal_db: Path) -> None:
        _, headers, body = wsgi_request("GET", "/api/search")
        payload = json_body(body, headers)
        assert payload["binaries"] == [] and payload["functions"] == []

    def test_unknown_api_path_404_json(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/nope")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "not found"

    def test_gzip_encoding(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        status, headers, body = wsgi_request(
            "GET", "/api/binaries", headers={"Accept-Encoding": "gzip"}
        )
        assert status.startswith("200")
        assert headers.get("Content-Encoding") == "gzip"
        assert json.loads(decode(body, headers))["binaries"][0]["name"] == "demo.exe"

    def test_rejected_host_400(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/health", host="evil.example")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "unexpected Host header"


class TestUi:
    """The built SPA served from ``assets/dist`` (built by Vite into ``web/``)."""

    def _dist(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, str]) -> Path:
        dist = tmp_path / "dist"
        for name, text in files.items():
            target = dist / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        monkeypatch.setattr(ui, "dist_dir", lambda: dist)
        return dist

    def test_index_503_when_not_built(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ui, "dist_dir", lambda: tmp_path / "missing")
        status, headers, body = wsgi_request("GET", "/")
        assert status.startswith("503")
        assert headers["Content-Type"].startswith("application/json")
        assert json_body(body, headers) == {
            "error": "ui-not-built",
            "detail": "run 'bun install && bun run build' in web/",
            "doc_url": f"{error_docs.DOC_BASE_URL}#ui-not-built",
        }

    def test_index_serves_built_app(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._dist(
            tmp_path,
            monkeypatch,
            {
                "index.html": (
                    "<!doctype html><html><head><title>reportal</title></head>"
                    '<body><div id="root"></div>'
                    '<script type="module" src="/static/assets/index-abc.js">'
                    "</script></body></html>"
                )
            },
        )
        status, headers, body = wsgi_request("GET", "/")
        assert status.startswith("200")
        assert "text/html" in headers["Content-Type"]
        assert b"reportal" in body
        assert b"/static/assets/index-abc.js" in body
        # The entry page names the deploy's asset hashes, so it is revalidated
        # on every load: a new build is picked up instead of a stale shell
        # pointing at bundles the server no longer has.
        assert headers["Cache-Control"] == ui.SHELL_CACHE_CONTROL

    def test_static_asset_served_from_dist(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._dist(
            tmp_path,
            monkeypatch,
            {"index.html": "reportal", "assets/index-abc.js": "console.log(1);"},
        )
        status, headers, body = wsgi_request("GET", "/static/assets/index-abc.js")
        assert status.startswith("200")
        assert b"console.log" in body
        # The bundle's name carries its content hash, so it is immutable: a
        # repeat load is served from the browser's cache with no request.
        assert headers["Cache-Control"] == ui.ASSET_CACHE_CONTROL

    def test_static_asset_gzip_when_accepted(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Large enough that gzip framing pays off; a one-liner would stay plain.
        payload = "console.log(" + ("x" * 400) + ");"
        self._dist(
            tmp_path,
            monkeypatch,
            {"index.html": "reportal", "assets/index-abc.js": payload},
        )
        status, headers, body = wsgi_request(
            "GET",
            "/static/assets/index-abc.js",
            headers={"Accept-Encoding": "gzip"},
        )
        assert status.startswith("200")
        assert headers.get("Content-Encoding") == "gzip"
        assert headers.get("Vary") == "Accept-Encoding"
        assert headers["Cache-Control"] == ui.ASSET_CACHE_CONTROL
        assert decode(body, headers) == payload.encode("utf-8")

    def test_static_asset_prefers_precompressed_sibling(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import gzip as gzip_mod

        dist = self._dist(
            tmp_path,
            monkeypatch,
            {"index.html": "reportal", "assets/index-abc.js": "console.log('source');"},
        )
        gz_body = gzip_mod.compress(b"console.log('precompressed');", 9)
        (dist / "assets" / "index-abc.js.gz").write_bytes(gz_body)
        status, headers, body = wsgi_request(
            "GET",
            "/static/assets/index-abc.js",
            headers={"Accept-Encoding": "gzip"},
        )
        assert status.startswith("200")
        assert headers.get("Content-Encoding") == "gzip"
        assert decode(body, headers) == b"console.log('precompressed');"

    def test_static_asset_prefers_brotli_over_gzip(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import gzip as gzip_mod

        dist = self._dist(
            tmp_path,
            monkeypatch,
            {"index.html": "reportal", "assets/index-abc.js": "console.log('source');"},
        )
        (dist / "assets" / "index-abc.js.gz").write_bytes(
            gzip_mod.compress(b"console.log('gzip');", 9)
        )
        (dist / "assets" / "index-abc.js.br").write_bytes(b"brotli-payload")
        status, headers, body = wsgi_request(
            "GET",
            "/static/assets/index-abc.js",
            headers={"Accept-Encoding": "gzip, br"},
        )
        assert status.startswith("200")
        assert headers.get("Content-Encoding") == "br"
        assert headers.get("Vary") == "Accept-Encoding"
        assert body == b"brotli-payload"

    def test_static_asset_skips_brotli_when_refused(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import gzip as gzip_mod

        dist = self._dist(
            tmp_path,
            monkeypatch,
            {"index.html": "reportal", "assets/index-abc.js": "console.log('source');"},
        )
        (dist / "assets" / "index-abc.js.gz").write_bytes(
            gzip_mod.compress(b"console.log('gzip');", 9)
        )
        (dist / "assets" / "index-abc.js.br").write_bytes(b"brotli-payload")
        status, headers, body = wsgi_request(
            "GET",
            "/static/assets/index-abc.js",
            headers={"Accept-Encoding": "br;q=0, gzip"},
        )
        assert status.startswith("200")
        assert headers.get("Content-Encoding") == "gzip"
        assert decode(body, headers) == b"console.log('gzip');"

    def test_static_favicon_served_from_public(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._dist(
            tmp_path,
            monkeypatch,
            {"index.html": "reportal", "favicon.svg": "<svg xmlns='x'/>"},
        )
        status, headers, body = wsgi_request("GET", "/static/favicon.svg")
        assert status.startswith("200")
        assert b"<svg" in body
        # A file whose name carries no hash can change under it, so it is
        # revalidated rather than pinned for a year.
        assert headers["Cache-Control"] == ui.SHELL_CACHE_CONTROL

    def test_static_traversal_blocked(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._dist(tmp_path, monkeypatch, {"index.html": "reportal"})
        status, _, _ = wsgi_request("GET", "/static/../server.py")
        assert not status.startswith("200")


class TestReportSite:
    """The generated report site served from <workspace>/reports/<id>."""

    def _site(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        files: dict[str, str],
        binary_id: int = 1,
    ) -> Path:
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        site = tmp_path / "reports" / str(binary_id)
        for name, text in files.items():
            target = site / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        return site

    def test_root_serves_index_html(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._site(tmp_path, monkeypatch, {"index.html": "<h1>coverage 100%</h1>"})
        status, headers, body = wsgi_request("GET", "/reports/1/")
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("text/html")
        assert body == b"<h1>coverage 100%</h1>"

    def test_nested_page_served(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._site(
            tmp_path,
            monkeypatch,
            {"index.html": "home", "strings.html": "<p>hello</p>"},
        )
        status, headers, body = wsgi_request("GET", "/reports/1/strings.html")
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("text/html")
        assert b"hello" in body

    def test_css_served_with_content_type(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._site(tmp_path, monkeypatch, {"index.html": "home", "style.css": "body{margin:0}"})
        status, headers, body = wsgi_request("GET", "/reports/1/style.css")
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("text/css")
        assert b"margin:0" in body

    def test_js_served_with_content_type(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._site(tmp_path, monkeypatch, {"index.html": "home", "site.js": "const x = 1;"})
        status, headers, body = wsgi_request("GET", "/reports/1/site.js")
        assert status.startswith("200")
        assert headers["Content-Type"].split(";")[0] in {
            "text/javascript",
            "application/javascript",
        }
        assert b"const x" in body

    def test_svg_served_with_content_type(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._site(
            tmp_path,
            monkeypatch,
            {"index.html": "home", "graph.svg": "<svg xmlns='http://www.w3.org/2000/svg'/>"},
        )
        status, headers, body = wsgi_request("GET", "/reports/1/graph.svg")
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("image/svg+xml")
        assert b"<svg" in body

    def test_missing_directory_404_no_report(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._site(tmp_path, monkeypatch, {})
        status, headers, body = wsgi_request("GET", "/reports/1/")
        assert status.startswith("404")
        assert headers["Content-Type"].startswith("application/json")
        payload = json_body(body, headers)
        assert payload["error"] == "no-report"
        assert "reportal report 1" in payload["detail"]

    def test_unknown_binary_id_404_no_report(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._site(tmp_path, monkeypatch, {"index.html": "home"}, binary_id=1)
        status, headers, body = wsgi_request("GET", "/reports/99/index.html")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload == {
            "error": "no-report",
            "detail": "no report site for binary 99; run 'reportal report 99'",
            "doc_url": f"{error_docs.DOC_BASE_URL}#no-report",
        }

    def test_traversal_cannot_escape_reports_dir(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._site(tmp_path, monkeypatch, {"index.html": "home"})
        (tmp_path / "reports" / "secret.txt").write_text("TOP SECRET", encoding="utf-8")
        # A WSGI server percent-decodes PATH_INFO before routing, so the
        # encoded form is decoded here the way the live server would.
        encoded = unquote("/reports/1/%2e%2e%2fsecret.txt")
        for target in ("/reports/1/../secret.txt", encoded):
            status, _, body = wsgi_request("GET", target)
            assert not status.startswith("200")
            assert b"TOP SECRET" not in body


class TestXrefsRoutes:
    def _context_function(self, conn: sqlite3.Connection) -> dict[str, int]:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["binary"], "/projects/notepad-rebrew")
        return ids

    def test_get_returns_engine_refs(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._context_function(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/xrefs")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 2
        assert [ref["kind"] for ref in payload["refs"]] == ["call", "jmp"]
        assert fake_engine.calls == ["xrefs"]
        assert fake_engine.xrefs_args == ("/projects/notepad-rebrew", 0x1000, ())

    def test_kind_query_filters_and_reaches_engine(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._context_function(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/xrefs?kind=call&kind=data"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert [ref["kind"] for ref in payload["refs"]] == ["call"]
        assert fake_engine.xrefs_args == ("/projects/notepad-rebrew", 0x1000, ("call", "data"))

    def test_404_unknown_function(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/xrefs")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_400_without_context(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/xrefs")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"
        assert fake_engine.calls == []

    def test_503_without_engine(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        ids = self._context_function(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/xrefs")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_500_engine_error(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew xrefs exited with code 2: bad va")

        monkeypatch.setattr(fake_engine, "xrefs", boom)
        ids = self._context_function(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/xrefs")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad va" in payload["detail"]


class TestStructsRoutes:
    def _context_binary(self, conn: sqlite3.Connection) -> int:
        binary_id = store.add_binary(conn, sha256="c1" * 32, name="demo.exe")
        store.set_rebrew_context(conn, binary_id, "/projects/notepad-rebrew")
        return binary_id

    def test_post_stores_then_get_serves_stored(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/structs", body=json.dumps({"limit": 10})
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["decompiled"] == 12
        assert payload["structs"][0]["name"] == "PlayerInfo"
        assert fake_engine.calls == ["structs"]
        assert fake_engine.structs_args == ("/projects/notepad-rebrew", "kuna", 10)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_STRUCTS) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/structs")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_post_defaults_backend_and_limit(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, _, _ = wsgi_request("POST", f"/api/binaries/{binary_id}/structs", body="{}")
        assert status.startswith("200")
        assert fake_engine.structs_args == (
            "/projects/notepad-rebrew",
            "kuna",
            DEFAULT_STRUCT_LIMIT,
        )

    def test_get_absent_404_no_scan(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/structs")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no structs scan for binary {binary_id}" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_get_absent_404_no_scan_without_engine(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/structs")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/structs")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_get_404_without_context(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="c2" * 32, name="demo.exe")
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/structs")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"
        assert fake_engine.calls == []

    def test_post_400_without_context(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="c3" * 32, name="demo.exe")
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/structs", body="{}"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"
        assert fake_engine.calls == []

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/structs", body="{}")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_invalid_backend(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{binary_id}/structs",
            body=json.dumps({"decompiler": "ida"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid backend"
        assert fake_engine.calls == []

    def test_post_400_negative_limit(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/structs", body=json.dumps({"limit": -1})
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid limit"
        assert fake_engine.calls == []

    def test_post_400_non_integer_limit(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/structs", body=json.dumps({"limit": "many"})
        )
        assert status.startswith("400")
        assert "limit" in json_body(body, headers)["error"]
        assert fake_engine.calls == []

    def test_post_400_bad_body(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/structs", body="{not json"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid JSON body"

    def test_post_503_without_engine(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/structs", body="{}"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_get_stored_serves_without_engine(self, conn: sqlite3.Connection) -> None:
        binary_id = self._context_binary(conn)
        analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS, {"decompiled": 1, "structs": []})
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/structs")
        assert status.startswith("200")
        assert json_body(body, headers)["decompiled"] == 1

    def test_post_500_engine_error(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew recover-structs exited with code 1: no backend")

        monkeypatch.setattr(fake_engine, "structs", boom)
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/structs", body="{}"
        )
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "no backend" in payload["detail"]


class TestCryptoScanRoutes:
    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="d1" * 32, name="demo.exe", path=str(target))

    def test_post_stores_then_get_serves_stored(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/crypto-scan")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["findings"] == CRYPTO["findings"]
        assert payload["count"] == CRYPTO["count"]
        assert payload["by_confidence"] == CRYPTO["by_confidence"]
        assert fake_engine.calls == ["crypto_scan"]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_CRYPTO) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/crypto-scan")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/crypto-scan")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no crypto scan for binary {binary_id}" in payload["detail"]
        assert "/crypto-scan" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_get_absent_404_no_scan_without_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/crypto-scan")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/crypto-scan")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/crypto-scan")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="d2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/crypto-scan")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/crypto-scan")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew crypto-scan exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "crypto_scan", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/crypto-scan")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "crypto")


class TestPeInfoRoutes:
    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="e1" * 32, name="demo.exe", path=str(target))

    def test_post_stores_then_get_serves_stored(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["format"] == "pe"
        assert payload["flags_summary"] == PE_INFO["flags_summary"]
        assert payload["sections"] == PE_INFO["sections"]
        assert payload["counts"] == PE_INFO["counts"]
        assert fake_engine.calls == ["pe_info"]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_PE_INFO) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no pe-info scan for binary {binary_id}" in payload["detail"]
        assert "/pe-info" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_get_absent_404_no_scan_without_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/pe-info")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/pe-info")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="e2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew pe-info exited with code 1: not a PE")

        monkeypatch.setattr(fake_engine, "pe_info", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "not a PE" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "pe-info")


class TestCapabilitiesRoutes:
    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="c1" * 32, name="demo.exe", path=str(target))

    def _stub_payloads(self, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine) -> None:
        imports = {
            "imports": [{"dll": "WS2_32.dll", "name": "WSAStartup", "iat_va": "0x401000"}],
            "stubs": [],
        }
        strings = {
            "strings": [
                {
                    "text": "https://example.test/beacon",
                    "va": "0x402000",
                    "size": 26,
                    "kind": "ascii",
                    "section": ".rdata",
                }
            ]
        }
        monkeypatch.setattr(fake_engine, "imports", lambda binary: dict(imports))
        monkeypatch.setattr(fake_engine, "strings", lambda binary: dict(strings))

    def test_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        self._stub_payloads(monkeypatch, fake_engine)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/capabilities")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == binary_id
        assert payload["count"] == 1
        assert payload["capabilities"][0]["name"] == "networking"
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_CAPABILITIES) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/capabilities")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan_makes_no_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/capabilities")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no capabilities scan for binary {binary_id}" in payload["detail"]
        assert "/capabilities" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_get_absent_404_no_scan_without_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/capabilities")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/capabilities")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/capabilities")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="c2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/capabilities")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/capabilities")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        _assert_scan_failed(conn, binary_id, "capabilities")

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew imports exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "imports", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/capabilities")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "capabilities")


class TestBehaviorRoutes:
    """The behavior POST/GET routes and the combined stored GET."""

    DOMAIN_EVIDENCE = {
        "execution": [{"dll": "KERNEL32.dll", "name": "CreateProcessA", "iat_va": "0x401000"}],
        "networking": [{"dll": "WS2_32.dll", "name": "WSAStartup", "iat_va": "0x401000"}],
        "filesystem": [{"dll": "KERNEL32.dll", "name": "CreateFileA", "iat_va": "0x401000"}],
    }

    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="b1" * 32, name="demo.exe", path=str(target))

    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        imports: list[dict[str, str]],
    ) -> None:
        monkeypatch.setattr(
            fake_engine, "imports", lambda binary: {"imports": list(imports), "stubs": []}
        )
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": []})

    @pytest.mark.parametrize("domain", ["execution", "networking", "filesystem"])
    def test_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        domain: str,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        self._stub(monkeypatch, fake_engine, self.DOMAIN_EVIDENCE[domain])
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/behavior/{domain}")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == binary_id
        assert payload["domain"] == domain
        assert payload["count"] == 1
        assert payload["findings"][0]["confidence"] == "high"
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, behavior.DOMAIN_SCAN_KINDS[domain]) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/behavior/{domain}")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    @pytest.mark.parametrize("domain", ["execution", "networking", "filesystem"])
    def test_get_absent_404_no_scan_makes_no_engine_call(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: FakeEngine,
        domain: str,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/behavior/{domain}")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no {domain} scan for binary {binary_id}" in payload["detail"]
        assert f"/behavior/{domain}" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_combined_get_returns_nulls_then_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/behavior")
        assert status.startswith("200")
        assert json_body(body, headers) == {
            "execution": None,
            "networking": None,
            "filesystem": None,
        }

        self._stub(monkeypatch, fake_engine, self.DOMAIN_EVIDENCE["networking"])
        wsgi_request("POST", f"/api/binaries/{binary_id}/behavior/networking")
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/behavior")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert set(payload) == {"execution", "networking", "filesystem"}
        assert payload["networking"]["domain"] == "networking"
        assert payload["execution"] is None
        assert payload["filesystem"] is None

    def test_combined_get_404_unknown_binary(
        self, portal_db: Path, fake_engine: FakeEngine
    ) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/behavior")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_unknown_domain_404(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine, method: str
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(method, f"/api/binaries/{binary_id}/behavior/registry")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "domain not found"

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/behavior/execution")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="b2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/behavior/execution"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/behavior/execution"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        _assert_scan_failed(conn, binary_id, "execution")

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew imports exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "imports", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/behavior/execution"
        )
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "execution")


class TestHardeningRoutes:
    """The hardening POST/GET routes and the combined stored GET."""

    ANTI_DEBUG_IMPORTS = [
        {"dll": "KERNEL32.dll", "name": "IsDebuggerPresent", "iat_va": "0x401000"}
    ]

    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(
            conn, sha256="h1" * 32, name="demo.exe", path=str(target), size=1024
        )

    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        *,
        imports: list[dict[str, str]] | None = None,
        strings: list[dict[str, str]] | None = None,
        sections: list[dict[str, object]] | None = None,
    ) -> None:
        monkeypatch.setattr(
            fake_engine, "imports", lambda binary: {"imports": list(imports or []), "stubs": []}
        )
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": list(strings or [])})
        monkeypatch.setattr(
            fake_engine,
            "fingerprint",
            lambda binary: {
                "format": "pe",
                "size": 1024,
                "section_entropies": list(sections or []),
            },
        )

    def test_anti_analysis_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        self._stub(monkeypatch, fake_engine, imports=self.ANTI_DEBUG_IMPORTS)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/hardening/anti-analysis"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["domain"] == "anti-analysis"
        assert payload["count"] == 1
        assert payload["findings"][0]["category"] == "anti-debug-api"
        assert payload["findings"][0]["confidence"] == "high"
        assert payload["packer_likelihood"] is None
        assert payload.pop("journal_action")
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert (
            store.get_scan(conn, analysis_id or 0, hardening.DOMAIN_SCAN_KINDS["anti-analysis"])
            == payload
        )

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/hardening/anti-analysis"
        )
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_obfuscation_post_stores_the_packer_likelihood(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        self._stub(
            monkeypatch,
            fake_engine,
            sections=[{"name": ".text", "entropy": 7.8, "raw_size": 512, "vsize": 512}],
        )
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/hardening/obfuscation"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["domain"] == "obfuscation"
        assert payload["packer_likelihood"] in {"high", "medium"}
        assert any(
            finding["category"] == "high-entropy-executable-section"
            for finding in payload["findings"]
        )

    def test_get_absent_404_no_scan_makes_no_engine_call(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/hardening/obfuscation"
        )
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no obfuscation scan for binary {binary_id}" in payload["detail"]
        assert "/hardening/obfuscation" in payload["detail"]
        assert fake_engine.calls == []

    def test_combined_get_returns_nulls_then_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/hardening")
        assert status.startswith("200")
        assert json_body(body, headers) == {"anti-analysis": None, "obfuscation": None}

        self._stub(monkeypatch, fake_engine, imports=self.ANTI_DEBUG_IMPORTS)
        wsgi_request("POST", f"/api/binaries/{binary_id}/hardening/anti-analysis")
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/hardening")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert set(payload) == {"anti-analysis", "obfuscation"}
        assert payload["anti-analysis"]["domain"] == "anti-analysis"
        assert payload["obfuscation"] is None

    def test_combined_get_404_unknown_binary(
        self, portal_db: Path, fake_engine: FakeEngine
    ) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/hardening")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_unknown_domain_404(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine, method: str
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(method, f"/api/binaries/{binary_id}/hardening/packing")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "domain not found"

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/hardening/anti-analysis")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="h2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/hardening/anti-analysis"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/hardening/obfuscation"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        _assert_scan_failed(conn, binary_id, "obfuscation")

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew imports exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "imports", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/hardening/anti-analysis"
        )
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "anti-analysis")


class TestSecretsRoutes:
    """`POST`/`GET /api/binaries/<id>/secrets`."""

    GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="e1" * 32, name="demo.exe", path=str(target))

    def _stub_strings(self, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine) -> None:
        strings = {"strings": [{"text": self.GITHUB_TOKEN, "va": "0x402000"}]}
        monkeypatch.setattr(fake_engine, "strings", lambda binary: dict(strings))

    def test_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        self._stub_strings(monkeypatch, fake_engine)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/secrets")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == binary_id
        assert payload["count"] == 1
        assert payload["findings"][0]["name"] == "github-token"
        assert payload["findings"][0]["value"] == self.GITHUB_TOKEN
        assert payload["findings"][0]["redacted"] != self.GITHUB_TOKEN
        assert payload["scanned"] == 1
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECRETS) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/secrets")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan_makes_no_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/secrets")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no secrets scan for binary {binary_id}" in payload["detail"]
        assert "/secrets" in payload["detail"]
        assert "reportal secrets" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_get_absent_404_no_scan_without_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/secrets")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/secrets")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/secrets")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="e2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/secrets")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/secrets")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        _assert_scan_failed(conn, binary_id, "secrets")

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew strings exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "strings", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/secrets")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "secrets")


class TestFileTypeRoutes:
    """`POST`/`GET /api/binaries/<id>/filetype`."""

    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="e9" * 32, name="demo.exe", path=str(target))

    def _stub_packed_pe(self, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine) -> None:
        packed = {
            **PE_INFO,
            "sections": [
                {"name": "UPX0", "execute": False},
                {"name": "UPX1", "execute": True},
            ],
        }
        monkeypatch.setattr(fake_engine, "pe_info", lambda binary: dict(packed))
        monkeypatch.setattr(
            fake_engine,
            "strings",
            lambda binary: {"strings": [{"text": "UPX!", "va": "0x402000"}]},
        )

    def test_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        self._stub_packed_pe(monkeypatch, fake_engine)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/filetype")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == binary_id
        assert payload["matches"][0]["name"] == "UPX"
        assert payload["matches"][0]["confidence"] == "high"
        assert payload["by_category"]["packer"] >= 1
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_FILETYPE) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/filetype")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan_makes_no_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/filetype")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no filetype scan for binary {binary_id}" in payload["detail"]
        assert "/filetype" in payload["detail"]
        assert "reportal filetype" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/filetype")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/filetype")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="ea" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/filetype")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/filetype")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_post_500_when_the_engine_call_fails(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(binary: str | Path) -> dict[str, object]:
            raise engines.EngineError("rebrew pe-info failed: not a PE")

        for name in ("pe_info", "fingerprint", "imports", "strings"):
            monkeypatch.setattr(fake_engine, name, boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/filetype")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "not a PE" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "filetype")

    def test_post_500_is_sanitized(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise RuntimeError("internal detail that must not leak")

        monkeypatch.setattr(filetypes, "run_filetype", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/filetype")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "internal server error"
        assert "internal detail" not in payload["detail"]
        _assert_scan_failed(conn, binary_id, "filetype")


class TestSecurityScanRoutes:
    def _context_binary(self, conn: sqlite3.Connection) -> int:
        binary_id = store.add_binary(conn, sha256="f1" * 32, name="demo.exe")
        store.set_rebrew_context(conn, binary_id, "/projects/notepad-rebrew")
        return binary_id

    def test_post_stores_then_get_serves_stored(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{binary_id}/security-scan",
            body=json.dumps({"min_severity": "high"}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["findings"] == SECURITY["findings"]
        assert payload["count"] == SECURITY["count"]
        assert payload["by_severity"] == SECURITY["by_severity"]
        assert payload["files_scanned"] == SECURITY["files_scanned"]
        assert fake_engine.calls == ["security_scan"]
        assert fake_engine.security_scan_args == ("/projects/notepad-rebrew", "high")
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECURITY) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/security-scan")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_post_defaults_to_low_severity(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, _, _ = wsgi_request("POST", f"/api/binaries/{binary_id}/security-scan")
        assert status.startswith("200")
        assert fake_engine.security_scan_args == ("/projects/notepad-rebrew", "low")

    def test_get_absent_404_no_scan_without_engine(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/security-scan")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no security scan for binary {binary_id}" in payload["detail"]
        assert "/security-scan" in payload["detail"]

    def test_get_absent_makes_no_engine_call(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/security-scan")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/security-scan")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/security-scan")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_without_context(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="f2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/security-scan")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"
        assert fake_engine.calls == []

    def test_post_400_invalid_severity(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{binary_id}/security-scan",
            body=json.dumps({"min_severity": "critical"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid severity"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/security-scan")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew security-scan exited with code 1: bad project")

        monkeypatch.setattr(fake_engine, "security_scan", boom)
        binary_id = self._context_binary(conn)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/security-scan")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad project" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "security")


class TestThreatRoutes:
    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="d1" * 32, name="demo.exe", path=str(target))

    def _stub_signals(self, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine) -> None:
        url = "https://c2.example.com/beacon"
        monkeypatch.setattr(
            fake_engine,
            "imports",
            lambda binary: {
                "imports": [{"dll": "WS2_32.dll", "name": "WSAStartup", "iat_va": "0x401000"}],
                "stubs": [],
            },
        )
        monkeypatch.setattr(
            fake_engine,
            "strings",
            lambda binary: {
                "strings": [{"text": url, "va": 0x402000, "size": len(url), "kind": "ascii"}]
            },
        )

    def test_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        self._stub_signals(monkeypatch, fake_engine)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["iocs"]["urls"][0]["value"] == "https://c2.example.com/beacon"
        assert payload["ioc_counts"]["urls"] == 1
        assert {item["id"] for item in payload["techniques"]} >= {"T1071"}
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        # The route adds the software type and the threat score, both derived at
        # request time from the binary's stored evidence; the stored scan stays
        # exactly what the report writer produced.
        classified = {key: payload.pop(key) for key in ("software_type", "threat_score")}
        assert classified["software_type"]["type"] is None
        assert classified["threat_score"]["score"] is not None
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_THREAT) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("200")
        assert json_body(body, headers) == {**payload, **classified}

    def test_get_absent_404_no_scan_makes_no_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no threat scan for binary {binary_id}" in payload["detail"]
        assert "/threat" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/threat")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/threat")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="d2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew strings exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "strings", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]

    def test_post_narrative_without_an_llm_is_not_an_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        monkeypatch.delenv(llm.ENDPOINT_ENV, raising=False)
        llm.set_client(None)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/threat", body=json.dumps({"narrative": True})
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["narrative"] is None
        assert "llm-unavailable" in payload["notes"][0]

    def test_post_invalid_narrative_is_400(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/threat", body=json.dumps({"narrative": "yes"})
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "narrative must be a boolean"


class TestUnstripRoutes:
    def _seed(self, conn: sqlite3.Connection, *, context: bool = True) -> dict[str, int]:
        binary_id = store.add_binary(conn, sha256="e1" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        first = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", name_source="rebrew"
        )
        second = store.add_function(
            conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", name_source="rebrew"
        )
        if context:
            store.set_rebrew_context(conn, binary_id, "/projects/demo")
        return {"binary": binary_id, "analysis": analysis_id, "first": first, "second": second}

    def test_post_stores_then_get_serves_stored(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/unstrip",
            body=json.dumps({"min_confidence": 0.0}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["candidates"] == 2
        assert [proposal["proposed_name"] for proposal in payload["proposals"]] == [
            "ChooseFontW",
            "GetOpenFileNameW",
        ]
        assert payload["applied"] is False
        assert fake_engine.calls == ["identify_library"]
        assert payload.pop("journal_action")
        assert store.get_scan(conn, ids["analysis"], store.SCAN_KIND_UNSTRIP) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/unstrip")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_post_accepts_an_empty_body(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn)
        status, _, _ = wsgi_request("POST", f"/api/binaries/{ids['binary']}/unstrip")
        assert status.startswith("200")

    def test_post_min_confidence_filters_proposals(
        self,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        ids = self._seed(conn)
        monkeypatch.setattr(
            fake_engine,
            "identify_library",
            lambda project_dir: {"candidates": [{"va": "0x1000", "name": "X", "confidence": 0.3}]},
        )
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/unstrip",
            body=json.dumps({"min_confidence": 0.5}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["candidates"] == 1
        assert payload["proposals"] == []

    def test_get_absent_404_no_scan(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/unstrip")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no unstrip scan for binary {ids['binary']}" in payload["detail"]
        assert fake_engine.calls == []

    def test_get_absent_404_no_scan_without_engine(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{ids['binary']}/unstrip")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/unstrip")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_400_without_context(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn, context=False)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{ids['binary']}/unstrip")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("POST", f"/api/binaries/{ids['binary']}/unstrip")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew identify-library exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "identify_library", boom)
        ids = self._seed(conn)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{ids['binary']}/unstrip")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]

    def test_apply_renames_and_returns_function(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn)
        wsgi_request("POST", f"/api/binaries/{ids['binary']}/unstrip")
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/unstrip/apply",
            body=json.dumps({"function_id": ids["first"]}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["old_name"] == "sub_1000"
        assert payload["new_name"] == "ChooseFontW"
        assert payload["function"]["name"] == "ChooseFontW"
        assert payload["function"]["name_source"] == "unstrip"
        history = store.list_name_history(conn, ids["first"])
        assert history[0]["source"] == "unstrip"

    def test_apply_name_override(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/unstrip/apply",
            body=json.dumps({"function_id": ids["first"], "name": "CustomName"}),
        )
        assert status.startswith("200")
        assert json_body(body, headers)["new_name"] == "CustomName"

    def test_apply_404_unknown_function(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/unstrip/apply",
            body=json.dumps({"function_id": 999}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_apply_404_without_a_stored_proposal(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/unstrip/apply",
            body=json.dumps({"function_id": ids["first"]}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-proposal"

    def test_apply_400_blank_name(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = self._seed(conn)
        wsgi_request("POST", f"/api/binaries/{ids['binary']}/unstrip")
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/unstrip/apply",
            body=json.dumps({"function_id": ids["first"], "name": "   "}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid name"

    def test_apply_400_non_string_name(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/unstrip/apply",
            body=json.dumps({"function_id": ids["first"], "name": 5}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "name must be a string"

    def test_apply_400_missing_function_id(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/unstrip/apply", body="{}"
        )
        assert status.startswith("400")
        assert "function_id" in json_body(body, headers)["error"]

    def test_apply_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/binaries/999/unstrip/apply", body=json.dumps({"function_id": 1})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


AI_RESPONSES: dict[str, str] = {
    "summary": AI_SUMMARY_RESPONSE,
    "comments": AI_COMMENTS_RESPONSE,
    "type-suggestions": AI_TYPES_RESPONSE,
}

# Wire path per artifact kind.  The inline-comments artifact keeps the kind
# `comments`, but the analyst comment routes own `/comments`.
AI_PATHS: dict[str, str] = {
    "summary": "summary",
    "comments": "ai-comments",
    "type-suggestions": "type-suggestions",
}


class TestAiRoutes:
    def _seed_with_decompilation(self, conn: sqlite3.Connection) -> dict[str, int]:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["binary"], "/projects/notepad-rebrew")
        store.set_decompilation(conn, ids["function"], "int f(void) { return 1; }", "kuna")
        return ids

    @pytest.mark.parametrize("kind", sorted(AI_RESPONSES))
    def test_post_stores_then_get_serves(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient, kind: str
    ) -> None:
        fake_llm.response = AI_RESPONSES[kind]
        ids = self._seed_with_decompilation(conn)
        path = AI_PATHS[kind]
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/{path}")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["function_id"] == ids["function"]
        assert payload["kind"] == kind
        assert payload["model"] == "fake-model"
        assert len(fake_llm.calls) == 1
        assert "int f(void)" in fake_llm.calls[0][1]["content"]

        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/{path}")
        assert status.startswith("200")
        stored = json_body(body, headers)
        assert stored["kind"] == kind
        assert stored["payload"] == payload["payload"]
        assert stored["model"] == "fake-model"
        assert stored["created_at"]
        assert len(fake_llm.calls) == 1

    def test_get_never_calls_the_llm(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/summary")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-artifact"
        assert fake_llm.calls == []

    def test_get_absent_is_no_artifact(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['function']}/type-suggestions"
        )
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-artifact"
        assert "suggest-types" in payload["detail"]

    def test_post_requires_a_stored_decompilation(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/summary")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-decompilation"
        assert "reportal decompile" in payload["detail"]
        assert fake_llm.calls == []

    def test_post_without_a_client_503(self, conn: sqlite3.Connection) -> None:
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/summary")
        assert status.startswith("503")
        payload = json_body(body, headers)
        assert payload["error"] == "llm-unavailable"
        assert "REPORTAL_LLM_ENDPOINT" in payload["detail"]

    def test_get_without_a_client_still_serves_stored(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        ids = self._seed_with_decompilation(conn)
        wsgi_request("POST", f"/api/functions/{ids['function']}/summary")
        llm.set_client(None)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['function']}/summary")
        assert status.startswith("200")
        assert json_body(body, headers)["kind"] == "summary"

    def test_post_unknown_function_404(self, portal_db: Path, fake_llm: FakeLlmClient) -> None:
        status, headers, body = wsgi_request("POST", "/api/functions/999/summary")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_get_unknown_function_404(self, portal_db: Path, fake_llm: FakeLlmClient) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/ai-comments")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_malformed_response_502(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = "not json at all"
        ids = self._seed_with_decompilation(conn)
        status, headers, body = wsgi_request("POST", f"/api/functions/{ids['function']}/summary")
        assert status.startswith("502")
        payload = json_body(body, headers)
        assert payload["error"] == "llm-error"
        assert "not valid JSON" in payload["detail"]

    def test_failed_request_does_not_store(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = "not json at all"
        ids = self._seed_with_decompilation(conn)
        wsgi_request("POST", f"/api/functions/{ids['function']}/summary")
        assert store.get_ai_artifact(conn, ids["function"], "summary") is None

    def test_post_is_an_upsert(self, conn: sqlite3.Connection, fake_llm: FakeLlmClient) -> None:
        ids = self._seed_with_decompilation(conn)
        wsgi_request("POST", f"/api/functions/{ids['function']}/ai-comments")
        fake_llm.response = '[{"line": 9, "comment": "second run"}]'
        wsgi_request("POST", f"/api/functions/{ids['function']}/ai-comments")
        stored = store.get_ai_artifact(conn, ids["function"], "comments")
        assert stored is not None
        assert stored["payload"]["comments"] == [{"line": 9, "comment": "second run"}]
        row = conn.execute("SELECT COUNT(*) FROM ai_artifacts").fetchone()
        assert row is not None and row[0] == 1


class TestConversationsRoutes:
    def _create(
        self,
        conn: sqlite3.Connection,
        *,
        scope_kind: str = "function",
        scope_id: int | None = None,
        title: str | None = None,
    ) -> int:
        ids = _seed(conn)
        payload: dict[str, object] = {
            "scope_kind": scope_kind,
            "scope_id": ids["function"] if scope_id is None else scope_id,
        }
        if title is not None:
            payload["title"] = title
        status, headers, body = wsgi_request("POST", "/api/conversations", body=json.dumps(payload))
        assert status.startswith("201"), body
        return int(json_body(body, headers)["id"])

    def test_list_empty(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/conversations")
        assert status.startswith("200")
        assert json_body(body, headers) == {"conversations": []}

    def test_create_function_scope_and_default_title(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            "/api/conversations",
            body=json.dumps({"scope_kind": "function", "scope_id": ids["function"]}),
        )
        assert status.startswith("201")
        payload = json_body(body, headers)
        assert payload["scope_kind"] == "function"
        assert payload["scope_id"] == ids["function"]
        assert payload["title"] == "sub_1000 @ 0x1000"
        assert payload["message_count"] == 0
        assert payload["created_at"]

    def test_create_binary_scope_with_title(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            "/api/conversations",
            body=json.dumps(
                {
                    "scope_kind": "binary",
                    "scope_id": ids["binary"],
                    "title": "Where is the entry point?",
                }
            ),
        )
        assert status.startswith("201")
        payload = json_body(body, headers)
        assert payload["scope_kind"] == "binary"
        assert payload["title"] == "Where is the entry point?"

    def test_create_invalid_scope_kind_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            "/api/conversations",
            body=json.dumps({"scope_kind": "galaxy", "scope_id": ids["binary"]}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid scope kind"

    def test_create_unknown_function_scope_404(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            "/api/conversations",
            body=json.dumps({"scope_kind": "function", "scope_id": 999}),
        )
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "function not found"
        assert "999" in payload["detail"]

    def test_create_unknown_binary_scope_404(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            "/api/conversations",
            body=json.dumps({"scope_kind": "binary", "scope_id": 999}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_list_filters_by_scope(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        first = self._create(conn, scope_kind="function", scope_id=ids["function"])
        second = self._create(conn, scope_kind="binary", scope_id=ids["binary"])
        _, headers, body = wsgi_request("GET", "/api/conversations")
        assert [row["id"] for row in json_body(body, headers)["conversations"]] == [first, second]
        _, headers, body = wsgi_request(
            "GET", f"/api/conversations?scope_kind=function&scope_id={ids['function']}"
        )
        rows = json_body(body, headers)["conversations"]
        assert [row["id"] for row in rows] == [first]

    def test_a_non_member_lists_no_team_conversations(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        # Built directly: `_create` re-seeds its own binary per call, which
        # would scope the wrong binary.
        team_conv = store.create_conversation(
            conn, scope_kind="binary", scope_id=ids["binary"], title="team thread"
        )
        docs_conv = store.create_conversation(conn, scope_kind="docs", scope_id=0, title="manual")
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
        _status, headers, body = wsgi_request(
            "GET", "/api/conversations", headers={"Authorization": f"Bearer {outsider}"}
        )
        assert [row["id"] for row in json_body(body, headers)["conversations"]] == [docs_conv]

        _status, headers, body = wsgi_request(
            "GET", "/api/conversations", headers={"Authorization": f"Bearer {token}"}
        )
        assert [row["id"] for row in json_body(body, headers)["conversations"]] == [
            team_conv,
            docs_conv,
        ]

    def test_list_non_integer_scope_id_400(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/conversations?scope_id=abc")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "scope_id must be an integer"

    def test_get_returns_the_messages(self, conn: sqlite3.Connection) -> None:
        conversation_id = self._create(conn)
        store.add_message(conn, conversation_id=conversation_id, role="user", content="q")
        store.add_message(conn, conversation_id=conversation_id, role="assistant", content="a")
        status, headers, body = wsgi_request("GET", f"/api/conversations/{conversation_id}")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["id"] == conversation_id
        assert [message["content"] for message in payload["messages"]] == ["q", "a"]
        assert [message["role"] for message in payload["messages"]] == ["user", "assistant"]

    def test_get_unknown_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/conversations/999")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "conversation not found"

    def test_delete_then_get_404(self, conn: sqlite3.Connection) -> None:
        conversation_id = self._create(conn)
        store.add_message(conn, conversation_id=conversation_id, role="user", content="q")
        status, headers, body = wsgi_request("DELETE", f"/api/conversations/{conversation_id}")
        assert status.startswith("200")
        assert json_body(body, headers)["deleted"] is True
        assert store.list_messages(conn, conversation_id) == []
        status, _, _ = wsgi_request("GET", f"/api/conversations/{conversation_id}")
        assert status.startswith("404")

    def test_delete_unknown_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("DELETE", "/api/conversations/999")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "conversation not found"

    def test_a_non_member_does_not_read_or_delete_a_team_conversation(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        conversation_id = self._create(conn, scope_kind="binary", scope_id=ids["binary"])
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
        stranger_status, headers, body = wsgi_request(
            "GET",
            f"/api/conversations/{conversation_id}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "conversation not found"

        stranger_status, headers, body = wsgi_request(
            "DELETE",
            f"/api/conversations/{conversation_id}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("403"), body
        assert json_body(body, headers)["error"] == "scope-forbidden"

        member_status, headers, body = wsgi_request(
            "GET",
            f"/api/conversations/{conversation_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), body

    def test_creating_a_conversation_on_a_hidden_scope_is_404(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
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
        stranger_status, headers, body = wsgi_request(
            "POST",
            "/api/conversations",
            body=json.dumps({"scope_kind": "binary", "scope_id": ids["binary"]}),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "binary not found"

        member_status, headers, body = wsgi_request(
            "POST",
            "/api/conversations",
            body=json.dumps({"scope_kind": "binary", "scope_id": ids["binary"]}),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("201"), body

    def test_post_message_stores_both_turns(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = "It returns 1."
        conversation_id = self._create(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/conversations/{conversation_id}/messages",
            body=json.dumps({"content": "what does this do?"}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["conversation_id"] == conversation_id
        assert payload["user"]["content"] == "what does this do?"
        assert payload["assistant"]["content"] == "It returns 1."
        assert len(fake_llm.calls) == 1
        assert conversations.SYSTEM_PROMPT in fake_llm.calls[0][0]["content"]
        _, headers, body = wsgi_request("GET", f"/api/conversations/{conversation_id}")
        stored = json_body(body, headers)
        assert [message["content"] for message in stored["messages"]] == [
            "what does this do?",
            "It returns 1.",
        ]

    def test_post_blank_message_400(
        self, conn: sqlite3.Connection, fake_llm: FakeLlmClient
    ) -> None:
        conversation_id = self._create(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/conversations/{conversation_id}/messages",
            body=json.dumps({"content": "   "}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "content must be a non-empty string"
        assert fake_llm.calls == []
        assert store.list_messages(conn, conversation_id) == []

    def test_post_without_a_client_503(self, conn: sqlite3.Connection) -> None:
        conversation_id = self._create(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/conversations/{conversation_id}/messages",
            body=json.dumps({"content": "hi"}),
        )
        assert status.startswith("503")
        payload = json_body(body, headers)
        assert payload["error"] == "llm-unavailable"
        assert "REPORTAL_LLM_ENDPOINT" in payload["detail"]

    def test_post_model_error_502_keeps_only_the_user_message(
        self, conn: sqlite3.Connection
    ) -> None:
        llm.set_client(FailingLlmClient("model exploded"))
        conversation_id = self._create(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/conversations/{conversation_id}/messages",
            body=json.dumps({"content": "hi"}),
        )
        assert status.startswith("502")
        payload = json_body(body, headers)
        assert payload["error"] == "llm-error"
        assert payload["detail"] == "model exploded"
        messages = store.list_messages(conn, conversation_id)
        assert [message["role"] for message in messages] == ["user"]

    def test_post_unknown_conversation_404(self, portal_db: Path, fake_llm: FakeLlmClient) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/conversations/999/messages", body=json.dumps({"content": "hi"})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "conversation not found"
        assert fake_llm.calls == []

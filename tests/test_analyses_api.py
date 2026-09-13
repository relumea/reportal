"""Tests for the analyses listing/log/delete routes and the function filters."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, json_body, wsgi_request

from reportal import analysis_log, engines, store

# A function name whose import family the capability rule table classifies as
# networking (the `WSA` prefix), used by the capability-filter test.
NETWORKING_FUNCTION = "WSAStartup"

# A name_source the composition labels as `User` (an unrecognised stored
# source, e.g. a manual rename).
USER_SOURCE = "manual"


def _binary(conn: sqlite3.Connection, name: str = "demo.exe") -> int:
    return store.add_binary(conn, sha256=name.encode().hex().ljust(64, "0"), name=name)


def _analysis(conn: sqlite3.Connection, binary_id: int, engine: str = "manual") -> int:
    return store.create_analysis(conn, binary_id=binary_id, engine=engine)


def _function(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    va: int = 0x1000,
    name: str = "sub_1000",
    size: int = 32,
    status: str = "STUB",
    name_source: str = "rebrew",
) -> int:
    return store.add_function(
        conn,
        analysis_id=analysis_id,
        va=va,
        name=name,
        size=size,
        status=status,
        name_source=name_source,
    )


def _get(path: str) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("GET", path)


class TestListAnalysesRoute:
    def test_rows_keep_their_keys_and_gain_the_filters_view_needs(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _binary(conn)
        analysis_id = _analysis(conn, binary_id)
        status, headers, body = _get("/api/analyses")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["total"] == 1
        row = payload["analyses"][0]
        assert {
            "id",
            "binary_id",
            "status",
            "engine",
            "created_at",
            "finished_at",
            "log",
            "binary_name",
            "tags",
        } <= set(row)
        assert row["id"] == analysis_id
        assert row["binary_name"] == "demo.exe"
        assert row["tags"] == []

    def test_status_filter_reports_the_unfiltered_total(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        pending = _analysis(conn, binary_id)
        done = _analysis(conn, binary_id)
        store.update_analysis_status(conn, done, status=store.ANALYSIS_STATUS_DONE)

        _, headers, body = _get("/api/analyses?status=pending")
        payload = json_body(body, headers)
        assert [row["id"] for row in payload["analyses"]] == [pending]
        assert payload["count"] == 1
        assert payload["total"] == 2

    def test_search_filter(self, conn: sqlite3.Connection) -> None:
        notepad = _binary(conn, "notepad.exe")
        _binary(conn, "calc.exe")
        analysis_id = _analysis(conn, notepad)
        _, headers, body = _get("/api/analyses?search=notepad")
        payload = json_body(body, headers)
        assert [row["id"] for row in payload["analyses"]] == [analysis_id]

    def test_a_filter_that_matches_nothing_says_so(self, conn: sqlite3.Connection) -> None:
        _analysis(conn, _binary(conn))
        _, headers, body = _get("/api/analyses?status=failed")
        payload = json_body(body, headers)
        assert payload["analyses"] == []
        assert payload["count"] == 0
        assert payload["total"] == 1

    def test_order_and_limit(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        first = _analysis(conn, binary_id)
        second = _analysis(conn, binary_id)
        _, headers, body = _get("/api/analyses?order=oldest")
        assert [row["id"] for row in json_body(body, headers)["analyses"]] == [first, second]
        _, headers, body = _get("/api/analyses?limit=1")
        assert [row["id"] for row in json_body(body, headers)["analyses"]] == [second]

    def test_binary_id_filter_scopes_the_total_too(self, conn: sqlite3.Connection) -> None:
        first = _binary(conn, "first.exe")
        second = _binary(conn, "second.exe")
        first_analysis = _analysis(conn, first)
        _analysis(conn, second)
        _, headers, body = _get(f"/api/analyses?binary_id={first}")
        payload = json_body(body, headers)
        assert [row["id"] for row in payload["analyses"]] == [first_analysis]
        assert payload["total"] == 1

    @pytest.mark.parametrize(
        "query,error",
        [
            ("status=finished", "invalid status"),
            ("order=random", "invalid order"),
            ("limit=0", "invalid limit"),
            (f"limit={store.MAX_ANALYSIS_LIMIT + 1}", "invalid limit"),
            ("limit=abc", "limit must be an integer"),
        ],
    )
    def test_unknown_values_refused(self, conn: sqlite3.Connection, query: str, error: str) -> None:
        status, headers, body = _get(f"/api/analyses?{query}")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == error


class TestAnalysisLogsRoute:
    def test_round_trip_newest_first_with_the_true_total(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        analysis_log.append_entry(conn, analysis_id, message="scan queued")
        analysis_log.append_entry(
            conn, analysis_id, severity=analysis_log.SEVERITY_WARN, message="slow engine"
        )

        _, headers, body = _get(f"/api/analyses/{analysis_id}/logs")
        payload = json_body(body, headers)
        assert payload["total"] == 3
        assert payload["count"] == 3
        assert payload["limit"] == analysis_log.DEFAULT_LOG_LIMIT
        assert payload["offset"] == 0
        assert [entry["message"] for entry in payload["logs"][:2]] == [
            "slow engine",
            "scan queued",
        ]
        assert [entry["severity"] for entry in payload["logs"][:2]] == ["warn", "info"]

    def test_limit_bounds_the_page_and_keeps_the_total(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        for index in range(4):
            analysis_log.append_entry(conn, analysis_id, message=f"entry {index}")
        _, headers, body = _get(f"/api/analyses/{analysis_id}/logs?limit=2&offset=1")
        payload = json_body(body, headers)
        assert payload["count"] == 2
        assert payload["total"] == 5
        assert [entry["message"] for entry in payload["logs"]] == ["entry 2", "entry 1"]

    def test_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _get("/api/analyses/4242/logs")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "analysis not found"

    @pytest.mark.parametrize(
        "query,error",
        [
            ("limit=0", "invalid limit"),
            (f"limit={analysis_log.MAX_LOG_LIMIT + 1}", "invalid limit"),
            ("offset=-1", "invalid offset"),
            ("limit=abc", "limit must be an integer"),
        ],
    )
    def test_out_of_range_values_refused(
        self, conn: sqlite3.Connection, query: str, error: str
    ) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        status, headers, body = _get(f"/api/analyses/{analysis_id}/logs?{query}")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == error

    def test_a_failed_scan_is_recorded_in_the_log(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path=str(target))

        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew imports exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "imports", boom)
        status, _, _body = wsgi_request("POST", f"/api/binaries/{binary_id}/capabilities")
        assert status.startswith("500")

        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert analysis_id is not None
        _, headers, body = _get(f"/api/analyses/{analysis_id}/logs")
        messages = [entry["message"] for entry in json_body(body, headers)["logs"]]
        assert "capabilities scan started" in messages
        assert any(message.startswith("capabilities scan failed") for message in messages)


class TestDeleteAnalysisRoute:
    def test_delete_removes_dependents_and_reverts_through_the_journal(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _binary(conn)
        kept = _analysis(conn, binary_id)
        doomed = _analysis(conn, binary_id)
        function_id = _function(conn, doomed)
        store.set_decompilation(conn, function_id, "void sub_1000(void) {}", "kuna")
        store.set_scan(conn, doomed, store.SCAN_KIND_TRIAGE, {"toolchain": {}})
        store.record_match(
            conn,
            function_id=function_id,
            candidate_function_id=function_id,
            similarity=99.0,
            confidence=1.0,
        )

        status, headers, body = wsgi_request("DELETE", f"/api/analyses/{doomed}")
        assert status.startswith("200")
        payload = json_body(body, headers)
        action = payload["journal_action"]
        assert payload["deleted"] == doomed
        assert payload["functions_removed"] == 1
        assert store.get_analysis(conn, doomed) is None
        assert store.list_functions(conn, analysis_id=doomed) == []
        assert store.get_decompilation(conn, function_id) is None
        assert analysis_log.count_entries(conn, doomed) == 0
        assert store.get_analysis(conn, kept) is not None

        reverted = wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        assert reverted[0].startswith("200")
        assert store.get_analysis(conn, doomed) is not None
        restored = store.list_functions(conn, analysis_id=doomed)
        assert [row["id"] for row in restored] == [function_id]
        assert store.get_decompilation(conn, function_id) is not None
        assert store.get_scan(conn, doomed, store.SCAN_KIND_TRIAGE) == {"toolchain": {}}
        assert analysis_log.count_entries(conn, doomed) > 0
        assert store.list_matches(conn, function_id) != []

    def test_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("DELETE", "/api/analyses/4242")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "analysis not found"

    def test_last_analysis_with_functions_is_409(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        only = _analysis(conn, binary_id)
        _function(conn, only)
        status, headers, body = wsgi_request("DELETE", f"/api/analyses/{only}")
        assert status.startswith("409")
        payload = json_body(body, headers)
        assert payload["error"] == "last-analysis"
        assert store.get_analysis(conn, only) is not None

    def test_last_analysis_without_functions_is_deletable(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        only = _analysis(conn, binary_id)
        status, _headers, _body = wsgi_request("DELETE", f"/api/analyses/{only}")
        assert status.startswith("200")
        assert store.get_analysis(conn, only) is None

    def test_a_second_analysis_is_deletable(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        first = _analysis(conn, binary_id)
        second = _analysis(conn, binary_id)
        _function(conn, first)
        _function(conn, second, va=0x2000)
        status, _headers, _body = wsgi_request("DELETE", f"/api/analyses/{second}")
        assert status.startswith("200")
        assert store.get_analysis(conn, second) is None
        assert store.get_analysis(conn, first) is not None


class TestFunctionFilterRoutes:
    def _seed(self, conn: sqlite3.Connection) -> dict[str, int]:
        binary_id = _binary(conn)
        analysis_id = _analysis(conn, binary_id)
        small = _function(conn, analysis_id, va=0x1000, name="sub_1000", size=16)
        large = _function(conn, analysis_id, va=0x2000, name="WinMain", size=512, status="EXACT")
        imported = _function(
            conn, analysis_id, va=0x3000, name=NETWORKING_FUNCTION, size=6, name_source="import"
        )
        renamed = _function(
            conn, analysis_id, va=0x4000, name="parse_config", size=64, name_source=USER_SOURCE
        )
        return {
            "binary": binary_id,
            "analysis": analysis_id,
            "small": small,
            "large": large,
            "imported": imported,
            "renamed": renamed,
        }

    def _functions(self, path: str) -> dict[str, Any]:
        status, headers, body = _get(path)
        assert status.startswith("200"), body
        payload: dict[str, Any] = json_body(body, headers)
        return payload

    def test_name_source_filter(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?name_source=User")
        assert [row["id"] for row in payload["functions"]] == [ids["renamed"]]
        assert payload["total"] == 4
        assert payload["count"] == 1
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?name_source=System")
        assert sorted(row["id"] for row in payload["functions"]) == sorted(
            [ids["large"], ids["imported"]]
        )
        # A placeholder name is `No Debug Info` whatever source it carries.
        payload = self._functions(
            f"/api/binaries/{ids['binary']}/functions?name_source=No+Debug+Info"
        )
        assert [row["id"] for row in payload["functions"]] == [ids["small"]]

    def test_capability_filter(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?capability=networking")
        assert [row["id"] for row in payload["functions"]] == [ids["imported"]]
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?capability=crypto")
        assert payload["functions"] == []

    def test_size_range_and_its_boundaries(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?min_size=16")
        assert sorted(row["id"] for row in payload["functions"]) == sorted(
            [ids["small"], ids["large"], ids["renamed"]]
        )
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?max_size=16")
        assert sorted(row["id"] for row in payload["functions"]) == sorted(
            [ids["small"], ids["imported"]]
        )
        payload = self._functions(
            f"/api/binaries/{ids['binary']}/functions?min_size=64&max_size=64"
        )
        assert [row["id"] for row in payload["functions"]] == [ids["renamed"]]

    def test_string_filter_reads_the_stored_decompilation(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        store.set_decompilation(
            conn, ids["large"], 'MessageBoxA(0, "unique marker", 0, 0);', "kuna"
        )
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?string=unique+marker")
        assert [row["id"] for row in payload["functions"]] == [ids["large"]]

    def test_match_filter(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        store.record_match(
            conn,
            function_id=ids["large"],
            candidate_function_id=ids["small"],
            similarity=95.0,
            confidence=0.9,
        )
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?match=matched")
        assert [row["id"] for row in payload["functions"]] == [ids["large"]]
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?match=unmatched")
        assert ids["large"] not in [row["id"] for row in payload["functions"]]

    def test_sort_and_order(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        sorted_sizes = self._functions(
            f"/api/binaries/{ids['binary']}/functions?sort=size&order=desc"
        )
        assert [row["size"] for row in sorted_sizes["functions"]] == [512, 64, 16, 6]
        by_name = self._functions(f"/api/binaries/{ids['binary']}/functions?sort=name&order=asc")
        assert [row["name"] for row in by_name["functions"]] == [
            NETWORKING_FUNCTION,
            "WinMain",
            "parse_config",
            "sub_1000",
        ]

    def test_default_order_is_by_va(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions")
        assert [row["va"] for row in payload["functions"]] == [0x1000, 0x2000, 0x3000, 0x4000]

    def test_counts_tell_a_filter_from_a_small_binary(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        payload = self._functions(f"/api/binaries/{ids['binary']}/functions?min_size=1024")
        assert payload["functions"] == []
        assert payload["count"] == 0
        assert payload["total"] == 4

    @pytest.mark.parametrize(
        "query,error",
        [
            ("name_source=Debug Info", "invalid name_source"),
            ("capability=telepathy", "invalid capability"),
            ("match=maybe", "invalid match"),
            ("sort=similarity", "invalid sort"),
            ("order=sideways", "invalid order"),
            ("min_size=-1", "invalid min_size"),
            ("max_size=abc", "max_size must be an integer"),
            ("min_size=100&max_size=10", "invalid size range"),
            (f"max_size={1 << 31}", "invalid max_size"),
        ],
    )
    def test_unknown_values_refused(self, conn: sqlite3.Connection, query: str, error: str) -> None:
        ids = self._seed(conn)
        status, headers, body = _get(f"/api/binaries/{ids['binary']}/functions?{query}")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == error

    def test_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _get("/api/binaries/4242/functions?sort=size")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

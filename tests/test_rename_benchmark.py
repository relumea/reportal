"""Tests for the rename half of the benchmark: proposals against symbol names.

The report is a stored read, so the tests seed the two stored inputs directly:
functions a debug symbol file named (the ``symbol`` name source) and the stored
library or unstrip reading the proposals come from.  No engine and no optional
extra are involved.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import benchmark, cli, library, mcp_server, store, symbols, unstrip

runner = CliRunner()


def _get(path: str) -> Any:
    """Issue a GET and return its JSON body, asserting the 200."""
    status, headers, body = wsgi_request("GET", path)
    assert status.startswith("200"), body
    return json_body(body, headers)


def _seed(
    conn: sqlite3.Connection,
    *,
    symbol_names: dict[int, str] | None = None,
    unnamed: int = 1,
) -> dict[str, int]:
    """One binary whose functions carry symbol names and plain names."""
    binary_id = store.add_binary(conn, sha256="cc" * 32, name="lib.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    ids: dict[str, int] = {"binary": binary_id, "analysis": analysis_id}
    for index, (va, name) in enumerate((symbol_names or {}).items()):
        ids[f"symbol_{index}"] = store.add_function(
            conn,
            analysis_id=analysis_id,
            va=va,
            name=name,
            size=32,
            name_source=symbols.SYMBOL_NAME_SOURCE,
        )
    for index in range(unnamed):
        ids[f"sub_{index}"] = store.add_function(
            conn,
            analysis_id=analysis_id,
            va=0x9000 + index * 0x10,
            name=f"sub_{0x9000 + index * 0x10:x}",
            size=16,
            name_source="rebrew",
        )
    return ids


def _store_library(
    conn: sqlite3.Connection, binary_id: int, candidates: list[dict[str, Any]]
) -> None:
    """Store a library reading whose candidates are the given rows."""
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(
        conn,
        analysis_id,
        library.SCAN_KIND,
        {
            "binary_id": binary_id,
            "stored": True,
            "components": [],
            "count": 0,
            "candidates": len(candidates),
            "functions": candidates,
            "notes": [],
        },
    )


def _candidate(
    va: int, name: str, *, module: str = "msvcrt", confidence: float = 0.9
) -> dict[str, Any]:
    return {
        "va": f"0x{va:08x}",
        "name": name,
        "module": module,
        "kind": "CRT",
        "confidence": confidence,
        "function_id": None,
        "size": 0,
    }


def _store_unstrip(
    conn: sqlite3.Connection, binary_id: int, proposals: list[dict[str, Any]]
) -> None:
    """Store an unstrip reading whose proposals are the given rows."""
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_UNSTRIP,
        {"candidates": len(proposals), "proposals": proposals, "applied": False},
    )


class TestMetrics:
    def _labelled(self) -> list[dict[str, Any]]:
        return [
            {"va": 0x1000, "name": "_memcpy"},
            {"va": 0x2000, "name": "inflate_block"},
            {"va": 0x3000, "name": "write_log"},
        ]

    def test_every_proposal_correct_scores_one(self) -> None:
        proposals = [
            {"va": "0x1000", "name": "_memcpy", "module": "msvcrt", "confidence": 0.9},
            {"va": "0x2000", "name": "inflate_block", "module": "zlib", "confidence": 0.8},
            {"va": "0x3000", "name": "write_log", "module": "msvcrt", "confidence": 0.7},
        ]
        scored = benchmark.rename_metrics(self._labelled(), proposals)
        assert scored["queries"] == 3
        assert scored["proposed"] == 3
        assert scored["correct"] == 3
        assert scored["precision"] == 1.0
        assert scored["recall"] == 1.0
        assert scored["f1"] == 1.0
        assert scored["wrong"] == []
        assert scored["missing"] == []

    def test_a_decorated_name_is_close_not_correct(self) -> None:
        proposals = [
            {"va": "0x1000", "name": "memcpy", "module": "msvcrt", "confidence": 0.9},
            {"va": "0x2000", "name": "Inflate_Block", "module": "zlib", "confidence": 0.8},
        ]
        scored = benchmark.rename_metrics(self._labelled(), proposals)
        assert scored["correct"] == 0
        assert scored["close"] == 2
        assert scored["precision"] == 0.0
        assert scored["recall"] == 0.0
        assert len(scored["wrong"]) == 2

    def test_a_missed_symbol_lowers_recall_only(self) -> None:
        proposals = [
            {"va": "0x1000", "name": "_memcpy", "module": "msvcrt", "confidence": 0.9},
        ]
        scored = benchmark.rename_metrics(self._labelled(), proposals)
        assert scored["proposed"] == 1
        assert scored["correct"] == 1
        assert scored["precision"] == 1.0
        assert scored["recall"] == pytest.approx(0.3333)
        assert [row["name"] for row in scored["missing"]] == ["inflate_block", "write_log"]

    def test_a_wrong_proposal_lowers_precision_only(self) -> None:
        proposals = [
            {"va": "0x1000", "name": "_memcpy", "module": "msvcrt", "confidence": 0.9},
            {"va": "0x2000", "name": "read_log", "module": "msvcrt", "confidence": 0.6},
        ]
        scored = benchmark.rename_metrics(self._labelled(), proposals)
        assert scored["proposed"] == 2
        assert scored["correct"] == 1
        assert scored["precision"] == 0.5
        assert scored["recall"] == pytest.approx(0.3333)
        assert scored["wrong"][0]["proposed"] == "read_log"

    def test_an_unlabelled_proposal_is_unscored(self) -> None:
        proposals = [
            {"va": "0x1000", "name": "_memcpy", "module": "msvcrt", "confidence": 0.9},
            {"va": "0x7000", "name": "strlen", "module": "msvcrt", "confidence": 0.5},
        ]
        scored = benchmark.rename_metrics(self._labelled(), proposals)
        assert scored["correct"] == 1
        assert scored["proposed"] == 1
        assert scored["precision"] == 1.0
        assert [row["name"] for row in scored["unscored"]] == ["strlen"]

    def test_no_proposals_scores_zero_without_dividing_by_zero(self) -> None:
        scored = benchmark.rename_metrics(self._labelled(), [])
        assert scored["queries"] == 3
        assert scored["proposed"] == 0
        assert scored["precision"] == 0.0
        assert scored["recall"] == 0.0
        assert scored["f1"] == 0.0

    def test_a_duplicate_address_keeps_the_first_proposal(self) -> None:
        proposals = [
            {"va": "0x1000", "name": "_memcpy", "module": "msvcrt", "confidence": 0.9},
            {"va": "0x1000", "name": "wrong", "module": "other", "confidence": 0.4},
        ]
        scored = benchmark.rename_metrics(self._labelled(), proposals)
        assert scored["correct"] == 1
        assert scored["wrong"] == []

    def test_the_detail_lists_are_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(benchmark, "MAX_RENAME_ROWS", 1)
        proposals = [{"va": f"0x{0x1000 + index * 0x10:x}", "name": "x"} for index in range(3)]
        labelled = [{"va": 0x1000 + index * 0x10, "name": "y"} for index in range(3)]
        scored = benchmark.rename_metrics(labelled, proposals)
        assert len(scored["wrong"]) == 1
        assert scored["truncated"] is True


class TestReport:
    def test_the_library_reading_is_preferred(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, symbol_names={0x1000: "_memcpy", 0x2000: "inflate_block"})
        _store_unstrip(
            conn,
            ids["binary"],
            [{"va": 0x1000, "proposed_name": "_memcpy", "module": "msvcrt", "confidence": 0.9}],
        )
        _store_library(
            conn,
            ids["binary"],
            [_candidate(0x1000, "_memcpy"), _candidate(0x2000, "inflate")],
        )
        payload = benchmark.rename_report(conn, ids["binary"])
        assert payload["stored"] is True
        assert payload["proposal_source"] == "library"
        assert payload["labels"]["count"] == 2
        assert payload["proposals"]["count"] == 2
        assert payload["metrics"]["correct"] == 1
        assert payload["metrics"]["recall"] == 0.5

    def test_the_unstrip_reading_is_used_when_that_is_all_there_is(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn, symbol_names={0x1000: "_memcpy"})
        _store_unstrip(
            conn,
            ids["binary"],
            [
                {
                    "function_id": ids["symbol_0"],
                    "va": 0x1000,
                    "current_name": "sub_1000",
                    "proposed_name": "_memcpy",
                    "module": "msvcrt",
                    "kind": "CRT",
                    "confidence": 0.9,
                }
            ],
        )
        payload = benchmark.rename_report(conn, ids["binary"])
        assert payload["proposal_source"] == "unstrip"
        assert payload["metrics"]["correct"] == 1
        assert payload["metrics"]["precision"] == 1.0

    def test_no_symbol_names_answers_stored_false(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _store_library(conn, ids["binary"], [_candidate(0x9000, "strlen")])
        payload = benchmark.rename_report(conn, ids["binary"])
        assert payload == {
            "binary_id": ids["binary"],
            "binary_name": "lib.exe",
            "stored": False,
            "reason": "no-symbols",
            "proposal_source": "",
            "labels": {"count": 0, "source": "symbol"},
            "proposals": {"count": 0, "scored": 0, "unscored": 0},
            "metrics": None,
            "notes": [
                benchmark.NO_SYMBOLS_DETAIL.format(
                    binary_id=ids["binary"],
                    command=f"reportal symbols {ids['binary']} <file>",
                )
            ],
        }

    def test_no_stored_reading_answers_stored_false(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, symbol_names={0x1000: "_memcpy"})
        payload = benchmark.rename_report(conn, ids["binary"])
        assert payload["stored"] is False
        assert payload["reason"] == "no-proposals"
        assert "reportal library" in payload["notes"][0]

    def test_an_unknown_binary_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(benchmark.BenchmarkError) as failure:
            benchmark.rename_report(conn, 9999)
        assert failure.value.code == "binary not found"

    def test_an_empty_reading_answers_stored_true_with_zeros(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn, symbol_names={0x1000: "_memcpy"})
        _store_library(conn, ids["binary"], [])
        payload = benchmark.rename_report(conn, ids["binary"])
        assert payload["stored"] is True
        assert payload["metrics"]["recall"] == 0.0
        assert any("holds no candidate" in note for note in payload["notes"])


class TestRoutes:
    def test_get_serves_the_report(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, symbol_names={0x1000: "_memcpy"})
        _store_library(conn, ids["binary"], [_candidate(0x1000, "_memcpy")])
        payload = _get(f"/api/binaries/{ids['binary']}/rename-benchmark")
        assert payload["proposal_source"] == "library"
        assert payload["metrics"]["correct"] == 1
        assert payload["metrics"]["precision"] == 1.0

    def test_nothing_to_score_is_a_200_with_the_reason(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _get(f"/api/binaries/{ids['binary']}/rename-benchmark")
        assert payload["stored"] is False
        assert payload["reason"] == "no-symbols"
        assert payload["metrics"] is None

    def test_an_unknown_binary_is_a_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/9999/rename-benchmark")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_the_doc_url_a_refusal_carries_resolves(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/9999/rename-benchmark")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["doc_url"] is not None


class TestMcp:
    def test_the_read_answers(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, symbol_names={0x1000: "_memcpy"})
        _store_library(conn, ids["binary"], [_candidate(0x1000, "_memcpy")])
        payload, failed = mcp_server.call_tool("get_rename_benchmark", {"binary_id": ids["binary"]})
        assert failed is False
        assert payload["metrics"]["correct"] == 1

    def test_nothing_to_score_is_not_a_tool_error(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, failed = mcp_server.call_tool("get_rename_benchmark", {"binary_id": ids["binary"]})
        assert failed is False
        assert payload["stored"] is False

    def test_an_unknown_binary_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        payload, failed = mcp_server.call_tool("get_rename_benchmark", {"binary_id": 9999})
        assert failed is True
        assert payload["error"] == "binary not found"


class TestCli:
    def test_the_command_prints_the_metrics(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn, symbol_names={0x1000: "_memcpy", 0x2000: "inflate_block"})
        _store_library(
            conn,
            ids["binary"],
            [_candidate(0x1000, "_memcpy"), _candidate(0x2000, "read_log", module="msvcrt")],
        )
        conn.commit()
        result = runner.invoke(cli.app, ["rename-benchmark", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "precision" in result.output
        assert "disagreements" in result.output
        assert "read_log" in result.output

    def test_the_json_flag_prints_the_payload(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn, symbol_names={0x1000: "_memcpy"})
        _store_library(conn, ids["binary"], [_candidate(0x1000, "_memcpy")])
        conn.commit()
        result = runner.invoke(cli.app, ["rename-benchmark", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["metrics"]["correct"] == 1
        assert payload["notes"]

    def test_nothing_to_score_names_the_command(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        conn.commit()
        result = runner.invoke(cli.app, ["rename-benchmark", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "reportal symbols" in result.output

    def test_an_unknown_binary_fails_loud(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        conn.commit()
        result = runner.invoke(cli.app, ["rename-benchmark", "9999"])
        assert result.exit_code == 1
        assert "binary not found" in result.output


def test_the_rename_report_reads_only_what_is_stored(conn: sqlite3.Connection) -> None:
    """The report is a read: no engine, no journal, no scan written."""
    ids = _seed(conn, symbol_names={0x1000: "_memcpy"})
    _store_library(conn, ids["binary"], [_candidate(0x1000, "_memcpy")])
    analyses_before = len(store.list_analyses(conn))
    scans_before = [dict(row) for row in conn.execute("SELECT kind FROM scans")]
    benchmark.rename_report(conn, ids["binary"])
    assert len(store.list_analyses(conn)) == analyses_before
    assert [dict(row) for row in conn.execute("SELECT kind FROM scans")] == scans_before
    assert unstrip.AUTO_NAME_SOURCES  # the proposal module is untouched by this read

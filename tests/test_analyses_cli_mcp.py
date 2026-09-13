"""Tests for the analysis lifecycle CLI commands and MCP tools."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from reportal import analysis_log, cli, journal, mcp_tools, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _seed(tmp_path: Path, monkeypatch: Any) -> dict[str, Any]:
    """A workspace with one binary, one analysis and one function."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(
            conn, sha256="e" * 64, name="demo.exe", path="/tmp/demo.exe", size=64
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16
        )
    return {
        "db": db,
        "binary": binary_id,
        "analysis": analysis_id,
        "function": function_id,
    }


class TestCli:
    def test_the_detail_read(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["analysis", str(ids["analysis"]), "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["function_count"] == 1
        assert payload["engine"] == "manual"

    def test_the_status_read(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["analysis", str(ids["analysis"]), "--json", "--status"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["status"] == "pending"

    def test_the_params_read(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["analysis", str(ids["analysis"]), "--params", "--json"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["binary"]["sha256"] == "e" * 64

    def test_the_function_map(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["analysis", str(ids["analysis"]), "--func-maps", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert [row["va"] for row in payload["functions"]] == [0x1000]
        assert payload["total"] == 1

    def test_the_tags_read(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["analysis", str(ids["analysis"]), "--tags", "--json"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["tags"] == []

    def test_an_unknown_analysis_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        _seed(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["analysis", "4242"]).exit_code == 1

    def test_the_relabel_and_its_revert(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app, ["analysis-update", str(ids["analysis"]), "--engine", "rebrew", "--json"]
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["engine"] == "rebrew"
        with contextlib.closing(store.connect(ids["db"])) as conn:
            journal.revert_action(conn, payload["journal_action"])
            restored = store.get_analysis(conn, ids["analysis"])
        assert restored is not None
        assert restored["engine"] == "manual"

    def test_the_log_append_and_its_revert(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app,
            [
                "analysis-log",
                str(ids["analysis"]),
                "checked the entry point",
                "--severity",
                "warn",
                "--json",
            ],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["severity"] == "warn"
        with contextlib.closing(store.connect(ids["db"])) as conn:
            journal.revert_action(conn, payload["journal_action"])
            entries, _ = analysis_log.list_entries(conn, ids["analysis"])
        assert all("entry point" not in str(entry["message"]) for entry in entries)

    def test_an_unknown_severity_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app, ["analysis-log", str(ids["analysis"]), "noted", "--severity", "loud"]
        )

        assert result.exit_code == 1
        assert "unknown severity" in result.output

    def test_a_blank_message_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["analysis-log", str(ids["analysis"]), "   "])

        assert result.exit_code == 1
        assert "must not be empty" in result.output

    def test_the_requeue_and_its_revert(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.update_analysis_status(conn, ids["analysis"], status="failed")

        result = runner.invoke(cli.app, ["analysis-requeue", str(ids["analysis"]), "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["status"] == "pending"
        with contextlib.closing(store.connect(ids["db"])) as conn:
            journal.revert_action(conn, payload["journal_action"])
            restored = store.get_analysis(conn, ids["analysis"])
        assert restored is not None
        assert restored["status"] == "failed"

    def test_the_tags_replace_and_its_revert(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app, ["analysis-tags", str(ids["analysis"]), "pe", "games", "--json"]
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["tags"] == ["games", "pe"]
        with contextlib.closing(store.connect(ids["db"])) as conn:
            journal.revert_action(conn, payload["journal_action"])
            assert store.get_binary_tags(conn, ids["binary"]) == []

    def test_the_tags_replace_of_an_unknown_analysis_exits_non_zero(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _seed(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["analysis-tags", "4242", "pe"]).exit_code == 1

    def test_the_imported_functions_listing(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.add_function(
                conn,
                analysis_id=ids["analysis"],
                va=0x3000,
                name="malloc",
                size=6,
                status="THUNK",
                name_source=store.IMPORTED_NAME_SOURCE,
            )
            store.set_decompilation(
                conn, ids["function"], "void sub_1000(void) { malloc(4); }", "kuna"
            )

        result = runner.invoke(cli.app, ["imported-functions", str(ids["analysis"]), "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["total"] == 1
        assert payload["caller_method"] == "decompilation-text"
        assert payload["functions"][0]["name"] == "malloc"
        assert payload["functions"][0]["caller_count"] == 1
        human = runner.invoke(cli.app, ["imported-functions", str(ids["analysis"])])
        assert human.exit_code == 0

    def test_the_imported_functions_listing_of_an_unknown_analysis_exits_non_zero(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _seed(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["imported-functions", "4242"]).exit_code == 1

    def test_an_out_of_range_limit_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app, ["imported-functions", str(ids["analysis"]), "--limit", "0"]
        )

        assert result.exit_code == 1

    def test_download_takes_an_analysis_id(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        source = tmp_path / "demo.exe"
        source.write_bytes(b"MZanalysis-bytes")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            conn.execute("UPDATE binaries SET path = ? WHERE id = ?", (str(source), ids["binary"]))
            conn.commit()

        result = runner.invoke(
            cli.app,
            [
                "download",
                str(ids["analysis"]),
                "--analysis",
                "--output",
                str(tmp_path / "out.bin"),
                "--json",
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["analysis_id"] == ids["analysis"]
        assert payload["binary_id"] == ids["binary"]
        assert (tmp_path / "out.bin").read_bytes() == b"MZanalysis-bytes"

    def test_download_of_an_unknown_analysis_exits_non_zero(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        _seed(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["download", "4242", "--analysis"]).exit_code == 1


class TestMcp:
    def test_the_read_tools_are_read_only(self) -> None:
        for name in (
            "get_analysis",
            "get_analysis_params",
            "get_analysis_func_maps",
            "get_imported_functions",
        ):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.read_only_hint is True
        for name in (
            "update_analysis",
            "append_analysis_log",
            "requeue_analysis",
            "set_analysis_tags",
        ):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.destructive_hint is True

    def _seed(self, conn: sqlite3.Connection) -> int:
        binary_id = store.add_binary(
            conn, sha256="f" * 64, name="mcp.exe", path="/tmp/mcp.exe", size=32
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=8)
        return analysis_id

    def test_get_analysis_carries_the_lifecycle(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        analysis_id = self._seed(conn)
        tool = mcp_tools.get_tool("get_analysis")
        assert tool is not None

        payload = tool.handler({"analysis_id": analysis_id})

        assert payload["function_count"] == 1
        assert payload["lifecycle"]["status"] == "pending"
        assert "journal_action" not in payload

    def test_get_analysis_params_and_func_maps(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        analysis_id = self._seed(conn)
        params = mcp_tools.get_tool("get_analysis_params")
        maps = mcp_tools.get_tool("get_analysis_func_maps")
        assert params is not None and maps is not None

        assert params.handler({"analysis_id": analysis_id})["engine"] == "manual"
        mapped = maps.handler({"analysis_id": analysis_id})
        assert [row["va"] for row in mapped["functions"]] == [0x2000]
        assert mapped["total"] == 1

    def test_update_append_and_requeue(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        analysis_id = self._seed(conn)
        update = mcp_tools.get_tool("update_analysis")
        append = mcp_tools.get_tool("append_analysis_log")
        requeue = mcp_tools.get_tool("requeue_analysis")
        assert update is not None and append is not None and requeue is not None

        relabelled = update.handler({"analysis_id": analysis_id, "engine": "rebrew"})
        assert relabelled["engine"] == "rebrew"
        assert relabelled["journal_action"]
        logged = append.handler(
            {"analysis_id": analysis_id, "message": "looked at it", "severity": "warn"}
        )
        assert logged["severity"] == "warn"
        assert logged["journal_action"]
        assert requeue.handler({"analysis_id": analysis_id})["status"] == "pending"

    def test_get_imported_functions(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        analysis_id = self._seed(conn)
        stub = store.add_function(
            conn,
            analysis_id=analysis_id,
            va=0x3000,
            name="free",
            size=6,
            status="THUNK",
            name_source=store.IMPORTED_NAME_SOURCE,
        )
        store.set_decompilation(
            conn,
            int(store.list_functions(conn, analysis_id=analysis_id)[0]["id"]),
            "void f(void) { free(0); }",
            "kuna",
        )
        tool = mcp_tools.get_tool("get_imported_functions")
        assert tool is not None

        payload = tool.handler({"analysis_id": analysis_id})

        assert payload["total"] == 1
        assert payload["functions"][0]["id"] == stub
        assert payload["functions"][0]["callers"][0]["name"] == "sub_2000"

    def test_an_unknown_severity_is_a_tool_error(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        analysis_id = self._seed(conn)
        append = mcp_tools.get_tool("append_analysis_log")
        assert append is not None

        try:
            append.handler({"analysis_id": analysis_id, "message": "noted", "severity": "loud"})
        except mcp_tools.ToolError as exc:
            assert exc.error == "invalid severity"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown severity must be a tool error")

    def test_set_analysis_tags_replaces_and_reverts(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        analysis_id = self._seed(conn)
        tool = mcp_tools.get_tool("set_analysis_tags")
        assert tool is not None

        payload = tool.handler({"analysis_id": analysis_id, "tags": ["pe", "games"]})

        assert payload["tags"] == ["games", "pe"]
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_binary_tags(conn, payload["binary_id"]) == []

    def test_an_unknown_analysis_is_a_tool_error(self, portal_db: Path) -> None:
        tool = mcp_tools.get_tool("get_analysis")
        assert tool is not None

        try:
            tool.handler({"analysis_id": 4242})
        except mcp_tools.ToolError as exc:
            assert exc.error == "analysis not found"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown analysis must be a tool error")

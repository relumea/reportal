"""Tests for the decompiler round-trip scripts.

The scripts are a pure render of the stored renames: no engine runs, no
state directory and no extra dependency.  The tests seed one binary with a
real name, a placeholder and an empty name, then check each format carries
only the real one, the API/CLI/MCP faces answer, and bad inputs refuse.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, decompiler_scripts, mcp_server, store

runner = CliRunner()


def _seed(conn: sqlite3.Connection, tmp_path: Path) -> int:
    """One binary with a named, a placeholder and an empty function."""
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ" + b"\x00" * 30)
    binary_id = store.add_binary(
        conn,
        sha256="ab" * 32,
        name="demo.exe",
        path=str(target),
        size=4096,
        fmt="PE",
        arch="x86_32",
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="memcpy", size=64, status="STUB"
    )
    store.add_function(
        conn, analysis_id=analysis_id, va=0x1010, name="sub_1010", size=64, status="STUB"
    )
    store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="", size=64, status="STUB")
    return binary_id


class TestRender:
    def test_only_real_names_are_carried(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        for fmt in decompiler_scripts.SCRIPT_FORMATS:
            payload = decompiler_scripts.script(conn, binary_id, fmt=fmt)
            assert payload["renames"] == 1
            assert payload["functions"] == 3

    def test_ghidra_script_renames_by_entry_point(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        text = str(decompiler_scripts.script(conn, binary_id, fmt="ghidra")["text"])
        assert "0x1000" in text and "memcpy" in text
        assert "sub_1010" not in text
        assert "SourceType.USER_DEFINED" in text

    def test_ida_script_uses_make_name(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        text = str(decompiler_scripts.script(conn, binary_id, fmt="ida")["text"])
        assert "MakeName(0x1000" in text and "memcpy" in text
        assert "sub_1010" not in text

    def test_binja_document_is_json(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        text = str(decompiler_scripts.script(conn, binary_id, fmt="binja")["text"])
        document = json.loads(text)
        assert document["renames"] == [{"address": 0x1000, "name": "memcpy"}]

    def test_unknown_binary_is_404(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        _seed(conn, tmp_path)
        try:
            decompiler_scripts.script(conn, 999, fmt="ghidra")
        except decompiler_scripts.ScriptError as exc:
            assert exc.code == "binary not found"
        else:  # pragma: no cover - the guard above must raise
            raise AssertionError("expected ScriptError")

    def test_unknown_format_is_rejected(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = decompiler_scripts.collect(conn, binary_id)
        try:
            decompiler_scripts.render(payload, fmt="radare2")
        except ValueError as exc:
            assert "unknown format" in str(exc)
        else:  # pragma: no cover - the guard above must raise
            raise AssertionError("expected ValueError")


class TestApi:
    def test_export_answers_a_script(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        status, _headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/decompiler-script?format=ida"
        )
        assert status == "200 OK"
        assert b"MakeName" in body

    def test_export_refuses_an_unknown_format(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/decompiler-script?format=nope"
        )
        assert status == "400 Bad Request"
        assert json_body(body, headers)["error"] == "invalid format"

    def test_export_404s_an_unknown_binary(self, conn: sqlite3.Connection) -> None:
        status, _headers, _body = wsgi_request("GET", "/api/binaries/999/decompiler-script")
        assert status == "404 Not Found"


class TestCli:
    def test_command_prints_the_script(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["decompiler-script", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "memcpy" in result.output

    def test_command_refuses_an_unknown_format(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["decompiler-script", str(binary_id), "--format", "nope"])
        assert result.exit_code != 0

    def test_command_writes_a_file(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        out = tmp_path / "renames.py"
        result = runner.invoke(
            cli.app,
            ["decompiler-script", str(binary_id), "--output", str(out), "--json"],
        )
        assert result.exit_code == 0, result.output
        assert out.is_file()
        assert json.loads(result.output)["path"] == str(out)


class TestMcp:
    def test_tool_answers_the_script(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        payload, failed = mcp_server.call_tool(
            "export_decompiler_script", {"binary_id": binary_id, "format": "ghidra"}
        )
        assert not failed
        assert payload["renames"] == 1

    def test_tool_refuses_an_unknown_format(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        _payload, failed = mcp_server.call_tool(
            "export_decompiler_script", {"binary_id": binary_id, "format": "nope"}
        )
        assert failed

    def test_tool_404s_an_unknown_binary(self, conn: sqlite3.Connection) -> None:
        _payload, failed = mcp_server.call_tool("export_decompiler_script", {"binary_id": 999})
        assert failed

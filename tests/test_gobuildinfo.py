"""Tests for Go build information recovery.

The parser is verified against a real go1.27 binary's layout (magic,
version, module path, build settings); the tests use a synthetic blob
in the same shape plus route/CLI/MCP coverage over a stored file.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, gobuildinfo, mcp_tools, store

runner = CliRunner()

BLOB = (
    b"Go buildinf:"
    b"\x08\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x13go1.27.1-X:nodwarf5\x96\x020w\xaf\x0c\x92t\x08\x02"
    b"path\tcommand-line-arguments\n"
    b"dep\tgithub.com/google/uuid\tv1.6.0\th1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=\n"
    b"build\t-buildmode=exe\n"
    b"build\t-compiler=gc\n"
    b"build\tGOOS=linux\n"
    b"build\tGOARCH=amd64\n"
)


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, data: bytes = BLOB) -> int:
    """A stored binary whose file carries the buildinfo blob."""
    target = tmp_path / "hello"
    target.write_bytes(b"\x7fELF" + b"\x00" * 64 + data)
    binary_id = store.add_binary(
        conn,
        sha256="go" * 32,
        name="hello",
        path=str(target),
        size=target.stat().st_size,
        fmt="ELF",
        arch="x86_64",
    )
    store.create_analysis(conn, binary_id=binary_id, engine="manual")
    return binary_id


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


class TestParse:
    def test_version_module_and_settings(self) -> None:
        payload = gobuildinfo.parse_buildinfo(BLOB)

        assert payload["version"] == "go1.27.1-X:nodwarf5"
        assert payload["module"] == "command-line-arguments"
        assert payload["settings"]["-compiler"] == "gc"
        assert payload["settings"]["GOOS"] == "linux"

    def test_dependencies(self) -> None:
        payload = gobuildinfo.parse_buildinfo(BLOB)

        assert payload["dependencies"] == [
            {"module": "github.com/google/uuid", "version": "v1.6.0"}
        ]

    def test_a_blob_without_deps_answers_empty(self) -> None:
        payload = gobuildinfo.parse_buildinfo(BLOB.split(b"dep\t")[0])

        assert payload["dependencies"] == []

    def test_missing_magic_is_not_go(self) -> None:
        try:
            gobuildinfo.parse_buildinfo(b"MZ" + b"\x00" * 100)
        except gobuildinfo.GobuildinfoError as exc:
            assert exc.code == "not-go"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a non-Go blob must raise")

    def test_magic_without_a_version_is_not_go(self) -> None:
        try:
            gobuildinfo.parse_buildinfo(b"Go buildinf:" + b"\x00" * 64)
        except gobuildinfo.GobuildinfoError as exc:
            assert exc.code == "not-go"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a version-less blob must raise")

    def test_build_id_from_note(self) -> None:
        import struct

        name = b"Go\x00\x00"
        desc = b"abc123\x00"
        note = struct.pack("<3I", 3, len(desc), 4) + name + desc
        assert gobuildinfo.build_id_from_note(note) == "abc123"
        assert gobuildinfo.build_id_from_note(b"short") == ""

    def test_build_id_from_note_reads_big_endian_headers(self) -> None:
        import struct

        name = b"Go\x00\x00"
        desc = b"be-build\x00"
        note = struct.pack(">3I", 3, len(desc), 4) + name + desc
        assert gobuildinfo.build_id_from_note(note) == "be-build"


class TestRecover:
    def test_recover_stores_the_scan(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = gobuildinfo.recover(conn, binary_id=binary_id)

        assert payload["version"] == "go1.27.1-X:nodwarf5"
        assert payload["module"] == "command-line-arguments"
        binary = store.get_binary(conn, binary_id)
        assert binary is not None
        assert binary["language"] == "Go"

    def test_recover_of_a_non_go_binary_is_not_go(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, data=b"plain text, no magic here")

        try:
            gobuildinfo.recover(conn, binary_id=binary_id)
        except gobuildinfo.GobuildinfoError as exc:
            assert exc.code == "not-go"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a non-Go binary must raise")

    def test_recover_of_an_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        try:
            gobuildinfo.recover(conn, binary_id=4242)
        except KeyError:
            pass
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown binary must raise KeyError")

    def test_recover_of_an_unreadable_file_is_unreadable(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        binary_id = store.add_binary(
            conn, sha256="ab" * 32, name="demo.exe", path=str(target), size=32
        )

        def boom(path: object, *args: object, **kwargs: object) -> object:
            raise OSError("denied")

        monkeypatch.setattr("builtins.open", boom)
        try:
            gobuildinfo.recover(conn, binary_id=binary_id)
        except gobuildinfo.GobuildinfoError as exc:
            assert exc.code == "unreadable"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unreadable file must raise")


class TestRoutes:
    def test_post_recovers_and_get_serves(self, portal_db: Path, conn: Any, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)

        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/gobuildinfo")
        assert status.startswith("200")
        assert json_body(body, headers)["version"] == "go1.27.1-X:nodwarf5"

        status, payload = _get(f"/api/binaries/{binary_id}/gobuildinfo")
        assert status.startswith("200")
        assert payload["module"] == "command-line-arguments"

    def test_post_of_a_non_go_binary_is_400_not_go(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, data=b"plain text, no magic here")

        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/gobuildinfo")

        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "not-go"

    def test_get_without_a_scan_is_404_no_scan(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        target = tmp_path / "plain"
        target.write_bytes(b"plain")
        binary_id = store.add_binary(conn, sha256="pl" * 32, name="plain", path=str(target), size=5)
        store.create_analysis(conn, binary_id=binary_id, engine="manual")

        status, payload = _get(f"/api/binaries/{binary_id}/gobuildinfo")

        assert status.startswith("404")
        assert payload["error"] == "no-scan"

    def test_routes_of_an_unknown_binary_are_404(self, portal_db: Path) -> None:
        status, payload = _get("/api/binaries/4242/gobuildinfo")
        assert status.startswith("404")
        assert payload["error"] == "binary not found"


class TestCli:
    def test_gobuildinfo_json(self, portal_db: Path, conn: Any, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)

        result = runner.invoke(cli.app, ["gobuildinfo", str(binary_id), "--json"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["version"] == "go1.27.1-X:nodwarf5"

    def test_gobuildinfo_human_output_names_version_and_module(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        result = runner.invoke(cli.app, ["gobuildinfo", str(binary_id)])

        assert result.exit_code == 0
        assert "go1.27.1" in result.output
        assert "command-line-arguments" in result.output
        assert "github.com/google/uuid v1.6.0" in result.output

    def test_gobuildinfo_of_a_non_go_binary_fails(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, data=b"plain text, no magic here")

        result = runner.invoke(cli.app, ["gobuildinfo", str(binary_id)])

        assert result.exit_code != 0
        assert "not-go" in result.output


class TestMcp:
    def test_get_and_run(self, portal_db: Path, conn: Any, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        run = mcp_tools.get_tool("run_gobuildinfo")
        get = mcp_tools.get_tool("get_gobuildinfo")
        assert run is not None and get is not None
        assert run.annotations.destructive_hint is True
        assert get.annotations.read_only_hint is True

        payload = run.handler({"binary_id": binary_id})

        assert payload["version"] == "go1.27.1-X:nodwarf5"
        assert get.handler({"binary_id": binary_id})["module"] == "command-line-arguments"

    def test_run_of_a_non_go_binary_is_a_tool_error(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, data=b"plain text, no magic here")
        tool = mcp_tools.get_tool("run_gobuildinfo")
        assert tool is not None

        try:
            tool.handler({"binary_id": binary_id})
        except mcp_tools.ToolError as exc:
            assert exc.error == "not-go"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a non-Go binary must be a tool error")

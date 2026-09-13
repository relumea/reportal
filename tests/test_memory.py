"""Tests for the memory-read route and tool: engine surface, API, CLI and MCP."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, engines, mcp_server, mcp_tools, store
from reportal._paths import DB_ENV

runner = CliRunner()

# .text of the conftest PE_INFO stub: RVA 0x1000, file offset 0x600, image base
# 0x400000, so VA 0x401000, RVA 0x1000 and file offset 0x600 are the same byte.
TEXT_VA = 0x401000
TEXT_RVA = 0x1000
TEXT_OFFSET = 0x600
PATTERN = bytes(range(256)) * 4  # exactly the read cap, so the boundary is testable


def _binary_file(tmp_path: Path) -> Path:
    """A file whose .text bytes at TEXT_OFFSET are PATTERN."""
    path = tmp_path / "demo.exe"
    data = bytearray(b"\x00" * (TEXT_OFFSET + len(PATTERN)))
    data[TEXT_OFFSET : TEXT_OFFSET + len(PATTERN)] = PATTERN
    path.write_bytes(bytes(data))
    return path


def _seed_binary(conn: sqlite3.Connection, path: Path) -> int:
    return store.add_binary(
        conn, sha256="ab" * 32, name="demo.exe", path=str(path), size=path.stat().st_size
    )


def _call(name: str, arguments: dict[str, Any] | None = None) -> tuple[Any, bool]:
    """Run one MCP tool through ``tools/call``; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestEngineSurface:
    def test_reads_the_actual_bytes(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        path = _binary_file(tmp_path)
        window = fake_engine.read_memory(path, address=TEXT_VA, length=8)
        assert window["bytes"] == PATTERN[:8].hex()
        assert window["kind"] == "va"
        assert window["address"] == hex(TEXT_VA)
        assert window["va"] == hex(TEXT_VA)
        assert window["section"] == ".text"
        assert window["length"] == 8
        assert fake_engine.calls == ["pe_info"]

    def test_default_length_is_the_portal_default(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        path = _binary_file(tmp_path)
        window = fake_engine.read_memory(path, address=TEXT_VA)
        assert window["length"] == engines.MEMORY_READ_DEFAULT
        assert window["bytes"] == PATTERN[: engines.MEMORY_READ_DEFAULT].hex()

    def test_address_kinds_resolve_to_the_same_bytes(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        path = _binary_file(tmp_path)
        by_va = fake_engine.read_memory(path, address=TEXT_VA, length=16, kind="va")
        by_rva = fake_engine.read_memory(path, address=TEXT_RVA, length=16, kind="rva")
        by_file = fake_engine.read_memory(path, address=TEXT_OFFSET, length=16, kind="file")
        assert by_va["bytes"] == by_rva["bytes"] == by_file["bytes"] == PATTERN[:16].hex()

    def test_one_byte_over_the_cap_is_refused(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        path = _binary_file(tmp_path)
        with pytest.raises(engines.EngineError, match="between 1 and"):
            fake_engine.read_memory(path, address=TEXT_VA, length=engines.MEMORY_READ_MAX + 1)

    def test_the_cap_itself_is_accepted(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        path = _binary_file(tmp_path)
        assert len(PATTERN) == engines.MEMORY_READ_MAX
        window = fake_engine.read_memory(path, address=TEXT_VA, length=engines.MEMORY_READ_MAX)
        assert window["length"] == engines.MEMORY_READ_MAX
        assert window["bytes"] == PATTERN.hex()

    def test_zero_length_is_refused(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        path = _binary_file(tmp_path)
        with pytest.raises(engines.EngineError, match="between 1 and"):
            fake_engine.read_memory(path, address=TEXT_VA, length=0)

    def test_an_unmapped_address_is_refused(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        path = _binary_file(tmp_path)
        # .text ends at VA 0x407600 and .data starts at 0x408000, so 0x407800
        # falls in the gap between the sections.
        with pytest.raises(engines.UnmappedAddressError):
            fake_engine.read_memory(path, address=0x407800, length=8)

    def test_an_address_below_the_image_base_is_refused(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        path = _binary_file(tmp_path)
        with pytest.raises(engines.UnmappedAddressError, match="below the image base"):
            fake_engine.read_memory(path, address=0x1000, length=8, kind="va")

    def test_a_window_past_the_section_is_refused(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        path = _binary_file(tmp_path)
        section_end = TEXT_VA + 26112
        with pytest.raises(engines.UnmappedAddressError, match="runs past"):
            fake_engine.read_memory(path, address=section_end - 4, length=8)

    def test_a_file_offset_past_the_file_is_refused(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        path = _binary_file(tmp_path)
        with pytest.raises(engines.UnmappedAddressError, match="runs past the file"):
            fake_engine.read_memory(path, address=path.stat().st_size - 4, length=8, kind="file")

    def test_an_unknown_kind_is_refused(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        path = _binary_file(tmp_path)
        with pytest.raises(engines.EngineError, match="unsupported address kind"):
            fake_engine.read_memory(path, address=TEXT_VA, kind="physical")

    def test_unavailable_engine_raises(self, tmp_path: Path) -> None:
        engine = engines.RebrewEngine(enabled=False)
        with pytest.raises(engines.EngineUnavailable):
            engine.read_memory(_binary_file(tmp_path), address=TEXT_VA)


class TestApiRoute:
    def test_reads_the_actual_bytes(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory?va=0x{TEXT_VA:x}&length=8"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == binary_id
        assert payload["kind"] == "va"
        assert payload["bytes"] == PATTERN[:8].hex()
        assert payload["length"] == 8

    def test_defaults_to_the_portal_length(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory?va={TEXT_VA}"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["length"] == engines.MEMORY_READ_DEFAULT
        assert payload["bytes"] == PATTERN[: engines.MEMORY_READ_DEFAULT].hex()

    def test_file_offset_kind(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET",
            f"/api/binaries/{binary_id}/memory?va=0x{TEXT_OFFSET:x}&length=4&kind=file",
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["kind"] == "file"
        assert payload["bytes"] == PATTERN[:4].hex()

    def test_length_at_the_cap_is_accepted(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET",
            f"/api/binaries/{binary_id}/memory?va={TEXT_VA}&length={engines.MEMORY_READ_MAX}",
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["length"] == engines.MEMORY_READ_MAX
        assert payload["bytes"] == PATTERN.hex()

    def test_length_over_the_cap_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET",
            f"/api/binaries/{binary_id}/memory?va={TEXT_VA}&length={engines.MEMORY_READ_MAX + 1}",
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid length"

    def test_unmapped_address_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory?va=0x407800&length=8"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "unmapped address"

    def test_missing_address_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/memory")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid address"

    def test_bad_kind_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory?va={TEXT_VA}&kind=physical"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid kind"

    def test_unknown_binary_404(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request("GET", "/api/binaries/999/memory?va=0x1000")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_engine_unavailable_503(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory?va={TEXT_VA}"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"


class TestCli:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int | Path]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        path = _binary_file(tmp_path)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _seed_binary(conn, path)
        return {"binary": binary_id, "path": path}

    def test_memory_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["memory", str(ids["binary"]), hex(TEXT_VA), "--length", "8", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["bytes"] == PATTERN[:8].hex()
        assert payload["kind"] == "va"

    def test_memory_command_refuses_over_the_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "memory",
                str(ids["binary"]),
                hex(TEXT_VA),
                "--length",
                str(engines.MEMORY_READ_MAX + 1),
            ],
        )
        assert result.exit_code != 0
        assert "between 1 and" in result.output

    def test_memory_command_refuses_an_unmapped_address(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["memory", str(ids["binary"]), "0x407800", "--length", "8"])
        assert result.exit_code != 0
        assert "not backed" in result.output


class TestMcp:
    def test_read_memory_tool(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        payload, is_error = _call(
            "read_memory", {"binary_id": binary_id, "address": TEXT_VA, "length": 8}
        )
        assert is_error is False
        assert payload["bytes"] == PATTERN[:8].hex()
        assert payload["kind"] == "va"

    def test_read_memory_tool_refuses_over_the_cap(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        payload, is_error = _call(
            "read_memory",
            {"binary_id": binary_id, "address": TEXT_VA, "length": engines.MEMORY_READ_MAX + 1},
        )
        assert is_error is True
        assert payload["error"] == "invalid length"

    def test_read_memory_tool_refuses_an_unmapped_address(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _binary_file(tmp_path))
        payload, is_error = _call(
            "read_memory", {"binary_id": binary_id, "address": 0x407800, "length": 8}
        )
        assert is_error is True
        assert payload["error"] == "unmapped address"

    def test_read_memory_is_registered_read_only(self) -> None:
        tools = {tool.name: tool for tool in mcp_tools.tools()}
        assert "read_memory" in tools
        assert tools["read_memory"].annotations.read_only_hint is True

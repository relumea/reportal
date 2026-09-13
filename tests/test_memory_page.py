"""Tests for the full-file memory page: engine surface, API and CLI.

The conftest PE_INFO stub places .text at VA 0x401000 (raw size 26112, file
offset 0x600) and .data at VA 0x408000 (raw size 1536, file offset 0x6C00), so
the VA range 0x407600..0x408000 is a real gap the section map does not back.
"""

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

TEXT_VA = 0x401000
TEXT_OFFSET = 0x600
PATTERN = bytes(range(256)) * 4
# The file spans both raw-backed sections, so a page at the end of .text can
# read its bytes and then report the gap.
FILE_BYTES = 0x6C00 + 0x600


def _section_file(tmp_path: Path) -> Path:
    """A file whose .text bytes at TEXT_OFFSET are PATTERN and long enough to read."""
    path = tmp_path / "demo.exe"
    data = bytearray(b"\x00" * FILE_BYTES)
    data[TEXT_OFFSET : TEXT_OFFSET + len(PATTERN)] = PATTERN
    path.write_bytes(bytes(data))
    return path


def _seed_binary(conn: sqlite3.Connection, path: Path) -> int:
    return store.add_binary(
        conn, sha256="cd" * 32, name="demo.exe", path=str(path), size=path.stat().st_size
    )


def _bytes_rows(page: dict[str, object]) -> list[dict[str, object]]:
    rows = page["rows"]
    assert isinstance(rows, list)
    return [row for row in rows if row["kind"] == "bytes"]


def _gap_rows(page: dict[str, object]) -> list[dict[str, object]]:
    rows = page["rows"]
    assert isinstance(rows, list)
    return [row for row in rows if row["kind"] == "gap"]


class TestEngineSurface:
    def test_a_page_starts_at_the_first_section(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        page = fake_engine.read_memory_page(_section_file(tmp_path), length=32)
        assert page["start"] == hex(TEXT_VA)
        assert page["kind"] == "va"
        assert page["address"] is None
        assert [row["hex"] for row in _bytes_rows(page)] == [
            PATTERN[:16].hex(),
            PATTERN[16:32].hex(),
        ]
        assert page["mapped"] == 32
        assert page["gaps"] == 0
        assert [section["name"] for section in page["sections"]] == [".text", ".data"]

    def test_paging_across_a_section_boundary_shows_a_gap(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        page = fake_engine.read_memory_page(_section_file(tmp_path), address=0x407580, length=256)
        assert page["mapped"] == 128
        assert page["gaps"] == 128
        kinds = [row["kind"] for row in page["rows"]]
        # Eight mapped rows (the tail of .text), then one gap row (the
        # unmapped range before .data).
        assert kinds == ["bytes"] * 8 + ["gap"]
        gap = _gap_rows(page)[0]
        assert gap["address"] == hex(0x407600)
        assert gap["length"] == 128

    def test_the_virtual_and_offset_kinds_reach_the_same_bytes(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        path = _section_file(tmp_path)
        by_va = fake_engine.read_memory_page(path, address=TEXT_VA, length=16, kind="va")
        by_file = fake_engine.read_memory_page(path, address=TEXT_OFFSET, length=16, kind="file")
        assert by_va["start"] == by_file["start"] == hex(TEXT_VA)
        assert [row["hex"] for row in _bytes_rows(by_va)] == [
            row["hex"] for row in _bytes_rows(by_file)
        ]

    def test_an_unmapped_start_is_refused(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        with pytest.raises(engines.UnmappedAddressError):
            fake_engine.read_memory_page(_section_file(tmp_path), address=0x407800, length=16)

    def test_a_file_offset_without_a_section_is_refused(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        with pytest.raises(engines.UnmappedAddressError, match="not backed by a section"):
            fake_engine.read_memory_page(
                _section_file(tmp_path), address=0x10, length=16, kind="file"
            )

    def test_next_and_prev_bound_the_walk(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        path = _section_file(tmp_path)
        first = fake_engine.read_memory_page(path, address=TEXT_VA, length=16)
        assert first["prev"] is None
        assert first["next"] == hex(TEXT_VA + 16)
        # A page inside .data has both a previous and a next while bytes remain.
        # The previous page snaps to the last mapped page of .text, because the
        # gap before .data is not a place a page may begin.
        data_page = fake_engine.read_memory_page(path, address=0x408000, length=16)
        assert data_page["next"] == hex(0x408010)
        assert data_page["prev"] == hex(0x407600 - 16)
        last = fake_engine.read_memory_page(path, address=0x4085F0, length=16)
        assert last["next"] is None

    def test_length_over_the_cap_is_refused(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        with pytest.raises(engines.EngineError, match="between 1 and"):
            fake_engine.read_memory_page(
                _section_file(tmp_path), address=TEXT_VA, length=engines.MEMORY_PAGE_MAX + 1
            )

    def test_an_unknown_kind_is_refused(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        with pytest.raises(engines.EngineError, match="unsupported address kind"):
            fake_engine.read_memory_page(_section_file(tmp_path), address=TEXT_VA, kind="physical")

    def test_an_rva_start_resolves_through_the_image_base(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        page = fake_engine.read_memory_page(
            _section_file(tmp_path), address=0x1000, length=16, kind="rva"
        )
        assert page["start"] == hex(TEXT_VA)

    def test_a_start_below_the_image_base_is_refused(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        with pytest.raises(engines.UnmappedAddressError, match="below the image base"):
            fake_engine.read_memory_page(_section_file(tmp_path), address=0x1000, length=16)

    def test_next_snaps_to_the_next_section_across_a_gap(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        # The last page of .text ends at the gap, which is not a place a page
        # may begin, so the next step lands at .data instead.
        page = fake_engine.read_memory_page(_section_file(tmp_path), address=0x407500, length=256)
        assert page["next"] == hex(0x408000)

    def test_zero_length_is_refused(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        with pytest.raises(engines.EngineError, match="between 1 and"):
            fake_engine.read_memory_page(_section_file(tmp_path), address=TEXT_VA, length=0)

    def test_a_negative_file_offset_is_refused(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        with pytest.raises(engines.UnmappedAddressError, match="not backed by a section"):
            fake_engine.read_memory_page(
                _section_file(tmp_path), address=-1, length=16, kind="file"
            )

    def test_a_binary_without_raw_sections_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setattr(fake_engine, "pe_info", lambda binary: {**PE_INFO, "sections": []})
        with pytest.raises(engines.UnmappedAddressError, match="no raw-backed sections"):
            fake_engine.read_memory_page(_section_file(tmp_path), address=TEXT_VA, length=16)


class TestApiRoute:
    def test_page_defaults_to_the_first_section(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _section_file(tmp_path))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/memory/page")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["start"] == hex(TEXT_VA)
        assert _bytes_rows(payload)[0]["hex"] == PATTERN[:16].hex()

    def test_the_page_bytes_match_a_window_read(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        path = _section_file(tmp_path)
        binary_id = _seed_binary(conn, path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory/page?va=0x{TEXT_VA:x}&length=16"
        )
        assert status.startswith("200")
        row = _bytes_rows(json_body(body, headers))[0]
        window = fake_engine.read_memory(path, address=TEXT_VA, length=16)
        # A selected range's copy is the row's hex, which is the engine's bytes.
        assert row["hex"] == window["bytes"]

    def test_gap_page(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _section_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory/page?va=0x407580&length=256"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["gaps"] == 128
        assert _gap_rows(payload)[0]["address"] == hex(0x407600)

    def test_unmapped_start_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _section_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory/page?va=0x407800&length=16"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "unmapped address"

    def test_length_over_the_cap_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _section_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET",
            f"/api/binaries/{binary_id}/memory/page?va={TEXT_VA}"
            f"&length={engines.MEMORY_PAGE_MAX + 1}",
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid length"

    def test_bad_kind_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _section_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory/page?va={TEXT_VA}&kind=physical"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid kind"

    def test_unknown_binary_404(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        _seed_binary(conn, _section_file(tmp_path))
        status, headers, body = wsgi_request("GET", "/api/binaries/999/memory/page")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_a_bad_address_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _section_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory/page?va=soon"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid address"

    def test_a_non_integer_length_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, _section_file(tmp_path))
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/memory/page?va={TEXT_VA}&length=soon"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid length"


class TestCli:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            return _seed_binary(conn, _section_file(tmp_path))

    def test_memory_page_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["memory-page", str(binary_id), hex(TEXT_VA), "--length", "16", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["start"] == hex(TEXT_VA)
        assert _bytes_rows(payload)[0]["hex"] == PATTERN[:16].hex()

    def test_memory_page_command_refuses_over_the_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "memory-page",
                str(binary_id),
                hex(TEXT_VA),
                "--length",
                str(engines.MEMORY_PAGE_MAX + 1),
            ],
        )
        assert result.exit_code != 0
        assert "between 1 and" in result.output

    def test_memory_page_command_human_prints_a_gap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["memory-page", str(binary_id), "0x407580", "--length", "256"],
        )
        assert result.exit_code == 0, result.output
        assert "gap" in result.output

    def test_memory_page_command_without_an_address_starts_at_the_first_section(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["memory-page", str(binary_id), "--length", "16"])
        assert result.exit_code == 0, result.output

    def test_memory_page_command_rejects_a_bad_address(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["memory-page", str(binary_id), "soon"])
        assert result.exit_code != 0
        assert "address must be" in result.output

    def test_memory_page_command_rejects_a_bad_kind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["memory-page", str(binary_id), hex(TEXT_VA), "--offset-kind", "physical"]
        )
        assert result.exit_code != 0

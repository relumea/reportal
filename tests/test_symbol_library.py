"""Tests for the workspace symbol library: identities, store, resolve, fetch.

The library is matched by identity, so the identity readers get byte-level
tests first (a PE CodeView record, a PDB info stream, an ELF build-id note),
then the store, the local resolve end to end over one ELF pair and one PE/PDB
pair, the symbol-server fetch behind its gate and transport seam, and finally
the three surfaces (route, CLI command, MCP tool) plus the upload hook.
"""

from __future__ import annotations

import contextlib
import json
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest
from conftest import json_body, wsgi_request
from test_pdb import (
    DATA_RAW,
    DATA_VA,
    SYMBOL_STREAM,
    TEXT_RAW,
    TEXT_VA,
    _container,
    _dbi,
    _records,
    _section,
    _section_map,
)
from test_symbols import SHT_STRTAB, SHT_SYMTAB, _strtab, _symtab, build_elf
from typer.testing import CliRunner

from reportal import cli, external, journal, mcp_tools, pdb, store, symbol_library, symbols
from reportal._paths import DB_ENV

BOUNDARY = "reportal-symlib-boundary"
GUID = bytes(range(16))
BUILD_ID = bytes(range(8, 16))
runner = CliRunner()


@pytest.fixture(autouse=True)
def _workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run in a throwaway workspace: stored symbol bytes land under its
    ``symbols/``, never the checkout's (which is a workspace too)."""
    root = tmp_path / "ws"
    root.mkdir()
    (root / "reportal.toml").write_text("", encoding="utf-8")
    monkeypatch.chdir(root)


@pytest.fixture(autouse=True)
def _isolate_http() -> Iterator[None]:
    """Leave no injected symbol-server client between tests."""
    external.set_http_client(None)
    yield
    external.set_http_client(None)


# ── Builders ───────────────────────────────────────────────────────


def synthetic_pdb(
    guid: bytes = GUID, age: int = 1, *, version: int = 20091201, info: bytes | None = None
) -> bytes:
    """The shared fixture container with a VC70+ identity header."""
    if info is None:
        info = struct.pack("<III", version, 0x1234, age) + guid
    sections = _section_map(
        [
            _section(b".text", TEXT_VA, TEXT_RAW, padded=True),
            _section(b".data", DATA_VA, DATA_RAW, padded=True),
        ]
    )
    return _container([b"", info, b"", _dbi(sections, SYMBOL_STREAM), _records()])


def build_pe(
    guid: bytes = GUID,
    age: int = 1,
    *,
    pdb_name: bytes = b"demo.pdb",
    debug: bool = True,
    plus: bool = False,
    entry_type: int = 2,
    codeview: str = "pointer",
    record_magic: bytes = b"RSDS",
) -> bytes:
    """A PE image with one debug-directory entry.

    *plus* builds a PE32+ optional header, *entry_type* sets the directory
    entry's type (2 is CodeView), *codeview* points the record at its file
    offset (``pointer``), at its RVA only (``rva``) or at nothing (``none``),
    and *record_magic* swaps the CodeView record's four bytes.
    """
    pe_offset = 0x80
    optional_size = 0xF0 if plus else 0xE0
    section_rva = 0x1000
    section_raw = 0x200
    record = record_magic + guid + struct.pack("<I", age) + pdb_name + b"\x00"
    record_at = 28
    if codeview == "pointer":
        pointer, address = section_raw + record_at, 0
    elif codeview == "rva":
        pointer, address = 0, section_rva + record_at
    else:
        pointer, address = 0, 0
    raw = bytearray(section_raw + 64)
    struct.pack_into("<IIHHIIII", raw, 0, 0, 0, 0, 0, entry_type, len(record), address, pointer)
    raw[record_at : record_at + len(record)] = record
    header = bytearray(section_raw)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, pe_offset)
    header[pe_offset : pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<H", header, coff, 0x014C)
    struct.pack_into("<H", header, coff + 2, 1)
    struct.pack_into("<H", header, coff + 16, optional_size)
    struct.pack_into("<H", header, coff + 18, 0x0102)
    optional = coff + 20
    struct.pack_into("<H", header, optional, 0x20B if plus else 0x10B)
    struct.pack_into("<I", header, optional + 28, 0x400000)
    rva_count_at, data_directory_at = (108, 112) if plus else (92, 96)
    struct.pack_into("<I", header, optional + rva_count_at, 16)
    if debug:
        struct.pack_into("<II", header, optional + data_directory_at + 6 * 8, section_rva, 28)
    section = optional + optional_size
    header[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", header, section + 8, 0x40, section_rva, section_raw, section_raw)
    return bytes(header + raw)


def build_id_note(build_id: bytes = BUILD_ID) -> bytes:
    """One NT_GNU_BUILD_ID note section body."""
    return struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id


def vendor_debug_elf(build_id: bytes = BUILD_ID) -> bytes:
    """A split debug file: the binary's build id plus a symtab naming make_thing."""
    text, names = _strtab("make_thing")
    return build_elf(
        [
            (".note.gnu.build-id", build_id_note(build_id), 7, 0),
            (
                ".symtab",
                _symtab(names, [("make_thing", 0x401000, "function", 8, 1)]),
                SHT_SYMTAB,
                3,
            ),
            (".strtab", text, SHT_STRTAB, 0),
        ]
    )


def binary_elf(build_id: bytes = BUILD_ID) -> bytes:
    """The stripped binary side: same build id, placeholder symbol names."""
    text, names = _strtab("sub_401000")
    return build_elf(
        [
            (".note.gnu.build-id", build_id_note(build_id), 7, 0),
            (
                ".symtab",
                _symtab(names, [("sub_401000", 0x401000, "function", 8, 1)]),
                SHT_SYMTAB,
                3,
            ),
            (".strtab", text, SHT_STRTAB, 0),
        ]
    )


def _seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    data: bytes,
    *,
    suffix: str = ".elf",
    name: str = "sub_401000",
) -> dict[str, Any]:
    """A portal DB with one binary on disk and one function at 0x401000."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    binary_file = tmp_path / f"sample{suffix}"
    binary_file.write_bytes(data)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(
            conn,
            sha256=symbols.digest(data),
            name=binary_file.name,
            path=str(binary_file),
            size=len(data),
            fmt=suffix.lstrip(".").upper(),
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=0x401000, name=name)
    return {
        "db": db,
        "binary": binary_id,
        "analysis": analysis_id,
        "function": function_id,
        "file": binary_file,
    }


def _multipart(files: list[tuple[str, bytes]]) -> tuple[bytes, dict[str, str]]:
    """A multipart body carrying one ``file`` part per (name, content) pair."""
    parts = [
        (
            f'Content-Disposition: form-data; name="file"; filename="{name}"'.encode()
            + b"\r\n\r\n"
            + content
        )
        for name, content in files
    ]
    body = b"".join(f"--{BOUNDARY}\r\n".encode() + part + b"\r\n" for part in parts)
    body += f"--{BOUNDARY}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}


def _transport(
    status: int = 200, content: bytes = b"", headers: dict[str, str] | None = None
) -> dict[str, str]:
    """Install a mock symbol-server client; returns the dict the handler fills."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(status, content=content, headers=headers or {})

    external.set_http_client(
        httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    )
    return seen


class TestIdentityReaders:
    def test_the_pe_debug_record_carries_the_pdb_identity(self) -> None:
        found = symbol_library.pe_debug_id(build_pe(GUID, 2, pdb_name=b"C:\\out\\demo.pdb"))
        assert found == {"guid": GUID.hex(), "age": 2, "pdb_name": "demo.pdb"}

    def test_an_image_without_a_debug_directory_answers_none(self) -> None:
        assert symbol_library.pe_debug_id(build_pe(debug=False)) is None

    def test_a_pe32_plus_image_is_read(self) -> None:
        found = symbol_library.pe_debug_id(build_pe(plus=True))
        assert found == {"guid": GUID.hex(), "age": 1, "pdb_name": "demo.pdb"}

    @pytest.mark.parametrize(
        ("keyword", "value"),
        [
            ("optional_size", 1),
            ("optional_size", 100),
            ("section_count", 0),
            ("debug_rva", 0x9000),
            ("entry_type", 4),
        ],
    )
    def test_a_header_the_reader_cannot_follow_answers_none(self, keyword: str, value: int) -> None:
        data = bytearray(build_pe())
        offsets = {
            "optional_size": 0x94,
            "section_count": 0x86,
            "debug_rva": 0x128,
            "entry_type": 0x20C,
        }
        fmt = "<H" if keyword in ("optional_size", "section_count") else "<I"
        struct.pack_into(fmt, data, offsets[keyword], value)
        assert symbol_library.pe_debug_id(bytes(data)) is None

    def test_the_record_is_read_through_its_rva_when_the_pointer_is_zero(self) -> None:
        found = symbol_library.pe_debug_id(build_pe(codeview="rva"))
        assert found == {"guid": GUID.hex(), "age": 1, "pdb_name": "demo.pdb"}

    def test_a_record_pointer_and_rva_outside_every_section_answer_none(self) -> None:
        assert symbol_library.pe_debug_id(build_pe(codeview="none")) is None

    def test_a_record_that_is_not_rsds_is_skipped(self) -> None:
        assert symbol_library.pe_debug_id(build_pe(record_magic=b"NB11")) is None

    def test_an_unknown_optional_header_magic_answers_none(self) -> None:
        data = bytearray(build_pe())
        struct.pack_into("<H", data, 0x98, 0x101)
        assert symbol_library.pe_debug_id(bytes(data)) is None

    def test_an_rva_count_without_a_debug_entry_answers_none(self) -> None:
        data = bytearray(build_pe())
        struct.pack_into("<I", data, 0x98 + 92, 6)
        assert symbol_library.pe_debug_id(bytes(data)) is None

    def test_a_debug_table_running_past_the_file_answers_none(self) -> None:
        data = bytearray(build_pe(entry_type=4))
        struct.pack_into("<I", data, 0x98 + 96 + 6 * 8 + 4, 0x1000)
        assert symbol_library.pe_debug_id(bytes(data)) is None

    def test_a_section_table_running_past_the_file_answers_none(self) -> None:
        data = bytearray(build_pe())
        struct.pack_into("<H", data, 0x94, len(data) - 0x98)
        assert symbol_library.pe_debug_id(bytes(data)) is None

    def test_a_file_that_is_not_a_pe_answers_none(self) -> None:
        assert symbol_library.pe_debug_id(b"not a pe" + b"\x00" * 200) is None
        assert symbol_library.pe_debug_id(b"MZ" + b"\x00" * 62) is None

    def test_an_e_lfanew_outside_the_file_answers_none(self) -> None:
        data = bytearray(build_pe())
        struct.pack_into("<I", data, 0x3C, len(data) + 16)
        assert symbol_library.pe_debug_id(bytes(data)) is None

    def test_a_section_count_outside_the_bounds_answers_none(self) -> None:
        data = bytearray(build_pe())
        struct.pack_into("<H", data, 0x86, 5000)
        assert symbol_library.pe_debug_id(bytes(data)) is None

    def test_an_image_with_no_number_of_rvas_answers_none(self) -> None:
        data = bytearray(build_pe())
        struct.pack_into("<I", data, 0x80 + 4 + 20 + 92, 0)
        assert symbol_library.pe_debug_id(bytes(data)) is None

    def test_a_pdb_identity_is_the_guid_and_age_of_the_info_stream(self) -> None:
        assert pdb.read_identity(synthetic_pdb(GUID, 3)) == {"guid": GUID.hex(), "age": 3}

    def test_a_pdb_whose_info_stream_is_short_is_refused(self) -> None:
        with pytest.raises(pdb.PdbError) as exc:
            pdb.read_identity(synthetic_pdb(info=struct.pack("<III", 20091201, 0, 1)))
        assert exc.value.code == "symbols-unreadable"
        assert "identity header" in exc.value.detail

    def test_a_pdb_from_before_the_guid_is_refused_by_name(self) -> None:
        with pytest.raises(pdb.PdbError) as exc:
            pdb.read_identity(synthetic_pdb(version=19970604))
        assert "carries no GUID" in exc.value.detail

    def test_a_container_that_is_not_a_pdb_is_refused(self) -> None:
        with pytest.raises(pdb.PdbError):
            pdb.read_identity(b"not an msf container")

    def test_the_elf_build_id_comes_out_of_its_note(self) -> None:
        assert symbols.build_id(vendor_debug_elf()) == BUILD_ID.hex()

    def test_an_elf_without_a_note_has_no_build_id(self) -> None:
        text, _names = _strtab("thing")
        elf = build_elf([(".strtab", text, SHT_STRTAB, 0)])
        assert symbols.build_id(elf) == ""

    def test_a_file_that_is_not_elf_has_no_build_id(self) -> None:
        assert symbols.build_id(b"MZ\x90\x00") == ""

    def test_a_note_header_running_past_the_section_has_no_build_id(self) -> None:
        broken = struct.pack("<III", 4, 0xFFFFFFFF, 3) + b"GNU\x00"
        text, _names = _strtab("x")
        elf = build_elf([(".note.gnu.build-id", broken, 7, 0), (".strtab", text, SHT_STRTAB, 0)])
        assert symbols.build_id(elf) == ""

    def test_a_note_owned_by_someone_else_is_not_the_build_id(self) -> None:
        other = struct.pack("<III", 4, 8, 3) + b"Go\x00\x00" + bytes(8)
        text, _names = _strtab("x")
        elf = build_elf([(".note.other", other, 7, 0), (".strtab", text, SHT_STRTAB, 0)])
        assert symbols.build_id(elf) == ""

    def test_binary_identity_reads_a_pe_file_from_disk(self, tmp_path: Path) -> None:
        target = tmp_path / "sample.exe"
        target.write_bytes(build_pe(GUID, 1))
        identity, pdb_name, reason = symbol_library.binary_identity(target)
        assert (identity, pdb_name, reason) == (f"pe:{GUID.hex()}-1", "demo.pdb", "")

    def test_binary_identity_reads_an_elf_file_from_disk(self, tmp_path: Path) -> None:
        target = tmp_path / "sample.elf"
        target.write_bytes(vendor_debug_elf())
        identity, pdb_name, reason = symbol_library.binary_identity(target)
        assert (identity, pdb_name, reason) == (f"elf:{BUILD_ID.hex()}", "", "")

    def test_binary_identity_says_why_it_cannot_read_one(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        other = tmp_path / "blob.bin"
        other.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 64)
        missing = tmp_path / "gone.bin"
        no_debug = tmp_path / "nodebug.exe"
        no_debug.write_bytes(build_pe(debug=False))
        text, _names = _strtab("x")
        no_note = tmp_path / "nonote.elf"
        no_note.write_bytes(build_elf([(".strtab", text, SHT_STRTAB, 0)]))
        assert "cannot be read" in symbol_library.binary_identity(missing)[2]
        assert symbol_library.binary_identity(empty)[2] == "the binary file is empty"
        assert "CodeView" in symbol_library.binary_identity(no_debug)[2]
        assert "neither" in symbol_library.binary_identity(other)[2]
        assert "build id" in symbol_library.binary_identity(no_note)[2]

    def test_a_symbol_file_identity_follows_the_same_rules(self) -> None:
        assert symbol_library.file_identity(synthetic_pdb()) == f"pe:{GUID.hex()}-1"
        assert symbol_library.file_identity(vendor_debug_elf()) == f"elf:{BUILD_ID.hex()}"

    def test_a_symbol_file_without_an_identity_is_refused(self) -> None:
        text, _names = _strtab("x")
        plain = build_elf([(".strtab", text, SHT_STRTAB, 0)])
        with pytest.raises(symbol_library.NoIdentityError) as exc:
            symbol_library.file_identity(plain)
        assert exc.value.code == "no-identity"
        with pytest.raises(symbols.UnreadableSymbolError):
            symbol_library.file_identity(b"not a symbol file")

    def test_a_symbol_pdb_from_before_the_guid_is_no_identity(self) -> None:
        with pytest.raises(symbol_library.NoIdentityError) as exc:
            symbol_library.file_identity(synthetic_pdb(version=19970604))
        assert exc.value.code == "no-identity"

    def test_a_binary_that_cannot_be_mapped_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "sample.elf"
        target.write_bytes(vendor_debug_elf())

        def _boom(*_args: object, **_kwargs: object) -> object:
            raise ValueError("mapping refused")

        monkeypatch.setattr(symbol_library.mmap, "mmap", _boom)
        identity, pdb_name, reason = symbol_library.binary_identity(target)
        assert (identity, pdb_name) == ("", "")
        assert "cannot be mapped" in reason


class TestStore:
    def test_an_added_file_is_stored_keyed_and_journaled(self, conn: Any, tmp_path: Path) -> None:
        data = vendor_debug_elf()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            row = symbol_library.add(conn, log, data, origin="/libs/vendor.debug")
        assert row["identity"] == f"elf:{BUILD_ID.hex()}"
        assert row["duplicate"] is False
        assert row["origin"] == "/libs/vendor.debug"
        assert row["symbols"] >= 1
        assert symbols.stored_path(row["sha256"]).is_file()
        assert symbol_library.list_entries(conn)[0]["id"] == row["id"]
        assert "parsed" not in symbol_library.list_entries(conn)[0]
        found = symbol_library.find(conn, f"elf:{BUILD_ID.hex()}")
        assert found is not None
        assert found["parsed"]["kind"] == "elf"
        assert journal.revert_action(conn, action)["reverted"] >= 1
        assert symbol_library.list_entries(conn) == []

    def test_the_same_bytes_twice_are_one_row(self, conn: Any, tmp_path: Path) -> None:
        data = vendor_debug_elf()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            first = symbol_library.add(conn, log, data)
            second = symbol_library.add(conn, log, data)
        assert first["duplicate"] is False
        assert second["duplicate"] is True
        assert second["id"] == first["id"]
        assert len(symbol_library.list_entries(conn)) == 1

    def test_a_pdb_entry_carries_its_pdb_name(self, conn: Any) -> None:
        data = synthetic_pdb()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            row = symbol_library.add(conn, log, data, origin=r"C:\symbols\demo.pdb")
        assert row["pdb_name"] == "demo.pdb"
        assert row["kind"] == "pdb"

    def test_a_file_that_cannot_be_stored_is_refused_before_any_write(self, conn: Any) -> None:
        text, _names = _strtab("x")
        plain = build_elf([(".strtab", text, SHT_STRTAB, 0)])
        action = journal.new_action()
        with (
            journal.journaled(conn, action) as log,
            pytest.raises(symbol_library.NoIdentityError),
        ):
            symbol_library.add(conn, log, plain)
        assert symbol_library.list_entries(conn) == []


class TestFetch:
    def test_the_url_is_the_store_layout_of_guid_and_age(self) -> None:
        url = symbol_library.symbol_server_url("demo.pdb", GUID.hex(), 7)
        assert url == (
            f"https://msdl.microsoft.com/download/symbols/demo.pdb/{GUID.hex().upper()}7/demo.pdb"
        )

    def test_a_fetch_while_remote_sources_are_off_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "0")
        with pytest.raises(external.DisabledExternalError):
            symbol_library.fetch_pdb("demo.pdb", GUID.hex(), 1)

    def test_a_name_that_is_not_a_plain_file_name_is_never_sent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        external.set_http_client(httpx.Client(transport=httpx.MockTransport(_boom_handler)))
        with pytest.raises(symbol_library.SymbolLibraryError) as exc:
            symbol_library.fetch_pdb("../secrets.pdb", GUID.hex(), 1)
        assert "plain .pdb file name" in exc.value.detail

    def test_a_served_pdb_comes_back_as_bytes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        seen = _transport(200, synthetic_pdb())
        data = symbol_library.fetch_pdb("demo.pdb", GUID.hex(), 1)
        assert data == synthetic_pdb()
        assert seen["url"] == (
            f"https://msdl.microsoft.com/download/symbols/demo.pdb/{GUID.hex().upper()}1/demo.pdb"
        )

    def test_a_miss_is_none_not_a_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        _transport(404)
        assert symbol_library.fetch_pdb("demo.pdb", GUID.hex(), 1) is None

    def test_a_redirect_is_a_bad_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        _transport(302, headers={"location": "https://elsewhere/"})
        with pytest.raises(external.ExternalFetchError) as exc:
            symbol_library.fetch_pdb("demo.pdb", GUID.hex(), 1)
        assert exc.value.code == external.ERROR_BAD_RESPONSE

    def test_a_server_failure_is_a_fetch_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        _transport(500)
        with pytest.raises(external.ExternalFetchError) as exc:
            symbol_library.fetch_pdb("demo.pdb", GUID.hex(), 1)
        assert exc.value.code == external.ERROR_FETCH_FAILED

    def test_a_body_past_the_cap_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        huge = symbol_library.MAX_FETCH_BYTES + 1
        _transport(200, headers={"content-length": str(huge)})
        with pytest.raises(external.ExternalFetchError) as exc:
            symbol_library.fetch_pdb("demo.pdb", GUID.hex(), 1)
        assert exc.value.code == external.ERROR_TOO_LARGE

    def test_a_body_pasting_the_cap_while_streaming_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        monkeypatch.setattr(symbol_library, "MAX_FETCH_BYTES", 4)
        _transport(200, b"12345", headers={"content-length": "unknown"})
        with pytest.raises(external.ExternalFetchError) as exc:
            symbol_library.fetch_pdb("demo.pdb", GUID.hex(), 1)
        assert exc.value.code == external.ERROR_TOO_LARGE

    def test_a_transport_failure_is_a_fetch_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")

        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        external.set_http_client(
            httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        )
        with pytest.raises(external.ExternalFetchError) as exc:
            symbol_library.fetch_pdb("demo.pdb", GUID.hex(), 1)
        assert exc.value.code == external.ERROR_FETCH_FAILED


def _boom_handler(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(500)


class TestResolveLocal:
    def test_an_elf_library_entry_renames_the_binary_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                symbol_library.add(conn, log, vendor_debug_elf(), origin="vendor.debug")
            report = symbol_library.resolve(conn, ids["binary"])
        assert report["matched"] is True
        assert report["source"] == "library"
        assert report["identity"] == f"elf:{BUILD_ID.hex()}"
        assert report["fetch"] == "not-needed"
        assert report["ingest"]["applied"] >= 1
        assert report["journal_action"]
        with contextlib.closing(store.connect(ids["db"])) as conn:
            function = store.get_function(conn, ids["function"])
            files = symbols.list_files(conn, ids["binary"])
        assert function is not None
        assert function["name"] == "make_thing"
        assert function["name_source"] == symbols.SYMBOL_NAME_SOURCE
        assert files and files[0]["applied"] >= 1

    def test_the_resolve_is_one_revertible_action(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                symbol_library.add(conn, log, vendor_debug_elf())
            report = symbol_library.resolve(conn, ids["binary"])
            assert journal.revert_action(conn, report["journal_action"])["reverted"] >= 1
            function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "sub_401000"

    def test_no_entry_reports_the_identity_and_the_disabled_fetch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"])
        assert report["matched"] is False
        assert report["identity"] == f"elf:{BUILD_ID.hex()}"
        assert report["fetch"] == "not-applicable"
        assert f"no library entry carries elf:{BUILD_ID.hex()}" in report["reason"]

    def test_a_pe_miss_says_the_fetch_was_disabled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "0")
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"])
        assert report["matched"] is False
        assert report["fetch"] == "disabled"
        assert "remote sources are off" in report["reason"]

    def test_a_local_resolve_never_fetches_even_when_remote_sources_are_on(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        seen = _transport(200, synthetic_pdb())
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"], fetch=False)
        assert report["matched"] is False
        assert report["fetch"] == "skipped"
        assert seen == {}

    def test_an_elf_identity_is_never_sent_to_the_symbol_server(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"], fetch=True)
        assert report["matched"] is False
        assert report["fetch"] == "not-applicable"
        assert "symbol server serves PDB identities only" in report["reason"]

    def test_a_forced_fetch_while_remote_sources_are_off_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "0")
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(external.DisabledExternalError),
        ):
            symbol_library.resolve(conn, ids["binary"], fetch=True)

    def test_an_image_without_a_codeview_record_is_reported_not_raised(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, build_pe(debug=False), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"])
        assert report["matched"] is False
        assert report["identity"] == ""
        assert "CodeView" in report["reason"]

    def test_a_missing_binary_file_is_reported_not_raised(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        ids["file"].unlink()
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"])
        assert report["matched"] is False
        assert "cannot be read" in report["reason"]

    def test_an_unknown_binary_is_refused(self, conn: Any) -> None:
        with pytest.raises(symbol_library.SymbolLibraryError) as exc:
            symbol_library.resolve(conn, 4242)
        assert exc.value.code == "binary not found"

    def test_a_library_row_whose_bytes_vanished_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                row = symbol_library.add(conn, log, vendor_debug_elf())
            symbols.stored_path(row["sha256"]).unlink()
            report = symbol_library.resolve(conn, ids["binary"])
        assert report["matched"] is False
        assert "missing on disk" in report["reason"]

    def test_the_upload_hook_swallows_its_own_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        ids["file"].unlink()
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.auto_resolve(conn, ids["binary"])
        assert report["matched"] is False
        assert "cannot be read" in report["reason"]
        with contextlib.closing(store.connect(ids["db"])) as conn:
            bad = symbol_library.auto_resolve(conn, 4242)
        assert bad["matched"] is False
        assert "symbol resolve failed" in bad["reason"]


class TestResolvePe:
    def test_a_pe_binary_matches_its_pdb_in_the_library(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                added = symbol_library.add(conn, log, synthetic_pdb(), origin="demo.pdb")
            report = symbol_library.resolve(conn, ids["binary"])
        assert report["matched"] is True
        assert report["source"] == "library"
        assert report["identity"] == f"pe:{GUID.hex()}-1"
        assert report["entry_id"] == added["id"]
        assert report["ingest"]["symbols"] >= 1

    def test_a_forced_fetch_stores_the_served_pdb_in_the_library(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        seen = _transport(200, synthetic_pdb())
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"], fetch=True)
            entries = symbol_library.list_entries(conn)
        assert report["matched"] is True
        assert report["source"] == "symbol-server"
        assert report["fetch"] == "stored"
        assert seen["url"].endswith(f"/{GUID.hex().upper()}1/demo.pdb")
        assert entries[0]["identity"] == f"pe:{GUID.hex()}-1"
        assert entries[0]["origin"].startswith("https://msdl.microsoft.com/")

    def test_the_automatic_choice_fetches_when_remote_sources_are_on(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        _transport(200, synthetic_pdb())
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"])
        assert report["matched"] is True
        assert report["source"] == "symbol-server"

    def test_a_miss_from_the_server_reports_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        _transport(404)
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"], fetch=True)
        assert report["matched"] is False
        assert report["fetch"] == "miss"
        assert "does not serve it" in report["reason"]

    def test_an_answer_with_another_identity_is_not_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        _transport(200, synthetic_pdb(bytes(16), 9))
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"], fetch=True)
            assert symbol_library.list_entries(conn) == []
        assert report["matched"] is False
        assert report["fetch"] == "mismatch"
        assert "not pe:" in report["reason"]

    def test_an_answer_that_is_not_a_pdb_is_a_bad_response(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        _transport(200, b"<html>not a pdb</html>")
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(external.ExternalFetchError) as exc,
        ):
            symbol_library.resolve(conn, ids["binary"], fetch=True)
        assert exc.value.code == external.ERROR_BAD_RESPONSE

    def test_a_debug_record_name_that_is_not_plain_skips_the_fetch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        seen = _transport(200, synthetic_pdb())
        ids = _seed(tmp_path, monkeypatch, build_pe(pdb_name=b"my demo.pdb"), suffix=".exe")
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = symbol_library.resolve(conn, ids["binary"], fetch=True)
        assert report["matched"] is False
        assert report["fetch"] == "refused"
        assert "was not fetched" in report["reason"]
        assert seen == {}


class TestRoutes:
    def test_the_library_lists_empty_then_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        status, headers, body = wsgi_request("GET", "/api/symbols/library")
        assert status.startswith("200")
        assert json_body(body, headers)["count"] == 0
        upload, upload_headers = _multipart([("vendor.debug", vendor_debug_elf())])
        status, headers, body = wsgi_request(
            "POST", "/api/symbols/library", body=upload, headers=upload_headers
        )
        assert status.startswith("200")
        assert json_body(body, headers)["added"] == 1
        status, headers, body = wsgi_request("GET", "/api/symbols/library")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["symbol_library"][0]["identity"] == f"elf:{BUILD_ID.hex()}"
        assert "parsed" not in payload["symbol_library"][0]
        assert ids["binary"]

    def test_a_bad_file_is_refused_and_nothing_is_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch, binary_elf())
        body, headers = _multipart([("vendor.debug", vendor_debug_elf()), ("bad.bin", b"zzz")])
        status, response_headers, response = wsgi_request(
            "POST", "/api/symbols/library", body=body, headers=headers
        )
        assert status.startswith("400")
        assert json_body(response, response_headers)["error"] == "symbols-unreadable"
        _status, list_headers, list_body = wsgi_request("GET", "/api/symbols/library")
        assert json_body(list_body, list_headers)["count"] == 0

    def test_an_identity_less_file_names_no_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch, binary_elf())
        text, _names = _strtab("x")
        plain = build_elf([(".strtab", text, SHT_STRTAB, 0)])
        body, headers = _multipart([("plain.elf", plain)])
        status, response_headers, response = wsgi_request(
            "POST", "/api/symbols/library", body=body, headers=headers
        )
        assert status.startswith("400")
        assert json_body(response, response_headers)["error"] == "no-identity"

    def test_a_library_add_needs_a_file_part(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch, binary_elf())
        status, headers, body = wsgi_request(
            "POST",
            "/api/symbols/library",
            body=b'--x\r\nContent-Disposition: form-data; name="other"\r\n\r\n1\r\n--x--\r\n',
            headers={"Content-Type": "multipart/form-data; boundary=x"},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-file"

    def test_the_resolve_route_applies_a_local_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        body, headers = _multipart([("vendor.debug", vendor_debug_elf())])
        wsgi_request("POST", "/api/symbols/library", body=body, headers=headers)
        status, response_headers, response = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols/resolve"
        )
        assert status.startswith("200")
        payload = json_body(response, response_headers)
        assert payload["matched"] is True
        assert payload["source"] == "library"
        with contextlib.closing(store.connect(ids["db"])) as conn:
            function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "make_thing"

    def test_an_unknown_binary_answers_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch, binary_elf())
        status, headers, body = wsgi_request("POST", "/api/binaries/4242/symbols/resolve")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_a_bad_fetch_value_answers_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols/resolve?fetch=maybe"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "fetch must be a boolean"

    def test_a_forced_fetch_while_disabled_answers_403(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "0")
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols/resolve?fetch=true"
        )
        assert status.startswith("403")
        assert json_body(body, headers)["error"] == "external-disabled"

    def test_a_forced_fetch_through_the_route_stores_the_pdb(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        _transport(200, synthetic_pdb())
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        status, response_headers, response = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols/resolve?fetch=true"
        )
        assert status.startswith("200")
        assert json_body(response, response_headers)["source"] == "symbol-server"

    def test_an_upload_resolves_against_the_library(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, b"\x00" * 4)
        body, headers = _multipart([("vendor.debug", vendor_debug_elf())])
        wsgi_request("POST", "/api/symbols/library", body=body, headers=headers)
        upload, upload_headers = _multipart([("sample.elf", binary_elf())])
        status, response_headers, response = wsgi_request(
            "POST", "/api/binaries", body=upload, headers=upload_headers
        )
        assert status.startswith("200")
        uploaded = json_body(response, response_headers)
        assert uploaded["duplicate"] is False
        listed, list_headers, list_body = wsgi_request(
            "GET", f"/api/binaries/{uploaded['id']}/symbols"
        )
        assert listed.startswith("200")
        payload = json_body(list_body, list_headers)
        assert payload["symbol_files"][0]["kind"] == "elf"
        with contextlib.closing(store.connect(ids["db"])) as conn:
            stored = symbol_library.find(conn, f"elf:{BUILD_ID.hex()}")
        assert stored is not None
        assert ids["binary"]


class TestCli:
    def test_the_library_commands_round_trip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        debug = tmp_path / "vendor.debug"
        debug.write_bytes(vendor_debug_elf())
        empty = runner.invoke(cli.app, ["symbols-library", "--json"])
        assert empty.exit_code == 0
        assert json.loads(empty.stdout)["count"] == 0
        added = runner.invoke(cli.app, ["symbols-library-add", str(debug), "--json"])
        assert added.exit_code == 0
        assert json.loads(added.stdout)["symbol_library"][0]["identity"] == (
            f"elf:{BUILD_ID.hex()}"
        )
        listed = runner.invoke(cli.app, ["symbols-library", "--json"])
        assert json.loads(listed.stdout)["count"] == 1
        resolved = runner.invoke(cli.app, ["symbols-resolve", str(ids["binary"]), "--json"])
        assert resolved.exit_code == 0
        report = json.loads(resolved.stdout)
        assert report["matched"] is True
        with contextlib.closing(store.connect(ids["db"])) as conn:
            function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "make_thing"

    def test_the_list_human_form_says_when_it_is_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch, binary_elf())
        result = runner.invoke(cli.app, ["symbols-library"])
        assert result.exit_code == 0
        assert "the symbol library is empty" in result.stderr

    def test_the_resolve_human_form_reports_a_miss(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        result = runner.invoke(cli.app, ["symbols-resolve", str(ids["binary"])])
        assert result.exit_code == 0
        assert "No match" in result.stderr

    def test_forced_fetch_and_local_cannot_both_be_given(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        result = runner.invoke(
            cli.app, ["symbols-resolve", str(ids["binary"]), "--fetch", "--local"]
        )
        assert result.exit_code != 0
        assert "--fetch and --local" in result.stderr

    def test_a_forced_fetch_while_disabled_fails_loud(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "0")
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        result = runner.invoke(cli.app, ["symbols-resolve", str(ids["binary"]), "--fetch"])
        assert result.exit_code != 0
        assert "external-disabled" in result.stderr

    def test_an_add_refuses_a_file_without_an_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch, binary_elf())
        plain = tmp_path / "plain.elf"
        text, _names = _strtab("x")
        plain.write_bytes(build_elf([(".strtab", text, SHT_STRTAB, 0)]))
        result = runner.invoke(cli.app, ["symbols-library-add", str(plain)])
        assert result.exit_code != 0
        assert "no-identity" in result.stderr


def _tool(name: str) -> mcp_tools.Tool:
    return next(tool for tool in mcp_tools.tools() if tool.name == name)


class TestMcp:
    def test_list_symbol_library_reads_the_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        tool = _tool("list_symbol_library")
        assert tool.handler({})["count"] == 0
        added = _tool("add_symbol_library")
        result = added.handler({"paths": [str(ids["file"])]})
        assert result["count"] == 1
        assert tool.handler({})["count"] == 1

    def test_add_symbol_library_refuses_an_unreadable_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch, binary_elf())
        bad = tmp_path / "bad.bin"
        bad.write_bytes(b"zzz")
        added = _tool("add_symbol_library")
        with pytest.raises(mcp_tools.ToolError) as exc:
            added.handler({"paths": [str(bad)]})
        assert exc.value.error == "symbols-unreadable"

    def test_add_symbol_library_needs_a_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch, binary_elf())
        with pytest.raises(mcp_tools.ToolError) as exc:
            _tool("add_symbol_library").handler({"paths": []})
        assert exc.value.error == "invalid params"

    def test_resolve_symbols_applies_the_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, binary_elf())
        debug = tmp_path / "vendor.debug"
        debug.write_bytes(vendor_debug_elf())
        _tool("add_symbol_library").handler({"paths": [str(debug)]})
        report = _tool("resolve_symbols").handler({"binary_id": ids["binary"]})
        assert report["matched"] is True
        with contextlib.closing(store.connect(ids["db"])) as conn:
            function = store.get_function(conn, ids["function"])
        assert function is not None
        assert function["name"] == "make_thing"

    def test_resolve_symbols_forces_no_fetch_when_asked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        seen = _transport(200, synthetic_pdb())
        ids = _seed(tmp_path, monkeypatch, build_pe(), suffix=".exe")
        report = _tool("resolve_symbols").handler({"binary_id": ids["binary"], "fetch": False})
        assert report["matched"] is False
        assert report["fetch"] == "skipped"
        assert seen == {}

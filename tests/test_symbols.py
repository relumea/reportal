"""Tests for the debug-symbol readers and the symbol import.

The ELF and DWARF fixtures are assembled in memory, byte by byte, so the
readers are exercised against the layout they claim to read rather than against
whatever a host toolchain happens to emit.  The PDB container is built by
``tests/test_pdb.py``; here the dispatch is asserted with a minimal one.
"""

from __future__ import annotations

import contextlib
import json
import struct
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import auth, cli, journal, mcp_server, store, symbols
from reportal._paths import DB_ENV

runner = CliRunner()
BOUNDARY = "reportal-symbols-boundary"

# ── fixture builders ───────────────────────────────────────────────

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
STT_OBJECT = 1
STT_FUNC = 2


def _strtab(*names: str) -> tuple[bytes, dict[str, int]]:
    """A string table and the offset of each name in it."""
    blob = b"\x00"
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(blob)
        blob += name.encode() + b"\x00"
    return blob, offsets


def _symtab(
    names: dict[str, int],
    entries: list[tuple[str, int, str, int, int]],
    *,
    endian: str = "<",
) -> bytes:
    """A 64-bit symbol table: (name, value, kind, size, shndx) per entry."""
    blob = b""
    for name, value, kind, size, shndx in entries:
        symbol_type = STT_FUNC if kind == "function" else STT_OBJECT
        info = (1 << 4) | symbol_type
        blob += struct.pack(f"{endian}IBBHQQ", names[name], info, 0, shndx, value, size)
    return blob


def build_elf(
    sections: list[tuple[str, bytes, int, int]],
    *,
    machine: int = 62,
    big_endian: bool = False,
) -> bytes:
    """One 64-bit ELF: (name, data, type, link) per section.

    *big_endian* builds an EI_DATA=2 container so the reader is exercised on
    both byte orders a firmware image can carry.
    """
    endian = ">" if big_endian else "<"
    names = ["", *[name for name, _data, _type, _link in sections], ".shstrtab"]
    shstrtab, name_offsets = _strtab(*names[1:])
    count = len(sections) + 2  # the null section, the sections, the shstrtab
    shstrndx = count - 1
    header_size = 64
    shoff = header_size
    cursor = shoff + count * 64
    placed: list[tuple[int, int, int, int, bytes]] = []
    for name, data, section_type, link in sections:
        cursor = (cursor + 7) // 8 * 8
        placed.append((name_offsets[name], section_type, cursor, link, data))
        cursor += len(data)
    shstrtab_offset = (cursor + 7) // 8 * 8

    ident = b"\x7fELF" + bytes([2, 2 if big_endian else 1, 1]) + b"\x00" * 9
    header = ident + struct.pack(
        f"{endian}HHIQQQIHHHHHH",
        2,
        machine,
        1,
        0,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        count,
        shstrndx,
    )
    out = bytearray(header)
    out.extend(b"\x00" * (shoff - len(out)))
    headers = bytearray()
    headers += struct.pack(f"{endian}IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 1, 0)
    for name_offset, section_type, offset, link, data in placed:
        headers += struct.pack(
            f"{endian}IIQQQQIIQQ",
            name_offset,
            section_type,
            0,
            0,
            offset,
            len(data),
            link,
            0,
            1,
            24 if section_type == SHT_SYMTAB else 0,
        )
    headers += struct.pack(
        f"{endian}IIQQQQIIQQ",
        name_offsets[".shstrtab"],
        SHT_STRTAB,
        0,
        0,
        shstrtab_offset,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )
    out.extend(headers)
    for _name, _type, offset, _link, data in placed:
        out.extend(b"\x00" * (offset - len(out)))
        out.extend(data)
    out.extend(b"\x00" * (shstrtab_offset - len(out)))
    out.extend(shstrtab)
    return bytes(out)


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _die(abbrev: int, *values: bytes) -> bytes:
    return _uleb(abbrev) + b"".join(values)


def build_dwarf4() -> dict[str, bytes]:
    """A DWARF 4 unit with one struct, two members and one subprogram."""
    strings, offsets = _strtab("point", "x", "y", "int", "make_point", "pointer")
    # Abbreviations: struct, member, subprogram, base type, pointer type.
    abbrev = b""
    abbrev += _uleb(1)  # code
    abbrev += _uleb(0x13)  # DW_TAG_structure_type
    abbrev += b"\x01"  # has children
    abbrev += _uleb(0x03) + _uleb(0x0E)  # DW_AT_name, DW_FORM_strp
    abbrev += _uleb(0x0B) + _uleb(0x0B)  # DW_AT_byte_size, DW_FORM_data1
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(2)
    abbrev += _uleb(0x0D)  # DW_TAG_member
    abbrev += b"\x00"
    abbrev += _uleb(0x03) + _uleb(0x0E)
    abbrev += _uleb(0x38) + _uleb(0x0B)  # DW_AT_data_member_location, data1
    abbrev += _uleb(0x49) + _uleb(0x13)  # DW_AT_type, DW_FORM_ref4
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(3)
    abbrev += _uleb(0x2E)  # DW_TAG_subprogram
    abbrev += b"\x00"
    abbrev += _uleb(0x03) + _uleb(0x0E)
    abbrev += _uleb(0x11) + _uleb(0x01)  # DW_AT_low_pc, DW_FORM_addr
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(4)
    abbrev += _uleb(0x24)  # DW_TAG_base_type
    abbrev += b"\x00"
    abbrev += _uleb(0x03) + _uleb(0x0E)
    abbrev += _uleb(0x0B) + _uleb(0x0B)
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(5)
    abbrev += _uleb(0x0F)  # DW_TAG_pointer_type
    abbrev += b"\x00"
    abbrev += _uleb(0x03) + _uleb(0x0E)
    abbrev += _uleb(0x49) + _uleb(0x12)
    abbrev += _uleb(0) + _uleb(0)
    abbrev += b"\x00"

    # The body is assembled in two passes: the referenced DIEs go first so the
    # ref4 offsets are known when the members are encoded.
    body = bytearray()
    start = 11  # unit_length, version, abbrev offset and address size
    body_offset = start
    base_type_at = body_offset + len(body)
    body += _die(4, _uleb(offsets["int"]), b"\x04")
    base_type_size = len(_die(4, _uleb(offsets["int"]), b"\x04"))
    pointer_at = body_offset + len(body)
    body += _die(5, _uleb(offsets["pointer"]), struct.pack("<I", base_type_at))
    body += _die(
        1,
        _uleb(offsets["point"]),
        b"\x08",
        _die(2, _uleb(offsets["x"]), b"\x00", struct.pack("<I", base_type_at)),
        _die(2, _uleb(offsets["y"]), b"\x04", struct.pack("<I", pointer_at)),
        b"\x00",
    )
    body += _die(3, _uleb(offsets["make_point"]), struct.pack("<Q", 0x401000))
    info = struct.pack("<IHI", len(body) + 7, 4, 0) + b"\x08" + bytes(body)
    assert base_type_size > 0
    return {
        ".debug_abbrev": abbrev,
        ".debug_info": info,
        ".debug_str": strings,
    }


def build_dwarf5() -> dict[str, bytes]:
    """A DWARF 5 unit whose names and addresses use the indexed forms."""
    strings, _offsets = _strtab("main", "argc")
    # .debug_str_offsets: unit_length, version, padding, then one 4-byte offset
    # per index (main at 1, argc at 6 in .debug_str).
    str_offsets = struct.pack("<IHH", 12, 5, 0) + struct.pack("<II", 1, 6)
    # .debug_addr: unit_length, version, address size, segment selector size,
    # then one 8-byte address per index.
    addresses = struct.pack("<IHBB", 12, 5, 8, 0) + struct.pack("<Q", 0x401020)
    abbrev = b""
    abbrev += _uleb(1)
    abbrev += _uleb(0x2E)  # subprogram
    abbrev += b"\x00"
    abbrev += _uleb(0x03) + _uleb(0x26)  # DW_AT_name, DW_FORM_strx2
    abbrev += _uleb(0x11) + _uleb(0x2A)  # DW_AT_low_pc, DW_FORM_addrx2
    abbrev += _uleb(0) + _uleb(0)
    abbrev += _uleb(2)
    abbrev += _uleb(0x11)  # DW_TAG_compile_unit
    abbrev += b"\x01"
    abbrev += _uleb(0x72) + _uleb(0x17)  # DW_AT_str_offsets_base, DW_FORM_sec_offset
    abbrev += _uleb(0x73) + _uleb(0x17)  # DW_AT_addr_base, DW_FORM_sec_offset
    abbrev += _uleb(0) + _uleb(0)
    abbrev += b"\x00"

    body = bytearray()
    body += _die(2, struct.pack("<I", 8), struct.pack("<I", 8))
    body += _die(1, struct.pack("<H", 0), struct.pack("<H", 0))
    info = (
        struct.pack("<I", len(body) + 8)
        + struct.pack("<H", 5)
        + bytes([1, 8])
        + struct.pack("<I", 0)
        + bytes(body)
    )
    assert strings
    return {
        ".debug_abbrev": abbrev,
        ".debug_info": info,
        ".debug_str": strings,
        ".debug_str_offsets": str_offsets,
        ".debug_addr": addresses,
    }


# ── ELF symbols ────────────────────────────────────────────────────


class TestElfSymbols:
    def test_functions_and_objects_are_read_with_their_addresses(self) -> None:
        text, names = _strtab("main", "counter")
        elf = build_elf(
            [
                (
                    ".symtab",
                    _symtab(
                        names,
                        [
                            ("main", 0x401000, "function", 32, 1),
                            ("counter", 0x404000, "object", 4, 2),
                        ],
                    ),
                    SHT_SYMTAB,
                    2,
                ),
                (".strtab", text, SHT_STRTAB, 0),
            ]
        )
        parsed = symbols.parse(elf)
        assert parsed["kind"] == symbols.SOURCE_ELF
        assert parsed["counts"]["symbols"] == 2
        by_name = {entry["name"]: entry for entry in parsed["symbols"]}
        assert by_name["main"] == {
            "name": "main",
            "va": 0x401000,
            "size": 32,
            "kind": symbols.KIND_FUNCTION,
            "source": symbols.SOURCE_ELF,
        }
        assert by_name["counter"]["kind"] == symbols.KIND_OBJECT

    def test_a_big_endian_elf_is_read(self) -> None:
        text, names = _strtab("entry")
        elf = build_elf(
            [
                (
                    ".symtab",
                    _symtab(
                        names,
                        [("entry", 0x1000, "function", 16, 1)],
                        endian=">",
                    ),
                    SHT_SYMTAB,
                    2,
                ),
                (".strtab", text, SHT_STRTAB, 0),
            ],
            machine=8,  # MIPS
            big_endian=True,
        )
        parsed = symbols.parse(elf)
        assert parsed["counts"]["symbols"] == 1
        assert parsed["symbols"][0] == {
            "name": "entry",
            "va": 0x1000,
            "size": 16,
            "kind": symbols.KIND_FUNCTION,
            "source": symbols.SOURCE_ELF,
        }

    def test_an_unknown_elf_endianness_is_refused(self) -> None:
        # EI_DATA=0 is neither little nor big.
        data = bytearray(b"\x7fELF" + bytes([2, 0, 1]) + b"\x00" * 9 + b"\x00" * 48)
        with pytest.raises(symbols.UnreadableSymbolError) as caught:
            symbols.parse(bytes(data))
        assert "endianness" in caught.value.detail

    def test_an_unrelated_format_is_refused(self) -> None:
        with pytest.raises(symbols.UnreadableSymbolError) as caught:
            symbols.parse(b"not a symbol file", filename="notes.txt")
        assert caught.value.code == symbols.ERROR_UNREADABLE
        assert "notes.txt" in caught.value.detail

    def test_a_truncated_elf_is_refused(self) -> None:
        elf = build_elf([(".strtab", b"\x00", SHT_STRTAB, 0)])
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols.parse(elf[:40])

    def test_a_magic_only_prefix_is_refused(self) -> None:
        with pytest.raises(symbols.UnreadableSymbolError) as caught:
            symbols.parse(symbols.ELF_MAGIC)
        assert caught.value.code == symbols.ERROR_UNREADABLE
        assert "truncated" in caught.value.detail


# ── DWARF ──────────────────────────────────────────────────────────


class TestDwarf:
    def test_a_dwarf4_unit_yields_a_type_its_members_and_a_subprogram(self) -> None:
        sections = build_dwarf4()
        elf = build_elf(
            [
                (".debug_abbrev", sections[".debug_abbrev"], SHT_PROGBITS, 0),
                (".debug_info", sections[".debug_info"], SHT_PROGBITS, 0),
                (".debug_str", sections[".debug_str"], SHT_PROGBITS, 0),
            ]
        )
        parsed = symbols.parse(elf)
        assert parsed["counts"]["types"] == 1
        data_type = parsed["types"][0]
        assert data_type["name"] == "point"
        assert data_type["size"] == 8
        assert data_type["members"] == [
            {"name": "x", "type": "int", "offset": 0},
            {"name": "y", "type": "int *", "offset": 4},
        ]
        functions = [entry for entry in parsed["symbols"] if entry["kind"] == symbols.KIND_FUNCTION]
        assert [(entry["name"], entry["va"]) for entry in functions] == [("make_point", 0x401000)]
        assert functions[0]["source"] == symbols.SOURCE_DWARF

    def test_a_dwarf5_unit_resolves_the_indexed_forms(self) -> None:
        sections = build_dwarf5()
        elf = build_elf(
            [
                (".debug_abbrev", sections[".debug_abbrev"], SHT_PROGBITS, 0),
                (".debug_info", sections[".debug_info"], SHT_PROGBITS, 0),
                (".debug_str", sections[".debug_str"], SHT_PROGBITS, 0),
                (".debug_str_offsets", sections[".debug_str_offsets"], SHT_PROGBITS, 0),
                (".debug_addr", sections[".debug_addr"], SHT_PROGBITS, 0),
            ]
        )
        parsed = symbols.parse(elf)
        assert [(entry["name"], entry["va"]) for entry in parsed["symbols"]] == [("main", 0x401020)]

    def test_an_elf_without_debug_sections_reads_no_type(self) -> None:
        elf = build_elf([(".strtab", b"\x00", SHT_STRTAB, 0)])
        parsed = symbols.parse(elf)
        assert parsed["types"] == []
        assert parsed["counts"] == {"symbols": 0, "types": 0}


# ── The export ─────────────────────────────────────────────────────


class TestRender:
    def test_json_is_the_parse_itself(self) -> None:
        parsed = {"kind": "elf", "symbols": [], "types": [], "notes": [], "counts": {}}
        assert json.loads(symbols.render_symbols(parsed)) == parsed

    def test_the_c_header_reuses_the_type_renderer(self) -> None:
        parsed = {
            "kind": "dwarf",
            "symbols": [
                {"name": "make_point", "va": 1, "kind": "function", "source": "dwarf"},
                {"name": "counter", "va": 2, "kind": "object", "source": "elf"},
            ],
            "types": [
                {
                    "name": "point",
                    "kind": "struct",
                    "size": 4,
                    "namespace": "",
                    "members": [{"name": "x", "type": "int", "offset": 0}],
                }
            ],
        }
        header = symbols.render_symbols(parsed, kind="c")
        assert header.startswith("#pragma once")
        assert "typedef struct point_s {" in header
        assert "/* make_point */" in header
        assert "counter" not in header

    def test_a_comment_terminator_in_a_name_does_not_close_the_comment(self) -> None:
        parsed = {
            "kind": "dwarf",
            "symbols": [
                {"name": "evil */ #define PWNED 1 /*", "va": 1, "kind": "function"},
            ],
            "types": [],
        }
        header = symbols.render_symbols(parsed, kind="c")
        assert "/* evil x| #define PWNED 1 |x */" in header
        assert "#define PWNED" not in header.split("/* evil")[0]


# ── The reader's own branches ──────────────────────────────────────
#
# The form table, the LEB128 decoders and the type renderer are the parts a
# hostile or unusual file reaches, so they are exercised directly: a unit per
# form would be a byte-builder per form for the same branch.

_DWARF_UNIT: dict[str, Any] = {
    "dwarf": None,
    "address_size": 8,
    "offset_size": 4,
    "abbrev_offset": 0,
    "start": 0,
    "end": 16,
    "bases": {0x72: 0, 0x73: 0},
}


def _unit(**overrides: Any) -> dict[str, Any]:
    """A unit whose ``dwarf`` sections are empty unless a test says otherwise."""
    unit = dict(_DWARF_UNIT)
    unit["dwarf"] = overrides.pop("dwarf", _Dwarf())
    unit.update(overrides)
    return unit


class _Dwarf:
    """A stand-in for the section holder the form readers index into."""

    def __init__(self, **sections: bytes | None) -> None:
        self.info = sections.get("info")
        self.abbrev = sections.get("abbrev")
        self.strings = sections.get("strings")
        self.str_offsets = sections.get("str_offsets")
        self.addr = sections.get("addr")


class TestFormReaders:
    def test_every_sized_form_reads_its_value_and_advances(self) -> None:
        strings = b"\x00alpha\x00beta\x00"
        dwarf = _Dwarf(strings=strings, str_offsets=b"", addr=b"")
        unit = _unit(dwarf=dwarf)
        cases: list[tuple[int, bytes, Any, int]] = [
            (0x01, b"\x00\x10\x40\x00\x00\x00\x00\x00", 0x401000, 8),
            (0x03, b"\x02\x00ab", b"ab", 4),
            (0x04, b"\x02\x00\x00\x00ab", b"ab", 6),
            (0x05, b"\x34\x12", 0x1234, 2),
            (0x06, b"\x78\x56\x34\x12", 0x12345678, 4),
            (0x07, b"\x01\x00\x00\x00\x00\x00\x00\x00", 1, 8),
            (0x08, b"alpha\x00", "alpha", 6),
            (0x09, b"\x02ab", b"ab", 3),
            (0x0A, b"\x02ab", b"ab", 3),
            (0x0B, b"\x07", 7, 1),
            (0x0C, b"\x01", True, 1),
            (0x0D, b"\x7f", -1, 1),
            (0x0E, b"\x01", "alpha", 1),
            (0x0F, b"\x81\x01", 129, 2),
            (0x10, b"\x00\x10\x40\x00\x00\x00\x00\x00", 0x401000, 8),
            (0x11, b"\x05", 5, 1),
            (0x12, b"\x05\x00", 5, 2),
            (0x13, b"\x05\x00\x00\x00", 5, 4),
            (0x14, b"\x05\x00\x00\x00\x00\x00\x00\x00", 5, 8),
            (0x15, b"\x05", 5, 1),
            (0x17, b"\x05\x00\x00\x00", 5, 4),
            (0x18, b"\x02\x23\x08", b"\x23\x08", 3),
            (0x19, b"", True, 0),
            (0x1C, b"\x05\x00\x00\x00", 5, 4),
            (0x1D, b"\x05\x00\x00\x00", 5, 4),
            (0x1E, b"\x01" + b"\x00" * 15, 1, 16),
            (0x1F, b"\x05\x00\x00\x00", 5, 4),
            (0x20, b"\x01\x00\x00\x00\x00\x00\x00\x00", 1, 8),
            (0x21, b"\x7f", -1, 1),
            (0x22, b"\x05", 5, 1),
            (0x23, b"\x05", 5, 1),
            (0x24, b"\x01\x00\x00\x00\x00\x00\x00\x00", 1, 8),
        ]
        for form, data, value, cursor in cases:
            read = symbols._form_value(data, 0, form, unit)
            assert read is not None, hex(form)
            assert read == (value, cursor), hex(form)

    def test_the_indexed_forms_read_their_width(self) -> None:
        strings = b"\x00name\x00"
        str_offsets = struct.pack("<II", 1, 0)
        addresses = struct.pack("<Q", 0x401000)
        unit = _unit(dwarf=_Dwarf(strings=strings, str_offsets=str_offsets, addr=addresses))
        assert symbols._form_value(b"\x00", 0, 0x1A, unit) == ("name", 1)
        assert symbols._form_value(b"\x00", 0, 0x25, unit) == ("name", 1)
        assert symbols._form_value(struct.pack("<H", 0), 0, 0x26, unit) == ("name", 2)
        assert symbols._form_value(b"\x00", 0, 0x1B, unit) == (0x401000, 1)
        assert symbols._form_value(struct.pack("<H", 0), 0, 0x2A, unit) == (0x401000, 2)

    def test_an_unsized_form_answers_none(self) -> None:
        assert symbols._form_value(b"", 0, 0x16, _unit()) is None

    def test_a_fixed_form_past_the_end_is_a_truncation(self) -> None:
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols._form_value(b"\x00", 0, 0x13, _unit())

    def test_the_leb128_decoders_refuse_a_run_off_the_end(self) -> None:
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols._uleb(b"\x80", 0)
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols._sleb(b"\x80", 0)
        assert symbols._sleb(b"\x7f", 0) == (-1, 1)

    def test_a_string_outside_its_table_is_empty(self) -> None:
        assert symbols._string_at(b"\x00ab\x00", 99) == ""
        assert symbols._string_at(b"ab", 0) == ""
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols._inline_string(b"abc", 0)

    def test_the_fixed_width_table_matches_the_bounds_check(self) -> None:
        assert symbols._fixed_width(0x01, 8, 4) == 8
        assert symbols._fixed_width(0x13, 8, 4) == 4
        assert symbols._fixed_width(0x17, 8, 8) == 8
        assert symbols._fixed_width(0x19, 8, 4) == 0


class TestDwarfBranches:
    def test_the_indexed_tables_missing_answer_empty(self) -> None:
        unit = _unit(dwarf=_Dwarf(strings=b"\x00x\x00"))
        assert symbols._strx_string(unit, 0) == ""
        assert symbols._addr_value(unit, 0) is None
        present = _unit(dwarf=_Dwarf(strings=b"", str_offsets=b"", addr=b""))
        assert symbols._strx_string(present, 999) == ""
        assert symbols._addr_value(present, 999) is None

    def test_an_unknown_abbreviation_offset_and_code_are_refused(self) -> None:
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols._abbrev_table(b"\x01", 9)
        unit = _unit(dwarf=_Dwarf(info=b"\x09", abbrev=b"\x01\x2e\x00\x00\x00"))
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols._dies(unit)

    def test_a_truncated_unit_list_stops_rather_than_guessing(self) -> None:
        assert symbols._units(b"") == []
        assert symbols._units(b"\x01\x00\x00\x00") == []
        assert symbols._units(struct.pack("<IHI", 20, 4, 0) + b"\x08" + b"\x00" * 4) == []

    def test_a_member_offset_expression_is_read_or_skipped(self) -> None:
        assert symbols._member_offset(4) == 4
        assert symbols._member_offset(b"\x23\x08") == 8
        assert symbols._member_offset(b"\x10") is None
        assert symbols._member_offset(None) is None

    def test_the_type_renderer_covers_every_tag_it_maps(self) -> None:
        dies: list[symbols._DIE] = [
            (0x24, {0x03: "int"}, 0, 10),
            (0x0F, {0x49: 10}, 0, 20),
            (0x26, {0x49: 10}, 0, 30),
            (0x13, {0x03: "point"}, 0, 40),
            (0x17, {0x03: "value"}, 0, 50),
            (0x04, {0x03: "colour"}, 0, 60),
            (0x16, {0x03: "handle"}, 0, 70),
            (0x01, {0x49: 10, 0x37: 4}, 0, 80),
            (0x15, {}, 0, 90),
            (0x3B, {}, 0, 100),
        ]
        by_offset = {entry[3]: entry for entry in dies}
        render = symbols._type_name
        assert render(10, by_offset, frozenset(), 0) == "int"
        assert render(20, by_offset, frozenset(), 0) == "int *"
        assert render(30, by_offset, frozenset(), 0) == "const int"
        assert render(40, by_offset, frozenset(), 0) == "struct point"
        assert render(50, by_offset, frozenset(), 0) == "union value"
        assert render(60, by_offset, frozenset(), 0) == "enum colour"
        assert render(70, by_offset, frozenset(), 0) == "handle"
        assert render(80, by_offset, frozenset(), 0) == "int[4]"
        assert render(90, by_offset, frozenset(), 0) == "void *"
        assert render(100, by_offset, frozenset(), 0) == "void"
        assert render(999, by_offset, frozenset(), 0) == ""
        assert render("x", by_offset, frozenset(), 0) == ""
        assert render(40, by_offset, frozenset({40}), 0) == ""
        assert render(20, by_offset, frozenset(), symbols.MAX_TYPE_DEPTH) == ""
        assert render(30, {30: dies[2]}, frozenset(), 0) == "const"

    def test_the_unit_type_scan_reports_a_truncated_member_list(self) -> None:
        notes: list[str] = []
        dies: list[symbols._DIE] = [(0x13, {0x03: "wide", 0x0B: 4}, 0, 0)]
        dies.extend(
            (0x0D, {0x03: f"m{index}", 0x38: index}, 1, index + 1)
            for index in range(symbols.MAX_MEMBERS + 2)
        )
        types = symbols._unit_types(dies, notes)
        assert len(types[0]["members"]) == symbols.MAX_MEMBERS
        assert any("truncated" in note for note in notes)

    def test_a_member_without_a_name_or_a_location_is_noted(self) -> None:
        notes: list[str] = []
        dies: list[symbols._DIE] = [
            (0x13, {0x03: "point"}, 0, 0),
            (0x0D, {0x03: "x"}, 1, 1),
            (0x0D, {0x03: "y", 0x38: b"\x10"}, 1, 2),
            (0x0D, {0x38: 0}, 1, 3),
        ]
        types = symbols._unit_types(dies, notes)
        assert types[0]["members"] == []
        assert any("location expression" in note for note in notes)
        assert any("unnamed" in note for note in notes)


class TestSymbolShape:
    def test_a_name_is_bounded_and_a_result_states_its_truncation(self) -> None:
        entry = symbols._symbol("x" * 900, va=1, kind=symbols.KIND_FUNCTION, source="elf")
        assert len(entry["name"]) == symbols.MAX_NAME_CHARS
        long_list = [
            symbols._symbol(f"n{index}", va=index, kind=symbols.KIND_FUNCTION, source="elf")
            for index in range(symbols.MAX_SYMBOLS + 1)
        ]
        result = symbols._result(kind="elf", symbols=long_list)
        assert result["counts"]["symbols"] == symbols.MAX_SYMBOLS
        assert any("truncated" in note for note in result["notes"])


# ── The store ──────────────────────────────────────────────────────


class TestStoredFiles:
    def test_the_digest_and_the_path_are_content_addressed(self, tmp_path: Path) -> None:
        data = b"symbols"
        digest = symbols.digest(data)
        assert len(digest) == 64
        assert symbols.stored_path(digest).name == digest
        assert tmp_path.exists()


# ── The store and the import ───────────────────────────────────────


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A portal DB with one binary and one function at 0x401000."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x401000, name="sub_401000"
        )
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id, "db": db}


def _symbol_elf() -> bytes:
    """An ELF whose DWARF names 0x401000 and declares one struct."""
    sections = build_dwarf4()
    text, names = _strtab("sub_401000", "make_point")
    dwarf = build_dwarf4_strings(names)
    return build_elf(
        [
            (
                ".symtab",
                _symtab(names, [("sub_401000", 0x401000, "function", 8, 1)]),
                SHT_SYMTAB,
                2,
            ),
            (".strtab", text, SHT_STRTAB, 0),
            (".debug_abbrev", sections[".debug_abbrev"], SHT_PROGBITS, 0),
            (".debug_info", dwarf, SHT_PROGBITS, 0),
            (".debug_str", sections[".debug_str"], SHT_PROGBITS, 0),
        ]
    )


def build_dwarf4_strings(_names: dict[str, int]) -> bytes:
    """The DWARF 4 unit of the shared fixture, which names make_point."""
    return build_dwarf4()[".debug_info"]


def _multipart(
    content: bytes | None, *, filename: str = "demo.pdb", apply: str | None = None
) -> tuple[bytes, dict[str, str]]:
    """A multipart body with one optional ``file`` part and an ``apply`` field."""
    parts: list[bytes] = []
    if content is not None:
        disposition = f'Content-Disposition: form-data; name="file"; filename="{filename}"'
        parts.append(disposition.encode() + b"\r\n\r\n" + content)
    if apply is not None:
        parts.append(b'Content-Disposition: form-data; name="apply"\r\n\r\n' + apply.encode())
    body = b"".join(f"--{BOUNDARY}\r\n".encode() + part + b"\r\n" for part in parts)
    body += f"--{BOUNDARY}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}


class TestImport:
    def test_it_renames_the_matching_function_and_stores_the_types(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        elf = _symbol_elf()
        with contextlib.closing(store.connect(ids["db"])) as conn:
            data = elf
            parsed = symbols.parse(elf)
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                report = symbols.import_symbols(
                    conn, log, binary_id=ids["binary"], data=data, parsed=parsed
                )
            function = store.get_function(conn, ids["function"])
            data_type = store.find_data_type_by_name(conn, ids["binary"], "point")
            assert report["applied"] == 1
            assert report["symbols"] >= 1
            assert report["types"] == 1
            assert function is not None
            assert function["name_source"] == symbols.SYMBOL_NAME_SOURCE
            assert data_type is not None
            assert len(data_type["members"]) == 2
            assert journal.revert_action(conn, action)["reverted"] > 0
            restored = store.get_function(conn, ids["function"])
            names = {entry["name"] for entry in symbols.list_files(conn, ids["binary"])}
        assert restored is not None
        assert restored["name"] == "sub_401000"
        assert names == set()

    def test_apply_false_stores_the_parse_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        elf = _symbol_elf()
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                report = symbols.import_symbols(
                    conn,
                    log,
                    binary_id=ids["binary"],
                    data=elf,
                    parsed=symbols.parse(elf),
                    apply=False,
                )
            function = store.get_function(conn, ids["function"])
        assert report["applied"] == 0
        assert report["truncated"] is True
        assert function is not None
        assert function["name"] == "sub_401000"

    def test_an_unknown_binary_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        elf = _symbol_elf()
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with (
                journal.journaled(conn, action) as log,
                pytest.raises(symbols.UnknownSymbolFileError),
            ):
                symbols.import_symbols(
                    conn, log, binary_id=999, data=elf, parsed=symbols.parse(elf)
                )

    def test_the_reads_report_what_is_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        elf = _symbol_elf()
        with contextlib.closing(store.connect(ids["db"])) as conn:
            with pytest.raises(symbols.UnknownSymbolFileError):
                symbols.get_file(conn, binary_id=ids["binary"])
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                report = symbols.import_symbols(
                    conn, log, binary_id=ids["binary"], data=elf, parsed=symbols.parse(elf)
                )
            one = symbols.get_file(conn, binary_id=ids["binary"], file_id=int(report["id"]))
            with pytest.raises(symbols.UnknownSymbolFileError):
                symbols.get_file(conn, binary_id=ids["binary"], file_id=999)
        assert one["kind"] == symbols.SOURCE_ELF
        assert one["parsed"]["counts"]["types"] == 1


class TestSymbolRoutes:
    def test_the_upload_applies_the_symbols(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        body, headers = _multipart(_symbol_elf(), filename="demo.elf")
        status, response_headers, response = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols", body=body, headers=headers
        )
        assert status.startswith("200"), response
        payload = json_body(response, response_headers)
        assert payload["applied"] == 1
        assert payload["types"] == 1
        assert payload["journal_action"]

        listed, response_headers, response = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/symbols"
        )
        assert listed.startswith("200"), response
        assert json_body(response, response_headers)["count"] == 1

        exported, response_headers, response = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/symbols/export?format=c"
        )
        assert exported.startswith("200")
        assert response_headers.get("Content-Type", "").startswith("text/plain")
        assert b"typedef struct point_s" in response

        as_json, _, response = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/symbols/export?format=json"
        )
        assert json.loads(response.decode())["counts"]["types"] == 1

    def test_store_only_and_the_refusals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        body, headers = _multipart(_symbol_elf(), apply="false")
        status, response_headers, response = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols", body=body, headers=headers
        )
        assert status.startswith("200"), response
        assert json_body(response, response_headers)["applied"] == 0

        body, headers = _multipart(b"not a symbol file")
        status, response_headers, response = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols", body=body, headers=headers
        )
        assert status.startswith("400"), response
        assert json_body(response, response_headers)["error"] == symbols.ERROR_UNREADABLE

        empty, headers = _multipart(None)
        status, response_headers, response = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols", body=empty, headers=headers
        )
        assert status.startswith("400")
        assert json_body(response, response_headers)["error"] == "no-file"

        missing, _, _ = wsgi_request("GET", "/api/binaries/999/symbols")
        assert missing.startswith("404")

        bad_format, response_headers, response = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/symbols/export?format=yaml"
        )
        assert bad_format.startswith("400")
        assert json_body(response, response_headers)["error"] == "invalid format"

    def test_unknown_binary_upload_leaves_no_symbol_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 404 after a valid parse must not keep content-addressed bytes."""
        root = tmp_path / "ws"
        root.mkdir()
        (root / "reportal.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(root)
        _seed(tmp_path, monkeypatch)
        body, headers = _multipart(_symbol_elf(), filename="demo.elf")
        status, response_headers, response = wsgi_request(
            "POST", "/api/binaries/999/symbols", body=body, headers=headers
        )
        assert status.startswith("404"), response
        assert json_body(response, response_headers)["error"] == "binary not found"
        symbols_dir = root / symbols.SYMBOLS_DIR
        leftover = (
            [path for path in symbols_dir.rglob("*") if path.is_file()]
            if symbols_dir.exists()
            else []
        )
        assert leftover == []

    def test_upload_to_a_hidden_binary_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
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
        body, headers = _multipart(_symbol_elf(), filename="demo.elf")
        headers = {**headers, "Authorization": f"Bearer {outsider}"}
        stranger_status, response_headers, response = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols", body=body, headers=headers
        )
        assert stranger_status.startswith("403"), response
        assert json_body(response, response_headers)["error"] == "scope-forbidden"

        body, headers = _multipart(_symbol_elf(), filename="demo.elf")
        headers = {**headers, "Authorization": f"Bearer {token}"}
        member_status, _, _ = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/symbols", body=body, headers=headers
        )
        assert member_status.startswith("200"), member_status

    def test_a_binary_with_no_ingest_reports_no_symbols(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, response_headers, response = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/symbols"
        )
        assert status.startswith("404")
        assert json_body(response, response_headers)["error"] == "no-symbols"
        missing, _, _ = wsgi_request("GET", f"/api/binaries/{ids['binary']}/symbols/export")
        assert missing.startswith("404")


class TestSymbolCli:
    @pytest.mark.parametrize("export_name", ["symbols.h", "s" * 248 + ".h"])
    def test_the_commands(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, export_name: str
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        path = tmp_path / "demo.elf"
        path.write_bytes(_symbol_elf())

        ingested = runner.invoke(cli.app, ["symbols", str(ids["binary"]), str(path), "--json"])
        assert ingested.exit_code == 0, ingested.output
        payload = json.loads(ingested.output)
        assert payload["applied"] == 1
        assert payload["journal_action"]

        human = runner.invoke(cli.app, ["symbols-status", str(ids["binary"]), "--json"])
        assert human.exit_code == 0, human.output
        assert json.loads(human.output)["count"] == 1

        table = runner.invoke(cli.app, ["symbols-status", str(ids["binary"])])
        assert table.exit_code == 0, table.output
        assert "symbol files of binary" in table.output

        one = runner.invoke(
            cli.app, ["symbols-status", str(ids["binary"]), "--file-id", str(payload["id"])]
        )
        assert one.exit_code == 0, one.output
        assert "make_point" in one.output

        export_path = tmp_path / export_name
        exported = runner.invoke(
            cli.app,
            [
                "symbols-export",
                str(ids["binary"]),
                "--output",
                str(export_path),
                "--json",
            ],
        )
        assert exported.exit_code == 0, exported.output
        assert "typedef struct point_s" in export_path.read_text()

        console_export = runner.invoke(
            cli.app, ["symbols-export", str(ids["binary"]), "--format", "json"]
        )
        assert console_export.exit_code == 0, console_export.output
        assert json.loads(console_export.output)["kind"] == symbols.SOURCE_ELF

        wrapped = runner.invoke(
            cli.app, ["symbols-export", str(ids["binary"]), "--format", "c", "--json"]
        )
        assert wrapped.exit_code == 0, wrapped.output
        envelope = json.loads(wrapped.stdout)
        assert envelope["format"] == "c"
        assert "typedef struct point_s" in envelope["text"]

    def test_the_commands_refuse_bad_input(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        bad = tmp_path / "notes.txt"
        bad.write_text("nothing to see")
        result = runner.invoke(cli.app, ["symbols", str(ids["binary"]), str(bad)])
        assert result.exit_code == 1
        assert symbols.ERROR_UNREADABLE in result.output

        missing = runner.invoke(cli.app, ["symbols", "999", str(bad)])
        assert missing.exit_code == 1

        no_ingest = runner.invoke(cli.app, ["symbols-status", str(ids["binary"])])
        assert no_ingest.exit_code == 1
        assert "no-symbols" in no_ingest.output

        format_result = runner.invoke(
            cli.app, ["symbols-export", str(ids["binary"]), "--format", "yaml"]
        )
        assert format_result.exit_code == 1
        assert "format must be" in format_result.output

        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        for argv in (
            ["symbols", "1", str(bad)],
            ["symbols-status", "1"],
            ["symbols-export", "1"],
        ):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no reportal database" in result.output


class TestSymbolMcp:
    @pytest.mark.parametrize("export_name", ["symbols.h", "s" * 248 + ".h"])
    def test_the_tools(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, export_name: str
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        path = tmp_path / "demo.elf"
        path.write_bytes(_symbol_elf())

        imported, failed = mcp_server.call_tool(
            "import_symbols", {"binary_id": ids["binary"], "path": str(path)}
        )
        assert not failed, imported
        assert imported["applied"] == 1
        assert imported["journal_action"]

        listed, failed = mcp_server.call_tool("get_symbols", {"binary_id": ids["binary"]})
        assert not failed, listed
        assert listed["count"] == 1

        one, failed = mcp_server.call_tool(
            "get_symbols", {"binary_id": ids["binary"], "file_id": imported["id"]}
        )
        assert not failed, one
        assert one["parsed"]["counts"]["types"] == 1

        export_path = tmp_path / export_name
        exported, failed = mcp_server.call_tool(
            "export_symbols", {"binary_id": ids["binary"], "path": str(export_path)}
        )
        assert not failed, exported
        assert export_path.read_text().startswith("#pragma once")

        bad, failed = mcp_server.call_tool(
            "import_symbols", {"binary_id": ids["binary"], "path": str(tmp_path / "nope.elf")}
        )
        assert failed
        assert bad["error"] == symbols.ERROR_UNREADABLE

        unknown, failed = mcp_server.call_tool("get_symbols", {"binary_id": 999})
        assert failed
        assert unknown["error"] == "binary not found"

        no_ingest, failed = mcp_server.call_tool(
            "get_symbols", {"binary_id": ids["binary"], "file_id": 999}
        )
        assert failed
        assert no_ingest["error"] == symbols.UnknownSymbolFileError("").code

        bad_format, failed = mcp_server.call_tool(
            "export_symbols",
            {"binary_id": ids["binary"], "path": str(export_path), "format": "yaml"},
        )
        assert failed
        assert bad_format["error"] == "invalid format"

        outside = tmp_path.parent / f"outside-{tmp_path.name}" / "escaped.h"
        escaped, failed = mcp_server.call_tool(
            "export_symbols",
            {"binary_id": ids["binary"], "path": str(outside)},
        )
        assert failed
        assert escaped["error"] == "invalid path"
        assert "workspace" in escaped["detail"]
        assert not outside.exists()


class TestElfRefusals:
    def test_an_elf_without_section_headers_is_refused(self) -> None:
        import struct as _struct

        elf = bytearray(build_elf([(".strtab", b"\x00", SHT_STRTAB, 0)]))
        _struct.pack_into("<Q", elf, 0x28, 0)
        _struct.pack_into("<H", elf, 0x3C, 0)
        with pytest.raises(symbols.UnreadableSymbolError, match="no section headers"):
            symbols.parse(bytes(elf))

    def test_an_absurd_section_count_is_refused(self) -> None:
        import struct as _struct

        elf = bytearray(build_elf([(".strtab", b"\x00", SHT_STRTAB, 0)]))
        _struct.pack_into("<H", elf, 0x3C, 0xFFFF)
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols.parse(bytes(elf))


class TestSymbolsEdges:
    def test_bad_link_reads_no_symbols(self) -> None:
        elf = build_elf([(".symtab", b"\x00" * 24, SHT_SYMTAB, 99)])
        result = symbols.parse(elf)
        assert result["symbols"] == []

    def test_zero_length_dwarf_unit_ends_the_scan(self) -> None:
        assert symbols._units(b"\x00\x00\x00\x00rest", byteorder="little") == []

    def test_truncated_leb128_is_unreadable(self) -> None:
        with pytest.raises(symbols.UnreadableSymbolError):
            symbols._uleb(b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80", 0)

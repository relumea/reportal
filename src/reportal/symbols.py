"""Debug-symbol ingestion: function names and types from a symbol file.

A debug symbol file is the one source of names reportal cannot derive: the
engine's project annotations, library identification and the rename paths all
produce a guess, while a PDB or an ELF/DWARF table states what the toolchain
knew when it built the binary.

The readers here are stdlib-only byte parsers and write nothing:

* :func:`parse_elf` reads the ELF symbol table (``.symtab`` and ``.dynsym``:
  function and object names, addresses, sizes);
* :func:`parse_dwarf` reads ``.debug_info`` for subprogram names with their
  addresses and for the aggregate types (struct, class, union, enum) with their
  members, which is what makes a symbol file a *type* source and not only a
  name source;
* :mod:`reportal.pdb` reads a PDB 7.0 container's public symbols (names only).

:func:`parse` dispatches on the file's magic, so a caller hands over bytes and
gets one shape back.  Every result carries the ``notes`` list saying what the
reader did not do, because a byte parser that silently returns less than it
looks like it does is worse than one that says so.

Applying a parse is :func:`import_symbols`: a function whose VA matches a
symbol is renamed through :func:`reportal.journal.journaled_rename` with the
``symbol`` name source, and every recovered aggregate type is stored in the
editable type model through :func:`reportal.store.add_data_type`.  Both are
journaled, so an import is revertible like every other write, and the raw file
is kept content-addressed under the workspace's ``symbols/`` directory.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from reportal import data_types, journal, pdb, store

# The table the ingested symbol files live in (created on first use).
TABLE = "symbol_files"

# What a symbol is.
KIND_FUNCTION = "function"
KIND_OBJECT = "object"
KIND_OTHER = "other"

# Where a symbol came from, and the name source an applied symbol records.
SOURCE_ELF = "elf"
SOURCE_DWARF = "dwarf"
SOURCE_PDB = "pdb"
SYMBOL_NAME_SOURCE = "symbol"

# The kinds a caller can ingest, and the workspace directory the raw files land in.
KINDS: tuple[str, ...] = (SOURCE_ELF, SOURCE_DWARF, SOURCE_PDB)
SYMBOLS_DIR = "symbols"

# Bounds: a symbol table is untrusted input, so every list is capped.
MAX_SYMBOLS = 200_000
MAX_TYPES = 5_000
MAX_MEMBERS = 2_048
MAX_TYPE_DEPTH = 6
MAX_NAME_CHARS = 512

# The error code the surfaces report for a file the reader cannot follow.
ERROR_UNREADABLE = "symbols-unreadable"

ELF_MAGIC = b"\x7fELF"
PDB_MAGIC = pdb.CONTAINER_MAGIC

# ELF constants the readers use.
_SHT_SYMTAB = 2
_SHT_DYNSYM = 11
_SHT_NOBITS = 8
_STT_OBJECT = 1
_STT_FUNC = 2
_SECTION_NAME = ".shstrtab"


class SymbolError(Exception):
    """Base class for a rejected symbol operation."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


class UnreadableSymbolError(SymbolError, ValueError):
    """The file is not a symbol file this reader can follow; the API answers 400."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_UNREADABLE, detail)


class UnknownSymbolFileError(SymbolError, LookupError):
    """No symbol file was ingested for the binary; the API answers 404."""

    def __init__(self, detail: str) -> None:
        super().__init__("no-symbols", detail)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the symbol-file table when the database predates it."""
    conn.executescript(_SCHEMA)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS symbol_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id   INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    sha256      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    size        INTEGER NOT NULL DEFAULT 0,
    path        TEXT NOT NULL DEFAULT '',
    parsed_json TEXT NOT NULL DEFAULT '{}',
    symbols     INTEGER NOT NULL DEFAULT 0,
    types       INTEGER NOT NULL DEFAULT 0,
    applied     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_symbol_files_binary ON symbol_files(binary_id);
"""


# ── The shared result shape ────────────────────────────────────────


def _bounded_name(name: str) -> str:
    """A symbol name, capped so one hostile file cannot store a megabyte name."""
    trimmed = name.strip("\x00").strip()
    return trimmed[:MAX_NAME_CHARS]


def _symbol(name: str, *, va: int | None, kind: str, source: str, size: int = 0) -> dict[str, Any]:
    """One symbol entry of the shared result shape."""
    return {
        "name": _bounded_name(name),
        "va": va,
        "size": int(size),
        "kind": kind,
        "source": source,
    }


def _result(
    *,
    kind: str,
    symbols: Sequence[dict[str, Any]],
    types: Sequence[dict[str, Any]] = (),
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """One parse result, with its counts and its stated ceilings."""
    kept = list(symbols[:MAX_SYMBOLS])
    if len(symbols) > MAX_SYMBOLS:
        notes = [
            *notes,
            f"the symbol list was truncated at {MAX_SYMBOLS} entries",
        ]
    return {
        "kind": kind,
        "symbols": kept,
        "types": list(types[:MAX_TYPES]),
        "notes": list(notes),
        "counts": {"symbols": len(kept), "types": len(types[:MAX_TYPES])},
    }


# ── ELF ────────────────────────────────────────────────────────────


class _Elf:
    """One parsed ELF container: its sections and its symbol table."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        if data[:4] != ELF_MAGIC:
            raise UnreadableSymbolError("not an ELF file")
        self.is64 = data[4] == 2
        if data[5] != 1:
            raise UnreadableSymbolError("only a little-endian ELF is read")
        if self.is64:
            header = self._unpack("<HHIQQQIHHHHHH", 16, 48)
            self.machine = int(header[1])
            self.shoff = int(header[5])
            self.shentsize = int(header[10])
            self.shnum = int(header[11])
            self.shstrndx = int(header[12])
        else:
            header = self._unpack("<HHIIIIIHHHHHH", 16, 36)
            self.machine = int(header[1])
            self.shoff = int(header[4])
            self.shentsize = int(header[9])
            self.shnum = int(header[10])
            self.shstrndx = int(header[11])
        if self.shnum == 0 or self.shoff == 0:
            raise UnreadableSymbolError("the ELF carries no section headers")
        if self.shnum > 65_535:
            raise UnreadableSymbolError("the ELF section count is out of range")
        self.sections = [self._section(index) for index in range(self.shnum)]

    def _unpack(self, fmt: str, offset: int, size: int) -> tuple[Any, ...]:
        """Unpack one struct, refusing a read past the end of the file."""
        if offset < 0 or offset + size > len(self.data):
            raise UnreadableSymbolError("the ELF is truncated")
        return struct.unpack_from(fmt, self.data, offset)

    def _section(self, index: int) -> dict[str, Any]:
        """One section header as a plain dict."""
        offset = self.shoff + index * self.shentsize
        if self.is64:
            fields = self._unpack("<IIQQQQIIQQ", offset, 64)
        else:
            fields = self._unpack("<IIIIIIIIII", offset, 40)
        return {
            "name_offset": int(fields[0]),
            "type": int(fields[1]),
            "addr": int(fields[3]),
            "offset": int(fields[4]),
            "size": int(fields[5]),
            "link": int(fields[6]),
            "entsize": int(fields[9]),
        }

    def section_data(self, section: Mapping[str, Any]) -> bytes:
        """The bytes of one section, refusing a range outside the file."""
        start = int(section["offset"])
        size = int(section["size"])
        if start < 0 or size < 0 or start + size > len(self.data):
            raise UnreadableSymbolError("a section range is outside the file")
        return self.data[start : start + size]

    def section_by_name(self, name: str) -> dict[str, Any] | None:
        """The first section with *name*, or None."""
        for section in self.sections:
            if self._name_of(section) == name:
                return section
        return None

    def _name_of(self, section: Mapping[str, Any]) -> str:
        """One section's name, read through the section-name string table."""
        if not 0 <= self.shstrndx < len(self.sections):
            return ""
        table = self.section_data(self.sections[self.shstrndx])
        offset = int(section["name_offset"])
        if offset < 0 or offset >= len(table):
            return ""
        end = table.find(b"\x00", offset)
        if end < 0:
            return ""
        return table[offset:end].decode("utf-8", "replace")

    def symbol_table(self) -> list[dict[str, Any]]:
        """Every symbol of ``.symtab`` and ``.dynsym``, deduplicated by ``(va, name)``."""
        found: dict[tuple[int, str], dict[str, Any]] = {}
        for section in self.sections:
            if int(section["type"]) not in (_SHT_SYMTAB, _SHT_DYNSYM):
                continue
            for entry in self._symbols_of(section):
                key = (int(entry["va"] or 0), str(entry["name"]))
                found.setdefault(key, entry)
        return list(found.values())

    def _symbols_of(self, section: Mapping[str, Any]) -> list[dict[str, Any]]:
        """The symbols of one symbol-table section, in table order."""
        entry_size = self.is64 and 24 or 16
        declared = int(section.get("entsize") or 0)
        if declared and declared != entry_size:
            entry_size = declared
        # The linked section is the string table the names index into.
        link = int(section["link"])
        if not 0 <= link < len(self.sections):
            return []
        strings = self.section_data(self.sections[link])
        blob = self.section_data(section)
        rows: list[dict[str, Any]] = []
        for offset in range(0, len(blob) - entry_size + 1, entry_size):
            if self.is64:
                name_at, info, _other, shndx, value, size = struct.unpack_from(
                    "<IBBHQQ", blob, offset
                )
            else:
                name_at, value, size, info, _other, shndx = struct.unpack_from(
                    "<IIIBBH", blob, offset
                )
            name = _string_at(strings, int(name_at))
            if not name:
                continue
            symbol_type = int(info) & 0xF
            if symbol_type == _STT_FUNC:
                kind = KIND_FUNCTION
            elif symbol_type == _STT_OBJECT:
                kind = KIND_OBJECT
            elif symbol_type == 0 and int(shndx) == 0:
                continue  # an undefined reference carries no address here
            else:
                kind = KIND_OTHER
            rows.append(
                _symbol(
                    name,
                    va=int(value) or None,
                    kind=kind,
                    source=SOURCE_ELF,
                    size=int(size),
                )
            )
        return rows


def _string_at(table: bytes, offset: int) -> str:
    """One NUL-terminated string of *table*, or "" when the offset is outside it."""
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end < 0:
        return ""
    return table[offset:end].decode("utf-8", "replace")


def parse_elf(data: bytes) -> dict[str, Any]:
    """A parse result for an ELF file's symbol table (and its DWARF, when present)."""
    elf = _Elf(data)
    dwarf_symbols, types, notes = parse_dwarf(elf)
    found: dict[tuple[int, str], dict[str, Any]] = {}
    for entry in [*elf.symbol_table(), *dwarf_symbols]:
        key = (int(entry["va"] or 0), str(entry["name"]))
        found.setdefault(key, entry)
    return _result(kind=SOURCE_ELF, symbols=list(found.values()), types=types, notes=notes)


# ── DWARF ──────────────────────────────────────────────────────────

# The tags the readers act on.
_DW_TAG_ARRAY_TYPE = 0x01
_DW_TAG_CLASS_TYPE = 0x02
_DW_TAG_ENUMERATION_TYPE = 0x04
_DW_TAG_MEMBER = 0x0D
_DW_TAG_POINTER_TYPE = 0x0F
_DW_TAG_STRUCTURE_TYPE = 0x13
_DW_TAG_SUBROUTINE_TYPE = 0x15
_DW_TAG_TYPEDEF = 0x16
_DW_TAG_UNION_TYPE = 0x17
_DW_TAG_BASE_TYPE = 0x24
_DW_TAG_CONST_TYPE = 0x26
_DW_TAG_SUBPROGRAM = 0x2E
_DW_TAG_VOLATILE_TYPE = 0x35
_DW_TAG_RESTRICT_TYPE = 0x37
_DW_TAG_UNSPECIFIED_TYPE = 0x3B

_ARRAY_TAGS = (_DW_TAG_ARRAY_TYPE,)
_AGGREGATE_TAGS = (_DW_TAG_STRUCTURE_TYPE, _DW_TAG_CLASS_TYPE, _DW_TAG_UNION_TYPE)
_QUALIFIER_TAGS = {
    _DW_TAG_CONST_TYPE: "const",
    _DW_TAG_VOLATILE_TYPE: "volatile",
    _DW_TAG_RESTRICT_TYPE: "restrict",
}

# The attributes the readers act on.
_DW_AT_NAME = 0x03
_DW_AT_BYTE_SIZE = 0x0B
_DW_AT_LOW_PC = 0x11
_DW_AT_HIGH_PC = 0x12
_DW_AT_COUNT = 0x37
_DW_AT_DATA_MEMBER_LOCATION = 0x38
_DW_AT_TYPE = 0x49
_DW_AT_STR_OFFSETS_BASE = 0x72
_DW_AT_ADDR_BASE = 0x73

# One DIE: (tag, attributes, depth, absolute offset in .debug_info).
_DIE = tuple[int, dict[int, Any], int, int]


class _Dwarf:
    """The sections one ELF's DWARF readers need, already bounds-checked."""

    def __init__(self, elf: _Elf) -> None:
        self.info = _section_bytes(elf, ".debug_info")
        self.abbrev = _section_bytes(elf, ".debug_abbrev")
        self.strings = _section_bytes(elf, ".debug_str")
        self.str_offsets = _section_bytes(elf, ".debug_str_offsets")
        self.addr = _section_bytes(elf, ".debug_addr")

    @property
    def usable(self) -> bool:
        """True when the two sections a unit header needs are both present."""
        return self.info is not None and self.abbrev is not None


def _section_bytes(elf: _Elf, name: str) -> bytes | None:
    """One section's bytes, or None when the ELF does not carry it."""
    section = elf.section_by_name(name)
    return None if section is None else elf.section_data(section)


def parse_dwarf(elf: _Elf) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """The subprogram names, aggregate types and notes of an ELF's ``.debug_info``."""
    dwarf = _Dwarf(elf)
    if not dwarf.usable:
        return [], [], []
    symbols: list[dict[str, Any]] = []
    types: list[dict[str, Any]] = []
    notes: list[str] = []
    for unit in _units(dwarf.info or b""):
        unit = {**unit, "dwarf": dwarf}
        try:
            bases = _unit_bases(unit)
            unit = {**unit, "bases": bases}
            dies = _dies(unit)
        except UnreadableSymbolError as exc:
            notes.append(f"a compilation unit was skipped: {exc.detail}")
            continue
        symbols.extend(_unit_symbols(dies))
        types.extend(_unit_types(dies, notes))
    if not symbols and not types:
        notes.append("the DWARF carries no subprogram name or aggregate type this reader maps")
    return symbols, types, notes


def _units(data: bytes) -> list[dict[str, Any]]:
    """Every compilation unit header of a ``.debug_info`` section."""
    units: list[dict[str, Any]] = []
    offset = 0
    while offset + 11 <= len(data) and len(units) < 4096:
        length = int.from_bytes(data[offset : offset + 4], "little")
        if length == 0:
            break
        dwarf64 = length == 0xFFFFFFFF
        if dwarf64:
            length = int.from_bytes(data[offset + 4 : offset + 12], "little")
            header = offset + 12
        else:
            header = offset + 4
        end = header + length
        if length <= 0 or end > len(data):
            break
        version = int.from_bytes(data[header : header + 2], "little")
        cursor = header + 2
        if version >= 5:
            unit_type = data[cursor] if cursor < end else 0
            address_size = data[cursor + 1] if cursor + 1 < end else 8
            cursor += 2
            width = 8 if dwarf64 else 4
            abbrev_offset = int.from_bytes(data[cursor : cursor + width], "little")
            cursor += width
        else:
            unit_type = 0
            width = 8 if dwarf64 else 4
            abbrev_offset = int.from_bytes(data[cursor : cursor + width], "little")
            address_size = data[cursor + width] if cursor + width < end else 8
            cursor += width + 1
        units.append(
            {
                "start": cursor,
                "end": end,
                "version": version,
                "unit_type": unit_type,
                "offset_size": 8 if dwarf64 else 4,
                "abbrev_offset": abbrev_offset,
                "address_size": address_size or 8,
                "bases": {_DW_AT_STR_OFFSETS_BASE: 0, _DW_AT_ADDR_BASE: 0},
            }
        )
        offset = end
    return units


def _abbrev_table(data: bytes, offset: int) -> dict[int, tuple[int, bool, list[tuple[int, int]]]]:
    """One unit's abbreviation table: code to (tag, has_children, (name, form) pairs)."""
    if offset < 0 or offset >= len(data):
        raise UnreadableSymbolError("the abbreviation offset is outside .debug_abbrev")
    cursor = offset
    table: dict[int, tuple[int, bool, list[tuple[int, int]]]] = {}
    while cursor < len(data):
        code, cursor = _uleb(data, cursor)
        if code == 0:
            break
        tag, cursor = _uleb(data, cursor)
        children = bool(data[cursor]) if cursor < len(data) else False
        cursor += 1
        attributes: list[tuple[int, int]] = []
        while cursor < len(data):
            name, cursor = _uleb(data, cursor)
            form, cursor = _uleb(data, cursor)
            if name == 0 and form == 0:
                break
            attributes.append((name, form))
        table[code] = (tag, children, attributes)
    return table


def _uleb(data: bytes, offset: int) -> tuple[int, int]:
    """One unsigned LEB128 value and the offset after it."""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
        if shift > 63:
            break
    raise UnreadableSymbolError("an LEB128 value ran past the section")


def _sleb(data: bytes, offset: int) -> tuple[int, int]:
    """One signed LEB128 value and the offset after it."""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                result -= 1 << shift
            return result, offset
    raise UnreadableSymbolError("a signed LEB128 value ran past the section")


# The DWARF 5 form numbers this reader knows.  A form outside the table ends the
# unit rather than desyncing the stream: one unknown form makes every later DIE
# a guess, and a guessed name is worse than no name.
def _form_value(
    data: bytes, offset: int, form: int, unit: Mapping[str, Any]
) -> tuple[Any, int] | None:
    """Read one attribute value; None when the form cannot be sized.

    The form numbers are DWARF 5's (Figure 7.2): the constants are stable from
    DWARF 2 to 5 for everything below ``DW_FORM_ref_addr``, and 0x10 upward
    changed meaning when DWARF 4 split reference and offset forms, so this table
    is the only correct one for a DWARF 4 or 5 unit.
    """
    size = int(unit["address_size"])
    offset_size = int(unit["offset_size"])
    if form in _FIXED_FORMS and offset + _fixed_width(form, size, offset_size) > len(data):
        raise UnreadableSymbolError("an attribute ran past the section")
    if form == 0x01:  # addr
        return int.from_bytes(data[offset : offset + size], "little"), offset + size
    if form == 0x03:  # block2
        length = int.from_bytes(data[offset : offset + 2], "little")
        return data[offset + 2 : offset + 2 + length], offset + 2 + length
    if form == 0x04:  # block4
        length = int.from_bytes(data[offset : offset + 4], "little")
        return data[offset + 4 : offset + 4 + length], offset + 4 + length
    if form == 0x05:  # data2
        return int.from_bytes(data[offset : offset + 2], "little"), offset + 2
    if form == 0x06:  # data4
        return int.from_bytes(data[offset : offset + 4], "little"), offset + 4
    if form == 0x07:  # data8
        return int.from_bytes(data[offset : offset + 8], "little"), offset + 8
    if form == 0x08:  # string: the bytes follow inline
        text, cursor = _inline_string(data, offset)
        return text, cursor
    if form == 0x09:  # block
        length, cursor = _uleb(data, offset)
        return data[cursor : cursor + length], cursor + length
    if form == 0x0A:  # block1
        length = data[offset] if offset < len(data) else 0
        return data[offset + 1 : offset + 1 + length], offset + 1 + length
    if form == 0x0B:  # data1
        return data[offset], offset + 1
    if form == 0x0C:  # flag
        return bool(data[offset]), offset + 1
    if form == 0x0D:  # sdata
        return _sleb(data, offset)
    if form == 0x0E:  # strp: an offset into .debug_str
        value, cursor = _uleb(data, offset)
        return _string_at(unit["dwarf"].strings or b"", value), cursor
    if form == 0x0F:  # udata
        return _uleb(data, offset)
    if form == 0x10:  # ref_addr
        return int.from_bytes(data[offset : offset + size], "little"), offset + size
    if form == 0x11:  # ref1
        return data[offset], offset + 1
    if form == 0x12:  # ref2
        return int.from_bytes(data[offset : offset + 2], "little"), offset + 2
    if form == 0x13:  # ref4
        return int.from_bytes(data[offset : offset + 4], "little"), offset + 4
    if form == 0x14:  # ref8
        return int.from_bytes(data[offset : offset + 8], "little"), offset + 8
    if form == 0x15:  # ref_udata
        return _uleb(data, offset)
    if form == 0x17:  # sec_offset
        return int.from_bytes(data[offset : offset + offset_size], "little"), offset + offset_size
    if form == 0x18:  # exprloc
        length, cursor = _uleb(data, offset)
        return data[cursor : cursor + length], cursor + length
    if form == 0x19:  # flag_present: no bytes at all
        return True, offset
    if form in _STRX_WIDTHS:  # strx, strx1..strx4
        index, cursor = _indexed(data, offset, form, _STRX_WIDTHS)
        return _strx_string(unit, index), cursor
    if form in _ADDRX_WIDTHS:  # addrx, addrx1..addrx4
        index, cursor = _indexed(data, offset, form, _ADDRX_WIDTHS)
        return _addr_value(unit, index), cursor
    if form == 0x1C:  # ref_sup4
        return int.from_bytes(data[offset : offset + 4], "little"), offset + 4
    if form == 0x1D:  # strp_sup
        return int.from_bytes(data[offset : offset + offset_size], "little"), offset + offset_size
    if form == 0x1E:  # data16
        return int.from_bytes(data[offset : offset + 16], "little"), offset + 16
    if form == 0x1F:  # line_strp
        return int.from_bytes(data[offset : offset + offset_size], "little"), offset + offset_size
    if form == 0x20:  # ref_sig8
        return int.from_bytes(data[offset : offset + 8], "little"), offset + 8
    if form == 0x21:  # implicit_const: its value lives in the abbreviation
        return _sleb(data, offset)
    if form in (0x22, 0x23):  # loclistx, rnglistx
        return _uleb(data, offset)
    if form == 0x24:  # ref_sup8
        return int.from_bytes(data[offset : offset + 8], "little"), offset + 8
    return None


# The forms whose width does not depend on the value that follows, so a read
# past the section is a truncation rather than a short encoding.
_FIXED_FORMS = frozenset(
    {0x01, 0x05, 0x06, 0x07, 0x0B, 0x0C, 0x11, 0x12, 0x13, 0x14, 0x19, 0x1C, 0x1E, 0x20, 0x24}
)


def _fixed_width(form: int, size: int, offset_size: int) -> int:
    """The byte width of a fixed-width form, for the bounds check."""
    if form == 0x01:
        return size
    if form in (0x05, 0x12):
        return 2
    if form == 0x06:
        return 4
    if form in (0x07, 0x14, 0x20, 0x24):
        return 8
    if form == 0x19:  # flag_present carries no bytes at all
        return 0
    if form in (0x0B, 0x0C, 0x11):
        return 1
    if form in (0x13, 0x1C):
        return 4
    if form == 0x1E:
        return 16
    return offset_size


def _inline_string(data: bytes, offset: int) -> tuple[str, int]:
    """A ``DW_FORM_string`` value and the offset after its terminator."""
    end = data.find(b"\x00", offset)
    if end < 0:
        raise UnreadableSymbolError("an inline string is not terminated")
    return data[offset:end].decode("utf-8", "replace"), end + 1


# The width of each indexed form: 0 means a ULEB128 index (the un-suffixed form).
_STRX_WIDTHS = {0x1A: 0, 0x25: 1, 0x26: 2, 0x27: 3, 0x28: 4}
_ADDRX_WIDTHS = {0x1B: 0, 0x29: 1, 0x2A: 2, 0x2B: 3, 0x2C: 4}


def _indexed(data: bytes, offset: int, form: int, widths: Mapping[int, int]) -> tuple[int, int]:
    """The index of a strx/addrx form, with its width taken from the form code."""
    width = widths.get(form, 0)
    if width == 0:
        return _uleb(data, offset)
    return int.from_bytes(data[offset : offset + width], "little"), offset + width


def _strx_string(unit: Mapping[str, Any], index: int) -> str:
    """The string one ``DW_FORM_strx`` index names, through .debug_str_offsets.

    A section the file does not carry, or an index outside it, answers an empty
    string rather than a guess; the unit's own note says which happened.
    """
    table = unit["dwarf"].str_offsets
    base = int(unit["bases"].get(_DW_AT_STR_OFFSETS_BASE) or 0)
    if table is None:
        return ""
    width = int(unit["offset_size"])
    start = base + index * width
    if start < 0 or start + width > len(table):
        return ""
    value = int.from_bytes(table[start : start + width], "little")
    return _string_at(unit["dwarf"].strings or b"", value)


def _addr_value(unit: Mapping[str, Any], index: int) -> int | None:
    """The address one ``DW_FORM_addrx`` index names, through .debug_addr."""
    table = unit["dwarf"].addr
    base = int(unit["bases"].get(_DW_AT_ADDR_BASE) or 0)
    size = int(unit["address_size"])
    if table is None:
        return None
    start = base + index * size
    if start < 0 or start + size > len(table):
        return None
    return int.from_bytes(table[start : start + size], "little")


def _unit_bases(unit: Mapping[str, Any]) -> dict[int, int]:
    """The root DIE's ``DW_AT_str_offsets_base`` and ``DW_AT_addr_base``.

    DWARF 5 moves the string and address tables behind per-unit bases that the
    root DIE declares, so the bases have to be read before any indexed form in
    the unit can be resolved.
    """
    bases = {_DW_AT_STR_OFFSETS_BASE: 0, _DW_AT_ADDR_BASE: 0}
    for _tag, attributes, depth, _offset in _dies(unit, limit=1):
        if depth != 0:
            break
        for key in bases:
            value = attributes.get(key)
            if isinstance(value, int):
                bases[key] = value
        break
    return bases


def _dies(unit: Mapping[str, Any], *, limit: int = MAX_SYMBOLS) -> list[_DIE]:
    """The DIE stream of one unit: tag, attributes, depth and absolute offset."""
    info = unit["dwarf"].info or b""
    table = _abbrev_table(unit["dwarf"].abbrev or b"", int(unit["abbrev_offset"]))
    cursor = int(unit["start"])
    end = min(int(unit["end"]), len(info))
    entries: list[_DIE] = []
    depth = 0
    while cursor < end and len(entries) < limit:
        offset = cursor
        code, cursor = _uleb(info, cursor)
        if code == 0:
            depth = max(0, depth - 1)
            continue
        spec = table.get(code)
        if spec is None:
            raise UnreadableSymbolError(f"unknown abbreviation code {code}")
        tag, has_children, attributes = spec
        values: dict[int, Any] = {}
        for name, form in attributes:
            read = _form_value(info, cursor, form, unit)
            if read is None:
                raise UnreadableSymbolError(f"form 0x{form:x} is not read")
            value, cursor = read
            values.setdefault(name, value)
        entries.append((tag, values, depth, offset))
        if has_children:
            depth += 1
    return entries


def _unit_symbols(dies: Iterable[_DIE]) -> list[dict[str, Any]]:
    """The subprogram names of one unit, with the address they declare."""
    found: list[dict[str, Any]] = []
    for tag, attributes, _depth, _offset in dies:
        if tag != _DW_TAG_SUBPROGRAM:
            continue
        name = attributes.get(_DW_AT_NAME)
        if not isinstance(name, str) or not name:
            continue
        low = attributes.get(_DW_AT_LOW_PC)
        high = attributes.get(_DW_AT_HIGH_PC)
        va = low if isinstance(low, int) and low else None
        size = high - low if isinstance(low, int) and isinstance(high, int) and high > low else 0
        found.append(_symbol(name, va=va, kind=KIND_FUNCTION, source=SOURCE_DWARF, size=size))
    return found


def _unit_types(dies: list[_DIE], notes: list[str]) -> list[dict[str, Any]]:
    """The aggregate types of one unit, with their members and offsets."""
    by_offset: dict[int, _DIE] = {entry[3]: entry for entry in dies}
    types: list[dict[str, Any]] = []
    for tag, attributes, _depth, _offset in dies:
        if tag not in _AGGREGATE_TAGS:
            continue
        name = attributes.get(_DW_AT_NAME)
        if not isinstance(name, str) or not name:
            continue
        size = attributes.get(_DW_AT_BYTE_SIZE)
        types.append(
            {
                "name": _bounded_name(name),
                "kind": "union" if tag == _DW_TAG_UNION_TYPE else "struct",
                "size": int(size) if isinstance(size, int) and size >= 0 else 0,
                "namespace": "",
                "members": _members_of(dies, _depth, by_offset, notes),
            }
        )
        if len(types) >= MAX_TYPES:
            notes.append(f"the type list was truncated at {MAX_TYPES} entries")
            break
    return types


def _members_of(
    dies: list[_DIE], depth: int, by_offset: Mapping[int, _DIE], notes: list[str]
) -> list[dict[str, Any]]:
    """The member DIEs that follow one aggregate, at the next depth."""
    members: list[dict[str, Any]] = []
    started = False
    for tag, attributes, entry_depth, _entry_offset in dies:
        if not started:
            if entry_depth <= depth:
                continue
            started = True
        if entry_depth <= depth:
            break
        if entry_depth != depth + 1 or tag != _DW_TAG_MEMBER:
            continue
        name = attributes.get(_DW_AT_NAME)
        location = _member_offset(attributes.get(_DW_AT_DATA_MEMBER_LOCATION))
        if location is None:
            notes.append("a member offset carried a location expression and was skipped")
            continue
        type_name = _type_name(attributes.get(_DW_AT_TYPE), by_offset, frozenset(), 0)
        if not isinstance(name, str) or not name:
            notes.append("an unnamed member was skipped")
            continue
        members.append(
            {"name": _bounded_name(name), "type": type_name or "void", "offset": location}
        )
        if len(members) >= MAX_MEMBERS:
            notes.append(f"a type's member list was truncated at {MAX_MEMBERS} entries")
            break
    return members


def _member_offset(location: Any) -> int | None:
    """A member's byte offset from its DW_AT_data_member_location.

    DWARF 4 and later store the offset as a constant for a plain member; DWARF 2
    and 3 store a one-operation expression, which is ``DW_OP_plus_uconst`` for
    the shapes a compiler emits.  Anything else is unknown and reported rather
    than guessed as zero.
    """
    if isinstance(location, int) and not isinstance(location, bool):
        return location
    if isinstance(location, (bytes, bytearray)) and location and location[0] == 0x23:
        value, _cursor = _uleb(bytes(location), 1)
        return value
    return None


def _type_name(
    reference: Any, by_offset: Mapping[int, _DIE], seen: frozenset[int], depth: int
) -> str:
    """Render a referenced DIE as C text, to a bounded depth."""
    if not isinstance(reference, int) or isinstance(reference, bool):
        return ""
    if depth >= MAX_TYPE_DEPTH or reference in seen:
        return ""
    entry = by_offset.get(reference)
    if entry is None:
        return ""
    tag, attributes, _depth, _offset = entry
    name = attributes.get(_DW_AT_NAME)
    hint = name if isinstance(name, str) else ""
    smaller = frozenset({*seen, reference})
    if tag == _DW_TAG_BASE_TYPE:
        return hint
    if tag in _QUALIFIER_TAGS:
        inner = _type_name(attributes.get(_DW_AT_TYPE), by_offset, smaller, depth + 1)
        return f"{_QUALIFIER_TAGS[tag]} {inner}".strip()
    if tag == _DW_TAG_POINTER_TYPE:
        inner = _type_name(attributes.get(_DW_AT_TYPE), by_offset, smaller, depth + 1)
        return f"{inner or 'void'} *"
    if tag in _AGGREGATE_TAGS:
        prefix = "union" if tag == _DW_TAG_UNION_TYPE else "struct"
        return f"{prefix} {hint}".strip()
    if tag == _DW_TAG_ENUMERATION_TYPE:
        return f"enum {hint}".strip()
    if tag == _DW_TAG_TYPEDEF:
        return hint
    if tag in _ARRAY_TAGS:
        inner = _type_name(attributes.get(_DW_AT_TYPE), by_offset, smaller, depth + 1)
        count = attributes.get(_DW_AT_COUNT)
        dimension = f"[{int(count)}]" if isinstance(count, int) else "[]"
        return f"{inner or 'char'}{dimension}"
    if tag == _DW_TAG_SUBROUTINE_TYPE:
        return "void *"
    if tag == _DW_TAG_UNSPECIFIED_TYPE:
        return "void"
    return ""


# ── Dispatch ───────────────────────────────────────────────────────


def parse(data: bytes, *, filename: str = "") -> dict[str, Any]:
    """Parse a symbol file, dispatching on its magic."""
    if data[:4] == ELF_MAGIC:
        return parse_elf(data)
    if data[: len(PDB_MAGIC)] == PDB_MAGIC:
        return _parse_pdb(data)
    raise UnreadableSymbolError(f"{filename or 'the file'} is not an ELF or a PDB container")


def _parse_pdb(data: bytes) -> dict[str, Any]:
    """One PDB container's public symbols in the shared shape.

    The reader is :mod:`reportal.pdb`; reportal adds the label its own readers
    keep (a symbol's source) and its note that the TPI stream is not parsed, so
    a PDB parse reads like an ELF one in every surface.
    """
    try:
        parsed = pdb.read_symbols(data)
    except pdb.PdbError as exc:
        raise UnreadableSymbolError(exc.detail) from exc
    notes = [
        *parsed.get("notes", []),
        "PDB types are not reconstructed: the TPI stream is not parsed",
    ]
    entries = [
        _symbol(
            str(entry.get("name") or ""),
            va=entry.get("va") if isinstance(entry.get("va"), int) else None,
            kind=str(entry.get("kind") or KIND_OTHER),
            source=SOURCE_PDB,
            size=int(entry.get("size") or 0),
        )
        for entry in parsed.get("symbols") or []
    ]
    return _result(
        kind=SOURCE_PDB, symbols=[entry for entry in entries if entry["name"]], notes=notes
    )


def parse_file(path: str | Path) -> tuple[bytes, dict[str, Any]]:
    """Read and parse one symbol file; returns its bytes and the parse result."""
    target = Path(path)
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise UnreadableSymbolError(f"cannot read {target}: {exc}") from exc
    return data, parse(data, filename=target.name)


def digest(data: bytes) -> str:
    """The content address a stored symbol file is keyed by."""
    return hashlib.sha256(data).hexdigest()


def stored_path(sha256: str) -> Path:
    """Where a symbol file's bytes live, content-addressed like an upload."""
    from reportal import _paths

    return _paths.project_root() / SYMBOLS_DIR / sha256[:2] / sha256


# ── The read ───────────────────────────────────────────────────────


def _row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """One stored symbol file as the surfaces report it."""
    return {
        "id": int(row["id"]),
        "binary_id": int(row["binary_id"]),
        "sha256": str(row["sha256"]),
        "kind": str(row["kind"]),
        "size": int(row["size"]),
        "path": str(row["path"]),
        "parsed": json.loads(str(row["parsed_json"]) or "{}"),
        "symbols": int(row["symbols"]),
        "types": int(row["types"]),
        "applied": int(row["applied"]),
        "created_at": str(row["created_at"]),
    }


def list_files(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """Every symbol file ingested for one binary, newest first."""
    ensure_schema(conn)
    rows = conn.execute(
        f"SELECT * FROM {TABLE} WHERE binary_id = ? ORDER BY id DESC", (int(binary_id),)
    ).fetchall()
    return [_row(row) for row in rows]


def get_file(
    conn: sqlite3.Connection, *, binary_id: int, file_id: int | None = None
) -> dict[str, Any]:
    """One ingested symbol file (the newest when *file_id* is None)."""
    ensure_schema(conn)
    if file_id is None:
        rows = list_files(conn, binary_id)
        if not rows:
            raise UnknownSymbolFileError(f"binary {binary_id} has no ingested symbol file")
        return rows[0]
    row = conn.execute(
        f"SELECT * FROM {TABLE} WHERE id = ? AND binary_id = ?", (int(file_id), int(binary_id))
    ).fetchone()
    if row is None:
        raise UnknownSymbolFileError(f"no symbol file {file_id} for binary {binary_id}")
    return _row(row)


# ── The import ─────────────────────────────────────────────────────


def _types_payload(parsed: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The aggregate types of a parse, in the shape ``store.add_data_type`` takes."""
    return [dict(entry) for entry in parsed.get("types") or [] if isinstance(entry, Mapping)]


def import_symbols(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    binary_id: int,
    data: bytes,
    parsed: Mapping[str, Any],
    path: str = "",
    apply: bool = True,
) -> dict[str, Any]:
    """Store one symbol file's parse and apply it to the binary's functions.

    A function whose VA matches a symbol is renamed to it with the ``symbol``
    name source, and every recovered aggregate type is stored in the type model.
    Both writes go through the caller's journaled action, so a revert puts the
    previous names and types back.  Returns the stored row plus the report.
    """
    ensure_schema(conn)
    if store.get_binary(conn, binary_id) is None:
        raise UnknownSymbolFileError(f"no binary with id {binary_id}")
    sha256 = digest(data)
    symbols = list(parsed.get("symbols") or [])
    types = _types_payload(parsed)
    applied, skipped = 0, 0
    if apply:
        applied, skipped = _apply_symbols(conn, log, binary_id=binary_id, symbols=symbols)
        _apply_types(conn, log, binary_id=binary_id, types=types)
    cursor = conn.execute(
        f"INSERT INTO {TABLE} (binary_id, sha256, kind, size, path, parsed_json, symbols,"
        " types, applied, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            int(binary_id),
            sha256,
            str(parsed.get("kind") or ""),
            len(data),
            path,
            json.dumps(dict(parsed), sort_keys=True),
            len(symbols),
            len(types),
            applied,
            store.now(),
        ),
    )
    conn.commit()
    file_id = int(cursor.lastrowid or 0)
    journal.journaled_create(
        log,
        table=TABLE,
        key=file_id,
        description=f"ingested a {parsed.get('kind')} symbol file for binary {binary_id}",
    )
    return {
        **get_file(conn, binary_id=binary_id, file_id=file_id),
        "applied": applied,
        "skipped": skipped,
        "truncated": not apply,
    }


def _functions_by_va(conn: sqlite3.Connection, binary_id: int) -> dict[int, dict[str, Any]]:
    """The binary's functions by VA, first wins."""
    found: dict[int, dict[str, Any]] = {}
    for function in store.list_functions(conn, binary_id=binary_id):
        found.setdefault(int(function["va"]), function)
    return found


def _apply_symbols(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    binary_id: int,
    symbols: Sequence[Mapping[str, Any]],
) -> tuple[int, int]:
    """Rename the functions a symbol names; returns (applied, skipped)."""
    known = _functions_by_va(conn, binary_id)
    touched: set[int] = set()
    skipped = 0
    for entry in symbols:
        va = entry.get("va")
        name = str(entry.get("name") or "")
        if not name or not isinstance(va, int) or isinstance(va, bool):
            skipped += 1
            continue
        function = known.get(va)
        if function is None:
            skipped += 1
            continue
        function_id = int(function["id"])
        if str(function["name"] or "") == name:
            touched.add(function_id)
            continue
        journal.journaled_rename(
            conn,
            log,
            function_id,
            new_name=name,
            actor=journal.current_actor(),
            source=SYMBOL_NAME_SOURCE,
        )
        touched.add(function_id)
    return len(touched), skipped


def _apply_types(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    binary_id: int,
    types: Sequence[Mapping[str, Any]],
) -> int:
    """Create or update the aggregate types a symbol file declared."""
    written = 0
    for entry in types:
        name = str(entry.get("name") or "")
        if not name:
            continue
        members = [dict(member) for member in entry.get("members") or []]
        existing = store.find_data_type_by_name(conn, binary_id, name)
        if existing is not None:
            journal.journaled_rows(
                conn,
                log,
                table="data_types",
                where="id = ?",
                params=(int(existing["id"]),),
                description=f"replaced type {name}",
            )
            store.update_data_type(
                conn,
                int(existing["id"]),
                members=[_with_offsets(member) for member in members],
                size=int(entry.get("size") or 0),
                source=data_types.SOURCE_SYMBOL,
            )
            written += 1
            continue
        data_type_id = store.add_data_type(
            conn,
            binary_id=binary_id,
            name=name,
            size=int(entry.get("size") or 0),
            members=[_with_offsets(member) for member in members],
            kind=str(entry.get("kind") or "struct"),
            source=data_types.SOURCE_SYMBOL,
        )
        journal.journaled_create(
            log,
            table="data_types",
            key=data_type_id,
            description=f"created type {name}",
        )
        written += 1
    return written


def _with_offsets(member: Mapping[str, Any]) -> dict[str, Any]:
    """One member in the shape the type model stores (offset, name, type)."""
    return {
        "name": str(member.get("name") or ""),
        "type": str(member.get("type") or "void"),
        "offset": int(member.get("offset") or 0),
    }


# ── The export ─────────────────────────────────────────────────────


def render_symbols(parsed: Mapping[str, Any], *, kind: str = "json") -> str:
    """Render a parse as JSON or as one C header.

    The C form reuses the type model's renderer, so an exported header and the
    editable model cannot disagree, and it names each function symbol as a
    comment so a reader can map a type back to the function it came from.
    """
    if kind == "json":
        return json.dumps(dict(parsed), indent=2, sort_keys=True) + "\n"
    types = _types_payload(parsed)
    rows = [
        {
            "name": str(entry.get("name") or ""),
            "kind": str(entry.get("kind") or "struct"),
            "size": int(entry.get("size") or 0),
            "namespace": "",
            "members": [_with_offsets(member) for member in entry.get("members") or []],
            "values": [],
        }
        for entry in types
        if entry.get("name")
    ]
    header = data_types.render_header(rows)
    functions = [
        str(entry.get("name"))
        for entry in parsed.get("symbols") or []
        if entry.get("kind") == KIND_FUNCTION and entry.get("name")
    ]
    if not functions:
        return header
    lines = [header.rstrip("\n"), "", "/* function symbols */"]
    # A symbol name is parsed-file text going into a comment: a `*` or `/`
    # inside one could combine with the delimiters into a terminator, so both
    # are folded to characters that render the name without closing anything.
    safe = str.maketrans({"*": "x", "/": "|"})
    lines.extend(f"/* {name.translate(safe)} */" for name in functions)
    return "\n".join(lines) + "\n"

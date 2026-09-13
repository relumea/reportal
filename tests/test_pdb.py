"""Tests for the PDB 7.0 public and module symbol reader."""

from __future__ import annotations

import struct
from typing import Any

import pytest

from reportal import pdb

# The synthetic container is assembled by hand: a superblock, a one-block block
# map, a one-block stream directory and one block per stream.
BLOCK_SIZE = 512
STREAM_COUNT = 5
SYMBOL_STREAM = 4

# The record kinds a symbol entry can come from.
S_THUNK32 = 0x1102
S_PUB32 = 0x110E
S_GPROC32 = 0x1110

# Section 1 puts .text at 0x1000 with its raw bytes at file offset 0x400, so a
# symbol at offset 0x410 answers 0x1010.  Section 2 puts .data at 0x3000 with
# its raw bytes at 0x1400.  Segment 5 is deliberately absent from the map.
TEXT_VA = 0x1000
TEXT_RAW = 0x400
DATA_VA = 0x3000
DATA_RAW = 0x1400
MISSING_SEGMENT = 5

# The layouts the fixture and the reader have to agree on.
assert struct.calcsize("<IIH") == 10
assert struct.calcsize("<IIIIHHB") == 21
assert struct.calcsize("<IIIIIIIIHB") == 35
assert struct.calcsize("<i I I H H H H H H i i i i i I i i H H I") == 64


def _pad(chunk: bytes | bytearray, block_size: int = BLOCK_SIZE) -> bytes:
    """*chunk* padded with zeros to a whole number of blocks."""
    return bytes(chunk) + b"\x00" * ((-len(chunk)) % block_size)


def _section(name: bytes, virtual_address: int, raw_pointer: int, *, padded: bool) -> bytes:
    """One section entry: name[8] and nine tail fields, with or without the pad."""
    tail = struct.pack(
        "<IIIIIIHHI", 0x1000, virtual_address, 0x1000, raw_pointer, 0, 0, 0, 0, 0x60000020
    )
    entry = name.ljust(8, b"\x00") + tail
    return b"\x00\x00" + entry if padded else entry


def _section_map(entries: list[bytes], *, declared_count: int | None = None) -> bytes:
    """The substream: its uint16 byte length, its uint16 entry count, the entries."""
    body = b"".join(entries)
    count = len(entries) if declared_count is None else declared_count
    return struct.pack("<HH", len(body) + 4, count) + body


def _record(kind: int, body: bytes) -> bytes:
    """One symbol record: uint16 length (kind plus body), uint16 kind, the body."""
    return struct.pack("<HH", len(body) + 2, kind) + body


def _public(name: bytes, *, flags: int, offset: int, segment: int) -> bytes:
    """An S_PUB32: flags, offset, segment, then the null-terminated name."""
    return _record(S_PUB32, struct.pack("<IIH", flags, offset, segment) + name + b"\x00")


def _procedure(name: bytes, *, offset: int, segment: int, size: int) -> bytes:
    """An S_GPROC32: parent, end, next, code size, debug start, debug end, type
    index and code offset (uint32 each), then segment (uint16), flags and name."""
    head = struct.pack("<IIIIIIIIHB", 0, 0, 0, size, 0, 0, 0, offset, segment, 0)
    return _record(S_GPROC32, head + name + b"\x00")


def _thunk(name: bytes, *, offset: int, segment: int, size: int) -> bytes:
    """An S_THUNK32: four uint32, segment, thunk length, ordinal, name."""
    head = struct.pack("<IIIIHHB", 0, 0, 0, offset, segment, size, 0)
    return _record(S_THUNK32, head + name + b"\x00")


def _dbi(section_map: bytes, symbol_stream: int = SYMBOL_STREAM) -> bytes:
    """A DBI stream: the 64-byte header, then the section map substream.

    The header fields are in the order ``pdb._DBI_HEADER`` documents.
    """
    header = struct.pack(
        "<i I I H H H H H H i i i i i I i i H H I",
        -1,
        19990903,
        1,
        0xFFFF,
        0x1000,
        0xFFFF,
        0,
        symbol_stream,
        0,
        0,
        0,
        len(section_map),
        0,
        0,
        0xFFFFFFFF,
        0,
        0,
        0,
        0x014C,
        0,
    )
    return header + section_map


def _container(streams: list[bytes]) -> bytes:
    """An MSF container: block 0 the superblock, block 1 the block map, then the
    stream directory and each stream's blocks in order."""
    held = [(len(stream) + BLOCK_SIZE - 1) // BLOCK_SIZE for stream in streams]
    directory_bytes = 4 + 4 * len(streams) + sum(4 * count for count in held)
    directory_blocks = (directory_bytes + BLOCK_SIZE - 1) // BLOCK_SIZE
    first_block = 2 + directory_blocks
    directory = bytearray(struct.pack("<I", len(streams)))
    directory += b"".join(struct.pack("<I", len(stream)) for stream in streams)
    block = first_block
    for count in held:
        directory += b"".join(struct.pack("<I", index) for index in range(block, block + count))
        block += count
    assert len(directory) == directory_bytes
    superblock = pdb.CONTAINER_MAGIC + struct.pack(
        "<IIIIII", BLOCK_SIZE, 0, block, directory_bytes, 0, 1
    )
    block_map = b"".join(struct.pack("<I", index) for index in range(2, first_block))
    container = (
        _pad(superblock)
        + _pad(block_map)
        + _pad(directory)
        + b"".join(_pad(stream) for stream in streams)
    )
    assert len(container) == block * BLOCK_SIZE
    return container


def _records() -> bytes:
    """Five symbols and the zero length that ends the stream."""
    return (
        _public(b"?pub_fn@@YAXXZ", flags=2, offset=0x410, segment=1)
        + _public(b"?g_value@@3HA", flags=0, offset=0x1420, segment=2)
        + _public(b"?missing@@YAXXZ", flags=0, offset=0x10, segment=MISSING_SEGMENT)
        + _procedure(b"?helper@@YAXXZ", offset=0x600, segment=1, size=0x40)
        + _thunk(b"?vcall_thunk@@YAXXZ", offset=0x500, segment=1, size=0x10)
        + b"\x00\x00\x00\x00"
    )


def _synthetic(
    *,
    sections: bytes | None = None,
    records: bytes | None = None,
    symbol_stream: int = SYMBOL_STREAM,
) -> bytes:
    """A container whose streams are the old directory, the info stream, the TPI
    stream, the DBI stream and the symbol record stream."""
    if sections is None:
        sections = _section_map(
            [
                _section(b".text", TEXT_VA, TEXT_RAW, padded=True),
                _section(b".data", DATA_VA, DATA_RAW, padded=True),
            ]
        )
    info = struct.pack("<III", 20091201, 0x1234, 1)
    body = _records() if records is None else records
    return _container([b"", info, b"", _dbi(sections, symbol_stream), body])


def _symbol(result: dict[str, Any], name: str) -> dict[str, Any]:
    for entry in result["symbols"]:
        if entry["name"] == name:
            found: dict[str, Any] = entry
            return found
    raise AssertionError(f"{name} is not among {result['symbols']}")


class TestReadSymbols:
    def test_it_reads_every_reported_symbol(self) -> None:
        result = pdb.read_symbols(_synthetic())
        assert result["kind"] == "pdb"
        assert result["types"] == []
        assert result["counts"] == {"symbols": 5, "types": 0}

    def test_a_public_function_answers_its_address(self) -> None:
        symbol = _symbol(pdb.read_symbols(_synthetic()), "?pub_fn@@YAXXZ")
        assert symbol["va"] == TEXT_VA + (0x410 - TEXT_RAW)
        assert symbol["kind"] == "function"
        assert symbol["size"] == 0

    def test_a_public_object_is_an_object(self) -> None:
        symbol = _symbol(pdb.read_symbols(_synthetic()), "?g_value@@3HA")
        assert symbol["kind"] == "object"
        assert symbol["va"] == DATA_VA + (0x1420 - DATA_RAW)

    def test_a_procedure_answers_its_address_and_size(self) -> None:
        symbol = _symbol(pdb.read_symbols(_synthetic()), "?helper@@YAXXZ")
        assert symbol["va"] == TEXT_VA + (0x600 - TEXT_RAW)
        assert symbol["kind"] == "function"
        assert symbol["size"] == 0x40

    def test_a_thunk_answers_its_address_and_size(self) -> None:
        symbol = _symbol(pdb.read_symbols(_synthetic()), "?vcall_thunk@@YAXXZ")
        assert symbol["va"] == TEXT_VA + (0x500 - TEXT_RAW)
        assert symbol["size"] == 0x10

    def test_a_segment_missing_from_the_map_answers_no_address(self) -> None:
        symbol = _symbol(pdb.read_symbols(_synthetic()), "?missing@@YAXXZ")
        assert symbol["va"] is None
        assert symbol["kind"] == "function"

    def test_the_notes_name_the_missing_types_and_the_unresolved_segment(self) -> None:
        notes = pdb.read_symbols(_synthetic())["notes"]
        assert any("TPI" in note for note in notes)
        assert any("va: None" in note for note in notes)

    def test_a_zero_entry_section_map_is_read_without_the_pad(self) -> None:
        sections = _section_map(
            [_section(b".text", TEXT_VA, TEXT_RAW, padded=False)], declared_count=0
        )
        result = pdb.read_symbols(_synthetic(sections=sections))
        assert _symbol(result, "?pub_fn@@YAXXZ")["va"] == TEXT_VA + (0x410 - TEXT_RAW)
        assert any("2-byte pad" in note for note in result["notes"])

    def test_it_caps_the_symbol_list_and_says_so(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(pdb, "MAX_SYMBOLS", 2)
        result = pdb.read_symbols(_synthetic())
        assert len(result["symbols"]) == 2
        assert any("truncated" in note for note in result["notes"])

    def test_a_dbi_without_a_symbol_record_stream_reports_nothing(self) -> None:
        result = pdb.read_symbols(_synthetic(symbol_stream=0xFFFF))
        assert result["symbols"] == []
        assert any("no symbol record stream" in note for note in result["notes"])

    def test_the_real_section_map_layout_answers_no_address(self) -> None:
        # A real container puts a count, a logical count and 20-byte
        # SectionMapEntry records here, which this reader names in a note.
        sections = struct.pack("<HH", 2, 2) + bytes(2 * 20)
        result = pdb.read_symbols(_synthetic(sections=sections))
        assert all(entry["va"] is None for entry in result["symbols"])
        assert any("SectionMapEntry" in note for note in result["notes"])

    def test_it_refuses_a_truncated_container(self) -> None:
        with pytest.raises(pdb.PdbError) as exc:
            pdb.read_symbols(_synthetic()[:-BLOCK_SIZE])
        assert exc.value.code == "symbols-unreadable"

    def test_it_refuses_a_container_that_is_not_msf(self) -> None:
        data = bytearray(_synthetic())
        data[0] = ord("X")
        with pytest.raises(pdb.PdbError):
            pdb.read_symbols(bytes(data))

    def test_it_refuses_bytes_shorter_than_the_superblock(self) -> None:
        with pytest.raises(pdb.PdbError):
            pdb.read_symbols(pdb.CONTAINER_MAGIC)

    def test_it_refuses_a_record_that_runs_past_the_stream(self) -> None:
        with pytest.raises(pdb.PdbError):
            pdb.read_symbols(_synthetic(records=struct.pack("<HH", 0x100, S_PUB32)))

    def test_it_refuses_a_stream_block_outside_the_container(self) -> None:
        data = bytearray(_synthetic())
        # Block 2 holds the stream directory: its stream count and the five
        # stream sizes precede the first stream block index.
        struct.pack_into("<I", data, 2 * BLOCK_SIZE + 4 + 4 * STREAM_COUNT, 0xFFFF)
        with pytest.raises(pdb.PdbError):
            pdb.read_symbols(bytes(data))

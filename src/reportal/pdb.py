"""Public and module symbols from a Windows PDB 7.0 file.

A PDB is the debug companion of a PE image: it keeps the names, the addresses
and the types the linker stripped out of the binary.  This module reads the two
symbol lists reportal can use, the public symbols and the procedure records of
the symbol record stream, and answers one entry per symbol with the virtual
address the function or the object lives at in the image.

The container is MSF 7.0 (Multi-Stream Format), the ``Microsoft C/C++ MSF
7.00`` magic.  A superblock names a block map, the block map names the blocks
holding the stream directory, and the directory names each stream's blocks.
Stream 1 is the PDB info stream and stream 3 the DBI stream: the DBI header
carries the sizes of its substreams and the index of the symbol record stream,
its section map substream turns a CodeView segment number into the image's
address space, and the symbol record stream is a flat sequence of records, each
a ``uint16`` length, a ``uint16`` kind and ``length - 2`` body bytes.

What this reader does not do, stated in every result's ``notes``: the TPI and
IPI streams are not parsed, so ``types`` is always empty and ``counts["types"]``
is always zero; only the shared symbol record stream is walked, not the module
info substreams nor the public and global hash tables; a symbol whose segment is
not in the section map answers ``va: None`` rather than a guessed address,
including every symbol of a real MSVC or lld container, whose section map
substream holds the 20-byte ``SectionMapEntry`` records this reader recognizes
but does not map; and ``kind`` is only ever ``function`` or ``object``, because
the interface's ``other`` kind describes the record kinds this reader skips.

The reader takes bytes, never a path, makes no network call and runs nothing.
Anything the container gets wrong, a wrong magic, a directory or a record that
runs past the buffer, a block index outside the file, raises :class:`PdbError`
instead of returning a partial answer.
"""

from __future__ import annotations

import struct
from typing import Any

# The 32-byte MSF 7.0 magic, then six little-endian uint32 fields: the block
# size, the free block map block, the block count, the directory byte count, an
# unused word and the block that holds the block map.
CONTAINER_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

# Upper bound on the returned symbol list.  A PDB can carry millions of records
# and reportal only renders a table from them, so the list is capped and the
# truncation is named in the notes.
MAX_SYMBOLS = 200_000

# The one error code this module raises.
_UNREADABLE = "symbols-unreadable"

# The superblock, and the smallest block size the format uses.
_SUPERBLOCK = struct.Struct("<32sIIIIII")
_MIN_BLOCK_SIZE = 512
_U16_PAIR = struct.Struct("<HH")
_U32 = struct.Struct("<I")


def _ceil_div(numerator: int, denominator: int) -> int:
    """Smallest integer at least *numerator* / *denominator* (positive ints)."""
    return (numerator + denominator - 1) // denominator


# Streams this reader needs by index.  Stream 1 is the PDB info stream and
# stream 3 the DBI stream; the symbol record stream is wherever its DBI header
# says, and 0xFFFF means the DBI header names none.
_INFO_STREAM = 1
_DBI_STREAM = 3
_NO_STREAM = 0xFFFF

# PDB info stream header: version, signature and age, uint32 each.  The reader
# validates the stream's length and recognizes the versions LLVM names, so an
# unknown one is a note rather than a failure.
_INFO_HEADER_SIZE = 12
_INFO_VERSIONS = frozenset(
    {
        19941610,
        19950623,
        19950814,
        19960307,
        19970604,
        19990604,
        20000404,
        20030901,
        20091201,
        20140508,
    }
)

# DBI stream header, 64 bytes, little-endian, in file order:
#   int32 version_signature, uint32 version_header, uint32 age,
#   uint16 global_stream_index, uint16 build_number, uint16 public_stream_index,
#   uint16 pdb_dll_version, uint16 symbol_record_stream_index,
#   uint16 pdb_dll_rebuild, int32 module_info_size,
#   int32 section_contribution_size, int32 section_map_size,
#   int32 source_info_size, int32 type_server_map_size,
#   uint32 mfc_type_server_index, int32 optional_debug_header_size,
#   int32 ec_substream_size, uint16 flags, uint16 machine, uint32 padding.
# The seven substream sizes are followed physically by the module info, the
# section contribution, the section map, the source info, the type server map,
# the EC substream and the optional debug header, in that order.
_DBI_HEADER = struct.Struct("<i I I H H H H H H i i i i i I i i H H I")

# The section map substream starts with a uint16 byte length and a uint16 count
# of entries, then the entries.  The reader locates it after the module info and
# the section contribution substreams, using their declared sizes.
_SECTION_HEADER_SIZE = 4

# A section entry is the 8-byte name and then nine fields: virtual_size,
# virtual_address, size_of_raw_data, pointer_to_raw_data, pointer_to_relocations,
# pointer_to_line_numbers, number_of_relocations (uint16), number_of_line_numbers
# (uint16) and characteristics, 32 bytes in all.  Writers disagree on whether two
# pad bytes precede the name, which makes an entry 42 or 40 bytes; the
# substream's declared length says which layout a file uses.
_SECTION_TAIL = struct.Struct("<IIIIIIHHI")
_SECTION_NAME_SIZE = 8
_SECTION_ENTRY_PADDED = 2 + _SECTION_NAME_SIZE + _SECTION_TAIL.size
_SECTION_ENTRY_COMPACT = _SECTION_NAME_SIZE + _SECTION_TAIL.size
# Positions of virtual_address and pointer_to_raw_data among the tail fields.
_TAIL_VIRTUAL_ADDRESS = 1
_TAIL_RAW_POINTER = 3

# A real MSVC or lld PDB puts 20-byte SectionMapEntry records here, addressed by
# a shared frame rather than by a section virtual address, so a substream of
# exactly this size is recognized and reported instead of being misread as a
# section header list.
_SECTION_MAP_ENTRY = 20

# Symbol record header: uint16 length (the kind field plus the body) and uint16
# kind.  A length of zero ends the stream.
_RECORD_HEADER = struct.Struct("<HH")
_RECORD_KIND_SIZE = 2

# Symbol record kinds this reader reports.
_PUBLIC = 0x110E
_LOCAL_PROC = 0x110F
_GLOBAL_PROC = 0x1110
_THUNK = 0x1102

# S_PUB32 body: flags (uint32), offset (uint32), segment (uint16), then the
# null-terminated name.  The flags mark code (bit 0) and a function (bit 1).
_PUBLIC_BODY = struct.Struct("<IIH")
_PUBLIC_CODE = 0x0001
_PUBLIC_FUNCTION = 0x0002

# S_GPROC32 and S_LPROC32 body: parent, end, next, code size, debug start, debug
# end (uint32 each), type index, code offset (uint32 each), segment (uint16),
# flags (uint8), then the null-terminated name.
_PROC_BODY = struct.Struct("<IIIIIIIIHB")

# S_THUNK32 body: parent, end, next, offset (uint32 each), segment (uint16),
# thunk length (uint16), ordinal (uint8), then the null-terminated name and the
# ordinal's own variant bytes, which this reader does not parse.
_THUNK_BODY = struct.Struct("<IIIIHHB")

# The two kinds a symbol entry carries.  The interface's third, "other", names
# the record kinds this reader skips rather than reports.
_KIND_FUNCTION = "function"
_KIND_OBJECT = "object"

# Facts about the reader that every result states, so a caller never reads a
# missing address or an empty type list as a fact about the binary.
_NOTES = (
    "the TPI and IPI streams are not parsed, so no types are recovered",
    (
        "only the DBI symbol record stream is walked, not the module info substreams"
        " nor the public and global hash tables"
    ),
    (
        "a symbol whose segment is not in the section map answers va: None, and an"
        " S_PUB32 that carries no segment and no offset does too; no address is invented"
    ),
    "an S_PUB32 carries no size, so a public symbol's size is 0",
    (
        "an S_PUB32's kind comes from its flags and its mangled-name shape, so a public"
        " with neither is an object"
    ),
)

# Notes a particular container earns.
_NO_COUNT_NOTE = (
    "the section map header declared 0 entries, so its entries were read without the 2-byte pad"
)
_REAL_MAP_NOTE = (
    "the section map substream holds the 20-byte SectionMapEntry records a real toolchain"
    " writes, which this reader does not turn into addresses, so symbols answer va: None"
)
_NO_STREAM_NOTE = "the DBI header names no symbol record stream, so no symbols are reported"
_UNRESOLVED_NOTE = "{count} symbols answer va: None because their segment is not in the section map"
_TRUNCATED_NOTE = "the symbol list is truncated at {limit} symbols"
_UNKNOWN_INFO_NOTE = (
    "the pdb info stream reports version {version}, which this reader does not know"
)


class PdbError(Exception):
    """A PDB container cannot be read; ``code`` is the API's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _block(data: bytes, index: int, block_size: int, num_blocks: int) -> bytes:
    """One whole block of *data*, refusing an index outside the container."""
    if index >= num_blocks:
        raise PdbError(_UNREADABLE, f"block {index} is outside the container")
    start = index * block_size
    if start + block_size > len(data):
        raise PdbError(_UNREADABLE, f"block {index} runs past the container")
    return data[start : start + block_size]


def _read_stream(
    data: bytes, blocks: list[int], size: int, block_size: int, num_blocks: int
) -> bytes:
    """The bytes of one stream: its blocks in order, cut to its declared size."""
    joined = b"".join(_block(data, index, block_size, num_blocks) for index in blocks)
    return joined[:size]


def _directory(data: bytes) -> tuple[list[int], list[list[int]], int, int]:
    """The stream sizes and block lists, plus the block size and the block count."""
    if len(data) < _SUPERBLOCK.size:
        raise PdbError(_UNREADABLE, "container is shorter than the MSF superblock")
    magic, block_size, _free_map, num_blocks, directory_bytes, _unused, block_map = (
        _SUPERBLOCK.unpack_from(data, 0)
    )
    if magic != CONTAINER_MAGIC:
        raise PdbError(_UNREADABLE, "container does not carry the MSF 7.0 magic")
    if block_size < _MIN_BLOCK_SIZE or block_size % _MIN_BLOCK_SIZE:
        raise PdbError(_UNREADABLE, f"block size {block_size} is not a multiple of 512")
    if num_blocks * block_size > len(data):
        raise PdbError(_UNREADABLE, "container is shorter than the superblock's block count")
    directory_blocks = _ceil_div(directory_bytes, block_size)
    if directory_bytes < _U32.size or directory_blocks > num_blocks:
        raise PdbError(_UNREADABLE, f"directory byte count {directory_bytes} is inconsistent")
    map_at = block_map * block_size
    if block_map >= num_blocks or map_at + directory_blocks * _U32.size > len(data):
        raise PdbError(_UNREADABLE, f"block map at block {block_map} is out of range")
    directory = b"".join(
        _block(data, _U32.unpack_from(data, map_at + at * _U32.size)[0], block_size, num_blocks)
        for at in range(directory_blocks)
    )
    count = _U32.unpack_from(directory, 0)[0]
    if _U32.size + count * _U32.size > directory_bytes:
        raise PdbError(_UNREADABLE, f"stream directory names {count} streams it cannot hold")
    sizes = [
        _U32.unpack_from(directory, _U32.size + index * _U32.size)[0] for index in range(count)
    ]
    blocks: list[list[int]] = []
    cursor = _U32.size + count * _U32.size
    for size in sizes:
        held = _ceil_div(size, block_size)
        end = cursor + held * _U32.size
        if end > directory_bytes:
            raise PdbError(_UNREADABLE, "stream directory is truncated inside its block lists")
        blocks.append(
            [_U32.unpack_from(directory, cursor + index * _U32.size)[0] for index in range(held)]
        )
        # Each block list is padded to a multiple of four bytes; a block index
        # is already four bytes, so the documented pad advances nothing.
        cursor = end
    return sizes, blocks, block_size, num_blocks


def _read_dbi(dbi: bytes) -> tuple[int, int, int]:
    """The symbol record stream index, the section map offset and its size."""
    if len(dbi) < _DBI_HEADER.size:
        raise PdbError(_UNREADABLE, "DBI stream is shorter than its header")
    (
        _version_signature,
        _version_header,
        _age,
        _global_stream,
        _build_number,
        _public_stream,
        _pdb_dll_version,
        symbol_stream,
        _pdb_dll_rebuild,
        module_info_size,
        section_contribution_size,
        section_map_size,
        source_info_size,
        type_server_map_size,
        _mfc_type_server,
        optional_debug_size,
        ec_substream_size,
        _flags,
        _machine,
        _padding,
    ) = _DBI_HEADER.unpack_from(dbi, 0)
    sizes = (
        module_info_size,
        section_contribution_size,
        section_map_size,
        source_info_size,
        type_server_map_size,
        optional_debug_size,
        ec_substream_size,
    )
    if any(size < 0 for size in sizes) or _DBI_HEADER.size + sum(sizes) > len(dbi):
        raise PdbError(_UNREADABLE, "DBI substream sizes do not fit the DBI stream")
    section_at = _DBI_HEADER.size + module_info_size + section_contribution_size
    return symbol_stream, section_at, section_map_size


def _sections(substream: bytes, notes: list[str]) -> dict[int, int]:
    """Segment number (1-based) to the bias that turns an offset into a VA."""
    if len(substream) < _SECTION_HEADER_SIZE:
        raise PdbError(_UNREADABLE, "section map substream is shorter than its header")
    length, count = _U16_PAIR.unpack_from(substream, 0)
    if length > len(substream):
        raise PdbError(_UNREADABLE, "section map declares more bytes than the substream holds")
    if count and len(substream) == _SECTION_HEADER_SIZE + count * _SECTION_MAP_ENTRY:
        # A real MSVC or lld PDB stores SectionMapEntry records here, addressed
        # through a shared frame and the section header list rather than through
        # this reader's section bias, so every symbol keeps its name and loses
        # its address instead of being given a made up one.
        notes.append(_REAL_MAP_NOTE)
        return {}
    if count == 0:
        # A writer that leaves the count at 0 still emits entries.  Without the
        # pad the 40-byte stride is the only one the declared length allows.
        notes.append(_NO_COUNT_NOTE)
        stride = _SECTION_ENTRY_COMPACT
        entries = max(0, (length - _SECTION_HEADER_SIZE) // _SECTION_ENTRY_COMPACT)
    elif len(substream) >= _SECTION_HEADER_SIZE + count * _SECTION_ENTRY_PADDED:
        stride, entries = _SECTION_ENTRY_PADDED, count
    else:
        stride, entries = _SECTION_ENTRY_COMPACT, count
    if _SECTION_HEADER_SIZE + entries * stride > len(substream):
        raise PdbError(_UNREADABLE, "section map entries run past the substream")
    segments: dict[int, int] = {}
    for index in range(entries):
        name_at = _SECTION_HEADER_SIZE + index * stride + (stride - _SECTION_ENTRY_COMPACT)
        tail = _SECTION_TAIL.unpack_from(substream, name_at + _SECTION_NAME_SIZE)
        # virtual_address + (offset - pointer_to_raw_data) is one per-section
        # bias added to the symbol's offset, so it is folded once here.
        segments[index + 1] = tail[_TAIL_VIRTUAL_ADDRESS] - tail[_TAIL_RAW_POINTER]
    return segments


def _cstring(body: bytes, at: int, what: str) -> str:
    """The null-terminated name at *at*, or a PdbError when it is unterminated."""
    end = body.find(b"\x00", at)
    if end < 0:
        raise PdbError(_UNREADABLE, f"{what} record carries no terminated name")
    return body[at:end].decode("utf-8", "replace")


def _address(segments: dict[int, int], segment: int, offset: int) -> int | None:
    """The virtual address of *offset* in *segment*, or None outside the map."""
    bias = segments.get(segment)
    return None if bias is None else bias + offset


def _public_kind(name: str, flags: int) -> str:
    """Whether a public symbol is code, from its flags and its mangled name."""
    if flags & (_PUBLIC_CODE | _PUBLIC_FUNCTION):
        return _KIND_FUNCTION
    # A mangled name whose marker after its scope is not a digit is a function
    # ("?f@@YAXXZ"); a digit marks data ("?g@@3HA").
    if name.startswith("?") and "@@" in name:
        marker = name.rpartition("@@")[2]
        if marker and not marker[0].isdigit():
            return _KIND_FUNCTION
    return _KIND_OBJECT


def _entry(kind: int, body: bytes, segments: dict[int, int]) -> dict[str, Any] | None:
    """One symbol entry, or None for a record kind this reader does not report."""
    if kind == _PUBLIC:
        flags, offset, segment = _PUBLIC_BODY.unpack_from(body, 0)
        name = _cstring(body, _PUBLIC_BODY.size, "S_PUB32")
        return {
            "name": name,
            "va": _address(segments, segment, offset),
            "kind": _public_kind(name, flags),
            "size": 0,
        }
    if kind in (_GLOBAL_PROC, _LOCAL_PROC):
        fields = _PROC_BODY.unpack_from(body, 0)
        # The procedure body's code size, code offset and segment.
        size, offset, segment = fields[3], fields[7], fields[8]
        return {
            "name": _cstring(body, _PROC_BODY.size, "procedure"),
            "va": _address(segments, segment, offset),
            "kind": _KIND_FUNCTION,
            "size": size,
        }
    if kind == _THUNK:
        fields = _THUNK_BODY.unpack_from(body, 0)
        # The thunk body's offset, segment and thunk length.
        offset, segment, size = fields[3], fields[4], fields[5]
        return {
            "name": _cstring(body, _THUNK_BODY.size, "thunk"),
            "va": _address(segments, segment, offset),
            "kind": _KIND_FUNCTION,
            "size": size,
        }
    return None


def _symbols(
    stream: bytes, segments: dict[int, int], notes: list[str]
) -> tuple[list[dict[str, Any]], bool]:
    """The reported symbols of the record stream, and whether the cap cut it."""
    symbols: list[dict[str, Any]] = []
    unresolved = 0
    capped = False
    at = 0
    while at + _RECORD_HEADER.size <= len(stream):
        length, kind = _RECORD_HEADER.unpack_from(stream, at)
        if length == 0:
            break
        if length < _RECORD_KIND_SIZE:
            raise PdbError(_UNREADABLE, f"symbol record at {at} has length {length}")
        end = at + _RECORD_HEADER.size + length - _RECORD_KIND_SIZE
        if end > len(stream):
            raise PdbError(_UNREADABLE, f"symbol record at {at} runs past the record stream")
        entry = _entry(kind, stream[at + _RECORD_HEADER.size : end], segments)
        at = end
        if entry is None:
            continue
        if entry["va"] is None:
            unresolved += 1
        if len(symbols) >= MAX_SYMBOLS:
            capped = True
            break
        symbols.append(entry)
    if unresolved and segments:
        notes.append(_UNRESOLVED_NOTE.format(count=unresolved))
    return symbols, capped


def _info_note(info: bytes, notes: list[str]) -> None:
    """Read the PDB info stream's version, which is reported and never enforced."""
    if len(info) < _INFO_HEADER_SIZE:
        raise PdbError(_UNREADABLE, "pdb info stream is shorter than its header")
    version = _U32.unpack_from(info, 0)[0]
    if version not in _INFO_VERSIONS:
        notes.append(_UNKNOWN_INFO_NOTE.format(version=version))


def read_symbols(data: bytes) -> dict[str, Any]:
    """The public and module symbols of a Windows PDB 7.0 container.

    Returns ``{"kind": "pdb", "symbols", "types", "notes", "counts"}``, where a
    symbol is ``{"name", "va", "kind", "size"}``: ``va`` is the image address or
    None when the section map cannot place the symbol, ``kind`` is ``"function"``
    or ``"object"``, and ``size`` is the declared extent, zero for a public.  The
    list is capped at :data:`MAX_SYMBOLS`, and ``notes`` names every fact the
    reader does not establish.
    """
    notes = list(_NOTES)
    try:
        sizes, blocks, block_size, num_blocks = _directory(data)
        if len(sizes) > _INFO_STREAM:
            info = _read_stream(
                data, blocks[_INFO_STREAM], sizes[_INFO_STREAM], block_size, num_blocks
            )
            _info_note(info, notes)
        if len(sizes) <= _DBI_STREAM:
            raise PdbError(_UNREADABLE, "container holds no DBI stream")
        dbi = _read_stream(data, blocks[_DBI_STREAM], sizes[_DBI_STREAM], block_size, num_blocks)
        symbol_stream, section_at, section_size = _read_dbi(dbi)
        segments = _sections(dbi[section_at : section_at + section_size], notes)
        symbols: list[dict[str, Any]] = []
        capped = False
        if symbol_stream == _NO_STREAM:
            notes.append(_NO_STREAM_NOTE)
        else:
            if symbol_stream >= len(sizes):
                raise PdbError(_UNREADABLE, f"symbol record stream {symbol_stream} is not present")
            records = _read_stream(
                data, blocks[symbol_stream], sizes[symbol_stream], block_size, num_blocks
            )
            symbols, capped = _symbols(records, segments, notes)
    except struct.error as exc:
        raise PdbError(_UNREADABLE, "container or symbol record is truncated") from exc
    if capped:
        notes.append(_TRUNCATED_NOTE.format(limit=MAX_SYMBOLS))
    return {
        "kind": "pdb",
        "symbols": symbols,
        "types": [],
        "notes": notes,
        "counts": {"symbols": len(symbols), "types": 0},
    }

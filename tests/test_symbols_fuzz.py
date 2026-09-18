"""Property fuzz for the untrusted ELF/DWARF and PDB symbol parsers.

``symbols.parse`` and ``pdb.read_symbols`` take arbitrary bytes from an
uploaded debug file.  These harnesses drive random and structure-aware
mutations through both readers and assert: only the documented reader
errors escape, and every successful answer keeps the shared result shape
the API, CLI and MCP surfaces already consume.
"""

from __future__ import annotations

import random
from typing import Any

from test_pdb import _synthetic
from test_symbols import (
    SHT_PROGBITS,
    SHT_STRTAB,
    SHT_SYMTAB,
    _strtab,
    _symtab,
    build_dwarf4,
    build_elf,
)

from reportal import pdb, symbols

_KINDS = frozenset({symbols.KIND_FUNCTION, symbols.KIND_OBJECT, symbols.KIND_OTHER})
_SOURCES = frozenset({symbols.SOURCE_ELF, symbols.SOURCE_DWARF, symbols.SOURCE_PDB})

# Bounded so a single CI pytest process stays under a second; raise locally
# when hunting for new crashes.
_ITERATIONS = 256
_MAX_RANDOM = 2048


def _seed_elf() -> bytes:
    """A minimal ELF with a symbol table and a DWARF unit, for mutation."""
    text, names = _strtab("main", "counter")
    dwarf = build_dwarf4()
    return build_elf(
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
            (".debug_abbrev", dwarf[".debug_abbrev"], SHT_PROGBITS, 0),
            (".debug_info", dwarf[".debug_info"], SHT_PROGBITS, 0),
            (".debug_str", dwarf[".debug_str"], SHT_PROGBITS, 0),
        ]
    )


def _seed_pdb() -> bytes:
    """A valid MSF 7.0 container the PDB reader already accepts."""
    return _synthetic()


def _mutate(rng: random.Random, seed: bytes) -> bytes:
    """One structure-aware mutant of *seed*: flips, inserts, truncates, splices."""
    data = bytearray(seed)
    if not data:
        return bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
    choice = rng.randrange(5)
    if choice == 0:
        # Bit flips at random offsets.
        for _ in range(rng.randint(1, 8)):
            at = rng.randrange(len(data))
            data[at] ^= 1 << rng.randrange(8)
    elif choice == 1:
        # Overwrite a short window with random bytes.
        at = rng.randrange(len(data))
        length = min(rng.randint(1, 64), len(data) - at)
        data[at : at + length] = (rng.getrandbits(8) for _ in range(length))
    elif choice == 2:
        # Truncate to a random prefix (including empty and magic-only).
        data = data[: rng.randrange(len(data) + 1)]
    elif choice == 3:
        # Insert a random blob somewhere, including past the end.
        at = rng.randrange(len(data) + 1)
        blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 128)))
        data[at:at] = blob
    else:
        # Duplicate or drop a random slice.
        start = rng.randrange(len(data))
        end = rng.randrange(start, len(data))
        if rng.random() < 0.5:
            data[start:end] = b""
        else:
            data[end:end] = data[start:end]
    return bytes(data)


def _assert_result_shape(result: dict[str, Any]) -> None:
    """Invariants every successful parse must keep for downstream consumers."""
    assert result["kind"] in _SOURCES
    assert isinstance(result["symbols"], list)
    assert isinstance(result["types"], list)
    assert isinstance(result["notes"], list)
    assert result["counts"] == {
        "symbols": len(result["symbols"]),
        "types": len(result["types"]),
    }
    assert len(result["symbols"]) <= symbols.MAX_SYMBOLS
    assert len(result["types"]) <= symbols.MAX_TYPES
    for entry in result["symbols"]:
        assert isinstance(entry["name"], str)
        assert len(entry["name"]) <= symbols.MAX_NAME_CHARS
        assert entry["kind"] in _KINDS
        assert entry["source"] in _SOURCES
        assert entry["va"] is None or isinstance(entry["va"], int)
        assert isinstance(entry["size"], int)
        assert entry["size"] >= 0
    for data_type in result["types"]:
        assert isinstance(data_type.get("name"), str)
        members = data_type.get("members") or []
        assert isinstance(members, list)
        assert len(members) <= symbols.MAX_MEMBERS


def _drive_symbols(rng: random.Random, corpus: list[bytes]) -> None:
    """Run *corpus* mutants through ``symbols.parse`` with shape assertions."""
    for _ in range(_ITERATIONS):
        seed = corpus[rng.randrange(len(corpus))]
        data = _mutate(rng, seed) if rng.random() < 0.85 else seed
        try:
            result = symbols.parse(data)
        except symbols.UnreadableSymbolError as exc:
            assert exc.code == symbols.ERROR_UNREADABLE
            assert isinstance(exc.detail, str)
            continue
        _assert_result_shape(result)


def _drive_pdb(rng: random.Random, corpus: list[bytes]) -> None:
    """Run *corpus* mutants through ``pdb.read_symbols`` with shape assertions."""
    for _ in range(_ITERATIONS):
        seed = corpus[rng.randrange(len(corpus))]
        data = _mutate(rng, seed) if rng.random() < 0.85 else seed
        try:
            result = pdb.read_symbols(data)
        except pdb.PdbError as exc:
            assert exc.code == "symbols-unreadable"
            assert isinstance(exc.detail, str)
            continue
        assert result["kind"] == "pdb"
        assert result["types"] == []
        assert result["counts"]["symbols"] == len(result["symbols"])
        assert result["counts"]["types"] == 0
        assert len(result["symbols"]) <= pdb.MAX_SYMBOLS
        for entry in result["symbols"]:
            assert isinstance(entry["name"], str)
            assert entry["kind"] in {"function", "object"}
            assert entry["va"] is None or isinstance(entry["va"], int)


def test_symbols_parse_random_bytes() -> None:
    """Pure random bytes, and the same with ELF/PDB magic prefixes spliced on."""
    rng = random.Random(0x51B01)
    for _ in range(_ITERATIONS):
        size = rng.randint(0, _MAX_RANDOM)
        data = bytes(rng.getrandbits(8) for _ in range(size))
        if size and rng.random() < 0.3:
            data = symbols.ELF_MAGIC + data[4:]
        elif size and rng.random() < 0.3:
            data = pdb.CONTAINER_MAGIC + data[len(pdb.CONTAINER_MAGIC) :]
        try:
            result = symbols.parse(data)
        except symbols.UnreadableSymbolError as exc:
            assert exc.code == symbols.ERROR_UNREADABLE
            continue
        _assert_result_shape(result)


def test_symbols_parse_mutates_valid_elf() -> None:
    """Structure-aware mutants of a known-good ELF+DWARF fixture."""
    elf = _seed_elf()
    # The seed itself must still parse, so a broken fixture fails loudly here.
    _assert_result_shape(symbols.parse(elf))
    _drive_symbols(random.Random(0xE1F), [elf, elf[:64], elf + b"\x00" * 16])


def test_symbols_parse_mutates_valid_pdb() -> None:
    """Structure-aware mutants of a known-good PDB through the dispatch path."""
    container = _seed_pdb()
    _assert_result_shape(symbols.parse(container))
    _drive_symbols(random.Random(0x0DB), [container, container[:64]])


def test_pdb_read_symbols_mutates_valid_container() -> None:
    """Structure-aware mutants aimed at the PDB reader directly."""
    container = _seed_pdb()
    _drive_pdb(random.Random(0xB10C), [container, container[:128], b""])

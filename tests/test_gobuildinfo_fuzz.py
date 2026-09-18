"""Property fuzz for the Go buildinfo byte parser.

``gobuildinfo.parse_buildinfo`` scans untrusted binary bytes for the
``Go buildinf:`` magic and decodes the version, module path, dependency
and settings lines that follow it.  These harnesses feed random and
structure-aware mutants and assert that only ``GobuildinfoError`` escapes
and that every successful answer keeps the keys the scan surfaces store.
"""

from __future__ import annotations

import random
from typing import Any

from reportal import gobuildinfo

# Synthetic blob matching the layout verified in ``test_gobuildinfo``.
_SEED = (
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

_ITERATIONS = 256
_MAX_RANDOM = 4096


def _mutate(rng: random.Random, seed: bytes) -> bytes:
    """One mutant: flips, overwrites, truncates, inserts or splices."""
    data = bytearray(seed)
    if not data:
        return bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
    choice = rng.randrange(5)
    if choice == 0:
        for _ in range(rng.randint(1, 8)):
            at = rng.randrange(len(data))
            data[at] ^= 1 << rng.randrange(8)
    elif choice == 1:
        at = rng.randrange(len(data))
        length = min(rng.randint(1, 64), len(data) - at)
        data[at : at + length] = (rng.getrandbits(8) for _ in range(length))
    elif choice == 2:
        data = data[: rng.randrange(len(data) + 1)]
    elif choice == 3:
        at = rng.randrange(len(data) + 1)
        blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 256)))
        data[at:at] = blob
    else:
        start = rng.randrange(len(data))
        end = rng.randrange(start, len(data))
        if rng.random() < 0.5:
            data[start:end] = b""
        else:
            data[end:end] = data[start:end]
    return bytes(data)


def _assert_payload(payload: dict[str, Any]) -> None:
    """Invariants every successful buildinfo decode must keep."""
    assert isinstance(payload["version"], str)
    assert payload["version"].startswith("go")
    assert isinstance(payload["module"], str)
    assert isinstance(payload["build_id"], str)
    assert isinstance(payload["settings"], dict)
    assert isinstance(payload["dependencies"], list)
    for key, value in payload["settings"].items():
        assert isinstance(key, str)
        assert isinstance(value, str)
    for entry in payload["dependencies"]:
        assert isinstance(entry["module"], str) and entry["module"]
        assert isinstance(entry["version"], str) and entry["version"]


def test_parse_buildinfo_random_bytes() -> None:
    """Pure random bytes, with and without the magic spliced in."""
    rng = random.Random(0x60B1)
    for _ in range(_ITERATIONS):
        size = rng.randint(0, _MAX_RANDOM)
        data = bytes(rng.getrandbits(8) for _ in range(size))
        if size and rng.random() < 0.4:
            at = rng.randrange(size)
            data = data[:at] + gobuildinfo.BUILDINFO_MAGIC + data[at:]
        try:
            payload = gobuildinfo.parse_buildinfo(data, build_id="fuzz")
        except gobuildinfo.GobuildinfoError as exc:
            assert exc.code == "not-go"
            assert isinstance(exc.detail, str)
            continue
        _assert_payload(payload)
        assert payload["build_id"] == "fuzz"


def test_parse_buildinfo_mutates_valid_blob() -> None:
    """Structure-aware mutants of a known-good go1.27-shaped blob."""
    _assert_payload(gobuildinfo.parse_buildinfo(_SEED))
    rng = random.Random(0x601D)
    corpus = [_SEED, _SEED[:32], b"\x00" * 64 + _SEED, _SEED + b"\xff" * 64]
    for _ in range(_ITERATIONS):
        seed = corpus[rng.randrange(len(corpus))]
        data = _mutate(rng, seed) if rng.random() < 0.9 else seed
        try:
            payload = gobuildinfo.parse_buildinfo(data)
        except gobuildinfo.GobuildinfoError as exc:
            assert exc.code == "not-go"
            continue
        _assert_payload(payload)

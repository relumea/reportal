"""Property fuzz for the untrusted firmware carve scanner.

``firmware.carve`` walks uploaded binary bytes looking for embedded-image
magics.  These harnesses feed random and structure-aware mutants and assert
that the pass never raises and that every region keeps the bounds and shape
the scan surfaces store.
"""

from __future__ import annotations

import random
import tempfile
from pathlib import Path
from typing import Any

from reportal import firmware

_ITERATIONS = 128
_MAX_RANDOM = 4096

_MAGICS = tuple(signature.magic for signature in firmware.SIGNATURES if not signature.offset)


def _seed_blob() -> bytes:
    """A small blob with several magics at known offsets for mutation."""
    parts = [
        b"\x00" * 32,
        b"hsqs",
        b"\xff" * 48,
        b"\x1f\x8b\x08",
        b"noise" * 16,
        b"ANDROID!",
        b"\x00" * 64,
        b"PK\x03\x04",
        b"tail" * 8,
    ]
    return b"".join(parts)


def _mutate(rng: random.Random, seed: bytes) -> bytes:
    """One mutant: flips, overwrites, truncates, inserts or splices."""
    data = bytearray(seed)
    if not data:
        return bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
    choice = rng.randrange(6)
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
    elif choice == 4:
        start = rng.randrange(len(data))
        end = rng.randrange(start, len(data))
        if rng.random() < 0.5:
            data[start:end] = b""
        else:
            data[end:end] = data[start:end]
    else:
        # Splice a real magic somewhere so the scanner's hit path is exercised.
        magic = _MAGICS[rng.randrange(len(_MAGICS))]
        at = rng.randrange(len(data) + 1)
        data[at:at] = magic
    return bytes(data)


def _assert_carve(payload: dict[str, Any], size: int) -> None:
    """Invariants every carve answer must keep for the scan store."""
    assert payload["size"] == size
    assert isinstance(payload["signatures"], int)
    assert payload["signatures"] >= 0
    assert isinstance(payload["regions"], list)
    assert payload["region_count"] == len(payload["regions"])
    assert payload["region_count"] <= firmware.MAX_REGIONS
    assert isinstance(payload["truncated"], bool)
    assert payload["truncated"] is (payload["signatures"] > firmware.MAX_REGIONS)
    assert isinstance(payload["entropy"], list)
    assert len(payload["entropy"]) <= firmware.MAX_ENTROPY_SAMPLES
    assert payload["entropy_window"] == firmware.ENTROPY_WINDOW
    assert payload["max_region_bytes"] == firmware.MAX_REGION_BYTES
    assert payload["extractable_kinds"] == sorted(firmware.ARCHIVE_SUFFIXES)
    assert isinstance(payload["note"], str) and payload["note"]
    previous_end = 0
    for index, region in enumerate(payload["regions"]):
        assert region["index"] == index
        assert isinstance(region["offset"], int) and region["offset"] >= 0
        assert isinstance(region["size"], int) and region["size"] > 0
        assert region["offset"] + region["size"] <= size
        assert region["size"] <= firmware.MAX_REGION_BYTES
        assert isinstance(region["kind"], str) and region["kind"]
        assert isinstance(region["label"], str) and region["label"]
        assert region["confidence"] in {
            firmware.CONFIDENCE_SIGNATURE,
            firmware.CONFIDENCE_EMBEDDED,
        }
        assert isinstance(region["truncated"], bool)
        assert isinstance(region["entropy"], float)
        assert 0.0 <= region["entropy"] <= 8.0
        assert region["offset"] >= previous_end or index == 0
        previous_end = region["offset"]
    for sample in payload["entropy"]:
        assert isinstance(sample["offset"], int) and sample["offset"] >= 0
        assert isinstance(sample["entropy"], float)
        assert 0.0 <= sample["entropy"] <= 8.0


def test_carve_random_bytes() -> None:
    """Pure random bytes, with and without real magics spliced in."""
    rng = random.Random(0xF12A)
    for _ in range(_ITERATIONS):
        size = rng.randint(0, _MAX_RANDOM)
        data = bytearray(rng.getrandbits(8) for _ in range(size))
        if size and rng.random() < 0.5:
            magic = _MAGICS[rng.randrange(len(_MAGICS))]
            at = rng.randrange(size)
            data[at : at + len(magic)] = magic[: max(0, size - at)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob.bin"
            path.write_bytes(bytes(data))
            payload = firmware.carve(path)
        _assert_carve(payload, len(data))


def test_carve_mutates_valid_blob() -> None:
    """Structure-aware mutants of a blob that already carries several magics."""
    seed = _seed_blob()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "seed.bin"
        path.write_bytes(seed)
        _assert_carve(firmware.carve(path), len(seed))
    rng = random.Random(0xCA2E)
    corpus = [seed, seed[:64], b"", b"\x00" * 128, seed + b"\xff" * 32]
    for _ in range(_ITERATIONS):
        blob = corpus[rng.randrange(len(corpus))]
        data = _mutate(rng, blob) if rng.random() < 0.9 else blob
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mut.bin"
            path.write_bytes(data)
            payload = firmware.carve(path)
        _assert_carve(payload, len(data))

"""Property fuzz for the untrusted archive extractor.

``archive.extract`` takes bytes an operator uploaded as a zip, tar or gzip.
These harnesses drive random and structure-aware mutants through the reader
and assert: only ``ArchiveError`` escapes, every written path stays under the
destination root, and each member outcome keeps the shape the API and CLI
already consume.
"""

from __future__ import annotations

import gzip
import io
import random
import tarfile
import tempfile
import zipfile
from pathlib import Path

from reportal import archive

_ITERATIONS = 128
_MAX_RANDOM = 2048

_ARCHIVE_CODES = frozenset(
    {
        "external-tool-required",
        "unsupported-format",
        "corrupt-archive",
        "too-many-members",
        "password-required",
        "bad-password",
        "archive-too-large",
    }
)

_BODY = bytes(range(256))


def _seed_zip() -> bytes:
    """A minimal deflated zip with one regular member."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.bin", _BODY)
        zf.writestr("nested/leaf.txt", b"hello\n")
    return buffer.getvalue()


def _seed_tar() -> bytes:
    """A minimal ustar with one regular member."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        info = tarfile.TarInfo("payload.bin")
        info.size = len(_BODY)
        tf.addfile(info, io.BytesIO(_BODY))
    return buffer.getvalue()


def _seed_gzip() -> bytes:
    """A single-member gzip whose payload is the seed body."""
    return gzip.compress(_BODY)


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
        blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 128)))
        data[at:at] = blob
    else:
        start = rng.randrange(len(data))
        end = rng.randrange(start, len(data))
        if rng.random() < 0.5:
            data[start:end] = b""
        else:
            data[end:end] = data[start:end]
    return bytes(data)


def _assert_extraction(result: archive.Extraction, destination: Path) -> None:
    """Invariants every successful extraction must keep for callers."""
    root = destination.resolve()
    assert isinstance(result.members, tuple)
    assert isinstance(result.notes, tuple)
    for note in result.notes:
        assert isinstance(note, str)
    for member in result.members:
        assert isinstance(member.name, str)
        assert isinstance(member.size, int)
        assert member.size >= 0
        assert isinstance(member.skipped, str)
        if member.path is None:
            assert member.skipped
            continue
        assert not member.skipped
        assert member.path.is_file()
        assert member.path.resolve().is_relative_to(root)
        assert member.path.stat().st_size == member.size
    for kept in result.kept:
        assert kept.path is not None


def _drive(
    rng: random.Random,
    corpus: list[tuple[bytes, str]],
    *,
    iterations: int = _ITERATIONS,
) -> None:
    """Run *corpus* mutants through ``archive.extract`` with shape assertions."""
    for _ in range(iterations):
        seed, suffix = corpus[rng.randrange(len(corpus))]
        data = _mutate(rng, seed) if rng.random() < 0.9 else seed
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / f"sample{suffix}"
            destination = root / "out"
            archive_path.write_bytes(data)
            try:
                result = archive.extract(archive_path, destination)
            except archive.ArchiveError as exc:
                assert exc.code in _ARCHIVE_CODES
                assert isinstance(exc.detail, str) and exc.detail
                continue
            _assert_extraction(result, destination)


def test_extract_random_bytes() -> None:
    """Pure random bytes under zip, tar and gzip names."""
    rng = random.Random(0xA2C4)
    for _ in range(_ITERATIONS):
        size = rng.randint(0, _MAX_RANDOM)
        data = bytes(rng.getrandbits(8) for _ in range(size))
        suffix = rng.choice([".zip", ".tar", ".gz", ".apk", ".tgz"])
        if size and rng.random() < 0.25:
            data = b"PK\x03\x04" + data[4:]
        elif size and rng.random() < 0.25:
            data = b"\x1f\x8b\x08" + data[3:]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / f"blob{suffix}"
            destination = root / "out"
            archive_path.write_bytes(data)
            try:
                result = archive.extract(archive_path, destination)
            except archive.ArchiveError as exc:
                assert exc.code in _ARCHIVE_CODES
                assert isinstance(exc.detail, str)
                continue
            _assert_extraction(result, destination)


def test_extract_mutates_valid_zip() -> None:
    """Structure-aware mutants of a known-good zip fixture."""
    seed = _seed_zip()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / "seed.zip"
        path.write_bytes(seed)
        _assert_extraction(archive.extract(path, root / "out"), root / "out")
    _drive(random.Random(0x21F), [(seed, ".zip"), (seed[:32], ".zip"), (b"", ".zip")])


def test_extract_mutates_valid_tar() -> None:
    """Structure-aware mutants of a known-good ustar fixture."""
    seed = _seed_tar()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / "seed.tar"
        path.write_bytes(seed)
        _assert_extraction(archive.extract(path, root / "out"), root / "out")
    _drive(random.Random(0x7A2), [(seed, ".tar"), (seed[:64], ".tar")])


def test_extract_mutates_valid_gzip() -> None:
    """Structure-aware mutants of a known-good single-member gzip."""
    seed = _seed_gzip()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = root / "seed.gz"
        path.write_bytes(seed)
        _assert_extraction(archive.extract(path, root / "out"), root / "out")
    _drive(random.Random(0x621F), [(seed, ".gz"), (seed[:8], ".gz"), (b"\x1f\x8b", ".gz")])

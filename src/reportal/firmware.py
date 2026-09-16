"""Firmware carving: find the images embedded in a stored blob, offline.

The hosted portal runs a hosted extractor over a firmware upload.  reportal does
the static half of that locally, with the standard library only and without
executing anything: :func:`scan` walks a stored binary looking for the magics
the embedded-image formats start with, reports every region it finds with its
offset, size, kind, confidence and Shannon entropy, and stores the pass as the
``firmware`` scan.  :func:`regions` reads that scan back.

A *region* runs from one signature to the next, or to the end of the file,
bounded by :data:`MAX_REGION_BYTES`.  That is a carve, not a parse: reportal does
not read a squashfs or a UBI inode table (a filesystem reader per format is a
project of its own), so a carved region is reported as material to work with
rather than as a tree of files.  The kinds the standard library *can* read
(gzip, a tar and a zip) are extracted for real by
:func:`reportal.archive.extract` when a caller asks for it, and every other
region is carved out as a binary of its own with its provenance recorded.

Nothing here runs, mounts or executes a sample: a scan reads the bytes reportal
already stores, and the only files written are temporary ones under the
workspace's `binaries/` directory.
"""

from __future__ import annotations

import math
import sqlite3
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from reportal import store
from reportal._paths import binaries_dir

# The scan kind the pass is stored under.  Mirrored as `store.SCAN_KIND_FIRMWARE`
# so the ratings vocabulary picks it up the day it lands.
SCAN_KIND = store.SCAN_KIND_FIRMWARE

# Window one entropy sample covers, and the most samples a map carries.
ENTROPY_WINDOW = 4096
MAX_ENTROPY_SAMPLES = 512

# Bytes one carve pass reads at a time while looking for magics.
SCAN_CHUNK_BYTES = 1024 * 1024

# Regions one pass reports, and how large one may be.  A region that would run
# past the cap is truncated and says so rather than swallowing the rest of the
# image: an 8 MiB squashfs at offset 0 of a 1 GiB firmware must not report one
# gigabyte of "squashfs".
MAX_REGIONS = 64
MAX_REGION_BYTES = 512 * 1024 * 1024

# Confidence labels a region carries.
CONFIDENCE_SIGNATURE = "signature"
CONFIDENCE_EMBEDDED = "embedded"

# The archive kinds `reportal.archive.extract` reads, keyed by the carve kind
# and the suffix the temporary file must carry for `archive_kind` to see it.
ARCHIVE_SUFFIXES: dict[str, str] = {
    "gzip": ".gz",
    "zip": ".zip",
    "tar": ".tar",
}


@dataclass(frozen=True)
class Signature:
    """One embedded-image magic: what it means and where it sits in a region."""

    kind: str
    label: str
    magic: bytes
    # Offset from the start of the region the magic sits at.  0 is a format
    # that starts with its magic; a fixed offset (the ext superblock at 0x438)
    # is checked only at the file's own start.
    offset: int = 0


# The formats one pass looks for.  The list is deliberately the magics a
# firmware image actually carries and that are long enough not to fire on
# noise; it is not a general file-identification table (that is `filetypes.py`).
SIGNATURES: tuple[Signature, ...] = (
    Signature("squashfs", "SquashFS filesystem", b"hsqs"),
    Signature("squashfs", "SquashFS filesystem (big endian)", b"sqsh"),
    Signature("jffs2", "JFFS2 filesystem", b"\x19\x85"),
    Signature("cramfs", "CramFS filesystem", b"\x45\x3d\xcd\x28"),
    Signature("ubifs", "UBI image", b"UBI#"),
    Signature("ext", "ext filesystem superblock", b"\x53\xef", offset=0x438),
    Signature("uimage", "U-Boot legacy image", b"\x27\x05\x19\x56"),
    Signature("bootimg", "Android boot image", b"ANDROID!"),
    Signature("elf", "ELF image", b"\x7fELF"),
    Signature("pe", "PE image", b"MZ"),
    Signature("gzip", "gzip stream", b"\x1f\x8b\x08"),
    Signature("xz", "xz stream", b"\xfd7zXZ\x00"),
    Signature("bzip2", "bzip2 stream", b"BZh"),
    Signature("lzma", "LZMA stream", b"\x5d\x00\x00"),
    Signature("zip", "zip archive", b"PK\x03\x04"),
    Signature("7z", "7z archive", b"7z\xbc\xaf\x27\x1c"),
    Signature("rar", "RAR archive", b"Rar!\x1a\x07"),
    Signature("tar", "tar archive", b"ustar", offset=257),
    Signature("upx", "UPX-packed image", b"UPX!"),
)

# The longest magic, which is how far past a chunk boundary a match can start.
_MAGIC_SPAN = max(len(signature.magic) for signature in SIGNATURES)


class FirmwareError(Exception):
    """A carve pass cannot run; ``code`` is the API's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _read_window(handle: BinaryIO, offset: int, length: int) -> bytes:
    """Read up to *length* bytes at *offset*, or fewer at the end of the file."""
    handle.seek(offset)
    return handle.read(length)


def find_signatures(path: Path, *, size: int) -> list[tuple[int, Signature]]:
    """Every signature hit in *path*, ordered by offset then kind.

    The file is read in :data:`SCAN_CHUNK_BYTES` chunks with the longest magic's
    length carried over, so a signature straddling a chunk boundary is still
    found; a fixed-offset signature is checked at the file's own start only,
    because that offset is meaningful there and nowhere else.
    """
    hits: list[tuple[int, Signature]] = []
    with path.open("rb") as handle:
        for signature in SIGNATURES:
            if signature.offset:
                window = _read_window(handle, signature.offset, len(signature.magic))
                if window == signature.magic:
                    hits.append((0, signature))
        start = 0
        while start < size:
            handle.seek(start)
            chunk = handle.read(SCAN_CHUNK_BYTES)
            if not chunk:
                break
            for signature in SIGNATURES:
                if signature.offset:
                    continue
                position = chunk.find(signature.magic)
                while position != -1:
                    hits.append((start + position, signature))
                    position = chunk.find(signature.magic, position + 1)
            start += max(len(chunk) - _MAGIC_SPAN, 1)
    # Two formats can share a magic prefix at one offset (a tar whose first
    # member is a zip, say); the longer magic is the more specific reading.
    hits.sort(key=lambda hit: (hit[0], -len(hit[1].magic), hit[1].kind))
    unique: list[tuple[int, Signature]] = []
    seen: set[int] = set()
    for offset, signature in hits:
        if offset in seen:
            continue
        seen.add(offset)
        unique.append((offset, signature))
    return unique


def entropy_map(path: Path, *, size: int) -> list[dict[str, Any]]:
    """Sampled Shannon entropy per :data:`ENTROPY_WINDOW`, at most the cap.

    A window count above :data:`MAX_ENTROPY_SAMPLES` is sampled at an even
    stride, so the map stays bounded for a gigabyte of firmware and says how
    many windows it skipped.  High entropy marks compressed or encrypted
    material; low entropy marks padding and zero fill.
    """
    if size <= 0:
        return []
    windows = max(1, math.ceil(size / ENTROPY_WINDOW))
    stride = max(1, math.ceil(windows / MAX_ENTROPY_SAMPLES))
    samples: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        for index in range(0, windows, stride):
            offset = index * ENTROPY_WINDOW
            window = _read_window(handle, offset, ENTROPY_WINDOW)
            if not window:
                break
            counts = [0] * 256
            for byte in window:
                counts[byte] += 1
            total = len(window)
            entropy = -sum((count / total) * math.log2(count / total) for count in counts if count)
            samples.append(
                {
                    "offset": offset,
                    "length": total,
                    "entropy": round(entropy, 4),
                }
            )
    return samples


def _regions_from(hits: list[tuple[int, Signature]], size: int) -> list[dict[str, Any]]:
    """Turn signature hits into the regions one pass reports."""
    regions: list[dict[str, Any]] = []
    for index, (offset, signature) in enumerate(hits[:MAX_REGIONS]):
        following = hits[index + 1][0] if index + 1 < len(hits) else size
        end = min(following, offset + MAX_REGION_BYTES, size)
        length = max(end - offset, 0)
        if length <= 0:
            continue
        regions.append(
            {
                "index": len(regions),
                "offset": offset,
                "size": length,
                "kind": signature.kind,
                "label": signature.label,
                "confidence": CONFIDENCE_SIGNATURE if offset == 0 else CONFIDENCE_EMBEDDED,
                "truncated": offset + length < size and length >= MAX_REGION_BYTES,
            }
        )
    return regions


def carve(path: Path) -> dict[str, Any]:
    """The carve pass over *path*: its size, its regions and its entropy map.

    Pure byte work: no engine call, no subprocess, nothing executed.
    """
    size = path.stat().st_size
    hits = find_signatures(path, size=size)
    regions = _regions_from(hits, size)
    with path.open("rb") as handle:
        for region in regions:
            window = _read_window(handle, int(region["offset"]), ENTROPY_WINDOW)
            region["entropy"] = round(_entropy(window), 4)
    return {
        "size": size,
        "signatures": len(hits),
        "regions": regions,
        "region_count": len(regions),
        "truncated": len(hits) > MAX_REGIONS,
        "entropy": entropy_map(path, size=size),
        "entropy_window": ENTROPY_WINDOW,
        "max_region_bytes": MAX_REGION_BYTES,
        "extractable_kinds": sorted(ARCHIVE_SUFFIXES),
        "note": (
            "a region is carved, not parsed: reportal reads no filesystem inode table,"
            " so a squashfs or UBI region is material to analyse, and the gzip, tar and"
            " zip ones can be extracted with the archive reader"
        ),
    }


def _entropy(window: bytes) -> float:
    """Shannon entropy of *window* in bits per byte."""
    if not window:
        return 0.0
    counts = [0] * 256
    for byte in window:
        counts[byte] += 1
    total = len(window)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _stored_path(conn: sqlite3.Connection, binary_id: int) -> Path:
    """The file a stored binary lives at, or a :class:`FirmwareError`."""
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise FirmwareError("binary not found", f"no binary with id {binary_id}")
    path = Path(str(binary["path"]))
    if not path.is_file():
        raise FirmwareError(
            "binary not on disk", f"binary {binary_id} has no file at {binary['path']!r}"
        )
    return path


def scan(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Carve *binary_id* and store the pass as its ``firmware`` scan.

    The scan hangs off the binary's newest analysis, the way every other scan
    does, and a re-run replaces it rather than accumulating passes.
    """
    path = _stored_path(conn, binary_id)
    payload = carve(path)
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="firmware")
    store.set_scan(conn, analysis_id, SCAN_KIND, payload)
    return {"binary_id": binary_id, "analysis_id": analysis_id, **payload}


def regions(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """The stored carve pass of *binary_id*, or None before the first run."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    stored = store.get_scan(conn, analysis_id, SCAN_KIND)
    if stored is None:
        return None
    return {"binary_id": binary_id, "analysis_id": analysis_id, **stored}


def region(path: Path, *, index: int, regions_payload: dict[str, Any]) -> dict[str, Any]:
    """The bytes one stored region names, as an offset, a name and a size.

    The API, the CLI and the MCP tool all carve the same way, so the region's
    own bounds are validated here rather than at each surface.
    """
    entries = regions_payload.get("regions") or []
    if index < 0 or index >= len(entries):
        raise FirmwareError("region not found", f"no region with index {index}")
    region_entry = entries[index]
    offset = int(region_entry["offset"])
    size = int(region_entry["size"])
    if size <= 0:
        raise FirmwareError("invalid-region", f"region {index} is empty")
    kind = str(region_entry["kind"])
    suffix = ARCHIVE_SUFFIXES.get(kind, ".bin")
    name = f"{path.stem}.{kind}.{offset:#x}{suffix}"
    trimmed = False
    if kind == "gzip":
        length = gzip_member_length(path, offset=offset, size=size)
        if length is not None and 0 < length < size:
            size = length
            trimmed = True
    return {
        "index": index,
        "offset": offset,
        "size": size,
        "kind": kind,
        "label": str(region_entry["label"]),
        "name": name,
        "extractable": kind in ARCHIVE_SUFFIXES,
        "trimmed": trimmed,
    }


def gzip_member_length(source: Path, *, offset: int, size: int) -> int | None:
    """The end of the gzip member at *offset*, or None when it is not readable.

    A region runs to the next signature, which for a gzip stream means it
    usually carries the bytes that follow it; the archive reader rejects a
    gzip with trailing non-zero data, so the extent zlib reports is what the
    carve writes.  A multi-member stream trims to its first member, which the
    caller reports rather than hides.
    """
    with source.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(min(size, MAX_REGION_BYTES))
    decompressor = zlib.decompressobj(31)
    try:
        decompressor.decompress(data)
    except zlib.error:
        return None
    if not decompressor.eof:
        return None
    return len(data) - len(decompressor.unused_data)


def write_region(source: Path, target: Path, *, offset: int, size: int) -> int:
    """Copy one region out of *source* into *target*; returns the bytes written.

    The copy is streamed in bounded chunks so a 512 MiB region never sits in
    memory whole.
    """
    written = 0
    with source.open("rb") as reader, target.open("wb") as writer:
        reader.seek(offset)
        remaining = size
        while remaining > 0:
            chunk = reader.read(min(SCAN_CHUNK_BYTES, remaining))
            if not chunk:
                break
            writer.write(chunk)
            written += len(chunk)
            remaining -= len(chunk)
    return written


def temp_region_path(name: str) -> Path:
    """A path under the workspace's `binaries/` directory for one carved region."""
    directory = binaries_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f".carve-{name}"

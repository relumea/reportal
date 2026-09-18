#!/usr/bin/env python3
"""Write ``.gz`` (and ``.br`` when brotli is on PATH) siblings next to SPA assets.

Hashed bundles are produced once per build and served many times, so they are
compressed at maximum effort here rather than on every request.  ``ui.py``
prefers a sibling ``.br`` when the client accepts brotli, then ``.gz`` for
gzip, and falls back to an on-the-fly compress at the request-time level when
none is present (a checkout that ran ``vite build`` without this step).
"""

from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Same suffixes ``ui.py`` will compress on the wire.  Already-compressed formats
# (images, fonts, archives) are left alone.
COMPRESSIBLE_SUFFIXES = frozenset(
    {".css", ".html", ".js", ".json", ".map", ".mjs", ".svg", ".txt", ".xml"}
)

# Below this, the gzip framing costs more than it saves.
MIN_BYTES = 256

# Build-time effort: the bytes are produced once and cached forever under a
# content-hashed name.  Measured on the vendor chunk: level 9 is 1.4% smaller
# than level 6 at roughly 3x the CPU, which is paid once per deploy.
GZIP_LEVEL = 9

# Brotli quality 11 is the documented maximum; paid once per deploy like gzip 9.
# Measured on the vendor chunk: ~13% smaller than gzip 9.
BROTLI_QUALITY = 11

DIST = Path(__file__).resolve().parents[1] / "src" / "reportal" / "assets" / "dist"


def gzip_mtime() -> int:
    """Gzip header mtime: ``SOURCE_DATE_EPOCH`` when set, else ``0`` (reproducible)."""
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not raw:
        return 0
    try:
        value = int(raw)
    except ValueError:
        return 0
    return max(value, 0)


def brotli_bin() -> str | None:
    """Path to a ``brotli`` CLI, or None when the build host has none."""
    return shutil.which("brotli")


def brotli_compress(body: bytes, *, quality: int = BROTLI_QUALITY) -> bytes | None:
    """Compress *body* with the system brotli CLI, or None when unavailable."""
    binary = brotli_bin()
    if binary is None:
        return None
    try:
        completed = subprocess.run(
            [binary, "-q", str(quality), "-c"],
            input=body,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout or None


def _write_if_changed(path: Path, payload: bytes) -> bool:
    """Write *payload* to *path* when missing or different; return True when written."""
    if path.is_file() and path.read_bytes() == payload:
        return False
    path.write_bytes(payload)
    return True


def precompress(root: Path) -> int:
    """Write or refresh compressed siblings under *root*; return how many were written."""
    if not root.is_dir():
        sys.stderr.write(f"no SPA build at {root}; run `bun run build` in web/ first\n")
        return 0
    written = 0
    mtime = gzip_mtime()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix in {".gz", ".br"} or path.suffix.lower() not in COMPRESSIBLE_SUFFIXES:
            continue
        if path.stat().st_size < MIN_BYTES:
            continue
        body = path.read_bytes()
        relative = path.relative_to(root)
        gz_payload = gzip.compress(body, compresslevel=GZIP_LEVEL, mtime=mtime)
        gz_path = Path(f"{path}.gz")
        if _write_if_changed(gz_path, gz_payload):
            written += 1
            sys.stdout.write(f"{relative}: {len(body)} -> {len(gz_payload)} bytes (gzip)\n")
        br_payload = brotli_compress(body)
        if br_payload is not None and len(br_payload) < len(body):
            br_path = Path(f"{path}.br")
            if _write_if_changed(br_path, br_payload):
                written += 1
                sys.stdout.write(f"{relative}: {len(body)} -> {len(br_payload)} bytes (br)\n")
    return written


def main() -> int:
    """Precompress the built SPA; exit 1 when the dist directory is missing."""
    root = DIST
    if len(sys.argv) > 1:
        root = Path(sys.argv[1])
    if not root.is_dir():
        sys.stderr.write(f"no SPA build at {root}; run `bun run build` in web/ first\n")
        return 1
    count = precompress(root)
    sys.stdout.write(f"precompressed {count} file(s) under {root}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

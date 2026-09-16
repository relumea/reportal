"""Go build information recovery from the stored binary file.

A Go binary embeds its own provenance twice: the ``.note.go.buildid``
section carries the build id, and the ``go.buildinfo`` section carries
the compiler version, the main module path and the build settings
(``Go buildinf:`` magic, then the version string, then the modinfo
blob).  Zenyard's supply-chain story starts from answers like these
("what is this third-party binary built from"); reportal detected Go
binaries but never read the answers out.

This module scans the stored file bytes for the magic and decodes what
follows it, with no engine, no project context and no writes: the
payload is stored as the ``gobuildinfo`` scan by the caller-shared
:func:`recover`.  The full pclntab function table is deliberately out
of scope: the current function-aligned format needs the varint frame
tables and CU tables to resolve names, which is a parser, not a scan
(the old text-table guess was verified wrong against a real go1.27
binary and removed rather than shipped half-right).  Go function names
already arrive through the existing symbol import when the binary keeps
its ELF symbol table.

:func:`parse_buildinfo` is pure over bytes and returns the version, the
module path, the build settings and the raw build id note when one is
supplied; :func:`recover` locates the magic in the file (bounded scan,
first hit wins) and reads the build id from the note section bytes it
is handed.  A file without the magic is ``not-go`` rather than an
error, so a caller can tell "not a Go binary" from "unreadable".
"""

from __future__ import annotations

import re
import sqlite3
import struct
from pathlib import Path
from typing import Any

from reportal import store

# The stored scan kind the build information is kept under.  Mirrored as
# `store.SCAN_KIND_GOBUILDINFO` so the ratings vocabulary picks it up.
SCAN_KIND = store.SCAN_KIND_GOBUILDINFO

# Magic opening the go.buildinfo payload, and the build settings lines it
# introduces.  The version string follows the magic's pointer block; the
# settings are `key\tvalue` lines after the module path line.
BUILDINFO_MAGIC = b"Go buildinf:"
SETTING_PREFIX = b"build\t"

# Bytes of the file searched for the magic.  A Go binary is megabytes; the
# section sits past the text, so the whole file is scanned but the match
# itself is a single memchr-style find.
MAX_SCAN_BYTES = 256 * 1024 * 1024

# Bytes kept from the modinfo blob.  The settings lines are short; the cap
# only trims a pathological dependency list while the counts stay exact.
MAX_MODINFO_BYTES = 16 * 1024

# A Go version string: `go` plus dotted numbers.  The suffix (a distro tag
# like `-X:nodwarf5`) is matched separately so a trailing dash alone never
# survives: a bare `go1.27.1-` is a truncated match, not a version.
_VERSION_RE = re.compile(rb"go\d+(?:\.\d+)+(?:-[A-Za-z0-9][A-Za-z0-9.\-:]*)?")

# The main module path line inside the modinfo blob.  The blob starts
# mid-window after the version's checksum bytes, so the line is matched by
# pattern rather than by line start.
_MODULE_RE = re.compile(r"path\t(\S+)")


class GobuildinfoError(RuntimeError):
    """Go build information that cannot be recovered."""

    def __init__(self, detail: str, *, code: str = "not-go") -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def parse_buildinfo(data: bytes, *, build_id: str = "") -> dict[str, Any]:
    """Decode the bytes at the ``Go buildinf:`` magic into build information.

    Returns ``{"version", "module", "dependencies", "settings", "build_id"}``
    where ``dependencies`` is one ``{"module", "version"}`` per ``dep``
    line, ``settings`` maps build keys to values and ``module`` is the main
    module path (empty when the blob carries none).  Raises
    :class:`GobuildinfoError` when the magic is absent or no version
    string follows it.
    """
    start = data.find(BUILDINFO_MAGIC)
    if start < 0:
        raise GobuildinfoError("no Go buildinfo magic in the scanned bytes")
    window = data[start : start + MAX_MODINFO_BYTES]
    version = _VERSION_RE.search(window)
    if version is None:
        raise GobuildinfoError("Go buildinfo magic without a version string")
    text = window.decode("utf-8", errors="replace")
    module = ""
    match = _MODULE_RE.search(text)
    if match is not None:
        module = match.group(1)
    settings: dict[str, str] = {}
    dependencies: list[dict[str, str]] = []
    for line in text.splitlines():
        if line.startswith("build\t"):
            rest = line.split("\t", 1)[1]
            key, _, value = rest.partition("=")
            settings[key.strip()] = value.strip()
        elif line.startswith("dep\t"):
            parts = line.split("\t")
            if len(parts) >= 3 and parts[1].strip() and parts[2].strip():
                dependencies.append({"module": parts[1].strip(), "version": parts[2].strip()})
    return {
        "version": version.group(0).decode("ascii"),
        "module": module,
        "dependencies": dependencies,
        "settings": settings,
        "build_id": build_id,
    }


def build_id_from_note(data: bytes) -> str:
    """The build id from ``.note.go.buildid`` section *data*, or empty.

    Skips the ELF note header (namesz, descsz, type) and the owner name;
    the descriptor is the build id.  The note header follows the ELF file's
    endianness, so both little- and big-endian layouts are tried; a header
    whose owner name is not ``Go`` is refused.  Anything malformed answers
    empty rather than guessing.
    """
    if len(data) < 12:
        return ""
    for endian in ("<", ">"):
        namesz, descsz, _ = struct.unpack_from(f"{endian}3I", data, 0)
        if namesz < 2 or descsz < 1:
            continue
        name_end = 12 + namesz
        desc_start = 12 + ((namesz + 3) & ~3)
        if name_end > len(data) or desc_start + descsz > len(data):
            continue
        if not data[12:name_end].startswith(b"Go"):
            continue
        blob = data[desc_start : desc_start + descsz]
        text = blob.decode("utf-8", errors="replace").strip("\x00").strip()
        if text:
            return text
    return ""


def recover(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    data: bytes | None = None,
    build_id: str = "",
) -> dict[str, Any]:
    """Recover a binary's Go build information and store it as a scan.

    The binary's file is resolved from the stored row; *data* overrides
    the scanned bytes outright and *build_id* the note-derived id, which
    is how tests keep the run hermetic.  Nothing is renamed and no
    engine runs.

    Raises :class:`KeyError` for an unknown binary,
    :class:`FileNotFoundError` when its row has no file on disk and
    :class:`GobuildinfoError` when the file is not a Go binary.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")
    if data is None:
        path = Path(str(binary["path"]))
        if not path.is_file():
            raise FileNotFoundError(f"binary {binary_id} has no file at {path}")
        try:
            size = path.stat().st_size
            with open(path, "rb") as handle:
                data = handle.read(min(size, MAX_SCAN_BYTES))
        except OSError as exc:
            raise GobuildinfoError(f"cannot read binary file: {exc}", code="unreadable") from exc
    payload = {"binary_id": binary_id, **parse_buildinfo(data, build_id=build_id)}
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, SCAN_KIND, payload, params={})
    return payload

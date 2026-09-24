"""Portable match corpora: named functions and their listings, carried between workspaces.

The hosted portal matches a binary against a large corpus of known functions it
keeps on its own servers.  reportal's matcher scores against every function its
store holds and reads a function's listing from ``disasm_cache`` first, so a
function with a stored listing is a match candidate without its binary file or
an engine.  A corpus pack is that: one gzip JSON file of binaries, each with its
named functions (a placeholder name transfers nothing) and their assembly
listings.

:func:`export_pack` writes one from any set of stored binaries, computing a
listing the cache lacks through the engine where the binary has a rebrew
context; :func:`import_pack` registers the pack's binaries as match candidates
in another workspace, so a corpus built once (from many projects, or a team's
reviewed work) serves every install that imports it.  A binary the importing
workspace already holds is left alone: its own analysis is the authority.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path
from typing import Any

from reportal import engines, function_triage, matching, store
from reportal.rebrew_import import sha256_file

# The pack's self-description; an import refuses any other format or a newer version.
PACK_FORMAT = "reportal-corpus"
PACK_VERSION = 1

# Engine label of the analysis an import creates, so a re-import refreshes it.
IMPORT_ENGINE = "corpus-pack"

# Functions a pack leaves out: an import thunk is one indirect jump, so every
# thunk's listing looks like every other's and would match on shape alone, and
# an import known only by ordinal carries no name worth transferring.
EXCLUDED_STATUSES = frozenset({"THUNK"})
ORDINAL_PREFIX = "ordinal_"

# A library function this short is a stub or a trampoline: its listing matches
# unrelated code on shape alone, so a library pack leaves it out.
MIN_LIBRARY_FUNCTION_BYTES = 16

# How a library pack describes its binaries and functions.
LIBRARY_FORMAT = "lib"
LIBRARY_STATUS = "LIBRARY"
LIBRARY_NAME_SOURCE = "library"

# Status an imported function carries when the pack names none.
DEFAULT_STATUS = "STUB"


class CorpusError(Exception):
    """A pack that cannot be written or read."""


def _named_functions(
    conn: sqlite3.Connection, binary_id: int, disassemble: matching.Disassembler
) -> list[dict[str, Any]]:
    """The binary's functions that carry a real name and a listing, in VA order."""
    functions: list[dict[str, Any]] = []
    for function in store.list_binary_functions(conn, binary_id=binary_id):
        name = str(function["name"] or "")
        if function_triage.is_placeholder_name(name) or name.startswith(ORDINAL_PREFIX):
            continue
        if str(function["status"] or "").upper() in EXCLUDED_STATUSES:
            continue
        listing = disassemble({**function, "binary_id": binary_id})
        if not listing:
            continue
        functions.append(
            {
                "va": int(function["va"]),
                "size": int(function["size"]),
                "name": name,
                "status": str(function["status"] or DEFAULT_STATUS),
                "name_source": str(function["name_source"] or ""),
                "listing": listing,
            }
        )
    return sorted(functions, key=lambda entry: entry["va"])


def export_pack(
    conn: sqlite3.Connection,
    path: Path,
    *,
    binary_ids: list[int] | None = None,
    engine: engines.RebrewEngine | None = None,
) -> dict[str, Any]:
    """Write the named functions of *binary_ids* (every binary when None) to *path*.

    Returns ``{"path", "binaries", "functions"}``: the file and what went into
    it.  A binary with no named function that has a listing is left out rather
    than written empty.  Raises :class:`CorpusError` for an unknown binary id.
    """
    disassemble = matching.cached_disassembler(
        conn, engine if engine is not None else engines.get_engine()
    )
    ids = (
        [int(row["id"]) for row in store.list_binaries(conn)] if binary_ids is None else binary_ids
    )
    binaries: list[dict[str, Any]] = []
    for binary_id in ids:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            raise CorpusError(f"no binary with id {binary_id}")
        if not binary["sha256"]:  # a pack binary is keyed by its content hash
            continue
        functions = _named_functions(conn, binary_id, disassemble)
        if not functions:
            continue
        binaries.append(
            {
                "sha256": binary["sha256"],
                "name": str(binary["name"]),
                "format": str(binary["format_override"] or binary["format"] or ""),
                "arch": str(binary["arch_override"] or binary["arch"] or ""),
                "functions": functions,
            }
        )
    return _write_pack(path, binaries)


def pack_from_libraries(
    libraries: list[Path],
    path: Path,
    *,
    engine: engines.RebrewEngine | None = None,
) -> dict[str, Any]:
    """Write the named functions of static libraries as a pack at *path*.

    The known-library half of a match corpus: every function a ``.lib`` or
    ``.a`` defines, named by its symbol and listed from its object code.  One
    pack binary per library, keyed by the library file's sha256; functions are
    laid out one after another from offset 0 (an object carries no address),
    and a function under :data:`MIN_LIBRARY_FUNCTION_BYTES` (a stub or a
    trampoline, which matches on shape alone) or with a placeholder name is left
    out.  The pack binary carries the ISA its objects were compiled for, each
    listing in that ISA's :func:`engines.listing_format`.  Raises
    :class:`CorpusError` for a library the engine cannot read or whose objects
    mix ISAs.
    """
    active = engine if engine is not None else engines.get_engine()
    binaries: list[dict[str, Any]] = []
    for library in libraries:
        try:
            extracted = active.library_functions(library)
        except engines.EngineError as exc:
            raise CorpusError(f"{library}: {exc}") from None
        arches = sorted({str(function["arch"]) for function in extracted})
        if len(arches) > 1:
            raise CorpusError(f"{library}: objects of more than one ISA ({', '.join(arches)})")
        functions: list[dict[str, Any]] = []
        va = 0
        for function in extracted:
            size = int(function["size"])
            name = str(function["name"])
            if size < MIN_LIBRARY_FUNCTION_BYTES or function_triage.is_placeholder_name(name):
                continue
            functions.append(
                {
                    "va": va,
                    "size": size,
                    "name": name,
                    "status": LIBRARY_STATUS,
                    "name_source": LIBRARY_NAME_SOURCE,
                    "listing": str(function["listing"]),
                }
            )
            va += size
        if functions:
            binaries.append(
                {
                    "sha256": sha256_file(library),
                    "name": library.name,
                    "format": LIBRARY_FORMAT,
                    "arch": arches[0],
                    "functions": functions,
                }
            )
    return _write_pack(path, binaries)


def _write_pack(path: Path, binaries: list[dict[str, Any]]) -> dict[str, Any]:
    """Write *binaries* as a pack at *path*; returns the export summary."""
    pack = {"format": PACK_FORMAT, "version": PACK_VERSION, "binaries": binaries}
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(pack, handle)
    return {
        "path": str(path),
        "binaries": len(binaries),
        "functions": sum(len(entry["functions"]) for entry in binaries),
    }


def _read_pack(path: Path) -> dict[str, Any]:
    """The pack at *path*, validated for its format and version."""
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            pack = json.load(handle)
    except (OSError, EOFError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CorpusError(f"{path} is not a readable corpus pack: {exc}") from None
    if not isinstance(pack, dict) or pack.get("format") != PACK_FORMAT:
        raise CorpusError(f"{path} is not a {PACK_FORMAT} pack")
    version = pack.get("version")
    if not isinstance(version, int) or version > PACK_VERSION:
        raise CorpusError(f"{path} is pack version {version!r}; this reportal reads {PACK_VERSION}")
    if not isinstance(pack.get("binaries"), list):
        raise CorpusError(f"{path} carries no binaries list")
    return pack


def _function_entry(raw: Any) -> dict[str, Any] | None:
    """One pack function, or None when it is malformed."""
    if not isinstance(raw, dict):
        return None
    va, size, name, listing = raw.get("va"), raw.get("size"), raw.get("name"), raw.get("listing")
    if not (isinstance(va, int) and isinstance(size, int) and size > 0):
        return None
    if not (isinstance(name, str) and name.strip() and isinstance(listing, str) and listing):
        return None
    return {
        "va": va,
        "size": size,
        "name": name.strip(),
        "status": str(raw.get("status") or DEFAULT_STATUS),
        "name_source": str(raw.get("name_source") or "corpus"),
        "listing": listing,
    }


def import_pack(conn: sqlite3.Connection, path: Path) -> dict[str, Any]:
    """Register the pack at *path* as match candidates; returns what it did.

    Each pack binary becomes a binary row with no file (keyed by its sha256, so
    a re-import refreshes it) and one ``corpus-pack`` analysis holding its
    functions and their listings; a re-import drops the functions the pack no
    longer carries (``pruned``).  A binary this workspace already has under
    another analysis is skipped, and a malformed function entry is counted and
    skipped rather than failing the pack.  Raises :class:`CorpusError` for a
    file that is not a readable pack.
    """
    pack = _read_pack(path)
    imported = skipped_binaries = functions = malformed = pruned = 0
    for raw in pack["binaries"]:
        if not isinstance(raw, dict) or not isinstance(raw.get("sha256"), str):
            malformed += 1
            continue
        sha256 = str(raw["sha256"])
        existing = store.find_binary_by_sha256(conn, sha256)
        if (
            existing is not None
            and store.find_analysis(conn, binary_id=int(existing["id"]), engine=IMPORT_ENGINE)
            is None
        ):
            skipped_binaries += 1
            continue
        binary_id = store.add_binary(
            conn,
            sha256=sha256,
            name=str(raw.get("name") or sha256),
            fmt=str(raw.get("format") or ""),
            arch=str(raw.get("arch") or ""),
        )
        analysis = store.find_analysis(conn, binary_id=binary_id, engine=IMPORT_ENGINE)
        analysis_id = (
            int(analysis["id"])
            if analysis is not None
            else store.create_analysis(
                conn, binary_id=binary_id, engine=IMPORT_ENGINE, status="done", log=f"from {path}"
            )
        )
        kept: set[int] = set()
        for entry in raw.get("functions") or []:
            function = _function_entry(entry)
            if function is None:
                malformed += 1
                continue
            kept.add(function["va"])
            function_id, _created = store.upsert_function(
                conn,
                analysis_id=analysis_id,
                va=function["va"],
                name=function["name"],
                size=function["size"],
                status=function["status"],
                name_source=function["name_source"],
            )
            store.set_disasm(conn, function_id, function["listing"])
            functions += 1
        pruned += store.prune_analysis_functions(conn, analysis_id, kept)
        imported += 1
    return {
        "path": str(path),
        "binaries": imported,
        "functions": functions,
        "skipped_binaries": skipped_binaries,
        "malformed": malformed,
        "pruned": pruned,
    }


def pack_summary(path: Path) -> dict[str, Any]:
    """What a pack holds, without importing it."""
    pack = _read_pack(path)
    binaries = [entry for entry in pack["binaries"] if isinstance(entry, dict)]
    functions = sum(
        len(entry["functions"]) for entry in binaries if isinstance(entry.get("functions"), list)
    )
    return {
        "path": str(path),
        "version": pack["version"],
        "binaries": len(binaries),
        "functions": functions,
    }

"""Journaled binary extract, carve and unpack actions.

Shared by the HTTP routes, the CLI and the MCP tools.  Lives outside
:mod:`reportal.api` so transport modules do not become the home of domain
writes, and so MCP/CLI need not import the JSON route module to unpack an
archive or rebuild a packed image.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
import tempfile
import unicodedata
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from reportal import archive, effects, engines, firmware, journal, store, unpack
from reportal._paths import binaries_dir

# Read size while hashing a member on disk.
_UPLOAD_CHUNK_BYTES = 1024 * 1024

# Shape of the suffix kept from a member filename.  Anything else is dropped
# rather than passed through, so no archive-supplied text reaches the stored
# file name.
_UPLOAD_SUFFIX = re.compile(r"^\.[A-Za-z0-9]{1,8}$")


def _upload_suffix(raw_filename: str) -> str:
    """Return the accepted suffix of a member filename, else ""."""
    suffix = Path(raw_filename).suffix
    return suffix if _UPLOAD_SUFFIX.match(suffix) else ""


def _client_name(raw_filename: str) -> str:
    """Return the display name a filename suggests, else "".

    Only the basename is kept, and a name that survives as a path component
    (``.`` or ``..``) is dropped so the caller falls back to the content hash.
    The basename is NFC-normalized so a macOS NFD member name matches an NFC
    rename of the same spelling.
    """
    candidate = unicodedata.normalize("NFC", Path(raw_filename).name)
    return "" if candidate in {"", ".", ".."} else candidate


class ExtractError(Exception):
    """An archive extraction the caller refuses, as ``(status, code, detail)``."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


def _sha256_file(path: Path) -> str:
    """The sha256 of *path*, streamed so a large member is never buffered."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_UPLOAD_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _member_collection_name(binary: Mapping[str, Any]) -> str:
    """The default collection name an archive's extracted binaries join."""
    return f"{binary.get('name') or 'archive'} extraction"


def _resolve_extract_collection(
    conn: sqlite3.Connection,
    log: journal.Journal,
    binary: Mapping[str, Any],
    collection_id: int,
) -> tuple[int, str]:
    """Return the collection an extraction joins, creating a default when none is named."""
    if collection_id:
        row = store.get_collection(conn, collection_id)
        if row is None:
            raise ExtractError(
                404, "collection not found", f"no collection with id {collection_id}"
            )
        return collection_id, str(row["name"])
    name = _member_collection_name(binary)
    existing = store.find_collection_by_name(conn, name)
    if existing is not None:
        return int(existing["id"]), str(existing["name"])
    created = store.create_collection(
        conn,
        name=name,
        description=f"binaries extracted from {binary.get('name') or 'an archive'}",
        scope="binary",
    )
    log.record(
        effects.EFFECT_ROW_DELETE,
        f"created collection {created}",
        journal.row_delete_descriptor("collections", created),
    )
    return created, name


def _register_member(
    conn: sqlite3.Connection,
    log: journal.Journal,
    member: archive.MemberOutcome,
    directory: Path,
) -> dict[str, Any]:
    """Register one extracted member as a stored binary, or report it as a duplicate."""
    if member.path is None:
        return {
            "name": member.name,
            "size": member.size,
            "binary_id": None,
            "duplicate": False,
            "skipped": member.skipped,
        }
    display = PurePosixPath(member.name).name or member.name
    sha256 = _sha256_file(member.path)
    size = member.path.stat().st_size
    existing = store.find_binary_by_sha256(conn, sha256)
    if existing is not None:
        binary_id = int(existing["id"])
        member.path.unlink(missing_ok=True)
        duplicate = True
    else:
        suffix = _upload_suffix(display)
        target = directory / f"{sha256}{suffix}"
        os.replace(member.path, target)
        binary_id = store.add_binary(
            conn,
            sha256=sha256,
            name=display or sha256,
            path=str(target),
            size=size,
            fmt=suffix.lstrip(".").upper(),
        )
        duplicate = False
        log.record(
            effects.EFFECT_FILE_DELETE,
            f"stored extracted file {target}",
            journal.file_delete_descriptor(str(target)),
        )
        log.record(
            effects.EFFECT_ROW_DELETE,
            f"registered extracted binary {binary_id}",
            journal.row_delete_descriptor("binaries", binary_id),
        )
    return {
        "name": display,
        "size": size,
        "binary_id": binary_id,
        "duplicate": duplicate,
        "skipped": "",
    }


def extract_archive_binary(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    password: str = "",
    collection_id: int = 0,
) -> dict[str, Any]:
    """Unpack the stored archive *binary_id* and register the binaries it holds.

    Shared by the HTTP route, the CLI and the MCP tool.  Members are extracted
    into a temporary directory under the workspace `binaries/` directory (never
    outside it) and every member that survives :mod:`reportal.archive`'s safety
    checks is registered by content hash exactly like an upload.  The binaries
    land in one collection (the named one, else one named after the archive,
    created on demand).  Raises :class:`ExtractError` for an unknown binary, a
    row without a file, an unknown collection, or an archive reportal cannot
    read at all.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise ExtractError(404, "binary not found", f"no binary with id {binary_id}")
    archive_path = Path(str(binary["path"]))
    if not archive_path.is_file():
        raise ExtractError(
            400, "binary not on disk", f"binary {binary_id} has no file at {binary['path']!r}"
        )
    directory = binaries_dir()
    directory.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(dir=directory, prefix=".extract-"))
    try:
        try:
            extraction = archive.extract(archive_path, temp_root, password=password or None)
        except archive.ArchiveError as exc:
            raise ExtractError(400, exc.code, exc.detail) from None
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            resolved_id, collection_name = _resolve_extract_collection(
                conn, log, binary, collection_id
            )
            members: list[dict[str, Any]] = []
            for member in extraction.members:
                entry = _register_member(conn, log, member, directory)
                registered = entry["binary_id"]
                if registered is not None and store.add_collection_binary(
                    conn, resolved_id, int(registered)
                ):
                    log.record(
                        effects.EFFECT_ROW_DELETE,
                        f"added binary {registered} to collection {resolved_id}",
                        journal.row_delete_descriptor(
                            "collection_binaries",
                            {"collection_id": resolved_id, "binary_id": registered},
                        ),
                    )
                members.append(entry)
        return log.attach(
            {
                "binary_id": binary_id,
                "collection_id": resolved_id,
                "collection_name": collection_name,
                "members": members,
                "notes": list(extraction.notes),
                "kept": sum(1 for row in members if row["skipped"] == ""),
                "skipped": sum(1 for row in members if row["skipped"] != ""),
            }
        )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def firmware_carve_binary(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Carve *binary_id* and store the pass as its ``firmware`` scan; journaled.

    Shared by the HTTP route, the CLI and the MCP tool, and wired the way every
    other scan route is: `journal.journaled_scan` journals the `scans` row the
    pass creates or replaces, and the analysis row only when the pass created it,
    so reverting the action takes the stored carve back.  Raises
    :class:`ExtractError` for an unknown binary or a row without a file, so the
    three surfaces report the same vocabulary.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise ExtractError(404, "binary not found", f"no binary with id {binary_id}")
    if not Path(str(binary["path"])).is_file():
        raise ExtractError(
            400, "binary not on disk", f"binary {binary_id} has no file at {binary['path']!r}"
        )
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        try:
            payload = journal.journaled_scan(
                conn,
                log,
                binary_id,
                firmware.SCAN_KIND,
                lambda: firmware.scan(conn, binary_id),
                engine="firmware",
            )
        except firmware.FirmwareError as exc:
            status = 404 if exc.code.endswith("not found") else 400
            raise ExtractError(status, exc.code, exc.detail) from None
    return log.attach(payload)


def firmware_extract_binary(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    region_indexes: Sequence[int] | None = None,
    collection_id: int = 0,
) -> dict[str, Any]:
    """Carve the regions of a stored firmware and register what they hold.

    One journal action covers the whole request: a region the archive reader
    can unpack (`reportal.firmware.ARCHIVE_SUFFIXES`) contributes its members,
    and every other region is written out as a binary of its own with its
    provenance recorded (the source binary, the offset and the kind).  Nothing
    is executed: this reads bytes and copies them.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise ExtractError(404, "binary not found", f"no binary with id {binary_id}")
    source = Path(str(binary["path"]))
    if not source.is_file():
        raise ExtractError(
            400, "binary not on disk", f"binary {binary_id} has no file at {binary['path']!r}"
        )
    stored = firmware.regions(conn, binary_id)
    if stored is None:
        raise ExtractError(
            404,
            "no-scan",
            f"binary {binary_id} has no firmware scan; run 'reportal firmware {binary_id}' first",
        )
    available = stored.get("regions") or []
    selected = list(range(len(available))) if region_indexes is None else list(region_indexes)
    if not selected:
        raise ExtractError(400, "invalid-region", "at least one region index is required")
    directory = binaries_dir()
    directory.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(dir=directory, prefix=".carve-"))
    try:
        resolved_regions: list[dict[str, Any]] = []
        for index in selected:
            try:
                entry = firmware.region(source, index=index, regions_payload=stored)
            except firmware.FirmwareError as exc:
                status = 404 if exc.code.endswith("not found") else 400
                raise ExtractError(status, exc.code, exc.detail) from None
            target = temp_root / entry["name"]
            firmware.write_region(source, target, offset=entry["offset"], size=entry["size"])
            resolved_regions.append(entry)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            resolved_id, collection_name = _resolve_extract_collection(
                conn, log, binary, collection_id
            )
            members: list[dict[str, Any]] = []
            for entry in resolved_regions:
                target = temp_root / entry["name"]
                if entry["extractable"]:
                    try:
                        extraction = archive.extract(target, temp_root)
                    except archive.ArchiveError as exc:
                        members.append(
                            {
                                "region": entry["index"],
                                "kind": entry["kind"],
                                "name": entry["name"],
                                "size": entry["size"],
                                "binary_id": None,
                                "duplicate": False,
                                "skipped": exc.code,
                            }
                        )
                        continue
                    for member in extraction.members:
                        registered = _register_member(conn, log, member, directory)
                        registered["region"] = entry["index"]
                        registered["kind"] = entry["kind"]
                        _link_member(conn, log, resolved_id, registered)
                        members.append(registered)
                    continue
                registered = _register_member(
                    conn,
                    log,
                    archive.MemberOutcome(
                        name=entry["name"], size=target.stat().st_size, path=target
                    ),
                    directory,
                )
                registered["region"] = entry["index"]
                registered["kind"] = entry["kind"]
                _link_member(conn, log, resolved_id, registered)
                members.append(registered)
        return log.attach(
            {
                "binary_id": binary_id,
                "collection_id": resolved_id,
                "collection_name": collection_name,
                "regions": resolved_regions,
                "members": members,
                "kept": sum(1 for row in members if row["skipped"] == ""),
                "skipped": sum(1 for row in members if row["skipped"] != ""),
                "note": (
                    "a carved region that is not a gzip, tar or zip is stored as a binary of"
                    " its own; reportal reads no filesystem inode table"
                ),
            }
        )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _link_member(
    conn: sqlite3.Connection,
    log: journal.Journal,
    collection_id: int,
    registered: dict[str, Any],
) -> None:
    """Add a registered member to the extraction's collection, journaled."""
    binary_id = registered.get("binary_id")
    if binary_id is None or not store.add_collection_binary(conn, collection_id, int(binary_id)):
        return
    log.record(
        effects.EFFECT_ROW_DELETE,
        f"added binary {binary_id} to collection {collection_id}",
        journal.row_delete_descriptor(
            "collection_binaries",
            {"collection_id": collection_id, "binary_id": int(binary_id)},
        ),
    )


def _unpacked_name(binary_name: str) -> str:
    """The default display name of an unpacked image: source stem, ``unpacked``, suffix."""
    candidate = Path(binary_name).name
    return f"{Path(candidate).stem or 'binary'}.unpacked{Path(candidate).suffix}"


def unpack_binary(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    packer: str = "",
    name: str = "",
) -> dict[str, Any]:
    """Rebuild a packed binary's image and register it as a new binary.

    The packer is the caller's when *packer* names one, else the one the source
    file's own stub identifies.  The rebuilt image is written into the workspace
    `binaries/` directory and registered by content hash exactly like an upload,
    so unpacking the same sample twice resolves to the binary already stored
    instead of a second copy.  The new binary carries the provenance as its
    ``unpack`` scan: the source binary and its hash, the packer, the method and
    the sizes, journaled with the row, so one revert removes the scan, the row
    and the file together.  The packed source is never touched.

    Raises :class:`ExtractError` for an unknown binary, a row without a file, an
    unknown or absent packer, and an engine that is not installed.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise ExtractError(404, "binary not found", f"no binary with id {binary_id}")
    source = Path(str(binary["path"]))
    if not source.is_file():
        raise ExtractError(
            400, "binary not on disk", f"binary {binary_id} has no file at {binary['path']!r}"
        )
    chosen = packer.strip().lower()
    if chosen and chosen not in unpack.PACKERS:
        raise ExtractError(
            400,
            unpack.ERROR_UNKNOWN_PACKER,
            f"packer must be one of {', '.join(unpack.PACKERS)}",
        )
    engine = engines.get_engine()
    detected = unpack.detect(source, engine=engine)
    matched = [entry for entry in detected if not chosen or entry["packer"] == chosen]
    if not matched:
        detail = unpack.NO_PACKER_DETAIL.format(binary_id=binary_id, name=str(binary["name"]))
        if chosen:
            detail = f"{detail} that is {chosen}-packed"
        raise ExtractError(400, unpack.ERROR_NO_PACKER, detail)
    entry = matched[0]
    display = _client_name(name) or _unpacked_name(str(binary["name"]))
    directory = binaries_dir()
    directory.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(dir=directory, prefix=".unpack-"))
    try:
        target = temp_root / display
        try:
            method = unpack.unpack_to(source, target, packer=entry["packer"], engine=engine)
        except unpack.UnpackError as exc:
            raise ExtractError(400, exc.code, exc.detail) from None
        except engines.EngineUnavailable as exc:
            raise ExtractError(503, "engine-unavailable", str(exc)) from None
        except engines.EngineError as exc:
            raise ExtractError(400, unpack.ERROR_UNPACK_FAILED, str(exc)) from None
        sha256 = _sha256_file(target)
        notes = [
            unpack.METHOD_NOTES[entry["packer"]].format(tool=unpack.UPX_TOOL),
            unpack.CEILING_NOTE,
            "the rebuilt image is a binary of its own; the packed source is left as it was",
        ]
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            registered = _register_member(
                conn,
                log,
                archive.MemberOutcome(name=display, size=target.stat().st_size, path=target),
                directory,
            )
            new_id = registered["binary_id"]
            stored = new_id is not None and not registered["duplicate"]
            provenance = {
                "binary_id": new_id,
                "stored": stored,
                "source": {
                    "binary_id": binary_id,
                    "name": str(binary["name"]),
                    "sha256": binary["sha256"],
                    "size": int(binary["size"]),
                },
                "packer": entry["packer"],
                "detected": entry["detail"],
                "method": method["method"],
                "tool": method.get("tool", ""),
                "version": method.get("version"),
                "image_size": method.get("image_size"),
                "file_size": method.get("file_size"),
                "unpacked_at": store.now(),
                "notes": list(notes),
            }
            if stored:
                journal.journaled_scan_result(conn, log, int(new_id), unpack.SCAN_KIND, provenance)
            else:
                notes.append(
                    "the rebuilt image matches a binary already stored; its row and its"
                    " provenance were left alone"
                )
        row = None if new_id is None else store.get_binary(conn, int(new_id))
        return log.attach(
            {
                "binary_id": binary_id,
                "source": provenance["source"],
                "packer": entry["packer"],
                "method": method["method"],
                "detected": detected,
                "unpacked": {
                    "binary_id": new_id,
                    "name": display,
                    "sha256": sha256,
                    "path": "" if row is None else str(row["path"]),
                    "duplicate": bool(registered["duplicate"]),
                },
                "provenance": provenance,
                "notes": notes,
            }
        )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


# Filename characters a download may keep.  Everything else becomes an
# underscore so a slash, quote, backslash or newline cannot break a header or
# a path component.
_UNSAFE_FILENAME_CHAR = re.compile(r"[^A-Za-z0-9._-]")

# Windows device names (case-insensitive stem before the first dot).  A browser
# or `reportal download` that saves to a Windows volume cannot create these as
# ordinary files, so a Content-Disposition that keeps them breaks the client
# even when the portal itself runs on Linux.
_WINDOWS_RESERVED_STEMS = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)


def _safe_download_name(raw: str) -> str:
    """One path component safe for a header and for a Windows save dialog."""
    cleaned = _UNSAFE_FILENAME_CHAR.sub("_", raw).strip(" .")
    if not cleaned:
        return ""
    stem = cleaned.split(".", 1)[0]
    if stem.upper() in _WINDOWS_RESERVED_STEMS:
        cleaned = f"_{cleaned}"
    return cleaned


def download_filename(binary: Mapping[str, Any]) -> str:
    """The filename a download of *binary* carries, safe for a header and a path.

    The name is reduced to one path component (so a name carrying a slash
    cannot name a directory) and everything outside
    :data:`_UNSAFE_FILENAME_CHAR`'s set becomes an underscore, so a quote, a
    backslash or a newline cannot break the ``Content-Disposition`` header.
    Windows reserved device stems (``AUX``, ``NUL``, ``COM1``, ...) get a
    leading underscore so a client saving on a Windows volume does not fail.
    A name that reduces to nothing falls back to the content-addressed file
    name reportal stored it under.
    """
    candidate = Path(str(binary.get("name") or "")).name
    cleaned = _safe_download_name(candidate)
    if cleaned:
        return cleaned
    stored = Path(str(binary.get("path") or "")).name
    fallback = _safe_download_name(stored)
    return fallback or f"binary-{int(binary['id'])}"

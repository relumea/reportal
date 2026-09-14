"""Workspace backup and restore: one portable archive of everything local.

reportal keeps its whole state in one directory: a SQLite file, the binaries it
stored, and the generated reports.  This module writes that state as one
gzip-compressed tar and reads it back into a workspace, which is what makes an
install movable and a mistake recoverable.

Two things make the archive honest rather than merely a copy of the files:

* the database is copied through SQLite's own backup API after its WAL is
  checkpointed, so the archive holds one consistent snapshot instead of a
  database file plus an unshipped `-wal` sidecar that would replay writes the
  reader never got;
* the manifest records the absolute workspace root the archive was made in, so a
  restore into a different directory rewrites the stored binary paths to the new
  root.  A path outside the workspace (an imported binary that lives in the
  user's own rebrew project) is left alone and reported, because reportal never
  owned it.

The archive is a tar of relative paths, so it is append-only in practice: a
member outside the manifest's names is refused rather than extracted, which
keeps a crafted archive from writing anywhere the workspace does not expect.
"""

from __future__ import annotations

import io
import json
import shutil
import sqlite3
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from reportal import __version__, store
from reportal._paths import (
    BINARIES_DIR,
    DB_NAME,
    MARKER,
    REPORTS_DIR,
    WorkspaceNotFound,
    project_root,
)

# The manifest a restore validates before it touches anything.  A format the
# reader does not know is refused rather than guessed at.
MANIFEST_NAME = "manifest.json"
FORMAT = "reportal-backup"
FORMAT_VERSION = 1

# Where a restore stages the archive before it swaps it in, so a truncated or
# crafted archive cannot leave a half-written workspace behind.
STAGING_PREFIX = ".restore-"

# The default archive name, and the suffix a caller's name gets when it has none.
DEFAULT_NAME = "reportal-backup.tar.gz"
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz")

# Error codes the CLI and the surfaces report.
ERROR_INVALID_ARCHIVE = "invalid-backup"
ERROR_UNSAFE_ARCHIVE = "unsafe-backup"
ERROR_NOT_A_WORKSPACE = "no-workspace"


class BackupError(Exception):
    """The archive cannot be written or read; ``code`` is the surface's name."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def _workspace() -> Path:
    """The workspace root, or :class:`BackupError` when there is none."""
    try:
        return project_root()
    except WorkspaceNotFound as exc:
        raise BackupError(ERROR_NOT_A_WORKSPACE, str(exc)) from exc


def _checkpoint(db: Path) -> None:
    """Flush the database's WAL into the file so a plain copy is consistent."""
    if not db.is_file():
        return
    connection = sqlite3.connect(db)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.commit()
    finally:
        connection.close()


def _snapshot(source: Path, target: Path) -> None:
    """Copy one SQLite file through the backup API, never as loose bytes."""
    source_connection = sqlite3.connect(source)
    target_connection = sqlite3.connect(target)
    try:
        source_connection.backup(target_connection)
    finally:
        target_connection.close()
        source_connection.close()


def _members(root: Path) -> list[tuple[str, Path]]:
    """Every file the archive carries, as ``(archive name, path)``.

    Only the workspace's own directories are walked: a stored binary's suffix
    stays what its registration gave it, and a missing directory is simply
    absent rather than an error.
    """
    found: list[tuple[str, Path]] = []
    for directory in (BINARIES_DIR, REPORTS_DIR):
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file():
                found.append((str(path.relative_to(root)), path))
    marker = root / MARKER
    if marker.is_file():
        found.append((MARKER, marker))
    return found


def create(
    *,
    output: Path | None = None,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Write one workspace archive and return its manifest plus the path.

    Raises :class:`BackupError` when there is no workspace or the archive cannot
    be written.  The manifest is the archive's own index: a restore refuses an
    archive whose members do not match it.
    """
    root = workspace if workspace is not None else _workspace()
    db = root / DB_NAME
    if not db.is_file():
        raise BackupError(ERROR_NOT_A_WORKSPACE, f"no reportal database at {db}")
    target = output if output is not None else root / DEFAULT_NAME
    if output is not None:
        target = Path(output).expanduser()
    _checkpoint(db)
    members = [(DB_NAME, db), *_members(root)]
    manifest: dict[str, Any] = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "version": __version__,
        "created_at": store.now(),
        "root": str(root.resolve()),
        "members": [name for name, _path in members],
        "counts": {
            "binaries": sum(1 for name, _path in members if name.startswith(f"{BINARIES_DIR}/")),
            "reports": sum(1 for name, _path in members if name.startswith(f"{REPORTS_DIR}/")),
        },
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="reportal-backup-") as staging:
            snapshot = Path(staging) / DB_NAME
            _snapshot(db, snapshot)
            with tarfile.open(target, "w:gz") as archive:
                for name, path in members:
                    source = snapshot if name == DB_NAME else path
                    archive.add(source, arcname=name, recursive=False)
                payload = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
                info = tarfile.TarInfo(MANIFEST_NAME)
                info.size = len(payload)
                info.mtime = 0
                archive.addfile(info, io.BytesIO(payload))
    except OSError as exc:
        raise BackupError(ERROR_INVALID_ARCHIVE, f"cannot write {target}: {exc}") from exc
    return {"path": str(target), "manifest": manifest, "bytes": target.stat().st_size}


def read_manifest(archive: Path) -> dict[str, Any]:
    """The manifest of one archive, validated.

    Raises :class:`BackupError` for an unreadable archive, a missing manifest,
    an unknown format or version, a member the manifest does not name, or a
    member that resolves outside the archive root.
    """
    path = Path(archive).expanduser()
    if not path.is_file():
        raise BackupError(ERROR_INVALID_ARCHIVE, f"no archive at {path}")
    try:
        with tarfile.open(path, "r:gz") as tar:
            names = tar.getnames()
            for name in names:
                if name == MANIFEST_NAME:
                    continue
                if not _safe_member(name):
                    raise BackupError(
                        ERROR_UNSAFE_ARCHIVE, f"archive member {name!r} leaves the archive root"
                    )
            if MANIFEST_NAME not in names:
                raise BackupError(ERROR_INVALID_ARCHIVE, "the archive carries no manifest")
            handle = tar.extractfile(MANIFEST_NAME)
            if handle is None:
                raise BackupError(ERROR_INVALID_ARCHIVE, "the archive carries no manifest")
            manifest = json.loads(handle.read().decode("utf-8"))
    except BackupError:
        raise
    except (tarfile.TarError, json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise BackupError(ERROR_INVALID_ARCHIVE, f"cannot read {path}: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise BackupError(ERROR_INVALID_ARCHIVE, "not a reportal backup archive")
    if manifest.get("format_version") != FORMAT_VERSION:
        raise BackupError(
            ERROR_INVALID_ARCHIVE,
            f"backup format {manifest.get('format_version')!r} is not version {FORMAT_VERSION}",
        )
    declared = {str(name) for name in manifest.get("members") or []}
    present = {name for name in names if name != MANIFEST_NAME}
    extra = present - declared
    if extra:
        raise BackupError(
            ERROR_UNSAFE_ARCHIVE,
            f"archive carries members the manifest does not name: {sorted(extra)}",
        )
    return manifest


def _safe_member(name: str) -> bool:
    """True when one archive member stays inside the archive root."""
    candidate = Path(name)
    if candidate.is_absolute() or name.startswith("/") or ".." in candidate.parts:
        return False
    return name not in {"", "."}


def _rewrite_paths(db: Path, *, old_root: Path, new_root: Path) -> list[dict[str, Any]]:
    """Point every stored path that lived under *old_root* at *new_root*.

    A path outside the old root is left alone and returned as a note: it belongs
    to the user's own files (an imported binary's rebrew project), and rewriting
    it would be a lie about where the file is.
    """
    moved: list[dict[str, Any]] = []
    connection = sqlite3.connect(db)
    connection.row_factory = sqlite3.Row
    try:
        for row in connection.execute("SELECT id, path FROM binaries").fetchall():
            stored = str(row["path"] or "")
            if not stored:
                continue
            candidate = Path(stored)
            try:
                relative = candidate.resolve().relative_to(old_root)
            except (OSError, ValueError):
                moved.append({"binary_id": int(row["id"]), "path": stored, "rewritten": False})
                continue
            updated = str(new_root / relative)
            if updated == stored:
                continue
            connection.execute(
                "UPDATE binaries SET path = ? WHERE id = ?", (updated, int(row["id"]))
            )
            moved.append({"binary_id": int(row["id"]), "path": updated, "rewritten": True})
        connection.commit()
    finally:
        connection.close()
    return moved


def restore(
    archive: Path,
    *,
    workspace: Path | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Read one archive back into a workspace and return what it restored.

    The archive is staged in a temporary directory, validated against its own
    manifest, and only then moved into place, so a refused archive leaves the
    workspace exactly as it was.  A workspace that already holds a database is
    refused unless *overwrite*, which is the destructive half; the caller
    confirms it.  Stored binary paths that lived under the archive's root are
    rewritten to the new root, and the ones that did not are reported.
    """
    manifest = read_manifest(archive)
    root = workspace if workspace is not None else _workspace()
    root = Path(root)
    db = root / DB_NAME
    if db.exists() and not overwrite:
        raise BackupError(
            ERROR_NOT_A_WORKSPACE,
            f"{db} already exists; pass overwrite to replace the workspace's state",
        )
    old_root = Path(str(manifest.get("root") or "")).resolve()
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=STAGING_PREFIX, dir=root) as staging:
        staged = Path(staging)
        try:
            with tarfile.open(Path(archive).expanduser(), "r:gz") as tar:
                tar.extractall(staged, filter="data")
        except (tarfile.TarError, OSError) as exc:
            raise BackupError(ERROR_INVALID_ARCHIVE, f"cannot extract {archive}: {exc}") from exc
        staged_db = staged / DB_NAME
        if not staged_db.is_file():
            raise BackupError(ERROR_INVALID_ARCHIVE, "the archive carries no database")
        moved = _rewrite_paths(staged_db, old_root=old_root, new_root=root.resolve())
        for directory in (BINARIES_DIR, REPORTS_DIR):
            source = staged / directory
            if source.is_dir():
                destination = root / directory
                if destination.is_dir() and overwrite:
                    shutil.rmtree(destination)
                destination.mkdir(parents=True, exist_ok=True)
                for entry in sorted(source.rglob("*")):
                    if not entry.is_file():
                        continue
                    target = destination / entry.relative_to(source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(entry), str(target))
        marker = staged / MARKER
        if marker.is_file() and (overwrite or not (root / MARKER).exists()):
            shutil.copy2(marker, root / MARKER)
        # The staged database is WAL-checkpointed by the archive's own copy, so
        # it can be moved into place last: the binaries it names are already
        # there, which keeps a half-restored workspace from looking complete.
        for sidecar in (f"{DB_NAME}-wal", f"{DB_NAME}-shm"):
            stale = root / sidecar
            if stale.exists():
                stale.unlink()
        shutil.move(str(staged_db), str(db))
    return {
        "path": str(archive),
        "workspace": str(root),
        "root": str(old_root),
        "version": str(manifest.get("version") or ""),
        "created_at": str(manifest.get("created_at") or ""),
        "counts": manifest.get("counts") or {},
        "members": len(manifest.get("members") or []),
        "paths": moved,
        "rewritten": sum(1 for entry in moved if entry["rewritten"]),
        "external": sum(1 for entry in moved if not entry["rewritten"]),
    }


def describe(archive: Path) -> dict[str, Any]:
    """One archive's manifest as the surfaces report it."""
    manifest = read_manifest(archive)
    return {"path": str(Path(archive).expanduser()), **manifest}


def suggest_name() -> str:
    """The default archive name for the current workspace."""
    stamp = store.now().replace(":", "").replace("-", "")
    return f"reportal-backup-{stamp[:15]}.tar.gz"

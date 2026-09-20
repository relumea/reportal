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

The live database path follows the workspace marker and ``REPORTAL_DB`` the same
way every other command does; the archive always stores that file under the
member name ``reportal.db`` so a restore can place it wherever the restored
marker names.  The default output path is a dated file under a sibling
``reportal-backups/`` directory, never inside the workspace, so an instance wipe
of the workspace cannot take the only copy.

The archive is a tar of relative paths, so it is append-only in practice: a
member outside the manifest's names is refused rather than extracted, which
keeps a crafted archive from writing anywhere the workspace does not expect.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sqlite3
import tarfile
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from reportal import __version__, store, symbols
from reportal._paths import (
    BINARIES_DIR,
    DB_NAME,
    MARKER,
    REPORTS_DIR,
    WorkspaceNotFound,
    database_path,
    db_path,
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

ARCHIVE_SUFFIXES = (".tar.gz", ".tgz")

# How long dated archives are kept by the scheduled prune.  Fourteen days covers
# logical corruption that sits unnoticed past a few daily cycles; shorter than
# that and a bad write that lasted a week has no older snapshot to land on.
DEFAULT_KEEP_DAYS = 14

# How old the newest archive may be before ``reportal doctor`` warns.  Twice the
# daily timer interval, so one missed night is a warning and a healthy schedule
# stays quiet.
FRESH_SECONDS = 48 * 60 * 60

# Sibling directory the default ``reportal backup`` writes into, and the timer's
# packaged destination.  Doctor and prune look here when they exist.
DEFAULT_BACKUP_DIRNAME = "reportal-backups"
TIMER_BACKUP_DIR = Path("/srv/backups")

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


def _resolve_root_and_db(workspace: Path | None) -> tuple[Path, Path]:
    """The workspace root and the live database path for one backup or restore.

    An explicit *workspace* reads the marker's ``[portal] db`` via
    :func:`database_path` and ignores ``REPORTAL_DB``, which is what tests and
    multi-root callers need.  With no override the live process path
    (:func:`db_path`) wins, so an operator who pointed ``REPORTAL_DB`` at the
    real file gets that file in the archive rather than an empty default name
    beside the marker.
    """
    if workspace is not None:
        root = Path(workspace)
        return root, database_path(root)
    return _workspace(), db_path()


def _default_output(root: Path) -> Path:
    """A dated archive path beside the workspace, never inside it.

    Writing the archive into the workspace puts the only copy in the same
    failure domain as the data it protects (instance wipe of the workspace
    directory).  A sibling ``reportal-backups/`` directory survives a workspace
    delete on the same host; operators who need a separate disk still pass
    ``--output``.
    """
    return root.parent / DEFAULT_BACKUP_DIRNAME / suggest_name()


def _sidecar_paths(db: Path) -> list[Path]:
    """The WAL and shared-memory sidecars SQLite keeps beside *db*."""
    return [db.parent / f"{db.name}-wal", db.parent / f"{db.name}-shm"]


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
    try:
        target_connection = sqlite3.connect(target)
        try:
            source_connection.backup(target_connection)
        finally:
            target_connection.close()
    finally:
        source_connection.close()


def _members(root: Path) -> list[tuple[str, Path]]:
    """Every file the archive carries, as ``(archive name, path)``.

    Only the workspace's own directories are walked: a stored binary's suffix
    stays what its registration gave it, and a missing directory is simply
    absent rather than an error.
    """
    found: list[tuple[str, Path]] = []
    for directory in (BINARIES_DIR, REPORTS_DIR, symbols.SYMBOLS_DIR):
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
    archive whose members do not match it.  The live database is always stored
    under the archive name :data:`DB_NAME` so a restore can place it wherever
    the restored marker (or ``REPORTAL_DB``) names.
    """
    root, db = _resolve_root_and_db(workspace)
    if not db.is_file():
        raise BackupError(ERROR_NOT_A_WORKSPACE, f"no reportal database at {db}")
    target = _default_output(root) if output is None else Path(output).expanduser()
    try:
        resolved_target = target.resolve()
        resolved_root = root.resolve()
        if resolved_target == resolved_root or resolved_target.is_relative_to(resolved_root):
            raise BackupError(
                ERROR_INVALID_ARCHIVE,
                f"refusing to write {target} inside the workspace; pass --output outside it",
            )
    except BackupError:
        raise
    except OSError:
        # A missing parent is fine; create() mkdirs it below.  The relative_to
        # check only matters when both paths already resolve.
        pass
    _checkpoint(db)
    members = [(DB_NAME, db), *_members(root)]
    manifest: dict[str, Any] = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "version": __version__,
        "created_at": store.now(),
        "root": str(root.resolve()),
        "database": str(db.resolve()),
        "members": [name for name, _path in members],
        "counts": {
            "binaries": sum(1 for name, _path in members if name.startswith(f"{BINARIES_DIR}/")),
            "reports": sum(1 for name, _path in members if name.startswith(f"{REPORTS_DIR}/")),
            "symbols": sum(
                1 for name, _path in members if name.startswith(f"{symbols.SYMBOLS_DIR}/")
            ),
        },
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="reportal-backup-", dir=target.parent) as staging:
            snapshot = Path(staging) / DB_NAME
            _snapshot(db, snapshot)
            staged = Path(staging) / "archive.tar.gz"
            with tarfile.open(staged, "w:gz") as archive:
                for name, path in members:
                    source = snapshot if name == DB_NAME else path
                    archive.add(source, arcname=name, recursive=False)
                payload = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
                info = tarfile.TarInfo(MANIFEST_NAME)
                info.size = len(payload)
                info.mtime = 0
                archive.addfile(info, io.BytesIO(payload))
            staged.replace(target)
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
    members = manifest.get("members")
    if not isinstance(members, list) or not all(isinstance(name, str) for name in members):
        raise BackupError(ERROR_INVALID_ARCHIVE, "the manifest has no valid member list")
    declared = set(members)
    present = {name for name in names if name != MANIFEST_NAME}
    if len(names) != len(set(names)) or len(members) != len(declared):
        raise BackupError(ERROR_INVALID_ARCHIVE, "the archive carries duplicate members")
    missing = declared - present
    if missing:
        raise BackupError(ERROR_INVALID_ARCHIVE, f"archive is missing members: {sorted(missing)}")
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


def _rewrite_paths(
    db: Path, *, old_root: Path, new_root: Path, table: str = "binaries"
) -> list[dict[str, Any]]:
    """Point every stored path that lived under *old_root* at *new_root*.

    A path outside the old root is left alone and returned as a note: it belongs
    to the user's own files (an imported binary's rebrew project), and rewriting
    it would be a lie about where the file is.
    """
    moved: list[dict[str, Any]] = []
    connection = sqlite3.connect(db)
    connection.row_factory = sqlite3.Row
    try:
        if table not in {"binaries", symbols.TABLE}:
            raise ValueError(f"unsupported path table: {table}")
        if (
            table == symbols.TABLE
            and not connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
            ).fetchone()
        ):
            return moved
        for row in connection.execute(f"SELECT id, path FROM {table}").fetchall():
            stored = str(row["path"] or "")
            if not stored:
                continue
            candidate = Path(stored)
            # A relative path was stored against the archived workspace, not
            # against the process cwd; resolve it under old_root so restore
            # still rewrites it when the operator used a relative add-binary.
            if not candidate.is_absolute():
                candidate = old_root / candidate
            try:
                relative = candidate.resolve().relative_to(old_root.resolve())
            except (OSError, ValueError):
                moved.append({"binary_id": int(row["id"]), "path": stored, "rewritten": False})
                continue
            updated = str(new_root / relative)
            if updated == stored:
                continue
            connection.execute(
                f"UPDATE {table} SET path = ? WHERE id = ?", (updated, int(row["id"]))
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
    rewritten to the new root, and the ones that did not are reported.  The
    database lands at the path the restored marker (or ``REPORTAL_DB``) names,
    not always beside the marker as ``reportal.db``.
    """
    manifest = read_manifest(archive)
    root, _ = _resolve_root_and_db(workspace)
    root = Path(root)
    # Refuse before extracting when the destination already holds a database.
    # The marker may not be present yet on a fresh root, so fall back to the
    # default name the archive itself carries.
    provisional = database_path(root) if (root / MARKER).is_file() else root / DB_NAME
    if workspace is None:
        provisional = db_path()
    if provisional.exists() and not overwrite:
        raise BackupError(
            ERROR_NOT_A_WORKSPACE,
            f"{provisional} already exists; pass overwrite to replace the workspace's state",
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
        _rewrite_paths(staged_db, old_root=old_root, new_root=root.resolve(), table=symbols.TABLE)
        for directory in (BINARIES_DIR, REPORTS_DIR, symbols.SYMBOLS_DIR):
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
        # Resolve the live destination only after the marker is in place, so a
        # custom ``[portal] db`` from the archive is honoured.  REPORTAL_DB still
        # wins when this restore is the process-wide workspace.
        db = db_path() if workspace is None else database_path(root)
        db.parent.mkdir(parents=True, exist_ok=True)
        # The staged database is WAL-checkpointed by the archive's own copy, so
        # it can be moved into place last: the binaries it names are already
        # there, which keeps a half-restored workspace from looking complete.
        for stale in _sidecar_paths(db):
            if stale.exists():
                stale.unlink()
        if db.exists():
            db.unlink()
        shutil.move(str(staged_db), str(db))
    return {
        "path": str(archive),
        "workspace": str(root),
        "database": str(db),
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
    """The default archive name for the current workspace.

    Parsed from :func:`reportal.store.now` so the stamp is always the UTC
    calendar instant, not a host-local wall time, and so a future change to the
    ISO form (offset sign, fractional seconds) cannot scramble the filename the
    way a raw ``replace("-", "")`` on the offset would.
    """
    stamp = datetime.fromisoformat(store.now()).astimezone(UTC).strftime("%Y%m%dT%H%M%S")
    return f"reportal-backup-{stamp}.tar.gz"


def is_archive_name(name: str) -> bool:
    """True when *name* looks like a reportal workspace archive filename.

    Matches both the CLI default (``reportal-backup-…``) and the timer's
    ``reportal-…`` prefix so prune and doctor share one recognition rule.
    """
    lower = name.lower()
    if not lower.startswith("reportal"):
        return False
    return any(lower.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def list_archives(directory: Path) -> list[Path]:
    """Every reportal archive file directly under *directory*, oldest first."""
    root = Path(directory)
    if not root.is_dir():
        return []
    found = [path for path in root.iterdir() if path.is_file() and is_archive_name(path.name)]
    return sorted(found, key=lambda path: path.stat().st_mtime)


def archive_dirs(workspace: Path | None = None) -> list[Path]:
    """Directories that may hold archives for *workspace*, when they exist.

    Looks at the sibling ``reportal-backups/`` next to the workspace and at the
    packaged timer destination ``/srv/backups``.  Missing directories are omitted
    rather than created: doctor and prune never invent a backup location.
    """
    found: list[Path] = []
    if workspace is not None:
        sibling = Path(workspace).resolve().parent / DEFAULT_BACKUP_DIRNAME
        if sibling.is_dir():
            found.append(sibling)
    if TIMER_BACKUP_DIR.is_dir() and TIMER_BACKUP_DIR not in found:
        found.append(TIMER_BACKUP_DIR)
    return found


def newest_archive(workspace: Path | None = None) -> Path | None:
    """The most recently modified archive beside *workspace*, or None."""
    archives: list[Path] = []
    for directory in archive_dirs(workspace):
        archives.extend(list_archives(directory))
    if not archives:
        return None
    return max(archives, key=lambda path: path.stat().st_mtime)


def prune(
    *,
    directory: Path,
    keep_days: int = DEFAULT_KEEP_DAYS,
    dry_run: bool = False,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Delete reportal archives in *directory* older than *keep_days*.

    Only files whose names match :func:`is_archive_name` are touched, so a
    shared backup volume's other tenants are left alone.  Refuses a directory
    inside the workspace for the same wipe-domain reason as :func:`create`.
    A *keep_days* of zero keeps nothing older than this instant (everything
    already written is eligible); negative values are refused.
    """
    if keep_days < 0:
        raise BackupError(ERROR_INVALID_ARCHIVE, f"keep_days must be >= 0, got {keep_days}")
    target = Path(directory).expanduser()
    if not target.is_dir():
        raise BackupError(ERROR_INVALID_ARCHIVE, f"no backup directory at {target}")
    root: Path | None
    if workspace is not None:
        root = Path(workspace).resolve()
    else:
        try:
            root = _workspace().resolve()
        except BackupError as exc:
            if exc.code != ERROR_NOT_A_WORKSPACE:
                raise
            root = None
    if root is not None:
        with contextlib.suppress(OSError):
            resolved = target.resolve()
            if resolved == root or resolved.is_relative_to(root):
                raise BackupError(
                    ERROR_INVALID_ARCHIVE,
                    f"refusing to prune {target} inside the workspace",
                )
    cutoff = time.time() - timedelta(days=keep_days).total_seconds()
    removed: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    for path in list_archives(target):
        age = path.stat()
        entry = {
            "path": str(path),
            "bytes": age.st_size,
            "mtime": datetime.fromtimestamp(age.st_mtime, tz=UTC).isoformat(),
        }
        if age.st_mtime >= cutoff:
            kept.append(entry)
            continue
        if not dry_run:
            path.unlink()
        removed.append(entry)
    return {
        "directory": str(target),
        "keep_days": keep_days,
        "dry_run": dry_run,
        "kept": kept,
        "removed": removed,
        "kept_count": len(kept),
        "removed_count": len(removed),
    }

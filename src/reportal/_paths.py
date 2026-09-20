"""Workspace path resolution for reportal.

A reportal workspace is any directory containing a ``reportal.toml`` marker,
found by walking up from the current directory the same way version control
systems locate their root.  Resolution outside a workspace raises
:class:`WorkspaceNotFound` instead of falling back to the current directory.
``REPORTAL_DB`` overrides the database path outright, which is what tests and
multi-workspace setups use; without it the workspace file's ``[portal] db``
names the database, and ``reportal.db`` beside the marker is the default.

The workspace file is the operator's own, so the path it names is resolved the
way an operator reads it: an absolute path is used as written, and a relative
one is taken from the workspace root.  It never escapes into reportal's own
directories, and a file reportal cannot parse falls back to the default rather
than failing every command (``reportal config`` reports that).
"""

from __future__ import annotations

import contextlib
import os
import tempfile
import tomllib
from pathlib import Path

MARKER = "reportal.toml"
DB_ENV = "REPORTAL_DB"
DB_NAME = "reportal.db"

# The table and key ``reportal init`` writes into the marker, naming the
# database beside it.
CONFIG_TABLE = "portal"
CONFIG_DB = "db"

# Workspace subdirectory holding generated engine reports, one per binary id.
REPORTS_DIR = "reports"

# Workspace subdirectory holding binaries uploaded through the portal, stored
# under their content hash.  The caller creates it before writing.
BINARIES_DIR = "binaries"

# Workspace subdirectory holding imported debug symbols, content-addressed by
# the symbol file's own sha256.  ``symbols.py`` re-exports this name.
SYMBOLS_DIR = "symbols"

# Every workspace subdirectory reportal owns.  ``reportal init`` creates them, so
# a fresh workspace has its folders before the first write.  The workspace's own
# ``docs/`` is deliberately absent: an empty one would shadow the shipped manual
# (``docs.documents_dir``).
WORKSPACE_DIRS = (BINARIES_DIR, REPORTS_DIR, SYMBOLS_DIR)

# Temp-file prefix shared by atomic writers that do not need a named kind.
_ATOMIC_PREFIX = ".reportal-"


def write_bytes_atomic(path: Path, data: bytes, *, prefix: str = _ATOMIC_PREFIX) -> Path:
    """Write *data* to *path* through a same-directory temp file and rename.

    Creates the parent directory.  A crash mid-write never leaves a half-written
    *path*; the temp file is removed on failure.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=prefix, suffix=".tmp")
    # fdopen takes ownership only on success; close the raw fd only when it never did.
    owned = True
    try:
        with os.fdopen(handle, "wb") as stream:
            owned = False
            stream.write(data)
        os.replace(temp_name, path)
    except BaseException:
        if owned:
            with contextlib.suppress(OSError):
                os.close(handle)
        raise
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
    return path


def write_text_atomic(path: Path, text: str, *, prefix: str = _ATOMIC_PREFIX) -> Path:
    """Write UTF-8 *text* to *path* through a same-directory temp file and rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=prefix, suffix=".tmp")
    owned = True
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            owned = False
            stream.write(text)
        os.replace(temp_name, path)
    except BaseException:
        if owned:
            with contextlib.suppress(OSError):
                os.close(handle)
        raise
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
    return path


def ensure_workspace_dirs(root: Path) -> list[str]:
    """Create *root*'s workspace subdirectories, returning the names created.

    An existing directory is left alone and not reported, so the answer is the
    folders this call made.
    """
    created: list[str] = []
    for name in WORKSPACE_DIRS:
        directory = root / name
        if not directory.is_dir():
            directory.mkdir(parents=True, exist_ok=True)
            created.append(name)
    return created


class WorkspaceNotFound(FileNotFoundError):  # noqa: N818  # name fixed by the workspace contract
    """No :data:`MARKER` was found walking up from the current directory."""


def project_root() -> Path:
    """Return the nearest ancestor directory containing :data:`MARKER`.

    Raises :class:`WorkspaceNotFound` when no marker exists, so a command run
    outside a workspace fails loud instead of creating a stray database in the
    current directory.
    """
    cwd = Path.cwd().resolve()
    for candidate in (cwd, *cwd.parents):
        if (candidate / MARKER).is_file():
            return candidate
    raise WorkspaceNotFound(f"no reportal workspace found ({MARKER}); run 'reportal init'")


def configured_db_name(root: Path | None = None) -> str:
    """The database name *root*'s workspace file carries, or "" when it names none.

    *root* defaults to the resolved workspace, which is what the process-wide
    :func:`db_path` wants; a caller that already knows the root (``reportal
    init``) passes it instead of changing directory first.  A file reportal
    cannot parse answers "" rather than raising: every command would otherwise
    fail on a typo unrelated to the command, and ``reportal config`` is where
    that typo is reported.
    """
    try:
        workspace = project_root() if root is None else root
        marker = workspace / MARKER
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (WorkspaceNotFound, OSError, tomllib.TOMLDecodeError):
        return ""
    table = document.get(CONFIG_TABLE)
    if not isinstance(table, dict):
        return ""
    value = table.get(CONFIG_DB)
    return value.strip() if isinstance(value, str) else ""


def database_path(root: Path) -> Path:
    """The database *root*'s workspace file names, without the environment override.

    A name the file carries is resolved against *root* (an absolute path is used
    as written), and a workspace naming none reads ``reportal.db`` beside the
    marker.  This is what ``reportal init`` writes, so a marker that names a
    database is honoured before anything else reads it.
    """
    named = configured_db_name(root)
    if not named:
        return root / DB_NAME
    candidate = Path(named).expanduser()
    return candidate if candidate.is_absolute() else root / candidate


def db_path() -> Path:
    """Return the reportal SQLite path: the environment, the file, then the default.

    ``REPORTAL_DB`` wins outright, which is what tests and multi-workspace
    setups use; otherwise the workspace file's ``[portal] db`` answers, and a
    workspace naming none reads ``reportal.db`` beside the marker.
    """
    override = os.environ.get(DB_ENV, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return database_path(project_root())


def reports_dir(binary_id: int) -> Path:
    """Return the workspace report output directory for *binary_id*.

    Reports land under the reportal workspace, never inside the rebrew project
    the binary was imported from.
    """
    return project_root() / REPORTS_DIR / str(binary_id)


def binaries_dir() -> Path:
    """Return the workspace directory holding uploaded binaries.

    Files are named by content hash, so the directory is content-addressed and
    a re-upload lands on the same path.  The directory is not created here; the
    caller does that before its first write.
    """
    return project_root() / BINARIES_DIR


def stored_binary_path(path: str | Path) -> bool:
    """True when *path* names a file reportal itself stored under :func:`binaries_dir`.

    Only an uploaded copy is reportal's to remove when its binary row goes: an
    imported binary lives in the user's rebrew project, so a delete leaves it
    alone.
    """
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        root = binaries_dir().resolve()
        return candidate.resolve().is_relative_to(root)
    except (OSError, WorkspaceNotFound):
        return False


def workspace_root() -> Path:
    """The directory network-facing writers treat as the install root.

    ``REPORTAL_DB`` isolates a process onto one database; its parent is then the
    bound for path checks, matching how tests and multi-root deploys pin the
    DB.  Without the override, the marker walk answers.
    """
    override = os.environ.get(DB_ENV, "").strip()
    if override:
        return Path(override).expanduser().resolve().parent
    return project_root().resolve()


def under_workspace(path: str | Path) -> bool:
    """True when *path* resolves under :func:`workspace_root`.

    Used by network-facing writers (HTTP export, MCP export) so a caller cannot
    name an arbitrary host path.  The CLI still writes wherever the operator
    points; those callers do not go through this check.
    """
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        root = workspace_root()
        return candidate.resolve().is_relative_to(root)
    except (OSError, WorkspaceNotFound):
        return False

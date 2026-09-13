"""Workspace path resolution for reportal.

A reportal workspace is any directory containing a ``reportal.toml`` marker,
found by walking up from the current directory the same way version control
systems locate their root.  Resolution outside a workspace raises
:class:`WorkspaceNotFound` instead of falling back to the current directory.
``REPORTAL_DB`` overrides the database path outright, which is what tests and
multi-workspace setups use.
"""

from __future__ import annotations

import os
from pathlib import Path

MARKER = "reportal.toml"
DB_ENV = "REPORTAL_DB"
DB_NAME = "reportal.db"

# Workspace subdirectory holding generated engine reports, one per binary id.
REPORTS_DIR = "reports"

# Workspace subdirectory holding binaries uploaded through the portal, stored
# under their content hash.  The caller creates it before writing.
BINARIES_DIR = "binaries"


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


def db_path() -> Path:
    """Return the reportal SQLite path, honouring the ``REPORTAL_DB`` override."""
    override = os.environ.get(DB_ENV, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return project_root() / DB_NAME


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

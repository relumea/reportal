"""Workspace git checkouts the agent reads and edits.

A checkout lives under the workspace's ``repos/`` directory: :func:`clone` puts
one there under a validated name, and an operator may clone a project in by
hand, which is how a local decomp or reveng repository joins the workspace.
Every path a caller names is resolved against the checkout's own root and
refused when it resolves outside (``path-outside-repo``), so neither ``..`` nor
a symlink planted inside the checkout reaches the rest of the host.

:func:`clone` is the module's only network path, and it runs behind the guard
the URL ingest already has: :func:`remote_ingest.require_enabled` refuses while
the workspace has not opted in, and :func:`remote_ingest.validate_target`
admits only ``http``/``https`` on an address the URL check accepts.  One flag
(``REPORTAL_ALLOW_REMOTE_INGEST`` or ``[knowledge] allow_remote``) covers both
callers, so an operator learns it once.  The local checks (name, git present,
name still free) run before that URL target, so a refused clone never reaches
the network.  ``allow_loopback`` is the guard's test-only seam, never a request
field.

Nothing here executes the cloned content: files are read as bytes and written
as text, and git runs only ``clone``.  The clone is shallow, runs with
``GIT_TERMINAL_PROMPT=0`` so a credential prompt fails instead of hanging, and
a clone that fails or times out removes its partial directory.  A write is one
atomic file write; git history, not reportal, is the record of what changed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import urllib.parse
from pathlib import Path
from typing import Any

from reportal import knowledge, remote_ingest
from reportal._paths import repos_dir, write_text_atomic

# Error codes the surfaces report; each one has its section in docs/ERRORS.md
# except the ones reused verbatim from an existing catalogue code.
ERROR_REPO_EXISTS = "repo-exists"
ERROR_REPO_NOT_FOUND = "repo-not-found"
ERROR_PATH_OUTSIDE = "path-outside-repo"
ERROR_CLONE_FAILED = "clone-failed"
ERROR_NO_GIT = "external-tool-required"
ERROR_INVALID_NAME = "invalid name"
ERROR_INVALID_PATH = "invalid path"
ERROR_NO_FILE = "no-file"
ERROR_FILE_TOO_LARGE = knowledge.ERROR_FILE_TOO_LARGE
ERROR_UNREADABLE = "unreadable-file"

# Bounds: the longest checkout name, the largest file read or written, the
# most entries one directory listing returns, how long one clone may run, and
# how much of a failed git answer becomes the refusal's detail.
MAX_NAME_CHARS = 80
MAX_FILE_BYTES = 262_144
MAX_ENTRIES = 200
CLONE_TIMEOUT_SECONDS = 120
CLONE_DETAIL_CHARS = 400

# A checkout name: starts alphanumeric, then name characters only, so it can
# never be a path (no separator, no leading dot).
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

# What one listing entry is, without following a link out of the checkout.
_KIND_DIR = "dir"
_KIND_FILE = "file"
_KIND_LINK = "link"
_KIND_OTHER = "other"


class RepoError(Exception):
    """A checkout operation cannot proceed; ``code`` is the surface's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _validated_name(raw: str) -> str:
    """*raw* as a checkout directory name, or the invalid-name refusal."""
    candidate = raw.strip()
    if not candidate or len(candidate) > MAX_NAME_CHARS or not _NAME_RE.fullmatch(candidate):
        raise RepoError(ERROR_INVALID_NAME, f"{raw!r} is not a valid checkout name")
    return candidate


def _name_from_url(url: str) -> str:
    """The checkout name a url implies: its last path segment without ``.git``."""
    segment = Path(urllib.parse.unquote(urllib.parse.urlsplit(url).path)).name
    name = segment.removesuffix(".git")
    if not name:
        raise RepoError(
            ERROR_INVALID_NAME,
            "the url carries no repository name; pass name explicitly",
        )
    return _validated_name(name)


def _checkout(name: str) -> Path:
    """The root of the checkout *name*, refusing an unknown or escaping name."""
    validated = _validated_name(name)
    root = repos_dir()
    try:
        target = (root / validated).resolve()
    except OSError as exc:
        raise RepoError(ERROR_REPO_NOT_FOUND, f"checkout {name!r} is not readable") from exc
    if not target.is_relative_to(root.resolve()):
        raise RepoError(ERROR_PATH_OUTSIDE, f"checkout {name!r} resolves outside the workspace")
    if not target.is_dir():
        raise RepoError(
            ERROR_REPO_NOT_FOUND,
            f"no checkout named {name!r} under repos/; clone it first",
        )
    return target


def _resolve(root: Path, relative: str) -> Path:
    """The path *relative* names inside the checkout root, refusing an escape.

    An empty *relative* is the checkout root itself.  ``resolve`` follows every
    link on the way, so a link inside the checkout that points outside fails the
    ``is_relative_to`` check rather than being read through.
    """
    raw = relative.strip()
    if not raw:
        return root
    candidate = Path(raw)
    if candidate.is_absolute():
        raise RepoError(ERROR_PATH_OUTSIDE, f"path {relative!r} must be relative to the checkout")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise RepoError(ERROR_PATH_OUTSIDE, f"path {relative!r} resolves outside the checkout")
    return resolved


def _git_binary() -> str:
    """The git executable on PATH, or the missing-tool refusal."""
    found = shutil.which("git")
    if found is None:
        raise RepoError(ERROR_NO_GIT, "git is not installed on the portal host")
    return found


def _git(
    arguments: list[str], *, cwd: Path, timeout: int = CLONE_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
    """Run one git command under the checkout root with no credential prompt."""
    environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(
        [_git_binary(), *arguments],
        cwd=str(cwd),
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _failure_detail(process: subprocess.CompletedProcess[str]) -> str:
    """A failed git answer's bounded stderr (or stdout), never an empty refusal."""
    text = (process.stderr or process.stdout or "").strip()
    if not text:
        return "git clone failed"
    return text[-CLONE_DETAIL_CHARS:]


def list_repos() -> dict[str, Any]:
    """Every checkout under ``repos/`` by name, names only."""
    root = repos_dir()
    if not root.is_dir():
        return {"repos": [], "count": 0}
    names = sorted(
        entry.name for entry in root.iterdir() if entry.is_dir() and not entry.name.startswith(".")
    )
    return {"repos": [{"name": name} for name in names], "count": len(names)}


def clone(url: str, *, name: str | None = None, allow_loopback: bool = False) -> dict[str, Any]:
    """Shallow-clone *url* into ``repos/``; returns the stored checkout's facts.

    Runs behind the remote-ingest guard (see the module docstring).  Everything
    local is checked before the URL target: the opt-in, the checkout name, that
    git is installed and that the name is free, so a refused call never reaches
    the network and an existing checkout is refused rather than overwritten.
    A clone that fails or times out leaves nothing behind.  ``allow_loopback``
    is the test-only seam; production callers never pass it.
    """
    remote_ingest.require_enabled()
    checkout = _validated_name(name) if name else _name_from_url(url)
    _git_binary()
    root = repos_dir()
    root.mkdir(parents=True, exist_ok=True)
    target = root / checkout
    if target.exists():
        raise RepoError(ERROR_REPO_EXISTS, f"checkout {checkout!r} already exists")
    normalized, _address = remote_ingest.validate_target(url, allow_loopback=allow_loopback)
    try:
        process = _git(["clone", "--depth", "1", "--", normalized, str(target)], cwd=root)
    except (OSError, subprocess.SubprocessError) as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise RepoError(ERROR_CLONE_FAILED, f"git clone failed: {exc}") from exc
    if process.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        raise RepoError(ERROR_CLONE_FAILED, _failure_detail(process))
    return {"name": checkout, "url": normalized, "path": str(target)}


def tree(name: str, path: str = "") -> dict[str, Any]:
    """One directory of a checkout: its entries' names, kinds and sizes.

    The listing skips ``.git`` (history is not the working tree) and stops at
    :data:`MAX_ENTRIES`, reporting ``truncated`` when it did.
    """
    root = _checkout(name)
    target = _resolve(root, path)
    if not target.is_dir():
        raise RepoError(ERROR_INVALID_PATH, f"{path!r} is not a directory in checkout {name!r}")
    entries: list[dict[str, Any]] = []
    truncated = False
    with os.scandir(target) as directory:
        rows = sorted(directory, key=lambda row: row.name)
    for row in rows:
        if row.name == ".git":
            continue
        if len(entries) >= MAX_ENTRIES:
            truncated = True
            break
        if row.is_dir(follow_symlinks=False):
            kind = _KIND_DIR
            size = None
        elif row.is_file(follow_symlinks=False):
            kind = _KIND_FILE
            size = row.stat(follow_symlinks=False).st_size
        elif row.is_symlink():
            kind = _KIND_LINK
            size = row.stat(follow_symlinks=False).st_size
        else:
            kind = _KIND_OTHER
            size = None
        entries.append({"name": row.name, "kind": kind, "size": size})
    return {
        "repo": name,
        "path": path,
        "entries": entries,
        "count": len(entries),
        "truncated": truncated,
    }


def read_file(name: str, path: str) -> dict[str, Any]:
    """One UTF-8 text file from a checkout, bounded at :data:`MAX_FILE_BYTES`."""
    root = _checkout(name)
    target = _resolve(root, path)
    if target.is_dir():
        raise RepoError(ERROR_INVALID_PATH, f"{path!r} is a directory in checkout {name!r}")
    if not target.is_file():
        raise RepoError(ERROR_NO_FILE, f"no file {path!r} in checkout {name!r}")
    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise RepoError(ERROR_FILE_TOO_LARGE, f"{path!r} exceeds {MAX_FILE_BYTES} bytes")
    data = target.read_bytes()
    if b"\x00" in data:
        raise RepoError(ERROR_UNREADABLE, f"{path!r} is not a text file")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepoError(ERROR_UNREADABLE, f"{path!r} is not UTF-8 text") from exc
    return {"repo": name, "path": path, "bytes": len(data), "text": text}


def write_file(name: str, path: str, content: str) -> dict[str, Any]:
    """Create or overwrite one text file in a checkout, creating its parents.

    The write is atomic (``write_text_atomic``), bounded like a read, and
    refused for a directory or an escaping path before anything is written.
    """
    root = _checkout(name)
    data = content.encode("utf-8")
    if len(data) > MAX_FILE_BYTES:
        raise RepoError(ERROR_FILE_TOO_LARGE, f"content exceeds {MAX_FILE_BYTES} bytes")
    target = _resolve(root, path)
    if target.is_dir():
        raise RepoError(ERROR_INVALID_PATH, f"{path!r} is a directory in checkout {name!r}")
    created = not target.exists()
    write_text_atomic(target, content)
    return {"repo": name, "path": path, "bytes": len(data), "created": created}

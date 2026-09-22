"""Read-only live-debug sessions, off by default.

The hosted portal has no live debugger; this is the local debugging tier from
``docs/LIVE_DEBUGGING.md``: launch the sample stopped, read registers and
memory, then detach.  ``lldb-dap`` speaks DAP, ``gdb`` speaks MI; both store
the transcript as the ``debug-session`` scan, never as live process handles
in the store.

Four guards hold before any session starts, mirroring :mod:`reportal.sandbox`:

1. the workspace opts in (``REPORTAL_DEBUG=enabled`` or ``[debug] enabled =
   true``), so the default install still never controls a process;
2. a debug backend is installed (``lldb-dap`` or ``gdb``);
3. the stored binary has a file on disk;
4. at most one ``running`` session per binary: a second attach while live
   reuses that row rather than starting a second session.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import threading
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reportal import journal, observability, plugins, store
from reportal._paths import MARKER, WorkspaceNotFound, project_root
from reportal.plugins import RegistryError

_log = logging.getLogger(__name__)

# The session table, its statuses, and the surface's error names.
TABLE = "debug_sessions"
STATUS_RUNNING = "running"
STATUS_FINISHED = "finished"
STATUS_FAILED = "failed"
STATUSES: tuple[str, ...] = (STATUS_RUNNING, STATUS_FINISHED, STATUS_FAILED)

ERROR_DISABLED = "debug-disabled"
ERROR_UNAVAILABLE = "debug-unavailable"
ERROR_INVALID = "invalid-debug"
ERROR_NO_SESSION = "no-debug-session"

# Scan kind the session transcript is stored under.
SCAN_KIND = "debug-session"

# How the opt-in and the backend are configured.
ENABLED_ENV = "REPORTAL_DEBUG"
CONFIG_TABLE = "debug"
CONFIG_ENABLED = "enabled"
CONFIG_BACKEND = "backend"
BACKEND_ENV = "REPORTAL_DEBUG_BACKEND"
CONFIG_IMAGE = "image"
IMAGE_ENV = "REPORTAL_DEBUG_IMAGE"

# Entry-point group third-party debug backends register in.
BACKEND_ENTRY_POINT_GROUP = "reportal.debug_backends"

_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled", "required"})
_FALSEY = frozenset({"0", "false", "no", "off", "disabled"})

DISABLED_DETAIL = "set REPORTAL_DEBUG=enabled or [debug] enabled = true to allow debug sessions"

# Caps.  A session may ask for less, never more.
DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 120
MAX_BREAKPOINTS = 64
MAX_READ_BYTES = 4096
MAX_TRANSCRIPT_BYTES = 64 * 1024

# VM overlay caps.  One overlay clone per session off the pinned base image;
# the clone is qcow2 with the base as its backing file, so the base stays
# immutable and two sessions never share a disk.
VM_OVERLAY_SUFFIX = ".overlay.qcow2"
MAX_VM_DISK_GB = 20


class DebugError(Exception):
    """A debug session the caller refuses; ``code`` is the API's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Caps:
    """The bounds one session runs under."""

    timeout_seconds: int
    max_breakpoints: int = MAX_BREAKPOINTS
    max_read_bytes: int = MAX_READ_BYTES

    def as_payload(self) -> dict[str, Any]:
        """The caps as the session record carries them."""
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_breakpoints": self.max_breakpoints,
            "max_read_bytes": self.max_read_bytes,
        }


def requested_caps(*, timeout: int | None = None) -> Caps:
    """Validate a caller's requested bounds against the caps above."""
    seconds = DEFAULT_TIMEOUT_SECONDS if timeout is None else int(timeout)
    if not 1 <= seconds <= MAX_TIMEOUT_SECONDS:
        raise DebugError(
            ERROR_INVALID, f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
        )
    return Caps(timeout_seconds=seconds)


def _env_flag(name: str) -> bool | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    lowered = raw.lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSEY:
        return False
    return None


def _workspace_config() -> dict[str, Any]:
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return {}
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        _log.warning(
            "cannot read %s for [%s]; debug.enabled falls back to off: %s",
            marker,
            CONFIG_TABLE,
            exc,
        )
        return {}
    table = document.get(CONFIG_TABLE)
    return table if isinstance(table, dict) else {}


def enabled() -> bool:
    """True when the environment or the workspace config allows debug sessions."""
    forced = _env_flag(ENABLED_ENV)
    if forced is not None:
        return forced
    return _workspace_config().get(CONFIG_ENABLED) is True


def require_enabled() -> None:
    """Raise the disabled error when debug sessions are off."""
    if not enabled():
        raise DebugError(ERROR_DISABLED, DISABLED_DETAIL)


@dataclass(frozen=True)
class Backend:
    """One debug backend: how to invoke it and whether it is installed."""

    name: str
    executable: str
    hint: str = ""
    describe: str = ""

    def path(self) -> str | None:
        """The installed executable's path, or None when not installed."""
        return shutil.which(self.executable)

    def available(self) -> bool:
        return self.path() is not None


BACKENDS: list[Backend] = [
    Backend(
        "lldb-dap",
        "lldb-dap",
        hint="install lldb (apt install lldb) or register another backend",
        describe="LLDB debug adapter: launch/attach, breakpoints, registers, memory",
    ),
    Backend(
        "gdb",
        "gdb",
        hint="install gdb (apt install gdb) or register another backend",
        describe="GDB machine interface: run to main, threads, registers, memory",
    ),
]
_BACKENDS_LOCK = threading.RLock()

BUILTIN_BACKEND = BACKENDS[0].name

# Which origin claimed each registered name, and which names the last refresh
# discovered.  One writer per name is what the component, effect, worker, tool,
# model, source and graph-backend registries hold too: a second origin claiming
# a live name is a composition error rather than a silent replacement, so a
# plugin cannot take over the built-in backend's name and leave it unremovable.
_BACKEND_ORIGINS: dict[str, str] = {backend.name: plugins.BUILTIN_ORIGIN for backend in BACKENDS}
_DISCOVERED_BACKENDS: set[str] = set()


def register_backend(backend: Backend, *, origin: str = plugins.BUILTIN_ORIGIN) -> Backend:
    """Register *backend* under its own name, from *origin*.

    A name another origin already holds is refused with :class:`RegistryError`.
    Re-registering from the same origin, which is what a rescan of one entry
    point does, replaces the declaration in place.
    """
    if not isinstance(backend, Backend) or not isinstance(backend.name, str):
        raise RegistryError(f"bad debug backend registration from {origin}: expected a Backend")
    if not backend.name.strip():
        raise RegistryError(f"bad debug backend registration from {origin}: empty name")
    with _BACKENDS_LOCK:
        held = _BACKEND_ORIGINS.get(backend.name)
        if held is not None and held != origin:
            raise RegistryError(
                f"duplicate debug backend registration {backend.name!r}: {origin} conflicts"
                f" with {held} (single-source discipline)"
            )
        BACKENDS[:] = [existing for existing in BACKENDS if existing.name != backend.name]
        BACKENDS.append(backend)
        _BACKEND_ORIGINS[backend.name] = origin
        return backend


def unregister_backend(name: str) -> None:
    """Withdraw the backend registered as *name*, the inverse of a registration."""
    with _BACKENDS_LOCK:
        if name not in [backend.name for backend in BACKENDS]:
            raise RegistryError(f"no debug backend registration {name!r} to withdraw")
        if name == BUILTIN_BACKEND:
            raise RegistryError(f"cannot withdraw the built-in backend {name!r}")
        BACKENDS[:] = [backend for backend in BACKENDS if backend.name != name]
        _BACKEND_ORIGINS.pop(name, None)
        _DISCOVERED_BACKENDS.discard(name)


def registered_backends() -> list[Backend]:
    """Every registered backend, installed or not."""
    with _BACKENDS_LOCK:
        return list(BACKENDS)


def get_backend(name: str) -> Backend | None:
    """One registered backend by name, or None."""
    with _BACKENDS_LOCK:
        for backend in BACKENDS:
            if backend.name == name:
                return backend
        return None


def configured_backend_name() -> str:
    """The backend name the environment or the workspace asks for, or ""."""
    raw = os.environ.get(BACKEND_ENV, "").strip()
    if raw:
        return raw
    value = _workspace_config().get(CONFIG_BACKEND)
    return value.strip() if isinstance(value, str) else ""


def configured_image() -> str:
    """The pinned guest image digest or path, or "" when none is configured.

    The value is a digest reference the operator pins (never a moving tag):
    either a local image path or a ``sha256:<hex>`` reference the VM backend
    resolves.  Empty means no VM tier: probes run on the host backends.
    """
    raw = os.environ.get(IMAGE_ENV, "").strip()
    if raw:
        return raw
    value = _workspace_config().get(CONFIG_IMAGE)
    return value.strip() if isinstance(value, str) else ""


def vm_overlay_paths(base: Path, session_id: int) -> Path:
    """The overlay clone path for one session off *base*."""
    return base.parent / f"{base.stem}-session-{session_id}{VM_OVERLAY_SUFFIX}"


def create_vm_overlay(base: Path, overlay: Path) -> list[str]:
    """The qemu-img argv creating *overlay* as a qcow2 clone of *base*.

    Pure argv builder like the sandbox runner: availability and execution are
    the caller's guards, so this stays assertable without a hypervisor.
    """
    qemu_img = shutil.which("qemu-img") or "qemu-img"
    return [qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay)]


def destroy_vm_overlay(overlay: Path) -> None:
    """Remove one overlay clone, ignoring a missing file."""
    with contextlib.suppress(OSError):
        overlay.unlink(missing_ok=True)


def available_backend() -> Backend | None:
    """The backend a session would use: the configured one, else the first installed."""
    wanted = configured_backend_name()
    if wanted:
        backend = get_backend(wanted)
        if backend is None or not backend.available():
            return None
        return backend
    with _BACKENDS_LOCK:
        backends = list(BACKENDS)
    for backend in backends:
        if backend.available():
            return backend
    return None


def unavailable_detail() -> str:
    """Why no backend is available, naming what to install or register."""
    wanted = configured_backend_name()
    if wanted:
        return f"the configured debug backend {wanted!r} is not registered or not installed"
    with _BACKENDS_LOCK:
        hints = [backend.hint for backend in BACKENDS if backend.hint]
    return "no debug backend is installed; " + ("; ".join(hints) or "register one")


def require_backend() -> Backend:
    """The available backend, or the unavailable error naming what is missing."""
    backend = available_backend()
    if backend is None:
        raise DebugError(ERROR_UNAVAILABLE, unavailable_detail())
    return backend


def refresh_backends() -> list[str]:
    """Re-discover the ``reportal.debug_backends`` group; returns the names.

    A second origin claiming a live name is refused rather than replacing it,
    and the inverse of a discovery is applied first: a name an earlier refresh
    discovered whose entry point is gone is withdrawn, while the backends
    reportal ships and any in-process registration stay.  A scan that fails
    part-way still records what it registered, so the next refresh can withdraw
    those names rather than leaving them untracked.
    """
    scan = list(plugins.load(BACKEND_ENTRY_POINT_GROUP, Backend, "Backend"))
    discovered = {plugin.name for _name, _value, plugin in scan}
    with _BACKENDS_LOCK:
        vanished = sorted(_DISCOVERED_BACKENDS - discovered)
    for name in vanished:
        unregister_backend(name)
    registered: set[str] = set()
    try:
        for name, value, plugin in scan:
            register_backend(plugin, origin=plugins.origin(name, value))
            registered.add(plugin.name)
    finally:
        with _BACKENDS_LOCK:
            _DISCOVERED_BACKENDS.clear()
            _DISCOVERED_BACKENDS.update(registered)
    with _BACKENDS_LOCK:
        return [backend.name for backend in BACKENDS]


# ── The session table ────────────────────────────────────────────


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the session table when the database predates it."""
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {TABLE} ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,"
        " binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,"
        " sha256 TEXT NOT NULL DEFAULT '',"
        f" status TEXT NOT NULL DEFAULT '{STATUS_RUNNING}',"
        " backend TEXT NOT NULL DEFAULT '',"
        " image TEXT NOT NULL DEFAULT '',"
        " argv_json TEXT NOT NULL DEFAULT '[]',"
        " caps_json TEXT NOT NULL DEFAULT '{}',"
        " transcript_json TEXT NOT NULL DEFAULT '[]',"
        " notes_json TEXT NOT NULL DEFAULT '[]',"
        " created_at TEXT NOT NULL,"
        " finished_at TEXT)"
    )
    existing = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({TABLE})")}
    if existing and "image" not in existing:
        conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN image TEXT NOT NULL DEFAULT ''")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_debug_sessions_analysis ON {TABLE}(analysis_id)")
    conn.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS idx_debug_sessions_live_binary"
        f" ON {TABLE}(binary_id) WHERE status = '{STATUS_RUNNING}'"
    )


def _row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """One session row as the API reports it."""
    keys = set(row.keys()) if isinstance(row, sqlite3.Row) else set(row)
    return {
        "id": int(row["id"]),
        "analysis_id": int(row["analysis_id"]),
        "binary_id": int(row["binary_id"]),
        "sha256": str(row["sha256"]),
        "status": str(row["status"]),
        "backend": str(row["backend"]),
        "image": str(row["image"]) if "image" in keys else "",
        "argv": json.loads(str(row["argv_json"]) or "[]"),
        "caps": json.loads(str(row["caps_json"]) or "{}"),
        "transcript": json.loads(str(row["transcript_json"]) or "[]"),
        "notes": json.loads(str(row["notes_json"]) or "[]"),
        "created_at": str(row["created_at"]),
        "finished_at": None if row["finished_at"] is None else str(row["finished_at"]),
    }


def find_live_session(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """The in-progress session for *binary_id*, or None."""
    ensure_schema(conn)
    row = conn.execute(
        f"SELECT * FROM {TABLE} WHERE binary_id = ? AND status = ? ORDER BY id LIMIT 1",
        (binary_id, STATUS_RUNNING),
    ).fetchone()
    return _row(row) if row else None


def start_session(
    conn: sqlite3.Connection,
    *,
    analysis_id: int,
    binary_id: int,
    sha256: str,
    backend: str,
    argv: Sequence[str],
    caps: Caps,
    image: str = "",
) -> tuple[int, bool]:
    """Claim a ``running`` row before the session starts; returns ``(id, created)``."""
    ensure_schema(conn)
    try:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                f"INSERT INTO {TABLE} (analysis_id, binary_id, sha256, status, backend, image,"
                " argv_json, caps_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    analysis_id,
                    binary_id,
                    sha256,
                    STATUS_RUNNING,
                    backend,
                    image,
                    json.dumps(list(argv)),
                    json.dumps(caps.as_payload()),
                    store.now(),
                ),
            )
        return int(cursor.lastrowid or 0), True
    except sqlite3.IntegrityError:
        existing = find_live_session(conn, binary_id)
        if existing is not None:
            return int(existing["id"]), False
        raise


def finish_session(
    conn: sqlite3.Connection, session_id: int, transcript: Sequence[Mapping[str, Any]]
) -> None:
    """Store what a finished session observed."""
    conn.execute(
        f"UPDATE {TABLE} SET status = ?, transcript_json = ?, finished_at = ? WHERE id = ?",
        (STATUS_FINISHED, json.dumps(list(transcript)), store.now(), session_id),
    )
    conn.commit()


def fail_session(conn: sqlite3.Connection, session_id: int, note: str) -> None:
    """Close a session row as ``failed`` with one note."""
    conn.execute(
        f"UPDATE {TABLE} SET status = ?, notes_json = ?, finished_at = ? WHERE id = ?",
        (STATUS_FAILED, json.dumps([note]), store.now(), session_id),
    )
    conn.commit()


def get_session(conn: sqlite3.Connection, session_id: int) -> dict[str, Any] | None:
    """One session by id, or None when the id is unknown."""
    ensure_schema(conn)
    row = conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (session_id,)).fetchone()
    return _row(row) if row else None


def latest_session(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any] | None:
    """The newest session of one analysis, or None before the first."""
    ensure_schema(conn)
    row = conn.execute(
        f"SELECT * FROM {TABLE} WHERE analysis_id = ? ORDER BY id DESC LIMIT 1", (analysis_id,)
    ).fetchone()
    return _row(row) if row else None


def count_sessions(conn: sqlite3.Connection, analysis_id: int) -> int:
    """How many sessions one analysis holds."""
    ensure_schema(conn)
    return int(
        conn.execute(
            f"SELECT COUNT(*) AS n FROM {TABLE} WHERE analysis_id = ?", (analysis_id,)
        ).fetchone()["n"]
    )


def _parse_address(raw: Any) -> int | None:
    """One hex address as an int, or None when it is not an address."""
    if not raw:
        return None
    with contextlib.suppress(TypeError, ValueError):
        return int(str(raw), 16)
    return None


def _transcript_addresses(session: Mapping[str, Any]) -> list[int]:
    """Every instruction address a session transcript observed, as ints."""
    addresses: list[int] = []
    transcript = session.get("transcript")
    if not isinstance(transcript, list):
        return addresses
    for entry in transcript:
        if not isinstance(entry, dict):
            continue
        for key in ("instructionPointerReference", "address"):
            parsed = _parse_address(entry.get(key))
            if parsed is not None:
                addresses.append(parsed)
        for frame in entry.get("frames") or []:
            if not isinstance(frame, dict):
                continue
            parsed = _parse_address(frame.get("instructionPointerReference"))
            if parsed is not None:
                addresses.append(parsed)
    return addresses


def observed_coverage(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Join the newest debug session's addresses to the stored functions.

    An address inside a function's `[va, va + size)` range marks it observed;
    a zero-size function matches its exact VA only.  Functions the session
    never touched are `unobserved`, which is not the same as absent.  Returns
    None before the first session.
    """
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    session = latest_session(conn, analysis_id)
    if session is None:
        return None
    addresses = _transcript_addresses(session)
    functions = store.list_functions(conn, binary_id=binary_id)
    total = len(functions)
    observed: list[dict[str, Any]] = []
    for function in functions:
        va = int(function["va"])
        size = int(function.get("size") or 0)
        hits = [
            address
            for address in addresses
            if address == va or (size > 0 and va <= address < va + size)
        ]
        if hits:
            observed.append(
                {
                    "id": int(function["id"]),
                    "name": str(function["name"]),
                    "va": va,
                    "size": size,
                    "hits": len(hits),
                }
            )
    observed.sort(key=lambda row: row["va"])
    return {
        "binary_id": binary_id,
        "analysis_id": analysis_id,
        "session_id": int(session["id"]),
        "backend": str(session["backend"]),
        "addresses": len(addresses),
        "observed": len(observed),
        "total": total,
        "functions": observed,
        "note": ("one session is one path, not a specification: unobserved is not absent"),
    }


# Name sources a session may overwrite: engine-produced names and placeholders.
# A hand rename, an applied match or a revert is a person's decision, so a
# session label never touches it.  Mirrors unstrip.AUTO_NAME_SOURCES.
SESSION_AUTO_SOURCES = frozenset({"rebrew", "unstrip", "debug"})

# Rename source a session proposal apply records in the function's history.
SESSION_SOURCE = "debug"


def _session_frames(session: Mapping[str, Any]) -> list[tuple[str, int]]:
    """Every named frame a session transcript carries, as (name, address)."""
    found: list[tuple[str, int]] = []
    transcript = session.get("transcript")
    if not isinstance(transcript, list):
        return found
    for entry in transcript:
        if not isinstance(entry, dict):
            continue
        for frame in entry.get("frames") or []:
            if not isinstance(frame, dict):
                continue
            name = str(frame.get("name") or "").strip()
            address = _parse_address(frame.get("instructionPointerReference"))
            if name and address is not None and not name.startswith("_"):
                found.append((name, address))
    return found


def session_proposals(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Propose renames from the newest session's frame names, joined by VA.

    A frame names the symbol the debugger resolved at that address; when a
    stored function contains the address and carries a placeholder or an
    engine-produced name, the frame name is proposed with source `debug`.
    A person-authored name is never proposed for overwrite, and a function
    already carrying the name is not proposed.  Proposals only: nothing is
    renamed.  Returns None before the first session.
    """
    from reportal import unstrip as _unstrip

    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    session = latest_session(conn, analysis_id)
    if session is None:
        return None
    frames = _session_frames(session)
    functions = store.list_functions(conn, binary_id=binary_id)
    proposals: list[dict[str, Any]] = []
    for name, address in frames:
        for function in functions:
            va = int(function["va"])
            size = int(function.get("size") or 0)
            if not (address == va or (size > 0 and va <= address < va + size)):
                continue
            current = str(function.get("name") or "")
            if current == name:
                continue
            source = str(function.get("name_source") or "")
            if not _unstrip._is_unnamed(current) and source not in SESSION_AUTO_SOURCES:
                continue
            proposals.append(
                {
                    "function_id": int(function["id"]),
                    "va": va,
                    "current_name": current,
                    "proposed_name": name,
                    "address": address,
                    "session_id": int(session["id"]),
                }
            )
    seen: set[int] = set()
    unique: list[dict[str, Any]] = []
    for proposal in proposals:
        if proposal["function_id"] not in seen:
            seen.add(proposal["function_id"])
            unique.append(proposal)
    unique.sort(key=lambda row: row["va"])
    return {
        "binary_id": binary_id,
        "analysis_id": analysis_id,
        "session_id": int(session["id"]),
        "backend": str(session["backend"]),
        "proposals": unique,
        "count": len(unique),
        "note": "proposals only: apply renames explicitly, never silently",
    }


def apply_session_proposal(
    conn: sqlite3.Connection, *, function_id: int, new_name: str | None = None
) -> dict[str, Any]:
    """Rename *function_id* to its session proposal, recording source `debug`.

    Without *new_name* the name comes from the binary's newest session
    proposals.  Raises KeyError for an unknown function and ValueError when
    the session holds no proposal for it.
    """
    function = store.get_function(conn, function_id)
    if function is None:
        raise KeyError(f"no function with id {function_id}")
    resolved = new_name
    if resolved is None:
        analysis_id = int(function["analysis_id"])
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            raise KeyError(f"no analysis {analysis_id} for function {function_id}")
        binary_id = int(analysis["binary_id"])
        proposals = session_proposals(conn, binary_id)
        match = (
            None
            if proposals is None
            else next((p for p in proposals["proposals"] if p["function_id"] == function_id), None)
        )
        if match is None:
            raise ValueError(f"no session proposal for function {function_id}")
        resolved = str(match["proposed_name"])
    if not resolved.strip():
        raise ValueError("name must not be empty")
    return store.rename_function(
        conn, function_id, new_name=resolved, actor=SESSION_SOURCE, source=SESSION_SOURCE
    )


def status_payload(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any]:
    """The debug status of one analysis: whether it can run and its last session."""
    backend = available_backend()
    last = latest_session(conn, analysis_id)
    return {
        "analysis_id": analysis_id,
        "enabled": enabled(),
        "available": backend is not None,
        "backend": None if backend is None else backend.name,
        "image": configured_image(),
        "backends": [
            {"name": entry.name, "available": entry.available(), "describe": entry.describe}
            for entry in registered_backends()
        ],
        "caps": {
            "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
            "max_timeout_seconds": MAX_TIMEOUT_SECONDS,
            "max_breakpoints": MAX_BREAKPOINTS,
            "max_read_bytes": MAX_READ_BYTES,
        },
        "sessions": count_sessions(conn, analysis_id),
        "last": None
        if last is None
        else {
            "id": last["id"],
            "status": last["status"],
            "image": last["image"],
            "created_at": last["created_at"],
        },
        "note": (
            "a session controls the stored sample under the debugger; it is refused"
            " unless the workspace opts in"
        ),
    }


# ── The DAP exchange ─────────────────────────────────────────────


def _dap_request(seq: int, command: str, arguments: Mapping[str, Any] | None = None) -> bytes:
    """One DAP request frame with its Content-Length header."""
    body = json.dumps(
        {"seq": seq, "type": "request", "command": command, "arguments": dict(arguments or {})}
    ).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


class _DapReader:
    """Buffered DAP frame reader: one connection, many messages, no lost bytes.

    A single ``os.read`` may return several frames (an event plus the response),
    so the reader keeps the unread tail between calls instead of discarding it.
    """

    def __init__(self, handle: Any, limit: int, timeout_s: float) -> None:
        import time

        self._handle = handle
        self._limit = limit
        self._deadline = time.monotonic() + timeout_s
        self._buffer = b""

    def _fill(self, need: int) -> None:
        import select
        import time

        while len(self._buffer) < need:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise DebugError(ERROR_INVALID, "the debug backend did not answer in time")
            ready, _, _ = select.select([self._handle], [], [], remaining)
            if not ready:
                raise DebugError(ERROR_INVALID, "the debug backend did not answer in time")
            chunk = os.read(self._handle.fileno(), max(need - len(self._buffer), 4096))
            if not chunk:
                raise DebugError(ERROR_INVALID, "the debug backend closed the connection")
            self._buffer += chunk

    def read_message(self) -> dict[str, Any]:
        """The next DAP message, whatever its type (event, response, request)."""
        while b"\r\n\r\n" not in self._buffer:
            self._fill(len(self._buffer) + 1)
        head, _, rest = self._buffer.partition(b"\r\n\r\n")
        self._buffer = rest
        length = 0
        for line in head.decode("latin-1").split("\r\n"):
            if line.lower().startswith("content-length:"):
                length = int(line.partition(":")[2].strip())
        if length <= 0 or length > self._limit:
            raise DebugError(ERROR_INVALID, "the debug backend answered an invalid frame")
        self._fill(length)
        body, self._buffer = self._buffer[:length], self._buffer[length:]
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DebugError(
                ERROR_INVALID, f"the debug backend answered invalid JSON: {exc}"
            ) from exc
        return parsed if isinstance(parsed, dict) else {}

    def read_response(self, seq: int) -> dict[str, Any]:
        """The response to request *seq*, skipping the events around it."""
        while True:
            message = self.read_message()
            if message.get("type") == "event":
                continue
            if message.get("type") == "response" and message.get("request_seq") == seq:
                return message
            if message.get("type") == "response":
                continue
            raise DebugError(ERROR_INVALID, "the debug backend answered an invalid message")

    def read_event(self, name: str) -> dict[str, Any]:
        """The next event called *name*, skipping every other message."""
        while True:
            message = self.read_message()
            if message.get("type") == "event" and message.get("event") == name:
                return message


def probe_binary(
    sample: Path,
    *,
    caps: Caps | None = None,
    backend: Backend | None = None,
    breakpoints: Sequence[int] | None = None,
    qemu_arch: str | None = None,
) -> dict[str, Any]:
    """Attach a read-only probe to *sample* and return the transcript.

    ``lldb-dap`` speaks DAP; ``gdb`` speaks MI.  Both launch the sample
    stopped, read the thread list, one frame, the general registers and a
    bounded memory window, then detach.  Nothing is stepped, continued or
    written.  With *qemu_arch* the gdb probe runs the sample under
    ``qemu-<arch> -g`` and drives it through ``target remote``.
    """
    resolved_caps = caps or requested_caps()
    chosen = backend or require_backend()
    try:
        points = [int(point) for point in (breakpoints or [])]
    except (TypeError, ValueError) as exc:
        raise DebugError(ERROR_INVALID, f"breakpoints must be integers: {exc}") from exc
    if len(points) > resolved_caps.max_breakpoints:
        raise DebugError(
            ERROR_INVALID, f"at most {resolved_caps.max_breakpoints} breakpoints per session"
        )
    arch = (qemu_arch or "").strip() or None
    if arch is not None and chosen.name != "gdb":
        raise DebugError(ERROR_INVALID, "qemu_arch needs the gdb backend")
    if chosen.name == "gdb":
        return _probe_mi(sample, caps=resolved_caps, backend=chosen, points=points, qemu_arch=arch)
    if chosen.name != "lldb-dap":
        raise DebugError(
            ERROR_UNAVAILABLE,
            f"debug backend {chosen.name!r} has no read-only probe; use lldb-dap",
        )
    return _probe_dap(sample, caps=resolved_caps, backend=chosen, points=points)


def _probe_dap(
    sample: Path,
    *,
    caps: Caps,
    backend: Backend,
    points: Sequence[int],
) -> dict[str, Any]:
    """The DAP half of :func:`probe_binary`, over ``lldb-dap``."""
    resolved_caps = caps
    chosen = backend
    executable = chosen.path()
    if executable is None:
        raise DebugError(ERROR_UNAVAILABLE, unavailable_detail())
    argv = [executable]
    transcript: list[dict[str, Any]] = []
    notes: list[str] = []
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin"},
        )
    except OSError as exc:
        raise DebugError(ERROR_INVALID, f"the debug backend could not be started: {exc}") from exc
    try:
        assert process.stdin is not None and process.stdout is not None
        reader = _DapReader(process.stdout, MAX_TRANSCRIPT_BYTES, resolved_caps.timeout_seconds)
        seq = 1
        process.stdin.write(
            _dap_request(
                seq,
                "initialize",
                {
                    "adapterID": "reportal",
                    "pathFormat": "path",
                    "linesStartAt1": True,
                    "columnsStartAt1": True,
                },
            )
        )
        process.stdin.flush()
        init = reader.read_response(seq)
        seq += 1
        transcript.append({"request": "initialize", "success": bool(init.get("success", True))})
        process.stdin.write(
            _dap_request(seq, "launch", {"program": str(sample), "stopOnEntry": True})
        )
        process.stdin.flush()
        launch_seq = seq
        seq += 1
        # lldb-dap emits `initialized` before answering launch: the client
        # must answer with configurationDone first, then both responses arrive.
        reader.read_event("initialized")
        process.stdin.write(_dap_request(seq, "configurationDone", {}))
        process.stdin.flush()
        config_seq = seq
        seq += 1
        # Either response may arrive first; collect both whatever the order.
        # The entry `stopped` event may interleave here too, so keep it.
        wanted = {launch_seq: "launch", config_seq: "configurationDone"}
        found: dict[str, dict[str, Any]] = {}
        stopped: dict[str, Any] | None = None
        while set(found) != set(wanted.values()):
            message = reader.read_message()
            if message.get("type") == "event":
                if message.get("event") == "stopped" and stopped is None:
                    stopped = message
                continue
            if message.get("type") != "response":
                raise DebugError(ERROR_INVALID, "the debug backend answered an invalid message")
            name = wanted.get(int(message.get("request_seq") or 0))
            if name is not None:
                found[name] = message
        launch = found["launch"]
        transcript.append({"request": "launch", "success": bool(launch.get("success", True))})
        done = found["configurationDone"]
        transcript.append(
            {"request": "configurationDone", "success": bool(done.get("success", True))}
        )
        # The entry stop carries the thread; threads, one stack frame, the
        # register group and a bounded memory window are the read-only evidence.
        if stopped is None:
            stopped = reader.read_event("stopped")
        thread_id = int(stopped.get("body", {}).get("threadId") or 0)
        transcript.append(
            {
                "request": "stopped",
                "threadId": thread_id,
                "reason": str(stopped.get("body", {}).get("reason") or ""),
                "success": True,
            }
        )
        process.stdin.write(_dap_request(seq, "threads", {}))
        process.stdin.flush()
        threads_seq = seq
        seq += 1
        process.stdin.write(
            _dap_request(seq, "stackTrace", {"threadId": thread_id, "startFrame": 0, "levels": 1})
        )
        process.stdin.flush()
        stack_seq = seq
        seq += 1
        wanted_reads = {threads_seq: "threads", stack_seq: "stackTrace"}
        reads: dict[str, dict[str, Any]] = {}
        while set(reads) != set(wanted_reads.values()):
            message = reader.read_message()
            if message.get("type") == "event":
                continue
            if message.get("type") != "response":
                raise DebugError(ERROR_INVALID, "the debug backend answered an invalid message")
            name = wanted_reads.get(int(message.get("request_seq") or 0))
            if name is not None:
                reads[name] = message
        transcript.append(
            {
                "request": "threads",
                "success": bool(reads["threads"].get("success", True)),
                "threads": reads["threads"].get("body", {}).get("threads", []),
            }
        )
        frames = reads["stackTrace"].get("body", {}).get("stackFrames", [])
        frame_id = int(frames[0].get("id") or 0) if frames else 0
        transcript.append(
            {
                "request": "stackTrace",
                "success": bool(reads["stackTrace"].get("success", True)),
                "frames": [
                    {
                        "name": str(item.get("name") or ""),
                        "instructionPointerReference": str(
                            item.get("instructionPointerReference") or ""
                        ),
                    }
                    for item in frames
                ],
            }
        )
        if frame_id:
            process.stdin.write(_dap_request(seq, "scopes", {"frameId": frame_id}))
            process.stdin.flush()
            scopes_answer = reader.read_response(seq)
            seq += 1
            groups = scopes_answer.get("body", {}).get("scopes", [])
            register_group = next(
                (
                    item
                    for item in groups
                    if "egister" in str(item.get("name") or "")
                    or str(item.get("presentationHint") or "") == "registers"
                ),
                None,
            )
            if register_group is not None:
                variables_ref = int(register_group.get("variablesReference") or 0)
                process.stdin.write(
                    _dap_request(seq, "variables", {"variablesReference": variables_ref})
                )
                process.stdin.flush()
                registers_answer = reader.read_response(seq)
                seq += 1
                groups = registers_answer.get("body", {}).get("variables", [])
                # The first level is register groups; expand the general group
                # so the transcript carries real names and values.
                general = next(
                    (
                        item
                        for item in groups
                        if "eneral" in str(item.get("name") or "")
                        or int(item.get("variablesReference") or 0) > 0
                    ),
                    None,
                )
                registers: list[dict[str, Any]] = []
                if general is not None and int(general.get("variablesReference") or 0):
                    process.stdin.write(
                        _dap_request(
                            seq,
                            "variables",
                            {"variablesReference": int(general["variablesReference"])},
                        )
                    )
                    process.stdin.flush()
                    general_answer = reader.read_response(seq)
                    seq += 1
                    registers = general_answer.get("body", {}).get("variables", [])
                else:
                    registers = groups
                transcript.append(
                    {
                        "request": "registers",
                        "success": bool(registers_answer.get("success", True)),
                        "registers": [
                            {
                                "name": str(item.get("name") or ""),
                                "value": str(item.get("value") or ""),
                            }
                            for item in registers
                        ][:64],
                        "register_count": len(registers),
                    }
                )
            pointer = (frames[0].get("instructionPointerReference") or "") if frames else ""
            instruction_pointer = str(pointer)
            if instruction_pointer:
                process.stdin.write(
                    _dap_request(
                        seq,
                        "readMemory",
                        {
                            "memoryReference": instruction_pointer,
                            "count": min(64, resolved_caps.max_read_bytes),
                        },
                    )
                )
                process.stdin.flush()
                memory_answer = reader.read_response(seq)
                seq += 1
                transcript.append(
                    {
                        "request": "readMemory",
                        "success": bool(memory_answer.get("success", True)),
                        "address": instruction_pointer,
                        "data": str(memory_answer.get("body", {}).get("data") or ""),
                        "encoding": "base64",
                    }
                )
        for point in points:
            transcript.append(
                {
                    "request": "setBreakpoints",
                    "address": point,
                    "success": False,
                    "note": (
                        "address breakpoints need a loaded source location;"
                        " this probe stops at entry only"
                    ),
                }
            )
        process.stdin.write(_dap_request(seq, "disconnect", {"terminateDebuggee": True}))
        process.stdin.flush()
        bye = reader.read_response(seq)
        seq += 1
        transcript.append({"request": "disconnect", "success": bool(bye.get("success", True))})
    except DebugError:
        raise
    except OSError as exc:
        raise DebugError(ERROR_INVALID, f"the debug backend could not be started: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    capped = transcript[: MAX_BREAKPOINTS + 3]
    if len(transcript) > len(capped):
        notes.append(f"the transcript was truncated to {len(capped)} entries")
    return {
        "status": STATUS_FINISHED,
        "backend": chosen.name,
        "argv": argv,
        "caps": resolved_caps.as_payload(),
        "transcript": capped,
        "notes": notes,
    }


def _mi_send(handle: Any, command: str) -> None:
    """One MI command line to *handle*."""
    handle.write((command + "\n").encode("utf-8"))
    handle.flush()


def _mi_read_until_prompt(handle: Any, limit: int, timeout_s: float, *, command: str) -> list[str]:
    """MI output lines up to the next ``(gdb)`` prompt."""
    import select
    import time

    deadline = time.monotonic() + timeout_s
    buffer = b""
    lines: list[str] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DebugError(ERROR_INVALID, f"the gdb {command} did not answer in time")
        ready, _, _ = select.select([handle], [], [], remaining)
        if not ready:
            raise DebugError(ERROR_INVALID, f"the gdb {command} did not answer in time")
        chunk = os.read(handle.fileno(), 4096)
        if not chunk:
            raise DebugError(ERROR_INVALID, "gdb closed the connection")
        buffer += chunk
        while b"\n" in buffer:
            raw, buffer = buffer.split(b"\n", 1)
            text = raw.decode("utf-8", "replace")
            if text.strip() == "(gdb)":
                if len("\n".join(lines).encode()) > limit:
                    raise DebugError(ERROR_INVALID, "the gdb answer exceeded its cap")
                return lines
            lines.append(text)


def _mi_result(lines: Sequence[str]) -> tuple[bool, str]:
    """Whether the last ``^`` line says done or running, and that line.

    Async `*`, `=` and `~` lines from the stop interleave before the command's
    own result, so the parse reads the last `^` line rather than the whole
    answer; stale fields from an earlier command never leak into this one.
    """
    answer = ""
    outcome = False
    for line in lines:
        if line.startswith("^"):
            answer = line
            outcome = line.startswith(("^done", "^running"))
    return outcome, answer


def _mi_wait_for_stop(handle: Any, limit: int, timeout_s: float, *, marker: str) -> str | None:
    """Drain MI output through the stop line and its prompt, or None on timeout.

    The stop line arrives mid-stream (`*stopped`), followed by the `^running`
    result of `-exec-run` and the `(gdb)` prompt; returning at the marker
    would strand those bytes in the pipe and pollute the next read, so the
    wait continues to the prompt.
    """
    import select
    import time

    deadline = time.monotonic() + timeout_s
    buffer = b""
    collected: list[str] = []
    seen = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([handle], [], [], remaining)
        if not ready:
            return None
        chunk = os.read(handle.fileno(), 4096)
        if not chunk:
            return None
        buffer += chunk
        while b"\n" in buffer:
            raw, buffer = buffer.split(b"\n", 1)
            text = raw.decode("utf-8", "replace")
            if text.strip() == "(gdb)":
                if seen:
                    if len("\n".join(collected).encode()) > limit:
                        raise DebugError(ERROR_INVALID, "the gdb answer exceeded its cap")
                    return "\n".join(collected)
                continue
            collected.append(text)
            if marker in text:
                seen = True


def _free_tcp_port() -> int:
    """One free loopback TCP port for a qemu stub to listen on."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _probe_mi(
    sample: Path,
    *,
    caps: Caps,
    backend: Backend,
    points: Sequence[int],
    qemu_arch: str | None = None,
) -> dict[str, Any]:
    """The MI half of :func:`probe_binary`, over ``gdb --interpreter=mi2``.

    Without *qemu_arch* gdb runs the sample natively: break on ``main``,
    run to the stop, read threads, one frame, register names and one memory
    window, then exit.  With *qemu_arch* (``x86_64``, ``aarch64``, ``arm``,
    ``mips`` ...) the sample runs under ``qemu-<arch> -g <port>`` and gdb
    drives it through ``target remote``: the same reads over a stub, which is
    how a foreign-arch firmware ELF is probed.  Nothing is continued past the
    stop either way.
    """
    executable = backend.path()
    if executable is None:
        raise DebugError(ERROR_UNAVAILABLE, unavailable_detail())
    stub: subprocess.Popen[bytes] | None = None
    gdb_argv = [executable, "-q", "--interpreter=mi2"]
    if qemu_arch is None:
        gdb_argv.append(str(sample))
    else:
        qemu = shutil.which(f"qemu-{qemu_arch}")
        if qemu is None:
            raise DebugError(
                ERROR_UNAVAILABLE, f"qemu-{qemu_arch} is not installed; cannot probe under it"
            )
        port = _free_tcp_port()
        try:
            stub = subprocess.Popen(
                [qemu, "-g", str(port), str(sample)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                env={"PATH": "/usr/bin:/bin"},
            )
        except OSError as exc:
            raise DebugError(
                ERROR_INVALID, f"qemu-{qemu_arch} could not be started: {exc}"
            ) from exc
    argv = gdb_argv
    transcript: list[dict[str, Any]] = []
    notes: list[str] = []
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin"},
        )
    except OSError as exc:
        if stub is not None:
            stub.kill()
        raise DebugError(ERROR_INVALID, f"gdb could not be started: {exc}") from exc
    try:
        assert process.stdin is not None and process.stdout is not None
        timeout_s = float(caps.timeout_seconds)
        _mi_read_until_prompt(process.stdout, MAX_TRANSCRIPT_BYTES, timeout_s, command="startup")

        def run(command: str, label: str) -> tuple[bool, str]:
            _mi_send(process.stdin, command)
            lines = _mi_read_until_prompt(
                process.stdout, MAX_TRANSCRIPT_BYTES, timeout_s, command=label
            )
            return _mi_result(lines)

        if stub is not None:
            ok, _ = run(f"target remote :{port}", "remote")
            transcript.append({"request": "target-remote", "success": ok})
            # The stub serves its libraries over the RSP file channel, which
            # is slow; reading them locally skips the transfer.
            run("set sysroot /", "sysroot")

        ok, _ = run("-break-insert main", "break")
        transcript.append({"request": "break-insert", "success": ok})
        if stub is None:
            _mi_send(process.stdin, "-exec-run")
            stopped_text = _mi_wait_for_stop(
                process.stdout, MAX_TRANSCRIPT_BYTES, timeout_s, marker='reason="breakpoint-hit"'
            )
            transcript.append({"request": "exec-run", "success": stopped_text is not None})
        else:
            # A remote stub is already stopped at entry and refuses `run`;
            # continue to the breakpoint instead.  Any stop ends the wait.
            _mi_send(process.stdin, "-exec-continue")
            stopped_text = _mi_wait_for_stop(
                process.stdout, MAX_TRANSCRIPT_BYTES, timeout_s, marker="*stopped"
            )
            transcript.append({"request": "exec-continue", "success": stopped_text is not None})
        ok, text = run("-thread-info", "threads")
        threads: list[dict[str, Any]] = []
        thread_id = 0
        for token in text.split("id="):
            head = token.strip().strip('"')
            digits = ""
            for char in head:
                if not char.isdigit():
                    break
                digits += char
            if digits:
                thread_id = int(digits)
                threads.append({"id": thread_id, "name": ""})
                break
        transcript.append({"request": "threads", "success": ok, "threads": threads})
        ok, text = run("-stack-list-frames 0 0", "frame")
        frame_name = ""
        frame_addr = ""
        for token in text.split(","):
            key, _, value = token.partition("=")
            key = key.strip()
            value = value.strip().strip('"')
            if key == "func":
                frame_name = value
            elif key == "addr":
                frame_addr = value
        transcript.append(
            {
                "request": "stackTrace",
                "success": ok,
                "frames": (
                    [{"name": frame_name, "instructionPointerReference": frame_addr}]
                    if frame_name or frame_addr
                    else []
                ),
            }
        )
        ok, text = run("-data-list-register-names", "registers")
        names: list[str] = []
        if "register-names" in text:
            body = text.partition("register-names=")[2]
            for token in body.replace("[", " ").replace("]", " ").replace(",", " ").split():
                cleaned = token.strip().strip('"')
                if cleaned and cleaned != '""':
                    names.append(cleaned)
        transcript.append(
            {
                "request": "registers",
                "success": ok,
                "registers": [{"name": name, "value": ""} for name in names[:64]],
                "register_count": len(names),
            }
        )
        if frame_addr:
            count = min(64, caps.max_read_bytes)
            ok, text = run(f"-data-read-memory-bytes {frame_addr} {count}", "memory")
            data = ""
            marker = 'contents="'
            if marker in text:
                data = text.split(marker, 1)[1].split('"', 1)[0]
            transcript.append(
                {
                    "request": "readMemory",
                    "success": ok,
                    "address": frame_addr,
                    "data": data,
                    "encoding": "hex",
                }
            )
        for point in points:
            transcript.append(
                {
                    "request": "setBreakpoints",
                    "address": point,
                    "success": False,
                    "note": "this probe stops at main only",
                }
            )
        _mi_send(process.stdin, "-exec-interrupt")
        ok, _ = run("-gdb-exit", "exit")
        transcript.append({"request": "disconnect", "success": ok})
    except DebugError:
        raise
    except OSError as exc:
        raise DebugError(ERROR_INVALID, f"gdb could not be started: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        if stub is not None:
            with contextlib.suppress(OSError):
                stub.kill()
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                stub.wait(timeout=5)
    capped = transcript[: MAX_BREAKPOINTS + 3]
    if len(transcript) > len(capped):
        notes.append(f"the transcript was truncated to {len(capped)} entries")
    return {
        "status": STATUS_FINISHED,
        "backend": backend.name,
        "argv": argv,
        "caps": caps.as_payload(),
        "transcript": capped,
        "notes": notes,
    }


def run_session(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    timeout: int | None = None,
    breakpoints: Sequence[int] | None = None,
    qemu_arch: str | None = None,
) -> dict[str, Any]:
    """Run one read-only probe over a stored binary and store the session.

    Shared by the HTTP route, the CLI and the MCP tool, so the guards are
    checked once.  A second call while a session is still ``running`` returns
    that row without starting another probe.  The transcript is stored as the
    ``debug-session`` scan, so a revert removes the record.  *qemu_arch* runs
    the gdb probe under ``qemu-<arch>`` through ``target remote``.
    """
    require_enabled()
    backend = require_backend()
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise DebugError("binary not found", f"no binary with id {binary_id}")
    stored = Path(str(binary["path"]))
    if not stored.is_file():
        raise DebugError(
            "binary not on disk", f"binary {binary_id} has no file at {binary['path']!r}"
        )
    caps = requested_caps(timeout=timeout)
    live = find_live_session(conn, binary_id)
    if live is not None:
        return live
    analysis_before = store.latest_analysis_for_binary(conn, binary_id)
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="debug")
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        if analysis_before is None:
            journal.journaled_create(
                log,
                table="analyses",
                key=analysis_id,
                description=f"created analysis {analysis_id} for binary {binary_id}",
            )
        session_id, created = start_session(
            conn,
            analysis_id=analysis_id,
            binary_id=binary_id,
            sha256=str(binary["sha256"] or ""),
            backend=backend.name,
            argv=[backend.path() or backend.executable],
            caps=caps,
            image=configured_image(),
        )
        if not created:
            raced = get_session(conn, session_id)
            return raced or {"id": session_id, "status": STATUS_RUNNING, "binary_id": binary_id}
        journal.journaled_create(
            log,
            table=TABLE,
            key=session_id,
            description=f"ran binary {binary_id} under the {backend.name} debugger",
        )
        try:
            report = probe_binary(
                stored, caps=caps, backend=backend, breakpoints=breakpoints, qemu_arch=qemu_arch
            )
        except Exception as exc:
            _log.error(
                "debug session aborted session_id=%s binary_id=%s error=%s%s",
                session_id,
                binary_id,
                f"{type(exc).__name__}: {exc}"[:200],
                observability.request_id_suffix(),
                exc_info=exc,
            )
            fail_session(conn, session_id, f"debug session aborted: {exc}")
            raise
        finish_session(conn, session_id, report["transcript"])
        journal.journaled_create(
            log,
            table="scans",
            key={"analysis_id": analysis_id, "kind": SCAN_KIND},
            description=f"stored {SCAN_KIND} scan for binary {binary_id}",
        )
        store.set_scan(conn, analysis_id, SCAN_KIND, {**report, "session_id": session_id})
        digest = render_transcript(report["transcript"], backend=backend.name)
        try:
            from reportal import knowledge

            payload = knowledge.ingest_document(
                conn,
                scope_kind=knowledge.SCOPE_KIND_BINARY,
                scope_id=binary_id,
                title=f"Debug session {session_id}",
                source=f"debug-session-{session_id}.md",
                mime="text/markdown",
                data=digest.encode("utf-8"),
            )
            journal.journaled_ingest(conn, log, payload)
        except Exception as exc:
            _log.warning(
                "debug digest ingest skipped session_id=%s binary_id=%s error=%s%s",
                session_id,
                binary_id,
                f"{type(exc).__name__}: {exc}"[:200],
                observability.request_id_suffix(),
            )
        finished = get_session(conn, session_id)
    return log.attach(finished or {"id": session_id, **report})


def render_transcript(transcript: Sequence[Mapping[str, Any]], *, backend: str) -> str:
    """The session transcript as a citable markdown digest."""
    lines = [f"# Debug session ({backend})", ""]
    for entry in transcript:
        request = str(entry.get("request") or "unknown")
        ok = entry.get("success", True)
        lines.append(f"## {request} ({'ok' if ok else 'failed'})")
        if entry.get("threadId") is not None:
            lines.append(f"thread: {entry['threadId']}, reason: {entry.get('reason', '')}")
        for thread in entry.get("threads") or []:
            if isinstance(thread, dict):
                lines.append(f"thread {thread.get('id')}: {thread.get('name', '')}")
        for frame in entry.get("frames") or []:
            if isinstance(frame, dict):
                lines.append(
                    f"frame {frame.get('name', '')} @"
                    f" {frame.get('instructionPointerReference', '')}"
                )
        for register in (entry.get("registers") or [])[:32]:
            if isinstance(register, dict) and register.get("name"):
                lines.append(f"{register['name']} = {register.get('value', '')}")
        if int(entry.get("register_count") or 0) > 32:
            lines.append(f"({int(entry['register_count']) - 32} more registers)")
        if entry.get("address"):
            lines.append(f"memory [{entry['address']}]: {entry.get('data', '')}")
        if entry.get("note"):
            lines.append(str(entry["note"]))
        lines.append("")
    lines.append("One session is one path: unobserved is not absent.")
    return "\n".join(lines)

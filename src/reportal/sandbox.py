"""Guarded sandbox detonation: run a stored sample, off by default, and record it.

reportal reads bytes and never runs a sample, with exactly one exception, and
this is it.  The hosted portal detonates a sample in its own sandbox and reports
what it did; the local form runs the sample under a sandbox runner that is
installed on the machine, with no network, a read-only root, its own PID and
mount namespaces, a memory and CPU cap and a wall-clock timeout, and records the
run: the command it issued, the caps in force, the exit status, how long it
took, a stdout/stderr tail and the files the sample wrote into its one writable
directory.

Four guards stand between the route and an execution, and all four must hold:

1. the workspace opts in (``REPORTAL_SANDBOX=enabled`` or ``[sandbox] enabled =
   true``), so the default install still never runs anything (:func:`require_enabled`);
2. a sandbox runner is installed (:func:`require_runner` refuses with
   ``sandbox-unavailable`` and the install hint when none is);
3. the stored binary has a file on disk (the caller checks that before it
   journals anything);
4. every run is bounded by :data:`DEFAULT_TIMEOUT_SECONDS` /
   :data:`MAX_TIMEOUT_SECONDS`, :data:`DEFAULT_MEMORY_MB` / :data:`MAX_MEMORY_MB`
   and a CPU cap, and is recorded whether it finishes or times out.

The one shipped runner is `bwrap` (bubblewrap), which needs its user namespaces
enabled; a third party registers another through the ``reportal.sandbox_runners``
entry-point group, whose value is a :class:`Runner` or a zero-argument factory
returning one.  The sample is never executed from the path reportal stores:
it is bind-mounted read-only at ``/sample`` inside the sandbox, and the only
writable path it sees is a fresh empty directory that reportal owns and removes.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import time
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reportal import journal, store
from reportal._paths import MARKER, WorkspaceNotFound, binaries_dir, project_root

# The run table, its statuses, and the execution surface's error names.
TABLE = "sandbox_runs"
STATUS_RUNNING = "running"
STATUS_FINISHED = "finished"
STATUS_TIMED_OUT = "timed_out"
STATUS_FAILED = "failed"
STATUSES: tuple[str, ...] = (STATUS_RUNNING, STATUS_FINISHED, STATUS_TIMED_OUT, STATUS_FAILED)

ERROR_DISABLED = "sandbox-disabled"
ERROR_UNAVAILABLE = "sandbox-unavailable"
ERROR_INVALID = "invalid-sandbox"
ERROR_NO_RUN = "no-run"

# How the opt-in and the runner are configured.
ENABLED_ENV = "REPORTAL_SANDBOX"
CONFIG_TABLE = "sandbox"
CONFIG_ENABLED = "enabled"
CONFIG_RUNNER = "runner"
RUNNER_ENV = "REPORTAL_SANDBOX_RUNNER"

# Entry-point group third-party sandbox runners register in.
RUNNER_ENTRY_POINT_GROUP = "reportal.sandbox_runners"
# Keep in sync with ``settings.FLAG_TRUTHY`` (and the other flag readers).
_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled", "required"})

# The fixed detail every disabled or unavailable path reports.
DISABLED_DETAIL = "set REPORTAL_SANDBOX=enabled or [sandbox] enabled = true to allow detonation"

# Caps.  A run may ask for less, never more.
DEFAULT_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 60
DEFAULT_MEMORY_MB = 512
MAX_MEMORY_MB = 4096
MAX_CPU_SECONDS = 60
DEFAULT_FILE_MB = 64

# Bytes of stdout and stderr a report keeps, and the files it lists.
MAX_OUTPUT_BYTES = 64 * 1024
MAX_FILES = 200

# Where the writable directory lands inside the sandbox, and the name the
# sample is mounted under inside it.  The mount point has to sit in the
# writable bind: bwrap cannot create it on the read-only root, and a directory
# created before the root bind is hidden by it.
WORKDIR_MOUNT = "/tmp"
SAMPLE_NAME = ".sample"
SAMPLE_MOUNT = f"{WORKDIR_MOUNT}/{SAMPLE_NAME}"

# The shell the caps are applied with, inside the sandbox's read-only root.
_SHELL = "/bin/sh"

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    binary_id     INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    sha256        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT '{STATUS_RUNNING}',
    runner        TEXT NOT NULL DEFAULT '',
    argv_json     TEXT NOT NULL DEFAULT '[]',
    caps_json     TEXT NOT NULL DEFAULT '{{}}',
    exit_code     INTEGER,
    timed_out     INTEGER NOT NULL DEFAULT 0,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    stdout        TEXT NOT NULL DEFAULT '',
    stderr        TEXT NOT NULL DEFAULT '',
    files_json    TEXT NOT NULL DEFAULT '[]',
    notes_json    TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL,
    finished_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_sandbox_runs_analysis ON {TABLE}(analysis_id);
"""


class SandboxError(Exception):
    """A detonation the caller refuses; ``code`` is the API's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Caps:
    """The bounds one run is executed under."""

    timeout_seconds: int
    memory_mb: int
    cpu_seconds: int
    file_mb: int

    def as_payload(self) -> dict[str, Any]:
        """The caps as the report carries them, including the fixed ones."""
        return {
            "timeout_seconds": self.timeout_seconds,
            "memory_mb": self.memory_mb,
            "cpu_seconds": self.cpu_seconds,
            "file_mb": self.file_mb,
            "network": "unshared",
            "root": "read-only",
            "sample": "read-only bind",
            "writable": WORKDIR_MOUNT,
        }


def requested_caps(*, timeout: int | None = None, memory_mb: int | None = None) -> Caps:
    """Validate a caller's requested bounds against the caps above.

    A value outside its bound is :class:`SandboxError` rather than a clamp: a
    caller asking for a minute of execution deserves to hear that it is not
    allowed rather than silently get less.
    """
    seconds = DEFAULT_TIMEOUT_SECONDS if timeout is None else int(timeout)
    if not 1 <= seconds <= MAX_TIMEOUT_SECONDS:
        raise SandboxError(
            ERROR_INVALID, f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
        )
    memory = DEFAULT_MEMORY_MB if memory_mb is None else int(memory_mb)
    if not 64 <= memory <= MAX_MEMORY_MB:
        raise SandboxError(ERROR_INVALID, f"memory_mb must be between 64 and {MAX_MEMORY_MB}")
    return Caps(
        timeout_seconds=seconds,
        memory_mb=memory,
        cpu_seconds=min(seconds, MAX_CPU_SECONDS),
        file_mb=DEFAULT_FILE_MB,
    )


def _truthy(value: str) -> bool:
    return value.strip().lower() in _TRUTHY


def _workspace_config() -> dict[str, Any]:
    """The workspace ``reportal.toml`` ``[sandbox]`` table, or an empty dict."""
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return {}
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    table = document.get(CONFIG_TABLE)
    return table if isinstance(table, dict) else {}


def enabled() -> bool:
    """True when the environment or the workspace config allows detonation."""
    if _truthy(os.environ.get(ENABLED_ENV, "")):
        return True
    return _workspace_config().get(CONFIG_ENABLED) is True


def require_enabled() -> None:
    """Raise the disabled error when detonation is off."""
    if not enabled():
        raise SandboxError(ERROR_DISABLED, DISABLED_DETAIL)


def configured_runner_name() -> str:
    """The runner name the environment or the workspace asks for, or ""."""
    raw = os.environ.get(RUNNER_ENV, "").strip()
    if raw:
        return raw
    value = _workspace_config().get(CONFIG_RUNNER)
    return value.strip() if isinstance(value, str) else ""


class Runner:
    """One sandbox runner: how to invoke it and whether it is installed.

    ``argv`` builds the complete command line for one run, so the surface that
    records it records what actually ran.  A runner is registered in
    :data:`RUNNERS` in-tree or through the ``reportal.sandbox_runners``
    entry-point group.
    """

    def __init__(
        self,
        name: str,
        executable: str,
        *,
        hint: str = "",
        describe: str = "",
    ) -> None:
        self.name = name
        self.executable = executable
        self.hint = hint
        self.describe = describe

    def path(self) -> str | None:
        """The installed executable's path, or None when it is not installed."""
        return shutil.which(self.executable)

    def available(self) -> bool:
        return self.path() is not None

    def argv(self, sample: Path, work: Path, caps: Caps) -> list[str]:
        """The command line that runs *sample* under *caps*, writing to *work*."""
        raise NotImplementedError


class BwrapRunner(Runner):
    """bubblewrap: namespaces, a read-only root and one writable directory.

    The caps are applied by the shell inside the sandbox rather than by
    ``preexec_fn``, which Python documents as unsafe in a threaded server: the
    ``ulimit`` builtin sets them for the sample the shell then ``exec``s.
    """

    def __init__(self) -> None:
        super().__init__(
            "bwrap",
            "bwrap",
            hint="install bubblewrap (apt install bubblewrap) or register another runner",
            describe="bubblewrap: unshared network/PID/mount namespaces, read-only root",
        )

    def argv(self, sample: Path, work: Path, caps: Caps) -> list[str]:
        """The command line that runs *sample* under *caps*, writing to *work*.

        The command is the runner's own name when it cannot be resolved to a
        path: availability is the caller's guard (``require_runner``), so this
        stays a pure function of its arguments and the guards it builds can be
        asserted on a host that does not have the tool installed.
        """
        path = self.path() or self.executable
        limits = (
            f"ulimit -t {caps.cpu_seconds} -v {caps.memory_mb * 1024}"
            f' -f {caps.file_mb * 1024} -u 64 -c 0; exec "$0"'
        )
        return [
            path,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--bind",
            str(work),
            WORKDIR_MOUNT,
            "--chdir",
            WORKDIR_MOUNT,
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--setenv",
            "HOME",
            WORKDIR_MOUNT,
            "--setenv",
            "TMPDIR",
            WORKDIR_MOUNT,
            "--ro-bind",
            str(sample),
            SAMPLE_MOUNT,
            "--",
            _SHELL,
            "-c",
            limits,
            SAMPLE_MOUNT,
        ]


# The runners reportal ships, in the order :func:`available_runner` tries them.
RUNNERS: list[Runner] = [BwrapRunner()]

# The in-tree runner name.  Withdrawing it is refused: a workspace with no
# plugin still needs a runner, and the refresh path documents it as unremovable.
BUILTIN_RUNNER = RUNNERS[0].name


def register_runner(runner: Runner) -> Runner:
    """Register *runner*; a duplicate name replaces the earlier declaration.

    Replacement (rather than the :class:`RegistryError` the other registries
    raise) keeps :func:`refresh_runners` idempotent across re-scans.
    """
    RUNNERS[:] = [existing for existing in RUNNERS if existing.name != runner.name]
    RUNNERS.append(runner)
    return runner


def unregister_runner(name: str) -> None:
    """Withdraw the runner registered as *name*.

    Raises :class:`RegistryError` for a name nothing holds and for the
    built-in runner, which the refresh path documents as unremovable: a
    workspace with no plugin still has `bwrap`.
    """
    from reportal.plugins import RegistryError

    if name not in [runner.name for runner in RUNNERS]:
        raise RegistryError(f"no runner registration {name!r} to withdraw")
    if name == BUILTIN_RUNNER:
        raise RegistryError(f"cannot withdraw the built-in runner {name!r}")
    RUNNERS[:] = [runner for runner in RUNNERS if runner.name != name]


def registered_runners() -> list[Runner]:
    """Every registered runner, installed or not."""
    return list(RUNNERS)


def get_runner(name: str) -> Runner | None:
    """One registered runner by name, or None."""
    for runner in RUNNERS:
        if runner.name == name:
            return runner
    return None


def available_runner() -> Runner | None:
    """The runner a run would use: the configured one, else the first installed.

    A configured name that is not registered, or is registered but not
    installed, is reported as unavailable rather than silently falling back to
    another runner: an operator who names one means it.
    """
    wanted = configured_runner_name()
    if wanted:
        runner = get_runner(wanted)
        if runner is None or not runner.available():
            return None
        return runner
    for runner in RUNNERS:
        if runner.available():
            return runner
    return None


def unavailable_detail() -> str:
    """Why no runner is available, naming what to install or register."""
    wanted = configured_runner_name()
    if wanted:
        return f"the configured sandbox runner {wanted!r} is not registered or not installed"
    hints = [runner.hint for runner in RUNNERS if runner.hint]
    return "no sandbox runner is installed; " + ("; ".join(hints) or "register one")


def require_runner() -> Runner:
    """The available runner, or the unavailable error naming what is missing."""
    runner = available_runner()
    if runner is None:
        raise SandboxError(ERROR_UNAVAILABLE, unavailable_detail())
    return runner


def _drop_incomplete_leading_utf8(data: bytes) -> bytes:
    """Drop leading continuation bytes left after a mid-sequence byte seek."""
    index = 0
    while index < len(data) and data[index] & 0xC0 == 0x80:
        index += 1
    return data[index:]


def _read_tail(path: Path, limit: int) -> tuple[str, bool]:
    """The last *limit* bytes of *path* as text, and whether it was truncated."""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > limit:
                handle.seek(size - limit)
            data = handle.read(limit)
    except OSError:
        return "", False
    if size > limit:
        data = _drop_incomplete_leading_utf8(data)
    return data.decode("utf-8", "replace"), size > limit


def _list_work(work: Path) -> tuple[list[dict[str, Any]], bool]:
    """What the sample wrote into its writable directory, bounded.

    The listing is the report's "files it wrote": the directory starts empty and
    reportal owns it, so everything in it came from the run.
    """
    entries: list[dict[str, Any]] = []
    truncated = False
    for root, _dirs, names in os.walk(work):
        for name in sorted(names):
            if len(entries) >= MAX_FILES:
                truncated = True
                break
            # The read-only sample bind is not something the run wrote.
            if Path(root) == work and name == SAMPLE_NAME:
                continue
            full = Path(root) / name
            with contextlib.suppress(OSError):
                entries.append(
                    {
                        "path": str(full.relative_to(work)),
                        "size": full.stat().st_size,
                    }
                )
        if truncated:
            break
    return entries, truncated


def execute(
    sample: Path,
    *,
    caps: Caps | None = None,
    runner: Runner | None = None,
) -> dict[str, Any]:
    """Run *sample* under *runner* and return the report.

    The caller checks the opt-in, the runner and the file; this does the work.
    The sample is bind-mounted read-only and never executed from its stored
    path, the only writable path it sees is a fresh directory reportal removes
    afterwards, and a run that outlives its timeout is killed by process group
    (bwrap's ``--die-with-parent`` and its own session make the group the whole
    sandbox).
    """
    resolved_caps = caps or requested_caps()
    chosen = runner or require_runner()
    work = Path(tempfile.mkdtemp(dir=binaries_dir(), prefix=".sandbox-"))
    out_path = work.parent / f"{work.name}.stdout"
    err_path = work.parent / f"{work.name}.stderr"
    notes: list[str] = []
    status = STATUS_FINISHED
    exit_code: int | None = None
    timed_out = False
    started = time.monotonic()
    try:
        # cordis-boundary: detonation is an emission, not a restorable effect.  What
        # the sample did to the world outside this process group cannot be undone;
        # the process-group kill and the cleanup below are the compensation, and the
        # three paths reportal *does* own (the work directory and the two output
        # files) are inverted in the `finally`, whatever the runner raised.
        argv = chosen.argv(sample, work, resolved_caps)
        try:
            with out_path.open("wb") as out, err_path.open("wb") as err:
                process = subprocess.Popen(
                    argv,
                    stdout=out,
                    stderr=err,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                    env={"PATH": "/usr/bin:/bin"},
                )
                try:
                    exit_code = process.wait(timeout=resolved_caps.timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    status = STATUS_TIMED_OUT
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    try:
                        exit_code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        # The group kill did not reap the child; a second signal
                        # and wait keep it from lingering as a zombie under load.
                        with contextlib.suppress(ProcessLookupError, PermissionError):
                            process.kill()
                        with contextlib.suppress(subprocess.TimeoutExpired):
                            exit_code = process.wait(timeout=5)
                    notes.append(
                        f"the sample outlived the {resolved_caps.timeout_seconds}s"
                        " wall-clock timeout and was killed by process group"
                    )
        except OSError as exc:
            status = STATUS_FAILED
            notes.append(f"the runner could not be started: {exc}")
        duration_ms = int((time.monotonic() - started) * 1000)
        stdout, stdout_cut = _read_tail(out_path, MAX_OUTPUT_BYTES)
        stderr, stderr_cut = _read_tail(err_path, MAX_OUTPUT_BYTES)
        files, files_cut = _list_work(work)
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(work, ignore_errors=True)
        for leftover in (out_path, err_path):
            with contextlib.suppress(OSError):
                leftover.unlink(missing_ok=True)
    if stdout_cut:
        notes.append(f"stdout was truncated to its last {MAX_OUTPUT_BYTES} bytes")
    if stderr_cut:
        notes.append(f"stderr was truncated to its last {MAX_OUTPUT_BYTES} bytes")
    if files_cut:
        notes.append(f"the file listing was truncated to {MAX_FILES} entries")
    return {
        "status": status,
        "runner": chosen.name,
        "argv": argv,
        "caps": resolved_caps.as_payload(),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
        "files": files,
        "notes": notes,
    }


# ── The run table ──────────────────────────────────────────────────


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the run table when the database predates it."""
    conn.executescript(_SCHEMA)


def _row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """One run row as the API reports it."""
    return {
        "id": int(row["id"]),
        "analysis_id": int(row["analysis_id"]),
        "binary_id": int(row["binary_id"]),
        "sha256": str(row["sha256"]),
        "status": str(row["status"]),
        "runner": str(row["runner"]),
        "argv": json.loads(str(row["argv_json"]) or "[]"),
        "caps": json.loads(str(row["caps_json"]) or "{}"),
        "exit_code": None if row["exit_code"] is None else int(row["exit_code"]),
        "timed_out": bool(row["timed_out"]),
        "duration_ms": int(row["duration_ms"]),
        "stdout": str(row["stdout"]),
        "stderr": str(row["stderr"]),
        "files": json.loads(str(row["files_json"]) or "[]"),
        "notes": json.loads(str(row["notes_json"]) or "[]"),
        "created_at": str(row["created_at"]),
        "finished_at": None if row["finished_at"] is None else str(row["finished_at"]),
    }


def start_run(
    conn: sqlite3.Connection,
    *,
    analysis_id: int,
    binary_id: int,
    sha256: str,
    runner: str,
    argv: Sequence[str],
    caps: Caps,
) -> int:
    """Record a run as ``running`` before it starts; returns its id.

    The row exists first so a caller reading the status route while the sandbox
    runs sees a run in progress, and a process that dies mid-run leaves the
    ``running`` row behind rather than a silent gap.
    """
    ensure_schema(conn)
    cursor = conn.execute(
        f"INSERT INTO {TABLE} (analysis_id, binary_id, sha256, status, runner,"
        " argv_json, caps_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            analysis_id,
            binary_id,
            sha256,
            STATUS_RUNNING,
            runner,
            json.dumps(list(argv)),
            json.dumps(caps.as_payload()),
            store.now(),
        ),
    )
    conn.commit()
    return int(cursor.lastrowid or 0)


def finish_run(conn: sqlite3.Connection, run_id: int, report: Mapping[str, Any]) -> None:
    """Store what a finished run reported."""
    conn.execute(
        f"UPDATE {TABLE} SET status = ?, exit_code = ?, timed_out = ?, duration_ms = ?,"
        " stdout = ?, stderr = ?, files_json = ?, notes_json = ?, finished_at = ?"
        " WHERE id = ?",
        (
            str(report["status"]),
            None if report.get("exit_code") is None else int(report["exit_code"]),
            1 if report.get("timed_out") else 0,
            int(report.get("duration_ms") or 0),
            str(report.get("stdout") or ""),
            str(report.get("stderr") or ""),
            json.dumps(list(report.get("files") or [])),
            json.dumps(list(report.get("notes") or [])),
            store.now(),
            run_id,
        ),
    )
    conn.commit()


def get_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    """One run by id, or None when the id is unknown."""
    ensure_schema(conn)
    row = conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (run_id,)).fetchone()
    return _row(row) if row else None


def latest_run(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any] | None:
    """The newest run of one analysis, or None before the first."""
    ensure_schema(conn)
    row = conn.execute(
        f"SELECT * FROM {TABLE} WHERE analysis_id = ? ORDER BY id DESC LIMIT 1", (analysis_id,)
    ).fetchone()
    return _row(row) if row else None


def list_runs(
    conn: sqlite3.Connection, analysis_id: int, *, limit: int = 20
) -> list[dict[str, Any]]:
    """One analysis's runs, newest first, bounded."""
    ensure_schema(conn)
    bounded = max(1, min(int(limit), 200))
    rows = conn.execute(
        f"SELECT * FROM {TABLE} WHERE analysis_id = ? ORDER BY id DESC LIMIT ?",
        (analysis_id, bounded),
    ).fetchall()
    return [_row(row) for row in rows]


def count_runs(conn: sqlite3.Connection, analysis_id: int) -> int:
    """How many runs one analysis holds."""
    ensure_schema(conn)
    return int(
        conn.execute(
            f"SELECT COUNT(*) AS n FROM {TABLE} WHERE analysis_id = ?", (analysis_id,)
        ).fetchone()["n"]
    )


def status_payload(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any]:
    """The detonation status of one analysis: whether it can run and its last run."""
    runner = available_runner()
    last = latest_run(conn, analysis_id)
    return {
        "analysis_id": analysis_id,
        "enabled": enabled(),
        "available": runner is not None,
        "runner": None if runner is None else runner.name,
        "runners": [
            {"name": entry.name, "available": entry.available(), "describe": entry.describe}
            for entry in registered_runners()
        ],
        "caps": {
            "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
            "max_timeout_seconds": MAX_TIMEOUT_SECONDS,
            "memory_mb": DEFAULT_MEMORY_MB,
            "max_memory_mb": MAX_MEMORY_MB,
        },
        "runs": count_runs(conn, analysis_id),
        "last": None
        if last is None
        else {
            "id": last["id"],
            "status": last["status"],
            "timed_out": last["timed_out"],
            "exit_code": last["exit_code"],
            "duration_ms": last["duration_ms"],
            "created_at": last["created_at"],
        },
        "note": (
            "a run executes the stored sample under the runner, with no network and a"
            " read-only root; it is refused unless the workspace opts in"
        ),
    }


# ── The entry-point registry ───────────────────────────────────────


def refresh_runners() -> list[str]:
    """Re-discover the ``reportal.sandbox_runners`` group; returns the names.

    The group is read through the one entry-point reader
    (:mod:`reportal.plugins`), whose value is a :class:`Runner` or a
    zero-argument factory returning one.  A broken registration is skipped with
    a warning there and a duplicate name replaces the earlier declaration here.
    The runner reportal ships cannot be removed: a workspace with no plugin
    still has `bwrap`.
    """
    from reportal import plugins

    for _name, _value, plugin in plugins.load(RUNNER_ENTRY_POINT_GROUP, Runner, "Runner"):
        register_runner(plugin)
    return [runner.name for runner in RUNNERS]


def detonate_binary(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    timeout: int | None = None,
    memory_mb: int | None = None,
) -> dict[str, Any]:
    """Run one stored binary under the sandbox and store the report.

    Shared by the HTTP route, the CLI and the MCP tool, so the four guards are
    checked once: the workspace opt-in, an installed runner, a file on disk, and
    bounds inside the caps.  The run row is written before the sample starts and
    updated with the report after, so a reader sees a run in progress and a
    process that dies mid-run leaves the `running` row behind.  An exception
    from the runner closes the row as ``failed`` instead, so a Python failure
    never looks like a detonation still in flight.  Raises
    :class:`SandboxError` for every refusal.
    """
    require_enabled()
    runner = require_runner()
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise SandboxError("binary not found", f"no binary with id {binary_id}")
    stored = Path(str(binary["path"]))
    if not stored.is_file():
        raise SandboxError(
            "binary not on disk", f"binary {binary_id} has no file at {binary['path']!r}"
        )
    caps = requested_caps(timeout=timeout, memory_mb=memory_mb)
    analysis_before = store.latest_analysis_for_binary(conn, binary_id)
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="sandbox")
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        if analysis_before is None:
            journal.journaled_create(
                log,
                table="analyses",
                key=analysis_id,
                description=f"created analysis {analysis_id} for binary {binary_id}",
            )
        run_id = start_run(
            conn,
            analysis_id=analysis_id,
            binary_id=binary_id,
            sha256=str(binary["sha256"] or ""),
            runner=runner.name,
            argv=runner.argv(stored, Path("/dev/null"), caps),
            caps=caps,
        )
        journal.journaled_create(
            log,
            table=TABLE,
            key=run_id,
            description=f"ran binary {binary_id} in the {runner.name} sandbox",
        )
        # A process kill still leaves ``running`` (no Python frame to close the
        # row).  A raised exception here must not: the status route would then
        # report a perpetual in-progress detonation.
        try:
            report = execute(stored, caps=caps, runner=runner)
        except Exception as exc:
            finish_run(
                conn,
                run_id,
                {
                    "status": STATUS_FAILED,
                    "timed_out": False,
                    "exit_code": None,
                    "duration_ms": 0,
                    "stdout": "",
                    "stderr": "",
                    "files": [],
                    "notes": [f"detonation aborted: {exc}"],
                },
            )
            raise
        finish_run(conn, run_id, report)
        finished = get_run(conn, run_id)
    return log.attach(finished or {"id": run_id, **report})

"""Guarded sandbox detonation: run a stored sample, off by default, and record it.

reportal reads bytes and never runs a sample, with exactly one exception, and
this is it.  The hosted portal detonates a sample in its own sandbox and reports
what it did; the local form runs the sample under a sandbox runner that is
installed on the machine, with no network, a read-only root, its own PID and
mount namespaces, a memory and CPU cap and a wall-clock timeout, and records the
run: the command it issued, the caps in force, the exit status, how long it
took, a stdout/stderr tail and the files the sample wrote into its one writable
directory.

Five guards stand between the route and an execution, and all five must hold:

1. the workspace opts in (``REPORTAL_SANDBOX=enabled`` or ``[sandbox] enabled =
   true``), so the default install still never runs anything (:func:`require_enabled`);
2. a sandbox runner is installed (:func:`require_runner` refuses with
   ``sandbox-unavailable`` and the install hint when none is);
3. the stored binary has a file on disk (the caller checks that before it
   journals anything);
4. every run is bounded by :data:`DEFAULT_TIMEOUT_SECONDS` /
   :data:`MAX_TIMEOUT_SECONDS`, :data:`DEFAULT_MEMORY_MB` / :data:`MAX_MEMORY_MB`
   and a CPU cap, and is recorded whether it finishes or times out;
5. at most one ``running`` detonation per binary: a double-click or a racing
   POST reuses the live row rather than executing the sample a second time
   (:func:`detonate_binary`).

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
import logging
import os
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reportal import journal, observability, store
from reportal._paths import MARKER, WorkspaceNotFound, binaries_dir, project_root

_log = logging.getLogger(__name__)

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
# Keep in sync with ``settings.FLAG_TRUTHY`` / ``FLAG_FALSEY`` (and the other
# flag readers). A falsey env value forces detonation off over the workspace.
_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled", "required"})
_FALSEY = frozenset({"0", "false", "no", "off", "disabled"})

# The fixed detail every disabled or unavailable path reports.
DISABLED_DETAIL = "set REPORTAL_SANDBOX=enabled or [sandbox] enabled = true to allow detonation"

# Caps.  A run may ask for less, never more.
DEFAULT_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 60
DEFAULT_MEMORY_MB = 512
MAX_MEMORY_MB = 4096
MAX_CPU_SECONDS = 60
DEFAULT_FILE_MB = 64
# ``ulimit -v`` is in KiB; ``ulimit -f`` is in 512-byte blocks (POSIX).
MEMORY_ULIMIT_KB_PER_MB = 1024
FILE_ULIMIT_BLOCKS_PER_MB = 2048

# Bytes of stdout and stderr a report keeps, and the files it lists.
MAX_OUTPUT_BYTES = 64 * 1024
MAX_FILES = 200

# Monotonic clock for run duration_ms.  A test patches ``_monotonic`` to pin
# the recorded duration so a failing detonation replays without wall time.
_monotonic = time.monotonic

# Where the writable directory lands inside the sandbox, and the name the
# sample is mounted under inside it.  The mount point has to sit in the
# writable bind: bwrap cannot create it on the read-only root, and a directory
# created before the root bind is hidden by it.
WORKDIR_MOUNT = "/tmp"
SAMPLE_NAME = ".sample"
SAMPLE_MOUNT = f"{WORKDIR_MOUNT}/{SAMPLE_NAME}"

# The shell the caps are applied with, inside the sandbox's read-only root.
_SHELL = "/bin/sh"

# A ``running`` row past the longest allowed wall-clock window plus this grace
# cannot still be executing (the sample is killed at the timeout).  Closing it
# lets a later detonation claim the binary after a crash left the row behind.
LIVE_STALE_GRACE_S = 30


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


def _env_flag(name: str) -> bool | None:
    """True/False when *name* forces on/off; None when unset or unrecognized."""
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
    """The workspace ``reportal.toml`` ``[sandbox]`` table, or an empty dict."""
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return {}
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        # Readers fall back to defaults on a bad file (see settings.problems);
        # without a log that fallback silently disables workspace detonation.
        _log.warning(
            "cannot read %s for [%s]; sandbox.enabled falls back to off: %s",
            marker,
            CONFIG_TABLE,
            exc,
        )
        return {}
    table = document.get(CONFIG_TABLE)
    return table if isinstance(table, dict) else {}


def enabled() -> bool:
    """True when the environment or the workspace config allows detonation.

    A falsey ``REPORTAL_SANDBOX`` forces off even when the workspace file asks
    for detonation: an operator who wrote ``0`` to kill the sandbox must get
    that, not a silent fall-through to ``[sandbox] enabled = true``.
    """
    forced = _env_flag(ENABLED_ENV)
    if forced is not None:
        return forced
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
            f"ulimit -t {caps.cpu_seconds}"
            f" -v {caps.memory_mb * MEMORY_ULIMIT_KB_PER_MB}"
            f" -f {caps.file_mb * FILE_ULIMIT_BLOCKS_PER_MB}"
            f' -u 64 -c 0; exec "$0"'
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
_RUNNERS_LOCK = threading.RLock()

# The in-tree runner name.  Withdrawing it is refused: a workspace with no
# plugin still needs a runner, and the refresh path documents it as unremovable.
BUILTIN_RUNNER = RUNNERS[0].name


def register_runner(runner: Runner) -> Runner:
    """Register *runner*; a duplicate name replaces the earlier declaration.

    Replacement (rather than the :class:`RegistryError` the other registries
    raise) keeps :func:`refresh_runners` idempotent across re-scans.
    """
    with _RUNNERS_LOCK:
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

    with _RUNNERS_LOCK:
        if name not in [runner.name for runner in RUNNERS]:
            raise RegistryError(f"no runner registration {name!r} to withdraw")
        if name == BUILTIN_RUNNER:
            raise RegistryError(f"cannot withdraw the built-in runner {name!r}")
        RUNNERS[:] = [runner for runner in RUNNERS if runner.name != name]


def registered_runners() -> list[Runner]:
    """Every registered runner, installed or not."""
    with _RUNNERS_LOCK:
        return list(RUNNERS)


def get_runner(name: str) -> Runner | None:
    """One registered runner by name, or None."""
    with _RUNNERS_LOCK:
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
    with _RUNNERS_LOCK:
        runners = list(RUNNERS)
    for runner in runners:
        if runner.available():
            return runner
    return None


def unavailable_detail() -> str:
    """Why no runner is available, naming what to install or register."""
    wanted = configured_runner_name()
    if wanted:
        return f"the configured sandbox runner {wanted!r} is not registered or not installed"
    with _RUNNERS_LOCK:
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
    started = _monotonic()
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
        duration_ms = int((_monotonic() - started) * 1000)
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
    """Create the run table when the database predates it.

    Before the live-binary unique index applies, older duplicate ``running``
    rows (possible before the index existed) are collapsed so the index can
    be created on an upgraded database.
    """
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {TABLE} ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,"
        " binary_id INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,"
        " sha256 TEXT NOT NULL DEFAULT '',"
        f" status TEXT NOT NULL DEFAULT '{STATUS_RUNNING}',"
        " runner TEXT NOT NULL DEFAULT '',"
        " argv_json TEXT NOT NULL DEFAULT '[]',"
        " caps_json TEXT NOT NULL DEFAULT '{}',"
        " exit_code INTEGER,"
        " timed_out INTEGER NOT NULL DEFAULT 0,"
        " duration_ms INTEGER NOT NULL DEFAULT 0,"
        " stdout TEXT NOT NULL DEFAULT '',"
        " stderr TEXT NOT NULL DEFAULT '',"
        " files_json TEXT NOT NULL DEFAULT '[]',"
        " notes_json TEXT NOT NULL DEFAULT '[]',"
        " created_at TEXT NOT NULL,"
        " finished_at TEXT)"
    )
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_sandbox_runs_analysis ON {TABLE}(analysis_id)")
    # Keep the newest running row per binary; mark older siblings failed so the
    # unique live index can apply on a database that predates it.
    duplicates = conn.execute(
        f"SELECT binary_id, MAX(id) AS keep_id FROM {TABLE}"
        f" WHERE status = ? GROUP BY binary_id HAVING COUNT(*) > 1",
        (STATUS_RUNNING,),
    ).fetchall()
    for row in duplicates:
        conn.execute(
            f"UPDATE {TABLE} SET status = ?, notes_json = ?, finished_at = ?"
            " WHERE binary_id = ? AND status = ? AND id != ?",
            (
                STATUS_FAILED,
                json.dumps(["abandoned: superseded by a newer live detonation"]),
                store.now(),
                int(row["binary_id"]),
                STATUS_RUNNING,
                int(row["keep_id"]),
            ),
        )
    conn.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS idx_sandbox_runs_live_binary"
        f" ON {TABLE}(binary_id) WHERE status = '{STATUS_RUNNING}'"
    )


def find_live_run(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """The in-progress detonation for *binary_id*, or None."""
    ensure_schema(conn)
    row = conn.execute(
        f"SELECT * FROM {TABLE} WHERE binary_id = ? AND status = ? ORDER BY id LIMIT 1",
        (binary_id, STATUS_RUNNING),
    ).fetchone()
    return _row(row) if row else None


def abandon_stale_live_runs(conn: sqlite3.Connection, binary_id: int) -> int:
    """Close ``running`` rows past the max detonation window; returns how many.

    A process killed mid-run leaves ``running`` forever.  Past
    :data:`MAX_TIMEOUT_SECONDS` plus :data:`LIVE_STALE_GRACE_S` that row cannot
    still be executing, so a later detonation must be able to claim the binary.
    """
    ensure_schema(conn)
    now = store.as_utc(store.now())
    limit_s = MAX_TIMEOUT_SECONDS + LIVE_STALE_GRACE_S
    closed = 0
    for row in conn.execute(
        f"SELECT id, created_at FROM {TABLE} WHERE binary_id = ? AND status = ?",
        (binary_id, STATUS_RUNNING),
    ).fetchall():
        try:
            created = store.as_utc(str(row["created_at"]))
        except ValueError:
            created = now
        if (now - created).total_seconds() <= limit_s:
            continue
        finish_run(
            conn,
            int(row["id"]),
            {
                "status": STATUS_FAILED,
                "timed_out": False,
                "exit_code": None,
                "duration_ms": 0,
                "stdout": "",
                "stderr": "",
                "files": [],
                "notes": ["abandoned: running past the maximum detonation window"],
            },
        )
        closed += 1
    return closed


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
) -> tuple[int, bool]:
    """Claim a ``running`` row before the sample starts; returns ``(id, created)``.

    The row exists first so a caller reading the status route while the sandbox
    runs sees a run in progress, and a process that dies mid-run leaves the
    ``running`` row behind rather than a silent gap.  A second claim for the
    same binary while one is still live returns that row with ``created=False``:
    the unique live-binary index is the lock, so a double-click cannot execute
    the sample twice.
    """
    ensure_schema(conn)
    abandon_stale_live_runs(conn, binary_id)
    try:
        with conn:
            conn.execute("BEGIN IMMEDIATE")
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
        return int(cursor.lastrowid or 0), True
    except sqlite3.IntegrityError:
        existing = find_live_run(conn, binary_id)
        if existing is not None:
            return int(existing["id"]), False
        raise


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
    with _RUNNERS_LOCK:
        return [runner.name for runner in RUNNERS]


def detonate_binary(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    timeout: int | None = None,
    memory_mb: int | None = None,
) -> dict[str, Any]:
    """Run one stored binary under the sandbox and store the report.

    Shared by the HTTP route, the CLI and the MCP tool, so the five guards are
    checked once: the workspace opt-in, an installed runner, a file on disk,
    bounds inside the caps, and at most one live detonation per binary.  A
    second call while a run is still ``running`` returns that row without
    executing again.  The run row is written before the sample starts and
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
    abandon_stale_live_runs(conn, binary_id)
    live = find_live_run(conn, binary_id)
    if live is not None:
        return live
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
        run_id, created = start_run(
            conn,
            analysis_id=analysis_id,
            binary_id=binary_id,
            sha256=str(binary["sha256"] or ""),
            runner=runner.name,
            argv=runner.argv(stored, Path("/dev/null"), caps),
            caps=caps,
        )
        if not created:
            # Lost the live-row race: another detonation is already executing.
            raced = get_run(conn, run_id)
            return raced or {"id": run_id, "status": STATUS_RUNNING, "binary_id": binary_id}
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
            _log.error(
                "sandbox detonation aborted run_id=%s binary_id=%s error=%s%s",
                run_id,
                binary_id,
                f"{type(exc).__name__}: {exc}"[:200],
                observability.request_id_suffix(),
                exc_info=exc,
            )
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

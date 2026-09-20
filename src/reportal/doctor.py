"""Pre-flight readiness: can this install serve, and what is missing if not.

``GET /api/health`` answers the same question from inside a running server.  It
cannot answer it *before* one starts, and it cannot check the two things a
start depends on: whether the SPA has a build (the server answers 503 at ``/``
without one) and whether the port is free.  ``reportal doctor`` is that half,
so a unit file can gate its own start on it and an operator can see the posture
of an install in one read.

Every check is a read.  Nothing here writes a row, creates a database file or
binds a socket for longer than the probe itself: a missing workspace is a
reported failure, never a directory reportal creates.  ``status`` is one of
``ok`` (the path works), ``warn`` (it works, with a caveat the caller should
know) and ``fail`` (the portal cannot serve correctly until it is fixed); a
warn never changes the process exit code, a fail always does.

The optional paths are reported as one check rather than several, because "the
similarity extra is not installed" is a fact about an install that chose not to
install it, not a defect to scroll past: the check warns only when a path is
asked for and unusable (detonation opted in with no runner, remote sources
opted in with no key, a graph backend whose package is missing) and lists every
path's state either way.
"""

from __future__ import annotations

import contextlib
import os
import socket
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from reportal import (
    __version__,
    auth,
    backup,
    billing,
    engines,
    external,
    graph_backends,
    llm,
    profiles,
    remote_ingest,
    sandbox,
    settings,
    similarity,
    store,
    ui,
)
from reportal._paths import WorkspaceNotFound, db_path, project_root

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"

STATUSES: tuple[str, ...] = (STATUS_OK, STATUS_WARN, STATUS_FAIL)

# The port ``reportal serve`` binds unless it is asked for another one.  It
# lives here so the command's default, the unit file's example and the readiness
# check cannot drift apart.
DEFAULT_PORT = 8002

HOST = "127.0.0.1"

WORKSPACE_HINT = "run 'reportal init' in the directory that should hold the workspace"
DATABASE_HINT = "check the path and its permissions, or run 'reportal init'"
SCHEMA_HINT = "the database exists but carries no schema; run 'reportal init'"
PORT_HINT = "stop the process holding the port, or serve on another one (--port)"
ENGINE_HINT = engines.ENGINE_UNAVAILABLE_HINT
SPA_HINT = ui.UI_NOT_BUILT_DETAIL
BACKUP_HINT = (
    "enable reportal-backup.timer or run 'reportal backup'; see docs/DR_RUNBOOK.md"
)

# The tables a usable schema needs before any read.  The journal's table is
# created on first use, so it is deliberately not required: a fresh workspace
# has it only after its first action.  The rest of the schema is proved by
# ``store.counts`` answering, which is what turns a corrupt or half-written file
# into a reported failure rather than a traceback.
REQUIRED_TABLES: tuple[str, ...] = ("binaries", "analyses", "functions", "scans")

# systemd unit templates.  The repository's ``deploy/`` directory is the source
# of truth; ``scripts/sync_packaged_deploy.py`` mirrors them into the packaged
# ``deploy/`` directory the wheel ships so a host without a checkout still has
# the templates ``reportal deploy-units`` prints.
DEPLOY_DIRECTORY = "deploy"
DEPLOY_UNIT_FILES: tuple[str, ...] = (
    "reportal.service",
    "reportal-backup.service",
    "reportal-backup.timer",
)


def deploy_units_dir() -> Path | None:
    """Directory that holds the systemd unit templates, or None when absent.

    Prefers the repository ``deploy/`` beside a checkout (editable install or
    working tree), then the packaged ``reportal/deploy/`` directory the wheel
    ships.  None means neither resolved, so ``reportal deploy-units`` fails
    rather than pointing at an empty path.
    """
    checkout = Path(__file__).resolve().parent.parent.parent / DEPLOY_DIRECTORY
    if _complete_deploy_dir(checkout):
        return checkout
    packaged = Path(__file__).resolve().parent / DEPLOY_DIRECTORY
    if _complete_deploy_dir(packaged):
        return packaged
    return None


def deploy_unit_paths() -> dict[str, Path] | None:
    """Map each required unit name to its path, or None when the set is incomplete."""
    directory = deploy_units_dir()
    if directory is None:
        return None
    return {name: directory / name for name in DEPLOY_UNIT_FILES}


def _complete_deploy_dir(directory: Path) -> bool:
    """True when *directory* carries every required unit template as a file."""
    return directory.is_dir() and all((directory / name).is_file() for name in DEPLOY_UNIT_FILES)


def _check(name: str, status: str, detail: str, hint: str = "") -> dict[str, str]:
    """One check row: its name, its status, what it found and what to do."""
    return {"name": name, "status": status, "detail": detail, "hint": hint}


def _schema_check(path: Path) -> tuple[dict[str, str], sqlite3.Connection | None]:
    """Open the database read-only and report whether its schema is usable."""
    if not path.is_file():
        return _check("schema", STATUS_FAIL, f"no database at {path}", DATABASE_HINT), None
    try:
        conn = store.connect(path)
    except sqlite3.Error as exc:
        return _check("schema", STATUS_FAIL, f"cannot open {path}: {exc}", DATABASE_HINT), None
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        names = {str(row[0]) for row in rows}
        missing = [table for table in REQUIRED_TABLES if table not in names]
        if missing:
            return (
                _check(
                    "schema",
                    STATUS_FAIL,
                    f"{path} is missing {', '.join(missing)}",
                    SCHEMA_HINT,
                ),
                conn,
            )
        counted = store.counts(conn)
        return (
            _check(
                "schema",
                STATUS_OK,
                f"{len(names)} tables, {counted['binaries']} binaries,"
                f" {counted['analyses']} analyses, {counted['functions']} functions",
            ),
            conn,
        )
    except sqlite3.Error as exc:
        with contextlib.closing(conn):
            pass
        return _check("schema", STATUS_FAIL, f"cannot read {path}: {exc}", SCHEMA_HINT), None


def _port_check(port: int) -> dict[str, str]:
    """Whether *port* can be bound on loopback, without holding it."""
    if port <= 0:
        return _check("port", STATUS_OK, "not checked")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # uvicorn binds with SO_REUSEADDR, so a TIME_WAIT socket from a
        # previous run does not block it and must not be reported as a conflict.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((HOST, port))
    except OSError as exc:
        return _check("port", STATUS_FAIL, f"{HOST}:{port} is not bindable: {exc}", PORT_HINT)
    finally:
        probe.close()
    return _check("port", STATUS_OK, f"{HOST}:{port} is free")


def _backup_check(root: Path | None) -> dict[str, str]:
    """Whether a recent workspace archive exists beside this install.

    A warn never blocks serve: backups are an operator schedule, not a start
    gate.  Silence means the newest archive under the sibling
    ``reportal-backups/`` or ``/srv/backups`` is younger than
    :data:`backup.FRESH_SECONDS` (two daily intervals).
    """
    if root is None:
        return _check("backup", STATUS_WARN, "no workspace to locate archives beside", BACKUP_HINT)
    directories = backup.archive_dirs(root)
    if not directories:
        return _check(
            "backup",
            STATUS_WARN,
            "no archive directory beside the workspace or at /srv/backups",
            BACKUP_HINT,
        )
    newest = backup.newest_archive(root)
    if newest is None:
        listed = ", ".join(str(path) for path in directories)
        return _check(
            "backup",
            STATUS_WARN,
            f"no reportal archives under {listed}",
            BACKUP_HINT,
        )
    age = max(0.0, time.time() - newest.stat().st_mtime)
    detail = f"{newest} ({_format_age(age)} old)"
    if age > backup.FRESH_SECONDS:
        return _check(
            "backup",
            STATUS_WARN,
            f"newest archive is stale: {detail}",
            BACKUP_HINT,
        )
    return _check("backup", STATUS_OK, detail)


def _format_age(seconds: float) -> str:
    """A short age string for the backup check detail."""
    hours = int(seconds // 3600)
    if hours < 48:
        return f"{hours}h"
    return f"{hours // 24}d"


def _optional_check() -> dict[str, str]:
    """Every optional path, with a warn for one that is asked for and unusable.

    The key probes are cheap reads: the LLM client reports whether an endpoint
    is configured, ``external.virustotal_key`` reads the environment, the
    workspace table and the store, and the graph backend registry reports each
    backend's availability.
    """
    enabled = sandbox.enabled()
    runner = sandbox.available_runner() if enabled else None
    external_on = external.remote_enabled()
    key_present = bool(external.virustotal_key()) if external_on else False
    backend = graph_backends.configured_backend_name()
    backend_entry = next(
        (entry for entry in graph_backends.graph_backends() if entry.name == backend), None
    )
    states = [
        f"profile={profiles.current()}",
        f"llm={'on' if llm.get_client().available() else 'off'}",
        f"similarity={'on' if similarity.available() else 'off'}",
        f"sandbox={'on' if enabled else 'off'}",
        f"external={'on' if external_on else 'off'}",
        f"remote_ingest={'on' if remote_ingest.remote_enabled() else 'off'}",
        f"graph_backend={backend}",
    ]
    broken: list[str] = []
    if profiles.is_saas() and not billing.billing_configured():
        broken.append(
            "the saas profile is on but no billing provider is configured;"
            " quotas enforce against plans nobody can buy"
        )
    if enabled and runner is None:
        broken.append("detonation is opted in but no sandbox runner is installed")
    if external_on and not key_present:
        broken.append("remote sources are opted in but no VirusTotal key resolves")
    if backend_entry is not None and not backend_entry.available():
        broken.append(f"the {backend} graph backend is configured but not installed")
    if backend_entry is None:
        broken.append(f"the graph backend {backend!r} is not registered")
    if (
        billing.provider_name() == billing.PROVIDER_STRIPE
        and billing.billing_configured()
        and _loopback_public_base_url(billing.public_base_url())
    ):
        broken.append(
            "Stripe billing is configured but REPORTAL_PUBLIC_BASE_URL still"
            f" points at loopback ({billing.public_base_url()})"
        )
    detail = ", ".join(states)
    if broken:
        return _check("optional", STATUS_WARN, detail, "; ".join(broken))
    return _check("optional", STATUS_OK, detail)


def _loopback_public_base_url(url: str) -> bool:
    """True when *url* would send a paying customer back to this host only."""
    lowered = url.strip().lower()
    return "127.0.0.1" in lowered or "localhost" in lowered or "[::1]" in lowered


def _config_check() -> dict[str, str]:
    """Whether the workspace file is one reportal reads.

    A file reportal cannot parse is a failure: every reader catches the parse
    error and falls back to its default, so the install serves on defaults while
    the operator believes their settings are in force.  A key or value reportal
    does not read is a warning naming it, because it costs exactly the setting it
    was meant to make.
    """
    problems = settings.problems()
    if not problems:
        return _check("config", STATUS_OK, f"{len(settings.SETTINGS)} settings, every key read")
    failing = [problem for problem in problems if problem["level"] == STATUS_FAIL]
    if failing:
        problem = failing[0]
        return _check("config", STATUS_FAIL, problem["problem"], problem["hint"])
    ignored = ", ".join(problem["where"] for problem in problems[:3])
    more = "" if len(problems) <= 3 else f" and {len(problems) - 3} more"
    return _check(
        "config",
        STATUS_WARN,
        f"{len(problems)} setting(s) ignored: {ignored}{more}",
        "run 'reportal config' to see what each one costs",
    )


def _auth_check(conn: sqlite3.Connection | None) -> dict[str, str]:
    """The auth posture, and the enabled users a non-loopback bind needs."""
    profile = profiles.current()
    if not auth.required():
        return _check(
            "auth",
            STATUS_OK,
            "single-user: every request is the local operator, and serve refuses a"
            " non-loopback bind",
        )
    if conn is None:
        return _check(
            "auth", STATUS_WARN, "token auth is required but the users table is unreadable"
        )
    users = auth.list_users(conn)
    active = [user for user in users if not user["disabled"]]
    if not active:
        return _check(
            "auth",
            STATUS_FAIL,
            "token auth is required and no enabled user exists",
            "run 'reportal user-add <name>' before serving on a non-loopback host",
        )
    return _check(
        "auth",
        STATUS_OK,
        f"profile {profile}, token auth, {len(active)} enabled user(s)",
    )


def report(*, port: int = DEFAULT_PORT) -> dict[str, Any]:
    """Every readiness check, as the payload the CLI prints and a unit gates on.

    The workspace resolution is the one probe that can fail before anything
    else exists, so it is the first check and the rest run from the workspace it
    found.  ``status`` is ``ok`` when no check failed and ``degraded`` otherwise;
    warnings are listed beside the failures so a unit file can act on the
    difference.
    """
    checks: list[dict[str, str]] = []
    root: Path | None = None
    try:
        root = project_root()
        checks.append(_check("workspace", STATUS_OK, str(root)))
    except WorkspaceNotFound as exc:
        checks.append(_check("workspace", STATUS_FAIL, str(exc), WORKSPACE_HINT))

    conn: sqlite3.Connection | None = None
    if root is None:
        schema = _check("schema", STATUS_FAIL, "no workspace to hold one", WORKSPACE_HINT)
        checks.append(_check("database", STATUS_FAIL, "no workspace to hold one", WORKSPACE_HINT))
    else:
        path = db_path()
        writable = os.access(path, os.W_OK) and os.access(path.parent, os.W_OK)
        if not path.is_file():
            checks.append(_check("database", STATUS_FAIL, f"no database at {path}", DATABASE_HINT))
        elif not writable:
            checks.append(
                _check(
                    "database",
                    STATUS_FAIL,
                    f"{path} accepts no write",
                    DATABASE_HINT,
                )
            )
        else:
            checks.append(_check("database", STATUS_OK, f"{path} accepts a write"))
        schema, conn = _schema_check(path)

    checks.append(schema)
    checks.append(_config_check())
    checks.append(_auth_check(conn))
    if conn is not None:
        with contextlib.closing(conn):
            pass

    engine = engines.get_engine()
    checks.append(
        _check(
            "engine",
            STATUS_OK if engine.available() else STATUS_FAIL,
            engine.origin or "rebrew is not importable",
            "" if engine.available() else ENGINE_HINT,
        )
    )
    index = ui.dist_dir() / ui.APP_INDEX
    checks.append(
        _check(
            "spa",
            STATUS_OK if index.is_file() else STATUS_WARN,
            str(index) if index.is_file() else "no SPA build",
            "" if index.is_file() else SPA_HINT,
        )
    )
    checks.append(_optional_check())
    checks.append(_backup_check(root))
    checks.append(_port_check(port))

    failures = [check["name"] for check in checks if check["status"] == STATUS_FAIL]
    warnings = [check["name"] for check in checks if check["status"] == STATUS_WARN]
    return {
        "status": STATUS_OK if not failures else "degraded",
        "version": __version__,
        "python": sys.version.split()[0],
        "workspace": "" if root is None else str(root),
        "port": port,
        "checks": checks,
        "failures": failures,
        "warnings": warnings,
    }

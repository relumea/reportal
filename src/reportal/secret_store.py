"""The local secret store: named credentials, written once and read redacted.

The hosted portal's settings carry an **API Key** tab and a team admin can set
the team's VirusTotal key for everyone on the team.  reportal's credentials used
to live only in the environment or ``reportal.toml``, which is fine for one
operator and wrong for a portal: no per-team scope, no way to rotate one without
editing a file, and nothing a future external source can read from the store.

This module is that store.  A row is one named credential at one scope
(:data:`SCOPE_LOCAL` for the workspace, :data:`SCOPE_TEAM` for one team), and
the rule the whole surface shares is that a **read never returns the value**:
the API, the CLI and the MCP tools get the name, the scope, the team, the byte
length and a last-four hint, and nothing else.  The value is reachable only
through :func:`value_of` and :func:`resolve_from_workspace`, which internal
consumers call (:mod:`reportal.llm` for the bridge key, and an external source
cluster H adds).

Resolution is first match wins, so an existing install is unchanged: the
environment, then the workspace ``reportal.toml``, then this store.  That order
is deliberate: an operator who exported a variable keeps what they exported, and
a value in the store is the fallback rather than an override.

Who may do what, when auth is on:

* a **local** secret is workspace configuration: any authenticated caller sees
  that it exists, and only an admin writes or deletes it;
* a **team** secret is visible to that team's members (and an admin), and a
  member with write permission may set it, which is the hosted team-admin case;
* with auth off the install is the single local operator, so everything is
  allowed, exactly as the rest of reportal behaves.

Values are local state, at rest in the workspace SQLite file, written in
plaintext.  ``docs/THREAT_MODEL.md`` states what that does and does not protect,
including the one residual worth naming here: the action journal keeps the row a
write replaced, so rotating a secret leaves the previous value in
``journal_entries`` until that action is reverted or pruned.  That is what makes
a rotation revertible, and a caller that wants the old value gone can revert and
re-set instead.
"""

from __future__ import annotations

import contextlib
import re
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any

from reportal import journal, store
from reportal._paths import WorkspaceNotFound, db_path

# Scope a secret lives at.
SCOPE_LOCAL = "local"
SCOPE_TEAM = "team"
SCOPES: tuple[str, ...] = (SCOPE_LOCAL, SCOPE_TEAM)

# The table the store owns (created on first use, so an existing database needs
# no migration).
TABLE = "secrets"

# The team id a local secret stores: 0 rather than NULL, because SQLite treats
# NULLs as distinct in a unique index and a second local secret of one name
# would otherwise be allowed.
NO_TEAM = 0

# Longest secret name, and the shape one may have.  A name is a lowercase
# dotted path (`virustotal.api_key`, `llm.api_key`), never free text, so a
# caller can find one and a typo is a rejection rather than a second row.
MAX_NAME_CHARS = 64
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]*")

# Longest value accepted, in bytes of its UTF-8 encoding.  A credential is a
# token, not a file; a value past the cap is rejected rather than stored.
MAX_VALUE_BYTES = 8192

# Shortest value that gets a last-four hint.  A four-character secret whose
# whole value is the hint would be printed in full, so a short value reports no
# hint at all.
MIN_HINT_LENGTH = 8

# The hint a redacted row carries when the value is too short to hint.
NO_HINT = ""

# Error codes the surface reports, shared by the API, CLI and MCP.
ERROR_INVALID = "invalid secret"
ERROR_NOT_FOUND = "secret not found"
ERROR_FORBIDDEN = "secret forbidden"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT 'local',
    team_id    INTEGER NOT NULL DEFAULT 0,
    value      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_scope ON secrets(name, scope, team_id);
"""


class SecretError(Exception):
    """Base class for a rejected secret-store operation."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


class InvalidSecretError(SecretError, ValueError):
    """A name, value or scope is unusable; the API answers 400."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_INVALID, detail)


class UnknownSecretError(SecretError, LookupError):
    """No secret carries the requested name and scope; the API answers 404."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_NOT_FOUND, detail)


class ForbiddenSecretError(SecretError, PermissionError):
    """The caller may not read or write this secret; the API answers 403."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_FORBIDDEN, detail)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the secret table when the database predates it."""
    conn.executescript(_SCHEMA)


# ── Validation ─────────────────────────────────────────────────────


def normalize_name(name: Any) -> str:
    """Validate a secret name, raising :class:`InvalidSecretError`."""
    if not isinstance(name, str) or not name.strip():
        raise InvalidSecretError("name must be a non-empty string")
    trimmed = name.strip()
    if len(trimmed) > MAX_NAME_CHARS:
        raise InvalidSecretError(f"name exceeds {MAX_NAME_CHARS} characters")
    if not NAME_PATTERN.fullmatch(trimmed):
        raise InvalidSecretError(
            "name must be a lowercase dotted path such as 'virustotal.api_key'"
        )
    return trimmed


def normalize_value(value: Any) -> str:
    """Validate a secret value, raising :class:`InvalidSecretError`."""
    if not isinstance(value, str) or not value:
        raise InvalidSecretError("value must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
        raise InvalidSecretError(f"value exceeds {MAX_VALUE_BYTES} bytes")
    return value


def normalize_scope(scope: Any, team_id: Any) -> tuple[str, int]:
    """Validate a requested scope; returns its scope name and team id."""
    if scope in (None, ""):
        scope = SCOPE_TEAM if team_id else SCOPE_LOCAL
    if not isinstance(scope, str) or scope not in SCOPES:
        raise InvalidSecretError(f"scope must be one of {', '.join(SCOPES)}")
    if scope == SCOPE_LOCAL:
        return SCOPE_LOCAL, NO_TEAM
    if team_id in (None, "", 0):
        raise InvalidSecretError("a team-scoped secret needs a team id")
    if isinstance(team_id, bool) or not isinstance(team_id, int) or team_id < 1:
        raise InvalidSecretError("team id must be a positive integer")
    return SCOPE_TEAM, int(team_id)


def hint_for(value: str) -> str:
    """The last-four hint a redacted row carries, or :data:`NO_HINT`."""
    if len(value) < MIN_HINT_LENGTH:
        return NO_HINT
    return value[-4:]


def _row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """One secret row as every read reports it: never the value."""
    value = str(row["value"])
    return {
        "name": str(row["name"]),
        "scope": str(row["scope"]),
        "team_id": int(row["team_id"]) or None,
        "length": len(value.encode("utf-8")),
        "hint": hint_for(value),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


# ── Store ──────────────────────────────────────────────────────────


def set_secret(
    conn: sqlite3.Connection,
    *,
    name: Any,
    value: Any,
    scope: Any = None,
    team_id: Any = None,
) -> dict[str, Any]:
    """Store or replace one secret; returns the redacted row.

    The scope and the team id are validated by the caller against the team
    table (an unknown team is :class:`reportal.auth.UnknownTeamError` on the
    routes); this function owns the name, the value, the scope vocabulary and
    the upsert.
    """
    ensure_schema(conn)
    resolved_name = normalize_name(name)
    resolved_value = normalize_value(value)
    resolved_scope, resolved_team = normalize_scope(scope, team_id)
    now = store.now()
    conn.execute(
        "INSERT INTO secrets (name, scope, team_id, value, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(name, scope, team_id) DO UPDATE SET value = excluded.value,"
        " updated_at = excluded.updated_at",
        (resolved_name, resolved_scope, resolved_team, resolved_value, now, now),
    )
    conn.commit()
    return get_secret(conn, name=resolved_name, scope=resolved_scope, team_id=resolved_team or None)


def get_secret(
    conn: sqlite3.Connection, *, name: Any, scope: Any = None, team_id: Any = None
) -> dict[str, Any]:
    """The redacted row of one secret; raises :class:`UnknownSecretError`."""
    ensure_schema(conn)
    resolved_name = normalize_name(name)
    resolved_scope, resolved_team = normalize_scope(scope, team_id)
    row = conn.execute(
        "SELECT * FROM secrets WHERE name = ? AND scope = ? AND team_id = ?",
        (resolved_name, resolved_scope, resolved_team),
    ).fetchone()
    if row is None:
        raise UnknownSecretError(f"no secret named {resolved_name!r} at scope {resolved_scope}")
    return _row(row)


def list_secrets(
    conn: sqlite3.Connection, *, scope: Any = None, team_id: Any = None
) -> list[dict[str, Any]]:
    """Every stored secret, newest first, redacted; `?scope=`/`?team_id=` filter."""
    ensure_schema(conn)
    where: list[str] = []
    params: list[Any] = []
    if scope or team_id:
        resolved_scope, resolved_team = normalize_scope(scope, team_id)
        where.append("scope = ?")
        params.append(resolved_scope)
        if resolved_scope == SCOPE_TEAM:
            where.append("team_id = ?")
            params.append(resolved_team)
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    rows = conn.execute(
        f"SELECT * FROM secrets{clause} ORDER BY name, scope, team_id", params
    ).fetchall()
    return [_row(row) for row in rows]


def delete_secret(
    conn: sqlite3.Connection, *, name: Any, scope: Any = None, team_id: Any = None
) -> dict[str, Any]:
    """Remove one secret and return its redacted row; 404 when it does not exist."""
    row = get_secret(conn, name=name, scope=scope, team_id=team_id)
    resolved_scope, resolved_team = normalize_scope(scope, team_id)
    conn.execute(
        "DELETE FROM secrets WHERE name = ? AND scope = ? AND team_id = ?",
        (row["name"], resolved_scope, resolved_team),
    )
    conn.commit()
    return row


def journaled_set(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    name: Any,
    value: Any,
    scope: Any = None,
    team_id: Any = None,
    description: str,
) -> dict[str, Any]:
    """Store one secret inside the caller's journaled action; returns the row.

    This is the one write path the routes, the CLI and the MCP tools share, so
    all three journal the row they replace (or the row they create) identically
    and a rotation is revertible.  The previous value stays in the journal's own
    row snapshot, which is what a revert restores; THREAT_MODEL states it.
    """
    resolved_name = normalize_name(name)
    resolved_scope, resolved_team = normalize_scope(scope, team_id)
    before = journal.journaled_rows(
        conn,
        log,
        table=TABLE,
        where="name = ? AND scope = ? AND team_id = ?",
        params=(resolved_name, resolved_scope, resolved_team),
        description=description,
    )
    row = set_secret(
        conn, name=resolved_name, value=value, scope=resolved_scope, team_id=resolved_team
    )
    if not before:
        journal.journaled_create(
            log,
            table=TABLE,
            key={"name": resolved_name, "scope": resolved_scope, "team_id": resolved_team},
            description=description,
        )
    return row


def journaled_delete(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    name: Any,
    scope: Any = None,
    team_id: Any = None,
    description: str,
) -> dict[str, Any]:
    """Remove one secret inside the caller's journaled action; returns its row."""
    journal.journaled_rows(
        conn,
        log,
        table=TABLE,
        where="name = ? AND scope = ? AND team_id = ?",
        params=(normalize_name(name), *normalize_scope(scope, team_id)),
        description=description,
    )
    return delete_secret(conn, name=name, scope=scope, team_id=team_id)


def value_of(conn: sqlite3.Connection, name: Any, *, team_id: int | None = None) -> str | None:
    """The raw value of *name* for an internal consumer, or None.

    This is the one read that returns a credential.  It is deliberately not
    reachable from a route, a command or a tool: the surfaces call it on behalf
    of the user (an external source fetching with the stored key), never to
    hand the value back.  A team-scoped value for *team_id* wins over the local
    one, so a team's own key overrides the workspace default.
    """
    resolved_name = normalize_name(name)
    ensure_schema(conn)
    params: list[Any] = [resolved_name]
    clause = "name = ?"
    if team_id:
        clause += " AND ((scope = ? AND team_id = ?) OR (scope = ? AND team_id = ?))"
        params += [SCOPE_TEAM, int(team_id), SCOPE_LOCAL, NO_TEAM]
    else:
        # No team context means the workspace value only: a caller that never
        # named a team must not read one team's credential.
        clause += " AND scope = ?"
        params.append(SCOPE_LOCAL)
    row = conn.execute(
        f"SELECT * FROM secrets WHERE {clause}"
        " ORDER BY CASE scope WHEN 'team' THEN 0 ELSE 1 END LIMIT 1",
        params,
    ).fetchone()
    return str(row["value"]) if row is not None else None


def resolve_from_workspace(name: str, *, team_id: int | None = None) -> str | None:
    """Read one secret from the workspace database, or None.

    This is the seam :mod:`reportal.llm` and an external source use: no
    connection is passed in, the workspace database is opened for the read, and
    a missing workspace, database or table is None rather than an error, so a
    caller that has no store still works.
    """
    try:
        path = db_path()
    except WorkspaceNotFound:
        return None
    if not path.exists():
        return None
    try:
        with contextlib.closing(store.connect(path)) as conn:
            return value_of(conn, name, team_id=team_id)
    except (sqlite3.Error, SecretError):
        return None


# ── Permissions ────────────────────────────────────────────────────


def _is_admin(user: Mapping[str, Any] | None) -> bool:
    return user is None or str(user.get("role")) == "admin"


def may_read(
    user: Mapping[str, Any] | None, row: Mapping[str, Any], *, team_ids: Sequence[int]
) -> bool:
    """Whether *user* may see that a secret exists (never its value)."""
    if _is_admin(user):
        return True
    if str(row.get("scope")) != SCOPE_TEAM:
        return True
    return int(row.get("team_id") or 0) in set(team_ids)


def may_write(
    user: Mapping[str, Any] | None,
    *,
    team_ids: Sequence[int],
    scope: str,
    team_id: int | None,
) -> bool:
    """Whether *user* may set or delete a secret at *scope*.

    A local secret is workspace configuration and needs an admin.  A team secret
    is writable by that team's members (the route gate already required the
    `write` permission) or an admin.
    """
    if _is_admin(user):
        return True
    if scope != SCOPE_TEAM or not team_id:
        return False
    return int(team_id) in set(team_ids)

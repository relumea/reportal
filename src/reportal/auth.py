"""Local identity: users, roles and bearer tokens, off until configured.

reportal binds loopback for a single user and its API has no identity at all,
which is the point of a loopback tool: anyone who can reach the port can
already read the workspace.  Binding beyond loopback is a different promise, so
`reportal serve --host` refuses a non-loopback host until token auth is switched
on (`REPORTAL_AUTH=required` or the workspace `[auth] required = true`) and at
least one user exists; see `docs/THREAT_MODEL.md`.

A user has a name, one of :data:`ROLES` and a token.  Only the token's SHA-256
digest is stored: the token is generated with :func:`secrets.token_urlsafe` and
shown once, at creation or rotation, so the database never carries a usable
credential.  A 256-bit random token is not guessable, so a plain digest is the
right comparison primitive here (a slow KDF defends a low-entropy password, of
which there are none).  Comparison goes through :func:`hmac.compare_digest`, so
a wrong token cannot be found byte by byte.

Roles map onto three permissions, declared once in :data:`ROLE_PERMISSIONS`:
a `viewer` may read, an `analyst` may read and write, and an `admin` may also
manage users.  :func:`required_permission` derives the permission one request
needs from its method and path, so the rule lives in one place instead of in
every route.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import tomllib
from datetime import UTC, datetime
from typing import Any

from reportal._paths import MARKER, WorkspaceNotFound, project_root

# Roles a user may carry, and their permission sets.
ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"
ROLES: tuple[str, ...] = (ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN)

# The permission names a role may hold.
PERMISSION_READ = "read"
PERMISSION_WRITE = "write"
PERMISSION_ADMIN = "admin"

ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    ROLE_VIEWER: (PERMISSION_READ,),
    ROLE_ANALYST: (PERMISSION_READ, PERMISSION_WRITE),
    ROLE_ADMIN: (PERMISSION_READ, PERMISSION_WRITE, PERMISSION_ADMIN),
}

# The permission every request needs when no user management is involved: a
# method that writes needs `write`, any other read.
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Path prefixes that need `admin` whatever the method: who may read the user
# table, its roles and its tokens is an administrative decision.
_ADMIN_PREFIXES: tuple[str, ...] = ("/api/users",)

# The authentication mode's environment variable and its workspace spelling.
REQUIRED_ENV = "REPORTAL_AUTH"
CONFIG_TABLE = "auth"
CONFIG_REQUIRED = "required"
_TRUTHY = frozenset({"1", "true", "yes", "on", "required"})

# Token shape: a greppable prefix plus 32 bytes of randomness.  A token is shown
# to the caller once and only its digest is kept.
TOKEN_PREFIX = "reportal_"
TOKEN_BYTES = 32

# Length bound on a user name.
MAX_USER_NAME = 64

# The header a bearer token arrives in.
AUTHORIZATION_HEADER = "authorization"
BEARER_PREFIX = "Bearer "

# The table users live in.
TABLE = "users"
_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role       TEXT NOT NULL,
    token_hash TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    disabled   INTEGER NOT NULL DEFAULT 0
);
"""

# Error names the API, CLI and MCP surfaces report.
ERROR_UNAUTHORIZED = "unauthorized"
ERROR_FORBIDDEN = "forbidden"
ERROR_INVALID_USER = "invalid-user"
ERROR_USER_EXISTS = "user-exists"
ERROR_USER_NOT_FOUND = "user-not-found"

# Fixed details the authentication failures report; neither echoes the token.
UNAUTHORIZED_DETAIL = "send Authorization: Bearer <token>"
FORBIDDEN_DETAIL = "this token's role does not carry the required permission"

# What an install without a user has to do, reported by `serve` and the CLI.
NO_USER_DETAIL = "no user token exists; create one with 'reportal user-add <name> --role admin'"
NOT_REQUIRED_DETAIL = (
    "remote binds need token auth: set REPORTAL_AUTH=required or [auth] required = true"
)


class AuthError(Exception):
    """A rejected user operation; ``code`` is the API's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class InvalidUserError(AuthError):
    """The user request itself is unusable (a blank name, an unknown role)."""


class UserExistsError(AuthError):
    """Another user already carries that name."""


class UnknownUserError(AuthError):
    """No user carries the requested id."""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the users table when the database predates it."""
    conn.executescript(_SCHEMA)


def now() -> str:
    """The current UTC time as an ISO 8601 string (second resolution)."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def _truthy(value: str) -> bool:
    return value.strip().lower() in _TRUTHY


def _workspace_required() -> bool:
    """True when the workspace ``reportal.toml`` sets ``[auth] required``."""
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return False
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return False
    table = document.get(CONFIG_TABLE)
    if not isinstance(table, dict):
        return False
    return table.get(CONFIG_REQUIRED) is True


def required() -> bool:
    """True when the environment or the workspace config requires token auth.

    A pure configuration read: it opens no database, so the per-request check is
    free and an install that never enables auth behaves exactly as before.
    """
    if _truthy(os.environ.get(REQUIRED_ENV, "")):
        return True
    return _workspace_required()


def new_token() -> str:
    """Return a fresh bearer token; only its digest is ever stored."""
    return f"{TOKEN_PREFIX}{secrets.token_urlsafe(TOKEN_BYTES)}"


def hash_token(token: str) -> str:
    """The digest stored for *token*."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def permissions_for(role: str) -> tuple[str, ...]:
    """The permissions *role* carries; an unknown role carries none."""
    return ROLE_PERMISSIONS.get(role, ())


def required_permission(method: str, path: str) -> str:
    """The permission one request needs, from its method and path."""
    if any(path.startswith(prefix) for prefix in _ADMIN_PREFIXES):
        return PERMISSION_ADMIN
    return PERMISSION_READ if method.upper() in _READ_METHODS else PERMISSION_WRITE


def _validated_name(name: str) -> str:
    cleaned = (name or "").strip()
    if not cleaned:
        raise InvalidUserError(ERROR_INVALID_USER, "name must not be blank")
    if len(cleaned) > MAX_USER_NAME:
        raise InvalidUserError(
            ERROR_INVALID_USER, f"name must be at most {MAX_USER_NAME} characters"
        )
    return cleaned


def _validated_role(role: str) -> str:
    if role not in ROLES:
        raise InvalidUserError(
            ERROR_INVALID_USER, f"unknown role: {role}; expected one of {', '.join(ROLES)}"
        )
    return role


def _user_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """One user as the API reports it: the digest never leaves this module."""
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "role": str(row["role"]),
        "created_at": str(row["created_at"]),
        "disabled": bool(row["disabled"]),
        "has_token": bool(row["token_hash"]),
    }


def get_user(conn: sqlite3.Connection, user_id: int) -> dict[str, Any] | None:
    """One user by id, without its token digest; None when unknown."""
    row = conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (user_id,)).fetchone()
    return _user_row(row) if row else None


def find_user(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    """One user by name (case-insensitive), without its token digest."""
    row = conn.execute(f"SELECT * FROM {TABLE} WHERE name = ?", (name.strip(),)).fetchone()
    return _user_row(row) if row else None


def list_users(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every user, oldest first, each without its token digest."""
    rows = conn.execute(f"SELECT * FROM {TABLE} ORDER BY id ASC").fetchall()
    return [_user_row(row) for row in rows]


def count_users(conn: sqlite3.Connection) -> int:
    """How many users exist, disabled ones included."""
    return int(conn.execute(f"SELECT COUNT(*) AS n FROM {TABLE}").fetchone()["n"])


def add_user(
    conn: sqlite3.Connection, *, name: str, role: str = ROLE_ANALYST
) -> tuple[dict[str, Any], str]:
    """Create one user with a fresh token; returns the user and the token.

    The token is returned exactly once, here: only its digest is stored.
    """
    cleaned = _validated_name(name)
    _validated_role(role)
    if find_user(conn, cleaned) is not None:
        raise UserExistsError(ERROR_USER_EXISTS, f"a user named {cleaned!r} already exists")
    token = new_token()
    cursor = conn.execute(
        f"INSERT INTO {TABLE} (name, role, token_hash, created_at) VALUES (?, ?, ?, ?)",
        (cleaned, role, hash_token(token), now()),
    )
    conn.commit()
    user_id = int(cursor.lastrowid or 0)
    user = get_user(conn, user_id)
    assert user is not None, "the row was just created"
    return user, token


def update_user(
    conn: sqlite3.Connection,
    user_id: int,
    *,
    role: str | None = None,
    disabled: bool | None = None,
) -> dict[str, Any] | None:
    """Set a user's role or disabled flag; None when the id is unknown."""
    if get_user(conn, user_id) is None:
        return None
    if role is not None:
        _validated_role(role)
        conn.execute(f"UPDATE {TABLE} SET role = ? WHERE id = ?", (role, user_id))
    if disabled is not None:
        conn.execute(
            f"UPDATE {TABLE} SET disabled = ? WHERE id = ?", (1 if disabled else 0, user_id)
        )
    conn.commit()
    return get_user(conn, user_id)


def delete_user(conn: sqlite3.Connection, user_id: int) -> bool:
    """Delete one user; False when the id is unknown."""
    cursor = conn.execute(f"DELETE FROM {TABLE} WHERE id = ?", (user_id,))
    conn.commit()
    return cursor.rowcount > 0


def rotate_token(conn: sqlite3.Connection, user_id: int) -> str | None:
    """Replace one user's token; returns the new token, or None when unknown."""
    if get_user(conn, user_id) is None:
        return None
    token = new_token()
    conn.execute(f"UPDATE {TABLE} SET token_hash = ? WHERE id = ?", (hash_token(token), user_id))
    conn.commit()
    return token


def token_of(header_value: str | None) -> str:
    """The token a request's ``Authorization`` header carries, or an empty string."""
    if not header_value:
        return ""
    value = header_value.strip()
    if not value.lower().startswith(BEARER_PREFIX.lower()):
        return ""
    return value[len(BEARER_PREFIX) :].strip()


def authenticate(conn: sqlite3.Connection, token: str) -> dict[str, Any] | None:
    """The active user *token* names, or None.

    The digest of every user is compared in constant time, and a disabled user
    never authenticates.
    """
    if not token:
        return None
    digest = hash_token(token)
    for row in conn.execute(f"SELECT * FROM {TABLE}").fetchall():
        if row["disabled"]:
            continue
        if hmac.compare_digest(str(row["token_hash"]), digest):
            return _user_row(row)
    return None

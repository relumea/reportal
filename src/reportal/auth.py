"""Local identity: users, roles and bearer tokens, off until configured.

reportal binds loopback for a single user and its API has no identity at all,
which is the point of a loopback tool: anyone who can reach the port can
already read the workspace.  Binding beyond loopback is a different promise, so
`reportal serve --host` refuses a non-loopback host until token auth is switched
on (`REPORTAL_AUTH` truthy: ``1``, ``true``, ``yes``, ``on``, ``enabled``,
or ``required``; or the workspace ``[auth] required = true``) and at
least one user exists; see `docs/THREAT_MODEL.md`.

A user has a name, one of :data:`ROLES` and a token.  Extra named API keys
live beside that login token, capped by the organisation's plan
(``max_api_keys``).  A named key may be ``read_only``: HTTP writes and
``/mcp`` (which needs write) then answer 403; the login token is never
read-only.  Only a token's SHA-256
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
import logging
import math
import os
import secrets
import sqlite3
import threading
import time
import tomllib
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any

from reportal import profiles
from reportal._paths import MARKER, WorkspaceNotFound, project_root

_log = logging.getLogger(__name__)

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


def is_read_method(method: str) -> bool:
    """True when *method* is a read (GET, HEAD, OPTIONS)."""
    return method.upper() in _READ_METHODS


# Path prefixes that need `admin` whatever the method: who may read the user
# table, its roles and its tokens is an administrative decision.
_ADMIN_PREFIXES: tuple[str, ...] = ("/api/users",)

# Paths under an admin prefix that every authenticated caller owns: the hosted
# portal's `users/activity` and `users/feedback` are self-service, so an analyst
# reads its own activity and writes its own note rather than needing an admin.
# Named API keys are the same: a caller mints, renames and revokes its own keys.
_SELF_PATHS: tuple[str, ...] = (
    "/api/users/activity",
    "/api/users/feedback",
    "/api/iam/keys",
)

# The authentication mode's environment variable and its workspace spelling.
REQUIRED_ENV = "REPORTAL_AUTH"
CONFIG_TABLE = "auth"
CONFIG_REQUIRED = "required"
# Keep in sync with ``settings.FLAG_TRUTHY`` / ``FLAG_FALSEY`` (and the other
# flag readers). A falsey env value forces auth off over the workspace file.
_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled", "required"})
_FALSEY = frozenset({"0", "false", "no", "off", "disabled"})

# Token shape: a greppable prefix plus 32 bytes of randomness.  A token is shown
# to the caller once and only its digest is kept.
TOKEN_PREFIX = "reportal_"
TOKEN_BYTES = 32

# Length bound on a user name.
MAX_USER_NAME = 64

# The header a bearer token arrives in.
AUTHORIZATION_HEADER = "authorization"
BEARER_PREFIX = "Bearer "

# The tables identity lives in.  ``teams`` plus ``team_members`` scope an
# object to the people who work on it; a membership carries a role, so the
# people who may manage a team are a subset of the people who work in it.
# ``organisations`` is one level above teams: the hosted hierarchy, with no
# effect on who may read or write an object.
TABLE = "users"
TEAM_TABLE = "teams"
MEMBER_TABLE = "team_members"
ORG_TABLE = "organisations"
_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role         TEXT NOT NULL,
    token_hash   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    disabled     INTEGER NOT NULL DEFAULT 0,
    last_used_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS {ORG_TABLE} (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS {TEAM_TABLE} (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description     TEXT NOT NULL DEFAULT '',
    organisation_id INTEGER REFERENCES {ORG_TABLE}(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS {MEMBER_TABLE} (
    team_id INTEGER NOT NULL REFERENCES {TEAM_TABLE}(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES {TABLE}(id) ON DELETE CASCADE,
    role    TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON {MEMBER_TABLE}(user_id);

CREATE TABLE IF NOT EXISTS team_invites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id     INTEGER NOT NULL REFERENCES {TEAM_TABLE}(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL UNIQUE,
    created_by  INTEGER REFERENCES {TABLE}(id) ON DELETE SET NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL DEFAULT '',
    used_by     INTEGER REFERENCES {TABLE}(id) ON DELETE SET NULL,
    used_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_team_invites_team ON team_invites(team_id);

CREATE TABLE IF NOT EXISTS user_api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES {TABLE}(id) ON DELETE CASCADE,
    name       TEXT NOT NULL COLLATE NOCASE,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_used_at TEXT NOT NULL DEFAULT '',
    read_only    INTEGER NOT NULL DEFAULT 0,
    UNIQUE (user_id, name)
);
CREATE INDEX IF NOT EXISTS idx_user_api_keys_user ON user_api_keys(user_id);

"""

# Team roles.  ``owner`` manages the team (its name, its description and its
# membership) and ``member`` works in it.  A user's *portal* role
# (``viewer``/``analyst``/``admin``) is a separate axis: an admin may act on any
# team, which is what keeps a lockout recoverable.
TEAM_ROLE_OWNER = "owner"
TEAM_ROLE_MEMBER = "member"
TEAM_ROLES: tuple[str, ...] = (TEAM_ROLE_OWNER, TEAM_ROLE_MEMBER)

ERROR_ORGANISATION_EXISTS = "organisation-exists"
ERROR_ORGANISATION_NOT_FOUND = "organisation-not-found"
ERROR_INVALID_ORGANISATION = "invalid-organisation"
ERROR_INVALID_TEAM_ROLE = "invalid-team-role"
ERROR_NOT_A_TEAM_OWNER = "not-a-team-owner"

# Length bounds on an organisation name and its description.
MAX_ORGANISATION_NAME = 64
MAX_ORGANISATION_DESCRIPTION = 280

# Visibility an object carries: public to every authenticated user, or scoped
# to the team that owns it.
VISIBILITY_PUBLIC = "public"
VISIBILITY_TEAM = "team"
VISIBILITIES: tuple[str, ...] = (VISIBILITY_PUBLIC, VISIBILITY_TEAM)

# Length bound on a team name and its description.
MAX_TEAM_NAME = 64
MAX_TEAM_DESCRIPTION = 280

# Error names the team surface reports.
ERROR_INVALID_TEAM = "invalid-team"
ERROR_TEAM_EXISTS = "team-exists"
ERROR_TEAM_NOT_FOUND = "team-not-found"
ERROR_NOT_A_MEMBER = "not-a-team-member"
ERROR_SCOPE_FORBIDDEN = "scope-forbidden"
ERROR_INVITE_NOT_FOUND = "invite-not-found"
ERROR_INVITE_USED = "invite-used"
ERROR_INVITE_EXPIRED = "invite-expired"

INVITE_TABLE = "team_invites"

# Invite code shape: greppable prefix plus randomness, shown once at create
# like a bearer token. Only the digest is stored.
INVITE_PREFIX = "invite_"
INVITE_BYTES = 16
INVITE_TTL_SECONDS = 7 * 24 * 60 * 60

# Error names the API, CLI and MCP surfaces report.
ERROR_UNAUTHORIZED = "unauthorized"
ERROR_FORBIDDEN = "forbidden"
ERROR_INVALID_USER = "invalid-user"
ERROR_USER_EXISTS = "user-exists"
ERROR_USER_NOT_FOUND = "user-not-found"
ERROR_SIGNUP_DISABLED = "signup-disabled"
ERROR_RATE_LIMITED = "rate-limited"
ERROR_API_KEY_NOT_FOUND = "api-key-not-found"
ERROR_API_KEY_LIMIT = "api-key-limit"
ERROR_INVALID_API_KEY = "invalid-api-key"

KEY_TABLE = "user_api_keys"
MAX_API_KEY_NAME = 64

# HTTP signup window: the public path creates a tenant with no bearer, so an
# unbounded caller can fill the user table. CLI and MCP skip this; they are
# not the public surface. Shared across the ASGI thread pool.
# Cap distinct peer keys so a flood of unique addresses within the window
# cannot grow the map without bound; past the cap the oldest peer is dropped.
SIGNUP_WINDOW_S = 3600.0
SIGNUP_MAX_HITS = 5
MAX_SIGNUP_KEYS = 1024
_signup_states: dict[str, list[float]] = {}
_signup_states_lock = threading.Lock()
_signup_monotonic = time.monotonic

# HTTP write window when token auth is on: one caller (user id, else TCP peer)
# cannot fill the job queue or burn inference by repeating POST/PATCH/PUT/DELETE.
# Loopback auth-off stays unbounded. CLI and MCP skip this; they are not HTTP.
# Cap distinct caller keys the same way signup does.
WRITE_WINDOW_S = 60.0
WRITE_MAX_HITS = 60
MAX_WRITE_KEYS = 4096
_write_states: dict[str, list[float]] = {}
_write_states_lock = threading.Lock()
_write_monotonic = time.monotonic

# Fixed details the authentication failures report; neither echoes the token.
UNAUTHORIZED_DETAIL = "send Authorization: Bearer <token>"
FORBIDDEN_DETAIL = "this token's role does not carry the required permission"
READ_ONLY_KEY_DETAIL = "this API key is read-only"

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


class InvalidTeamError(AuthError):
    """The team request itself is unusable (a blank name, an unknown visibility)."""


class TeamExistsError(AuthError):
    """Another team already carries that name."""


class UnknownTeamError(AuthError):
    """No team carries the requested id."""


class NotAMemberError(AuthError):
    """The caller is not a member of the team an object is scoped to."""


class UnknownOrganisationError(AuthError):
    """No organisation carries the requested id."""


class ScopeForbiddenError(AuthError):
    """The caller may not change an object its team owns."""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the users table when the database predates it."""
    conn.executescript(_SCHEMA)


def now() -> str:
    """The current UTC time; delegates to :func:`reportal.clock.now`."""
    from reportal import clock

    return clock.now()


def invite_expires_at(created_at: str) -> str:
    """The ISO stamp *created_at* plus :data:`INVITE_TTL_SECONDS`, always UTC."""
    from reportal import clock

    stamp = clock.as_utc(created_at)
    return (stamp + timedelta(seconds=INVITE_TTL_SECONDS)).isoformat(timespec="seconds")


def invite_is_expired(row: Mapping[str, Any], *, at: str | None = None) -> bool:
    """True when an unused invite's expiry is at or before *at* (default now)."""
    from reportal import clock

    keys = set(row.keys())
    if "used_by" in keys and row["used_by"] is not None:
        return False
    expires = str(row["expires_at"] if "expires_at" in keys and row["expires_at"] else "")
    if not expires:
        expires = invite_expires_at(str(row["created_at"]))
    return clock.as_utc(at or now()) >= clock.as_utc(expires)


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


def _workspace_required() -> bool:
    """True when the workspace ``reportal.toml`` sets ``[auth] required``."""
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return False
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        # Readers fall back to defaults on a bad file (see settings.problems);
        # without a log that fallback silently disables workspace auth.
        _log.warning(
            "cannot read %s for [%s]; auth.required falls back to off: %s",
            marker,
            CONFIG_TABLE,
            exc,
        )
        return False
    table = document.get(CONFIG_TABLE)
    if not isinstance(table, dict):
        return False
    return table.get(CONFIG_REQUIRED) is True


def required() -> bool:
    """True when token auth guards the API.

    The SaaS profile always requires it; otherwise the environment or the
    workspace config decides.  A pure configuration read: it opens no
    database, so the per-request check is free and an install that never
    enables auth behaves exactly as before.
    """
    if profiles.is_saas():
        return True
    forced = _env_flag(REQUIRED_ENV)
    if forced is not None:
        return forced
    return _workspace_required()


# Entropy source for bearer tokens.  A test patches ``_token_urlsafe`` to pin
# the token a create or rotate returns, so auth setup is seed-reproducible.
_token_urlsafe = secrets.token_urlsafe


def new_token() -> str:
    """Return a fresh bearer token; only its digest is ever stored."""
    return f"{TOKEN_PREFIX}{_token_urlsafe(TOKEN_BYTES)}"


def hash_token(token: str) -> str:
    """The digest stored for *token*."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def permissions_for(role: str) -> tuple[str, ...]:
    """The permissions *role* carries; an unknown role carries none."""
    return ROLE_PERMISSIONS.get(role, ())


def required_permission(method: str, path: str) -> str:
    """The permission one request needs, from its method and path."""
    if any(path.startswith(prefix) for prefix in _SELF_PATHS):
        return PERMISSION_READ if method.upper() in _READ_METHODS else PERMISSION_WRITE
    if any(path.startswith(prefix) for prefix in _ADMIN_PREFIXES):
        return PERMISSION_ADMIN
    if path == "/mcp" or path.startswith("/mcp/"):
        return PERMISSION_WRITE
    return PERMISSION_READ if method.upper() in _READ_METHODS else PERMISSION_WRITE


def _has_control_characters(cleaned: str) -> bool:
    """True when *cleaned* carries a control, format, or separator character.

    ASCII C0 controls and DEL are refused, and so are Unicode format characters
    (zero-width spaces, bidi controls) and line/paragraph separators that would
    otherwise look blank in a name while still distinguishing two identities.
    """
    return any(
        ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"}
        for ch in cleaned
    )


def _canonical_identity_name(name: str) -> str:
    """Strip padding and NFC-normalize an identity name before validate or lookup."""
    return unicodedata.normalize("NFC", (name or "").strip())


def _validated_name(name: str) -> str:
    cleaned = _canonical_identity_name(name)
    if not cleaned:
        raise InvalidUserError(ERROR_INVALID_USER, "name must not be blank")
    if len(cleaned) > MAX_USER_NAME:
        raise InvalidUserError(
            ERROR_INVALID_USER, f"name must be at most {MAX_USER_NAME} characters"
        )
    if _has_control_characters(cleaned):
        raise InvalidUserError(ERROR_INVALID_USER, "name must not contain control characters")
    return cleaned


def _validated_role(role: str) -> str:
    if role not in ROLES:
        raise InvalidUserError(
            ERROR_INVALID_USER, f"unknown role: {role}; expected one of {', '.join(ROLES)}"
        )
    return role


def _user_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """One user as the API reports it: the digest never leaves this module."""
    keys = set(row.keys())
    active = row["active_team_id"] if "active_team_id" in keys else None
    last_used = str(row["last_used_at"] or "") if "last_used_at" in keys else ""
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "role": str(row["role"]),
        "created_at": str(row["created_at"]),
        "disabled": bool(row["disabled"]),
        "has_token": bool(row["token_hash"]),
        "active_team_id": None if active is None else int(active),
        "last_used_at": last_used,
    }


def get_user(conn: sqlite3.Connection, user_id: int) -> dict[str, Any] | None:
    """One user by id, without its token digest; None when unknown."""
    row = conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (user_id,)).fetchone()
    return _user_row(row) if row else None


def find_user(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    """One user by name (case-insensitive), without its token digest."""
    row = conn.execute(
        f"SELECT * FROM {TABLE} WHERE name = ?", (_canonical_identity_name(name),)
    ).fetchone()
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
    token = new_token()
    try:
        cursor = conn.execute(
            f"INSERT INTO {TABLE} (name, role, token_hash, created_at) VALUES (?, ?, ?, ?)",
            (cleaned, role, hash_token(token), now()),
        )
    except sqlite3.IntegrityError:
        raise UserExistsError(
            ERROR_USER_EXISTS, f"a user named {cleaned!r} already exists"
        ) from None
    conn.commit()
    user_id = int(cursor.lastrowid or 0)
    user = get_user(conn, user_id)
    assert user is not None, "the row was just created"
    return user, token


def _unique_tenant_name(conn: sqlite3.Connection, *, table: str, base: str) -> str:
    """A name that does not collide with an existing team or organisation."""
    stem = _canonical_identity_name(base) or "tenant"
    if table == TEAM_TABLE:
        stem = stem[:MAX_TEAM_NAME]
        exists = find_team
        limit = MAX_TEAM_NAME
    else:
        stem = stem[:MAX_ORGANISATION_NAME]
        exists = find_organisation
        limit = MAX_ORGANISATION_NAME
    if exists(conn, stem) is None:
        return stem
    suffix = 2
    while True:
        extra = f"-{suffix}"
        # A suffix longer than *limit* would make ``stem[:limit - len(extra)]``
        # a negative slice and produce an over-long name; stop before that.
        assert len(extra) <= limit, "tenant name suffixes exhausted"
        candidate = f"{stem[: limit - len(extra)]}{extra}"
        assert len(candidate) <= limit, "tenant name must fit the column"
        if exists(conn, candidate) is None:
            return candidate
        suffix += 1


def signup_tenant(conn: sqlite3.Connection, *, name: str) -> tuple[dict[str, Any], str]:
    """Create one SaaS tenant: user, organisation, owned team, free plan.

    Personal profile refuses: a loopback install already has an operator, and
    this path is how a hosted visitor becomes a tenant without an admin.
    The user is an ``analyst`` (not an admin): they own their team, not the
    install. The organisation lands on the default billed plan.
    """
    if not profiles.is_saas():
        raise AuthError(ERROR_SIGNUP_DISABLED, "self-serve signup needs the saas profile")
    from reportal import metering

    metering.ensure_schema(conn)
    user, token = add_user(conn, name=name, role=ROLE_ANALYST)
    org_name = _unique_tenant_name(conn, table=ORG_TABLE, base=str(user["name"]))
    organisation = create_organisation(conn, name=org_name)
    team_name = _unique_tenant_name(conn, table=TEAM_TABLE, base=str(user["name"]))
    team = create_team(conn, name=team_name)
    set_team_organisation(conn, int(team["id"]), int(organisation["id"]))
    add_member(conn, int(team["id"]), int(user["id"]))
    set_member_role(conn, int(team["id"]), int(user["id"]), TEAM_ROLE_OWNER)
    set_active_team(conn, int(user["id"]), int(team["id"]))
    refreshed = get_user(conn, int(user["id"]))
    assert refreshed is not None, "the user was just created"
    refreshed_organisation = get_organisation(conn, int(organisation["id"]))
    refreshed_team = get_team(conn, int(team["id"]))
    assert refreshed_organisation is not None, "the organisation was just created"
    assert refreshed_team is not None, "the team was just created"
    return {
        **refreshed,
        "organisation": refreshed_organisation,
        "team": refreshed_team,
        "plan_id": metering.organisation_plan(conn, int(refreshed_organisation["id"])).id,
    }, token


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


# Tables that keep a login name beside an optional user id.  On delete the id
# may clear via ``ON DELETE SET NULL`` (or stay as an orphaned audit key where
# there is no FK); the display name is personal data and must go either way.
# Replacement is empty except for comments, which keep the module default
# author so a note does not render as blank.
_USER_NAME_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("feedback", "actor", "user_id", ""),
    ("comments", "author", "author_user_id", "analyst"),
    ("journal_entries", "actor", "actor_user_id", ""),
    ("name_history", "actor", "actor_user_id", ""),
    ("signature_history", "actor", "actor_user_id", ""),
    ("data_type_history", "actor", "actor_user_id", ""),
    ("artifact_ratings", "actor", "actor_user_id", ""),
    ("conversation_runs", "actor", "actor_user_id", ""),
    ("user_strings", "actor", "actor_user_id", ""),
    ("jobs", "submitted_by", "submitted_by_user_id", ""),
)

# The journal keeps ``actor_user_id`` after delete on purpose (see
# ``journal`` module): a stable audit key without the display name.  Every
# other table drops both.
_KEEP_ACTOR_USER_ID = frozenset({"journal_entries"})


def _scrub_deleted_user_names(
    conn: sqlite3.Connection, *, tables: set[str], user_id: int, name: str
) -> None:
    """Clear login names attributed to *user_id* / *name* before the row goes."""
    for table, name_col, id_col, blank in _USER_NAME_COLUMNS:
        if table not in tables:
            continue
        columns = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}
        if name_col not in columns:
            continue
        if id_col in columns:
            conn.execute(
                f"UPDATE {table} SET {name_col} = ? WHERE {id_col} = ?",
                (blank, user_id),
            )
            if table not in _KEEP_ACTOR_USER_ID:
                conn.execute(
                    f"UPDATE {table} SET {id_col} = NULL WHERE {id_col} = ?",
                    (user_id,),
                )
        # Rows that recorded the login name without a stable id (older schema
        # or auth-off free text) still name the person.
        conn.execute(
            f"UPDATE {table} SET {name_col} = ? WHERE {name_col} = ?",
            (blank, name),
        )


def delete_user(conn: sqlite3.Connection, user_id: int) -> bool:
    """Delete one user; False when the id is unknown.

    Attributed display names are scrubbed before the row goes: foreign keys
    with ``ON DELETE SET NULL`` clear the id, but the login name would otherwise
    remain in actor, author and submitter text columns.
    """
    user = get_user(conn, user_id)
    if user is None:
        return False
    tables = {
        str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    _scrub_deleted_user_names(conn, tables=tables, user_id=user_id, name=str(user["name"]))
    cursor = conn.execute(f"DELETE FROM {TABLE} WHERE id = ?", (user_id,))
    conn.commit()
    return cursor.rowcount > 0


def rotate_token(conn: sqlite3.Connection, user_id: int) -> str | None:
    """Replace one user's token; returns the new token, or None when unknown.

    The new token has never authenticated, so ``last_used_at`` is cleared.
    """
    if get_user(conn, user_id) is None:
        return None
    token = new_token()
    conn.execute(
        f"UPDATE {TABLE} SET token_hash = ?, last_used_at = '' WHERE id = ?",
        (hash_token(token), user_id),
    )
    conn.commit()
    return token


def _api_key_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """One named key as the API reports it: the digest never leaves this module."""
    keys = set(row.keys())
    last_used = str(row["last_used_at"] or "") if "last_used_at" in keys else ""
    read_only = bool(row["read_only"]) if "read_only" in keys else False
    return {
        "id": int(row["id"]),
        "user_id": int(row["user_id"]),
        "name": str(row["name"]),
        "created_at": str(row["created_at"]),
        "last_used_at": last_used,
        "read_only": read_only,
    }


def _validated_api_key_name(name: str) -> str:
    cleaned = _canonical_identity_name(name)
    if not cleaned:
        raise InvalidUserError(ERROR_INVALID_API_KEY, "name must not be blank")
    if len(cleaned) > MAX_API_KEY_NAME:
        raise InvalidUserError(
            ERROR_INVALID_API_KEY, f"name must be at most {MAX_API_KEY_NAME} characters"
        )
    if _has_control_characters(cleaned):
        raise InvalidUserError(ERROR_INVALID_API_KEY, "name must not contain control characters")
    return cleaned


def api_key_limit(conn: sqlite3.Connection, user_id: int) -> int:
    """How many bearer tokens *user_id* may hold, from its organisations' plans.

    The login token on the user row counts as one.  A user in no organisation
    is the self-hosted case and is unmetered.  Several orgs take the highest
    cap; unlimited on any of them wins.
    """
    from reportal import metering, plans

    limit = 0
    found = False
    for team in teams_of_user(conn, user_id):
        org_id = team.get("organisation_id")
        if org_id is None:
            continue
        found = True
        cap = metering.organisation_plan(conn, int(org_id)).max_api_keys
        if cap == plans.UNLIMITED:
            return plans.UNLIMITED
        limit = max(limit, cap)
    if not found:
        return plans.get_plan(plans.SELF_HOST_PLAN_ID).max_api_keys
    return limit


def count_api_keys(conn: sqlite3.Connection, user_id: int) -> int:
    """Login token plus named keys *user_id* currently holds."""
    user = conn.execute(f"SELECT token_hash FROM {TABLE} WHERE id = ?", (user_id,)).fetchone()
    primary = 1 if user is not None and str(user["token_hash"]) else 0
    extra = conn.execute(
        f"SELECT COUNT(*) AS n FROM {KEY_TABLE} WHERE user_id = ?", (user_id,)
    ).fetchone()
    return primary + (int(extra["n"]) if extra is not None else 0)


def list_api_keys(conn: sqlite3.Connection, user_id: int) -> list[dict[str, Any]]:
    """Named keys *user_id* minted, oldest first, without digests."""
    rows = conn.execute(
        f"SELECT id, user_id, name, created_at, last_used_at, read_only FROM {KEY_TABLE}"
        " WHERE user_id = ? ORDER BY id ASC",
        (user_id,),
    ).fetchall()
    return [_api_key_row(row) for row in rows]


def get_api_key(conn: sqlite3.Connection, key_id: int) -> dict[str, Any] | None:
    """One named key by id, without its digest, or None."""
    row = conn.execute(
        f"SELECT id, user_id, name, created_at, last_used_at, read_only"
        f" FROM {KEY_TABLE} WHERE id = ?",
        (key_id,),
    ).fetchone()
    return _api_key_row(row) if row else None


def create_api_key(
    conn: sqlite3.Connection, user_id: int, name: str, *, read_only: bool = False
) -> tuple[dict[str, Any], str]:
    """Mint one named extra key for *user_id*; the token is shown once.

    *read_only* keys authenticate as the user but HTTP writes (and ``/mcp``)
    answer 403. The login token is never read-only.

    Raises :class:`UnknownUserError` when the user is unknown,
    :class:`InvalidUserError` for a blank or already-used name, and
    :class:`AuthError` ``api-key-limit`` when the plan's ``max_api_keys``
    is already held (the login token counts).
    """
    from reportal import plans

    if get_user(conn, user_id) is None:
        raise UnknownUserError(ERROR_USER_NOT_FOUND, f"no user with id {user_id}")
    cleaned = _validated_api_key_name(name)
    limit = api_key_limit(conn, user_id)
    if limit != plans.UNLIMITED and count_api_keys(conn, user_id) >= limit:
        raise AuthError(
            ERROR_API_KEY_LIMIT,
            f"plan allows {limit} API key(s); revoke one or upgrade",
        )
    token = new_token()
    try:
        cursor = conn.execute(
            f"INSERT INTO {KEY_TABLE}"
            " (user_id, name, token_hash, created_at, last_used_at, read_only)"
            " VALUES (?, ?, ?, ?, '', ?)",
            (user_id, cleaned, hash_token(token), now(), 1 if read_only else 0),
        )
    except sqlite3.IntegrityError:
        raise InvalidUserError(
            ERROR_INVALID_API_KEY, f"an API key named {cleaned!r} already exists"
        ) from None
    conn.commit()
    key = get_api_key(conn, int(cursor.lastrowid or 0))
    assert key is not None, "the row was just created"
    return key, token


def rename_api_key(conn: sqlite3.Connection, key_id: int, name: str) -> dict[str, Any]:
    """Rename one named extra key. The token is unchanged.

    Raises :class:`UnknownUserError` when the key is unknown and
    :class:`InvalidUserError` for a blank or already-used name.
    """
    if get_api_key(conn, key_id) is None:
        raise UnknownUserError(ERROR_API_KEY_NOT_FOUND, f"no API key with id {key_id}")
    cleaned = _validated_api_key_name(name)
    try:
        conn.execute(f"UPDATE {KEY_TABLE} SET name = ? WHERE id = ?", (cleaned, key_id))
    except sqlite3.IntegrityError:
        raise InvalidUserError(
            ERROR_INVALID_API_KEY, f"an API key named {cleaned!r} already exists"
        ) from None
    conn.commit()
    key = get_api_key(conn, key_id)
    assert key is not None, "the row was just renamed"
    return key


def revoke_api_key(conn: sqlite3.Connection, key_id: int) -> dict[str, Any]:
    """Delete one named extra key. The login token is rotated, not revoked here."""
    row = conn.execute(f"SELECT * FROM {KEY_TABLE} WHERE id = ?", (key_id,)).fetchone()
    if row is None:
        raise UnknownUserError(ERROR_API_KEY_NOT_FOUND, f"no API key with id {key_id}")
    conn.execute(f"DELETE FROM {KEY_TABLE} WHERE id = ?", (key_id,))
    conn.commit()
    return {"key_id": key_id, "deleted": True}


def token_of(header_value: str | None) -> str:
    """The token a request's ``Authorization`` header carries, or an empty string."""
    if not header_value:
        return ""
    value = header_value.strip()
    if not value.lower().startswith(BEARER_PREFIX.lower()):
        return ""
    return value[len(BEARER_PREFIX) :].strip()


# ── Teams ──────────────────────────────────────────────────────────


def _validated_team_name(name: str) -> str:
    cleaned = _canonical_identity_name(name)
    if not cleaned:
        raise InvalidTeamError(ERROR_INVALID_TEAM, "name must not be blank")
    if len(cleaned) > MAX_TEAM_NAME:
        raise InvalidTeamError(
            ERROR_INVALID_TEAM, f"name must be at most {MAX_TEAM_NAME} characters"
        )
    if _has_control_characters(cleaned):
        raise InvalidTeamError(ERROR_INVALID_TEAM, "name must not contain control characters")
    return cleaned


def _team_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "description": str(row["description"]),
        "organisation_id": None if row["organisation_id"] is None else int(row["organisation_id"]),
        "created_at": str(row["created_at"]),
    }


def create_team(conn: sqlite3.Connection, *, name: str, description: str = "") -> dict[str, Any]:
    """Create one team; a duplicate name (case-insensitive) is refused."""
    cleaned = _validated_team_name(name)
    text = (description or "").strip()[:MAX_TEAM_DESCRIPTION]
    try:
        cursor = conn.execute(
            f"INSERT INTO {TEAM_TABLE} (name, description, created_at) VALUES (?, ?, ?)",
            (cleaned, text, now()),
        )
    except sqlite3.IntegrityError:
        raise TeamExistsError(
            ERROR_TEAM_EXISTS, f"a team named {cleaned!r} already exists"
        ) from None
    conn.commit()
    team = get_team(conn, int(cursor.lastrowid or 0))
    assert team is not None, "the row was just created"
    return team


def get_team(conn: sqlite3.Connection, team_id: int) -> dict[str, Any] | None:
    """One team by id, with its member ids; None when unknown."""
    row = conn.execute(f"SELECT * FROM {TEAM_TABLE} WHERE id = ?", (team_id,)).fetchone()
    if row is None:
        return None
    team = _team_row(row)
    organisation = (
        get_organisation(conn, int(team["organisation_id"]))
        if team["organisation_id"] is not None
        else None
    )
    team["organisation_name"] = None if organisation is None else organisation["name"]
    members = conn.execute(
        f"SELECT u.id, u.name, u.role AS portal_role, m.role AS team_role"
        f" FROM {MEMBER_TABLE} m JOIN {TABLE} u ON u.id = m.user_id"
        " WHERE m.team_id = ? ORDER BY u.id",
        (team_id,),
    ).fetchall()
    team["members"] = [dict(member) for member in members]
    team["member_count"] = len(team["members"])
    return team


def find_team(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    """One team by name (case-insensitive), without its members."""
    row = conn.execute(
        f"SELECT * FROM {TEAM_TABLE} WHERE name = ?", (_canonical_identity_name(name),)
    ).fetchone()
    return _team_row(row) if row else None


def list_teams(
    conn: sqlite3.Connection, *, visible_to: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Teams oldest first, each with its member count and organisation.

    Personal profile (or admin, or auth off): every team. SaaS non-admin: only
    the teams the caller belongs to, so one tenant never enumerates another's
    team names.
    """
    if (
        visible_to is not None
        and profiles.is_saas()
        and str(visible_to.get("role") or "") != ROLE_ADMIN
    ):
        rows = conn.execute(
            f"SELECT t.*, o.name AS organisation_name,"
            f" (SELECT COUNT(*) FROM {MEMBER_TABLE} m2 WHERE m2.team_id = t.id)"
            f" AS member_count FROM {TEAM_TABLE} t"
            f" JOIN {MEMBER_TABLE} m ON m.team_id = t.id"
            f" LEFT JOIN {ORG_TABLE} o ON o.id = t.organisation_id"
            " WHERE m.user_id = ? ORDER BY t.id",
            (int(visible_to["id"]),),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT t.*, o.name AS organisation_name,"
            f" (SELECT COUNT(*) FROM {MEMBER_TABLE} m WHERE m.team_id = t.id)"
            f" AS member_count FROM {TEAM_TABLE} t"
            f" LEFT JOIN {ORG_TABLE} o ON o.id = t.organisation_id ORDER BY t.id"
        ).fetchall()
    teams: list[dict[str, Any]] = []
    for row in rows:
        team = _team_row(row)
        team["member_count"] = int(row["member_count"])
        team["organisation_name"] = row["organisation_name"]
        teams.append(team)
    if teams:
        by_team: dict[int, list[int]] = {int(team["id"]): [] for team in teams}
        placeholders = ",".join("?" for _ in by_team)
        for member in conn.execute(
            f"SELECT team_id, user_id FROM {MEMBER_TABLE} WHERE team_id IN ({placeholders})",
            tuple(by_team),
        ).fetchall():
            by_team[int(member["team_id"])].append(int(member["user_id"]))
        for team in teams:
            team["member_ids"] = by_team[int(team["id"])]
    return teams


def update_team(
    conn: sqlite3.Connection,
    team_id: int,
    *,
    name: str | None = None,
    description: str | None = None,
) -> dict[str, Any] | None:
    """Set a team's name or description; None when the id is unknown."""
    if get_team(conn, team_id) is None:
        return None
    if name is not None:
        cleaned = _validated_team_name(name)
        clash = find_team(conn, cleaned)
        if clash is not None and int(clash["id"]) != team_id:
            raise TeamExistsError(ERROR_TEAM_EXISTS, f"a team named {cleaned!r} already exists")
        conn.execute(f"UPDATE {TEAM_TABLE} SET name = ? WHERE id = ?", (cleaned, team_id))
    if description is not None:
        conn.execute(
            f"UPDATE {TEAM_TABLE} SET description = ? WHERE id = ?",
            (description.strip()[:MAX_TEAM_DESCRIPTION], team_id),
        )
    conn.commit()
    return get_team(conn, team_id)


def delete_team(conn: sqlite3.Connection, team_id: int) -> bool:
    """Delete one team; its objects (and their memberships) lose the scope.

    The objects the team owned return to the whole workspace rather than
    disappearing with it: a stale ``owner_team_id`` would make them invisible to
    everyone, which is data loss by another name.  Users who had this team as
    their active view lose that selection the same way, so metering and the SPA
    do not keep a dangling team id.
    """
    if get_team(conn, team_id) is None:
        return False
    for table in ("binaries", "collections"):
        conn.execute(
            f"UPDATE {table} SET owner_team_id = NULL, visibility = ? WHERE owner_team_id = ?",
            (VISIBILITY_PUBLIC, team_id),
        )
    conn.execute(f"UPDATE {TABLE} SET active_team_id = NULL WHERE active_team_id = ?", (team_id,))
    conn.execute(f"DELETE FROM {MEMBER_TABLE} WHERE team_id = ?", (team_id,))
    conn.execute(f"DELETE FROM {TEAM_TABLE} WHERE id = ?", (team_id,))
    conn.commit()
    return True


def add_member(conn: sqlite3.Connection, team_id: int, user_id: int) -> bool:
    """Add a user to a team; False when either id is unknown or already in it."""
    if conn.execute(f"SELECT 1 FROM {TEAM_TABLE} WHERE id = ?", (team_id,)).fetchone() is None:
        return False
    if conn.execute(f"SELECT 1 FROM {TABLE} WHERE id = ?", (user_id,)).fetchone() is None:
        return False
    if conn.execute(
        f"SELECT 1 FROM {MEMBER_TABLE} WHERE team_id = ? AND user_id = ?", (team_id, user_id)
    ).fetchone():
        return False
    conn.execute(f"INSERT INTO {MEMBER_TABLE} (team_id, user_id) VALUES (?, ?)", (team_id, user_id))
    conn.commit()
    return True


def remove_member(conn: sqlite3.Connection, team_id: int, user_id: int) -> bool:
    """Remove a user from a team; False when the membership does not exist.

    A user who had this team selected as their active view loses that selection,
    because membership is required to keep it and a dangling id would read as a
    team nobody can resolve.
    """
    cursor = conn.execute(
        f"DELETE FROM {MEMBER_TABLE} WHERE team_id = ? AND user_id = ?", (team_id, user_id)
    )
    if cursor.rowcount > 0:
        conn.execute(
            f"UPDATE {TABLE} SET active_team_id = NULL WHERE id = ? AND active_team_id = ?",
            (user_id, team_id),
        )
    conn.commit()
    return cursor.rowcount > 0


def member_role(conn: sqlite3.Connection, team_id: int, user_id: int) -> str | None:
    """The role a user holds in a team, or None when it is not a member."""
    row = conn.execute(
        f"SELECT role FROM {MEMBER_TABLE} WHERE team_id = ? AND user_id = ?",
        (team_id, user_id),
    ).fetchone()
    return None if row is None else str(row["role"])


# ── Team invites ─────────────────────────────────────────────────


def new_invite_code() -> str:
    """Return a fresh invite code; only its digest is ever stored."""
    return f"{INVITE_PREFIX}{_token_urlsafe(INVITE_BYTES)}"


def create_invite(
    conn: sqlite3.Connection, team_id: int, created_by: int | None
) -> tuple[int, str]:
    """Mint one single-use invite code for *team_id*.

    Returns ``(invite_id, code)``; the code is shown once, here. Raises
    :class:`UnknownTeamError` for an unknown team.
    """
    if get_team(conn, team_id) is None:
        raise UnknownTeamError(ERROR_TEAM_NOT_FOUND, f"no team with id {team_id}")
    code = new_invite_code()
    created_at = now()
    cursor = conn.execute(
        f"INSERT INTO {INVITE_TABLE}"
        " (team_id, code_hash, created_by, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (team_id, hash_token(code), created_by, created_at, invite_expires_at(created_at)),
    )
    conn.commit()
    return int(cursor.lastrowid or 0), code


def get_invite(conn: sqlite3.Connection, invite_id: int) -> dict[str, Any] | None:
    """One invite by id, without its code digest, or None."""
    row = conn.execute(
        f"SELECT id, team_id, created_by, created_at, expires_at, used_by, used_at"
        f" FROM {INVITE_TABLE} WHERE id = ?",
        (invite_id,),
    ).fetchone()
    if row is None:
        return None
    item = dict(row)
    expires = str(item.get("expires_at") or "")
    if not expires:
        expires = invite_expires_at(str(item["created_at"]))
        item["expires_at"] = expires
    item["expired"] = invite_is_expired(item)
    return item


def revoke_invite(conn: sqlite3.Connection, invite_id: int) -> dict[str, Any]:
    """Delete one unused invite; used rows stay for the audit trail.

    Raises :class:`UnknownTeamError` when the id is unknown, and
    :class:`AuthError` ``invite-used`` when it was already redeemed.
    """
    row = conn.execute(f"SELECT * FROM {INVITE_TABLE} WHERE id = ?", (invite_id,)).fetchone()
    if row is None:
        raise UnknownTeamError(ERROR_INVITE_NOT_FOUND, f"no invite with id {invite_id}")
    if row["used_by"] is not None:
        raise AuthError(ERROR_INVITE_USED, "that invite was already used")
    conn.execute(f"DELETE FROM {INVITE_TABLE} WHERE id = ?", (invite_id,))
    conn.commit()
    return {"invite_id": invite_id, "deleted": True}


def list_invites(conn: sqlite3.Connection, team_id: int) -> list[dict[str, Any]]:
    """Every invite a team minted, newest first, without code digests."""
    rows = conn.execute(
        f"SELECT id, team_id, created_by, created_at, expires_at, used_by, used_at"
        f" FROM {INVITE_TABLE} WHERE team_id = ? ORDER BY id DESC",
        (team_id,),
    ).fetchall()
    stamped = now()
    listed: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        expires = str(item.get("expires_at") or "")
        if not expires:
            expires = invite_expires_at(str(item["created_at"]))
            item["expires_at"] = expires
        item["expired"] = invite_is_expired(item, at=stamped)
        listed.append(item)
    return listed


def redeem_invite(conn: sqlite3.Connection, code: str, user_id: int) -> dict[str, Any]:
    """Join the invite's team as *user_id*; single-use.

    Raises :class:`UnknownTeamError` for a code no invite carries
    (reported as invite-not-found, never naming a team),
    :class:`AuthError` ``invite-used`` for a redeemed one, and
    ``invite-expired`` past :data:`INVITE_TTL_SECONDS`. An already-member
    redeemer consumes the code and reads the team back: the code is spent
    either way, so it cannot be passed on.
    """
    digest = hash_token((code or "").strip())
    row = conn.execute(f"SELECT * FROM {INVITE_TABLE} WHERE code_hash = ?", (digest,)).fetchone()
    if row is None:
        raise UnknownTeamError(ERROR_INVITE_NOT_FOUND, "no invite carries that code")
    if row["used_by"] is not None:
        raise AuthError(ERROR_INVITE_USED, "that invite was already used")
    if invite_is_expired(row):
        raise AuthError(ERROR_INVITE_EXPIRED, "that invite has expired")
    team_id = int(row["team_id"])
    if get_user(conn, user_id) is None:
        raise UnknownUserError(ERROR_USER_NOT_FOUND, f"no user with id {user_id}")
    claimed = conn.execute(
        f"UPDATE {INVITE_TABLE} SET used_by = ?, used_at = ? WHERE id = ? AND used_by IS NULL",
        (user_id, now(), int(row["id"])),
    )
    if claimed.rowcount == 0:
        raise AuthError(ERROR_INVITE_USED, "that invite was already used")
    add_member(conn, team_id, user_id)
    conn.commit()
    team = get_team(conn, team_id)
    assert team is not None, "the team was just read"
    return team


def set_member_role(conn: sqlite3.Connection, team_id: int, user_id: int, role: str) -> bool:
    """Set one membership's role; False when the membership does not exist.

    Raises :class:`InvalidUserError` for a role outside :data:`TEAM_ROLES`, so
    the surface maps one code for every bad team-role request.
    """
    if role not in TEAM_ROLES:
        raise InvalidUserError(
            ERROR_INVALID_TEAM_ROLE,
            f"unknown team role: {role}; expected one of {', '.join(TEAM_ROLES)}",
        )
    cursor = conn.execute(
        f"UPDATE {MEMBER_TABLE} SET role = ? WHERE team_id = ? AND user_id = ?",
        (role, team_id, user_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def team_owners(conn: sqlite3.Connection, team_id: int) -> list[dict[str, Any]]:
    """The members holding the owner role, oldest first."""
    rows = conn.execute(
        f"SELECT u.id, u.name FROM {MEMBER_TABLE} m JOIN {TABLE} u ON u.id = m.user_id"
        " WHERE m.team_id = ? AND m.role = ? ORDER BY u.id",
        (team_id, TEAM_ROLE_OWNER),
    ).fetchall()
    return [dict(row) for row in rows]


def may_manage_team(conn: sqlite3.Connection, user: Mapping[str, Any] | None, team_id: int) -> bool:
    """Whether *user* may rename a team, set its members or change its roles.

    With auth off there is no caller and the install is the single local
    operator, so the answer is yes; otherwise an admin may manage any team,
    which is what keeps a lockout recoverable, a team's own owner may manage it,
    and a plain member may not.
    """
    if user is None:
        return True
    if str(user.get("role") or "") == ROLE_ADMIN:
        return True
    return member_role(conn, team_id, int(user["id"])) == TEAM_ROLE_OWNER


def may_access_team(conn: sqlite3.Connection, user: Mapping[str, Any] | None, team_id: int) -> bool:
    """Whether *user* may read this team's roster.

    Auth off is the local operator. An admin may reach any team. Otherwise the
    caller must be a member, so one tenant cannot enumerate another's names by
    guessing a team id.
    """
    if user is None or str(user.get("role") or "") == ROLE_ADMIN:
        return True
    return member_role(conn, team_id, int(user["id"])) is not None


def may_access_organisation(
    conn: sqlite3.Connection, user: Mapping[str, Any] | None, organisation_id: int
) -> bool:
    """Whether *user* may read this organisation's billing and usage.

    Auth off is the local operator. An admin may reach any organisation.
    Otherwise the caller must belong to a team filed under it, so one tenant
    cannot read another's ledger by guessing the id.
    """
    if user is None or str(user.get("role") or "") == ROLE_ADMIN:
        return True
    row = conn.execute(
        f"SELECT 1 FROM {TEAM_TABLE} t JOIN {MEMBER_TABLE} m ON m.team_id = t.id"
        " WHERE t.organisation_id = ? AND m.user_id = ? LIMIT 1",
        (organisation_id, int(user["id"])),
    ).fetchone()
    return row is not None


def may_administer_tenants(user: Mapping[str, Any] | None) -> bool:
    """Whether *user* may create or delete organisations and grant plans.

    Auth off is the local operator; otherwise only an admin reshapes the tenant
    catalog, matching the threat model's tenant-administration layer.
    """
    return user is None or str(user.get("role") or "") == ROLE_ADMIN


def _organisation_row(row: Any) -> dict[str, Any]:
    """One organisation row as the API returns it."""
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "description": str(row["description"]),
        "created_at": str(row["created_at"]),
    }


def _validated_organisation_name(name: str) -> str:
    """A usable organisation name, or :class:`InvalidUserError`."""
    cleaned = _canonical_identity_name(name)
    if not cleaned:
        raise InvalidUserError(ERROR_INVALID_ORGANISATION, "an organisation name is required")
    if len(cleaned) > MAX_ORGANISATION_NAME:
        raise InvalidUserError(
            ERROR_INVALID_ORGANISATION,
            f"an organisation name is at most {MAX_ORGANISATION_NAME} characters",
        )
    if _has_control_characters(cleaned):
        raise InvalidUserError(
            ERROR_INVALID_ORGANISATION, "an organisation name must not contain control characters"
        )
    return cleaned


def create_organisation(
    conn: sqlite3.Connection, *, name: str, description: str = ""
) -> dict[str, Any]:
    """Create one organisation; a duplicate name is refused.

    An organisation is structure, not access control: it groups teams the way
    the hosted portal does, and an object's team is still what decides who may
    read or write it.
    """
    cleaned = _validated_organisation_name(name)
    text = (description or "").strip()[:MAX_ORGANISATION_DESCRIPTION]
    try:
        cursor = conn.execute(
            f"INSERT INTO {ORG_TABLE} (name, description, created_at) VALUES (?, ?, ?)",
            (cleaned, text, now()),
        )
    except sqlite3.IntegrityError:
        raise AuthError(
            ERROR_ORGANISATION_EXISTS, f"an organisation named {cleaned!r} already exists"
        ) from None
    organisation_id = int(cursor.lastrowid or 0)
    # Open the first quota window now so free-tier usage is monthly from day
    # one rather than a lifetime sum against an empty ``period_started_at``.
    from reportal import metering

    metering.ensure_schema(conn)
    metering.start_period(conn, organisation_id, commit=False)
    conn.commit()
    organisation = get_organisation(conn, organisation_id)
    assert organisation is not None, "the row was just created"
    return organisation


def get_organisation(conn: sqlite3.Connection, organisation_id: int) -> dict[str, Any] | None:
    """One organisation by id, with the teams it holds; None when unknown."""
    row = conn.execute(f"SELECT * FROM {ORG_TABLE} WHERE id = ?", (organisation_id,)).fetchone()
    if row is None:
        return None
    organisation = _organisation_row(row)
    teams = conn.execute(
        f"SELECT id, name FROM {TEAM_TABLE} WHERE organisation_id = ? ORDER BY id",
        (organisation_id,),
    ).fetchall()
    organisation["teams"] = [dict(team) for team in teams]
    organisation["team_count"] = len(organisation["teams"])
    return organisation


def find_organisation(conn: sqlite3.Connection, name: str) -> dict[str, Any] | None:
    """One organisation by name (case-insensitive), without its teams."""
    row = conn.execute(
        f"SELECT * FROM {ORG_TABLE} WHERE name = ?", (_canonical_identity_name(name),)
    ).fetchone()
    return _organisation_row(row) if row else None


def list_organisations(
    conn: sqlite3.Connection, *, visible_to: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Organisations oldest first, each with its teams.

    Personal profile (or admin, or auth off): every organisation. SaaS
    non-admin: only the organisations behind the caller's teams, so one
    tenant never enumerates another's.
    """
    if (
        visible_to is not None
        and profiles.is_saas()
        and str(visible_to.get("role") or "") != ROLE_ADMIN
    ):
        rows = conn.execute(
            f"SELECT DISTINCT t.organisation_id AS id FROM {TEAM_TABLE} t"
            f" JOIN {MEMBER_TABLE} m ON m.team_id = t.id"
            " WHERE m.user_id = ? AND t.organisation_id IS NOT NULL ORDER BY t.organisation_id",
            (int(visible_to["id"]),),
        ).fetchall()
    else:
        rows = conn.execute(f"SELECT id FROM {ORG_TABLE} ORDER BY id").fetchall()
    found: list[dict[str, Any]] = []
    for row in rows:
        organisation = get_organisation(conn, int(row["id"]))
        if organisation is not None:
            found.append(organisation)
    return found


def delete_organisation(conn: sqlite3.Connection, organisation_id: int) -> bool:
    """Delete one organisation; its teams stay, no longer grouped."""
    cursor = conn.execute(f"DELETE FROM {ORG_TABLE} WHERE id = ?", (organisation_id,))
    conn.commit()
    return cursor.rowcount > 0


def set_team_organisation(
    conn: sqlite3.Connection, team_id: int, organisation_id: int | None
) -> bool:
    """Move one team into an organisation, or out of every one with None.

    False when the team does not exist; an organisation id no row carries is
    refused rather than stored, because a dangling reference would read as a
    team with a name nobody can resolve.
    """
    if get_team(conn, team_id) is None:
        return False
    if organisation_id is not None and get_organisation(conn, organisation_id) is None:
        raise UnknownOrganisationError(
            ERROR_ORGANISATION_NOT_FOUND, f"no organisation with id {organisation_id}"
        )
    conn.execute(
        f"UPDATE {TEAM_TABLE} SET organisation_id = ? WHERE id = ?", (organisation_id, team_id)
    )
    conn.commit()
    return True


def set_active_team(conn: sqlite3.Connection, user_id: int, team_id: int | None) -> bool:
    """Switch the team a user has selected, or clear it with None.

    Membership is required, so a caller cannot select a team it is not in; the
    portal's own role is not consulted, because switching is a view preference
    rather than a permission.  False when the user is unknown.
    """
    user = get_user(conn, user_id)
    if user is None:
        return False
    if team_id is not None:
        if get_team(conn, int(team_id)) is None:
            raise UnknownTeamError(ERROR_TEAM_NOT_FOUND, f"no team with id {team_id}")
        if member_role(conn, int(team_id), user_id) is None and str(user["role"]) != ROLE_ADMIN:
            raise NotAMemberError(
                ERROR_NOT_A_MEMBER, f"user {user_id} is not a member of team {team_id}"
            )
    conn.execute(f"UPDATE {TABLE} SET active_team_id = ? WHERE id = ?", (team_id, user_id))
    conn.commit()
    return True


def teams_of_user(conn: sqlite3.Connection, user_id: int) -> list[dict[str, Any]]:
    """Every team the user belongs to, oldest first."""
    rows = conn.execute(
        f"SELECT t.* FROM {TEAM_TABLE} t JOIN {MEMBER_TABLE} m ON m.team_id = t.id"
        " WHERE m.user_id = ? ORDER BY t.id",
        (user_id,),
    ).fetchall()
    return [_team_row(row) for row in rows]


# ── Object scope ───────────────────────────────────────────────────


def visible_clause(
    conn: sqlite3.Connection, user: Mapping[str, Any] | None, *, prefix: str = ""
) -> tuple[str, list[Any]] | None:
    """The SQL that narrows a listing to what *user* may see, or None.

    None means "no restriction": auth is off (the local operator sees the whole
    workspace) or the caller is an admin.  Otherwise an object is visible when
    it is public or owned by one of the caller's teams, which is the one rule
    the read paths share.
    """
    if user is None or str(user.get("role")) == ROLE_ADMIN:
        return None
    clause = (
        f"({prefix}visibility = ? OR {prefix}owner_team_id IN"
        f" (SELECT team_id FROM {MEMBER_TABLE} WHERE user_id = ?))"
    )
    return clause, [VISIBILITY_PUBLIC, int(user["id"])]


def may_write(
    user: Mapping[str, Any] | None, row: Mapping[str, Any], *, team_ids: Sequence[int]
) -> bool:
    """Whether *user* may change *row*, from the row's visibility and team.

    A public object is writable by anyone whose role carries `write` (the route
    gate already checked that); a team-scoped one only by a member of that team
    (*team_ids* is the caller's membership) or an admin, so an object a team
    owns cannot be changed by the rest of the workspace.
    """
    if user is None or str(user.get("role")) == ROLE_ADMIN:
        return True
    if str(row.get("visibility") or VISIBILITY_PUBLIC) != VISIBILITY_TEAM:
        return True
    return int(row.get("owner_team_id") or 0) in set(team_ids)


def scope_of(
    conn: sqlite3.Connection, *, team_id: int | None, visibility: str
) -> tuple[int | None, str]:
    """Validate a requested object scope: its team id and visibility.

    A `team` visibility needs a team that exists; a `public` one clears the
    owner, so "back to everyone" is one call rather than two.
    """
    if visibility not in VISIBILITIES:
        raise InvalidTeamError(
            ERROR_INVALID_TEAM,
            f"unknown visibility: {visibility}; expected {', '.join(VISIBILITIES)}",
        )
    if visibility == VISIBILITY_PUBLIC:
        return None, VISIBILITY_PUBLIC
    if team_id is None:
        raise InvalidTeamError(ERROR_INVALID_TEAM, "a team-scoped object needs a team_id")
    if get_team(conn, int(team_id)) is None:
        raise UnknownTeamError(ERROR_TEAM_NOT_FOUND, f"no team with id {team_id}")
    return int(team_id), VISIBILITY_TEAM


def authenticate(conn: sqlite3.Connection, token: str) -> dict[str, Any] | None:
    """The active user *token* names, or None.

    The digest of every user login token and every named extra key is compared
    in constant time, and a disabled user never authenticates.  A successful
    login-token authenticate stamps ``users.last_used_at``; a named-key
    authenticate stamps ``user_api_keys.last_used_at`` instead.  A
    read-only named key returns the user with ``api_key_read_only`` set.
    """
    if not token:
        return None
    digest = hash_token(token)
    for row in conn.execute(f"SELECT * FROM {TABLE}").fetchall():
        if row["disabled"]:
            continue
        if hmac.compare_digest(str(row["token_hash"]), digest):
            conn.execute(
                f"UPDATE {TABLE} SET last_used_at = ? WHERE id = ?",
                (now(), int(row["id"])),
            )
            conn.commit()
            return get_user(conn, int(row["id"]))
    for row in conn.execute(
        f"SELECT id, user_id, token_hash, read_only FROM {KEY_TABLE}"
    ).fetchall():
        if not hmac.compare_digest(str(row["token_hash"]), digest):
            continue
        user = get_user(conn, int(row["user_id"]))
        if user is None or user["disabled"]:
            return None
        conn.execute(
            f"UPDATE {KEY_TABLE} SET last_used_at = ? WHERE id = ?",
            (now(), int(row["id"])),
        )
        conn.commit()
        if int(row["read_only"] or 0):
            return {**user, "api_key_read_only": True}
        return user
    return None


def retry_after_seconds(hits: Sequence[float], window_s: float, now: float) -> int:
    """Seconds until the oldest hit in *hits* leaves *window_s*.

    HTTP ``Retry-After`` is an integer delay; a fractional remainder rounds
    up so the client waits long enough for a slot to free.  An empty hit
    list (a race after expiry) still names the whole window.
    """
    if not hits:
        return max(1, math.ceil(window_s))
    return max(1, math.ceil(window_s - (now - min(hits))))


def signup_retry_after(client_key: str) -> int:
    """Seconds until *client_key* may mint another HTTP tenant."""
    key = (client_key or "").strip() or "unknown"
    now = _signup_monotonic()
    with _signup_states_lock:
        return retry_after_seconds(_signup_states.get(key, []), SIGNUP_WINDOW_S, now)


def write_retry_after(client_key: str) -> int:
    """Seconds until *client_key* may make another HTTP write."""
    key = (client_key or "").strip() or "unknown"
    now = _write_monotonic()
    with _write_states_lock:
        return retry_after_seconds(_write_states.get(key, []), WRITE_WINDOW_S, now)


def signup_allowed(client_key: str) -> bool:
    """Whether *client_key* may mint another HTTP tenant inside the window.

    A key whose window has emptied is dropped rather than left as a permanent
    entry.  Distinct live keys are also capped at :data:`MAX_SIGNUP_KEYS` so a
    flood of unique peers cannot grow the map for the whole window.
    """
    key = (client_key or "").strip() or "unknown"
    now = _signup_monotonic()
    with _signup_states_lock:
        for other, hits in list(_signup_states.items()):
            if all(now - hit >= SIGNUP_WINDOW_S for hit in hits):
                del _signup_states[other]
        hits = [hit for hit in _signup_states.get(key, []) if now - hit < SIGNUP_WINDOW_S]
        if len(hits) >= SIGNUP_MAX_HITS:
            _signup_states[key] = hits
            return False
        hits.append(now)
        _signup_states[key] = hits
        while len(_signup_states) > MAX_SIGNUP_KEYS:
            _signup_states.pop(next(iter(_signup_states)))
        return True


def write_allowed(client_key: str) -> bool:
    """Whether *client_key* may make another HTTP write inside the window.

    A key whose window has emptied is dropped rather than left as a permanent
    entry.  Distinct live keys are also capped at :data:`MAX_WRITE_KEYS`.
    """
    key = (client_key or "").strip() or "unknown"
    now = _write_monotonic()
    with _write_states_lock:
        for other, hits in list(_write_states.items()):
            if all(now - hit >= WRITE_WINDOW_S for hit in hits):
                del _write_states[other]
        hits = [hit for hit in _write_states.get(key, []) if now - hit < WRITE_WINDOW_S]
        if len(hits) >= WRITE_MAX_HITS:
            _write_states[key] = hits
            return False
        hits.append(now)
        _write_states[key] = hits
        while len(_write_states) > MAX_WRITE_KEYS:
            _write_states.pop(next(iter(_write_states)))
        return True

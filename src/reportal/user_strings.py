"""Analyst-supplied strings, at function or analysis scope.

The hosted portal lets an analyst attach strings to a function (`POST
/v3/functions/{id}/user-provided-strings`), to an analysis (`POST
/v3/analyses/{id}/user-provided-strings`) and replace an analysis's whole list
(`PUT /v2/analyses/{id}/strings`).  Locally the same rows are a small store:
one string per row with a scope, an optional note and the actor that recorded
it, so an analyst can say "this literal is a command line template" or "this
address is a URL" without pretending the engine found it.

The per-function *read* merges two things and labels them: the strings the
analyst recorded, and the string literals the function's stored decompilation
carries (a local scan of its quoted literals, :func:`derived_literals`).  The
two are reported separately in ``analyst`` and ``derived`` rather than mixed, so
a reader can tell what a human asserted from what a scanner found.

A scope is validated against the row it names, so an unknown function or
analysis is a not-found rather than an orphan row, and the whole store is
per-scope bounded (:data:`MAX_STRINGS_PER_SCOPE`) so one scope cannot grow
without limit.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any

from reportal import journal, store

# The two scopes a string can live at, and the kinds it may carry.
SCOPE_FUNCTION = "function"
SCOPE_ANALYSIS = "analysis"
SCOPES: tuple[str, ...] = (SCOPE_FUNCTION, SCOPE_ANALYSIS)

KIND_STRING = "string"
KINDS: tuple[str, ...] = (KIND_STRING, "import", "export")

# The table the store owns (created on first use).
TABLE = "user_strings"

# Bounds: a string is a literal, a note is a sentence, and one scope holds a
# bounded list rather than an unbounded paste.
MAX_STRING_CHARS = 1024
MAX_NOTE_CHARS = 500
MAX_STRINGS_PER_SCOPE = 500

# Where a read's entries came from.
SOURCE_ANALYST = "analyst"
SOURCE_DERIVED = "decompilation"

# The note the merged read carries about the derived half.
DERIVED_NOTE = (
    "the derived entries are the quoted literals reportal found in the function's"
    " stored decompilation; they are a text scan, not engine output"
)

# Error codes the surface reports, shared by the API, CLI and MCP.
ERROR_INVALID = "invalid string"
ERROR_NOT_FOUND = "string not found"

# A C string literal: a double-quoted run, with escapes, on one line.
_LITERAL_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')

_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_strings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_kind TEXT NOT NULL,
    scope_id   INTEGER NOT NULL,
    value      TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'string',
    note       TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_strings_scope ON user_strings(scope_kind, scope_id);
"""


class StringError(Exception):
    """Base class for a rejected analyst-string operation."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


class InvalidStringError(StringError, ValueError):
    """A value, kind or scope is unusable; the API answers 400."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_INVALID, detail)


class UnknownStringError(StringError, LookupError):
    """No string carries the requested id in that scope; the API answers 404."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_NOT_FOUND, detail)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the string table when the database predates it."""
    conn.executescript(_SCHEMA)


# ── Validation ─────────────────────────────────────────────────────


def normalize_value(value: Any) -> str:
    """Validate one string, raising :class:`InvalidStringError`."""
    if not isinstance(value, str) or not value.strip():
        raise InvalidStringError("value must be a non-empty string")
    trimmed = value.strip()
    if len(trimmed) > MAX_STRING_CHARS:
        raise InvalidStringError(f"value exceeds {MAX_STRING_CHARS} characters")
    return trimmed


def normalize_note(note: Any) -> str:
    """Validate an optional note, raising :class:`InvalidStringError`."""
    if note is None:
        return ""
    if not isinstance(note, str):
        raise InvalidStringError("note must be a string")
    trimmed = note.strip()
    if len(trimmed) > MAX_NOTE_CHARS:
        raise InvalidStringError(f"note exceeds {MAX_NOTE_CHARS} characters")
    return trimmed


def normalize_kind(kind: Any) -> str:
    """Validate a kind, raising :class:`InvalidStringError`."""
    if kind in (None, ""):
        return KIND_STRING
    if not isinstance(kind, str) or kind.strip() not in KINDS:
        raise InvalidStringError(f"kind must be one of {', '.join(KINDS)}")
    return kind.strip()


def normalize_scope(scope_kind: Any, scope_id: Any) -> tuple[str, int]:
    """Validate a scope kind and id shape, raising :class:`InvalidStringError`."""
    if not isinstance(scope_kind, str) or scope_kind not in SCOPES:
        raise InvalidStringError(f"scope must be one of {', '.join(SCOPES)}")
    if isinstance(scope_id, bool) or not isinstance(scope_id, int) or scope_id < 1:
        raise InvalidStringError("scope_id must be a positive integer")
    return scope_kind, int(scope_id)


def check_scope(conn: sqlite3.Connection, *, scope_kind: str, scope_id: int) -> None:
    """Validate that the row a scope names exists, raising a not-found.

    The error carries the same code the surfaces report; the API maps it to 404
    with the detail naming the scope, so an unknown function and an unknown
    analysis read the same way.
    """
    resolved_kind, resolved_id = normalize_scope(scope_kind, scope_id)
    exists = (
        store.get_function(conn, resolved_id) is not None
        if resolved_kind == SCOPE_FUNCTION
        else store.get_analysis(conn, resolved_id) is not None
    )
    if not exists:
        raise UnknownStringError(f"no {resolved_kind} with id {resolved_id}")


def _row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """One stored string as the surfaces report it."""
    return {
        "id": int(row["id"]),
        "scope_kind": str(row["scope_kind"]),
        "scope_id": int(row["scope_id"]),
        "value": str(row["value"]),
        "kind": str(row["kind"]),
        "note": str(row["note"]),
        "actor": str(row["actor"]),
        "created_at": str(row["created_at"]),
    }


# ── Store ──────────────────────────────────────────────────────────


def add_string(
    conn: sqlite3.Connection,
    *,
    scope_kind: str,
    scope_id: int,
    value: Any,
    kind: Any = None,
    note: Any = None,
    actor: str = "",
) -> dict[str, Any]:
    """Store one analyst string, replacing an identical value in that scope.

    A value already stored at the scope (same kind and value) keeps its row and
    its creation time, so re-adding the same literal is a no-op rather than a
    duplicate; a new value appends.  The scope is checked first, so an unknown
    row is a not-found.
    """
    ensure_schema(conn)
    resolved_kind, resolved_id = normalize_scope(scope_kind, scope_id)
    check_scope(conn, scope_kind=resolved_kind, scope_id=resolved_id)
    resolved_value = normalize_value(value)
    resolved_string_kind = normalize_kind(kind)
    resolved_note = normalize_note(note)
    existing = conn.execute(
        f"SELECT * FROM {TABLE} WHERE scope_kind = ? AND scope_id = ? AND value = ? AND kind = ?",
        (resolved_kind, resolved_id, resolved_value, resolved_string_kind),
    ).fetchone()
    if existing is not None:
        if resolved_note and resolved_note != str(existing["note"]):
            conn.execute(
                f"UPDATE {TABLE} SET note = ? WHERE id = ?",
                (resolved_note, int(existing["id"])),
            )
            conn.commit()
            existing = conn.execute(
                f"SELECT * FROM {TABLE} WHERE id = ?", (int(existing["id"]),)
            ).fetchone()
        return _row(existing)
    count = conn.execute(
        f"SELECT COUNT(*) AS n FROM {TABLE} WHERE scope_kind = ? AND scope_id = ?",
        (resolved_kind, resolved_id),
    ).fetchone()
    if count is not None and int(count["n"]) >= MAX_STRINGS_PER_SCOPE:
        raise InvalidStringError(f"a scope holds at most {MAX_STRINGS_PER_SCOPE} strings")
    cursor = conn.execute(
        f"INSERT INTO {TABLE} (scope_kind, scope_id, value, kind, note, actor, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            resolved_kind,
            resolved_id,
            resolved_value,
            resolved_string_kind,
            resolved_note,
            str(actor or ""),
            store.now(),
        ),
    )
    conn.commit()
    return get_string(conn, string_id=int(cursor.lastrowid or 0))


def get_string(conn: sqlite3.Connection, *, string_id: int) -> dict[str, Any]:
    """One stored string by id; raises :class:`UnknownStringError`."""
    ensure_schema(conn)
    row = conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (int(string_id),)).fetchone()
    if row is None:
        raise UnknownStringError(f"no string with id {string_id}")
    return _row(row)


def list_strings(
    conn: sqlite3.Connection,
    *,
    scope_kind: str,
    scope_id: int,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Every analyst string at one scope, oldest first; the scope must exist.

    ``visible_to`` answers [] for a scope on a binary the caller may not
    see, so a listing never names what the single-read gate would 404; the
    parent row stays the authority for existence.
    """
    from reportal import auth

    ensure_schema(conn)
    resolved_kind, resolved_id = normalize_scope(scope_kind, scope_id)
    check_scope(conn, scope_kind=resolved_kind, scope_id=resolved_id)
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, params = scope
        if resolved_kind == SCOPE_FUNCTION:
            function = store.get_function(conn, resolved_id)
            owner = None if function is None else store.get_binary(conn, int(function["binary_id"]))
        else:
            analysis = store.get_analysis(conn, resolved_id)
            owner = None if analysis is None else store.get_binary(conn, int(analysis["binary_id"]))
        if owner is not None:
            visible = conn.execute(
                f"SELECT b.id AS id FROM binaries b WHERE b.id = ? AND {clause}",
                [int(owner["id"]), *params],
            ).fetchone()
            if visible is None:
                return []
    rows = conn.execute(
        f"SELECT * FROM {TABLE} WHERE scope_kind = ? AND scope_id = ? ORDER BY id",
        (resolved_kind, resolved_id),
    ).fetchall()
    return [_row(row) for row in rows]


def delete_string(
    conn: sqlite3.Connection, *, scope_kind: str, scope_id: int, string_id: int
) -> dict[str, Any]:
    """Remove one stored string from its scope; 404 when it is not there."""
    resolved_kind, resolved_id = normalize_scope(scope_kind, scope_id)
    row = get_string(conn, string_id=string_id)
    if row["scope_kind"] != resolved_kind or row["scope_id"] != resolved_id:
        raise UnknownStringError(f"string {string_id} is not in {resolved_kind} {resolved_id}")
    conn.execute(f"DELETE FROM {TABLE} WHERE id = ?", (int(string_id),))
    conn.commit()
    return row


def replace_strings(
    conn: sqlite3.Connection,
    *,
    scope_kind: str,
    scope_id: int,
    values: Sequence[Any],
    actor: str = "",
) -> dict[str, Any]:
    """Replace a scope's analyst strings with *values*; returns the new list.

    This is the hosted `PUT /v2/analyses/{id}/strings` form: the whole list at
    once.  Each value is validated before anything is written, so an unusable
    one is a 400 with the store untouched.
    """
    resolved_kind, resolved_id = normalize_scope(scope_kind, scope_id)
    check_scope(conn, scope_kind=resolved_kind, scope_id=resolved_id)
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise InvalidStringError("strings must be a list of values")
    if len(values) > MAX_STRINGS_PER_SCOPE:
        raise InvalidStringError(f"a scope holds at most {MAX_STRINGS_PER_SCOPE} strings")
    normalized = [normalize_value(entry) for entry in values]
    ensure_schema(conn)
    removed = conn.execute(
        f"DELETE FROM {TABLE} WHERE scope_kind = ? AND scope_id = ?",
        (resolved_kind, resolved_id),
    ).rowcount
    conn.commit()
    for value in normalized:
        add_string(
            conn,
            scope_kind=resolved_kind,
            scope_id=resolved_id,
            value=value,
            actor=actor,
        )
    return {
        "scope_kind": resolved_kind,
        "scope_id": resolved_id,
        "removed": int(removed),
        "strings": list_strings(conn, scope_kind=resolved_kind, scope_id=resolved_id),
    }


# ── The derived half ───────────────────────────────────────────────


def derived_literals(code: str, *, limit: int = MAX_STRINGS_PER_SCOPE) -> list[str]:
    """The quoted string literals *code* carries, deduped, in first-seen order.

    It is a text scan of the stored decompilation, so an escaped quote, a
    multi-line literal or a literal built at runtime is outside what it can
    see, and an empty literal carries nothing and is left out; the read that
    serves this labels it as derived rather than engine output.
    """
    found: list[str] = []
    seen: set[str] = set()
    for match in _LITERAL_RE.finditer(code or ""):
        text = match.group(1)
        if not text or text in seen:
            continue
        seen.add(text)
        found.append(text)
        if len(found) >= limit:
            break
    return found


def function_strings(
    conn: sqlite3.Connection,
    function_id: int,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One function's strings: the analyst's, and the derived literals beside them.

    The two halves are never merged, so a reader can tell what a human recorded
    from what the text scan found, and the payload carries the note saying which
    is which.  ``visible_to`` empties both halves for a function on a hidden
    binary, so the read never names what the gate would 404.
    """
    from reportal import auth

    function = store.get_function(conn, function_id)
    if function is None:
        raise UnknownStringError(f"no function with id {function_id}")
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, params = scope
        owner = store.get_binary(conn, int(function["binary_id"]))
        visible = (
            None
            if owner is None
            else conn.execute(
                f"SELECT b.id AS id FROM binaries b WHERE b.id = ? AND {clause}",
                [int(owner["id"]), *params],
            ).fetchone()
        )
        if visible is None:
            return {
                "function_id": function_id,
                "analyst": [],
                "derived": [],
                "count": 0,
            }
    analyst = list_strings(
        conn, scope_kind=SCOPE_FUNCTION, scope_id=function_id, visible_to=visible_to
    )
    stored = store.get_decompilation(conn, function_id)
    derived = derived_literals(str(stored["code"])) if stored is not None else []
    recorded = {entry["value"] for entry in analyst}
    return {
        "function_id": function_id,
        "analyst": analyst,
        "derived": [
            {"value": text, "source": SOURCE_DERIVED} for text in derived if text not in recorded
        ],
        "counts": {"analyst": len(analyst), "derived": len(derived)},
        "note": DERIVED_NOTE,
    }


def journaled_add(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    scope_kind: str,
    scope_id: int,
    value: Any,
    kind: Any = None,
    note: Any = None,
    actor: str = "",
    description: str | None = None,
) -> dict[str, Any]:
    """Add one string inside the caller's journaled action.

    A new row is journaled for deletion on revert; an existing one is
    snapshotted first, so re-adding a value is revertible either way.
    """
    before = journal.snapshot_rows(
        conn,
        table=TABLE,
        where="scope_kind = ? AND scope_id = ? AND value = ?",
        params=(
            str(scope_kind),
            int(scope_id),
            str(value).strip() if isinstance(value, str) else "",
        ),
    )
    if before:
        journal.journaled_rows(
            conn,
            log,
            table=TABLE,
            where="scope_kind = ? AND scope_id = ? AND value = ?",
            params=(
                str(scope_kind),
                int(scope_id),
                str(value).strip() if isinstance(value, str) else "",
            ),
            description=description,
        )
    row = add_string(
        conn,
        scope_kind=scope_kind,
        scope_id=scope_id,
        value=value,
        kind=kind,
        note=note,
        actor=actor,
    )
    if not before:
        journal.journaled_create(
            log,
            table=TABLE,
            key=int(row["id"]),
            description=description or f"stored a string in {scope_kind} {scope_id}",
        )
    return row


def journaled_delete(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    scope_kind: str,
    scope_id: int,
    string_id: int,
    description: str | None = None,
) -> dict[str, Any]:
    """Remove one string inside the caller's journaled action."""
    journal.journaled_rows(
        conn,
        log,
        table=TABLE,
        where="id = ?",
        params=(int(string_id),),
        description=description or f"removed string {string_id}",
    )
    return delete_string(conn, scope_kind=scope_kind, scope_id=scope_id, string_id=string_id)


def journaled_replace(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    scope_kind: str,
    scope_id: int,
    values: Sequence[Any],
    actor: str = "",
    description: str | None = None,
) -> dict[str, Any]:
    """Replace a scope's strings inside the caller's journaled action.

    The rows the write replaces are snapshotted first and the rows it creates
    journalled for deletion after, so a revert puts the previous list back
    whether the scope held one or was empty.
    """
    where = "scope_kind = ? AND scope_id = ?"
    params = (str(scope_kind), int(scope_id))
    before = journal.journaled_rows(
        conn,
        log,
        table=TABLE,
        where=where,
        params=params,
        description=description or f"replaced the strings of {scope_kind} {scope_id}",
    )
    report = replace_strings(
        conn,
        scope_kind=scope_kind,
        scope_id=scope_id,
        values=values,
        actor=actor,
    )
    journal.journaled_new_rows(
        conn,
        log,
        table=TABLE,
        where=where,
        params=params,
        before=before,
        key=("id",),
        description=description or f"created a string of {scope_kind} {scope_id}",
    )
    return report

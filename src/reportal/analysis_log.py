"""Structured analysis-log rows: one lifecycle event per row, with a severity.

The hosted portal shows a per-analysis View Log whose rows carry a severity
(ERROR, WARN, INFO) and a time.  reportal predates that: the ``analyses`` table
carries a single ``log`` TEXT column, which ``import-rebrew`` fills with one
summary sentence.  A TEXT column cannot carry a severity, a timestamp or a
bound per row, so the lifecycle events live in their own table,
``analysis_log_entries``, rather than overloading that column.  The column
stays what it always was (the importer's summary string) and this module is
the only writer of the log row.

One entry names the analysis it belongs to, a severity from the closed set
:data:`SEVERITIES`, the message and the time.  :func:`append_entry` is the one
documented writer; :func:`list_entries` reads newest first, bounded by
:data:`MAX_LOG_LIMIT`, and returns the analysis's true entry count beside the
page so a reader can tell a bounded page from the whole log.  Rows cascade
with their analysis (``ON DELETE CASCADE``), so no reader has to clean up
after one.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

# Severities an entry may carry, in increasing order of attention.  The set is
# closed: `append_entry` raises for anything else instead of storing it.
SEVERITY_INFO = "info"
SEVERITY_WARN = "warn"
SEVERITY_ERROR = "error"
SEVERITIES: tuple[str, ...] = (SEVERITY_INFO, SEVERITY_WARN, SEVERITY_ERROR)

# Entries `list_entries` returns when the caller names no bound, and the
# largest bound it accepts.  A log is read as a page; the true total is what
# tells a reader there is more.
DEFAULT_LOG_LIMIT = 200
MAX_LOG_LIMIT = 1000

# Longest message stored.  An engine failure can carry a multi-line stderr
# dump; the tail is dropped with an explicit ellipsis rather than stored whole.
MAX_MESSAGE_CHARS = 2000

# The table the entries live in.  It is public so a caller reverting an
# analysis delete can snapshot it by name, the way the journal snapshots every
# other table.
TABLE = "analysis_log_entries"
_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysis_log_analysis ON {TABLE}(analysis_id);
"""

# Suffix a truncated message ends with, so a reader can see text was dropped.
TRUNCATION_MARKER = "..."


class UnknownSeverityError(ValueError):
    """The severity is outside :data:`SEVERITIES`."""


def now() -> str:
    """Return the current UTC time as an ISO 8601 string (second resolution)."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the log table when the database predates it."""
    conn.executescript(_SCHEMA)


def _message_of(message: str) -> str:
    """Return *message* with its whitespace collapsed and its tail bounded.

    An engine failure's text can carry newlines and stray runs of spaces; a log
    row is one line, and a message past :data:`MAX_MESSAGE_CHARS` is cut with
    :data:`TRUNCATION_MARKER` so the cut is visible rather than silent.
    """
    collapsed = " ".join(message.split())
    if not collapsed:
        raise ValueError("message must not be empty")
    if len(collapsed) <= MAX_MESSAGE_CHARS:
        return collapsed
    return collapsed[: MAX_MESSAGE_CHARS - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def append_entry(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    message: str,
    severity: str = SEVERITY_INFO,
) -> int:
    """Append one log entry to *analysis_id*; returns its id.

    The severity must be one of :data:`SEVERITIES` (else
    :class:`UnknownSeverityError`), and the message must not be blank (else
    :class:`ValueError`).
    """
    if severity not in SEVERITIES:
        raise UnknownSeverityError(f"unknown severity: {severity!r}")
    ensure_schema(conn)
    cur = conn.execute(
        f"INSERT INTO {TABLE} (analysis_id, severity, message, created_at) VALUES (?, ?, ?, ?)",
        (analysis_id, severity, _message_of(message), now()),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def _entry_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """One stored entry as a plain dict."""
    return {
        "id": int(row["id"]),
        "analysis_id": int(row["analysis_id"]),
        "severity": str(row["severity"]),
        "message": str(row["message"]),
        "created_at": str(row["created_at"]),
    }


def count_entries(conn: sqlite3.Connection, analysis_id: int) -> int:
    """The analysis's whole entry count, whatever a reader's bound is."""
    ensure_schema(conn)
    row = conn.execute(
        f"SELECT COUNT(*) AS total FROM {TABLE} WHERE analysis_id = ?", (analysis_id,)
    ).fetchone()
    return int(row["total"]) if row else 0


def list_entries(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    limit: int = DEFAULT_LOG_LIMIT,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Return ``(rows, total)`` for one analysis, newest first.

    *limit* is bounded by :data:`MAX_LOG_LIMIT` and *offset* skips that many of
    the newest entries; either being out of range raises :class:`ValueError`.
    *total* is the analysis's whole entry count, not the page's, so a caller
    can say "showing 200 of 431".
    """
    if limit < 1 or limit > MAX_LOG_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LOG_LIMIT}")
    if offset < 0:
        raise ValueError("offset must not be negative")
    ensure_schema(conn)
    total = count_entries(conn, analysis_id)
    cursor = conn.execute(
        f"SELECT * FROM {TABLE} WHERE analysis_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        (analysis_id, limit, offset),
    )
    return [_entry_row(row) for row in cursor.fetchall()], total


def count_recent(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> int:
    """How many entries there are, whatever a reader's page is.

    ``visible_to`` counts only entries on analyses of binaries the caller
    may see, like :func:`list_recent`.
    """
    from reportal import auth

    ensure_schema(conn)
    sql = f"SELECT COUNT(*) FROM {TABLE} l JOIN analyses a ON a.id = l.analysis_id"
    params: list[Any] = []
    clauses: list[str] = []
    if since is not None:
        clauses.append("l.created_at >= ?")
        params.append(since)
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, scope_params = scope
        clauses.append(f"EXISTS (SELECT 1 FROM binaries b WHERE b.id = a.binary_id AND {clause})")
        params.extend(scope_params)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    return int(conn.execute(sql, params).fetchone()[0])


def list_recent(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    limit: int = DEFAULT_LOG_LIMIT,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """The newest entries across every analysis, with their binary's name.

    :func:`list_entries` reads one analysis; this is what a feed reads, so each
    row carries the owning analysis's ``binary_id`` and ``binary_name`` for a
    client to link.  *since* is an ISO timestamp compared as text, the format
    the rows are written in, and it is inclusive, so an entry written at the
    named second is still returned.  *limit* is bounded by
    :data:`MAX_LOG_LIMIT`.  ``visible_to`` narrows to entries on analyses of
    binaries the caller may see, like the other scoped reads.
    """
    from reportal import auth

    if limit < 1:
        raise ValueError("limit must be positive")
    ensure_schema(conn)
    sql = (
        f"SELECT l.*, a.binary_id AS binary_id, b.name AS binary_name"
        f" FROM {TABLE} l JOIN analyses a ON a.id = l.analysis_id"
        f" JOIN binaries b ON b.id = a.binary_id"
    )
    params: list[Any] = []
    clauses: list[str] = []
    if since is not None:
        clauses.append("l.created_at >= ?")
        params.append(since)
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, scope_params = scope
        clauses.append(f"({clause})")
        params.extend(scope_params)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY l.id DESC LIMIT ?"
    params.append(min(limit, MAX_LOG_LIMIT))
    rows = []
    for row in conn.execute(sql, params):
        entry = _entry_row(row)
        entry["binary_id"] = int(row["binary_id"])
        entry["binary_name"] = str(row["binary_name"])
        rows.append(entry)
    return rows

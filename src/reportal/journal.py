"""A persisted action journal: every wired mutation records its inverse.

The pipeline and auto mode journal their writes in-process through
:class:`reportal.components.Context` and keep their plans on their own run rows
(``pipeline_runs.effects_json``, ``auto_runs.effects_json``).  They stay that
way by design: a run's plan is scoped to the run, its bindings and revocations
live in one process, and ``pipeline.revert_run`` / ``auto_mode.revert_auto_run``
are the entry points for it.  This module is the app-wide counterpart for the
request-scoped writers.  One :class:`Journal` covers one HTTP request or CLI
invocation, its entries land in ``journal_entries``, and any recorded action is
revertible later, including from a different process, because the descriptors
are persisted and replayed through the one dispatcher the runs use
(:func:`reportal.effects.apply_undo_plan`).

The helpers below produce both halves of a wiring: the descriptor the entry
stores and the inverse the dispatcher applies, so covering a writer is a
two-line change.  :func:`journaled_rows`, :func:`journaled_create`,
:func:`journaled_new_rows` and :func:`journaled_file` build the generic row and
file descriptors; :func:`journaled_ingest`, :func:`journaled_rename`,
:func:`journaled_scan`, :func:`journaled_scan_result` and
:func:`journaled_graph_rebuild` cover the shapes those writers share (a document
with its chunks, a rename's functions and history rows, a scan with the analysis
it created, a graph's nodes and edges).  A descriptor kind must be registered in
:mod:`reportal.effects`; this module registers nothing itself, and the four
kinds its helpers emit are declared in-tree by
``effects.builtin_effect_handlers()``.
"""

from __future__ import annotations

import base64
import contextlib
import json
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reportal import analysis_log, effects, store

# Table an action's entries live in.  The journal owns its own schema so an
# existing database picks it up on first use, the way `store._upgrade_schema`
# handles a column added after the first release.
_TABLE = "journal_entries"

# The table's name, for a reader outside this module (the activity feed groups
# by actor with its own query).
TABLE = _TABLE

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {_TABLE} (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    action          TEXT NOT NULL,
    kind            TEXT NOT NULL,
    description     TEXT NOT NULL,
    descriptor_json TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    actor           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_journal_entries_action ON {_TABLE}(action);
"""

# The actor index is created after the column migration below, because an index
# on a column an older database does not have yet would fail the script.
_ACTOR_INDEX = f"CREATE INDEX IF NOT EXISTS idx_journal_entries_actor ON {_TABLE}(actor);"

# The actor an action was taken by: the authenticated user's name for a request,
# ``local`` while token auth is off, and empty for a process with no identity
# (a CLI invocation or an MCP tool call).  The server sets it around the request
# it serves, so every entry the request records carries who made it.
_ACTOR: ContextVar[str] = ContextVar("reportal_journal_actor", default="")

# The actor name a request without an authenticated user records.
LOCAL_ACTOR = "local"

# Entry statuses.  `active` is a recorded write a revert has not taken back,
# `reverted` one whose inverse applied, and `partial` one whose inverse could
# not restore everything it recorded (a file past MAX_FILE_BYTES).
STATUS_ACTIVE = "active"
STATUS_REVERTED = "reverted"
STATUS_PARTIAL = "partial"

# Response field carrying the action id of a wired mutating request, so the
# caller can revert that one action later.
ACTION_FIELD = "journal_action"

# Bytes of randomness in an action id; the id groups the entries of one request
# and is short enough to type back into `reportal journal-revert`.
ACTION_ID_BYTES = 6

# Default and maximum entry count `GET /api/journal` returns.
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 500

# Entries `prune_entries` keeps when the caller names no count.
DEFAULT_PRUNE_KEEP = 5000

# Largest file content a `file-restore` descriptor carries.  Above it the
# descriptor records the path only and its inverse reports partial: the journal
# is not a backup store, so a large binary's bytes are not copied into the
# database on every delete.
MAX_FILE_BYTES = 8 * 1024 * 1024

# A table or column name the row helpers splice into SQL.  Descriptors are
# persisted, so the inverse validates every identifier it is handed.
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class JournalError(Exception):
    """Base class for a rejected journal operation."""


class UnknownActionError(JournalError, KeyError):
    """No entry carries the requested action id; the API answers 404."""


class UnknownEntryError(JournalError, KeyError):
    """No entry carries the requested id; the API answers 404."""


class EntryNotActiveError(JournalError, ValueError):
    """The entry was already reverted; the API answers 400."""


def quote_identifier(name: object) -> str:
    """Return *name* as a quoted SQL identifier, or raise :class:`ValueError`."""
    text = str(name)
    if _IDENTIFIER.match(text) is None:
        raise ValueError(f"not a table or column name: {text!r}")
    return f'"{text}"'


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the journal table when the database predates it.

    A database written before the ``actor`` column existed gets it added here,
    the way ``store._upgrade_schema`` handles a column added after a release;
    the backfill leaves those entries with an empty actor, which is the honest
    reading of a write nobody recorded an identity for.
    """
    conn.executescript(_SCHEMA)
    columns = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({_TABLE})")}
    if "actor" not in columns:
        conn.execute(f"ALTER TABLE {_TABLE} ADD COLUMN actor TEXT NOT NULL DEFAULT ''")
    conn.execute(_ACTOR_INDEX)
    conn.commit()


@contextlib.contextmanager
def acting_as(actor: str) -> Iterator[None]:
    """Record *actor* on every entry this block writes, and restore after.

    The value travels in a :class:`contextvars.ContextVar` so a writer deep in a
    call stack does not have to thread it through; the server sets it around the
    request it serves, and the worker thread the route runs on inherits it.
    """
    token = _ACTOR.set(actor)
    try:
        yield
    finally:
        _ACTOR.reset(token)


def current_actor() -> str:
    """The actor the current context records, or an empty string."""
    return _ACTOR.get()


def new_action() -> str:
    """Return a short unique action id for one request or invocation."""
    return secrets.token_hex(ACTION_ID_BYTES)


def now() -> str:
    """The journal's own UTC timestamp, in the format the store's tables use."""
    return datetime.now(UTC).isoformat(timespec="seconds")


class Journal:
    """The entries of one action, recorded in memory then flushed to the table.

    ``record`` appends; ``flush`` writes.  A request that fails partway through
    never flushes, so a failed operation leaves no half-recorded action behind.
    """

    def __init__(self, conn: sqlite3.Connection, action: str) -> None:
        if not action.strip():
            raise ValueError("action must not be empty")
        self.conn = conn
        self.action = action
        self._pending: list[dict[str, str]] = []
        self._recorded = 0
        ensure_schema(conn)

    def record(self, kind: str, description: str, descriptor: Mapping[str, Any]) -> None:
        """Append one entry for a write *descriptor* takes back.

        The descriptor is serialized here rather than at flush: one that cannot
        be stored is a wiring bug, and failing at record time names the write
        instead of the whole batch.
        """
        encoded = json.dumps(dict(descriptor))
        self._pending.append(
            {
                "kind": kind,
                "description": description,
                "descriptor_json": encoded,
                "actor": current_actor(),
            }
        )

    def pending(self) -> int:
        """Entries recorded since the last flush."""
        return len(self._pending)

    def recorded(self) -> int:
        """Entries this journal has recorded, flushed or not."""
        return self._recorded + len(self._pending)

    def flush(self) -> int:
        """Write the pending entries to the table; returns how many landed."""
        if not self._pending:
            return 0
        stamp = now()
        rows = [
            (
                self.action,
                entry["kind"],
                entry["description"],
                entry["descriptor_json"],
                stamp,
                STATUS_ACTIVE,
                entry["actor"],
            )
            for entry in self._pending
        ]
        self.conn.executemany(
            f"INSERT INTO {_TABLE} (action, kind, description, descriptor_json, created_at,"
            " status, actor) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()
        count = len(rows)
        self._recorded += count
        self._pending.clear()
        return count

    def revert(self) -> dict[str, Any]:
        """Flush, then replay this journal's entries newest-first."""
        self.flush()
        return revert_action(self.conn, self.action)

    def attach(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Return *payload* plus :data:`ACTION_FIELD` when this action wrote something."""
        if self.recorded() == 0:
            return dict(payload)
        return {**payload, ACTION_FIELD: self.action}


@contextlib.contextmanager
def journaled(conn: sqlite3.Connection, action: str) -> Iterator[Journal]:
    """Yield a :class:`Journal` that flushes on a clean exit, not on a raise."""
    log = Journal(conn, action)
    yield log
    log.flush()


# ── Descriptor builders ────────────────────────────────────────────


def snapshot_rows(
    conn: sqlite3.Connection, *, table: str, where: str, params: Sequence[Any] = ()
) -> list[dict[str, Any]]:
    """Return the rows *table* is about to lose, as plain dicts.

    *where* is a trusted SQL fragment authored by reportal; *params* are bound,
    never interpolated.  A table the schema has not created yet has no rows to
    snapshot, and its absence is not an error: a snapshot list may name a table
    that is created lazily on first use (`sandbox_runs` in a database where
    nothing was detonated), and the delete it belongs to has nothing to lose.
    """
    if not table_exists(conn, table):
        return []
    cursor = conn.execute(f"SELECT * FROM {quote_identifier(table)} WHERE {where}", tuple(params))
    return [dict(row) for row in cursor.fetchall()]


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """Whether *table* exists in the open database."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return row is not None


def row_restore_descriptor(table: str, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """A descriptor whose inverse re-inserts *rows* with ``INSERT OR REPLACE``."""
    columns = [str(column) for column in rows[0]] if rows else []
    return {
        "kind": effects.EFFECT_ROW_RESTORE,
        "table": table,
        "columns": columns,
        "rows": [dict(row) for row in rows],
    }


def row_delete_descriptor(table: str, pk: int | str | Mapping[str, Any]) -> dict[str, Any]:
    """A descriptor whose inverse deletes the row this action created.

    *pk* is either the primary key value (deleted by the ``id`` column) or a
    mapping of column to value for a table with a composite or non-``id`` key.
    """
    keys = dict(pk) if isinstance(pk, Mapping) else {"id": pk}
    if not keys:
        raise ValueError("a row-delete descriptor needs at least one key column")
    return {"kind": effects.EFFECT_ROW_DELETE, "table": table, "keys": keys}


def file_delete_descriptor(path: str) -> dict[str, Any]:
    """A descriptor whose inverse deletes the file an action wrote."""
    return {"kind": effects.EFFECT_FILE_DELETE, "path": str(path)}


def read_bounded(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read at most *limit* + 1 bytes of *path*.

    The extra byte is what makes a file past the cap read as oversized to
    :func:`file_restore_descriptor` without pulling the whole file into memory.
    """
    with path.open("rb") as handle:
        return handle.read(limit + 1)


def file_restore_descriptor(path: str, data: bytes) -> dict[str, Any]:
    """A descriptor whose inverse writes *data* back to *path*.

    Content past :data:`MAX_FILE_BYTES` is not carried: the descriptor records
    the path, its inverse reports partial, and the entry is marked
    :data:`STATUS_PARTIAL` on revert.
    """
    if len(data) > MAX_FILE_BYTES:
        return {"kind": effects.EFFECT_FILE_RESTORE, "path": str(path), "partial": True}
    return {
        "kind": effects.EFFECT_FILE_RESTORE,
        "path": str(path),
        "data_b64": base64.b64encode(data).decode("ascii"),
        "size": len(data),
    }


# ── Wiring helpers ─────────────────────────────────────────────────


def journaled_rows(
    conn: sqlite3.Connection,
    log: Journal,
    *,
    table: str,
    where: str,
    params: Sequence[Any] = (),
    description: str | None = None,
) -> list[dict[str, Any]]:
    """Snapshot the rows a write is about to replace and journal their restore.

    Returns the rows so the caller can compare them with the state after the
    write; the recorded descriptor updates each one in place, or re-inserts it
    when a revert finds it missing.
    """
    rows = snapshot_rows(conn, table=table, where=where, params=params)
    if rows:
        log.record(
            effects.EFFECT_ROW_RESTORE,
            description or f"changed {len(rows)} row(s) of {table}",
            row_restore_descriptor(table, rows),
        )
    return rows


def journaled_create(
    log: Journal, *, table: str, key: int | str | Mapping[str, Any], description: str
) -> None:
    """Journal the row a write created, so a revert deletes it."""
    log.record(effects.EFFECT_ROW_DELETE, description, row_delete_descriptor(table, key))


def journaled_new_rows(
    conn: sqlite3.Connection,
    log: Journal,
    *,
    table: str,
    where: str,
    params: Sequence[Any],
    before: Sequence[Mapping[str, Any]],
    key: Sequence[str],
    description: str | None = None,
) -> None:
    """Journal deletes for the rows a write created under the same scope.

    *before* is what :func:`journaled_rows` returned for that scope and *key*
    the columns identifying one row.  Recorded after the restore entry, so a
    revert removes the new rows before it puts the old ones back.
    """
    known = {_row_key(row, key) for row in before}
    for row in snapshot_rows(conn, table=table, where=where, params=params):
        if _row_key(row, key) in known:
            continue
        log.record(
            effects.EFFECT_ROW_DELETE,
            description or f"created a row of {table}",
            row_delete_descriptor(table, {column: row[column] for column in key}),
        )


def _row_key(row: Mapping[str, Any], key: Sequence[str]) -> tuple[Any, ...]:
    """The values of *key* in *row*, as a hashable tuple."""
    return tuple(row[column] for column in key)


def journaled_file(
    log: Journal, path: Path, *, previous: bytes | None, description: str | None = None
) -> None:
    """Journal the file a write created or replaced.

    *previous* is what the path held before the write, or None when it did not
    exist: a revert removes a file the action created and writes the bytes back
    when it replaced one.
    """
    target = str(path)
    if previous is None:
        log.record(
            effects.EFFECT_FILE_DELETE,
            description or f"wrote {target}",
            file_delete_descriptor(target),
        )
    else:
        log.record(
            effects.EFFECT_FILE_RESTORE,
            description or f"overwrote {target}",
            file_restore_descriptor(target, previous),
        )


# Note a journaled conversation message carries: the row is restorable, the
# model call that produced the reply is not.
MESSAGE_REPLAY_NOTE = "a revert removes the exchange, not the model call"


def journaled_messages(
    conn: sqlite3.Connection,
    log: Journal,
    conversation_id: int,
    before: frozenset[int] | set[int],
) -> None:
    """Journal the messages a send appended, out of the ids *before* it."""
    for row in store.list_messages(conn, conversation_id):
        if int(row["id"]) in before:
            continue
        journaled_create(
            log,
            table="messages",
            key=int(row["id"]),
            description=(
                f"sent the {row['role']} message of conversation {conversation_id};"
                f" {MESSAGE_REPLAY_NOTE}"
            ),
        )


def journaled_ingest(conn: sqlite3.Connection, log: Journal, payload: Mapping[str, Any]) -> None:
    """Journal a newly stored document and its chunks; a duplicate stored nothing."""
    if payload.get("duplicate"):
        return
    document_id = int(payload["id"])
    journaled_create(
        log, table="documents", key=document_id, description=f"ingested document {document_id}"
    )
    for chunk in store.list_chunks(conn, document_id):
        journaled_create(
            log,
            table="chunks",
            key=int(chunk["id"]),
            description=f"ingested chunk {chunk['id']} of document {document_id}",
        )


def _journal_rename_rows(
    conn: sqlite3.Connection,
    log: Journal,
    function_id: int,
    before: Sequence[Mapping[str, Any]],
    known_history_ids: frozenset[int],
) -> None:
    """Journal the history row a rename appended and the functions row it changed."""
    added = [
        int(row["id"])
        for row in store.list_name_history(conn, function_id)
        if int(row["id"]) not in known_history_ids
    ]
    if not added:
        return
    journaled_create(
        log,
        table="name_history",
        key=max(added),
        description=f"rename history of function {function_id}",
    )
    if before:
        log.record(
            effects.EFFECT_ROW_RESTORE,
            f"renamed function {function_id}",
            row_restore_descriptor("functions", before),
        )


def journaled_name_change(
    conn: sqlite3.Connection,
    log: Journal,
    function_id: int,
    run: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run a rename, journaling the functions row and the history row it changed."""
    before = snapshot_rows(conn, table="functions", where="id = ?", params=(function_id,))
    known = frozenset(int(row["id"]) for row in store.list_name_history(conn, function_id))
    change = run()
    _journal_rename_rows(conn, log, function_id, before, known)
    return change


def journaled_rename(
    conn: sqlite3.Connection,
    log: Journal,
    function_id: int,
    *,
    new_name: str,
    actor: str,
    source: str,
) -> dict[str, Any]:
    """Rename a function, journaling the functions row and the history row."""
    return journaled_name_change(
        conn,
        log,
        function_id,
        lambda: store.rename_function(
            conn, function_id, new_name=new_name, actor=actor, source=source
        ),
    )


def journaled_revert_name(
    conn: sqlite3.Connection, log: Journal, function_id: int, history_id: int
) -> None:
    """Revert one history row, journaling the rename that revert itself records."""
    before = snapshot_rows(conn, table="functions", where="id = ?", params=(function_id,))
    known = frozenset(int(row["id"]) for row in store.list_name_history(conn, function_id))
    store.revert_name(conn, history_id)
    _journal_rename_rows(conn, log, function_id, before, known)


def journaled_analysis(
    conn: sqlite3.Connection, log: Journal, binary_id: int, *, engine: str
) -> int:
    """Return the binary's latest analysis, journaling it when this created it."""
    existing = store.latest_analysis_for_binary(conn, binary_id)
    if existing is not None:
        return existing
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=engine)
    journaled_create(
        log,
        table="analyses",
        key=analysis_id,
        description=f"created analysis {analysis_id} for binary {binary_id}",
    )
    return analysis_id


def _snapshot_scan(
    conn: sqlite3.Connection, log: Journal, analysis_id: int | None, binary_id: int, kind: str
) -> bool:
    """Journal the scan row a run is about to replace; True when one existed."""
    if analysis_id is None:
        return False
    previous = snapshot_rows(
        conn, table="scans", where="analysis_id = ? AND kind = ?", params=(analysis_id, kind)
    )
    if not previous:
        return False
    log.record(
        effects.EFFECT_ROW_RESTORE,
        f"stored {kind} scan for binary {binary_id}",
        row_restore_descriptor("scans", previous),
    )
    return True


def journaled_scan_result(
    conn: sqlite3.Connection,
    log: Journal,
    binary_id: int,
    kind: str,
    result: dict[str, Any],
    *,
    engine: str = store.SCAN_ENGINE,
) -> None:
    """Store one scan *result*, journaling the row it replaced and the analysis it created."""
    analysis_before = store.latest_analysis_for_binary(conn, binary_id)
    replaced = _snapshot_scan(conn, log, analysis_before, binary_id, kind)
    analysis_id = journaled_analysis(conn, log, binary_id, engine=engine)
    store.set_scan(conn, analysis_id, kind, result)
    if not replaced:
        journaled_create(
            log,
            table="scans",
            key={"analysis_id": analysis_id, "kind": kind},
            description=f"stored {kind} scan for binary {binary_id}",
        )


def journaled_graph_rebuild(
    conn: sqlite3.Connection,
    log: Journal,
    binary_id: int,
    build: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run a graph rebuild, journaling the previous graph and the new rows.

    A revert restores the previous nodes and edges and removes the ones the
    rebuild created; the graph backend the rebuild may have pushed to is not
    part of the journal.
    """
    before_nodes = journaled_rows(
        conn,
        log,
        table="graph_nodes",
        where="binary_id = ?",
        params=(binary_id,),
        description=f"replaced the graph nodes of binary {binary_id}",
    )
    before_edges = journaled_rows(
        conn,
        log,
        table="graph_edges",
        where="binary_id = ?",
        params=(binary_id,),
        description=f"replaced the graph edges of binary {binary_id}",
    )
    result = build()
    journaled_new_rows(
        conn,
        log,
        table="graph_nodes",
        where="binary_id = ?",
        params=(binary_id,),
        before=before_nodes,
        key=("id",),
        description=f"built a graph node of binary {binary_id}",
    )
    journaled_new_rows(
        conn,
        log,
        table="graph_edges",
        where="binary_id = ?",
        params=(binary_id,),
        before=before_edges,
        key=("id",),
        description=f"built a graph edge of binary {binary_id}",
    )
    return result


def journaled_scan(
    conn: sqlite3.Connection,
    log: Journal,
    binary_id: int,
    kind: str,
    run: Callable[[], dict[str, Any]],
    *,
    engine: str = store.SCAN_ENGINE,
) -> dict[str, Any]:
    """Run a scan that stores itself, journaling the row it replaced or created.

    The analysis row is journaled only when *run* created it, so a revert of a
    binary's first scan removes the carrier and a later one leaves it alone.
    The run goes inside a :func:`reportal.store.scan_span`, which records the
    scan's start in the analysis log and a failure when it raises; a failure
    leaves the analysis carrier behind so the entry has somewhere to live.
    """
    analysis_before = store.latest_analysis_for_binary(conn, binary_id)
    replaced = _snapshot_scan(conn, log, analysis_before, binary_id, kind)
    with store.scan_span(conn, binary_id=binary_id, kind=kind, engine=engine):
        result = run()
    analysis_after = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_before is None and analysis_after is not None:
        journaled_create(
            log,
            table="analyses",
            key=analysis_after,
            description=f"created analysis {analysis_after} for binary {binary_id}",
        )
    if replaced or analysis_after is None:
        return result
    journaled_create(
        log,
        table="scans",
        key={"analysis_id": analysis_after, "kind": kind},
        description=f"stored {kind} scan for binary {binary_id}",
    )
    return result


# Scope of a function row in one analysis, as a subquery that binds the
# analysis id once.
_FUNCTIONS_OF_ANALYSIS = "SELECT id FROM functions WHERE analysis_id = ?"

# Every table an analysis delete removes, with the WHERE clause selecting the
# rows scoped to one analysis id.  The foreign keys cascade these rows anyway;
# snapshotting them is what makes the delete revertible.  Children precede
# parents, so the reversed replay inserts the analysis before its functions.
ANALYSIS_DELETE_SNAPSHOTS: tuple[tuple[str, str], ...] = (
    ("sandbox_runs", "analysis_id = ?"),
    ("scans", "analysis_id = ?"),
    (analysis_log.TABLE, "analysis_id = ?"),
    ("function_signatures", f"function_id IN ({_FUNCTIONS_OF_ANALYSIS})"),
    ("signature_history", f"function_id IN ({_FUNCTIONS_OF_ANALYSIS})"),
    ("ai_artifacts", f"function_id IN ({_FUNCTIONS_OF_ANALYSIS})"),
    ("decompilations", f"function_id IN ({_FUNCTIONS_OF_ANALYSIS})"),
    ("disasm_cache", f"function_id IN ({_FUNCTIONS_OF_ANALYSIS})"),
    ("name_history", f"function_id IN ({_FUNCTIONS_OF_ANALYSIS})"),
    (
        "matches",
        (
            f"function_id IN ({_FUNCTIONS_OF_ANALYSIS})"
            f" OR candidate_function_id IN ({_FUNCTIONS_OF_ANALYSIS})"
        ),
    ),
    (
        "pipeline_steps",
        (
            "run_id IN (SELECT id FROM pipeline_runs WHERE"
            f" function_id IN ({_FUNCTIONS_OF_ANALYSIS}))"
        ),
    ),
    ("pipeline_runs", f"function_id IN ({_FUNCTIONS_OF_ANALYSIS})"),
    ("functions", f"id IN ({_FUNCTIONS_OF_ANALYSIS})"),
    ("analyses", "id = ?"),
)


def journaled_analysis_delete(conn: sqlite3.Connection, log: Journal, analysis_id: int) -> bool:
    """Delete one analysis, journaling every dependent row the cascade removes.

    Returns whether the analysis existed.  The collection's revert replays the
    snapshots newest-first, so the analysis row and its functions come back
    before the rows that reference them.
    """
    for table, where in ANALYSIS_DELETE_SNAPSHOTS:
        rows = snapshot_rows(
            conn, table=table, where=where, params=(analysis_id,) * where.count("?")
        )
        if rows:
            log.record(
                effects.EFFECT_ROW_RESTORE,
                f"deleted {table} rows of analysis {analysis_id}",
                row_restore_descriptor(table, rows),
            )
    return store.delete_analysis(conn, analysis_id)


# ── Reading and reverting ──────────────────────────────────────────


def _columns_of(row: sqlite3.Row | Mapping[str, Any]) -> Any:
    """The column names of a row, whichever driver type it is.

    ``sqlite3.Row`` and a mapping both answer ``keys()``; ``in`` on the row
    itself would test its *values*, which is not what the actor lookup means.
    """
    return row.keys()


def _entry_row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """The metadata of one entry, without its descriptor payload."""
    return {
        "id": int(row["id"]),
        "action": str(row["action"]),
        "kind": str(row["kind"]),
        "description": str(row["description"]),
        "created_at": str(row["created_at"]),
        "status": str(row["status"]),
        "actor": str(row["actor"]) if "actor" in _columns_of(row) else "",
    }


def list_entries(
    conn: sqlite3.Connection, *, action: str | None = None, limit: int = DEFAULT_LIST_LIMIT
) -> list[dict[str, Any]]:
    """Entries newest first, optionally narrowed to one action.

    The descriptor payload is not returned: a file descriptor can carry bytes,
    and the metadata is what a listing renders.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    ensure_schema(conn)
    sql = f"SELECT * FROM {_TABLE}"
    params: list[Any] = []
    if action is not None:
        sql += " WHERE action = ?"
        params.append(action)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(min(limit, MAX_LIST_LIMIT))
    return [_entry_row(row) for row in conn.execute(sql, params)]


def count_actions(conn: sqlite3.Connection, *, since: str | None = None) -> int:
    """How many actions there are, whatever a reader's page is."""
    ensure_schema(conn)
    sql = f"SELECT COUNT(DISTINCT action) FROM {_TABLE}"
    params: list[Any] = []
    if since is not None:
        sql += " WHERE created_at >= ?"
        params.append(since)
    return int(conn.execute(sql, params).fetchone()[0])


def list_actions(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    actor: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
) -> list[dict[str, Any]]:
    """One row per action, newest first, described by its newest entry.

    An action writes one entry per descriptor, so a listing that read entries
    would repeat the same action many times.  This reads the newest entry of
    each action and counts the action's rows, which is what a feed renders:
    ``id``, ``action``, ``kind``, ``description``, ``created_at`` and ``status``
    of that newest entry, ``entries`` for the action's row count and ``active``
    for how many of them are still awaiting a revert.  *since* is an ISO
    timestamp compared as text, the format the rows are written in, and it is
    inclusive: two writes in the same second share one timestamp, so an item
    written at the named second is still returned and a polling reader
    de-duplicates by id rather than losing it.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    ensure_schema(conn)
    sql = (
        f"SELECT e.*, (SELECT COUNT(*) FROM {_TABLE} c WHERE c.action = e.action) AS entries,"
        f" (SELECT COUNT(*) FROM {_TABLE} a WHERE a.action = e.action AND a.status = ?) AS active"
        f" FROM {_TABLE} e WHERE e.id IN (SELECT MAX(id) FROM {_TABLE} GROUP BY action)"
    )
    params: list[Any] = [STATUS_ACTIVE]
    if since is not None:
        sql += " AND e.created_at >= ?"
        params.append(since)
    if actor is not None:
        sql += " AND e.actor = ?"
        params.append(actor)
    sql += " ORDER BY e.id DESC LIMIT ?"
    params.append(min(limit, MAX_LIST_LIMIT))
    rows = []
    for row in conn.execute(sql, params):
        entry = _entry_row(row)
        entry["entries"] = int(row["entries"])
        entry["active"] = int(row["active"])
        rows.append(entry)
    return rows


def _load_descriptor(raw: str) -> dict[str, Any]:
    """Parse a stored descriptor, or raise :class:`JournalError` for a corrupt one."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise JournalError(f"corrupt journal descriptor: {exc}") from exc
    if not isinstance(parsed, dict):
        raise JournalError("corrupt journal descriptor: not a JSON object")
    return parsed


def _status_for(outcome: Mapping[str, Any]) -> str:
    """The entry status an inverse's report maps to."""
    reported = str(outcome.get("status", effects.EFFECT_REVERTED))
    if reported == effects.EFFECT_FAILED:
        return STATUS_ACTIVE
    if reported == effects.EFFECT_PARTIAL:
        return STATUS_PARTIAL
    return STATUS_REVERTED


def _active_rows(conn: sqlite3.Connection, action: str) -> list[sqlite3.Row]:
    """Rows of one action still awaiting a revert, oldest first."""
    cursor = conn.execute(
        f"SELECT * FROM {_TABLE} WHERE action = ? AND status = ? ORDER BY id",
        (action, STATUS_ACTIVE),
    )
    return list(cursor.fetchall())


def revert_action(conn: sqlite3.Connection, action: str) -> dict[str, Any]:
    """Replay one action's active descriptors newest-first.

    Returns ``{"action", "entries", "reverted", "partial", "failed"}``; the
    per-entry list carries the inverse's own report, one failing inverse does
    not strand the rest, and an action with nothing left to revert answers an
    empty report.  ``partial`` counts entries whose inverse could not restore
    everything it recorded (an oversized file).
    Raises :class:`UnknownActionError` for an action the journal never recorded.
    """
    ensure_schema(conn)
    rows = _active_rows(conn, action)
    if not rows:
        known = conn.execute(
            f"SELECT 1 FROM {_TABLE} WHERE action = ? LIMIT 1", (action,)
        ).fetchone()
        if known is None:
            raise UnknownActionError(f"no journal action {action!r}")
        return {"action": action, "entries": [], "reverted": 0, "partial": 0, "failed": 0}
    descriptors = [_load_descriptor(str(row["descriptor_json"])) for row in rows]
    outcomes = effects.apply_undo_plan(conn, descriptors)
    report: list[dict[str, Any]] = []
    reverted = 0
    partial = 0
    failed = 0
    for row, outcome in zip(reversed(rows), outcomes, strict=True):
        status = _status_for(outcome)
        if status == STATUS_REVERTED:
            reverted += 1
        elif status == STATUS_PARTIAL:
            partial += 1
        else:
            failed += 1
        if status != STATUS_ACTIVE:
            conn.execute(f"UPDATE {_TABLE} SET status = ? WHERE id = ?", (status, row["id"]))
        report.append(
            {
                **_entry_row(row),
                "status": status,
                "detail": str(outcome.get("detail", "")),
            }
        )
    conn.commit()
    return {
        "action": action,
        "entries": report,
        "reverted": reverted,
        "partial": partial,
        "failed": failed,
    }


def revert_entry(conn: sqlite3.Connection, entry_id: int) -> dict[str, Any]:
    """Apply one entry's inverse and report its status.

    Raises :class:`UnknownEntryError` for an unknown id and
    :class:`EntryNotActiveError` for an entry that is no longer active.  A
    failing inverse is reported, not raised, and leaves the entry active.
    """
    ensure_schema(conn)
    row = conn.execute(f"SELECT * FROM {_TABLE} WHERE id = ?", (entry_id,)).fetchone()
    if row is None:
        raise UnknownEntryError(f"no journal entry with id {entry_id}")
    if str(row["status"]) != STATUS_ACTIVE:
        raise EntryNotActiveError(f"journal entry {entry_id} is already {row['status']}")
    descriptor = _load_descriptor(str(row["descriptor_json"]))
    try:
        outcome = effects.apply_descriptor(conn, descriptor)
    except Exception as exc:  # one bad descriptor is a reported failure, not a crash
        return {
            "entry": _entry_row(row),
            "status": STATUS_ACTIVE,
            "detail": str(exc),
        }
    status = _status_for(outcome)
    if status != STATUS_ACTIVE:
        conn.execute(f"UPDATE {_TABLE} SET status = ? WHERE id = ?", (status, entry_id))
    conn.commit()
    return {
        "entry": _entry_row(row),
        "status": status,
        "detail": str(outcome.get("detail", "")),
    }


def prune_entries(conn: sqlite3.Connection, keep: int = DEFAULT_PRUNE_KEEP) -> int:
    """Delete every entry but the newest *keep*; returns how many went.

    Pruning is by id, not by status: a reverted action's entries are its
    history, and the journal is a bounded operator log, not an archive.
    """
    if keep < 0:
        raise ValueError("keep must not be negative")
    ensure_schema(conn)
    cursor = conn.execute(
        f"DELETE FROM {_TABLE} WHERE id NOT IN (SELECT id FROM {_TABLE} ORDER BY id DESC LIMIT ?)",
        (keep,),
    )
    conn.commit()
    return int(cursor.rowcount) if cursor.rowcount > 0 else 0

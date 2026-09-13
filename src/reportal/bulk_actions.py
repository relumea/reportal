"""Bulk actions over binaries and functions, shared by the API, CLI and MCP.

Each action applies to a bounded list of ids and never fails as a whole for one
bad id: an unknown id, or one the action cannot touch, lands in the result's
``skipped`` list with a reason while the remaining ids still run.  A malformed
request, an unknown action, an empty list or a list past :data:`MAX_BULK_IDS`
raises :class:`BulkError`, which the callers map to a 400.

A bulk prefix rename goes through :func:`reportal.store.rename_function`, so
every renamed function keeps a ``name_history`` row with source
:data:`BULK_RENAME_SOURCE` and the old name.  The default form appends
``prefix`` to the current name; the replace form drops the leading segment up
to and including the first :data:`PREFIX_SEPARATOR` before adding it, so
"sub_1000" with prefix "NP_" becomes "NP_1000".

A caller that passes a :class:`reportal.journal.Journal` gets every write
recorded as a revertible entry: the link rows a tag change touches, the rows a
binary delete removes (:data:`BINARY_DELETE_SNAPSHOTS`), the uploaded file that
delete removes, the functions and history rows a prefix rename changes, and the
matches rows ``clear_matches`` drops.  A caller that passes none gets today's
behaviour, unchanged.
"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Collection, Sequence
from pathlib import Path
from typing import Any

from reportal import effects, journal, store
from reportal._paths import stored_binary_path

# Actions `POST /api/binaries/bulk` accepts.
BINARY_ACTIONS: tuple[str, ...] = ("add_tag", "remove_tag", "delete")

# Actions `POST /api/functions/bulk` accepts.
FUNCTION_ACTIONS: tuple[str, ...] = ("rename", "clear_matches")

# Actions `POST /api/analyses/bulk` accepts.  A tag action writes the tags of
# each analysis's owning binary, the only scope reportal tags at.
ANALYSIS_ACTIONS: tuple[str, ...] = ("add_tag", "remove_tag", "delete")

# Ids one bulk request may carry.  A longer list is rejected whole rather than
# applied in part, so the caller can split it deliberately.
MAX_BULK_IDS = 500

# Separator between a function name's prefix and its remainder, which the
# replace form of the prefix rename splits on.
PREFIX_SEPARATOR = "_"

# `name_history.source` recorded by a bulk prefix rename, so the change is
# traceable to the action that produced it.
BULK_RENAME_SOURCE = "bulk-prefix"

# `name_history.actor` recorded by a bulk prefix rename.
BULK_RENAME_ACTOR = "bulk"

# Reason a skipped id carries.
REASON_NOT_FOUND = "not found"
REASON_NO_TAG = "tag not found"
REASON_UNCHANGED = "unchanged"
REASON_LAST_ANALYSIS = "only analysis with functions"
REASON_FORBIDDEN = "not permitted"

# The functions of one binary, as a subquery binding the binary id once.
_FUNCTIONS_OF_BINARY = (
    "SELECT f.id FROM functions f JOIN analyses a ON f.analysis_id = a.id WHERE a.binary_id = ?"
)

# The documents of one binary, in either the binary or the function scope.
_DOCUMENTS_OF_BINARY = (
    "SELECT d.id FROM documents d WHERE (d.scope_kind = 'binary' AND d.scope_id = ?)"
    f" OR (d.scope_kind = 'function' AND d.scope_id IN ({_FUNCTIONS_OF_BINARY}))"
)

# Every table a binary delete touches, with the WHERE clause selecting the rows
# scoped to one binary id.  A snapshot of each precedes the delete, so the
# action's revert re-inserts them; the order is children before parents, which
# makes the reversed replay insert parents first and satisfy the foreign keys.
BINARY_DELETE_SNAPSHOTS: tuple[tuple[str, str], ...] = (
    ("sandbox_runs", "binary_id = ?"),
    ("collection_binaries", "binary_id = ?"),
    ("data_type_history", "binary_id = ?"),
    ("data_types", "binary_id = ?"),
    ("graph_edges", "binary_id = ?"),
    ("graph_nodes", "binary_id = ?"),
    ("families", "reference_binary_id = ?"),
    ("rebrew_contexts", "binary_id = ?"),
    ("binary_fingerprints", "binary_id = ?"),
    ("binary_tags", "binary_id = ?"),
    ("scans", "analysis_id IN (SELECT id FROM analyses WHERE binary_id = ?)"),
    ("function_signatures", f"function_id IN ({_FUNCTIONS_OF_BINARY})"),
    ("ai_artifacts", f"function_id IN ({_FUNCTIONS_OF_BINARY})"),
    ("decompilations", f"function_id IN ({_FUNCTIONS_OF_BINARY})"),
    ("disasm_cache", f"function_id IN ({_FUNCTIONS_OF_BINARY})"),
    ("name_history", f"function_id IN ({_FUNCTIONS_OF_BINARY})"),
    ("signature_history", f"function_id IN ({_FUNCTIONS_OF_BINARY})"),
    (
        "matches",
        (
            f"function_id IN ({_FUNCTIONS_OF_BINARY})"
            f" OR candidate_function_id IN ({_FUNCTIONS_OF_BINARY})"
        ),
    ),
    (
        "comments",
        (
            "(scope_kind = 'binary' AND scope_id = ?)"
            f" OR (scope_kind = 'function' AND scope_id IN ({_FUNCTIONS_OF_BINARY}))"
        ),
    ),
    (
        "conversations",
        (
            "(scope_kind = 'binary' AND scope_id = ?)"
            f" OR (scope_kind = 'function' AND scope_id IN ({_FUNCTIONS_OF_BINARY}))"
        ),
    ),
    ("chunks", f"document_id IN ({_DOCUMENTS_OF_BINARY})"),
    ("documents", f"id IN ({_DOCUMENTS_OF_BINARY})"),
    ("functions", f"id IN ({_FUNCTIONS_OF_BINARY})"),
    ("analyses", "binary_id = ?"),
    ("binaries", "id = ?"),
)


class BulkError(ValueError):
    """The bulk request itself is unusable; the API answers 400."""


def resolve_ids(ids: Sequence[int]) -> list[int]:
    """Validate a bulk id list, deduplicated in place, or raise :class:`BulkError`."""
    unique: list[int] = []
    seen: set[int] = set()
    for value in ids:
        if isinstance(value, bool) or not isinstance(value, int):
            raise BulkError("ids must be a list of integers")
        if value not in seen:
            seen.add(value)
            unique.append(value)
    if not unique:
        raise BulkError("at least one id is required")
    if len(unique) > MAX_BULK_IDS:
        raise BulkError(f"at most {MAX_BULK_IDS} ids per request")
    return unique


def _result(action: str, requested: int) -> dict[str, Any]:
    return {"action": action, "requested": requested, "applied": 0, "skipped": []}


def _skip(result: dict[str, Any], entry_id: int, reason: str) -> None:
    result["skipped"].append({"id": entry_id, "reason": reason})


def _record_file(log: journal.Journal | None, path: str) -> None:
    """Journal the uploaded file a delete removes, reading it through the size cap."""
    if log is None or not stored_binary_path(path):
        return
    log.record(
        effects.EFFECT_FILE_RESTORE,
        f"deleted file {path}",
        journal.file_restore_descriptor(path, journal.read_bounded(Path(path))),
    )


def _remove_binary(conn: sqlite3.Connection, log: journal.Journal | None, binary_id: int) -> bool:
    """Delete one binary, journaling the rows and the uploaded file it removes."""
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        return False
    if log is not None:
        for table, where in BINARY_DELETE_SNAPSHOTS:
            rows = journal.snapshot_rows(
                conn, table=table, where=where, params=(binary_id,) * where.count("?")
            )
            if rows:
                log.record(
                    effects.EFFECT_ROW_RESTORE,
                    f"deleted {table} rows of binary {binary_id}",
                    journal.row_restore_descriptor(table, rows),
                )
    path = str(binary.get("path") or "")
    _record_file(log, path)
    store.delete_binary(conn, binary_id)
    if path and stored_binary_path(path):
        with contextlib.suppress(OSError):
            Path(path).unlink(missing_ok=True)
    return True


def _tag_result(
    conn: sqlite3.Connection,
    log: journal.Journal | None,
    *,
    action: str,
    tag_id: int,
    binary_id: int,
) -> None:
    """Apply one tag link change and journal the link row it inserted or removed."""
    if action == "add_tag":
        if store.add_binary_tag(conn, binary_id, tag_id) and log is not None:
            log.record(
                effects.EFFECT_ROW_DELETE,
                f"tagged binary {binary_id} with tag {tag_id}",
                journal.row_delete_descriptor(
                    "binary_tags", {"binary_id": binary_id, "tag_id": tag_id}
                ),
            )
        return
    link = (
        journal.snapshot_rows(
            conn,
            table="binary_tags",
            where="binary_id = ? AND tag_id = ?",
            params=(binary_id, tag_id),
        )
        if log is not None
        else []
    )
    store.remove_binary_tag(conn, binary_id, tag_id)
    if log is not None and link:
        log.record(
            effects.EFFECT_ROW_RESTORE,
            f"untagged binary {binary_id} from tag {tag_id}",
            journal.row_restore_descriptor("binary_tags", link),
        )


def _resolve_tag(
    conn: sqlite3.Connection, log: journal.Journal | None, *, action: str, tag_name: str
) -> int:
    """The tag id one tag action works on; 0 when a removal names no known tag.

    ``add_tag`` creates the name when it does not exist yet, journaling the
    creation so a revert drops it again.
    """
    if action == "add_tag":
        created = store.find_tag(conn, tag_name) is None
        tag_id = store.create_tag(conn, tag_name)
        if created and log is not None:
            log.record(
                effects.EFFECT_ROW_DELETE,
                f"created tag {tag_id}",
                journal.row_delete_descriptor("tags", tag_id),
            )
        return tag_id
    known = store.find_tag(conn, tag_name)
    return int(known["id"]) if known else 0


def apply_binary_action(
    conn: sqlite3.Connection,
    *,
    action: str,
    ids: Sequence[int],
    tag: str = "",
    log: journal.Journal | None = None,
    allowed: Collection[int] | None = None,
) -> dict[str, Any]:
    """Apply one bulk action to binaries and return its per-id result.

    *allowed* is the set of ids the caller may reach (a team-scoped install
    passes the binaries it can see); an id outside it is skipped with
    :data:`REASON_FORBIDDEN` rather than acted on.  None means every id.
    """
    if action not in BINARY_ACTIONS:
        raise BulkError(f"unsupported action: {action}")
    resolved = resolve_ids(ids)
    if allowed is not None:
        permitted = [binary_id for binary_id in resolved if binary_id in set(allowed)]
        blocked = [binary_id for binary_id in resolved if binary_id not in set(allowed)]
    else:
        permitted, blocked = resolved, []
    tag_name = (tag or "").strip()
    if action != "delete" and not tag_name:
        raise BulkError(f"tag is required for action {action}")
    result = _result(action, len(resolved))
    for binary_id in blocked:
        _skip(result, binary_id, REASON_FORBIDDEN)
    if action == "delete":
        for binary_id in permitted:
            if not _remove_binary(conn, log, binary_id):
                _skip(result, binary_id, REASON_NOT_FOUND)
            else:
                result["applied"] += 1
        return result
    tag_id = _resolve_tag(conn, log, action=action, tag_name=tag_name)
    for binary_id in permitted:
        if store.get_binary(conn, binary_id) is None:
            _skip(result, binary_id, REASON_NOT_FOUND)
        elif not tag_id:
            _skip(result, binary_id, REASON_NO_TAG)
        else:
            _tag_result(conn, log, action=action, tag_id=tag_id, binary_id=binary_id)
            result["applied"] += 1
    return result


def apply_analysis_action(
    conn: sqlite3.Connection,
    *,
    action: str,
    ids: Sequence[int],
    tag: str = "",
    log: journal.Journal | None = None,
) -> dict[str, Any]:
    """Apply one bulk action to analyses and return its per-id result.

    A tag action writes each analysis's owning binary, the scope reportal tags
    at.  A delete replays the same journaled snapshot the single-analysis route
    uses, and a binary's only analysis while it holds functions is skipped with
    a reason rather than taken with them (delete the binary instead).
    """
    if action not in ANALYSIS_ACTIONS:
        raise BulkError(f"unsupported action: {action}")
    resolved = resolve_ids(ids)
    tag_name = (tag or "").strip()
    if action != "delete" and not tag_name:
        raise BulkError(f"tag is required for action {action}")
    result = _result(action, len(resolved))
    if action == "delete":
        for analysis_id in resolved:
            if store.get_analysis(conn, analysis_id) is None:
                _skip(result, analysis_id, REASON_NOT_FOUND)
            elif store.is_last_analysis_with_functions(conn, analysis_id):
                _skip(result, analysis_id, REASON_LAST_ANALYSIS)
            else:
                if log is not None:
                    journal.journaled_analysis_delete(conn, log, analysis_id)
                else:
                    store.delete_analysis(conn, analysis_id)
                result["applied"] += 1
        return result
    tag_id = _resolve_tag(conn, log, action=action, tag_name=tag_name)
    for analysis_id in resolved:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            _skip(result, analysis_id, REASON_NOT_FOUND)
        elif not tag_id:
            _skip(result, analysis_id, REASON_NO_TAG)
        else:
            _tag_result(
                conn,
                log,
                action=action,
                tag_id=tag_id,
                binary_id=int(analysis["binary_id"]),
            )
            result["applied"] += 1
    return result


def _prefix_name(name: str, prefix: str, replace: bool) -> str:
    """Return *name* with *prefix* appended, or replacing its leading segment."""
    if not replace:
        return f"{prefix}{name}"
    _, separator, tail = name.partition(PREFIX_SEPARATOR)
    return f"{prefix}{tail}" if separator and tail else f"{prefix}{name}"


def apply_function_action(
    conn: sqlite3.Connection,
    *,
    action: str,
    ids: Sequence[int],
    prefix: str = "",
    replace: bool = False,
    log: journal.Journal | None = None,
) -> dict[str, Any]:
    """Apply one bulk action to functions and return its per-id result."""
    if action not in FUNCTION_ACTIONS:
        raise BulkError(f"unsupported action: {action}")
    resolved = resolve_ids(ids)
    prefix = (prefix or "").strip()
    if action == "rename" and not prefix:
        raise BulkError("prefix is required for action rename")
    result = _result(action, len(resolved))
    for function_id in resolved:
        function = store.get_function(conn, function_id)
        if function is None:
            _skip(result, function_id, REASON_NOT_FOUND)
            continue
        if action == "clear_matches":
            matches = (
                journal.snapshot_rows(
                    conn,
                    table="matches",
                    where="function_id = ? OR candidate_function_id = ?",
                    params=(function_id, function_id),
                )
                if log is not None
                else []
            )
            store.clear_matches_for(conn, function_id)
            if log is not None and matches:
                log.record(
                    effects.EFFECT_ROW_RESTORE,
                    f"cleared matches of function {function_id}",
                    journal.row_restore_descriptor("matches", matches),
                )
            result["applied"] += 1
            continue
        old_name = str(function["name"])
        new_name = _prefix_name(old_name, prefix, replace)
        if new_name == old_name:
            _skip(result, function_id, REASON_UNCHANGED)
            continue
        before = (
            journal.snapshot_rows(conn, table="functions", where="id = ?", params=(function_id,))
            if log is not None
            else []
        )
        known = frozenset(int(row["id"]) for row in store.list_name_history(conn, function_id))
        store.rename_function(
            conn,
            function_id,
            new_name=new_name,
            actor=BULK_RENAME_ACTOR,
            source=BULK_RENAME_SOURCE,
        )
        if log is not None:
            added = [
                int(row["id"])
                for row in store.list_name_history(conn, function_id)
                if int(row["id"]) not in known
            ]
            if added:
                log.record(
                    effects.EFFECT_ROW_DELETE,
                    f"rename history of function {function_id}",
                    journal.row_delete_descriptor("name_history", max(added)),
                )
            if before:
                log.record(
                    effects.EFFECT_ROW_RESTORE,
                    f"renamed function {function_id}",
                    journal.row_restore_descriptor("functions", before),
                )
        result["applied"] += 1
    return result

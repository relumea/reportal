"""The checks and journal helpers the HTTP, CLI and MCP surfaces share.

Every surface exposes the same operations over the same stored state, so the
checks it runs before a read or a write are the same check: whether a binary row
exists, whether its bytes are still on disk, whether a rebrew project context is
stored, whether the engine is available, and how a data-type or signature write
is journaled so it can be reverted.

A surface answers a failure in its own vocabulary -- the HTTP API with a status
and its ``{"error", "detail"}`` envelope, MCP with a :class:`ToolError` -- so a
helper that can fail takes a *fail* factory and raises what it returns instead
of building the exception itself.  The rule lives here once; each surface keeps
the codes and messages its clients already depend on.

Helpers whose surfaces genuinely differ, such as the request-body decoders that
answer ``invalid member`` here and ``invalid params`` there, stay with their
surface.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reportal import engines, families, journal, lineage, store, threat

# ``fail(status, error, detail)``: build the exception a surface raises.
Fail = Callable[[int, str, str], Exception]


def require_binary(conn: sqlite3.Connection, binary_id: int, *, fail: Fail) -> dict[str, Any]:
    """Return the binary row of *binary_id*, or raise through *fail*."""
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise fail(404, "binary not found", f"no binary with id {binary_id}")
    return binary


def binary_file(conn: sqlite3.Connection, binary_id: int, *, fail: Fail) -> Path:
    """Return the on-disk file of *binary_id*, or raise through *fail*.

    A 404 marks an unknown id; a 400 marks a row whose ``path`` is empty or no
    longer holds a file, since every engine call reads the bytes.
    """
    binary = require_binary(conn, binary_id, fail=fail)
    path = Path(str(binary["path"]))
    if not path.is_file():
        raise fail(
            400,
            "binary not on disk",
            f"binary {binary_id} has no file at {binary['path']!r}",
        )
    return path


def project_context(conn: sqlite3.Connection, binary_id: int, *, fail: Fail) -> str:
    """Return the rebrew project directory an engine call needs, or raise a 400."""
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise fail(
            400,
            "no-engine-context",
            f"binary {binary_id} has no rebrew project context",
        )
    return project_dir


def engine(*, fail: Fail) -> engines.RebrewEngine:
    """Return the process-wide engine, raising a 503 through *fail* when absent."""
    source = engines.get_engine()
    if not source.available():
        raise fail(503, "engine-unavailable", engines.ENGINE_UNAVAILABLE_HINT)
    return source


def family_detail(exc: families.FamilyError) -> tuple[str, str]:
    """The error code and detail a family validation failure reports."""
    invalid_name = isinstance(exc, families.InvalidFamilyNameError)
    return ("invalid name" if invalid_name else "duplicate family"), str(exc)


def classified(conn: sqlite3.Connection, binary_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    """Return *payload* plus the derived `software_type` and `threat_score`.

    Both are computed from the binary's stored evidence at request time, so
    every surface answers the same value for the same stored state, and the
    stored scan keeps exactly what its writer produced.
    """
    return {**payload, **threat.classify_binary(conn, binary_id)}


def store_lineage(conn: sqlite3.Connection, comparison: dict[str, Any]) -> dict[str, Any]:
    """Store one lineage comparison and return it, for a journaled scan run."""
    lineage.store_comparison(conn, comparison)
    return comparison


def journaled_signature_write(
    conn: sqlite3.Connection,
    log: journal.Journal,
    function_id: int,
    description: str,
    run: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run a signature write, journaling the row it replaced and the history it appended.

    A revert of the action puts the previous signature row back and deletes the
    history rows the write appended, the way ``journal.journaled_name_change``
    covers a rename.
    """
    before = journal.journaled_rows(
        conn,
        log,
        table="function_signatures",
        where="function_id = ?",
        params=(function_id,),
        description=description,
    )
    known = [{"id": int(row["id"])} for row in store.list_signature_history(conn, function_id)]
    result = run()
    journal.journaled_new_rows(
        conn,
        log,
        table="function_signatures",
        where="function_id = ?",
        params=(function_id,),
        before=before,
        key=("function_id",),
        description=f"signature of function {function_id}",
    )
    journal.journaled_new_rows(
        conn,
        log,
        table="signature_history",
        where="function_id = ?",
        params=(function_id,),
        before=known,
        key=("id",),
        description=f"signature history of function {function_id}",
    )
    return result


def journaled_data_type_write(
    conn: sqlite3.Connection,
    log: journal.Journal,
    data_type_id: int,
    description: str,
    run: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run a data-type write, journaling the row it replaced and the history it appended.

    A revert of the action puts the previous type row back (or removes the one
    a create added) and deletes the history rows the write appended, the way
    :func:`journaled_signature_write` covers a signature edit.
    """
    before = journal.journaled_rows(
        conn,
        log,
        table="data_types",
        where="id = ?",
        params=(data_type_id,),
        description=description,
    )
    known = [{"id": int(row["id"])} for row in store.list_data_type_history(conn, data_type_id)]
    result = run()
    journal.journaled_new_rows(
        conn,
        log,
        table="data_types",
        where="id = ?",
        params=(data_type_id,),
        before=before,
        key=("id",),
        description=f"data type {data_type_id}",
    )
    journal.journaled_new_rows(
        conn,
        log,
        table="data_type_history",
        where="data_type_id = ?",
        params=(data_type_id,),
        before=known,
        key=("id",),
        description=f"history of data type {data_type_id}",
    )
    return result

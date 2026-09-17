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
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from reportal import auth, data_types, engines, families, journal, lineage, store, threat

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


def journaled_row_write(
    conn: sqlite3.Connection,
    log: journal.Journal,
    row_id: int,
    description: str,
    run: Callable[[], dict[str, Any]],
    *,
    table: str,
    where: str,
    key: str,
    history_table: str,
    history_where: str,
    list_history: Callable[[sqlite3.Connection, int], Sequence[Mapping[str, Any]]],
    label: str,
) -> dict[str, Any]:
    """Run a row write, journaling the row it replaced and the history it appended.

    A revert of the action puts the previous row back and deletes the history
    rows the write appended, the way ``journal.journaled_name_change`` covers a
    rename.  *table*/*where* locate the row, *history_table*/*history_where*
    its history, and *list_history* reads the history rows known beforehand.
    """
    before = journal.journaled_rows(
        conn, log, table=table, where=where, params=(row_id,), description=description
    )
    known = [{"id": int(row["id"])} for row in list_history(conn, row_id)]
    result = run()
    journal.journaled_new_rows(
        conn,
        log,
        table=table,
        where=where,
        params=(row_id,),
        before=before,
        key=(key,),
        description=f"{label} {row_id}",
    )
    journal.journaled_new_rows(
        conn,
        log,
        table=history_table,
        where=history_where,
        params=(row_id,),
        before=known,
        key=("id",),
        description=f"{label} history of {row_id}",
    )
    return result


def journaled_signature_write(
    conn: sqlite3.Connection,
    log: journal.Journal,
    function_id: int,
    description: str,
    run: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run a signature write, journaling the row it replaced and the history it appended."""
    return journaled_row_write(
        conn,
        log,
        function_id,
        description,
        run,
        table="function_signatures",
        where="function_id = ?",
        key="function_id",
        history_table="signature_history",
        history_where="function_id = ?",
        list_history=store.list_signature_history,
        label="signature of function",
    )


def bulk_data_type_definitions(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    binary_id: int,
    definitions: Sequence[Any],
    create: bool = True,
) -> dict[str, Any]:
    """Create or update many data types from C definitions in one action.

    This is the shared bulk write path: the HTTP route, the CLI and the MCP tool
    all call it, so the same definitions produce the same report and the same
    revert.  An existing type goes through :func:`journaled_data_type_write`,
    which snapshots the row it replaces and the history it appends; a create has
    no id to snapshot yet, so it runs first and the row it added (with its
    history) is journaled as new, which is what makes a revert delete it.
    """
    applied: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for entry in definitions:
        definition = entry.get("definition") if isinstance(entry, dict) else entry
        hint = str(entry.get("name") or "") if isinstance(entry, dict) else ""
        name = _definition_name(definition)
        existing = None if not name else store.find_data_type_by_name(conn, binary_id, name)
        if existing is not None:

            def _update(definition: Any = definition) -> dict[str, Any]:
                outcome, detail = data_types.apply_definition(
                    conn,
                    binary_id=binary_id,
                    definition=definition,
                    create=True,
                )
                return {"outcome": outcome, "detail": detail}

            try:
                row = journaled_data_type_write(
                    conn,
                    log,
                    int(existing["id"]),
                    f"updated data type {existing['id']} in bulk",
                    _update,
                )
            except data_types.DataTypeError as exc:
                skipped.append({"name": hint or str(name), "reason": str(exc)})
                continue
            if row["outcome"] == "skipped":
                skipped.append({"name": hint or str(row["detail"]), "reason": str(row["detail"])})
                continue
            applied.append({"name": str(row["detail"]), "outcome": "updated"})
            continue
        try:
            outcome, detail = data_types.apply_definition(
                conn,
                binary_id=binary_id,
                definition=definition,
                create=create,
            )
        except data_types.DataTypeError as exc:
            skipped.append({"name": hint or str(name), "reason": str(exc)})
            continue
        if outcome == "skipped":
            skipped.append({"name": hint or str(detail), "reason": str(detail)})
            continue
        if outcome == "created":
            created_row = store.find_data_type_by_name(conn, binary_id, str(detail))
            if created_row is not None:
                created_id = int(created_row["id"])
                journal.journaled_new_rows(
                    conn,
                    log,
                    table="data_types",
                    where="id = ?",
                    params=(created_id,),
                    before=[],
                    key=("id",),
                    description=f"created data type {created_id} in bulk",
                )
                journal.journaled_new_rows(
                    conn,
                    log,
                    table="data_type_history",
                    where="data_type_id = ?",
                    params=(created_id,),
                    before=[],
                    key=("id",),
                    description=f"history of data type {created_id}",
                )
        applied.append({"name": str(detail), "outcome": outcome})
    return {
        "binary_id": binary_id,
        "created": sum(1 for entry in applied if entry["outcome"] == "created"),
        "updated": sum(1 for entry in applied if entry["outcome"] == "updated"),
        "applied": applied,
        "skipped": len(skipped),
        "skipped_types": skipped,
    }


def _definition_name(definition: Any) -> str:
    """The name one C declaration declares, or "" when it does not parse."""
    if not isinstance(definition, str) or not definition.strip():
        return ""
    try:
        parsed = data_types.parse_definition(definition)
    except data_types.DefinitionError:
        return ""
    name = parsed.get("name")
    return str(name) if name else ""


def journaled_signup(
    conn: sqlite3.Connection, log: journal.Journal, name: str
) -> tuple[dict[str, Any], str]:
    """Create one SaaS tenant and journal every row it inserted.

    Revert deletes the membership, team, organisation and user in that order.
    """
    payload, token = auth.signup_tenant(conn, name=name)
    user_id = int(payload["id"])
    organisation_id = int(payload["organisation"]["id"])
    team_id = int(payload["team"]["id"])
    journal.journaled_create(
        log,
        table=auth.TABLE,
        key=user_id,
        description=f"signed up user {payload['name']}",
    )
    journal.journaled_create(
        log,
        table=auth.ORG_TABLE,
        key=organisation_id,
        description=f"created organisation {payload['organisation']['name']}",
    )
    journal.journaled_create(
        log,
        table=auth.TEAM_TABLE,
        key=team_id,
        description=f"created team {payload['team']['name']}",
    )
    journal.journaled_create(
        log,
        table=auth.MEMBER_TABLE,
        key={"team_id": team_id, "user_id": user_id},
        description=f"user {user_id} owns team {team_id}",
    )
    return payload, token


def journaled_invite_join(
    conn: sqlite3.Connection,
    log: journal.Journal,
    code: str,
    user_id: int,
) -> dict[str, Any]:
    """Redeem one invite and journal the spent code plus any new membership.

    A revert restores the invite to unused, then (when the redeemer was new)
    removes the membership, so the code can be handed out again.
    """
    digest = auth.hash_token((code or "").strip())
    invite = conn.execute(
        f"SELECT id, team_id, used_by, created_at, expires_at"
        f" FROM {auth.INVITE_TABLE} WHERE code_hash = ?",
        (digest,),
    ).fetchone()
    if invite is None:
        raise auth.UnknownTeamError(auth.ERROR_INVITE_NOT_FOUND, "no invite carries that code")
    if invite["used_by"] is not None:
        raise auth.AuthError(auth.ERROR_INVITE_USED, "that invite was already used")
    if auth.invite_is_expired(invite):
        raise auth.AuthError(auth.ERROR_INVITE_EXPIRED, "that invite has expired")
    already = auth.member_role(conn, int(invite["team_id"]), user_id) is not None
    journal.journaled_rows(
        conn,
        log,
        table=auth.INVITE_TABLE,
        where="id = ?",
        params=(int(invite["id"]),),
        description=f"spent invite {invite['id']}",
    )
    team = auth.redeem_invite(conn, code, user_id)
    if not already:
        journal.journaled_create(
            log,
            table=auth.MEMBER_TABLE,
            key={"team_id": int(team["id"]), "user_id": user_id},
            description=f"user {user_id} joined team {team['id']} by invite",
        )
    return team


def journaled_data_type_write(
    conn: sqlite3.Connection,
    log: journal.Journal,
    data_type_id: int,
    description: str,
    run: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run a data-type write, journaling the row it replaced and the history it appended.

    A revert of the action puts the previous type row back (or removes the one
    a create added) and deletes the history rows the write appended.
    """
    return journaled_row_write(
        conn,
        log,
        data_type_id,
        description,
        run,
        table="data_types",
        where="id = ?",
        key="id",
        history_table="data_type_history",
        history_where="data_type_id = ?",
        list_history=store.list_data_type_history,
        label="data type",
    )

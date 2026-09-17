"""SQLite CRUD for auto mode: runs, the task tree they decompose into, and attempts.

The tables themselves are declared in :mod:`reportal.store` (`_SCHEMA`), which
stays the single owner of the schema; this module holds only the typed readers
and writers the orchestrator and the API use, plus the status and kind
constants they share.  Rows are returned as plain dicts so the JSON API
serializes them without a mapping layer.

One run decomposes one binary into tasks: a ``root`` task whose children are
``batch`` tasks, each covering one worker-sized group of functions.  Every
attempt a batch makes is a row in ``auto_attempts``, written as it happens, so
a run is inspectable while it runs and after a crash.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from typing import Any

from reportal.store import _json_list, now

# Statuses an `auto_runs` row carries.  A run is created `running` and closed
# `done` when every batch was decided, `failed` when the run itself could not
# proceed (an unknown worker, a missing binary) or was recovered with nothing
# completed, `partial` when a recovered run had finished some batches, or
# `reverted` once its writes were undone.
AUTO_RUN_RUNNING = "running"
AUTO_RUN_DONE = "done"
AUTO_RUN_FAILED = "failed"
AUTO_RUN_PARTIAL = "partial"
AUTO_RUN_REVERTED = "reverted"

# Statuses an `auto_tasks` row carries.  `pending` is a task that was planned
# but never started (the run was capped or crashed), `running` is a batch a
# worker is on, and the terminal three mirror the batch verdict: `done` when a
# function was accepted, `failed` when every function failed, `skipped` when
# nothing was accepted and something was skipped or improved.
AUTO_TASK_PENDING = "pending"
AUTO_TASK_RUNNING = "running"
AUTO_TASK_DONE = "done"
AUTO_TASK_FAILED = "failed"
AUTO_TASK_SKIPPED = "skipped"

# Kinds an `auto_tasks` row carries.  A run has one `root` and one `batch` per
# group of functions; the root aggregates, the batches run workers.
AUTO_TASK_ROOT = "root"
AUTO_TASK_BATCH = "batch"

# Depth of the two levels the decomposition produces: the root at 0, its
# batches at 1.
AUTO_ROOT_DEPTH = 0
AUTO_BATCH_DEPTH = 1

# Statuses an auto-task write intent carries.  The orchestrator persists an
# intent `pending` before the write it describes and marks it `applied` once
# the write returned, so a `pending` intent is the record a recovery must treat
# as possibly applied.  Intents live in the task's ``result_json`` under
# :data:`INTENT_RESULT_KEY`: the row is already auto mode's per-task record and
# keyed by task id (queryable by task), and keeping them there leaves
# :mod:`reportal.store` the single owner of the schema with no migration.
INTENT_PENDING = "pending"
INTENT_APPLIED = "applied"

# Result key a task's intents are stored under, and the descriptor field a
# merged intent is stamped with so a plan reader can tell a confirmed write
# from a reserved one.
INTENT_RESULT_KEY = "pending_intents"
INTENT_FIELD = "intent"


def _json_object(raw: Any) -> dict[str, Any]:
    """Parse a JSON object column, returning {} when it is unusable."""
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _auto_attempt_row(row: sqlite3.Row) -> dict[str, Any]:
    """One ``auto_attempts`` row with its detail parsed from JSON."""
    return {
        "id": int(row["id"]),
        "task_id": int(row["task_id"]),
        "attempt": int(row["attempt"]),
        "worker": str(row["worker"]),
        "status": str(row["status"]),
        "detail": _json_object(row["detail_json"]),
        "created_at": str(row["created_at"]),
    }


def _auto_task_row(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """One ``auto_tasks`` row with its result and its attempts attached."""
    task_id = int(row["id"])
    return {
        "id": task_id,
        "run_id": int(row["run_id"]),
        "parent_id": int(row["parent_id"]) if row["parent_id"] is not None else None,
        "depth": int(row["depth"]),
        "kind": str(row["kind"]),
        "title": str(row["title"]),
        "function_id": int(row["function_id"]) if row["function_id"] is not None else None,
        "va": int(row["va"]) if row["va"] is not None else None,
        "status": str(row["status"]),
        "worker": str(row["worker"]),
        "attempts": int(row["attempts"]),
        "result": _json_object(row["result_json"]),
        "created_at": str(row["created_at"]),
        "finished_at": str(row["finished_at"]) if row["finished_at"] is not None else None,
        "attempt_log": list_auto_attempts(conn, task_id),
    }


def _auto_run_row(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """One ``auto_runs`` row with its config, stats, undo plan and task tree."""
    run_id = int(row["id"])
    return {
        "id": run_id,
        "binary_id": int(row["binary_id"]),
        "status": str(row["status"]),
        "config": _json_object(row["config_json"]),
        "stats": _json_object(row["stats_json"]),
        "effects": _json_list(row["effects_json"]),
        "created_at": str(row["created_at"]),
        "finished_at": str(row["finished_at"]) if row["finished_at"] is not None else None,
        "tasks": list_auto_tasks(conn, run_id),
    }


def create_auto_run(conn: sqlite3.Connection, *, binary_id: int, config: dict[str, Any]) -> int:
    """Create a ``running`` auto run for *binary_id*; returns its id."""
    cur = conn.execute(
        "INSERT INTO auto_runs (binary_id, status, config_json, created_at) VALUES (?, ?, ?, ?)",
        (binary_id, AUTO_RUN_RUNNING, json.dumps(config), now()),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def finish_auto_run(
    conn: sqlite3.Connection, run_id: int, *, status: str, stats: dict[str, Any]
) -> bool:
    """Close a run with its final *status* and the coverage numbers it measured."""
    cur = conn.execute(
        "UPDATE auto_runs SET status = ?, stats_json = ?, finished_at = ? WHERE id = ?",
        (status, json.dumps(stats), now(), run_id),
    )
    conn.commit()
    return cur.rowcount > 0


def set_auto_run_effects(
    conn: sqlite3.Connection, run_id: int, effects: Sequence[dict[str, Any]]
) -> bool:
    """Replace a run's undo plan with *effects*, which a revert replays.

    The plan is the run's own record of what it wrote, in the order it wrote
    it: :func:`reportal.auto_mode.revert_auto_run` replays it newest-first
    through the shared dispatcher.
    """
    cur = conn.execute(
        "UPDATE auto_runs SET effects_json = ? WHERE id = ?",
        (json.dumps(list(effects)), run_id),
    )
    conn.commit()
    return cur.rowcount > 0


def auto_run_effects(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """The undo plan a run currently holds, empty for an unknown run."""
    row = conn.execute("SELECT effects_json FROM auto_runs WHERE id = ?", (run_id,)).fetchone()
    return _json_list(row["effects_json"]) if row else []


def get_auto_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    """One run with its undo plan, tasks and their attempts, or None."""
    row = conn.execute("SELECT * FROM auto_runs WHERE id = ?", (run_id,)).fetchone()
    return _auto_run_row(conn, row) if row else None


def latest_auto_run(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Newest run of *binary_id* with its tasks and their attempts, or None."""
    row = conn.execute(
        "SELECT * FROM auto_runs WHERE binary_id = ? ORDER BY id DESC LIMIT 1",
        (binary_id,),
    ).fetchone()
    return _auto_run_row(conn, row) if row else None


def list_auto_runs(
    conn: sqlite3.Connection, *, binary_id: int | None = None
) -> list[dict[str, Any]]:
    """Runs without their task trees, newest first, optionally scoped to one binary."""
    sql = "SELECT * FROM auto_runs"
    params: list[Any] = []
    if binary_id is not None:
        sql += " WHERE binary_id = ?"
        params.append(binary_id)
    sql += " ORDER BY id DESC"
    return [
        {
            "id": int(row["id"]),
            "binary_id": int(row["binary_id"]),
            "status": str(row["status"]),
            "config": _json_object(row["config_json"]),
            "stats": _json_object(row["stats_json"]),
            "created_at": str(row["created_at"]),
            "finished_at": str(row["finished_at"]) if row["finished_at"] is not None else None,
        }
        for row in conn.execute(sql, params).fetchall()
    ]


def newest_auto_run_summary(
    conn: sqlite3.Connection, *, binary_id: int | None = None
) -> dict[str, Any] | None:
    """The newest auto run without its task tree, or None before the first one."""
    sql = "SELECT * FROM auto_runs"
    params: list[Any] = []
    if binary_id is not None:
        sql += " WHERE binary_id = ?"
        params.append(binary_id)
    sql += " ORDER BY id DESC LIMIT 1"
    row = conn.execute(sql, params).fetchone()
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "binary_id": int(row["binary_id"]),
        "status": str(row["status"]),
        "config": _json_object(row["config_json"]),
        "stats": _json_object(row["stats_json"]),
        "created_at": str(row["created_at"]),
        "finished_at": str(row["finished_at"]) if row["finished_at"] is not None else None,
    }


def delete_auto_run(conn: sqlite3.Connection, run_id: int) -> bool:
    """Delete a run and, by cascade, its tasks and attempts; False when unknown."""
    cur = conn.execute("DELETE FROM auto_runs WHERE id = ?", (run_id,))
    conn.commit()
    return cur.rowcount > 0


def create_auto_task(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    parent_id: int | None,
    depth: int,
    kind: str,
    title: str = "",
    worker: str = "",
    function_id: int | None = None,
    va: int | None = None,
) -> int:
    """Append one task of a run; returns its id."""
    cur = conn.execute(
        "INSERT INTO auto_tasks (run_id, parent_id, depth, kind, title, function_id, va,"
        " status, worker, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            parent_id,
            depth,
            kind,
            title,
            function_id,
            va,
            AUTO_TASK_PENDING,
            worker,
            now(),
        ),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def update_auto_task(
    conn: sqlite3.Connection,
    task_id: int,
    *,
    status: str | None = None,
    attempts: int | None = None,
    result: dict[str, Any] | None = None,
    finish: bool = False,
) -> bool:
    """Update a task's status, attempt count and result; False when unknown.

    ``finish`` also stamps ``finished_at``, which is how a terminal write from
    the orchestrator records when the batch stopped being live.
    """
    assignments: list[str] = []
    params: list[Any] = []
    if status is not None:
        assignments.append("status = ?")
        params.append(status)
    if attempts is not None:
        assignments.append("attempts = ?")
        params.append(attempts)
    if result is not None:
        assignments.append("result_json = ?")
        params.append(json.dumps(result))
    if finish:
        assignments.append("finished_at = ?")
        params.append(now())
    if not assignments:
        return False
    params.append(task_id)
    cur = conn.execute(f"UPDATE auto_tasks SET {', '.join(assignments)} WHERE id = ?", params)
    conn.commit()
    return cur.rowcount > 0


def record_auto_task_outcome(
    conn: sqlite3.Connection,
    task_id: int,
    *,
    run_id: int,
    status: str,
    result: dict[str, Any],
    effects: Sequence[dict[str, Any]],
    attempts: int | None = None,
) -> bool:
    """Close a task and replace its run's undo plan in one transaction.

    A hard kill between the task write and the plan write would leave writes the
    task recorded missing from the plan a revert replays, so both UPDATEs commit
    together.  *attempts* is left alone when None.
    """
    assignments = ["status = ?", "result_json = ?", "finished_at = ?"]
    params: list[Any] = [status, json.dumps(result), now()]
    if attempts is not None:
        assignments.insert(1, "attempts = ?")
        params.insert(1, attempts)
    params.append(task_id)
    cur = conn.execute(f"UPDATE auto_tasks SET {', '.join(assignments)} WHERE id = ?", params)
    conn.execute(
        "UPDATE auto_runs SET effects_json = ? WHERE id = ?",
        (json.dumps(list(effects)), run_id),
    )
    conn.commit()
    return cur.rowcount > 0


def add_auto_attempt(
    conn: sqlite3.Connection,
    *,
    task_id: int,
    worker: str,
    status: str,
    detail: dict[str, Any],
    attempt: int | None = None,
) -> int:
    """Append one attempt of a task; returns its id.

    Written as the attempt happens, so a run interrupted mid-batch still shows
    the attempts it made before it died.  ``attempt`` is a per-task sequence
    number (unique with ``task_id``): omit it to take the next free value, which
    is what a multi-function batch needs so two functions cannot both claim
    attempt 1 on the same task.
    """
    if attempt is None:
        row = conn.execute(
            "SELECT COALESCE(MAX(attempt), 0) + 1 AS n FROM auto_attempts WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        attempt = int(row["n"]) if row is not None else 1
    cur = conn.execute(
        "INSERT INTO auto_attempts (task_id, attempt, worker, status, detail_json, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (task_id, attempt, worker, status, json.dumps(detail), now()),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def list_auto_attempts(conn: sqlite3.Connection, task_id: int) -> list[dict[str, Any]]:
    """Attempts of a task in the order they were made."""
    cur = conn.execute("SELECT * FROM auto_attempts WHERE task_id = ? ORDER BY id", (task_id,))
    return [_auto_attempt_row(row) for row in cur.fetchall()]


def list_auto_tasks(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """Tasks of a run in creation order, each with its attempts attached."""
    cur = conn.execute("SELECT * FROM auto_tasks WHERE run_id = ? ORDER BY id", (run_id,))
    return [_auto_task_row(conn, row) for row in cur.fetchall()]


def auto_task_tree(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """The run's tasks nested under their parents, roots first.

    A task whose parent is not in the run (it was deleted) is reported at the
    top level rather than dropped, so the tree always shows every row.
    """
    tasks = list_auto_tasks(conn, run_id)
    by_id = {task["id"]: task for task in tasks}
    for task in tasks:
        task["children"] = []
    roots: list[dict[str, Any]] = []
    for task in tasks:
        parent = by_id.get(task["parent_id"]) if task["parent_id"] is not None else None
        if parent is None:
            roots.append(task)
        else:
            parent["children"].append(task)
    return roots


def attempt_count(conn: sqlite3.Connection, run_id: int) -> int:
    """Number of attempts recorded for a run."""
    row = conn.execute(
        "SELECT COUNT(*) FROM auto_attempts a JOIN auto_tasks t ON a.task_id = t.id"
        " WHERE t.run_id = ?",
        (run_id,),
    ).fetchone()
    return int(row[0]) if row else 0


def set_function_status(conn: sqlite3.Connection, function_id: int, status: str) -> bool:
    """Set one function's status; False when the id is unknown.

    Auto mode is the only writer that promotes a function's status from a
    worker's verified result; a revert restores the status this replaced.
    """
    cur = conn.execute("UPDATE functions SET status = ? WHERE id = ?", (status, function_id))
    conn.commit()
    return cur.rowcount > 0


def status_changes_for_task(task: dict[str, Any]) -> list[dict[str, Any]]:
    """The status promotions a task's result recorded, as it wrote them."""
    raw = task.get("result", {}).get("status_changes")
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def written_files_for_task(task: dict[str, Any]) -> Sequence[str]:
    """The source files a task's result recorded having written."""
    raw = task.get("result", {}).get("written_files")
    if not isinstance(raw, list):
        return ()
    return [str(entry) for entry in raw if isinstance(entry, str) and entry]


# Fields a descriptor carries about one write rather than about what the write
# is: a file descriptor's digest describes the bytes of that single write, so a
# reservation made before the write and the confirmation made after it are the
# same intent.  Identity ignores it, which is what keeps a plan from holding the
# same path twice (once reserved, once confirmed) and a revert from removing the
# file twice.  ``auto_mode._descriptor_identity`` applies the same rule.
_VOLATILE_DESCRIPTOR_FIELDS = ("sha256",)


def _intent_identity(descriptor: dict[str, Any]) -> str:
    """A stable identity for one intent descriptor, used to de-duplicate."""
    body = {
        key: value for key, value in descriptor.items() if key not in _VOLATILE_DESCRIPTOR_FIELDS
    }
    return json.dumps(body, sort_keys=True)


def task_intents(task: dict[str, Any]) -> list[dict[str, Any]]:
    """The write intents a task's result carries, pending and applied.

    An entry is ``{"descriptor": {...}, "status": "pending" | "applied"}``; a
    malformed entry is skipped rather than raising, since the column is read
    after a crash and must not strand a recovery.
    """
    raw = task.get("result", {}).get(INTENT_RESULT_KEY)
    if not isinstance(raw, list):
        return []
    intents: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        descriptor = entry.get("descriptor")
        status = entry.get("status")
        if isinstance(descriptor, dict) and status in (INTENT_PENDING, INTENT_APPLIED):
            intents.append({"descriptor": descriptor, "status": status})
    return intents


def _read_task_intents(
    conn: sqlite3.Connection, task_id: int
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """A task's result object and its intent list, or None for an unknown task."""
    row = conn.execute("SELECT result_json FROM auto_tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        return None
    result = _json_object(row["result_json"])
    raw = result.get(INTENT_RESULT_KEY)
    intents = [entry for entry in raw if isinstance(entry, dict)] if isinstance(raw, list) else []
    return result, intents


def _write_task_intents(
    conn: sqlite3.Connection, task_id: int, result: dict[str, Any], intents: list[dict[str, Any]]
) -> None:
    """Store a task's intent list back in its result object on this connection."""
    result[INTENT_RESULT_KEY] = intents
    conn.execute(
        "UPDATE auto_tasks SET result_json = ? WHERE id = ?",
        (json.dumps(result), task_id),
    )
    conn.commit()


def auto_task_intents(conn: sqlite3.Connection, task_id: int) -> list[dict[str, Any]]:
    """The raw intent entries a task currently carries, pending and applied."""
    state = _read_task_intents(conn, task_id)
    return state[1] if state else []


def reserve_auto_task_intents(
    conn: sqlite3.Connection, task_id: int, descriptors: Sequence[dict[str, Any]]
) -> int:
    """Persist *descriptors* as pending intents on a task before their write.

    Called immediately before the write the inverse describes, so a process
    killed between the reserve and the write leaves a record recovery can act
    on.  An intent already recorded keeps its status, so a retry that
    re-reserves an applied write does not weaken the fact.  Returns the number
    newly reserved; an unknown task reserves nothing.
    """
    state = _read_task_intents(conn, task_id)
    if state is None:
        return 0
    result, intents = state
    seen = {_intent_identity(entry.get("descriptor") or {}) for entry in intents}
    added = 0
    for descriptor in descriptors:
        identity = _intent_identity(descriptor)
        if identity in seen:
            continue
        seen.add(identity)
        intents.append({"descriptor": descriptor, "status": INTENT_PENDING})
        added += 1
    if added:
        _write_task_intents(conn, task_id, result, intents)
    return added


def confirm_auto_task_intents(
    conn: sqlite3.Connection, task_id: int, descriptors: Sequence[dict[str, Any]]
) -> int:
    """Mark the intents for *descriptors* applied after their write returned.

    A descriptor with no recorded intent is added applied, so the confirmation
    is authoritative when a worker wrote something the reservation did not
    predict.  Returns the number of intents whose status changed.
    """
    state = _read_task_intents(conn, task_id)
    if state is None:
        return 0
    result, intents = state
    by_identity = {_intent_identity(entry.get("descriptor") or {}): entry for entry in intents}
    changed = 0
    for descriptor in descriptors:
        identity = _intent_identity(descriptor)
        entry = by_identity.get(identity)
        if entry is None:
            entry = {"descriptor": descriptor, "status": INTENT_PENDING}
            intents.append(entry)
            by_identity[identity] = entry
        if entry.get("status") != INTENT_APPLIED:
            entry["status"] = INTENT_APPLIED
            changed += 1
    if changed:
        _write_task_intents(conn, task_id, result, intents)
    return changed

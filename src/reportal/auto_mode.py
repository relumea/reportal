"""Auto-mode orchestration: decompose a binary, fan out to workers, aggregate.

The shape is spydr's: one root task per binary, decomposed top-down into tasks
and, at the leaf, into work a worker can do; results flow bottom up, the parent
aggregates them, and the root reports the coverage delta.  What replaces
spydr's reviewer/aggregator agents is an objective acceptance rule: a function
is accepted only when its worker carries a verified matching status from the
engine (:func:`_accepted`).  The parent never judges, it only aggregates
verified results.

Here the decomposition is one level deep: the root task owns one ``batch`` task
per group of ``functions_per_task`` functions, and batches are handed to daemon
worker threads behind a bounded queue, so the fan-out never exceeds
``concurrency`` live workers.  Every task and every attempt is written to SQLite
as it happens, so ``GET /api/auto/runs/<id>`` shows a live run and a crash
leaves consistent rows.  A failed attempt that has another attempt left waits a
jittered exponential backoff (from :data:`RETRY_BASE_SECONDS` up to
:data:`RETRY_MAX_SECONDS`) before the next one, so a downed LLM endpoint or a
transient SQLite lock is not retried at full speed.

Planning and execution are separate calls (:func:`create_auto_run` then
:func:`execute_auto_run`) so the API can create the run row in the request
thread and run it in a background thread; each batch task stores the functions
it was planned for, so execution never depends on in-process state.

Acceptance writes are gated on ``execute``: a dry run records the run, its
tasks and its attempts but changes no function status and writes no file.  An
executing run reserves the inverse of each write before it happens (a file the
worker may write, a status the batch is about to promote) as a pending intent
on the task, confirms it applied once the write returned, and folds the task's
undo descriptors into the run's plan in the same commit as its result, so a
hard kill between batches loses nothing an earlier task folded and a kill
mid-write leaves the pending intent behind.  Closing the run consolidates the
plan from the task results without duplicating an entry an earlier task already
persisted, which is what :func:`revert_auto_run` replays newest-first through
the shared dispatcher (``reportal.effects``).  A run left ``running`` by a dead
process is closed by :func:`recover_auto_run`, which merges the writes its
unfinished tasks recorded and the intents they reserved, listing a still-pending
intent in ``uncertain_intents`` because it may or may not have been applied.  It
is the same mechanism a pipeline run reverts with.
"""

from __future__ import annotations

import contextlib
import json
import logging
import queue
import random
import sqlite3
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reportal import auto_store, auto_workers, effects, engines, llm, store
from reportal.auto_workers import (
    WORKER_FAILED,
    WORKER_IMPROVED,
    WORKER_MATCHED,
    WORKER_SKIPPED,
    WorkerContext,
    WorkerResult,
)

_log = logging.getLogger(__name__)

# Concurrency bounds: the default fan-out, and the floor/ceiling a caller may
# ask for.  A run never starts more worker threads than the ceiling.
DEFAULT_CONCURRENCY = 4
MIN_CONCURRENCY = 1
MAX_CONCURRENCY = 32

# Functions per leaf batch.
DEFAULT_FUNCTIONS_PER_TASK = 1
MIN_FUNCTIONS_PER_TASK = 1
MAX_FUNCTIONS_PER_TASK = 64

# Attempts per function before the batch gives up on it.
DEFAULT_MAX_ATTEMPTS = 2
MIN_MAX_ATTEMPTS = 1
MAX_MAX_ATTEMPTS = 10

# Total task rows one run may create (the root plus its batches), which caps
# how much work a single run can do.
DEFAULT_MAX_TASKS = 200
MIN_MAX_TASKS = 1
MAX_MAX_TASKS = 5000

# Wall-clock budget for one worker call.  A wedged worker is abandoned (its
# daemon thread is left behind) and the attempt is recorded as a timeout, so
# the run never hangs on it.
DEFAULT_TASK_TIMEOUT_SECONDS = 300.0
MIN_TASK_TIMEOUT_SECONDS = 1.0
MAX_TASK_TIMEOUT_SECONDS = 3600.0

# Pacing between the attempts of one function.  The delay is exponential from
# the base and capped at the maximum, with a jitter factor so workers that fail
# together (a downed LLM endpoint, a transient SQLite lock) do not retry in
# lockstep.  It applies only between attempts: never before the first and never
# after the last.
RETRY_BASE_SECONDS = 0.5
RETRY_MAX_SECONDS = 8.0
RETRY_JITTER_LOW = 0.8
RETRY_JITTER_HIGH = 1.25

# Jitter source and sleep indirection.  A test patches `_retry_jitter` to pin
# the schedule and `_sleep` to record it, so the suite asserts the delay
# sequence without waiting for it; production draws from `_RETRY_RNG` and
# calls `time.sleep`.
_RETRY_RNG = random.Random()
_sleep = time.sleep

# SQLite settings for the connections auto mode opens per worker.  Batches run
# concurrently and all of them write, so a writer waits for the lock rather
# than failing the batch, and WAL lets a reader (the polling API) proceed while
# a worker writes.
DB_BUSY_TIMEOUT_MS = store.BUSY_TIMEOUT_MS
DB_JOURNAL_MODE = "WAL"
# WAL's durability knob: a commit does not fsync the WAL on every write, only
# at a checkpoint.  A crash of this process still loses nothing; only a power
# loss can drop the last commits, which is the standard WAL tradeoff and what
# makes fanned-out per-attempt writes cheap.
DB_SYNCHRONOUS = "NORMAL"

# Whether a failed attempt's source file is kept.  False removes it, so a run
# that matched nothing leaves the project as it found it.
KEEP_FAILED_SOURCES = False

# Reason a timed-out attempt records, and the reason an attempt that raised
# inside the worker records.
REASON_TIMEOUT = "timeout"
REASON_INTERNAL_ERROR = "internal-error"
REASON_BUSY = "busy"

# Reason a task that a recovery found unfinished records.
REASON_INTERRUPTED = "interrupted"

# Live attempt threads, including ones abandoned after a timeout.  Without a
# ceiling a wedged worker would leave a daemon behind on every attempt and the
# process would grow one thread per call; the semaphore is released only when
# the attempt thread actually finishes, so a hung worker holds its slot.
MAX_LIVE_ATTEMPT_THREADS = MAX_CONCURRENCY * 2
_attempt_slots = threading.BoundedSemaphore(MAX_LIVE_ATTEMPT_THREADS)

# Result key a planned batch stores its function snapshots under.
PLANNED_FUNCTIONS = "functions"


@dataclass(frozen=True)
class AutoParams:
    """Validated inputs of one auto run."""

    worker: str
    execute: bool
    concurrency: int
    functions_per_task: int
    max_attempts: int
    max_tasks: int
    disabled: frozenset[str]
    task_timeout: float
    keep_failures: bool = KEEP_FAILED_SOURCES

    def as_config(self) -> dict[str, Any]:
        """The JSON object stored in the run's ``config_json``."""
        return {
            "worker": self.worker,
            "execute": self.execute,
            "concurrency": self.concurrency,
            "functions_per_task": self.functions_per_task,
            "max_attempts": self.max_attempts,
            "max_tasks": self.max_tasks,
            "disabled": sorted(self.disabled),
            "task_timeout": self.task_timeout,
            "keep_failures": self.keep_failures,
        }


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> int:
    """Return *value* when it is an int inside ``[minimum, maximum]``, else raise."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_timeout(value: float) -> float:
    """Return *value* as a task timeout inside its bounds, else raise."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("task_timeout must be a number")
    timeout = float(value)
    if timeout < MIN_TASK_TIMEOUT_SECONDS or timeout > MAX_TASK_TIMEOUT_SECONDS:
        raise ValueError(
            f"task_timeout must be between {MIN_TASK_TIMEOUT_SECONDS:g}"
            f" and {MAX_TASK_TIMEOUT_SECONDS:g} seconds"
        )
    return timeout


def build_params(
    *,
    worker: str = auto_workers.WORKER_OFFLINE,
    execute: bool = False,
    concurrency: int = DEFAULT_CONCURRENCY,
    functions_per_task: int = DEFAULT_FUNCTIONS_PER_TASK,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    max_tasks: int = DEFAULT_MAX_TASKS,
    disabled: Iterable[str] = (),
    task_timeout: float | None = None,
) -> AutoParams:
    """Validate one run's inputs; raises :class:`ValueError` naming the field.

    The worker name is resolved here, so an unknown worker fails before a run
    row exists.  *disabled* names workers a caller has switched off; asking a
    run to use one is an error rather than a silently ignored input.
    """
    if not isinstance(execute, bool):
        raise ValueError("execute must be a boolean")
    if auto_workers.get_worker(worker) is None:
        known = ", ".join(entry.name for entry in auto_workers.workers())
        raise ValueError(f"unknown worker {worker!r}; known workers: {known}")
    disabled_names = frozenset(str(name) for name in disabled)
    if worker in disabled_names:
        raise ValueError(f"worker {worker!r} is disabled")
    return AutoParams(
        worker=worker,
        execute=execute,
        concurrency=_bounded_int("concurrency", concurrency, MIN_CONCURRENCY, MAX_CONCURRENCY),
        functions_per_task=_bounded_int(
            "functions_per_task",
            functions_per_task,
            MIN_FUNCTIONS_PER_TASK,
            MAX_FUNCTIONS_PER_TASK,
        ),
        max_attempts=_bounded_int("max_attempts", max_attempts, MIN_MAX_ATTEMPTS, MAX_MAX_ATTEMPTS),
        max_tasks=_bounded_int("max_tasks", max_tasks, MIN_MAX_TASKS, MAX_MAX_TASKS),
        disabled=disabled_names,
        task_timeout=_bounded_timeout(
            DEFAULT_TASK_TIMEOUT_SECONDS if task_timeout is None else task_timeout
        ),
    )


# ── Selection and decomposition ────────────────────────────────────


def select_functions(
    conn: sqlite3.Connection, binary_id: int, *, limit: int | None = None
) -> list[dict[str, Any]]:
    """Functions of *binary_id* that still need work, smallest first then VA.

    A function already in a matching status is not work; everything else (a
    STUB, a NEAR_MATCHING, an empty status) is selected.
    """
    rows = [
        row
        for row in store.list_functions(conn, binary_id=binary_id)
        if str(row["status"]) not in store.MATCHED_STATUSES
    ]
    rows.sort(key=lambda row: (int(row["size"]), int(row["va"])))
    if limit is not None:
        return rows[:limit]
    return rows


def _batch_title(batch: Sequence[dict[str, Any]]) -> str:
    """A human label for one leaf batch."""
    if len(batch) == 1:
        row = batch[0]
        name = str(row["name"]).strip() or f"func_{int(row['va']):x}"
        return f"{name} @ {hex(int(row['va']))}"
    first = hex(int(batch[0]["va"]))
    last = hex(int(batch[-1]["va"]))
    return f"{len(batch)} functions {first}..{last}"


def _chunks(rows: Sequence[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    """Split *rows* into consecutive groups of at most *size*."""
    return [list(rows[index : index + size]) for index in range(0, len(rows), size)]


def _function_snapshot(row: dict[str, Any]) -> dict[str, Any]:
    """The planned-function record a batch task stores."""
    return {
        "id": int(row["id"]),
        "va": int(row["va"]),
        "name": str(row["name"]),
        "size": int(row["size"]),
        "status": str(row["status"]),
    }


def create_auto_run(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    params: AutoParams,
    functions: Sequence[dict[str, Any]],
) -> int:
    """Create a run row and its task tree without executing it; returns the run id.

    The root task is created first, then one batch task per group of
    ``functions_per_task`` functions, each carrying the function snapshots it
    was planned for.  ``max_tasks`` caps the rows created, with the root
    counting as one, so the functions past the cap are simply not planned.
    Raises :class:`KeyError` for an unknown binary.
    """
    if store.get_binary(conn, binary_id) is None:
        raise KeyError(f"no binary with id {binary_id}")
    run_id = auto_store.create_auto_run(conn, binary_id=binary_id, config=params.as_config())
    root_id = auto_store.create_auto_task(
        conn,
        run_id=run_id,
        parent_id=None,
        depth=auto_store.AUTO_ROOT_DEPTH,
        kind=auto_store.AUTO_TASK_ROOT,
        title=f"binary {binary_id}",
        worker=params.worker,
    )
    capacity = max(params.max_tasks - 1, 0)
    for batch in _chunks(functions, params.functions_per_task)[:capacity]:
        task_id = auto_store.create_auto_task(
            conn,
            run_id=run_id,
            parent_id=root_id,
            depth=auto_store.AUTO_BATCH_DEPTH,
            kind=auto_store.AUTO_TASK_BATCH,
            title=_batch_title(batch),
            worker=params.worker,
            function_id=int(batch[0]["id"]) if len(batch) == 1 else None,
            va=int(batch[0]["va"]) if len(batch) == 1 else None,
        )
        auto_store.update_auto_task(
            conn,
            task_id,
            result={PLANNED_FUNCTIONS: [_function_snapshot(row) for row in batch]},
        )
    return run_id


def planned_batches(
    conn: sqlite3.Connection, run_id: int
) -> list[tuple[int, list[dict[str, Any]]]]:
    """The run's not-yet-started batch tasks with the functions they were planned for."""
    batches: list[tuple[int, list[dict[str, Any]]]] = []
    for task in auto_store.list_auto_tasks(conn, run_id):
        if task["kind"] != auto_store.AUTO_TASK_BATCH:
            continue
        if task["status"] != auto_store.AUTO_TASK_PENDING:
            continue
        raw = task["result"].get(PLANNED_FUNCTIONS)
        planned = raw if isinstance(raw, list) else []
        batches.append((int(task["id"]), [entry for entry in planned if isinstance(entry, dict)]))
    return batches


# ── Acceptance ─────────────────────────────────────────────────────


def _accepted(result: WorkerResult) -> bool:
    """True when a worker's claim is a verified matching status from the engine.

    The worker owns the engine call; the orchestrator owns the acceptance rule,
    so a worker that returns ``matched`` without a verified matching status is
    downgraded rather than believed.
    """
    return (
        result.status == WORKER_MATCHED
        and result.verified
        and auto_workers.is_matching_status(result.status_after)
    )


def _effective_status(result: WorkerResult) -> str:
    """The outcome the run records for one function, after the acceptance rule.

    A ``matched`` claim the rule rejects becomes ``improved`` when the worker
    produced something and ``failed`` when it did not, so a run's counters
    never report unverified work as done.
    """
    if _accepted(result):
        return WORKER_MATCHED
    if result.status == WORKER_MATCHED:
        return WORKER_IMPROVED if result.artifacts else WORKER_FAILED
    return result.status


def _failed_attempt(ctx: WorkerContext, reason: str, detail: str = "") -> WorkerResult:
    """A failed-attempt result for the function the context carries."""
    return WorkerResult(
        status=WORKER_FAILED,
        function_id=int(ctx.function["id"]),
        status_before=str(ctx.function["status"]),
        detail={"reason": reason, "detail": detail} if detail else {"reason": reason},
    )


def _retry_jitter() -> float:
    """Return one jitter factor from the module RNG, for one retry delay."""
    return _RETRY_RNG.uniform(RETRY_JITTER_LOW, RETRY_JITTER_HIGH)


def _retry_delay(attempt: int) -> float:
    """Seconds to wait after *attempt* (1-based) before the next attempt.

    Exponential backoff with jitter: ``RETRY_BASE_SECONDS * 2 ** (attempt - 1)``
    capped at :data:`RETRY_MAX_SECONDS`, scaled by :func:`_retry_jitter` and
    clamped again so a jittered delay never exceeds the cap.  The caller applies
    it only between two attempts, so a run of one attempt never waits.
    """
    base = min(RETRY_BASE_SECONDS * float(2 ** (attempt - 1)), RETRY_MAX_SECONDS)
    return min(base * _retry_jitter(), RETRY_MAX_SECONDS)


def _call_with_timeout(
    worker: auto_workers.Worker, ctx: WorkerContext, timeout: float, db_path: Path
) -> WorkerResult:
    """Run one worker call under *timeout*; a stall is a failed attempt.

    The call runs in its own daemon thread, so a worker that never returns
    cannot pin the run: its thread is abandoned and the attempt records a
    timeout.  An exception the worker raises is a failed attempt with its
    message, never a crashed run.  Live attempt threads (including abandoned
    ones) are capped by :data:`MAX_LIVE_ATTEMPT_THREADS`; past the cap the
    attempt fails busy rather than spawning another thread.

    The attempt thread opens its own connection: a SQLite connection belongs to
    the thread that made it, so handing the worker the batch thread's one would
    fail the moment it touched the store.
    """
    if not _attempt_slots.acquire(blocking=False):
        return _failed_attempt(
            ctx,
            REASON_BUSY,
            f"at most {MAX_LIVE_ATTEMPT_THREADS} worker attempts may run at once",
        )
    box: dict[str, Any] = {}
    finished = threading.Event()

    def target() -> None:
        try:
            with contextlib.closing(_connect(db_path)) as attempt_conn:
                ctx.conn = attempt_conn
                box["result"] = worker.run(ctx)
        except BaseException as exc:  # a worker crash is a failed attempt, not a run crash
            box["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            finished.set()
            _attempt_slots.release()

    try:
        thread = threading.Thread(
            target=target, name=f"auto-attempt-{ctx.function['id']}", daemon=True
        )
        thread.start()
    except BaseException:
        _attempt_slots.release()
        raise
    if not finished.wait(timeout):
        return _failed_attempt(ctx, REASON_TIMEOUT)
    if "error" in box:
        return _failed_attempt(ctx, REASON_INTERNAL_ERROR, str(box["error"]))
    result = box.get("result")
    if not isinstance(result, WorkerResult):
        return _failed_attempt(ctx, REASON_INTERNAL_ERROR, "worker returned no result")
    return result


# ── Batch execution ────────────────────────────────────────────────


def _attempt_detail(result: WorkerResult) -> dict[str, Any]:
    """The compact attempt record persisted for one worker call."""
    return {
        "status_before": result.status_before,
        "status_after": result.status_after,
        "verified": result.verified,
        "written_files": list(result.written_files),
        **result.detail,
    }


def _reservable_file(path: str, owned: set[str]) -> bool:
    """True when the run may write *path*, so its inverse is safe to replay.

    A worker refuses to overwrite a file it does not own, so a path that exists
    and is not in *owned* is one the worker skips: reserving an inverse for it
    would let a revert remove a file the run never wrote.  The file-write
    handler does not verify ownership itself (it removes any file present and
    reports a missing one), so this filter is what keeps a pending intent
    honest.
    """
    return path in owned or not Path(path).exists()


def _planned_file_intents(
    worker: auto_workers.Worker, ctx: WorkerContext, owned: set[str]
) -> list[dict[str, Any]]:
    """The file-write intents to reserve before *worker* runs for *ctx*.

    A worker with no ``planned_paths`` declares none, and its writes are
    recorded from its result when it returns.  A predicted path the worker ends
    up not writing leaves a pending intent the task's result drops when it
    closes normally, or recovery reports uncertain if the process died first.
    """
    resolver = worker.planned_paths
    if resolver is None:
        return []
    intents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in resolver(ctx):
        path = str(raw)
        if not path or path in seen or not _reservable_file(path, owned):
            continue
        seen.add(path)
        intents.append({"kind": effects.EFFECT_FILE_WRITE, "path": path})
    return intents


def _run_function(
    conn: sqlite3.Connection,
    *,
    task_id: int,
    function: dict[str, Any],
    project_dir: str | None,
    params: AutoParams,
    worker: auto_workers.Worker,
    engine: Any,
    llm_client: llm.LlmClient | None,
    db_path: Path,
) -> dict[str, Any]:
    """Run one function through up to ``max_attempts`` worker calls.

    Returns the function's outcome record, which the batch result aggregates
    and a revert reads to restore the status the run replaced.  A retry is
    handed the previous attempt's detail, which is how an engine-backed worker
    feeds the last mismatch back into its prompt.

    Each attempt reserves the inverse of the file it may write before the call
    and confirms it once the worker returns, so a write survives a process
    killed mid-attempt as a pending intent recovery reports uncertain.
    """
    previous: dict[str, Any] | None = None
    outcome = WORKER_FAILED
    status_after = ""
    reason = ""
    attempts = 0
    written: list[str] = []
    status_changes: list[dict[str, Any]] = []
    for attempt in range(1, params.max_attempts + 1):
        ctx = WorkerContext(
            conn=conn,
            function=function,
            project_dir=project_dir,
            engine=engine,
            llm_client=llm_client,
            execute=params.execute,
            keep_failures=params.keep_failures,
            previous=previous,
        )
        owned = {
            str(path) for path in (previous or {}).get("written_files", []) if isinstance(path, str)
        }
        planned = _planned_file_intents(worker, ctx, owned)
        if planned:
            auto_store.reserve_auto_task_intents(conn, task_id, planned)
        result = _call_with_timeout(worker, ctx, params.task_timeout, db_path)
        attempts += 1
        if result.written_files:
            auto_store.confirm_auto_task_intents(
                conn,
                task_id,
                [
                    {"kind": effects.EFFECT_FILE_WRITE, "path": str(path)}
                    for path in result.written_files
                ],
            )
        detail = _attempt_detail(result)
        auto_store.add_auto_attempt(
            conn,
            task_id=task_id,
            attempt=attempt,
            worker=params.worker,
            status=result.status,
            detail=detail,
        )
        written.extend(result.written_files)
        status_changes.extend(
            change for change in result.status_changes if isinstance(change, dict)
        )
        outcome = _effective_status(result)
        status_after = result.status_after
        reason = str(result.detail.get("reason", ""))
        if outcome in (WORKER_MATCHED, WORKER_IMPROVED, WORKER_SKIPPED):
            break
        previous = detail
        if attempt < params.max_attempts:
            _sleep(_retry_delay(attempt))
    return {
        "function_id": int(function["id"]),
        "va": int(function["va"]),
        "name": str(function["name"]),
        "outcome": outcome,
        "status_before": str(function["status"]),
        "status_after": status_after if outcome == WORKER_MATCHED else "",
        "reason": reason,
        "attempts": attempts,
        "written_files": written,
        "status_changes": status_changes,
    }


def _batch_outcome(outcomes: Sequence[dict[str, Any]]) -> str:
    """The verdict of one batch: done on any acceptance, failed only if all failed."""
    matched = sum(1 for outcome in outcomes if outcome["outcome"] == WORKER_MATCHED)
    failed = sum(1 for outcome in outcomes if outcome["outcome"] == WORKER_FAILED)
    if matched:
        return auto_store.AUTO_TASK_DONE
    if outcomes and failed == len(outcomes):
        return auto_store.AUTO_TASK_FAILED
    return auto_store.AUTO_TASK_SKIPPED


def _run_batch(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    task_id: int,
    planned: Sequence[dict[str, Any]],
    binary: dict[str, Any],
    params: AutoParams,
    engine: Any,
    llm_client: llm.LlmClient | None,
    db_path: Path,
) -> None:
    """Run every function of one batch and close its task row."""
    worker = auto_workers.get_worker(params.worker)
    if worker is None:  # the run's params were validated; a missing worker is a store fault
        auto_store.update_auto_task(
            conn,
            task_id,
            status=auto_store.AUTO_TASK_FAILED,
            result={"error": f"worker {params.worker!r} is not registered"},
            finish=True,
        )
        return
    # Re-read the rows: a function may have changed (or gone) since planning.
    functions = [
        row
        for row in (store.get_function(conn, int(entry["id"])) for entry in planned)
        if row is not None
    ]
    project_dir = store.get_rebrew_context(conn, int(binary["id"]))
    # The planned function list stays in the task result until the batch
    # finishes, so a run interrupted mid-batch keeps the work it had planned.
    auto_store.update_auto_task(conn, task_id, status=auto_store.AUTO_TASK_RUNNING)
    outcomes = [
        _run_function(
            conn,
            task_id=task_id,
            function=function,
            project_dir=project_dir,
            params=params,
            worker=worker,
            engine=engine,
            llm_client=llm_client,
            db_path=db_path,
        )
        for function in functions
    ]
    if params.execute:
        for outcome in outcomes:
            if outcome["outcome"] == WORKER_MATCHED and outcome["status_after"]:
                descriptor = {
                    "kind": effects.EFFECT_STATUS_CHANGE,
                    "function_id": int(outcome["function_id"]),
                    "before": str(outcome["status_before"]),
                }
                auto_store.reserve_auto_task_intents(conn, task_id, [descriptor])
                auto_store.set_function_status(
                    conn, int(outcome["function_id"]), str(outcome["status_after"])
                )
                auto_store.confirm_auto_task_intents(conn, task_id, [descriptor])
    status = _batch_outcome(outcomes)
    result = {
        "outcomes": outcomes,
        "written_files": [path for outcome in outcomes for path in outcome["written_files"]],
        "status_changes": [change for outcome in outcomes for change in outcome["status_changes"]],
    }
    _record_task_outcome(
        conn,
        run_id=run_id,
        task_id=task_id,
        status=status,
        result=result,
        descriptors=_task_undo_descriptors({"result": result}, verified=True),
        attempts=sum(int(outcome["attempts"]) for outcome in outcomes),
    )


def _worker_loop(
    db_path: Path,
    pending: queue.Queue[tuple[int, list[dict[str, Any]]] | None],
    *,
    run_id: int,
    binary: dict[str, Any],
    params: AutoParams,
    engine: Any,
    llm_client: llm.LlmClient | None,
) -> None:
    """Drain the batch queue on this thread's own SQLite connection.

    One batch that raises must not stop the loop: the batch is closed as failed
    and the next one runs.  Closing it is itself best effort, since the write
    that failed may have been the one holding the lock.
    """
    with contextlib.closing(_connect(db_path)) as conn:
        while True:
            item = pending.get()
            if item is None:
                return
            task_id, planned = item
            try:
                _run_batch(
                    conn,
                    run_id=run_id,
                    task_id=task_id,
                    planned=planned,
                    binary=binary,
                    params=params,
                    engine=engine,
                    llm_client=llm_client,
                    db_path=db_path,
                )
            except Exception as exc:  # one bad batch must not strand the run
                _log.exception("auto batch %s crashed", task_id)
                try:
                    # The batch may have reserved or confirmed intents before
                    # it crashed.  Carry them into the failed result so
                    # recovery can still fold them into the run's plan.
                    result: dict[str, Any] = {"error": f"{REASON_INTERNAL_ERROR}: {exc}"}
                    intents = auto_store.auto_task_intents(conn, task_id)
                    if intents:
                        result[auto_store.INTENT_RESULT_KEY] = intents
                    auto_store.update_auto_task(
                        conn,
                        task_id,
                        status=auto_store.AUTO_TASK_FAILED,
                        result=result,
                        finish=True,
                    )
                except sqlite3.Error:
                    _log.exception("auto batch %s could not be closed", task_id)


def _database_path(conn: sqlite3.Connection) -> Path | None:
    """The file a connection points at, or None for a memory database."""
    for row in conn.execute("PRAGMA database_list").fetchall():
        if str(row["name"]) == "main" and str(row["file"]):
            return Path(str(row["file"]))
    return None


def _configure(conn: sqlite3.Connection) -> None:
    """Apply the auto-mode SQLite settings to the coordinator connection.

    The journal mode is a database-level setting, so it is switched once here,
    before any worker connection opens: doing it per connection races, since
    switching modes needs a brief exclusive lock.
    """
    conn.execute(f"PRAGMA busy_timeout = {DB_BUSY_TIMEOUT_MS}")
    try:
        conn.execute(f"PRAGMA journal_mode = {DB_JOURNAL_MODE}")
    except sqlite3.OperationalError:
        # Another connection holds the database; the run still works in the
        # default journal mode, just with more write contention.
        _log.warning("auto mode could not switch the database to %s", DB_JOURNAL_MODE)
    conn.execute(f"PRAGMA synchronous = {DB_SYNCHRONOUS}")


def _connect(db_path: Path) -> sqlite3.Connection:
    """Open one auto-mode worker connection on *db_path*.

    Concurrent batches all write, so the connection waits for the write lock
    (``busy_timeout``) instead of failing the batch.  The journal mode is not
    touched here: :func:`_configure` switched it once on the coordinator.
    """
    conn = store.connect(db_path)
    conn.execute(f"PRAGMA busy_timeout = {DB_BUSY_TIMEOUT_MS}")
    conn.execute(f"PRAGMA synchronous = {DB_SYNCHRONOUS}")
    return conn


def _execute_batches(
    *,
    db_path: Path,
    run_id: int,
    binary: dict[str, Any],
    params: AutoParams,
    engine: Any,
    llm_client: llm.LlmClient | None,
    batches: Sequence[tuple[int, list[dict[str, Any]]]],
) -> None:
    """Fan the batches out over bounded daemon worker threads."""
    if not batches:
        return
    count = min(params.concurrency, len(batches))
    pending: queue.Queue[tuple[int, list[dict[str, Any]]] | None] = queue.Queue()
    for item in batches:
        pending.put(item)
    threads = [
        threading.Thread(
            target=_worker_loop,
            args=(db_path, pending),
            kwargs={
                "run_id": run_id,
                "binary": binary,
                "params": params,
                "engine": engine,
                "llm_client": llm_client,
            },
            name=f"auto-worker-{index}",
            daemon=True,
        )
        for index in range(count)
    ]
    for thread in threads:
        thread.start()
    for _ in threads:
        pending.put(None)
    for thread in threads:
        thread.join()


# ── Aggregation ────────────────────────────────────────────────────


def _coverage(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Matched-versus-total function coverage of one binary."""
    rows = store.list_functions(conn, binary_id=binary_id)
    total = len(rows)
    matched = sum(1 for row in rows if str(row["status"]) in store.MATCHED_STATUSES)
    return {
        "matched": matched,
        "total": total,
        "ratio": round(matched / total, 4) if total else 0.0,
    }


def _summarize(tasks: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Count the final outcome of every function a run worked on."""
    counters = {WORKER_MATCHED: 0, WORKER_IMPROVED: 0, WORKER_FAILED: 0, WORKER_SKIPPED: 0}
    for task in tasks:
        outcomes = task.get("result", {}).get("outcomes")
        if not isinstance(outcomes, list):
            continue
        for outcome in outcomes:
            if isinstance(outcome, dict) and outcome.get("outcome") in counters:
                counters[str(outcome["outcome"])] += 1
    return counters


def _close_root(conn: sqlite3.Connection, *, root_id: int, tasks: Sequence[dict[str, Any]]) -> str:
    """Close the root task with the aggregate of its children; returns its status.

    A child that never reached a terminal status means the run did not finish
    its plan (a worker thread died, the process stopped): the root is `failed`
    rather than `done`, so an incomplete run never reads as a complete one.
    """
    children = [task for task in tasks if task["parent_id"] == root_id]
    counters = _summarize(tasks)
    terminal = (
        auto_store.AUTO_TASK_DONE,
        auto_store.AUTO_TASK_FAILED,
        auto_store.AUTO_TASK_SKIPPED,
    )
    unfinished = [task for task in children if task["status"] not in terminal]
    if not children:
        status = auto_store.AUTO_TASK_SKIPPED
    elif unfinished:
        status = auto_store.AUTO_TASK_FAILED
    elif any(task["status"] == auto_store.AUTO_TASK_DONE for task in children):
        status = auto_store.AUTO_TASK_DONE
    elif all(task["status"] == auto_store.AUTO_TASK_FAILED for task in children):
        status = auto_store.AUTO_TASK_FAILED
    else:
        status = auto_store.AUTO_TASK_SKIPPED
    auto_store.update_auto_task(
        conn,
        root_id,
        status=status,
        result={**counters, "children": len(children), "unfinished": len(unfinished)},
        finish=True,
    )
    return status


# ── Undo plan ──────────────────────────────────────────────────────


def _task_undo_descriptors(task: dict[str, Any], *, verified: bool = False) -> list[dict[str, Any]]:
    """The undo descriptors of the writes one task recorded, in write order.

    A file the task wrote becomes a `file-write` descriptor and a status it
    replaced becomes a `status-change` one, which are exactly the inverses the
    shared dispatcher knows how to apply.  A task that never recorded a result
    (a process killed mid-batch) contributes its persisted intents instead,
    each stamped with :data:`auto_store.INTENT_FIELD` so a plan reader can tell
    a confirmed write from a reserved one.  The same builders serve the per-task
    persistence and the recovery of a task that died before closing.

    *verified* says the caller watched the write happen in this process, so each
    file descriptor can carry the digest of what was written and the inverse can
    refuse a path another writer has replaced since.  Recovery of a dead task
    passes False: it reads the paths the task recorded, not the bytes it wrote,
    so a digest taken now would claim a file the run may never have written and
    the descriptor claims none instead.
    """
    descriptors: list[dict[str, Any]] = []
    for raw in auto_store.written_files_for_task(task):
        if verified:
            descriptors.append(effects.file_write_descriptor(raw))
        else:
            descriptors.append({"kind": effects.EFFECT_FILE_WRITE, "path": raw})
    for change in auto_store.status_changes_for_task(task):
        function_id = int(change.get("function_id", 0))
        before = str(change.get("before", ""))
        if not function_id or not before:
            continue
        descriptors.append(
            {
                "kind": effects.EFFECT_STATUS_CHANGE,
                "function_id": function_id,
                "before": before,
            }
        )
    for intent in auto_store.task_intents(task):
        descriptor = dict(intent["descriptor"])
        descriptor[auto_store.INTENT_FIELD] = intent["status"]
        descriptors.append(descriptor)
    return descriptors


def _undo_descriptors(tasks: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The undo descriptors of every write *tasks* recorded, in write order."""
    return [descriptor for task in tasks for descriptor in _task_undo_descriptors(task)]


def _descriptor_identity(descriptor: dict[str, Any]) -> str:
    """A stable identity for one undo descriptor, used to de-duplicate a merge.

    The rule is :func:`auto_store._intent_identity`'s, digest fields excluded:
    a task's reservation and its confirmation describe one write, so they must
    merge to one plan entry rather than two removals of the same path.
    """
    body = {
        key: value
        for key, value in descriptor.items()
        if key not in auto_store._VOLATILE_DESCRIPTOR_FIELDS
    }
    return json.dumps(body, sort_keys=True)


def _merge_descriptors(
    existing: Sequence[dict[str, Any]], additions: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Merge *additions* into *existing*, keeping write order and dropping duplicates.

    A task's descriptors are persisted when it completes and re-derived when the
    run closes, so the same descriptor reaches the plan twice.  Identity is the
    descriptor's canonical JSON, which keeps the plan a set in write order
    instead of a log with repeats.
    """
    merged = list(existing)
    seen = {_descriptor_identity(descriptor) for descriptor in merged}
    for descriptor in additions:
        identity = _descriptor_identity(descriptor)
        if identity in seen:
            continue
        seen.add(identity)
        merged.append(descriptor)
    return merged


def _record_task_outcome(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    task_id: int,
    status: str,
    result: dict[str, Any],
    descriptors: Sequence[dict[str, Any]],
    attempts: int | None = None,
) -> int:
    """Close a task and fold its undo descriptors into the run's plan atomically.

    The task row and the plan land in one commit, so a process killed between
    the two cannot leave a write recorded on the task but missing from the plan
    a revert reads.  The read-merge-write runs under ``BEGIN IMMEDIATE`` because
    batches persist concurrently on their own connections: without the write
    lock taken before the read, two batches could each merge into the plan they
    read and the later write would drop the earlier one's descriptors.  Returns
    the number of descriptors the merge added.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        existing = auto_store.auto_run_effects(conn, run_id)
        plan = _merge_descriptors(existing, descriptors)
        auto_store.record_auto_task_outcome(
            conn,
            task_id,
            run_id=run_id,
            status=status,
            result=result,
            effects=plan,
            attempts=attempts,
        )
    except BaseException:
        conn.rollback()
        raise
    return len(plan) - len(existing)


def persist_undo_plan(conn: sqlite3.Connection, run_id: int) -> None:
    """Consolidate a run's task-recorded writes into its stored undo plan.

    Called when a run closes, and again when one crashes; by then each completed
    task already persisted its own descriptors, so the consolidation only fills
    in what a task closed before this call could not (and never duplicates an
    entry the run already holds).
    """
    existing = auto_store.auto_run_effects(conn, run_id)
    descriptors = _undo_descriptors(auto_store.list_auto_tasks(conn, run_id))
    auto_store.set_auto_run_effects(conn, run_id, _merge_descriptors(existing, descriptors))


def _recovered_run_status(batches: Sequence[dict[str, Any]]) -> str:
    """The status a recovered run closes with, from its batches' recorded outcomes."""
    completed = [task for task in batches if task["status"] == auto_store.AUTO_TASK_DONE]
    if batches and len(completed) == len(batches):
        return auto_store.AUTO_RUN_DONE
    if completed:
        return auto_store.AUTO_RUN_PARTIAL
    return auto_store.AUTO_RUN_FAILED


def _pending_intent_descriptors(
    descriptors: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """The descriptors of *descriptors* whose write is only reserved, not confirmed."""
    return [
        descriptor
        for descriptor in descriptors
        if descriptor.get(auto_store.INTENT_FIELD) == auto_store.INTENT_PENDING
    ]


def _unique_descriptors(descriptors: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """*descriptors* with duplicate identities removed, order preserved."""
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for descriptor in descriptors:
        identity = _descriptor_identity(descriptor)
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(descriptor)
    return unique


def _merge_task_descriptors(
    conn: sqlite3.Connection, run_id: int, descriptors: Sequence[dict[str, Any]]
) -> int:
    """Merge *descriptors* into a run's plan without touching a task row.

    Used for a batch a crash closed as failed while it still carried the
    intents it had reserved: recovery does not revisit a terminal task, so its
    intents are folded into the plan here.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        existing = auto_store.auto_run_effects(conn, run_id)
        plan = _merge_descriptors(existing, descriptors)
        auto_store.set_auto_run_effects(conn, run_id, plan)
    except BaseException:
        conn.rollback()
        raise
    return len(plan) - len(existing)


def recover_auto_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """Recover a stale auto run: fold its unfinished tasks' writes into its plan.

    There is no in-process registry of live runs, so any run still `running` is
    treated as stale: its worker threads died with a previous process.  Every
    batch task still `running` or `pending` is marked `failed` with reason
    `interrupted`, and the files and status changes it had recorded, plus the
    write intents it reserved before them, are merged into the run's undo plan
    so a revert can still take them back.  An intent still `pending` is reported
    as possibly applied: it is merged, marked with
    :data:`auto_store.INTENT_PENDING`, and listed in ``uncertain_intents``,
    because the process that would have confirmed the write died before it did.
    The run closes `done` when every batch had completed, `partial` when some
    had, and `failed` when none had.  A run already closed is left untouched.
    Raises :class:`KeyError` for an unknown run.
    """
    run = auto_store.get_auto_run(conn, run_id)
    if run is None:
        raise KeyError(f"no auto run with id {run_id}")
    if run["status"] != auto_store.AUTO_RUN_RUNNING:
        return {
            "run_id": run_id,
            "recovered_tasks": 0,
            "added_descriptors": 0,
            "uncertain_intents": [],
            "status": str(run["status"]),
        }
    stale = [
        task
        for task in auto_store.list_auto_tasks(conn, run_id)
        if task["kind"] == auto_store.AUTO_TASK_BATCH
        and task["status"] in (auto_store.AUTO_TASK_RUNNING, auto_store.AUTO_TASK_PENDING)
    ]
    added = 0
    uncertain: list[dict[str, Any]] = []
    for task in stale:
        descriptors = _task_undo_descriptors(task)
        uncertain.extend(_pending_intent_descriptors(descriptors))
        added += _record_task_outcome(
            conn,
            run_id=run_id,
            task_id=int(task["id"]),
            status=auto_store.AUTO_TASK_FAILED,
            result={"reason": REASON_INTERRUPTED},
            descriptors=descriptors,
        )
    stale_ids = {int(task["id"]) for task in stale}
    for task in auto_store.list_auto_tasks(conn, run_id):
        if task["kind"] != auto_store.AUTO_TASK_BATCH or int(task["id"]) in stale_ids:
            continue
        if not auto_store.task_intents(task):
            continue
        descriptors = _task_undo_descriptors(task)
        uncertain.extend(_pending_intent_descriptors(descriptors))
        added += _merge_task_descriptors(conn, run_id, descriptors)
    tasks = auto_store.list_auto_tasks(conn, run_id)
    root_id = next(
        (int(task["id"]) for task in tasks if task["kind"] == auto_store.AUTO_TASK_ROOT), 0
    )
    if root_id:
        _close_root(conn, root_id=root_id, tasks=tasks)
    batches = [task for task in tasks if task["kind"] == auto_store.AUTO_TASK_BATCH]
    status = _recovered_run_status(batches)
    auto_store.finish_auto_run(
        conn,
        run_id,
        status=status,
        stats={**_summarize(tasks), "recovered": len(stale)},
    )
    return {
        "run_id": run_id,
        "recovered_tasks": len(stale),
        "added_descriptors": added,
        "uncertain_intents": _unique_descriptors(uncertain),
        "status": status,
    }


# ── Entry points ───────────────────────────────────────────────────


def execute_auto_run(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    params: AutoParams,
    engine: engines.RebrewEngine | None = None,
    llm_client: llm.LlmClient | None = None,
) -> dict[str, Any]:
    """Run the planned batches of a stored run and close its root and run rows.

    Batches run on daemon worker threads, each with its own SQLite connection,
    so the run is persisted as it happens and never exceeds ``concurrency`` live
    workers.  Raises :class:`KeyError` for an unknown run and :class:`ValueError`
    when the database has no file behind it (the workers need their own
    connection to it).
    """
    run = auto_store.get_auto_run(conn, run_id)
    if run is None:
        raise KeyError(f"no auto run with id {run_id}")
    binary_id = int(run["binary_id"])
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")
    before = _coverage(conn, binary_id)
    db_path = _database_path(conn)
    if db_path is None:
        raise ValueError("auto mode needs a file-backed reportal database")
    _configure(conn)
    batches = planned_batches(conn, run_id)
    active_engine = engine if engine is not None else engines.get_engine()
    client = llm_client if llm_client is not None else llm.get_client()
    _execute_batches(
        db_path=db_path,
        run_id=run_id,
        binary=binary,
        params=params,
        engine=active_engine,
        llm_client=client,
        batches=batches,
    )
    tasks = auto_store.list_auto_tasks(conn, run_id)
    root_id = next(
        (int(task["id"]) for task in tasks if task["kind"] == auto_store.AUTO_TASK_ROOT), 0
    )
    persist_undo_plan(conn, run_id)
    root_status = _close_root(conn, root_id=root_id, tasks=tasks)
    counters = _summarize(tasks)
    coverage_after = _coverage(conn, binary_id)
    if not params.execute:
        # A dry run changed no function row, so the delta it reports is the
        # projection its accepted claims would produce.
        coverage_after = {
            **before,
            "matched": before["matched"] + counters[WORKER_MATCHED],
            "ratio": (
                round((before["matched"] + counters[WORKER_MATCHED]) / before["total"], 4)
                if before["total"]
                else 0.0
            ),
        }
    status = auto_store.AUTO_RUN_DONE
    if root_status == auto_store.AUTO_TASK_FAILED:
        status = auto_store.AUTO_RUN_FAILED
    auto_store.finish_auto_run(
        conn,
        run_id,
        status=status,
        stats={**counters, "coverage_before": before, "coverage_after": coverage_after},
    )
    return run_summary(conn, run_id)


def run_summary(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """The stored run as the API, CLI and SPA return it, with its task tree."""
    run = auto_store.get_auto_run(conn, run_id)
    if run is None:
        raise KeyError(f"no auto run with id {run_id}")
    stats = run["stats"]
    return {
        "run_id": int(run["id"]),
        "binary_id": int(run["binary_id"]),
        "status": str(run["status"]),
        "worker": str(run["config"].get("worker", "")),
        "config": run["config"],
        "created_at": run["created_at"],
        "finished_at": run["finished_at"],
        "tasks": len(run["tasks"]),
        "attempts": auto_store.attempt_count(conn, run_id),
        "matched": int(stats.get("matched", 0)),
        "improved": int(stats.get("improved", 0)),
        "failed": int(stats.get("failed", 0)),
        "skipped": int(stats.get("skipped", 0)),
        "coverage_before": stats.get("coverage_before", {}),
        "coverage_after": stats.get("coverage_after", {}),
        "tree": auto_store.auto_task_tree(conn, run_id),
    }


def run_auto(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    worker: str = auto_workers.WORKER_OFFLINE,
    execute: bool = False,
    concurrency: int = DEFAULT_CONCURRENCY,
    functions_per_task: int = DEFAULT_FUNCTIONS_PER_TASK,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    max_tasks: int = DEFAULT_MAX_TASKS,
    disabled: Iterable[str] = frozenset(),
    engine: engines.RebrewEngine | None = None,
    llm_client: llm.LlmClient | None = None,
    task_timeout: float | None = None,
) -> dict[str, Any]:
    """Decompose one binary's outstanding functions, work them, report the delta.

    Selects the binary's functions that are not already matched (smallest
    first), plans a root task plus one batch per group, fans the batches out to
    the named worker over bounded threads, aggregates each batch's verified
    results, and closes the run with the coverage it measured.  ``execute``
    gates every write into the rebrew project; without it nothing is compiled
    and no function status changes.  Raises :class:`ValueError` for a bad input
    and :class:`KeyError` for an unknown binary.
    """
    params = build_params(
        worker=worker,
        execute=execute,
        concurrency=concurrency,
        functions_per_task=functions_per_task,
        max_attempts=max_attempts,
        max_tasks=max_tasks,
        disabled=disabled,
        task_timeout=task_timeout,
    )
    if store.get_binary(conn, binary_id) is None:
        raise KeyError(f"no binary with id {binary_id}")
    functions = select_functions(conn, binary_id)
    run_id = create_auto_run(conn, binary_id=binary_id, params=params, functions=functions)
    try:
        return execute_auto_run(
            conn, run_id=run_id, params=params, engine=engine, llm_client=llm_client
        )
    except Exception:
        # Persist whatever the failed run managed to write before closing it,
        # so a revert can still take those writes back.
        persist_undo_plan(conn, run_id)
        auto_store.finish_auto_run(
            conn,
            run_id,
            status=auto_store.AUTO_RUN_FAILED,
            stats={"coverage_before": _coverage(conn, binary_id)},
        )
        raise


def revert_auto_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """Remove what a run wrote and delete its rows; returns what it undid.

    The run's stored undo plan is replayed newest-first through the shared
    dispatcher, so a rewrite or status change a run made is taken back by the
    same code a pipeline revert uses.  A failed or reverted run removes exactly
    its own writes and nothing else.  Function statuses the run promoted are
    restored to the value it replaced, so a revert puts coverage back where it
    started.  Raises :class:`KeyError` for an unknown run.
    """
    run = auto_store.get_auto_run(conn, run_id)
    if run is None:
        raise KeyError(f"no auto run with id {run_id}")
    undone = effects.apply_undo_plan(conn, run["effects"])
    removed = [entry for entry in undone if "path" in entry]
    restored = [entry for entry in undone if "function_id" in entry]
    auto_store.delete_auto_run(conn, run_id)
    return {
        "run_id": run_id,
        "status": auto_store.AUTO_RUN_REVERTED,
        "removed": removed,
        "restored": restored,
    }

"""Worker registry for auto mode: what turns one function into a result.

An auto run decomposes a binary into batches of functions and hands each batch
to a worker.  A worker is a name, a description and a ``run(context)`` call that
inspects one function and returns a :class:`WorkerResult`.  Built-in workers
live in this module, :mod:`reportal.auto_llm_worker` and
:mod:`reportal.auto_goal_worker`; a third party
declares an entry point in the :data:`WORKER_ENTRY_POINT_GROUP` group whose
value is ``module:attr`` naming a :class:`Worker` or a zero-argument factory
returning one.  Discovery mirrors ``reportal.components``: a broken registration
is skipped with a warning, and a duplicate name raises :class:`RegistryError`.

A result carries its own verdict, never a free-form verdict the orchestrator
re-derives: ``matched`` means the worker has an engine-verified matching status
for the function, ``improved`` means it produced something usable without a
match, ``failed`` means the attempt did not work, ``skipped`` means the worker
declined with a reason.  The orchestrator only accepts a ``matched`` claim whose
``form`` is a matching status and whose ``verified`` flag is set, so a worker
that guesses cannot mark work done.
"""

from __future__ import annotations

import importlib
import re
import sqlite3
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from reportal import llm, plugins, store
from reportal.plugins import RegistryError as RegistryError

# Entry-point group third-party workers register in.
WORKER_ENTRY_POINT_GROUP = "reportal.auto_workers"

# Origin label a built-in registration reports.
BUILTIN_ORIGIN = plugins.BUILTIN_ORIGIN

# Verdicts a `WorkerResult` carries.  They are also the counters the run
# summary reports.
WORKER_MATCHED = "matched"
WORKER_IMPROVED = "improved"
WORKER_FAILED = "failed"
WORKER_SKIPPED = "skipped"

# Name of the deterministic offline worker.
WORKER_OFFLINE = "offline"

# Name of the engine-verified LLM worker.
WORKER_LLM_C_SOURCE = "llm_c_source"

# Name of the goal-directed LLM worker.
WORKER_LLM_GOAL = "llm_goal"

# A function whose name is an address placeholder was never identified, so the
# offline worker treats it as unmarked.  Everything else is "marked" work.
_ADDRESS_NAME = re.compile(r"^(?:sub|func|fcn|loc|unk)_[0-9a-fA-F]+$")

# Status the offline worker claims for a marked function.  It stands in for the
# engine verification a real worker performs; the offline worker is dry-run
# only, so the claim never reaches the store's function rows.
OFFLINE_CLAIMED_STATUS = "EXACT"

# Reason the offline worker reports when a run asks it to execute.
REASON_OFFLINE_NOT_EXECUTABLE = "offline-worker-is-dry-run-only"

# Reason a worker reports when the function carries no usable symbol name.
REASON_NO_SYMBOL = "no-symbol"

# Reason a worker reports when the configured model endpoint is absent.
REASON_LLM_UNAVAILABLE = "llm-unavailable"

# Reason a worker reports when no engine is configured.
REASON_ENGINE_UNAVAILABLE = "engine-unavailable"

# Reason a worker reports when the binary has no stored rebrew project.
REASON_NO_ENGINE_CONTEXT = "no-engine-context"

# Reason a goal-directed worker reports when the run carries no goal.
REASON_NO_GOAL = "no-goal"


@dataclass
class WorkerContext:
    """Everything one worker needs to decide what a function needs.

    ``engine`` and ``llm_client`` are the process-wide instances the
    orchestrator resolved; either may be an unusable instance (``available()``
    False) rather than None, which is how a worker reports the skip reason
    instead of crashing.  ``previous`` is the last attempt's detail when the
    orchestrator is retrying this function.  ``goal`` is the run's free-form
    objective, empty for a run that carries none.
    """

    conn: sqlite3.Connection
    function: dict[str, Any]
    project_dir: str | None
    engine: Any
    llm_client: llm.LlmClient | None
    execute: bool
    keep_failures: bool = False
    previous: dict[str, Any] | None = None
    goal: str = ""


@dataclass
class WorkerResult:
    """One worker's verdict on one function.

    ``written_files`` is the record the run keeps so a failed or reverted run
    can remove exactly the files it wrote, and ``status_changes`` the record a
    revert restores.  A dry-run result carries neither.
    """

    status: str
    function_id: int | None = None
    status_before: str = ""
    status_after: str = ""
    verified: bool = False
    detail: dict[str, Any] = field(default_factory=dict)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    written_files: list[str] = field(default_factory=list)
    status_changes: list[dict[str, Any]] = field(default_factory=list)


WorkerRun = Callable[[WorkerContext], WorkerResult]
PlannedPaths = Callable[[WorkerContext], Sequence[str]]


@dataclass(frozen=True)
class Worker:
    """One auto-mode worker: its name, what it does, and how it runs.

    ``planned_paths`` names the persistent files the worker may write for a
    context, so the orchestrator can reserve the undo inverse before the write
    and keep it out of a process that is killed mid-write.  It must not write:
    it returns the paths, and a worker that writes something it did not plan
    still has the write recorded from its result.
    """

    name: str
    description: str
    run: WorkerRun
    planned_paths: PlannedPaths | None = None


_registry: dict[str, Worker] = {}
_builtins_loaded = False
_entry_points_loaded = False
_registry_lock = threading.RLock()


def register_worker(worker: Worker, *, origin: str = BUILTIN_ORIGIN) -> None:
    """Register *worker* under its own name.

    Raises :class:`RegistryError` for a malformed value or a name that is
    already taken, naming both origins (single-source discipline).
    """
    if not isinstance(worker, Worker):
        raise RegistryError(
            f"bad worker registration from {origin}: expected a Worker, got {type(worker).__name__}"
        )
    if not worker.name.strip():
        raise RegistryError(f"bad worker registration from {origin}: empty name")
    if not callable(worker.run):
        raise RegistryError(
            f"bad worker registration {worker.name!r} from {origin}: run is not callable"
        )
    with _registry_lock:
        if worker.name in _registry:
            raise RegistryError(
                f"duplicate worker registration {worker.name!r}: {origin} conflicts"
                f" with an existing registration (single-source discipline)"
            )
        _registry[worker.name] = worker


def workers() -> tuple[Worker, ...]:
    """Every registered worker, built-ins first, in declaration order."""
    _ensure_builtins()
    _ensure_entry_points()
    with _registry_lock:
        return tuple(_registry.values())


def get_worker(name: str) -> Worker | None:
    """The registered worker named *name*, or None."""
    return next((worker for worker in workers() if worker.name == name), None)


def unregister_worker(name: str) -> None:
    """Withdraw the worker registered as *name*.

    Raises :class:`RegistryError` for a name nothing holds.  Withdrawing a
    built-in lasts until the next :func:`refresh_workers`.
    """
    _ensure_builtins()
    _ensure_entry_points()
    with _registry_lock:
        if name not in _registry:
            raise RegistryError(f"no worker registration {name!r} to withdraw")
        del _registry[name]


def refresh_workers() -> tuple[Worker, ...]:
    """Discard discovered workers and re-run discovery.

    Built-ins are re-declared and the entry-point group is scanned again, which
    is how a long-lived process picks up a plugin installed after startup.
    """
    global _builtins_loaded, _entry_points_loaded
    with _registry_lock:
        _registry.clear()
        _builtins_loaded = False
        _entry_points_loaded = False
    return workers()


def _ensure_builtins() -> None:
    """Load the in-tree workers once."""
    global _builtins_loaded
    with _registry_lock:
        if _builtins_loaded:
            return
        _builtins_loaded = True
        module = importlib.import_module("reportal.auto_llm_worker")
        goal_module = importlib.import_module("reportal.auto_goal_worker")
        register_worker(offline_worker(), origin=BUILTIN_ORIGIN)
        register_worker(
            replace(module.llm_c_source_worker(), planned_paths=planned_llm_source_paths),
            origin=BUILTIN_ORIGIN,
        )
        register_worker(
            replace(goal_module.llm_goal_worker(), planned_paths=planned_goal_paths),
            origin=BUILTIN_ORIGIN,
        )


def planned_llm_source_paths(ctx: WorkerContext) -> Sequence[str]:
    """The candidate source path the built-in LLM worker may write for *ctx*.

    The path is the worker's own naming rule, resolved here so the orchestrator
    can reserve the undo inverse before the worker writes.  It is a prediction:
    a worker that skips or fails leaves the path unwritten, and the task's
    result never records it.  A dry run writes no file and resolves to none.
    """
    if not ctx.execute or ctx.project_dir is None:
        return ()
    worker_module = importlib.import_module("reportal.auto_llm_worker")
    target = worker_module.target_config(ctx.project_dir)
    if target is None:
        return ()
    stem = worker_module.source_slug(ctx.function)
    return (str(Path(str(target["reversed_dir"])) / f"{stem}.c"),)


def planned_goal_paths(ctx: WorkerContext) -> Sequence[str]:
    """The persistent paths the goal worker may write for *ctx*.

    The candidate source it names for the function plus, when the binary is
    known, the patched copy of it the worker derives from the model's byte
    edits.  Resolved here without writing, so the orchestrator reserves the
    undo inverse before either write.  A dry run and a run with no goal resolve
    to none, because the worker writes nothing then.
    """
    if not ctx.execute or not ctx.goal.strip() or ctx.project_dir is None:
        return ()
    worker_module = importlib.import_module("reportal.auto_llm_worker")
    goal_module = importlib.import_module("reportal.auto_goal_worker")
    target = worker_module.target_config(ctx.project_dir)
    if target is None:
        return ()
    paths = [
        str(Path(str(target["reversed_dir"])) / f"{worker_module.source_slug(ctx.function)}.c")
    ]
    binary = goal_module.binary_path_for(ctx)
    if binary is not None:
        paths.append(str(goal_module.patched_binary_path(binary)))
    return tuple(paths)


def _ensure_entry_points() -> None:
    """Load third-party workers once, skipping a broken registration."""
    global _entry_points_loaded
    with _registry_lock:
        if _entry_points_loaded:
            return
        _entry_points_loaded = True
        for name, value, worker in plugins.load(WORKER_ENTRY_POINT_GROUP, Worker, "Worker"):
            # A duplicate name is not skipped: two workers claiming one name is a
            # composition error, and the RegistryError says which registration lost.
            register_worker(worker, origin=plugins.origin(name, value))


def is_address_placeholder(name: str) -> bool:
    """True when *name* is an address-derived placeholder, not a real symbol."""
    return bool(_ADDRESS_NAME.match(name.strip()))


def is_matching_status(status: str) -> bool:
    """True when *status* is one of rebrew's byte-equality match statuses."""
    return status in store.MATCHED_STATUSES


def _skipped(function: dict[str, Any], reason: str) -> WorkerResult:
    """A skip result for *function* carrying *reason*."""
    return WorkerResult(
        status=WORKER_SKIPPED,
        function_id=int(function["id"]),
        status_before=str(function["status"]),
        detail={"reason": reason},
    )


def _failed(function: dict[str, Any], reason: str) -> WorkerResult:
    """A failure result for *function* carrying *reason*."""
    return WorkerResult(
        status=WORKER_FAILED,
        function_id=int(function["id"]),
        status_before=str(function["status"]),
        detail={"reason": reason},
    )


def offline_worker() -> Worker:
    """The deterministic no-engine worker used by tests and ``--demo``.

    It never calls a model or an engine.  A function that already matches is
    skipped; a function whose name is a real symbol is "marked" and reported
    matched with :data:`OFFLINE_CLAIMED_STATUS`; an address-placeholder name is
    reported failed.  A run asking it to execute is refused, since a claim with
    no engine behind it must never reach the store.
    """

    def run(ctx: WorkerContext) -> WorkerResult:
        function = ctx.function
        if ctx.execute:
            return _failed(function, REASON_OFFLINE_NOT_EXECUTABLE)
        before = str(function["status"])
        if is_matching_status(before):
            return _skipped(function, "already-matched")
        name = str(function["name"])
        if not name.strip() or is_address_placeholder(name):
            return _failed(function, REASON_NO_SYMBOL)
        return WorkerResult(
            status=WORKER_MATCHED,
            function_id=int(function["id"]),
            status_before=before,
            status_after=OFFLINE_CLAIMED_STATUS,
            verified=True,
            detail={"marked_name": name},
        )

    return Worker(
        name=WORKER_OFFLINE,
        description=(
            "Deterministic offline worker: no LLM, no engine. Marks functions"
            " with a real symbol name as matched and refuses to execute."
        ),
        run=run,
    )

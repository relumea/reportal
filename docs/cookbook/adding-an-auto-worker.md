# Adding an auto worker

Prerequisites: read [auto_workers.py](../../src/reportal/auto_workers.py) (`Worker`,
`WorkerContext`, `WorkerResult`, `register_worker`, `workers`, `refresh_workers`), the built-in
declarations in [auto_llm_worker.py](../../src/reportal/auto_llm_worker.py), and
[ARCHITECTURE.md](../ARCHITECTURE.md#auto-mode).

## Steps

1. Write the run function. It takes one `WorkerContext` and returns one `WorkerResult`:

   ```python
   def _run_symbol_lookup(ctx: WorkerContext) -> WorkerResult:
       function = ctx.function
       if not str(function["name"]).strip():
           return WorkerResult(
               status=WORKER_FAILED,
               function_id=int(function["id"]),
               status_before=str(function["status"]),
               detail={"reason": REASON_NO_SYMBOL},
           )
       return WorkerResult(status=WORKER_SKIPPED, function_id=int(function["id"]))
   ```

   `ctx` carries `conn`, `function`, `project_dir`, `engine`, `llm_client`, `execute`,
   `keep_failures`, `previous` and `goal` (the run's free-form objective, empty when the run
   carries none). The context is not a data source: read the store through
   `ctx.conn`.
2. Pick the verdict honestly. `WORKER_MATCHED` claims an engine-verified match and the orchestrator
   accepts it only when `verified` is set and `form` is a matching status. `WORKER_IMPROVED` means
   usable without a match, `WORKER_FAILED` means the attempt did not work, `WORKER_SKIPPED` means
   the worker declined, with a `reason` in `detail`.
3. A dry run must not write. When `ctx.execute` is false, return the result without touching the
   filesystem, as the built-in offline worker does at `REASON_OFFLINE_NOT_EXECUTABLE`.
4. Record what a real run wrote: list the paths in `WorkerResult.written_files` and the statuses it
   replaced in `status_changes`. A failed or reverted run removes exactly those.
5. Declare the worker as a `Worker` with a `name`, a `description` and the run, and register it.
   The in-tree workers are registered in `auto_workers._ensure_builtins`, which also wraps each
   writing worker with its `planned_paths` resolver (`planned_llm_source_paths`,
   `planned_goal_paths`).
6. Implement `planned_paths` when the worker may write a file. It returns the paths for a context
   without writing anything, so the orchestrator can reserve the undo inverse before the write. A
   dry run returns `()`.
7. Add the worker name to `tests/test_auto_workers.py` when the worker has behavior worth pinning;
   `test_builtins_are_registered` names the in-tree workers.

A third-party worker registers through the `reportal.auto_workers` entry-point group whose value is
`module:attr` naming a `Worker` or a zero-argument factory returning one. A duplicate name raises
`RegistryError`; a broken registration is skipped with a warning.

## Verify

1. `.venv/bin/python -m pytest tests/test_auto_workers.py -q` proves the registry and the built-in
   workers.
2. `.venv/bin/python -m pytest tests/test_auto_mode.py -q` proves the orchestrator accepts and
   records a worker result.
3. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#auto-mode)
- [API.md](../API.md)

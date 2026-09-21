# Auto mode

Sources: src/reportal/auto_mode.py, src/reportal/auto_store.py, src/reportal/auto_workers.py, src/reportal/auto_llm_worker.py, src/reportal/auto_goal_worker.py

This subsystem owns the auto-run orchestration loop, its task tree and attempt store, and the
worker registry that turns one function into a result. The contract is that acceptance is the
engine's byte comparison, never a worker's claim, and that every write a run makes is folded into
its undo plan before the write is lost.

## Vocabulary

- `AutoParams` and `build_params`: the run configuration (`worker`, `execute`, `concurrency`,
  `functions_per_task`, `max_attempts`, `max_tasks`, `task_timeout`, `disabled`, `goal`). Bounds:
  `DEFAULT_CONCURRENCY` 4 within `MIN_CONCURRENCY`..`MAX_CONCURRENCY` (32), `functions_per_task`
  1..64, `max_attempts` 1..10, `max_tasks` 1..5000, `goal` at most `MAX_GOAL_CHARS` (2000).
- `Worker` (`name`, `description`, `run`, optional `planned_paths`) and `WorkerContext`
  (`conn`, `function`, `project_dir`, `engine`, `llm_client`, `execute`, `keep_failures`,
  `previous`, `goal`).
- `WorkerResult`: `status`, `function_id`, `status_before`, `status_after`, `verified`, `detail`,
  `artifacts`, `written_files`, `status_changes`. Verdicts are `WORKER_MATCHED`,
  `WORKER_IMPROVED`, `WORKER_FAILED`, `WORKER_SKIPPED`.
- Run statuses `AUTO_RUN_RUNNING`, `AUTO_RUN_DONE`, `AUTO_RUN_FAILED`, `AUTO_RUN_PARTIAL`,
  `AUTO_RUN_REVERTED`; task statuses `AUTO_TASK_PENDING`, `AUTO_TASK_RUNNING`, `AUTO_TASK_DONE`,
  `AUTO_TASK_FAILED`, `AUTO_TASK_SKIPPED`; kinds `AUTO_TASK_ROOT`, `AUTO_TASK_BATCH` with depths
  `AUTO_ROOT_DEPTH` and `AUTO_BATCH_DEPTH`.
- Write intents: `INTENT_PENDING`, `INTENT_APPLIED`, `INTENT_RESULT_KEY`, `INTENT_FIELD`; a
  pending intent is what a recovery treats as possibly applied.
- Tables `auto_runs` (with `effects_json`), `auto_tasks`, `auto_attempts`. Reasons:
  `REASON_TIMEOUT`, `REASON_INTERNAL_ERROR`, `REASON_BUSY`, `REASON_INTERRUPTED`, `REASON_NO_GOAL`.
- Built-in workers `offline` (`WORKER_OFFLINE`), `llm_c_source` (`WORKER_LLM_C_SOURCE`) and
  `llm_goal` (`WORKER_LLM_GOAL`). `llm_goal` answers the run's goal with a patched C file, its
  unified diff and length-preserving byte edits, and writes `<binary>.patched` beside the binary.
- Goal-result keys: `GOAL_KIND_SOURCE`, `GOAL_KIND_SOURCE_PATCH`, `GOAL_KIND_BINARY_PATCH`,
  `PATCHED_BINARY_SUFFIX` (`.patched`).

## Wiring

- Routes: `POST` and `GET /api/binaries/{binary_id}/auto`, `GET /api/auto/runs/{run_id}`,
  `POST /api/auto/runs/{run_id}/revert`, `POST /api/auto/runs/{run_id}/recover`.
- CLI `auto`, `auto-revert`, `auto-recover`; MCP tools `run_auto`, `revert_auto_run`,
  `recover_auto_run`.
- Entry-point group `reportal.auto_workers` (`module:attr` naming a `Worker` or a zero-argument
  factory).

## Invariants

- A `matched` result is accepted only when its status is a matching one and `verified` is set
  (`tests/test_auto_mode.py`).
- Every write is gated on `execute`; a dry run records rows and changes no function status and no
  file.
- The `offline` worker refuses an execute run (`REASON_OFFLINE_NOT_EXECUTABLE`).
- A duplicate worker name raises `RegistryError`; a broken entry point is skipped with a warning
  (`tests/test_auto_workers.py`).
- A batch confirms its reserved intents and folds its descriptors into `auto_runs.effects_json`
  in the same commit as its result (`tests/test_auto_intents.py`).
- `recover_auto_run` marks stale `running`/`pending` tasks `failed` with reason `interrupted` and
  merges their recorded writes, listing a still-pending intent in `uncertain_intents`
  (`tests/test_auto_recover.py`).
- `revert_auto_run` replays the plan newest-first through `effects.apply_undo_plan`.
- A run with a non-empty `goal` plans every function of the binary
  (`store.list_binary_functions`), not only the unmatched ones.
- `llm_goal` applies a byte edit only when the engine reads back its `original` bytes at the
  function's VA, and splices only a function window that occurs once in the binary
  (`REASON_BINARY_AMBIGUOUS` otherwise); an unconsumed edit is reported in `rejected_edits`.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#auto-mode)
- [API.md](../API.md)
- [CLI.md](../CLI.md)

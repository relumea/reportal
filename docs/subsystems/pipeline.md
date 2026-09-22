# Pipeline

Sources: src/reportal/pipeline.py

This subsystem owns the AI decompilation pipeline as a composition of components: the built-in
component declarations, the loader that activates them, the per-run context and its stored undo
plan. The contract is that each function's run carries its own reversible plan, and that a step
which cannot run is recorded with a reason instead of failing the run.

## Vocabulary

- Seeds the runner binds: `SEED_FUNCTION`, `SEED_BINARY`, `SEED_PROJECT`, `SEED_CONN`,
  `SEED_ENGINE`, `SEED_LLM`. `llm` is seeded only when a client is configured.
- Provided names: `NAME_FUNCTION_META`, `NAME_DISASSEMBLY`, `NAME_CONTROL_FLOW`,
  `NAME_CALL_TRACE`, `NAME_DECOMPILATION`, `NAME_SIMILAR_FUNCTIONS`, `NAME_PREDICTED_NAME`,
  `NAME_KNOWLEDGE`, `NAME_REWRITE`, `NAME_RENAMES`, `NAME_RENAMED_CODE`,
  `NAME_TYPE_SUGGESTIONS`, `NAME_INLINE_COMMENTS`, `NAME_SUMMARY`.
- Built-in component names: `COMPONENT_PREPARE`, `COMPONENT_READ_TRACE`, `COMPONENT_DECOMPILE`,
  `COMPONENT_SEARCH_FUNCTIONALITY`, `COMPONENT_RESOLVE_NAMES`,
  `COMPONENT_RETRIEVE_KNOWLEDGE`, `COMPONENT_REWRITE`, `COMPONENT_RENAME_VARIABLES`,
  `COMPONENT_NAME_VARIABLES`, `COMPONENT_SUMMARIZE`, `COMPONENT_STORE`.
- Skip reasons: `REASON_DISABLED`, `REASON_LLM_UNAVAILABLE`, `REASON_NO_ENGINE_CONTEXT`,
  `REASON_ENGINE_UNAVAILABLE`, `REASON_NO_DECOMPILATION`, `REASON_NO_RENAME_SUGGESTIONS` and the
  `REASON_DEPENDENCY_*` family. Step and run statuses come from `store` (`STEP_DONE`,
  `STEP_SKIPPED`, `STEP_FAILED`, `STEP_DEACTIVATED`, `RUN_DONE`, `RUN_FAILED`).
- `StepFailure`, `PipelineUnavailable`, `NotWithdrawableError`, `ComponentHost`,
  `dependency_order`.
- Tables `pipeline_runs` (with `effects_json`) and `pipeline_steps`; `KNOWN_SYMBOL_LIMIT` bounds
  the symbol block; `DEFAULT_BATCH_LIMIT` 25 and `MAX_BATCH_LIMIT` 500.

## Wiring

- Routes: `POST /api/functions/{function_id}/pipeline`, `GET /api/functions/{function_id}/pipeline`,
  `GET /api/pipeline/runs/{run_id}`, `POST /api/pipeline/runs/{run_id}/revert`.
- CLI `pipeline`, `pipeline-revert`; MCP tools `run_pipeline`, `revert_pipeline_run`,
  `get_pipeline`.
- Config: `[pipeline] disabled` in the workspace `reportal.toml` (setting `pipeline.disabled`);
  an unknown name is ignored.
- The whole-binary batch is the `ai-enrich` job kind, not a route of its own.

## Invariants

- Activation order is a deterministic topological order over `requires`/`provides`, declaration
  order breaking ties; a component runs as soon as its requirements hold
  (`tests/test_components.py`).
- A step whose effect raises is recorded `failed` with its reason and does not abort the run.
- An unassemblable composition (`RegistryError`) becomes `PipelineUnavailable`, which the API maps
  to 503 (`tests/test_pipeline_api.py`).
- `run_pipeline_batch` runs one `run_pipeline` per function, so one failure leaves the others
  intact.
- `revert_run` walks the stored plan newest-first and reports a binding a later process cannot
  resolve as `applied: false` (`tests/test_pipeline.py`).
- `run_pipeline` raises `KeyError` for an unknown function (`tests/test_pipeline.py`).
- `ComponentHost.sync` retires a fiber whose declaration left the registry
  (`tests/test_pipeline.py`).

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#components)
- [COMPONENTS.md](../COMPONENTS.md)
- [API.md](../API.md)

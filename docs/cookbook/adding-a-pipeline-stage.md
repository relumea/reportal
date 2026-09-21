# Adding a pipeline stage

Prerequisites: read the component model in [components.py](../../src/reportal/components.py), the
built-in stage declarations and the effect functions in
[pipeline.py](../../src/reportal/pipeline.py), and
[COMPONENTS.md](../COMPONENTS.md#writing-a-component). A pipeline stage is a `Component`; read
`docs/cookbook/adding-a-component.md` first.

## Steps

1. Name the stage. Add a `COMPONENT_*` constant in `src/reportal/pipeline.py` beside
   `COMPONENT_PREPARE`, `COMPONENT_DECOMPILE` and `COMPONENT_STORE`. The name is the value the run
   reports per step and the value `[pipeline] disabled` in `reportal.toml` switches off.
2. Declare the inputs and outputs as context names. Seeds (`SEED_FUNCTION`, `SEED_CONN`,
   `SEED_PROJECT`, `SEED_ENGINE`, `SEED_LLM`) are bound before the run; a stage's product is a
   `NAME_*` constant (`NAME_DECOMPILATION`, `NAME_SUMMARY`, ...).
3. Write the effect function. It reads with `ctx.require(name)` and writes with
   `ctx.provide(name, value)`. `_effect_decompile` is the reference: it reuses a stored row when
   there is one, raises `StepFailure(REASON_ENGINE_UNAVAILABLE)` when the engine cannot run, calls
   the engine, stores the result and records the inverse.
4. Journal every persistent write through `_record_effect(ctx, conn, descriptor)`. The descriptor's
   `kind` must have a handler in the effect dispatcher, or a revert of the run fails for that entry.
5. Declare the stage in `builtin_components()` as a `Component` with `name`, `requires`, `provides`
   and `effect`:

   ```python
   Component(
       name=COMPONENT_SUMMARIZE,
       requires=frozenset({NAME_RENAMED_CODE, SEED_LLM}),
       provides=frozenset({NAME_SUMMARY}),
       effect=_effect_summarize,
   ),
   ```

   Position in the tuple is a tie-break: the loader activates a stage when its requirements are
   satisfied, and deactivates one whose requirement is revoked mid-run.
6. Keep one writer per context name. A second provider of one name raises `RegistryError` from
   `assert_unique_providers` before the run starts.
7. Update the order test in `tests/test_pipeline.py` when the new stage belongs in the reported
   sequence: `TestDependencyOrder.test_builtin_order_matches_the_reported_step_sequence` compares
   declaration order against the step sequence.
8. Say why the stage sits where it does in a comment beside its declaration, as the enrich chain
   does, when the order is a real edge in the graph rather than an accident.

## Verify

1. `.venv/bin/python -m pytest tests/test_pipeline.py -q` proves the dependency order, the run
   record, the disabled argument and the built-in stages.
2. `.venv/bin/python -m pytest tests/test_components.py -q` proves the registry refuses two
   providers of one name.
3. `.venv/bin/python -m pytest tests/test_pipeline_api.py tests/test_pipeline_cli.py -q` proves the
   run and revert surfaces report the new stage.
4. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#components)
- [COMPONENTS.md](../COMPONENTS.md)

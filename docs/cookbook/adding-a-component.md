# Adding a component

Prerequisites: read [components.py](../../src/reportal/components.py) (`Component`, `Context`,
`register_component`, `components`, `unregister_component`), the loader in
[pipeline.py](../../src/reportal/pipeline.py) (`builtin_components`, `configured_disabled`) and
[COMPONENTS.md](../COMPONENTS.md#writing-a-component).

## Steps

1. Add the name constant to `src/reportal/pipeline.py`, beside `COMPONENT_DECOMPILE` and the rest.
   Use the spelling the step sequence reports.
2. Name the context values the component reads and writes. Seeds are declared there too:
   `SEED_FUNCTION`, `SEED_BINARY`, `SEED_PROJECT`, `SEED_CONN`, `SEED_ENGINE`, `SEED_LLM`, and the
   derived names (`NAME_DECOMPILATION`, `NAME_SUMMARY`, ...). A value no existing component
   provides is a new `NAME_*` constant.
3. Write the effect function:

   ```python
   def _effect_read_tags(ctx: Context) -> None:
       function = ctx.require(SEED_FUNCTION)
       conn = ctx.require(SEED_CONN)
       binary = store.get_binary(conn, int(function["binary_id"]))
       ctx.provide(NAME_BINARY_TAGS, store.get_binary_tags(conn, int(binary["id"])))
   ```

   `ctx.require(name)` raises `RequirementError` for an unbound name. `ctx.provide(name, value)`
   journals an inverse that restores the previous binding, so a revert walks it back.
4. For a persistent write, record its inverse through `_record_effect(ctx, conn, descriptor)`, which
   hands the descriptor to `components.Context.record` and therefore to the shared effect
   dispatcher. Reuse an existing kind (`EFFECT_DISASM`, `EFFECT_DECOMPILATION`,
   `EFFECT_AI_ARTIFACT`, `EFFECT_FILE_WRITE`, `EFFECT_STATUS_CHANGE`) or add a handler first
   (`docs/cookbook/adding-an-effect-handler.md`).
5. Raise `StepFailure(REASON_*)` for a step that cannot run (no engine, no project, no LLM).
   The loader records the step as skipped or failed and deactivates its dependents; a raised
   `StepFailure` is not a crash.
6. Declare the component in `builtin_components()` in the order it must run. `requires` and
   `provides` are `frozenset[str]`; the loader activates a component when its requirements are
   satisfied, so the order is a tie-break rather than the schedule.
7. Keep one provider per name. `assert_unique_providers` and `ComponentHost` refuse two components
   that provide the same name.
8. Document the stage in `docs/COMPONENTS.md` when it adds a mechanism or a vocabulary term.

A third-party component registers through the `reportal.components` entry-point group whose value
is `module:attr` naming a `Component` or a zero-argument factory returning one. A duplicate name
raises `RegistryError`; a broken registration is skipped with a warning.

## Verify

1. `.venv/bin/python -m pytest tests/test_components.py tests/test_pipeline.py -q` proves the
   context, the registry, the loader and the built-in stages behave.
2. `.venv/bin/python -m pytest tests/test_pipeline.py -q -k TestDependencyOrder` proves the step
   order.
3. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#components)
- [COMPONENTS.md](../COMPONENTS.md)

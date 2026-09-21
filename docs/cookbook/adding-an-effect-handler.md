# Adding an effect handler

Prerequisites: read [effects.py](../../src/reportal/effects.py) (`EffectHandler`,
`register_effect_handler`, `effect_handlers`, `builtin_effect_handlers`, `apply_descriptor`,
`apply_undo_plan`) and [COMPONENTS.md](../COMPONENTS.md#adding-an-effect-kind).

## Steps

1. Pick the descriptor `kind` string. A kind is an identifier-like value: `EFFECT_DISASM`,
   `EFFECT_DECOMPILATION`, `EFFECT_AI_ARTIFACT`, `EFFECT_FILE_WRITE` and `EFFECT_STATUS_CHANGE` are
   the pipeline's writes, `EFFECT_ROW_RESTORE`, `EFFECT_ROW_DELETE`, `EFFECT_FILE_DELETE` and
   `EFFECT_FILE_RESTORE` the action journal's, and `EFFECT_CONTEXT_CHANGE` a binding.
2. Add the constant to `src/reportal/effects.py` beside the others, with a comment naming what
   writes it.
3. Write the inverse handler:

   ```python
   def _undo_import_cache(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
       store.clear_disasm(conn, int(descriptor.get("function_id", 0)))
       return _pipeline_entry(descriptor)
   ```

   The signature is `(conn, descriptor) -> dict[str, Any] | None`. It applies the inverse and
   returns the fields the revert entry carries, or None when it reports nothing beyond the reverting
   status. `_pipeline_entry(descriptor)` is the pipeline entry shape; a journal inverse returns
   `store.EFFECT_*`-style status fields instead.
4. Add the kind to the mapping `builtin_effect_handlers()` returns, beside `EFFECT_DISASM` and the
   rest.

5. Teach `effects.describe(descriptor)` how the write reads in a revert report. An unhandled kind
   falls through to `f"effect {kind!r} on function {function_id}"`, which is the wrong sentence
   once a handler exists.
6. Write the descriptor where the write happens, through the pipeline's `_record_effect` or the
   journal's own descriptor builder (`journal` writes the `row-`/`file-` kinds). A write with no
   descriptor is not revertible.
7. Add a test to `tests/test_effects.py`: the inverse itself, and that the built-in kind set
   carries the new name.

A third-party handler registers through the `reportal.effect_handlers` entry-point group. A
callable value registers under the entry-point name as its kind; a mapping registers every kind it
names. A malformed mapping is skipped with a warning; a duplicate kind raises `RegistryError`. The
resolved value is not called: in this group a callable is the handler, not a factory.

## Verify

1. `.venv/bin/python -m pytest tests/test_effects.py -q` proves dispatch, the built-in kinds and the
   entry-point path.
2. `.venv/bin/python -m pytest tests/test_pipeline.py -q` proves a run's stored plan reverts through
   the dispatcher.
3. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#action-journal)
- [COMPONENTS.md](../COMPONENTS.md)

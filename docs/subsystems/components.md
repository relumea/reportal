# Components, effects, journal and plugins

Sources: src/reportal/components.py, src/reportal/effects.py, src/reportal/journal.py, src/reportal/plugins.py, src/reportal/integrations.py

This subsystem owns the composition framework and the two things that make a write reversible: the
run-scoped `Context` journal and the request-scoped action journal. The contract is one writer per
context name, one dispatcher for every undo descriptor, and a plugin registry that skips a broken
registration but refuses a duplicate name.

## Vocabulary

- `Component` (frozen dataclass): `name`, `requires`, `provides`, `effect`, optional `revert`.
- `Context`: `provide`, `revoke`, `require`, `get`, `has`, `seed`, `record`, `effects`,
  `undo_plan`, `revert`, `subscribe`, `take_binding_change`, `derive`, `drop`, `intercept`,
  `load`, `spawn`. `RequirementError` is an absent required name.
- `Effect`: `description`, `inverse`, optional `undo` descriptor, `kind`, `name`.
- `EffectStep`: one load step (`context`, `effect`, `inverse`, `rest`); a None `rest` ends it.
- `Fiber` (parent, context, retiring flag, states `FIBER_PENDING`/`ACTIVE`/`RETIRED`/`DISPOSED`,
  committed view), `Inertia` (retirement handle), `FiberStateError`.
- `Registration` (`component`, `origin`, `module_name`, `reloadable`, `entry_point`);
  `NotReloadableError`, `ComponentMissingError`.
- `EffectHandler` (`conn`, `descriptor`) to entry dict. Kinds: `EFFECT_DISASM`,
  `EFFECT_DECOMPILATION`, `EFFECT_AI_ARTIFACT`, `EFFECT_FILE_WRITE`, `EFFECT_STATUS_CHANGE`,
  `EFFECT_ROW_RESTORE`, `EFFECT_ROW_DELETE`, `EFFECT_FILE_DELETE`, `EFFECT_FILE_RESTORE`,
  `EFFECT_CONTEXT_CHANGE`; `UnknownEffectError`.
- `Journal`: `record`, `pending`, `recorded`, `flush`, `revert`, `attach`. `journal_entries`
  carries `action`, `kind`, `description`, `descriptor_json`, `created_at`, `status`, `actor`,
  `actor_user_id`; statuses `STATUS_ACTIVE`, `STATUS_REVERTED`, `STATUS_PARTIAL`.
  `MAX_FILE_BYTES` is 8 MiB and `DEFAULT_PRUNE_KEEP` 5000.
- `plugins.RegistryError`, `plugins.BUILTIN_ORIGIN`, `plugins.Check`; `integrations.SEAMS`,
  `PART_READERS`, `inventory()`, `tool_totals()`.

## Wiring

- Entry-point groups `reportal.components` and `reportal.effect_handlers`.
- Routes `GET /api/components`, `GET /api/integrations`, `POST /api/components/reload`,
  `POST /api/components/{name}/deactivate`, `POST /api/journal/revert`.
- CLI `components`, `integrations`, `components-reload`, `components-deactivate`, `journal`,
  `journal-revert`; MCP tools `list_components`, `reload_components`, `deactivate_components`,
  `list_integrations`, `list_journal`, `revert_journal_entry`.

## Invariants

- A duplicate component, worker, handler, tool, source, model, runner or graph backend raises
  `RegistryError`; a broken entry point is skipped with a warning (`tests/test_components.py`).
- `assert_unique_providers` refuses two enabled components providing one context name
  (`tests/test_components.py`).
- `Context.revert` consumes the journal, walks inverses newest-first, keeps seeded names, and
  reports one failing inverse without stranding the rest (`tests/test_components.py`).
- `derive` reads the parent and journals only the child's effects; `drop` detaches the realm;
  `intercept` is a journaled effect a revert uninstalls (`tests/test_components.py`).
- `Fiber.retire` deactivates children newest-first and settles one `Inertia`; a withdrawal reports
  it (`tests/test_components.py`, `tests/test_pipeline.py`).
- `journaled` flushes on a clean exit and writes nothing when the request raises
  (`tests/test_journal.py`).
- `row-restore` updates an existing row and inserts a missing one, never `INSERT OR REPLACE`; a
  file past `MAX_FILE_BYTES` ends `partial` (`tests/test_effects.py`, `tests/test_journal.py`).
- Every seam in `SEAMS` has a reader, checked at import (`tests/test_integrations.py`).

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#components)
- [ARCHITECTURE.md action journal](../ARCHITECTURE.md#action-journal)
- [COMPONENTS.md](../COMPONENTS.md)

# Components

How reportal's component model maps to the context paradigm described in
*[A Programming Paradigm for Spatiotemporal Composability][paper]*
(arXiv:2608.25512, [github.com/cordiverse/paper][repo]).  The model is what the
AI decompilation pipeline (`pipeline.py`) is built from and what auto mode
(`auto_mode.py`) reverts through; this document is the map from the paper's
mechanisms to the code, followed by what the implementation does **not** do.

[paper]: https://arxiv.org/abs/2608.25512
[repo]: https://github.com/cordiverse/paper

## Mechanism map

| Paper mechanism | Code (symbol) | How it is realized |
|-----------------|---------------|--------------------|
| Revertible effects (temporal composability) | `components.Context.provide`, `Context.revoke`, `Context.record`, `Context.revert`; `effects.apply_descriptor`, `effects.apply_undo_plan` | Every context transformation journals an inverse: `provide`/`revoke` capture the binding they replaced, `record` carries a JSON undo descriptor for a persistent write.  `revert()` applies them newest-first, and one failing inverse does not strand the rest. |
| Reactive coeffects (spatial composability) | `components.Context.subscribe`, `Context.names`; `pipeline._ActivationWatch`, `pipeline._record_deactivations` | The loader subscribes before the first component runs and re-evaluates every pending component's `requires` on each `(name, kind)` change: a component activates as soon as its last requirement is bound, and one that loses a requirement before it ran is recorded `deactivated` with `requires-revoked:<name>`. |
| Unified context | `components.Context`, `components.Component`, `effects.plan_context` | One `Context` holds both the coeffect values and the effect journal.  A stored run's undo descriptors are journaled back onto a `Context` (`plan_context`), so its revert is one newest-first pass over the bindings and writes that journal holds, driven by the same `Context.revert`. |
| Declarative component loader | `components.register_component`, `components()`, `components.refresh_components`, `Component.requires/provides/effect/revert` | A component declares its inputs, outputs and work; the registry supplies the built-ins (`pipeline.builtin_components()`) plus the `reportal.components` entry-point group, and a duplicate name is a `RegistryError`. |
| Configuration reconciliation | `pipeline.dependency_order`, `pipeline.configured_disabled`, `pipeline.run_pipeline(disabled=...)`, `pipeline._skip_reason` | The composition is reconciled against the workspace `reportal.toml` `[pipeline] disabled` list (a caller's `disabled=` overrides it) and ordered so a provider precedes every component that needs it, with declaration order breaking ties. |
| Hot module replacement | `components.reload_component`, `components.reload_all`, `components.registrations`, `pipeline.ComponentHost` | Every registration records the module that declares it and whether it can be reloaded.  `reload_component` re-imports that module through `importlib.reload` (or re-scans the entry-point group) and swaps the registry entry in place, keeping declaration order; `reload_all` reports one result per component and skips the non-reloadable ones with a reason.  `ComponentHost` holds a live `Context` and drives deactivate → reload → activate for a component and its dependents.  See the boundary below. |
| One effect mechanism (pipeline, auto mode and the action journal) | `effects.apply_undo_plan`; `effects.register_effect_handler`, `effects.effect_handlers`, `effects.refresh_effect_handlers`, `effects.builtin_effect_handlers`; `pipeline._stored_plan`; `effects.EFFECT_CONTEXT_CHANGE`; `auto_mode.persist_undo_plan`, `auto_mode.recover_auto_run`, `auto_mode.revert_auto_run`; `auto_store.set_auto_run_effects`, `auto_store.record_auto_task_outcome`; `journal.Journal`, `journal.journaled`, `journal.revert_action`, `journal.revert_entry` | The dispatcher is the single place a descriptor kind maps to its inverse, and the kind-to-handler registry is what a third party extends without editing it.  Auto mode folds each task's descriptors into `auto_runs.effects_json` in the commit that records the task's result and reverts through `apply_undo_plan`; the pipeline journals during the run and reverts through `plan_context(...).revert()`; the action journal persists one request's descriptors in `journal_entries` and replays them through the same `apply_undo_plan`.  A pipeline run also stores a `context-change` descriptor per binding it made (`pipeline._stored_plan`): `revert_run` applies it against the run's live context where this process still holds it and reports it under `context_changes` otherwise. |
| Request-scoped effects (action journal) | `journal.journaled_rows`, `journal.journaled_create`, `journal.journaled_new_rows`, `journal.journaled_file`, `journal.journaled_ingest`, `journal.journaled_rename`, `journal.journaled_scan`, `journal.journaled_scan_result`, `journal.journaled_graph_rebuild`, `journal.snapshot_rows`, `journal.row_restore_descriptor`, `journal.row_delete_descriptor`, `journal.file_delete_descriptor`, `journal.file_restore_descriptor`; `effects.EFFECT_ROW_RESTORE`, `EFFECT_ROW_DELETE`, `EFFECT_FILE_DELETE`, `EFFECT_FILE_RESTORE` | Four generic descriptors cover a request-scoped writer: the rows it replaced, the row it created, the file it wrote, and the file it deleted (bounded by `journal.MAX_FILE_BYTES`, above which the entry ends `partial`).  The helpers wrap the builders per write shape, so a wired site snapshots and mutates and the dispatcher reverses it.  Reverting an action applies the descriptors newest-first, so a row insert is deleted before the table it points at goes and a child row is restored after its parent.  The descriptors are JSON in the database, so the revert works from any later process. |

The step statuses a run records are the activation decisions:
`done` (activated, effect completed), `failed` (activated, effect raised),
`deactivated` (was ready, lost a requirement before it ran) and `skipped`
(never activated, with the reason its provider is missing).

## Writing a component

A third-party component is a `Component` value whose effect works against the
`Context`; it registers through the `reportal.components` entry-point group with
a value of `module:attr` naming the component or a zero-argument factory that
returns one.

```python
# my_reportal_plugin.py
from reportal.components import Component, Context

WORD_COUNT = "word_count"


def count_words(ctx: Context) -> None:
    """Bind the decompilation's word count for the components that follow."""
    code = str(ctx.require("decompilation")["code"])
    ctx.provide(WORD_COUNT, len(code.split()))


WORD_COUNT_COMPONENT = Component(
    name="word-count",
    requires=frozenset({"decompilation"}),
    provides=frozenset({WORD_COUNT}),
    effect=count_words,
)
```

```toml
# pyproject.toml of the plugin
[project.entry-points."reportal.components"]
word-count = "my_reportal_plugin:WORD_COUNT_COMPONENT"
```

`requires` is the coeffect specification the loader activates against, and
`provides` is what activates components after it.  A component that writes to
the store journals the write with `ctx.record(description, inverse, undo)`, so
`Context.revert` takes it back; the `undo` descriptor must be JSON-serializable
and its `kind` must have a handler in the `reportal.effects` registry.

### Adding an effect kind

A new persistent effect kind is a plugin, like a component: register a handler
through the `reportal.effect_handlers` entry-point group, whose value is either
a single handler (registered under the entry-point name as its kind) or a
mapping of kind to handler.  A handler is a callable
`(sqlite3.Connection, descriptor) -> dict | None` that applies the descriptor's
inverse; the dict it returns is merged into the revert entry, and None reports
nothing beyond the reverting status.  This closes the gap where a third-party
persistent write meant a new branch in `reportal.effects._DISPATCH`; the
built-in kinds stay declared in-tree by `effects.builtin_effect_handlers()`.

```python
# my_reportal_plugin.py
from __future__ import annotations

import sqlite3
from typing import Any

from reportal.components import Component, Context
from reportal.effects import apply_descriptor

NOTE_KIND = "note-write"


def undo_note(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Delete the note row a run wrote."""
    note_id = int(descriptor["note_id"])
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    return {"note_id": note_id}


def write_note(ctx: Context) -> None:
    """Write one note row and journal how a revert takes it back."""
    conn = ctx.require("conn")
    cursor = conn.execute("INSERT INTO notes (body) VALUES (?)", ("from the pipeline",))
    note_id = int(cursor.lastrowid)
    descriptor = {"kind": NOTE_KIND, "note_id": note_id}
    ctx.record(
        f"wrote note {note_id}",
        lambda: apply_descriptor(conn, descriptor),
        descriptor,
    )


NOTE_COMPONENT = Component(
    name="note-writer",
    requires=frozenset({"conn"}),
    provides=frozenset(),
    effect=write_note,
)
```

```toml
# pyproject.toml of the plugin
[project.entry-points."reportal.effect_handlers"]
note-write = "my_reportal_plugin:undo_note"

[project.entry-points."reportal.components"]
note-writer = "my_reportal_plugin:NOTE_COMPONENT"
```

The entry-point name `note-write` is the kind the single handler registers
under, matching `NOTE_KIND` in the descriptor.  A duplicate kind is a
`RegistryError`, and a broken registration is skipped with a warning.

### Journaling a request-scoped writer

A writer outside a composition (an API route or a CLI command) uses the same
model at request scope through `reportal.journal`: build a descriptor with one
of the generic row or file helpers, hand it to
`Journal.record(kind, description, descriptor)` inside
`journal.journaled(conn, journal.new_action())`, and return the action id in
the response so the caller can revert it later.  The journal's four kinds are
built into the same `reportal.effect_handlers` registry a plugin extends, so a
handler registered for a new kind is reachable from both a run and a request.

```python
with journal.journaled(conn, journal.new_action()) as log:
    journal.journaled_rows(
        conn,
        log,
        table="notes",
        where="id = ?",
        params=(note_id,),
        description=f"edited note {note_id}",
    )
    store.update_note(conn, note_id, "rewritten")
```

### Reloading a live component

`reload_component(name)` re-reads the declaration and replaces the registry
entry, which is enough for the next composition.  To swap a component a live
`Context` is already running, drive it through a `ComponentHost`: `deactivate`
calls each component's `revert(ctx)` when it declares one, records the
`deactivated` decision and revokes the names it provided; after the reload,
`sync()` re-reads the registry and `activate` runs the new effect and every
dependent that becomes ready again.

```python
from reportal import components, pipeline

host = pipeline.ComponentHost({"function": row, "conn": conn})
host.activate("prepare")
# ... the live run uses the component ...
components.reload_component("prepare")
host.sync()
host.deactivate("prepare")   # dependents first, revert called where declared
host.activate("prepare")     # the reloaded effect, then its dependents
```

## Gaps

What the implementation does **not** do, stated plainly so nothing below is
read as a claim:

- **Hot module replacement replaces the registry entry, not a run in flight.**
  `reload_component` swaps the live registry entry for the components composed
  after it, and `ComponentHost` re-runs a swapped component and its dependents
  against one context.  A `run_pipeline` call already in flight keeps the
  snapshot it started with, and a caller that copied `components()` keeps its
  own copy.  The reload goes through `importlib.reload`, so the declaring
  module is re-executed: module-level state is re-initialized, not merged, and
  an effect that caches in a module global loses that cache.  Only built-in and
  entry-point components are reloadable; one registered in-process through
  `register_component` has no declaring module and raises
  `NotReloadableError`, whose reason names that.  An entry-point module that
  stops binding its declaration raises `ComponentMissingError`: because
  `importlib.reload` re-executes into the same namespace, a name the new source
  drops would otherwise survive as a stale attribute, so the reload compares
  the attribute before and after.  The rewritten source is recompiled only when
  the import system sees it as changed (size or mtime), which is what the
  bytecode cache checks; a same-size rewrite inside one mtime tick reuses the
  old bytecode.
- **No formal observational-equivalence guarantee.**  A revert restores the
  bindings and replays the journaled inverses, and the tests check that.  There
  is no proof that revert-then-rerun is observationally equivalent: a
  component whose effect depends on state outside the context (an engine
  subprocess, the clock, a live LLM) is outside the model.
- **Auto-mode reserves each write, and a crash still leaves uncertainty.**  A
  task's descriptors are folded into `auto_runs.effects_json` in the same commit
  that records the task's result, and the task's own writes are now reserved
  first: `auto_mode._run_function` and `_run_batch` store a `pending` intent (a
  `file-write` or a `status-change` descriptor) through
  `auto_store.reserve_auto_task_intents` before the write and confirm it with
  `confirm_auto_task_intents` after, so a hard kill between the two leaves a
  record.  `recover_auto_run` merges a stale task's intents into the plan and
  reports the unconfirmed ones in `uncertain_intents`: such a write may or may
  not have reached the disk, so recovery says so instead of dropping it or
  claiming it applied.  A worker that writes a file without declaring
  `Worker.planned_paths` gets no reservation, and its write is only recorded
  when it returns; every other producer of a `file-write` descriptor has the
  same gap.  A `running` run is treated as stale because there is no registry of
  live runs: running recovery on a run another process is genuinely still
  working marks its live tasks `failed` under it.
- **The file-write inverse does not check ownership.**  `effects._undo_file_write`
  removes whatever file sits at the descriptor's path, so a revert whose path
  something else re-created deletes that file instead.  Auto mode compensates
  where it reserves, since `auto_mode._reservable_file` reserves only a path
  that does not exist or that a previous attempt of the same run owns.  The
  contract that would close it is recording the path's prior state in the
  descriptor and refusing to delete a file the run did not write.
- **The journal is request-scoped state with an actor, not a session log.**  One
  `Journal` per HTTP request or CLI invocation is the unit the paper's revertible
  effect maps onto here, and each entry now records the `actor` the server set
  around the request (`server.authenticate` + `journal.acting_as`: the user's
  name, `local` while auth is off, empty for a CLI or MCP write).  It records
  *which* identity acted, not a session: no token, address or agent, and the
  actor is a name, so a rename leaves the historic entries under the old one.
- **App-wide mediation is partial, and the wired set is explicit.**  The
  pipeline journals through a `Context` and auto mode journals per task into its
  run's plan, and both stay run-scoped by design: a run's plan is scoped to the
  run and its bindings live in one
  process, so `pipeline.revert_run` and `auto_mode.revert_auto_run` are its
  entry points.  Everything else is mediated by the action journal
  (`journal.py`), one `Journal` per HTTP request or CLI invocation, its entries
  persisted in `journal_entries` and replayed through the same
  `effects.apply_undo_plan` dispatcher.  Every wired site uses the shared
  helpers (`journaled_rows`, `journaled_create`, `journaled_new_rows`,
  `journaled_file`, `journaled_ingest`, `journaled_rename`, `journaled_scan`,
  `journaled_scan_result`, `journaled_graph_rebuild`) rather than hand-rolled
  descriptors, so a new writer is a helper call and a `log.attach` in the
  response.  Wired:
  - **Binaries.**  Upload (`POST /api/binaries`, `reportal add-binary`), the
    binary and function bulk actions (`bulk_actions.py`: tag add and remove,
    binary delete with its stored file, prefix rename, `clear_matches`), and the
    fingerprint POST (`binary_fingerprints`).
  - **Tags.**  Single-binary tag add and remove (API and `reportal tag`), tag
    creation (`POST /api/tags`, `reportal tag` when the tag is new), and the MCP
    `create_tag`, `tag_binary` and `untag_binary` tools.
  - **Functions.**  The stored decompilation
    (`POST /api/functions/<id>/decompilation`, `reportal decompile`) and the
    matches a match run rewrites (`POST /api/binaries/<id>/match`,
    `reportal match`, MCP `run_match`).
  - **Names.**  Function rename and history revert
    (`POST /api/functions/<id>/rename`, `/history/<hid>/revert`,
    `/binaries/<id>/unstrip/apply`, `reportal revert`, `reportal apply-match`,
    `reportal unstrip-apply`, and the MCP `rename_function`, `revert_name`,
    `apply_match`, `apply_unstrip` tools) covering the `functions` row and the
    `name_history` row, and the optional function rename an apply-renames does.
  - **Scans.**  Every scan that stores a `scans` row, on all three entry
    points: the API POSTs (triage, report, structs, crypto, pe-info, security,
    capabilities, secrets, protocols, behavior, hardening, filetype, threat,
    remediation, unstrip, related, composition, detect, lineage, function-triage,
    match),
    their CLI commands, and the MCP `run_*` tools.  The `analyses` row one of
    them creates on demand is journaled only when the action created it, so a
    revert removes a first scan's carrier and leaves an existing one alone.
  - **Conversations.**  Create, delete (with its messages) and message send, on
    the routes and the MCP tools.  A message send journals only the `messages`
    rows it inserted, and the entry's description says the model call is not
    replayed: a revert removes the exchange, not what produced it.
  - **Knowledge.**  Ingest (file, JSON text and URL) and document delete, on
    the routes and the MCP tools.  An ingest journals its document and chunks; a
    delete journals the document and chunks it removes, restored parent-first.
  - **Comments.**  Create, update and delete, on the routes and the MCP tools.
  - **Analyses and collections.**  Analysis creation and collection creation and
    add on the routes.
  - **Families and models.**  Family registration and deletion (routes, CLI and
    MCP); data-type import, rename, member add/edit/remove and delete plus the
    exported header file; signature import, return type, calling convention,
    parameter add/edit/remove and delete plus the exported prototype file.
  - **AI artifacts.**  Summary, inline comments and type suggestions, rename
    suggestions, the `renames-applied` text an apply keeps and a revert
    restores, and the AI decompilation artifact (the rewrite, its token map and
    attributions, an override set, a rating and the per-line inline comments,
    all in one `ai_artifacts` row written through one `ai_decomp.write_artifact`
    path), on the routes, CLI and MCP.
  - **Graph and report files.**  The graph rebuild (see the caveat below) and
    the PDF report file.
  - **The analysis lifecycle.**  The engine relabel, the log append and the
    requeue (`PATCH /api/analyses/<id>`, `POST .../logs`, `POST .../requeue`, the
    `update_analysis` / `append_analysis_log` / `requeue_analysis` MCP tools and
    the matching CLI commands), where a requeue revert restores the status, the
    finish time and the log entry it added; and the analysis bulk delete and
    bulk tag (`POST /api/analyses/bulk`), one action over the id list.
  - **Queued operations.**  Submitting a job journals the `jobs` row it inserts
    (`POST /api/jobs`, `reportal job-submit`, the `submit_job` MCP tool), so a
    revert takes the queue entry back; cancelling journals the row it flips and
    a revert returns it to `queued` (`POST /api/jobs/<id>/cancel` and its two
    siblings).  The scan a job performs is journaled by the runner through the
    same `journal.journaled_scan` the direct route uses, so a queued run is
    revertible exactly like a direct one.
  - **Identity and teams.**  User create (the row is deleted on revert), the
    role or disabled update, token rotation (the previous digest is restored)
    and delete (the row comes back), on the routes, the CLI and the MCP tools;
    team create, update and delete, where a team delete journals its members and
    the binaries and collections that lose their scope; membership add and
    remove; and the object scope setter on a binary or a collection.
  - **Sandbox runs.**  A detonation writes its `sandbox_runs` row as `running`
    before the sample starts and updates it with the report after, and the whole
    run is one action (`journal.journaled_create` on the row, the analysis it
    created included), so a revert removes the record.  The sample's own effects
    are *contained* by the sandbox rather than journaled: reportal records what
    it observed, it does not claim to undo what the sample did.
  - **Feedback.**  A note is one journaled `feedback` row (`POST
    /api/users/feedback`, `reportal feedback-add`, the `add_feedback` MCP tool),
    deleted on revert.  The activity feed beside it stores nothing: it merges the
    journal's actions with the analysis log at read time, which is why it is not
    in this list.
  - **Firmware.**  The carve pass journals the `scans` row it creates or
    replaces (and the `analyses` row only when it created it), through the same
    `journal.journaled_scan` every other scan route uses; the region extraction
    is one action covering every carved binary, the files it stored and the
    collection it joined (`POST /api/binaries/<id>/firmware/extract`, `reportal
    firmware-extract`, the `extract_firmware_regions` MCP tool).
  Still unwired, with the reason:
  - **Run-scoped plans.**  The pipeline and auto mode keep their own plans by
    design (above), so `run_pipeline`, `revert_pipeline_run`, `run_auto`,
    `revert_auto_run` and `recover_auto_run` write no action-journal entry.
    `sync_graph_backend` pushes the stored graph to an external backend and
    writes no local row, and `reload_components` swaps a registry entry rather
    than a row, so neither has an inverse.
  - **The disassembly cache.**  `GET /api/functions/<id>/disasm` and matching's
    default disassembler write `disasm_cache`.  The route is a read and the row
    is a derived cache of it, so it is not journaled; the cache is regenerated
    on demand and carries no source of truth.
  - **The report site files.**  The report run writes the generated site under
    the workspace reports directory; the action journals the `scans` row and
    the PDF file, not the engine's site files, which the next run overwrites.
  - **The bootstrap importer.**  `reportal import-rebrew` creates the
    workspace's baseline rows (binaries, analyses, functions, project contexts,
    fingerprints) in one pass, like `reportal init`; it is not a per-request
    mutation and is not journaled.
  - **User-named artifact files.**  `reportal yara/snort/stix --output` writes
    the payload to the path the user names; the stored `scans` row is
    journaled, the caller's file is not.
  - **Embedding vectors.**  `chunks.embedding_json` is written inside the
    ingest the journal covers, so reverting an ingest removes the chunks and
    their vectors together; nothing re-embeds on restore, which is why the
    journal records no separate vector descriptor.
  - **The finished-job history.**  `jobs._prune` drops terminal `jobs` rows
    past `MAX_JOB_HISTORY`.  It is bookkeeping over rows nothing reads back (a
    job's durable effect is the scan it journaled), so it is not one of the
    writes the action journal covers.  A queued job's own row is journaled, as
    the wired list above says.
  - **The graph backend a rebuild may have pushed to.**  A graph rebuild's
    revert restores the local `graph_nodes` and `graph_edges` rows and removes
    the ones the rebuild created; a `graph/sync` already made is not undone, and
    the local database is the only source the journal covers.
- **Context bindings are recorded, and only the process that made them can undo one.**
  A run's stored plan now carries a `context-change` descriptor for every
  binding a component provided or revoked (`pipeline._stored_plan`), so
  `pipeline.revert_run` reports them under `context_changes` instead of `[]`.
  The descriptor is informational to the effect dispatcher: it names the
  binding and the direction, not the value, so a later process has nothing to
  restore from.  A revert that runs in the process that made the binding still
  holds the run's context (`pipeline._run_contexts`) and applies the change for
  real, reporting `applied: true`; a later process, or one whose bounded
  registry has evicted the run, reports `applied: false` and never claims a
  restore.  `pipeline.RUN_CONTEXT_LIMIT` bounds how many run contexts stay
  resolvable, and `pipeline.reset_live_state()` drops them.  A run stored before
  this change has no binding descriptors and reverts exactly as it did, with
  `context_changes: []`.
- **Activation is not re-entrant.**  A component becomes ready as soon as the
  change notification fires, but it runs after the providing component's effect
  returns; the loader never runs a component from inside the notification.
- **A withdrawal is an explicit, process-local decision; a run's own deactivation is not an undo.**
  In a `run_pipeline` pass a component that loses a requirement is recorded
  `deactivated` and does not run; a component that already ran is not withdrawn
  by the activation watch, and the effects it performed stay journaled for the
  run's own revert.  The explicit withdrawal path is
  `ComponentHost.deactivate(name)`, reachable through
  `POST /api/components/<name>/deactivate`, `reportal components-deactivate
  <name>`, the `deactivate_components` MCP tool and the Components view: it
  calls the component's `revert(ctx)` where it declares one, revokes the names
  it provided, and records the `deactivated` decision.  An unknown name is a
  404; a component that provides nothing and declares no revert is a 409
  `not-withdrawable`, as is a second withdrawal in the same process.  The
  withdrawal acts on one process-wide host (`pipeline.live_host()`) that nothing
  else activates, so a built-in stage whose requirements need a run's seeds is
  withdrawn cold: its `revert` runs where declared, but it had bound no name in
  that host.  A withdrawal whose only effect is a process-local binding records
  no action-journal entry and its payload carries `journaled: false`; only a
  durable write the withdrawal records on the context becomes a
  `journal_action` that `revert_journal_entry` replays.  The live context keeps
  the binding inverses of every activation and withdrawal it made, so a
  long-lived server holds them until the process ends or
  `pipeline.reset_live_state()` drops the host.
- **No distributed scheduler or cross-process discovery.**  reportal is one
  process over one SQLite file, so there is nothing to coordinate beyond the
  row writes the journal already reverses.
- **Effect kinds are pluggable; their descriptors still have to be JSON.**  A
  third-party persistent write no longer means a branch in host source: the
  `reportal.effect_handlers` entry-point group registers a handler (or a
  mapping of kind to handler), and the built-in kinds remain declared in-tree
  by `effects.builtin_effect_handlers()`.  The handler is ordinary Python, but
  the descriptor it reverses must be JSON-serializable, since a run stores its
  plan as JSON (`pipeline_runs.effects_json`, `auto_runs.effects_json`) and
  replays it from a later process.  A descriptor whose kind has no handler
  raises `UnknownEffectError`; `apply_undo_plan` reports that one descriptor
  `failed` and continues with the rest.

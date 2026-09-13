# Data Model

*Reference material moved out of AGENTS.md.*

`store.py` owns the schema.  `functions` is UNIQUE on `(analysis_id, va)`, which
is what makes `upsert_function` and therefore `import-rebrew` idempotent: a
binary is keyed by sha256 (or name+path when the binary bytes are unavailable),
its import analysis is reused by engine label, and functions are refreshed by VA.
`import-rebrew` adds the target binary's import stubs through
`add_function_if_absent`, which never replaces a row the analysis already holds:
each stub becomes a `THUNK` function at its VA with `name_source` `import` and
the 6-byte `jmp dword ptr [iat]` size, and a coverage-db row wins at the same VA.

An external source's answer is a `scans` row like every other scan, keyed by
the analysis and the kind `external:<source>` (`external.scan_kind`), so a
re-pull upserts the same row and a revert removes it.  Nothing new is stored:
the row's payload carries `analysis_id`, `binary_id`, `source`, `kind`,
`fetched_at` and the source's own `payload`, and the `local` and `virustotal`
answers replace each other only within their own kind.

`secrets` holds the local credential store (`secret_store.py`), one row per
`(name, scope, team_id)` with the value in plaintext and the times it was
created and last written.  The table is created on first use, so an existing
database needs no migration, and the unique index is over the three key columns
with `team_id` 0 rather than NULL for a workspace secret (SQLite treats NULLs as
distinct, which would allow a second local row of one name).  Reads are redacted
by construction: `secret_store._row` builds the payload, which carries the byte
length and a last-four hint and never the value, and `value_of` is the one
function that returns a credential.  A write is journaled, so a rotation leaves
the previous value in `journal_entries` until that action is reverted.

`analyses.model` names the registry entry (`models.py`) that last produced the
analysis's stored AI artifacts; a row that predates the column is empty, which
reads as "no model recorded" rather than an invented one.  The per-artifact
model is where it always was, `ai_artifacts.model`, so one analysis upgraded to
a new bridge model can hold artifacts from both, each labelled with the model
that produced it.

`analyses.status` is the source of truth for where an analysis stands, with the
set declared once in `store.ANALYSIS_STATUSES` (`pending`, `processing`, `done`,
`failed`, `cancelled`, mapping onto the hosted portal's Queued, Processing,
Complete and Error); `create_analysis` and `update_analysis_status` refuse a
value outside it.  The writers advance it honestly: `store.set_scan` marks the
analysis `done` and logs the scan's finish, `store.scan_span` logs a scan's
start and marks the analysis `failed` with an error entry when the work raises,
and every status change appends an entry.  `analysis_log.py` owns the
structured log (`analysis_log_entries`, one row per event with a severity from
`SEVERITIES`, the message and the time), appended only through
`analysis_log.append_entry` and read newest-first and bounded by
`list_entries`, which also returns the log's true total.  The `analyses.log`
TEXT column stays what it always was (the importer's summary sentence); a
column cannot carry a severity, a timestamp or a bound per row, so the events
live in their own table and cascade with their analysis.

`binary_fingerprints` stores one engine fingerprint object per binary (a JSON
blob keyed by `binary_id`), written by `POST /api/binaries/<id>/fingerprint`,
`reportal enrich`, and best-effort during `import-rebrew`.

`rebrew_contexts` stores one rebrew project directory per binary, written by
`import-rebrew` and read by the disassembly route as its working directory.
Storing it is not engine-gated: an import succeeds without an engine installed.

`disasm_cache` stores one NASM listing per function, keyed by function id,
written by the disassembly route and by matching's default disassembler.
`decompilations` stores one decompiled source per function, keyed by function
id and carrying the backend that produced it, written by `reportal decompile`
and `POST /api/functions/<id>/decompilation`; `GET` on that route recomputes
live without storing when no row exists.
`ai_artifacts` stores the optional LLM results, one row per
`(function_id, kind)` with `kind` in `summary`, `comments` and
`type-suggestions` (plus `renames`, the identifier rename suggestions,
`function-triage`, one triage row per function, and `ai-decompilation`, the
whole-function rewrite with its token map, per-line attributions, overrides,
rating and line comments), the
payload as JSON and the model that produced it; the
composite primary key makes `set_ai_artifact` an upsert, so a re-run refreshes
the artifact.  `GET /api/functions/<id>/summary`, `/type-suggestions` and
`/renames` serve their kind, and `GET /api/functions/<id>/ai-comments` serves
the inline-comments kind since the analyst comment routes own `/comments`; each
answers 404 `no-artifact` when nothing is stored.  The AI decompilation artifact
is served and mutated by the `/api/functions/<id>/ai-decompilation` routes,
which write it through one shared `ai_decomp.write_artifact` path so every write
journals the row it replaces, and which never add a second table: the token map,
attributions, overrides, rating and line comments are payload fields of that one
row, and a line comment is keyed by its line number rather than by an id.  The AI decompilation pipeline also stores its predicted
name there under kind `predicted-name` (same table, same upsert), so a run's
prediction survives the run that produced it.  An apply of rename suggestions
writes a journal row of kind `renames-applied` whose payload carries the
previous decompilation text and backend, so `revert_renames` restores exactly
that text and deletes the row.

`jobs` holds one row per queued operation: its `kind`, the `binary_id` it targets, its
`status` (`queued`/`running`/`done`/`failed`/`cancelled`), `progress` and
`steps_total`, `message`, the submitted `params_json`, the `result_json` or `error`,
and its created/started/finished times.  `jobs.ensure_schema` creates it on first use,
so a database that predates it upgrades in place; `submit` bounds the waiting queue and
prunes the oldest terminal rows past `MAX_KEPT_JOBS`, so the table is a bounded
operational log.  The work itself is journaled through the same `journaled_scan` its
synchronous route uses, which is what makes a queued scan revertible.

The notification feed (`notifications.py`) has no table: it derives its items
from `journal_entries` (one item per action, described by the action's newest
entry) and `analysis_log_entries` (one item per entry, joined to its binary),
which is why nothing can drift from what those two wrote and why a dismissal is
the client's to remember.  `journal.list_actions`/`count_actions` and
`analysis_log.list_recent`/`count_recent` are the readers it uses; `since` is
an inclusive ISO comparison so a poller never loses an item written in the same
second as its watermark.

`journal_entries` holds one row per recorded inverse of a request-scoped write
(`action` groups the entries of one HTTP request or CLI invocation, `kind` the
descriptor kind, `description`, `descriptor_json`, `created_at` and `status`
`active`/`reverted`/`partial`).  The journal owns the table and creates it on
first use (`journal.ensure_schema`), so a database that predates it upgrades in
place; `revert_action` replays one action's active descriptors newest-first
through `effects.apply_undo_plan` and marks each entry, `revert_entry` does one,
`list_entries` answers metadata without the payload and `prune_entries` keeps
the newest `keep` ids.  `docs/ARCHITECTURE.md` carries the full policy.

`comments` holds the analyst comments, one row per `(scope_kind, scope_id)`
entry with `author`, `body`, `created_at` and `updated_at`; the scope is a loose
reference like a conversation's (no table holds both functions and binaries), so
`comments.py` is what checks the scope exists.  `delete_binary` removes the
binary's own and its functions' comments, conversations and documents
explicitly, since those three tables have no foreign key to the binary, then
deletes the binary row so the schema's `ON DELETE CASCADE` clears the analyses,
functions, matches, scans, decompilations, rename history, tags, fingerprints,
graph rows, data types and family rows.

`pipeline_runs` holds one row per pipeline invocation (`function_id`, `status`
`running`/`done`/`failed`, `started_at`, `finished_at`, `model`, `created_at`)
plus an `effects_json` column carrying the run's journaled undo descriptors, and
`pipeline_steps` one row per component of a run (`name`, `status`
`done`/`skipped`/`failed`/`deactivated`, `reason`, `started_at`, `finished_at`,
`duration_ms`, `provides_json` = the provided names).  Both cascade with their
function or run.  `get_pipeline_run`/`latest_pipeline_run` return a run with its
steps and its undo plan; `finish_pipeline_run` closes a run with its status and
undo plan, and `set_pipeline_effects` replaces that plan (which a revert uses to
consume it).  `clear_disasm`, `clear_decompilation` and `clear_ai_artifact`
are the delete halves the dispatcher (`effects.apply_descriptor`) replays.
`init_db` also adds a column an older database predates (see `_ADDED_COLUMNS`),
so an existing `reportal.db` upgrades in place.
`auto_runs` holds one row per auto-mode invocation (`binary_id`, `status`
`running`/`done`/`failed`/`partial`/`reverted`, `config_json` with every
validated input,
`stats_json` with the counters and coverage deltas, and `effects_json` with the
run's undo plan), and `auto_tasks` its task
tree (`run_id`, self-referencing `parent_id`, `depth`, `kind` `root`/`batch`,
`title`, the `function_id`/`va` of a one-function batch, `status`, `worker`,
`attempts` and `result_json`).  A batch task's `result_json` carries the
functions it was planned for until it runs, then the per-function outcomes,
every file it wrote and every status it replaced.  A completing task folds
those descriptors into its run's plan in the same commit as its result
(`record_auto_task_outcome`), so a hard kill loses at most the task still in
flight; `auto_store.auto_run_effects` reads the plan a merge extends.  A run a
dead process left `running` is closed by `recover_auto_run`, which marks its
unfinished tasks `failed` with reason `interrupted` and merges what they
recorded.  `auto_attempts` holds one
row per worker call (`task_id`, `attempt`, `worker`, `status`,
`detail_json`), written as the attempt happens, so a run interrupted mid-batch
is inspectable and `auto_store.planned_batches` returns exactly the batches
that still need running.  Deleting a run cascades to its tasks and attempts.
`conversations` holds one chat per `(scope_kind, scope_id)` reference (no
foreign key: functions and binaries live in different tables, so the API is
what rejects an unknown scope id) with its title and creation time, and
`messages` holds each turn as `(conversation_id, role, content, created_at)`
with `ON DELETE CASCADE`, so deleting a conversation removes its history.
`conversations.py` builds a bounded context (a named `MAX_CONTEXT_CHARS` cap)
from stored rows only: a function's VA, name, size and status plus its stored
disassembly and decompilation, or a binary's row plus its stored triage
summary and capability scan.  `send_message` writes the user turn, sends the
system prompt, context, the last `HISTORY_TURN_LIMIT` turns and the new
message to the LLM bridge, then writes the assistant turn.

`documents` holds one row per ingested document (`scope_kind`, `scope_id`,
`title`, `source`, `mime`, `sha256`, `size`, the extracted `text`) with a
UNIQUE `(scope_kind, scope_id, sha256)`, which is what makes ingest idempotent
inside a scope; `chunks` holds the document's overlapping chunks
(`document_id`, `ordinal`, `text`, `embedding_json`) with `ON DELETE CASCADE`,
so deleting a document leaves no orphan chunk.  `store.add_document`,
`find_document_by_sha256`, `get_document`, `list_documents`, `delete_document`,
`add_chunk`, `list_chunks` and `iter_chunks_with_embeddings` are the CRUD the
knowledge module and the API use; `iter_chunks_with_embeddings` returns each
chunk with its document fields and its parsed vector, which serves the cosine
ranking and the TF-IDF fallback with one query.  The embedding column is NULL
for a document ingested without an embeddings endpoint.

`graph_nodes` holds one row per graph node (id `b<binary_id>:<kind>:<key>`, its
`binary_id`, `kind`, `key`, `label` and `meta_json`) with a UNIQUE
`(binary_id, kind, key)`, and `graph_edges` one row per directed edge (id
`<source>|<rel>|<target>`, plus `source`, `target`, `rel`, `weight` and
`meta_json`) with a UNIQUE `(binary_id, source, target, rel)`.  Both ids are
derived from their columns and both tables cascade with the binary, so a
rebuild writes the same rows again and `graph.build_graph` can replace one
binary's graph without touching another's.  `list_graph_nodes`,
`list_graph_edges`, `list_graph_edges_for_node`, `get_graph_node`,
`add_graph_node`, `add_graph_edge`, `count_graph_nodes`, `count_graph_edges`
and `delete_graph` are the CRUD the graph module and the routes use, and each
row's parsed `meta` is the JSON object its builder wrote (a node's VA, status
or chunk count, and the `truncated` flag on the binary node).

`scans` stores one engine result per `(analysis_id, kind)` pair(`SCAN_KIND_TRIAGE`, `SCAN_KIND_REPORT`, `SCAN_KIND_STRUCTS`, `SCAN_KIND_CRYPTO`,
`SCAN_KIND_SECURITY`, `SCAN_KIND_UNSTRIP`, `SCAN_KIND_CAPABILITIES`,
`SCAN_KIND_THREAT`, `SCAN_KIND_REMEDIATION`, `SCAN_KIND_EXECUTION`,
`SCAN_KIND_NETWORKING`, `SCAN_KIND_FILESYSTEM`, `SCAN_KIND_SECRETS`,
`SCAN_KIND_PROTOCOLS`,
`SCAN_KIND_ANTI_ANALYSIS`, `SCAN_KIND_OBFUSCATION`, `SCAN_KIND_LINEAGE`,
`SCAN_KIND_DETECT`, `SCAN_KIND_FUNCTION_TRIAGE`, `SCAN_KIND_RELATED`,
`SCAN_KIND_PE_INFO`, `SCAN_KIND_FILETYPE`, `SCAN_KIND_COMPOSITION`); the unique index
makes `set_scan` an upsert, so a re-run refreshes the stored dossier, report or
struct recovery instead of adding a row.  A scan hangs off an analysis, so
`ensure_analysis_for_binary` reuses the binary's newest analysis and creates one
labelled `SCAN_ENGINE` only when the binary has none.  The stored report value
is the engine's whole result (`out`, `pages`, `summary`) and the stored structs
value the engine's whole `decompiled`/`skipped`/`structs` object, which is what
`GET` serves back.  The stored threat value is reportal's own report object
(`iocs`, `ioc_counts`, `techniques`, `narrative`, `notes`), since the
deterministic extraction happens locally over what the engine returns; the
`software_type` and `threat_score` the threat and triage responses carry are
derived at read time from the stored scans (`threat.classify_binary`), so both
surfaces answer the same value for the same stored state and the stored row
keeps exactly what its writer produced.  The
stored remediation value is reportal's own artifact payload (`rule`, `rule_name`,
`string_count`, `import_count`, `specificity`, `validated`, `validator`, `meta`,
`notes`, and the `snort` and `stix` sub-objects), since the artifacts are
rendered, graded and validated locally over what the
engine returns.  The stored secrets value is reportal's own scan object
(`findings`, `count`, `by_confidence`, `scanned`), since the pattern matching and
entropy check happen locally over the strings the engine returns; each finding
carries the raw value, so the stored payload is sensitive.  The stored protocols
value is reportal's own scan object (`protocols`, `count`, `by_confidence`,
`notes`), since the inference happens locally over what the engine returns.
The stored lineage
value is reportal's own comparison payload: one `comparisons` object keyed by
the compared binary's id as a string, each entry carrying the two binary ids and
names, `refined`, the status counts and the rows, so one left binary keeps one
comparison per pair and re-running a pair refreshes just that entry.
The stored function-triage value is reportal's own aggregate payload
(`model`, `functions` with each row's score, summary, capabilities and method
`llm`/`heuristic`, `count`, `by_method`, `skipped` with a reason per row, and
`notes`), each row backed by its `ai_artifacts` entry of the same kind.
`families` holds one row per locally registered malware family (`name`
UNIQUE COLLATE NOCASE, `aliases_json`, `notes`, `reference_binary_id` with
`ON DELETE CASCADE`, `signatures_json`, `created_at`); `signatures_json` is the
bundle derived once from the reference binary (its engine fingerprint's
`sha256`, `imphash` and `rich_header_hash`, the sha256 import hash over the
sorted lowercased `dll:name` entries, the canonical import-name set and the
capability set), so detection never re-runs the engine for the reference.
`store.add_family`/`list_families`/`get_family`/`find_family_by_name`/
`delete_family` are the CRUD `families.py` uses, and the table cascades with
its reference binary.  The stored detect value is reportal's own payload
(`binary_id`, `families_checked`, `matches` with each match's confidence and
signals, `count`, `notes` carrying the scope and both overlap thresholds).
`matches` holds the computed edges: `reportal match` replaces a source
function's rows on every run, so a stale candidate never survives.

`data_types` holds the editable type model, one row per `(binary_id, name)`
with the declaration `kind` (`struct`, `union`, `enum`, `typedef`, `pointer`,
`array`, `function`), an optional `namespace`, the computed `size`, the members
as JSON, an enum's named values as JSON, the kind's `target`, an array's
`element_count`, a `source` (`scan` for a row imported from the stored structs
scan, `manual` for an edited one) and both timestamps; `store` owns the table
DDL and the row primitives
(`add_data_type`, `list_data_types`, `get_data_type`, `find_data_type_by_name`,
`update_data_type`, `delete_data_type`), while `data_types.py` owns the parse,
validation, offset computation, render, export, filter, namespace-tree and
reverse-index logic and is what the API, the CLI and the MCP tools call.  The
table cascades with its binary.  A member carries `name`, `type`, `pointer`,
`count`, `bits`, `offset`, `size` and `note`; `normalize_members` recomputes
every offset and the total size after each edit (a union's members all sit at
offset 0), `recompute` is the one size rule per kind, an unknown type is size 0
with a note instead of a parse failure, and a definition that matches no
supported shape is skipped with a reason.  A row written before the `kind`
column existed came from the structs-scan import, so the migration defaults it
to `struct` and never invents another kind.  `render_header` is deterministic
(types by name) and emits each kind's C form; `render_as_c` is the padded As-C
block (a struct's gaps as `/* +0xN padding */` comments, a union's overlap
stated); `export_header` is the apply step: it writes that header atomically to
the explicit path the caller names and never picks a path inside the workspace
or the rebrew project.  `filter_types` and `namespace_tree` back the route's
`kind`/`namespace`/`search` filters and the panel's tree, and `references`
builds the `referenced_by`/`used_by_functions` reverse indices over the stored
rows, matching by name with the payload's `note` saying so.

`data_type_history` holds one row per type mutation, keyed by its own id with
`data_type_id` (no foreign key, so a deleted type's history survives and stays
readable and revertible), `binary_id` (which cascades with the binary, so
deleting a binary takes its type history the way it takes every other row
scoped to it), `previous_json` and `current_json` (the model state the mutation
replaced and wrote, either side JSON `null` for a create or a delete), `source`,
`actor` and `created_at`.  `store` owns the table DDL and the row primitives
(`add_data_type_history`, `list_data_type_history`, `get_data_type_history`,
`restore_data_type`, and `ensure_data_type_history`, which creates the table on
first use so a database written before it existed picks it up), while
`data_types.py` records the two states on every
write (an import that creates a type, a rename, a namespace or kind change, a
member add, edit or remove, a delete) and `revert_history` restores the
recorded state, clipping its own revert into the history under source `revert`
so the revert is revertible; reverting a row whose state the type already holds
is a no-op, and a deleted row is re-inserted under its original id (a name
another row now holds is refused `duplicate name` rather than overwriting it).
The recorded state carries `source` so a revert restores it, but the per-field
diff covers the model fields only (`HISTORY_FIELDS`), so a reader can tell a
rename from a member edit and a write that changes no model field records
nothing.  The design mirrors `signature_history`: the revert is recorded the
same way, and the API, CLI and MCP revert routes journal the row they replace
and the history row they append, so a `journal_action` revert puts both back.
A row written before this table existed still reads (its history list is empty)
and its next edit records a history entry whose previous state is that legacy
row.

`function_signatures` holds the editable signature model, one row per function
keyed by `function_id` (nullable `name`, `return_type`, `calling_convention`,
`parameters_json`, `source`, both timestamps); `store` owns the table DDL and
the row primitives (`upsert_signature`, `get_signature`, `list_signatures`,
`delete_signature`), while `signatures.py` owns the parse, validation,
prototype rendering and export logic and is what the API, the CLI and the MCP
tools call.  The table cascades with its function, and `list_signatures` joins
`functions`/`analyses` to scope one row set to a binary.  A parameter carries
`index`, `type` and `name` plus three optional fields: `at` (where the target
convention passes the argument, a register like `ecx` or a stack slot like
`[esp+4]`), `kind` (one of `signatures.PARAMETER_KINDS`) and `bits` (its
width).  All three are `null` until someone sets them: the model never fills a
field nobody set, `render_prototype` annotates only the fields a parameter
carries, and the convention table is exposed beside the model as the derived
`default_at`, never written into `at`.  The indices are reindexed from 0 after
every edit, so they stay contiguous, and `move_parameter` recomputes each
derivable `at` from the parameter's new index so a reorder never keeps a stale
arrival location.  `render_prototypes` is deterministic (functions by
name then id) and `export_prototypes` is the apply step: it writes that header
atomically to the explicit path the caller names and never picks a path inside
the workspace or the rebrew project.

`signature_history` holds one row per signature mutation, keyed by its own id
with `function_id`, `previous_json` (the signature row the mutation replaced,
or JSON `null` when the mutation created it), `source`, `actor` and
`created_at`.  `store` owns the table DDL and the row primitives
(`add_signature_history`, `list_signature_history`, `get_signature_history`),
while `signatures.py` records the previous state on every write (a manual edit,
an import, a delete) and `revert_history` restores exactly that state, clipping
its own revert into the history under source `revert` so the revert is
revertible; reverting a row whose state the signature already holds is a no-op.
The table cascades with its function.  The design mirrors `name_history`, the
rename history: the revert is recorded the same way, and the API, CLI and MCP
revert routes journal the row they replace and the history row they append, so
a `journal_action` revert puts both back.  A signature row that predates this
table still reads (its history list is empty) and its next edit records a
history entry whose previous state is that legacy row.

Path resolution lives in `_paths.py`: `project_root()` walks up for a
`reportal.toml` marker (like version control) and raises `WorkspaceNotFound`
when there is none, so a command run outside a workspace fails loud instead of
writing a stray `reportal.db`; `reportal init` writes its target marker and
database directly.  `reports_dir(binary_id)` resolves `<workspace>/reports/<binary_id>`
for generated engine reports.  `REPORTAL_DB` overrides the database path outright.  The
server creates the schema on first database access, so a missing `reportal.db`
is not a startup failure; a request that escapes `WorkspaceNotFound` answers a
JSON 500 `{"error": "no-workspace", ...}`.

`pdf.py` is the portal's own report export: reportal lays the pages out and
reportlab's canvas writes the file, so the objects, the page tree, the xref
table and the string escaping are the library's.  The canvas is built with
`invariant=1` and no page compression, so the same rows and the same date give
the same bytes and a test can still read the expected strings out of the
stream.  `render_report` walks
the stored scans in a fixed order and emits a section only when its scan is
present: title block (name, sha256, format/arch/size and the caller-supplied
generated date), coverage summary, fingerprint, capabilities, triage,
function triage, security, crypto, threat, secrets (counts and confidences,
never a value), behavior, protocols, hardening, remediation (rule name,
specificity, and the rule body capped at `RULE_BODY_LINE_CAP` lines) and
lineage.  Every other cap is a named module constant
(`MAX_ROWS_PER_SECTION`, `MAX_TECHNIQUE_ROWS`, `MAX_IOC_ROWS`,
`MAX_LINEAGE_ROWS`, `MAX_CELL_CHARS`), so a huge scan cannot produce a
thousand pages.  The layout wraps at the frame width -- measured with
reportlab's Helvetica metrics, not an approximation -- breaks to a new page
when the cursor passes `MARGIN_BOTTOM`, and repeats the binary name in the
header and `Page N of M` in the footer.  `PdfLayout` records what goes where
and `build()` replays it onto the canvas, which is how the footer can name a
total the layout only knows once it is complete.  The engine is consulted only for the
optional coverage summary and only when the `report` scan is absent; the API
and CLI render stored-only.  Output is deterministic for the same rows and
date: `render_report` writes the bytes, `write_report` writes them atomically
and returns `{"path", "bytes", "pages", "sections"}`, and `page_count` counts
the page objects.  The binary detail Report panel carries a Download PDF link
and a Generate PDF control that posts the route.

`collections` is a named group of binaries (`name` UNIQUE, plus `description`
and `scope`, and `updated_at`, the last time its fields, its membership or its
tags changed; `created_at` is when it was made and `_upgrade_schema` backfills
`updated_at` from it for a database that predates the column), so
`GET /api/collections?order=updated` and `reportal collections --order updated`
sort by the most recent change.  Every writer goes through `touch_collection`:
a rename or a scope change, a membership change that actually added or removed
something, and a tag change that did.  A call that changes nothing leaves the
timestamp alone, so the sort never reports a change that did not happen.

`collection_binaries` is its membership and `collection_tags` is
its tag links; both link tables cascade with the collection and with the binary
or tag they point at.  `POST /api/collections` and `reportal collection-new`
create one, `PATCH` renames it or sets its description and scope, `DELETE`
removes it with its links, and the membership and tag routes replace the whole
set rather than toggling one row: `PATCH .../binaries` makes the body's ids the
exact members, `DELETE .../binaries` removes the ids it names and keeps the
rest, and `PATCH .../tags` replaces the tags, creating the names that are new.
A member id that names no binary is refused before anything is written, so a
typo cannot half rewrite a collection.  Every one of those writes is one journal
action: a delete records its links before its own row, because a revert replays
newest-first and a link restored before its parent exists trips the foreign key
(`tests/test_collections_api.py` pins that order).

`users` is the local identity table, owned by `auth.py` and created by
`store.init_db` through `auth.ensure_schema` like the analysis log is.  One row
is one identity: a `name` (unique, case-insensitive, at most
`auth.MAX_USER_NAME` characters), a `role` from `auth.ROLES` (`viewer`,
`analyst`, `admin`, whose permissions are `auth.ROLE_PERMISSIONS`), the
`token_hash` (SHA-256 of the bearer token, written by `auth.hash_token`, the
token itself never stored or returned again), `created_at` and a `disabled`
flag that stops the token authenticating without deleting the row.  It is
deliberately not a directory of trust: no password, no expiry, no attempt
counter, because the credential is 256 bits of `secrets.token_urlsafe`
randomness and every comparison goes through `hmac.compare_digest`.
`auth.required()` decides whether the API gate is armed and is a configuration
read; the table only answers *which* user a presented token names.  The user
writes are journaled like every other write, so a create, a role change, a
rotation and a delete are each revertible.

`teams` and `team_members` are the identity side of visibility, owned by
`auth.py` alongside `users`.  A team is a name, an optional description and its
creation time; membership is the pair `(team_id, user_id)` and nothing else,
because a team here answers "who may write this" rather than carrying its own
roles.  `binaries` and `collections` each carry `owner_team_id` (nullable) and
`visibility` (`public`, the default, or `team`), added to databases that predate
them by the `_ADDED_COLUMNS` migration: a pre-team row is public and ownerless,
which is what it always meant.  Deleting a team resets the objects it owned to
public and ownerless rather than leaving a dangling scope, because a stale
`owner_team_id` would make them invisible to everyone.

`feedback` stores the local notes about reportal itself, the one identity-side
thing that is stored rather than derived: a nullable `user_id` (the
authenticated caller, `NULL` for a note written with auth off), the `actor` name
recorded with it, the trimmed `body` (bounded by `store.MAX_FEEDBACK_CHARS`) and
`created_at`.  It is written by `store.add_feedback` and read by
`store.list_feedback`, the notes are journaled like every other write, and the
activity feed that sits beside them (`src/reportal/activity.py`) stores nothing:
it merges the journal's actions with the analysis log at read time.

`journal_entries` gained an `actor` column with the same release: the name the
server recorded the request for (`server.authenticate` and
`journal.acting_as`), the literal `local` while token auth is off, and empty for
a write no request made.  An existing database gets the column through
`journal.ensure_schema`, which adds it before creating its index, and the rows
written before it read as an empty actor rather than an invented one.

`function_edges` and `user_strings` are the two per-function extras that carry
rows of their own, each owned by its module (`function_extras.py`,
`user_strings.py`) and created lazily by its own `ensure_schema`, the pattern
`sandbox_runs` uses.  A `function_edges` row is one analyst-declared callee edge:
the `function_id` that claims it, the `callee_name`, the `kind` (`call` or
`indirect`), a bounded `note`, `source` (`analyst`, so a reader can tell a claim
from a scan) and the time.  A row for the same `(function, callee, kind)` is
updated in place, so re-declaring an edge is not a duplicate, and both writes are
journaled.  A `user_strings` row is one analyst string at a scope: `scope_kind`
(`function` or `analysis`), `scope_id`, the `value`, a `kind` (`string`,
`import` or `export`), a bounded `note`, the `actor` and the time.  A value
already stored at its scope keeps its row and updates its note rather than
appending a duplicate, one scope holds at most
`user_strings.MAX_STRINGS_PER_SCOPE` values, and the whole-list replace is one
journaled action.  Neither table has a derived half: the literals and callees a
read reports beside these rows are text scans of the stored decompilation and are
never written down.

`sandbox_runs` is the detonation ledger, owned by `sandbox.py` and created
lazily by its own `ensure_schema` (the same pattern `journal.py` uses, which
keeps `store` from importing the sandbox module back).  One row is one run:
the `analysis_id` and `binary_id` it belongs to, the `sha256` it was run from,
the `runner` and the exact `argv_json`, the `caps_json` in force, the terminal
`status` (`running`, `finished`, `timed_out`, `failed`), the `exit_code`, the
`duration_ms`, the bounded `stdout`/`stderr` tails, `files_json` (what the
sample wrote into its one writable directory), `notes_json` and the times.  The
row is written as `running` before the sample starts and updated with the report
after, so a reader sees a run in progress and a process that dies mid-run leaves
the `running` row rather than a gap; the whole run is one journaled action, so a
revert removes the record.  A binary or analysis delete snapshots the table with
the rest of the cascade, and `journal.snapshot_rows` treats a table the schema
has not created yet as empty rather than failing, which is what lets a database
where nothing was ever detonated take the same path.


# Disaster recovery runbook

Everything here is derived from the code as it stands.  reportal is a
single-host application: one SQLite database plus a few workspace directories,
no replica and no managed storage.  The row store is `reportal.store` (schema in
`store._SCHEMA`), the request-scoped undo log is `reportal.journal`, the auto-run
undo log is `reportal.auto_mode`, and every inverse is replayed by
`reportal.effects.apply_undo_plan`.  A symbol named below is the checkable
source of the claim.

## State inventory

| State | Location | Written by | Rebuildable |
|-------|----------|-----------|-------------|
| Portal database | the marker's `[portal] db` name, `reportal.db` by default, override `REPORTAL_DB` (`_paths.db_path`); `reportal config` prints the path in force | `reportal init` -> `store.init_db` | No: the rows are the work |
| Action journal (revert record) | `journal_entries` table, same database | `journal.ensure_schema`, `journal.Journal.flush` | Partially: it is what makes another write revertible |
| Auto runs and attempts | `auto_runs`, `auto_tasks`, `auto_attempts` tables | `auto_store`; undo plan in `auto_runs.effects_json` | The undo plan is the recoverable part |
| Uploaded binaries | `<workspace>/binaries/<sha256><suffix>` (`_paths.binaries_dir`) | `api.upload_binary` | Yes, re-upload the same file (content-addressed) |
| Engine reports and PDF | `<workspace>/reports/<binary_id>/`, PDF at `pdf.REPORT_PDF_NAME` | the report route and `pdf` | Yes, re-run the report |
| Imported binary bytes | the rebrew project (`binaries.path`, `rebrew_contexts.project_dir`) | `reportal import-rebrew` | Outside reportal: re-run the import |
| Stored derived rows | `disasm_cache`, `decompilations`, `scans`, `binary_fingerprints`, `ai_artifacts` | routes and engine runs | `disasm_cache` and `scans` regenerate on demand; AI artifacts cost a model call |
| Similarity cache | process memory only (`similarity.PREPARED_CACHE_SIZE`) | `similarity` | Yes, recomputed on the next request |

reportal keeps no compile cache.  The rebrew engine's own compile cache lives in
the rebrew project, which reportal does not own or back up.

Auto mode switches the database to WAL (`auto_mode.DB_JOURNAL_MODE`), a
database-level setting that persists, with `auto_mode.DB_SYNCHRONOUS =
"NORMAL"`.  Once it has, `reportal.db-wal` and `reportal.db-shm` sit beside the
database.  Copy all three, or stop the server first and let a checkpoint fold
the WAL back in.

## What the code already guarantees

- A request-scoped write is journaled through `journal.journaled`, which flushes
  only on a clean exit; a failed request leaves no half-recorded action.  Entry
  statuses are `journal.STATUS_ACTIVE`, `STATUS_REVERTED` and `STATUS_PARTIAL`.
- Auto mode reserves a write's inverse before the write
  (`auto_store.reserve_auto_task_intents`), confirms it after
  (`confirm_auto_task_intents`), and folds the task's descriptors into the run's
  plan in the same transaction as its result (`auto_mode._record_task_outcome`,
  under `BEGIN IMMEDIATE`).
- Every inverse is a JSON descriptor applied by one dispatcher,
  `effects.apply_descriptor`, newest-first (`effects.apply_undo_plan`).  The
  journal, a pipeline run and an auto run all revert through it, so a revert
  works from a later process.

## What is revertible, and what is not

Revertible through the journal or the run's own plan:

- Binaries: upload, bulk actions, delete with its stored file, fingerprint.
- Tags, functions, names (`name_history`), scans and their on-demand analyses.
- Conversations, comments, knowledge documents and chunks, analyses and
  collections, families, data types and signatures, AI artifacts (summary,
  comments, type suggestions, rename suggestions), the graph rebuild and the
  report PDF file.

Not revertible, with the reason:

- Run-scoped plans: `run_pipeline`, `run_auto` and their reverts write no
  journal entry; the run's own plan is the record (`pipeline.revert_run`,
  `auto_mode.revert_auto_run`).
- The engine report site files under `reports/<binary_id>/`: only the `scans`
  row and the PDF are journaled; the next report run overwrites the rest.
- A user-named output file (`reportal yara/snort/stix --output`): the scan row
  is journaled, the caller's file is not.
- The bootstrap import (`reportal import-rebrew`) and `reportal init`: baseline
  row creation, not a per-request mutation.
- `disasm_cache`: a derived cache of a read.
- Embedding vectors: reverted with their chunks, but nothing re-embeds on
  restore.
- A graph backend a `graph-sync` already pushed to.
- An LLM model call: a revert removes the stored artifact, not the call that
  produced it.
- A file write past `journal.MAX_FILE_BYTES` (8 MiB): the descriptor carries no
  bytes, so the entry reverts `partial` and cannot restore the file.
- The file-write inverse does not check ownership
  (`effects._undo_file_write` removes whatever file is at the path).  Auto mode
  filters this where it reserves (`auto_mode._reservable_file`); a hand-rolled
  site does not.

## Recovery procedures

### A corrupt database

1. Stop the server (Ctrl+C on `reportal serve`).  Confirm nothing has it open.
2. Check integrity: `sqlite3 <workspace>/reportal.db "PRAGMA integrity_check;"`.
   A result other than `ok` means the file is damaged.
3. Restore `reportal.db` from the last good backup (with its `-wal` and `-shm`
   companions, or after a clean stop).  reportal ships no automatic backup and
   no `.bak` generation.
4. If a table is missing a column a newer release added, `store._upgrade_schema`
   adds it on the next `store.init_db`, which every command runs through
   `server.db` or `cli._db_path`.  A missing database is recreated empty by
   `store.init_db`; that restores the schema, not the rows.
5. Start the server and check `GET /api/health` (version, db path, counts).

### A half-run auto mode

1. Find the run: `GET /api/auto/runs` or the `auto_runs` table.  A run left
   `running` by a dead process is stale (`auto_mode.recover_auto_run`).
2. Recover it: `reportal auto-recover <run_id>`, or
   `POST /api/auto/runs/<run_id>/recover`.  Unfinished batch tasks close
   `failed` with reason `interrupted`, their recorded writes fold into the plan,
   and a write that was reserved but never confirmed is listed in
   `uncertain_intents` because it may or may not have reached the disk.
3. Read `uncertain_intents` before reverting.  A path there may exist or not.
4. Remove the run's writes: `reportal auto-revert <run_id>`, or
   `POST /api/auto/runs/<run_id>/revert`.  Statuses the run promoted are
   restored to the value it replaced.

### A wrong rename

1. List the function's rename history: `GET /api/functions/<id>/history`
   (`store.list_name_history`).
2. Revert the entry: `reportal revert <function_id> <history_id>`, or
   `POST /api/functions/<id>/history/<history_id>/revert`.  Both journal the
   reversal (`journal.journaled_revert_name`), so the revert is itself
   revertible.
3. To undo a whole request instead, revert its action:
   `reportal journal-revert --action <id>`, or `POST /api/journal/revert`.
   The action id is the `journal_action` field of the original response.

### A deleted binary

1. If the delete was journaled, the response carried `journal_action`.  Revert
   it: `reportal journal-revert --action <id>` or
   `POST /api/journal/revert {"action": "<id>"}`.  This restores the `binaries`
   row and, for an uploaded file, its bytes from the `file-restore` descriptor.
2. If the binary was larger than `journal.MAX_FILE_BYTES`, the entry reverts
   `partial` and the bytes are gone.  Re-upload the original file (the content
   hash dedupes it back to the same row) and re-run `reportal import-rebrew`
   for an imported target.
3. An imported binary's bytes live in the rebrew project, not in `binaries/`;
   deleting the row never deleted that file (`_paths.stored_binary_path`).

### An interrupted ingest

1. List recent actions: `reportal journal` or `GET /api/journal`
   (`journal.list_entries`), newest first.
2. Revert the interrupted ingest:
   `reportal journal-revert --action <id>` or `POST /api/journal/revert`.  The
   document row and its chunks go together; reverting an ingest deletes the
   chunks and their embedding vectors.
3. Re-ingest the same source.  Nothing re-embeds on a revert, so a restored
   chunk stays unranked until a new ingest embeds it.

## Restore drill

A backup that has never been restored is a hypothesis.  After setting up
backups, and periodically afterwards:

1. Copy a workspace to a scratch directory (database plus `-wal`/`-shm`, and
   `binaries/` and `reports/` if the portal stored them).
2. Point a new process at the copy:
   `REPORTAL_DB=<scratch>/reportal.db reportal stats`.
3. Check the schema opens and the counts look right (the same numbers
   `store.counts` reports through `GET /api/health`).
4. Spot-check one binary: `reportal report <binary_id> --output <scratch>/out`.
5. Record the date and the result next to the backup destination.

## Known gaps

- No automatic backup ships with reportal; the procedure above is manual.
- Backups hold the same secrets the workspace holds (the optional LLM key lives
  in the environment or `reportal.toml`, not in the database).
- A revert cannot be verified as observationally equivalent to a rerun; see the
  gaps section of [COMPONENTS.md](COMPONENTS.md).
- Recovery assumes one process over the database.  A second process writing
  while a revert runs is outside the model.

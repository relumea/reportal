# Disaster recovery runbook

Everything here is derived from the code as it stands.  reportal is a
single-host application: one SQLite database plus a few workspace directories,
no replica and no managed storage.  The row store is `reportal.store` (schema in
`store._SCHEMA`), the request-scoped undo log is `reportal.journal`, the auto-run
undo log is `reportal.auto_mode`, and every inverse is replayed by
`reportal.effects.apply_undo_plan`.  Whole-workspace durability is
`reportal.backup` (`reportal backup` / `reportal restore` / `reportal
backup-info`).  A symbol named below is the checkable source of the claim.

## Objectives (RPO / RTO)

| Objective | Value | Why |
|-----------|-------|-----|
| RPO (how much work you can lose) | One backup interval | There is no continuous replication.  With the shipped daily timer (`deploy/reportal-backup.timer`) that is up to about 24 hours of writes; a tighter cron or timer shortens it.  With no scheduled backup, RPO is unbounded. |
| RTO (how long until service returns) | Time to place a host, install the package, and `reportal restore --overwrite --yes` | Dominated by archive size and disk speed.  Measure it during the restore drill below; do not guess from the backup job's exit code. |

Point-in-time recovery inside one interval does not exist: a backup is a full
workspace snapshot, not a WAL shipping stream.  Logical corruption that sat in
production longer than the interval is only recoverable if an older archive was
kept.

## State inventory

| State | Location | Written by | In `reportal backup`? | Rebuildable |
|-------|----------|-----------|----------------------|-------------|
| Portal database | `[portal] db` / `REPORTAL_DB` / `reportal.db` (`_paths.db_path`) | `store.init_db` and every write path | Yes (SQLite backup API after `wal_checkpoint(TRUNCATE)`) | No: the rows are the work |
| Action journal | `journal_entries` in the portal database | `journal.Journal.flush` | Yes (same file) | Partially: it is what makes another write revertible |
| Auto runs and attempts | `auto_runs`, `auto_tasks`, `auto_attempts` | `auto_store` | Yes | The undo plan is the recoverable part |
| Secret store | tables in the portal database | `secret_store` | Yes (plaintext in the archive) | No |
| Uploaded binaries | `<workspace>/binaries/<sha256><suffix>` | `api.upload_binary` | Yes | Re-upload (content-addressed) |
| Uploaded debug symbols | `<workspace>/symbols/<prefix>/<sha256>` and `symbol_files` | symbol import via API, CLI or MCP | Yes; local file paths are relocated on restore | No: original symbol bytes cannot be derived from the binary |
| Job backlog | `jobs` in the portal database | `jobs` | Yes | In-process workers are not backed up; do not start workers during a restore drill |
| Engine reports and PDF | `<workspace>/reports/<binary_id>/` | report route / `pdf` | Yes | Re-run the report |
| Workspace marker | `reportal.toml` | `reportal init` / operators | Yes | Re-create; secrets in env are not in the file |
| Imported binary bytes | rebrew project (`binaries.path`, `rebrew_contexts.project_dir`) | `reportal import-rebrew` | No (path left external on restore) | Outside reportal: re-run the import |
| Derived rows | `disasm_cache`, `decompilations`, `scans`, `ai_artifacts`, … | routes / engines | Yes | Caches regenerate; AI artifacts cost a model call |
| Similarity cache | process memory (`similarity.PREPARED_CACHE_SIZE`) | `similarity` | No | Recomputed on the next request |
| rebrew `coverage.db` / compile cache | rebrew project | rebrew | No | Re-run analysis in that project |

Auto mode may leave the database in WAL (`auto_mode.DB_JOURNAL_MODE`) with
`synchronous = NORMAL`.  `reportal backup` checkpoints before copying, so the
archive does not depend on shipping `-wal` / `-shm` sidecars.  A hand copy of
the live files still must include those sidecars or stop the server first.

## What is protected

- `reportal backup` writes one gzip tar of the live database (configured path
  included), `reportal.toml`, `binaries/`, `symbols/`, and `reports/`, with a manifest that
  `reportal restore` checks before touching the workspace (`backup.create`,
  `backup.restore`).  Round-trip coverage is `tests/test_backup.py`.
- The default archive path is a dated file under `../reportal-backups/` beside
  the workspace, never inside it.  Writing inside the workspace is refused so
  an instance wipe of the workspace directory cannot take the only copy.
- `deploy/reportal-backup.service` plus `deploy/reportal-backup.timer` are the
  scheduled form: daily into `/srv/backups/` with a UTC instant filename, failing
  the unit when the archive is missing, empty, or refused by
  `reportal backup-info`, then pruning archives older than 14 days.

## Failure domains (accepted unless the operator moves the archive)

| Disaster | Posture |
|----------|---------|
| Instance / workspace directory loss | Recoverable if an archive exists outside that directory |
| Host disk / same-volume loss | Not covered by the default sibling `reportal-backups/` path; keep `/srv/backups` (or equivalent) on another volume or host |
| Zone / region loss | Out of scope in-tree; copy archives off-box |
| Malicious or fat-finger delete of data and backups | One account that can write both can delete both; use a separate backup principal, append-only storage, or offline copies |
| Logical corruption for longer than retention | Keep multiple dated archives (timer prunes past 14 days); there is no PITR inside one file |
| Bad deploy / schema upgrade | Additive upgrades via `store._upgrade_schema`; roll back by restoring a pre-upgrade archive after stopping the service |

## What the code already guarantees (row-level undo)

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

### Instance loss or corrupt database (whole workspace)

1. Stop the service: `systemctl stop reportal` (or Ctrl+C on `reportal serve`).
2. Optional integrity check on a suspect file:
   `sqlite3 <db> "PRAGMA integrity_check;"` (anything other than `ok` means the
   file is damaged).
3. Inspect the archive without writing: `reportal backup-info /path/to/archive.tar.gz`.
4. Restore into the workspace directory (destructive):
   `cd /srv/reportal && reportal restore /srv/backups/reportal-YYYY-MM-DD.tar.gz --overwrite --yes`.
   Paths that lived under the archived root are rewritten; imported binaries
   whose files lived outside that root are reported and left pointing where they
   were.
5. `reportal doctor` then `systemctl start reportal`.  Confirm `GET /api/health`
   (version, db path, counts).

`store.init_db` recreates an empty schema when the file is missing; that restores
the tables, not the rows.  Prefer `reportal restore`.

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

A backup that has never been restored is a hypothesis.  After enabling the
timer (or any schedule), and periodically afterwards:

1. Copy a recent archive to an isolated scratch host with the archived reportal
   version installed. Do not mount production paths or supply production credentials.
   `reportal backup-info /path/to/archive.tar.gz --json` gives the version and members.
2. In a fresh shell, create a private workspace with `umask 077`,
   `mkdir /tmp/reportal-drill`, then `cd /tmp/reportal-drill`.
   Set `export REPORTAL_DB=/tmp/reportal-drill/reportal.db` before `reportal init`.
   Keep this override for every drill command: the archived marker may name an
   absolute production database path.
3. `time reportal restore /path/to/archive.tar.gz --overwrite --yes`
4. `sqlite3 "$REPORTAL_DB" 'PRAGMA integrity_check;'` must return `ok`.
   Run `reportal stats` and compare against statistics recorded at backup time,
   not against a changing production database. Manifest `counts` are file counts,
   not database row counts.
5. Compare restored binaries, symbols and reports against the manifest members;
   spot-check their bytes. Do not start the server, job workers or engine reports:
   restored jobs and external project paths can still refer to production work.
6. Record date, archive name, byte size, wall-clock restore time (your RTO sample),
   integrity result and pass/fail next to the backup destination.
7. Delete only the scratch workspace and unset `REPORTAL_DB`.

Automated proof in CI is the round trip in `tests/test_backup.py`; the drill
above is what proves the operator path and the off-box archive still load.

## Scheduling and failure visibility

```bash
sudo mkdir -p /srv/backups
sudo chown reportal:reportal /srv/backups
sudo cp deploy/reportal-backup.service deploy/reportal-backup.timer /etc/systemd/system/
# edit both if the workspace is not /srv/reportal
sudo systemctl daemon-reload
sudo systemctl enable --now reportal-backup.timer
systemctl list-timers reportal-backup.timer
systemctl --failed
journalctl -u reportal-backup.service -n 50
```

A successful run leaves a non-empty
`/srv/backups/reportal-YYYYMMDDTHHMMSSZ.tar.gz` named for the UTC instant.  The
oneshot runs `test -s` and `reportal backup-info` on that path so a zero-byte or
corrupt write fails the unit, then `reportal backup-prune --keep-days 14`.
`reportal doctor` warns when no archive under `../reportal-backups/` or
`/srv/backups` is younger than 48 hours.

## Known gaps

- No continuous replication or PITR; RPO is the backup interval.
- Archives are not encrypted; they hold every secret the workspace database
  holds (`docs/THREAT_MODEL.md`).  LLM keys in the environment are not in the
  archive unless also stored in the secret store.
- Default and timer destinations are still the same host unless the operator
  copies archives elsewhere.
- A revert cannot be verified as observationally equivalent to a rerun; see the
  gaps section of [COMPONENTS.md](COMPONENTS.md).
- Recovery assumes one writer over the database during `reportal restore`.
  Stop the service first.

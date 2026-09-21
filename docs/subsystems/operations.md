# Operations

Sources: src/reportal/backup.py, src/reportal/doctor.py, src/reportal/pdf.py

Workspace backup and restore, pre-flight readiness, and the deterministic PDF summary. Backup is
the only module that reads or writes a whole workspace, doctor answers "can this install serve"
without starting one, and the PDF renderer lays out pages while reportlab owns the file format.

## Vocabulary

- A backup manifest carries `format`, `format_version`, `version`, `created_at`, `root`,
  `database`, `members` and `counts`. `MANIFEST_NAME` is `manifest.json`, `FORMAT` is
  `reportal-backup`, and the database member inside the archive is always `reportal.db`.
- `BackupError.code`: `invalid-backup`, `unsafe-backup`, `no-workspace`.
- A doctor check is `{"name", "status", "detail", "hint"}` with a status of `ok`, `warn` or
  `fail`; the report's own `status` is `ok` or `degraded`. `REQUIRED_TABLES` names the four tables
  the schema check needs.
- `pdf.PdfLayout` owns the page cursor and `RenderedReport` the result; `REPORT_PDF_NAME` is
  `report.pdf`. Per-section caps are `MAX_ROWS_PER_SECTION`, `MAX_TECHNIQUE_ROWS`, `MAX_IOC_ROWS`
  and `MAX_LINEAGE_ROWS`.

## Wiring

- CLI: `backup`, `restore`, `backup-info`, `backup-prune`, `doctor`, `deploy-units`,
  `report-pdf`. No HTTP route for backup or restore. `deploy-units` resolves repository
  `deploy/` or the packaged `reportal/deploy/` copy, and optionally copies with `--write`.
- Routes: `GET /api/doctor`; `POST` and `GET /api/binaries/{binary_id}/report/pdf`; and
  `GET /api/binaries/{binary_id}/report/pdf/status`.
- MCP: `get_doctor`, `generate_pdf_report`, `get_pdf_status`.
- A PDF is written into `reports_dir(binary_id) / pdf.REPORT_PDF_NAME` by `jobs.render_pdf`
  under kind `report-pdf`, so the route and queued job produce and journal the same file.
- The wheel's `package-data` carries `deploy/*` after `scripts/sync_packaged_deploy.py`;
  `scripts/check_wheel.py` fails when any of `doctor.DEPLOY_UNIT_FILES` is missing.
  `scripts/check_sdist.py` fails when the sdist omits the root `deploy/` templates or
  ships host-dependent `*.br` / `*.map` siblings.

## Invariants

- The database is copied through SQLite's backup API after a `wal_checkpoint(TRUNCATE)`, never
  as a plain file copy (`tests/test_backup.py`).
- An `--output` inside the workspace is refused (`tests/test_backup.py`).
- `read_manifest` refuses an unreadable archive, a missing or unknown-version manifest, a member
  the manifest does not name, and a member path that leaves the archive root
  (`tests/test_backup.py`).
- A restore stages then moves the database last; an existing database needs overwrite
  (`tests/test_backup.py`).
- `backup-prune` deletes only reportal-looking archive names, refuses a workspace directory, and
  always keeps the newest `DEFAULT_KEEP_MIN` archives (`tests/test_backup.py`).
- `create` re-opens the archive through `read_manifest` before returning, so an empty or
  unreadable write fails the command (`tests/test_backup.py`).
- Doctor's `backup` check warns when no archive under `../reportal-backups/` or `/srv/backups` is
  younger than `backup.FRESH_SECONDS`, empty, or refused by `read_manifest`, and never fails the
  start gate (`tests/test_doctor.py`).
- Every doctor check is a read; a `warn` never changes the exit code while a `fail` always does
  (`tests/test_doctor.py`).
- A PDF is rendered with `invariant=1` and no page compression (`tests/test_pdf.py`).
- A section whose scan is absent is omitted rather than rendered empty (`tests/test_pdf.py`).

## See also

- [ARCHITECTURE.md: Backup and restore](../ARCHITECTURE.md#backup-and-restore)
- [ARCHITECTURE.md: Readiness](../ARCHITECTURE.md#readiness)
- [DR_RUNBOOK.md](../DR_RUNBOOK.md)

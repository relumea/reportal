# Jobs

Sources: src/reportal/jobs.py

Queued operations: one `jobs` row per run, its status and result, cancel, and the in-process
pool that drains the queue. A queued scan is journaled like the synchronous route it wraps; a
failure is a stored `failed` job, never an exception out of the worker.

## Vocabulary

- `JobKind`: `name`, `label`, `scan_kinds` (a `scans` kind, per-domain map, or `None`), `run`,
  `params`, optional `perform` / `perform_progress`. `scan_kind_for(params)` resolves domains.
- `JOB_KINDS` from `builtin_kinds()`; `job_kind_for_scan` and `queue_stored_scans` map stored
  scans onto it. `ProgressPerform` is a `perform` with a `(done, total)` sink.
- Statuses: `STATUS_QUEUED`, `STATUS_RUNNING`, `STATUS_DONE`, `STATUS_FAILED`,
  `STATUS_CANCELLED`; `LIVE_STATUSES` is queued/running.
- `jobs` columns: `kind`, `binary_id`, `status`, `progress`, `steps_total`, `message`,
  `params_json`, `result_json`, `error`, timestamps, `submitted_by`, `submitted_by_user_id`,
  `request_id` (HTTP id at submit, when any).
- `JobWorker`: bounded daemon threads, each with its own SQLite connection; `_progress_sink`
  writes at most once per `PROGRESS_REPORT_EVERY` steps.

## Wiring

- Routes: `GET /api/jobs`, `GET /api/jobs/<id>`, `POST /api/jobs`, `POST /api/jobs/<id>/cancel`,
  `POST /api/jobs/run`, `GET /api/jobs/<id>/events` (SSE via `events`).
- CLI: `reportal jobs`, `job`, `job-submit`, `job-run`, `job-cancel`.
- MCP: `list_jobs`, `get_job`, `submit_job`, `cancel_job`, `run_jobs`.
- `REPORTAL_JOBS_POOL` disables the pool when falsey; `observability.record_job` counts each run
  and `SLOW_JOB_MS` marks a slow one. `submit` stores `current_request_id()`; `execute` rebinds
  it on a pool thread so `job failed` / `job slow` still carry
  `observability.request_id_suffix()`.
- The `flirt` kind matches against the indexed FLIRT catalog with no engine call.

## Invariants

- Only a `queued` job can be cancelled; cancelling a `running` one raises `ValueError`, and the
  status check is the `UPDATE` predicate so a racing worker cannot leave a cancelled job running
  (`tests/test_jobs.py`).
- A second submit of one kind, binary and `params_json` while a matching job is live returns that
  row instead of inserting another (`tests/test_jobs.py`).
- `submit` refuses an unknown kind, an unknown binary, a parameter the kind does not take, and a
  queue at `MAX_QUEUED_JOBS`; `list_jobs` bounds `limit` at `MAX_JOB_LIMIT`
  (`tests/test_jobs.py`).
- `execute` never raises: a failure becomes status `failed` with `error` bounded at 500
  characters.
- A successful queued run is journaled like its route and is revertible through the journal
  action it attaches (`tests/test_jobs.py`).
- Requeue queues a job for each stored scan that has a job kind and skips the rest
  (`tests/test_analyses_api.py`, `tests/test_jobs.py`).
- `_prune` keeps only the newest `MAX_KEPT_JOBS` terminal rows.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#process-layout)
- [API.md](../API.md)
- [DATA_MODEL.md](../DATA_MODEL.md)

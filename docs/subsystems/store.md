# Store

Sources: src/reportal/store.py, src/reportal/analysis_log.py, src/reportal/clock.py

This subsystem owns reportal's only persistent state: the SQLite schema, the typed CRUD, search,
the upload and extract helpers, and the structured analysis log. Readers return plain `dict` rows
so the JSON API serializes them without a mapping layer; writers commit on their own.
`analyses.status` is the source of truth for an analysis's lifecycle and every writer routes
through it.

## Vocabulary

- `store.ANALYSIS_STATUSES` (`pending`, `processing`, `done`, `failed`, `cancelled`) and
  `TERMINAL_STATUSES`: the closed lifecycle set `create_analysis` and `update_analysis_status`
  enforce.
- `store.SCAN_KIND_*` and `SCAN_STATUS_DONE`: the scan kinds stored one row per `(analysis, kind)`;
  `set_scan` upserts and `get_scan_params` reads the caller's recorded inputs.
- `MATCHED_STATUSES`, `IMPORTED_NAME_SOURCE` (`import`), `FUNCTION_SORT_COLUMNS`, `BINARY_ORDERS`,
  `ANALYSIS_ORDERS`, `WORKSPACE_FILTERS`, `SEARCH_KINDS`, `MIN_SHA256_PREFIX`.
- The caps: `MAX_ANALYSIS_LIMIT` (1000), `MAX_SEARCH_LIMIT` (500), `MAX_FUNCTION_LIMIT` (1000),
  `MAX_BINARY_NOTES` (2000), `BUSY_TIMEOUT_MS` (30000).
- `connect(path)`, `init_db(path)` and `open_db()`: the opener (WAL, busy timeout), the schema
  creator (which applies `_ADDED_COLUMNS`, `_ADDED_INDEXES` and `_BACKFILLS` to a database that
  predates a column), and the workspace opener HTTP/MCP/CLI share so non-HTTP surfaces do not
  import the FastAPI module for a connection.
- `analysis_log.SEVERITIES` (`info`, `warn`, `error`), `TABLE` (`analysis_log_entries`),
  `append_entry` (the only writer), `list_entries` (newest first, `MAX_LOG_LIMIT` 1000, true total
  beside the page) and `list_recent`.
- `store.InvalidFeedbackError`, `store.SearchError` and `store.compile_regex`: the refusals a
  listing raises for an unusable filter.
- `store.history_actor_names` resolves the display names history rows point at; history views
  pair it with `clock.relative_age`, so attribution survives a user delete the way the stored
  login name does.

## Wiring

Tables include `binaries`, `analyses`, `functions`, `matches`, `name_history`, `collections`,
`tags`, `scans`, `decompilations`, `ai_artifacts`, `comments`, `conversations`, `messages`,
`pipeline_runs`, `auto_runs`, `documents`, `chunks`, `graph_nodes`, `graph_edges`, `data_types`,
`function_signatures`, `secrets` and `analysis_log_entries`. Upload files land under
`<workspace>/binaries/` as `<sha256><suffix>`. Forms: `scan_span`, `set_scan`, `begin_scan`,
`fail_scan`, `imported_functions`.

## Invariants

- Functions are UNIQUE on `(analysis_id, va)`; `upsert_function` is idempotent and
  `add_function_if_absent` never replaces a stored row (`tests/test_store.py`).
- Binaries dedupe by sha256, and by name and path when the bytes are unavailable
  (`tests/test_store.py`, `tests/test_upload.py`).
- An unknown analysis status is refused rather than stored, and every status change appends one log
  entry naming the old and the new value (`tests/test_analysis_log.py`).
- An out-of-range log `limit` or a negative `offset` raises `ValueError`; a message is collapsed to
  one bounded line (`tests/test_analysis_log.py`).
- Log rows cascade with their analysis (`tests/test_analysis_log.py`).

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#store)
- [DATA_MODEL.md](../DATA_MODEL.md)

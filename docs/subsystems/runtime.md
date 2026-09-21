# Runtime

Sources: src/reportal/__init__.py, src/reportal/__main__.py, src/reportal/webapp.py, src/reportal/server.py, src/reportal/observability.py, src/reportal/instance.py

This subsystem owns the process: the packaged version, the composition root that mounts the
routers, the one FastAPI application every route shares, request correlation, and the instance
description that says what this install can do. Its contract is the response envelope, the auth
gate, and the JSON 404 a path nothing matches still answers.

## Vocabulary

- `JsonError`: both a Starlette response and a raisable exception, carrying `error`, `detail` and
  `doc_url`; `json_error` builds it and `json_response` serializes a payload.
- `_reportal_headers`: the single HTTP middleware. It validates the Host header, authenticates,
  mints the request id, sets security headers, records counters and applies
  `disclosure.redact_payload`.
- `_scoped_object` and `_enforce_scope`: resolve the object a path names (eleven kinds, each
  through its owning binary) and refuse a read as that object's 404 and a write as 403
  `scope-forbidden`.
- `_CALLER` and `ACCEPT_ENCODING`: ContextVars for redact/compress without a request argument;
  `accepts_gzip` / `accepts_br` parse the header. `server.db()` wraps `store.open_db` for HTTP;
  MCP tools call `store.open_db` directly.
- `observability.REQUEST_ID_HEADER` (`X-Request-Id`), `SLOW_REQUEST_MS`, `SLOW_JOB_MS`,
  `http_snapshot`, `job_snapshot`, `should_log_completion`, `request_id_suffix`;
  `configure_logging` attaches a stderr handler (uvicorn leaves root bare).
- `instance.describe()`: version, engine, LLM, database, `features()`, `limits()` and the MCP
  totals; `MAX_UPLOAD_BYTES`, `MAX_UPLOAD_FILES` and `MAX_FUNCTION_SIZE` live here.

## Wiring

`webapp` includes `api.router` and `ui.router` on `server.app`. Routes: `GET /api/health`,
`GET /api/config`, `GET /api/doctor`, and the mount at `MCP_PATH` (`/mcp`) with methods `GET`,
`POST` and `DELETE`, answering 503 `mcp-unavailable` without a live lifespan manager.
Environment: `REPORTAL_DB`, `REPORTAL_AUTH`, `REPORTAL_PROFILE`, plus the metering hook keyed by
the caller's organisation. `python -m reportal` calls `cli.main()`; `reportal.__version__` is the
FastAPI version.

## Invariants

- The middleware is the only auth gate; a route added later is behind it without being told
  (`tests/test_auth.py`).
- Every `/api` error body keeps `{"error", "detail", "doc_url"}`; an unhandled `/api` failure is
  500 `internal server error` (`tests/test_api.py`, `tests/test_error_docs.py`).
- A 404 is never a redirect: `redirect_slashes=False`, and the handlers fold FastAPI's own
  refusals (`tests/test_api.py`).
- Every `/api` response echoes `X-Request-Id`; a forged id is replaced, never trusted
  (`tests/test_observability.py`).
- `GET /api/health` is `ok` or `degraded` (same vocabulary as `reportal doctor`) while
  HTTP stays 200; a database that is not writable or fails to open is named in
  `failures` (`tests/test_api.py`).
- `describe()` is a pure read: no engine call, no network call, no write (`tests/test_instance.py`).

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#http-surface)
- [API.md](../API.md)

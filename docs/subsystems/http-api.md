# HTTP API

Sources: src/reportal/api.py

This subsystem owns every `/api/*` JSON route. One module declares the router and the helpers its
handlers share, so a route is a plain `def` on the threadpool, reads its body through a `Depends`
dependency and returns a `Response`. The contract is uniform: a success body is the payload, and a
refusal is the `{"error", "detail", "doc_url"}` envelope built by `server.json_error`.

## Vocabulary

- `router`: the `APIRouter` `webapp` includes on `server.app`; 341 route decorators are declared
  here.
- Body dependencies from `server`: `json_body` for a required JSON object and `optional_json_body`
  where an absent body reads as `{}`.
- Upload vocabulary: `UPLOAD_FORMATS` (`pe`, `elf`, `blob`), `UPLOAD_ARCHITECTURES` (`x86_32`,
  `x86_64`, `arm64`), `UPLOAD_COMPILERS` (from `filetypes.toolchain_names()`), and the caps
  `MAX_UPLOAD_BYTES` and `MAX_UPLOAD_FILES` re-exported from `instance`.
- Download vocabulary: `BINARY_CONTENT_TYPES`, `BINARY_DOWNLOAD_CHUNK_BYTES` (1 MiB),
  `BINARY_DOWNLOAD_CACHE_CONTROL`, and `_streamed_binary`, the one streamed-response helper the
  download and the analysis-bytes route share.
- `_last_auto_run`, `_jobs_health` and `_database_health`: the probe helpers behind
  `GET /api/health`.
- The `_query_*` helpers: one per validated parameter family, reading `request.query_params`.

## Wiring

Load-bearing routes: `GET /api/health`, `GET /api/doctor` (optional `?port=`, 400 for a non-integer
or out-of-range value), `GET /api/config` (the `instance.describe()` payload), `POST /api/binaries`
(the multipart upload and its batch form), `GET /api/binaries/<id>/download`,
`POST /api/binaries/<id>/extract`, `GET /api/search`, `GET /api/docs` and `GET /api/docs/<slug>`.
`docs/API.md` is the exhaustive route table; this page does not restate it. Stored-only scan GETs
answer 404 `no-scan`; the matching POSTs run the engine and store.

## Invariants

- Every declared route has a row or a covered family in `docs/API.md`, and the page names no route
  the router lacks (`tests/test_api_docs.py`).
- A request for an undeclared path or a disallowed method is the JSON 404 envelope, never a
  redirect (`tests/test_api.py`).
- A malformed body is 400 `invalid JSON body` or 400 `request body must be a JSON object`
  (`tests/test_api.py`).
- The upload keeps sha256 dedupe and content-addressed publication; a repeat answers the stored row
  (`tests/test_upload.py`, `tests/test_upload_batch.py`).
- New object-id routes carry scope coverage, or `tools/audit_scope.py` fails the lint target.

## See also

- [API.md](../API.md)
- [ARCHITECTURE.md section](../ARCHITECTURE.md#http-surface)

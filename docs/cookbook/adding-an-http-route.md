# Adding an HTTP route

Prerequisites: read the route helpers in [server.py](../../src/reportal/server.py) (`json_body`,
`json_error`, `json_response`, `optional_json_body`), the query helpers (`_query_int`,
`_query_bool`, `_query_text`, `_invalid_query`) and the body helpers (`_require_int`,
`_optional_str`) in [api.py](../../src/reportal/api.py), plus the scope section of
[ARCHITECTURE.md](../ARCHITECTURE.md#identity-and-the-api-gate).

## Steps

1. Decide the method and path. Every route lives under `/api/` and mounts on `router` in
   `src/reportal/api.py`. A path segment naming a stored row is `{binary_id}`, `{function_id}` and
   so on.
2. Declare the handler with the router decorator and a return annotation:

   ```python
   @router.get("/api/binaries/{binary_id}/symbols")
   def binary_symbols(binary_id: int) -> Response:
   ```

   A handler that reads a JSON body takes `body: dict[str, Any] = Depends(json_body)`, or
   `optional_json_body` when an absent body is `{}`. A handler that reads the query string takes
   `request: Request` and calls `_query_text`, `_query_int`, `_query_bool` or `_query_flag`. An
   unknown value for a closed set is answered by `_invalid_query`.
3. Validate the body through `_require_int`, `_require_str`, `_optional_str`, `_optional_int`,
   `_optional_bool` and `_optional_int_list`. Each raises `json_error(400, error=...)` with a code
   the catalogue already names (`docs/ERRORS.md`), for example `f"{key} must be an integer"` or
   `"invalid binary"`.
4. Open the store with `with contextlib.closing(_open()) as conn:` and use the `store` function for
   the row. A missing row answers `json_error(404, error="binary not found", detail=...)`.
5. Return `json_response(payload)` for success and `json_error(status, error=..., detail=...)` for
   refusal. A `JsonError` may be raised instead of returned; the app's handler serves it the same
   way.
6. Do not repeat a scope check. The `_reportal_headers` middleware calls `server._enforce_scope`,
   which reads the object id off the path through `_SCOPED_PATHS`: a read of a team-scoped object
   the caller cannot see answers the object's own 404, and a write answers 403 `scope-forbidden`.
   Extend `_SCOPED_PATHS` (and `_NOT_FOUND_NAME`) when the route names a new object kind, not the
   handler.
7. Declare the route in `tools/audit_scope.py` when its id is not a gate prefix: add the
   `METHOD /api/path` key to `HANDLER_SCOPED` with the mechanism (`visible_to`, `allowed`,
   `may_write`, `_visible_binary`) or add a new id name to `UNSCOPED_ID_NAMES` with its reason.
8. Add a table row to `docs/API.md`: `| \`/api/binaries/<id>/symbols\` | GET | ... |`. The row path
   is normalized (`{binary_id}` and `<id>` both count as `<id>`), and a row is required per method.
   A route whose last segment is a parameter may be covered by one concrete family row.
9. Journal a write with `journal.new_action()` and `journal.journaled(conn, action)`, then attach
   `log.attach(payload)` to the response body, as `rename_binary` does.

## Verify

1. `.venv/bin/python -m pytest tests/test_api_docs.py -q` proves every live route has a row in
   `docs/API.md` and every row names a live route.
2. `.venv/bin/python tools/audit_scope.py` proves every object-id route is gate- or
   handler-scoped.
3. `.venv/bin/python -m pytest tests/test_api.py -q` exercises the route handlers.
4. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#http-surface)
- [ARCHITECTURE.md section](../ARCHITECTURE.md#identity-and-the-api-gate)
- [API.md](../API.md)

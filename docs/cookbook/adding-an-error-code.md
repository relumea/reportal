# Adding an error code

Prerequisites: read [error_docs.py](../../src/reportal/error_docs.py) (`ERROR_DOC_ANCHORS`,
`PARAMETRIZED_DOC_ANCHORS`, `doc_anchor`, `doc_url`, `heading_anchor`), the `json_error` helper in
[server.py](../../src/reportal/server.py), and [ERRORS.md](../ERRORS.md).

## Steps

1. Pick the code string. A code is the `error=` value a caller sees: a fixed identifier such as
   `no-scan` and `export-exists`, or the prose a route already answers, such as `binary not found`
   and `invalid binary`. Codes are not renamed once shipped, because the `doc_url` and the
   catalogue key on the exact string.
2. Add a `### <heading>` section to `docs/ERRORS.md` under the family it belongs to (`## Request
   shape`, `## Uploads and archives`, and so on), stating what the caller did and what to do next.
3. Map the code to that section's anchor in `ERROR_DOC_ANCHORS` in `src/reportal/error_docs.py`:

   ```python
   "no-import-cache": "no-import-cache",
   ```

   The anchor is `heading_anchor(heading)`: the heading lowercased, with every character outside
   `[a-z0-9 _-]` removed and spaces replaced by hyphens. Two spellings of one failure share one
   anchor (the page names both), as `data type not found` and `data-type-not-found` do.
4. For a code built at the call site from a field name (`f"{key} must be an integer"`,
   `f"invalid {name}"`), do not add an entry. Add or extend a pattern in
   `PARAMETRIZED_DOC_ANCHORS` so the whole family shares `INVALID_PARAMS_ANCHOR`.
5. Raise the code through the surface's error channel: `json_error(400, error="no-import-cache",
   detail=...)` in a route, or the module's own error class (`ToolError` for MCP, `_cli_fail` for
   the CLI). The response carries `doc_url` automatically, and a code with no catalogue entry gets
   `null` rather than a dead link.
6. Add the section to `## Contents` in `docs/ERRORS.md` if the page lists one, so the code is
   reachable from the top.

## Verify

1. `.venv/bin/python -m pytest tests/test_error_docs.py -q` proves every literal `error=` and
   `code=` in the package has a catalogue entry, every anchor in the catalogue has exactly one
   matching `###` heading, and every documented heading is a catalogue anchor.
2. `.venv/bin/python -m pytest tests/test_error_docs.py -q -k TestErrorEnvelope` proves an error
   body from each status family carries the live `doc_url`.
3. Request the failing path and read the body: `{"error": ..., "detail": ..., "doc_url": ...}`, with
   `doc_url` ending in the new anchor.
4. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#http-surface)
- [ERRORS.md](../ERRORS.md)

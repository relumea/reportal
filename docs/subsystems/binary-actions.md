# Binary actions

Sources: src/reportal/binary_actions.py, src/reportal/bulk_actions.py, src/reportal/surface.py

This subsystem owns the shared write paths over a binary: journaled extract, carve and unpack, the
bulk actions over binaries, functions and analyses, and the pre-read checks every surface routes
through. Each action is written once so the HTTP route, the CLI command and the MCP tool cannot
diverge, and a caller that passes a `journal.Journal` gets a revertible entry for every row and file
it touches.

## Vocabulary

- `binary_actions.ExtractError`: a status, a fixed error code and a detail, which each surface maps
  to its own envelope. `download_filename` sanitizes a stored name for a download.
- `bulk_actions`: `BINARY_ACTIONS` (`add_tag`, `remove_tag`, `delete`), `FUNCTION_ACTIONS`
  (`rename`, `clear_matches`) and `ANALYSIS_ACTIONS`. `MAX_BULK_IDS` is 500. A prefix rename records
  its own history source `BULK_RENAME_SOURCE` and actor `BULK_RENAME_ACTOR`.
  `BINARY_DELETE_SNAPSHOTS` lists the rows a binary delete removes, so that delete is revertible.
- `bulk_actions.resolve_ids` de-duplicates a requested list and rejects a non-integer, an empty list or
  one past `MAX_BULK_IDS`.
- `surface.Fail` is the `(status, error, detail)` factory a helper raises through, so the rule lives
  here once while each surface keeps its own codes. `require_binary`, `binary_file`,
  `project_context` and `engine` are the pre-read checks; `journaled_row_write`,
  `journaled_signature_write` and `journaled_data_type_write` are the shared journal helpers.

## Wiring

- Routes: `POST /api/binaries/<id>/extract`, `POST .../firmware`, `POST .../firmware/extract`, `POST
  .../unpack`, `POST /api/binaries/bulk`, `POST /api/analyses/bulk`, `POST /api/functions/bulk`,
  `GET .../download`, `GET .../download-zipped`.
- CLI: `extract`, `firmware`, `firmware-extract`, `unpack`, `unpack-info`, `bulk-tag`,
  `bulk-delete`, `bulk-prefix`, `analysis-bulk-tag`, `download`.
- MCP: `extract_archive`, `extract_firmware_regions`, `run_unpack`, `get_unpack`, `bulk_binaries`,
  `bulk_functions`.
- `unpack_binary` registers the rebuilt image by content hash like an upload and stores the
  provenance as the `unpack` scan; the packed source is never touched.

## Invariants

- An unknown id never fails a bulk call: it lands in `skipped` with a reason while the rest
  run. `tests/test_bulk.py`.
- A malformed request, an unknown action, an empty list or one past `MAX_BULK_IDS` raises
  `BulkError`, which callers map to 400. `tests/test_bulk.py`.
- A prefix rename keeps a `name_history` row per renamed function with its old name.
  `tests/test_bulk.py`.
- Unpacking the same sample twice resolves to the binary already stored instead of a second copy,
  and one revert removes the scan, the row and the file together. `tests/test_unpack.py`.
- An archive member's suffix is validated before it reaches a stored file name; no archive-supplied
  text is passed through. `tests/test_extract_api.py`.

## See also

- [ARCHITECTURE.md, Action journal](../ARCHITECTURE.md#action-journal)
- [ARCHITECTURE.md, Unpacking a packed executable](../ARCHITECTURE.md#unpacking-a-packed-executable)
- [CLI.md](../CLI.md)

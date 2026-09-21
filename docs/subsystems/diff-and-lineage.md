# Diff and lineage

Sources: src/reportal/diffing.py, src/reportal/diffview.py, src/reportal/lineage.py

This subsystem owns comparing two functions or two binaries: the pure line alignment, the match-pair
diff view that resolves both sides, and the pairwise version comparison behind the Lineage panel.
`diffing.py` imports only the standard library, `diffview.function_diff` is the one resolver the
route, the CLI and the MCP tool share, and a finished comparison is stored on the left binary.

## Vocabulary

- `diffing.align` returns ordered `DiffEntry` records, each naming the operation and the 1-based
  line number on each side (`None` where that side has no line). A `replace` opcode becomes a delete
  run followed by an insert run, so entries carry only `equal`, `insert` and `delete`. `summary`
  adds `changed`, the number of replacement groups.
- `diffing.strip_addresses` removes a listing's address column, encoded bytes and trailing comment,
  so the alignment is not dominated by them.
- `diffview.KIND_DISASM` (`disasm`) and `KIND_DECOMP` (`decomp`), with `DEFAULT_KIND` `decomp`;
  `diffview.DiffError` carries the API status and error name.
- `lineage` statuses: `unchanged`, `changed`, `removed`, `added`. Thresholds `UNCHANGED_THRESHOLD`
  (95.0) and `CHANGED_THRESHOLD` (70.0), size bucket `SIZE_TOLERANCE_PERCENT` (10), `MAX_CANDIDATES`
  (20), `MAX_ROWS` (500). `SameBinaryError` refuses a binary compared with itself.
- The stored comparison is the `lineage` scan under a `comparisons` object keyed by the right binary
  id.

## Wiring

- Routes: `GET /api/functions/<id>/diff`, `GET /api/functions/<id>/diff/<candidate_id>`, `POST`/`GET
  /api/binaries/<id>/lineage`.
- CLI: `diff`, `lineage`.
- MCP: `diff_functions`, `get_lineage`, `run_lineage`.
- Inputs: the `disasm` side comes from `disasm_cache` or a live `rebrew asm`; the `decomp` side from
  the stored row, else a live unstored decompile.

## Invariants

- `diffing` stays pure and standard-library only, so the alignment is testable on strings alone.
  `tests/test_diffing.py`.
- The API diff route requires an explicit candidate to be a recorded match; the omitted-candidate
  form falls back to the function's best recorded match. `tests/test_diff_api.py`.
- Comparison falls back to name and size only when refinement is unavailable, and the payload then
  records `refined: false` instead of failing the request. `tests/test_lineage.py`.
- A named function whose name does not appear on the other side becomes one removal plus one
  addition, so a rename is reported rather than guessed. `tests/test_lineage.py`.
- Ties fall to the closer size, then the lower VA, so the outcome does not depend on iteration
  order. `tests/test_lineage.py`.
- Summary counts and `matched_percent` cover every function, cap or not. `tests/test_lineage.py`.

## See also

- [ARCHITECTURE.md, Diff view](../ARCHITECTURE.md#diff-view)
- [ARCHITECTURE.md, Lineage](../ARCHITECTURE.md#lineage)
- [API.md](../API.md)

# Binary detail

Sources: src/reportal/details.py, src/reportal/function_extras.py, src/reportal/composition.py, src/reportal/related.py, src/reportal/families.py

This subsystem owns the derived reads and rankings around one binary: the composed detail reports,
the per-function extras, the composition block, related-binary ranking and local family detection.
Every read here is stored-only and composes scans the workspace already holds. The one thing that is
not derived is an analyst-declared callee edge.

## Vocabulary

- `details.DIE_SOURCES` (`pe-info`, `filetype`, `fingerprint`) and `DETAIL_SOURCES`;
  `SOURCE_COMMANDS` maps each source to the command that fills it, which is the hint a missing input
  carries.
- `function_extras.EDGE_TABLE` (`function_edges`) holds an analyst edge with `EDGE_SOURCE_ANALYST`;
  `EDGE_KINDS` is `call` and `indirect`. Bounds: `MAX_FUNCTIONS_PER_QUERY` (50),
  `MAX_EDGES_PER_FUNCTION`.
- `composition.NAME_SOURCE_MAP` maps reportal's stored `name_source` vocabulary onto five labels,
  and `QUALITY_BANDS` onto four cutoffs (95.0, 80.0, 70.0). `CATEGORIES` is `malware`, `debug`,
  `unique`, `library`; `MAX_ROWS` is 500.
- `related.RELATED_CLASSIFICATIONS` runs `identical`, `same-imports`, `same-toolchain`,
  `similar-lifecycle`, `similar-capabilities`, `similar-size`, `unrelated`, each with a confidence
  and a signal kind. `IMPORT_OVERLAP_THRESHOLD` and `CAPABILITY_OVERLAP_THRESHOLD` are 0.8,
  `SIZE_TOLERANCE_PERCENT` is 10, `DEFAULT_LIMIT` 20 and `MAX_LIMIT` 200.
- `families` stores one signature bundle per family: the fingerprint hashes, a locally computed
  `import_hash`, the canonical import name set and the capability set.

## Wiring

- Routes: `GET .../die-info`, `GET .../additional-details`, `GET .../additional-details/status`;
  `GET /api/functions/callees-callers`, `/api/functions/matches`,
  `/api/functions/canonical-names`, `GET`/`POST /api/functions/<id>/callees`, `DELETE
  .../callees/<edge_id>`; `.../related`, `.../composition`, `.../detect`, `/api/families`.
- CLI: `die-info`, `additional-details`, `callees-callers`, `callee-add`, `callee-rm`,
  `function-matches`, `canonical-names`, `related`, `composition`, `families`, `family-add`,
  `family-rm`, `detect`.
- MCP: `get_die_info`, `get_additional_details`, `get_details_status`,
  `get_functions_callees_callers`, `add_function_edge`, `delete_function_edge`,
  `list_function_edges`, `get_related_binaries`, `run_related_binaries`, `get_composition`,
  `run_composition`, `list_families`, `get_detect_scan`, `register_family`, `delete_family`,
  `run_detect`.
- Scans: `related`, `composition`, `detect`.

## Invariants

- A read never starts work: a function with no cached listing reports `has_disassembly: false` and
  no call sites. `tests/test_function_extras.py`.
- An analyst edge is reported beside derived callees, never merged into them, and `add_edge`
  replaces a row for the same `(function, callee, kind)` in place. `tests/test_function_extras.py`.
- A self-match is excluded from the composition rollup and its function count is reported in the
  notes. `tests/test_composition.py`.
- A pair that matches nothing is `unrelated`, carries no signals, and is dropped unless the caller
  asks for it. `tests/test_related.py`.
- A blank family name raises `InvalidFamilyNameError` and a case-insensitive repeat
  `DuplicateFamilyError`. `tests/test_families.py`.

## See also

- [ARCHITECTURE.md, Function-level extras](../ARCHITECTURE.md#function-level-extras)
- [ARCHITECTURE.md, Composition analysis](../ARCHITECTURE.md#composition-analysis)
- [API.md](../API.md)

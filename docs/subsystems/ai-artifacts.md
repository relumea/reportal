# AI artifacts

Sources: src/reportal/ai_decomp.py, src/reportal/function_triage.py, src/reportal/renames.py, src/reportal/ratings.py, src/reportal/decompiler_scripts.py

This subsystem owns the stored AI artifacts: the rewritten function with its token map,
per-function triage, identifier renames, analyst ratings and the decompiler round-trip scripts.
The contract is that every derivation is local and deterministic, every write goes through the
action journal, and no artifact needs a model endpoint except the ones that ask a model for text.

## Vocabulary

- `ai_decomp.KIND` (`ai-decompilation`) is one `ai_artifacts` row carrying the rewrite, its model,
  the token map, per-line attributions, overrides, rating and line comments. `token_kind`,
  `tokens_of`, `attributions_of`, `apply_overrides`, `write_artifact`, `rewrite`, `set_overrides`,
  `rate` and the line-comment writers. `MAX_TOKEN_LINES` bounds the
  map and `MAX_OVERRIDE_NAME` a replacement. Errors: `AiDecompError` with
  `NoAiDecompilationError`, `InvalidOverrideError`, `UnknownTokenError`, `InvalidRatingError`,
  `InvalidLineCommentError` and `UnknownLineCommentError`.
- `function_triage.FUNCTION_TRIAGE_KIND` (`function-triage`); `score_candidates` returns a named
  `heuristic_score` in `0..1` from `WEIGHT_SIZE`, `WEIGHT_STATUS`, `WEIGHT_DECOMPILATION`,
  `WEIGHT_NAME`, `WEIGHT_MATCHES`. `METHOD_LLM` / `METHOD_HEURISTIC` say which produced the
  payload; `DEFAULT_LIMIT` 10 and `MAX_LIMIT` 50.
- `renames.RENAMES_KIND` (the suggestions) and `RENAMES_APPLIED_KIND`. `MIN_IDENTIFIER_LENGTH` is 3
  and `PROTECTED_IDENTIFIERS` are never targeted; `identifier_present`, `replace_identifier`,
  `suggest_renames`, `apply_renames`, `revert_renames`.
- `ratings.TABLE` (`artifact_ratings`), keyed by `(binary_id, kind)`; `SCAN_KINDS` is read from the
  store's own `SCAN_KIND_*` constants, `RATINGS` is (`up`, `down`), `MAX_NOTE_CHARS` 500. Error
  codes `invalid rating` and `no-artifact`.
- `decompiler_scripts.SCRIPT_FORMATS` (`ghidra`, `ida`, `binja`) with `MEDIA_TYPES` and
  `FILENAMES`; `collect`, `render`, `script`; `PLACEHOLDER_PREFIXES` names are left out.

## Wiring

- Routes: `/api/functions/{function_id}/ai-decompilation` (including `status`, `events`, `tokens`,
  `overrides`, `rating` and `inline-comments`),
  `POST`/`GET /api/binaries/{binary_id}/function-triage`,
  `/api/functions/{function_id}/renames` with `apply` and `revert`, `GET`/`PUT`
  `/api/binaries/{binary_id}/ratings` and `/ratings/{kind}`,
  `GET /api/binaries/{binary_id}/decompiler-script`.
- CLI `ai-decompile`, `function-triage`, `suggest-renames`, `apply-renames`, `revert-renames`,
  `ratings`, `decompiler-script`; MCP tools `run_ai_decompilation`, `get_ai_decompilation`,
  `list_ai_decompilation_tokens`, `set_ai_decompilation_overrides`, `rate_ai_decompilation`,
  `run_function_triage`, `get_function_triage`, `suggest_renames`, `apply_renames`,
  `revert_renames`, `list_artifact_ratings`, `rate_artifact`, `export_decompiler_script`.
- Tables `ai_artifacts`, `artifact_ratings` and the `function-triage` `scans` row.

## Invariants

- The stored rewrite is never mutated: overrides are applied at read time, so clearing one restores
  the model's words (`tests/test_ai_decomp.py`).
- An override must name a carried token and a valid C identifier; a bad rating, line or comment
  body is refused with the shared `invalid X` vocabulary (`tests/test_ai_decomp.py`).
- `apply_renames` journals the text it replaces, so `revert_renames` restores it
  (`tests/test_renames.py`).
- A rating needs a stored scan of that kind and setting it again replaces it through `journaled_set`
  (`tests/test_ratings.py`).
- Scripts carry only real names, never a `PLACEHOLDER_PREFIXES` name
  (`tests/test_decompiler_scripts.py`).
- With no endpoint, triage keeps the heuristic score and a one-line summary, and a rename suggest
  raises `LlmUnavailable` (`tests/test_function_triage.py`, `tests/test_renames.py`).

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#ai-decompilation-artifact)
- [ARCHITECTURE.md function triage](../ARCHITECTURE.md#function-triage)
- [API.md](../API.md)

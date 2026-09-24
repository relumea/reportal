# Corpus packs

Sources: src/reportal/corpus.py

A portable match corpus: named functions and their assembly listings, written from one workspace
and imported into another as match candidates. The matcher reads a candidate's listing from
`disasm_cache` first, so an imported function needs neither its binary file nor an engine.

## Vocabulary

- A pack is one gzip JSON file: `format` `PACK_FORMAT` (`reportal-corpus`), `version`
  `PACK_VERSION` (1), and `binaries`, each with its `sha256`, `name`, `format`, `arch` and
  `functions` (`va`, `size`, `name`, `status`, `name_source`, `listing`).
- `export_pack` keeps a function with a real name and a listing, computing a missing listing
  through `matching.cached_disassembler`. It leaves out placeholder names
  (`function_triage.is_placeholder_name`), `ORDINAL_PREFIX` names, `EXCLUDED_STATUSES`
  (`THUNK`: one indirect jump matches every other on shape alone), and binaries without a sha256.
- `import_pack` writes one file-less binary per pack entry with an `IMPORT_ENGINE`
  (`corpus-pack`) analysis. A re-import upserts by VA and prunes what the pack dropped
  (`store.prune_analysis_functions`); a malformed entry is counted, not fatal.
- `pack_from_libraries` writes the known-library half: each static library's (`.lib` / `.a`)
  named functions (file-static ones included) via `RebrewEngine.library_functions`, one pack binary per library (format
  `lib`, status `LIBRARY`), laid out from offset 0 and skipping ones under
  `MIN_LIBRARY_FUNCTION_BYTES` (16). The pack binary carries its objects' ISA, each listing in
  `engines.listing_format` for it; a library mixing ISAs is a `CorpusError`.
- `pack_summary` reads a pack without importing it; `CorpusError` names an unreadable file, a
  foreign format or a newer version.

## Wiring

- CLI: `corpus-export <path> [--binary ID]...`, `corpus-from-libs <path> <lib>...`,
  `corpus-import <path>`, `corpus-info <path>`.
- Building one from rebrew projects: `import-rebrew <dir> --build-db` per project (builds a
  missing or outdated `coverage.db` first), then `corpus-export`.
- Matching needs nothing more: every `match` run scores against the imported functions.

## Invariants

- A binary the importing workspace already holds under another analysis is skipped: its own
  analysis is the authority (`tests/test_corpus.py`).
- An imported function is a match candidate a stripped function with the same code finds
  (`tests/test_corpus.py`).
- An import never reads a pack of another format or a newer version (`tests/test_corpus.py`).

## See also

- [matching.md](matching.md)
- [CLI.md](../CLI.md)

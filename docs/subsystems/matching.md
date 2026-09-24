# Matching, similarity and library identification

Sources: src/reportal/matching.py, src/reportal/match_index.py, src/reportal/similarity.py, src/reportal/benchmark.py, src/reportal/library.py, src/reportal/flirt_sigs.py, src/reportal/unstrip.py

This subsystem owns scoring one function against a corpus and everything built on that score: the
match run, the LSH candidate index, the ad-hoc similar-functions query, the assembly similarity
core, benchmark scoring, library identification, the signature catalog, the bill of materials and
un-stripping. `matching.py` holds the only scorer, disassembly and the scorer are injected, and a
proposal is never applied by the read that builds it.

## Vocabulary

- `matching.MatchSettings`: `min_similarity`, `min_confidence`, `include_self`, `top`, `platforms`,
  `architectures`, `binary_ids`, `collection_ids`. Every field has a default, and each recorded row
  stores the settings the run used.
- `matching.TransferRequest` and `matching.TransferPlan`: one transfer row, and the plan computed
  before any write.
- `similarity.SimilarityUnavailable`: raised when the optional `similarity` extra is absent.
  `similarity.jaccard_floor` prefilter skips a pair that cannot reach `min_similarity`.
- `match_index`: `LSH_BANDS` bands of `LSH_ROWS` MinHash values; exact candidates above
  `LSH_PAIRWISE_MAX_SIMILARITY` (80.0), pairwise at or below.
- `matching.SimilarQuery`: a listing, or code bytes with an arch from `QUERY_ARCHES`; a refused
  query raises `INVALID_SIMILAR_QUERY`.
- `benchmark`: labels come from a corpus (`LABEL_SOURCE_CORPUS`) or from the binaries' own names
  (`LABEL_SOURCE_NAMES`, the weaker source). `rename_report` scores stored proposals from the
  `library` or `unstrip` reading and names which.
- `library.SBOM_FORMATS`: `cyclonedx`, `spdx`, `csv`. The rollup caps at `MAX_COMPONENTS`.
- `flirt_sigs.SIGS_DIR_ENV` (`REPORTAL_FLIRT_SIGS_DIR`) names the checkout to index; `sigset_key`
  digests the enabled blobs of an architecture, so a refresh invalidates cached scans.
- `unstrip.AUTO_NAME_SOURCES` (`rebrew`, `unstrip`) is the only source a proposal may overwrite.

## Wiring

- Routes: `POST /api/binaries/<id>/match`, `GET .../matches`, `POST .../matches/transfer`,
  `POST /api/functions/similar`, `POST /api/functions/<id>/similar`,
  `POST`/`GET .../library`, `GET .../sbom`, `POST`/`GET .../unstrip`, `POST .../unstrip/apply`,
  `POST`/`GET .../benchmark`, `GET .../rename-benchmark`, `GET /api/flirt/sigsets`,
  `POST /api/flirt/sigsets/refresh`, `POST`/`GET /api/binaries/<id>/flirt`,
  `POST .../flirt/apply`.
- CLI: `match`, `match-index`, `similar`, `function-matches`, `apply-match`, `library`, `sbom`,
  `unstrip`, `unstrip-apply`, `benchmark`, `benchmark-info`, `rename-benchmark`, `flirt`,
  `flirt-refresh`, `flirt-apply`.
- MCP: `get_matches`, `find_similar_functions`, `run_match`, `apply_match`, `get_library`,
  `run_library`, `export_sbom`, `get_unstrip`, `run_unstrip`, `apply_unstrip`, `get_benchmark`,
  `run_benchmark`, `get_rename_benchmark`, `get_flirt_sigsets`, `refresh_flirt_sigsets`,
  `get_flirt`, `run_flirt`, `apply_flirt`.
- Tables and scans: `matches`, `disasm_cache`, `lsh_fingerprints` and `lsh_buckets`; stored scans
  `library`, `unstrip`, `benchmark` and `flirt`; the catalog `sigset` and its scan cache
  `flirt_scan`.

## Invariants

- A settings value outside its range or vocabulary raises `InvalidSettingsError` rather than being
  coerced. `tests/test_match_settings.py`.
- A signature transfer with a differing non-empty calling convention refuses with
  `signature-conflict` and writes nothing. `tests/test_match_transfer.py`.
- Without the `similarity` extra the default scorer raises `SimilarityUnavailable`; the install
  still runs. `tests/test_similarity.py`.
- The index returns exactly the pairwise rows and hits; a changed listing drops its index row.
  `tests/test_match_index.py`.
- A similar-functions query records nothing and never returns the queried function or a hidden
  binary's. `tests/test_similar_functions.py`, `tests/test_match_index.py`.
- `unstrip` proposes only names an engine produced; a name a person authored is never overwritten,
  and an apply is a separate explicit request. `tests/test_unstrip.py`.
- `sbom` renders the stored reading and never runs an engine. `tests/test_library.py`.
- The catalog indexes `.sig` files one row each, and serves a repeat scan from `flirt_scan`.
  `tests/test_flirt_sigs.py`.

## See also

- [ARCHITECTURE.md, Matching](../ARCHITECTURE.md#matching)
- [ARCHITECTURE.md, Benchmarking a run](../ARCHITECTURE.md#benchmarking-a-run)
- [DATA_MODEL.md](../DATA_MODEL.md)

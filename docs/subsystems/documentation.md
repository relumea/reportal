# Documentation

Sources: src/reportal/docs.py, src/reportal/error_docs.py

This subsystem owns the in-app manual and the error-code catalogue. `docs` serves a document as
structure rather than markup: a title, the sub-headings with their anchors, and a flat list of
blocks, which keeps `dangerouslySetInnerHTML` and a markdown dependency out of the SPA bundle.
`error_docs` maps every error code the API writes to a section of `docs/ERRORS.md`, so each error
body carries a `doc_url` that resolves.

## Vocabulary

- `docs.DOCS_ENV` (`REPORTAL_DOCS`), `DOCS_DIRECTORY` (`docs`), `PACKAGED_MANUAL` (`manual`),
  `CHANGELOG_FILE`, `MAX_DOC_BYTES` (512 KiB).
- `documents_dir()`: the resolution order, first match wins: the override, the workspace `docs/`,
  the checkout, then the packaged `manual/`. `changelog_path()` finds the changelog beside it.
- `page(slug)`: `title`, `headings`, `blocks`, `previous`, `next`, `source` and `version`.
  `pages()` lists every page in reading order (`PAGE_ORDER`, then the rest by name, then
  subdirectories, then the changelog).
- `REPOSITORY_ONLY_PAGES`: business, research and competitive pages (funding, commercialization,
  parity, the backlog) that stay in `docs/` but are neither listed, served nor packaged; a table
  row or list item linking to one is dropped from a rendered page.
- Block kinds: `heading`, `paragraph`, `code`, `list` (with each item's `depth`), `quote`, `table`.
  Anything outside the subset becomes a paragraph rather than being dropped.
- Scope: `SCOPE_KIND` (`docs`) and `SCOPE_ID` (0), the knowledge scope `excerpts()` feeds.
- Errors: `NoDocsError` (404 `no-docs`) and `UnknownDocError` (404 `no-doc`).
- `error_docs.ERROR_DOC_ANCHORS` (code to anchor), `PARAMETRIZED_DOC_ANCHORS` and
  `INVALID_PARAMS_ANCHOR` for messages built at the call site, `DOC_BASE_URL`, `doc_anchor`,
  `doc_url` and `heading_anchor`.

## Wiring

Routes: `GET /api/docs` and `GET /api/docs/{slug:path}` (a subdirectory page reads
`/api/docs/subsystems/store`). CLI: `reportal docs [slug]` and
`reportal changelog`. `settings` reports `docs.directory` by calling `documents_dir`; `knowledge`
ingests `excerpts()` under the `docs` scope; `server.JsonError` calls `doc_url(error)` for every
error body. `scripts/sync_packaged_docs.py` mirrors the `docs/` tree, subdirectories included and
repository-only pages left out, and `CHANGELOG.md` into the packaged `manual/` directory.

## Invariants

- Every code a route writes literally, or an exception class carries, has a catalogue entry
  (`tests/test_error_docs.py`).
- Every catalogue anchor matches exactly one heading in `docs/ERRORS.md`, and every heading is an
  anchor the catalogue names (`tests/test_error_docs.py`).
- A code the catalogue does not name gets `doc_url` `null`, never a guessed link
  (`tests/test_error_docs.py`).
- A slug that is empty, has a backslash, starts with `.` or `/`, or carries a `.` or `..` segment is
  refused rather than resolved (`tests/test_docs.py`).
- A document over `MAX_DOC_BYTES` is truncated silently rather than failing the page
  (`tests/test_docs.py`).

## See also

- [ERRORS.md](../ERRORS.md)
- [ARCHITECTURE.md section](../ARCHITECTURE.md#documentation)

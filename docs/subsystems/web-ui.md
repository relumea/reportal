# Web UI

Sources: src/reportal/ui.py, src/reportal/landing.py

This subsystem owns what a browser gets: the built SPA, its hashed assets, the generated report
site under a binary, and the public pricing page. Every request is resolved under its own root and
refused when it escapes, so a traversal cannot read elsewhere. `landing` renders `/pricing` from
the plan catalog, so a figure on the page cannot drift from the code that bills.

## Vocabulary

- `router`: the `APIRouter` `webapp` includes beside the JSON API.
- `dist_dir()`: `src/reportal/assets/dist`, the generated Vite output; `APP_INDEX` is `index.html`
  and `REPORT_INDEX` is the report site's own entry page.
- `UI_NOT_BUILT_DETAIL`: the hint `503 ui-not-built` carries.
- `ASSET_DIRECTORY` (`assets`), `ASSET_CACHE_CONTROL` (immutable) and `SHELL_CACHE_CONTROL`
  (`no-cache`): the hashed-bundle against everything-else caching split.
- `COMPRESSIBLE_SUFFIXES`, `MIN_COMPRESS_BYTES`, `GZIP_LEVEL`, `_gzip_cached`,
  `_precompressed_sibling`: a `.br` sibling is preferred, then `.gz`, else request-time gzip at the
  shared level.
- `_resolve_under`, `_file_under`, `_revalidate`, `_media_type`: one path under one root, its
  conditional revalidation and its content type.
- `landing.CACHE_CONTROL` (`public, max-age=300`) and `landing.render()`, the whole page as one
  escaped HTML string built from `plans.public_plans()`, `plans.Plan` fields and
  `credits.catalog()`. `/pricing` answers an `ETag` (and `304` on revalidation) and prefers a
  once-per-body brotli or gzip encoding over compressing on every request.

## Wiring

Routes: `GET /` (the SPA shell), `GET /static/{path}` (built assets), `GET /pricing` (served
whether or not the SPA is built), `GET /reports/{binary_id}/` and `GET /reports/{binary_id}/{path}`.
A binary with no report directory is 404 `no-report`; a report file outside its root is 404
`not found`. `/pricing` links its plan actions at `/#/billing?plan=<id>`.

## Invariants

- `/` answers 503 `ui-not-built` when no build exists, never a broken shell (`tests/test_api.py`).
- A request for a path outside the SPA or report root is 404, never a read elsewhere
  (`tests/test_api.py`).
- Every figure on `/pricing` comes from `plans` and `credits`, so a catalog edit moves the page
  (`tests/test_landing.py`).
- `/pricing` carries an `ETag` and answers `304` when `If-None-Match` matches
  (`tests/test_landing.py`).
- A hashed bundle under `assets/` is answered `immutable` and a shell file `no-cache`
  (`tests/test_api.py`).
- The Vite build writes `.gz` siblings under `assets/dist/` (and `.br` when brotli is on PATH),
  which `scripts/check_wheel.py` asserts at package time and `tools/smoke_spa.py` checks on the
  entry JS and CSS.

## See also

- [SPA.md](../SPA.md)
- [ARCHITECTURE.md](../ARCHITECTURE.md)

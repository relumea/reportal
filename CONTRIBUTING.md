# Contributing to reportal

## Start here

- `make help`: every contributor target and a one-line description.
- `AGENTS.md`: layout, gate, commands, and conventions for this tree.
- `docs/ARCHITECTURE.md`: module map and process layout.

## Bootstrap

Python 3.13+ (`.python-version`), `uv` (`>=0.8.22`, pinned in
`[tool.uv] required-version` and CI), and `bun` (`web/package.json`
`packageManager`). `rebrew` is a path dependency on `../rebrew`; clone it
beside this repo before setup. CI pins sibling commits in
`.github/workflows/check.yml`.

```bash
git clone https://github.com/maci0/rebrew ../rebrew
make setup
```

After setup the CLI is `.venv/bin/reportal` (not on `PATH` until you activate
`.venv`). Quick readiness check: `make doctor`.

Optional similarity scoring also needs `../resembl`, then:

```bash
make setup SYNC_EXTRAS='--extra dev --extra similarity'
```

Gate extras (not installed by `make setup`): `shellcheck`, Java 17+, and
`vnu` via the same user-local install CI uses:

```bash
npm install --prefix "$HOME/.local" -g vnu-jar@26.8.21
export PATH="$HOME/.local/bin:$PATH"
```

## Edit loop

```bash
make test-one ARGS='tests/test_foo.py'          # one file or node
make check-fast                                 # lint + types + pytest, no cov
make check-ci                                   # what GitHub Actions runs
make check                                      # full gate, including browsers
```

`make check-ci` matches the workflow step `make lint typecheck test
package-check` under the same `SOURCE_DATE_EPOCH` / `LC_ALL=C` / `TZ=UTC` /
`PYTHONHASHSEED=0` exports. The headless `ui` target needs a local
`../rebrew-projects/notepad-rebrew` fixture and is not run in CI.

New tests live under `tests/` (no `tests/__init__.py`); use `tmp_path` and
mirror a nearby file that covers the same surface. New Python modules go under
`src/reportal/` with typed parameters and returns (`AGENTS.md` conventions).

## Before opening a PR

1. Run `make check-ci` (or `make check` if you have the browser fixture).
2. Keep the change scoped; match surrounding style and the conventions in
   `AGENTS.md`.
3. Add or extend tests for new behavior; the suite keeps a coverage floor
   (`COVERAGE_MIN` / `[tool.coverage.report] fail_under` in `pyproject.toml`).
4. Regenerated SPA output lives under `src/reportal/assets/dist/` and is
   gitignored; `make spa` / `make run` / `make ui` / `make package-check`
   rebuild it (including `.gz` siblings). Do not hand-edit that tree.
5. Consumer-facing API, CLI, MCP, config, schema or pricing changes belong in
   `CHANGELOG.md` under `## Unreleased` (put breaks under `### Breaking
   changes`, with before/after and what a client should do).  Do not bump
   `src/reportal/__init__.py` `__version__` in the same PR unless you are
   cutting the release.

## Cutting a release

Version has one source of truth: `reportal.__version__` in
`src/reportal/__init__.py` (wired through `pyproject.toml` as a dynamic
version).  `reportal --version`, `GET /api/health`, MCP `serverInfo` and the
packaged docs all read that string.

1. Move `## Unreleased` into a new `## X.Y.Z` section (newest first, same shape
   as `1.2.0` / `1.1.0`).  Leave an empty `## Unreleased` heading for the next
   cycle.
2. Set `__version__ = "X.Y.Z"` to the same string as that section so the tag,
   the package metadata and the running process cannot disagree.
3. Tag `vX.Y.Z` on the commit that carries both the version bump and the
   changelog section.  Do not retag or re-publish an already-shipped version.
4. Run `make check-ci` (and `make package-check` when shipping a wheel) before
   the tag so the artifact matches the notes.

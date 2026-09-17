# AGENTS.md: reportal

Working guide for agents. Human reference material lives under `docs/`
([index](docs/README.md)); keep this file short, current, and safe to obey.

## Overview

**reportal** is a self-hosted reverse-engineering portal (local RevEng.AI clone).
It stores binaries, analyses, functions, matches, rename history, collections and
tags in SQLite, and serves a FastAPI JSON API plus a Vite/React/TypeScript SPA.

It is a **consumer and orchestrator** of sibling engines, never a reimplementation:

| Engine | Role here |
|--------|-----------|
| `rebrew` | In-process binaries, coverage.db, disasm/decompile/xrefs/structs/security (`engines.py`) |
| `resembl` | Optional `similarity` extra; assembly scores for `matches` |
| `recoverage` | Shared `db/coverage.db` format |
| RevEng.AI API | Optional remote; not required. Runtime network only when the user opts in: LLM bridge or guarded URL ingest (`remote_ingest.py`) |

Sandbox detonation (`sandbox.py`) is off until the workspace opts in and a runner
is installed (`docs/THREAT_MODEL.md` boundary 7). Static analysis never executes a
sample. The LLM bridge (`llm.py`) is off until an endpoint is configured; without
one every AI route is 503 `llm-unavailable`.

## Project structure

```
reportal/
├── pyproject.toml           # package, mypy, ruff, coverage
├── Makefile                 # make check / make run
├── scripts/                 # vnu-html.sh, check_wheel.py, precompress_spa.py, …
├── .github/workflows/check.yml
├── deploy/                   # reportal.service, reportal-backup.service/.timer
├── docs/                    # see docs/README.md
├── tests/                   # pytest, tmp_path based (no tests/__init__.py)
├── tools/                   # smoke_spa.py, audit_ui.py, seed_e2e.py, cdp.py
├── web/                     # SPA (bun); src/views, src/panels
└── src/reportal/            # package; module map: docs/ARCHITECTURE.md ("Process layout")
```

## Gate

`make check` is the single done gate: ruff + format, oxlint, shellcheck on
`scripts/`, VNU on `web/index.html` and `web/src/styles.css`, mypy, `tsc --noEmit`,
pytest under the coverage floor, headless SPA smoke + audit, wheel packaging.
CI runs `make check-ci` (`lint typecheck test package-check`); browsers are local
only (smoke/audit seed `../rebrew-projects/notepad-rebrew`).
`make check-fast` skips coverage, browsers, and the wheel.

Every target uses `.venv/bin/python`; missing tools fail loud. External: `shellcheck`,
`vnu` (needs Java 17+).

**mypy.** Config in `[tool.mypy]` (`python_version = "3.13"`, typed-defs flags,
`warn_return_any`, `disallow_any_generics`, …). Do **not** add a
`[[tool.mypy.overrides]]` that matches `*.*` to relax `tests/`: that pattern also
matches `src/reportal` and would weaken the package. Plain `mypy` is the gate;
`--strict` on `src/reportal` alone still reports five known attribute/return
errors (`journal.py`, `pdf.py`, `engines.py`) and is not a compliance claim.

**Coverage.** `make test` runs
`pytest --cov --cov-fail-under=$(COVERAGE_MIN)` with `COVERAGE_MIN ?= 92`, kept
equal to `[tool.coverage.report] fail_under`. The floor only moves up, in the
same commit that raises coverage.

**Packaging.** `make package-check` builds the wheel and
`scripts/check_wheel.py` asserts packaged SPA assets under `assets/dist/` (plus
`.gz` siblings) and mirrored manual pages under `manual/`.

## Commands

```bash
# Install (clone sibling ../rebrew beside this repo first)
make setup
# Optional: make setup SYNC_EXTRAS='--extra dev --extra similarity'
# Optional Cognee graph backend: uv sync --extra cognee

make spa                     # Vite build + .gz siblings into assets/dist
(cd web && bun run dev)
(cd web && bun run lint)
(cd web && bun run typecheck)
(cd web && bun run test:ui)

make run                     # build SPA, serve (PORT=8002)
make serve                   # serve current build
make doctor                  # preflight; exits 1 on failure; docs/DEPLOY.md
.venv/bin/reportal config
.venv/bin/reportal doctor

make check
make check-ci
make check-fast
make test-one ARGS='tests/test_foo.py'

.venv/bin/python -m pytest -q
.venv/bin/python -m pytest --cov
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy
.venv/bin/python tools/smoke_spa.py
.venv/bin/python tools/audit_ui.py
vnu --format text web/index.html
vnu --css --format text web/src/styles.css
```

CLI surface: `docs/CLI.md` / `.venv/bin/reportal --help` (after `make setup`).

## Configuration (defaults off)

Resolution is first match wins: environment, then workspace `reportal.toml`.
Operators see full detail via `reportal config`. Do not lower a quality gate or
bypass auth/sandbox/remote guards to make a check pass; fix the code.

| Concern | Env / table | Default |
|---------|-------------|---------|
| LLM endpoint / key / model | `REPORTAL_LLM_*` / `[llm]` | AI disabled |
| Remote URL ingest | `REPORTAL_ALLOW_REMOTE_INGEST` / `[knowledge] allow_remote` | off → 403 |
| Job pool | `REPORTAL_JOBS_POOL` (falsey disables) | on |
| Token auth | `REPORTAL_AUTH` / `[auth] required` | off (loopback operator) |
| External sources (e.g. VT) | `REPORTAL_ALLOW_EXTERNAL` / `[external]` | off → 403 |
| Sandbox detonation | `REPORTAL_SANDBOX` / `[sandbox]` | off |
| Graph backend | `REPORTAL_GRAPH_BACKEND` / `[knowledge] graph_backend` | `sqlite` |
| Billing | `REPORTAL_BILLING_*` / Stripe keys | off without key |

Non-obvious:

- `remote_ingest.validate_target(..., allow_loopback=True)` is **test-only**; never
  expose it as a request field.
- Secret store: values never returned; reads are name/scope/length/last-four only
  (`docs/THREAT_MODEL.md`).
- Tenant responses go through `disclosure.redact_payload`; operators are exempt
  while auth is off or the caller is admin. Credits/metering:
  `docs/ARCHITECTURE.md` ("Plans, credits, metering and billing").
- Pipeline: `[pipeline] disabled = ["component", ...]` (unknown names ignored).

## Docs map (do not inline here)

| Topic | Doc |
|-------|-----|
| HTTP routes | `docs/API.md` |
| SPA | `docs/SPA.md` |
| Schema | `docs/DATA_MODEL.md` |
| Modules / engines / billing | `docs/ARCHITECTURE.md` |
| Components / effects | `docs/COMPONENTS.md` |
| Threat boundaries | `docs/THREAT_MODEL.md` |
| Errors | `docs/ERRORS.md` |
| Hosted parity / MCP counts | `docs/PARITY.md` |

## MCP

`reportal mcp` is stdio JSON-RPC via `mcp_server.py` (only stdout writer). The
same registry is `POST /mcp` (JSON replies) and `GET /mcp` (SSE session
stream, `Last-Event-ID` resume), bearer-gated when auth is on; needs write.
Tools are plugins in `mcp_tools.py`
(`reportal.mcp_tools` entry points). Handlers call internals directly, never
HTTP back into reportal. Read tools stay stored-only; writers carry
`destructiveHint: true`. Counts are pinned by `tests/test_mcp.py` (currently
261 / 122 read-only / 139 destructive); update the test when the registry
changes, not a prose list here.

## Engines and matching

- `engines.py` is the only engine runner: in-process `rebrew`, no payload reshape;
  failures become `EngineError`. Access via `get_engine()` / `set_engine()`.
- Project methods reload `rebrew.config.load_config(root)` every call.
- `matching.py` is the only scorer; default scorer needs the `similarity` extra
  (`SimilarityUnavailable` otherwise). Symbol transfer journals; signature
  conflicts refuse with `signature-conflict`.

## Conventions

- Python 3.13+, `src/` layout, setuptools, version from `reportal.__version__`.
- Type every parameter and return; PEP 604 unions; specific generics.
- Ruff: line length 100; select groups as in `pyproject.toml`; no ignores.
- Typer: human text on stderr (`Console(stderr=True)`); `--json` on stdout.
- FastAPI: plain `def` handlers (threadpool); `json_error` envelope for refusals;
  loopback bind by default; Host-header guard.
- Auth is one middleware (`server._reportal_headers` → `authenticate`) that also
  sets `journal.acting_as`. Object scope via `visibility`/`owner_team_id`,
  `server._enforce_scope`, `auth.visible_clause`. `tools/audit_scope.py` (under
  `make lint`) fails new object-id routes without coverage. `serve --host`
  refuses non-loopback while auth is off or no enabled user exists.
- SPA: bun build into `src/reportal/assets/dist/`; every view but the dashboard
  is `React.lazy`; smoke fails if a view marker lands in the entry bundle.
- Plugin seams share one pattern (built-ins + entry-point group; broken
  registration → warn; duplicate name → `RegistryError`):
  `components`, `effect_handlers`, `auto_workers`, `mcp_tools`, `models`,
  `external_sources`, `graph_backends`, `sandbox_runners`. Details:
  `docs/COMPONENTS.md` / `docs/ARCHITECTURE.md`.
- Auto mode is dry-run unless `--execute` / `"execute": true`; never overwrite an
  existing candidate source; revert via the shared effects dispatcher.
- No em dashes in docs, code, or commits. No comments that narrate control flow.
- Never weaken `COVERAGE_MIN` / `fail_under`, skip hooks, or disable sandboxes to
  pass a gate; fix the failing code.

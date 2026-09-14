# AGENTS.md: reportal

## Overview

**reportal** is a self-hosted reverse-engineering portal: a local clone of the
RevEng.AI web portal.  It stores binaries, analyses, functions, cross-function
matches, rename history, collections and tags in SQLite, and serves them from a
FastAPI (ASGI) JSON API plus a build-step SPA (Vite + React + TypeScript).

It is a **consumer and orchestrator** of the sibling engines, never a
reimplementation:

| Engine | What reportal takes from it |
|--------|-----------------------------|
| `rebrew` | target binaries, `db/coverage.db` function rows and import stubs (via `import-rebrew`), binary fingerprints/imports/strings, disassembly and decompilation, cross-references, struct recovery (the editable type model is built from that scan, locally) and rule-based security scanning of the reversed sources (`engines.py`, in process), used for the function explorer, the disasm, decompilation, xrefs, struct-recovery and capability-tagging routes, and local matching |
| `resembl` | assembly-similarity scores for the `matches` table (through the optional `similarity` extra; `similarity.py`) |
| `recoverage` | the coverage database format it also reads (`db/coverage.db`) |
| RevEng.AI API | optional and remote; reportal never requires it and makes no network calls at runtime, with two opted-in exceptions: the optional AI bridge calls a chat-completions endpoint the user explicitly configures, and guarded URL ingestion (`remote_ingest.py`, off by default) fetches a URL the user names |

reportal **does not execute a sample by default**.  The one path that can is the
sandbox (`sandbox.py`), off until the workspace opts in and a runner is installed;
`docs/THREAT_MODEL.md` boundary 7 states the guards and the residuals.  Static
analysis (bytes, engine JSON, archive extraction, firmware carving) never runs
anything.

An optional OpenAI-compatible LLM bridge (`llm.py`) provides the portal's AI
extras (a whole-function rewrite with its token map and line attributions, a
function summary, inline comments, type suggestions and identifier renames)
over a decompilation reportal already stored.  It is disabled until an
endpoint is configured; without one every AI route answers 503
`llm-unavailable` and no network call is made.

## Project Structure

```
reportal/
├── pyproject.toml          # package config, entry point: reportal; mypy, ruff and coverage config
├── Makefile                # the gate (make check) and the dev server (make run)
├── scripts/                # gate helpers: vnu-html.sh, check_wheel.py
├── .github/workflows/check.yml  # CI: every gate target but the two browser ones
├── README.md               # user-facing docs
├── LICENSE                 # MIT
├── docs/                   # README (index), PARITY, ARCHITECTURE, COMPONENTS, ERRORS,
│                           #   API, CLI, SPA, DATA_MODEL, THREAT_MODEL, DR_RUNBOOK
├── tests/                  # pytest suite (self-contained, tmp_path based)
├── tools/                  # cdp.py (DevTools client), smoke_spa.py, audit_ui.py, seed_e2e.py
├── web/                    # Vite + React + TypeScript SPA (bun); src/views and src/panels
└── src/reportal/           # the package: the module-by-module map is
                            #   docs/ARCHITECTURE.md ("Process layout"), which is the one
                            #   canonical list; the modules this file's Conventions section
                            #   describes in detail are the plugin seams (components.py,
                            #   effects.py, auto_workers.py, mcp_tools.py,
                            #   graph_backends.py) and the shared helpers (store.py,
                            #   journal.py, server.py, api.py, cli.py)
```
## Gate

`make check` is the single gate: ruff and ruff format over the tree, oxlint,
shellcheck over `scripts/`, W3C VNU over `web/index.html` and
`web/src/styles.css`, mypy, `tsc --noEmit`, pytest under the coverage floor,
the built SPA smoke (which fails a route that logs a page error, a console
error or a dropped request) and audit in headless Chrome, and the wheel
packaging check. Run it before calling anything done. CI runs
`make lint typecheck test package-check`: the two browser targets are the one
part of the gate a runner cannot do, because their smoke and audit seed a
workspace from `../rebrew-projects/notepad-rebrew`, a per-binary
decompilation project (a target executable plus its reversed sources and its
database) that lives in a local data directory rather than in any repository.
`make check-fast` drops the slow parts for iteration, skipping
the coverage trace (`test-fast` is `pytest --no-cov`) and the browser and wheel
targets (`ui`, `package-check`).

Every target uses the project venv (`.venv/bin/python`); a missing tool fails
loud with its install hint, never a silent skip. `shellcheck` and `vnu` are the
two external tools (`vnu` also needs Java 17+).

**mypy.** `[tool.mypy]` holds the package and the suite to a graduated flag
set: `python_version = "3.12"`, `disallow_untyped_defs`, `check_untyped_defs`,
`warn_unused_ignores`, `no_implicit_optional`, `strict_equality`,
`warn_return_any` and `disallow_any_generics`. The suite runs at the same
level as the package rather than under a per-module relaxation: `tests/` has
no `__init__.py`, so mypy names its modules by basename and the only pattern
that matches the directory (`*.*`) also matches every package module, which
would silently weaken `src/reportal`. Plain `mypy` reads the config;
`Success: no issues found in 226 source files` is the finish line.

`--strict` is a documented follow-up, not a claim of compliance.
`.venv/bin/python -m mypy --strict --python-version 3.12 src/reportal` reports
5 errors, none of them about the HTTP layer: `journal.py:749` and
`journal.py:750` plus `pdf.py:619` and `pdf.py:620` are module-attribute
errors (a name another module imports without re-exporting it), and
`engines.py:302` is a return-value error on the engine's decorator.

**Coverage.** The floor is enforced by the `test` target as
`pytest --cov --cov-fail-under=$(COVERAGE_MIN)` (`COVERAGE_MIN ?= 92`, kept
equal to `[tool.coverage.report] fail_under`): pytest-cov reads the config key
to *report* a shortfall but still exits 0 on it, so the flag is what makes the
gate fail.  `.venv/bin/python -m pytest --cov` (or `make test`) measured
92.05%, 30906 statements with 2458 missed. `[tool.coverage.report] fail_under`
is the whole percent below that, 92. The floor only ever moves up; raise it in
the commit that raises coverage.

**Packaging.** `make package-check` builds the wheel with `uv build --wheel`,
then `scripts/check_wheel.py` reads it back and asserts the built SPA is
packaged: `assets/dist/index.html` plus at least one `assets/*.js` and one
`assets/*.css`. The bundle is generated and gitignored, so this checks the
wheel that is actually built rather than a committed artifact.

## Commands

```bash
# Install (`rebrew` is a base dependency, a path source on the sibling
# ../rebrew checkout, so this installs the engine too)
uv venv .venv
uv pip install -e ".[dev]" --python .venv/bin/python
# Optional: enable `reportal match` scoring (resembl sibling + rapidfuzz)
uv pip install -e ".[similarity]" --python .venv/bin/python
# Optional: enable the Cognee graph backend (`reportal graph-sync --backend cognee`);
# without it the backend is registered but unavailable and every path is 503
uv pip install -e ".[cognee]" --python .venv/bin/python

# Frontend (Vite + React + TypeScript, bun).  Build before `reportal serve`:
# the server serves src/reportal/assets/dist, which is generated, not committed.
cd web && bun install
cd web && bun run build     # tsc --noEmit + vite build into src/reportal/assets/dist
cd web && bun run dev       # Vite dev server
cd web && bun run lint      # oxlint src tests playwright.config.ts
cd web && bun run typecheck # tsc --noEmit
cd web && bun run test:ui   # Playwright over a seeded workspace (see tests/)

# Run
# The command reference is docs/CLI.md (`reportal --help` prints the same list).
# Serve: `make run` builds the SPA from web/ and then serves the portal;
# `make serve` serves the current build without rebuilding.
make run            # build src/reportal/assets/dist, then serve (PORT=8002)
make serve          # serve the current build

# Gate (see "Gate"): lint + types + tests under the coverage floor + SPA + wheel
make check          # the whole gate, in order
make check-fast     # drops the coverage trace, the browsers and the wheel

# The same steps individually
.venv/bin/python -m pytest -q                         # tests without coverage
.venv/bin/python -m pytest --cov                      # tests under the floor
.venv/bin/python -m ruff check .
.venv/bin/python -m ruff format --check .
.venv/bin/python -m mypy                              # the flag set in pyproject.toml
.venv/bin/python tools/smoke_spa.py                   # builds web/ if needed, then headless Chrome
.venv/bin/python tools/audit_ui.py                    # UI gate: layout, contrast, names at both viewports
cd web && bun run test:ui                             # Playwright e2e: seeds .scratch/e2e-web, serves it
vnu --format text web/index.html
vnu --css --format text web/src/styles.css
```

### Optional LLM configuration

The AI extras need an OpenAI-compatible chat-completions endpoint.  Resolution
is first match wins per field: the environment, then the workspace
`reportal.toml` `[llm]` table.

| Setting | Env var | `reportal.toml` key | Default |
|---------|---------|---------------------|---------|
| Endpoint | `REPORTAL_LLM_ENDPOINT` | `[llm] endpoint` | none, so AI is disabled |
| API key | `REPORTAL_LLM_API_KEY` | `[llm] api_key` | none, so requests are anonymous |
| Model | `REPORTAL_LLM_MODEL` | `[llm] model` | `gpt-4o-mini` |

A request is a JSON POST to `<endpoint>/chat/completions` (the path is not
appended when the endpoint already carries it) with the body
`{"model", "messages", "temperature"}` and `Authorization: Bearer <key>` only
when a key is set.  The key is never logged or returned.  Without an endpoint,
the AI routes answer 503 `llm-unavailable` and the AI commands exit 1.

The same endpoint optionally serves embeddings: `POST <endpoint>/embeddings`
with `{"model", "input"}`, at most `EMBEDDINGS_BATCH_SIZE` inputs per request,
which the knowledge feature uses to rank document chunks.  An endpoint that
does not implement it is not an error: ingest and search fall back to the local
TF-IDF ranking, so knowledge works without any configuration.

### Pipeline configuration

The workspace `reportal.toml` `[pipeline]` table disables stages of the AI
decompilation composition by component name; a caller passing `disabled=`
overrides it, and a name that is not a registered component is ignored.

| Setting | `reportal.toml` key | Default |
|---------|---------------------|---------|
| Disabled components | `[pipeline] disabled = ["name", ...]` | none |

### Remote ingestion configuration

Guarded URL ingestion is off by default; either the environment variable or the
workspace table enables it (`remote_ingest.remote_enabled()`).

| Setting | Env var | `reportal.toml` key | Default |
|---------|---------|---------------------|---------|
| Enable URL ingestion | `REPORTAL_ALLOW_REMOTE_INGEST` (truthy: `1`, `true`, `yes`, `on`) | `[knowledge] allow_remote = true` | off |

While it is off every remote path answers 403 `remote-ingest-disabled` and
makes no network call.  `src/reportal/remote_ingest.py` holds the guards
(`validate_target`, `fetch`, `ingest_url`) and the named caps
(`MAX_REDIRECTS`, `MAX_BYTES`, `FETCH_TIMEOUT_SECONDS`, `ALLOWED_PORTS`,
`ALLOWED_CONTENT_TYPES`).

`validate_target(..., allow_loopback=True)` is a **test-only seam**: it admits a
loopback target on its ephemeral port so a throwaway `http.server` can be
exercised end to end.  It is unsafe for production, only tests and the
`.scratch/` end-to-end script pass it, and it is never exposed as a request
field.  The guards keep a residual TOCTOU race, documented in
`docs/ARCHITECTURE.md`.

### Job pool configuration

Queued operations are drained by a bounded background pool that the API starts
on the first submit.  It can be switched off, which is what a test does so no
thread runs a job behind an assertion, and what an operator does who would
rather drive the queue with `reportal job-run`.

| Setting | Env var | Default |
|---------|---------|---------|
| Job pool | `REPORTAL_JOBS_POOL` (falsey: `0`, `false`, `no`, `off`) | on |

### Identity configuration

Token auth is off by default, so a loopback install answers every request as the
local operator.  Turning it on puts every `/api` route behind
`Authorization: Bearer <token>`; `reportal serve --host` refuses a non-loopback
bind unless it is on and an enabled user exists.

| Setting | Env var | `reportal.toml` key | Default |
|---------|---------|---------------------|---------|
| Require token auth | `REPORTAL_AUTH` (truthy: `1`, `true`, `yes`, `on`, `required`) | `[auth] required = true` | off |

User management is `reportal user-add <name> [--role viewer|analyst|admin]`
(which prints the token once), `user-token`, `user-edit`, `user-rm` and `users`;
teams are `reportal teams`, `team-add`, `team-rm`, `team-member`, `binary-scope`
and `collection-scope`; and the identity-side reads are `reportal activity
[--actor] [--since]`, `feedback` and `feedback-add <message>`.  Only the token's
SHA-256 digest is stored, the SPA keeps the bearer token in `localStorage`
(`api.TOKEN_STORAGE_KEY`), and each journal entry records the `actor` the server
set around the request (`server.authenticate` + `journal.acting_as`).

### Secret-store configuration

The optional LLM bridge resolves its API key first match wins: the environment,
then the workspace `reportal.toml` `[llm]` table, then the store under
`llm.api_key`.  The external sources read the same way: the VirusTotal key
resolves from its own environment variable and table key, then the store's
`virustotal.api_key` entry (`secret_store.resolve_from_workspace`).

| Where | Spelling | Notes |
|-------|----------|-------|
| Store name | `llm.api_key` | set with `reportal secrets-set llm.api_key --stdin`, or the API/SPA/MCP |

The store itself is `reportal secrets-list` / `secrets-set` / `secrets-rm` and
`GET`/`PUT`/`DELETE /api/secrets[/<name>]`: one credential per `(name, scope,
team_id)`, at workspace scope or a team's.  A read reports the name, scope, byte
length and a last-four hint (nothing for a value shorter than
`secret_store.MIN_HINT_LENGTH`) and never the value; `value_of` is the internal
read.  A workspace secret needs an admin to write and a team secret that team's
membership, and every write is journaled, so a rotation is revertible.
`docs/THREAT_MODEL.md` states the plaintext-at-rest boundary and the journal
residual.

### External source configuration

An external source answers one question about one analysis.  The offline `local`
source derives its answer from rows the workspace already holds and never makes
a request.  The remote `virustotal` source is off until the workspace opts in
and a key resolves; a request goes to one fixed https host, follows no redirect
and stores a normalized subset of the answer.

| Setting | Env var | `reportal.toml` key | Default |
|---------|---------|---------------------|---------|
| Enable remote sources | `REPORTAL_ALLOW_EXTERNAL` (truthy: `1`, `true`, `yes`, `on`) | `[external] allow_remote = true` | off |
| VirusTotal key | `REPORTAL_VIRUSTOTAL_KEY` | `[external] virustotal_api_key` | the secret store's `virustotal.api_key` |

While the gate is off every remote call answers 403 `external-disabled` and no
socket is opened; without a key the answer is 503 `external-unavailable`.
`GET /api/external/sources`, `reportal external-sources`,
`POST /api/analyses/<id>/external/<source>`, `reportal external <analysis-id>
[--source NAME]` and the four MCP tools from `list_external_sources` to
`run_external_source` expose the registry, the pulls and the status, and a third
party registers a source through the `reportal.external_sources` entry-point
group.  `docs/THREAT_MODEL.md` states what a pull discloses.

### Sandbox configuration

Detonation is off by default, and the second guard is a runner that is actually
installed.  `reportal sandbox --status` reports both.

| Setting | Env var | `reportal.toml` key | Default |
|---------|---------|---------------------|---------|
| Allow detonation | `REPORTAL_SANDBOX` (truthy: `1`, `true`, `yes`, `on`, `enabled`) | `[sandbox] enabled = true` | off |
| Runner to use | `REPORTAL_SANDBOX_RUNNER` | `[sandbox] runner` | the first installed runner (`bwrap`) |

A third party registers a runner through the `reportal.sandbox_runners`
entry-point group, whose value is a `sandbox.Runner` or a zero-argument factory
returning one.  The caps are `sandbox.DEFAULT_TIMEOUT_SECONDS` 10 /
`MAX_TIMEOUT_SECONDS` 60, `DEFAULT_MEMORY_MB` 512 / `MAX_MEMORY_MB` 4096 and a
CPU cap no larger than the wall clock.

### Graph backend configuration

The knowledge graph's backend registry is local and needs no configuration: the
built-in `sqlite` backend is the default and the Cognee backend is available
only when its extra is installed.  Both settings resolve first match wins: the
environment, then the workspace `reportal.toml` `[knowledge]` table.

| Setting | Env var | `reportal.toml` key | Default |
|---------|---------|---------------------|---------|
| Default sync backend | `REPORTAL_GRAPH_BACKEND` | `[knowledge] graph_backend` | `sqlite` |
| Cognee dataset | `REPORTAL_COGNEE_DATASET` | `[knowledge] cognee_dataset` | `reportal` |

A backend name the registry does not know is 404 `backend not found` on the
sync route (the CLI fails with `unknown graph backend`), and the `cognee`
backend without the extra is 503 `backend-unavailable` with the
`uv sync --extra cognee` hint.  No credentials are read or stored.

## API Endpoints

Moved to [docs/API.md](docs/API.md).

## MCP server

`reportal mcp [--json]` runs a local MCP server over stdio: newline-delimited
JSON-RPC 2.0 on stdin/stdout, the transport local MCP clients use.  It
implements `initialize`, the `notifications/initialized` notification,
`tools/list` and `tools/call`, reports protocol version `2025-06-18` and
`serverInfo` `{"name", "title", "version"}` (the hosted portal's shape), and
advertises a `tools` capability.  The protocol is the official `mcp` SDK's
(`mcp_server.py` builds a `Server` with `on_list_tools`/`on_call_tool` handlers
and runs it over the SDK's stdio transport), so the framing, the version
negotiation and the dispatch are the library's; reportal supplies the tool
registry and `call_tool`, which the suite also drives directly.  Nothing but protocol JSON reaches
stdout; a one-line readiness message (name, version, tool count, workspace)
goes to stderr.  Startup resolves the workspace through the normal
`reportal.toml` walk-up and fails loud outside one.

Tools are plugins declared in `mcp_tools.py`.  Each is a `Tool` with a `name`,
a `description`, an input JSON Schema, `annotations` (`readOnlyHint`,
`destructiveHint`) and a handler.  Built-ins register in-tree; a third party
registers an entry point in the `reportal.mcp_tools` group whose value is
`module:attr` naming a `Tool` or a zero-argument factory returning one
(discovery mirrors `reportal.components`: a broken registration is skipped with
a warning and a duplicate name is a `RegistryError`).  The sub-registry exposes
`register_tool`, `tools` and `refresh_tools`.  Handlers call reportal's
internal functions directly (store, engines, pipeline, llm) and never make an
HTTP request back into reportal.

The split is by what a tool may change.  Read tools call the internal helpers
the `GET` routes use, so a stored-only route stays stored-only.  Destructive
tools carry `destructiveHint: true`: anything that runs an engine, renames,
uploads, deletes, or runs or reverts a pipeline.  `search` reads the store and
runs nothing, so it is read-only.  A destructive handler that wrote at least one
journaled row returns its JSON payload with a `journal_action` field, the same
id the routes carry, so an agent can revert the tool's writes through
`revert_journal_entry`; a no-op (an already-known tag, a duplicate ingest) omits
it.  The pipeline and auto-mode tools keep their run-scoped plans, and
`reload_components`, `sync_graph_backend` and `revert_journal_entry` itself
write no journaled row, so they carry no action id.  A handler that fails
answers an MCP tool error (`isError: true` with `{"error", "detail"}`); an
unknown method, an unknown tool and invalid params answer JSON-RPC error
objects, and a tool error never ends the loop.  `list_components` reads the component registry and is
read-only, and `list_integrations` reads every plugin seam with the parts its registry holds;
`reload_components` re-imports one component's declaration or every
reloadable one and swaps the live registry entry, and `deactivate_components`
withdraws one component from the live composition (running its revert and
revoking the names it provided, journaling a durable write when it records
one), so both are destructive.
`list_documents`, `search_knowledge` and `retrieve_knowledge` read the store
and run nothing, so they are read-only; `ingest_document` writes it and
`ingest_url` fetches a URL (enabled only when `remote_ingest.remote_enabled()`,
else a `remote-ingest-disabled` tool error) and writes it, so both are
destructive, and `delete_document` writes it and is destructive.  `get_graph` and
`graph_neighbors` read the stored graph and are read-only; `build_graph`
rewrites it from the stored rows and is destructive.  `list_graph_backends`
reads the backend registry and is read-only; `sync_graph_backend` pushes the
stored graph to a backend (the configured one when none is named) and is
destructive, answering a `backend-unavailable` tool error with the install hint
when the backend is not installed.  `get_threat_report` serves
the stored report (plus the derived `software_type` and `threat_score`) and is
read-only; `run_threat_report` builds and stores one
(running the engine, and the LLM only when `narrative` is set) and is
destructive; `get_triage` and `run_triage` answer the same two derived keys.
`get_remediation` serves the stored remediation payload (YARA,
Snort and STIX) and is read-only; `run_remediation` generates, validates and
stores all three and is destructive.
`get_secrets_scan` serves the stored secrets scan and is read-only;
`run_secrets_scan` matches and stores one and is destructive.
`get_protocols_scan` serves the stored protocol inference and is read-only;
`run_protocols_scan` infers and stores one and is destructive.
`get_behavior_scan` serves the stored behavior scans (one domain, or all three)
and is read-only; `run_behavior_scan` matches and stores one domain, or all
three when none is named, and is destructive.  `get_hardening_scan` serves the
stored hardening scans (one domain, or both) and is read-only;
`run_hardening_scan` applies one domain, or both when none is named, and is
destructive.  `get_pe_info` serves a binary's stored PE metadata and is
read-only; `run_pe_info` inspects the binary through the engine and stores the
result, so it is destructive.  `read_memory` reads a window of a binary's bytes
by address through the engine and is read-only.  `get_function_triage` serves a binary's stored per-function
summaries and scores and is read-only; `run_function_triage` summarizes and
stores them (the configured LLM, else the heuristic) and is destructive.
`get_renames` serves a function's stored rename suggestions and
is read-only; `suggest_renames` asks the bridge for them and stores them,
`apply_renames` rewrites the stored decompilation (accepting an explicit
`applied` list or, without one, every stored suggestion) and journals the
previous text, and `revert_renames` restores that text, so all three write and
are destructive.  `get_lineage` serves a stored comparison of two binaries (one
pair with `other_binary_id`, or every comparison stored for the binary without
it) and is read-only; `run_lineage` compares two binaries and stores the
comparison on the left binary, and is destructive.  `get_related_binaries`
serves a binary's stored relationship ranking and is read-only;
`run_related_binaries` ranks the other binaries against one binary and stores
the ranking, and is destructive.  `get_composition` serves a binary's stored
composition analysis and is read-only; `run_composition` builds it from the
stored matches and stores it (running no matching and no engine), and is
destructive.  `search` reads the store and runs nothing, so it is read-only;
its `kind` argument selects the typed query.  `extract_archive` unpacks a
stored archive and registers its members into one collection as one journaled
action, so it is destructive (`binary not found`, `binary not on disk`,
`collection not found` and the archive module's own codes answer tool errors).
`list_families` reads the
family store and `get_detect_scan` serves a stored detection, so both are
read-only; `register_family` derives and stores a signature bundle,
`delete_family` removes a family and `run_detect` matches a binary and stores
the detection, so all three are destructive.  `list_data_types` reads the local
type model (each type encoded with its members' gap flags, its enum values'
hex echoes, its As-C block and its size-vs-members check) and is read-only;
`import_data_types` seeds it from the stored
structs scan, `edit_data_type` sets a type's name, kind, namespace or declared
size, edits, adds, positions, converts or removes its members (including a
member's `pointer`, `count`, `bits` and its `index`/`after` position, and the
to-gap/from-gap conversion) or adds, renames, revalues or removes its enum
values, and `export_data_types` writes the rendered header to the
caller's path, so all three are destructive.  `get_data_type_history` reads a
type's edit history with each version's per-field diff and is read-only;
`revert_data_type_history` restores the state one history row recorded, is
journaled (a deleted type's row comes back) and is destructive.  `get_signature` and
`list_signatures` read the stored signature model and are read-only;
`run_signature_import` seeds it from the stored decompilations,
`edit_signature` sets the return type or convention or edits, adds, moves,
removes or
deletes a parameter (its edit and add objects take the optional `at`, `kind`
and `bits`) and `export_signatures` writes the rendered prototype
header, so all three are destructive.  `get_signature_history` reads a
function's signature-edit history and is read-only; `revert_signature_history`
restores the state one history row recorded, is journaled and is destructive.
`list_comments` reads the analyst
comment store and is read-only; `add_comment`, `update_comment` and
`delete_comment` write it and are destructive.  `bulk_binaries`,
`bulk_functions` and `bulk_analyses` apply one action to a bounded id list through
`bulk_actions`, so all three are destructive.  `list_users` reads the user table
(never a digest) and is read-only; `add_user`, `rotate_user_token`,
`update_user` and `delete_user` write it and are destructive.  `list_teams`
reads the team store and is read-only; `create_team`, `delete_team`,
`add_team_member`, `remove_team_member`, `set_binary_scope`,
`set_collection_scope`, `set_team_member_role`, `create_organisation`,
`delete_organisation` and `set_team_organisation` write it and are destructive;
`list_organisations` reads the organisation store and is read-only, and a
membership's `owner`/`member` role is what `set_team_member_role` sets.  `list_journal` reads the
action-journal entries and is read-only; `revert_journal_entry` replays one
action's or one entry's stored inverses and is destructive.  `get_filetype`
serves a binary's stored file-type detection and is read-only; `run_filetype`
assembles the evidence, detects and stores the matches, and is destructive.
`get_firmware_scan` reads the stored carve pass and is read-only;
`run_firmware_scan` carves and stores one and `extract_firmware_regions` carves
its regions out as binaries, so both are destructive.  `list_analyses` lists analyses with their binary, status and scope (the owning
binary's `visibility`, owner team and the `personal`/`team`/`public` workspace
filter) and is read-only.  `list_artifact_ratings` reads every stored agent artifact of a binary with the
analyst's verdict on it and is read-only; `rate_artifact` records or clears that
verdict, journaled, and is destructive.  `get_stats_series` reads the dashboard's 30-day series (analyses, auto runs,
journaled actions and the derived software types) from stored rows and is read-only.
`get_activity` reads the
activity feed and `list_feedback` the stored notes, so both are read-only;
`add_feedback` writes one and is destructive.  `get_ai_decompilation`,
`get_ai_decompilation_status`, `list_ai_decompilation_tokens`,
`get_ai_line_attributions` and `list_ai_line_comments` read the stored AI
decompilation artifact and are read-only; `run_ai_decompilation` asks the
configured LLM for a whole rewritten function and stores it,
`set_ai_decompilation_overrides` sets or clears the analyst names of its
placeholder tokens, `rate_ai_decompilation` records feedback and
`add_ai_line_comment`, `update_ai_line_comment` and `delete_ai_line_comment`
write its per-line comments, so all six are destructive.  `get_signature_batch` reads many functions'
signatures in one call and `get_data_type_functions` reads the functions using
one type, so both are read-only; `copy_signature` copies one function's
signature onto others in its analysis and `import_type_definitions` creates or
updates an analysis's types from C declarations, so both are destructive.
`get_library` reads a binary's stored library identification (the module
rollup and the per-candidate list) and `export_sbom` renders it as CycloneDX,
SPDX or CSV, so both are read-only; `run_library` runs the engine's signature
match over the binary's rebrew project and stores the reading, and is
destructive.  `get_unpack` reads a binary's stored unpack provenance (the packed
source and its hash, the packer and what identified it, the method and the
sizes), and `run_unpack` rebuilds a packed binary's image, registers it as a
binary of its own and stores that provenance on the new binary, so the read is
read-only and the run is destructive (it answers a `no-packer`,
`unknown-packer`, `no-unpacker` or `unpack-failed` tool error for a file it
cannot rebuild).  `get_symbols` reads a binary's ingested debug symbol
files (kind, counts, notes and the parse) and is read-only; `import_symbols`
parses a PDB or an ELF/DWARF file, renames the functions whose VA matches a
symbol and adds the aggregate types it declares as one journaled action, and
`export_symbols` writes one parse out as a C header or JSON, so both are
destructive.  `list_docs` reads the shipped manual's page index and `get_doc`
parses one page into blocks (headings, paragraphs, lists, code, quotes and
tables, never markup), so both are read-only.  `list_conversation_runs` and `get_conversation_run` read an agent conversation's runs
(the status, the tool-call count, the events, the call awaiting confirmation and the
answer) and are read-only; `run_conversation_agent` runs one tool loop over the local
MCP registry (a read-only tool runs at once, a destructive one pauses the run),
`confirm_conversation_run` approves or rejects the pending call and continues the run,
and `cancel_conversation_run` stops a live one, so all three are destructive.
`get_indirect_call_sites`,
`get_function_capabilities`, `get_function_strings`, `list_analysis_strings`,
`list_function_edges`, `get_functions_callees_callers` and `get_function_matches`
read the per-function extras (the cached listing's indirect call sites, the
classification over the function's own imports and literals, the analyst strings
beside the derived literals, the declared callee edges and the two batch reads)
and are read-only; `add_function_string`, `delete_function_string`,
`replace_analysis_strings`, `add_function_edge`, `delete_function_edge` and
`canonicalize_function_names` write them and are destructive, and every payload
of a derived read carries the note saying it is a text scan rather than engine
output.  `list_external_sources`,
`get_external_report` and `get_external_status` read the external-source registry
and the stored answers and are read-only; `run_external_source` runs one source
for an analysis and stores its answer, and is destructive (a remote source is
refused unless the workspace opted in and a key resolves).  `list_secrets` reads the
secret store, redacted to its name, scope, byte length and a last-four hint, and
is read-only; `set_secret` and `delete_secret` write it and are destructive, and
neither ever returns the value.  `list_models` reads the model
registry and is read-only; `upgrade_analysis_model` re-runs an analysis's stored
LLM artifacts under a named `llm` model, journaling every artifact it replaces,
and is destructive.  `get_sandbox_report` and
`get_sandbox_status` read the detonation ledger and are read-only;
`run_sandbox_detonation` executes a sample under the sandbox runner and is
destructive (and refused unless the install opted in).
The registry
declares 238 built-in tools, 112 read-only and 126 destructive.

## SPA

Moved to [docs/SPA.md](docs/SPA.md).

## Data Model

Moved to [docs/DATA_MODEL.md](docs/DATA_MODEL.md).

## Engines

`engines.py` is the only module that runs an engine.  `RebrewEngine` calls the
sibling `rebrew` package in process and returns what it returns: a call the CLI
exposed as parsed JSON gets the module function's dict, and a failure
(`typer.Exit` from rebrew's `error_exit`, a missing module, or any other
exception) becomes an `EngineError` with a bounded one-line message.  Nothing
is re-shaped.

`rebrew` is a base dependency (a path source on the sibling checkout).
`RebrewEngine.available()` reports whether its package is importable, and
`enabled` pins either side for a caller or a test; every method raises
`EngineUnavailable` when it is not, so a broken engine degrades to a named
error rather than a traceback.  Callers go through `get_engine()` /
`set_engine()`, the process-wide accessor.

| Method | rebrew entry point | Context |
|--------|--------------------|---------|
| `fingerprint` | `rebrew.fingerprints.fingerprint_bundle` | standalone |
| `imports` | `rebrew.imports.imports_payload` | standalone |
| `strings` | `rebrew.strings.collect_strings` | standalone |
| `analyze` | `rebrew.analyze.build_dossier` | standalone (the cwd project's config when there is one) |
| `crypto_scan` | `rebrew.crypto_scan.crypto_scan` | standalone |
| `pe_info` | `rebrew.pe_info.pe_info` | standalone |
| `decompile` | `rebrew.decompiler.fetch_decompilation`, plus `rebrew.name_decomp.apply_known_names` for `named` | project |
| `xrefs` | `rebrew.xrefs.build_xrefs_payload` | project |
| `describe` | `rebrew.describe.build_dossier` over `rebrew.binary_loader.load_binary` | project |
| `structs` | `rebrew.struct_recover.recover_project_structs` | project |
| `security_scan` | `rebrew.security_scan.security_scan` | project |
| `identify_library` | `rebrew.identify_library.collect_candidates` | project |
| `lzexe_version` | `rebrew.lzexe.lzexe_version` | standalone |
| `unpack_lzexe` | `rebrew.lzexe.unpack_lzexe`, written into the caller's path | standalone |
| `report` | `rebrew.report.generate_report` | project |

A project method loads its config with `rebrew.config.load_config(root)` from
the validated project root on every call: a project's TOML and annotations
change between calls, so a cached config would go stale.  `DECOMPILER_BACKENDS`
(`auto`, `kuna`, `r2ghidra`, `r2dec`, `ghidra`) and `SECURITY_SEVERITIES`
(`high`, `medium`, `low`) are validated before any engine work.
`identify_library` is the engine's dry run: it returns the payload a write
would report (`identified`, `to_write`, `written: 0`, `candidates`) and writes
nothing.  `decompile`'s `named` applies the project's declared structs through
`apply_known_names`; the result carries the engine's `code`, `backend`,
`applied` and `named`.  `report` writes its HTML into reportal's own output
directory (`_paths.reports_dir(binary_id)`), never into the rebrew project.

Three calls use the engine's own entry points in process, with the project's
resolved config:

- `disassemble` returns `rebrew.asm.disassemble_to_nasm` for `nasm` and
  `rebrew.asm.hex_disassembly` for `hex`, each the text the CLI prints, so the
  disassembly route caches and serves the same bytes.
- `control_flow_graph` returns `rebrew.asm.build_cfg_payload(cfg, va, size)`,
  the same object `rebrew asm --format cfg --json` prints: the blocks, the
  edges and the `block_count`/`block_total`/`block_cap`/`truncated`/`note`
  fields, with every address as `0x...` text.  A positive *size* is the
  declared extent; zero lets the engine resolve the extent itself and answers
  empty blocks with a note rather than a guessed window.
- `test_source` returns `rebrew.test.run_test(cfg, source, no_promote=True)`.
  A mismatch is a result, not a failure: the object is returned for a match and
  a mismatch alike, and only a tooling failure raises.
- `unpack_lzexe` writes `rebrew.lzexe.unpack_lzexe(path).to_bytes()` to the
  caller's path, so the LZEXE case of `reportal unpack` is the engine's own
  unpacker in process and reportal reimplements no decompressor; its detection
  half, `lzexe_version`, answers None for a binary that is not LZEXE-packed
  rather than raising.

`read_memory` and
`read_memory_page` take their section map from the engine's own `pe_info` and
then read the file exactly where that map says the bytes live; rebrew exposes
no raw byte-read entry point and reportal never parses a PE.

The health route reports the engine as `{"available": ..., "origin": ...}`,
where `origin` is the installed package's path (null when it is absent).

`matching.py` is the only module that scores functions.  `match_binary` ranks
each function of a binary against the candidate corpus through an injected
scorer and disassembler, under a `MatchSettings` scope (`min_similarity`,
`min_confidence`, `include_self`, `top`, `platforms`, `architectures`,
`binary_ids`, `collection_ids`; `from_request` validates a request body against
each setting's bound or closed vocabulary and raises `InvalidSettingsError`,
which the API, CLI and MCP map to their own error vocabulary, and
`resolve_scope` validates the named binary and collection ids).  The candidate
corpus is the whole register unless the settings name a scope; the
platform/architecture filter is a coarse best-effort comparison against a
binary's stored fingerprint (else its suffix-derived `format`/`arch` columns),
which `scope_notes` states in the response.  Every recorded row carries the
settings that produced it, so a later reader can tell which run wrote it.  The
scorer defaults to `similarity.similarity`, which lazy imports the optional
`similarity` extra and raises `SimilarityUnavailable` without it.  The default
disassembler resolves the function's rebrew context, reads `disasm_cache`, else
runs `rebrew asm` and caches the result.  Without the extra, matching reports
unavailability and reportal works unchanged.

`plan_transfer` computes one symbol transfer (a mode of `name`, `signature` or
`both`) without writing, `apply_transfer` writes and journals it, and
`transfer_matches` plans and applies a batch as one journaled action with a
per-row `applied`/`skipped`/`failed` report (`dry_run` writes nothing).  A
signature transfer copies the candidate's return type, calling convention and
parameters; a referenced local type the target's binary has no `data_types`
row for is reported in `missing_types`, and a target carrying a different
non-empty calling convention is refused `signature-conflict`.  `apply_match`
and `run_match` expose the same over MCP, and the counts stay 238 built-in
tools (112 read-only, 126 destructive).

### Scaling

`match_binary` scores pairwise over the corpus, so a run makes
`len(functions) * (len(corpus) - 1)` ratio comparisons and the cost grows with
the square of the corpus size.  `similarity.similarity` prepares each distinct
listing once per process (tokenized, MinHash-built and packed, keyed by the
listing text, bounded by `PREPARED_CACHE_SIZE`); `cache_info()` and
`clear_cache()` expose and drop that cache.  The cache removes the repeated
preprocessing, not the pairwise term.  Shortlisting candidates by LSH banding
over the packed fingerprints is the next lever once a corpus grows past a few
thousand functions.

## Conventions

- Python 3.12+, `src/` layout, setuptools, `dynamic = ["version"]` from `reportal.__version__`.
- Runtime deps: `fastapi`, `uvicorn` (the ASGI application),
  `python-multipart` (its multipart reader), `reportlab` (the PDF export's
  writer), `openai` (the optional LLM bridge, `llm.py`), `httpx2` (the one HTTP
  client line: the bridge, the `mcp` SDK and guarded URL ingestion in
  `remote_ingest.py`), `rebrew`
  (sibling path dep via `[tool.uv.sources]`; the in-process engine and the
  shared `rebrew-project.toml` + coverage.db resolver), `rich`, `typer`.  No
  network call happens until an LLM endpoint is configured or a URL is
  ingested.  Dev extra: `pytest`, `pytest-cov`, `ruff`, `mypy`.  Optional `similarity` extra:
  `resembl` (sibling path dep via `[tool.uv.sources]`), `rapidfuzz` (pygments
  arrives through resembl).
  Optional `cognee` extra: `cognee>=1.5`, which makes the graph-sync Cognee
  backend available.  `cognee.add` accepts text records and `cognee.cognify`
  needs a configured model, so the sync pushes the translated graph as JSON
  records and answers `backend-unavailable` with the model reason when no model
  is configured; `tests/test_graph_backends.py` exercises the real package when
  it is installed and skips when it is not.
- Type annotations on every parameter and return; PEP 604 unions; specific generics.
- Ruff: line length 100, `select` groups E/F/W/I/UP/B/SIM/A/DTZ/G/N/PGH/TID/RUF100/T10/C4/RET/PIE/ISC/FURB/T20, no ignores.
- Typer CLI; human output to stderr through `Console(stderr=True)`; `--json` payloads to stdout.
- FastAPI application served by uvicorn, loopback bind by default, Host-header guard against DNS rebinding.  `server.app` is the ASGI app and `api.router`/`ui.router` are its routes.  A handler is a plain `def` (FastAPI runs it on the threadpool) unless it parses a multipart body itself, takes `request: Request` when it reads the query string and `body: dict[str, Any] = Depends(json_body)` (or `optional_json_body`) when it reads a JSON body.  Nothing 500s on a request error: `json_error` is both a response and an exception, and the handlers in `server.py` keep FastAPI's own refusals (405, a malformed path parameter, an unreadable multipart body) inside the `{"error", "detail", "doc_url"}` envelope.
- The API gate is one middleware (`server._reportal_headers` calling
  `server.authenticate`), not a per-route dependency, because it also sets the
  `journal.acting_as` actor the request's entries record; a `/api` path is behind it
  by construction and an install that never enables auth behaves exactly as before.
  `auth.py` owns the `users` and `teams` tables, the role permission sets
  (`ROLE_PERMISSIONS`, with `_SELF_PATHS` keeping `users/activity` and
  `users/feedback` self-service), the digest-only token storage and the constant-time
  comparison; `cli.serve` refuses a non-loopback bind while the gate is off or no
  enabled user exists, and `docs/THREAT_MODEL.md` records the boundary.
  Object authorization rides the same check: a binary or a collection carries a
  `visibility` (`public`/`team`) and an `owner_team_id`, `server._enforce_scope`
  resolves the object a path names (a function or analysis through its binary) and
  `auth.visible_clause` is the SQL rule the listings, the search and the bulk guard
  share, so a new route is scoped by construction too.
- SPA is Vite + React + TypeScript in `web/`, built with bun into
  `src/reportal/assets/dist/` (generated, gitignored).  Routing is
  react-router and every fetch is `@tanstack/react-query`; no CDN.
- Components: the AI decompilation pipeline is a composition of components
  (`src/reportal/components.py`).  A component declares `requires`/`provides`
  plus an `effect`.  `Context` carries the values and the reversible journal:
  `provide`/`revoke` capture the binding they replaced, `record` journals a
  persistent write with its JSON undo descriptor, and `revert` applies the
  journal newest-first.  `Context.subscribe` reports each `(name, kind)` change,
  which is what lets `pipeline.run_pipeline` re-evaluate activation mid-run: a
  component activates when its requirements hold and is recorded `deactivated`
  when one is revoked before it ran.  Persistent writes revert through one
  dispatcher, `src/reportal/effects.py` (`apply_descriptor`,
  `apply_undo_plan`, `plan_context`), which both the pipeline and `auto_mode`
  use.  The dispatcher resolves a descriptor's `kind` through a registry
  (`register_effect_handler` / `effect_handlers` / `refresh_effect_handlers`);
  the built-in kinds are declared by `builtin_effect_handlers()`, and a third
  party adds a kind through the `reportal.effect_handlers` entry-point group,
  whose value is a handler `(conn, descriptor) -> dict | None` or a mapping of
  kind to handler.  A broken registration is skipped with a warning; a duplicate
  kind is a `RegistryError`.  Built-ins are declared in
  `pipeline.builtin_components()`; a third
  party registers one through the `reportal.components` entry-point group,
  whose value is `module:attr` naming a `Component` or a zero-argument factory
  returning one.  A broken registration is skipped with a warning; a duplicate
  name is a `RegistryError`.  Every registration records its origin, declaring
  module and reloadability (`components.registrations()`):
  `components.reload_component(name)` re-imports the declaring module through
  `importlib.reload` (re-initializing module-level state) and swaps the live
  registry entry in place, keeping declaration order, and `reload_all()`
  reports one result per entry and skips the non-reloadable ones with a reason.
  `refresh_components()` stays the whole-registry re-discovery; the reload
  swaps one entry.  A component registered in-process has no declaring module
  and raises `NotReloadableError`; an entry-point module that stops binding its
  declaration raises `ComponentMissingError`.  `pipeline.ComponentHost` holds a
  live `Context` and drives deactivate → reload → activate for a component and
  its dependents, calling `Component.revert` where declared and revoking the
  names withdrawn.  A withdrawal is reachable outside Python through
  `pipeline.withdraw_component` (the process-wide live host of
  `pipeline.live_host()`), the `POST /api/components/<name>/deactivate` route,
  the `reportal components-deactivate` command and the `deactivate_components`
  MCP tool; it refuses a component that provides nothing and declares no revert
  or one already withdrawn, and journals a durable write the withdrawal records
  as one action entry (`journaled: false` when it recorded none).
  `pipeline.revert_run` stores and replays the binding changes a run made
  (`effects.EFFECT_CONTEXT_CHANGE`): a change this process still holds is
  applied for real and reported `applied: true`, one a later process cannot
  resolve is reported `applied: false`.  The swap applies to the next
  composition: a run in flight keeps its snapshot.  `docs/COMPONENTS.md` maps
  the model to the paper it follows and lists what is not implemented.
- Auto workers follow that pattern (`src/reportal/auto_workers.py`): built-ins
  are declared by `offline_worker()` in `auto_workers.py` and
  `llm_c_source_worker()` in `auto_llm_worker.py`; a third party registers
  through the `reportal.auto_workers` entry-point group, whose value is
  `module:attr` naming a `Worker` or a zero-argument factory returning one.  A
  broken registration is skipped with a warning; a duplicate name is a
  `RegistryError`.  `reportal auto` and `POST /api/binaries/<id>/auto` are
  dry-run by default: only `--execute` (or `"execute": true`) writes candidate
  C files into the rebrew project and compiles them, never overwriting an
  existing source file; a run records every file it wrote and every status it
  replaced, each task folds its own undo descriptors into
  `auto_runs.effects_json` in the commit that records its result, and
  `auto-revert` replays that plan through the shared dispatcher to put both
  back.  A run a dead process left `running` is closed by `auto-recover` (or
  `reportal auto --recover` / `POST /api/auto/runs/<id>/recover`), which merges
  the writes its unfinished tasks recorded before marking them `interrupted`.
- MCP tools follow the same pattern (`src/reportal/mcp_tools.py`): built-ins
  are declared in `builtin_tools()` and a third party registers through the
  `reportal.mcp_tools` entry-point group, whose value is `module:attr` naming a
  `Tool` or a zero-argument factory returning one.  The stdio server is
  `src/reportal/mcp_server.py`; it is the only module that writes the protocol
  to stdout.
- Models follow the same pattern (`src/reportal/models.py`): the built-ins are
  declared by `builtin_models()` (the engine, each decompiler backend, the
  configured bridge model and the optional similarity extra) and a third party
  registers through the `reportal.models` entry-point group, whose value is
  `module:attr` naming a `Model` or a zero-argument factory returning one.  A
  broken registration is skipped with a warning and a duplicate name is a
  `RegistryError`.  `Model.describe()` carries the kind, version, availability
  and the reason it is not available; only an `llm` model can be the target of
  `models.upgrade_analysis`, which re-runs an analysis's stored LLM artifacts
  and journals every replacement rather than re-analysing the binary.
- External sources follow the same pattern (`src/reportal/external.py`): the
  built-ins are declared by `builtin_sources()` (the offline `local` derivation
  and the guarded remote `virustotal` pull) and a third party registers through
  the `reportal.external_sources` entry-point group, whose value is
  `module:attr` naming a `Source` or a zero-argument factory returning one.  A
  broken registration is skipped with a warning and a duplicate name is a
  `RegistryError`.  `Source.retrieve(context)` returns the payload stored as the
  analysis's `external:<source>` scan, and `journaled_run` is the one write path
  the routes, the CLI and the MCP tools share.
- Knowledge-graph backends follow the same pattern
  (`src/reportal/graph_backends.py`): built-ins are declared in
  `builtin_graph_backends()` (`sqlite`, the default, and the optional `cognee`)
  and a third party registers through the `reportal.graph_backends` entry-point
  group, whose value is `module:attr` naming a `GraphBackend` or a zero-argument
  factory returning one.  A `GraphBackend` carries `available()`, `describe()`,
  `sync(conn, *, binary_id, payload)` and an optional `query(conn, *, query,
  limit)`; `sync_graph` assembles the payload (document nodes included) and
  dispatches, and `run_query` dispatches a query.  A registered backend that is
  not installed raises `BackendUnavailableError`, surfaced as 503
  `backend-unavailable` by the API, `backend-unavailable` by the CLI and a
  `backend-unavailable` tool error by MCP.  The default backend comes from
  `REPORTAL_GRAPH_BACKEND` or `[knowledge] graph_backend`, and the Cognee
  dataset from `REPORTAL_COGNEE_DATASET` or `[knowledge] cognee_dataset`.
- No em dashes in docs, code or commits. No comments that narrate control flow.

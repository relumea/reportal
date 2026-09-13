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

An optional OpenAI-compatible LLM bridge (`llm.py`) provides the portal's AI
extras (a function summary, inline comments, type suggestions and identifier
renames) over a decompilation reportal already stored.  It is disabled until an
endpoint is configured; without one every AI route answers 503
`llm-unavailable` and no network call is made.

## Project Structure

```
reportal/
├── pyproject.toml          # package config, entry point: reportal; mypy, ruff and coverage config
├── Makefile                # the gate (make check, see "Gate") and the dev server (make run)
├── scripts/                # gate helpers: vnu-html.sh, check_wheel.py
├── .github/workflows/check.yml  # CI: every gate target but the two browser ones
├── README.md               # user-facing docs
├── LICENSE                 # MIT
├── docs/README.md          # docs index
├── docs/PARITY.md          # capability map vs portal.reveng.ai
├── docs/ARCHITECTURE.md    # module map, store, engine contract, HTTP surface, SPA
├── docs/COMPONENTS.md      # component model: revertible effects, reactive activation, gaps
├── docs/ERRORS.md          # one section per error code, what it means and what to do
├── docs/API.md             # the HTTP surface, route by route
├── docs/CLI.md             # every `reportal` command, its options and what it writes
├── docs/SPA.md             # the single-page app, module by module
├── docs/DATA_MODEL.md      # the SQLite schema and what writes each table
├── tests/                  # pytest suite (self-contained, tmp_path based)
├── tools/
│   ├── cdp.py              # shared DevTools client: launch Chrome, render a route, wait on the DOM
│   ├── smoke_spa.py        # builds web/ when needed, then headless-Chrome smoke over every route
│   ├── audit_ui.py         # headless-Chrome UI gate: overflow, clipped text, contrast, names
│   └── seed_e2e.py         # seeds the Playwright suite's workspace (smoke seeding + collections + tag)
├── web/                    # Vite + React + TypeScript frontend (bun)
│   ├── package.json        # scripts: dev, build, preview, lint (oxlint), typecheck, test:ui
│   ├── vite.config.ts      # root web/, base /static/, outDir ../src/reportal/assets/dist
│   ├── playwright.config.ts # Playwright: one chromium project, global seed + server setup
│   ├── index.html          # Vite entry page (mounts #root)
│   ├── public/favicon.svg  # copied verbatim into the build
│   ├── tests/              # Playwright specs plus the seed, server and fixture helpers
│   └── src/
│       ├── main.tsx        # React root, imports the global stylesheet
│       ├── App.tsx         # shell: grouped sidebar, topbar, health line, route dispatch
│       ├── components.tsx  # UI primitives: Panel, Button, Badge, Field, DataTable,
│       │                   #   SegmentMeter, Readout, EmptyState, Loading, ErrorNote,
│       │                   #   CodeBlock, KeyValue
│       ├── design.ts       # instrument token names: status/confidence/severity
│       │                   #   entities, the hue families, the meter geometry
│       ├── queryClient.ts  # the one react-query client the views and the
│       │                   #   panel cache fetch through
│       ├── useAsync.ts     # a view's query: data/error/reload over react-query,
│       │                   #   with a per-signal poll interval
│       ├── live.ts         # useChangedIds: the change flash, reduced-motion aware
│       ├── keys.ts         # the keyboard layer: the shortcut registry, combo
│       │                   #   normalization, the focus/typing rules, the shared
│       │                   #   filter-focus and table-row handlers, displayCombo
│       ├── styles.css      # design tokens (hues, ramp, grid, spacing, type) + primitives
│       ├── router.ts       # the sidebar's groups, labels and view paths
│       ├── api.ts          # typed fetch wrapper (ApiError carries error/detail)
│       ├── panelCache.ts   # the detail panels' cache, over react-query
│       ├── types.ts        # API response types
│       ├── constants.ts    # decompiler backends and disassembly formats
│       ├── views/          # dashboard, binaries, functions, matches, collections,
│       │                   #   conversations, search, details, the search modal
│       │                   #   and the keyboard cheatsheet dialog
│       └── panels/         # binary and function detail panels
└── src/reportal/
    ├── __init__.py         # __version__
    ├── __main__.py         # python -m reportal
    ├── _paths.py           # reportal.toml walk-up (WorkspaceNotFound), REPORTAL_DB override,
    │                       #   db_path(), reports_dir(), binaries_dir(), stored_binary_path()
    ├── store.py            # SQLite schema + typed CRUD; the typed search
    │                       #   (SEARCH_KINDS/SEARCH_GROUPS, SearchError, MIN_SHA256_PREFIX,
    │                       #   DEFAULT_/MAX_SEARCH_LIMIT) and the upload/extract helpers
    │                       #   (find_binary_by_sha256, find_collection_by_name) (binaries, analyses, functions, matches,
    │                       #   scans, rebrew project contexts, malware families, decompilations,
    │                       #   comments, binary deletion with its cascade, collections with
    │                       #   their membership and tags, ...)
    ├── analysis_log.py     # structured analysis log: analysis_log_entries (analysis, severity
    │                       #   from one closed set, message, time), append_entry, list_entries
    │                       #   (newest first, bounded, with the true total), MAX_LOG_LIMIT
    ├── engines.py          # in-process rebrew adapter:
    │                       #   fingerprints/imports/strings/pe-info/decompilation/analyze/
    │                       #   report/xrefs/struct-recovery/crypto-scan/security-scan as parsed
    │                       #   dicts, disassembly as text; disassemble/control_flow_graph/
    │                       #   test_source call the engine's entry points directly
    ├── llm.py              # optional OpenAI-compatible bridge for the AI extras
    │                       #   (AI_KINDS, LlmConfig from env then reportal.toml [llm], LlmClient,
    │                       #   chat completions, embeddings, summarize/inline_comments/
    │                       #   suggest_types/rename_suggestions/threat_narrative,
    │                       #   get_client/set_client)
    ├── components.py       # component framework: Context (named values + reversible journal,
    │                       #   subscribe/names, provide/revoke/record/revert), Component
    │                       #   (requires/provides/effect/revert), registry with the
    │                       #   `reportal.components` entry-point group, Registration
    │                       #   (origin/module/reloadable), reload_component/reload_all
    ├── effects.py          # the one undo dispatcher: a registry of descriptor kinds ->
    │                       #   inverse actions (`reportal.effect_handlers` entry-point
    │                       #   group), apply_descriptor/apply_undo_plan, plan_context,
    │                       #   and the journal's row/file kinds
    ├── journal.py          # the app-wide action journal: Journal/journaled (one action
    │                       #   per request or invocation, entries in `journal_entries`),
    │                       #   the generic row/file descriptor builders and the wiring
    │                       #   helpers (journaled_rows/create/new_rows/file/ingest/rename/
    │                       #   scan/scan_result/graph_rebuild), revert_action/revert_entry/
    │                       #   list_entries/prune_entries, MAX_FILE_BYTES
    ├── pipeline.py         # the AI decompilation composition: built-in stages, reactive
    │                       #   activation (activate/deactivate), run_pipeline/revert_run,
    │                       #   ComponentHost (live context for reload) plus the process-wide
    │                       #   live host and withdraw_component, `[pipeline] disabled`
    ├── auto_store.py       # auto-mode tables CRUD: auto_runs/auto_tasks/auto_attempts,
    │                       #   latest_auto_run, auto_run_effects, record_auto_task_outcome
    │                       #   (task + undo plan in one commit), run/task status + kind constants
    ├── auto_workers.py     # auto-mode worker registry (Worker/WorkerResult/WorkerContext,
    │                       #   register_worker/workers/refresh_workers, `reportal.auto_workers`
    │                       #   entry-point group) and the deterministic offline worker
    ├── auto_llm_worker.py  # the engine-verified `llm_c_source` worker: annotation marker
    │                       #   from rebrew-project.toml, model prompt, rebrew test verification
    ├── auto_mode.py        # auto orchestrator: selection, decomposition, bounded fan-out,
    │                       #   objective acceptance, aggregation, per-task undo-plan
    │                       #   persistence, run_auto/revert_auto_run/recover_auto_run
    ├── conversations.py    # scoped chats over stored local data and the LLM bridge
    │                       #   (SCOPE_KINDS, build_context, scope_knowledge, SYSTEM_PROMPT,
    │                       #   send_message, default_title, MAX_CONTEXT_CHARS, HISTORY_TURN_LIMIT)
    ├── comments.py         # analyst comments: scope and body validation over the `comments`
    │                       #   table (SCOPE_KINDS, MAX_COMMENT_CHARS, DEFAULT_AUTHOR,
    │                       #   add/list/get/update/delete, UnknownScopeError)
    ├── bulk_actions.py     # bulk actions shared by the API, the CLI and the MCP tools
    │                       #   (BINARY_ACTIONS, FUNCTION_ACTIONS, MAX_BULK_IDS,
    │                       #   apply_binary_action, apply_function_action)
    ├── archive.py          # stdlib-only archive extraction (zip/apk, tar/tar.gz/tgz/tar.bz2/
    │                       #   tar.xz, single-member gz): archive_kind, extract with per-member
    │                       #   outcomes, the traversal/link/device/bomb refusals and the named
    │                       #   caps (MAX_MEMBER_BYTES, MAX_TOTAL_BYTES, MAX_COMPRESSION_RATIO,
    │                       #   MAX_MEMBERS); `.rar`/`.7z` are refused by name (external tool),
    │                       #   firmware unpacking is out of scope
    ├── similarity.py       # optional resembl-backed structural similarity (SimilarityUnavailable,
    │                       #   available, similarity, confidence_scores, cache_info, clear_cache)
    ├── matching.py         # local function matching over the corpus under MatchSettings
    │                       #   (match_binary, cached_disassembler, binary_match_rows,
    │                       #   transfer_matches, plan_transfer, apply_transfer)
    ├── diffing.py          # pure line alignment for the Match / Diff view (align,
    │                       #   summary, strip_addresses)
    ├── diffview.py         # resolve a match pair to two listings and align them
    │                       #   (function_diff, DiffError, DIFF_KINDS)
    ├── lineage.py          # pairwise function lineage between two binaries:
    │                       #   compare_functions, compare_binaries and the stored
    │                       #   comparison CRUD (the `lineage` scan, keyed by the
    │                       #   right binary id)
    ├── related.py          # relationship ranking of the stored binaries around
    │                       #   one target: relationship (signals and their
    │                       #   classification), find_related (the `related` scan)
    │                       #   and derive_bundle; named thresholds and caps
    ├── composition.py      # per-binary composition against the stored matches:
    │                       #   compute_composition/run_composition, the five
    │                       #   name-source labels, the quality bands and the
    │                       #   `composition` scan (stored-only, no engine)
    ├── unstrip.py          # auto-unstrip: library-identification proposals and apply
    ├── renames.py          # LLM identifier renaming over a stored decompilation:
    │                       #   suggest_renames/apply_renames/revert_renames, the
    │                       #   word-boundary rewrite and the `renames-applied` journal
    ├── capabilities.py     # capability tagging: deterministic import/string classification
    ├── families.py         # local malware-family signatures: the store-backed bundle
    │                       #   (sha256/imphash/rich-header hashes, import hash and set,
    │                       #   capability set), derive_bundle, detect_binary scoring,
    │                       #   register_family/list_families/get_family/delete_family,
    │                       #   stored as the `detect` scan
    ├── function_triage.py  # per-function triage: the deterministic heuristic
    │                       #   (score_candidates, WEIGHT_*, METHOD_*), the LLM run
    │                       #   (summarize_functions, stored_function_triage) and the
    │                       #   `function-triage` scan/artifact kind
    ├── behavior.py         # behavioral scans: execution, networking and filesystem
    │                       #   import/string heuristics (BEHAVIOR_DOMAINS, BEHAVIOR_RULES,
    │                       #   DOMAIN_SCAN_KINDS, classify, scan_domain)
    ├── hardening.py        # anti-analysis and obfuscation scans: an import/string rule
    │                       #   table plus numeric/structure thresholds over the
    │                       #   fingerprint, imports, strings and stored triage
    │                       #   (HARDENING_DOMAINS, ANTI_ANALYSIS_RULES, DOMAIN_SCAN_KINDS,
    │                       #   classify_anti_analysis, classify_obfuscation, scan_hardening)
    ├── filetypes.py        # bundled file-type, packer and protector detection: the
    │                       #   SIGNATURES table (FileSignature/SignatureMatch over section
    │                       #   names, entry-point bytes, strings, import DLLs, the Rich
    │                       #   header and an executable-section entropy threshold), the
    │                       #   derived confidence rule, detect and run_filetype (the
    │                       #   `filetype` scan)
    ├── secrets.py          # secrets scan: the credential pattern table (SECRET_PATTERNS),
    │                       #   Shannon entropy and redaction; scan_secrets, run_secrets,
    │                       #   stored as the `secrets` scan
    ├── protocols.py        # protocol inference: the PROTOCOLS table (import/scheme/
    │                       #   literal rules, well-known ports), infer_protocols,
    │                       #   scan_protocols, stored as the `protocols` scan
    ├── threat.py           # local threat report: IOC extraction (extract_iocs), ATT&CK
    │                       #   mapping (map_techniques, TECHNIQUES), optional LLM narrative
    │                       #   (build_threat_report), stored as the `threat` scan; the
    │                       #   software-type classifier (SOFTWARE_TYPES, SOFTWARE_TYPE_RULES,
    │                       #   classify_software) and the 0-100 threat score (score_threat,
    │                       #   CONTRIBUTION_*, SCORE_*) over the stored evidence, with
    │                       #   stored_evidence/classify_binary deriving both at read time
    ├── error_docs.py       # the error-code catalogue: ERROR_DOC_ANCHORS (code -> the
    │                       #   docs/ERRORS.md section), PARAMETRIZED_DOC_ANCHORS for the
    │                       #   per-field validation messages, doc_anchor/doc_url
    ├── remediation.py      # remediation artifacts: distinctive_strings, distinctive_imports,
    │                       #   build_yara_rule, classify_specificity, validate_rule (yarac),
    │                       #   build_snort_rule, build_stix_bundle, as_json, build_remediation;
    │                       #   PE rules anchor on pe.imphash() when the fingerprint carries
    │                       #   one; Snort rules come from the stored `threat` scan's network
    │                       #   indicators (ports from the stored `protocols` scan), STIX is a
    │                       #   deterministic 2.1 bundle over the same indicators; all three
    │                       #   are stored as the `remediation` scan
    ├── pdf.py              # PDF report writer over the stored scans, laid out here and
    │                       #   serialized by reportlab (invariant, uncompressed:
    │                       #   PdfLayout (wrap/paginate/tables/header+footer), text_width,
    │                       #   wrap_text, page_count, render_report, write_report; text-only
    ├── knowledge.py        # document ingestion, semantic search and retrieval: extract_text,
    │                       #   chunk_text, ingest_document, search_knowledge, retrieve, as_context,
    │                       #   TEXT_EXTENSIONS, KnowledgeError, the embedding path and the local
    │                       #   TF-IDF fallback
    ├── remote_ingest.py    # guarded remote (URL) ingestion, off by default: remote_enabled/
    │                       #   require_enabled (ALLOW_REMOTE_ENV or [knowledge]
    │                       #   allow_remote), validate_target (scheme/host/credentials/address/port
    │                       #   guards), fetch (manual redirect re-validation, size cap, content-type
    │                       #   allowlist) and ingest_url; the test-only allow_loopback seam
    ├── graph.py            # deterministic knowledge graph over stored rows: build_graph,
    │                       #   graph_payload, neighbors, entity_mentions, GRAPH_NODE_KINDS,
    │                       #   the node kinds, edge relations and their caps
    ├── graph_backends.py   # pluggable graph-backend registry: GraphBackend (name,
    │                       #   available/describe/sync/optional query), sync_graph/run_query,
    │                       #   the built-in sqlite and optional cognee backends, translate_graph,
    │                       #   the `reportal.graph_backends` entry-point group, configured_backend_name
    │                       #   and cognee_dataset_name (REPORTAL_GRAPH_BACKEND /
    │                       #   REPORTAL_COGNEE_DATASET or [knowledge] graph_backend / cognee_dataset)
    ├── data_types.py       # editable type model over the stored structs scan: parse_definition
    │                       #   (struct/union/enum/typedef/pointer/array/function kinds),
    │                       #   normalize_members/recompute, import_types, the type/member edits,
    │                       #   the per-mutation history and its revert (list_history/revert_history),
    │                       #   render_header/render_as_c and export_header (the apply artifact),
    │                       #   filter_types/namespace_tree and the references reverse indices
    ├── signatures.py       # editable function signatures over the stored decompilations:
    │                       #   parse_signature, seed_signatures, the head/parameter edits,
    │                       #   render_prototype(s) and export_prototypes (the apply artifact)
    ├── instance.py         # what this install can do: versions, features, limits, counts
    ├── details.py          # the composed binary-detail reads: the Detect-It-Easy
    │                       #   identity (die_info) and the asynchronous details
    │                       #   (additional_details, status) derived from the stored
    │                       #   pe-info/filetype scans and the fingerprint, each
    │                       #   reporting the sources it used and the command that
    │                       #   fills a missing one
    ├── plugins.py          # the one entry-point reader every registry discovers through
    ├── zipcrypto.py        # the password-protected zip writer (PKWARE ZipCrypto)
    ├── surface.py          # the checks and journal writers the API, CLI and MCP share
    ├── server.py           # shared FastAPI (ASGI) app: JSON helpers, gzip, Host guard,
    │                       #   the error envelope as a response and an exception, the
    │                       #   json_body/optional_json_body dependencies, db()
    ├── api.py              # router: every /api/* route (the JSON API)
    ├── ui.py               # router: the built SPA, /static assets and the
    │                       #   /reports/<id> generated site, each resolved under its root
    ├── webapp.py           # composition root: includes the two routers
    ├── cli.py              # Typer CLI: init, serve, mcp, config, stats, revert, tags, tag,
    │                       #   collections, collection-show, collection-new,
    │                       #   collection-edit, collection-rm, collection-add,
    │                       #   collection-remove, collection-tags, apply-match,
    │                       #   comments, comment-add, comment-rm, bulk-tag, bulk-delete,
    │                       #   bulk-prefix, diff, lineage, related, composition, families,
    │                       #   family-add, family-rm, detect,
    │                       #   add-binary, download, extract, enrich, decompile, triage, report,
    │                       #   report-pdf,
    │                       #   unstrip, unstrip-apply, import-rebrew, crypto-scan, pe-info,
    │                       #   die-info, additional-details, filetype,
    │                       #   capabilities,
    │                       #   secrets, protocols, behavior, hardening, security-scan, threat, yara,
    │                       #   snort, stix,
    │                       #   structs, match, ingest, suggest-renames, apply-renames,
    │                       #   revert-renames, types, types-import, type-rename,
    │                       #   type-member, types-export, types-history,
    │                       #   types-revert, signature-history,
    │                       #   signature-revert, memory, section-coverage,
    │                       #   documents, knowledge, ingest-url,
    │                       #   graph-build, graph, ai-comments
    ├── mcp_tools.py        # MCP tool registry: Tool (name/description/input_schema/
    │                       #   annotations/handler), register_tool/tools/refresh_tools,
    │                       #   the 141 built-in tools, `reportal.mcp_tools` entry-point group
    ├── mcp_server.py       # stdio MCP server: newline-delimited JSON-RPC 2.0 over stdin/stdout
    │                       #   (initialize, notifications/initialized, tools/list, tools/call)
    └── assets/dist/        # generated Vite build (gitignored; served by ui.py)
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
`Success: no issues found in 177 source files` is the finish line.

`--strict` is a documented follow-up, not a claim of compliance.
`.venv/bin/python -m mypy --strict --python-version 3.12 src/reportal` reports
5 errors, none of them about the HTTP layer: `journal.py:749` and
`journal.py:750` plus `pdf.py:619` and `pdf.py:620` are module-attribute
errors (a name another module imports without re-exporting it), and
`engines.py:302` is a return-value error on the engine's decorator.

**Coverage.** `.venv/bin/python -m pytest --cov` (or `make test`) measured
92.61%, 20808 statements with 1537 missed. `[tool.coverage.report] fail_under`
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
# The command reference (`reportal init` through `reportal ai-comments`)
# is docs/CLI.md; `reportal --help` prints the same list.
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
`delete_comment` write it and are destructive.  `bulk_binaries` and
`bulk_functions` apply one action to a bounded id list through
`bulk_actions`, so both are destructive.  `list_journal` reads the
action-journal entries and is read-only; `revert_journal_entry` replays one
action's or one entry's stored inverses and is destructive.  `get_filetype`
serves a binary's stored file-type detection and is read-only; `run_filetype`
assembles the evidence, detects and stores the matches, and is destructive.
The registry
declares 141 built-in tools, 67 read-only and 74 destructive.

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
and `run_match` expose the same over MCP, and the counts stay 141 built-in
tools (67 read-only, 74 destructive).

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

# reportal architecture

reportal is a self-hosted reverse-engineering portal: a local clone of the
RevEng.AI web portal built on the sibling engines. It is a FastAPI (ASGI)
JSON API plus a Vite-built React SPA over a SQLite store. It runs offline and calls the
network only in two opted-in cases: the optional AI bridge, and only when an
OpenAI-compatible LLM endpoint is explicitly configured, and guarded URL
ingestion, and only when remote ingestion is enabled (both default off);
`docs/PARITY.md` maps every hosted portal capability to its local status and
backing engine.

## Process layout

```
reportal/
├── pyproject.toml            # package, entry point `reportal`
├── web/                      # Vite + React + TypeScript frontend (bun)
│   ├── package.json          # dev/build/preview/lint/typecheck scripts
│   ├── vite.config.ts        # root web/, base /static/, outDir ../src/reportal/assets/dist
│   ├── index.html            # Vite entry page (#root)
│   ├── public/favicon.svg    # copied into the build
│   └── src/                  # api, router, panel cache, views, panels, styles
├── src/reportal/
│   ├── __init__.py           # __version__
│   ├── __main__.py           # python -m reportal
│   ├── cli.py                # Typer CLI (init, import-rebrew, add-binary, serve, ...)
│   ├── server.py             # shared FastAPI app, JSON helpers, Host guard, db(),
│   │                         #   the require_auth dependency (off unless configured)
│   ├── sandbox.py            # guarded sample detonation: the opt-in and runner guards,
│   │                         #   the bounded bwrap argv, the run ledger and the runner
│   │                         #   registry; the one module that executes a sample
│   ├── auth.py               # local identity: users, teams, roles, bearer tokens, the gate
│   │                         #   and the object-visibility rule (visible_clause/may_write)
│   ├── api.py                # every /api/* route (the JSON API)
│   ├── ui.py                 # the built SPA, /static assets and /reports site
│   ├── webapp.py             # composition root: includes the two routers
│   ├── store.py              # SQLite schema + typed CRUD; typed search and the
│   │                         #   upload/extract helpers
│   ├── archive.py            # stdlib-only archive extraction: zip/apk, tar/tar.gz/tgz/
│   │                         #   tar.bz2/tar.xz, single-member gz; per-member safety
│   │                         #   refusals and named caps; `.rar`/`.7z` refused by name
│   ├── engines.py            # rebrew adapter: in-process calls, JSON + text
│   ├── firmware.py           # firmware carving: magic-based region detection, the
│   │                         #   sampled entropy map and the region extents the
│   │                         #   archive reader can unpack; nothing executed
│   ├── components.py         # component framework: context, journal, registry, reload
│   ├── effects.py            # undo dispatcher: kind-to-handler registry, plan replay
│   ├── integrations.py       # plugin-seam inventory read from the live registries
│   ├── pipeline.py           # AI decompilation pipeline: stages, loader, host, revert
│   ├── auto_store.py         # auto runs, task tree and attempt rows (CRUD)
│   ├── auto_workers.py       # auto worker registry + the deterministic offline worker
│   ├── auto_llm_worker.py    # the engine-verified llm_c_source worker
│   ├── auto_mode.py          # auto orchestrator: decompose, fan out, accept, aggregate, persist,
│   │                          #   revert/recover
│   ├── llm.py                # optional OpenAI-compatible bridge: chat completions + embeddings
│   ├── models.py             # the model registry and the analysis upgrade: what produced a
│   │                         #   stored result, and re-running the LLM artifacts
│   ├── ai_decomp.py          # the AI decompilation artifact: the rewrite, its token map,
│   │                         #   per-line attributions, overrides, rating and line comments
│   ├── conversations.py      # scoped chats: stored context + retrieved documents, prompt assembly
│   ├── agent.py              # agent runs: the tool loop over the MCP registry, the
│   │                         #   confirmation gate, cancel and the state stream
│   ├── comments.py           # analyst comments: scope/body validation over the comments table
│   ├── bulk_actions.py       # bulk tag/delete over binaries and analyses, and prefix
│   │                         #   rename/clear over functions
│   ├── similarity.py         # resembl-backed scoring, cached per listing
│   ├── matching.py           # corpus matching: MatchSettings scope, rank, floor,
│   │                         #   confidence, store; symbol transfer (name/signature/both)
│   ├── diffing.py            # pure line alignment: align, summary, strip_addresses
│   ├── diffview.py           # resolve a match pair to two listings and align them
│   ├── lineage.py            # pairwise function lineage between two binaries
│   ├── related.py            # relationship ranking of the stored binaries around one target
│   ├── composition.py        # stored-only composition of one binary against its matches:
│   │                         #   matched counts, name sources, quality bands and the rollup
│   ├── unstrip.py            # library-identification proposals and explicit apply
│   ├── renames.py            # LLM identifier renaming: suggestions, word-boundary apply
│   │                         #   with a revert journal, and the `renames-applied` restore
│   ├── capabilities.py       # deterministic capability tagging over imports and strings
│   ├── families.py           # local malware-family signatures and detection (the `detect` scan)
│   ├── function_triage.py    # per-function triage: heuristic score, LLM run, aggregate scan
│   ├── symbols.py            # debug symbol ingestion: the ELF/DWARF readers, the
│   │                         #   content-addressed store, the import and the export
│   ├── pdb.py                # the PDB 7.0 reader: MSF container, DBI section map and
│   │                         #   symbol record stream
│   ├── function_extras.py    # per-function extras: indirect call sites, capabilities,
│   │                         #   derived callees, analyst-declared edges, canonical names
│   ├── user_strings.py       # analyst strings at function or analysis scope, plus
│   │                         #   the derived literals reported beside them
│   ├── behavior.py           # behavioral scans (execution, networking, filesystem) over imports and strings
│   ├── hardening.py          # anti-analysis and obfuscation scans over fingerprints, imports, strings and triage
│   ├── filetypes.py          # bundled file-type, packer and protector detection (the `filetype` scan)
│   ├── secrets.py            # secrets scan: credential patterns, Shannon entropy, redaction
│   ├── secret_store.py       # named credentials: workspace/team scope, redacted
│   │                         #   reads and journaled writes
│   ├── external.py            # external sources: the offline evidence answer and the
│   │                         #   guarded, opt-in third-party fetch
│   │                         #   reads and journaled writes
│   ├── protocols.py          # protocol inference from imports, schemes, literals and ports
│   ├── threat.py             # local threat report: IOC extraction, ATT&CK mapping, narrative,
│   │                         #   software-type classification and the 0-100 threat score
│   ├── error_docs.py         # the error-code catalogue and the doc_url every error body carries
│   ├── docs.py               # the in-app manual: resolve REPORTAL_DOCS/workspace/checkout,
│   │                         #   the page index and the markdown-to-blocks reader
│   ├── analytics.py          # the dashboard's bounded time series over stored rows
│   ├── ratings.py            # the analyst's verdict on a stored agent artifact
│   ├── remediation.py        # remediation artifacts: YARA rule render, Snort rules, STIX bundle
│   ├── knowledge.py          # ingestion, chunk search and retrieval: retrieve, as_context, TF-IDF
│   ├── remote_ingest.py      # guarded URL ingestion, off by default: validate_target guards,
│   │                         #   redirect re-validating fetch, ingest_url, the test-only seam
│   ├── graph.py              # deterministic knowledge graph over stored rows: build_graph,
│   │                         #   graph_payload, neighbors, entity_mentions, node kinds and relations
│   ├── graph_backends.py     # pluggable graph backends: GraphBackend registry, built-in
│   │                         #   sqlite and optional cognee backends, sync_graph, run_query
│   ├── data_types.py         # editable type model: definition parse (struct/union/enum/typedef/
│   │                         #   pointer/array/function), kind/namespace/size writes, member
│   │                         #   shape/position/gap edits, enum values, size check, header
│   │                         #   render/export, filters, namespace tree and reverse indices
│   ├── signatures.py         # editable function signatures: declaration parse, head/parameter
│   │                         #   edits, prototype render/export
│   ├── details.py            # composed binary-detail reads over the stored scans: the
│   │                         #   Detect-It-Easy identity (die_info) and the asynchronous
│   │                         #   details (additional_details, status), each reporting the
│   │                         #   sources it used and the command that fills a missing one
│   ├── zipcrypto.py          # the password-protected zip writer (PKWARE ZipCrypto)
│   ├── instance.py           # what this install can do: versions, features, limits, counts
│   ├── pdf.py                # PDF report writer: layout here, serialized by reportlab
│   │                         #   (PdfLayout, wrap_text, render_report, write_report)
│   ├── _paths.py             # workspace resolution (reportal.toml walk-up)
│   ├── mcp_tools.py          # MCP tool registry (Tool, register_tool/tools/refresh_tools)
│   ├── mcp_server.py         # stdio MCP server (newline-delimited JSON-RPC 2.0)
│   └── assets/dist/          # generated Vite build (gitignored, served by ui.py)
└── tools/
    ├── smoke_spa.py        # builds web/ when needed, then headless-browser smoke
    ├── audit_ui.py         # headless-browser UI gate over the same routes/viewports
    └── seed_e2e.py         # seeds the Playwright suite's workspace (smoke seeding + collections)
```

The request path is `server.py` (shared app plus helpers) composed by
`webapp.py`, with routes in `api.py` and `ui.py`. Engine work is confined to
`engines.py`; tests inject a fake engine through `engines.set_engine()` rather
than running the engine.

## Library choices

Every layer a library does better is a library. On the server: FastAPI on
Starlette behind uvicorn, Starlette's `python-multipart` reader, the official
`mcp` SDK for the MCP stdio server, the official `openai` SDK for the optional
LLM bridge, `httpx` for guarded URL ingestion, Typer and Rich for the CLI, the
standard library's `sqlite3`, `tomllib` and `difflib`, and reportlab for the PDF
export. In `web/`: React with react-router for the route table and
`@tanstack/react-query` for every fetch (the views' queries and the detail
panels' cache), Vite/TypeScript, oxlint and Playwright.

Two things are hand-rolled on purpose, each measured against the library a
reader would reach for first:

* **The STIX 2.1 bundle** (`remediation.build_stix_bundle`) is a deterministic
  dict: every id is a `uuid5` of the indicator's pattern, so two builds of one
  input are identical. `stix2` would add `pytz` and `requests`, and produce ids
  and timestamps the scan would have to pin anyway.
* **The TF-IDF fallback** (`knowledge.py`) is about fifty lines of cosine
  similarity, used only when the configured endpoint serves no embeddings. The
  ranking method is part of the returned contract (`METHOD_TFIDF` versus
  `METHOD_EMBEDDINGS`), so SQLite FTS5 would change what a caller sees for no
  gain at the corpus sizes the portal holds.

## Store

`reportal.db` is created by `init` and schema-initialized on first use.

| Table | Holds |
|-------|-------|
| `binaries` | id, sha256 (dedupe key), name, path, size, format, arch |
| `analyses` | one row per binary, engine label, status (the source of truth) |
| `analysis_log_entries` | the structured analysis log: one row per lifecycle event with a severity, a message and its time |
| `functions` | analysis, VA, name, size, STATUS, name_source, confidence |
| `matches` | ranked candidate edges: function, candidate, similarity, confidence, the JSON scope (`settings_json`) the run recorded them under |
| `name_history` | rename log: old/new name, source, actor, timestamp |
| `collections`, `collection_binaries` | named binary groups |
| `tags`, `binary_tags` | tags and their binary links |
| `scans` | engine results keyed by (analysis, kind), upserted |
| `binary_fingerprints` | stored fingerprint bundle per binary |
| `disasm_cache` | function assembly listing, so matching does not re-spawn |
| `decompilations` | stored decompiler output per function and backend |
| `ai_artifacts` | optional LLM artifacts keyed by (function, kind), upserted; `function-triage` holds one score/summary row per function and `renames-applied` journals the text an apply replaced |
| `conversations` | one chat per scope (function or binary), with title |
| `messages` | conversation turns, cascaded when the conversation is deleted |
| `comments` | analyst comments: scope (binary or function), author, body, created/updated timestamps |
| `pipeline_runs` | one AI decompilation run per invocation, with its undo plan |
| `pipeline_steps` | one row per component of a run: status, reason, timing, provided names |
| `auto_runs` | one auto-mode run per invocation: config, status, counters, coverage deltas and its undo plan |
| `auto_tasks` | the run's task tree: parent, depth, kind, status, worker, attempts, result |
| `auto_attempts` | one row per worker call: attempt number, worker, status, detail |
| `rebrew_contexts` | binary to rebrew project dir, for project-scoped commands |
| `families` | one row per locally registered malware family: unique name, aliases, notes, reference binary, stored signature bundle |
| `documents` | one row per ingested document: scope, title, source, mime, sha256, size, text |
| `chunks` | the document's overlapping chunks: ordinal, text, embedding JSON |
| `graph_nodes` | one knowledge-graph node per stored fact: binary, kind, key, label, metadata JSON |
| `graph_edges` | one knowledge-graph edge per relation: source, target, relation, weight, metadata JSON |
| `data_types` | editable type model: one row per (binary, name) with kind, namespace, declared size (recomputed by a member write, stored as given by a size edit), members JSON (each with name, type, pointer, count, bits and its derived offset/size), enum values JSON, target, element count and source |
| `data_type_history` | one row per type mutation: the type id (no foreign key, so a deleted type's history survives), the binary, the states before and after, source, actor, time |
| `function_signatures` | editable signature model: one row per function with name, return type, convention, parameters JSON, source |

Idempotency rules: binaries dedupe by sha256, functions are unique on
`(analysis_id, va)`, scans upsert on `(analysis_id, kind)`. Uploaded binaries
are content-addressed files under `<workspace>/binaries/`, named
`<sha256><suffix>`; the row's `path` points at that file, and a repeated upload
returns the same row.
`import-rebrew` also ingests the target binary's import stubs (`rebrew imports`)
as `THUNK` rows at their VAs with `name_source` `import`, added through
`store.add_function_if_absent`, which never replaces a row the analysis already
holds, so a coverage-db function wins at the same address. The stub call is best
effort, so an import succeeds without an engine.

Documents dedupe on `(scope_kind, scope_id, sha256)`, so the same bytes twice in
one scope return the stored row; chunks are keyed by `document_id` and cascade
with it, so a deleted document leaves no orphan chunk.

`families` is unique on `name` (`COLLATE NOCASE`) and cascades with its
reference binary, so deleting that binary removes the family and the signature
bundle stored with it.  A family's bundle is derived once at registration
(the engine fingerprint's `sha256`, `imphash` and `rich_header_hash`, the
sha256 import hash over the sorted lowercased `dll:name` entries, the canonical
import-name set and the capability set), and a detection is stored as the
`detect` scan.

`analyses.status` is the source of truth for an analysis's lifecycle, with its
closed set declared once as `store.ANALYSIS_STATUSES` (`pending`,
`processing`, `done`, `failed`, `cancelled`, which map onto the hosted
portal's Queued, Processing, Complete and Error); `create_analysis` and
`update_analysis_status` refuse a value outside it.  The writers advance it
honestly and record what happened in `analysis_log_entries`
(`analysis_log.append_entry` is the only writer): creating an analysis appends
its creation, `store.set_scan` marks the analysis `done` and logs the scan's
finish, `store.scan_span` logs a scan's start and marks the analysis `failed`
with an error entry when the wrapped work raises, and every status change
appends an entry naming the old and new value.  `analysis_log.list_entries`
reads an analysis's entries newest first, bounded by `MAX_LOG_LIMIT`, and
returns the log's true total beside the page.  The `analyses.log` TEXT column
stays the importer's summary sentence: one column cannot carry a severity, a
timestamp or a bound per row, so the events live in their own table and cascade
with their analysis.

`store.imported_functions` reads the import stubs of one analysis
(`functions.name_source` is `store.IMPORTED_NAME_SOURCE`, written by the
importer) and derives each stub's callers from `decompilations.code`, because
reportal stores no call graph: a caller is a function of the same analysis whose
stored source carries the stub's name.  The heuristics are named in the payload
(`caller_method`, `caller_limit`, and `caller_count` beside the bounded
`callers` list) rather than implied, so a reader can tell a text match from an
engine-reported edge.  `GET /api/analyses/<id>/bytes` resolves an analysis to its
binary and returns the same streamed response
`GET /api/binaries/<id>/download` builds, through the one
`api._streamed_binary` helper.

## Identity and the API gate

Token auth is off unless `REPORTAL_AUTH=required` or the workspace
`[auth] required = true` turns it on (`auth.required`, a pure configuration
read), so a loopback install behaves exactly as before and no request pays for
a check it does not need.  With it on, `api.router` is built with
`dependencies=[Depends(server.require_auth)]`, which is the one place the gate
lives: a route added later is behind it without being told, and a route cannot
opt out by omission.  The dependency resolves the bearer token to a user
(`auth.authenticate`, constant-time digest comparison), refuses a disabled user,
computes the permission the method and path need (`auth.required_permission`:
`read`, `write`, or `admin` for `/api/users*`) and compares it with the role's
set (`auth.ROLE_PERMISSIONS`); it leaves the user on `request.state.user`, which
is what `GET /api/iam/me` reports and what the next slice's per-object scoping
will read.  `cli.serve` refuses a non-loopback bind unless the gate is armed and
at least one enabled user exists (`cli._require_lan_auth`), so the unauthenticated
remote control plane the old posture allowed cannot be reached by forgetting a
flag.  Only a token's SHA-256 digest is stored; the token is returned once, by
the call that created or rotated it.

A binary or a collection additionally carries a scope (`owner_team_id` plus a
`visibility` of `public` or `team`), and the same dependency enforces it:
`server._scoped_object` resolves the object a path names (a function or an
analysis resolves through the binary it belongs to, since that is where the
scope lives) and `_enforce_scope` refuses a read a non-member may not make with
the object's own 404 (no existence disclosure) and a write with 403
`scope-forbidden`.  `auth.visible_clause` is the one SQL rule the listings,
`/api/search` and the bulk guard share, and `auth.may_write` is the one
predicate the scope setters and the collection membership route share.  A team
delete resets its objects to public rather than orphaning them.  `docs/THREAT_MODEL.md` carries the residual
risks, the largest of which is that authorization is per route kind rather than
per object.

## Sandbox detonation

`sandbox.py` is the only module that executes a sample, and it is built so that
the default install still never does.  `sandbox.enabled()` reads
`REPORTAL_SANDBOX` / `[sandbox] enabled`; `require_runner()` resolves the runner
from `REPORTAL_SANDBOX_RUNNER` / `[sandbox] runner` or the first installed entry
in the in-tree `RUNNERS` list (bwrap, whose user namespaces must be enabled), and
a third party adds one through the `reportal.sandbox_runners` entry-point group
read by `plugins.load`.  `BwrapRunner.argv` is the whole safety story in one pure
list: `--unshare-all`, `--die-with-parent`, `--new-session`, `--clearenv`, the
host root bound read-only, fresh `/proc` and `/dev`, one writable directory bound
at `/tmp`, the sample bound read-only inside it (the mount point has to live in a
writable bind, because bwrap cannot create one on the read-only root) and a shell
whose `ulimit` line applies the CPU, address-space, file-size and process caps
before `exec`.  `sandbox.execute` writes the run row first, starts the process in
its own session, kills the group on a wall-clock timeout, and records the exit
status, the duration, bounded output tails and the files the sample left in the
directory reportal then removes.  `api.sandbox_detonate_binary` is the shared
orchestration the route, the CLI and the MCP tool call, so the four guards are
checked once; `docs/THREAT_MODEL.md` records what the boundary does and does not
promise.

## Firmware carving

`firmware.py` is the one module that looks for embedded images, and it is pure
byte work: it reads the file `store` already holds, finds the magics in
`firmware.SIGNATURES` (a magic straddling a read boundary is still found, and a
fixed-offset signature is checked at the file's start only), and reports each
region as the span to the next magic, capped at `firmware.MAX_REGION_BYTES` and
bounded at `MAX_REGIONS`.  A region is a *carve*, not a parse: reportal reads no
squashfs or UBI inode table, so a filesystem region is material rather than a
tree, and the payload says so.  A gzip region is trimmed to the extent
`firmware.gzip_member_length` reports (zlib reads the member; the archive reader
rejects trailing non-zero data), which is what makes the gzip, tar and zip
regions extractable through `archive.extract`, keyed by
`firmware.ARCHIVE_SUFFIXES`.  `api.firmware_extract_binary` orchestrates one
journaled action for the three surfaces: an extractable region contributes the
members the archive reader finds, every other region is written out as a binary
of its own through the same `_register_member` path an upload uses, and all of
them join one collection.  Nothing is mounted, spawned or executed.

## Engine contract

`rebrew` is a base dependency, imported in process by `engines.py`. An install
whose rebrew package cannot be imported still runs, and its engine routes
answer `503 engine-unavailable`.

| Call | Used for | Context |
|------|----------|---------|
| `rebrew.fingerprints.fingerprint_bundle` | digests (MD5/SHA1/SHA256/SHA512/SHA3), crc32, imphash, export hash, Rich header, entropy | standalone |
| `rebrew.pe_info.pe_info` | PE identity and type, resource count, exports, sections (entropy + IMAGE_SCN_*), security flags and the 11-item checklist, Authenticode, debug, Rich header | standalone |
| `rebrew.imports.imports_payload` / `rebrew.strings.collect_strings` | import table, strings | standalone |
| `rebrew.crypto_scan.crypto_scan` | crypto constants and API names | standalone |
| `rebrew.analyze.build_dossier` | triage dossier | standalone |
| `rebrew.security_scan.security_scan` | rule-based findings over the reversed C sources | project cwd |
| `rebrew.decompiler.fetch_decompilation` (+ `rebrew.name_decomp.apply_known_names` for `named`) | decompilation | project cwd |
| `rebrew.xrefs.build_xrefs_payload` | cross-references | project cwd |
| `rebrew.describe.build_dossier` | one function's globals, callers, callees and imports | project cwd |
| `rebrew.struct_recover.recover_project_structs` | recovered struct typedefs | project cwd |
| `rebrew.identify_library.collect_candidates` | library-identify rename proposals | project cwd |
| `rebrew.report.generate_report` | coverage summary plus HTML site | project cwd |
| `rebrew.asm.hex_disassembly` / `rebrew.asm.disassemble_to_nasm` | disassembly | project cwd |
| `rebrew.asm.build_cfg_payload` | basic-block control-flow graph | project cwd |
| `rebrew.test.run_test` | compile-and-compare verification | project cwd |

An in-process call resolves the library entry point; a failure (`typer.Exit`
from rebrew's `error_exit`, a missing module, any other exception) becomes an
`EngineError` with a bounded message. Project-scoped calls load the config from
the binary's stored rebrew project and never write into that project: `report`
writes to reportal's own `reports/<binary_id>/`, and `identify-library` is the
engine's dry run, so it writes no `library_*.h`. The disassembly row uses the
engine's text-returning entry points (`hex_disassembly` for `hex`,
`disassemble_to_nasm` for `nasm`), the CFG row returns the object
`build_cfg_payload` builds, and `test_source` returns the object `run_test`
builds; none spawns a process.

`capabilities.py` composes the two standalone calls, `rebrew imports` and
`rebrew strings`, and needs no project context. It matches the returned import
names (exact, prefix or substring) and string texts (case-insensitive regexes)
against a fixed rule table, so the classification is deterministic and makes no
network call.

`behavior.py` also composes those two standalone calls and needs no project
context. Each domain in `BEHAVIOR_DOMAINS` (`execution`, `networking`,
`filesystem`) has its own rule table in `BEHAVIOR_RULES`: import names matched
with the same exact/prefix/substring comparison `capabilities.py` uses, plus
case-insensitive string regexes for the domain's literal evidence (URLs,
IPv4 addresses and labeled ports; drive-letter and UNC paths and file
extensions). An import hit is `high` confidence and string-only evidence
`medium`; findings deduplicate by name and rule label, sort by confidence then
name and cap at `MAX_FINDINGS` while `count` and `by_confidence` stay exact.
Each domain's result is stored as its own scan kind (`DOMAIN_SCAN_KINDS`).

`hardening.py` covers the portal's anti-analysis and obfuscation surfaces with
two domains in `HARDENING_DOMAINS`. `anti-analysis` matches the same two
standalone engine payloads against `ANTI_ANALYSIS_RULES`, a fixed table of
categories (`anti-debug-api`, `timing-check`, `vm-or-sandbox-artifact`,
`exception-tampering`, `debugger-detection-string`) with import rules and
case-insensitive string regexes. `obfuscation` reads `rebrew fingerprints` too
and, when the store holds one, the triage dossier, then applies numeric and
structural thresholds: a code-like section (`_is_code_section`: a name
containing `text` or `code`) at or above `HIGH_ENTROPY_THRESHOLD`, a
size-weighted mean section entropy at or above
`HIGH_OVERALL_ENTROPY_THRESHOLD`, an import or string table below
`SPARSE_IMPORT_THRESHOLD`/`SPARSE_STRING_THRESHOLD` for a binary at or above
64 KiB, and packer names (`_PACKER_NAMES`) or section conventions
(`PACKER_SECTION_PREFIXES`, from the triage's section names or the
fingerprint's). The grade is `packer_likelihood`: `high` from
`PACKER_HIGH_MIN_FINDINGS` findings, `medium` from
`PACKER_MEDIUM_MIN_FINDINGS`, else `low`. A fingerprint with no section
entropies is recorded as a note (`SECTION_ENTROPY_NOTE`) and the entropy
thresholds are skipped, so a partly missing engine result never fails the scan.
Import evidence is `high` confidence and string evidence `medium`; findings
deduplicate by `(category, name)`, sort by confidence then category then name
and cap at `MAX_FINDINGS` while `count` and `by_confidence` stay exact. Both
domains are stored under their own scan kind. The scans are static heuristics:
a missing finding is not proof of protection and a firing heuristic is not
proof of a packer.

`threat.py` composes the same two standalone calls, extracts indicators of
compromise from the strings with a fixed rule set per category (scheme-anchored
URLs, TLD-checked domains and emails, octet-validated IPv4 with private and
loopback ranges flagged in the finding's `kind`, hive-anchored registry paths,
drive- or UNC-anchored file paths, and exactly 32/40/64-character hashes), and
maps them with the imports and the stored capability scan onto the curated
ATT&CK table (`TECHNIQUES`). A string carrying a printf conversion is skipped
whole, since a format template would extract placeholder text. The optional
narrative is the only model call, goes through `llm.threat_narrative`, and is
skipped with a recorded reason when no endpoint is configured. The result is
stored as the `threat` scan; no external threat-intelligence service is
contacted.

The same module owns the two analysis-level verdicts the threat and triage
responses carry. `classify_software` names a software type from the closed
vocabulary `SOFTWARE_TYPES` (`ransomware`, `keylogger`, `coinminer`,
`downloader`, `installer`, `managed-application`, `packed-executable`) over the
stored `filetype`, `capabilities`, `threat` and `triage` scans, and returns the
signals that fired with a derived confidence (two independent signal kinds are
`high`, a single concrete one `medium`, a lone string `low`). The vocabulary is
deliberately short: the hosted portal's agent also names Trojan, Backdoor,
Spyware and Worm, and reportal does not, because static evidence cannot tell a
remote-access tool from a networked application; naming one would be a
fabricated classification. `score_threat` aggregates a 0-100 score from the same
evidence, and every point is named in the payload's `contributions` (packing,
capabilities, indicators, techniques) with the evidence behind it. The scale is
reportal's own, stated in every payload: 1-24 `low`, 25-49 `moderate`,
50-74 `high`, 75-100 `critical` (`SCORE_MODERATE_FLOOR`, `SCORE_HIGH_FLOOR`,
`SCORE_CRITICAL_FLOOR`, capped at `SCORE_MAX`), and each contribution's weight
is a named constant (`PACKER_POINTS`, `PROTECTOR_POINTS`, `CAPABILITY_POINTS`,
`IOC_POINTS`, `TECHNIQUE_POINTS`) with a per-contribution cap so one busy
category cannot saturate the total. A capability
tag or a string marker never names a type or scores on its own: a capability is
a building block several types share, and a string sample is the weakest
evidence, so a rule that needs more than one signal declares `min_signals`.
Evidence carrying nothing answers `score: null` with the reason rather than a
zero, and every payload says in its notes that the score is reportal's own
heuristic and not the hosted platform's model score.
`stored_evidence` reads the newest analysis's scans (never the engine, never the
model), so `classify_binary` answers the same value on every route for the same
stored state: the API and the MCP tools derive both keys from it when they serve
the threat or triage payload, and the stored row keeps exactly what its writer
produced.

`remediation.py` composes the standalone `rebrew strings` and `rebrew imports`
calls and reads or builds the fingerprint via `rebrew fingerprints`. It selects
two bounded sets of distinctive literals: data strings (longest first,
deduplicated, with a named denylist of runtime vocabulary and a minimum length)
and import API names (longest first with ties reverse-alphabetical, deduplicated,
with a curated generic-API denylist dropped and their own minimum length and
cap). It renders one complete YARA rule (sanitized name; meta with `author`, the
supplied date, binary name, sha256, imphash and Rich-header hash; hex-escaped
`$sN` and `$iN` entries, wide literals carrying `ascii wide`) with a single
condition expression. A PE with an imphash imports the `pe` module and anchors
on `pe.imphash() == "<hash>"`, falling back to the string clause and, when
imports exist, the import clause; otherwise the condition anchors on the file
magic. Every form bounds the filesize and clamps each match count to the
literals carried. `classify_specificity` grades the rule `high`, `medium` or
`low` and the grade is stored in the payload with both literal counts. Validation
runs `yarac` as a subprocess (`subprocess.run`, never a shell) against a
temporary source written under the workspace `.scratch/` directory and removed
afterwards; `yarac` is optional, so a rule is stored with `validated: false` and
`validator: null` when it is absent.  `build_snort_rule` renders one Snort 2
rule per URL, domain and IPv4 indicator of the stored `threat` scan, ordered by
family then value, matching the indicator's host with `content`/`http_header`
and taking the destination port from the indicator's own URL port or the stored
`protocols` scan (else `any`); the SID counts up from `SNORT_SID_BASE` and an
empty indicator set is a valid empty result with a note.  `build_stix_bundle`
renders a deterministic STIX 2.1 bundle over the same indicators: a reportal
`identity`, one `indicator` per URL, domain, IPv4, email and hash IOC, a `note`
when none exists, and ids derived with `uuid.uuid5` from the pattern, so two
builds are byte-identical.  The stored `threat` and `protocols` scans are read,
never re-run; all three artifacts are stored as the `remediation` scan.

`similarity.py` is the only module that touches the optional `similarity`
extra (resembl path dependency, rapidfuzz, pygments). It caches tokenization
and MinHash per listing, so scoring many candidates against one function does
the per-listing work once. It is lazy: without the extra, matching raises
`SimilarityUnavailable`.

## Components

The AI decompilation pipeline is a composition of components, not a fixed
sequence of calls. A component (`components.py`) declares the context values it
`requires` and the values it `provides`, plus the effect it performs; the
loader in `pipeline.py` activates a component as soon as its requirements are
satisfied and deactivates one whose requirements go away mid-run.
`docs/COMPONENTS.md` maps each mechanism of the context paradigm this follows
to the code and states what is not implemented. In short:

| Property | Implementation |
|----------|----------------|
| Coeffects (what a component needs) | `Component.requires`. The runner seeds `function`, `binary`, `project`, `conn` and `engine`, and `llm` only when a client is configured; each active component's `provides` joins the available set |
| Effects (what a component writes) | `Context.provide` and `Context.revoke` for bindings, `Context.record` for persistent writes; every one of them journals an inverse |
| Temporal composability | `Context.revert` applies the journaled inverses newest-first in-process, and `pipeline.revert_run` journals a stored run's descriptors back onto a context to replay them from a later process |
| Spatial composability | `Context.subscribe` reports each change to the loader, whose `_ActivationWatch` re-evaluates every pending component: a component activates when its last requirement is bound and is recorded `deactivated` when one is revoked before it ran. A never-ready component is skipped with `requires-<name>`, `dependency-skipped:<provider>`, `dependency-failed:<provider>` or `dependency-deactivated:<provider>` |
| One effect dispatcher | `effects.apply_descriptor` resolves an undo descriptor kind through a registry (`register_effect_handler` / `effect_handlers` / `refresh_effect_handlers`); built-in kinds come from `effects.builtin_effect_handlers()` and third parties from the `reportal.effect_handlers` entry-point group, and `effects.apply_undo_plan` replays a plan newest-first. Auto mode's `revert_auto_run` uses it too |
| Loader reconciliation | `register_component` / `components()` / `refresh_components()`; built-ins come from `reportal.pipeline.builtin_components()`, third parties from the `reportal.components` entry-point group, and a duplicate name is a `RegistryError` |
| Hot module replacement | `registrations()` records each entry's declaring module and reloadability; `reload_component(name)` re-imports it and swaps the entry in place, `reload_all()` reports one result per entry, and `pipeline.ComponentHost` drives deactivate → reload → activate against a live `Context`. A run in flight keeps its snapshot; `refresh_components()` remains the whole-registry re-discovery |

Ordering is a deterministic topological order over the `requires`/`provides`
graph with declaration order breaking ties, which is what makes the built-ins
run in the order the portal reports its steps:

| Component | Requires | Provides | Local work |
|-----------|----------|----------|------------|
| `prepare` | `function` | `function_meta`, `disassembly` | the cached NASM listing, else `rebrew asm` |
| `read-trace` | `disassembly` | `control_flow`, `call_trace` | parses the listing; names callees from stored rows |
| `decompile` | `function`, `project` | `decompilation` | the stored source, else `rebrew decompile` and a stored row |
| `search-functionality` | `function` | `similar_functions` | the recorded `matches` rows, never a live match |
| `resolve-names` | `function` | `predicted_name` | a stored unstrip proposal, else the best match candidate |
| `retrieve-knowledge` | `function` | `knowledge` | the binary's documents ranked against the function's name, VA and stored summary; read-only, journals nothing |
| `name-variables` | `decompilation`, `llm` | `type_suggestions`, `inline_comments` | the LLM bridge, with the `knowledge` context in the prompt |
| `summarize` | `decompilation`, `llm` | `summary` | the LLM bridge, with the `knowledge` context in the prompt |
| `store` | none | none | persists the run's artifacts, journaling each write |

A step that fails is recorded as `failed` with its reason rather than aborting
the run, and a component's optional `revert(ctx)` runs when its effect raises.
A step whose requirement is revoked before it ran is recorded `deactivated`
with its reason; that is a decision, not a run failure. Only a composition that
cannot be assembled at all (`RegistryError`) becomes `PipelineUnavailable`,
which the API maps to 503.

Hot module replacement is registry-level. `reload_component(name)` records the
declaring module on each registration, re-imports it through
`importlib.reload` (re-initializing module-level state) and replaces the live
entry in place, so the next composition reads the new declaration while a run
already in flight keeps its snapshot; a component registered in-process is not
reloadable and raises `NotReloadableError`. `ComponentHost` is what re-runs a
swapped component against a live `Context`: `deactivate` withdraws a component
and its dependents (calling `Component.revert` where declared and revoking the
names it provided) and `activate` runs the reloaded effect and every dependent
that becomes ready again. Deliberately not emulated: cross-process live
discovery and a distributed scheduler. reportal is one process over one SQLite
file, so there is nothing to coordinate beyond the row writes the journal
already reverses.

A `[pipeline] disabled = [...]` table in the workspace `reportal.toml` skips
named components; a caller passing `disabled=` overrides it.

## Action journal

The action journal (`journal.py`) is the app-wide counterpart to the run-scoped
plans above: it is how a request-scoped writer records its inverse without
joining a component composition. One `Journal` covers one HTTP request or CLI
invocation, its entries land in the `journal_entries` table, and any recorded
action is revertible later, including from a different process, because the
descriptors are stored and replayed through the same dispatcher the runs use.

| Piece | Implementation |
|-------|----------------|
| Entry | `journal_entries(id, action, kind, description, descriptor_json, created_at, status)`. `action` groups the entries of one request (a short random id), `status` is `active`, `reverted` or `partial` |
| Recorder | `Journal.record(kind, description, descriptor)` appends; `Journal.flush()` writes; `journal.journaled(conn, action)` flushes on a clean exit and writes nothing when the request raises |
| Generic descriptors | `snapshot_rows` reads the rows a write is about to change, `row_restore_descriptor` names their inverse, `row_delete_descriptor` names the row a write created, and `file_delete_descriptor` / `file_restore_descriptor` cover the stored file. A file past `journal.MAX_FILE_BYTES` is recorded by path only and its entry ends `partial` |
| Wiring helpers | One helper per write shape wraps the builders so a wired site is a call, not a hand-rolled descriptor: `journaled_rows` snapshots the rows a write replaces and records their restore, `journaled_create` records the row a write created, `journaled_new_rows` records the rows a scoped replace created, `journaled_file` records a file write or replacement, `journaled_ingest` covers a document and its chunks, `journaled_rename` / `journaled_revert_name` cover the functions and history rows, `journaled_scan` / `journaled_scan_result` cover a scan row and the analysis it created, and `journaled_graph_rebuild` covers the graph's nodes and edges |
| Inverse dispatch | The four kinds (`row-restore`, `row-delete`, `file-delete`, `file-restore`) are declared in-tree by `effects.builtin_effect_handlers()` and replayed by `effects.apply_undo_plan`, so the journal and the runs share one dispatcher and one plugin registry. `row-restore` updates the row in place and inserts it only when it is missing: `INSERT OR REPLACE` would delete the parent row first and cascade into the children the restore is keeping |
| Revert | `revert_action(conn, action)` replays the action's active descriptors newest-first; one failing inverse is reported and does not strand the rest, and an entry whose inverse failed stays `active` for a retry. `revert_entry(conn, entry_id)` does one. Both work from any connection, which is what makes a revert survive the process that recorded it |
| Reading | `list_entries(conn, action=None, limit=...)` returns metadata newest-first without the descriptor payload, so a listing never carries a journaled file's bytes |
| Pruning | `prune_entries(conn, keep)` deletes every entry but the newest `keep` by id, regardless of status: the journal is a bounded operator log, not an archive. `journal.DEFAULT_PRUNE_KEEP` is the default; nothing prunes automatically |

The pipeline and auto mode keep their own run-scoped plans by design: a run's
plan is scoped to the run, its bindings and revocations live in one process,
and `pipeline.revert_run` / `auto_mode.revert_auto_run` are its entry points.
`docs/COMPONENTS.md` names the writers wired through the journal and the ones
that are not.

Two limits the entries state rather than hide. A conversation message send makes
a model call that cannot be replayed, so it journals only the user and assistant
`messages` rows it inserted and the entry's description says so: a revert
removes the exchange, not the request that produced the reply. A graph rebuild
replaces the binary's `graph_nodes` and `graph_edges`, so it journals the rows it
removes and the rows it created and a revert restores the previous graph; a
`graph/sync` already pushed to an external backend is not undone, and the local
database is the only source the journal covers.

## Auto mode

Auto mode is the workbench's orchestration loop: one binary goes in, a task
tree comes out, and the parent reports how much coverage the run added.  The
shape is modeled on the sibling `spydr` project (one root task, top-down
decomposition, bottom-up aggregation, bounded fan-out, a per-attempt timeout
and retries).  What replaces spydr's reviewer and aggregator agents is an
objective rule instead of a model's judgement.

| Stage | Implementation |
|-------|----------------|
| Selection | `auto_mode.select_functions` takes the binary's functions whose status is not a matching one (`EXACT`/`RELOC`/`PROVEN`), smallest first then VA |
| Decomposition | `create_auto_run` writes one `root` task and one `batch` task per group of `functions_per_task` functions, each batch carrying the function snapshots it was planned for |
| Fan-out | `_execute_batches` puts the batches on a `queue.Queue` drained by `min(concurrency, batches)` daemon worker threads; the cap is a named constant with a floor and ceiling |
| Execution | each batch thread opens its own SQLite connection and runs each function through up to `max_attempts` worker calls, each under `task_timeout` in its own daemon thread so a wedged worker is abandoned, not waited on |
| Acceptance | `_accepted`: a `matched` result is accepted only when its status is a matching one and its `verified` flag is set, i.e. the worker got it from `rebrew test`; a rejected `matched` becomes `improved` (something was produced) or `failed` |
| Aggregation | a batch with any accepted function is `done`, all-failed is `failed`, otherwise `skipped`; the root aggregates its children and is `failed` if any child never reached a terminal status; the run reports `matched`/`improved`/`failed`/`skipped` and the coverage delta |
| Revertibility | an executing run records every file it wrote and every status it replaced in the batch result, and each completed batch folds its descriptors into `auto_runs.effects_json` in the same commit as that result, so a hard kill loses only the task in flight; `revert_auto_run` replays that plan newest-first through the shared dispatcher, removing exactly those files, restoring those statuses and deleting the run's rows |

Planning and execution are separate calls (`create_auto_run` then
`execute_auto_run`) so the API can create the run row in the request thread and
work it in a background thread; because a batch's functions live in its stored
result until it runs, `planned_batches` returns exactly the batches still to
do, which is what makes an interrupted run inspectable and re-runnable.

Incremental plan persistence closes the hard-kill window down to one task.  Each
batch's close writes the task row and the run's undo plan in one transaction
(`auto_store.record_auto_task_outcome`), so a process killed between batches
leaves the plan holding every completed task's writes; only the batch still in
flight, whose result is not recorded yet, can be lost.  Closing the run
consolidates the plan from the task results without duplicating an entry an
earlier task already persisted.  A run a previous process left `running` is
closed by `auto_mode.recover_auto_run`: it treats the run as stale (there is no
registry of live runs), marks each `running`/`pending` batch task `failed` with
reason `interrupted`, merges the `written_files` and `status_changes` those
tasks had recorded into the plan, and closes the run `failed` when nothing
completed, `partial` when some batches did and `done` when every batch did.  A
run already closed is returned unchanged.  The API route is `POST
/api/auto/runs/<id>/recover`, the CLI `reportal auto-recover <run-id>` (with
`reportal auto --recover` recovering the binary's latest stale run first) and
the MCP tool `recover_auto_run`; all three are destructive.

Batches run on their own SQLite connections, so the run sets `busy_timeout`
(30s), WAL and `synchronous = NORMAL` on its connections: a batch waits for the
write lock instead of failing, and the polling `GET` never blocks behind a
writer.  The journal mode is a database-level setting and is switched once on
the coordinator connection before any worker opens one.

Every write is gated on `execute`.  A dry run records the run, its tasks and
its attempts, and reports the coverage its accepted claims *would* produce; it
never compiles anything, never writes into the rebrew project and never changes
a function row.  An executing run uses `rebrew test --json` (through
`RebrewEngine.test_source`) as its only source of truth, which is why a worker
can never mark work done by claiming it.

Workers are plugins, in the same shape as components: `auto_workers.py` holds
the registry (`register_worker` / `workers` / `refresh_workers`) and the
`reportal.auto_workers` entry-point group, whose value is `module:attr` naming
a `Worker` or a zero-argument factory returning one.  Built-ins:

| Worker | Needs | What it does |
|--------|-------|--------------|
| `offline` | nothing | deterministic: skips a function that already matches, reports a real symbol name as matched and an address placeholder as failed, and refuses an execute run |
| `llm_c_source` | the LLM bridge and (for a context it lacks, or for execute) the engine | gathers the cached NASM listing and the stored decompilation, asks the model for an MSVC6/C89 source file carrying rebrew's `// FUNCTION: <MODULE> 0x<VA>` marker, and verifies it with `rebrew test --json` |

`llm_c_source` takes the marker module and the reversed source directory from
the project's `rebrew-project.toml` the way `rebrew.config` resolves them
(`default_target`'s `marker`, else the target name upper-cased; `reversed_dir`,
else `src/<target>`), so it never invents annotation metadata, and it writes
`STATUS`, `SIZE` and `CFLAGS` nowhere: those stay metadata-owned, and
`test_source` passes `no_promote=True` so the engine does not write them either.
A retry is handed the previous attempt's engine status and mismatch summary,
which the worker feeds back into the prompt.

Deliberately not emulated from spydr: LLM review or aggregation gates (acceptance
is the engine's byte comparison), a human approval step at the root, lateral
edges between siblings (there are none), and a distributed queue.  reportal is
one process over one SQLite file; the fan-out is threads in that process, not
workers on other hosts.

## LLM bridge

`llm.py` is the only module that talks to a model, and it is optional. The AI
extras (summary, inline comments, type suggestions, identifier renames) are
OpenAI-compatible chat completions requests made through the official `openai`
SDK: `LlmClient.complete` calls `chat.completions.create(model, messages,
temperature)` against a base URL derived from the configured endpoint and
`embeddings.create(model, input, encoding_format="float")` for the knowledge
feature. Retries are the caller's (`max_retries=0`), because reportal's own AI
paths carry the retry policy and its test seams.

The SDK refuses to be constructed without an API key, so a keyless
configuration passes the placeholder `ANONYMOUS_KEY` and a request event hook
on the injected client strips that exact bearer again; with a real key set the
hook leaves the header alone. The endpoint may be given with or without the
trailing `/chat/completions` or `/embeddings` path, which `_base_url` strips.
`LlmClient` builds its own `httpx2.Client` unless one is injected, which is the
seam the suite's `MockTransport` drives instead of the network.

Configuration resolves per field from `REPORTAL_LLM_ENDPOINT` /
`REPORTAL_LLM_API_KEY` / `REPORTAL_LLM_MODEL`, then the workspace
`reportal.toml` `[llm]` table. Without an endpoint `LlmConfig.resolve` returns
None, `LlmClient.available()` is False, every AI route answers 503
`llm-unavailable` and every AI command exits 1; the default install and the
whole test suite run without one.

`summarize`, `inline_comments`, `suggest_types`, `rename_suggestions`,
`rewrite_decompilation` and `function_triage` build
the prompt, call the
client, strip a markdown fence if the model added one, parse the JSON object or
list, and return a normalized payload (`{"summary"}`, `{"comments"}`,
`{"suggestions"}`, `{"code"}`). A response that is neither a JSON object nor a
list, or that carries none of the expected fields, raises `LlmError`.
`rewrite_decompilation` also accepts a bare C string, which is the requested
value under a different envelope. `get_client` /
`set_client` are the process-wide accessor, mirroring `engines.get_engine`, so
tests inject a fake client and no test touches the network.

`conversations.py` builds scoped chats on top of that bridge. A conversation is
scoped to one stored function or binary and keeps its turns in SQLite.
`build_context` assembles a block from stored rows (a function's VA, name,
size and status plus its stored disassembly and decompilation, or a binary's
row plus its stored triage summary and capability scan), then appends the
binary's documents that `knowledge.retrieve` ranks against the message, as a
`Relevant documents` section placed last so `MAX_CONTEXT_CHARS` truncates it
first. `send_message` writes the user turn, sends the system prompt, that
context and the last `HISTORY_TURN_LIMIT` turns, then writes the assistant
turn; it returns the retrieved hits as `sources`, which the SPA renders as a
disclosure under the reply. Retrieved text is untrusted: it is quoted as data
to reason about, never executed or spliced into a command, and the system
prompt says so. This is not a tool-calling agent: the model sees the stored
context, the retrieved documents and the history, nothing more.

## AI decompilation artifact

`ai_decomp.py` is the one rewritten-function artifact: the hosted portal's
richest AI surface. It stores everything in one `ai_artifacts` row of kind
`ai-decompilation` (the rewrite, the model, the token map, the per-line
attributions, the analyst overrides, the rating and the per-line inline
comments) rather than in a table of its own, so every write goes through the
existing generic row-restore journal path and the delete plans that already
snapshot `ai_artifacts` cover it with no new entry. `write_artifact` is the
single write path the routes, the CLI and the MCP tools share, so all of them
journal the row they replace identically.

Three parts are derived locally and deterministically, and every response that
carries one says so under `derivation`:

- `tokens_of` scans the rewrite for the placeholder shapes the decompilers emit
  (`local_8`, `param_1`, `uVar2`, `DAT_...`, `FUN_...`, `LAB_...`, `_UNK...`)
  and reports each token's kind, use count and line numbers, bounded at
  `MAX_TOKEN_LINES` with the true count kept;
- `attributions_of` diffs the rewrite against the decompilation the model read
  with `difflib.SequenceMatcher` and marks each rewritten line `original`,
  `rewritten` or `added`, with the source line numbers each block paired with.
  It is a derived attribution, not model-reported provenance;
- `apply_overrides` renders the served code by rewriting each overridden token
  through `renames.replace_identifier` (whole tokens only, string literals
  skipped, keys in sorted order), so the stored rewrite is never mutated and
  clearing an override restores the model's own words.

An override must name a token the artifact carries (`unknown token`) and a C
identifier that is not a keyword (`invalid override`); a property beyond
`MAX_OVERRIDE_NAME` or a bad rating/line/body is the shared `invalid X`
vocabulary. Line comments are keyed by line number, one per line, so the hosted
`inline-comments/{line}` contract needs no id of its own.

Two ceilings are deliberate. The workflow is one model call, so
`GET .../ai-decompilation/events` reports the state it finds and its terminal
marker rather than pretending to stream progress the call does not have, and a
rewrite in flight cannot be cancelled. The token map is a scan plus the
analyst's overrides, not the hosted portal's model-reported analysis of what
each placeholder means.

## Models

`models.py` is the model registry: the one place that names what can produce a
stored result.  The hosted portal runs an analysis under a named model and can
upgrade it; reportal's producers are the `rebrew` engine, one decompiler
backend, the configured bridge model and the optional similarity extra, so the
registry names those instead of inventing a hosted model id.

A `Model` is a frozen dataclass of name, kind, version, description, an
`available()` check and the reason it is not, with `describe()` building the
wire row.  The built-ins probe rather than cache a guess: the engine entry asks
`engines.get_engine().available()`, the bridge entry reads the resolved
`llm.LlmClient` (and lists the single `unconfigured` entry, which is never
available, when no endpoint is set), and the similarity entry asks
`similarity.available()`, which is a `find_spec` probe.  The registry mirrors
the graph-backend seam: built-ins from `builtin_models()`, a third party
through the `reportal.models` entry-point group, a broken registration skipped
with a warning and a duplicate name a `RegistryError`.

`upgrade_analysis` is the one writer, and it is deliberately narrow.  The
hosted upgrade re-analyses the binary on a newer model; reportal cannot
re-analyse without the engine and the project, so the upgrade re-runs the *LLM
artifacts the analysis already stored* (a summary, inline comments, type
suggestions, identifier renames) under the named `llm` model, journals every
artifact it replaces through `journal.journaled_rows` and records the new model
on the `analyses` row.  The before/after pair is therefore the action journal's,
and a revert restores the previous payloads; a function whose re-run fails is
reported in `skipped` and keeps its stored artifact, so one bad model response
cannot strand a half-upgraded analysis.  A client that already sends the named
model is used as it is, so an injected transport (and a test's stub) survives;
a different name goes through `llm.with_model`, which shares the HTTP client and
changes only the request's model field.

The registry caches its built-ins at first use like every other registry here,
so a process that configures an endpoint after that read calls
`models.refresh_models()` to pick the new model name up.

## External sources

`external.py` is the source registry and the two answers it ships.  A source is
an offline one that derives its payload from rows the workspace already holds
(the fingerprint, the detected families, the capability tags, the threat report
and the secrets count, each reported present or absent) or a remote one that
makes a request.

The remote path is the one place reportal talks to a third party about a binary,
and it is guarded three ways.  The gate is the `remote_ingest.py` shape:
`REPORTAL_ALLOW_EXTERNAL` or `[external] allow_remote = true`, else every
remote call is 403 `external-disabled` before a socket is opened.  The key
resolves environment, then `reportal.toml`, then the secret store under
`virustotal.api_key`, which is the store's first real consumer.  The request
itself is fixed: one https host, a path built from the hash alone, the key in
the `x-apikey` header, `follow_redirects=False` so a 3xx fails rather than
hopping, a body capped at `MAX_BYTES`, a `FETCH_TIMEOUT_SECONDS` wall clock, and
a normalized subset stored (per-engine results capped at `MAX_ENGINE_RESULTS`,
no vendor links, no raw response).  A 404 is a result (`found: false`); any
other failure raises and stores nothing.

The transport is injectable (`set_http_client`), the way `llm.set_client` is, so
the suite drives it over an `httpx.MockTransport` and no test reaches the
network.  `journaled_run` is the one write path the routes, the CLI and the MCP
tools share: it snapshots the scan it replaces, stores the answer and journals
the created row when there was none, so a pull is revertible like every other
scan.

## Function-level extras

`function_extras.py` and `user_strings.py` carry the reads and writes the hosted
portal has on top of a stored decompilation, and both are built so a read never
starts work of its own.

The derivations are text scans over rows the workspace already holds and every
payload says so in its own `derivation` note.  `indirect_call_sites` walks the
function's `disasm_cache` listing: a `call` or `jmp` whose operand is a register
or a memory reference is reported with its line and instruction text, and a
function with no cached listing reports `has_disassembly: false` and no sites
rather than spawning the engine behind a read.  `function_capabilities` feeds
the imports and quoted literals the stored decompilation mentions through
`capabilities.classify`, the same rule table the binary-level scan uses, so a
function and its binary cannot disagree about a rule.  `callees_from_text`
matches the identifiers in the text against the binary's stored function names
and import stubs, and `callers_and_callees` runs that both ways in one pass over
the binary's functions.  The register vocabulary in `_REGISTERS` is what keeps
`call rax` indirect while `call sub_401000` stays direct, because a bare
identifier matches a symbol and a register alike.

`function_edges` is the one thing there that is not derived: an analyst-declared
callee edge, written with `source: analyst` and reported beside the derived
callees rather than merged into them, so a claim is never mistaken for a scan.
`add_edge` replaces a row for the same `(function, callee, kind)` in place and
the journaled pair is the write path the routes, the CLI and the MCP tools
share.

`user_strings.py` stores an analyst string at function or analysis scope, with a
kind and a note.  A value already present at its scope keeps its row and updates
its note, one scope holds at most `MAX_STRINGS_PER_SCOPE` values, and the
hosted whole-list `PUT` is `replace_strings`: every value is validated before
anything is written, and the journaled form snapshots the rows it replaces and
journals the rows it creates, so a revert restores the previous list whether the
scope held one or was empty.  `derived_literals` is the other half of a
function's string read: the quoted literals in the stored decompilation, deduped
and reported under their own label with the note that they are a text scan, so
what a human recorded is never confused with what the text carries.

`canonical_names` renames a batch to the candidate the store already recorded (a
predicted name, else the newest recorded rename) and reports a function with
neither as `skipped` rather than renaming it to a guess; each rename goes
through `journal.journaled_rename`, so one action reverts the batch.  `match_rows`
answers the recorded match rows of a batch with the same derived `difference`
and `band` the single-function route reports and runs no scoring.

`api._batch_ids` bounds every batch read at
`function_extras.MAX_FUNCTIONS_PER_QUERY` (50) and the two function-scoped
routes that would otherwise be shadowed by the int path parameter
(`/api/functions/callees-callers`, `/api/functions/matches`,
`/api/functions/canonical-names`) are registered before
`/api/functions/{function_id}` so the literal path wins.

## Secret store

`secret_store.py` owns named credentials.  A row is one name at one scope
(`local` for the workspace, `team` plus a team id), and the table is created on
first use so an existing database needs no migration.  The module's one
invariant is that a read never returns a value: `_row` builds every read payload
(name, scope, team, byte length, last-four hint) and `journaled_set` returns it,
while `value_of` is the single function that returns a credential and is called
only by an internal consumer on the caller's behalf (`llm` resolves the bridge
key as environment, then `reportal.toml`, then the store under `llm.api_key`).

Resolution order is deliberate: an operator who exported a variable or wrote the
table keeps what they set, and a stored value is the fallback.  A team-scoped
value wins over the local one for a caller that names the team, so a team's own
key overrides the workspace default, and a caller that names no team reads only
the workspace value.

`journaled_set` and `journaled_delete` are the one write path the routes, the
CLI and the MCP tools share, so all three journal the row they replace or create
identically and a rotation is revertible.  The previous value therefore lives in
`journal_entries` until that action is reverted or pruned, which is what makes
the rotation undoable and is stated in `docs/THREAT_MODEL.md` along with the
plaintext-at-rest boundary.  Authorization is two rules: a workspace secret
needs an admin, a team secret needs that team's membership (or an admin), and
with auth off the install is the single local operator.

## Documentation

`docs.py` is the in-app manual, and its one design decision is that the server
sends structure rather than markup.  `GET /api/docs/<slug>` answers a title, the
sub-headings with their anchors and a flat list of blocks (heading, paragraph,
list with each item's depth, fenced code, quote, table), and the SPA's
Documentation view renders them with its own small inline pass.  That is what
keeps `dangerouslySetInnerHTML` and a markdown dependency out of the bundle: a
document is data, and the only markup in the app is the app's own.

The subset is the ceiling.  A heading, fence, list, quote or table the reader
recognizes becomes that block; anything else is folded into a paragraph, so a
construct the reader does not know is shown rather than dropped, and a document
that grows a new syntax degrades to readable text instead of an empty page.  The
fence marker is matched by its own character (` ``` ` closes ` ``` ` and `~~~`
closes `~~~`), a table needs its dashed separator row to be one at all, and a
list item's depth is its indent, which is what the view uses to indent it.

Where the documents live resolves once per request, first match wins: an
explicit `REPORTAL_DOCS` directory, then the workspace's own `docs/`, then the
checkout beside the installed package.  None of the three is a real error (a
wheel installed on a host with neither), so it answers 404 `no-docs` with that
reason rather than an empty manual, and a slug that is not a page is 404
`no-doc`.  `MAX_DOC_BYTES` bounds one read, so a stray huge file cannot turn a
page load into a slow parse; the truncation is silent, which is the one
deliberate residual here because the alternative (refusing to show a document
that is merely long) is worse for a reader.

## Analytics

`analytics.py` is the dashboard's only computation.  It reads `analyses`,
`auto_runs` and `journal_entries` by day (`substr(created_at, 1, 10)`) and
derives one more series from stored evidence: the software type each analysis's
binary classifies as, through the same `threat.classify_binary` the threat and
triage routes answer with, so the chart and the badge cannot disagree.  Nothing
is stored: the series is a read, so a new scan or a rename shows up on the next
load rather than waiting for a job to refresh a table.

Two decisions are deliberate.  Every day in the window is present, a quiet one
with a zero, because a chart with holes reads as missing data rather than as no
activity; and the software-type derivation is bounded (`MAX_SERIES_ANALYSES`)
with the bound stated in the payload's `notes`, because deriving a type reads
several scans per binary and a long history would otherwise turn a dashboard
load into a full-table scan of the scan table.  A binary whose type cannot be
derived counts as `unknown` rather than being dropped, so the counts still add
up to the analyses in the window.

## Search
## Search

`store.search` is one function behind the search route, the CLI and the MCP tool,
so the substring form and the opt-in regular-expression form cannot drift.  The
substring form escapes `LIKE` wildcards and matches in SQL; the regex form
registers a `REGEXP` function on the connection (`store.register_regexp`, a
deterministic Python function, because SQLite carries no engine of its own) and
swaps the clause, so the match still happens in the query rather than in Python
over every row.

A pattern is untrusted input: `store.compile_regex` caps it at
`MAX_REGEX_CHARS`, caches the compiled form up to `REGEX_CACHE_SIZE`, and raises
`SearchError("invalid regex", ...)` for a pattern that does not compile, which
every surface maps to its own 400.  The honest ceiling is that Python's `re`
cannot be interrupted once a match is running, so the pattern's length is what is
bounded, not its running time.  The `sha256` kind is refused under `regex`
because a hash prefix is a literal by definition.

`store.list_functions` takes `strings` (several needles, combined as any-of in
one `EXISTS` clause) and the same `regex` flag, so the function list's string
filter uses one code path with the typed search rather than a second pattern
engine.

## Agent runs

`agent.py` turns a conversation from one model call into a tool loop over the
local MCP registry.  A run is one row in `conversation_runs` holding its status,
its events, the message list sent to the model and the call it paused on.

`tool_definitions` offers every registered tool with its own `input_schema`, so
the model sees exactly the arguments the registry validates and a plugin tool is
offered without a second list to keep in step.  The gate is
`Tool.annotations`: a read-only tool runs at once through the same
`mcp_server.call_tool` the stdio server uses, and a tool that changes the
workspace pauses the run at `waiting_confirmation` with the call it wants to
make.  An unknown tool counts as destructive, so a name the registry does not
declare is never run unconfirmed.

`llm.LlmClient.chat` is the tool-calling half of the bridge: it returns the
assistant turn normalized to `{"content", "tool_calls", "finish_reason"}`, where
each call's `arguments` stay the raw JSON text the endpoint sent.  Parsing them
is reportal's job, because an unparsable argument list is a result the model can
correct: it is fed back as a refused tool result and the loop continues rather
than failing the run.

The loop re-reads its own row before every step, so a cancel from another
request or process stops it at the next step boundary; a model or tool call
already in flight completes, which the payload states rather than pretending
otherwise.  A run is bounded by `MAX_TOOL_CALLS`, a tool's answer by
`MAX_TOOL_RESULT_CHARS` and one argument object by `MAX_ARGUMENT_CHARS`, and the
events list is capped at `MAX_EVENTS`.

`conversations.agent_messages` assembles the system prompt, the stored context
and the history through the same helpers a plain turn uses, so the two cannot
disagree about what the model is shown; only `AGENT_SYSTEM_SUFFIX` is added,
naming the tools and the confirmation rule.  A tool's result is quoted as data to
reason about, never spliced into a command or an instruction.

The run row and the messages a turn wrote are one journaled action
(`journal.journaled_create` for the row, `journal.journaled_messages` for the
messages).  A tool the run called carries its own journal action, which the run's
action does not cover: reverting a conversation does not undo a tool's write.

## Debug symbols

`symbols.py` reads the one name source reportal cannot derive.  The engine's
annotations, library identification and the rename paths all guess; a PDB or an
ELF/DWARF table states what the toolchain knew when it built the binary.

`parse` dispatches on the file's magic.  `parse_elf` reads `.symtab` and
`.dynsym` (the 32- and 64-bit layouts, the linked string table, `STT_FUNC` and
`STT_OBJECT`) and then merges the DWARF subprograms, so one ELF gives one list.
`parse_dwarf` reads `.debug_info` unit by unit: the unit headers of DWARF 2 to
5, each unit's abbreviation table, the DIE stream with the full DWARF 5 form
table, subprograms with their `DW_AT_low_pc`, and the aggregate tags with their
members, member offsets and rendered member types.  DWARF 5 moved names and
addresses behind the per-unit `DW_AT_str_offsets_base` and `DW_AT_addr_base`, so
the root DIE is parsed first to resolve them before any indexed form in the unit
is read.  `parse` hands a PDB to `pdb.py`, which reads the MSF 7.0 superblock,
the stream directory and the DBI stream's section map and symbol record stream
(public and procedure symbols, names only).

`pdb.py` was checked against a PDB built by `clang -gcodeview` and `lld-link /debug`
and cross-read with `llvm-pdbutil dump -publics`: the container, the DBI header and
the symbol record stream read back the same publics.  A real PDB keeps its section
map as `SectionMapEntry` records and its addresses in a separate section header
stream, which this reader does not follow, so a real PDB's symbols answer
`va: null` and only their names and kinds are reported; no address is invented.

A form the reader cannot size ends the unit with a note rather than desyncing
the DIE stream, and a member whose offset is a location expression is skipped
rather than assumed to be zero: a guessed name or address is worse than a
missing one, so every parse carries its own `notes` saying what it did not do.

`import_symbols` is the one write path.  The file's bytes are stored
content-addressed under the workspace's `symbols/` directory (the sha256 of the
content, the way an upload is), a function whose VA matches a symbol is renamed
through `journal.journaled_rename` with the `symbol` name source (a system name
in `composition.NAME_SOURCE_MAP`), and every aggregate type is created or
updated in the editable model, with both writes inside the caller's journaled
action.  `render_symbols` renders a parse as JSON or as a C header through
`data_types.render_header`, so the export and the editable model cannot
disagree, and a function symbol is carried as a comment so a type maps back to
the function it came from.

## HTTP surface

The application is FastAPI on ASGI, served by uvicorn (`reportal serve`).
`server.py` holds the app and the shared contract: `json_response` (the same
`Vary`/`Content-Length`/gzip behaviour the Bottle server had), `json_error`
(the `{"error", "detail", "doc_url"}` envelope), the loopback Host guard, the
security headers and `db()`. `json_error` returns a `JsonError` that is both a
Starlette response *and* an exception, so a route writes `return
json_error(...)` or `raise json_error(...)` exactly as the Bottle routes did;
the handlers registered in `server.py` keep FastAPI's own refusals (405 on a
known path, 422 on a malformed path parameter) inside the same envelope, and
turn an unhandled exception into 500 `internal server error` for `/api/*`.

**The Bottle migration is done.** Every route is FastAPI on ASGI, served by
uvicorn: `api.py` holds the JSON API and `ui.py` the built SPA, its assets and
the generated report sites, and `webapp.py` includes both routers.  The
conventions a handler follows:

- the path is FastAPI's (`/api/x/{id}`), and the return annotation is
  `Response`;
- a handler that reads the query string takes `request: Request` and passes it
  to the `_query_*` helpers, which read through `request.query_params`;
- a handler that reads a JSON body takes `body: dict[str, Any] =
  Depends(json_body)` from `server.py`, or `Depends(optional_json_body)` when
  an absent body means `{}`.  Both resolve on the event loop, so the handler
  stays a plain `def` and runs on the threadpool;
- the two multipart uploads read `await request.form()` themselves rather than
  declaring `File`/`Form` parameters, because a part that is not a file has to
  be a missing file (400 `no-file`) and a body the reader cannot follow has to
  be 400 `invalid-body`; the copy into `binaries/` then runs on the threadpool
  through `run_in_threadpool`, so a large upload does not block the loop.

Nothing about a request error becomes a 500: `json_error` returns an object
that is both a response and an exception, so a handler may return or raise it,
and the handlers in `server.py` fold FastAPI's own refusals (405 on a known
path, an uncoercible path parameter, an unreadable body) into the
`{"error", "detail", "doc_url"}` envelope.  `redirect_slashes` is off so a
trailing slash stays the JSON 404 the router has always answered.

One deliberate difference from the Bottle server: Starlette parses a multipart
body before the route sees it and spools a part over 1 MiB to the system temp
directory, where the Bottle route streamed the part straight to `binaries/`.
`MAX_UPLOAD_BYTES` still decides what is stored; only the transient temp usage
changed, and `api.py`'s upload section names the upgrade path if it matters.

Binary intake: `POST /api/binaries` takes a `multipart/form-data` upload (`file`
part, optional `name` field), streams it to `<workspace>/binaries/` while
hashing it, and publishes it as `<sha256><suffix>` with `os.replace`, so a
partial upload is never visible. The suffix is kept from the client filename
only when it matches `^\.[A-Za-z0-9]{1,8}$`. Dedupe is by sha256: a repeat
upload removes the temporary file and returns the existing row with
`"duplicate": true`. The size cap is `MAX_UPLOAD_BYTES` (413 `file-too-large`);
a missing part is 400 `no-file` and an empty one 400 `empty-file`. The CLI
(`add-binary`, `import-rebrew`) still registers binaries from local paths.
Repeated `file` parts, or a JSON `files` field beside one part, make the same
route a batch: `files[i]` carries part *i*'s `name`, `tags`, `collection_ids`
and explicit `format`/`arch` (validated against `UPLOAD_FORMATS`/
`UPLOAD_ARCHITECTURES`), each failing part reports the single-file path's own
code inside its entry while the rest register, a duplicate is reported as
`"duplicate": true`, and the whole request is one journal action capped at
`MAX_UPLOAD_FILES` (400 `too-many-files` past it). `POST
/api/binaries/<id>/extract` reads a stored archive through `reportal.archive`
and registers its members into one collection as one journal action, reporting
each member's id or skip reason; `reportal extract` and the `extract_archive`
MCP tool call the same `extract_archive_binary` helper.
`GET /api/binaries/<id>/download` streams a stored binary back as an
attachment, reading and yielding it in `BINARY_DOWNLOAD_CHUNK_BYTES` (1 MiB)
chunks rather than loading it whole, because an upload may be up to
`MAX_UPLOAD_BYTES` (256 MiB) and a single `read()` would hold the binary in
memory per concurrent download. The filename comes from the stored name
through `download_filename` (one path component, every character outside
`[A-Za-z0-9._-]` an underscore, the content-addressed file name as a
fallback), never from the request; `Content-Length` is the file's own byte
count, the content type comes from its suffix through `BINARY_CONTENT_TYPES`
(else `DEFAULT_BINARY_CONTENT_TYPE`), and `Cache-Control` is
`BINARY_DOWNLOAD_CACHE_CONTROL` (`public, max-age=31536000, immutable`)
because the bytes are content-addressed. An unknown id is 404 `binary not
found`; a row whose file is gone is 404 `binary not on disk` naming the path it
looked for, where the engine routes answer 400 for the same condition, since a
download is of a representation that is gone. `reportal download` writes the
same bytes to an explicit path.
Read routes are `GET /api/binaries`, `/api/binaries/<id>`, `.../functions`
(which takes the filter and sort parameters the Functions view sends:
`name_source`, `capability`, `min_size`, `max_size`, `string`, `match`, `sort`
and `order`, each validated against its closed set with a 400 for an unknown
value, and answers `count` and `total` so a filter is distinguishable from a
small binary),
`.../fingerprint`, `.../imports`, `.../strings`, `.../tags`, `.../triage`,
`.../function-triage`,
`.../report`, `.../report/pdf`, `.../structs`, `.../crypto-scan`, `.../pe-info`, `.../die-info`, `.../additional-details`, `.../additional-details/status`, `.../filetype`, `.../capabilities`,
`.../secrets`, `.../protocols`,
`.../behavior` (all three domains) and `.../behavior/<domain>`,
`.../hardening` (both domains) and `.../hardening/<domain>`,
`.../security-scan`, `.../unstrip`, `.../threat`, `.../remediation` and
`.../remediation/<yara|snort|stix>`,
`.../lineage`, `.../related`, `.../composition`, `.../detect`, `.../data-types`, `.../signatures`,
`.../comments`, `.../auto`, `.../documents`, `.../knowledge` and `.../graph`;
the graph node route is `GET /api/graph/nodes/<node_id>`, and
`GET /api/functions/<id>/signature` returns one function's signature.

| Group | Routes |
|-------|--------|
| Health | `GET /api/health` |
| Jobs | `GET`/`POST /api/jobs`, `GET /api/jobs/<id>`, `POST /api/jobs/<id>/cancel`, `GET /api/jobs/<id>/events` (server-sent events), `POST /api/jobs/run` |
| Binaries | `GET /api/binaries`, `GET /api/binaries/<id>`, `.../download`, `.../download-zipped`, `.../die-info`, `.../additional-details`, `.../additional-details/status`, `.../functions`, `.../matches`, `.../lineage`, `.../related`, `.../composition`, `.../detect`, `.../comments`, `.../memory`, `.../memory/page`, `.../section-coverage`, `POST /api/binaries`, `POST /api/binaries/<id>/extract`, `POST /api/binaries/bulk` |
| Families | `GET`/`POST /api/families`, `GET`/`DELETE /api/families/<id>` |
| Data types | `GET`/`POST /api/binaries/<id>/data-types[/import\|/export]` (the GET takes `?kind=&namespace=&search=`), `PATCH`/`DELETE /api/data-types/<id>`, `POST`/`DELETE /api/data-types/<id>/members[/<member>]`, `POST /api/data-types/<id>/members/<member>/gap`, `POST /api/data-types/<id>/members/<member>/ungap`, `POST`/`PATCH`/`DELETE /api/data-types/<id>/values[/<value>]`, `GET /api/data-types/<id>/references`, `GET /api/data-types/<id>/history`, `POST /api/data-types/<id>/history/<history_id>/revert` |
| Signatures | `GET`/`POST /api/binaries/<id>/signatures[/import\|/export]`, `GET`/`PATCH`/`DELETE /api/functions/<id>/signature`, `POST`/`PATCH`/`DELETE /api/functions/<id>/signature/parameters[/<index>]`, `GET /api/functions/<id>/signature/history`, `POST /api/functions/<id>/signature/history/<history_id>/revert` |
| Functions | `GET /api/functions/<id>`, `.../disasm`, `.../cfg`, `.../decompilation`, `.../xrefs`, `.../references`, `.../history`, `.../matches`, `.../diff`, `.../diff/<candidate_id>`, `.../summary`, `.../comments`, `.../type-suggestions`, `.../renames`, `.../ai-comments`, `POST /api/functions/bulk` |
| Comments | `GET`/`POST /api/binaries/<id>/comments`, `GET`/`POST /api/functions/<id>/comments`, `PATCH`/`DELETE /api/comments/<id>` |
| Mutations | `POST .../rename`, `.../apply-match`, `.../history/<hid>/revert`, `.../fingerprint`, `.../match`, `.../lineage`, `.../related`, `.../composition`, `.../detect`, `.../triage`, `.../function-triage`, `.../report`, `.../report/pdf`, `.../structs`, `.../crypto-scan`, `.../pe-info`, `.../filetype`, `.../capabilities`, `.../secrets`, `.../protocols`, `.../behavior/<domain>`, `.../hardening/<domain>`, `.../security-scan`, `.../threat`, `.../remediation`, `.../unstrip`, `.../unstrip/apply`, `.../decompilation`, `.../summary`, `.../ai-comments`, `.../type-suggestions`, `.../renames`, `.../renames/apply`, `.../renames/revert`, `POST /api/binaries/<id>/matches/transfer` (bulk symbol transfer; its binary is the one the listed functions must belong to) |
| Analyses | `GET`/`POST /api/analyses`, `GET /api/analyses/<id>/scans`, `GET /api/analyses/<id>/logs`, `DELETE /api/analyses/<id>` |
| Collections | `GET`/`POST /api/collections`, `POST /api/collections/<id>/binaries` |
| Tags | `GET`/`POST /api/tags`, `GET`/`POST /api/binaries/<id>/tags`, `DELETE .../tags/<tag_id>` |
| Conversations | `GET`/`POST /api/conversations`, `GET`/`DELETE /api/conversations/<id>`, `POST /api/conversations/<id>/messages` |
| Pipeline | `POST`/`GET /api/functions/<id>/pipeline`, `GET /api/pipeline/runs/<id>`, `POST /api/pipeline/runs/<id>/revert` |
| Components | `GET /api/components`, `POST /api/components/reload`, `POST /api/components/<name>/deactivate` |
| Integrations | `GET /api/integrations` |
| Auto mode | `POST`/`GET /api/binaries/<id>/auto`, `GET /api/auto/runs/<id>`, `POST /api/auto/runs/<id>/revert` |
| Knowledge | `POST`/`GET /api/binaries/<id>/documents`, `GET`/`POST /api/documents`, `GET`/`DELETE /api/documents/<id>`, `GET /api/knowledge/search`, `GET /api/binaries/<id>/knowledge`, `GET /api/functions/<id>/knowledge`, `POST`/`GET /api/binaries/<id>/graph`, `GET /api/graph/nodes/<node_id>`, `GET /api/graph/backends`, `POST /api/binaries/<id>/graph/sync`, `GET /api/graph/query` |
| Search | `GET /api/search?q=&kind=&limit=` |
| UI | `GET /` (built SPA), `GET /static/<path>` (its assets), `GET /reports/<id>/` and `/reports/<id>/<path>` |

Semantics worth knowing: scan GETs (`triage`, `function-triage`, `report`,
`structs`,
`crypto-scan`, `pe-info`, `filetype`, `capabilities`, `secrets`, `protocols`, `behavior`, `hardening`,
`security-scan`,
`unstrip`, `threat`, `remediation`, `remediation/<format>`, `detect`, `lineage`, `related`, `composition`) are **stored-only** and answer
`404 no-scan` when
nothing was recorded; the matching POSTs run the engine and store. Every error
body is `{"error": ..., "detail": ..., "doc_url": ...}`: `error` is the stable
code, `detail` the human context, and `doc_url` a link into
`docs/ERRORS.md`'s section for that code, or `null` when the catalogue does not
name it. This is a deliberate, documented change to the error contract of every
route, including the SPA's error notes and the MCP tool errors that mirror the
vocabulary; the catalogue lives in `src/reportal/error_docs.py` and
`tests/test_error_docs.py` checks it against the page in both directions, so a
code is never linked to a heading that does not exist. `GET /` answers
`503 ui-not-built` when the frontend has no build.

The match routes carry the Match Settings scope. `POST /api/binaries/<id>/match`
takes `min_similarity` (80.0), `min_confidence` (0.0), `include_self` (true),
`top` (10), `platforms`, `architectures`, `binary_ids` and `collection_ids`,
parses them through `matching.MatchSettings.from_request` (a bound or a closed
vocabulary, 400 for a value outside it) and stores the settings on every row
the run records. The platform/architecture scope is best-effort: it compares a
binary's stored fingerprint when one exists, else its suffix-derived
`format`/`arch` columns, so it is a coarse filter and not a guarantee, and the
response says so in `notes`. `GET /api/binaries/<id>/matches` is stored-only
and reports the recorded edges with their run settings (null for rows written
outside a run) plus the derived `difference` (`100 - similarity`) and `band`
fields; `GET /api/functions/<id>/matches` adds the same derived fields to one
function's edges. `POST /api/functions/<id>/apply-match` and
`POST /api/binaries/<id>/matches/transfer` transfer a candidate's name,
signature or both; a signature transfer refuses a differing non-empty calling
convention with 409 `signature-conflict`, and the bulk route reports per-row
`applied`/`skipped`/`failed` in one journal entry, with `dry_run` writing
nothing.

The PDF routes are the local report export: `POST /api/binaries/<id>/report/pdf`
renders `pdf.write_report` from the stored scans into
`<workspace>/reports/<id>/report.pdf` and answers
`{"path", "bytes", "pages", "download_url"}`; `GET` on the same route serves
that file as `application/pdf`, or `404 no-pdf` with the generate hint before
the first render. Both answer `404 binary not found` for an unknown id, and
neither runs the engine.

The data-type routes read and write the local model, never an engine:
`GET /api/binaries/<id>/data-types` always answers with the model, taking an
optional `kind` (400 `invalid kind` outside `data_types.KINDS`), `namespace`
(a path matches itself and every descendant, `Binary` names the program-defined
types, an unknown path answers an empty list rather than an error) and
`search` (a substring of the type name, a member name or an enum value name);
the body carries the filtered `count`, the unfiltered `total`, each type's
kind, namespace and padded `as_c` declaration, and the namespace tree over the
whole model. `GET /api/data-types/<id>/references` answers the two reverse
indices (`referenced_by` and `used_by_functions`), matched by name with the
payload's `note` stating so, and 404 `data-type-not-found` for an unknown id.
`POST .../data-types/import` is stored-only (404 `no-scan` without a stored
`structs` scan and 404 `binary not found` for an unknown id), and
`POST .../data-types/export` takes `{"path", "force"}` (409 `export-exists`
when the target exists without `force`, 400 `invalid path` when its parent
cannot be created). The `PATCH` route takes the type-level fields (`name`,
`kind`, `namespace`, `size`, applied in one write and one history entry) or the
exclusive `member` edit (400 `invalid request` when neither or both are given,
400 `invalid kind` outside `data_types.KINDS` listing the known ones, 400
`invalid size` for a negative or non-integer declared size). The `members`
routes answer 404
`data-type-not-found` / `member-not-found` for an unknown id or selector, 400
`invalid name` for a non-identifier, 400 `duplicate name` / `duplicate member`
for a clash, and 400 `invalid member` for an empty declaration, an unparsable
member type, a member edit on a kind without members, or an add naming both an
insert `index` and an `after` (the two are exclusive rather than silently
ordered). An add carries the member's `pointer`, `count` and `bits` beside its
`name` and `type`; `POST .../members/<member>/gap` converts a struct member to
the recovered explicit-padding convention (`char gap_XXXX[N]`, its name derived
from the member's offset) and `POST .../members/<member>/ungap` turns one back
into a named, typed member. The enum value routes (`POST`, `PATCH` and `DELETE`
on `/api/data-types/<id>/values[/<value>]`) add, rename/revalue and remove an
enum constant: a value is an integer or a decimal/`0x` literal, an omitted one
continues from the last constant with the payload's `note` naming the derived
number, an unknown selector is 404 `member-not-found` (a constant is a named
entry of the enum, so it shares the member selector's code), and a duplicate
name or value is 400 `duplicate member`. Every type payload also carries
`size_check`, which compares the declared size with the extent the members imply
and names both numbers in its `warning` when they disagree; the check is
read-only and rewrites neither value.
Every one of those mutations records the state it replaced and the state it
wrote: `GET /api/data-types/<id>/history` answers the versions newest first,
each entry carrying `previous` and `current` (either side null for a create or
a delete), its `source`/`actor` and the per-field `changes` diff over
`data_types.HISTORY_FIELDS`. The route always answers and carries `exists`
(and a `binary_id`), because the history rows are keyed by the type id and hold
no foreign key to `data_types`: a deleted type's history stays readable and
`POST /api/data-types/<id>/history/<history_id>/revert` puts the row back under
its original id. A revert records its own inverse state under source `revert`,
journals the row it replaces and the history row it appends, and answers
`changed: false` with a `reason` when there is nothing to do (the type already
holds that state, or a recorded creation's type is already gone); an unknown
history row is 404 `history not found` and a name another type now holds is 400
`duplicate name`.

The signature routes likewise read and write the local model and never run an
engine: `GET /api/binaries/<id>/signatures` always answers with the model,
`POST .../signatures/import` parses the binary's stored decompilations (no
stored one is a summary of zero, not an error), and
`POST .../signatures/export` takes `{"path", "force"}` (409 `export-exists`,
400 `invalid path`). `GET /api/functions/<id>/signature` returns the row plus
its rendered prototype and answers 404 `signature-not-found` without one; each
parameter also carries `default_at`, the arrival location its calling
convention implies, which is derived beside the model and never written into
`at`; the
`PATCH` route takes `return_type` and/or `calling_convention` (400
`invalid request` when neither is given, 400 `invalid type` for an empty or
unknown one), the `parameters` POST/PATCH/DELETE routes answer 400
`invalid type`, `invalid name`, `duplicate parameter` and `invalid index`, and
`DELETE` on the signature answers 404 `signature-not-found`. A parameter also
carries the optional `at`, `kind` and `bits` (an explicit `null` clears one,
an absent key leaves it; 400 `invalid parameter` when a PATCH names none or
gives one the wrong type), and `POST
/api/functions/<id>/signature/parameters/<index>/move` reorders one parameter
by `to_index`, recomputing every derivable `at` from its new index.

The reference routes read the engine's per-function dossier. `GET
/api/functions/<id>/references` runs `rebrew describe <va> --json` in the
binary's stored project context and normalizes the dossier into `globals`,
`callers` and `callees`: a global names its address, the engine's reference
kind, the access (`read`/`write`, or `null` when the instruction does not make
it clear) and the section the stored `pe-info` scan places it in (or `null`),
a caller carries its `from_va` and the containing function's name, and a
callee carries its target, name, kind and an `indirect` flag for an import-slot
call with no resolved name. `counts` reports the row counts and `count_note`
states that callers counts call sites while callees counts (target, kind)
pairs. The route follows the xrefs mapping (404 unknown function, 400
`no-engine-context`, 503 without an engine, 500 `engine-error`).

`GET /api/functions/<id>/cfg` is the function's derived control-flow graph:
it calls `rebrew.asm.build_cfg_payload` in the same stored
project context and converts the engine's `0x...` addresses to ints, so the
client never parses hex. The payload carries `function_id`, the extent's `va`
and `size`, `blocks` (each with `va`, `size`, `instruction_count`, `first` and
`last`) and `edges` (each with `from`, `to` and `back_edge`), plus the
honesty fields: `block_count` (what the payload returns), `block_total` (the
engine's true count), `block_cap` (the engine's per-function cap),
`truncated` and `note`. The stored function's size is passed as `--size` when
it is positive, the same declared extent the listing covers; a non-positive
size omits the flag so the engine resolves the extent itself and answers empty
`blocks` with a `note` rather than a guessed window, and the route substitutes
its own explanation when a payload carries neither. A malformed block or edge
is dropped rather than rendered as a fabricated address. Nothing is stored and
no cache is written: the graph is recomputed per request like the xrefs and
references views. The route follows the same mapping as those two (404 unknown
function, 400 `no-engine-context`, 503 `engine-unavailable` without an engine,
500 `engine-error` for a non-x86 target or any other engine failure).

The strings route normalizes the engine's entries and sorts them
server-side: `GET /api/binaries/<id>/strings?sort=value|length&order=asc|desc`
answers one row per string (`va`, `section`, `kind`, `size`, `text`, with an
unreported field `null`), ties broken on the text then the address, and the
functions route's `refers_to` filter keeps the stored functions whose byte
range contains one of the address's cross-references, resolved through the
same `rebrew xrefs` call the xrefs route makes (it is the one engine-backed
filter on the otherwise stored-only listing).

`GET /api/binaries/<id>/memory/page` is the full-file hex view's page read:
`?va=` is the page's first address (omitted starts at the first raw-backed
section), `?length=` the page size (default `engines.MEMORY_PAGE_DEFAULT`, cap
`MEMORY_PAGE_MAX`) and `?kind=` the address kind (`va`, `rva` or `file`, so a
jump is virtual or an offset). The engine's own `pe-info` section map decides
what is data: a run inside a section's raw bytes is a `bytes` row read from
the file, and every other byte in the page (a header, the gap between two
sections, a section's uninitialized tail) is a `gap` row, because the engine
refuses a read it cannot serve. `next`/`prev` carry the neighbouring page
starts, `sections` the map, and a start without backing bytes answers 400
`unmapped address`.

The AI routes (`summary`, `type-suggestions`, and the inline-comments artifact
at `.../ai-comments`) share that shape with
their own codes: the POSTs require a stored decompilation and never run the
decompiler (404 `no-decompilation`), answer 503 `llm-unavailable` without a
configured endpoint, and store nothing on an unusable model response (502
`llm-error`); a successful POST returns `{"function_id", "kind", "payload",
"model"}`. Their GETs are stored-only, resolve neither engine nor LLM, and
answer 404 `no-artifact` when nothing is stored.  The inline-comments artifact
keeps the stored kind `comments` but is served at `ai-comments`, because the
analyst comment routes own `/comments`; the analyst routes validate the scope,
author and body through `comments.py` (400 `invalid comment`, 404 for an
unknown scope or comment) and the bulk routes through `bulk_actions.py` (400
`invalid bulk request`, per-id `skipped` rather than a batch failure).

The function-triage routes add the per-function layer to the triage surface.
`POST /api/binaries/<id>/function-triage` takes the optional body
`{"function_ids": [...], "limit": N}`, answers 404 for an unknown binary, 400
`invalid body` for a `function_ids` that is not a list of integers, an unknown
function id or a limit outside `1..function_triage.MAX_LIMIT`, and 503
`engine-unavailable` only when the LLM path needs a disassembly and no engine
is available. A missing LLM endpoint is not an error: the run falls back to
the heuristic, records `model: ""` and a note, and still stores the artifacts
and the aggregate. A function whose context cannot be resolved is recorded in
the payload's `skipped` list with a reason rather than failing the request.
Its GET is stored-only and answers 404 `no-scan`.

The rename routes (`renames.py`) extend that family to identifiers. `POST
/api/functions/<id>/renames` stores the model's suggestions under the
`renames` artifact kind and answers the stored envelope; its GET is stored-only
(404 `no-artifact`). `POST .../renames/apply` takes `{"applied": [...],
"rename_function": bool}` (400 `invalid applied` / 400 `rename_function must be
a boolean`), needs the stored decompilation (404 `no-decompilation`), applies
whole-token rewrites outside string literals, refuses protected keywords and
identifiers shorter than `renames.MIN_IDENTIFIER_LENGTH` as skipped entries,
journals the previous text as kind `renames-applied`, and returns
`{"function_id", "applied", "skipped", "decompilation_updated"}`; with no
`applied` it applies every stored suggestion and answers 404 `no-artifact` when
none is stored. `POST .../renames/revert` restores that journaled text and
answers 404 `no-artifact` when there is nothing to revert.

The pipeline routes run the component composition. `POST
/api/functions/<id>/pipeline` answers 404 for an unknown function and 503
`pipeline-unavailable` only when the composition itself cannot be assembled;
everything else is a step on the run, so a skipped or failed stage never fails
the request. Its optional body accepts `{"disabled": [...]}`. `GET` on the same
path serves the latest run with its steps and the function's durable artifacts
and answers 404 `no-run` before the first run. `GET /api/pipeline/runs/<id>`
serves one run (404 `run not found`) and `POST /api/pipeline/runs/<id>/revert`
replays the run's undo plan newest-first, returning what it undid.

The component routes read and reload the process-wide registry; neither touches
the store. `GET /api/components` lists every entry's name, `requires`,
`provides`, `origin` and `reloadable`. `POST /api/components/reload` takes
`{"name": "..."}` or `{"all": true}` (400 for neither, for both, or for a
non-boolean `all`) and re-imports the declaring module, swapping the registry
entry in place; an unknown name is 404, an in-process registration 409
`not-reloadable`, and a reloaded module that no longer declares the component
500 `component-missing`. A run already in flight keeps the snapshot it started
with.

The auto-mode routes decompose and work one binary. `POST
/api/binaries/<id>/auto` validates every bound (400 `invalid params` for a
non-integer or out-of-range value, 400 for an unknown worker, 404 for an
unknown binary), creates the run and its task tree, and returns 202
`{"run_id", "binary_id", "status": "running"}` while a background thread works
the batches, so the request never blocks for minutes; a worker that fails
mid-run leaves a `failed` run rather than a permanent `running` one. Its body
fields are all optional: `worker`, `execute` (false), `concurrency`,
`functions_per_task`, `max_attempts`, `max_tasks`. `GET
/api/binaries/<id>/auto` serves the binary's latest run with its task tree and
coverage delta (404 `no-run` before the first run), `GET /api/auto/runs/<id>`
one run (404 `run not found`), `POST /api/auto/runs/<id>/revert` removes
the files the run wrote, restores the statuses it changed and deletes its rows,
and `POST /api/auto/runs/<id>/recover` closes a run a dead process left
`running`: it marks each unfinished task `failed`, merges what those tasks
recorded into the run's undo plan and answers `{"run_id", "recovered_tasks",
"added_descriptors", "status"}` (a closed run is returned unchanged with
zeroes; 404 `run not found`).

The conversation routes share that error shape. `POST /api/conversations`
validates `scope_kind` against `conversations.SCOPE_KINDS` (400
`invalid scope kind`) and the scope id against the stored functions or binaries
(404 `function not found` / `binary not found`), deriving the title from the
scope row when the body carries none. `GET`/`DELETE /api/conversations/<id>`
and the message POST answer 404 `conversation not found` for an unknown id; the
message POST answers 400 for a blank `content`, 503 `llm-unavailable` without a
configured endpoint and 502 `llm-error` when the model call fails. It writes
the user turn before the call, so a failed call leaves the user message and no
assistant message. `GET /api/conversations` filters on `?scope_kind=` and
`?scope_id=` (400 for a non-integer id).

The knowledge routes reuse that shape. A document POST validates `scope_kind`
against `knowledge.SCOPE_KINDS` (400 `invalid scope kind`), a binary scope
against the stored binaries (404 `binary not found`) and a project scope only
against a negative id (400 `invalid scope id`); unusable content answers 400
`unsupported-format` (a file whose suffix is not on the allowlist),
`binary-content` (too many NUL and control bytes) or `empty-text`, and a body
past `MAX_DOCUMENT_BYTES` answers 413 `file-too-large`. A created document
answers 201 and a repeated one 200 with `duplicate: true`. `GET
/api/documents/<id>` serves metadata and the chunk count, adding the text and
its chunks only with `?include_text=true`; `DELETE` answers 404 `document not
found` for an unknown id; `GET /api/knowledge/search` answers 400 for a
non-integer or non-positive bound and an empty result list for a blank query,
and never calls an embeddings endpoint that is not configured.
`GET /api/binaries/<id>/knowledge?q=` and `GET /api/functions/<id>/knowledge?q=`
are the read-only retrieval routes: each answers `{"query", "count",
"results"}` for the binary's stored documents at `RETRIEVAL_LIMIT`, a blank
query answering an empty list, and the function form defaults the query to the
function's name. An unknown binary or function is 404.

`GET /api/search` is the global search over the store. `?q=` is the query and
`?kind=` selects one of `store.SEARCH_KINDS`: `all` (the default) keeps the
substring behaviour the route always had (binaries by name, path or hash,
functions by name, collections by name or description, tags by name), while
`sha256` matches a binary hash prefix, `binary` a binary name, `collection` a
collection name and `tag` a tag name, so a typed query is a subset of `all`.
Every row carries the metadata the store holds (a binary's size, format, arch,
created and tags; a collection's member count) plus the `match` field that made
it hit, and `counts` reports each group's returned count against its matched
total so a limit never reads as a total. A SHA-256 prefix shorter than
`store.MIN_SHA256_PREFIX`, a non-hex value and a prefix that matches more than
one binary answer 400 `short-hash`, `invalid-hash` and `ambiguous-hash`, and an
unknown kind 400 `invalid-kind`. `GET /api/search` is the only backend: the
MCP `search` tool and the SPA's Search view and `⌘K` modal all read it.

`POST /api/binaries/<id>/extract` unpacks a stored archive with
`reportal.archive` (stdlib only) and registers its members as binaries in one
collection, created from the body's `collection_id` or named after the archive.
Members are extracted into a temporary directory under `<workspace>/binaries/`
and removed either way, so nothing is written outside it; each is validated
first and a refusal is reported per member rather than failing the request. The
route, `reportal extract` and the MCP `extract_archive` tool all call
`api.extract_archive_binary`, whose `ExtractError` maps to the route's JSON
body (404 unknown binary or collection, 400 `binary not on disk`, and the
archive module's own codes: `unsupported-format`, `external-tool-required` for
`.rar`/`.7z`, `password-required`/`bad-password`, `too-many-members`,
`archive-too-large`, `corrupt-archive`).

## File type detection

`filetypes.py` is the bundled file-type, packer and protector detector: a
curated `SIGNATURES` table of `FileSignature(name, category, confidence,
match)` entries over evidence reportal already fetches, so it adds no
dependency, makes no network call and never executes the sample.  The
categories are `packer`, `protector`, `installer`, `runtime` and `toolchain`.
A `SignatureMatch` is a record of the evidence a signature can fire on: a
section-name prefix, an entry-point byte prefix, a string marker, an import DLL
name (matched with a trailing `.dll` ignored), a Rich header, or an executable
section at or above `HIGH_ENTROPY_THRESHOLD`.

`detect()` is pure and takes an evidence mapping (`format`, `sections`,
`entropies`, `entry_point`, `imports`, `strings`, `rich_header` and the
optional `entry_bytes`), and a signature declares `exclude_formats`, which
keeps the DOS-only packers off a PE or ELF whose strings carry their marker.
Confidence is derived from the matched signal kinds, never
guessed per row: two or more independent kinds are `high`, otherwise the match
takes the weaker of the signature's declared confidence and the fired kind's
own ceiling, so a lone string marker or entropy heuristic never exceeds `low`
while a section name, an import or an entry-point prefix can carry `medium`.
Matches deduplicate by `(category, name)`, sort by confidence, then category,
then name, and are capped at `MAX_MATCHES` (signals per match at
`MAX_SIGNALS_PER_MATCH`) while `count` and `by_category` stay exact; an empty
match list is valid.

`run_filetype()` resolves the binary and assembles the evidence from the
engine's `pe-info`, `fingerprints`, `imports` and `strings` calls, each
standalone.  A call that fails leaves its field empty and is recorded as a note
instead of failing the run, and the payload always states the scope, the
confidence rule and the entry-point-bytes gap.  The result is stored as the
`filetype` scan, served stored-only by its `GET` (404 `no-scan` before the
first run).

## Composed detail reads

`details.py` serves the two hosted `Binaries` reads that are derivations rather
than engine calls, so both are stored-only and run nothing: `die_info` and
`additional_details`, plus the `status` read the hosted asynchronous workflow
exposes. Each composes the scans already in the store through
`store.latest_analysis_for_binary` and `store.get_scan` (the fingerprint through
its own table), which is why neither needs a new table and neither writes.

`die_info` groups the stored `filetype` scan's matches by category (packer,
protector, installer, runtime, toolchain) and keeps each match's confidence and
signal list beside the identity from the `pe-info` scan, plus the fingerprint's
section entropies and a section-name packer hint. It reports `sources`, so an
empty `packer` list beside a present `filetype` source is a signature miss, and
the bundled table is visibly smaller than Detect-It-Easy's database rather than
presented as an equivalent. `additional_details` measures the overlay from the
binary's file size against the last section's end (falling back to the stored
row's size when the file is gone), and summarizes the Rich header, the debug
entries, the directory presence flags, the counts, the Authenticode block and
the section table's shape.

`status` is the same source report on its own and always answers once the
binary exists, naming each missing input with the command that fills it, which
is what the hosted `/status` route is for. The three are served by their `GET`
routes (`die-info` 404 `no-scan` without a stored `pe-info` or `filetype` scan;
`additional-details` 404 `no-scan` without a stored `pe-info` scan; `status`
200 or 404 `binary not found`), by `reportal die-info` and `reportal
additional-details [--status]`, by the read-only `get_die_info`,
`get_additional_details` and `get_details_status` MCP tools, and in the SPA by
one `DetailCoveragePanel` that renders the coverage report beside the overlay
and Rich-header facts the existing identity, packer and section panels do not
show.

## Secrets scan

`secrets.py` is a deterministic secrets scan over the strings `rebrew strings`
returns; it makes no network call and uses no model. `SECRET_PATTERNS` is the
fixed table of `SecretPattern` entries, each a name, a compiled matcher, a
`high`/`medium` confidence and a description: an AWS access key id, a
context-anchored AWS secret access key, a Google API key, the GitHub `gh[pousr]_`
token family, a Slack `xox[baprs]-` token, Stripe live/test keys, OpenAI-style
`sk-` keys, a three-part JWT, a PEM private key header, a database connection
string carrying `Password=`/`Pwd=` beside a `Server=`/`Data Source=` field and a
generic quoted assignment to a credential-named field of at least
`MIN_LITERAL_LENGTH` characters. A pattern that anchors on context names its
credential with a `value` group, so the finding is the credential and not the
surrounding text; every specific shape is `high` confidence and the two
label-anchored rules are `medium`.

Each string is also graded with `entropy()` (Shannon bits per character) and
`looks_high_entropy()`: a value shorter than `MIN_ENTROPY_LENGTH` is rejected,
an even-length hexadecimal blob is graded against the slightly lower
`HEX_MIN_ENTROPY_BITS` (above `log2(10)`, so a digits-only string never
qualifies), and anything else needs the mixed character class (a letter plus a
digit or base64 punctuation) with no whitespace and `MIN_ENTROPY_BITS` bits per
character, so an English sentence, a dotted version string and a long lowercase
dictionary word do not qualify.

`scan_secrets()` is pure: findings deduplicate by value keeping the highest
confidence and the first VA, sort by confidence then name then VA, and cap at
`MAX_FINDINGS` while `count` and `by_confidence` stay exact. `redact()` masks
all but the first and last `REDACT_PREFIX_CHARS` characters (a shorter value is
masked whole), and every finding carries both the raw `value` and its
`redacted` form. `run_secrets()` resolves the binary, reads the strings, scans
up to `MAX_STRINGS_INSPECTED` of them, stores the result as the `secrets` scan
and returns `{"binary_id", "findings", "count", "by_confidence", "scanned"}`,
where `scanned` is the number of strings examined. A finding's raw value makes
the stored payload sensitive.

## Protocols scan

`protocols.py` is a deterministic protocol inference over the same two
standalone engine payloads (`rebrew imports` and `rebrew strings`); it makes no
network call and uses no model. `PROTOCOLS` is the fixed table of
`ProtocolSpec` entries, each a protocol name, a description, import rules
(matched with the capabilities comparison), the confidence an import hit alone
is worth, URL schemes and case-sensitive literal patterns. It covers `http`,
`https`, `tls`, `dns`, `ftp`, `smtp`, `imap`, `pop3`, `irc`, `telnet`, `ssh`,
`smb`, `rdp`, `ldap`, `snmp`, `ntp`, `quic`, `mqtt`, `websocket`, `tcp` and
`udp`.

Inference collects evidence per protocol and deduplicates it by
`(kind, value)`. An import match against a dedicated API is `high` (the
`_HTTP_CLIENT_IMPORTS`, `Ftp`, `ldap`, `Snmp`, `SSL_`/`TLS_`, `DnsQuery`,
`WinHttpWebSocket`, `WTS` and `mqtt_` families), while the shared
`_SOCKET_IMPORTS` family on `tcp` and `udp` is `medium`. A scheme found in a
`scheme://` literal is `high`, since the scheme is the protocol. A literal
match (`HTTP/1.1`, `EHLO`, `SSH-2.0`, `USER `) is `medium`. `_confidence()`
is the named promotion rule: a protocol with both an import match and a scheme
or literal match is raised to `high`.

Port evidence is optional and conservative. `WELL_KNOWN_PORTS` is the named
table of decimal port literals and their owning protocols (443 names `https`,
`tls` and `quic`); a port is recognized only as the number after a colon in a
string that also carries a host or URL (a `scheme://` form, a dotted-decimal
IPv4 literal or a dotted host name), so a lone `80` or `443` constant names
nothing. It is reported as `string` evidence, keeping the kinds at `import`,
`scheme` and `string`.

`infer_protocols()` is pure: protocols sort by name, evidence sorts by kind
then value, `count` and `by_confidence` are exact, and an empty result is
valid (its `notes` say so). `scan_protocols()` resolves the binary, reads the
imports and up to `MAX_STRINGS_INSPECTED` strings, stores the result as the
`protocols` scan and returns `{"binary_id", "protocols", "count",
"by_confidence", "notes"}`. Inference is not proof of use: an import means the
binary can call that API and a literal means the text is present.

## Function triage

`function_triage.py` adds the per-function layer to the triage surface. The
heuristic half is pure and deterministic: `score_candidates` reads each row's
size, status, `has_decompilation`, name and `match_count` and sums five named
weights (`WEIGHT_SIZE`, `WEIGHT_STATUS`, `WEIGHT_DECOMPILATION`, `WEIGHT_NAME`,
`WEIGHT_MATCHES`, summing to 1.0) into a `heuristic_score` rounded to
`SCORE_DECIMALS`, returning the contributing reasons in a fixed order. The size
and match-count signals saturate at `SIZE_REFERENCE_BYTES` and
`MATCH_REFERENCE`; a status in `store.MATCHED_STATUSES` contributes nothing,
and a placeholder name (empty, a `PLACEHOLDER_NAME_PREFIXES` prefix, or a bare
address) contributes the name weight. Rows sort by score descending, then VA,
then function id, so equal scores keep a stable order.

`candidate_rows` builds those rows from the store: the function columns plus a
decompilation lookup and the recorded match count. `summarize_functions`
selects the targets (an explicit `function_ids` list is used as given, else the
top `limit` rows of `score_candidates`, with `limit` bounded by `MAX_LIMIT`)
and resolves each one's context: its stored decompilation, else a `rebrew asm`
disassembly in the binary's stored rebrew project (which needs a project
context and a positive size), truncated at `MAX_CONTEXT_CHARS`. A function with
neither is recorded in the payload's `skipped` list with one of
`NO_PROJECT_REASON`, `NO_SIZE_REASON`, `NO_ENGINE_REASON` or
`EMPTY_DECOMPILATION_REASON`.

With a configured LLM client the context goes through `llm.function_triage`
(the prompt labels it untrusted data) and the answer's summary, clamped score
and capability tags become the row; without one the row keeps the heuristic
score and `_heuristic_summary`, a deterministic one-liner over the status,
size, name and match count, and the payload records `HEURISTIC_NOTE`. Every
summarized function stores an `ai_artifacts` row of kind
`FUNCTION_TRIAGE_KIND` carrying `{"summary", "score", "capabilities",
"method"}` and the model (`""` for a heuristic row), and the aggregate is
stored as the binary's `function-triage` scan, so `stored_function_triage`
serves it back without touching the engine or the model. The payload's
`functions` sort by score descending then VA, `by_method` counts the `llm` and
`heuristic` rows, and `model` is the answering model or `""`.

## MCP server

`reportal mcp [--json]` serves reportal's capabilities to local MCP clients
over stdio: newline-delimited JSON-RPC 2.0 on stdin/stdout. `mcp_server.py`
implements `initialize`, the `notifications/initialized` notification,
`tools/list` and `tools/call`, reports protocol version `2025-06-18` and
`serverInfo` `{"name", "title", "version"}`, and advertises a `tools`
capability. There is no `mcp` SDK dependency: the protocol is small enough to
implement over the standard library, which keeps the default install light and
offline. Only protocol JSON reaches stdout; the readiness line goes to stderr.
Startup resolves the workspace with the normal `reportal.toml` walk-up and
fails loud outside one.

Tools are plugins in `mcp_tools.py`. A `Tool` carries a `name`, a
`description`, an input JSON Schema, `annotations` and a handler; handlers call
the same internal functions the routes do (store, engines, pipeline, llm) and
never make an HTTP request back into reportal. Built-ins are declared in
`builtin_tools()`; a third party registers an entry point in the
`reportal.mcp_tools` group (`module:attr` naming a `Tool` or a zero-argument
factory), mirroring `reportal.components`: a broken registration is skipped
with a warning and a duplicate name is a `RegistryError`. The sub-registry is
`register_tool` / `tools` / `refresh_tools`.

The read tools call the internal helpers of the `GET` routes, so the
stored-only routes (triage, function triage, report, structs, crypto, security,
capabilities,
protocols, behavior, hardening, threat, remediation, unstrip, detect, summary,
the inline comments artifact, type
suggestions, renames, comments) stay
stored-only and never run an engine the route would not. Destructive tools carry `destructiveHint: true`:
anything that runs an engine, renames, uploads, deletes, or runs or reverts a
pipeline, plus `add_comment`, `update_comment`, `delete_comment`,
`bulk_binaries` and `bulk_functions`. `search` reads the store and is read-only. A handler failure answers
an MCP tool error (`isError: true`, `{"error", "detail"}`); an unknown method,
an unknown tool and invalid params answer JSON-RPC error objects. A tool error
never ends the loop. `list_documents`, `search_knowledge` and
`retrieve_knowledge` read the store and run nothing, so they are read-only;
`ingest_document` writes it and `ingest_url` fetches a URL when remote
ingestion is enabled (else it answers the `remote-ingest-disabled` tool error)
and writes it, so both are destructive, and `delete_document` is destructive.
`get_graph` and `graph_neighbors` read the stored graph and are read-only;
`build_graph` rewrites it from the stored rows and is destructive.
`list_graph_backends` reads the backend registry and is read-only;
`sync_graph_backend` pushes the stored graph to a backend and is destructive.
`list_families` and `get_detect_scan` read the family store and a stored
detection, so they are read-only; `register_family`, `delete_family` and
`run_detect` derive a bundle, delete a family or run and store a detection, so
they are destructive. `get_related_binaries` serves a binary's stored
relationship ranking and is read-only; `run_related_binaries` ranks the other
binaries against one binary and stores the ranking, and is destructive.
`get_renames` serves the stored rename suggestions and is
read-only; `suggest_renames` asks the bridge and stores them, `apply_renames`
rewrites the stored decompilation and journals the previous text, and
`revert_renames` restores that text, so all three are destructive.
`list_data_types` reads the local type model (each type encoded with its
members' gap flags, its enum values' hex echoes, its As-C block and its
size-vs-members check) and is read-only;
`import_data_types` seeds it from the stored structs scan, `edit_data_type`
sets a type's name, kind, namespace or declared size, adds, edits, positions,
converts or removes its members (the member objects carry `pointer`, `count`,
`bits` and the `index`/`after` position, and `to_gap`/`from_gap` convert
padding) and adds, renames, revalues or removes its enum constants, and
`export_data_types` writes the rendered header to the caller's path, so all
three are destructive. `get_data_type_history` reads a type's edit history with
each version's per-field diff and is read-only; `revert_data_type_history`
restores the state one history row recorded (a deleted type's row comes back),
is journaled and is destructive. `get_signature` and `list_signatures` read the stored
signature model and are read-only; `run_signature_import` seeds it from the
stored decompilations, `edit_signature` sets the return type or convention or
edits, adds, moves, removes or deletes a parameter (its edit and add objects
take the optional `at`, `kind` and `bits`), and `export_signatures` writes the
rendered prototype header, so all three are destructive. `get_function_triage`
serves the stored per-function
summaries and scores and is read-only; `run_function_triage` summarizes and
stores them (the configured LLM, else the deterministic heuristic) and is
destructive. `get_pdf_status` reads the generated PDF's path, size and page
count and is read-only; `generate_pdf_report` renders the PDF from the stored
scans and writes it into the workspace report directory, so it is destructive.
`list_components` reads the component registry and is read-only;
`reload_components` re-imports one component's declaration or every reloadable
one and swaps the live registry entry, so it is destructive. `list_journal`
reads the journal entries and is read-only; `revert_journal_entry` replays one
action's or one entry's stored inverses and is destructive. `get_auto_run`
reads an auto run and is read-only; `run_auto`, `revert_auto_run` and
`recover_auto_run` (which closes a stale run and merges what its unfinished
tasks recorded) are destructive.  The registry
declares 138 built-in tools, 64 read-only and 74 destructive.

Deliberately not emulated: OAuth/JWT and API keys. The hosted server
authenticates each request; reportal is a loopback, single-user tool on a local
pipe, so the stdio transport is the whole trust boundary and there is no token
to check. Streamable HTTP (SSE responses, `mcp-session-id`), server-initiated
logging notifications and `tools.listChanged` are also out: one process, one
registry snapshot, `refresh_tools()` the opt-in reload.

## SPA

Vite + React + TypeScript in `web/`, built with bun into
`src/reportal/assets/dist/` (generated, gitignored) and served from there by
`ui.py`. `vite.config.ts` sets `root` to `web/`, `base: "/static/"` and
`outDir: ../src/reportal/assets/dist` with `emptyOutDir`.

- `src/App.tsx`: shell (grouped sidebar, topbar title, health line, route
  dispatch). Below 900px the shell is one column and the sidebar becomes a
  sticky top bar whose nav keeps every group label and divider in one
  horizontally scrollable strip.
- `src/components.tsx`: the shared primitives (Panel, Toolbar, Button,
  ConfirmButton, Badge, Field, EmptyState, Loading, ErrorNote, Note, CodeBlock,
  KeyValue, DataTable, SegmentMeter, Readout) over the design tokens in
  `src/styles.css`. The token layer carries the contrast contract (4.5:1 for
  the 11-12px labels and for badge ink over its soft fill, both themes),
  measured by `tools/audit_ui.py`.
- `src/design.ts`: the instrument token names. Status entities (`--st-exact`,
  `--st-reloc`, `--st-proven`, `--st-thunk`, `--st-near`, `--st-stub`,
  `--st-idle`, `--st-live`, `--st-fail`) fold a reported status onto one ink
  token via `statusEntity`; confidence (`--conf-high/-medium/-low`) and severity
  (`--sev-high/-medium/-low`) are one hue each at three intensities; a
  `data-hue` container exposes its family as `--hue-ink/-soft/-line`; the
  sequential magnitude ramp `--ramp-1 .. --ramp-5` (cold to matched) is used by
  coverage and progress meters only. `METER_SEGMENTS`, `RAMP_STEPS` and
  `FLASH_MS` are the geometry contracts.
- `src/useAsync.ts` and `src/queryClient.ts`: a view's data. `useAsync(load,
  deps, enabled, poll)` is one react-query query keyed by the hook instance and
  the caller's dependencies, returning `data`/`error`/`reload`; the fourth
  argument is the poll, a number or a function of the data that returns `false`
  once the run it follows settles. `queryClient.ts` holds the one client both
  this and the panel cache fetch through.
- `src/live.ts`: the change flash. `useChangedIds` marks the ids whose watched
  value moved, inert under `prefers-reduced-motion: reduce`. The language comes
  from `~/Desktop/tmog/DESIGN_RULES.md`.
- `src/router.ts`: the sidebar's information architecture -- the nav groups,
  their labels and the path each view lives at. Routing is react-router's: one
  route table in `src/App.tsx` is rendered by `useRoutes` and matched by
  `matchRoutes` for the topbar title and the active sidebar section, so the
  paths (`/`, `/binaries`, `/binaries/<id>`, `/binaries/<id>/functions`,
  `/functions`, `/functions/<id>`, `/diff/<id>/<candidate-id>`, `/matches`,
  `/analyses`, `/auto`, `/auto/<binary-id>`, `/collections`, `/conversations`,
  `/conversations/<id>`, `/knowledge`, `/components`, `/journal`,
  `/journal/<action>`, `/search`) are written down once. A route may carry a
  query (`#/analyses?status=failed&search=notepad`,
  `#/binaries/3/functions?sort=size&order=desc`), which the list views read with
  `useSearchParams`: the path decides the route, and the query is the filter
  state a link can be shared with and a reload keeps.
- `src/api.ts`: typed fetch wrapper, JSON in and out, `FormData` for the
  upload, `ApiError` carrying `error`/`detail`.
- `src/panelCache.ts`: panel results in react-query's cache, keyed by request
  identity, so a panel survives a view unmount and a write refreshes it in
  place (`refreshPanel`); a successful journal revert clears every panel
  (`clearPanels`), since its undo plan can touch any scoped row; `PanelBody`
  renders skeleton rows, the empty state for a `no-scan`, or the error name and
  detail with a retry.
- `src/views/`: the dashboard cockpit (system-state readouts and the aggregate
  coverage meter, one row per binary with a segmented match meter and its status
  breakdown, the live auto-run card with a progress meter and the current task,
  the per-section coverage of the focused binary, the journal tail and the
  quick-link strip) and the list views (binaries, analyses, functions, matches,
  auto, collections, conversations, components, integrations, search), the
  binary/function/conversation detail views and the function diff view. The
  matches view is the Match / Diff surface: it loads a function's binary, lists
  the recorded edges ranked by the Similarity / Confidence / Difference toggle
  with a stacked quality bar over the five bands (a per-segment hue from
  design.ts, the unlit remainder and the fixed-position readout of the meter
  primitives), and carries the Match Settings sheet (a control per setting, a
  removable chip per active setting, the run button) plus the Bulk Transfer
  dialog (per-row Names/Signature checkboxes with master toggles, a preview and
  a transfer);
  `src/panels/` the binary and function detail panels. The Components view
  lists the live registry (name, requires, provides, origin, reloadable,
  withdrawable with the reason it cannot be) and posts
  `POST /api/components/reload` from a per-row Reload and a Reload all control,
  disabling a row that is not reloadable, plus a per-row Withdraw over
  `POST /api/components/<name>/deactivate`. The Integrations view renders
  `GET /api/integrations`: one card per plugin seam with its entry-point group,
  the module declaring the built-ins and a table of the parts the registry
  holds. The binary detail page carries a Memory panel with two modes. Window
  mode reads a byte window at an address on demand (kind `va`, `rva` or
  `file`, at most `engines.MEMORY_READ_MAX` bytes) and renders it as an
  addressed hex grid with an ASCII gutter; a read is never guessed, so an
  address without backing bytes is refused. Full-file mode pages the binary
  through `GET /binaries/<id>/memory/page`, walking the engine's own section
  map: each page carries `bytes` rows (address, file offset, hex) and `gap`
  rows for every byte no section backs, so a header, a gap between sections or
  an uninitialized tail is stated rather than zero-filled. The mode offers a
  section select and a `G` go-to accepting a virtual address or a file offset,
  Previous/Next page controls, a zero byte dimmed to the muted ink without
  being hidden, and a byte-range selection copied as space-separated hex or a
  C array initializer. The Sections card marks each section's share of bytes
  the stored function table accounts for, from the stored-only
  `GET /section-coverage`.

The dashboard reads only existing endpoints: `GET /api/health` for the row
counts and the aggregate match meter, `GET /api/binaries` plus per-binary
`/functions` and `/auto`, the stored `/pe-info` and `/report` for the section
and byte coverage of the first `SECTION_CAP` binaries, and `GET /api/journal`
for the tail. While a run reports `running`, that binary's run and function list
are polled on their own (1s and 4s); the row counts poll at 2s and the journal
at 5s. A value the source does not provide (a binary with no stored report, a
section with no functions) renders as an explicit missing state rather than a
zero.

The Binaries view carries the batch upload control: a multiple file input, a
collection picker and a selected-files table with one row per file (name, a
chip tag control, a Format and an ISA select, Remove), posting `FormData` with
the repeated `file` parts and the `files` JSON options to
`POST /api/binaries` and refreshing the list; the response renders one line per
file, a duplicate as `Already stored <file> as binary #N.` rather than as a
failure, and the batch's journal action as a link. It also carries the
malware-family store: a name input, a reference-binary select and an optional
alias input post `POST /api/families`, and the registered families list in a
table with a per-row Delete behind an inline confirm, under a note that
reportal bundles no external threat-intelligence feed. The binaries table also has a selection checkbox per
row, a comment-count badge and a per-row Download action: a plain link to
`GET /api/binaries/<id>/download`, which needs no headers and so needs no fetch
wrapper, with the row's own click navigation suppressed by the table's
interactive-target guard. A Bulk actions panel below the table posts
`POST /api/binaries/bulk` for the selection (add tag, remove tag, or a delete
behind an inline confirm) and reports the applied and skipped counts; the Functions
view carries the matching Bulk actions panel, whose prefix input and
replace-existing-prefix toggle post `POST /api/functions/bulk`.

`src/keys.ts` is the SPA's keyboard layer: one registry every shortcut lives in
as a `(combo, scope, description, handler)` binding, installed once by the shell
and rendered by the cheatsheet, so the documented set cannot drift from the
live one. A combo is a chord (`mod+k`, where `mod` is Command on a Mac and
Control elsewhere) or a space-separated sequence whose prefix stays armed for
`PREFIX_TIMEOUT_MS` (`g d`). A `view`-scoped binding outranks a `global` one
with the same combo, and registering a combo twice in one scope throws, so a
conflict fails at registration rather than at dispatch. Two rules are
unconditional: a binding never fires while the focus owns text (an input, a
textarea, a select or a contenteditable, the rule `isTypingTarget` states), and
none fires while a modal dialog owns the keyboard. `focusViewFilter` and
`moveTableRow` are the two shared handlers: the first focuses the view's filter
box (the convention is the first `input[type="search"]` in the content area, and
a view without one leaves the key inert), the second walks the tabbable rows of
the view's first data table.

`src/App.tsx` registers the shell's own bindings there: `mod+k` for the global
search modal, `?` for the cheatsheet, one `g <key>` jump per sidebar view, and
the `view`-scoped `j`, `k` and `/`. `src/views/CheatsheetDialog.tsx` renders the
live registry grouped by scope with each combo spelled for the platform
(`displayCombo`), takes the focus on open, traps Tab, closes on Escape and
returns the focus it took. Nothing is registered for a control that does not
exist: there is no sidebar collapse to bind, no focused-row model beyond a
table's tabbable rows, and no history control in the UI, so the layer carries no
binding for them.

`src/App.tsx` mounts the global search modal (`src/views/SearchModal.tsx`) on
that `⌘K`/`Ctrl+K` binding. The modal keeps the query input
focused, debounces the fetch (`SEARCH_DEBOUNCE_MS`), renders the four query-type
toggles from `SEARCH_KINDS`, and moves a roving highlight through the combined
result list with the arrow keys (Enter, or a click, opens the highlighted hit;
Escape closes and returns focus to where it was, and Tab cycles the query type
rather than leaving the dialog, with a `focusin` listener as the focus trap).
`src/views/SearchResults.tsx` is the shared hit model the modal and the Search
view both build from: `searchHits` flattens the response into ordered
`SearchHit` values, `hitHref`/`hitTitle` are the one place a hit
becomes a destination and a name, and `SearchHitRow` renders one
keyboard-navigable row. The Search view keeps its three-group tables (its
established, asserted contract) rather than the modal's flat list, so the two
surfaces share the model and the helpers rather than one component; reportal has
no per-collection or per-tag detail route, so those hits lead to the Collections
and Binaries lists and the binary and function hits to their detail pages.

The Analyses view (`src/views/AnalysesView.tsx`, `#/analyses`) is the analyses
list: each row carries the analysis id, the binary (linked to its detail page),
its format and arch badges, its size, the engine label, the created time, a
status badge drawn from the design language's status hues and the owning
binary's tags. A status select, an order select and a search box write the hash
query, the table states `N of M analyses`, and a filter that matched nothing
renders the count it searched rather than an empty table. Each row opens an
on-demand log drawer over `GET /api/analyses/<id>/logs` (newest first, severity
badges on the severity scale, the loaded count against the log's true total and
a Load more control while more remain) and carries a Delete behind the inline
confirm, which calls `DELETE /api/analyses/<id>` and refreshes the list. The
view has no owner column: reportal is single-user and loopback, the panel says
so, and it links to the Journal view, which is where who did what is recorded.

The Functions view (`src/views/FunctionsView.tsx`) sends its filters and sort to
the server instead of filtering in the browser: a name-source select, a
capability select, a match-state select, a min/max size pair and a
string-reference input post `GET /api/binaries/<id>/functions`, the table
states the filtered-of-total counts, the empty state names the filter that
matched nothing, and the VA, Name, Size and Status headers sort the column
(clicking the active column flips the direction). All of it lives in the hash
query, so a filtered, sorted list is shareable and survives a reload. Panels that mutate
never auto-run heavy engine work on render: stored scans load automatically,
and the run buttons POST explicitly. The binary detail view opens with the
portal's binary-detail surface: the Binary details card (auto-loads the stored
PE metadata and posts from its Run PE details control, rendering the identity
table with the PE type, base address and image base, entry point, checksum,
resource count, import hash and export hash, plus the debug and Rich-header
summary), the Hashes card (the digest set as copyable rows with
Compute/Recompute), the Security mitigations card (the `N/11` score and the
11-item checklist with each item's state and raw flag), the Imports, Exports,
Sections and Strings cards (each with a client-side filter and its
filtered-of-total count; the Sections card carries an entropy meter and the full
`IMAGE_SCN_*` list), the Code signature card, the Packer detection card
(auto-loads the stored detection and posts from its Run detector control,
rendering the packer verdict, a peak-section-entropy meter with the packed range
marked, the section count, the toolchain compiler string and the match table
with each match's category, name, confidence and signal list), and the Unpacked
files card stating that reportal never unpacks and the engine's only unpack path
is `rebrew unpack-lzexe`. The binary and function detail views carry
the shared Comments panel (`panels/CommentsPanel.tsx`): it auto-loads the
scope's comments, adds one with the browser's remembered author, and shows Edit
and Delete only on a comment that author wrote. The binary detail view carries the
Detect panel, which loads the stored detection and posts from its Run detect
control, rendering each match's family name with its aliases, confidence and
signal list plus the payload's scope and threshold notes, the
Auto-unstrip panel, which loads the stored proposals and posts a
min-confidence value from its Run control, rendering each proposal with a
per-row Apply and an Apply all listed control, and the Lineage panel, which
auto-loads the stored comparisons, picks another binary from its compare-with
select and posts the pair from its Run comparison control, rendering the status counts
with `matched_percent` and one table per changed/removed/added group, each
function linked to its detail view and each group capped at
`MAX_LINEAGE_ROWS_SHOWN` with its true count stated, the Related binaries
panel, which auto-loads the stored ranking and posts from its Run scan
control, rendering the candidate count plus each candidate's classification
badge, confidence, name linked to its detail view, similarity and signal list,
the Composition analysis panel, which auto-loads the stored analysis and posts
from its Run analysis control, rendering the `Matched: N / M (P%)` meter, the
name-source and match-quality meters, the per-binary rollup (name linked to that
binary's detail view, sha256, count and percent) and the per-function rows (name
linked to its detail view, VA, size, band badge, similarity and the matched
binary, or an explicit `No match` badge), capped at
`MAX_COMPOSITION_ROWS_SHOWN` with the true total stated,
and the Security panel, which loads the stored scan and posts a min-severity value from its Run
control,
rendering each finding as a table row with the by-severity counts. The
Capabilities panel loads the stored scan and posts from its Run capability scan
control, rendering each category's confidence, evidence count and description
with an expandable evidence list. The Behavior panel carries a domain select
(execution, networking, filesystem), auto-loads the stored scan for the
selected domain through its stored-only GET, shows the nothing-scanned hint
with the run control on a `no-scan`, and posts from its Run behavior scan
control, rendering each finding's confidence, kind, name and detail with the
by-confidence counts. The Hardening panel carries a domain select
(anti-analysis, obfuscation), auto-loads the stored scan for the selected
domain through its stored-only GET, shows the nothing-scanned hint with the run
control on a `no-scan`, and posts from its Run hardening scan control,
rendering each finding's confidence, category, name and detail with the
by-confidence counts, the packer likelihood for obfuscation and any recorded
notes. The Protocols panel loads the stored inference and posts from its Run
protocol scan control, rendering each protocol's confidence, well-known ports,
an expandable evidence list and description with the by-confidence counts, and
a nothing-inferred message when nothing matched. The Function triage panel
loads the stored aggregate through its stored-only GET, shows the
nothing-stored hint with a limit input and a Run function triage control on a
`no-scan`, and posts the limit, rendering the model/method line, the scored
rows (score, name, VA, size, status, method badge, summary and capabilities),
the skipped list with each reason and the notes. The Threat report panel loads the stored
report and posts from its Run threat report control with a narrative checkbox,
rendering the summary when one is stored, each IOC category in a collapsible
group with its count, the techniques table with confidence and expandable
evidence, and the report's notes. The Remediation panel loads the stored payload
and posts from its Generate control, rendering the rule name, string count and
validation status plus a collapsible section per artifact (YARA, Snort, STIX),
each with a copy control or its own empty state, and the Snort and YARA notes. The Report panel carries a Download PDF link to
`GET /api/binaries/<id>/report/pdf` and a Generate PDF control that posts the
same route, reporting the written path, page count and byte size and linking
the served file. The Data types panel loads the local type model
(`GET /api/binaries/<id>/data-types`, filtered through the same route's `kind`,
`namespace` and `search` query parameters), posts a struct-recovery run and an
Import from scan, renders each type with its kind, namespace, size and a table
chosen by the kind (a struct's or union's member offsets, an enum's values with
their hex, or an alias/pointer/array/function target) plus its padded As-C
block, and edits inline: rename the type, set its kind, namespace and declared
size together, rename/retype a member and set its bit width, add a member
(appended or inserted after a named one from that row's action), convert a
member to explicit padding and back, or delete the type, each refreshing the
model. The card warns when the declared size and the members' extent disagree,
naming both numbers without changing either. The enum table edits in place: a
constant's name and value are inputs with a live hex echo, and an add with a
blank value increments from the last constant and says so. Its
namespace tree carries its own search and a Collapse control, a References
control loads `GET /api/data-types/<id>/references` into the Referenced by and
Used by functions tables, and a History control loads
`GET /api/data-types/<id>/history` into a version list: each version names its
source, actor and time, states the per-field diff between the two recorded
states (or that it created or deleted the type), and carries a Revert behind
the shared inline confirm, which posts
`POST /api/data-types/<id>/history/<history_id>/revert` and refreshes both the
history and the model. Its Export control takes a path and, when the API
answers 409 `export-exists`, offers a Force overwrite confirmation, and it
carries an Import signatures button and an Export prototypes control with the
same force handling. The function detail Signature panel auto-loads the stored
signature through its own GET (a `signature-not-found` answer shows the
nothing-stored hint), renders the returned prototype, edits the return type and
calling convention with a Save, and lists the parameters in a table with
inline type/name edit, Save, Remove and an add-parameter row. The function
detail code panel carries the Disassembly / Control flow toggle: Disassembly
is the engine's nasm or hex listing (the panel `views/FunctionDetail.tsx` has
always rendered) with its format select, and Control flow is
`panels/CfgPanel.tsx` rendering `GET /api/functions/<id>/cfg` as an
address-ordered block list, each block carrying its index, address, byte size,
instruction count and first/last instruction text, and each block's outgoing
edges as jump controls that scroll to and focus the target block (a `#`
fragment link would fight the hash router, so the jump stays in the panel). A
back edge carries the warn ink on the row and a labelled `back edge` badge;
`truncated` renders as a warning note naming the true `block_total` beside the
engine's `block_cap`, the engine's `note` renders as its own note, and an empty
block list renders its reason instead of an empty diagram. The panel adds no
charting or graph library. The
function detail AI section groups the
Summary, AI comments, Type suggestions and Renames panels; each auto-loads its
stored-only GET, shows a nothing-stored hint when the artifact is absent, and
posts from its Generate (Suggest) control, rendering a 503 `llm-unavailable` in
place. The Renames panel lists each stored suggestion with a checkbox, its
reason and confidence, Apply selected / Apply all (with a rename-function
toggle for a function-kind suggestion) and a Revert; an apply or a revert
refreshes the decompilation panel and the function header.
The function detail view also carries the AI decompilation panel: it auto-loads
the stored pipeline run, renders the step timeline with each step's status,
duration and skip reason, the predicted name with an Apply rename action, the
summary, the inline comments interleaved into the decompiled source, and the
decompilation itself, and its toolbar runs the pipeline again or reverts the
run (a 404 `no-run` shows the nothing-stored hint with the run control).
The Auto-mode view (`views/AutoView.tsx`, `#/auto` and `#/auto/<binary-id>`)
picks a binary, starts a run from its form (worker, dry-run/execute,
concurrency), renders the run's task tree with each task's status, worker and
attempts plus the coverage delta, refreshes itself while the run is still
working, and reverts the run from its toolbar (a 404 `no-run` shows the
nothing-stored hint with the start form).
The function and binary detail views also carry a Conversations panel whose
Chat about this action posts `POST /api/conversations` for that scope and opens
the thread. The Conversations view lists each thread's scope and message count
and creates one from a scope kind and id; the thread route renders the stored
messages, sends from its composer (a 503 `llm-unavailable` surfaces in place)
and deletes the thread; a reply's retrieved documents render as a `Sources`
disclosure under the assistant turn. The function detail Matches panel carries a Diff link
per candidate; the diff view (`views/DiffView.tsx`,
`#/diff/<function-id>/<candidate-id>`) loads
`GET /api/functions/<id>/diff/<candidate_id>` and renders the two listings side
by side with the changed lines marked, a kind select (`decomp`/`disasm`), a
normalize checkbox, the similarity and the summary counts.
The Knowledge view (`views/KnowledgeView.tsx`, `#/knowledge`) picks a binary
from a scope select, ingests a document (a file input posting `FormData` to
`POST /api/binaries/<id>/documents`, or a pasted note posting JSON to
`POST /api/documents`), lists the scope's documents with each row's title,
source, size, chunk count and a Delete action, and searches the scope through
`GET /api/knowledge/search`, rendering each ranked hit with its document title,
score and ranking method.
The build step is the accepted tradeoff
for a UI-heavy portal; packaging the built UI is a follow-up (package-data
still ships only `assets/*`).

## Matching

`matching.match_binary` compares each function of a binary against every
stored function, keeps candidates at or above `min_similarity`, caps them at
`top`, and records a softmax confidence over the kept list. Disassembly is
injected (default: cache-backed engine adapter) and the scorer is injected
(default: `similarity.similarity`), which is what makes the tests hermetic.

Scaling: scoring stays pairwise, so comparisons grow with the square of the
corpus; the per-listing cache removes repeated preprocessing. LSH candidate
shortlisting is the next lever if corpora grow past a few thousand functions.

## Diff view

`diffing.py` is the pure alignment core: `align` runs `difflib.SequenceMatcher`
line by line and returns ordered entries with 1-based line numbers on each side
(a `replace` opcode becomes a delete run followed by an insert run), `summary`
counts the operations plus the replacement groups, and `strip_addresses`
removes a listing's address column, encoded bytes and trailing comment so the
alignment is not dominated by them. It imports only the standard library.

`diffview.function_diff` is the shared resolver behind the API route, the
`reportal diff` command and the `diff_functions` MCP tool: it resolves both
functions, assembles a `disasm` side from `disasm_cache` or `rebrew asm` and a
`decomp` side from the stored row (else a live, unstored `rebrew decompile`),
normalizes when asked, aligns, and reports the recorded similarity or a live
score (null without the optional extra). It raises `DiffError` with the API's
status and error name; the API route additionally requires an explicit
candidate to be a recorded match, and the omitted-candidate form falls back to
the function's best recorded match.

## Lineage

`lineage.py` is the pairwise version comparison behind the Lineage panel, the
`reportal lineage` command, the `/api/binaries/<id>/lineage` routes and the
`get_lineage`/`run_lineage` MCP tools. `compare_functions` pairs two function
lists in two passes and classifies every function of both sides.

Pass 1 pairs exact, case-sensitive names, preferring the candidate whose size
is closest, then the lowest VA: the same size is `unchanged`, a different size
`changed`. Pass 2 takes the left functions whose names carry no identity
(`sub_*`, `fcn_*`, `FUNC_*`, empty), gathers the unclaimed right functions
inside the same size bucket (`SIZE_TOLERANCE_PERCENT`, 10% of the larger
size), keeps the `MAX_CANDIDATES` (20) nearest sizes and scores them through
the injected scorer; the best candidate at or above `UNCHANGED_THRESHOLD` (95)
is `unchanged`, at or above `CHANGED_THRESHOLD` (70) `changed`, and below that
nothing. Ties fall to the closer size, then the lower VA, so the outcome does
not depend on iteration order. A named function whose name does not appear on
the other side is never scored structurally: it becomes one removal plus one
addition, so a rename is reported rather than guessed at. Everything unmatched
on the left is `removed` and everything unmatched on the right `added`. Rows
are sorted status-first
(unchanged, changed, removed, added) then by left VA and capped at `MAX_ROWS`
(500); the summary counts and `matched_percent` (the paired share of both
sides' functions) always cover every function, cap or not.

`compare_binaries` reads both function lists from the store and builds the
scorer only when a scorer or disassembler is injected, or when refinement is
requested and the optional `similarity` extra and a usable rebrew engine are both
available; the disassembler is `matching.cached_disassembler`, so each
function is disassembled once through its own binary's rebrew project context
and reused from `disasm_cache`. Otherwise the comparison is name/size only and
the payload records `refined: false`, so a missing engine degrades the result
instead of failing the request. A binary compared with itself raises
`SameBinaryError` and an unknown id a `KeyError`; the API maps both.

A finished comparison is stored as the `lineage` scan on the left binary,
under a `comparisons` object keyed by the right binary id, so one binary keeps
one stored comparison per pair and a re-run refreshes that pair.
`GET /api/binaries/<id>/lineage?other_binary_id=N` serves one entry and the
same route without the query lists them all.

## Related binaries

`related.py` is the relationship ranking behind the Related binaries panel, the
`reportal related` command, the `/api/binaries/<id>/related` routes and the
`get_related_binaries`/`run_related_binaries` MCP tools. It reuses the identity
signals `families.py` already derives (`families.import_names` and
`families.capability_names`) rather than recomputing them.

`relationship(target, other)` scores two bundles and names the strongest
matched signal as the classification: an identical `sha256` is `identical`
(`CONFIDENCE_HIGH`), an identical `imphash` `same-imports` (`high`), an
identical Rich-header hash `same-toolchain` (`medium`), an import-name Jaccard
ratio at or above `IMPORT_OVERLAP_THRESHOLD` (0.8) `similar-lifecycle`
(`medium`), a capability-set Jaccard ratio at or above
`CAPABILITY_OVERLAP_THRESHOLD` (0.8) `similar-capabilities` (`low`) and, only
when nothing stronger matched, the same format and architecture with a size
within `SIZE_TOLERANCE_PERCENT` (10%) of the larger file `similar-size` (`low`).
Every matched signal is returned with its confidence and detail, so the output
explains a ranking rather than a bare score; a pair that matches nothing is
`unrelated`, carries `CONFIDENCE_NONE` and no signals, and is dropped unless
the caller asks for it.

`find_related` derives the target bundle from the stored fingerprint when one
exists, else the engine, and the same rule applies to each candidate; imports
and strings come from the engine when it is available, and a stored
`capabilities` scan stands in when it is not. A missing engine is not an error:
the scan degrades to the stored data and records `NO_ENGINE_NOTE`. Every other
binary with a file on disk is scored, the target is never its own candidate,
and a binary whose row has no file is skipped with a note. Rows sort by
classification rank, then similarity, then name, and cap at `limit`
(`DEFAULT_LIMIT` 20, up to `MAX_LIMIT` 200); `candidates_considered` counts
every binary considered before the cap and `count` is the number of rows
returned. The payload is stored as the `related` scan, replacing the previous
one, and `GET /api/binaries/<id>/related` serves it stored-only.

## Composition analysis

`composition.py` is the portal's per-binary composition block, behind the
Composition analysis panel, the `reportal composition` command, the
`/api/binaries/<id>/composition` routes and the
`get_composition`/`run_composition` MCP tools. It reads the store only:
`store.list_functions` for the binary's functions and
`matching.binary_match_rows` for the stored `matches` edges, with the
candidate's owning binary resolved through `store.get_function` and
`store.get_binary`. It never runs matching and never calls the engine, so the
payload is a reading of what `reportal match` already stored.

The headline is `matched_functions` over `total_functions` with
`matched_percent` (one decimal, `METRIC_DECIMALS`); `refined` is false when the
store holds no match edge for the binary and the notes then name the command
that fills the table. The name-source breakdown maps reportal's stored
`name_source` vocabulary onto the portal's five labels through one explicit
`NAME_SOURCE_MAP` (`import` and `rebrew` are `System`, `unstrip` is
`Auto Unstrip`, `renames` and any `ai*` source are `AI Agent`), with a
placeholder or empty name falling to `No Debug Info` and any other source to
`User`. The quality distribution uses three named cutoffs
(`STRONG_MATCH_MIN_SIMILARITY` 95.0, `MATCH_MIN_SIMILARITY` 80.0,
`PARTIAL_MATCH_MIN_SIMILARITY` 70.0) aligned with the floors the rest of
reportal already uses; `No Match` is the absence of a stored match row, never a
similarity of zero. A self-match (a candidate that belongs to this same binary,
which reportal's corpus can produce) is not a composition: it is excluded from
the rollup and the per-function best match, and its function count is reported
in the notes.

The composition rollup is one row per other binary with `count` descending then
binary id, uncapped because it is bounded by the binary count; the per-function
list is capped at `MAX_ROWS` (500) while every summary count stays exact. Both
`POST` and the CLI/MCP run store the payload as the `composition` scan through
the journal, and `GET /api/binaries/<id>/composition` serves it stored-only
(404 `no-scan`).

## Detect

`families.py` is local malware-family matching, behind the Detect panel, the
`families`/`family-add`/`family-rm`/`detect` commands, the `/api/families` and
`/api/binaries/<id>/detect` routes and the `list_families`, `get_detect_scan`,
`register_family`, `delete_family` and `run_detect` MCP tools. reportal ships
no external threat-intelligence feed and cannot: a malicious-family feed is a
hosted, continuously updated service, so Detect matches against a store the
analyst curates instead.

Registration derives one signature bundle from the reference binary's engine
payload: the fingerprint's `sha256`, `imphash` and `rich_header_hash`, a
locally computed `import_hash` (the sha256 of the sorted, lowercased
`dll:name` entries), the canonical import-name set and the capability set from
`capabilities.classify`. The bundle is stored with the family, so a detection
never re-runs the engine for the reference. A family name is unique
case-insensitively (`COLLATE NOCASE`) and the row cascades with its reference
binary.

`detect_binary` derives the target's bundle the same way and scores it against
every family. Each matched signal carries its own confidence: an exact
`sha256` is `high` `exact-binary`, an exact `imphash` `high`
`import-fingerprint`, an exact `rich_header_hash` `medium`
`toolchain-fingerprint`, an exact import hash `high` `import-set`, an
import-name Jaccard ratio at or above `IMPORT_OVERLAP_THRESHOLD` (0.8)
`medium` `import-overlap`, and a capability-set Jaccard ratio at or above
`CAPABILITY_OVERLAP_THRESHOLD` (0.8) `low` `capability-overlap`. A family's
confidence is its strongest signal and every matched signal is returned with
its detail (the overlap signals carry the ratio), so the output explains why a
family was proposed; matches sort by confidence, then similarity, then name.
The payload states the reportal scope and both thresholds in its notes, and a
binary that matches nothing is a valid result. The detection is stored as the
`detect` scan, so `GET /api/binaries/<id>/detect` answers from the store
without an engine.

Registration and detection need a resolvable binary (a `KeyError` for an
unknown id, a `FileNotFoundError` for a row with no file) and an engine
(`EngineUnavailable` without one); a blank name raises `InvalidFamilyNameError`
and a case-insensitive repeat `DuplicateFamilyError`. The API maps an unknown
id to 404, a row with no file to 400 and a missing engine to 503, and either
name failure to 400.

## Knowledge

`knowledge.py` is the first half of the knowledge/RAG feature: it stores text
documents, ranks their chunks and renders a bounded citation block for a
prompt. The deterministic graph over those documents is the second half
([Knowledge graph](#knowledge-graph)); retrieval feeds the conversations and
the `retrieve-knowledge` pipeline stage, described below.

| Stage | Implementation |
|-------|----------------|
| Scopes | `SCOPE_KINDS` is `binary` and `project`. A binary scope names a stored binary id, which the API validates; a project scope is a workspace-level bucket no table holds, the same loose reference the conversation scopes use |
| Extraction | `extract_text` decodes UTF-8 with invalid sequences replaced, rejects content whose NUL and control share passes `BINARY_CONTROL_RATIO`, reduces HTML to its visible text through `html.parser`, and rejects content with nothing left after trimming. `is_supported_name` gates a file ingest on `TEXT_EXTENSIONS` |
| Chunking | `chunk_text` takes `CHUNK_CHARS` windows overlapping by `CHUNK_OVERLAP`, cut at a paragraph, sentence or space break found within `BOUNDARY_SEARCH_CHARS` of the window end. It is deterministic, never emits an empty chunk and stops at `MAX_CHUNKS_PER_DOCUMENT` |
| Dedupe and caps | `ingest_document` dedupes on `(scope_kind, scope_id, sha256)`: the same bytes twice in one scope return the stored row with `duplicate: true`. A document past `MAX_DOCUMENT_BYTES`, a scope holding `MAX_DOCUMENTS_PER_SCOPE` documents and data that extracts to nothing raise `KnowledgeError`, whose `code` is the API's error string |
| Ranking | `search_knowledge` embeds the query when an endpoint is configured and some chunk in scope carries a vector, then ranks by cosine similarity; otherwise, and whenever the embedding call fails, it ranks the same chunks with a local TF-IDF cosine (smoothed IDF over the chunk corpus, tokens from word characters, a small stopword set). Every hit reports the `method` that scored it |
| Retrieval | `retrieve` is `search_knowledge` with the named `RETRIEVAL_LIMIT` and a blank-query guard, and `as_context` renders the hits as `[n] <title> (<source>): <text>` lines, truncating each snippet to `RETRIEVAL_SNIPPET_CHARS` and dropping a hit whose line would push the block past `RETRIEVAL_CONTEXT_CHARS`. Both are read-only |

`as_context` is the seam every prompt builder uses. `conversations.py` appends
the block of a conversation scope's binary to the stored context, and
`pipeline.py`'s `retrieve-knowledge` component provides the same shape as its
`knowledge` value, which `name-variables` and `summarize` pass as the
`context` argument of the `llm` prompt builders. Because retrieved text is
untrusted, it is labelled as data in the user message and never treated as an
instruction; the conversations system prompt says the same.

`llm.py` carries the optional embeddings call: `LlmClient.embeddings` posts
`{"model", "input"}` to `<endpoint>/embeddings` in `EMBEDDINGS_BATCH_SIZE`
batches and raises `LlmError` for a response that does not carry one numeric
vector per input. An unconfigured endpoint answers None, which is why the
default install and the whole test suite run without one. An ingest swallows
an embeddings `LlmError` on purpose: the stored text is what makes a document
searchable, so a broken endpoint degrades to the TF-IDF path instead of failing
the ingest.

Retrieval is exposed read-only through `GET /api/binaries/<id>/knowledge?q=`,
`GET /api/functions/<id>/knowledge?q=` (the query defaults to the function
name), the `reportal context <function-id> [--query TEXT]` command and the
`retrieve_knowledge` MCP tool.

### Remote ingestion

`remote_ingest.py` is the guarded URL source. It is off by default:
`remote_enabled()` is true only when `REPORTAL_ALLOW_REMOTE_INGEST` holds a
truthy value or the workspace `reportal.toml` carries
`[knowledge] allow_remote = true`. While it is off `ingest_url` raises the
fixed `remote-ingest-disabled` error, every surface maps it to 403, and no
request is made. `GET /api/knowledge/config` reports the state so the SPA can
hide the URL field when the server would refuse it.

The guard is `validate_target`: only `http`/`https`, a host is required,
credentials in the URL are rejected, and every address the host resolves to
(via `socket.getaddrinfo`) is parsed with `ipaddress` and must be public; a
loopback, private, link-local, multicast, unspecified, reserved or IPv4-mapped
IPv6 address rejects the whole target rather than letting a multi-answer DNS
record pick a reachable private one. The port must be in the named
`ALLOWED_PORTS` allowlist (80/443) or the scheme default. `fetch` opens an
`httpx.Client` with `follow_redirects=False` and `trust_env=False`, so
environment proxies cannot reroute a request, and follows redirects itself:
each hop's target is re-validated before it is requested, so a public URL that
redirects to `http://10.0.0.1/` is refused rather than followed. The body is
streamed and aborted past `MAX_BYTES` (a `TooLargeError`), only a content type
on the named allowlist (or a missing one) is accepted, and no auth header and
no cookie is sent. `ingest_url` decodes through `knowledge.extract_text` and
stores through `knowledge.ingest_document` with `source` set to the final URL,
so a re-fetch of the same bytes dedupes by sha256; a fetch, size or
content-type failure raises before the store is touched, so no partial document
is written.

`validate_target(..., allow_loopback=True)` is a test-only seam that admits a
loopback target on its ephemeral port, which is what lets the test suite and
the `.scratch/` end-to-end run exercise a throwaway `http.server`. It is unsafe
for production, no production caller passes it, and it is not reachable from a
request field.

One race is not closed: a DNS answer can change between `validate_target` and
the connection (TOCTOU), so a host that resolves publicly during validation and
to a private address when `httpx` connects is not caught. Pinning the validated
address, or fetching from a network namespace with no private routes, would
close it; this module does neither, which is one reason the feature defaults
off.

## Knowledge graph

`graph.py` is the second half of the knowledge feature: a deterministic graph
derived from rows the store already holds. Nothing is authored and nothing is
fetched; a rebuild reads the binary row, its functions, its recorded matches,
its binary-scoped documents, its stored struct/capability/unstrip/triage scans
and its tags, and writes one node and one edge row per fact. The same rows
always produce the same graph, so a rebuild is idempotent, and the previous
graph is replaced only after the new one is assembled.

| Node kind | Source |
|-----------|--------|
| `binary` | the `binaries` row; label is the name, metadata the format, arch, size, sha256 and the `truncated` flag |
| `function` | the binary's `functions` by VA; label is the name, else `sub_<va>`, metadata its va, size, status and name_source |
| `document` | the `documents` scoped to the binary; label is the title, metadata its source, mime, size and chunk count |
| `struct` | the stored `structs` scan's entries; key and label are the recovered name |
| `tag` | the binary's tags (`binary_tags` joined to `tags`) |
| `capability` | the stored `capabilities` scan's entries; metadata its confidence, evidence count and description |
| `library` | the stored `unstrip` scan's proposals and the triage dossier's `library` and `flirt` sections, merged under the module the engine reported, else the kind or name |

| Relation | Meaning | Weight |
|----------|---------|--------|
| `binary -contains-> function` | the binary holds the function | 1.0 |
| `binary -documented-by-> document` | the document is scoped to the binary | 1.0 |
| `binary -has-capability-> capability` | the stored scan classified the binary with it | 1.0 |
| `binary -has-tag-> tag` | the tag is applied to the binary | 1.0 |
| `binary -recovered-> struct` | the stored struct recovery produced it | 1.0 |
| `binary -identifies-> library` | the unstrip or triage evidence names the library | 1.0 |
| `function -matched-with-> function` | a recorded match between two of the binary's functions | the recorded similarity |
| `document -mentions-> function` | the document's text names the function | 1.0 |
| `document -mentions-> struct` | the document's text names the struct | 1.0 |

Call edges (`function -calls-> function`) are not built: nothing reportal
stores carries them, since the call graph lives in the rebrew project and is
read per function through `rebrew xrefs`, so the relation is omitted rather
than approximated. A match whose candidate belongs to another binary is skipped
for the same reason: that candidate is not a node of this graph.

`entity_mentions(text, names=...)` is the pure extractor behind every `mentions`
edge. It matches any accepted name at an identifier boundary, dropping a name
shorter than `MENTION_MIN_NAME_LENGTH` so a three-character name cannot match
inside prose, and canonicalizes every word-bounded `0x` hex run so `0x00401000`
and `0x401000` are one token. The builder resolves a token against the function
and struct names first, then against their VAs, and a name mention and a VA
mention of the same entity collapse into one edge, because
`(source, rel, target)` is unique.

Node ids are `b<binary_id>:<kind>:<key>`, unique across binaries, and edge ids
are `<source>|<rel>|<target>`, so a rebuild rewrites identical rows.
`MAX_GRAPH_NODES` and `MAX_GRAPH_EDGES` bound one graph: a build stops at the
cap, records `truncated: true` in the binary node's metadata (which the payload
reports), and never writes an edge whose endpoint node was not kept.

`graph_payload(conn, binary_id=..., kind=None, include_documents=False)` serves
a view. Document nodes and their mention edges are left out by default and a
degree counts a node's edges in the returned set; the CLI's `graph` command
passes `include_documents=True`, since it inspects the whole stored graph.
`neighbors(conn, node_id=...)` returns one node with its incident edges grouped
by relation, each neighbor carrying its id, kind, key, label and weight.
`store.delete_graph` clears one
binary's rows, and `build_graph` calls it only after assembling the new graph,
so a failed rebuild leaves the stored graph intact.

### Graph backends

The graph itself is local and derived; `graph_backends.py` is the seam that
lets it leave the process.  A `GraphBackend` value carries a `name`, an
`available()` check, a `describe()` report, a `sync(conn, *, binary_id, payload)`
call and an optional `query(conn, *, query, limit)`.  `sync_graph` resolves the
selected backend (`REPORTAL_GRAPH_BACKEND` or `[knowledge] graph_backend`,
default `sqlite`), refuses a binary with no stored graph, builds the payload
with `graph.graph_payload(..., include_documents=True)` and hands it to the
backend.

| Backend | Availability | Sync | Query |
|---------|--------------|------|-------|
| `sqlite` | always (it is the store of record) | a no-op that reports the stored node and edge counts | exact node id, else a label/key/id substring search across every binary (`store.search_graph_nodes`, `DEFAULT_QUERY_LIMIT` capped at `MAX_QUERY_LIMIT`) |
| `cognee` | `importlib.util.find_spec("cognee")`; otherwise unavailable with the `uv sync --extra cognee` hint | `translate_graph` maps each node to a record carrying its id, kind, key and label and each relation to an edge record, `cognee_records` serializes each record as a JSON document (the package's `add` rejects a bare dict), then `add` ingests them into the named dataset and `cognify` builds the graph | none |

`translate_graph` and `cognee_records` are pure, so the translation is covered
by tests without the package.  Against cognee 1.5.4, `add` ingests the JSON
documents into the named dataset and `cognify` builds the graph, which needs a
configured model: with none, the backend raises `BackendUnavailableError` with
a model-required reason, which the route answers as 503 `backend-unavailable`.
A live model run and a hosted Cognee service are not exercised.

The registry is the same entry-point seam `components.py`, `effects.py`,
`auto_workers.py` and `mcp_tools.py` use: built-ins come from
`builtin_graph_backends()`, a third party declares a `reportal.graph_backends`
entry point whose value is `module:attr` naming a `GraphBackend` or a
zero-argument factory returning one, a broken registration is skipped with a
warning, and a duplicate name is a `RegistryError`.  A registered backend that
is not installed raises `BackendUnavailableError`, which the API maps to 503
`backend-unavailable` with the backend's install hint, the CLI reports as
`backend-unavailable`, and the MCP tool returns as a tool error.

## Data types

`data_types.py` turns the stored `structs` scan into an editable model and
renders it back as C. It owns parsing, validation, offset computation,
rendering, export, the filters, the namespace tree and the reverse indices;
`store.py` owns the `data_types` table DDL and the row primitives
(`add_data_type`, `list_data_types`, `get_data_type`,
`find_data_type_by_name`, `update_data_type`, `delete_data_type`).  A row
carries the declaration `kind` (`struct`, `union`, `enum`, `typedef`,
`pointer`, `array`, `function`), an optional `namespace`, the members JSON, an
enum's named values JSON, the kind's `target` (a typedef target, a pointee, an
array or function element/return type) and an array's `element_count`.  A
bitfield is a member property (`bits`), not a row kind: an enum with named
values is not a struct with offsets, while a bit width belongs to one member of
the struct that holds it.

`parse_definition` accepts the tagged shapes (`typedef struct|union|enum <tag>
{ ... } <name>;`), a function type (`typedef <ret> (*<name>)(<params>);`) and a
plain typedef (an alias, a pointer or an array), and returns `{"kind", "name",
"members", "values", "target", "element_count", "size"}`.  It splits each
member's declaration on tokens, so a multi-word type (`unsigned int`) is never
confused with the member name, takes the type off a trailing array dimension,
and reads a `: width` suffix as a bitfield's width.  A member carries `name`,
`type`, `pointer`, `count`, `bits`, `offset`, `size` and `note`;
`PRIMITIVE_SIZES` maps the primitives to their widths, a pointer is
`POINTER_SIZE` (4) whatever its base, an array multiplies its element size by
the count, and an enum is `ENUM_SIZE` (4).  `normalize_members` lays a struct's
members end to end and puts every union member at offset 0 with the widest
member as the union's size; `recompute` is the one size rule per kind, shared
by an edit, an import and a caller building a row.  An unknown type is size 0
with a note naming it, so a spelling the table does not know loses no member; a
definition that matches no shape, a member line that does not parse, and a
duplicate member name each raise `DefinitionError`, which the import records as
a skip with its reason.  A row written before the `kind` column existed came
from the structs scan, so the migration defaults it to `struct` and invents no
other kind.

`import_types(conn, binary_id=...)` reads the binary's newest analysis and its
stored `structs` scan (an absent one raises `NoScanError`, the API's 404
`no-scan`; no engine runs, so the `engine` argument is never called) and
upserts each parsed type on `(binary_id, name)`, counting created, updated and
skipped. The edits (`update_type`, `update_member`, `add_member`,
`remove_member`, `convert_to_gap`, `convert_from_gap`, `add_value`,
`update_value`, `remove_value`, `delete_type`) validate the identifier, reject a
duplicate member, recompute every offset and the total size through
`normalize_members`/`recompute` and stamp `source = manual`. Removing the last
member is refused (`EmptyStructError`), since C89 has no empty declaration, and
a member edit on a kind whose data is not a member list (`enum`, `typedef`,
`pointer`, `array`) is refused (`InvalidMemberError`).

`update_type` is the one type-level write: it applies the `name`, `kind`,
`namespace` and `size` the caller names in one row and one history entry, so a
kind switch and a namespace land together and diff together. `kind` is
validated against `KINDS` (`InvalidKindError`, whose message lists the known
kinds in `KNOWN_KINDS` order), a rename still rejects a name clash, and `size`
is the *declared* size: a member write recomputes it, an explicit size stores it
as given. A kind switch recomputes the shape the new kind implies, so switching
to a kind with no member list (an enum, a typedef, a pointer or an array)
reduces the stored members to that kind's shape; the history entry records the
members it replaced, so a revert restores them. `size_check` compares that declared size with `member_extent` (the
size the members imply, whatever the row says) and reports the disagreement,
naming both numbers, without rewriting either one.

A member write carries the full shape (`name`, `type`, `pointer`, `count`,
`bits`) and can name a position: `index` is where the member goes and `after`
names the member it follows, and the two are refused together rather than
silently ordered. A retype replaces `type`/`pointer`/`count` and leaves a
hand-set `bits` alone, so a narrower type keeps the width its author set and
only an explicit `new_bits=None` clears it; `pointer`, `count` and `bits`
distinguish "leave alone" from "clear" through the module's `UNSET` sentinel.
Padding has two representations and the model keeps them distinct: an *implicit*
hole is a byte range no member covers, and an *explicit* gap is an ordinary
member named `gap_XXXX` over a `char` array, the convention `rebrew
recover-structs` emits. `convert_to_gap` writes that member (its name derived
from the offset by `gap_name`, its size the member's own unless the caller names
one, and refused for a union, whose members overlap, or a zero-byte member);
`convert_from_gap` requires `is_gap_member` to hold before it renames and
retypes. The explicit member wins at render time: a member is model state, so
the renderer emits it and the `/* +0xN padding */` comment marks only bytes no
member covers. Rendering a gap as a comment would drop model state, so a layout
spelled with an explicit gap and one left as a hole stay different models that
each render truthfully; a struct without explicit gaps renders exactly what it
always did.

The enum value operations carry the same rigor: `add_value` takes an integer or
a decimal/`0x` literal (`parse_value` reads both through one base-detecting
call), continues from the last constant when the caller omits one, and states
the derived number in the payload's `note`; `update_value` renames and/or
revalues (the payload echoes every constant as a decimal and a hex value); a
duplicate name or value is refused naming the constant it collides with
(`DuplicateValueError`), an unknown selector is `UnknownValueError`, a bad
literal is `InvalidValueError`, and removing the last constant is refused so the
enumeration stays non-empty.

`filter_types` applies the `kind`, `namespace` (the path itself and every
descendant, or `PROGRAM_NAMESPACE` for the types with no namespace) and
`search` (a substring of the name, a member name or an enum value name)
filters; `namespace_tree` builds the `::`-separated tree over the whole model
with each node's count including its descendants and the program-defined types
under `Binary`. Both are pure functions over the stored rows, and the API route
is their only caller. `references` builds the two reverse indices over the
stored rows: `referenced_by` walks the sibling types' members and targets (a
member, a typedef target, a pointee, an array element, a function parameter or
return type) and `used_by_functions` walks the `function_signatures` return
type and parameters, both matching a name token inside the type text. The
payload's `note` states that it is a name match, so a namespaced or shadowed
name is reported as an ordinary match rather than a proven identity.

`render_header(types)` emits one `#pragma once` header with one block per type
sorted by name: a struct or union as `typedef struct|union <name>_s { ... }
<name>;` with its members ordered by offset (a union states that its members
overlap), an enum as `typedef enum <name>_s { <name> =
<value>, ... } <name>;`, and a typedef, pointer, array or function type as its
`typedef <target> ... <name>;` form, each followed by a `/* size N */`
comment. The existing struct output is byte-identical to what it always was.
`render_as_c` is the padded As-C block the payload carries: a struct's gaps
between members and its trailing gap are emitted as `/* +0xN padding */`
comments computed from the real offsets, and a union states its overlap. An
explicit gap member renders as its own declaration, so the comment marks only
the bytes no member covers and the member is never dropped. `encode_type` is the
one payload shape every read and write serves: members with their derived
`is_gap`, enum values as a decimal and a hex echo, the `as_c` block and the
`size_check`.
`export_header` writes `render_header` atomically through a temporary file and
`os.replace`, refuses an existing target without `force` (`ExportExistsError`),
and creates the target's parent directory only when its own parent already
exists (`ExportParentMissingError` otherwise), so a typo cannot materialize a
tree. The path is always the caller's; reportal never picks one inside the
workspace or the rebrew project.

`data_type_history` makes every one of those mutations revertible. `store`
owns its DDL (`_DATA_TYPE_HISTORY_DDL`, shared by `_SCHEMA` and
`ensure_data_type_history`, which creates the table on first use so a database
written before it existed picks it up). Each write
records the state it replaced (`previous`) and the state it wrote (`current`)
through `store.add_data_type_history`, with either side null for a create or a
delete; `data_types._state` is the recorded projection (the model fields plus
`source`, so a revert restores the source too) and `HISTORY_FIELDS` is the
differed subset, so the entry's `changes` list can tell a rename from a member
edit and is empty for a create or a delete, whose shape the null side states.
A write that changes no model field (a re-import of an identical definition)
records nothing. `list_history` reads a type's versions newest first;
`revert_history` restores one, updating a live row in place or re-inserting a
deleted one under its original id through `store.restore_data_type` (the type
column is `AUTOINCREMENT`, so an id is never reused). A revert appends its own
inverse state under source `revert`, so it is revertible in turn, and answers
`changed: false` with a reason when the type already holds the recorded state
or a recorded creation's type is already gone. The table holds no foreign key
to `data_types`, which is what keeps a deleted type's history readable and
revertible; it does cascade with the binary, so deleting a binary removes the
history of its types the way it removes every other row scoped to it. A
recorded state whose name another row now holds is refused `DuplicateNameError`
rather than overwriting that row.

## Function signatures

`signatures.py` turns the declaration line of a stored decompilation into an
editable per-function model and renders it back as C prototypes. It owns
parsing, validation, rendering and export; `store.py` owns the
`function_signatures` table DDL and the row primitives (``upsert_signature``,
``get_signature``, ``list_signatures``, ``delete_signature``).

`parse_signature` scans a listing for the first line that parses as a function
declaration and returns
``{"name", "return_type", "calling_convention", "parameters"}``; every other
line returns None without raising. The declaration regex rejects a nested pair
of parentheses, so a function-pointer parameter skips the line rather than
mis-parsing it. A head is a return type plus a name, with an optional
calling-convention keyword (`__cdecl`, `__stdcall`, `__fastcall`,
`__thiscall`, `__vectorcall`) removed and stored without its underscores; a
pointer return keeps its stars in the type text. A parameter list of `void` or
empty means zero parameters. A parameter's name is the last token when it is
an identifier that is not a type keyword, so `unsigned int a0` is named and
`char *` is not; a trailing array dimension stays with the type (`char[16]`),
and a duplicate parameter name makes the line unparsable.

`seed_signatures(conn, binary_id=...)` walks the binary's functions, parses
each stored decompilation and upserts the parsed row, counting created, updated
and skipped (a decompilation that does not parse is skipped with a reason; a
function without one is not touched). The edits (`set_return_type`,
`set_calling_convention`, `set_parameter`, `add_parameter`, `remove_parameter`,
`move_parameter`, `delete_signature`) validate a C identifier, reject an empty
type, a duplicate parameter name and an out-of-range index, and reindex the
parameters from 0
through `_reindex` after an add or a remove, so the stored indices stay
contiguous. An empty calling convention means unspecified and renders no
keyword.

A parameter carries `index`, `type` and `name` plus the optional `at` (an
argument location: a register like `ecx` or a stack slot like `[esp+4]`),
`kind` (one of `PARAMETER_KINDS`) and `bits` (a width up to
`MAX_PARAMETER_BITS`). All three are null until someone sets them; the stored
row is normalized on read so a legacy row's missing keys read as null. The
x86-32 argument-passing table (`_CONVENTION_REGISTERS`,
`ARGUMENT_SLOT_BYTES`) is the source of truth for `default_at(convention,
index)`: cdecl and stdcall place every argument on the stack, fastcall the
first two in `ecx`/`edx`, thiscall the `this` pointer in `ecx`. The API offers
that derived value beside the model as `default_at` rather than storing it, so
an absent `at` stays absent. `move_parameter` reorders one parameter and
recomputes every `at` the table can place from the parameter's new index; a
location the table cannot place (an unknown convention) keeps its value.

`render_prototype` emits ``<head> [__<convention>] <name>(<params>);`` with an
empty parameter list rendered as `void`; a parameter carrying any of `at`,
`kind` or `bits` renders them as a trailing C comment in that fixed order, so
a prototype never claims a field the model does not have. `render_prototypes`
emits one
`#pragma once` header with one prototype per function ordered by name (then
function id), so the same model always renders the same bytes.
`export_prototypes` writes it atomically through a temporary file and
`os.replace`, refuses an existing target without `force`, and creates the
target's parent directory only when its own parent already exists.

## Verification

```bash
uv run --python .venv/bin/python pytest -q                  # full suite
uv run --python .venv/bin/python ruff check src/ tests/ tools/
cd web && bun install && bun run build                      # typecheck + Vite build
cd web && bunx tsc --noEmit && bun run lint                 # types and oxlint
vnu --format text web/index.html                            # source HTML
vnu --css --format text web/src/styles.css                  # source stylesheet
uv run --python .venv/bin/python tools/smoke_spa.py         # builds web/ if needed, then every route
uv run --python .venv/bin/python tools/audit_ui.py          # UI gate: layout, contrast, names at both viewports
cd web && bun run test:ui                                   # Playwright: seed + serve + browser specs
```

`tools/smoke_spa.py` builds the frontend when `assets/dist/index.html` is
missing (`bun install` when `web/node_modules` is absent, then `bun run
build`), seeds a scratch workspace, starts the server, renders each hash route
with headless Chrome, asserts DOM markers, switches the seeded loop function's
code panel to its control-flow view and asserts the graph's markers and an
edge jump's focus move, and tears the process group down in a `finally`. It
exits 0 with a message when no browser is present.

`tools/audit_ui.py` is the UI gate over the same seeded workspace and route
list. It drives headless Chrome over the DevTools protocol
(`--remote-debugging-pipe`), renders every route at 1600x1000 and 480x900 in
both colour schemes (dark is emulated: headless Chrome defaults to light), and
fails with a `route/selector` list when it finds horizontal document overflow,
clipped text, text contrast under WCAG AA (4.5:1, or 3:1 for text at least 18px
or 14px bold), a box outside the viewport, or an interactive element with no
accessible name. The thresholds are its module constants and are injected into
the page. `--base-url` audits an already-running server, `--json` prints the
report, and `--viewport WxH` / `--theme` narrow the matrix.

`web/tests/` is the Playwright suite (`cd web && bun run test:ui`; specs are
`web/tests/*.spec.ts`). The config is one chromium project using the cached
browser the pinned `@playwright/test` 1.62.1 resolves (`chromium-1234` under
`~/.cache/ms-playwright`), so a run downloads nothing. The global setup seeds
the workspace through `tools/seed_e2e.py` (the smoke's `build_workspace` plus
two collections) and starts `reportal serve` against it in its own process
group, which the teardown stops; that is a global setup rather than the
config's `webServer`, because the server needs the database the seed creates.
Specs run serially over the one workspace and cover every hash route's render
with a clean console and network, the sidebar group navigation, the destructive
confirm flows, the collection, tag and note write paths, a journal write and
its revert through the UI, the 480px shell, and the keyboard tab order into the
nav, a table's row actions and an activated row, the keyboard layer (the
registry's rules in the Node context, `?` and its focus return, the cheatsheet's
rendered set, the typing rule, `/`, `j`/`k` and the `g` prefix), the function
page's control-flow view (the Disassembly / Control flow toggle swapping the
panel, a block's address, byte size, instruction count and labelled instruction
text, and an edge's labelled jump control moving focus to its target block),
and the threat
report's software-type badge, score meter and MITRE link. A shared fixture fails every
test on a console error, an uncaught page error, a dropped request or an error
response, filtering only the documented empty-result 404s (`no-scan`,
`no-artifact`, `no-run`, `no-graph`) a stored-only read answers before the
matching scan is stored.

## Scope

The hosted platform's black-box surfaces are not reproduced; see
`docs/PARITY.md` for the per-capability status. In short: neural embedding
matching is replaced by structural similarity, AI decompilation prose
(summary, inline comments, type suggestions, per-function triage) and scoped
conversations are
available only through the
optional OpenAI-compatible bridge against whatever model the user configures,
and neither calls a tool or an engine,
the hosted portal's own models and its security/LM/execution/networking/filesystem
agents are out of scope (reportal's behavior and security scans are deterministic
import/string and rule heuristics),
the remediation surface ships local YARA, Snort and STIX renderers over the
stored scans (the Snort rule is a basic content rule and the STIX bundle a
minimal deterministic 2.1 export, neither validated against an external
validator), and
the threat report is reportal's own deterministic IOC/ATT&CK output (the hosted
model-driven report and any external threat-intelligence source are not
reproduced),
Detect is local family matching against a store the analyst curates from
reference binaries (reportal bundles no external threat-intelligence feed, and
the hosted portal's own curated families and models are coming soon upstream,
not reproduced here),
and there is no auth, teams, dynamic execution, or firmware.
The AI decompilation pipeline is local and component-based: its stages read the
store and the rebrew engine, the model-backed stages are skipped with
`llm-unavailable` without an endpoint, and the hosted models are not involved.
Auto mode is local in the same way: its orchestration is threads in this
process over the local store and the rebrew engine, an accepted function is one
`rebrew test` byte-compared, there is no hosted worker and no LLM review gate,
and a run that matched nothing leaves the rebrew project as it found it.
Knowledge is local too: documents come from local files, pasted text and HTTP
uploads, ranking falls back to a local TF-IDF cosine without an embeddings
endpoint, and the knowledge graph is a deterministic entity/relation graph
built from stored rows with no LLM or external store.  Guarded URL ingestion is
the one exception and it is off by default (see Remote ingestion): enabling it
makes the portal fetch a caller-chosen URL, which is why the address, port,
redirect, size and content-type guards exist.
Retrieval is built: the function and binary knowledge routes, `reportal
context`, the read-only `retrieve_knowledge` MCP tool and the pipeline's
`retrieve-knowledge` component return the ranked documents, and a conversation
appends them as bounded, citable context. The optional Cognee-backed knowledge
graph of the sibling relumea workbench remains a separate, planned integration.

# Changelog

reportal is versioned in `src/reportal/__init__.py`; the same string is what
`reportal --version`, `GET /api/health` and the MCP server's `serverInfo`
report. This file is the human summary, newest first, and the SPA's changelog
view renders it from here.

## 1.2.0

Closes every capability gap the parity inventory found and the crawl backlog
recorded: `docs/PARITY.md` has no open cluster and `docs/TODO.md` has no open
entry.

### Asynchronous operations and jobs

- A queued job workflow (`jobs.py`): `POST /api/jobs`, `GET /api/jobs`,
  `GET /api/jobs/<id>`, `POST /api/jobs/<id>/cancel`, the `reportal job*`
  commands, the Jobs view and the `job_*` MCP tools, drained by a bounded
  background pool (`REPORTAL_JOBS_POOL` switches it off).
- Analyses, matching, decompilation, report rendering and the rest can run as
  a job instead of holding the request.

### AI decompilation

- A stored AI decompilation artifact per function: the rewritten source, its
  placeholder token map, the analyst's overrides for those names and the
  per-line attributions and comments, with the routes, commands, MCP tools and
  the function panel that read and write them.
- The composition runs as a component pipeline with an effect dispatcher
  (`components.py`, `effects.py`, `pipeline.py`); a third party adds a component,
  an effect kind or an auto worker through an entry point, and
  `docs/COMPONENTS.md` maps the model to the paper it follows.
- `reportal components-deactivate` withdraws one component from the live
  composition and journals what its revert recorded.

### Sandbox, firmware and archives

- Guarded detonation (`sandbox.py`): off until the workspace opts in *and* a
  runner is installed, with the wall-clock, memory and CPU caps and the ledger
  the routes, commands and MCP tools read. `docs/THREAT_MODEL.md` states the
  boundary and the residuals.
- Firmware carving and region extraction (`firmware.py`), and archive members
  registered into a collection as one journaled action.

### Identity, teams and scope

- Local identity: users with the `viewer`/`analyst`/`admin` role sets, a
  digest-only bearer token shown once and compared in constant time, and the one
  middleware that gates every `/api` path when `REPORTAL_AUTH` or
  `[auth] required` turns it on. A non-loopback bind is refused while the gate
  is off or no enabled user exists.
- Teams, per-object `visibility` and `owner_team_id`, and the shared
  `auth.visible_clause` the listings, the search and the bulk guard use, so a
  new route is scoped by construction. The analyses list gained the workspace
  filter and the owner/seen-by columns.
- The optional secret store (`secret_store.py`): one credential per
  `(name, scope, team)`, admin-or-team-membership writes, journaled rotations,
  and reads that report the name, scope, byte length and a last-four hint rather
  than the value.

### External sources and models

- An external-source seam (`external.py`): the offline `local` derivation and
  the guarded remote `virustotal` pull, which needs the workspace opt-in *and* a
  resolvable key and otherwise makes no request.
- A model registry (`models.py`) and `POST /api/analyses/<id>/upgrade`, which
  re-runs an analysis's stored LLM artifacts under a named model and journals
  every replacement. It never re-analyses the binary; the route says so.

### Analyses, matching and function extras

- The analysis lifecycle reads and writes, the analysis log, per-analysis scope,
  the raw bytes and imported functions, and the bulk delete/tag actions.
- Symbol transfer (`name`, `signature` or `both`) with `dry_run`, per-row
  `applied`/`skipped`/`failed` reporting and `missing_types`, plus the signature
  and data-type batch reads.
- Function-level extras: the cached indirect call sites, the capability
  classification over a function's own imports and literals, analyst strings
  beside the derived ones, the declared callee edges and the canonical-name
  pass. Every derived payload carries the note that it is a text scan, not
  engine output.
- Debug symbol ingestion (`symbols.py`, `pdb.py`): ELF/DWARF and PDB readers,
  the renames and aggregate types an import applies as one journaled action, and
  the C-header or JSON export.

### Reporting and the portal surface

- The password-protected zipped download, the queued PDF report render, the
  activity feed, the feedback notes and the notification feed derived from the
  journal.
- Dashboard analytics: `GET /api/stats/series` over the last 30 days (analyses,
  auto runs, journaled actions and the derived software types).
- Agent-artifact ratings: a thumbs up/down and a note per stored scan, journaled
  and revertible.
- A conversation about reportal itself: the `docs` scope ingests the shipped
  manual on the first question and answers from it, with a per-scope canned
  prompt list in the Conversations view.
- The Integrations view's MCP onboarding card, which prints the one-liner and
  the client config for the 228 built-in tools.
- Regular-expression and multi-value search, per-type provenance in the
  data-type model, and the in-app documentation browser over `docs/*.md` and
  this file.

## 1.1.0

The first release: a self-hosted local clone of the RevEng.AI web portal over
`rebrew`, `resembl` and `recoverage`.

- SQLite storage for binaries, analyses, functions, types, signatures, comments,
  cross-function matches, rename history, collections and tags.
- A FastAPI JSON API, a Vite + React + TypeScript SPA and a Typer CLI over the
  same store, plus a stdio MCP server that exposes it to an agent.
- Local engine orchestration: fingerprints, imports, strings, disassembly and
  decompilation, cross-references, struct recovery, security scanning, the
  coverage import and local matching.
- The PDF report and the coverage view, the journal with its revert, the tags
  and collections, the knowledge store and the graph backends.
- Offline by default: no network call happens until an LLM endpoint is
  configured or a URL is explicitly ingested.

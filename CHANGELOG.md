# Changelog

reportal is versioned in `src/reportal/__init__.py`; the same string is what
`reportal --version`, `GET /api/health` and the MCP server's `serverInfo`
report. This file is the human summary, newest first, and the SPA's changelog
view renders it from here.

## Unreleased

- A composition in which two enabled components provide the same context name
  is now refused before any effect runs (`components.assert_unique_providers`,
  checked by `run_pipeline`, `ComponentHost.__init__` and `ComponentHost.sync`),
  instead of the first declaration silently winning the provider map while both
  components ran and the second's binding outlived the provider's revert.  The
  rule is the paper's coeffect precondition (one writer per key is exactly what
  its independence condition needs), and `docs/COMPONENTS.md` now maps the
  paper's mechanisms it does not implement (fibers, coeffect isolation and
  interception, derived realization, inertia) and the two deliberate deviations
  it keeps (an overwritten context name, and a revert that is idempotent rather
  than invertible off the paths whose revert writes rows).

- `reportal fingerprint <binary-id>` prints a binary's fingerprint: the stored
  bundle when `reportal enrich` kept one, else a live compute through the engine
  that is not stored.  The read half of the pair existed in the HTTP route and
  the MCP tool and had no command, so the terminal could compute the bundle and
  keep it but not simply look at it.

- The command line can print a function's disassembly and a binary's imports.
  Both reads were reachable from the HTTP API and the MCP server and from no
  command: `reportal disasm <function-id> [--format nasm|hex]` resolves the
  binary's rebrew project context and prints the listing (reading the same
  `disasm_cache` the route fills, with `--json` reporting whether the answer
  came from it), and `reportal imports <binary-id>` lists the engine's import
  table as library, function and IAT rows.  The rule that only the nasm listing
  is cached now lives once, in `store.CACHEABLE_DISASM_FORMAT`, instead of being
  written in the route and the tool separately.

- The analyses list can be paged.  It always asked the route for exactly
  `store.DEFAULT_ANALYSIS_LIMIT` rows and offered no way to ask for more, so a
  workspace with more than a hundred analyses could see the first hundred and
  nothing else even though the payload reported the true total and the route
  accepts up to `store.MAX_ANALYSIS_LIMIT`.  A Show field now sets the bound in
  the route hash (left out while it is the default, and clamped to the range the
  route accepts so a hand-edited URL cannot ask for a 400), and the count line
  says when rows are hidden and which control lists the rest.

- The journal filters by the actor it recorded.  `GET /api/journal` takes
  `?actor=` beside its existing `?action=` and `?limit=`, echoes what it applied
  and names the `actors` the journal holds (the same facet idea as the job
  queue's `statuses`), `reportal journal --actor` and the `list_journal` tool
  take the same filter, and the Journal view lists an Actor column with an actor
  select and a page-size control in the route hash.  The per-action route stays
  as it is (every entry of one action, no filters); the view now asks the
  listing for one action as well, so the two new controls keep working while an
  action is selected.

- The job queue is filterable from every surface.  `GET /api/jobs` already took
  `?status=`, `?kind=`, `?binary_id=` and `?limit=`, but the CLI's `jobs` command
  had no binary filter, the `list_jobs` tool had none either, and the Jobs view
  carried only a status select held in component state, so a filtered queue
  could not be linked or reloaded.  The command and the tool take `--binary-id`
  and `binary_id`, the payload now names the `statuses` beside the `kinds` so
  the view's two selects are built from the registry, and the view's Status,
  Kind, Binary and Show controls live in the route hash with a Clear.

- A function list is filterable by name and address, and `reportal functions`
  exists: `GET /api/binaries/<id>/functions` takes `?name=` (a case-insensitive
  substring, with the LIKE wildcards escaped) and `?va=` (one exact address,
  decimal or `0x` hex; 400 `invalid va` otherwise), the CLI gains the command
  that listed the binary's functions (it had none, although the route and the
  `list_functions` tool both existed), the `list_functions` tool takes the same
  two arguments, and the Functions view carries a Name and an Address control
  in its route hash.  The `refers_to` filter now shares one address parser with
  `va`, so both read the same way and refuse the same way.

- The binary register is filterable and `reportal binaries` exists: `GET
  /api/binaries` takes `?search=` (the name or the SHA-256, a prefix is enough),
  `?tag=` (that exact tag name), `?format=` (one stored format) and `?order=`
  (id, newest, name, name-desc, size, size-desc; an unknown one is 400
  `invalid order`), echoing every filter it applied beside `count` against the
  unfiltered `total` and the `formats` the register holds.  The register had no
  filter at all and the CLI had no command that listed it, although the API
  route and the `list_binaries` MCP tool both existed; the command and the
  tool's four arguments close that, and the Binaries view gains the four
  controls in its route hash.

- An analysis search matches the binary's SHA-256 as well as its name and the
  engine label, so a pasted hash or hash prefix finds the analysis, which is
  what an analyst has for a sample whose name they do not know.  The hosted
  analyses list searches the same three fields, and the search box's placeholder
  now says so.

- The data types list sorts: `GET /api/binaries/<id>/data-types` takes
  `?sort=name|size` (400 `invalid sort`) and `?direction=asc|desc` (400
  `invalid direction`), a type whose size the model states as zero (an unknown
  one) sorts last in either direction so it cannot claim the head of a
  descending list, `reportal types --sort/--direction` and the `list_data_types`
  MCP tool take the same pair, and the panel carries Sort and Direction selects
  in the route hash beside its other filters.  The hosted data-types panel
  offers that control; reportal's list was grouped by name only.

- An analysis row's tags are editable in place: each tag is a chip with its own
  remove control and the cell carries an add field, both of which post the
  binary's whole tag set through `PATCH /api/analyses/<id>/tags`.  The hosted
  analyses list offers the same inline editing, and the list and the binary's
  Tags panel now write the same row, so the two cannot disagree.

- Tags can be maintained: `PATCH /api/tags/<id>` renames one and
  `DELETE /api/tags/<id>` removes one with every binary and collection link to
  it, both journaled (a revert restores the old name, or the tag and its links
  parent-last), with `reportal tag-rename` and `reportal tag-rm`, the
  destructive `rename_tag` and `delete_tag` MCP tools, and a Tags view
  (`#/tags`) listing the vocabulary with what carries each tag.  Until now a
  tag could be created where it was applied but never renamed or pruned, so a
  misspelling was permanent, and `GET /api/tags` now reports how many
  collections carry a tag beside how many binaries do.

- A revert no longer deletes a file another writer replaced.  A `file-write` (an
  auto run's candidate source) and a `file-delete` (the action journal's stored
  upload or export) descriptor now carries the SHA-256 of the bytes the writer
  stored, and their shared inverse removes the path only when it still holds
  them: a path whose bytes changed is reported `diverged` and left alone, and a
  journal entry that hits it reverts `partial` instead of claiming the file went
  away.  A descriptor with no digest (one persisted before the field existed, or
  one a crashed task never confirmed) behaves as it always did.

- The in-app manual reads in order: `docs.neighbours` answers the page before and
  after one in the same order the index numbers, `GET /api/docs/<slug>` carries
  the pair beside the page's blocks (null at either end), the Documentation view
  renders it as a previous/next pager at the foot of the body, `reportal docs
  <slug>` names the next page and the read-only `get_doc` MCP tool reports the
  same pair.  A page with no neighbour answers null rather than erroring, so the
  first page and the changelog (which is last) render one link.

- The collections list carries the scope it was missing: `GET /api/collections`
  takes `?workspace=personal|team|public` against the collection's own
  `visibility`/`owner_team_id` (an unknown value is 400 `invalid workspace`) and
  answers each row with its `owner_team_name`, `?order=` gained `owner` (sorting
  by the owning team's name, the personal collections first),
  `reportal collections` takes `--workspace` and draws an Owner column, the
  `list_collections` MCP tool takes the same filter, and the Collections view
  carries a Workspace control and an Owner column, with its sort and scope kept
  in the route hash so a filtered list is a link.

- Long tables render only what is in view: `DataTable` takes a `windowed` prop,
  set on the Functions and Matches lists, which renders the rows around the
  viewport with a spacer row carrying the height of the rows it left out and
  sizes them from the first row's measured height.  Measured in headless Chrome,
  20,000 functions cost 3,751 ms to the first row and 106.5 MB of JS heap before
  and 453 ms and 10.3 MB after; 25,000 match rows cost 6,441 ms and 127.4 MB
  before and 311 ms and 13.1 MB after.  The API time is unchanged, so the cost
  was the DOM rather than the request.

- A faster first paint in the SPA: every view but the dashboard is now a lazy
  route (`React.lazy` plus a `Suspense` boundary), React and the router are one
  cached `vendor` chunk, and the initial payload drops from one 617 kB bundle
  (172 kB gzip) to a 77 kB entry (22 kB gzip) plus a 289 kB vendor chunk (91 kB
  gzip).  The binary detail view, which is a third of the source, is now 113 kB
  that only that route fetches.  `tools/smoke_spa.py` asserts the split, so a
  view import that goes back to being static fails the gate, and the analyses
  e2e spec waits for its table instead of counting it while the view loads.
  `GET /` is answered `no-cache` and the hashed bundles under
  `/static/assets/` `immutable`, so a repeat load serves them from the browser
  cache instead of revalidating 28 files.

- Recorded scan inputs: a stored scan now carries the inputs the caller named
  beside its result (`scans.params_json`), so a reading can be run again the same
  way instead of guessed at: the decompiler and limit of a struct recovery, the
  severity floor of a security scan, the confidence floor of an unstrip or
  library identification, the selected functions of a triage, the limit of a
  related-binary run, whether a threat report asked for a narrative, and the
  partner binary and settings of a benchmark.  `GET /api/binaries/<id>/scans`,
  `reportal scans <binary-id>` and the read-only `list_scans` MCP tool report
  them; the result payload is left out of the listing and the inputs are never
  injected into it (an engine payload is still stored exactly as it came back).
  A scan that records none reads as an empty object.

- One read of every setting: `reportal config` now prints the instance
  description and then each setting reportal reads with the value in force and
  whether the environment, the workspace `reportal.toml`, the secret store or a
  default answered, plus every key and value in that file reportal does not read
  (an unknown key and a value of the wrong type are both ignored silently today,
  and a file reportal cannot parse switches the whole install to defaults, so it
  exits 1).  `reportal doctor` carries the same check as its `config` row.  The
  marker's `[portal] db` name is now what it says it is: `db_path` resolves it
  against the workspace root, `reportal init` writes the database it names, and
  `REPORTAL_DB` still overrides the path outright.

- Scoring the rename proposals: `reportal rename-benchmark <binary-id>` and
  `GET /api/binaries/<id>/rename-benchmark` score the proposals the workspace
  already holds against the one source of names reportal cannot derive, a debug
  symbol file (which renames the functions it covers with the `symbol` name
  source).  It reports precision, recall, F1, every disagreement and every
  missed symbol, counts a difference of case or a leading underscore as `close`
  rather than `correct`, and counts a proposal at an address no symbol names as
  unscored rather than wrong.  A stored read: no engine runs and nothing is
  written, which is also what the Benchmark panel's new Rename proposals
  section renders.

- Deployment readiness and a service unit: `reportal doctor [--port N]
  [--json]` checks that this install can serve before anything starts (the
  workspace, the database and its schema, the auth posture, the engine, the SPA
  build, every optional path and whether the port is bindable), exits 1 on a
  failure and 0 on a warning, and is what `deploy/reportal.service` runs as its
  `ExecStartPre`.  `docs/DEPLOY.md` is the sequence around it: the host
  requirements, the unit's directives and their deliberate omissions, remote
  access with token auth, the backup timer and the upgrade steps.  `GET
  /api/config`'s `features` now reports the detonation and remote-source opt-ins
  from the gates those paths read, instead of two hardcoded falses.

- Benchmarking a match run: `reportal benchmark <left-id> <right-id>` and
  `POST /api/binaries/<id>/benchmark` run the ordinary match with the partner
  binary as the candidate scope and score the rows it recorded against labelled
  counterpart addresses, reporting precision, recall, F1 and mean reciprocal
  rank with every query's rank and every miss.  The labels are a corpus file
  (the route and the MCP tool take the pairs in the body, so no request names a
  path) or, without one, the two binaries' shared real function names, which the
  payload states as the weaker source.  The result is stored as the binary's
  `benchmark` scan.  Rename proposals are deliberately not scored.

- Unpacking a packed executable: `reportal unpack <binary-id>` and
  `POST /api/binaries/<id>/unpack` identify the packer from the file's own stub
  (the LZEXE stub at the entry point, the UPX marker), rebuild the image the
  packer replaced and register it as a binary of its own, with the packed
  source, the packer and the method kept as the new binary's `unpack` scan.
  LZEXE runs in process through the engine; UPX runs the external `upx` tool,
  which reportal does not ship, so a machine without it answers `no-unpacker`
  with the install hint.  Nothing executes the sample, the packed source is
  never modified, and one journal revert removes the new scan, row and file.

- Workspace backup and restore: `reportal backup` writes the whole workspace
  (database, stored binaries, reports) as one gzipped tar with a manifest, and
  `reportal restore` reads it back.  The database is copied through SQLite's own
  backup API after a WAL checkpoint, so the archive holds one consistent
  snapshot, and a restore is staged and checked against its manifest before
  anything moves.

- Library identification and the bill of materials: the engine's signature match
  is stored as its own reading (one component per module with its kinds,
  function count, byte total and best confidence, plus the per-candidate list),
  and the same reading exports as CycloneDX 1.5, SPDX 2.3 or CSV.  Before this
  the module a function came from was discarded after auto-unstrip used it.

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
- Team roles and organisations: a membership carries owner or member (only an
  owner or an admin may manage a team), an organisation groups teams without
  deciding access, and a user can switch the team the portal shows.
- Composition scoping and the hosted categories: a summary can be limited to
  chosen binaries or collections (the match-settings vocabulary), the stored
  scan records the scope it ran under, and the payload groups functions into
  malware, debug, unique and library with each category's top binaries.
- The keyboard layer's shell half: a collapsible sidebar (`Cmd/Ctrl+B`), a
  per-tab view history on `Alt+Left`/`Alt+Right`, `[`/`]` section cycling and
  `Space` to switch a function's Disassembly and Control flow view.  Fixed with
  it: an unstable effect dependency in the functions view that made the router
  stop processing locations after that view mounted.
- The upload panel's conveniences: a drag-and-drop zone, a per-row plan badge
  with a Configure-all control, duplicate and error banners over the per-entry
  results, and an in-place Extract an archive panel.
- The analyses list's richer controls: a multi-select status filter, platform
  and architecture filters built from what the register holds, six sort orders,
  a per-row re-analyse action, and copy-hashes in the bulk toolbar.
- A continuous whole-binary hex view: one scrollable dump in virtual-address
  order, gaps stated rather than zero-filled, a click-through from a section's
  address, and `G`/`Tab` for the address box and the offset column.
- The Integrations view's MCP onboarding card, which prints the one-liner and
  the client config for the built-in tools.
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

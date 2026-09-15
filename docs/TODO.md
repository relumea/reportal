# reportal todo

The running backlog.  One entry per thing reportal does not have yet, with the
evidence that it is a real hosted surface, what reportal has today, and the
local shape to build.  A closed entry keeps its evidence and gains a
`**Status:** Closed` line naming the slice that closed it, so this file stays
the record of what the crawl found rather than only of what is left.

Two feeds keep it current:

- [PARITY.md](PARITY.md) owns the capability map and the API-spec-derived gap
  inventory, clusters A to N.  Its open clusters are listed at the bottom of
  this file with a link, not restated.
- A live Playwright crawl of `https://portal.reveng.ai`, the authenticated UI.
  That is where the entries below come from: the portal's own `/documentation`
  pages and its network traffic name surfaces the public OpenAPI spec does not
  carry at all (teams, organisations, credits, the secret store, debug
  symbols), so the spec-derived inventory could not see them.

## How the list was measured

Crawled 2026-09-13 against the live portal, signed in with the local
`~/.secrets/reveng.ai` token (read-only: no run, upload, rename or delete was
triggered), 69 routes plus a section walk of one complete analysis.  Three
sources on the hosted side: the routes themselves, the portal's own
`/documentation` pages, and the weekly `/changelog` feed, which names shipped
features the documentation has not caught up with.  Raw capture and scripts:
`.scratch/portal-crawl/` (`crawl.mjs` walks links, `detail.mjs` pulls the
documentation, `changelog.mjs` scrolls the feed, `auth.mjs` sets the
`access_token` cookie).  Evidence in the entries below is either a portal route
(a URL a browser can open) or an API path the portal itself called, both
re-checkable.

**Re-crawled 2026-09-14 and nothing new.**  `changelog.mjs` came back
byte-identical to the 2026-09-13 capture, so no weekly entry has been published
since the 3 to 9 August one, and `crawl.mjs` walked 68 routes against the
previous walk's 69, every one the same shape (the only differences are which
concrete `/analyses/<id>` pages the walk happened to open, plus the dashboard's
greeting, `Greetings maci` having become `Hello maci`, and one row's
single-digit label moving with the data).  The `/v3/analyses` call the list
makes still asks for `page_size=50` with no page parameter, and no route or form
appeared that the entries below do not already name.  So the crawl feed is
exhausted: what is left in this file is the gaps stated inside its closed
entries, not surfaces the crawl has not seen.

reportal's side of every comparison is its FastAPI schema, its MCP registry and
`web/src/views/`.

## New findings from the UI crawl

### 1. Debug symbol ingestion (PDB and DWARF)

- Portal: the upload panel has a per-file **Debug Symbols** zone; attaching a
  PDB or DWARF file recovers function names and types for the decompiler
  (`/documentation/upload-binaries`, section "Debug symbols").  The analysis
  header export menu downloads PDB/ELF symbols, and Binary Details carries
  Symbols and Relocations panels for ELF.
- reportal: no symbol-file input at all.  Names come from rebrew's project
  annotations, library identification and the rename paths; there is no local
  PDB/DWARF reader and no symbol artifact to export.
- Build: store the symbol file beside the binary (content-addressed, the way
  `binaries/` already is), parse names and types into the existing name-source
  model as a `symbol` source, `reportal symbols <binary-id> <path>` plus
  `POST /api/binaries/<id>/symbols` and a read sibling, and an export that
  reuses the signature/type renderers.  A PDB writer is out of scope; export
  stays C headers and JSON.
- Size: M.
- **Status:** Closed.  `symbols.py` holds the readers and `pdb.py` the PDB one.
  `reportal symbols <binary-id> <path>` (or `POST /api/binaries/<id>/symbols`, a
  multipart upload) stores the file under `<workspace>/symbols/<sha256>`, parses
  it with the stdlib readers and applies it as one journaled action: a function
  whose VA matches a symbol is renamed to it with the `symbol` name source
  (`store`-level, so the composition buckets read it as a system name) and every
  aggregate type the file declares is created or updated in the editable type
  model.  A DWARF subprogram, a base type, a pointer and a struct member come
  from `.debug_info` (DWARF 2 to 5, the indexed `strx`/`addrx` forms included,
  through the unit's own bases), an ELF symbol table from `.symtab`/`.dynsym`,
  and a PDB from the MSF container's DBI symbol record stream (public and
  procedure symbols, names only).  `GET /api/binaries/<id>/symbols` reads the
  ingests (404 `no-symbols` before the first), `GET .../symbols/export?format=c`
  renders the header through `data_types.render_header` so the export and the
  model cannot disagree, the `get_symbols`, `import_symbols` and
  `export_symbols` MCP tools expose the same, and the SPA's Debug symbols panel
  uploads, lists and exports.  Each parse carries its own `notes` naming what
  the reader did not do; the ceilings are DWARF expressions (a member offset
  carried by one is skipped rather than guessed), DWARF type names deeper than
  `MAX_TYPE_DEPTH`, and PDB types (the TPI stream is not parsed).  A real MSVC or lld PDB
  stores its section map as `SectionMapEntry` records and its addresses in a section
  header stream, so the PDB reader reports a symbol's name and its `kind` and answers
  `va: null` rather than a made-up address: a PDB ingest therefore records names in the
  stored parse and in the export, and renames a function only when the symbol carries
  an address the map resolves (the ELF/DWARF path).  The reader was verified against
  a PDB built with `clang -gcodeview` + `lld-link /debug` and cross-checked with
  `llvm-pdbutil dump -publics`: the container, the DBI header, the symbol record
  stream and the two publics it reports all read back, and no address is invented.

### 2. Teams, organisations and roles

- Portal: the team is the ownership unit.  Members see and work on the team's
  binaries; team admins add, remove and promote members and rename the team.
  A user can belong to several teams and switch the active one.  Teams sit
  inside organisations, owned by organisation owners, with groups (org-level
  teams carrying their own credits)
  (`/documentation/teams-and-access`).  Endpoints absent from the public spec:
  `GET /v2/iam/teams`, `GET /v2/iam/teams/{id}`, `GET
  /v2/iam/teams/{id}/members`, `GET /v2/iam/organisations`.
- reportal: `teams` and `team_members` plus the team-as-owner model are now
  shipped (cluster F): a team owns binaries and collections through
  `owner_team_id`/`visibility`, membership is managed over HTTP, the CLI and
  MCP, and a non-member's read is a 404 while its write is 403.  Roles exist
  (`viewer`/`analyst`/`admin`).
- **Status:** Closed.  The team scope, team roles, organisations and the
  active-team switch all shipped.  A `team_members` row carries a `role`
  (`owner`/`member`): an owner may rename the team, set its members and change
  roles, a member works on what the team owns, and an admin may manage any
  team, which is what keeps a lockout recoverable (`may_manage_team`,
  `PUT /api/teams/<id>/members/<user_id>/role`, `reportal team-role`, the
  `set_team_member_role` tool, and the Users view's per-team Members table with
  a role select per row).  An `organisations` table sits one level above teams:
  `GET`/`POST /api/organisations`, `GET`/`DELETE
  /api/organisations/<id>`, `PUT /api/teams/<id>/organisation` (the body's
  `organisation_id` or null to ungroup), the `reportal organisations`,
  `organisation-add`, `organisation-rm` and `team-organisation` commands, the
  `list_organisations`/`create_organisation`/`delete_organisation`/
  `set_team_organisation` tools, and the Users view's organisation table with a
  per-team select.  `PUT /api/iam/active-team` switches the team a user has
  selected (membership required, an admin may select any team; null clears it)
  and `GET /api/iam/me` reports `active_team_id`.  Deliberate gap, stated
  rather than hidden: an organisation is structure, not access control, which
  `docs/ARCHITECTURE.md` and the SPA say in place; the hosted per-organisation
  credits and the groups inside an organisation (org-level teams with their own
  credits) are a hosted billing concept with no local meaning, and there is no
  credit model here to attach them to.  Covered by `TestTeamRoles`,
  `TestOrganisations`, `TestActiveTeam` and `TestTeamRoleAndOrganisationRoutes`.

### 3. Secret store

- Portal: `GET /v2/secret-store` backs the settings **API Key** tab, and a team
  admin sets the team's VirusTotal API key, which enriches threat intelligence
  for everyone on the team (`/documentation/teams-and-access`).
- reportal: credentials live only in the environment or `reportal.toml`
  (`REPORTAL_LLM_*`, `REPORTAL_ALLOW_REMOTE_INGEST`).  There is no store, no
  per-team scope and no write-only read.
- Build: a `secrets` table (name, scope, value) with a write-only read (last
  four characters), used by the LLM bridge and by whatever external source
  cluster H adds, plus `reportal secrets-set` / `secrets-list`.  Values are
  local state: document them in [THREAT_MODEL.md](THREAT_MODEL.md).
- Size: M.
- **Status:** Closed.  `src/reportal/secret_store.py` is the store: one row per
  `(name, scope, team_id)` at workspace or team scope, a read that never returns
  the value (name, scope, byte length and a last-four hint, and no hint at all
  for a value shorter than `MIN_HINT_LENGTH`), `PUT`/`GET`/`DELETE
  /api/secrets[/<name>]`, `reportal secrets-list` / `secrets-set` (with
  `--stdin`) / `secrets-rm`, the `list_secrets`, `set_secret` and `delete_secret`
  MCP tools and the Secrets panel on the SPA's Users view.  Every write is
  journaled, so a rotation is revertible.  :func:`secret_store.value_of` is the
  one read that returns a credential, and it is internal only: `llm.LlmConfig`
  resolves the bridge key from the environment, then `reportal.toml`, then the
  store, so an existing install is unchanged and cluster H's external source
  reads the same way.  A workspace secret needs an admin and a team secret that
  team's members; with auth off the install is the single local operator and
  everything is allowed.  The trust boundary and its residual (the journal keeps
  the value a rotation replaced) are written out in
  [THREAT_MODEL.md](THREAT_MODEL.md).

### 4. Dashboard analytics (time series and usage)

- Portal: the dashboard greeting carries the tier badge and a credit count, and
  three 30-day charts: binaries processed, software type detections, agents
  triggered.  Endpoints the UI calls: `GET
  /v2/reports/users/{id}/analyses-count`, `GET
  /v2/reports/users/{id}/agent-workflows`, `GET /v2/iam/users/{id}/credits`.
- reportal: `DashboardView` shows current row counts, a matched-byte meter, the
  live run and the newest journal entries.  Nothing over time.
- Build: `GET /api/stats/series?days=30` computed from `analyses.created_at`,
  the stored `threat` scans' software types and `auto_runs`, rendered as the
  three charts.  Usage counters (engine calls and LLM tokens per period) are
  the local analogue of credits; billing and a subscription page are not
  applicable locally.
- Size: M.
- **Status:** Closed.  `analytics.py` computes the three series plus the usage
  counter over rows the workspace already holds and stores nothing, so a chart
  cannot drift from the lists it summarizes: analyses created per day, auto runs
  started per day, journaled actions per day (the local analogue of the hosted
  credit count) and, per day, the software type each created analysis's binary
  derives through `threat.classify_binary` (one derivation per binary, reused
  for its analyses, capped by `MAX_SERIES_ANALYSES` with a note when the cap
  bites, and a binary whose type cannot be derived counts as `unknown` rather
  than being dropped).  Every day in the window is present, a quiet one with a
  zero, because a chart with holes reads as missing data;
  `GET /api/stats/series?days=` (30 by default, `MAX_SERIES_DAYS` at most, 400
  `invalid days` outside), `reportal stats --series [--days N]` (the existing
  command gained the series beside the row counts) and the read-only
  `get_stats_series` MCP tool expose it.  The SPA's dashboard renders the three
  charts as one bar per day over a shared peak, each labelled for a screen
  reader with its total, plus the software-type totals and the payload's notes.
  The hosted portal's credit balance, its subscription page and its per-user
  attribution are not ported: a correct local analogue of a credit is an action
  this workspace recorded, and there is no billing to attribute it to.

### 5. Analysis visibility, ownership and workspace scoping

- Portal: every analysis is Public or Private, chosen per file at upload and
  toggleable from the header; private is tier-gated and owner-scoped.  The
  analyses list has an Owner column, a Workspace filter (Personal, Team,
  Public), a lock icon per row, and owner-only actions.  Library analyses carry
  a System badge instead of the visibility toggle
  (`/documentation/analyses`, `/documentation/analysis-overview`,
  `/documentation/teams-and-access`).
- reportal: `binaries` and `collections` carry `visibility` (`public` or
  `team`) and `owner_team_id`; the API gate enforces them on every route by
  resolving the object a path names, the listings and the typed search filter
  their pages, and the bulk guard skips what the caller cannot reach.  With
  auth off this is labelling (the local operator sees everything); with it on
  it is access control.
- **Status:** Closed.  `binaries` and `collections` carry `visibility` and
  `owner_team_id`; the API gate enforces them on every route, the listings and
  the typed search filter their pages, and the bulk guard skips what the caller
  cannot reach.  The analyses listing now carries the scope with each row:
  `store.list_analyses(...)` also joins the owning team and reports
  `visibility`, `owner_team_id` and `owner_team_name`, and
  `?workspace=personal|team|public` (`store.WORKSPACE_FILTERS`) is the hosted
  portal's three controls read against the local model, where the owner team is
  the only ownership reportal stores: `personal` is an object no team owns,
  `team` one a team does, and `public` one the whole workspace may see.  The
  analyses list view draws Owner and Seen by columns and the workspace filter,
  which lives in the route hash with the other filters, so a filtered list is a
  link; `reportal analyses --workspace` and the read-only `list_analyses` MCP
  tool expose the same.  A per-analysis visibility toggle is deliberately not
  added: an analysis has no scope of its own, and the write already exists as
  `PATCH /api/binaries/<id>/scope` (`reportal binary-scope`), which is the object
  a team is stored on, so a second control would write the same row twice.  With
  auth off this is labelling and filtering, not access control, and
  `docs/THREAT_MODEL.md` says so.  The Library/System badge for a seeded example
  analysis stays out of scope: reportal seeds no example analyses, so there is
  no row to carry it.

### 6. Agent feedback and the Custom (MCP) onboarding card

- Portal: every agent card carries a regenerate button and thumbs up/down
  feedback on the result, and the Agents -> Custom tab shows the
  `claude mcp add` one-liner and the `~/.claude.json` snippet
  (`/documentation/analysis-agents`).
- reportal: the AI decompilation artifact carries an analyst rating
  (`PATCH /api/functions/<id>/ai-decompilation/rating`, `reportal ai-rate`, the
  `rate_ai_decompilation` MCP tool and the function detail's panel), so the
  rating primitive exists; the agent artifacts (triage, threat, capabilities,
  remediation) are stored and served but not rated, and the Integrations view
  lists its own registries rather than showing a client how to connect.
- Build: a rating on a stored agent artifact (one small table), and a "Connect
  an MCP client" card in `IntegrationsView` rendering the `reportal mcp`
  command and the client config JSON.
- Size: S.
- **Status:** Closed.  `ratings.py` is the one small table: a verdict is keyed
  by `(binary_id, kind)`, where the kind is one of the store's own scan kinds
  (read from the `SCAN_KIND_*` constants, so a kind added there is rateable the
  day it lands), and the artifact is the binary's stored scan of that kind, so a
  verdict survives a re-run of the scan.  A verdict is `up` or `down` with an
  optional note, an empty one clears it, and every write is journaled with the
  row it replaced snapshotted and the row it created journalled for deletion, so
  a revert restores the previous verdict whether the artifact was rated or not.
  `GET /api/binaries/<id>/ratings` lists every stored artifact with its verdict
  (an artifact that was never produced is left out; one that was produced and
  not rated carries a null rating), `GET`/`PUT .../ratings/<kind>` read and write
  one (400 `invalid rating`, 404 `no-artifact`), `reportal rate <binary-id>
  <kind> [up|down] [--note]` and `reportal ratings <binary-id>` are the CLI, the
  read-only `list_artifact_ratings` and destructive `rate_artifact` MCP tools
  expose the same, and the binary detail's Agent feedback panel carries Up, Down
  and Clear per stored artifact.  The AI decompilation artifact keeps its own
  rating inside its payload, because it is a function-scoped artifact rather
  than a binary's scan; nothing is duplicated.  The second half is the
  `IntegrationsView` "Connect an MCP client" card, which renders the
  `claude mcp add` one-liner and the `~/.claude.json` snippet with copy controls
  and reads the tool counts from `GET /api/config`, so the card cannot promise a
  registry the server does not have.

### 7. In-app documentation browser and changelog

- Portal: `/documentation` is a 12-page site with a sidebar, previous/next and
  an on-this-page table of contents (keyboard shortcuts, uploading binaries,
  browsing analyses, global search, analysis overview, functions, data types,
  match/diff, agents, memory, sandbox, teams and access).  `/changelog` is a
  weekly release feed.
- reportal: the same material exists as `docs/*.md` in the repository, but
  `ui.py` serves only the SPA and generated reports, so nothing in the app
  shows it, and there is no changelog surface.
- Build: `GET /api/docs` returning the shipped markdown (or pre-rendered HTML
  written by the Vite build), and a Documentation view plus a Changelog view
  over a `CHANGELOG.md`.  The SPA has no markdown renderer and no CDN, so the
  renderer is a small subset converter or a build-time step.
- Size: M.
- **Status:** Closed.  `docs.py` resolves the documents (`REPORTAL_DOCS`, then
  the workspace's `docs/`, then the checkout beside the package) and answers a
  page as blocks rather than markup: `GET /api/docs` for the index,
  `GET /api/docs/<slug>` for one page's title, its on-this-page headings and its
  blocks (headings, paragraphs, lists with each item's depth, fenced code,
  quotes and tables).  `reportal docs [<slug>]` and `reportal changelog` print
  the same, `list_docs` and `get_doc` are the two read-only MCP tools, and the
  SPA's Documentation view (`#/docs`, `#/docs/:slug`, `#/changelog`) renders the
  blocks with its own inline pass for links, code spans and emphasis, so no
  document text is injected as HTML and no markdown dependency is added.  The
  subset is the deliberate ceiling: a construct outside it becomes a paragraph,
  which is readable rather than lost.  `CHANGELOG.md` is new and holds 1.2.0
  (this backlog, closed) and 1.1.0.  A wheel with neither a workspace nor a
  checkout answers 404 `no-docs` rather than an empty page.  The hosted
  portal's per-page previous/next navigation shipped later: `docs.neighbours`
  reads the same `_page_files` order the index numbers, `docs.page` answers the
  pair beside the blocks (null at either end), and the view renders it as a
  pager at the foot of the body, so the index and the control cannot disagree.
  `reportal docs <slug>` names the next page and the `get_doc` tool carries the
  same pair.

### 8. Continuous whole-binary hex viewer (Memory)

- Portal: the Memory view is one scrollable hex dump of the whole binary, 16
  bytes per row, with Offset and Virtual columns, an ASCII column, zero bytes
  dimmed, `G` to focus "Go to address", Tab to toggle Offset/Virtual (remembered
  across sessions), section addresses in Binary Details that jump to and
  highlight their byte range, and drag-selection that copies space-separated hex
  from the Bytes column or the raw string from the ASCII column
  (`/documentation/analysis-memory`).
- reportal: `MemoryPanel` pages 256-byte windows (cap 4096) with a section
  select, go-to, previous/next and a copy control.  [PARITY.md](PARITY.md)
  claims the hosted whole-binary view is that panel; the continuous scroll, the
  Virtual column, drag selection and the click-through from the section table
  are the actual gap.
- Build: a virtualized continuous viewer over the existing section map, the
  offset/virtual mode, range selection with both copy forms, and clickable
  addresses in the sections panel.
- Size: M.
- **Status:** Closed.  The Memory panel's `Whole binary` mode is one scrollable
  dump in virtual-address order: the span comes from the engine's own section
  map, a region no section backs is the same stated `gap` row the paged view
  renders (never zeros), and only the rows on screen are rendered, so a large
  binary scrolls without loading whole.  The bytes arrive 256 at a time along
  the engine's `next` address as the viewport approaches a window.  The Columns
  control switches the virtual and file-offset readings (the file offset of an
  address is shown beside the virtual one), `G` focuses the address box and
  `Tab` switches the column, and the choice is remembered under
  `MEMORY_COLUMN_STORAGE_KEY`.  The section table's virtual-address cell is a
  `Link` into the dump, which lands on and selects that row, so a section and a
  byte range are one click apart.  Byte click and shift-click select a range,
  copied as space-separated hex, a C array or the raw ASCII.  Ceiling: the span
  is the section map, so a byte before the first section or past the last is not
  reachable; the paged mode's go-to covers an address the dump cannot name.  The
  panel and the dump are covered by `web/tests/memory-page.spec.ts` and the
  smoke's `check_memory_dump`, which asserts the link lands on the linked
  address and that `G` focuses the box.

### 9. Per-type provenance and list controls (Data types)

- Portal: each type carries a source badge (System, User, Auto Unstrip, AI) and
  the list opens with a provenance strip counting each source; the filter panel
  filters by kind, source and namespace; the list sorts by name or size with
  unknown sizes last; large binaries load types progressively with a progress
  counter; filters live in the address bar so a filtered view is a link
  (`/documentation/data-types`).
- reportal: the model has kind, namespace, size, members, enum values and
  history, with kind/namespace/search filters and a namespace tree.  There is
  no source on a type, no filter by source, no shareable filter URL and no
  progressive load.
- Build: record a `source` when a type is imported (`System` from the engine
  scan, `User` for edits, `Auto Unstrip`, `AI`), expose the breakdown and the
  filter, and move the filters into the route hash, the convention
  `AnalysesView` already uses.
- Size: M.
- **Status:** Closed.  A type row already carried a `source` (the structs scan,
  a manual create, the symbol import, a bulk declaration); what was missing was
  the vocabulary, the breakdown and the filter.
  `data_types.source_label` maps every stored source onto the portal's four
  labels through the explicit `SOURCE_MAP` (an undeclared source reads as
  `User`, and an `ai` prefix as `AI`), `SOURCE_LABELS` is the closed order the
  strip and the error details spell, and `source_totals` counts the whole model
  per label so a filter never hides what it is hiding.  `filter_types(...,
  source=...)` and `GET /api/binaries/<id>/data-types?source=` filter by it (an
  unknown label is 400 `invalid source`), the payload always carries `sources`,
  and `reportal types <binary-id> --source LABEL` and the `list_data_types` MCP
  tool (with a `source` enum) expose the same.  The SPA's Data types panel opens
  with a provenance strip (one button per label, carrying its count, each one a
  toggle), adds a Source filter beside the kind and search filters, and renders
  the list a page (`DATA_TYPE_PAGE`) at a time with a Load more control and a
  shown-of-matching counter.  The filters live in the route hash
  (`#/binaries/<id>?kind=&namespace=&search=&source=`), which is the convention
  the Analyses view already uses, so a filtered model is a link that survives a
  reload.  The sort shipped later, and the note that first closed this entry was
  wrong to say the hosted panel's size sort was not in the crawl's evidence: the
  data-types page the crawl captured documents it (`Sort — order by Name or
  Size`, with a type of unknown size last in either direction).
  `data_types.sort_types` orders by name or size, `GET
  /api/binaries/<id>/data-types` takes `?sort=name|size&direction=asc|desc`
  (400 `invalid sort`/`invalid direction`), `reportal types --sort/--direction`
  and the `list_data_types` tool take the same pair, and the panel carries the
  two selects in its route hash.  A type whose size the model states as zero
  (how `recompute` records an unknown base) sorts last in either direction, so
  it cannot claim the head of a descending list.

### 10. Analyses list: per-row actions, bulk mode, richer filters

- Portal: per-row three-dot menu (View Log, Download, Re-analyse, Delete), the
  owner's inline tag chips, an Order filter (Created, Name, Size, ascending or
  descending), a Platform filter with architecture, a multi-select Status
  filter, a Workspace filter, a clear-all control, Shift bulk mode with Copy
  Hashes, Add tag and Delete, a hand-set-versus-detected highlight with hover
  provenance, and open-in-new-tab on modifier click
  (`/documentation/analyses`).
- reportal: `AnalysesView` filters by status, order and free text through the
  route hash; `BinariesView` has bulk tag and delete.  Missing: platform and
  architecture filters, workspace filter, multiple statuses, per-row actions,
  copy-hashes, inline row tag editing.
- Build: extend `GET /api/analyses` with the platform, architecture and
  workspace filters and multi-status, add the row menu (download exists,
  re-analyse needs cluster D's stored parameters) and the bulk toolbar.
- Size: M.
- **Status:** Closed.  `GET /api/analyses` takes `?status=` repeated (any-of),
  `?platform=` and `?arch=` against the stored binary's own `format`/`arch`, and
  the six `ANALYSIS_ORDERS` (`newest`, `oldest`, `name`, `name-desc`, `size`,
  `size-desc`), so the SPA's Order control covers the hosted one; the payload
  answers the `platforms` and `architectures` the register actually holds, so
  each filter lists only real choices.  `reportal analyses` takes the same
  (`--status` repeats, `--platform`, `--arch`, `--order`).  The Analyses view
  carries a status chip per state (any-of, and the last one off means any), the
  two selects, a `Clear` control, a per-row `View log` / `Re-analyse` (the
  cluster D requeue) / `Delete`, and `Copy hashes` in the bulk toolbar beside
  Add tag, Remove tag and Delete.  The hosted inline tag chips shipped later:
  each row's tag cell is an editor (a chip with a remove control per tag plus an
  add field) posting the whole set through `PATCH /api/analyses/<id>/tags`, so
  the list and the binary's own Tags panel write the same row.  Gap, stated
  rather than built: the hosted three-dot menu is not built, because its four
  actions (View Log, Download, Re-analyse, Delete) are the buttons in the
  Actions column, and the tag cell was the piece that carried information the
  other surfaces did not.  Covered by `TestAnalysisFilters`, the CLI's filter
  cases and the Analyses e2e.

### 11. Upload panel: drag and drop, per-entry reporting and extraction in place

- Portal: one drop zone for binaries, firmware and archives, files upload in
  parallel with a live in-flight counter, duplicate hashes are dropped with a
  banner, an over-limit file becomes an "Upload errors" row naming the tier's
  maximum, and each row is configured on its own (Analysis: Visibility,
  Platform, ISA, File Format, Tags, Debug Symbols; Dynamic Execution: sandbox,
  arguments, start method, timeout, supplementary archive) with a Configure all
  control and a dashed Auto badge until something is changed.  The Extract
  dialog takes a password and reports how many files were recovered
  (`/documentation/upload-binaries`).
- reportal: the batch path already exists.  `POST /api/binaries` takes repeated
  `file` parts with an entry per part (`name`, `tags`, `collection_ids`,
  `format`/`arch`), answers per-entry `duplicate`/`errors`, and journals the
  whole request as one action; `BinariesView` uploads several files with tags
  and a collection; `reportal extract` unpacks a stored archive with a password
  and a target collection.
- Build: only the panel conveniences are missing, and the payload already
  carries what they need: drag and drop, the in-flight counter, a duplicate and
  error banner over the existing per-entry fields, and an Extract action on the
  upload surface.  The per-file settings with no local meaning (model choice,
  tier-gated visibility, sandbox) are not built; debug symbols is entry 1.
- Size: S.
- **Status:** Closed.  The upload panel gained a dashed drop zone (`Drop
  binaries, firmware images or archives here`) that queues whatever is dropped,
  an in-flight line while the batch posts, a `Configure all` pair of selects
  that applies a Format and an ISA to every queued row at once, and a `Plan`
  column whose `auto` badge a row keeps until something changes it (the hosted
  portal's dashed Auto badge).  The result list opens with a duplicate banner
  and an error banner above the per-entry rows that already named each cause.
  A new `Extract an archive` panel unpacks a stored archive in place: pick the
  archive, a collection (else one named after it) and a password, and the
  members come back with the binary each became or the reason it was skipped,
  with the one journal action that reverts the whole extraction linked.  The
  hosted per-file Analysis and Dynamic Execution settings that have no local
  meaning (model choice, tier-gated visibility, sandbox arguments) are
  deliberately not built and are stated as the gap.  Covered by the upload
  batch e2e, whose drop-zone case drives a real `DragEvent`.

### 12. Keyboard layer: history, collapse, section cycling and per-view bindings

- Portal (`/documentation/keyboard-shortcuts`): `Cmd/Ctrl+K` search,
  `Cmd/Ctrl+B` collapse the sidebar, single letters per analysis section (O, F,
  D, T, S, A, M), `[` and `]` to cycle sections, `{` `}` or Alt+Left/Right for a
  back/forward history stack of sections and functions, `J`/`K` and
  Shift+`J`/Shift+`K` to step items and content, `/` to focus search, `P` for
  the filters panel, `R` to rename, Space to toggle Disassembly/Control Flow in
  Functions and Disassembly/AI Decompilation in Match/Diff, `G` for the memory
  go-to, `Cmd/Ctrl+Enter` to save an edited type, Esc to discard, `?` for the
  cheatsheet.
- reportal: `web/src/keys.ts` registers the view jumps, table row movement, `/`
  filter focus, Esc and the `?` cheatsheet.  [PARITY.md](PARITY.md) already
  records that there is no sidebar collapse, in-app history control or
  focused-row model to bind.
- Build: a sidebar collapse preference (`Cmd/Ctrl+B`), a router-backed history
  stack, and a selected-row or selected-pane model per view that let the `P`,
  `R`, `Space`, `G` and `Cmd/Ctrl+Enter` bindings exist at all.
- Size: M.
- **Status:** Closed for the collapse, the history stack, section cycling and
  the code-view switch.  `Cmd/Ctrl+B` collapses the sidebar to a 64px rail
  (labels and links go, the section dots stay) and the preference is remembered
  under `SIDEBAR_STORAGE_KEY`; a first-of-its-kind control in the brand row is
  the same toggle for a pointer.  `Alt+Left`/`Alt+Right` step a per-tab view
  history kept in `sessionStorage` under `HISTORY_STORAGE_KEY` (fifty entries,
  and `stepHistory` marks the navigation so recording does not push the entry
  the reader just left); the router's own back and forward still work beside it.
  `[` and `]` scroll to the previous and next panel, and `Space` flips a
  function's Disassembly and Control flow through `toggleFunctionCodeView`,
  which the mounted `CodeSection` publishes.  The cheatsheet renders all of it
  from the live registry.  A real defect found while closing this entry is fixed
  with it: `FunctionsView`'s drafts effect depended on the `filters.strings`
  array, which `filtersFromQuery` rebuilds every render, so the view re-rendered
  forever and the router never processed the next location.  Leaving
  `#/functions` for any other view left the shell stuck on Functions with the
  URL changed; the effect now keys on a stable string, and
  `web/tests/navigation.spec.ts` covers it.  Gaps, stated rather than built: the
  `P` (filters panel), `R` (rename) and `Cmd/Ctrl+Enter` (save a type) bindings
  need a per-view selection model reportal does not have, and `G` belongs to the
  memory dump's own address box.

### 13. Regular-expression and multi-value string search

- Portal: "Search strings using regular expressions" (changelog, week of 13 Jul
  2026) and the Functions string filter holds several strings at once, matching
  functions that contain any of them, each removable on its own (week of 29 Jun
  2026).
- reportal: `store.search` and the function list are literal `LIKE` queries with
  the wildcards escaped, and a filter carries one `string` value
  (`web/src/views/FunctionsView.tsx`).
- Build: an opt-in `regex` flag on the typed search and the function-list string
  filter, compiled with a bounded pattern and a compiled-pattern cache, a bad
  pattern answered 400, plus repeated `string` values combined as any-of.  This
  is a query change; the secrets and strings scans stay fixed pattern tables.
- Size: S.
- **Status:** Closed.  `store.search(..., regex=True)` matches the query as a
  regular expression instead of a substring and `store.list_functions(strings=[...],
  regex=...)` combines several needles as any-of.  A pattern goes through
  `store.compile_regex`, which caps it at `MAX_REGEX_CHARS`, caches the compiled
  form (`REGEX_CACHE_SIZE`), and raises `SearchError("invalid regex", ...)` for
  one that does not compile, so `GET /api/search?q=&regex=true` and a function
  filter answer 400 `invalid regex`; `store.register_regexp` installs the SQL
  `REGEXP` function (SQLite has no engine of its own), which is what lets the
  match stay in the query rather than in Python over every row.  The `sha256`
  kind refuses a pattern because a hash prefix is a literal by definition.  The
  function filter repeats the `string` parameter (at most
  `api.MAX_FUNCTION_STRINGS` values, each with its own Remove control in the
  SPA, carried in the hash one per line so a needle may contain any character),
  and `reportal search <query> [--kind K] [--regex]` plus the CLI's JSON form is
  the new command-line face of the typed search, which the CLI did not have at
  all.  `GET /api/search`, the `search` and `list_functions` MCP tools (the
  latter gaining `strings` and `regex`) and the SPA's Search regex toggle and
  Functions string chips expose the same.  A ceiling is stated rather than
  hidden: Python's `re` cannot be interrupted once a match is running, so a
  pathological pattern costs what it costs; the pattern length is what is
  bounded.

### 14. Notifications

- Portal: a notification centre with per-item dismissal and a dismiss-all
  (changelog, week of 29 Jun 2026).
- reportal: nothing.  A finished engine run, a failed scan or a revert is only
  visible by opening the Journal view.
- Build: derive the feed rather than store it, from the journal and the analysis
  log (`GET /api/notifications?since=`), with a topbar bell; dismissal lives in
  the browser unless it has to persist, in which case one small table.
- Size: S.
- **Status:** Closed, derived and unstored.  `notifications.feed` normalizes one
  item per journaled action (with its status, row count and whether it is still
  revertible) and one per analysis-log entry (with its severity and its binary)
  into one newest-first page with the true total and an inclusive `since`;
  `GET /api/notifications` (400 `invalid since`/`invalid limit`/`invalid
  sources`), `reportal notifications [--since] [--limit]`, the read-only
  `list_notifications` MCP tool and the topbar bell with per-item and dismiss-all
  controls over a localStorage set cover it.  Nothing is stored, which is the
  point: there is no second writer to drift from the journal and the log.

### 15. Composition scoping and the hosted category taxonomy

- Portal: a composition search can be limited to chosen collections or binaries
  and the page groups results into malware, debug, unique and library, each
  surfacing the binaries with the most overlap (changelog, weeks of 20 Jul and
  13 Jul 2026).
- reportal: `composition.compute_composition` reads every stored match edge for
  one binary and reports the five name-source buckets and five quality bands.
  It takes no scope, and the hosted category names do not appear.
- Build: accept `binary_ids` and `collection_ids` through the vocabulary
  `matching.resolve_scope` already validates, record the scope on the stored
  `composition` scan, and add the hosted categories as a second grouping beside
  the existing buckets with a per-category top-binary list.
- Size: M.
- **Status:** Closed.  `composition.compute_composition` and `run_composition`
  take `binary_ids` and `collection_ids`, resolved through
  `matching.resolve_scope`, so a scoped composition reads exactly the edges a
  scoped `reportal match` would have written; an id no row carries raises
  `InvalidSettingsError`, which the route answers 400 (`unknown binary` /
  `unknown collection`), the CLI fails on and the `run_composition` tool returns
  as a tool error.  The payload carries a `scope` block (the named ids and how
  many candidate binaries they resolved to) and the stored scan records it, so a
  later reader can tell a scoped scan from a whole-register one.  The hosted
  categories are a second grouping beside the name-source buckets and the
  quality bands: `malware` (matched another binary), `debug` (no match and a
  placeholder name), `unique` (no match and a real name) and `library` (a name
  an import stub, the engine or an ingested symbol file supplied), each with its
  count, percent and top five binaries, plus a `category_notes` line stating
  that reportal matches by assembly similarity and holds no family feed, so
  `malware` is a match rather than a verdict.  `POST
  /api/binaries/<id>/composition` takes the scope in its body, `reportal
  composition <id> --binary-id/--collection-id` takes it as options, the
  `run_composition` tool takes it as arguments, and the SPA panel has the two
  comma-separated scope fields beside Run analysis and a Categories table.
  Ceiling: the categories are derived from stored rows only, so a function whose
  name came from a symbol file and also matched another binary counts as
  library, which is the hosted reading.  Covered by `TestCategories`,
  `TestCompositionScope` and `TestCompositionScopeSurfaces`.

### 16. An assistant that answers questions about reportal itself

- Portal: the AI chat assistant answers questions about RevEng.AI and its
  integrations from the product documentation (changelog, week of 27 Jul 2026),
  and its panel offers a prompt library that changes with the page context
  (analysis prompts, collection prompts and general ones, 6 to 13 depending on
  where it is opened).
- reportal: `conversations.py` scopes a chat to one stored function or binary.
  There is no product-documentation scope, although `knowledge.py` already
  ingests documents and retrieves from them.
- Build: a `docs` conversation scope that ingests the shipped `docs/*.md` on
  first use and answers through `knowledge.retrieve` and `as_context`, and a
  short canned-prompt list per scope in `ConversationsView`.  Off unless the LLM
  bridge is configured, like every other AI path.
- Size: S.
- **Status:** Closed.  `conversations.SCOPE_KIND_DOCS` is the third conversation
  scope: `POST /api/conversations` with `{"scope_kind": "docs"}` (its
  `scope_id` is carried for the row and never matched), the same over the
  `create_conversation` MCP tool, and the scope select in the Conversations
  view.  `docs.excerpts()` hands every page to `knowledge.ingest_document` under
  the `docs` knowledge scope on the first question, deduped by content hash so a
  later question only queries, and the answer is assembled from the chunks
  `knowledge.retrieve` ranks plus a base block naming the release.  The
  context's own base text says the manual is the source, so a model that is
  asked about a version has one to cite.  `SCOPE_PROMPTS` in the Conversations
  view adds the canned openers per scope (manual, binary, function); every
  opener names something its scope can actually answer.  Ceiling: the ranking is
  the local TF-IDF one unless an embeddings endpoint is configured, so a keyword
  query ranks best; the hosted portal's assistant is tool-calling and this one
  is not, which is cluster L's agent, a separate surface.

### 17. Collections list controls

- Portal: the collections page filters by Personal, Team and Public and shows
  the owner and the last update, sortable by owner (changelog, weeks of 20 Jul
  and 13 Jul 2026).
- reportal: `CollectionsView` lists collections with their members and tags.
  There is no sort control and, with one local user, no owner or scope column.
- Build: a sort control (name, size, updated).  The scope filter arrives with
  cluster F's identity, and the AI-model link the portal dropped has no local
  equivalent.
- Size: S.
- **Status:** Closed.  `collections.updated_at` records the last field,
  membership or tag change (`touch_collection`, backfilled from `created_at`
  for a database that predates the column), `list_collections(order=...)`
  accepts `id`/`name`/`size`/`updated`/`owner`, `GET /api/collections?order=`
  echoes the order it applied and answers 400 `invalid order` for an unknown one,
  `reportal collections --order` and the `list_collections` MCP tool expose the
  same, and the Collections view carries the Sort control.  The scope half
  shipped with cluster F's identity: `list_collections(workspace=...)` reads a
  collection's own scope (`personal` is one no team owns, `team` one a team does,
  `public` one the whole workspace may see), each row carries `visibility`,
  `owner_team_id` and `owner_team_name`, `GET /api/collections?workspace=`
  answers 400 `invalid workspace` for an unknown value and echoes the filter,
  `reportal collections --workspace` and the `list_collections` tool take it, and
  the Collections view carries the Workspace control and an Owner column.  The
  view's sort and scope live in the route hash (`#/collections?order=&workspace=`),
  so a filtered list is a link, and the two controls cover the hosted page's
  Personal/Team/Public filter, its owner column and its sort.  The AI-model link
  the hosted page dropped has no local equivalent.

## Open clusters from PARITY.md

These are already specified there; the entry above is the pointer, the gap
description lives in that file.

| Cluster | What it is | Status |
|---------|------------|--------|
| A | Asynchronous operation workflow (jobs, status, cancel, progress, SSE) | Closed in PARITY.md |
| B | AI decompilation as a first-class artifact (tokens, per-line comments, attributions, rating) | Closed in PARITY.md |
| C | Dynamic execution and sandbox detonation (the opt-in runner and the firmware carve) | Closed in PARITY.md |
| D | Analysis lifecycle (basic, params, requeue, bytes, tags, bulk, imported functions) | Closed in PARITY.md (example analyses is not applicable locally) |
| F | Users, auth and IAM (roles, permissions, teams, scope, activity, feedback) | Closed in PARITY.md |
| G | Models (registry, model per artifact, upgrade) | Closed in PARITY.md |
| H | External sources (VirusTotal), now with the team key in entry 3 | Closed in PARITY.md |
| J | Function-level extras (indirect call sites, capabilities, strings, user strings) | Closed in PARITY.md |
| K | Data types and signatures bulk operations | Closed in PARITY.md |
| L | Agentic conversations (tool loop, SSE, cancel, confirm) | Closed in PARITY.md |
| M | Reports as an asynchronous job | Closed in PARITY.md |

Closed in PARITY.md and not reopened here: E (collections), I (config), N
(binary extras).

## Confirmed already covered by the crawl

Checked against the live UI and not a gap, so a later round does not re-open
them: example analyses (`/v3/analyses/examples`), per-analysis tags
(`/v2/analyses/{id}/tags`), imported functions
(`/v3/analyses/{id}/imported-functions`), the analysis log with severity
badges, DIE info, related binaries and additional details
(`/v2/binaries/{id}/die-info`, `/related`, `/additional-details`), auto-unstrip
status, per-function strings and capabilities, the four typed global search
query kinds, the `?` cheatsheet, the analysis tag chips in the SPA.

## Deliberately not applicable locally

Recorded so the list does not grow into a clone of a hosted service: single
sign-on against an external OIDC identity provider with DNS domain verification,
the hosted VirusTotal feed, cross-architecture matching and hosted model
availability.

Three entries that used to be here are now shipped and recorded in PARITY.md
instead: the sandbox detonation (cluster C: off by default, a runner must be
installed, capped, unnetworked and recorded), firmware extraction (the carve
and the region extraction; a squashfs or UBI inode reader is deliberately not
written), and billing with subscription tiers (`plans.py`, `metering.py`,
`billing.py` and the `/pricing` page: off by default, so a self-hosted install
is unmetered and unchanged).  Prepaid credits stay out: the model here is a
monthly allowance with an overage, not a balance to draw down, and a credit
ledger would be a second accounting system beside the one in `usage_events`.
PCAP capture stays out of scope: reportal runs no network capture and its
sandbox has no route at all.

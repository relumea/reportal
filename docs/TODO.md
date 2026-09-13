# reportal todo

The running backlog.  One entry per thing reportal does not have yet, with the
evidence that it is a real hosted surface, what reportal has today, and the
local shape to build.

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

### 2. Teams, organisations and roles

- Portal: the team is the ownership unit.  Members see and work on the team's
  binaries; team admins add, remove and promote members and rename the team.
  A user can belong to several teams and switch the active one.  Teams sit
  inside organisations, owned by organisation owners, with groups (org-level
  teams carrying their own credits)
  (`/documentation/teams-and-access`).  Endpoints absent from the public spec:
  `GET /v2/iam/teams`, `GET /v2/iam/teams/{id}`, `GET
  /v2/iam/teams/{id}/members`, `GET /v2/iam/organisations`.
- reportal: single user, no identity.  [PARITY.md](PARITY.md) cluster F plans
  users, roles and per-object scoping, but not the team-as-owner model, team
  switching, organisations or groups.
- Build: `teams`, `team_members` and `organisations` tables, a team scope on
  binaries, analyses and collections, an active-team setting, and team roles
  (admin/member) on the write paths.  No billing, no external IdP.
- Size: L.

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

### 5. Analysis visibility, ownership and workspace scoping

- Portal: every analysis is Public or Private, chosen per file at upload and
  toggleable from the header; private is tier-gated and owner-scoped.  The
  analyses list has an Owner column, a Workspace filter (Personal, Team,
  Public), a lock icon per row, and owner-only actions.  Library analyses carry
  a System badge instead of the visibility toggle
  (`/documentation/analyses`, `/documentation/analysis-overview`,
  `/documentation/teams-and-access`).
- reportal: single-user, every row is equally visible.  Cluster D already plans
  the examples read (`/v3/analyses/examples`); visibility is not in it.
- Build: a `visibility` and `owner` on analyses and collections, a workspace
  filter on the list routes, and an examples flag with a System badge.  With
  one local user this is labelling and filtering, not access control, and the
  docs must say so.  Shares cluster F's identity work.
- Size: S once F lands.

### 6. Agent feedback and the Custom (MCP) onboarding card

- Portal: every agent card carries a regenerate button and thumbs up/down
  feedback on the result, and the Agents -> Custom tab shows the
  `claude mcp add` one-liner and the `~/.claude.json` snippet
  (`/documentation/analysis-agents`).
- reportal: agent artifacts (triage, threat, capabilities, remediation) are
  stored and served, but nothing records a rating, and the Integrations view
  lists its own registries rather than showing a client how to connect.
- Build: a rating on a stored agent artifact (one small table), and a "Connect
  an MCP client" card in `IntegrationsView` rendering the `reportal mcp`
  command and the client config JSON.
- Size: S.

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

### 14. Notifications

- Portal: a notification centre with per-item dismissal and a dismiss-all
  (changelog, week of 29 Jun 2026).
- reportal: nothing.  A finished engine run, a failed scan or a revert is only
  visible by opening the Journal view.
- Build: derive the feed rather than store it, from the journal and the analysis
  log (`GET /api/notifications?since=`), with a topbar bell; dismissal lives in
  the browser unless it has to persist, in which case one small table.
- Size: S.

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

### 16. An assistant that answers questions about reportal itself

- Portal: the AI chat assistant answers questions about RevEng.AI and its
  integrations from the product documentation (changelog, week of 27 Jul 2026).
- reportal: `conversations.py` scopes a chat to one stored function or binary.
  There is no product-documentation scope, although `knowledge.py` already
  ingests documents and retrieves from them.
- Build: a `docs` conversation scope that ingests the shipped `docs/*.md` on
  first use and answers through `knowledge.retrieve` and `as_context`.  Off
  unless the LLM bridge is configured, like every other AI path.
- Size: S.

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

## Open clusters from PARITY.md

These are already specified there; the entry above is the pointer, the gap
description lives in that file.

| Cluster | What it is | Status |
|---------|------------|--------|
| A | Asynchronous operation workflow (jobs, status, cancel, progress, SSE) | Planned |
| B | AI decompilation as a first-class artifact (tokens, per-line comments, attributions, rating) | Planned |
| C | Dynamic execution and sandbox detonation | Planned |
| D | Analysis lifecycle (basic, params, requeue, examples, bytes, tags, bulk, imported functions) | Planned, partly planned elsewhere |
| F | Users, auth and IAM (roles, permissions, activity, feedback) | Planned, extended by entry 2 |
| G | Models (registry, model per artifact, upgrade) | Planned |
| H | External sources (VirusTotal), now with the team key in entry 3 | Planned |
| J | Function-level extras (indirect call sites, capabilities, strings, user strings) | Planned |
| K | Data types and signatures bulk operations | Planned |
| L | Agentic conversations (tool loop, SSE, cancel, confirm) | Planned |
| M | Reports as an asynchronous job | Planned |

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

Recorded so the list does not grow into a clone of a hosted service: malware
sandbox and PCAP capture (cluster C, a trust-boundary change, not a feature
gap), billing, credits and subscription tiers, single sign-on against an
external OIDC identity provider with DNS domain verification, the hosted
VirusTotal feed, firmware extraction (planned separately in PARITY.md),
cross-architecture matching and hosted model availability.

# SPA

*Reference material moved out of AGENTS.md.*

The frontend is a Vite + React + TypeScript app in `web/`, built with bun into
`src/reportal/assets/dist/` (generated, gitignored).  `ui.py` serves that
directory: `GET /` returns its `index.html` and `GET /static/<path>` its hashed
assets, with `base: "/static/"` set in `vite.config.ts`.  A checkout with no
build answers `GET /` with 503
`{"error": "ui-not-built", "detail": "run 'bun install && bun run build' in web/"}`
instead of a broken page.  The build step is the accepted tradeoff for a
UI-heavy portal; package-data still ships only `assets/*`, so packaging the
built UI is a follow-up.

### What loads when

Every view but the dashboard is a `React.lazy` import in `App.tsx`, so the
browser parses the shell, the dashboard and the shortcut layer on the first
paint and fetches a view's code when its route is opened.  The binary detail is
the reason this matters: its panels, the memory dump and the data type editor
are a third of the SPA's source, and they are one chunk (113 kB) that no other
route pays for.  React and the router are one `vendor` chunk
(`vite.config.ts`, `build.rollupOptions.output.manualChunks`), which a browser
keeps across a deploy while the per-view chunks change.  Two imports stay
static on purpose: the dashboard, because it is the landing route, and
`FunctionPanels`, because the shell's `Space` binding is its module state (a
lazy import there would move the binding out of the registry the cheatsheet
reads).  A `<Suspense>` boundary around the route content shows the shell's
`Loading` line while a view's chunk arrives.

`GET /` answers the entry page `no-cache` (so a deploy is picked up on the
next load) and the hashed bundles under `/static/assets/` `immutable` with a
one-year `max-age`: their names carry their content hash, so a repeat load makes
no request for them at all.  A file without a hash (the favicon) is answered
`no-cache` like the shell.

The measurement that matters is the initial payload: before the split the SPA
was one 617 kB (172 kB gzip) bundle that every route parsed; now the entry is
77 kB (22 kB gzip) and the vendor chunk 289 kB (91 kB gzip), with 25 view
chunks behind them.  `tools/smoke_spa.py` asserts the split rather than trusting
it: the entry chunk must not carry a marker only the binary detail view renders,
and some other chunk must, so a view import that goes back to being static
fails the gate.

### Long tables

A table carries `windowed` when its list is the stored rows themselves rather
than a reading the server already bounded, which is the Functions list and the
Matches list: `DataTable` then renders only the rows in view, with a spacer row
above and below carrying the height of the rows it left out, `WINDOW_OVERSCAN`
(20) extra rows on either side and a `WINDOW_THRESHOLD` of 200 below which it
renders everything.  It measures the first row's height (a `useLayoutEffect`,
re-measured on resize through a `ResizeObserver`) and multiplies, so the height
is assumed rather than measured per row: a table whose rows differ in height (a
cell that wraps at a narrow width) would drift.  That is why this is a prop per
table and not the default, and why the tables whose rows carry blocks rather
than one line of cells stay un-windowed.

Measured in headless Chrome at 1440x900 over a seeded workspace, 20,000
functions on `#/functions` cost 3,751 ms to the first row, 20,000 DOM rows,
320,150 nodes and 106.5 MB of JS heap before the window, and 453 ms, 57 rows,
1,048 nodes and 10.3 MB after.  The matches table with 25,000 stored rows on
`#/matches` cost 6,441 ms, 25,000 rows, 400,128 nodes and 127.4 MB before, and
311 ms, 53 rows, 962 nodes and 13.1 MB after.  The API time is not what changed
(66 ms for the 20,000 functions, 145 ms for the 25,000 matches): a windowed
table pays for the payload and the fetch, and no longer for the DOM.

`src/main.tsx` mounts `QueryClientProvider` and `HashRouter` around
`src/App.tsx`, the shell: a grouped sidebar (`NAV_GROUPS` in `src/router.ts`:
Overview, Targets, Analysis, Agent, System; the System group ends with Jobs,
Journal, Components, Integrations, Users and Docs), a topbar title and the health line.
Routing is react-router's: `App` holds one route table, `useRoutes` renders it,
and the same table is matched against the location for the topbar title and the
sidebar's active section, so no path is written down twice.  Every view is
composed from the primitives in `src/components.tsx` (Panel, Toolbar, Button,
ConfirmButton, Badge, Field, EmptyState, Loading, ErrorNote, Note, CodeBlock,
KeyValue, DataTable) over the token layer in `src/styles.css`.  `src/api.ts` is
the typed fetch wrapper: JSON in and out, `FormData` for the binary upload, and
an `ApiError` carrying `error`/`detail` from a non-2xx body.  `api.ts` also
owns the bearer token: `storedToken`/`storeToken` read and write
`localStorage["reportal.token"]` (`TOKEN_STORAGE_KEY`) and every request carries
`Authorization: Bearer <token>` when one is stored, so an authenticated install
works from the browser without a cookie or a session.
`src/useAsync.ts` is a view's query over react-query (a per-instance key plus
the caller's dependencies) and `src/panelCache.ts` is the panels' shared one,
keyed by request identity, so a panel loaded once is reused when a view unmounts
and mounts again; a successful journal revert drops every panel through
`clearPanels`, since its undo plan can touch any scoped row.  `PanelBody` renders a skeleton
while a panel is loading, the empty state
for a stored-only GET that answered `no-scan`, or the error name and detail
with a retry.  Heavy engine work never runs on render: stored scans load
automatically and the run controls POST explicitly.

The shell's own bindings (`src/App.tsx`) are the sidebar collapse
(`Cmd/Ctrl+B`, a 64px rail whose preference is `SIDEBAR_STORAGE_KEY`), the
per-tab view history on `Alt+Left`/`Alt+Right` (`HISTORY_STORAGE_KEY` in
`sessionStorage`, fifty entries), `[`/`]` section cycling
(`keys.cycleViewSection`) and `Space` flipping a function's Disassembly and
Control flow view (`toggleFunctionCodeView`, which the mounted `CodeSection`
publishes).  The router's own back and forward keep working beside the in-app
history, and `stepHistory` marks its navigation so recording does not push the
entry the reader just left.

`src/keys.ts` is the SPA's keyboard layer.  Every shortcut is one registry entry
(`combo`, `scope`, `description`, `handler`): `registerShortcut` refuses a combo
twice in one scope, a `view`-scoped binding outranks a `global` one, `mod` is
Command on a Mac and Control elsewhere, and a sequence combo (`g d`) keeps its
prefix armed for `PREFIX_TIMEOUT_MS`.  Two rules are unconditional: a binding
never fires while the focus owns text (`isTypingTarget` in
`src/views/SearchModal.tsx`) and none fires while a modal dialog owns the
keyboard.  `focusViewFilter` focuses the view's filter box (the first
`input[type="search"]` in the content area) and `moveTableRow` walks the
tabbable rows of the view's first data table; `displayCombo` spells a combo for
the platform.

`src/App.tsx` registers the shell's bindings and installs the layer once:
`mod+k` (the global search modal), `?` (the cheatsheet), one `g <key>` jump per
sidebar view, and the `view`-scoped `j`, `k` and `/`.
`src/views/CheatsheetDialog.tsx` renders the live registry grouped by scope, so
the documented set cannot drift from the registered one; it takes the focus on
open, traps Tab, closes on Escape and returns the focus it took.  No binding
exists for a control that does not: the shell has no sidebar collapse, no
history control and no focused-row model beyond a table's tabbable rows, so
those keys are not registered at all.

`src/views/SearchModal.tsx` is the global search modal the `⌘K` binding opens,
and `src/views/SearchResults.tsx` is the shared hit model both the modal and the
Search view build from: `searchHits` flattens the response, `hitHref`/`hitTitle`
are the one place a hit becomes a destination and a name, and `SearchHitRow`
renders one keyboard-navigable row.  The modal traps focus while open (Tab
cycles the query type rather than leaving the dialog, and a `focusin` listener
pulls focus back), moves a roving highlight with the arrow keys, opens the
highlighted hit with Enter or a click and returns focus to where it was on
Escape; the Search view keeps its three-group tables, which is why the two
surfaces share the hit model and helpers rather than a single component.

Below 900px the shell is one column: the sidebar becomes a sticky top bar and
its nav keeps every group label and divider in a single horizontally scrollable
strip, so the grouped information architecture survives at narrow widths.  The
`src/styles.css` token layer carries the contrast contract: every 11-12px label
clears 4.5:1 and every badge ink clears 4.5:1 over its soft fill on both
`--surface` and `--surface-2` in both themes; `tools/audit_ui.py` measures the
rendered result.

### Instrument design language

The SPA is an instrument, not a report; the language comes from
`~/Desktop/tmog/DESIGN_RULES.md`.  A change that touches colour, a badge, a
metric or the dashboard follows these names:

- **Hue families** (`src/styles.css`): `--hue-match`, `--hue-near`,
  `--hue-stub`, `--hue-thunk`, `--hue-fail`, `--hue-live`, each with a `-soft`
  fill and a `-line` border tint.  Setting `data-hue="match"` (any family) on a
  container exposes them as `--hue-ink/-soft/-line` to its subtree, so a panel,
  its card border and the badges inside it share one hue.
- **Status ink** (`--st-exact`, `--st-reloc`, `--st-proven`, `--st-thunk`,
  `--st-near`, `--st-stub`, `--st-idle`, `--st-live`, `--st-fail`): the entity
  behind `Badge entity={...}` / `StatusCell`; `src/design.ts`
  (`statusEntity`) folds a reported status onto one, and an unlisted status
  stays neutral.
- **Confidence** (`--conf-high/-medium/-low`, `--conf-soft`) and **severity**
  (`--sev-high/-medium/-low`, `--sev-soft`): one hue each, three intensities,
  behind `ConfidenceBadge` / `SeverityBadge`.
- **The magnitude ramp** `--ramp-1 .. --ramp-5` (cold to matched) is the only
  sequential ramp; coverage and progress meters use it and nothing else.
- **Primitives** (`src/components.tsx`): `SegmentMeter` (quantized segments,
  unlit remainder visible, fixed-position readout, a faint reference grid,
  `value={null}` renders the explicit missing state, an optional `band`
  fraction range marked along the track bottom), `Readout` (a headline
  number with its label and unit), and `NA` / `UNAVAILABLE` for the missing
  states.  `Panel`/`Card` take `hue` and `className`; `DataTable` takes
  `rowClassName`.
- **Live edge** (`src/useAsync.ts`, `src/live.ts`): a poll is the query's own
  interval, so its rate lives beside the signal it follows (`useAsync`'s fourth
  argument, a number or a function of the data that stops when the run settles),
  and `useChangedIds` is the change flash (`FLASH_MS`, the same duration as
  `--flash-duration`).  Both are inert under `prefers-reduced-motion: reduce`,
  which turns the flash and the live glow off rather than shortening them.
- **Geometry** (`src/design.ts`): `METER_SEGMENTS`, `RAMP_STEPS`, `FLASH_MS`,
  `ENTROPY_MAX` and `PACKED_ENTROPY_THRESHOLD` (the entropy scale the packer
  card marks).  Every threshold and interval is a named module constant.

The Integrations view (`views/IntegrationsView.tsx`, `#/components` and
`#/integrations`) reads `GET /api/integrations` for every plugin seam and its
parts, and ends with an Instance card from `GET /api/config`: the version, the
engine's availability and origin, its decompiler backends, the LLM bridge's
state and model, the database's table count, the feature flags and the MCP tool
counts, over the table of every cap the server enforces.

Hash routes: `#/` (dashboard), `#/binaries`, `#/binaries/<id>`,
`#/binaries/<id>/functions` (the functions list filtered to that binary),
`#/functions`, `#/functions/<id>`, `#/diff/<id>/<candidate-id>`, `#/matches`,
`#/analyses`, `#/auto`, `#/auto/<id>`, `#/collections`, `#/conversations`,
`#/conversations/<id>`, `#/knowledge`, `#/graph`, `#/components`, `#/journal`,
`#/journal/<action>` and `#/search`.  A route may carry a hash query
(`#/analyses?status=failed`, `#/binaries/<id>/functions?sort=size&order=desc`):
`router.parseQuery`/`formatQuery` turn it into `RouteState.query`, which the
list views read as their filter state.
Every route is served by the JSON API above.

The Dashboard view (`src/views/DashboardView.tsx`) is the cockpit landing page,
built from existing endpoints only: the row counts from `GET /api/health` with
the aggregate coverage meter, one row per binary with its segmented match meter
and status chips, the live auto-run card (progress meter plus current task), the
per-section meters of the focused binary, the newest `GET /api/journal` entries
and the quick-link strip.  Matched counts and latest auto runs need one request
per binary, so the view enriches the first `SUMMARY_CAP` binaries; the stored
PE details and coverage report are two more requests each, so only the first
`SECTION_CAP` binaries carry the section and byte meters, and the view states
both caps.  Live signals poll at their own rate (health 2s, the running
binary's run 1s and its functions 4s, the journal 5s) and a changed row, card or
readout flashes and fades.

The Binaries view carries the batch upload control: a multiple file input, a
collection picker and a selected-files table with one row per file (name,
a chip tag control, a Format and an ISA select, Remove), posting `FormData`
with the repeated `file` parts and the `files` JSON options to
`POST /api/binaries`.  The response renders one line per file, a duplicate as
`Already stored <file> as binary #N.` rather than as a failure, and the whole
batch's journal action as a link; the list refetches and a failure renders in
place with the error name and detail.
It also carries the malware-family store: a name input, a reference-binary
`<select>` and an optional alias input posting `POST /api/families`, then the
registered families as a table with a per-row Delete behind an inline confirm,
over the note that reportal bundles no external threat-intelligence feed.  The
binaries table carries a selection checkbox per row, a comment-count badge and
a per-row Download action and a Zipped action (plain links to
`GET /api/binaries/<id>/download` and
`GET /api/binaries/<id>/download-zipped`,
which streams the stored bytes with a `Content-Disposition` filename), and a
`Bulk actions` panel below it applies add tag, remove tag or delete
(behind an inline confirm) to the selection through `POST /api/binaries/bulk`
and reports how many applied and how many were skipped.

Binary detail (`#/binaries/<id>`) opens with the portal's binary-detail surface.
header (name, sha256, format, arch, size, path); binary details (auto-loads the
stored PE metadata and, for the build-identity rows, the fingerprint bundle; a
`no-scan` response shows the nothing-stored message with a Run PE details
control that posts and stores it; the identity table carries the PE type, base
address and image base, entry point, checksum, resource count, import hash and
export hash, and the debug-directory and Rich-header summary is kept beside it);
hashes (auto-loads the fingerprint `GET`, with a Compute/Recompute control, and
renders md5, sha1, sha256, sha512, the four SHA-3 digests, crc32 and the
Rich-header hash as copyable mono rows); security mitigations (the `N/11`
`security_score` readout plus the 11-item checklist in portal order, each item's
state and its raw flag name and value from the stored scan, an item with no
source value rendering `n/a`); imports (loaded on demand, a client-side filter
over library and function with the filtered-of-total count); exports (the stored
export table with a filter over name, ordinal and forwarder, showing each
export's name, absolute address, ordinal and forwarder target); sections (the
stored section table with a filter and columns for name, virtual address, file
offset, virtual size, raw size, an entropy meter, the R/W/X protection letters
and the full `IMAGE_SCN_*` name list); code signature (Authenticode state,
signature count and signers); packer detection (auto-loads the stored file-type
detection and never runs the engine on render; a `no-scan` response shows the
nothing-stored message with a Run detector control, which posts and renders the
packer verdict, a peak-section-entropy meter with the packed range marked, the
section count, the toolchain compiler string and the match table with each
match's category, name, confidence and signal list); detail coverage (three
stored-only reads: the source list from
`/binaries/<id>/additional-details/status` with a ready/missing badge and the
`Fills the gap:` command line, which always answers so an uninspected binary
reports what is missing rather than an empty panel; the overlay size and
offset, the Rich header's entry count and build ids, the debug entry count and
the section-table packer hint from `/binaries/<id>/additional-details`; and the
Detect-It-Easy identity with the by-category match counts and the packed
verdict from `/binaries/<id>/die-info`); unpacked files (the unpack panel, see
below); strings (loaded on demand,
a client-side filter with the filtered-of-total count, capped at
`MAX_STRINGS_SHOWN` with the true total stated, server-side `sort`/`order`
controls over `value` or `length`, and each row's VA and text linking to the
Functions view filtered to the functions that reference that address); tags (a table of tags with an add control and a per-row Remove
behind an inline confirm); comments (`panels/CommentsPanel.tsx` with the binary scope, see below);
lineage (auto-loads the stored comparisons and never runs an engine on
render; a compare-with `<select>` over the other binaries and a Run comparison
control that posts the pair, then the status counts, `matched_percent`, whether the
comparison was refined, and one table per changed/removed/added group with each
function linked to its detail, capped at `MAX_LINEAGE_ROWS_SHOWN` with the
group's true count stated); related binaries (auto-loads the stored ranking and
never runs an engine on render; a Run scan control posts, then the candidate
count and a table of each candidate's classification badge, confidence, name
linked to that binary's detail, similarity and signal list); composition
(auto-loads the stored analysis and never runs matching or the engine on
render; a `no-scan` response shows the nothing-stored message with a Run
analysis control, which posts and renders the `Matched: N / M (P%)` meter, the
name-source and match-quality meters, the per-binary rollup (name linked to
that binary's detail, sha256, count and percent) and the per-function rows
(name linked to its function detail, VA, size, band badge, similarity and the
matched binary, or an explicit `No match` badge), capped at
`MAX_COMPOSITION_ROWS_SHOWN` with the true total stated); triage and report
(View loads the stored result, surfacing `no-scan` as a muted nothing-stored
message, while Run posts to the engine; rendering the same software-type badge
and `Threat score` verdict the threat panel renders, then the toolchain/section
summary or the coverage summary with status counts, plus the raw JSON in a
`<details>`; the report body links to the generated site at
`/reports/<id>/index.html`); function triage (auto-loads the stored aggregate
and never runs the engine or the LLM on render; a `no-scan` response shows the
nothing-stored message with a limit input and a Run function triage control,
which posts the limit and renders the model/method line, the scored rows with
their score, name, VA, size, status, method badge, summary and capabilities,
the skipped list and the notes); detect (auto-loads the stored family detection
and never runs the engine on render; a `no-scan` response shows the
nothing-detected message with a Run detect control, which posts and renders
each match's family name (with its aliases), confidence and signal list, plus
the payload's scope and threshold notes); crypto (auto-loads the stored crypto scan and
never runs the engine on render; a `no-scan` response shows the friendly
nothing-scanned message with a Run crypto scan control, which posts and
renders each finding's confidence, kind, name and detail with the
by-confidence counts); security (auto-loads the stored security scan and never
runs the engine on render; a `no-scan` response shows the nothing-scanned
message with a severity `<select>` and a Run security scan control, which posts
and renders each finding's severity, rule, CWE, file:line, function and snippet
with the by-severity counts); secrets (auto-loads the stored secrets scan and
never runs the engine on render; a `no-scan` response shows the nothing-scanned
message with a Run secrets scan control, which posts and renders each finding's
confidence, kind, name, redacted value and VA with the by-confidence and
scanned-string counts and a caution that the values are live secrets, each row
carrying a Reveal/Hide toggle); protocols (auto-loads the stored inference and
never runs the engine on render; a `no-scan` response shows the nothing-scanned
message with a Run protocol scan control, which posts and renders each
protocol's confidence, well-known ports, an expandable evidence list and
description with the by-confidence counts); data types (auto-loads the local
type model through its own GET, which always answers, and never runs the engine
on render; it carries a backend `<select>` and a limit input whose Recover
structs control posts the struct-recovery run, an Import from scan control that
seeds the model from the stored scan, an Export path input whose Export header
control renders the model to that path and offers a Force overwrite
confirmation when the API answers 409 `export-exists`, and one block per type
with its name, size and source, a member table (offset, size, member name and
the declared type), inline rename/retype/save/remove controls per member, an
add-member row, a Rename type control and a Delete type control, a History
control that loads `GET /api/data-types/<id>/history` into a version list (each
version naming its source, actor and time, its per-field diff and a Revert
behind the shared inline confirm, which posts the revert route and refreshes
the model), plus an Import signatures button and an Export prototypes path
input with the same Force overwrite confirmation); auto-unstrip
(auto-loads the stored proposals and never runs the engine on render; a
`no-scan` response shows the run control with a nothing-stored message, and Run
auto-unstrip posts a min-confidence value, rendering each proposal's VA,
current name, proposed name, module, kind and confidence with a per-row Apply
and an Apply all listed control); capabilities (auto-loads the stored
capability scan and never runs the engine on render; a `no-scan` response shows
the nothing-scanned message with a Run capability scan control, which posts and
renders each category's confidence, evidence count and description with an
expandable evidence list); behavior (a domain select over execution, networking
and filesystem; auto-loads the stored scan for the selected domain and never
runs the engine on render; a `no-scan` response shows the nothing-scanned
message with a Run behavior scan control, which posts and renders each
finding's confidence, kind, name and detail with the by-confidence counts);
hardening (a domain select over anti-analysis and obfuscation; auto-loads the
stored scan for the selected domain and never runs the engine on render; a
`no-scan` response shows the nothing-scanned message with a Run hardening scan
control, which posts and renders each finding's confidence, category, name and
detail with the by-confidence counts, the packer likelihood badge for
obfuscation and any recorded notes);
threat (auto-loads the stored report and never runs
the engine on render; a `no-scan` response shows the nothing-stored message with
a Run threat report control and a narrative checkbox, rendering the software-type
badge with its signal list beside the `Threat score` meter and the named
`packing`/`capabilities`/`indicators`/`techniques` contributions, then the
summary when one is stored, each IOC category in a collapsible group with its
count, the techniques table with each row's id (linked to
`attack.mitre.org`, the stored row keeping the plain id), name, confidence and
expandable evidence, and the report's notes); remediation (auto-loads the stored payload and never runs
the engine on render; a `no-scan` response shows the nothing-stored message with
a Generate control, rendering the rule name, string count and validation status
plus a collapsible section per artifact, YARA, Snort and STIX, each with its
text in a `<pre class="code">` and a copy control or an artifact-specific empty
state, then the Snort and YARA notes); and a link to the binary's functions.

Function detail (`#/functions/<id>`) panels: header (id, VA, name, size,
status, name_source); signature (auto-loads the stored signature through its
own GET, shows the returned `prototype`, a `signature-not-found` answer showing
the nothing-stored hint, edits the return type and calling convention with a
Save, and lists the parameters in a table with inline type/name/`at`/`kind`/`bits`
edit, per-row reorder controls that recompute the arrival locations the
convention implies, Save, Remove and an add-parameter row); the code panel
(auto-loaded, a Disassembly / Control flow toggle; Disassembly renders the
listing with the nasm/hex toggle wired to the `format` query and a Reload, and
Control flow renders the engine's basic-block graph through
`GET /api/functions/<id>/cfg` as an address-ordered block list, each block
naming its address, byte size, instruction count and first/last instruction
text, each outgoing edge a jump control that scrolls to and focuses the target
block, and a back edge carrying the warn ink plus a labelled `back edge` badge;
`truncated` renders a note naming the true `block_total` and the engine's
`block_cap`, the engine's `note` renders as a note, and an empty block list
renders its reason, never an empty diagram); decompilation (auto-loaded,
backend `<select>`, `POST`
Decompile or Recompute, stored backend shown); globals, callers and callees
(three panels sharing one on-demand `references` load, each badged with its
count; a caller's `from_va` and a callee's target link to that function detail
when the binary has one at that VA, an import-slot call with no resolved name
renders as `indirect`, and a global names its address, section and access);
matches (Apply per row, a Diff link per row to
`#/diff/<function-id>/<candidate-id>`, candidate linked to its function detail)
and history (Revert per row), plus the same Comments panel with the function
scope.  `Apply` and `Revert` refetch
the panels they changed and the function header, so the new name shows.  The
diff view (`views/DiffView.tsx`) renders the two listings side by side with
the changed lines marked (delete/insert styling), a `kind` select
(`decomp`/`disasm`), a normalize checkbox, the similarity and the summary
counts, loading through the diff route.  The Functions view's filters carry several decompilation needles at once: each
one is added with Enter, drawn as a chip with its own Remove control, and sent as
repeated `string` parameters (any-of); an adjacent `regular expressions`
checkbox sends `regex=true` so every needle is a pattern.  The needles travel in
the hash one per line, so the filter stays shareable and a needle may contain any
character.  The Search view's `regular expression` checkbox does the same for the
typed search (disabled for the `sha256` kind, which is a literal prefix).

The conversation detail carries the Agent run panel: the question box
(`Run agent`), the run's status with its tool-call count, the event list (each
tool call, a confirmation request, a rejection, the answer or a failure), the
pending call with its exact arguments and `Approve call`/`Reject call`, a
`Cancel run` control while the run is live and the model's answer.  It reads
`GET /api/conversations/<id>/runs`, posts to `POST .../runs`, `.../confirm` and
`.../cancel`, and refreshes after every action; a client that wants live updates
follows the run's state stream at `GET /api/conversations/<id>/events`.  The
panel is explicit that a tool which changes the workspace waits for the
analyst's approval and that a rejection is answered another way.

The Data types panel's neighbour is the Debug symbols panel: a file control, an
`Apply names and types` checkbox and `Ingest symbols`, which posts the file as
`multipart/form-data` to `POST /api/binaries/<id>/symbols` and renders the
result (kind, symbol count, type count, names applied) with the parse's own
notes under the table of ingests; each row exports the parse as a C header or
JSON through `GET .../symbols/export`.  A binary with no ingest renders the
nothing-stored state from the route's 404 `no-symbols` rather than an error.

The per-function extras render between the references tables and the matches
panel: indirect call sites (the cached listing's register and memory calls, each
with its line, mnemonic and operand, with the nothing-cached hint when the
function has no listing and a Refresh control); capabilities (the rules the
function's own imports and literals matched, with their confidence and evidence
count); strings (the analyst's list with an add form and a Remove per row, and
below it, labelled as the text scan it is, the literals the stored
decompilation carries); callees (a Declare callee form with the edge's kind and
note, the declared edges with a Remove per row, and the derived names as one
line of text); and a canonical-name panel whose Apply canonical name posts this
function's id to `POST /api/functions/canonical-names` and reports the rename
count or the reason it was skipped.  The analysis log drawer carries the analysis
strings panel: the same list and add form at analysis scope plus a
one-string-per-line Replace list box, which posts to `PUT
/api/analyses/<id>/strings` and reports how many values the list now holds.  All
of it reads the derived payloads as labelled derivations and never calls an
engine or a model on render.
An AI
section groups the AI decompilation, Summary, AI comments, Type suggestions and
Renames panels.  The AI decompilation panel is the whole-function rewrite: the
lines with their origin (`original`/`rewritten`/`added`) in a table, a per-token
override input beside its kind, uses and lines, a rating selector with its note,
and a comment editor for the line the analyst picks, all over the
`/functions/<id>/ai-decompilation` routes and each surfacing the route's own
error in place.  The four flat artifacts each auto-load their stored-only `GET`
and never call a model on render, a
`no-artifact` answer shows a nothing-stored hint, and Generate (Suggest for
Renames) posts to the AI route, surfacing 503 `llm-unavailable` in place.  The
Models view (System group) tabulates the model registry, `GET /api/models`, with
each entry's kind, version, availability and reason, and carries the upgrade
form: an analysis id, an `llm` model and an optional function bound, posting to
`POST /api/analyses/<id>/upgrade` and rendering the per-function `applied` and
`skipped` rows, the `from` to `to` transition and the note that reportal re-runs
artifacts rather than re-analysing the binary.  The Users view adds a Secrets
panel (the settings **API Key** tab): the stored credentials with their scope,
team, byte length and last-four hint, a form that stores or replaces one (name,
value, scope and team) or removes a row, and a password-typed value field; it
reads `GET /api/secrets` and writes `PUT`/`DELETE /api/secrets/<name>`, and it
never renders a value because no response carries one.  The signature panel carries a copy control: comma-separated target ids and
Copy signature, posting to `POST /api/analyses/<id>/signatures/copy` with the
panel's function as the source, and reporting how many targets took the copy.
The binary detail's Agent feedback panel lists every stored agent artifact with
its verdict and carries Up, Down and Clear per row, over
`GET`/`PUT /api/binaries/<id>/ratings[/<kind>]`; it says how many of the stored
artifacts carry a verdict.  The Integrations view ends with the "Connect an MCP
client" card: the `claude mcp add` one-liner and the `~/.claude.json` snippet,
each with a copy control, above the tool counts read from `GET /api/config`.

The analyses list carries Owner and Seen by columns and a Workspace filter
(personal, team or public) beside the status and search filters, all of them in
the route hash, so a filtered list is a link.  The scope is the owning binary's,
which is the object reportal stores a team on, so the write stays
`PATCH /api/binaries/<id>/scope` (`reportal binary-scope`) rather than a second
control on the row.

The dashboard carries the 30-day activity series: three bar charts (binaries
processed, agents triggered and journaled actions), one bar per day over a shared
peak, each chart labelled for a screen reader with its total, plus the
software-type totals and any note the payload carries.  The bars read
`GET /api/stats/series` and are computed from stored rows only, so the panel
never runs an engine and cannot disagree with the lists beside it.

The Data types panel opens with a provenance strip (one toggle per label, carrying the count over the whole model), a Source filter beside the kind and search filters, and a page-at-a-time list with a Load more control; its four filters live in the route hash, so a filtered model is a link.  It also carries a declaration box with Create from declarations and
Update from declarations, posting the pasted C to `POST` or `PUT
/api/analyses/<id>/data-types` for the binary's latest analysis (the route is
analysis-scoped) and rendering the created/updated/skipped counts.  The External view
(Analysis group) lists the external-source registry with each source's kind and
availability and the two switches behind a remote one, and carries a pull form
(analysis id and source, with Pull posting to `POST
/api/analyses/<id>/external/<source>` and Read stored loading the `GET` on the
same path) that renders whatever the source returned under a note naming it, its
kind and the fetch time.  The
Renames panel lists each stored suggestion with a checkbox, its reason and
confidence, an Apply selected / Apply all pair (with a rename-function toggle
for a function-kind suggestion) and a Revert; an apply or a revert refreshes the
decompilation panel and the function header.  The AI decompilation panel
(`panels/PipelinePanel.tsx`) auto-loads the stored run through its stored-only
`GET`, renders the step timeline (name, status, duration, skip reason,
provided names), the predicted name with an Apply rename action, the summary,
the inline comments merged into the decompilation and the decompilation itself;
a `no-run` answer shows the nothing-stored hint with a Run pipeline control,
and the toolbar carries Run pipeline/Re-run and Revert run (which posts the
revert route and refreshes the history panel).  The Functions view
(`views/FunctionsView.tsx`, `#/functions` and `#/binaries/<id>/functions`)
picks a binary, lists its functions with per-row Matches, History and Rename
actions, and carries a filter panel plus sortable headers: name source,
capability, match state, a size range and a string reference are sent to the
server as query parameters (`GET /api/binaries/<id>/functions`), the table
reports the filtered-of-total counts and the empty state names the filter, and
the sort headers toggle a column and its direction.  The filter and sort state
lives in the route's hash query (`#/binaries/<id>/functions?sort=size&order=desc`),
the same convention the router encodes route state with, so a filtered list is
shareable and survives a reload; the router parses a hash's `?query` into
`RouteState.query` for the list views.  It also carries a `Bulk actions` panel:
a prefix input with a
replace-existing-prefix toggle that posts `POST /api/functions/bulk` for the
selected rows and reports how many renamed and how many were skipped.

The Tags view (`views/TagsView.tsx`, `#/tags`, in the Targets group) is the
register's tag vocabulary: every tag with how many binaries and how many
collections carry it, from `GET /api/tags`.  A tag is created where it is
applied (the binary detail's Tags panel and a collection's tag field), so this
view maintains rather than creates: selecting a row opens its panel, where the
name saves through `PATCH /api/tags/<id>` (every link follows, and the write is
journaled so a revert restores the old name) and Delete sits behind an inline
confirm over `DELETE /api/tags/<id>`, which takes the tag off every binary and
collection.  Before it a misspelled tag could never be renamed or pruned.

The Collections view (`views/CollectionsView.tsx`, `#/collections`) lists the
collections with their member and tag counts, their owner and their scope, and
creates one from a name and a description.  A Sort control offers `id` (the
default), `name`, `size`, `updated` and `owner` over `GET
/api/collections?order=`, a Workspace control filters by `personal`, `team` or
`public` over `?workspace=` against the collection's own scope, and both live in
the route hash (`#/collections?order=owner&workspace=personal`), so a filtered
list is a link.  The route sorts server-side and echoes both values it applied;
a filter that matches nothing says so instead of reading as an empty register.
Selecting a row opens its detail panel: the collection's name,
description and scope are editable and saved with `PATCH /api/collections/<id>`,
its tags are a comma-separated field saved with `PATCH
/api/collections/<id>/tags` (the set is replaced, so clearing the field removes
every tag), its members are a table whose Remove button posts `DELETE
/api/collections/<id>/binaries` with that one id, a binary id field adds a
member through `POST /api/collections/<id>/binaries`, and Delete sits behind an
inline confirm (`DELETE /api/collections/<id>`).  Every one of those writes is
one journal action on the server, so the journal view can revert it.

The Users view (`views/UsersView.tsx`, `#/users`, in the System group) renders
the identity the API reports: `GET /api/iam/me` as a key/value block (the auth
mode, who this browser is, the role and its permission badges) beside a bearer
token field that saves or clears what this browser sends, and `GET /api/users`
as the user table.  Creating a user takes a name and a role select and shows the
returned token once in a `CodeBlock`, because that is the only time the server
has it; each row's role select saves a `PATCH`, Disable/Enable flips the
disabled flag, New token rotates and shows the replacement once, and Delete
goes through the confirm pattern.  With auth off the page says so and the API is
the local operator's, which is the honest reading of an empty user table.

The Memory panel's `Whole binary` mode (`panels/MemoryPanel.tsx`) is the
continuous hex dump: one scrollable region in virtual-address order whose span
comes from the engine's own section map, with only the rows on screen rendered
and the bytes read 256 at a time as the viewport approaches a window.  A region
no section backs is a stated `gap` row, the same one the paged mode renders, so
the dump never shows invented zeros.  The `Columns` control switches the virtual
and file-offset readings (the file offset is shown beside the virtual address),
`G` focuses the address box, `Tab` switches the column and the choice is
remembered in `localStorage` under `MEMORY_COLUMN_STORAGE_KEY`.  The section
table's virtual-address cell links here with `?memory=<address>`, which lands on
and selects that row; the smoke's `check_memory_dump` and
`web/tests/memory-page.spec.ts` assert the landing, the reading and the `G`
binding.

The binary detail's Library identification panel
(`panels/BinaryPanels.tsx`) reads `GET /api/binaries/<id>/library`, runs the
identification over `POST` with an optional minimum confidence, and renders the
module rollup (module, kinds, functions, bytes, confidence, linkage) over a
second table of the identified functions, each linking to its function view when
it is one.  The `Export` control fetches `/api/binaries/<id>/sbom?format=`, the
shape chosen in the select (CycloneDX, SPDX or CSV), and shows the document in a
code block.  Before the first run the panel names the command that fills it
rather than showing an empty table.

The binary detail's Benchmark panel (`panels/BinaryPanels.tsx`) reads
`GET /api/binaries/<id>/benchmark` and posts from its `Run benchmark` control
with a partner binary chosen in the panel's select (the workspace's other
binaries, so the run has a corpus).  A stored run renders the queries, retrieved
rows, hits, precision, recall, F1, mean reciprocal rank and mean rank beside the
recorded pair count, every label's rank and similarity in a table (a miss is a
badge, not a blank), and the payload's notes, so a reader can see that the
labels came from shared names rather than a corpus and why a query missed.  The
panel runs nothing on render and names the two sources of labels before the
first run.  The same panel carries the rename half under a `Rename proposals`
heading: it reads `GET /api/binaries/<id>/rename-benchmark`, which scores the
stored proposals against the names a debug symbol file supplied, and renders the
scored/correct/close counts, precision, recall and F1 beside a table of the
disagreements and the missed symbols.  A binary with either input missing shows
the reason the read reports (no symbol names, or no stored reading) and the
command that supplies it, never a table of zeros.  `web/tests/benchmark.spec.ts`
covers the empty reading, the partner select, the disabled-to-enabled run
control and the rename half's missing input.

The binary detail's Unpacked files panel (`panels/BinaryPanels.tsx`) reads
`GET /api/binaries/<id>/unpack`, which answers the provenance of a binary
reportal unpacked and `stored: false` for one it did not, and posts from its
`Run unpack` control with a packer select (Auto, LZEXE, UPX; Auto is the
file's own stub).  A run renders the method, the rebuilt binary with a link to
its detail view, its sha256, whether it matched a binary already stored, and
what identified the packer, and a failure (nothing packed, UPX without the
`upx` tool, an LZEXE image without the engine) is the route's own error code in
the panel.  The panel runs nothing on render: the reconstruct itself is the
server's, and no sample is executed.

The binary detail's Composition panel (`panels/BinaryPanels.tsx`) reads
`GET /api/binaries/<id>/composition` and runs it over `POST`, whose body is the
panel's two scope fields: a comma-separated binary id list and a collection id
list, empty meaning the whole register.  The panel renders the headline match
meter, the name-source and quality breakdowns, the hosted category table (each
category's count, percent and top binaries) and the per-binary rollup, so the
scope narrows what the run reads rather than what the matching did.

The binary detail's Sandbox detonation panel (`panels/BinaryPanels.tsx`) reads
`GET /api/binaries/<id>/dynamic-execution/status` for the opt-in state, the
runner in use and the runs so far, carries a Detonate button with the two
bounded inputs (seconds, memory MiB) that posts the run, and renders the report:
the status badge (a timeout is the warn hue), the runner, the exit code, the
duration, the caps in force, the files the sample wrote and the stdout/stderr
tails in code blocks.  With the opt-in off or no runner installed the button is
disabled and the note says which of the two is missing.

The binary detail's Firmware panel (`panels/BinaryPanels.tsx`) reads the stored
carve pass and offers Carve (the POST), a region table (index, offset, size,
kind badge, label, confidence, entropy) with a per-row Carve out control that
posts one region to `/firmware/extract` and reports what it registered, and the
entropy summary line; before the first run it shows the no-scan hint with the
same Carve button.

The Users view's Activity panel reads `GET /api/users/activity` (a table of
when, actor, kind and description, with an actor select built from the names the
feed reports) and carries the feedback form: a note posts to
`POST /api/users/feedback` and the stored notes render under it, so the feed and
the notes are on the page an operator already opens to manage identity.

The Users view's identity half carries the team structure.  Its Teams panel reads
`GET /api/teams` and renders id, name, member count, the owning organisation and
the description, with a create form, a per-row organisation select that PUTs
`/api/teams/<id>/organisation`, an "add member" select and a Delete behind the
confirm pattern.  A row's `Members` button opens that team's detail
(`GET /api/teams/<id>`) as a second table whose Team role column is a select per
member (owner or member) PUTing `/api/teams/<id>/members/<user_id>/role`, so a
team can be managed from the browser.  Above it, an organisation table reads
`GET /api/organisations` with a create form and a Delete per row; the panel says
in place that an organisation groups teams and decides nothing about access.

The Users view also carries the Teams panel: `GET /api/teams` as a table (id,
name, member count, description) with a create form, a per-row "add member"
select over the known users and a Delete behind the confirm pattern, so team
membership is managed in the browser the same way the CLI manages it.

The Binaries view's upload panel (`views/BinariesView.tsx`) takes a batch one
file at a time: a `Files` control and a dashed drop zone both queue files, each
queued row carries its own name, tags, format and ISA, a `Configure all` pair
applies a format and an ISA to every row at once, and a row nobody configured
keeps the `auto` plan badge.  The batch posts as one multipart request with one
options entry per part, so the whole request is one journal action; the result
list opens with a duplicate banner and an error banner above the per-entry rows,
each of which names what happened to that file.  The `Extract an archive` panel
below unpacks an already stored archive into a collection (or one named after
it) with an optional password and reports each member with the binary it became
or the reason it was skipped.

The Binaries view (`views/BinariesView.tsx`) carries the scope of each row as a
select in the table: `public` for the whole workspace, or a team that owns it
(`PATCH /api/binaries/<id>/scope`).  The options come from `GET /api/teams`, so
the control lists exactly the teams that exist.

A conversation carries a prompt library: `SCOPE_PROMPTS` in
`views/ConversationsView.tsx` names a few canned openers per scope (the manual,
a binary, a function) and each is a ghost button that fills the message box, so
the local assistant offers the hosted portal's context-dependent prompt choices
without ever suggesting something its scope cannot answer.  The documentation
scope grounds a chat in reportal's own manual (TODO entry 16): the scope kind is
`docs`, its id is carried but never matched, and the pages are ingested into the
`docs` knowledge scope on the first question.

The Documentation view (`views/DocumentationView.tsx`, `#/docs`, `#/docs/:slug`
and `#/changelog`, in the System group) is the portal's own manual, read from
the workspace rather than from a checkout: `GET /api/docs` answers the index the
view renders as cards and `GET /api/docs/<slug>` answers one page's title, its
on-this-page headings and its blocks.  The server sends structure, never markup,
so the view carries its own renderer: `renderInline` is one pass over code
spans, links, bold and italics (in that order, which is what keeps `**bold**`
from reading as two italics) and `DocBlockView` is one element per block kind
(heading, paragraph, list with each item's indent, fenced code, quote, table)
with an unknown kind falling back to its text rather than being dropped.  An
internal `[label](/docs/<slug>)` link becomes a react-router `Link` and an
external one opens in a new tab with `rel="noreferrer noopener"`, so a document
cannot navigate the app somewhere unexpected.  The reading column is sticky
beside the body and becomes a wrapping strip above it at phone width, the
current section is marked by an `IntersectionObserver` over the heading anchors,
and the page list is the same view with no slug.  Each page also carries the
reading-order pair the server sends it (`docs.neighbours`, the same order the
index numbers) as a pager at the foot of the body, so a reader walks the manual
without going back to the index.  `#/changelog` renders
`CHANGELOG.md` through the same reader, so the release notes ship with the
release.  A deployment with neither a workspace `docs/` directory nor a checkout
beside the package answers 404 `no-docs`, which the view shows as an error note
rather than an empty page.

The Analyses view (`views/AnalysesView.tsx`) carries the entry 10 filters: a
chip per status (the set is any-of, the last one off means any status), a
platform and an architecture select built from the values the payload reports
the register actually holds, an Order select over `store.ANALYSIS_ORDERS` and a
Clear control; every one of them is in the route hash, so a filtered list is
shareable.  Each row's Actions cell carries View log, Re-analyse (the cluster D
requeue, which puts the analysis back to pending and clears its finish time) and
Delete, and the bulk toolbar adds Copy hashes beside Add tag, Remove tag and
Delete.

The Analyses view's log drawer (`views/AnalysesView.tsx`) opens with the
lifecycle read for that analysis: its status badge, engine, created and finished
times and the scan and log counts by status and severity, beside an Add log
entry control, a Requeue button and links to the function map, the re-run
parameters and the raw bytes.  The writes go through the same routes the CLI and
MCP use.  Below the lifecycle block the drawer renders the analysis's imported
functions (`GET /api/analyses/<id>/imported-functions`): one row per import stub
with its address and the functions whose stored decompilation mentions it, the
first `caller_limit` of them as name badges with a `+n more` count, and a line
saying the callers come from the decompilation text because reportal stores no
call graph.

The Analyses view (`views/AnalysesView.tsx`, `#/analyses`) lists each analysis's
id, binary (linked to its detail page), platform badges, binary size, engine,
created time, status badge (the design language's status hues: `done` is the
match green, `failed` the fail red, `processing` the live hue) and the owning
binary's tags as an editor: each tag is a chip with its own remove control and
the cell carries an add field, both of which post the whole set through
`PATCH /api/analyses/<id>/tags` (the binary's tags are what reportal tags, so a
change here and a change in the binary's Tags panel are one write).  A status select, an order select and a search box write the
hash query (`#/analyses?status=failed&search=notepad`), the table states
`N of M analyses` so a filter is distinguishable from a small project, and a
filter that matched nothing says so instead of rendering an empty table.  Each
row has a View log control that opens an on-demand drawer over
`GET /api/analyses/<id>/logs` (severity badges on the severity scale, the
newest entries first, a Load more control while the true total is larger) and a
Delete behind the confirm pattern that calls `DELETE /api/analyses/<id>`.  Each
row also carries a selection checkbox and the view's Bulk actions panel applies
one `POST /api/analyses/bulk` action to the checked rows (add tag, remove tag,
delete), states how many applied and how many were skipped, and links the
journal entry the action recorded.  There
is no owner column: reportal is a single-user loopback tool, the view says so,
and it links to the Journal view, which is where who did what is recorded.  The
Binaries view carries a Browse analyses action beside Browse functions.
The binary detail Report panel (`panels/BinaryPanels.tsx`) offers Generate PDF (the
synchronous render) beside Queue PDF, which submits a `report-pdf` job and then
polls `/binaries/<id>/report/pdf/status` while the job is live, showing the job
id, its status and the page count once the file is on disk.

The Jobs view (`views/JobsView.tsx`, `#/jobs`) is the async operation workflow:
a Queue toolbar over the operations `GET /api/jobs` advertises (the kind, the
binary, the domain a behavior or hardening job needs), the list of queued and
finished jobs with a status badge, the `progress`/`steps_total` readout, the
created time and each job's message, result or error, a Cancel button on a job
that has not started and a Run waiting now control that drains the queue inline.
It polls while anything is queued and runs nothing itself: what the view shows
is what the server's pool did.

The topbar carries a Notifications button (`views/NotificationsDialog.tsx`):
the count of feed items this browser has not dismissed, opening a dialog over
`GET /api/notifications` with each item's severity badge, time, message and its
binary link, a Dismiss per item and a Dismiss all.  The feed refreshes on an
interval while the shell is mounted, and the dismissed ids live in
localStorage under `reportal.notifications.dismissed`, because the server
stores nothing: dismissal is the reader's, exactly as the hosted portal keeps
it.  The dialog follows the cheatsheet's focus contract (focus on open, return
on close, Tab contained, Escape closes).

Both detail views carry a Comments panel (`panels/CommentsPanel.tsx`) scoped to
the binary or the function: it lists each comment's author and timestamps with
an add box, and shows Edit and Delete on a comment whose author equals the
author this browser last used (kept in localStorage under
`COMMENT_AUTHOR_STORAGE_KEY`).  Both detail views carry a
Conversations panel whose Chat about this action posts `POST /api/conversations`
for that scope and opens the new thread.  The Conversations view lists each
thread's title, scope and message count, creates one from a scope kind and id,
and the thread route renders the messages, sends from its composer (a 503
`llm-unavailable` surfaces in place) and deletes the thread.
The Knowledge view (`views/KnowledgeView.tsx`, `#/knowledge`) picks a binary
from a scope select, ingests a document from a file input (posting `FormData`
to `POST /api/binaries/<id>/documents`) or from the paste area (posting JSON to
`POST /api/documents`), lists the scope's documents with their title, source,
size, chunk count and a Delete action, and searches the scope through
`GET /api/knowledge/search`, rendering each ranked hit with its document title,
score and ranking method.  Its `GET /api/knowledge/config` read decides whether
the URL field renders: with remote ingestion enabled a URL input posts to
`POST /api/knowledge/fetch`, and while it is disabled the control is replaced by
the inline reason (`REMOTE_INGEST_DISABLED_DETAIL`), so the URL path is never
offered when the server would refuse it.

The Graph view (`views/GraphView.tsx`, `#/graph`) picks a binary, rebuilds its
graph through `POST /api/binaries/<id>/graph` and loads the stored payload
through its stored-only `GET` (a `no-graph` answer shows the build hint and the
control).  It renders the node counts by kind, a node table (kind, label,
degree) with a kind select and a label/kind filter, and, for the selected node,
the incoming and outgoing neighbor groups with each neighbor's relation,
kind, label and weight, linked to the function detail or the Knowledge view
where the kind has a view.  Document nodes stay out unless the include-documents
control is on, since they and their mention edges dwarf the rest of a graph, and
the table stops at `MAX_GRAPH_ROWS_SHOWN` while stating the true total.  A
`Backends` panel below it loads `GET /api/graph/backends`, offers a backend
selector (an unavailable backend is marked and its option disabled), a Sync to
backend control that posts `POST /api/binaries/<id>/graph/sync` and is disabled
with the backend's `unavailable_reason` shown while it is unavailable, and,
when the selected backend reports `supports_query`, a text box that queries
`GET /api/graph/query?q=&backend=` and renders the matching nodes.

`tools/smoke_spa.py` is the browser smoke: it builds the frontend when
`assets/dist/index.html` is missing (`bun install` when `web/node_modules` is
absent, then `bun run build` with `cwd=web`), seeds a scratch workspace under
`.scratch/` (binary, rebrew context, analysis, functions from the notepad
project, a stored PE metadata scan so the Binary details panel renders its
identity, security flags and section table, a stored file-type detection so the
File type panel renders a packed-section match,
a stored structs scan plus a seeded editable data type whose members carry a
bitfield and an explicit gap member and whose declared size is past their extent,
so the Data types panel renders both a stored recovery and a model row, the
member shape controls and the size-vs-members warning, a stored
function-triage scan so the Function triage panel renders a scored row and its
model line, a stored match pair
with both decompilations so the diff route
renders a stored alignment, a stored conversation so the Conversations
routes render a thread, a stored knowledge document so the Knowledge view
renders a scope with a document, a built knowledge graph so the Graph view
renders its node counts and node table, a stored malware family with a stored
detection so the Detect panel and the Binaries view's family table render a
match and its signals, analyst comments on the binary and its first function so
the Comments panels render a stored row each, a tag on the seeded binary so the
global search modal's tag query renders a row, and a stored lineage comparison against
a registered copy of the binary so the Lineage panel renders its counts and
rows; the analysis carries a structured log, so the Analyses route's log drawer
has real entries to load), starts `reportal serve` on a free port with the
sibling rebrew checkout installed, renders every hash
route with headless Chrome (`google-chrome-stable`, falling back to `chromium`),
and asserts each view's markers.  After the route loop it opens the global search modal through
the documented `⌘K` shortcut (`check_search_modal`), waits for React to mount
the dialog, types a query into the controlled input and asserts a result row.
It then switches the seeded loop function's code panel to its control-flow view
(`check_cfg_view`), which clicks the Disassembly / Control flow toggle, waits
for the graph's markers (the panel title, the block summary and a labelled back
edge) and activates an edge's jump control to assert the focus landed on the
block it names; the loop function is pinned by VA
(`CFG_LOOP_FUNCTION_VA`) so a reordered function list fails loud rather than
asserting a different function's graph.
A render goes through the shared DevTools client
(`tools/cdp.py`) and the wait polls the live document until every marker group
is satisfied or `MARKER_DEADLINE_SECONDS` passes: a one-shot DOM dump after a
virtual-time budget is not used, because that budget caps how far ahead the
page's timers run rather than how long a pending fetch takes to resolve, which
made this step flake on a route whose data landed late.  It skips with exit 0
and a message when neither browser is on PATH, before it builds anything.

`tools/audit_ui.py` is the UI gate over the same seeded workspace and route
list: it drives headless Chrome over the DevTools protocol
(`--remote-debugging-pipe`, so no websocket dependency), renders every route at
each viewport in `VIEWPORTS` (1600x1000 and 480x900) and each colour scheme in
`THEMES` (dark and light; headless Chrome defaults to light, so dark is
emulated), and fails with a `route/selector` list on horizontal document
overflow, clipped text, text contrast under WCAG AA, a box outside the
viewport, or an interactive element with no accessible name.  The thresholds
are its module constants and are passed into the page, so the report and the
gate cannot drift.  `--base-url` audits a server already running, `--json`
prints the report, and `--viewport WxH` / `--theme` narrow the matrix.  It skips
with exit 0 when no browser is on PATH, like the smoke.

`web/tests/` is the Playwright suite (`cd web && bun run test:ui`; specs are
`web/tests/*.spec.ts`).  The config is one chromium project and the browser is
the cached build the pinned `@playwright/test` 1.62.1 resolves
(`chromium-1234` under `~/.cache/ms-playwright`), so a run never downloads a
browser and a pin that resolves another revision fails instead.  One global
setup seeds the workspace through `tools/seed_e2e.py` (the smoke's
`build_workspace` plus the two collections the smoke leaves out, printed as
one JSON object including the seeded tag name) and starts `reportal serve`
against it in its own process
group, which the global teardown stops; it is a global setup rather than the
config's `webServer` because the server needs the database the seed creates.
The specs run serially (`workers: 1`) over that one workspace, so a writer
cannot race a reader.  The hash routes themselves are walked by `tools/smoke_spa.py`, which runs in
`make check` and fails a route that logs an uncaught error, an error-level
console line or a dropped request; the specs cover the sidebar group
navigation, the destructive confirm flows, the
collection, tag and note write paths, a journal write with its revert through
the UI, the 480px shell and the keyboard tab order into the nav, a table's row
actions and an activated row, the Analyses list filters with its log drawer and
a journalled per-row delete, the Functions filter and sort controls with
their hash state, the Data types kind filter and namespace tree with the
counts they produce, the global search modal (the shortcut, the query types,
the arrow-key path, Escape's focus return and the focus trap), the keyboard
layer (the registry's own rules in the Node context, `?` opening the cheatsheet
with its focus return, the rendered set matching the registered one, no binding
firing inside a text field, `/` focusing the view's filter box, `j`/`k` walking
a table's rows and the `g` prefix jumping to a view), the threat report's
software-type badge and score meter with its MITRE link, the function page's
control-flow view (the Disassembly / Control flow toggle swapping the panel,
a block's address, byte size, instruction count and labelled instruction text,
an edge's labelled jump control moving focus to its target block), and the batch
upload control (one row per file, per-file tags, the per-file result lines and
the duplicate answer).  A shared fixture fails every test on a console
error, an uncaught page error, a dropped request or an error response; the
only filtered noise is a 404 carrying a documented empty-result code
(`no-scan`, `no-artifact`, `no-run`, `no-graph`) on a stored-only read, which
the affected panel renders as its nothing-stored hint.

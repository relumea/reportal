# Changelog

reportal is versioned in `src/reportal/__init__.py`; the same string is what
`reportal --version`, `GET /api/health` and the MCP server's `serverInfo`
report. This file is the human summary, newest first, and the SPA's changelog
view renders it from here.

## Unreleased

- Cloud recon lights up by provider.  The threat extractor flags instance
  metadata endpoints with the cloud they belong to (`cloud-aws`,
  `cloud-aws-ecs`, `cloud-gcp`, `cloud-alibaba`, `cloud-tencent`) instead of
  a bare `ipv4-private`, so a LinPEAS-shaped post-exploitation binary reads
  as cloud recon at triage time.  Same categories, same pipeline, no new
  surfaces.
- Go binaries report their own provenance.  `gobuildinfo.py` scans the stored
  file for the `go.buildinfo` magic and keeps the compiler version, the main
  module path, the module dependencies and the build settings as the
  `gobuildinfo` scan, over
  `POST`/`GET /api/binaries/<id>/gobuildinfo`, `reportal gobuildinfo` and the
  `run_gobuildinfo`/`get_gobuildinfo` MCP tools.  No engine and no project
  context: a file without the magic is `not-go` rather than an error.  The
  pclntab function table stays out on purpose: the current aligned format
  needs frame-table parsing to resolve names, verified against a real go1.27
  binary, so Go function names keep arriving through the symbol import.  The
  SBOM export joins those pins beside the engine's modules: each dependency
  is a component with its declared version and a `pkg:golang` purl, in all
  three shapes.
- Security findings rank by reachability.  `exploitability.py` reads the stored
  `security` scan beside the `capabilities` scan and the stored decompilations:
  a finding is reachable when another stored function's text mentions its
  function, network-adjacent when its function text mentions network imports or
  the binary carries the networking capability, ordered by severity then
  reachability, over `GET /api/binaries/<id>/exploitability`, `reportal
  exploitability` and the read-only `get_exploitability` MCP tool.  Stored-only
  with no engine and no writes; the callers are a text derivation, stated as
  such, not a call graph.
- A binary's attack surface reads off its stored scans.  `attack_surface.py`
  composes the `protocols`, `behavior`, `capabilities`, `threat` and `crypto`
  scans at read time into network entries, local input handlers and crypto
  usage, over `GET /api/binaries/<id>/attack-surface`, `reportal
  attack-surface` and the read-only `get_attack_surface` MCP tool.  Stored-only
  with no engine and no writes: a binary with no source scan answers 404
  `no-scan` with the commands that fill the gaps.
- The file-type scan names Go, Rust and Swift binaries.  Three `runtime`
  signatures join the `SIGNATURES` table beside .NET, Visual Basic and Delphi,
  matched the same way over sections, strings and imports with the same
  confidence rule, so `reportal filetype`, the stored scan and `run_filetype`
  answer the runtimes modern malware and supply-chain targets are written in.
- Stored renames now round-trip into the decompiler.  `decompiler_scripts.py`
  renders a binary's named functions as a runnable script per tool, a Ghidra
  Python script, an IDA script or a Binary Ninja rename document, over
  `GET /api/binaries/<id>/decompiler-script`, `reportal decompiler-script`
  and the read-only `export_decompiler_script` MCP tool.  Stored-only with no
  engine and no state directory: a function still carrying a placeholder is
  left out, so the script only carries names the tool would not already show.
- reportal can be run as a service, and the plans are priced on what inference
  actually costs.  Three modules carry it: `plans.py` is the catalog,
  `metering.py` the append-only usage ledger and the quota checks, and
  `billing.py` the Stripe integration (checkout, the customer portal,
  signature-verified webhooks and a reconcile path for a lost delivery).  The
  token allowances are *derived* rather than chosen: reportal resells
  inference, so each tier's allowance is the share of its price that Claude
  tokens may consume (`MAX_COGS_SHARE`, 20%) at the published rates blended
  80/20 input to output, which puts Analyst at $39 for 2M tokens, Team at $149
  for 8M and Enterprise at $749 for 40M, every one of them 18-20% cost of
  goods.  `tests/test_plans.py` asserts the margin property rather than the
  literal numbers, so raising an allowance is allowed and raising it past what
  the price supports fails the gate; the free tier is bounded outright at a
  dollar of inference a month.  Past its allowance a paid plan buys more at $6
  per million rather than stopping, and a tenant using its own model endpoint
  is not metered at all.

  Metering attaches once rather than per call site: `llm.py` gained a usage
  sink every completion reports its endpoint-reported token counts to, and the
  server installs one for the duration of a request that has a tenant, so
  every AI route is metered by construction and no AI code knows billing
  exists.  Counts are never estimated, because a guessed number that bills a
  customer is worse than a missing one.  A workspace with no organisation reads
  as the unmetered `internal` plan, so a self-hosted or single-operator install
  is unchanged and unmetered, which `tests/test_metering.py` pins.

  The billing module is built around the four invariants that keep a payment
  integration from granting a plan nobody paid for: completion is not payment
  (entitlement waits for `payment_status == "paid"`), webhooks are idempotent
  (the event id is claimed in the transaction that applies it, so a redelivery
  answers `duplicate` and does not restart the period), the subscription's
  price id decides the plan rather than caller-supplied checkout metadata, and
  an unverified signature changes nothing.  Writing the tests found a real bug
  in the third: a fallback was reading an unvalidated `plan_id` straight off
  customer-controlled metadata, so a customer could have claimed any tier.

  The eleven routes `docs/API.md` already described now exist and answer
  (`/api/plans`, the usage and billing reads, the operator plan assignment, the
  checkout, portal, manual confirm and cancel writes, the webhook and the
  sync), a `/pricing` marketing page is rendered server-side from the same
  catalog so the marketing numbers and the billing numbers cannot drift, and
  the SPA gained a Billing view with per-dimension quota meters, the period's
  cost to serve and the plan cards.  Billing is off until a Stripe key is
  configured: the default install meters usage, shows it, and offers no
  checkout.

- Readiness is readable in the SPA.  The Integrations view sat an Instance card
  (`GET /api/config`) beside the MCP onboarding without ever showing the
  pre-flight report a unit file gates on.  A Readiness card reads
  `GET /api/doctor` beside it: the report status, workspace, failures and
  warnings over the per-check table, covered by the smoke's integrations
  expectations.

- Readiness is readable over HTTP.  `reportal doctor` was CLI-only, so a remote
  caller or a supervisor without shell access could not ask what the unit file
  gates on.  `GET /api/doctor` answers `doctor.report` with an optional
  `?port=` (default 8002, 0 or blank skips the bind probe): workspace, database
  and schema, auth posture, engine, SPA build, optional paths and the port,
  every check a read, 200 either way with the same `ok`/`degraded` vocabulary;
  400 `port must be an integer`.  Covered beside the CLI cases.

- The API reference covers every route and proves it.  `tests/test_api_docs.py`
  walks the live router tables and fails the gate for a route with no
  `docs/API.md` row (or no same-method family row, which is how the
  `remediation/yara` row covers `remediation/<fmt>`); it caught sixteen
  missing rows on landing, all from uncommitted feature work: the plans,
  usage, billing, checkout, portal, webhook, sync, plan, manual and manual
  cancel reads and writes, the two user-provider link reads, the provider list
  and the binary options, binary summaries, detonation status and auto recover
  rows.  `tests/test_cli_docs.py` keeps the same promise for `docs/CLI.md`.

- The Agent feedback panel takes a verdict note.  The rating note existed on
  the route, the CLI's `--note` and the MCP tool's `note`, but the panel that
  records verdicts could not write one: it sent only `{rating}`, so the Note
  column it already rendered stayed empty for SPA-recorded rows.  Each row now
  carries a Note control beside Up, Down and Clear that opens a verdict select
  and a 500-character note input posting `{rating, note}`, prefilled with the
  stored verdict and note.  The panels spec saves a note through the control and
  reads it back through the ratings read, then clears the verdict so the seeded
  workspace is unchanged.

- The auto run form sends the whole run configuration.  The route and the CLI
  take six knobs (the worker, execute, the concurrency, the functions per leaf
  batch, the attempts per function and the task cap) and the form carried three
  of them, so a run started from the UI always planned one function per batch
  with two attempts under the 200-task ceiling, whatever the workspace wanted
  the decomposition to be.  The form now carries all six, each with the bound
  `auto_mode` validates against, and the round-trip test asserts the two knobs
  it did not cover (`functions_per_task`, `max_tasks`) land in the stored
  config.  `docs/SPA.md` also gains the Auto view, which had no paragraph at
  all.

- The match settings sheet can set the candidate cap.  `top` is part of
  `matching.MatchSettings`, and the route, the CLI and the MCP tool each take
  it, but the sheet offered the other seven settings and not this one: a run
  started from the SPA kept the server's default of 10 candidates per function
  whatever the corpus held, and the sheet then wrote that default back as if it
  had been chosen.  The sheet now offers Top candidates (1 or more), sends it
  with the run, records it in the settings the run stores and shows it as a
  clearable chip like the other settings.

- The Jobs view keeps following a live job to its end.  Its poll asked the
  queue's `queued` count, which counts the jobs still waiting, so the refresh
  stopped the moment a job started running: a `match` job's `progress` and
  `steps_total` froze at the value the first load saw and its row never reached
  `done`.  The poll now follows any live row (queued or running), the same
  signal the job payload's `live` field carries.

- A binary's analyses are reachable from the binary.  `GET /api/analyses`
  already took `?binary_id=`, but the other read surfaces did not:
  `reportal analyses --binary <binary-id>` narrows the listing (and counts its
  `total` over that binary), the `list_analyses` MCP tool takes `binary_id`, and
  the binary detail opens with an Analyses panel listing that binary's runs
  with the engine, the created and finished times, the status and the
  importer's log line inside a scoped `count of total` line.  An unknown binary
  id fails the command instead of reading as an empty list.

- A match job is refused at submit when the similarity extra is not installed.
  The route already answers 503 before it runs, and a queued job would have run
  and failed later; `jobs.submit` now names the extra and the command that
  installs it, the way every other parameter a kind needs is checked before the
  job is queued.

- A stored AI artifact can be discarded.  The four artifacts (the rewrite, the
  summary, the inline comments and the type suggestions) could be generated,
  read, rated and commented and never removed: an analyst who disliked a
  rewrite could only rate it down or generate another.  `DELETE` on each of the
  four routes drops the artifact with everything inside it, journaled through
  the same restore descriptor the other deletes use, so the journal's revert
  puts the payload (rating, overrides and line comments included) back;
  `reportal ai-clear <function-id> [--kind KIND]` and the `clear_ai_artifact`
  MCP tool expose it, and each panel carries a Discard behind the confirm
  pattern.  That is 246 built-in tools, 115 read-only and 131 destructive.

- A binary reports the rebrew project its engine-backed reads use.  The context
  was stored per binary and every engine-backed route answered 400
  `no-engine-context` without one, but no read returned it, so a client could
  only discover the gap by watching a read fail.  `GET /api/binaries/<id>` and
  the `get_binary` MCP tool now carry `rebrew_project` (null when there is
  none), `reportal binary <binary-id>` prints it with the `import-rebrew`
  command that sets one, and the binary detail's header names it in place.

- A user's active team can be set from the terminal and over MCP.  The stored
  preference was settable only from the SPA (`PUT /api/iam/active-team`, the
  caller's own switch), so an operator driving an authenticated install from
  the CLI or an agent had no way to set it for a user.  `reportal user-edit`
  takes `--active-team <id>` and `--clear-active-team` and the `update_user`
  MCP tool takes `active_team_id`/`clear_active_team`, both inside the same
  journaled action as the user's other fields (so a revert puts the previous
  team back) and both refusing a team the user is not in.

- A queued match run reports its progress.  A job was one step (`progress` 0 or
  100) because the engine calls a scan makes cannot be interrupted; a match run
  is the one kind whose loop is reportal's own, so `match_binary` now takes a
  `progress(done, total)` sink and calls it once per source function, and the
  runner writes the job's `progress`/`steps_total` from it (`match` declares
  `JobKind.perform_progress` for that, written at most every
  `jobs.PROGRESS_REPORT_EVERY` functions).  The Jobs view's Progress cell shows
  it without any change, since the fields were already in the payload.

- A match run can be queued as a job.  Matching is the longest operation the
  portal runs (every function against the whole corpus) and it was the one
  operation with no queued form: `POST /api/binaries/<id>/match` blocks for the
  whole run, and the job registry held the eight scans plus the engine report
  and the PDF.  `match` is now a job kind whose params are the match settings,
  validated at submit so a bad value is a 400 rather than a failed job later.
  The three surfaces that ran the match each carried their own copy of the
  snapshot-run-journal sequence; they now share
  `matching.journaled_match`, which is what makes a queued run exactly as
  revertible as a direct one.  `reportal job-submit` also gained the
  `--param KEY=VALUE` its route and MCP tool already had, so a match job can be
  queued with its settings from the terminal.

- Function matching rarely computes a full pair score it can prove is wasted.
  A blended score is 40% MinHash Jaccard and 60% text ratio, and the ratio is
  capped, so a pair whose Jaccard is below `(min_similarity - 60) / 40` cannot
  reach the threshold: at the default floor of 80, any pair under 0.5 Jaccard is
  decided before the expensive text comparison runs.
  `similarity.jaccard` computes that structural half alone (packed
  fingerprints, no tokenizer, no ratio) and `similarity.jaccard_floor` is the
  bound, so `match_binary` skips the scorer for those pairs.  It is exact: the
  recorded rows are byte-identical to the full sweep, and the prefilter engages
  only for the default blended scorer, never for a caller's injected one.
  Measured on a 384-function corpus (147,072 pairs): 8.2 s to 0.6 s, 12.5x,
  with identical rows.

- The External view reports the analysis's own source status before a pull.
  `GET /api/analyses/<id>/external/<source>/status` says whether a source can
  run for that analysis and whether an answer is stored, and only `reportal
  external-status` and the `get_external_status` tool read it: the view showed
  the workspace-level registry and nothing about the analysis in front of the
  analyst until a pull had already happened.  The pull form now renders that
  line, and a pull refreshes it.

- A binary's detail shows and edits which collections hold it.  Membership was
  reachable only from the collection's side: `GET /api/collections/<id>` lists a
  collection's members and no read answered "which collections is this binary
  in", so the binary page could not say where it lived.  `GET
  /api/binaries/<id>/collections` (binary scope enforced by the route gate, and
  a collection the caller may not see left out), `reportal collections-of
  <binary-id>`, the `list_collections` MCP tool's `binary_id` argument and the
  binary detail's Collections panel all read it, and the panel adds and removes
  membership through the collection routes that already existed.

- The analyses log drawer lists that analysis's stored scans.  `GET
  /api/analyses/<id>/scans` was reached by the CLI and the MCP tool only, and
  the binary detail's Scans panel reads the *newest* analysis, so an older
  analysis could not be asked what ran in it.  The drawer's `Scans` section
  renders one row per stored scan with its kind, status, the inputs it ran with
  and when it ran, through the table the binary panel now shares
  (`panels/ScansPanel.tsx`).

- An agent can register a binary.  The MCP registry had no tool for the portal's
  own entry point: `reportal add-binary` registers a local file by content hash
  and nothing over MCP did, so an agent could only work with binaries somebody
  else had already registered.  `register_binary` takes the path the server
  reads, a display name and optionally the team whose scope the binary joins,
  calls the same store and journal path the command does, and is destructive
  like every other writer.  That is 245 built-in tools, 115 read-only and 130
  destructive.

- An upload can register its files into a team's scope.  The batch upload's
  per-file options carried a name, tags, collections and a format/arch hint and
  no scope, so every uploaded binary landed public and ownerless and a team
  workflow had to re-scope each one afterwards through `PATCH
  /api/binaries/<id>/scope`.  An entry may now name `visibility`/`team_id` (a
  `team_id` alone means team visibility; naming a team the caller is not in is
  403 `not-a-team-member`, and re-scoping a duplicate is the scope route's own
  refusal on that entry), the whole batch stays one journal action with each
  re-scope journaled, and every entry reports the scope the binary carries.
  `reportal add-binary` takes the same choice as `--team`.  In the SPA the
  upload rows carry a scope select, `Configure all` reaches it, and a new row
  starts on the caller's active team.

- The Users view can switch the caller's active team.  `PUT
  /api/iam/active-team` stored the preference and the SPA neither showed nor set
  it, so `active_team_id` decided nothing a user could reach.  The identity
  panel now carries an `Active team` select over the caller's teams (with an
  empty option that clears it), and the upload panel's scope select starts there.

- Each stored remediation artifact can be downloaded.  `GET
  /api/binaries/<id>/remediation/<yara|snort|stix>` served one artifact as the
  raw text or JSON the store holds, and the panel that renders all three
  offered only a copy: each artifact's section now links to the read that
  serves that one format.

- The function detail can search its binary's stored documents.
  `GET /api/functions/<id>/knowledge` ranks the binary's knowledge scope
  against a query and resolves a blank one to the function's own name, and
  nothing in the SPA read it: the Knowledge view searches a whole binary's
  scope and the function page offered no way to ask what the documents say
  about the function in front of the analyst.  The knowledge panel takes a
  query, reports the chunk count the route resolved, and renders the same
  ranked-hit list the Knowledge view uses, which now lives in
  `panels/KnowledgePanel.tsx` rather than inside the view.

- The auto-mode view can recover a run whose process died.  `reportal
  auto-recover <run-id>` and `POST /api/auto/runs/<id>/recover` closed a run a
  killed worker left `running`, and the SPA had no control for it: that run
  never left `running`, so the view polled it forever, showed "a run is
  working" and offered nothing but Revert.  The panel now offers Recover while
  a run reads `running`, with a confirm saying the run is treated as stale, and
  its notice reports how many tasks were interrupted, how many descriptors
  stayed revertible and how many reserved writes may or may not have landed.

- The binary detail lists the stored scans with the inputs each ran with.
  `GET /api/binaries/<id>/scans`, `GET /api/analyses/<id>/scans`, `reportal
  scans` and the `list_scans` tool served the listing (the recorded inputs
  beside every scan, which is what a reader needs to run one again the same
  way) and the SPA only said which scans were present, through the detail
  coverage panel.  The `Scans` panel lists one row per scan of the newest
  analysis: its kind, its status, its recorded inputs (a scan that recorded
  none says `none recorded`) and when it ran.

- The signature panel can show its edit history and revert a version.  The
  history model, the revert, the journal, the CLI (`signature-history`,
  `signature-revert`) and the `get_signature_history`/`revert_signature_history`
  tools all existed and the SPA rendered none of it, while the data-type editor
  one panel away had exactly that.  The panel's `History` toggle lists one row
  per recorded version (its id, source, actor, timestamp and the prototype that
  version replaced, or `created this signature` for the row whose previous state
  was nothing) with a Revert that restores it.  Each history row now carries
  that prototype rendered by `signatures.render_prototype`, the same renderer
  the CLI, the header export and the function's own signature read use, so the
  panel does not re-implement the rendering.

- The function detail renders the engine's cross-references.  `GET
  /api/functions/<id>/xrefs`, `reportal xrefs` and the `get_xrefs` tool all
  reached the live scan and the SPA had no panel for it, so the page showed the
  stored globals, callers and callees and not the instructions the binary
  actually points at the address with.  The panel loads on demand, like the
  other engine-backed reads on that page, and renders one row per reference:
  the referencing address, its kind and the instruction text, plus a note when
  the target is an import slot.

- A composition in which two enabled components provide the same context name
  is now refused before any effect runs (`components.assert_unique_providers`,
  checked by `run_pipeline`, `ComponentHost.__init__` and `ComponentHost.sync`),
  instead of the first declaration silently winning the provider map while both
  components ran and the second's binding outlived the provider's revert.  The
  rule is the paper's coeffect precondition (one writer per key is exactly what
  its independence condition needs), and `docs/COMPONENTS.md` now maps the
  paper's mechanisms it does not implement (fibers, coeffect isolation and
  interception, derived realization, inertia, and the effect iterator as a
  reified value) and the two deliberate deviations
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

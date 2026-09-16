# Threat model

Last reviewed: 2026-09-17.

This is a source-derived model of reportal's exposure, not a live probe.  It
names the boundary, the control that exists, and the residual risk a reader
should weigh.  Every control below is a symbol in the tree, so it can be
checked.  Point vulnerabilities and code fixes belong elsewhere; this document
records the system-level posture.  Owner and review cadence are organizational
and are not named here.

## Risk-ranked summary

| Rank | Risk | Boundary | Why it ranks here | Control today | Gap |
|------|------|----------|-------------------|---------------|-----|
| 1 | Opt-in sample detonation shares the host kernel | 7 | Only path that executes attacker-supplied bytes; a kernel escape is host compromise | Off until `sandbox.require_enabled` + installed runner; `BwrapRunner` unshares namespaces and caps wall/CPU/AS (`sandbox.py`) | No seccomp, no VM, runner binary not attested |
| 2 | Plaintext secrets and binaries at rest | 2, Secrets | Stolen `reportal.db` or `reportal backup` archive yields every stored credential and sample | FS permissions; reads never return secret values (`secret_store`); tokens stored as SHA-256 only (`auth.hash_token`) | No encryption at rest; journal retains prior secret values until pruned |
| 3 | Auth-off loopback is full operator | 1 | Any local process that can open the bind is the operator | Default `127.0.0.1`; `cli._require_lan_auth` refuses a wider bind until auth is on and a user exists | No rate limit; XSS against the SPA origin steals `localStorage` token (`web/src/api.ts` `TOKEN_STORAGE_KEY`) |
| 4 | Billing webhook vs bearer gate | 10 | Entitlement change is high impact; Stripe cannot present a portal bearer | HMAC + timestamp in `billing.verify_webhook`; no secret configured refuses every webhook | When `auth.required()` is true, `server._reportal_headers` demands a bearer on every `/api` path *before* signature check, so a LAN-auth install cannot receive Stripe deliveries as written |
| 5 | Metering records but does not refuse | Abuse | A tenant (or auth-off operator) can burn inference / auto runs past published allowances | `metering.charge_task` / `record_usage` append the ledger; `quota_check` computes `allowed` for the usage panel | No request path branches on `quota_check(...)["allowed"]` to stop work |
| 6 | SSRF-shaped URL ingest (opt-in) | 5 | Caller-chosen URL leaves the process | Off by default; `remote_ingest.validate_target` + peer check | Residual TOCTOU; handshake bytes may leave before block |
| 7 | LLM / agent as untrusted actuator | 6 | Model sees workspace text; destructive tools run after one analyst confirm | Bridge off without endpoint; destructive tools pause for `POST .../confirm` (`agent.py`) | Read-only tools run unbound by analyst intent; results leave to the configured endpoint |

## Posture

reportal is a single-process, single-host application: one SQLite database
(`store._SCHEMA`, the `users` table included) and a `binaries/` plus `reports/`
directory per workspace.  It is designed to run on a loopback interface beside
the rebrew checkout it drives, and the default bind is `127.0.0.1`
(`cli.serve`, `server.LOOPBACK_HOSTS`).  On that bind it is a single-user tool
with no identity in play; a bind another machine can reach refuses to start
until token auth is on and a user exists (`cli._require_lan_auth`).  It does not
execute the binary it analyses by default: it reads bytes and calls the sibling
`rebrew` package in process (`engines.RebrewEngine`; every method imports
rebrew entry points rather than spawning a CLI), and, only when the workspace
opts in, a sandbox runner (`sandbox.py`) that isolates a sample it was asked to
detonate.  External list-argv helpers still exist where a tool is not in-tree
(for example `unpack._run_upx`).  That boundary is what the rest of this
document qualifies, and the sandbox is the one place sample execution moves, so
it is written out in full below.

## Trust boundaries

1. **Network client to application.**  The SPA and any reachable HTTP client
   reach every route in `api.py` and the static assets served by `ui.py`.  The
   server rejects a request whose Host header is not allowlisted
   (`server._validate_host`, `server.LOOPBACK_HOSTS`) and answers with fixed
   security headers (`server._security_headers`).  Authentication has two
   modes, chosen once per install by `auth.required()` (`REPORTAL_AUTH=required`
   or `[auth] required = true`):
   - **off** (the default).  The caller *is* the operator.  The loopback bind is
     the safeguard, and `cli.serve` refuses a non-loopback bind in this mode
     (`cli._require_lan_auth`), so an exposed control plane cannot be reached by
     forgetting a flag.
   - **on**.  Every `/api` request needs `Authorization: Bearer <token>`
     (the `server._reportal_headers` middleware calling `server.authenticate`,
     so it cannot be bypassed by a route added later).  `auth.authenticate` compares the digest
     of the presented token with every user's in constant time
     (`hmac.compare_digest`) and refuses a disabled user; the caller's role must
     carry the permission the method and path imply (`auth.required_permission`:
     `read` for a read, `write` for a write, `admin` for the user table).  Only
     the token's SHA-256 digest is stored (`auth.hash_token`), the token is
     shown once, and it is 256 bits of `secrets.token_urlsafe` randomness.
   The static SPA shell and its assets stay public in both modes: they carry no
   portal data, and a browser cannot attach a header to the initial document
   request.  Every `/api` route, `/api/health` included, is behind the gate.
   Authorization beyond the route kind is per object: a binary or a collection
   carries a `visibility` (`public` or `team`) and an `owner_team_id`, and
   `server._enforce_scope` resolves the object a path names (a function, an
   analysis, a data type, a comment, a document, a conversation, a pipeline
   run, an auto run or a graph node through its owning binary) to refuse a
   non-member's read with the object's own 404 and its write with 403
   `scope-forbidden`.
   The listings (`/api/binaries`, `/api/collections`, `/api/analyses`,
   `/api/jobs`), the batch reads (`/api/functions/matches`,
   `/api/functions/callees-callers`, `/api/functions/signatures`) and
   `/api/search` filter their pages by the same rule (`auth.visible_clause`)
   and a bulk action skips the ids outside it.
   Three access layers stay distinct: team scope guards data objects,
   role checks (`viewer`/`analyst`/`admin`) guard tenant administration
   (users, teams, organisations, billing, components), and the secret store
   enforces its own workspace/team `may_read`/`may_write`.  Scoping tenant
   admin to team membership would let any member reshape the tenant, and
   scoping global vocabularies (tags, families, models) would fragment
   shared taxonomies for no security gain.
2. **Application to durable local state.**  The database and workspace are
   written by the store, the journal and auto mode.  Filesystem permissions and
   host-user access therefore cross this boundary; there is no encryption.
   Request-scoped writes are revertible through `journal` and run-scoped writes
   through `effects.apply_undo_plan`, but the journal is not an audit trail of
   identities, only of writes.
3. **Uploaded bytes to the parser.**  A binary arrives through
   `api.upload_binary`, which streams it to `binaries/<sha256>` while hashing,
   stops at `api.MAX_UPLOAD_BYTES` (256 MiB) with 413 `file-too-large`, derives
   the stored suffix only from `api._UPLOAD_SUFFIX`, and drops a `.`/`..` client
   name (`api._client_name`).  The file is stored; the parsing happens in the
   rebrew engine, not in reportal.
4. **Ingested documents and URLs to the knowledge store.**
   `knowledge.ingest_document` bounds a document at
   `knowledge.MAX_DOCUMENT_BYTES` (512 KiB) and accepts only
   `knowledge.is_supported_name` names.  A URL is a separate, off-by-default
   path (boundary 5).
5. **Guarded URL ingestion to the network.**  `remote_ingest` is enabled only
   by `REPORTAL_ALLOW_REMOTE_INGEST` or `[knowledge] allow_remote`, and while it
   is off every remote path answers 403 `remote-ingest-disabled` with no
   request.  When on, `remote_ingest.validate_target` requires `http`/`https`,
   rejects credentials in the URL, checks every address the host resolves to
   against the loopback, private, link-local, multicast, unspecified and
   reserved ranges (an IPv4-mapped IPv6 form included), and restricts the port
   to `remote_ingest.ALLOWED_PORTS`.  `remote_ingest.fetch` re-validates each
   redirect hop, bounds the body at `MAX_BYTES`, and checks the address the
   connection actually reached (the peer check); a transport that exposes no
   peer reports `PEER_UNVERIFIED`.
6. **Model to stored artifact.**  The optional LLM bridge sends decompiled code
   and retrieved documents as untrusted data (labelled in the prompt by
   `llm._messages` and `llm.function_triage_messages`) and validates the answer
   before storing it.  `llm._strip_reasoning` removes leaked reasoning and
   tool-call markup, and the artifact parsers require their fields, so a
   malformed answer raises `LlmError` rather than storing a partial artifact.
   The model's output is data; nothing in reportal evaluates it.  A rewritten
   function (`ai_decomp.py`) is the largest such artifact and the rule is the
   same: it is stored as text and served as text, nothing compiles or runs it,
   and an analyst override is a whole-token text substitution over that text
   with the C keywords and the string literals left alone.
   An **agent run** (`agent.py`) is the one place the model can ask for an
   action rather than only produce text.  Its answer is a tool call, and the
   call is not executed on the model's word: a tool whose `Tool.annotations` do
   not say `readOnlyHint` and do say `destructiveHint` pauses the run, and only
   an explicit `POST /api/conversations/<id>/confirm` with `approve: true` runs
   it.  An unknown tool name counts as destructive, arguments are validated
   against the tool's own input schema by the registry, and every call's
   arguments and bounded result are recorded on the run.  A tool the model
   chooses is still a tool the *analyst* approved; that is the whole gate, so an
   operator who does not want a model to be able to reach a tool should not
   enable the bridge (the feature is off without an endpoint).
7. **Sample bytes to the sandbox (opt-in, bounded).**  `POST
   /api/binaries/<id>/dynamic-execution` executes a stored sample, and it is the
   only path in reportal that does.  Four guards hold before any process starts:
   the workspace opts in (`REPORTAL_SANDBOX=enabled` or `[sandbox] enabled =
   true`, `sandbox.require_enabled`), a runner is installed
   (`sandbox.require_runner`, else 503 `sandbox-unavailable`), the row has a file
   on disk, and the bounds are inside the caps (`sandbox.requested_caps`:
   `DEFAULT_TIMEOUT_SECONDS` 10 / `MAX_TIMEOUT_SECONDS` 60, `DEFAULT_MEMORY_MB`
   512 / `MAX_MEMORY_MB` 4096, and a CPU cap no larger than the wall clock).
   `sandbox.BwrapRunner` runs `bwrap` with `--unshare-all` (network, PID, mount,
   IPC and UTS namespaces), `--die-with-parent`, `--new-session`, `--clearenv`,
   the host root bound read-only, fresh `/proc` and `/dev`, and exactly one
   writable path (a directory reportal created and removes on every exit path,
   including one where the runner itself raised).  The sample is
   bind-mounted read-only inside that directory and executed from there, never
   from its stored path; the caps are applied by the shell's `ulimit` inside the
   sandbox rather than by `preexec_fn`, which Python documents as unsafe in a
   threaded server.  The run is recorded (`sandbox_runs`: the command, the caps,
   the exit status, the duration, bounded stdout/stderr tails and the files the
   sample wrote) and journaled, and a run that outlives its timeout is killed by
   process group.
8. **Firmware bytes to the carve.**  `firmware.py` reads the stored file and
   looks for magics; it writes nothing itself, and
   `api.firmware_extract_binary` writes carved regions into temporary files
   under the workspace's `binaries/` directory, which the same
   `archive.extract` and `_register_member` path an upload uses then registers
   or refuses.  Nothing is mounted, spawned or executed, so a firmware image is
   untrusted input to a byte scanner and to the stdlib archive readers, not to a
   loader.
9. **Engine results to the store.**  `engines.RebrewEngine` calls rebrew in
   process (see the module docstring: every method imports the engine's own
   entry points).  Failures become `EngineError` with a message bounded by
   `engines.ERROR_MESSAGE_CHARS`.  The engine's output is trusted only as far
   as it is stored as data; reportal does not sandbox the engine process, so a
   hostile project or toolchain bug runs with the portal's OS user.
10. **Provider webhook to entitlement.**  `POST /api/billing/webhook`
    (`api.apply_billing_webhook`) is the one HTTP path whose intended
    authenticator is not a portal bearer: `billing.verify_webhook` requires a
    configured `REPORTAL_STRIPE_WEBHOOK_SECRET`, verifies the Stripe HMAC and
    timestamp window, refuses an install with no secret (503), and
    `billing.apply_event` is idempotent through `billing_events`.  Plan
    entitlement comes from the subscription's price id
    (`billing._plan_from_subscription_object` / `plans.plan_for_price_id`), not
    from caller-supplied checkout metadata.  Checkout and portal sessions still
    need an authenticated tenant admin (`api.start_billing_checkout`).  Public
    `/pricing` (`ui.py` / `landing.py`) and `GET /api/plans` advertise catalog
    text only.  Residual: when `auth.required()` is true, the bearer middleware
    (`server._reportal_headers` → `server.authenticate`) still gates every
    `/api` path, including this webhook, before signature verification runs.

## Attack surface and entry points

| Entry point | Input origin | Code |
|-------------|--------------|------|
| API routes | Network client; JSON bodies and query strings | `api.py`, `server.read_json_object` |
| Static SPA assets | Network client | `ui.py`, `reportal/assets/dist` |
| Public pricing page | Network client; no portal data | `ui.py` `/pricing`, `landing.py` |
| Stripe billing webhook | External provider; signed body + `Stripe-Signature` | `api.apply_billing_webhook`, `billing.verify_webhook` |
| Job queue submit / cancel / run | Network client; kind + binary id | `api.py` `/api/jobs*`, `jobs.submit`, `jobs.ensure_worker` |
| Background job pool | In-process workers (off via `REPORTAL_JOBS_POOL`) | `jobs.JobWorker`, `jobs.MAX_WORKERS`, `jobs.MAX_QUEUED_JOBS` |
| Binary upload | Network client; arbitrary bytes and filename | `api.upload_binary`, `api._stream_upload` |
| Document upload and paste | Network client; untrusted text | `api.py` knowledge routes, `knowledge.ingest_document` |
| URL ingest | Network client; caller-chosen URL | `api.py` ingest-url route, `remote_ingest.validate_target` / `fetch` |
| Authenticated API client | Network client; bearer token header | `server._reportal_headers` + `server.authenticate`, `auth.authenticate` |
| Team-scoped object request | Network client; object id in the path | `server._scoped_object`, `server._enforce_scope`, `auth.visible_clause` |
| External-source pull (opt-in) | External service (only when enabled and keyed); the binary's hash | `api.py` external routes, `external.virustotal_source`, `external.fetch_virustotal` |
| External-source plugin | Third-party package on the host | `external.refresh_sources`, `reportal.external_sources` |
| Secret read and write | Network client; a credential name, scope and value | `api.py` secret routes, `secret_store.normalize_*`, `secret_store.journaled_set` / `journaled_delete` |
| Sample detonation (opt-in) | Network client; a stored sample and capped bounds | `sandbox.detonate_binary`, `sandbox.BwrapRunner`, `sandbox.execute` |
| Packer rebuild (`upx -d`) | Stored binary bytes, plus the external `upx` tool on `PATH` | `unpack.unpack_to`, `unpack._run_upx`, `binary_actions.unpack_binary` |
| Registered sandbox runner | Third-party package on the host | `sandbox.refresh_runners`, `reportal.sandbox_runners` |
| LLM endpoint responses | External service (only when configured) | `llm.LlmClient.complete`, `llm.LlmClient.chat`, `llm._parse_json` |
| Metered AI / auto usage | Authenticated tenant request; organisation from active team | `server._charge_credits`, `metering.charge_task`, `metering.record_usage` |
| Agent tool calls | LLM endpoint response, gated by an analyst's confirmation | `agent._drive`, `agent.confirm`, `mcp_server.call_tool` |
| MCP stdio client | Local process on stdin | `mcp_server.py`, `mcp_tools.py` |
| CLI arguments and environment | Local operator | `cli.py`, `_paths.DB_ENV` |
| Stripe secret / webhook secret / price ids | Environment (`REPORTAL_STRIPE_*`) | `billing._webhook_secret`, `settings.py` billing.* |
| Background continuations (pipeline/auto workers, agent loop, conversation
  context) | The authorized request that started them; no second principal |
  `pipeline.function_knowledge`, `auto_llm_worker`, `agent._execute`,
  `conversations.scope_knowledge` |
| Workspace `reportal.toml` and database files | Local filesystem | `_paths`, `store`, `journal` |
| Readiness check (`reportal doctor`) | Local operator; the workspace, the port and the optional paths | `doctor.report`, `_port_check`, `_schema_check` |

## What is out of scope

- **Unconditional static-only analysis.**  Detonation exists and is bounded
  (boundary 7), so "reportal never runs a sample" is a default, not a guarantee:
  it is off until an operator enables it and installs a runner, and it is capped,
  unnetworked and read-only-rooted when it runs.  What remains out of scope is
  *safe* execution: reportal ships no seccomp filter, no syscall tracing and no
  kernel of its own, so a sample that escapes the runner's namespaces (a kernel
  bug) is the host's problem, and running untrusted code is never risk-free.
  Malware containment and full dynamic-analysis depth stay the operator's and
  bubblewrap's, not reportal's.
- **Mounting or parsing the sample's contents.**  Firmware carving reads bytes
  and writes region files; it never mounts an image or runs what it holds, and
  the analysis paths (filetype, capabilities, secrets, triage) are static.  Only
  boundary 7 executes anything.
- **Documents, comments, conversations, runs and graph nodes have no scope of
  their own.**  The team scope lives on binaries and collections; a document,
  a comment, a conversation, a pipeline run, an auto run or a graph node is
  reached through the binary or function it hangs off, so it follows that
  object's scope (a project- or docs-scoped document or conversation names
  no binary and stays global), but there is no per-document restriction
  inside a visible binary.  The comment `author` remains free text kept in
  the browser (`comments.DEFAULT_AUTHOR`, `comments.normalize_author`), an
  attribution convenience, not a security principal.
- **Embedded rows follow their container.**  A collection's member list, a
  conversation's messages, a document's chunks, an analysis's scans and a
  run's artifacts/tasks are served with the container's own visibility, not
  filtered per row: the container route is gated, and filtering members
  would make a shared container lie about what it holds.  Cross-scope
  embedding is stopped at the writes (membership `may_write`, scoped
  creates), not at the reads.
- **A registered binary points at its path.**  `reportal add-binary`, its
  `register_binary` MCP twin and `import-rebrew` record a file's path rather than
  copying its bytes, so a binary the operator registered is read from where it
  lies for every later engine call: a caller who can name a path can make the
  server read it, which `import_symbols` and the export tools already could.  The
  upload path is the one that streams the bytes into `binaries/` instead.
- **The journal halves of the feeds stay global.**  The analysis-log halves of
  `/api/notifications` and `/api/users/activity` narrow to the caller's scope,
  but the journal halves list every action: an entry carries a free-text
  description ("tagged binary 4 with tag 7"), never a structured object
  reference, so narrowing it would mean resolving every descriptor shape to an
  owning binary on each read *and* on the revert path (hiding an action while
  accepting its id for revert is a confused deputy).  A non-member learns
  numeric ids of acted-on objects, never names or contents: the
  cardinality-class residual below, accepted rather than filtered.
- **The team scope narrows objects, not aggregates.**  `GET /api/health` counts
  every row and `store.search`'s per-group `total` is the unfiltered match
  count, so a member of the workspace can learn *how many* objects exist that it
  cannot open, though not their names.  The dashboard, notification and
  activity series narrow their binary-owned counts to the caller's scope; the
  match, composition, lineage, related and benchmark runs score only visible
  binaries, so the remaining aggregate leak is counts, not content.
- **Multi-tenancy.**  One process owns one workspace and one database
  (`_paths.project_root`).  Concurrent independent users are outside the model,
  as is per-tenant isolation.
- **A reverse-proxy deployment.**  reportal's own token gate is the only
  authentication it implements; an operator who fronts it with a proxy owns
  that layer's configuration (TLS, client certificates, rate limits).  A proxy
  that must admit Stripe to `/api/billing/webhook` while keeping bearer auth on
  the rest of `/api` is outside reportal: the process itself has no path
  exemption for that route (`server._reportal_headers`).
- **Engine and toolchain isolation.**  The rebrew package runs in the portal
  process with the operator's privileges; reportal does not sandbox it.  The
  same holds for the external unpacker: `reportal unpack` runs `upx -d` on a
  stored sample when that tool is installed, as a list-argv subprocess with no
  shell, a captured output and a bounded timeout, and it decodes a file rather
  than running it, but a bug in UPX itself is UPX's problem.  The engine's own
  LZEXE case is arithmetic over the bytes in this process and shells out to
  nothing.

## Abuse cases

Hostile-but-authenticated (or auth-off operator) scenarios with the enabling
path named.  None of these are demonstrated here.

- **Fill the job queue.**  `POST /api/jobs` accepts kinds from `jobs.JOB_KINDS`
  until `jobs.MAX_QUEUED_JOBS` (100).  The pool is `jobs.MAX_WORKERS` (2)
  threads.  There is no per-caller rate limit, so a write-capable caller can
  keep the workers busy with expensive kinds (match, pipeline, PDF) and delay
  other work.  Caps are size and queue depth, not request rate
  (`jobs.submit`, `jobs.ensure_worker`).
- **Burn inference past the published allowance.**  For an organisation with an
  active team, `server._reportal_headers` installs `llm.charging` →
  `metering.charge_task`, which only appends usage.  `metering.quota_check`
  computes whether units would fit and is served on
  `GET /api/organisations/<id>/usage`, but no AI or auto route refuses on
  `allowed: false`.  Credits.py comments describe refusal; the live request
  path does not implement it.
- **Workspace-wide journal revert.**  Any authenticated caller with write may
  revert journal entries (`revert_journal_entry`), including another actor's
  writes.  Team scope does not narrow the journal half of activity feeds
  (see out-of-scope above).
- **SPA token theft via origin XSS.**  Enforcement of auth is server-side; the
  client only stores and attaches the bearer (`web/src/api.ts`).  A script on
  the portal origin reads `TOKEN_STORAGE_KEY` from `localStorage`.  There is no
  HttpOnly cookie session to fall back on.
- **Register a path instead of uploading bytes.**  `reportal add-binary` /
  `register_binary` records a filesystem path the server later reads for engine
  work.  A caller who can name paths the portal user can read enlarges the read
  surface beyond `binaries/` (same residual as out-of-scope above).

## Secrets

- The optional LLM API key resolves from `REPORTAL_LLM_API_KEY`, else
  `[llm] api_key` in `reportal.toml`, else the secret store under
  `llm.api_key` (`llm.LlmConfig.resolve`).  It is excluded
  from the config's `repr` and is never logged or returned; a request carries it
  only as a bearer header (`llm.LlmClient._headers`).  Environment variables are
  preferred over the workspace file, and both are preferred over the store.
- **The secret store holds credentials in plaintext at rest.**
  `secret_store.py` keeps one row per `(name, scope, team_id)` in the workspace
  SQLite file, so the file's own permissions are the boundary: anyone who can
  read `reportal.db` can read every stored credential.  What the module does
  enforce is that no *read path* returns a value: `list_secrets`, `get_secret`
  and `journaled_set` report the name, scope, byte length and a last-four hint
  (and no hint at all for a value shorter than `MIN_HINT_LENGTH`), the API, CLI
  and MCP surfaces serve only that, and `secret_store.value_of` is the single
  function that returns a credential, called by an internal consumer on the
  caller's behalf (`llm` for the bridge, an external source for its own key).
  A workspace secret needs an admin to write, a team secret that team's
  membership; with auth off the install is the single local operator.  A write
  is journaled, so a rotation is revertible and the *previous* value stays in
  `journal_entries` until that action is reverted or pruned: that is the one
  residual worth naming, and it is what makes a rotation undoable.  The value
  is never passed through argv: ``reportal secrets-set`` requires ``--stdin``
  so the value cannot land in the shell history or a process listing.
- `secrets.py` is a scanner, not a credential store: it finds secret-shaped
  strings in a binary's strings and records both the value and a `redacted` form
  (`secrets._add`, `secrets.redact`).  The raw value is stored in the scan
  payload, so a scan of a binary that contains a live credential puts that
  credential in the database (a residual risk below).
- A user's bearer token is generated by `auth.new_token` and returned once, at
  creation or rotation; only `auth.hash_token` (SHA-256) is stored, so the
  database carries no usable credential and a stolen database copy cannot
  authenticate.  The token is never logged: the middleware reports a fixed
  detail that does not echo the header value.
- **A backup carries every secret the workspace holds, plus the stored binary
  bytes.**  `reportal backup` writes one archive of the database, the stored
  binaries and the generated reports, and the database is where the secret store
  keeps its plaintext values.  The archive is therefore exactly as sensitive as
  the workspace directory itself and must be stored with the same care; it is
  not encrypted, and reportal ships no passphrase for it.  `reportal restore`
  refuses an archive whose members do not match its own manifest and refuses a
  member whose path leaves the archive root, so a crafted archive cannot write
  outside the workspace, but nothing there authenticates *who* made an archive:
  a restore trusts the archive the operator named, which is the same trust the
  operator already extends to the filesystem.
- No secret is passed through argv.

## Residual risks

- **A token in the browser is only as safe as the origin.**  The SPA keeps the
  bearer token in `localStorage` (`api.TOKEN_STORAGE_KEY`) and sends it on every
  request, so a cross-site scripting flaw in the SPA or an extension with access
  to the origin can read it.  There is no cookie, no session and no rotation on
  a timer; `reportal user-token <id>` rotates one by hand.
- **Authorization is per route kind and per object scope, not per owner.**  A
  caller whose role carries `write` may write any *public* object in the
  workspace, and any authenticated user may revert the journal
  (`revert_journal_entry`), which is workspace-wide.  Team members share a
  team's objects fully: there is no per-member ownership inside a team, and an
  object has one owning team rather than a set of collaborators.
- **The journal is a revert tool that now attributes its entries.**  Each entry
  carries the `actor` the server recorded the request for (`local` while auth is
  off, empty for a CLI or MCP write), and `GET /api/users/activity` reports it.
  What it does not carry is the session: no token, no address, no user agent, so
  an entry says which identity acted, not from where or with which credential.
  An actor is a name, and a name is not a principal: renaming or deleting a user
  leaves the historic entries under the old name.
- **The user table is not a directory of trust.**  A name is free text and the
  role is the only attribute; there is no password, second factor, expiry,
  lockout after failed attempts or login attempt log.  That is a deliberate
  trade: the credential is a 256-bit random token, which is not guessable, so
  the missing controls defend against nothing an attacker can currently do.
- **An external pull tells a third party what you are looking at.**  With the
  remote source enabled and keyed, the binary's SHA-256 is sent to VirusTotal, so
  the request itself discloses which file is under analysis (and the workspace's
  key, which identifies the account).  The digest is the only thing sent: no
  bytes, no name, no path, and the answer is normalized rather than stored
  whole.  The gate is off by default, a URL a caller controls is impossible (one
  fixed host, the path built from the hash), a redirect is not followed, and the
  body is capped; what cannot be undone is the disclosure the request makes.
- **An agent run is a model with hands, behind one confirmation.**  A
  destructive tool is gated on the analyst's approval, but a read-only tool is
  not, and the model chooses which read-only tool to call, how often (bounded by
  `agent.MAX_TOOL_CALLS`) and with which arguments (validated against the tool's
  schema but not against the analyst's intent).  Reads disclose whatever the
  caller may read, a tool result is fed back into the model's context (so
  workspace data leaves to the configured endpoint), and the run's own journal
  action does not cover a tool's writes: reverting the conversation removes the
  run and its messages, not what a tool changed, which carries its own action.
  Cancel is honoured at a step boundary, so a call in flight completes.
- **A stored credential is only as safe as the database file.**  The secret
  store keeps values in plaintext in the workspace SQLite file and reports the
  last four characters of any value long enough to hint, so a stolen database
  copy loses every stored credential; there is no encryption at rest, no key
  derivation and no per-row access control beyond the admin/team rule the
  routes apply.  The rotation path also leaves the replaced value in
  `journal_entries` until that action is reverted or pruned.
- **Remote-ingest TOCTOU is reduced, not eliminated.**  Validation and the
  connection are separate steps; the peer check withholds the body of a blocked
  connection but the request and (for HTTPS) handshake bytes have already left
  the process.  A namespace with no private routes would isolate more strongly
  (`remote_ingest` module docstring).
- **Prompt injection through untrusted context.**  Decompilation, documents and
  the threat-report evidence are sent to the model.  The output is parsed and
  stored, never executed, but it is shown to the user and a rename suggestion is
  applied on request (`renames.apply_renames`); `renames._refusal` requires both
  names to be valid C identifiers, rejects a protected identifier
  (`renames.PROTECTED_IDENTIFIERS`) and an absent `from`
  (`renames.identifier_present`), which limits but does not remove a misleading
  suggestion.
- **Stored agent output is trusted on read.**  An artifact is rendered by the
  SPA and included in reports; reportal sanitizes the JSON shape, not the text
  content.  Any escaping is the renderer's.
- **Secret values are stored in cleartext.**  A secrets scan keeps the matched
  value (`secrets._add`); anyone with the database can read it.
- **The file-write inverse does not check ownership.**
  `effects._undo_file_write` removes whatever file is at the descriptor's path.
  Auto mode compensates where it reserves (`auto_mode._reservable_file`); a
  hand-rolled journal site does not.
- **A stale auto run is treated as dead.**  There is no registry of live runs,
  so recovering a run another process is still working marks its live tasks
  `failed` (`auto_mode.recover_auto_run`).
- **Detonation is one process boundary, not a second machine.**  The sandbox
  shares the host kernel and its user namespace; there is no seccomp filter, no
  syscall log and no VM.  `RLIMIT_AS` (the `ulimit -v` cap) bounds address space,
  not resident memory, so a sample that maps sparsely can hold more RSS than the
  cap suggests; the wall-clock timeout and the CPU cap are the backstops.  A
  sample's own network attempts are contained by the unshared network namespace
  (there is no route and only loopback), not enumerated: the report says the
  network was unshared rather than listing what it tried.
- **The runner is an external tool reportal does not audit.**  reportal builds
  the argv and records it; it does not verify that `bwrap` is the real binary, and
  a runner registered through the `reportal.sandbox_runners` group is trusted
  code.  `REPORTAL_SANDBOX_RUNNER` or `[sandbox] runner` naming a plugin is the
  same trust statement as installing it.
- **A run is recorded, not reversible in its effects.**  The `sandbox_runs` row
  is journaled, so a revert removes the record; what the sample did while it ran
  (its writes in the removed directory, its process tree) is contained by the
  sandbox rather than undone by the journal, which is the honest boundary of the
  effect model here.
- **No rate limiting or quota enforcement on the request path.**  Each request
  is bounded (upload size, body size, task counts, `auto_mode.MAX_CONCURRENCY`,
  `jobs.MAX_QUEUED_JOBS`), but a client can repeat requests or start many runs.
  `metering.quota_check` is advisory for the usage panel only; see Abuse cases.
- **Billing webhook signature is not reachable under LAN auth.**  The intended
  control is `billing.verify_webhook`.  With `auth.required()`, Stripe's POST
  lacks a portal bearer and is refused by `server.authenticate` first.  An
  install that both binds non-loopback (which requires auth) and expects Stripe
  webhooks therefore has no working in-process path for entitlement updates
  unless something outside reportal supplies a bearer Stripe does not have.
- **The database is unencrypted and single-host.**  Host compromise, a stolen
  backup, or filesystem access discloses all portal state; see
  [DR_RUNBOOK.md](DR_RUNBOOK.md).
- **Open model gaps recorded in [COMPONENTS.md](COMPONENTS.md)**  carry security
  weight: no observational-equivalence guarantee for a revert, the file-write
  ownership gap above, and partial app-wide mediation (a writer that does not
  journal is not revertible).

## Response readiness (note only)

- Journal entries record an `actor` name for authenticated HTTP writes
  (`journal.acting_as`); CLI/MCP writes may carry an empty actor.  There is no
  source address, user agent or token id on the entry, so investigation of
  "who from where" needs host or reverse-proxy logs, not the journal alone.
- This repository's disclosure path is stated in [SECURITY.md](../SECURITY.md).
  There is no in-tree runbook from "report received" to "fix shipped".
# Threat model

This is a source-derived model of reportal's exposure, not a live probe.  It
names the boundary, the control that exists, and the residual risk a reader
should weigh.  Every control below is a symbol in the tree, so it can be
checked.  Vulnerabilities and code fixes belong to review; this document records
the system-level posture.

## Posture

reportal is a single-process, single-host application: one SQLite database
(`store._SCHEMA`, the `users` table included) and a `binaries/` plus `reports/`
directory per workspace.  It is designed to run on a loopback interface beside
the rebrew checkout it drives, and the default bind is `127.0.0.1`
(`cli.serve`, `server.LOOPBACK_HOSTS`).  On that bind it is a single-user tool
with no identity in play; a bind another machine can reach refuses to start
until token auth is on and a user exists (`cli._require_lan_auth`).  It never
executes the binary it analyses: it reads bytes and parses engine JSON, and its
own subprocess is the rebrew CLI at `engines.RebrewEngine._run`.  That design
choice is a real boundary, and it is what the rest of this document qualifies.

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
     (`server.require_auth`, wired as a router dependency, so it cannot be
     bypassed by a route added later).  `auth.authenticate` compares the digest
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
   `server._enforce_scope` resolves the object a path names (a function or an
   analysis through its binary) to refuse a non-member's read with the object's
   own 404 and its write with 403 `scope-forbidden`.  The listings and
   `/api/search` filter their pages by the same rule (`auth.visible_clause`) and
   a bulk action skips the ids outside it.
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
   The model's output is data; nothing in reportal evaluates it.
7. **Firmware bytes to the carve.**  `firmware.py` reads the stored file and
   looks for magics; it writes nothing itself, and
   `api.firmware_extract_binary` writes carved regions into temporary files
   under the workspace's `binaries/` directory, which the same
   `archive.extract` and `_register_member` path an upload uses then registers
   or refuses.  Nothing is mounted, spawned or executed, so a firmware image is
   untrusted input to a byte scanner and to the stdlib archive readers, not to a
   loader.
8. **Engine JSON to the store.**  `engines.RebrewEngine._run` spawns the rebrew
   CLI with a fixed subcommand and decodes its stdout as JSON, raising
   `EngineError` for invalid JSON or a non-object; the bounded stderr tail is
   `engines.STDERR_TAIL_CHARS`.  The engine's output is trusted only as far as
   it is stored as data.

## Attack surface and entry points

| Entry point | Input origin | Code |
|-------------|--------------|------|
| API routes | Network client; JSON bodies and query strings | `api.py`, `server.read_json_object` |
| Static SPA assets | Network client | `ui.py`, `reportal/assets/dist` |
| Binary upload | Network client; arbitrary bytes and filename | `api.upload_binary`, `api._stream_upload` |
| Document upload and paste | Network client; untrusted text | `api.py` knowledge routes, `knowledge.ingest_document` |
| URL ingest | Network client; caller-chosen URL | `api.py` ingest-url route, `remote_ingest.validate_target` / `fetch` |
| Authenticated API client | Network client; bearer token header | `server.require_auth`, `auth.authenticate` |
| Team-scoped object request | Network client; object id in the path | `server._scoped_object`, `server._enforce_scope`, `auth.visible_clause` |
| LLM endpoint responses | External service (only when configured) | `llm.LlmClient.complete`, `llm._parse_json` |
| MCP stdio client | Local process on stdin | `mcp_server.py`, `mcp_tools.py` |
| CLI arguments and environment | Local operator | `cli.py`, `_paths.DB_ENV` |
| Workspace `reportal.toml` and database files | Local filesystem | `_paths`, `store`, `journal` |

## What is out of scope

- **Executing the analysed sample.**  reportal has no route that runs the
  binary; analysis is delegated to rebrew subcommands that parse bytes
  (`engines.RebrewEngine`).  Malware containment, dynamic analysis and network
  isolation of a sample are the sandbox's problem, not reportal's.  Firmware
  carving follows the same rule: it reads bytes and writes region files, and it
  never mounts an image or runs its contents.
- **Documents, comments and conversations have no scope of their own.**  The
  team scope lives on binaries and collections; a document, a comment or a
  conversation is reached through the binary or function it hangs off, so it
  follows that object's scope, but there is no per-document restriction inside a
  visible binary.  The comment `author` remains free text kept in the browser
  (`comments.DEFAULT_AUTHOR`, `comments.normalize_author`), an attribution
  convenience, not a security principal.
- **The team scope narrows objects, not aggregates.**  `GET /api/health` counts
  every row and `store.search`'s per-group `total` is the unfiltered match
  count, so a member of the workspace can learn *how many* objects exist that it
  cannot open, though not their names.  Corpus-wide operations (matching,
  lineage, related) rank against every stored function rather than the visible
  subset, so their scores can be influenced by data the caller cannot read.
- **Multi-tenancy.**  One process owns one workspace and one database
  (`_paths.project_root`).  Concurrent independent users are outside the model,
  as is per-tenant isolation.
- **A reverse-proxy deployment.**  reportal's own token gate is the only
  authentication it implements; an operator who fronts it with a proxy owns
  that layer's configuration (TLS, client certificates, rate limits).
- **Engine and toolchain isolation.**  The rebrew CLI and its docker images run
  with the operator's privileges; reportal does not sandbox them.

## Secrets

- The optional LLM API key resolves from `REPORTAL_LLM_API_KEY`, else
  `[llm] api_key` in `reportal.toml` (`llm.LlmConfig.resolve`).  It is excluded
  from the config's `repr` and is never logged or returned; a request carries it
  only as a bearer header (`llm.LlmClient._headers`).  Environment variables are
  preferred over the workspace file.
- `secrets.py` is a scanner, not a credential store: it finds secret-shaped
  strings in a binary's strings and records both the value and a `redacted` form
  (`secrets._add`, `secrets.redact`).  The raw value is stored in the scan
  payload, so a scan of a binary that contains a live credential puts that
  credential in the database (a residual risk below).
- A user's bearer token is generated by `auth.new_token` and returned once, at
  creation or rotation; only `auth.hash_token` (SHA-256) is stored, so the
  database carries no usable credential and a stolen database copy cannot
  authenticate.  The token is never logged: `server.require_auth` reports a fixed
  detail that does not echo the header value.
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
- **The journal is a revert tool, not an audit log.**  It records the write and,
  once the identity slice lands, no actor column: the authenticated user of a
  request is not recorded beside the entry it caused (`journal._SCHEMA`).  Who
  did what is therefore not answerable from the database yet.
- **The user table is not a directory of trust.**  A name is free text and the
  role is the only attribute; there is no password, second factor, expiry,
  lockout after failed attempts or login attempt log.  That is a deliberate
  trade: the credential is a 256-bit random token, which is not guessable, so
  the missing controls defend against nothing an attacker can currently do.
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
- **No rate limiting or quota.**  Each request is bounded (upload size, body
  size, task counts, `auto_mode.MAX_CONCURRENCY`), but a client can repeat
  requests or start many runs.
- **The database is unencrypted and single-host.**  Host compromise, a stolen
  backup, or filesystem access discloses all portal state; see
  [DR_RUNBOOK.md](DR_RUNBOOK.md).
- **Open model gaps recorded in [COMPONENTS.md](COMPONENTS.md)**  carry security
  weight: no observational-equivalence guarantee for a revert, the file-write
  ownership gap above, and partial app-wide mediation (a writer that does not
  journal is not revertible).

# Threat model

This is a source-derived model of reportal's exposure, not a live probe.  It
names the boundary, the control that exists, and the residual risk a reader
should weigh.  Every control below is a symbol in the tree, so it can be
checked.  Vulnerabilities and code fixes belong to review; this document records
the system-level posture.

## Posture

reportal is a single-user, single-process, single-host application: one SQLite
database (`store._SCHEMA`) and a `binaries/` plus `reports/` directory per
workspace.  There is no identity, session or permission table.  It is designed
to run on a loopback interface beside the rebrew checkout it drives, and the
default bind is `127.0.0.1` (`cli.serve`, `server.LOOPBACK_HOSTS`).  It never
executes the binary it analyses: it reads bytes and parses engine JSON, and its
own subprocess is the rebrew CLI at `engines.RebrewEngine._run`.  That design
choice is a real boundary, and it is what the rest of this document qualifies.

## Trust boundaries

1. **Network client to application.**  The SPA and any reachable HTTP client
   reach every route in `api.py` and the static assets served by `ui.py`.  The
   server rejects a request whose Host header is not allowlisted
   (`server._validate_host`, `server.LOOPBACK_HOSTS`) and answers with fixed
   security headers (`server._security_headers`).  There is no authentication:
   the caller *is* the operator.  The loopback default is a deployment
   safeguard, and `cli.serve` disables the Host guard outright when the bind is
   not loopback (`server.configure_hosts(None)`); a non-loopback bind is an
   unauthenticated control plane (see residual risks).
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
7. **Engine JSON to the store.**  `engines.RebrewEngine._run` spawns the rebrew
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
| LLM endpoint responses | External service (only when configured) | `llm.LlmClient.complete`, `llm._parse_json` |
| MCP stdio client | Local process on stdin | `mcp_server.py`, `mcp_tools.py` |
| CLI arguments and environment | Local operator | `cli.py`, `_paths.DB_ENV` |
| Workspace `reportal.toml` and database files | Local filesystem | `_paths`, `store`, `journal` |

## What is out of scope

- **Executing the analysed sample.**  reportal has no route that runs the
  binary; analysis is delegated to rebrew subcommands that parse bytes
  (`engines.RebrewEngine`).  Malware containment, dynamic analysis and network
  isolation of a sample are the sandbox's problem, not reportal's.
- **User accounts, authentication and authorization.**  There is no identity
  model.  The comment `author` is free text kept in the browser
  (`comments.DEFAULT_AUTHOR`, `comments.normalize_author`), an attribution
  convenience, not a security principal.
- **Multi-tenancy.**  One process owns one workspace and one database
  (`_paths.project_root`).  Concurrent independent users are outside the model,
  as is per-tenant isolation.
- **A network-exposed deployment.**  Binding to a non-loopback interface is
  supported but disables the Host guard and leaves every route unauthenticated;
  a reverse proxy with its own auth is the operator's responsibility.
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
- No secret is passed through argv.

## Residual risks

- **An unauthenticated non-loopback bind exposes the whole control plane.**  The
  Host guard is disabled for such a bind and no route checks an identity, so a
  reachable client can mutate or delete state, run engine work and revert the
  journal.
- **The journal is a revert tool, not an audit log.**  It records the write, not
  who made it, and the revert route itself is unauthenticated.
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

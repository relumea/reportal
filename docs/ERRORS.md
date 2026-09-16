# reportal error codes

Every JSON error reportal returns has the same shape:

```json
{"error": "no-scan", "detail": "no threat scan for binary 7; ...", "doc_url": "https://github.com/maci0/reportal/blob/main/docs/ERRORS.md#no-scan"}
```

`error` is a stable, sanitized code: branch on it, never on `detail`, which is
human context and may name an id, a path or an engine message. `doc_url` links
to the section below that documents that code, or is `null` when the catalogue
does not name it, so a code is never linked to a section that does not exist.

The same vocabulary covers the stdio MCP server, where a code reaches the
caller as an MCP tool error (`isError: true` with `{"error", "detail"}`) rather
than an HTTP body.

The catalogue itself lives in one place in the code,
`src/reportal/error_docs.py` (`ERROR_DOC_ANCHORS`), and
`tests/test_error_docs.py` checks it against this page in both directions:
every code a route writes literally has a section here, every section heading
is an anchor the catalogue names, and no code is mapped to a missing heading.

Two families share one section: field-level validation messages built at the
call site (`narrative must be a boolean`, `invalid kind`) are documented under
[invalid-params](#invalid-params), and the two spellings of a code that both
exist in the codebase (`invalid body` / `invalid-body`) are documented once,
under the hyphenated heading.

## Contents

- Request shape: [invalid-body](#invalid-body), [invalid-json-body](#invalid-json-body), [request-body-must-be-a-json-object](#request-body-must-be-a-json-object), [invalid-params](#invalid-params), [invalid-bulk-request](#invalid-bulk-request), [invalid-data-type](#invalid-data-type), [invalid-scope-id](#invalid-scope-id), [invalid-scope-kind](#invalid-scope-kind), [invalid-size-range](#invalid-size-range), [invalid-kind](#invalid-kind), [invalid-limit](#invalid-limit), [invalid-hash](#invalid-hash), [short-hash](#short-hash), [ambiguous-hash](#ambiguous-hash), [invalid-url](#invalid-url)
- Uploads and archives: [no-file](#no-file), [empty-file](#empty-file), [file-too-large](#file-too-large), [too-many-files](#too-many-files), [unsupported-format](#unsupported-format), [external-tool-required](#external-tool-required), [password-required](#password-required), [bad-password](#bad-password), [corrupt-archive](#corrupt-archive), [archive-too-large](#archive-too-large), [too-many-members](#too-many-members), [binary-not-on-disk](#binary-not-on-disk), [too-many-documents](#too-many-documents)
- Not found: [edge-not-found](#edge-not-found), [string-not-found](#string-not-found), [binary-not-found](#binary-not-found), [function-not-found](#function-not-found), [collection-not-found](#collection-not-found), [family-not-found](#family-not-found), [comment-not-found](#comment-not-found), [conversation-not-found](#conversation-not-found), [data-type-not-found](#data-type-not-found), [document-not-found](#document-not-found), [member-not-found](#member-not-found), [node-not-found](#node-not-found), [project-not-found](#project-not-found), [run-not-found](#run-not-found), [tag-not-found](#tag-not-found), [format-not-found](#format-not-found), [domain-not-found](#domain-not-found), [component-not-found](#component-not-found), [action-not-found](#action-not-found), [entry-not-found](#entry-not-found), [history-not-found](#history-not-found), [analysis-not-found](#analysis-not-found), [candidate-not-found](#candidate-not-found), [signature-not-found](#signature-not-found), [not-found](#not-found)
- Debug symbols: [symbols-unreadable](#symbols-unreadable), [no-symbols](#no-symbols)
- Go binaries: [not-go](#not-go), [unreadable](#unreadable)
- Agent artifacts: [no-artifact](#no-artifact)
- Stored-only reads: [no-scan](#no-scan), [no-artifact](#no-artifact), [no-run](#no-run), [no-graph](#no-graph), [no-report](#no-report), [no-pdf](#no-pdf), [no-decompilation](#no-decompilation), [no-proposal](#no-proposal), [no-strings](#no-strings), [no-such-match](#no-such-match), [no-engine-context](#no-engine-context), [last-analysis](#last-analysis), [no-workspace](#no-workspace)
- Conflicts: [signature-conflict](#signature-conflict), [export-exists](#export-exists), [duplicate-name](#duplicate-name), [duplicate-member](#duplicate-member), [duplicate-parameter](#duplicate-parameter), [duplicate-family](#duplicate-family), [not-reloadable](#not-reloadable), [not-withdrawable](#not-withdrawable), [not-active](#not-active), [component-missing](#component-missing)
- Engines and models: [engine-error](#engine-error), [engine-unavailable](#engine-unavailable), [llm-error](#llm-error), [llm-unavailable](#llm-unavailable), [pipeline-unavailable](#pipeline-unavailable), [similarity-unavailable](#similarity-unavailable), [backend-unavailable](#backend-unavailable), [query-unsupported](#query-unsupported), [unmapped-address](#unmapped-address), [write-failed](#write-failed), [journal-error](#journal-error), [internal-server-error](#internal-server-error)
- Remote ingestion: [remote-ingest-disabled](#remote-ingest-disabled), [fetch-failed](#fetch-failed), [unresolvable-host](#unresolvable-host), [unsupported-content-type](#unsupported-content-type), [too-many-redirects](#too-many-redirects)
- Transfer and graph targets: [same-binary](#same-binary), [tag-not-on-binary](#tag-not-on-binary), [unknown-binary](#unknown-binary), [unknown-collection](#unknown-collection), [candidate-has-no-name](#candidate-has-no-name), [candidate-has-no-signature](#candidate-has-no-signature), [transfers-must-be-a-non-empty-list](#transfers-must-be-a-non-empty-list), [too-many-transfers](#too-many-transfers)
- Identity: [unauthorized](#unauthorized), [forbidden](#forbidden), [invalid-user](#invalid-user), [user-exists](#user-exists), [user-not-found](#user-not-found)
- Firmware: [invalid-region](#invalid-region), [region-not-found](#region-not-found)
- Sandbox: [sandbox-disabled](#sandbox-disabled), [sandbox-unavailable](#sandbox-unavailable), [invalid-sandbox](#invalid-sandbox)
- Identity: [invalid-feedback](#invalid-feedback), [invalid-team](#invalid-team), [team-exists](#team-exists), [team-not-found](#team-not-found), [not-a-team-member](#not-a-team-member), [scope-forbidden](#scope-forbidden)
- Conversations and jobs: [run-not-found](#run-not-found), [run-not-cancellable](#run-not-cancellable), [no-pending-confirmation](#no-pending-confirmation), [auto-busy](#auto-busy)
- Server: [ui-not-built](#ui-not-built), [unexpected-host-header](#unexpected-host-header), [provide-a-name-or-all-not-both](#provide-a-name-or-all-not-both), [provide-a-component-name-or-all](#provide-a-component-name-or-all)
- Documentation: [no-docs](#no-docs), [no-doc](#no-doc)

## Request shape

### invalid-body

`400`. The request body is not what the route expects: malformed
`multipart/form-data`, a body field of the wrong JSON type, or an option the
route cannot read. Read `detail` for the field, and send the shape the route's
entry in `docs/API.md` documents.

### invalid-json-body

`400` (`invalid JSON body`). The request declared a JSON body that does not
parse as UTF-8 JSON. Send a JSON object.

### request-body-must-be-a-json-object

`400`. The body parsed as JSON but is not an object (an array, a number, a
string). Wrap the payload in an object.

### invalid-params

`400`. The shared section for per-field validation messages: a body field of
the wrong type (`narrative must be a boolean`, `limit must be an integer`,
`name must be a string`), a value outside its bound (`top must be positive`), or
a value outside its closed vocabulary (`invalid params` for the auto-mode
bounds, `invalid override`, `invalid rating`, `invalid line-comment`,
`invalid kind`, `invalid backend`, `invalid severity`, `invalid format`
(a component list asked for a shape the exporter does not carry), `invalid doc`
(a documentation slug that is not a page's), `invalid regex`
(a search pattern that does not compile or is too long), and the rest).
`detail` names the field and the accepted values. Send a value inside the range
or the set the route documents.

### invalid-bulk-request

`400`. A bulk request's body is missing `action`, carries an unknown action, or
lists no ids. Send one of the route's actions and a non-empty id list.

### invalid-data-type

`400`. A type-model edit that no more specific code covers. `detail` names the
operation; check the request against the data-type routes in `docs/API.md`.

### invalid-scope-id

`400`. A knowledge scope id that cannot be used: a project scope needs a
negative id and a binary scope a stored binary. Send an id of the right kind.

### invalid-scope-kind

`400`. The scope kind is outside the closed set for that route
(`conversations.SCOPE_KINDS`, `knowledge.SCOPE_KINDS`). Send one of the kinds
the route documents.

### invalid-size-range

`400`. A function-list query gave `min_size` above `max_size`. Swap the bounds.

### invalid-kind

`400` (also `invalid-kind`). A query or body named a kind outside its closed
set: a scan kind, a search kind, a data-type kind, an artifact kind or a
diff kind. Send one of the names the route documents.

### invalid-limit

`400` (also `invalid limit`). A limit is not an integer, is not positive, or is
above the route's cap. Send a positive integer inside the documented bound.

### invalid-password

`400`. The password a zipped download was asked for is empty or longer than
`api.ZIP_PASSWORD_MAX_CHARS` (128 characters). The password is a shared
convention rather than a secret, so the route echoes it back in
`X-Reportal-Zip-Password`; send 1 to 128 characters, or omit the parameter to
get the default.

### invalid-hash

`400`. A SHA-256 query is not hexadecimal or is longer than 64 characters. Send
a hex prefix.

### short-hash

`400`. A SHA-256 prefix shorter than `store.MIN_SHA256_PREFIX` characters would
match too much. Send a longer prefix.

### ambiguous-hash

`400`. A SHA-256 prefix matches more than one stored binary. Send more
characters, or a full digest.

### invalid-url

`400`. A remote-ingestion target failed validation: empty, unparsable, without
a host, carrying credentials, with an invalid port, or on a port that is not
allowed. Send a plain `http`/`https` URL.

## Uploads and archives

### edge-not-found

`404` (`edge not found`). No analyst-declared callee edge carries the requested
id on that function. An edge belongs to the function that declared it, so an id
that exists on another function reads the same way.

### string-not-found

`404` (`string not found`). No analyst string carries the requested id at that
scope. A string belongs to the function or analysis it was recorded against, so
an id that exists at another scope reads the same way.

### run-not-found

`404`. A conversation has no agent run with the requested id (or has none at
all, which the reads report the same way). A run id that belongs to another
conversation reads the same, so one conversation cannot probe another's runs.

### run-not-cancellable

`409`. The run already finished, failed or was cancelled, so there is nothing to
stop. Cancelling is refused rather than reported as done, because a run whose
work is over cannot be un-run.

### no-pending-confirmation

`409`. The run is not waiting on a tool call, so there is nothing to approve or
reject. A run pauses only when the model asks for a tool that changes the
workspace, and only while it is waiting is a confirmation meaningful.

### auto-busy

`503`. The process is already running as many background auto runs as it
allows. Wait for one to finish, or poll an existing run; the request did not
create a new one.

### no-artifact

`404`. An agent artifact's rating was asked for or set on a binary that has no
stored scan of that kind, so there is nothing to have an opinion about. This is
the artifact-specific sibling of `no-scan`: a rating route names a kind, and a
kind the binary never produced is refused rather than stored against nothing.

### symbols-unreadable

`400`. The uploaded file is not a symbol container the readers can follow: not
an ELF, not a PDB 7.0 MSF container, or a container whose internal offsets do not
fit its own bytes. Nothing was stored and no name was applied. The file is not
guessed at: a parse that would have to invent an address or a name answers this
instead.

### no-symbols

`404`. No debug symbol file has been ingested for the binary, so there is no
stored parse to read or export. It is not an error state: a binary whose names
came from the engine has no symbol file and needs none.

### not-go

`400`. The stored file carries no `go.buildinfo` magic, so it is not a Go
binary the build-information scan can read. Run it against a Go binary, or
use the file-type scan when the question is only which runtime produced it.

### unreadable

`400`. The stored file could not be read while recovering Go build
information. The row exists but its bytes do not, so there is nothing to
scan; re-register the binary rather than retrying the scan.

### unsafe-name

`400`. A stored rename holds both quote styles, so no Python quoting renders
it as text rather than code in a Ghidra or IDA script. Rename the function
to a name with at most one quote style, or take the Binja document, which
needs no quoting.

### no-file

`400`. A multipart upload carried no `file` part. Send the file.

### no-docs

`404`. `GET /api/docs` found no documentation directory to serve: no
`REPORTAL_DOCS` override that is a directory, no `docs/` in the workspace, and
no checkout beside the installed package. Set `REPORTAL_DOCS` to a directory of
markdown files, or run the portal from a checkout. It is a deployment answer,
not an empty manual: the page list would otherwise have to be invented.

### no-doc

`404`. No documentation page carries the requested slug (or the slug is empty,
carries a separator, or starts a hidden name, which is refused for the same
reason). `GET /api/docs` lists the slugs that do exist; a page's slug is its
filename stem, lowercased.

### empty-file

`400`. The uploaded part had zero bytes. Nothing was stored.

### file-too-large

`413`. The upload, document or fetched body is over the route's cap
(`api.MAX_UPLOAD_BYTES`, `knowledge.MAX_DOCUMENT_BYTES`, or the remote
ingestion cap). Send something smaller.

### too-many-files

`400`. A batch upload carried more parts than `api.MAX_UPLOAD_FILES`. Split the
batch.

### unsupported-format

`400`. The content's suffix is not on the supported list for that route:
neither an archive kind `reportal.archive` reads nor a text extension
`reportal.knowledge` reads. Convert the input or unpack it yourself.

### external-tool-required

`400`. The archive is a format reportal deliberately does not read in-process
(`.rar`, `.7z`), because unpacking it needs an external tool. Unpack it with
that tool and upload the members.

### password-required

`400`. The archive is encrypted and no password was given. Retry with the
`password` field.

### bad-password

`400`. The archive password is wrong. Retry with the right one.

### corrupt-archive

`400`. The archive could not be read as its declared format, or a member failed
its own integrity check. Re-export the archive.

### archive-too-large

`400`. A member expands past the compression-ratio or total-size cap
(`archive.MAX_COMPRESSION_RATIO`, `archive.MAX_TOTAL_BYTES`). Nothing is
extracted from it.

### too-many-members

`400`. The archive holds more members than `archive.MAX_MEMBERS`. Split it.

### binary-not-on-disk

`400` for an engine call, `404` for `GET /api/binaries/<id>/download`. The stored
row's `path` is empty or no longer holds a file, so the engine has nothing to
read, or the download has nothing to stream. The download answers not-found
rather than the engine family's bad-request because the caller asked for a
resource, not for a parse. Re-upload the binary or fix the path.

### too-many-documents

`400`. The scope already holds `knowledge.MAX_DOCUMENTS_PER_SCOPE` documents.
Delete one before ingesting another.

### no-packer

`400`. The binary's own bytes carry no packer signature reportal knows, so there
is nothing to rebuild. Detection reads the LZEXE stub at the entry point and the
UPX marker, so a packer that rewrites its own stub is not identified; the stored
file-type scan names the wider signature set.

### unknown-packer

`400`. The `packer` name is outside `unpack.PACKERS` (`lzexe`, `upx`). Send one
of those, or leave it out and let the file's own stub decide.

### no-unpacker

`400`. The binary is UPX-packed and the external `upx` tool is not installed.
reportal ships no packer, so no rebuild can run: install UPX on `PATH` and run
the unpack again. The detection and the stored file-type scan still name the
packer, so the sample is identified even when it cannot be opened.

### unpack-failed

`400`. The packer was identified and the rebuild itself failed: the engine
refused the file's header geometry, or the external tool exited non-zero (its
last output line is the detail). The packed source is never modified, so there
is nothing to undo.

## Not found

### binary-not-found

`404` (`binary not found`). The id names no stored binary. The body counts every
not-found case for this resource, including one that belongs to another binary.

### function-not-found

`404` (`function not found`). The id names no stored function.

### collection-not-found

`404`. The id names no stored collection.

### family-not-found

`404`. The id names no registered malware family.

### comment-not-found

`404`. The id names no analyst comment.

### conversation-not-found

`404`. The id names no stored conversation.

### data-type-not-found

`404` (`data type not found` and `data-type-not-found`). The id names no row in
the local type model.

### document-not-found

`404`. The id names no ingested document.

### model-not-found

`404`. An upgrade named a model the registry does not carry. Read
`GET /api/models` and name one of its entries; only a `llm` entry can re-run an
artifact, and another kind answers 400 `invalid model`.

### member-not-found

`404`. The selector names no member of that data type.

### node-not-found

`404`. The node id names no row in a stored knowledge graph.

### project-not-found

`404`. A knowledge scope used kind `project` with an id that is not a negative
project id.

### run-not-found

`404`. The id names no pipeline run, auto run or task.

### tag-not-found

`404`. The tag id names no tag.

### format-not-found

`404`. The route serves one artifact format and the requested one is not on the
stored payload (`yara`, `snort`, `stix`).

### domain-not-found

`404`. A hardening or behavior domain is outside the closed set for that scan.

### component-not-found

`404`. The name matches no component in the live registry.

### action-not-found

`404`. The journal action id names no recorded action.

### entry-not-found

`404`. The journal entry id names no recorded entry.

### history-not-found

`404`. The rename-history id, module signature-history id or data-type
definition-history id names no recorded row.

### analysis-not-found

`404`. The id names no stored analysis.

### candidate-not-found

`404`. The candidate function of a match transfer names no stored function.

### signature-not-found

`404` (`signature not found` and `signature-not-found`). The function has no
stored signature row.

### not-found

`404`. The catch-all for a path no route serves, and for a request that names no
known resource. Check the path; the API's routes are listed in `docs/API.md`.

## Stored-only reads

### no-scan

`404`. The route serves a stored scan and the binary has none of that kind. Run
the matching POST (or the CLI command `detail` names) first; reportal never runs
an engine on a read.

### no-artifact

`404`. The route serves a stored AI artifact or detection artifact and none is
stored. Generate it first.

### no-run

`404`. The route serves the latest pipeline or auto run and none exists yet.
Run it first.

### no-graph

`404`. The binary has no stored knowledge graph. Build it first.

### no-line-comment

`404`. The AI decompilation carries no inline comment at that line. Add one
first, or read the artifact's `line_comments` to see which lines have one.

### no-report

`404`. The generated report site does not exist yet. Run `reportal report` or
the report POST.

### no-pdf

`404`. The PDF export has not been rendered for this binary. Post the PDF route
first.

### no-decompilation

`404`. The AI route needs a stored decompilation and the function has none.
Decompile it first.

### no-proposal

`404`. The auto-unstrip proposal the request names is not on the stored scan.

### no-strings

`404`. A scan needed the binary's string table and the engine returned none.
Nothing was stored over an existing result.

### secret-not-found

`404`. No stored credential carries the requested name at the requested scope. A
name is a lowercase dotted path (`virustotal.api_key`) and a scope is `local`
(the workspace) or `team` (with a team id), so read `GET /api/secrets` or run
`reportal secrets-list` and name one of its rows exactly.

### no-such-match

`400`. A match transfer named a stored match edge that does not exist. List the
function's matches first.

### no-engine-context

`400`. The binary has no stored rebrew project directory, which the engine call
needs as its working directory. Run `reportal import-rebrew` for it.

### job-not-found

`404`. No job has that id. List them with `reportal jobs` or `GET /api/jobs`.

### invalid-job

`400`. A submitted job names an unknown kind, a parameter the kind does not
take, a value that kind refuses (an unknown behavior or hardening domain) or a
queue that is already at its waiting bound. The detail names the kind, the
parameter or the domain that was refused.

### invalid-job-query

`400`. A job listing asked for a status or a kind outside the closed set. The
detail names the accepted values.

### job-not-cancellable

`409`. The job has already started (or has already finished): a scan that
entered the engine cannot be stopped, so the cancel would report a stop that
never happens. Wait for the result, or cancel a job that is still queued.

### last-analysis

`400`. The request would remove the binary's newest analysis, which every scan
is attached to.

### no-workspace

`500`. The process is not inside a reportal workspace: the `reportal.toml`
walk-up found no marker and no `REPORTAL_DB` override. Run `reportal init` or
start from inside a workspace.

## Conflicts

### signature-conflict

`409`. A signature transfer would overwrite a target function whose calling
convention differs and is not empty. Rename the convention first or transfer the
name alone.

### export-exists

`409`. The export target path exists and `force` was not set. Pass `force` to
overwrite.

### duplicate-name

`400`. A create or rename would collide with an existing name (a data type, a
family). Pick another name.

### duplicate-member

`400`. A data-type member with that name already exists.

### duplicate-parameter

`400`. A function signature already has a parameter with that name.

### duplicate-family

`409`. A family with that name is already registered.

### not-reloadable

`409`. The component was registered in-process and has no declaring module to
re-read, so it cannot be reloaded. Restart the process instead.

### not-withdrawable

`409`. The component provides nothing and declares no revert, so there is
nothing to withdraw.

### not-active

`409`. The action or run is already reverted, closed or withdrawn.

### component-missing

`500`. The component's declaring module was re-imported and no longer binds the
declaration. Fix the module and reload again.

## Engines and models

### engine-error

`500`. The rebrew engine ran and failed, or a module of it could not be
imported. `detail` carries the engine's bounded message. Fix the underlying
engine problem and retry; nothing partial is stored.

### engine-unavailable

`503`. The installed `rebrew` package cannot be imported, so no engine call can
run. `rebrew` is a base dependency, so this means a broken install: reinstall
with `uv sync`.

### llm-error

`502`. The configured OpenAI-compatible endpoint answered with an error or an
unusable body. Nothing was stored. Check the endpoint and the model name.

### llm-unavailable

`503`. No LLM endpoint is configured, so the route cannot run. Configure
`[llm] endpoint` or `REPORTAL_LLM_ENDPOINT`; every deterministic route keeps
working without it.

### pipeline-unavailable

`503`. The AI decompilation composition could not be assembled at all. Check
that the component registry loads (the route lists what failed).

### backend-not-found

`404`. The route names a registered plugin backend and no backend has that
name. List the registered backends and pick one of them.

### similarity-unavailable

`503`. The optional `similarity` extra (the sibling `resembl`) is not installed,
so no assembly similarity can be computed. Install `reportal[similarity]`.

### billing-error

`400`, `409`, `502` or `503` depending on what failed. The billing provider
could not honor a checkout, a portal session, a webhook or a reconcile. `400` is
a refused input (an unknown or non-purchasable plan, an invalid webhook
signature, a spent or unknown manual token); `409` means there is no
subscription to manage or reconcile; `502` means the provider was unreachable or
rejected the call; `503` means billing is disabled on this install, the plan has
no configured price, or no webhook signing secret is set. The `detail` names
which. An install with no `REPORTAL_STRIPE_SECRET_KEY` answers `503` for every
checkout path by design: usage is still metered and readable.

### rate-limited

`429`. Too many calls to a route that reaches the payment provider on your
behalf (the per-organisation subscription sync). Webhooks are the primary path
for subscription state and arrive on their own, so this endpoint is a fallback
for a lost delivery rather than something to poll. Wait and try again.

### backend-unavailable

`503`. A registered plugin backend is not installed or not usable in this
process (a knowledge-graph backend such as `cognee`, or a model it needs).
Install it, or select a backend that reports `available: true`.

### query-unsupported

`400`. The selected knowledge-graph backend does not implement `query`. Use a
backend whose `supports_query` is true, or read the stored graph directly.

### unmapped-address

`400`. A memory read names an address that no stored section covers, so there
are no bytes to return.

### write-failed

`500`. A transfer computed its plan and the store write failed. Nothing was
committed; retry the transfer.

### journal-error

`500`. An action-journal operation could not be completed, so the request's
inverse was not recorded. The writes it did make are reported in `detail`.

### internal-server-error

`500`. An unhandled exception reached the route. The response is sanitized and
carries no stack trace; the server log holds the traceback.

## Remote ingestion

### remote-ingest-disabled

`403`. Remote URL ingestion is off, which is the default. Enable it with
`REPORTAL_ALLOW_REMOTE_INGEST=1` or `[knowledge] allow_remote = true` before
fetching a URL.

### fetch-failed

`502`. The guarded fetch failed: a connection error, a rejected status, or a
body that could not be read. Nothing was stored.

### unresolvable-host

`400`. The target host does not resolve, or resolves to no usable address.

### unsupported-content-type

`415`. The response's content type is not on the ingestion allowlist. Send text
or a document type reportal can extract.

### too-many-redirects

`400`. The fetch followed more redirects than the guard allows. Send the final
URL.

## Transfer and graph targets

### same-binary

`400`. A comparison or transfer named the same binary on both sides.

### tag-not-on-binary

`404`. The binary does not carry that tag, so there is nothing to remove.

### unknown-binary

`400`. A matching scope named a binary id that is not stored.

### unknown-collection

`400`. A matching scope named a collection id that is not stored.

### unknown-token

`404`. An override named a placeholder token the stored AI decompilation does not
carry. Read `GET /api/functions/<id>/ai-decompilation/tokens` and name one of
its tokens exactly.

### candidate-has-no-name

`400`. A name transfer's candidate has no name to copy.

### candidate-has-no-signature

`400`. A signature transfer's candidate has no stored signature to copy.

### transfers-must-be-a-non-empty-list

`400`. A bulk transfer carried an empty `transfers` list. Send at least one.

### too-many-transfers

`400`. A bulk transfer carried more entries than the route allows in one
request. Split it.

## Identity

Token auth is off unless `REPORTAL_AUTH=required` (or the workspace
`[auth] required = true`) turns it on, so a loopback install answers none of
these.  See `docs/THREAT_MODEL.md` for what the modes promise.

### unauthorized

`401`. The request carried no `Authorization: Bearer <token>` header, the token
does not match any user, or the user is disabled. Turn auth on deliberately and
send the token `reportal user-add` or `reportal user-token` printed:
`Authorization: Bearer reportal_...`.

### forbidden

`403`. The token is valid but its role does not carry the permission the request
needs: a `viewer` may only read, an `analyst` may read and write, and the user
table is `admin` only. Ask an operator for a role with `reportal user-edit
<id> --role analyst`. The secret store reports the same status as `secret
forbidden` when the role is not enough: a workspace secret needs an admin, and a
team secret needs that team's membership (or an admin).

### invalid-user

`400`. A user request named a blank or oversized name, an unknown role, or an
update with neither `role` nor `disabled`. Roles are `viewer`, `analyst` and
`admin`.

### user-exists

`409`. Another user already carries that name (names compare case-insensitively).
`reportal users` lists them.

### user-not-found

`404`. No user carries that id.

### invalid-feedback

`400`. A feedback note was blank or past `store.MAX_FEEDBACK_CHARS` (2000), or
the request's `message` was not a string. Send the text `POST
/api/users/feedback` (or `reportal feedback-add`) should store.

### sandbox-disabled

`403`. A detonation was asked for while the workspace has not opted in. Set
`REPORTAL_SANDBOX=enabled` or `[sandbox] enabled = true`, which is the guard that
keeps reportal from executing anything by default.

### sandbox-unavailable

`503`. The workspace opted in but no usable sandbox runner is installed (or the
configured one, `REPORTAL_SANDBOX_RUNNER` or `[sandbox] runner`, is not). Install
bubblewrap (`apt install bubblewrap`) or register a runner through the
`reportal.sandbox_runners` entry-point group; reportal never runs a sample
without one.

### invalid-sandbox

`400`. A detonation bound is outside its cap: `timeout` must be 1 to 60 seconds,
`memory_mb` 64 to 4096, and both must be integers. Capturing less than the cap is
allowed; raising it is not.

### invalid-team

`400`. A team request named a blank or oversized name, an update with neither
`name` nor `description`, a membership for an unknown or already-member user, or
a scope whose `visibility` is outside `public`/`team` (a `team` one also needs a
`team_id`).

### team-exists

`409`. Another team already carries that name (names compare
case-insensitively).

### team-not-found

`404` (`team-not-found`). No team carries that id, or no such team is named in a
scope request.

### not-a-team-member

`404`. The membership addressed by `DELETE /api/teams/<id>/members/<user_id>`
does not exist, so there is nothing to remove.

### invalid-region

`400`. A firmware carve named a region index that does not exist, an empty
`regions` list, or a region list that is not a list of indexes. Run `reportal
firmware <binary-id>` (or `GET /api/binaries/<id>/firmware`) to see the indexes
the stored pass reports.

### region-not-found

`404`. No region carries that index in the binary's stored firmware scan.

### invalid-labels

`400`. A benchmark's labels are malformed: a pair is not an object, an address
is neither an integer nor a decimal or `0x` string, a pair is missing `left_va`
or `right_va`, or the same binary was named on both sides. A benchmark compares
two different binaries, so send `right_binary_id` and one `{left_va, right_va}`
object per labelled pair.

### no-labels

`400`. A benchmark resolved no label to a stored function in both binaries, so
there is nothing to score. Name addresses the two binaries actually carry (the
run reports each label it could not resolve), or drop `labels` and let the two
binaries' shared real function names label the run.

### scope-forbidden

`403`. The object belongs to a team the caller is not a member of, so the write
is refused. A *read* of such an object is a 404 for its own kind instead, so the
answer does not disclose that it exists. Ask a team member or an admin to add
you (`reportal team-member <team-id> <user-id>`).

## Server

### ui-not-built

`503`. The SPA has no build: `src/reportal/assets/dist/index.html` is missing.
Run `bun install && bun run build` in `web/`.

### unexpected-host-header

`400`. The `Host` header names a hostname outside the loopback allowlist, which
is the DNS-rebinding guard. Send the loopback name the server is bound to, or
configure a remote bind deliberately.

### provide-a-name-or-all-not-both

`400`. A component reload was given both a `name` and `all`. Send one.

### provide-a-component-name-or-all

`400`. A component reload was given neither a `name` nor `all`. Send one.

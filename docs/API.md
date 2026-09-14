# API Endpoints

*Reference material moved out of AGENTS.md.*

## Authentication

Token auth is off unless `REPORTAL_AUTH=required` (or the workspace
`[auth] required = true`) turns it on, so a loopback install is unchanged and
every route answers as it always did.  With it on, every `/api` request needs
`Authorization: Bearer <token>` (`server.require_auth`, a router dependency, so
no route can be added outside it): a missing, wrong or disabled user's token is
401 `unauthorized`, and a role that does not carry the permission the method and
path imply is 403 `forbidden`.  Roles are `viewer` (read), `analyst` (read and
write) and `admin` (also the user table); `docs/THREAT_MODEL.md` has the rest.
`cli.serve` refuses a non-loopback bind unless auth is on and at least one
enabled user exists.

A binary or a collection also carries a **scope**: `public` (every
authenticated caller) or `team` (only the members of the team that owns it).
`server._enforce_scope` reads the object a path names (`/api/binaries/<id>`,
`/api/collections/<id>`, and a function or analysis through the binary it
belongs to) and refuses a read of a scoped object the caller cannot see with the
object's own 404, and a write with 403 `scope-forbidden`.  Because the check
lives in the router dependency, a route added later is covered without repeating
it.  The listings (`/api/binaries`, `/api/collections`, `/api/search`) filter
their pages by the same rule.

| Path | Method | Description |
|------|--------|-------------|
| `/api/iam/me` | GET | who the caller is: `auth` (`open` or `required`), the `user`, its `role` and the `permissions` that role carries; with auth off the user is null and the permissions are all three, because the caller is the local operator |
| `/api/iam/me/permissions` | GET | the caller's `role`, the `permissions` it carries, the `auth` mode and the closed `roles` list |
| `/api/users/activity` | GET | the activity feed, derived rather than stored: one item per journaled action (its `actor`, `action`, newest `description`, `at`, `status`, `entries`) plus one per analysis-log entry, newest first, with `count`, the true `total`, `latest` and the `actors` that appear; `?actor=` (an empty value means the writes no request made), `?since=` (inclusive ISO), `?limit=` (default `activity.DEFAULT_ACTIVITY_LIMIT`, cap `MAX_ACTIVITY_LIMIT`) and `?sources=action,log`; a bad value is 400; self-service, so any authenticated caller reads it |
| `/api/users/feedback` | GET | stored feedback notes, newest first, with `count` and the true `total`; `?limit=` bounded by 500; read-only |
| `/api/users/feedback` | POST | store one feedback note about reportal itself; body `{"message"}` (400 `invalid feedback` for a blank, oversized or non-string one); 201 with the note, attributed to the authenticated caller's name (`local` while auth is off) and journaled, so a revert removes it; self-service |
| `/api/users` | GET | every user with its `role`, `has_token`, `disabled` and `created_at`; the token digest is never part of an answer; admin only when auth is on |
| `/api/users` | POST | create a user; body `{"name", "role"?}` (role defaults to `analyst`); 201 with the user and its `token`, which is shown once because only the digest is stored; journaled and revertible; 400 `invalid-user` for a blank name or an unknown role, 409 `user-exists` |
| `/api/users/<id>` | PATCH | set the user's `role` or `disabled`; body `{"role"?, "disabled"?}` (400 `invalid-user` with neither); journaled and revertible |
| `/api/users/<id>/token` | POST | replace the user's token and return the new one once; the previous token stops authenticating; journaled, so a revert restores the digest |
| `/api/users/<id>` | DELETE | delete one user; journaled, so a revert puts the row back |
| `/api/teams` | GET | every team with its `member_count`; readable by any authenticated caller |
| `/api/teams` | POST | create a team; body `{"name", "description"?}`; 201, journaled and revertible; 400 `invalid-team` for a blank name, 409 `team-exists` |
| `/api/teams/<id>` | GET | one team with its members (each `id`, `name`, `portal_role` and `team_role`) and its `organisation_id`/`organisation_name`; 404 `team-not-found` |
| `/api/teams/<id>` | PATCH | set the team's `name` or `description` (400 `invalid-team` with neither); journaled |
| `/api/teams/<id>` | DELETE | delete a team; the binaries and collections it owned return to the whole workspace, and the revert restores the team, its members and their scope |
| `/api/teams/<id>/members` | POST | add a user; body `{"user_id"}`; 201 with the team, 400 `invalid-team` for an unknown or already-member user; journaled |
| `/api/teams/<id>/members/<user_id>` | DELETE | remove a membership (404 `not-a-team-member` when it does not exist); journaled |
| `/api/teams/<id>/members/<user_id>/role` | PUT | set one membership's team role; body `{"role": "owner"\|"member"}`; 403 `not-a-team-owner` unless the caller owns the team or is an admin, 404 `not-a-team-member` for a non-member, 400 `invalid-team-role` for an unknown role; journaled |
| `/api/teams/<id>/organisation` | PUT | move a team into an organisation or out of every one; body `{"organisation_id": <id>\|null}`; 404 `organisation-not-found` for an unknown id, 400 `invalid-organisation` for a non-integer; journaled |
| `/api/organisations` | GET | every organisation with the teams it holds; an organisation groups teams and is not access control |
| `/api/organisations` | POST | create an organisation; body `{"name", "description"?}`; 201, journaled; 400 `invalid-organisation` for a blank name, 409 `organisation-exists` |
| `/api/organisations/<id>` | GET | one organisation with its teams; 404 `organisation-not-found` |
| `/api/organisations/<id>` | DELETE | delete an organisation; its teams stay and stop being grouped; journaled |
| `/api/iam/active-team` | PUT | switch the team the caller has selected; body `{"team_id": <id>\|null}`; membership required (403 `not-a-team-member`), 404 `team-not-found` for an unknown team, 400 `invalid-team` while auth is off because there is no caller to switch |
| `/api/binaries/<id>/scope` | PATCH | set a binary's visibility: body `{"visibility": "public"}` or `{"visibility": "team", "team_id": N}` (400 `invalid-team` for a missing or unknown team, 404 for an unknown binary); if the binary already belongs to a team the caller is not in, 403 `scope-forbidden`; journaled and revertible |
| `/api/collections/<id>/scope` | PATCH | the same for a collection; journaled and revertible |
| `/api/health` | GET | status, version, database path, row counts; this is the running server's read, and `reportal doctor` is the pre-flight half (the SPA build, a free port, the schema and the auth posture before anything starts) |
| `/api/config` | GET | what this instance can do: `version`, the engine's availability and origin, its decompiler backends, the LLM bridge's state and model, the database path and table count, the on/off `features`, every cap in `limits`, and the MCP tool counts; a pure read, so a client can fetch it on start |
| `/api/binaries` | GET | all binaries with function counts |
| `/api/binaries` | POST | upload one or many binaries; `multipart/form-data` with repeated `file` parts and an optional JSON `files` field (entry *i* describing part *i*: `name`, `tags`, `collection_ids`, `format`/`arch`); one `file` part with no `files` field is the single-file upload whose response is unchanged (`duplicate` flag, deduped by sha256); a batch answers `{"files": [{"file", "binary_id", "duplicate", "tags", "collections", "error"}], "count", "duplicates", "errors"}` with the same refusal vocabulary per entry, and the whole request is one journal action |
| `/api/binaries/<id>/extract` | POST | unpack a stored archive and register its members by content hash into one collection (the body's `collection_id`, else a collection named after the archive); each supported member is validated first (traversal, absolute name, symlink/hardlink, device/FIFO, per-member/per-total/per-ratio bomb caps) and reported with its id or its skip reason, and the request is one journal action; 404 unknown binary or collection, 400 `binary not on disk`, 400 `unsupported-format`, `external-tool-required` (`.rar`/`.7z` name the tool), `password-required`/`bad-password` |
| `/api/binaries/<id>` | GET | one binary |
| `/api/binaries/<id>/firmware` | POST | carve the stored image: walk it for the magics the embedded formats start with (`firmware.SIGNATURES`), report every region with its offset, size, kind, confidence, sampled entropy and `truncated` flag, plus the entropy map (per `firmware.ENTROPY_WINDOW`, capped at `MAX_ENTROPY_SAMPLES`), and store the pass as the binary's `firmware` scan; pure byte work, nothing executed; 404 `binary not found`, 400 `binary not on disk` |
| `/api/binaries/<id>/firmware` | GET | the stored carve pass; 404 `no-scan` before the first run, 404 `binary not found` for an unknown id; read-only |
| `/api/binaries/<id>/firmware/extract` | POST | carve the stored regions out as binaries: body `{"regions": [index, ...]}` (every region when absent) and `{"collection_id": N}` (one named after the firmware when absent); a region whose kind is gzip, tar or zip is unpacked by the archive reader and its members registered, every other region is stored as a binary of its own, and the whole request is one journal action; 201, 404 `no-scan`, 400 `invalid-region`, 404 `region not found`/`collection not found`, 400 `binary not on disk` |
| `/api/binaries/<id>/download` | GET | stream the stored bytes as an attachment: the file is read and yielded in `BINARY_DOWNLOAD_CHUNK_BYTES` (1 MiB) chunks rather than loaded whole (an upload may be up to `MAX_UPLOAD_BYTES`, 256 MiB), `Content-Disposition` names the sanitized stored filename (`download_filename`: one path component, every character outside `[A-Za-z0-9._-]` an underscore, the content-addressed file name as a fallback), `Content-Length` is the file's own byte count, the content type comes from the suffix via `BINARY_CONTENT_TYPES` (else `DEFAULT_BINARY_CONTENT_TYPE`), and `Cache-Control` is `BINARY_DOWNLOAD_CACHE_CONTROL` (`public, max-age=31536000, immutable`) because the bytes are content-addressed; 404 `binary not found` for an unknown id and 404 `binary not on disk` with the path for a row whose file is gone (the engine routes answer 400 for that condition; a download is of a representation that is gone) |
| `/api/binaries/<id>/download-zipped` | GET | stream the stored bytes as a zip whose one member is password protected (PKWARE ZipCrypto, which the stdlib reads but cannot write); `?password=` defaults to `infected` and is echoed in `X-Reportal-Zip-Password` (a shared convention, not a secret: it exists so a mail gateway or an upload form accepts the archive); `Cache-Control: no-store` because the encryption header is drawn per request, and the archive is assembled as it streams so a 256 MiB binary is never held whole; 400 `invalid password` for an empty or over-long one, 404 `binary not found`/`binary not on disk` |
| `/api/binaries/<id>/functions` | GET | functions of one binary, filtered and sorted from the query string: `name_source` (one of `composition.NAME_SOURCE_LABELS`), `capability` (one of `capabilities.CAPABILITIES`), `min_size`/`max_size` (inclusive byte bounds, at most `api.MAX_FUNCTION_SIZE`), `string` (a literal the stored decompilation carries), `match` (`matched`/`unmatched` over the stored `matches` table), `refers_to` (an address; the one engine-backed filter, keeping the stored functions whose byte range contains one of the address's cross-references, resolved through the same `rebrew xrefs` call the xrefs route makes; 400 `invalid refers_to` for a non-integer, 400 `no-engine-context` without a project, 503 without an engine, 500 `engine-error`), `sort` (`va`/`size`/`name`/`status`) and `order` (`asc`/`desc`); an unknown value is 400; ties break on the function id; the body carries `count` (returned) and `total` (the binary's whole function set) |
| `/api/binaries/<id>/fingerprint` | GET | stored fingerprint, else a live compute that is not stored |
| `/api/binaries/<id>/fingerprint` | POST | compute and store a fingerprint |
| `/api/binaries/<id>/match` | POST | run local function matching under the Match Settings scope: `{"min_similarity": 80.0, "min_confidence": 0.0, "include_self": true, "top": 10, "platforms": [], "architectures": [], "binary_ids": [], "collection_ids": []}`, each validated against its bound or closed vocabulary (400 otherwise); returns the summary plus the recorded `settings` and the scope `notes` |
| `/api/binaries/<id>/lineage` | POST | compare the binary with another pairwise and store the comparison on the left binary; body `{"other_binary_id": ..., "refine": ...}` (`refine` defaults to true and false forces name/size only); 400 `same binary` or `invalid other_binary_id` |
| `/api/binaries/<id>/lineage` | GET | with `?other_binary_id=N` the stored comparison of that pair (404 `no-scan` before the first run), otherwise every comparison stored for the binary; stored-only |
| `/api/families` | GET | every locally registered malware family with its stored signature bundle; read-only, never runs the engine |
| `/api/families` | POST | register a family from a reference binary and store its derived signature bundle; body `{"name", "reference_binary_id", "aliases"?, "notes"?}`; 201 on create |
| `/api/families/<id>` | GET | one registered family with its signature bundle |
| `/api/families/<id>` | DELETE | delete a registered family; 404 `family not found` |
| `/api/binaries/<id>/detect` | POST | derive the binary's signature bundle and score it against every registered family, then store the detection; no external intel feed is contacted |
| `/api/binaries/<id>/detect` | GET | stored family detection; 404 `no-scan` without one; stored-only, never runs the engine |
| `/api/binaries/<id>/related` | POST | rank the other stored binaries against this one by its hashes, imports, capabilities and size, then store the ranking; optional body `{"limit": N, "include_unrelated": bool}`; 400 `invalid limit`, 404 unknown binary |
| `/api/binaries/<id>/related` | GET | stored relationship ranking; 404 `no-scan` without one; stored-only, never runs the engine |
| `/api/binaries/<id>/composition` | POST | build the binary's composition analysis from the stored functions and `matches` rows and store it; the optional body `{"binary_ids", "collection_ids"}` narrows the candidate corpus through `matching.resolve_scope` and the stored payload records the scope; 400 `unknown binary`/`unknown collection` for an id no row carries, 404 unknown binary; stored-only, never runs matching or the engine |
| `/api/binaries/<id>/composition` | GET | stored composition analysis; 404 `no-scan` without one; stored-only, never runs matching or the engine |
| `/api/binaries/<id>/tags` | GET | tags applied to one binary |
| `/api/binaries/<id>/tags` | POST | link a tag; body `{"name": ...}` (created if needed) or `{"tag_id": ...}` |
| `/api/binaries/<id>/tags/<tag_id>` | DELETE | unlink a tag; 404 when the link does not exist |
| `/api/binaries/<id>/comments` | GET | analyst comments stored on one binary, oldest first |
| `/api/binaries/<id>/comments` | POST | store one analyst comment; body `{"body", "author"?}` (`author` defaults to `comments.DEFAULT_AUTHOR`); 201 with the row; 400 `invalid comment` for a blank or oversized body, 404 `binary not found` |
| `/api/functions/<id>/comments` | GET | analyst comments stored on one function, oldest first |
| `/api/functions/<id>/comments` | POST | store one analyst comment on a function; same body and codes as the binary scope |
| `/api/comments/<id>` | PATCH | replace one comment's body; body `{"body"}`; 400 `invalid comment` for a blank or oversized body, 404 `comment not found` |
| `/api/comments/<id>` | DELETE | delete one comment; 404 `comment not found` |
| `/api/binaries/bulk` | POST | apply one action (`add_tag`, `remove_tag`, `delete`) to many binaries; body `{"action", "binary_ids", "tag"?}`; 400 `invalid bulk request` for an unknown action, an empty list or a list past `bulk_actions.MAX_BULK_IDS`; returns `{"action", "requested", "applied", "skipped": [{"id", "reason"}]}` with an unknown id skipped rather than failing the batch; `delete` cascades |
| `/api/functions/bulk` | POST | apply one action (`rename`, `clear_matches`) to many functions; body `{"action", "function_ids", "prefix"?, "replace"?}`; a `rename` records each change in `name_history` with source `bulk-prefix`; same codes and result shape as the binary bulk route |
| `/api/binaries/<id>/imports` | GET | live import table from the engine |
| `/api/binaries/<id>/strings` | GET | live strings from the engine, normalized server-side to one row per string (`va`, `section`, `kind`, `size`, `text`; a field the engine did not report stays `null`) and sorted by `?sort=value\|length` and `?order=asc\|desc` (an unknown value is 400); ties break on the text then the address; `binary`, `count` and `strings` keep their meaning, with `binary_id`, `sort` and `order` added after them |
| `/api/binaries/<id>/triage` | GET | stored triage dossier plus the derived `software_type` and `threat_score`; 404 `no-scan` without one |
| `/api/binaries/<id>/triage` | POST | run `rebrew analyze` on the binary file and store the dossier; the response adds the derived `software_type` and `threat_score` |
| `/api/binaries/<id>/function-triage` | GET | stored per-function triage summaries and scores; 404 `no-scan` without one; stored-only, never runs the engine or the LLM |
| `/api/binaries/<id>/function-triage` | POST | score and summarize the selected functions with the configured LLM, else the deterministic heuristic, and store one artifact per function plus the aggregate; body `{"function_ids": [...], "limit": N}`, both optional |
| `/api/binaries/<id>/report` | GET | stored report result; 404 `no-scan` without one |
| `/api/binaries/<id>/report` | POST | run `rebrew report` into `<workspace>/reports/<id>` and store the result |
| `/api/binaries/<id>/report/pdf` | POST | render a text-only PDF summary from the stored scans into `<workspace>/reports/<id>/report.pdf`; returns `{"path", "bytes", "pages", "download_url"}`; stored-only, never runs the engine |
| `/api/binaries/<id>/report/pdf/status` | GET | whether the binary's PDF exists, with its path, size, page count and generation time, plus the newest `report-pdf` job and its status, so a caller that queued one can watch it here or on `GET /api/jobs/<id>`; 404 `binary not found` |
| `/api/binaries/<id>/report/pdf` | GET | serve that PDF as `application/pdf`; 404 `no-pdf` with the generate hint before the first render |
| `/api/binaries/<id>/structs` | GET | stored struct recovery; 404 `no-scan` without one |
| `/api/binaries/<id>/structs` | POST | run `rebrew recover-structs` and store the result; body `{"decompiler": ..., "limit": ...}`, both optional (`limit` defaults to `DEFAULT_STRUCT_LIMIT`) |
| `/api/binaries/<id>/data-types` | GET | the editable type model with each type's kind, namespace, size, members, enum values, target and padded `as_c` declaration, plus the namespace tree; always answers; optional `kind` (400 `invalid kind` outside `data_types.KINDS`), `namespace` (the path and every descendant, `Binary` for program-defined types, an unknown path an empty list), `search` (a substring of the name, a member name or an enum value name) and `source` (one of `data_types.SOURCE_LABELS`, 400 `invalid source` outside them); the body carries `count` (filtered), `total` (unfiltered) and `sources` (the count per provenance label over the whole model) |
| `/api/data-types/<id>/references` | GET | the two reverse indices: `referenced_by` (each type naming it as a member, a typedef target, a pointee, an array element, a function parameter or a return type) and `used_by_functions` (each function whose stored signature names it), matched by name with the payload's `note` stating so; 404 `data-type-not-found` |
| `/api/binaries/<id>/data-types/import` | POST | parse the stored structs scan into the model; 404 `no-scan` without one; stored-only, never runs the engine |
| `/api/binaries/<id>/data-types/export` | POST | render the model as one C header; body `{"path", "force"}`; 409 `export-exists` without `force`, 400 `invalid path` when the parent cannot be created |
| `/api/data-types/<id>` | PATCH | edit the type's level fields or one member; body `{"name"\|"kind"\|"namespace"\|"size"}` (one write, one history entry; 400 `invalid kind` outside `data_types.KINDS` listing the known ones, 400 `invalid size` for a non-integer) or `{"member": {"name"\|"index", "new_name", "new_type", "new_pointer"\|null, "new_count"\|null, "new_bits"\|null}}`; the member edit is 400 `invalid request` beside any type-level field, and a retype leaves a hand-set `bits` alone |
| `/api/data-types/<id>` | DELETE | delete one data type; 404 `data-type-not-found` for an unknown id |
| `/api/data-types/<id>/values` | POST | append one enum constant; body `{"name", "value"}` (an integer or a decimal/`0x` literal; omitted, it increments from the last constant and the payload's `note` names the number); 400 `duplicate member` for a duplicate name or value, 400 `invalid member` on a kind without values or a bad literal |
| `/api/data-types/<id>/values/<value>` | PATCH | rename and/or revalue one enum constant by name or decimal index; body `{"new_name", "new_value"}`; 404 `member-not-found` for an unknown selector |
| `/api/data-types/<id>/values/<value>` | DELETE | remove one enum constant by name or decimal index; 400 `invalid member` for the last one |
| `/api/data-types/<id>/history` | GET | a type's edit history, newest first, each entry carrying the states the mutation replaced (`previous`) and wrote (`current`, both null on one side for a create or a delete), its `source`/`actor`, and the per-field `changes` diff over `data_types.HISTORY_FIELDS` (`name`, `kind`, `namespace`, `size`, `members`, `values`, `target`, `element_count`); always answers, with `exists` telling whether the row is still stored, so a deleted type's history stays readable (the rows are keyed by the type id and do not cascade with the row) and a legacy row answers an empty list |
| `/api/data-types/<id>/history/<history_id>/revert` | POST | restore the state one history row recorded; a deleted type's row comes back under its original id, the revert is journaled (its `journal_action` reverts the revert) and reverting the same row twice is a no-op (`changed: false` with the `reason`); 404 `history not found` for an unknown row or one of another type, 400 `duplicate name` when another type now holds the name |
| `/api/data-types/<id>/members` | POST | add one member; body `{"name", "type"}` plus the rest of the member shape (`"pointer"`, `"count"`, `"bits"`) and the position (`"index"` is the position it takes, `"after"` names the member it follows; naming both is 400 `invalid member` rather than silently picking one, naming neither appends) |
| `/api/data-types/<id>/members/<member>` | DELETE | remove a member by name or decimal index |
| `/api/data-types/<id>/members/<member>/gap` | POST | convert a struct member to explicit padding named after its offset (`char gap_XXXX[N]`); body `{"size"}` defaults to the member's own size; 400 `invalid member` for a union or a zero-byte member |
| `/api/data-types/<id>/members/<member>/ungap` | POST | turn a padding member back into a named, typed member; body `{"name", "type"}` plus the optional `"pointer"`, `"count"`, `"bits"`; 400 `invalid member` when the member is not a gap |
| `/api/binaries/<id>/signatures` | GET | the binary's stored function signatures, ordered by name; always answers |
| `/api/binaries/<id>/signatures/import` | POST | parse the binary's stored decompilations into the model; always answers a summary (created/updated/skipped); stored-only, never runs the engine |
| `/api/binaries/<id>/signatures/export` | POST | render one C prototype header; body `{"path", "force"}`; 409 `export-exists` without `force`, 400 `invalid path` when the parent cannot be created |
| `/api/functions/<id>/signature` | GET | one function's signature plus its rendered `prototype` (each parameter also carries the derived `default_at`); 404 `signature-not-found` without one |
| `/api/functions/<id>/signature` | PATCH | set the return type and/or calling convention; body `{"return_type"?, "calling_convention"?}`; 400 `invalid request` when neither is given |
| `/api/functions/<id>/signature` | DELETE | delete one function's signature; 404 `signature-not-found` without one |
| `/api/functions/<id>/signature/history` | GET | a function's signature-edit history, newest first, each row carrying the state the edit replaced; always answers (an empty list for a row predating the history table) |
| `/api/functions/<id>/signature/history/<history_id>/revert` | POST | restore the signature state one history row recorded; the revert is journaled (its `journal_action` reverts the revert) and reverting the same row twice is a no-op; 404 `history not found` for an unknown row or one of another function |
| `/api/functions/<id>/signature/parameters` | POST | add a parameter; body `{"type", "name"?, "index"?, "at"?, "kind"?, "bits"?}` (appended without an index; the optional fields are stored as given, an absent one null) |
| `/api/functions/<id>/signature/parameters/<index>` | PATCH | edit one parameter; body `{"type"?, "name"?, "at"?, "kind"?, "bits"?}`, where an explicit `null` clears an optional field and an absent key leaves it as it is; 400 `invalid parameter` when none is given or a field has the wrong type, 400 `invalid type`/`invalid name` for an unusable value |
| `/api/functions/<id>/signature/parameters/<index>/move` | POST | move one parameter to another position; body `{"to_index"}` (400 `invalid index` for a non-integer or an out-of-range one); every `at` the convention table can place is recomputed from the parameter's new index, an underivable one keeps its value and an absent one stays absent |
| `/api/functions/<id>/signature/parameters/<index>` | DELETE | remove one parameter, reindexing the rest |
| `/api/binaries/<id>/crypto-scan` | GET | stored crypto scan; 404 `no-scan` without one |
| `/api/binaries/<id>/crypto-scan` | POST | run `rebrew crypto-scan` on the binary file and store the result |
| `/api/binaries/<id>/pe-info` | GET | stored PE metadata; 404 `no-scan` without one; stored-only, never runs the engine |
| `/api/binaries/<id>/pe-info` | POST | run `rebrew pe-info` on the binary file and store the identity, sections, security flags, signature, debug and Rich-header metadata |
| `/api/binaries/<id>/die-info` | GET | the Detect-It-Easy shaped identity (format, arch, bits, mode, entry point, image base) beside the packer, protector, installer, runtime and toolchain matches, each with the file-type scan's confidence and the signals that matched, plus the stored fingerprint's section entropy and the section-table packer hint; `sources` names every input, whether it is stored and the command that fills it in, so an empty category reads as a miss rather than an absence; 404 `no-scan` without a stored `pe-info` or `filetype` scan; stored-only, never runs the engine |
| `/api/binaries/<id>/additional-details` | GET | the overlay (the bytes past the last section, measured from the file against the stored section table), the Rich header's entry count plus its build and tool ids, the debug entries, the directory presence flags, the import/export/relocation counts, the Authenticode summary and the section table's shape; 404 `no-scan` without a stored `pe-info` scan; stored-only |
| `/api/binaries/<id>/additional-details/status` | GET | which sources the detail reads have, which are missing and the command that fills each one (`pe-info`, `filetype` and the fingerprint); always 200 once the binary exists, so a caller learns what is missing instead of being refused; 404 `binary not found` |
| `/api/binaries/<id>/section-coverage` | GET | per-section byte coverage over the binary's stored functions and stored `pe-info` sections: each section's `covered`/`size`/`coverage_pct` and the totals, with overlapping functions unioned and a straddling function clipped; 404 `no-scan` without a stored `pe-info` scan, `null` percentages with a zero-function note when nothing is stored; reportal's own metric (the hosted portal publishes none); stored-only, never runs the engine |
| `/api/binaries/<id>/memory` | GET | read a window of the binary's bytes by address through the engine (`?va=`, `?length=` default 64 cap 1024, `?kind=va\|rva\|file`); the payload reports the kind, the address and the bytes as hex; 400 `invalid address`/`invalid length`/`invalid kind`/`unmapped address`, 503 `engine-unavailable`, 500 `engine-error` |
| `/api/binaries/<id>/memory/page` | GET | read one page of the binary's bytes for the full-file hex view through the same `pe-info` section map: `?va=` is the page's first address (omitted starts at the first raw-backed section), `?length=` the page size (default `engines.MEMORY_PAGE_DEFAULT`, cap `MEMORY_PAGE_MAX`) and `?kind=` the address kind (`va`, `rva` or `file`, so a jump is virtual or an offset); `rows` are `bytes` rows (address, file offset, lowercase hex) and `gap` rows (address and length) for every byte the map does not back (a header, the gap between sections, a section's uninitialized tail), with `mapped`/`gaps` totals, `next`/`prev` page starts (`null` at either end) and the `sections` map; a start without backing bytes is 400 `unmapped address`, an engine failure 500 `engine-error` |
| `/api/binaries/<id>/filetype` | GET | stored file-type detection; 404 `no-scan` without one; stored-only, never runs the engine |
| `/api/binaries/<id>/filetype` | POST | run `rebrew pe-info`, `fingerprints`, `imports` and `strings`, match the local signature table and store the matches; 404 unknown binary, 400 no file, 503 without an engine |
| `/api/binaries/<id>/capabilities` | GET | stored capability scan; 404 `no-scan` without one |
| `/api/binaries/<id>/capabilities` | POST | run `rebrew imports` and `rebrew strings`, classify the binary with the local rule table and store the result |
| `/api/binaries/<id>/secrets` | GET | stored secrets scan; 404 `no-scan` without one; stored-only |
| `/api/binaries/<id>/secrets` | POST | run `rebrew strings`, match the credential pattern table plus the entropy check and store the findings; each finding carries the raw value and a redacted form, so the response is sensitive |
| `/api/binaries/<id>/protocols` | GET | stored protocol inference; 404 `no-scan` without one; stored-only |
| `/api/binaries/<id>/protocols` | POST | run `rebrew imports` and `rebrew strings`, infer the protocols from the imports, schemes, literals and host:port evidence and store the result |
| `/api/binaries/<id>/behavior` | GET | all three stored behavior scans (`execution`, `networking`, `filesystem`), null where absent; stored-only |
| `/api/binaries/<id>/behavior/<domain>` | GET | stored behavior scan of one domain; 404 `no-scan` without one, 404 `domain not found` for an unknown domain; stored-only |
| `/api/binaries/<id>/behavior/<domain>` | POST | run `rebrew imports` and `rebrew strings`, match the domain's behavior rule table and store the result |
| `/api/binaries/<id>/hardening` | GET | both stored hardening scans (`anti-analysis`, `obfuscation`), null where absent; stored-only |
| `/api/binaries/<id>/hardening/<domain>` | GET | stored hardening scan of one domain; 404 `no-scan` without one, 404 `domain not found` for an unknown domain; stored-only |
| `/api/binaries/<id>/hardening/<domain>` | POST | run the engine's fingerprint/imports/strings (plus the stored triage for obfuscation), apply the domain's rules and store the result |
| `/api/binaries/<id>/security-scan` | GET | stored security scan; 404 `no-scan` without one |
| `/api/binaries/<id>/security-scan` | POST | run `rebrew security-scan` in the binary's rebrew project and store the findings; body `{"min_severity": ...}` optional |
| `/api/binaries/<id>/threat` | GET | stored threat report plus the derived `software_type` and `threat_score`; 404 `no-scan` without one |
| `/api/binaries/<id>/threat` | POST | extract IOCs from `rebrew strings`, map them with the imports and the stored capability scan to the ATT&CK table, and store the report; body `{"narrative": ...}` optional; the response adds the derived `software_type` and `threat_score` |
| `/api/binaries/<id>/remediation` | GET | stored remediation payload (YARA rule, Snort rule set, STIX bundle); 404 `no-scan` without one |
| `/api/binaries/<id>/remediation` | POST | select distinctive literals from `rebrew strings` and import names from `rebrew imports`, render a YARA rule (a PE fingerprint's imphash anchors the condition), grade its specificity, validate it with `yarac` when installed, render the Snort rule set and STIX bundle from the stored `threat` and `protocols` scans (read, never re-run) and store all three; 404 `no-strings` when no literal survives selection |
| `/api/binaries/<id>/remediation/yara` | GET | stored YARA rule as `text/plain`; 404 `no-artifact` when the payload has none, 404 `no-scan` without a payload |
| `/api/binaries/<id>/remediation/snort` | GET | stored Snort rule set as `text/plain` (an empty body is a valid result with no network indicator); 404 `no-artifact` when the payload has none |
| `/api/binaries/<id>/remediation/stix` | GET | stored STIX 2.1 bundle as `application/json`; 404 `no-artifact` when the payload has none |
| `/api/binaries/<id>/unstrip` | GET | stored unstrip proposals; 404 `no-scan` without one |
| `/api/binaries/<id>/unstrip` | POST | run `rebrew identify-library --dry-run --json` in the binary's rebrew project context, join the candidates to its functions, and store the proposals; body `{"min_confidence": ...}` optional |
| `/api/binaries/<id>/library` | POST | identify which libraries the binary is built from through the engine's signature match and store the reading (the module rollup and the per-candidate list); body `{"min_confidence"?}` drops the candidates below it before the rollup; the binary needs a rebrew project context (400 `no-engine-context`), 404 unknown binary, 500 `engine-error`; journaled |
| `/api/binaries/<id>/library` | GET | the stored library reading: the modules with their kinds, function counts, byte totals and best confidence, plus the candidates; `stored: false` with an empty list and the command that fills it before the first run, rather than 404 |
| `/api/binaries/<id>/sbom` | GET | render the stored library reading as a component list: `?format=cyclonedx` (the default), `spdx` or `csv`; JSON for the two schema shapes and text for the CSV; 400 `invalid format`, 404 unknown binary; stored-only, it never runs the engine again |
| `/api/binaries/<id>/benchmark` | POST | match the binary against a partner and score the run against labelled counterpart addresses; body `{"right_binary_id", "labels"?, "top"?, "min_similarity"?, "min_confidence"?}` where each label is `{"left_va", "right_va"}` (an integer or a decimal/`0x` string) and, without `labels`, the ground truth is the two binaries' shared real function names; the candidates are always the partner binary; 404 unknown binary, 400 `invalid right_binary_id`, `invalid labels`, `invalid-labels` for the same binary twice or a malformed pair, `no-labels` when nothing resolves, 503 `similarity-unavailable` without the extra; it runs an ordinary match, so it replaces the binary's recorded matches and is journaled as one action |
| `/api/binaries/<id>/rename-benchmark` | GET | score the stored rename proposals against the names an ingested debug symbol file supplied: precision, recall, F1, every disagreement and every missed symbol; 200 with `stored: false` and the reason (`no-symbols` or `no-proposals`) when an input is missing, 404 unknown binary; stored-only, it runs no engine |
| `/api/binaries/<id>/benchmark` | GET | the stored benchmark: the labels it scored, the metrics (precision, recall, F1, mean reciprocal rank), every query's rank and the misses; `stored: false` with the command that produces one, rather than 404 |
| `/api/binaries/<id>/unpack` | POST | rebuild a packed binary's image and register it as a new binary; body `{"packer"?, "name"?}` names the packer (else the file's own stub decides) and the new binary's display name; the packed source is untouched; 404 unknown binary, 400 `binary not on disk`, `no-packer` when nothing is packed, `unknown-packer` for a name outside `unpack.PACKERS`, `no-unpacker` for UPX without the external tool, `unpack-failed` when the rebuild itself fails, 503 `engine-unavailable` for an LZEXE image without the engine; journaled, so one revert removes the scan, the row and the file |
| `/api/binaries/<id>/unpack` | GET | the stored provenance of a binary reportal unpacked: the packed source and its hash, the packer and what identified it, the method, the sizes and the moment; `stored: false` with the command that produces one, rather than 404 |
| `/api/binaries/<id>/unstrip/apply` | POST | apply one stored proposal by `function_id`, recording the rename with source `unstrip`; body `{"function_id": ..., "name": ...}` (`name` optional) |
| `/api/analyses/<id>/scans` | GET | stored scans of one analysis, newest first, without their payloads, each with the `params` the caller named when it ran (an empty object for a scan that records none) |
| `/api/binaries/<id>/scans` | GET | the same listing for the binary's newest analysis: `binary_id`, `analysis_id`, `scans` and `count`; a binary with no analysis answers an empty list, and 404 `binary not found` for an unknown id |
| `/api/functions/<id>` | GET | one function |
| `/api/functions/<id>/rename` | POST | rename; body `{"name": ..., "actor": ...}`; records history |
| `/api/functions/<id>/history` | GET | rename history, newest first |
| `/api/functions/<id>/history/<history_id>/revert` | POST | revert one history row; returns the restored name |
| `/api/functions/<id>/matches` | GET | recorded matches for one function, each with the derived `difference` and `band` fields |
| `/api/functions/<id>/apply-match` | POST | transfer a recorded candidate onto the function; body `{"candidate_function_id": ..., "mode": "name\|signature\|both", "actor": ...}` (`mode` defaults to `name`); a signature mode reports `missing_types` and refuses a differing non-empty calling convention with 409 `signature-conflict` |
| `/api/binaries/<id>/matches` | GET | stored-only; the binary's recorded edges with the run settings they were recorded under (`settings`, null outside a run), the derived `difference` and `band` fields and the scope `notes` |
| `/api/binaries/<id>/matches/transfer` | POST | bulk symbol transfer; body `{"transfers": [{"function_id", "candidate_function_id", "mode"}], "dry_run": bool, "actor": ...}`; every function must belong to that binary, a row failure is reported per row, and the whole action is one journal entry |
| `/api/functions/<id>/diff` | GET | side-by-side alignment against the function's best recorded match (`?kind=disasm|decomp&normalize=`); 404 `no-match` without one |
| `/api/functions/<id>/diff/<candidate_id>` | GET | side-by-side alignment against one candidate (`?kind=disasm|decomp&normalize=`); 400 `no-such-match` when the pair is not a recorded match |
| `/api/functions/<id>/disasm` | GET | NASM or hex listing through the binary's rebrew project context (`?format=nasm` or `hex`); NASM listings are cached in `disasm_cache` |
| `/api/functions/<id>/cfg` | GET | the function's basic-block control-flow graph through the same project context: `rebrew.asm.build_cfg_payload(cfg, va, size)`, the object `rebrew asm --format cfg --json` prints, with every address converted to an int. The payload carries `blocks` (`va`, `size`, `instruction_count`, `first`, `last`), `edges` (`from`, `to`, `back_edge`), the extent's `va`/`size`, and the honesty fields `block_count` (returned), `block_total` (the engine's true count), `block_cap` (the engine's per-function cap), `truncated` and `note` (the engine's reason when it resolved no extent; an empty block list always carries one). The stored size is passed when positive, zero otherwise so the engine resolves the extent itself; a malformed row is dropped rather than rendered as a fabricated address. Never cached and never stored; 404 unknown function, 400 `no-engine-context`, 503 `engine-unavailable`, 500 `engine-error` (a non-x86 target included) |
| `/api/functions/<id>/decompilation` | GET | stored decompiled C source, else a live `rebrew decompile` that is not stored (`?backend=kuna&named=true`); stored rows answer without an engine |
| `/api/functions/<id>/decompilation` | POST | decompile and store; body `{"backend": ..., "named": ...}`, both optional |
| `/api/functions/<id>/xrefs` | GET | live cross-references to a function through its rebrew project context; a repeated `?kind=` keeps only those kinds |
| `/api/functions/<id>/references` | GET | the function's globals, callers and callees from one `rebrew describe` call (through its rebrew project context): each global names its `address`, the engine `kind`, the `access` (`read`/`write`, or `null` when the instruction does not make it clear) and the owning `section` from the stored `pe-info` scan (or `null`); each caller names its `from_va` and the containing function's `name`; each callee names its `to_va`, `name`, `kind` and an `indirect` flag for an import-slot call with no resolved name; `counts` reports the row counts and `count_note` states that callers counts call sites while callees counts (target, kind) pairs; 404 `function not found`, 400 `no-engine-context`, 503 `engine-unavailable`, 500 `engine-error` |
| `/api/functions/<id>/summary` | GET | stored AI summary; 404 `no-artifact` without one; never calls the LLM |
| `/api/functions/<id>/summary` | POST | summarize the stored decompilation with the configured LLM and store the result |
| `/api/functions/<id>/ai-comments` | GET | stored AI inline comments; 404 `no-artifact` without any; never calls the LLM |
| `/api/functions/<id>/ai-comments` | POST | ask the configured LLM for inline comments on the stored decompilation and store them |
| `/api/functions/<id>/type-suggestions` | GET | stored AI type suggestions; 404 `no-artifact` without any; never calls the LLM |
| `/api/functions/<id>/type-suggestions` | POST | ask the configured LLM for type suggestions on the stored decompilation and store them |
| `/api/functions/<id>/renames` | GET | stored identifier rename suggestions; 404 `no-artifact` without any; never calls the LLM |
| `/api/functions/<id>/renames` | POST | ask the configured LLM for identifier renames on the stored decompilation and store them |
| `/api/functions/<id>/renames/apply` | POST | rewrite whole-token identifiers in the stored decompilation (refusing keywords and short names), journaling the previous text; body `{"applied": [...], "rename_function": bool}`, both optional and an omitted `applied` applies every stored suggestion |
| `/api/functions/<id>/renames/revert` | POST | restore the decompilation text the last apply journaled and drop the journal |
| `/api/functions/<id>/ai-decompilation` | GET | the stored AI decompilation rendered with its overrides, plus its token map, per-line attributions, rating and line comments; 404 `no-artifact` without one; never calls the LLM |
| `/api/functions/<id>/ai-decompilation` | POST | ask the configured LLM for a complete rewritten function over the stored decompilation and store the artifact; 404 `no-decompilation` without one, 503 `llm-unavailable`, 502 `llm-error` |
| `/api/functions/<id>/ai-decompilation/status` | GET | the artifact's workflow state (line, token, override, attribution, rating and comment counts, with the model and its time) without its text |
| `/api/functions/<id>/ai-decompilation/events` | GET | the workflow as server-sent events: the current state and its terminal marker, because the one model call is already over when a client can attach |
| `/api/functions/<id>/ai-decompilation/tokens` | GET | the rewrite's placeholder tokens with the analyst name each one carries |
| `/api/functions/<id>/ai-decompilation/overrides` | PATCH | set or clear analyst names for the rewrite's tokens; body `{"overrides": {"<token>": "<name>"}}`, a null or blank name clears one; 400 `invalid override`, 404 `unknown token` |
| `/api/functions/<id>/ai-decompilation/rating` | GET | the stored analyst rating and its note |
| `/api/functions/<id>/ai-decompilation/rating` | PATCH | record analyst feedback; body `{"rating": "up"|"down"|null, "note": str}`; 400 `invalid rating` |
| `/api/functions/<id>/ai-decompilation/inline-comments` | GET | the per-line inline comments stored beside the artifact, ordered by line |
| `/api/functions/<id>/ai-decompilation/inline-comments` | POST | store one comment at a line; body `{"line": int, "body": str, "author": str}`; 400 `invalid line-comment` |
| `/api/functions/<id>/ai-decompilation/inline-comments/<line>` | PATCH | replace the body of the comment at `<line>`; 400 `invalid line-comment`, 404 `no-line-comment` |
| `/api/functions/<id>/ai-decompilation/inline-comments/<line>` | DELETE | remove the comment at `<line>`; 400 `invalid line-comment`, 404 `no-line-comment` |
| `/api/functions/<id>/pipeline` | POST | run the AI decompilation component composition; body `{"disabled": [...]}` optional; 404 unknown function, 503 `pipeline-unavailable` only when the composition cannot be assembled (a skipped or failed stage is a step on the run) |
| `/api/functions/<id>/pipeline` | GET | stored latest run with its steps and the function's durable artifacts; 404 `no-run` before the first run |
| `/api/pipeline/runs/<id>` | GET | one pipeline run with its steps; 404 `run not found` |
| `/api/search` | GET | the typed search; `?q=`, `?kind=all\|sha256\|binary\|collection\|tag`, `?limit=`, and `?regex=true` to match the query as a bounded, cached regular expression (400 `invalid regex` for one that does not compile, and for `kind=sha256`, which is a literal hash prefix by definition) |
| `/api/binaries/<id>/functions` | GET | the function list; `?string=` may repeat, and every value is combined as any-of against the stored decompilation, with `?regex=true` treating each as a bounded regular expression (400 `invalid regex`; at most `MAX_FUNCTION_STRINGS` values, else 400 `invalid string`) |
| `/api/functions/signatures` | GET | signatures for many functions in one read; `?ids=1,2,3` (at most 200), in the caller's order, with `signature: null` for a function that has none and `found: false` for an unknown id; 400 `invalid ids` |
| `/api/analyses/<id>/signatures/copy` | POST | copy one function's signature onto others in the analysis; body `{"source_function_id", "targets"}`; journaled, with a per-target `applied`/`skipped` report; 400 `invalid source`/`invalid targets`, 404 unknown analysis or a function outside it |
| `/api/analyses/<id>/data-types` | POST | create or update an analysis's data types from C declarations; body `{"types": [<declaration>...]}` or one header string, split at top-level semicolons; one journaled action with per-entry results; 400 `invalid types` |
| `/api/analyses/<id>/data-types` | PUT | the same body, but a declaration whose type is not stored is skipped rather than created (the bulk update half) |
| `/api/analyses/<id>/data-types/<data_type_id>/functions` | GET | the functions that use one type of the analysis's binary, from the stored reference index; 404 `data type not found` when the type belongs to another binary |
| `/api/functions/callees-callers` | GET | the derived callers and callees of many functions in one read; `?ids=1,2,3` (at most `function_extras.MAX_FUNCTIONS_PER_QUERY` = 50), in the caller's order, with `found: false` for an unknown id; each payload carries the `derivation` note; 400 `invalid ids` |
| `/api/functions/matches` | GET | the recorded match rows of many functions in one read, each with the derived `difference` and `band`; runs no scoring and no engine, which the payload's `note` states; 400 `invalid ids` |
| `/api/functions/matches` | POST | the same read with the ids in the body; `{"function_ids": [...]}`; 400 `invalid ids` |
| `/api/functions/canonical-names` | POST | rename many functions to the canonical name the store already recorded (a predicted name, else the newest recorded rename), journaling every rename; body `{"function_ids", "apply"?}`, where `apply: false` only plans; a function with no candidate is `skipped` rather than renamed to a guess; 400 `invalid apply` |
| `/api/functions/<id>/indirect-call-sites` | GET | the indirect calls and jumps in the function's cached disassembly listing, each with its line, mnemonic and operand; a function with no cached listing answers an empty list with `has_disassembly: false` rather than spawning the engine; 404 `function-not-found` |
| `/api/functions/<id>/capabilities` | GET | classify one function from the imports and string literals its stored decompilation mentions, with the same rule table the binary-level scan uses; 404 `function-not-found` |
| `/api/functions/<id>/strings` | GET | the function's analyst strings and, separately, the quoted literals its stored decompilation carries; the two halves are never merged and the payload's `note` says the derived half is a text scan; 404 `function-not-found` |
| `/api/functions/<id>/strings` | POST | record one analyst string at function scope; body `{"value", "kind"?, "note"?}`; a value already stored keeps its row and updates its note; journaled; 400 `invalid string`, 404 `function-not-found` |
| `/api/functions/<id>/strings/<string_id>` | DELETE | remove one analyst string, journaled; 404 `string-not-found` for an unknown id or one of another scope |
| `/api/functions/<id>/callees` | GET | the function's derived callees (names its text mentions that the binary stores) and the edges an analyst declared, reported separately rather than merged; 404 `function-not-found` |
| `/api/functions/<id>/callees` | POST | record one analyst-declared callee edge; body `{"callee", "kind"?: "call"|"indirect", "note"?}`; re-declaring the same edge updates it in place; journaled; 400 `invalid edge`, 404 `function-not-found` |
| `/api/functions/<id>/callees/<edge_id>` | DELETE | remove one analyst-declared edge, journaled; 404 `edge-not-found` for an unknown id or one of another function |
| `/api/analyses/<id>/strings` | GET | every analyst string recorded at analysis scope; 404 `analysis not found` |
| `/api/analyses/<id>/strings` | POST | record one analyst string at analysis scope, journaled; 400 `invalid string` |
| `/api/analyses/<id>/strings` | PUT | replace the analysis's whole analyst string list in one journaled action, so one revert puts the previous list back; body `{"strings": [...]}`; every value is validated before anything is written; 400 `invalid string` |
| `/api/conversations/<id>/runs` | POST | run one agent turn: the model is offered every local MCP tool and may call them until it answers in text; body `{"content"}`; a read-only tool runs at once and a destructive one pauses the run; journaled (the run row and the messages it wrote), 503 `llm-unavailable`, 502 `llm-error`, 404 `conversation not found` |
| `/api/conversations/<id>/runs` | GET | every agent run of one conversation, newest first, each with its status, tool-call count and events |
| `/api/conversations/<id>/runs/<run_id>` | GET | one run with its events, the call it paused on and its answer; 404 `run not found` for an unknown id or one of another conversation |
| `/api/conversations/<id>/confirm` | POST | approve or reject the tool call a paused run named and continue it; body `{"approve", "run_id"?}`; a rejection is fed back to the model as a refused call; 400 `invalid approval`, 409 `no-pending-confirmation`, 404 `run not found` |
| `/api/conversations/<id>/cancel` | POST | cancel a live run at its next step boundary; body `{"run_id"?}`; 409 `run-not-cancellable` for a run that already finished, 404 `run not found` |
| `/api/conversations/<id>/events` | GET | the newest (or `?run_id=`) run's state as server-sent events: one `event: run` frame per observed change, the current state first, ending on a terminal status with a `timeout` frame at the cap; it is a state stream, not a token stream |
| `/api/external/sources` | GET | the external-source registry: each source's name, kind, availability and reason, plus whether the remote gate is on and a VirusTotal key resolves |
| `/api/analyses/<id>/external/<source>` | POST | run one source for the analysis and store its answer as the `external:<source>` scan; 403 `external-disabled`, 503 `external-unavailable`, 400 `no-content-hash`, 502 `external-fetch-failed`, 404 `unknown source`; journaled |
| `/api/analyses/<id>/external/<source>` | GET | the stored answer of one source; 404 `no-scan` before the first pull |
| `/api/analyses/<id>/external/<source>/status` | GET | whether the source can run for the analysis, why it cannot, and whether an answer is stored |
| `/api/secrets` | GET | every stored credential the caller may see, redacted to its name, scope, team, byte length and a last-four hint; `?scope=`/`?team_id=` filter; the value is never in a payload |
| `/api/secrets/<name>` | PUT | store or replace one credential; body `{"value", "scope"?, "team_id"?}`; a workspace secret needs an admin, a team secret that team's membership; 400 `invalid secret`, 403 `secret forbidden`, 404 `team not found`; journaled |
| `/api/secrets/<name>` | DELETE | remove one credential, journaled (a revert restores the row); `?scope=`/`?team_id=` name it; 404 `secret not found` |
| `/api/binaries/<id>/symbols` | POST | ingest a debug symbol file: a multipart upload with one `file` part (a PDB or an ELF with DWARF) and an optional `apply` field (false stores the parse without applying it); the file is stored under `<workspace>/symbols/<sha256>` and its functions are renamed and its types added as one journaled action; 400 `no-file`/`too-many-files`/`empty-file`/`symbols-unreadable`, 404 `binary not found` |
| `/api/binaries/<id>/symbols` | GET | every symbol file ingested for the binary, newest first, each with its kind, counts, notes and the whole parse; 404 `no-symbols` before the first ingest |
| `/api/binaries/<id>/symbols/export` | GET | render one parse as a C header (`?format=c`, the default, through the type model's renderer) or as JSON (`?format=json`), `?file_id=` naming one ingest (the newest without it); 400 `invalid format`, 404 `no-symbols`/`run not found` for an unknown ingest |
| `/api/binaries/<id>/ratings` | GET | every stored agent artifact of the binary (its scans) with the analyst's verdict on it; an artifact that was never produced is left out and one that was produced but not rated carries `rating: null`; the payload also carries `rated`, `count` and the rateable `kinds` |
| `/api/binaries/<id>/ratings/<kind>` | GET | one artifact's rating, whether or not a verdict is stored; 404 `no-artifact` when the binary has no stored scan of that kind |
| `/api/binaries/<id>/ratings/<kind>` | PUT | record or clear one verdict; body `{"rating": "up"\|"down"\|null, "note"?}`; an empty rating clears it, the write is journaled so a revert restores the previous one, and a kind outside the store's scan vocabulary is 400 `invalid rating` |
| `/api/stats/series` | GET | the dashboard time series over `?days=` (30 by default, at most `analytics.MAX_SERIES_DAYS`): analyses created, auto runs started and journaled actions per day plus the software type each analysis's binary derives; every day in the window is present, a quiet one with a zero, a derivation capped at `MAX_SERIES_ANALYSES` reports itself in `notes`, and 400 `invalid days` is answered outside the bounds |
| `/api/models` | GET | the local model registry: the engine, every decompiler backend, the configured bridge model (or the single `unconfigured` entry) and the optional similarity extra, each with its kind, version, availability and reason |
| `/api/docs` | GET | every shipped documentation page in reading order, each with its `slug` and title; the pages are the workspace's `docs/*.md` plus `CHANGELOG.md`; 404 `no-docs` when no documentation directory resolves (`REPORTAL_DOCS`, then the workspace, then the checkout) |
| `/api/docs/<slug>` | GET | one page parsed into its title, its `headings` (the on-this-page anchors), its `blocks` (headings, paragraphs, lists with each item's `depth`, fenced `code`, `quote`s and `table`s) and its `previous`/`next` neighbours in reading order (each a `slug` and title, null at either end), so the SPA renders it without any markup injection and without re-deriving the order; 404 `no-doc` for an unknown or malformed slug, `no-docs` when there is no directory |
| `/api/analyses/<id>/upgrade` | POST | re-run one analysis's stored AI artifacts under a named `llm` model, journaling every artifact replaced; body `{"model", "functions"?, "limit"?}`; 400 `invalid model`, 404 `analysis not found` / `model not found`, 503 `llm-unavailable` |
| `/api/pipeline/runs/<id>/revert` | POST | replay the run's undo plan newest-first and return what was undone; 404 `run not found` |
| `/api/components` | GET | the component registry: each entry's `name`, `requires`, `provides`, `origin` and `reloadable` |
| `/api/components/reload` | POST | re-read one component's declaring module and swap the live registry entry; body `{"name": "..."}` or `{"all": true}`; 404 unknown name, 400 neither/both/non-boolean `all`, 409 `not-reloadable`, 500 `component-missing` |
| `/api/components/<name>/deactivate` | POST | withdraw one component from the live composition: run its `revert` where declared and revoke the names it provided; returns the `deactivated` entries and a `journal_action` when the withdrawal recorded a durable write; 404 unknown name, 409 `not-withdrawable` (nothing to withdraw, or already withdrawn) |
| `/api/integrations` | GET | every plugin seam (pipeline components, auto-mode workers, graph backends, effect handlers, MCP tools) with the parts its registry currently holds, read from the live registries; read-only |
| `/api/journal` | GET | recorded action-journal entries, newest first, without their descriptor payload; `?limit=` (default `journal.DEFAULT_LIST_LIMIT`, hard cap `journal.MAX_LIST_LIMIT`) and optional `?action=`; 400 for a non-integer or non-positive limit; read-only |
| `/api/jobs` | GET | queued and finished operations, newest first: `?status=` (one of `jobs.STATUSES`), `?kind=` (a registered job kind), `?binary_id=` and `?limit=` (bounded by `jobs.MAX_JOB_LIMIT`) are each validated with a 400; the payload carries the `jobs`, the matching `total`, the `queued` count and the `kinds` that may be queued |
| `/api/jobs` | POST | queue one operation and answer `202` with the job; the registered kinds are the eight scans plus `report` (the engine report over the reversed sources) and `report-pdf` (the PDF over the stored scans); body `{"kind", "binary_id", "params"?}` (an unknown kind, an unexpected parameter, a refused domain value or a full queue is 400 `invalid job`, an unknown binary 404 `binary not found`); the server's bounded pool runs it, and when no pool can start the job runs inline |
| `/api/jobs/<id>` | GET | one job with its `status`, `progress`/`steps_total`, `message` and its `result` or `error`; 404 `job not found` |
| `/api/jobs/<id>/cancel` | POST | cancel a job that has not started; 409 `job-not-cancellable` once it is running or finished (an engine call cannot be interrupted), 404 `job not found` |
| `/api/jobs/<id>/events` | GET | the job's state as server-sent events (`text/event-stream`): one `event: job` frame per observed change, the current state first, and a `timeout` frame at the stream's cap; 404 `job not found` |
| `/api/jobs/run` | POST | run the oldest waiting jobs inline and answer what finished (`?limit=` bounded); the pool does this on its own in a serving process |
| `/api/notifications` | GET | the notification feed, derived from the action journal (one item per action, with its `status`, row `entries` and whether it is still `revertible`) and the analysis log (one item per entry, with its `severity` and its binary's id and name), normalized to one shape and newest first; `?since=` is an inclusive ISO timestamp and must be percent-encoded (its `+` offset is a space otherwise), `?limit=` is bounded by `notifications.MAX_FEED_LIMIT` and `?sources=` narrows to `action`, `log` or both; each item carries `seq`, the source row id that breaks a same-second tie, and the payload carries `count`, the true `total` and `latest`, which a poller passes back as `since`; 400 `invalid since`/`invalid limit`/`invalid sources`; stores and writes nothing, and dismissal is the client's, keyed by each item's stable `id` |
| `/api/journal/<action>` | GET | every entry of one action; 404 `action not found` for an action never recorded; read-only |
| `/api/journal/revert` | POST | replay one action's active descriptors newest-first or one entry's; body `{"action"}` or `{"entry_id"}`; 404 `action not found`/`entry not found`, 400 `invalid body` (neither, both, a non-integer `entry_id`) or `not-active` for an entry already reverted, 500 `journal-error` for an unreadable stored descriptor |
| `/api/binaries/<id>/auto` | POST | plan an auto run and execute it in a background thread; body `{"worker", "execute", "concurrency", "functions_per_task", "max_attempts", "max_tasks"}`, all optional and every bound validated (400 `invalid params`); answers 202 `{"run_id", "binary_id", "status": "running"}`; `execute` defaults to false |
| `/api/binaries/<id>/auto` | GET | the binary's latest auto run with its task tree and coverage delta; 404 `no-run` before the first run |
| `/api/auto/runs/<id>` | GET | one auto run with its task tree and coverage; 404 `run not found` |
| `/api/auto/runs/<id>/revert` | POST | remove the files the run wrote, restore the statuses it changed and delete its rows; 404 `run not found` |
| `/api/conversations` | GET | conversations, optionally filtered by `?scope_kind=` and `?scope_id=` |
| `/api/conversations` | POST | create a conversation; body `{"scope_kind": "function"\|"binary"\|"docs", "scope_id": ..., "title": optional}`; 404 for an unknown scope id. A `docs` conversation grounds its answers in the shipped manual, which is ingested into the `docs` knowledge scope on the first question; its `scope_id` is carried but never matched, and its default title is `reportal documentation` |
| `/api/conversations/<id>` | GET | one conversation plus its messages |
| `/api/conversations/<id>` | DELETE | delete a conversation and its messages |
| `/api/conversations/<id>/messages` | POST | send one message; body `{"content": ...}`; 400 on blank, 503 `llm-unavailable` without a client, 502 `llm-error` on model failure |
| `/api/analyses/<id>` | GET | one analysis with its `function_count`, its scans (each kind and status), its `log_count` and the owning binary's `tags`; 404 `analysis not found` |
| `/api/analyses/<id>/status` | GET | the lifecycle read: `status`, `terminal`, the created and finished times, `scans` and `scans_by_status`, `logs` and `logs_by_severity`; 404 `analysis not found` |
| `/api/analyses/<id>/params` | GET | what a re-run would need, read from the stored rows: the engine label, the times, the binary with its content hash, size, format, arch and path, the rebrew project context and the scan kinds already stored; 404 `analysis not found` |
| `/api/analyses/<id>/func-maps` | GET | the analysis's function map, ordered by address: each function's `id`, `va`, `name` and `size`, with `count` and the true `total`; an analysis with no functions answers an empty map; 404 `analysis not found` |
| `/api/binaries/<id>/dynamic-execution` | POST | detonate a stored sample under the sandbox runner and store the report; body `{"timeout": seconds, "memory_mb": MiB}` narrows the caps (400 `invalid-sandbox` outside them or for a non-integer); 403 `sandbox-disabled` unless the workspace opted in, 503 `sandbox-unavailable` without an installed runner, 404 `binary not found`, 400 `binary not on disk`; 201 with the report (the runner, the exact argv, the caps, the exit status, the duration, bounded stdout/stderr and the files the sample wrote), one journaled row |
| `/api/binaries/<id>/dynamic-execution` | GET | the binary's newest detonation report plus the `detonation` status block; 404 `no-run` before the first run, 404 `binary not found` for an unknown id |
| `/api/analyses/<id>/dynamic-execution` | GET | the same report read through its analysis (the hosted `dynamic-execution/report` read); 404 `no-run`, 404 `analysis not found` |
| `/api/analyses/<id>/dynamic-execution/status` | GET | whether this install can detonate (`enabled`, `available`, the `runner` in use and every registered runner with its availability), the caps in force and the analysis's `runs` with the `last` run's summary; 404 `analysis not found`; read-only |
| `/api/analyses/<id>/imported-functions` | GET | the analysis's import stubs (`functions.name_source` is `import`), each with the functions whose stored decompilation mentions its name: `callers` (bounded by `caller_limit`, each with `id`, `va`, `name`), the true `caller_count`, `caller_method` naming how the callers were derived, `count` and the true `total`; `?limit=` defaults to `store.DEFAULT_IMPORTED_LIMIT` and is capped at `MAX_IMPORTED_LIMIT` (400 `invalid limit` outside it); 404 `analysis not found` |
| `/api/analyses/<id>/bytes` | GET | the analysis's binary bytes, streamed exactly as `GET /api/binaries/<id>/download` streams them (chunked, named attachment, immutable cache); 404 `analysis not found`, 404 `binary not on disk` when the file is gone |
| `/api/analyses/<id>` | PATCH | relabel the analysis's engine; body `{"engine"}` (400 `invalid body` without it), journaled and revertible; 404 `analysis not found` |
| `/api/analyses/<id>/logs` | POST | append one log entry; body `{"message", "severity"?}` with the severity from the closed set (400 `invalid severity`, 400 `message must be a non-empty string`); 201 with the entry, journaled so a revert removes it; 404 `analysis not found` |
| `/api/analyses/<id>/requeue` | POST | put the analysis back to `pending`, clear its finish time and log the transition, all journaled (a revert restores the status, the time and the log); 404 `analysis not found` |
| `/api/analyses/<id>/tags` | GET | the tags on the analysis's binary, which is the scope reportal tags at; 404 `analysis not found` |
| `/api/analyses/<id>/tags` | PATCH | replace those tags; body `{"tags": [name, ...]}` (400 `invalid body` for anything else), creating the names that are new, journaled per link so a revert restores the previous set; 404 `analysis not found` |
| `/api/analyses` | GET | analyses with the binary name, size, format, arch, its tags and its scope; `?status=` (any of `store.ANALYSIS_STATUSES`, repeatable and combined as any-of), `?search=` (binary name or engine), `?platform=`/`?arch=` (the stored binary's own `format`/`arch`), `?order=` (one of `store.ANALYSIS_ORDERS`: `newest`, `oldest`, `name`, `name-desc`, `size`, `size-desc`), `?limit=` (default and cap `store.MAX_ANALYSIS_LIMIT`), `?binary_id=` and `?workspace=personal\|team\|public` (one of `store.WORKSPACE_FILTERS`, reading the owning binary's scope: no owning team, an owning team, or one the whole workspace may see); an unknown value is 400; each row carries `visibility`, `owner_team_id` and `owner_team_name`, and the body carries `count` (returned), `total` (unfiltered, so a filter that matched nothing is distinguishable from an empty project), `statuses`, and the `platforms`/`architectures` the register actually holds, which is what the SPA's filter controls are built from |
| `/api/analyses` | POST | create analysis; body `{"binary_id": ..., "engine": ...}` |
| `/api/analyses/bulk` | POST | apply one action to many analyses; body `{"action", "analysis_ids", "tag"?}` with the action from `add_tag`/`remove_tag`/`delete`, at least one id and at most `bulk_actions.MAX_BULK_IDS` (400 `invalid bulk request` otherwise); a tag action writes the tags of each analysis's owning binary (the only scope reportal tags at), a delete replays the journaled snapshot `DELETE /api/analyses/<id>` uses, and the whole request is one journal action answering `{"action", "requested", "applied", "skipped"}` where an unknown id is `not found` and a binary's only analysis with functions is `only analysis with functions` |
| `/api/analyses/<id>/logs` | GET | the analysis's structured log, newest first; `?limit=` (default `analysis_log.DEFAULT_LOG_LIMIT`, cap `MAX_LOG_LIMIT`) and `?offset=`; returns `{"logs", "count", "total", "limit", "offset"}` with the log's true total; 404 `analysis not found`, 400 for an out-of-range or non-integer bound; read-only |
| `/api/analyses/<id>` | DELETE | delete one analysis with its functions, matches, scans and log entries, journaled so the revert restores them parent-first; 404 `analysis not found`, 409 `last-analysis` for a binary's only analysis while it holds functions (delete the binary instead) |
| `/api/collections` | GET | collections with binary counts, their scope and their owner, in `?order=` (`id`, the default, `name`, `size` by member count, `updated` by the last field, membership or tag change, `owner` by the owning team's name with the personal collections first); `?workspace=personal\|team\|public` (one of `store.WORKSPACE_FILTERS`, reading the collection's own scope: no owning team, an owning team, or one the whole workspace may see); an unknown value is 400 `invalid order`/`invalid workspace`; each row carries `visibility`, `owner_team_id` and `owner_team_name` (null for a personal collection), and the response echoes the `order` and the `workspace` filter it applied |
| `/api/collections` | POST | create collection; body `{"name": ..., "description": ..., "scope": ...}` |
| `/api/collections/<id>/binaries` | POST | add a binary; body `{"binary_id": ...}` |
| `/api/collections/<id>` | GET | one collection with its members (`id`, `name`, `sha256`, `size`) and its tags; 404 `collection not found` |
| `/api/collections/<id>` | PATCH | rename it or set `description`/`scope` (absent fields stay); 400 `invalid collection` for an empty body, an empty name or a name already taken; journaled |
| `/api/collections/<id>` | DELETE | delete it with its membership and tag links; 404 `collection not found`; journaled, and a revert puts the links and the row back in that order |
| `/api/collections/<id>/binaries` | PATCH | make `{"binary_ids": [...]}` the exact member list; 404 `binary not found` naming the first unknown id, and nothing is written; journaled |
| `/api/collections/<id>/binaries` | DELETE | remove `{"binary_ids": [...]}`, keeping the other members; 400 when the key is absent; journaled |
| `/api/collections/<id>/tags` | PATCH | replace the tags with `{"tags": [...]}`, creating the new names (`[]` clears them); 400 when the key is absent; journaled |
| `/api/tags` | GET | all tags with their tagged-binary count |
| `/api/tags` | POST | create a tag by name; body `{"name": ...}`; idempotent |
| `/api/binaries/<id>/documents` | POST | ingest a document file into the binary's knowledge scope; `multipart/form-data` with a `file` part and an optional `title` field; 201 on create, 200 with `duplicate: true` on a repeat |
| `/api/binaries/<id>/documents` | GET | the knowledge documents of one binary, newest last, without their text |
| `/api/documents` | GET | documents, optionally filtered by `?scope_kind=` and `?scope_id=` |
| `/api/documents` | POST | ingest a pasted note; body `{"scope_kind": "binary"\|"project", "scope_id", "title", "text", "source"}`, `text` required |
| `/api/documents/<id>` | GET | one document: metadata and chunk count, adding `text` and `chunks` with `?include_text=true` |
| `/api/documents/<id>` | DELETE | delete a document and, by cascade, its chunks; 404 `document not found` |
| `/api/knowledge/config` | GET | `{"allow_remote": bool}`; whether guarded URL ingestion is enabled; read-only |
| `/api/knowledge/fetch` | POST | fetch an http(s) URL into a knowledge scope; body `{"scope_kind", "scope_id", "url", "title"}`; 403 `remote-ingest-disabled` while off, 400 for a blocked or malformed target or an unsupported content type, 413 `file-too-large`, 502 `fetch-failed`, 404 for an unknown binary scope, 201 on create and 200 with `duplicate: true` on a repeat |
| `/api/knowledge/search` | GET | `?q=&binary_id=&limit=` ranks stored document chunks (embeddings, else local TF-IDF); read-only |
| `/api/functions/<id>/knowledge` | GET | read-only bounded retrieve from the function's binary documents against `?q=`; the query defaults to the function name |
| `/api/binaries/<id>/knowledge` | GET | read-only bounded retrieve from the binary's documents against `?q=` |
| `/api/binaries/<id>/graph` | POST | rebuild the binary's knowledge graph from the stored rows; returns `{"binary_id", "nodes", "edges", "truncated", "built_at"}` |
| `/api/binaries/<id>/graph` | GET | the stored graph with node degrees and per-kind counts; 404 `no-graph` before the first build; `?kind=` keeps one node kind, `?include_documents=true` adds document nodes and their mention edges |
| `/api/graph/nodes/<node_id>` | GET | one graph node with its incoming and outgoing edges grouped by relation; 404 `node not found` |
| `/api/graph/backends` | GET | the registered knowledge-graph backends (`name`, `available`, `description`, `unavailable_reason`, `supports_query`) plus the configured `default`; read-only |
| `/api/binaries/<id>/graph/sync` | POST | push the binary's stored graph to a backend; optional body `{"backend": "..."}` (default: the configured backend); returns the backend's report; 404 unknown binary or backend, 404 `no-graph` without a stored graph, 400 `invalid body`, 503 `backend-unavailable` with the install hint |
| `/api/graph/query` | GET | `?q=&backend=` queries a backend that supports query; an exact node id or a label/key substring search across every binary; 404 unknown backend, 503 `backend-unavailable`, 400 `query-unsupported`; read-only |
| `/api/search` | GET | `?q=` and `?kind=` (`all` default; `sha256`, `binary`, `collection`, `tag`) typed search over binaries, functions, collections and tags; rows carry the store's metadata (size, format, arch, created, tags) plus the `match` kind, `counts` reports each group's returned count against its matched total, and `?limit=` bounds each group; 400 `invalid-kind`, `invalid-hash`, `short-hash`, `ambiguous-hash`, `invalid limit` |
| `/` | GET | built SPA (`assets/dist/index.html`); 503 `ui-not-built` before the first build |
| `/static/<path>` | GET | built SPA assets from `assets/dist` |
| `/reports/<id>/` | GET | generated report site entry page (`index.html`) |
| `/reports/<id>/<path>` | GET | one file of a binary's generated report site |

POST bodies are JSON objects; bad input returns 400 with a fixed message, an
unknown id returns 404.  Every JSON error body is `{"error": ..., "detail": ...,
"doc_url": ...}`: `error` is the stable code to branch on, `detail` the human
context (an id, a path, a bounded engine message) and `doc_url` a link into
`docs/ERRORS.md`'s section for that code (the catalogue is
`src/reportal/error_docs.py`), or `null` for a code the catalogue does not name,
so no code is ever linked to a heading that does not exist.  This is a
deliberate change to every route's error contract; the MCP tool errors carry the
same vocabulary.  A field-level validation message built at the call site
(`narrative must be a boolean`, `invalid kind`) shares the page's
`invalid-params` section.
A wired mutating route adds a `journal_action` field to its success body when
the request recorded at least one journaled write: the upload, fingerprint,
tag, bulk, rename, revert, unstrip-apply, apply-match, comment, conversation,
collection, analysis, family, data-type, signature, AI-artifact, graph-rebuild,
PDF and knowledge-ingest routes carry it, and every scan POST that stores a
`scans` row does too (its `analyses` carrier is journaled only when the action
created it).  `DELETE /api/analyses/<id>` carries it as well: its entry
snapshots the analysis, its functions, matches, scans, decompilations, AI
artifacts, pipeline rows and log entries, so the revert restores them
parent-first.  Passing that id to `POST /api/journal/revert` takes the request's
writes back; a route whose no-op stored nothing (a duplicate upload or ingest,
an unchanged rename, an already-known tag) omits the field, and the matching CLI
commands print the id to stderr in human mode (or carry it in the `--json`
payload).  A destructive MCP tool result carries the same field in its JSON
payload.
The rename, revert and apply-match routes return 404 for an unknown function or
history row; apply-match adds 400 `no-such-match` without a recorded match and
400 `candidate-has-no-name` for a nameless candidate.  The binary-tag POST
answers 400 `invalid body` unless the body carries exactly one of `name` or
`tag_id`, and the DELETE answers 404 when the link does not exist.
`POST /api/binaries` is the one non-JSON body: `multipart/form-data` with a
`file` part and an optional `name` field.  A missing part answers 400
`no-file`, an empty part 400 `empty-file`, a malformed body 400 `invalid-body`,
and an upload past `MAX_UPLOAD_BYTES` (256 MiB) 413 `file-too-large`.  The part
is streamed to a temporary file under `<workspace>/binaries/` while sha256 is
computed, then published with `os.replace` as `<sha256><suffix>`; the suffix
comes from the client filename only when it matches `^\.[A-Za-z0-9]{1,8}$`, so
the client name never becomes a path component.  A repeat upload of the same
bytes returns the existing row with `"duplicate": true` instead of adding one.
Repeated `file` parts, or a JSON `files` field beside one part, make the same
route a **batch**: the parts are streamed in order, `files[i]` carries part
*i*'s `name`, `tags`, `collection_ids` and explicit `format`/`arch` (validated
against `UPLOAD_FORMATS`/`UPLOAD_ARCHITECTURES`, `auto` being absent), an entry
that fails answers the same code the single-file path would (`empty-file`,
`file-too-large`) inside its own `error` object while the other files still
register, and a duplicate is reported as `"duplicate": true` rather than as a
failure.  A batch past `MAX_UPLOAD_FILES` (64) is 400 `too-many-files`; naming
files through the top-level `name` in a batch is 400 `invalid-body`.  Tags are
applied through `create_tag`/`add_binary_tag` and the collection links through
`add_collection_binary`, all inside one `journaled` action, so reverting the
response's `journal_action` removes every binary, tag and link the request
created.  A compiler hint has no column in reportal's binary model (the hosted
portal's Platform and Visibility have no local meaning either), so it is not
stored.
`POST /api/binaries/<id>/extract` reads a stored archive through
`reportal.archive` (stdlib only) and registers its members as binaries in one
collection, reached by the route, `reportal extract` and the `extract_archive`
MCP tool from the same `extract_archive_binary` helper.  Supported are
`.zip`/`.apk`, `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`, `.tar.xz` and a
single-member `.gz` (a `.gz` that is a tar is read as one); `.rar` and `.7z`
answer 400 `external-tool-required` naming the unpacker reportal does not ship,
firmware images are out of scope, and nothing is shelled out.  Every member is
validated before a byte is written: an absolute name, a `..` component, a path
resolving outside the temporary extraction root, a symlink or hardlink, a
device, FIFO or socket is refused per member with its reason, as is a member
past `MAX_MEMBER_BYTES`, a total past `MAX_TOTAL_BYTES`, a ratio past
`MAX_COMPRESSION_RATIO` and an archive past `MAX_MEMBERS`.  An archive that
cannot be read at all (a missing/wrong password, a corrupt stream) is one 400
with the module's own code, and the temporary directory is removed either way.
The response reports `members` (name, size, the binary id it became or the
`skipped` reason), the `notes` the extraction recorded, `kept`/`skipped`, the
collection and the `journal_action`.
Engine routes answer 503 `{"error": "engine-unavailable"}` when the installed
rebrew package cannot be imported, and 400 when the binary row has no file on disk.
The disassembly route answers 400 `{"error": "no-engine-context", ...}` for a
binary `import-rebrew` never gave a rebrew project, 400 for an unsupported
format, and 500 for an engine failure.  The decompilation routes share that
mapping and add 400 `invalid backend` for an unknown decompiler name; a stored
row answers 200 without an engine.  The diff routes share that mapping (404
unknown function or candidate, 400 `no-engine-context` for a live side without
a project, 503 without an engine, 500 `engine-error`) and add 400
`no-such-match` when the explicit candidate is not a recorded match, 400
`invalid kind` for a `kind` other than `disasm`/`decomp`, and 400 for a
non-boolean `normalize`; the omitted-candidate route uses the function's best
recorded match and answers 404 `no-match` without one, and a stored
decompilation serves a `decomp` side without an engine.  The `reportal diff`
command and the `diff_functions` MCP tool call the same helper without the
recorded-match requirement, so they align any two stored functions.  The triage
POST follows the engine mapping
(404 unknown id, 400 when the binary row has no file, 503 without an engine,
500 `engine-error`) and the report POST adds 400 `no-engine-context` like
disassembly; both compute and store.  Their GET routes are stored-only: a
stored scan answers 200 without resolving the engine or the project context,
and a binary without one answers 404
`{"error": "no-scan", "detail": "no <kind> scan for binary <id>; ..."}`.  The
xrefs route follows the disassembly mapping (404 unknown
function, 400 `no-engine-context`, 503 without an engine, 500 `engine-error`)
and is never cached.  The structs POST shares that engine mapping and adds 400
`invalid backend` for an unknown decompiler name and 400 `invalid limit` for a
negative or non-integer limit; `GET /api/binaries/<id>/structs` is stored-only
like triage and report.  The data-type routes read and write the local model
and never touch the engine: `GET /api/binaries/<id>/data-types` always answers
with the model, takes the optional `kind`/`namespace`/`search` filters (an
unknown kind 400 `invalid kind`, an unknown namespace an empty list rather
than an error) and reports the filtered `count` against the unfiltered `total`
plus the namespace tree; `GET /api/data-types/<id>/references` answers the two
name-matched reverse indices with their `note`; `POST .../data-types/import` is
stored-only (404 `no-scan` without a stored structs scan), and
`POST .../data-types/export` takes
`{"path", "force"}` and answers 409 `export-exists` for an existing target
without `force` and 400 `invalid path` when the parent directory cannot be
created.  The `PATCH /api/data-types/<id>` and member routes answer 404
`data-type-not-found`/`member-not-found`, 400 `invalid name` for a
non-identifier, 400 `invalid kind` listing the known kinds, 400 `invalid size`
for a negative or non-integer declared size, 400 `duplicate name`/`duplicate
member` for a clash, and 400 `invalid member` for an unparsable member type,
naming both an insert `index` and an `after`, removing the last member or a
member edit on a kind without a member list.  The enum value routes answer 404
`member-not-found` for an unknown selector (a value is a member entry of the
enum, so it shares the documented selector code), 400 `duplicate member` for a
duplicate constant name or value, and 400 `invalid member` for a bad literal,
the last value or a kind without values.  Every type payload carries
`size_check`: the declared size, the extent the members imply, `match`, and a
`warning` naming both numbers when they disagree; the check is read-only and
rewrites neither number.
An agent run goes one step past a plain turn: `POST
/api/conversations/<id>/runs` offers the model every tool the local MCP registry
declares, runs the read-only ones it asks for through the same handler the stdio
server calls and feeds each result back as a tool turn, until the model answers
in text or the run reaches `agent.MAX_TOOL_CALLS`.  A tool that changes the
workspace pauses the run instead: the run row stores the pending call and the
message list, `POST .../confirm` decides it (a rejection is fed back as a
refused tool result, so the run continues), `POST .../cancel` stops a live run at
its next step boundary, and `GET .../events` streams the run's state rather than
the model's tokens.  The run row and the messages it wrote are one journaled
action; a tool the run called carries its own, so reverting a conversation does
not undo a tool's write.
A debug symbol file is the one name source reportal cannot derive, so `POST
/api/binaries/<id>/symbols` stores it content-addressed under the workspace's
`symbols/` directory, parses it with the stdlib readers (ELF symbol tables,
DWARF 2 to 5 in `.debug_info` with the indexed `strx`/`addrx` forms resolved
through the unit's own bases, and a PDB's MSF container and DBI symbol record
stream) and applies it as one journaled action: a function whose VA matches a
symbol is renamed with the `symbol` name source and every aggregate type is
created or updated in the type model, so a revert puts both back.  `apply:
false` stores the parse alone.  Every parse carries its `notes` naming the
ceilings (a member offset carried by a DWARF location expression is skipped, a
type reference deeper than `MAX_TYPE_DEPTH` is left out, and PDB types are not
reconstructed because the TPI stream is not parsed), and `?format=c` renders
the export through `data_types.render_header` so a header and the model cannot
disagree.
The function-level extras are derived from rows the workspace already holds and
say so in every payload: the indirect call sites come from `disasm_cache` (a
function with no cached listing reports `has_disassembly: false` and no sites
rather than spawning the engine behind a read, and an operand that is a register
or a memory reference is what makes a call indirect), the per-function
capabilities come from the imports and quoted literals the stored decompilation
mentions classified through the same rule table the binary-level scan uses, and
the callees are the names that text mentions matched against the binary's
function names and import stubs.  The one thing there that is not derived is an
analyst-declared edge: `POST /api/functions/<id>/callees` stores a claim the
engine could not resolve, with `source: analyst`, and it is reported beside the
derived callees rather than merged into them.  The analyst strings are stored at
function or analysis scope, the derived literals are reported separately from
them, and `POST /api/functions/canonical-names` renames to a candidate the store
already recorded (a predicted name, else the newest rename) and skips a function
with none instead of renaming it to a guess.
The signature routes also read and write the local model and never touch the
engine: `GET /api/binaries/<id>/signatures` always answers with the model,
`POST .../signatures/import` parses the binary's stored decompilations (a
binary with none answers a zero summary, not an error), and
`POST .../signatures/export` takes `{"path", "force"}` (409 `export-exists`,
400 `invalid path`).  `GET /api/functions/<id>/signature` returns the row plus
its rendered `prototype` and answers 404 `signature-not-found` without one;
each parameter also carries `default_at`, the arrival location its calling
convention implies (a derived value, never the model's `at`), which stays
`null` for a convention the table does not know; its
`PATCH` takes `return_type` and/or `calling_convention` (400 `invalid request`
when neither is given, 400 `invalid type` for an empty or unknown one), the
`parameters` POST/PATCH/DELETE routes answer 400 `invalid type`, `invalid
name`, `duplicate parameter` and `invalid index`, and `DELETE` on the
signature answers 404 `signature-not-found`.  The parameter `PATCH` also takes
the optional `at`, `kind` and `bits` (an explicit `null` clears a field, an
absent key leaves it), 400 `invalid parameter` when no field is named or one
has the wrong type, and the `parameters/<index>/move` POST reorders one
parameter by `to_index`, recomputing every derivable `at` from its new index.
Every mutation appends the state
it replaced to the function's signature history, served by `GET
/api/functions/<id>/signature/history` (an empty list for a legacy row);
`POST /api/functions/<id>/signature/history/<history_id>/revert` restores that
state, journals the row it replaces and the history row it appends (so the
revert carries a `journal_action` that reverts the revert), answers 404
`history not found` for an unknown row or one of another function, and is a
no-op when the signature already holds the recorded state.  `GET
/api/binaries/<id>/section-coverage` is stored-only and reads the stored
entities into a per-section byte-coverage payload (see below), and `GET
/api/binaries/<id>/memory` is the engine-backed byte-window read while `GET
/api/binaries/<id>/memory/page` is the full-file page walk.
The crypto-scan POST needs only the binary file (no
project context) and follows the same engine mapping, and its GET is
stored-only like the other scans.  The pe-info POST also needs only the binary
file: it runs `rebrew pe-info`, follows the same engine mapping (404 unknown
id, 400 no file, 503 without an engine, 500 `engine-error`) and stores the
payload, and its GET is stored-only like the other scans.  The memory GET is
the one engine read that returns binary bytes: it takes `?va=` (required),
`?length=` (default 64, cap 1024, the hosted portal's `read_memory` bounds) and
`?kind=` (`va`, `rva` or `file`) and answers `{"binary_id", "kind", "address",
"va", "section", "length", "bytes"}` with the bytes as lowercase hex.  rebrew
exposes no raw byte-read command, so the engine surface locates the bytes with
its own `rebrew pe-info` section map and reads the file exactly where that map
says they live, never parsing a PE in reportal; an address not backed by the
image's raw bytes (a gap between sections, a header-only RVA, or a section's
uninitialized tail), and a window that runs past the backing bytes, answer 400
`unmapped address`, a bad `va`/`length`/`kind` answers 400 `invalid
address`/`invalid length`/`invalid kind`, and a failed engine invocation answers
500 `engine-error`.  The section-coverage GET is stored-only: it reads the
stored `pe-info` sections and the stored functions and answers each section's
`covered`, `size`, `coverage_pct` and `uncovered` plus the totals, unioning
overlapping functions (no double counting) and clipping a function that
straddles a section end; it answers 404 `no-scan` without a stored `pe-info`
scan, reports `null` percentages with a zero-function note when no function is
stored (never a fabricated 0%), and its payload's `note` says plainly that this
is reportal's own metric and not a hosted-portal feature.  The capabilities POST also needs only the
binary file: it runs `rebrew imports` and `rebrew strings`, matches them against
the local rule table and stores the result, following the same engine mapping,
and its GET is stored-only like the other scans.  The secrets POST also needs only
the binary file: it runs `rebrew strings`, matches the entries against the local
pattern table and the entropy check and stores the findings, following the same
engine mapping, and its GET is stored-only like the other scans.  The protocols POST also needs
only the binary file: it runs `rebrew imports` and `rebrew strings`, infers the protocols with the
local rule table (a dedicated API or a scheme is `high`, the generic socket family or a literal
`medium`, and an import plus a scheme or literal match is promoted to `high`) and stores the
result, following the same engine mapping, and its GET is stored-only like the other scans.  The
behavior POST also needs only the
binary file: it validates the domain against `behavior.BEHAVIOR_DOMAINS` (404
`domain not found` for an unknown one), runs `rebrew imports` and `rebrew
strings`, matches them against the domain's rule table and stores the result,
following the same engine mapping; `GET /api/binaries/<id>/behavior/<domain>`
is stored-only and answers 404 `no-scan` with the run hint, and `GET
/api/binaries/<id>/behavior` serves all three stored scans with nulls where a
domain has none; neither GET touches the engine.  The hardening POST needs only the
binary file (no project context): it validates the domain against
`hardening.HARDENING_DOMAINS` (404 `domain not found` for an unknown one), runs
`rebrew imports` and `rebrew strings` (and, for `obfuscation`,
`rebrew fingerprints` plus the stored triage dossier read, never run), applies
the domain's rules and stores the result, following the same engine mapping; an
unavailable fingerprint is recorded as a note with the entropy thresholds
skipped rather than failing the request.  `GET /api/binaries/<id>/hardening/<domain>`
is stored-only and answers 404 `no-scan` with the run hint, and `GET
/api/binaries/<id>/hardening` serves both stored scans with nulls where a domain
has none; neither GET touches the engine.  The security-scan POST needs the binary's
rebrew project context (400 `no-engine-context` without one), validates the
optional `min_severity` against `high`/`medium`/`low` (400 `invalid severity`),
follows the same engine mapping, and its GET is stored-only like the other
scans.  The threat POST needs only the binary file (no project context): it runs
`rebrew strings` and `rebrew imports`, reads the stored capability scan without
re-running it, and follows the same engine mapping (404 unknown id, 400 no file,
503 without an engine, 500 `engine-error`), with the optional `narrative`
validated as a boolean (400 `narrative must be a boolean`); a requested
narrative without a configured LLM is not an error, it is returned with a note,
and its GET is stored-only like the other scans.  The remediation POST needs
only the binary file (no project context): it reads `rebrew strings` and
`rebrew imports` and, when no fingerprint is stored, `rebrew fingerprints`,
follows the same engine mapping (404 unknown id, 400 no file, 503 without an
engine, 500 `engine-error`), and answers 404 `no-strings` with a hint when no
literal survives selection; it also reads the stored `threat` and `protocols`
scans (never re-runs them) to render the Snort and STIX artifacts.
`yarac` validation is optional, so a missing validator stores the rule
unvalidated with a note rather than failing, and its GET is stored-only like
the other scans.  The per-format GETs are stored-only: `yara` and `snort`
answer `text/plain` and `stix` answers `application/json`, 404 `no-artifact`
when the stored payload lacks that piece (a legacy payload without the Snort or
STIX sub-object), and 404 `format-not-found` for another name.  The unstrip
POST follows the triage
project-context mapping (404 unknown id, 400 `no-engine-context`, 503 without
an engine, 500 `engine-error`), stores the joined proposals, and its GET is
stored-only like the other scans; the unstrip apply POST renames through the
stored scan, answering 404 for an unknown function or no stored proposal and
400 `invalid name` for a blank name.  `GET /api/analyses/<id>/scans`
answers 404 for an unknown analysis.  The match route answers 503
`{"error": "similarity-unavailable"}` when the optional `similarity` extra is
absent, 503 `engine-unavailable` when rebrew cannot be imported, and 500
`engine-error` for an engine failure.

The lineage routes compare two binaries' functions and never require an
engine: `POST /api/binaries/<id>/lineage` reads `other_binary_id` (400
`invalid other_binary_id` when it is missing or not an integer) and an
optional boolean `refine` (400 `refine must be a boolean`), answers 404
`binary not found` for either unknown id and 400 `same binary` when both ids
name one binary, then computes and stores the comparison.  Refinement needs
the optional `similarity` extra and a usable rebrew engine; without either the
request still succeeds with `refined: false`, so the engine is an enrichment
rather than a requirement.  `GET` on the same path is stored-only: with
`?other_binary_id=N` it serves the stored comparison and answers 404
`{"error": "no-scan", ...}` with the run hint before the first run, and
without the query it lists every comparison stored for the binary.  An
unexpected failure is a sanitized 500 `internal server error`.

The related routes rank the stored binaries against one target and never make
the engine a requirement: `POST /api/binaries/<id>/related` reads an optional
integer `limit` (400 `limit must be an integer` for a non-integer, 400
`invalid limit` for a non-positive or oversized one) and an optional boolean
`include_unrelated` (400 `include_unrelated must be a boolean`), answers 404
`binary not found` for an unknown id and 500 `engine-error` for an engine
failure, then computes and stores the ranking.  Without an engine the scan
degrades to the stored fingerprints and `capabilities` scans and records a
note, so this route is 200 either way.  `GET` on the same path is stored-only
and answers 404 `no-scan` with the run hint before the first run.

The composition routes read the store alone and never make matching or the
engine a requirement: `POST /api/binaries/<id>/composition` takes no body,
builds the payload with `composition.compute_composition` (the binary's
functions, the `matches` edges and the candidate's owning binary), stores it
through `journal.journaled_scan_result` as the `composition` scan and returns
it with the `journal_action` field; an unknown id answers 404
`binary not found`.  A binary with no match rows still answers 200 with
`refined: false` and a note naming `reportal match <binary-id>`.  `GET` on the
same path is stored-only and answers 404 `no-scan` with the run hint before the
first run.

The family and detection routes cover the portal's Detect surface as local
matching against a store the analyst curates; no external threat-intelligence
feed is bundled or contacted.  `POST /api/families` reads `name` (400
`name must be a non-empty string` for a missing or blank one), a required
integer `reference_binary_id`, an optional list of strings `aliases` (400
`aliases must be a list of strings`) and optional `notes`; a name that is
already taken case-insensitively is 400 `duplicate family`, an unknown
reference binary 404 `binary not found`, a reference whose row has no file
400 `binary not on disk`, and a missing engine 503 `engine-unavailable`,
because registration derives the bundle with the engine.  `GET /api/families`
and `GET /api/families/<id>` are read-only and never resolve the engine;
`DELETE /api/families/<id>` answers 404 `family not found` for an unknown id.
`POST /api/binaries/<id>/detect` follows the same engine mapping as
registration (404 unknown binary, 400 no file, 503 without an engine, 500
`engine-error`) and stores the detection as the `detect` scan;
`GET /api/binaries/<id>/detect` is stored-only and answers 404 `no-scan` with
the run hint before the first run.

The function-triage POST is the per-function half of the triage surface and
follows the AI error contract rather than the engine one: 404 for an unknown
binary, 400 `invalid body` for a `function_ids` that is not a list of integers,
an unknown function id or a `limit` outside 1..`function_triage.MAX_LIMIT`,
and 503 `engine-unavailable` only when the LLM path needs a disassembly and no
engine is available.  A missing LLM endpoint is not an error: the run falls
back to the deterministic heuristic, records `model: ""` and a note, and still
stores the artifacts and the aggregate.  A function whose context cannot be
resolved (no stored decompilation and no engine, no rebrew project context, or
a non-positive size) is recorded in the payload's `skipped` list with a reason
instead of failing the request.  Its GET is stored-only like the other scans
and answers 404 `no-scan` with the run hint.

The AI routes follow the same error contract.  A `POST` to
`/api/functions/<id>/{summary,comments,type-suggestions}` needs the function's
stored decompilation and never runs the decompiler itself: without one it
answers 404 `no-decompilation` with the command that produces it, and without a
configured LLM endpoint it answers 503 `{"error": "llm-unavailable", "detail":
"configure REPORTAL_LLM_ENDPOINT (and REPORTAL_LLM_API_KEY) to enable AI
features"}`.  An unusable model response is 502
`{"error": "llm-error", "detail": ...}` and stores nothing.  A successful POST
returns `{"function_id", "kind", "payload", "model"}`.  Their `GET`s are
stored-only: they resolve neither the engine nor the LLM, serve the stored
artifact with its `created_at`, and answer 404
`{"error": "no-artifact", "detail": ...}` when there is none.  An unknown
function is 404 on both methods.

The secret-store routes follow the same envelope with a vocabulary of their own.
A read is redacted by construction: `GET /api/secrets` and the `PUT` response
carry the name, the scope, the team, the byte length and a last-four hint, and
never the value.  A name is a lowercase dotted path and a value is bounded at
`secret_store.MAX_VALUE_BYTES`, so an unusable one is 400 `invalid secret`; a
name at a scope with no row is 404 `secret not found`; and a caller whose role
is not enough (a workspace secret needs an admin, a team secret that team's
membership) is 403 `secret forbidden`, the same status and page as `forbidden`.

The AI decompilation artifact (`ai_decomp.py`) reuses the same error shape with
its own additions.  `POST /api/functions/<id>/ai-decompilation` needs the stored
decompilation (404 `no-decompilation`), a configured endpoint (503
`llm-unavailable`) and an usable model response (502 `llm-error`), and returns
the served artifact: the rendered `code`, the model's `rewritten_code`, the
`tokens` with their `name`, the `attributions`, the `overrides`, the `rating`
and its note, the `line_comments`, the `model`, the `created_at` and a
`derivation` string stating which parts are locally derived rather than
model-reported.  Every `GET` is stored-only and answers 404 `no-artifact` with
the `reportal ai-decompile` hint.  `PATCH .../overrides` bodies are
`{"overrides": {"<token>": "<name>"}}` with a null or blank name clearing one:
400 `invalid override` for a non-object mapping or a name that is not a C
identifier or is a keyword, 404 `unknown token` for a token the artifact does
not carry.  `PATCH .../rating` takes `{"rating": "up"|"down"|null, "note": str}`
and answers 400 `invalid rating` outside that vocabulary.  The per-line comment
routes take `{"line", "body", "author"}` on `POST` and `{"body"}` on `PATCH`,
answer 400 `invalid line-comment` for a bad line or an empty body and 404
`no-line-comment` when no comment is stored at the line.

The rename routes (`renames.py`) reuse that shape.  `POST
/api/functions/<id>/renames` needs the stored decompilation (404
`no-decompilation`), a configured endpoint (503 `llm-unavailable`) and an
usable model response (502 `llm-error`), and returns the stored envelope with
the suggestion `count`.  `GET` is stored-only and answers 404 `no-artifact`
with the `reportal suggest-renames` hint.  `POST .../renames/apply` reads
`{"applied": [...], "rename_function": bool}` (400 `invalid applied` for a
non-list or non-object element, 400 `rename_function must be a boolean`), needs
the stored decompilation (404 `no-decompilation`), answers 404 `no-artifact`
when it is told to apply everything and nothing is stored, and returns
`{"function_id", "applied", "skipped", "decompilation_updated"}`; a malformed
entry, a protected C keyword, an identifier shorter than
`renames.MIN_IDENTIFIER_LENGTH`, a no-op rename or a `from` no longer present is
skipped with a reason rather than failing the request.  `POST .../renames/revert`
restores the journaled text and answers 404 `no-artifact` when no apply is
journaled.

The pipeline routes run the component composition (`components.py`,
`pipeline.py`).  `POST /api/functions/<id>/pipeline` answers 404 for an unknown
function and 503 `{"error": "pipeline-unavailable", ...}` only when the
composition cannot be assembled; every other outcome is a step on the run
(`done`, `skipped` with a reason, or `failed` with a reason), so the request
still succeeds and returns the run with its steps and the function's durable
artifacts.  Its optional body is `{"disabled": ["component", ...]}`, which
overrides the workspace `[pipeline] disabled` list (400 `invalid disabled` for
a non-list of strings).  `GET` on the same path is stored-only and answers 404
`{"error": "no-run", ...}` before the first run.  `GET /api/pipeline/runs/<id>`
answers 404 `run not found`; `POST /api/pipeline/runs/<id>/revert` journals the
run's stored descriptors onto a context, applies them newest-first through
`Context.revert`, consumes the undo plan, and returns `{"run_id",
"function_id", "reverted": [...], "context_changes": [...], "applied": N,
"failed": N}` (404 `run not found`).  `context_changes` names the bindings the
run provided or revoked, each with an `applied` flag: a revert running in the
process that made a binding still holds the run's context and applies the
change for real, while one a later process cannot resolve reports
`applied: false` and never claims a restore; a run stored before the binding
descriptors were recorded reverts with `context_changes: []`.

The component routes read and reload the process-wide registry and touch no
store.  `GET /api/components` lists every entry with its `requires`,
`provides`, `origin`, `reloadable`, `withdrawable` and `withdraw_reason`
fields.  `POST /api/components/reload`
takes `{"name": "..."}` or `{"all": true}` (400 for neither, both, or a
non-boolean `all`), re-imports the declaring module through `importlib.reload`
and swaps the registry entry in place; an unknown name answers 404
`component not found`, an in-process registration 409 `not-reloadable`, and a
reloaded module that no longer declares the component 500 `component-missing`.
A run already in flight keeps its snapshot: the swap applies to the next
composition.  `POST /api/components/<name>/deactivate` withdraws a component
from the process-wide live host: it calls the component's `revert(ctx)` where it
declares one and revokes the names it provided, and the response carries the
`deactivated` entries plus a `journal_action` when the withdrawal recorded a
durable write (a withdrawal whose effect is a process-local binding reports
`journaled: false`).  An unknown name answers 404 `component not found`; a
component that provides nothing and declares no revert, and a component this
process already withdrew, answer 409 `not-withdrawable` with the reason in
`detail`.

The auto-mode routes decompose one binary's not-yet-matched functions and work
them with a worker.  `POST /api/binaries/<id>/auto` validates the body bounds
(400 `invalid params` for a non-integer or out-of-range value, 400 for an
unknown worker, 404 for an unknown binary), creates the run and its task tree,
and returns 202 `{"run_id", "binary_id", "status": "running"}` while a
background thread executes the batches, so an HTTP request never blocks for
minutes; the body's `worker` defaults to `offline`, `execute` to false
(dry-run), and `concurrency`/`functions_per_task`/`max_attempts`/`max_tasks` to
their named defaults.  A background failure is written as a `failed` run, so
the polling client always reaches a terminal status.  `GET
/api/binaries/<id>/auto` serves the binary's latest run with its task tree and
coverage delta and answers 404 `no-run` before the first run; `GET
/api/auto/runs/<id>` serves one run (404 `run not found`).  `POST
/api/auto/runs/<id>/revert` removes the files the run's task results recorded,
restores the function statuses it replaced, deletes its rows, and returns
`{"run_id", "status", "removed", "restored"}` (404 `run not found`).  `POST
/api/auto/runs/<id>/recover` closes a run a dead process left `running` (there
is no registry of live runs, so any `running` run is treated as stale): it marks
each unfinished batch task `failed` with reason `interrupted`, merges the files
and statuses those tasks recorded into the run's undo plan, closes the run
`failed` (nothing completed), `partial` (some batches did) or `done` (every
batch did), and returns `{"run_id", "recovered_tasks", "added_descriptors",
"status"}`; a run already closed is returned unchanged with zeroes (404 `run not
found`).

The conversation routes reuse that shape.  `POST /api/conversations` validates
`scope_kind` against `conversations.SCOPE_KINDS` (400 `invalid scope kind`) and
the scope id against the stored functions or binaries (404 `function not
found` / `binary not found`), and derives the title from the scope row when the
body carries none.  The `docs` scope names no table: it is one manual for the
whole install, so its id is carried for the conversation row and never matched,
and the first question ingests the shipped pages into the `docs` knowledge scope
(deduped by content hash, so later ones only query).  `GET`/`DELETE /api/conversations/<id>` and the message POST
answer 404 `conversation not found` for an unknown id; the message POST
answers 400 `content must be a non-empty string` for a blank body, 503
`llm-unavailable` without a configured endpoint and 502 `llm-error` when the
model call fails, and it stores the user message before the call, so a failed
call leaves the user turn and no assistant turn.  `GET /api/conversations`
answers 400 `scope_id must be an integer` for a non-integer filter.

The report site routes serve the workspace `reports/<id>` tree and answer 404
`{"error": "no-report", "detail": ...}` when that directory does not exist,
which covers an unknown binary id and a binary whose report was never
generated the same way.  `ui.py` resolves every request under its root before
it is checked, so no request can read outside the tree.

The knowledge routes validate their scope before they touch the data.
`POST /api/documents` requires `scope_kind` in `knowledge.SCOPE_KINDS` (400
`invalid scope kind`), an existing binary for a binary scope (404
`binary not found`) and a non-negative id for a project scope (400
`invalid scope id`).  A file whose suffix is not in `knowledge.TEXT_EXTENSIONS`
answers 400 `unsupported-format`, content past
`knowledge.BINARY_CONTROL_RATIO` NUL/control characters 400 `binary-content`,
content with no text 400 `empty-text`, and a body past
`knowledge.MAX_DOCUMENT_BYTES` 413 `file-too-large`; the per-scope document cap
answers 400 `too-many-documents`.  A created document answers 201 and a
repeated one 200 with `"duplicate": true`.  `GET /api/documents/<id>` omits the
stored text unless `?include_text=true` is given, and `DELETE` answers 404
`document not found` for an unknown id.  `GET /api/knowledge/search` answers
400 `limit must be an integer` / `limit must be positive` / `binary_id must be
an integer` for a bad bound and an empty result list for a blank query, and it
only calls an embeddings endpoint when one is configured.
`GET /api/binaries/<id>/knowledge` and `GET /api/functions/<id>/knowledge` are
the read-only retrieval routes: each answers `{"query", "count", "results"}`
for the binary's stored documents at `knowledge.RETRIEVAL_LIMIT`, a blank
query answering an empty list, and the function form defaults the query to the
function's name.  The AI decompilation pipeline's `retrieve-knowledge`
component (between `resolve-names` and `name-variables`, requiring only
`function`) provides `knowledge`: the binary's documents ranked against the
function's name, VA and stored summary.  It journals nothing, the provided
list is empty when the binary has no documents, and `name-variables` and
`summarize` add the rendered block to their prompts.  Retrieved text is
untrusted: it is quoted as data to reason about, never executed or spliced into
a command.

Guarded URL ingestion is off by default.  `GET /api/knowledge/config` reports
`{"allow_remote": bool}` from `remote_ingest.remote_enabled()`; while it is
false `POST /api/knowledge/fetch` answers 403 `remote-ingest-disabled` with the
fixed detail naming the environment variable and the config key.  That route
validates `scope_kind`/`scope_id` the way `POST /api/documents` does, then
fetches through `remote_ingest.ingest_url`: only `http`/`https`, a required
host, no credentials, any resolved address in the loopback, private,
link-local, multicast, unspecified, reserved or IPv4-mapped IPv6 ranges
rejected, and the port restricted to 80/443 plus the scheme default.  A blocked
or malformed target and an unsupported content type answer 400, a body past
`remote_ingest.MAX_BYTES` 413, a transport failure or a redirect past
`MAX_REDIRECTS` 502, an unknown binary scope 404, and a new document 201 (a
repeat 200 with `"duplicate": true`, deduped by the content stored under the
final URL).  A failed fetch writes nothing.

The graph routes read and write the derived graph; neither runs an engine.
`POST /api/binaries/<id>/graph` rebuilds it from the stored rows and answers the
counts, where `truncated` is true when `MAX_GRAPH_NODES` or `MAX_GRAPH_EDGES`
stopped the build (404 for an unknown binary).  `GET
/api/binaries/<id>/graph` serves the stored payload and answers 404 `no-graph`
with the POST hint before the first build; `?kind=` outside
`graph.GRAPH_NODE_KINDS` is 400 `invalid kind`, `?include_documents=` is parsed
as a boolean (400 otherwise), and document nodes are left out by default so the
graph stays small.  `GET /api/graph/nodes/<node_id>` answers 404
`node not found` for an unknown id and takes no binary context, because a node
id embeds its binary.

The graph-backend routes read the backend registry and hand the stored graph to
one backend; none runs an engine.  `GET /api/graph/backends` lists every
registered backend with `name`, `available`, `description`, `unavailable_reason`
(empty while available) and `supports_query`, plus the configured `default`
(`REPORTAL_GRAPH_BACKEND` or `[knowledge] graph_backend`, else `sqlite`).
`POST /api/binaries/<id>/graph/sync` takes an optional body
`{"backend": "..."}` (400 `invalid body` for a non-string; the configured
backend runs when the body or the field is absent) and pushes the binary's
stored graph, answering the backend's report; an unknown backend is 404
`backend not found`, a binary without a stored graph 404 `no-graph`, and a
registered backend that is not installed 503 `backend-unavailable` with its
install hint (`install the optional extra: uv sync --extra cognee`).  The
built-in `sqlite` backend's `sync` writes nothing and reports the stored node
and edge counts; the optional `cognee` backend translates the payload (one node
per graph node with its kind, key and label, one edge per relation) and pushes
it into a Cognee dataset named by `REPORTAL_COGNEE_DATASET` or
`[knowledge] cognee_dataset` (default `reportal`).  `GET /api/graph/query?q=&backend=`
answers an exact node id, else a label/key/id substring search across every
binary, capped at `graph_backends.DEFAULT_QUERY_LIMIT`; 404 unknown backend,
503 `backend-unavailable`, 400 `query-unsupported` for a backend without query
support, and a blank `q` answers an empty result.

# Parity with portal.reveng.ai

What the hosted RevEng.AI portal offers, what reportal does today, and which
local engine backs each capability.

The `rebrew` engine is the sibling package, a base dependency called in process
(`engines.py`); the command names in the notes name the engine operation behind
a capability, not a CLI invocation.

Status vocabulary:

- **Implemented**: usable end to end through the API or CLI.
- **Scaffolded**: storage and/or endpoints exist, but the capability is
  incomplete or has no engine behind it yet.
- **Planned**: not built yet; a local implementation is specified and tracked in the
  gap inventory below.
- **Not-applicable**: no local implementation is meaningful, because the capability
  is a hosted service with no offline equivalent.

| Capability | Status | Backing engine | Notes |
|------------|--------|----------------|-------|
| Upload / analysis lifecycle | Implemented | local + rebrew | `POST /api/binaries` accepts a `multipart/form-data` upload (`file` part, optional `name` field), streams it to `<workspace>/binaries/` while computing sha256, and publishes it as `<sha256><suffix>` (the client filename contributes only a suffix matching `^\.[A-Za-z0-9]{1,8}$`, never a path component). Dedupe is by sha256: a repeat upload returns the existing row with `"duplicate": true`. Uploads are capped at `MAX_UPLOAD_BYTES` (256 MiB), answered 413 `file-too-large`; a missing `file` part is 400 `no-file`, an empty one 400 `empty-file`. Repeating the `file` part (or adding a JSON `files` field, entry *i* describing part *i* with a `name`, `tags`, `collection_ids` and an explicit `format`/`arch`) makes the same route a batch: each part is streamed in order, an entry that fails answers the single-file code inside its own `error` object while the others still register, a duplicate is reported as `"duplicate": true` rather than as a failure, the body carries `{"files", "count", "duplicates", "errors"}` and the whole request is one journal action (a batch past `MAX_UPLOAD_FILES`, 64, is 400 `too-many-files`). Tags go through the existing `create_tag`/`add_binary_tag` helpers and the collection links through `add_collection_binary`, all inside that one action, so a revert takes back every binary, tag and link the request made. The hosted portal's Platform, ISA and File Format pickers map to reportal's stored `format`/`arch` (the explicit hint, else the suffix-derived value); a compiler hint, Visibility and the debug-symbol upload have no local column and are not stored. The SPA Binaries view carries the browser batch upload control: a multiple file input, a collection picker and one options row per file (name, tag chips, Format and ISA), with each result reported per file and a duplicate named as such. `reportal add-binary <path>` and `import-rebrew` remain the CLI paths, and `POST /api/analyses` plus the `binaries`/`analyses` tables back the lifecycle. The status is a real lifecycle: `store.ANALYSIS_STATUSES` (`pending`, `processing`, `done`, `failed`, `cancelled`, mapping onto the hosted portal's Queued, Processing, Complete and Error) is the source of truth, `store.set_scan` marks an analysis `done` when a scan is stored, `store.scan_span` logs a scan's start and marks the analysis `failed` with an error entry when the work raises, and every status change appends an entry. The log the hosted portal shows per row is `GET /api/analyses/<id>/logs` (newest first, bounded, with the log's true total, severity per entry) over the `analysis_log_entries` table, written only through `analysis_log.append_entry`; `reportal analysis-logs <id>` reads the same log. `GET /api/analyses` takes the filters the list view needs (`status`, `search`, `order`, `limit`, plus `binary_id` for one binary's analyses, which the binary detail's analyses panel, `reportal analyses --binary` and the `list_analyses` MCP tool's `binary_id` all read), `DELETE /api/analyses/<id>` removes one analysis with its dependent rows and is journaled (refused 409 `last-analysis` for a binary's only analysis while it holds functions), and the SPA Analyses view (`#/analyses`) renders the table, filters, the on-demand log drawer and the per-row delete. The rest of the hosted lifecycle is in the cluster D inventory below: reading one analysis, its status, its recorded parameters, its function map, its import stubs with their callers, its raw bytes and its tags, a relabel, a log append and a requeue. A requeue moves the lifecycle row back to `pending` and logs the transition rather than replaying the engine calls: the stored scans record results, not the inputs they ran with, so a re-run is not reconstructable from the store. |
| Binary metadata + hashes | Implemented | rebrew | sha256 (streamed at import or `add-binary`), size, path. md5, sha1, sha256, sha512, the four SHA-3 digests (`sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`), crc32, format, arch, imphash, the export hash and section entropies come from `rebrew fingerprints` through `GET`/`POST /api/binaries/<id>/fingerprint` and `reportal enrich` (the export hash is SHA-256 over the sorted, lowercased `<ordinal>:<name>` export lines, or over the empty string when the image has no exports). The `format`/`arch` columns set at registration come from the file suffix and stay best effort; the stored fingerprint carries the header-derived values. The binary detail view renders the digest set as copyable mono rows, with Compute/Recompute. PE details are the second half: `reportal pe-info <binary-id>` and `GET`/`POST /api/binaries/<id>/pe-info` run `rebrew pe-info <binary> --json` (standalone, no project context) and store the identity (format, arch, bits, PE type, image base, entry point, subsystem, timestamp, checksum, size, resource count), the export table (name, absolute VA, ordinal, forwarder target; a forwarded export keeps its record), the section table with each section's entropy, full `IMAGE_SCN_*` characteristic names and read/write/execute flags, the security flags with their summary and raw `dll_characteristics`, the 11-item mitigation checklist (`aslr`, `dep`, `cfg`, `driver_model`, `app_container`, `terminal_server_aware`, `image_isolation`, `code_integrity`, `high_entropy`, `seh`, `bound_image`) with its `security_score` (`enabled` over the fixed total 11), the Authenticode state, the debug directory entries, the Rich header, and the presence/counts blocks; an item whose source value is unavailable reports unknown (`null`), never a false the file did not state. the POST stores and the GET is stored-only (404 `no-scan`), and the binary detail view is the portal's detail surface: a Binary details card (identity, import and export hashes, debug/Rich-header summary), a Hashes card, a Security mitigations card (`N/11` plus the checklist), an Imports card, an Exports card, a Sections card (entropy meter and full `IMAGE_SCN_*` list), a Code signature card, a Packer detection card, an Unpacked files card and a Strings card, each row list carrying a client-side filter with its filtered-of-total count. A binary whose format carries no PE metadata answers identity plus a note. File-type, packer and protector detection is bundled: `reportal filetype <binary-id>` and `GET`/`POST /api/binaries/<id>/filetype` match the same evidence (the PE sections, the entry point's own bytes, the section entropies, the imports and the strings) against the curated `SIGNATURES` table in `src/reportal/filetypes.py` (`packer`, `protector`, `installer`, `runtime` and `toolchain` categories: UPX, ASPack, MPRESS, PECompact, NsPack, Petite, tElock, FSG, PKLITE, LZEXE, BoxedApp, Paranoiac-RAT-family, NeTiS-Gafgyt-family, Themida/WinLicense, VMProtect, Enigma, Obsidium, Armadillo, NSIS, Inno Setup, InstallShield, .NET, Visual Basic, Delphi, Go, Rust, Swift, MSVC and MinGW GCC, plus a high-entropy-executable heuristic), deterministically and with no new dependency, no network call and no execution of the sample. Confidence is derived from the matched signal kinds: two independent kinds are `high`, a single section name, import or entry-point prefix is `medium`, and a lone string marker, byte constant or entropy heuristic is `low`. The POST stores the `filetype` scan, the GET is stored-only (404 `no-scan`) and never runs the engine, a missing evidence piece is recorded as a note instead of failing the run, and the binary detail view folds the detection into the Packer detection card (verdict, peak-section-entropy meter with the packed range marked, section count, compiler string and the match table). The table is a curated subset, not the full DIE database, and a missing signature is not proof a binary is unpacked. |
| Binary download | Implemented | local store | `GET /api/binaries/<id>/download` streams a stored binary back as an attachment, reading it in 1 MiB chunks rather than whole (an upload may be up to the API's 256 MiB cap), so a large binary is never held in memory whole. The filename comes from the sanitized stored name (one path component, everything outside `[A-Za-z0-9._-]` an underscore, the content-addressed file name as a fallback) and never from the request; `Content-Length` is the file's own byte count, the content type comes from its suffix (a PE suffix gets the portable-executable type, everything else `application/octet-stream`), and `Cache-Control` marks the answer immutable because the bytes are content-addressed. An unknown id is 404 `binary not found`; a row whose file is gone is 404 `binary not on disk` naming the path (the engine routes answer 400 for that condition, but a download is of a representation that is gone). `reportal download <binary-id> [--output PATH] [--force]` writes the same bytes to an explicit path in bounded chunks, and the Binaries view carries a per-row Download link. The hosted portal's per-row download is the comparison; this is a local file write with no upload or storage backend. |
| Strings / imports | Implemented | rebrew | `GET /api/binaries/<id>/imports` is a live pass-through of `rebrew imports`; `GET /api/binaries/<id>/strings` runs `rebrew strings`, normalizes each entry to `{va, section, kind, size, text}` and sorts server-side by `sort=value\|length` and `order=asc\|desc` (`reportal strings <binary-id> [--sort value\|length] [--order asc\|desc]`), ties broken on the text then the address. The binary detail view loads both on demand (strings capped at 500 shown, with the true total), carries the sort controls and links a string's VA and text to the Functions view filtered to the functions that reference that address (`?refers_to=<hex>`), which resolves the address's cross-references through the same `rebrew xrefs` call the xrefs route makes. |
| Function explorer | Implemented | rebrew coverage DB + imports | `GET /api/binaries/<id>/functions` plus the SPA Functions view, populated by `import-rebrew` from `db/coverage.db` and, for a target binary on disk, from the engine's import stubs (`rebrew imports`) as `THUNK` rows at their VAs with `name_source` `import` and the 6-byte `jmp dword ptr [iat]` size. A coverage-db row always wins over a stub at the same VA (a stub is added only where no row exists), and the stub step is best effort, so an import succeeds without an engine. Each row links to the function detail view. The listing is filtered and sorted server-side, the way the hosted explorer's sortable columns and filter panel are: `name_source` (one of the five labels `composition.name_source_label` derives, so a placeholder name is `No Debug Info` whatever source it carries), `capability` (one of `capabilities.CAPABILITIES`, matched when the function's own name is an import name that rule table classifies, i.e. an import stub or a function still named after the API it wraps), `min_size`/`max_size` (inclusive byte bounds), `string` (a literal the function's stored decompilation carries; live xrefs are not stored, so a function with no stored decompilation never matches), `match` (`matched` when the stored `matches` table names the function as a match source, `unmatched` otherwise), `sort` (`va`, `size`, `name`, `status`) and `order` (`asc`, `desc`). Every parameter has a documented refusal (400 with the repo's `{"error", "detail"}` vocabulary) for an unknown value, ties break on the function id so a listing is deterministic, and the payload states `count` (returned) and `total` (the binary's whole function set) so a filter is distinguishable from a small binary. The SPA keeps the filter and sort state in the URL hash, so a filtered list is shareable and survives a reload. |
| Disassembly | Implemented | rebrew | `GET /api/functions/<id>/disasm?format=nasm` (or `hex`) runs `rebrew asm <hex-va> --size N --format ...` with the working directory set to the rebrew project `import-rebrew` stored for that binary (`rebrew_contexts`). A binary without that context answers 400 `no-engine-context`; the `rebrew asm` contract requires the project's `rebrew-project.toml`, so an `add-binary` row alone cannot be disassembled. The function detail view renders the listing with a nasm/hex toggle. |
| Control-flow graph | Implemented | rebrew | `GET /api/functions/<id>/cfg` runs `rebrew asm <hex-va> --size N --format cfg --json` in the same stored project context and returns the function's basic blocks and the edges between them, with every address converted to an int so the SPA never parses hex. This is the derived view the disassembly cache does not cover: the graph is computed on every request and stores nothing. The payload states the engine's `block_count` (returned), `block_total` (the true count), `block_cap` (the engine's per-function block cap) and `truncated`, and carries the engine's `note` when it resolved no extent; an empty block list always carries a reason. A positive stored size is passed as `--size` (the same extent the listing covers); a size the store does not carry is omitted so the engine resolves the extent itself and reports the failure instead of a guessed window. A non-x86 target and a missing engine answer 500 `engine-error` and 503 `engine-unavailable` like the other engine routes. The function detail view's code panel toggles between Disassembly and Control flow: the graph renders each block with its address, byte size, instruction count and first/last instruction text, and each block's outgoing edges as jump controls, with a back edge labelled and marked. |
| Decompilation view | Implemented | rebrew | `reportal decompile <function-id> [--backend kuna] [--named]` and `GET`/`POST /api/functions/<id>/decompilation` run `rebrew decompile <hex-va> --decompiler kuna\|r2ghidra\|r2dec\|ghidra\|auto [--named] --json` in the rebrew project context `import-rebrew` stored for the binary, and keep the C source in the `decompilations` table. `GET` serves the stored row and otherwise computes live without storing; `POST` computes and stores. This is rebrew's local decompiler backends, not an AI model. The function detail view loads the stored source (or computes live), offers the backend select, and stores on Decompile. |
| AI decompilation summary / comments / type suggestions | Implemented (optional) | external LLM (OpenAI-compatible) + rebrew | `reportal summary\|ai-comments\|suggest-types <function-id>` and `POST /api/functions/<id>/summary\|ai-comments\|type-suggestions` feed a function's **stored** decompilation to an OpenAI-compatible chat-completions endpoint and store the parsed artifact in `ai_artifacts` (one row per function and kind). `GET` on the same routes is stored-only and answers 404 `no-artifact`; it never calls the model. The inline-comments artifact keeps the stored kind `comments` and is served at `/ai-comments`, since the analyst comment routes own `/comments`. The bridge is off unless an endpoint is configured (`REPORTAL_LLM_ENDPOINT`/`REPORTAL_LLM_API_KEY`/`REPORTAL_LLM_MODEL`, then the workspace `reportal.toml` `[llm]` table); without one every AI route answers 503 `llm-unavailable` and every AI command exits non-zero, and the default install and test suite need no endpoint. This uses whatever model the endpoint serves; it is not the hosted portal's models. The function detail view carries the AI section (Summary, AI comments, Type suggestions panels). |
| AI identifier renaming (Agents/Reverse) | Implemented (optional) | external LLM (OpenAI-compatible) + local store | `reportal suggest-renames <function-id>` and `POST /api/functions/<id>/renames` ask the configured endpoint for clearer names for the unclear identifiers of a function's **stored** decompilation and keep them as an `ai_artifacts` row of kind `renames` (one `{"from", "to", "kind", "reason", "confidence"}` per suggestion, `kind` one of variable/parameter/function/global); entries that are not `from`/`to` pairs or whose `from` does not occur verbatim in the source are dropped, and duplicates by `from` keep the first. `GET` is stored-only (404 `no-artifact`). `reportal apply-renames <function-id> [--all\|--from NAME --to NAME] [--rename-function]` and `POST /api/functions/<id>/renames/apply` rewrite whole-token occurrences outside string literals, refuse C keywords and identifiers shorter than `renames.MIN_IDENTIFIER_LENGTH`, journal the previous text as kind `renames-applied`, and `reportal revert-renames <function-id>` / `POST /api/functions/<id>/renames/revert` restore exactly that text and drop the journal. A `function`-kind suggestion renames the function row too when `rename_function` is set, recorded in `name_history` with source `renames`; otherwise the row is left untouched. The function detail AI section renders a Renames panel with a checkbox per suggestion, the reason and confidence, Apply selected / Apply all and Revert, and an apply refreshes the decompilation view. Function naming from library identification and recorded matches is the separate auto-unstrip / apply-match path below. The model is whatever the configured endpoint serves; without one the suggest routes answer 503 `llm-unavailable` and an apply, which is deterministic text work, still runs. |
| AI decompilation pipeline | Implemented (optional LLM) | local store + rebrew + external LLM (OpenAI-compatible) | `reportal pipeline <function-id>` and `POST /api/functions/<id>/pipeline` run the steps the hosted portal reports (preparing decompilation, reading the function trace, decompiling, searching for functionality, resolving names, naming variables and types, storing results) as a component composition (`src/reportal/components.py`, `src/reportal/pipeline.py`). Each component declares the context values it requires and provides; the loader activates only those whose requirements hold and records why the rest were skipped, and every persistent write is journaled with its inverse. The run is stored in `pipeline_runs`/`pipeline_steps` with per-step status, reason and duration; `GET /api/functions/<id>/pipeline` serves the latest run with the function's durable artifacts (404 `no-run` before the first run), `GET /api/pipeline/runs/<id>` serves one run, and `reportal pipeline-revert <run-id>` / `POST /api/pipeline/runs/<id>/revert` undoes exactly what the run wrote. Disassembly, decompilation, matches and the predicted name come from stored rows and the rebrew engine (`rebrew asm`, `rebrew decompile`, the recorded `matches`, stored unstrip proposals); the summary, inline comments and type suggestions come from the optional configured endpoint, and those steps are skipped with reason `llm-unavailable` without one. Nothing here is the hosted portal's models or its decompilation service. The function detail view renders the step timeline, the predicted name with an Apply-rename action, the summary, the inline comments merged into the decompilation and a Revert run control. Components are hot-swappable at the registry level: `reportal components` and `GET /api/components` list the registry, `reportal components-reload <name>` / `--all` / `POST /api/components/reload` / the SPA Components view re-import a component's declaring module and swap the live entry, and `pipeline.ComponentHost` drives deactivate, reload and reactivate against one context; a run already in flight keeps its snapshot and an in-process registration is not reloadable. |
| Auto-mode | Implemented (dry-run by default) | local store + rebrew + optional workers (LLM) | `reportal auto <binary-id>` and `POST /api/binaries/<id>/auto` decompose a binary's not-yet-matched functions into a task tree and work it: the root task owns one `batch` task per group of `functions_per_task` functions, batches run on bounded daemon worker threads (`concurrency`, a named floor and ceiling), and each batch's results are aggregated bottom-up into the root's coverage delta (`matched`/`improved`/`failed`/`skipped`, `coverage_before` to `coverage_after`). The orchestration shape is modeled on the sibling `spydr` project (one root task, top-down decomposition, bottom-up aggregation, bounded fan-out, per-attempt timeout, retries). What replaces spydr's reviewer/aggregator agents is an objective acceptance rule: a function is accepted only when its worker carries a verified matching status from the engine, so an unverified `matched` claim is downgraded to `improved` or `failed`. Workers are plugins (`src/reportal/auto_workers.py`, the `reportal.auto_workers` entry-point group); the built-in `offline` worker is deterministic with no LLM and no engine and the `llm_c_source` worker asks the configured OpenAI-compatible bridge for an MSVC6/C89 source file in rebrew's annotation format and verifies it with `rebrew test --json`. The default is a dry run: no source file is written into the rebrew project, nothing is compiled and no function status changes; `--execute` (or `"execute": true`) writes the candidate into the project's reversed source directory and compiles it, never overwriting an existing file, and records every file it wrote plus every status it replaced so `reportal auto-revert <run-id>` / `POST /api/auto/runs/<id>/revert` puts both back. Before each write an executing run persists a pending intent on the task describing the inverse (the file a worker may write, the status a batch is about to promote) and marks it applied once the write returned, then each completed batch folds its descriptors into the run's undo plan in the same commit as its result, so a hard kill loses at most the write it was in the middle of, and that write is described by its intent; `reportal auto-recover <run-id>` / `POST /api/auto/runs/<id>/recover` closes a run a dead process left `running`, marking its unfinished tasks `interrupted`, merging what they recorded plus the intents they reserved, and listing a still-pending intent in `uncertain_intents` because it may or may not have been applied, before closing the run `failed`/`partial`/`done`. Runs, tasks and attempts are rows in `auto_runs`/`auto_tasks`/`auto_attempts`, written as they happen, so `GET /api/binaries/<id>/auto` (404 `no-run`) and `GET /api/auto/runs/<id>` show a live task tree, and the SPA Auto-mode view renders the tree with per-task status, worker and attempts plus the coverage delta, the start form and the revert control. This is not the hosted portal's hosted implementation: there is no hosted worker, no LLM review gate and no cloud queue. |
| Function matching / similarity | Implemented | rebrew + resembl | `reportal match <binary-id>` and `POST /api/binaries/<id>/match` rank each function of a binary against the candidate corpus under the Match Settings the hosted sheet exposes: `min_similarity` (80.0), `min_confidence` (0.0, the softmax floor, applied after the softmax so it drops candidates without re-ranking the ones it keeps), `include_self` (true, whether the binary's own functions may be candidates), `top` (10), `platforms` (`windows`/`linux`/`android`), `architectures` (`x86_64`/`x86_32`/`arm64`), `binary_ids` and `collection_ids`. Every setting has a default that reproduces the unscoped run, a validated bound or a closed vocabulary, and a 400 with the repo's error vocabulary for a value outside it (an unknown binary or collection id included). The platform/architecture scope is best-effort: it compares a binary's stored fingerprint when one exists, else its suffix-derived `format`/`arch` columns, so it is a coarse filter and not a guarantee, and Android shares Linux's ELF tokens; the response states both caveats in `notes`. The run stores its settings on every row it records, so `GET /api/binaries/<id>/matches` reports them back (null for rows written outside a run) beside the candidate edges, and `GET /api/functions/<id>/matches` serves one function's edges. Both GETs are stored-only and add the derived metric fields: `difference` is the complement `100 - similarity` (never a stored value) and `band` is the quality band the similarity falls into. `reportal match` takes the same settings as `--min-similarity`, `--min-confidence`, `--top`, `--self`/`--no-self`, `--platform`, `--arch`, `--binary` and `--collection`. Scoring is local structural similarity: rebrew disassembly (`rebrew asm`) tokenized and MinHash-compared by resembl's scoring core, blended with a text ratio, then a softmax confidence over the kept candidates. This is not RevEng.AI's neural embedding model; it is the closest local equivalent. Requires the optional `similarity` extra. The SPA's `#/matches` view is the Match / Diff surface: it loads a function's binary, shows the recorded edges ranked by a Similarity / Confidence / Difference toggle with a stacked quality bar over the five bands, carries the Match Settings sheet with a removable filter chip per active setting, and adds a per-row transfer-mode selector and a Bulk Transfer dialog. |
| Match / Diff view | Implemented | local + rebrew | `reportal diff <function-id> <candidate-function-id> [--kind disasm\|decomp] [--no-normalize]` and `GET /api/functions/<id>/diff/<candidate_id>?kind=&normalize=` align the two functions' listings side by side with the changed lines marked: a `disasm` side comes from `rebrew asm` (cache-backed) and a `decomp` side from the stored decompilation, else a live `rebrew decompile` that is not stored. The response carries both sides, the aligned entries (1-based line numbers, null where a side has no line), the per-operation summary counts and the recorded match similarity (a live structural score when the optional `similarity` extra is present, else null). An explicit candidate must be a recorded match for the source function (400 `no-such-match`, like apply-match); the omitted-candidate form aligns against the function's best recorded match (404 `no-match` when there is none). `strip_addresses` normalization removes a listing's address, bytes and trailing comment before comparing. The `reportal diff` command and the `diff_functions` MCP tool take an explicit pair and do not require a recorded match, so their similarity falls back to a live structural score (null without the extra). The function detail Matches panel and the `#/matches` view each carry a per-row Compare action to `#/diff/<function-id>/<candidate-id>`, which renders the two listings side by side with delete/insert styling, a kind toggle, a normalize toggle, the similarity and the summary counts. This is a local line-level alignment (`difflib`), not the hosted portal's pairing service. |
| Lineage | Implemented | local + rebrew + resembl (optional) | `reportal lineage <left-binary-id> <right-binary-id> [--no-refine] [--json]` and `POST /api/binaries/<id>/lineage` (body `{"other_binary_id": N, "refine": true}`) compare two binaries' stored function lists pairwise and classify every function as `unchanged`, `changed`, `added` or `removed`. Pass 1 pairs exact, case-sensitive names, preferring the candidate whose size is closest: the same size is `unchanged`, a different size `changed`. Pass 2 pairs the unnamed/placeholder names (`sub_*`, `fcn_*`, `FUNC_*`, empty) inside a size bucket (`SIZE_TOLERANCE_PERCENT`, 10% of the larger size) with the structural similarity the optional `similarity` extra scores over the cached rebrew disassembly (`UNCHANGED_THRESHOLD` 95, `CHANGED_THRESHOLD` 70), scoring at most `MAX_CANDIDATES` (20) nearest-size candidates per left function. Without the extra, or with `refine: false`, only the name/size pass runs and the payload records `refined: false` instead of failing. Ambiguity resolves by best score, then size closeness, then VA. The payload carries the exact status counts plus `matched_percent` (the paired share of both sides' functions) and rows sorted by status then left VA, capped at `MAX_ROWS` (500) while the counts stay exact. `GET /api/binaries/<id>/lineage?other_binary_id=N` serves the stored comparison (404 `no-scan` before the first run) and the same route without the query lists every comparison stored for that binary; one entry is kept per pair, keyed by the right binary id in the left binary's `lineage` scan, so a re-run refreshes that pair. The binary detail view carries a Lineage panel (compare-with select, Compare, the counts and per-status tables with function links), and `get_lineage`/`run_lineage` expose the same over MCP. This is a deterministic local comparison; the hosted portal's "investigate differences between versions" surface is agent-based. |
| Related binaries | Implemented | local + rebrew | `reportal related <binary-id> [--limit N] [--all] [--json]` and `POST /api/binaries/<id>/related` (body optional `{"limit": N, "include_unrelated": bool}`) rank every other stored binary against the target by the data reportal already holds: same `sha256` is `identical` (`high`), same `imphash` `same-imports` (`high`), same `rich_header_hash` `same-toolchain` (`medium`), an import-name Jaccard ratio at or above `IMPORT_OVERLAP_THRESHOLD` (0.8) `similar-lifecycle` (`medium`), a capability-set Jaccard ratio at or above `CAPABILITY_OVERLAP_THRESHOLD` (0.8) `similar-capabilities` (`low`), and, only when nothing stronger matched, the same format/arch with a size within `SIZE_TOLERANCE_PERCENT` (10%) `similar-size` (`low`). A candidate that matches nothing is `unrelated` and is dropped unless `include_unrelated` (or `--all`) is set. The target bundle comes from the stored fingerprint when one exists, else the engine; imports and strings come from the engine when it is available and from the stored fingerprint and `capabilities` scan otherwise, so a missing engine degrades with a note instead of failing. Rows sort by classification rank, then similarity, then name and cap at `limit` (`DEFAULT_LIMIT` 20), the payload reports the exact `candidates_considered` and records the note for each binary skipped for having no file on disk, and the result is stored as the `related` scan; `GET /api/binaries/<id>/related` serves it stored-only (404 `no-scan`) and never touches the engine. The binary detail view carries a Related binaries panel and `get_related_binaries`/`run_related_binaries` expose the same over MCP. This is a deterministic local ranking; the hosted portal compares a binary against its own corpus. |
| Composition analysis | Implemented | local store (`matches`) | `reportal composition <binary-id> [--json]`, `POST`/`GET /api/binaries/<id>/composition` and `get_composition`/`run_composition` over MCP read the binary's stored functions and the `matches` table only (no engine and no matching run) and report the portal's binary-detail block: the `Matched: N / M (P%)` headline, the five function-name-source buckets (`System`, `Auto Unstrip`, `AI Agent`, `User`, `No Debug Info`) mapped onto reportal's stored `name_source` vocabulary, the five match-quality bands (`Strong Match`, `Match`, `Partial Match`, `Weak Match`, `No Match`), one row per other binary this binary's functions matched to (name, sha256, count and percent of this binary's total functions, sorted by count descending then binary id) and one row per function with its best match's similarity and the matched binary's name, or an explicit `No match`. The band cutoffs (`STRONG_MATCH_MIN_SIMILARITY` 95.0, `MATCH_MIN_SIMILARITY` 80.0, `PARTIAL_MATCH_MIN_SIMILARITY` 70.0) are reportal's own named constants, aligned with `lineage.UNCHANGED_THRESHOLD`, `matching.DEFAULT_MIN_SIMILARITY` and `lineage.CHANGED_THRESHOLD`; the hosted portal does not publish its cutoffs, so they are not a documented RevEng.AI spec. `No Match` is exactly the absence of a stored match row, never a similarity of zero. A store with no match rows still succeeds with `refined: false` and a note naming `reportal match <binary-id>` (or the Match button); a stored match whose candidate belongs to the same binary is not a composition and is reported in the notes. |
| Rename + history / revert | Implemented | local | Rename, history and revert are end to end (`POST /api/functions/<id>/rename`, `GET .../history`, `POST .../history/<history_id>/revert`, `reportal revert`, the functions-list Rename action, and the function detail History panel's Revert). `apply-match` (`POST /api/functions/<id>/apply-match`, `reportal apply-match [--mode name\|signature\|both]`) transfers a recorded match candidate onto a function, recorded with source `match`: `name` (the default, today's rename behaviour, keeping the rename journal and history), `signature` (copy the candidate's return type, calling convention and parameters; the types those parameters name are resolved by the existing type model, and a referenced local type the target's binary has no data-type row for is reported in `missing_types` rather than dropped) or `both` (journals both writes, so one revert puts both back). Collision policy: the target's return type, calling convention and parameters are replaced, but a target that already carries a different non-empty calling convention is refused with 409 `signature-conflict`, so an ABI-level mismatch is never overwritten silently. The bulk path `POST /api/binaries/<id>/matches/transfer` applies a list of `(function, candidate, mode)` rows, each function belonging to that binary, as one journaled action with a per-row `applied`/`skipped`/`failed` report; one row's failure never loses the rows that succeeded, `dry_run` previews without writing, and the whole action reverts as one journal entry. The MCP `apply_match` tool takes the same `mode`. |
| Auto-unstrip | Implemented | rebrew | `reportal unstrip <binary-id> [--min-confidence F]` and `POST /api/binaries/<binary-id>/unstrip` run `rebrew identify-library --dry-run --json` in the binary's rebrew project context, join the candidates to the stored functions by VA, and store the proposals as the `unstrip` scan; nothing is renamed. `reportal unstrip-apply <function-id> [--name TEXT]` and `POST /api/binaries/<binary-id>/unstrip/apply` apply one stored proposal through the rename path with source `unstrip`, recording history. Identification is rebrew's FLIRT, CRT and IAT import matching; the dry run writes nothing back into the project, a user-authored name is never proposed for overwrite, and the binary detail Auto-unstrip panel renders the proposals with a per-row Apply and an Apply all control. A candidate whose VA is not among the stored functions becomes no proposal. `import-rebrew` ingests the engine's IAT import stubs as already-named `THUNK` rows, so those candidates now join a function and are dropped as already carrying the proposed name: on the bundled notepad-rebrew project, whose import names are known, the run reports candidates with zero proposals, which is correct. |
| Data types / signatures | Implemented (structs, unions, enums, aliases, pointers, arrays and function types; namespaces; reverse indices; editable model with its kind, namespace, declared size, member shape/position, explicit gaps, bitfields and enum values; size-vs-members check; mutation history and revert; header export; editable function signatures) | rebrew + local | Struct recovery and manual type editing are end to end. `reportal structs <binary-id> [--decompiler kuna] [--limit N]` and `POST /api/binaries/<id>/structs` run `rebrew recover-structs --json --decompiler NAME [--limit N]` in the binary's rebrew project context and store the engine result as the `structs` scan; `GET` serves the stored result and answers 404 `no-scan` when none exists. Over that scan sits a local, editable type model (`src/reportal/data_types.py`, the `data_types` table, one row per binary and name): `POST /api/binaries/<id>/data-types/import` (`reportal types-import <binary-id>`) parses each recovered `definition` (a tagged `typedef struct`/`union`/`enum`, a function type, or a plain typedef) into the declaration shape it names: `struct` and `union` members with running offsets (a union's members all sit at offset 0, its size the widest member), an `enum`'s named values with their integer values, a `typedef`/`pointer`/`array`/`function` type's target (and element count for an array), and a function type's parameters. A bitfield is a member property (`bits`), not a type of its own. Sizes are derived from the primitives (`char` 1, `short` 2, `int`/`unsigned int`/`float` 4, `double` 8, a pointer 4, an array multiplied by its count, an enum 4); an unknown type is size 0 with a note instead of failing, and a definition that does not match a shape is skipped with a reason. A row written before the `kind` column existed was imported from the structs scan and reads as `struct`. `GET /api/binaries/<id>/data-types` (`reportal types <binary-id>`) serves the model with each type's size, kind and namespace, a padded `as_c` declaration (a struct's gaps as `/* +0xN padding */` comments, a union's overlap stated) and a namespace tree; it takes optional `kind` (400 `invalid kind` for a value outside `data_types.KINDS`), `namespace` (a path or any descendant, `Binary` for the program-defined types, an unknown path an empty list rather than an error) and `search` (a substring of the name, a member name or an enum value name), and reports `count` of `total`. `GET /api/data-types/<id>/references` is the two reverse indices: `referenced_by` (each type that names it as a member, a typedef target, a pointee, an array element, a function parameter or a return type) and `used_by_functions` (each function whose stored signature names it), both matched by name with the payload's `note` saying so; `PATCH /api/data-types/<id>` sets a type's name, kind, namespace or declared size (the platform editor's own fields, applied in one write and one history entry; an unknown kind is 400 `invalid kind` listing the known ones) or renames/retypes one member, `POST`/`DELETE /api/data-types/<id>/members[/<member>]` add and remove members, `POST .../members/<member>/gap` converts a member to explicit padding (`char gap_XXXX[N]`, named after its offset, the recovered struct convention) and `POST .../members/<member>/ungap` turns one back into a named, typed member (`reportal type-kind`, `type-namespace`, `type-size`, `type-member`, `type-member-add`, `type-member-gap`, `type-member-ungap`), and `DELETE /api/data-types/<id>` deletes one. A member write carries the full shape the model stores (`name`, `type`, `pointer`, `count`, `bits`) and a position (`index` is where it goes and `after` names the member it follows, refused together rather than silently ordered), so a member is inserted at a position and not only appended; a retype leaves a hand-set bit width alone, and only an explicit null clears it. `POST`/`PATCH`/`DELETE /api/data-types/<id>/values[/<value>]` (`reportal type-value-add`, `type-value-edit`, `type-value-remove`) add, rename/revalue and remove an enum constant: a value is an integer or a decimal/`0x` literal, both echo back, an omitted value continues from the last constant and the payload's `note` says which number it derived, and a duplicate name or value is refused naming the constant it collides with. Every type payload carries a `size_check` (the declared size, the members' extent, and a warning naming both numbers when they disagree) which the panel renders and which rewrites neither number. Every edit recomputes offsets and the total size and rejects a bad identifier or a duplicate member; removing the last member is refused so the declaration stays non-empty, and a member edit on a kind without a member list (an enum, a typedef) is refused. Padding is rendered one way: an explicit gap member is emitted as its own declaration and the `/* +0xN padding */` comment marks only the bytes no member covers, so a member is never dropped from the header; a struct without explicit gaps renders exactly what it always did. Every mutation records the state it replaced and the state it wrote in a `data_type_history` table: `GET /api/data-types/<id>/history` (`reportal types-history <type-id>`) lists the versions newest first with each one's per-field diff (name, kind, namespace, size, members, enum values, target, element count), and `POST /api/data-types/<id>/history/<history_id>/revert` (`reportal types-revert <type-id> <history-id>`) restores one recorded version, journaling the row it replaces and the history row it appends so the revert is itself revertible, answering 404 `history not found` for an unknown row and no-oping with a reason when the type already holds the recorded state. The history rows are keyed by the type id and hold no foreign key to the row, so a deleted type's history stays readable and its revert restores the row under its original id; a name another type now holds is refused `duplicate name`. `POST /api/binaries/<id>/data-types/export` (`reportal types-export <binary-id> <path> [--force]`) is the apply step: it renders the model as one deterministic `#pragma once` C header (one block per type sorted by name, a struct's or union's members ordered by offset, the tagged forms `typedef struct|union <name>_s { ... } <name>;`, `typedef enum <name>_s { ... } <name>;` and the `typedef <target> ...` alias/pointer/array/function forms, each with a trailing `/* size N */`), writes it atomically to the explicit path, refuses to overwrite without `force` (409 `export-exists`) and creates the target's parent only when its own parent exists. reportal never writes into the rebrew project or the workspace unless the caller names the path. Function signatures are the second half: `POST /api/binaries/<id>/signatures/import` (`reportal signatures-import <binary-id>`) parses the declaration line of every stored decompilation into a local model (`src/reportal/signatures.py`, the `function_signatures` table, one row per function): the first line that parses as a function declaration wins, so leading comments are skipped, a `void` parameter list (or an empty one) means zero parameters, a `__cdecl`/`__stdcall`/`__fastcall`/`__thiscall`/`__vectorcall` keyword is stored as the calling convention, a pointer return keeps its `*`, and an array parameter keeps its dimension (`char[16]`); a decompilation whose line does not parse is skipped with a reason while the rest seed, and a function with no stored decompilation is not touched. `GET /api/binaries/<id>/signatures` (`reportal signatures <binary-id>`) lists the model ordered by name, `GET /api/functions/<id>/signature` (`reportal signature <function-id>`) returns the row plus its rendered prototype, `PATCH /api/functions/<id>/signature` sets the return type and/or calling convention, `POST`/`PATCH`/`DELETE /api/functions/<id>/signature/parameters[/<index>]` add a parameter (appended or at an index), edit its type and/or name or remove it, and `DELETE /api/functions/<id>/signature` deletes the signature. Every edit validates a C identifier, rejects an empty type, a duplicate parameter name and an out-of-range index, and reindexes the parameters from 0 so they stay contiguous. `POST /api/binaries/<id>/signatures/export` (`reportal signatures-export <binary-id> <path> [--force]`) is the apply step: it renders one deterministic `#pragma once` prototype header (one `<head> <name>(<params>);` line per function ordered by name, an empty list as `void`, the calling convention between the head and the name) and writes it atomically with the same `force` (409 `export-exists`) and parent-directory rules as the type header. The model is local and stored-only: importing parses reportal's own stored decompilations and never runs the decompiler, and export writes only the path the caller names. Every signature mutation appends the state it replaced to a `signature_history` table (mirroring `name_history` for renames), served by `GET /api/functions/<id>/signature/history` and `reportal signature-history <function-id>`; `POST /api/functions/<id>/signature/history/<history_id>/revert` and `reportal signature-revert <function-id> <history-id>` restore exactly that state, journaling the row they replace and the history row they append so the revert is itself revertible, answering 404 `history not found` for an unknown row, and no-oping when the signature already holds the recorded state. A signature row that predates the history table still reads (an empty history list) and its next edit records a history entry whose previous state is that legacy row. A parameter carries the optional `at` (a register or a stack slot), `kind` (value, pointer, array or struct) and `bits`, editable through `reportal signature-param <function-id> <index> [--at SLOT] [--kind K] [--bits N] [--clear FIELD]` and the per-parameter reorder `reportal signature-param-move <function-id> <index> <to-index>` (also the `parameters/<index>/move` POST); an absent field stays null (the payload offers the convention-implied value as `default_at`, never as `at`), the rendered prototype annotates only the fields it has, and a reorder recomputes the arrival locations the calling convention implies. |
| Memory read (`read_memory`) and full-file view | Implemented | rebrew (`pe-info` section map) + local file read | `GET /api/binaries/<id>/memory?va=&length=&kind=` (`reportal memory <binary-id> <address> [--length N] [--offset-kind va\|rva\|file]`, plus the read-only `read_memory` MCP tool) returns a window of the binary's bytes by absolute virtual address, RVA or raw file offset. The window defaults to 64 bytes and is capped at 1024, the bounds the hosted portal's `read_memory` tool documents; the payload reports the resolved `kind`, the `address`, the `section` and the bytes as lowercase hex. rebrew exposes no raw byte-read command, so reportal takes the section map from the engine's own `rebrew pe-info` call and reads the file exactly where that map says the bytes live, never parsing a PE itself; an address not backed by the image's raw bytes (a gap between sections, a header-only RVA, a section's uninitialized tail) and a window past the backing bytes answer 400 `unmapped address` rather than fabricating bytes, a bad `va`/`length`/`kind` answers 400 `invalid address`/`invalid length`/`invalid kind`, an absent engine answers 503 `engine-unavailable` and a failed invocation 500 `engine-error`. The hosted page's whole-binary hex view is the SPA Memory panel's full-file mode over `GET /api/binaries/<id>/memory/page` (`reportal memory-page <binary-id> [address] [--length N] [--offset-kind va\|rva\|file]`): a page (default 256 bytes, cap 4096) walks the same section map and answers `bytes` rows (address, file offset, hex) and `gap` rows for every byte no section backs, so a region between two sections is a stated gap rather than zero bytes; the mode offers a section select, a go-to accepting a virtual address or a file offset (the two kinds the hosted control offers), Previous/Next paging, a zero byte dimmed to the muted ink without being hidden, and a byte-range selection copied as space-separated hex or a C array initializer.  The panel's `Whole binary` mode is the hosted continuous view: one scrollable dump in virtual-address order, its span taken from the same section map, only the rows on screen rendered and the bytes read 256 at a time as the viewport approaches a window; a region no section backs stays a stated `gap` row rather than zeros, the `Columns` control switches the virtual and file-offset readings (`Tab`, remembered across sessions), `G` focuses the address box, and a section table's virtual-address cell links into the dump and selects that row.  reportal's own metric, not a hosted field. |
| Per-section byte coverage | Implemented (reportal's own metric, not a portal feature) | local store (stored `pe-info` sections + stored functions) | `GET /api/binaries/<id>/section-coverage` and `reportal section-coverage <binary-id> [--json]` compute, per stored `pe-info` section, the bytes covered by stored functions whose VA falls inside it, the section size, the percentage and the uncovered count, plus the totals. Overlapping functions are unioned so no byte counts twice, and a function that straddles a section end is clipped to the section. A binary with no stored `pe-info` scan answers 404 `no-scan`; a binary with no stored functions reports `null` percentages with a zero-function note, never a fabricated 0%. The payload's `note` and the CLI help say plainly that this is reportal's own readout over its stored function table: the hosted portal publishes no per-section byte coverage, so this row is not a parity claim. |
| Cross-references | Implemented | rebrew | `reportal xrefs <function-id> [--kind NAME]...` and `GET /api/functions/<id>/xrefs?kind=...` run `rebrew xrefs <hex-va> --json` with the working directory set to the binary's stored rebrew project context, and return the engine's reference list live (never stored). `reportal references <function-id>` and `GET /api/functions/<id>/references` run `rebrew describe <hex-va> --json` in the same context for the hosted portal's three reference tables: globals (the data addresses the function reads, writes or loads, each with the access the instruction makes clear and the section the stored `pe-info` scan places it in), callers (one row per call site, linked to its function) and callees (the function's calls, an import-slot call with no resolved name reported as indirect), each with a count badge in the SPA. |
| Collections / tags | Implemented | local | Collections and binary tags are end to end. Tags: `GET`/`POST /api/tags`, `GET`/`POST /api/binaries/<id>/tags`, `DELETE /api/binaries/<id>/tags/<tag_id>`, plus `reportal tags` and `reportal tag <binary-id> <name> [--remove]`. The binary detail view renders a binary's tags as chips with add and remove. |
| Analysis comments | Implemented | local store | Analyst comments are end to end. `GET`/`POST /api/binaries/<id>/comments`, `GET`/`POST /api/functions/<id>/comments` and `PATCH`/`DELETE /api/comments/<id>` back the `comments` table through `src/reportal/comments.py`, and `reportal comments --binary ID` (or `--function ID`), `reportal comment-add --binary ID` (or `--function ID`) `"text"` `[--author NAME]` and `reportal comment-rm <comment-id>` wrap the same store. A comment names a scope (`binary` or `function`) that must exist, an author (default `DEFAULT_AUTHOR` when the caller names none) and a body trimmed and capped at `MAX_COMMENT_CHARS`; a blank or oversized body is 400 `invalid comment`, an unknown scope or comment id 404, and the list is oldest first. An update replaces the body and stamps `updated_at`. The `list_comments` MCP tool is read-only and `add_comment`, `update_comment` and `delete_comment` are destructive; the SPA renders a Comments panel on both detail views with an add box and per-comment edit and delete for the browser's own author, and the Binaries list carries each binary's comment count. reportal's AI inline comments are a separate stored artifact, served at `/api/functions/<id>/ai-comments`. |
| Bulk actions | Implemented | local store | `POST /api/binaries/bulk` (`add_tag`, `remove_tag`, `delete`) and `POST /api/functions/bulk` (`rename`, `clear_matches`) apply one action to a bounded id list (`MAX_BULK_IDS`), validate the action against a named set, reject an empty list, and answer `{"action", "requested", "applied", "skipped": [{"id", "reason"}]}`; an unknown id is skipped with a reason instead of failing the batch, and a `delete` cascades the binary's analyses, functions, scans, comments, conversations and documents. `reportal bulk-tag <tag> <binary-id>... [--remove]`, `reportal bulk-delete <binary-id>... [--yes]` (an interactive confirmation without `--yes`) and `reportal bulk-prefix <prefix> <function-id>... [--replace]` wrap the same actions, and a prefix rename goes through the normal rename path so every change is recorded in `name_history` with source `bulk-prefix`. `POST /api/analyses/bulk` applies the same three actions over analysis ids (`reportal analysis-bulk-tag`, `reportal analysis-bulk-delete`, the destructive `bulk_analyses` MCP tool and the analyses view's selection checkbox beside its Bulk actions panel): a tag writes the binaries the analyses belong to, a delete replays the single-analysis snapshot, and a binary's only analysis while it holds functions is skipped as `only analysis with functions`. The `bulk_binaries`, `bulk_functions` and `bulk_analyses` MCP tools are destructive, and the SPA Binaries list carries selection checkboxes with an add-tag, remove-tag and delete bar while the Functions list carries a bulk prefix rename. |
| Search | Implemented | local | `GET /api/search?q=&kind=&limit=` over binaries, functions, collections and tags, with LIKE escaping. `kind=all` (the default) is the substring behaviour the route always had; `kind=sha256` matches a full hash or a prefix, `kind=binary` a binary name, `kind=collection` a collection name and `kind=tag` a tag name, so every typed query stays a subset of the default. Every row carries the metadata the store holds (a binary's size, format, arch, created and tags; a collection's member count; a tag's tagged-binary count) plus the `match` field that made it hit, and `counts` reports each group's returned count against its matched total so a limited page never reads as a total. A SHA-256 prefix shorter than `store.MIN_SHA256_PREFIX` (8), a non-hex value and a prefix matching more than one binary answer 400 `short-hash`, `invalid-hash` and `ambiguous-hash`; an unknown kind is 400 `invalid-kind`. The SPA carries both surfaces: the Search view's grouped tables (each heading states returned-of-total) and the global `⌘K`/`Ctrl+K` modal, which opens from anywhere, keeps the query input focused, cycles the four query types with Tab, moves a roving highlight with the arrow keys, opens the highlighted hit with Enter, closes on Escape and returns focus where it was, and traps focus while open. Both read `src/views/SearchResults.tsx`'s shared hit model; reportal has no per-collection or per-tag detail route, so those hits lead to the Collections and Binaries lists. This is a local, offline store search; the hosted portal searches its own hosted corpus. |
| Firmware and archive extraction | Implemented (stdlib formats only) | local | `reportal extract <binary-id> [--password TEXT] [--collection ID]`, `POST /api/binaries/<id>/extract` and the destructive `extract_archive` MCP tool unpack a **stored** archive and register the binaries it holds, reporting each member with the id it became or the reason it was skipped, as one journal action. Supported formats are exactly the ones the standard library reads without an external tool: `.zip` and `.apk` (a zip), `.tar`, `.tar.gz`/`.tgz`, `.tar.bz2`, `.tar.xz` and a single-member `.gz` (a `.gz` whose contents are a tar is read as one, sniffed with `tarfile.is_tarfile`). `.rar` and `.7z` are refused 400 `external-tool-required` naming the unpacker reportal does not ship (`unrar`, `7z`), and reportal never shells out; **firmware unpacking is not implemented** (the hosted portal runs a hosted extractor for firmware images; that is not-applicable locally). Safety comes before the feature: members are extracted into a temporary directory under `<workspace>/binaries/` (removed either way, so nothing is written outside it) and every member is validated before a byte is written. Refused per member with its reason: an absolute name, a `..` component, a path resolving outside the extraction root, a symlink or hardlink, a device, FIFO or socket, a member past `MAX_MEMBER_BYTES` (256 MiB), a total past `MAX_TOTAL_BYTES` (512 MiB), a ratio past `MAX_COMPRESSION_RATIO` (200:1) and an archive past `MAX_MEMBERS` (4096). A password-protected zip extracts with the supplied password (ZipCrypto; the stdlib reads it) and is refused `password-required` without one and `bad-password` with the wrong one; tar archives carry no password. Members register by content hash into one collection (the body's `collection_id`, else one named after the archive, reused when it exists), so a member already stored is reported as a duplicate; the whole request is one journal action. |
| Firmware upload / sandbox detonation | Implemented | local (stdlib only) | `reportal firmware <binary-id>`, `POST /api/binaries/<id>/firmware` and the destructive `run_firmware_scan` MCP tool carve a stored image offline: the magics in `firmware.SIGNATURES` (SquashFS, JFFS2, CramFS, UBI, an ext superblock, a U-Boot image, an Android boot image, ELF, PE, gzip, xz, bzip2, LZMA, zip, 7z, RAR, tar, UPX) are located across read boundaries, each region is reported with its offset, size, kind, confidence, entropy and `truncated` flag, and the pass carries a sampled entropy map (`firmware.ENTROPY_WINDOW`, capped at `MAX_ENTROPY_SAMPLES`) and is stored as the `firmware` scan. A region is a *carve*, not a parse: reportal writes no squashfs or UBI inode reader, so a filesystem region is material rather than a tree and the payload says so. `reportal firmware-extract <binary-id> [--region N]...` and `POST /api/binaries/<id>/firmware/extract` then carve the regions out as binaries in one journal action: a gzip (trimmed to its stream by zlib), tar or zip region is unpacked by `reportal.archive` and its members registered, and every other region is stored as a binary of its own with its provenance. Nothing is executed, mounted or spawned, and no external tool is called. The sandbox detonation half is shipped too, with the runner guard and the opt-in the `Dynamic execution` row above states. |
| Knowledge documents + semantic search + graph | Implemented | local + optional LLM (OpenAI-compatible) | `reportal ingest <binary-id> <path> [--title TEXT]`, `reportal documents <binary-id>` and `reportal knowledge <binary-id> "query" [--limit N]`, plus `POST /api/binaries/<id>/documents` (a `multipart/form-data` upload), `POST /api/documents` (a pasted note), `GET /api/binaries/<id>/documents`, `GET`/`DELETE /api/documents/<id>` and `GET /api/knowledge/search?q=&binary_id=&limit=` store text documents (markdown, source, config, logs, HTML) scoped to one binary or to the project. Ingestion decodes UTF-8 with invalid sequences replaced, rejects content past `knowledge.BINARY_CONTROL_RATIO` NUL/control characters as binary and empty content as empty, strips HTML to its visible text, splits the text into `CHUNK_CHARS` chunks overlapping by `CHUNK_OVERLAP` at paragraph/sentence boundaries, dedupes by sha256 inside the scope and caps the document at `MAX_DOCUMENT_BYTES`, the scope at `MAX_DOCUMENTS_PER_SCOPE` and each document at `MAX_CHUNKS_PER_DOCUMENT`. Search ranks the stored chunks: with an embeddings endpoint configured the query is embedded (a `POST <endpoint>/embeddings` request) and compared to the stored vectors by cosine similarity, and without one the local TF-IDF cosine ranks the same chunks, so search needs no configuration and no extra dependency; each hit reports the `method` (`embeddings` or `tfidf`) that scored it. Nothing fetches a URL: the only request is the optional embeddings call, and a document ingested without one stays searchable through the TF-IDF path. Six MCP tools expose the same store (`list_documents`, `search_knowledge`, `retrieve_knowledge` read-only; `ingest_document`, `ingest_url`, `delete_document` destructive) and the SPA Knowledge view lists, ingests (file or pasted note) and searches. Guarded URL ingestion is built and off by default: `REPORTAL_ALLOW_REMOTE_INGEST` or a workspace `[knowledge] allow_remote = true` enables `reportal ingest-url <binary-id> <url> [--title TEXT] [--project]`, `POST /api/knowledge/fetch` (body `{"scope_kind", "scope_id", "url", "title"}`), `GET /api/knowledge/config`, the SPA Knowledge view's URL field (shown only when the config route reports it enabled) and the destructive `ingest_url` MCP tool. The guards: only `http`/`https`, a host is required, credentials in the URL are rejected, every address the host resolves to is checked against the loopback, private, link-local, multicast, unspecified, reserved and IPv4-mapped IPv6 ranges with any one blocked answer rejecting the target, and the port is restricted to 80/443 plus the scheme default; `fetch` follows redirects manually, re-validates each hop and reads the connected peer's own address before consuming the body, so a host that resolves publicly during the check and connects to a private address is still rejected (a transport that exposes no peer address reports it as `unverified` and the pre-flight answer stands); it streams the body and aborts past `MAX_BYTES`, and accepts only `text/*`, `application/json`, `application/xml`, `application/x-yaml` or a missing content type, sending no auth header and no cookie. What is not covered: the request has already been sent by the time the peer is known, so only the body is withheld, and a network namespace with no private routes would isolate more strongly. A fetch that fails writes no document, a stored document's `source` is the final URL so a re-fetch of the same bytes is a duplicate, and a disabled path answers 403 `remote-ingest-disabled`. Otherwise the only request is the optional embeddings call, and a document ingested without one stays searchable through the TF-IDF path. The knowledge graph over those documents is the second half and is implemented locally as a deterministic entity/relation graph: `POST /api/binaries/<id>/graph` rebuilds it from stored rows (the binary, its functions, the recorded matches, its documents, the stored struct/capability/unstrip/triage scans and its tags), `GET /api/binaries/<id>/graph` serves it (404 `no-graph` before the first build, `?kind=` keeps one node kind, `?include_documents=true` adds the document nodes, which are left out by default so the graph stays small), `GET /api/graph/nodes/<node_id>` returns one node with its neighbors grouped by relation, `reportal graph-build <binary-id>` and `reportal graph <binary-id> [--node ID]` are the CLI, three MCP tools (`get_graph`, `graph_neighbors` read-only; `build_graph` destructive) expose the same calls and the SPA Graph view renders the node counts by kind, a filterable node table (kind, label, degree) and the selected node's neighbor groups with links to the function or document behind a node. The node kinds are `binary`, `function`, `document`, `struct`, `tag`, `capability` and `library` and the relations `contains`, `documented-by`, `has-capability`, `has-tag`, `recovered`, `identifies`, `matched-with` and `mentions`; call edges (`function -calls-> function`) are omitted because nothing stored carries them (reportal reads the call graph per function through `rebrew xrefs`), so they are not fabricated. The build is local and deterministic with no LLM, no external store and no new dependency. Retrieval is implemented: `knowledge.retrieve` is the ranking with a named `RETRIEVAL_LIMIT` and a blank-query guard, and `knowledge.as_context` renders the hits as a bounded, citable block (`[n] <title> (<source>): <text>`, each snippet cut at `RETRIEVAL_SNIPPET_CHARS`, a hit that would push the block past `RETRIEVAL_CONTEXT_CHARS` dropped). A conversation appends a `Relevant documents` section built from its binary's documents, placed last so the `MAX_CONTEXT_CHARS` cap truncates it first, and returns the hits as `sources` for the SPA's `Sources` disclosure; `GET /api/functions/<id>/knowledge?q=`, `GET /api/binaries/<id>/knowledge?q=`, `reportal context <function-id> [--query TEXT]` and the read-only `retrieve_knowledge` MCP tool expose the same retrieval. The AI decompilation pipeline's `retrieve-knowledge` component derives `knowledge` from the function's name, VA and stored summary, and `name-variables` and `summarize` pass it into their prompts. Retrieved document text is untrusted input: it is quoted as data to reason about, never executed and never spliced into a command, and the conversation system prompt says so and never treats it as an instruction. The graph is pluggable through a backend registry (`reportal.graph_backends`): `GET /api/graph/backends` lists the registered backends, `POST /api/binaries/<id>/graph/sync` (body `{"backend": "..."}`, default the configured one), `GET /api/graph/query?q=&backend=`, `reportal graph-backends`, `reportal graph-sync <binary-id> [--backend NAME]` and `reportal graph-query <query> [--backend NAME]` drive them, the read-only `list_graph_backends` and destructive `sync_graph_backend` MCP tools expose the same calls, and the SPA Graph view carries a backend selector, a Sync control that is disabled with its reason when the backend is unavailable, and a query box for a backend that supports querying. The built-in `sqlite` backend is the default and reads the local store (its sync is a no-op that reports the stored counts); the optional `cognee` backend pushes the same graph into a Cognee dataset, is available only with the `cognee` extra (`uv sync --extra cognee`), and takes its dataset name from `REPORTAL_COGNEE_DATASET` or `[knowledge] cognee_dataset` (default `reportal`). An uninstalled backend answers 503 `backend-unavailable` with the install hint rather than a traceback. |
| Reports / PDF | Implemented | rebrew + local PDF writer | `reportal report <binary-id>` and `POST /api/binaries/<id>/report` run `rebrew report --json --output <workspace>/reports/<binary-id>` in the binary's rebrew project context and store the engine result (`out`, `pages` and a coverage `summary` of `total_functions`, `covered_functions`, `coverage_pct`, `matched_pct`, `byte_coverage_pct`, `status_counts`); `GET /api/binaries/<id>/report` serves the stored result and answers 404 `no-scan` when none exists. `GET /reports/<binary-id>/` and `GET /reports/<binary-id>/<path>` serve the generated HTML site from that tree (the root serves `index.html`), and the binary detail Report panel links to it. PDF export is implemented locally over the scans the portal already stored (`src/reportal/pdf.py`, laid out by reportal and serialized by reportlab): `reportal report-pdf <binary-id> [--output PATH] [--force] [--json]` and `POST /api/binaries/<id>/report/pdf` render a multi-page text-only PDF (Helvetica/Helvetica-Bold, uncompressed content streams, written with reportlab's `invariant=1` so the bytes are reproducible) with a title block, the coverage summary, fingerprint, capabilities, triage, function triage, security, crypto, threat, secrets counts (never a value), behavior, protocols, hardening, remediation and lineage, and write it to `<workspace>/reports/<binary-id>/report.pdf`; `GET /api/binaries/<id>/report/pdf` serves it as `application/pdf` and answers 404 `no-pdf` with the generate hint before the first render, 404 `binary not found` for an unknown id. The render is stored-only (no engine run), a section whose scan is absent is omitted, every row list has a named cap so a huge scan cannot produce a thousand pages, and the bytes are deterministic for the same rows and generated date. This is a text-only summary of reportal's own scans, not the hosted portal's PDF export and not a rendering of the `rebrew report` HTML site. |
| Triage | Implemented | rebrew + optional LLM (OpenAI-compatible) | Two layers. The binary dossier: `reportal triage <binary-id>` and `POST /api/binaries/<id>/triage` run `rebrew analyze --json` and store the one-shot dossier under the binary's analysis; `GET /api/binaries/<id>/triage` serves the stored dossier and answers 404 `no-scan` when none exists. The dossier covers binary layout, detected toolchain, strings, imports, references, function coverage, dispatch tables and FLIRT hits, and the binary detail Triage panel renders the toolchain, meta and count summary with the raw JSON in a `<details>`. The per-function layer: `reportal function-triage <binary-id> [--limit N] [--function ID]...` and `POST /api/binaries/<id>/function-triage` (body `{"function_ids": [...], "limit": N}`, both optional) select the target functions (explicit ids, else the top `limit` candidates), build each one's untrusted context (its stored decompilation, else a disassembly through `rebrew asm`), ask the configured endpoint for `{"summary", "score" 0..1, "capabilities"}` and store one `ai_artifacts` row of kind `function-triage` per function plus one aggregate `function-triage` scan for the binary; `GET` on the same route is stored-only and answers 404 `no-scan`. `function_triage.score_candidates` is the deterministic fallback and the ranking when no endpoint is configured: it scores size, a status that is not a byte match (`STUB`, `NEAR_MATCHING`, ...), a stored decompilation, a placeholder name and the recorded match count into a named `heuristic_score` in 0..1 with the contributing reasons. With no LLM the same shape is produced from that score and a one-line summary derived from the function's metadata, `model` is `""` and the payload's notes say so; a function whose context cannot be resolved (no stored decompilation and no engine, or no rebrew project context) is recorded in the payload's `skipped` list with a reason instead of failing the run. A missing engine is 503 only when the LLM path needs a disassembly. The binary detail Function triage panel renders the model/method line, the scored rows with their summaries and method badge, and the skipped list. The hosted portal's AI threat report is not reproduced here; the local Threat Report capability below covers the IOC and MITRE half deterministically. |
| Capabilities | Implemented | local (imports + strings) | `reportal capabilities <binary-id>` and `POST /api/binaries/<id>/capabilities` feed the binary's import table and extracted strings (`rebrew imports` and `rebrew strings`, both standalone, no project context) through the deterministic classifier in `src/reportal/capabilities.py` and store the result as the `capabilities` scan; `GET /api/binaries/<id>/capabilities` serves the stored result and answers 404 `no-scan` when none exists. The rule table covers networking, crypto, file-io, registry, process-execution, threading, memory, dynamic-loading, anti-debug, persistence, synchronization, compression, ui and console. Each result carries a description, `high` confidence when an import rule matched, `medium` for string-only evidence, the matching evidence and an exact evidence count. The binary detail Capabilities panel loads the stored scan and renders the categories with their evidence. This is not the hosted portal's LLM capabilities agent: it is a fixed rule table over imports and strings, with no model and no network call. |
| Execution behavior (Agents/Execution) | Implemented | local (imports + strings) | `reportal behavior <binary-id> <domain>` and `POST /api/binaries/<id>/behavior/<domain>` match the binary's import table and extracted strings (`rebrew imports` and `rebrew strings`, both standalone, no project context) against a fixed rule table per domain and store the result as the `execution` scan; the domain GET serves the stored result and answers 404 `no-scan` when none exists, and `GET /api/binaries/<id>/behavior` serves all three stored scans (null where absent). The fixed rule table in `src/reportal/behavior.py` covers process launch (`CreateProcessA/W`, `ShellExecuteA/W/Ex`, `WinExec`, `_spawn*`, `system`, `popen`, `execve`/`execl`/`fork`/`posix_spawn`), service control (`CreateServiceA/W`, `StartServiceA/W`, `OpenSCManagerA/W`, `RegisterServiceCtrlHandler*`) and IoT-dropper string markers (masquerade names, distinctive staging dirs, downloader names, multiarch filename clusters). An import rule match is `high` confidence, string-only evidence `medium`; findings deduplicate, sort by confidence then name and cap at `MAX_FINDINGS` while `count` and `by_confidence` stay exact. The binary detail Behavior panel selects a domain, loads the stored scan and runs the scan on demand. The hosted `execution-scan` is an agent; this is a deterministic import/string heuristic, not a model, and it does not execute the binary. |
| Networking behavior (Agents/Networking) | Implemented | local (imports + strings) | The `networking` domain of `reportal behavior` and `POST /api/binaries/<id>/behavior/networking` matches the same standalone `rebrew imports` and `rebrew strings` payloads against a fixed rule table and stores the result as the `networking` scan. It covers the socket API (`WSAStartup`, `socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`, `sendto`, `recvfrom`, `gethostbyname`, `getaddrinfo`), HTTP and download clients (`WinHttp*`, `InternetOpen*`, `InternetConnect*`, `HttpOpenRequest*`, `HttpSendRequest*`, `URLDownloadToFile*`, `curl_easy_*`) and string evidence for URLs, octet-validated IPv4 addresses, labeled ports and DDoS flood-template literals (`Content-Length: 10485760`, H2 preface, `M-SEARCH`). Import evidence is `high` confidence, string-only evidence `medium`; the stored scan is served by the domain GET (404 `no-scan` before the first run) and appears in the combined `GET /api/binaries/<id>/behavior`. The hosted `networking-scan` is an agent; this is a deterministic import/string heuristic with no model and no network call of its own. |
| Protocols | Implemented (deterministic inference) | local (imports + strings) | `reportal protocols <binary-id>` and `POST /api/binaries/<id>/protocols` feed the binary's import table and extracted strings (`rebrew imports` and `rebrew strings`, both standalone, no project context) through the fixed table in `src/reportal/protocols.py` and store the result as the `protocols` scan; `GET /api/binaries/<id>/protocols` serves the stored result and answers 404 `no-scan` when none exists. Each entry names a protocol family (`http`, `https`, `tls`, `dns`, `ftp`, `smtp`, `imap`, `pop3`, `irc`, `telnet`, `ssh`, `smb`, `rdp`, `ldap`, `snmp`, `ntp`, `quic`, `mqtt`, `websocket`, `tcp`, `udp`) with a description, a confidence, the evidence that named it (`import`, `scheme` or `string`) and its well-known ports. A dedicated API (`WinHttpSendRequest`, `ldap_bind`) is `high`, the generic socket family on `tcp`/`udp` is `medium`, a `scheme://` literal is `high` (the scheme is the protocol) and a protocol literal (`HTTP/1.1`, `EHLO`, `SSH-2.0`) is `medium`; a protocol with both an import and a scheme or literal match is raised to `high`. A port is evidence only when the same string also carries a host or URL, so a lone `80` or `443` constant names nothing. The binary detail Protocols panel loads the stored scan and runs it on demand. This goes beyond the networking behavior domain, which only reports API usage, by naming concrete families; it is a deterministic rule table, not the hosted portal's model. The hosted portal's protocols surface is coming soon upstream, so there is no hosted behavior to match yet. Inference is not proof of use: an import means the binary can call that API and a literal means the text is present, not that a session was opened. |
| Filesystem behavior (Agents/Filesystem) | Implemented | local (imports + strings) | The `filesystem` domain of `reportal behavior` and `POST /api/binaries/<id>/behavior/filesystem` matches the same standalone engine payloads against a fixed rule table and stores the result as the `filesystem` scan. It covers file operations (`CreateFileA/W`, `ReadFile`, `WriteFile`, `DeleteFileA/W`, `MoveFile*`, `CopyFile*`, `FindFirstFile*`, `FindNextFile*`, `GetTempPath*`, `SHFileOperation*`, `CreateDirectory*`, `RemoveDirectory*`), the POSIX `open`/`read`/`write`/`unlink`/`rename`/`opendir` family and string evidence for drive-letter paths, UNC paths and file-name extensions. Import evidence is `high` confidence, string-only evidence `medium`; the stored scan is served by the domain GET (404 `no-scan` before the first run). The hosted `filesystem-scan` is an agent; this is a deterministic import/string heuristic, not a model. |
| Anti-Analysis and Obfuscation | Implemented (deterministic heuristics) | local (fingerprints + imports + strings + stored triage) | `reportal hardening <binary-id> <domain>` (or `--all`), `POST /api/binaries/<id>/hardening/<domain>`, the stored-only `GET` on the same path and the combined `GET /api/binaries/<id>/hardening` cover two domains from `src/reportal/hardening.py`. `anti-analysis` matches the import table and the extracted strings against a fixed rule table: `anti-debug-api`, `timing-check`, `vm-or-sandbox-artifact`, `exception-tampering`, `debugger-detection-string`, `io-port-probe`, `cpu-state-probe`, `int3-trap` and `lock-canary`. An import hit (a concrete API) is `high` confidence, string-only evidence `medium`. `obfuscation` applies named thresholds: an executable or code-like section at or above `HIGH_ENTROPY_THRESHOLD` (7.0), a size-weighted mean section entropy at or above `HIGH_OVERALL_ENTROPY_THRESHOLD` (6.8), fewer than `SPARSE_IMPORT_THRESHOLD` (10) imports or `SPARSE_STRING_THRESHOLD` (20) strings for a binary at or above 64 KiB, and packer/protector names or section conventions (`UPX0`, `.aspack`, `.themida`) in the strings, the fingerprint's section names or the stored triage dossier; the payload carries a `packer_likelihood` (`high` from three findings, `medium` from two, else `low`). Both domains deduplicate, sort and cap findings at `MAX_FINDINGS` while the counts stay exact, and a missing fingerprint is recorded as a note with the entropy thresholds skipped rather than failing the run. What they can conclude: a matched API means the binary calls it and a matched packer name or section convention means that tool's footprint is present; an entropy or sparse-table threshold means the static shape is consistent with packing. What they cannot: a missing finding is not proof of protection (a dynamically resolved anti-debug check or a rewritten import table leaves no import and no string to match), and a firing heuristic is not proof of a packer (a legitimately compressed or stripped binary fires the same entropy and sparse-table rules). The hosted portal's anti-analysis and obfuscation surfaces are agents; this is a fixed local rule table and threshold set, with no model, no network call and no execution of the binary. |
| Crypto scan | Implemented | rebrew | `reportal crypto-scan <binary-id>` and `POST /api/binaries/<id>/crypto-scan` run `rebrew crypto-scan <binary> --json` and store the result as the `crypto` scan; `GET /api/binaries/<id>/crypto-scan` serves the stored result and answers 404 `no-scan` when none exists. Detection is local: constant-table lookup (AES S-box and inverse S-box, SHA-256 initial hash H and round constants K) plus name and import matching, reported per finding as `constant`, `import` or `name` with a `high`/`medium` confidence. The hosted portal's AI `crypto-explain` narrative is not reproduced. |
| Security scan | Implemented | rebrew | `reportal security-scan <binary-id> [--min-severity high\|medium\|low]` and `POST /api/binaries/<id>/security-scan` run `rebrew security-scan --json [--min-severity ...]` in the binary's rebrew project context and store the result as the `security` scan; `GET /api/binaries/<id>/security-scan` serves the stored result and answers 404 `no-scan` when none exists. Detection is local and rule-based (unbounded copy, format string, command execution, unchecked memcpy, insecure random, stack allocation), reported per finding as a rule with its CWE, severity, confidence, file, line, function and snippet. It scans the project's reversed C sources, not decompiled-only output; the hosted portal's LLM/AI scanners are not reproduced. |
| Secrets | Implemented locally | local (strings) | `reportal secrets <binary-id>` and `POST /api/binaries/<id>/secrets` read `rebrew strings` (standalone, no project context) and match the entries against the fixed pattern table in `src/reportal/secrets.py`: an AWS access key id and a context-anchored AWS secret access key, a Google API key, the GitHub `gh[pousr]_` token family, a Slack `xox[baprs]-` token, Stripe live/test keys, OpenAI-style `sk-` keys, a three-part JWT, a PEM private key header, a database connection string carrying `Password=`/`Pwd=` next to a `Server=`/`Data Source=` field, and a generic quoted assignment to a `password`/`passwd`/`secret`/`api_key`/`apikey`/`token`/`access_key` field of at least `MIN_LITERAL_LENGTH` characters. Each string is also checked for a key-sized high-entropy blob: a mixed character class (a letter plus a digit or base64 punctuation), no whitespace and at least `MIN_ENTROPY_BITS` bits per character, with even-length hex blobs graded against the lower `HEX_MIN_ENTROPY_BITS`; and for a staged second stage: a base64-shaped run at or above `MIN_PAYLOAD_LENGTH` (4 KiB) with no whitespace reports `embedded-payload` rather than a key-sized blob, with the same redaction and pipeline. Findings are stored as the `secrets` scan; `GET /api/binaries/<id>/secrets` serves the stored result and answers 404 `no-scan` when none exists. Each finding carries the raw `value` and a `redacted` display form (all but the first and last `REDACT_PREFIX_CHARS` characters masked), deduplicates by value keeping the highest confidence and the first VA, sorts by confidence then name then VA, and caps the list at `MAX_FINDINGS` while `count` and `by_confidence` stay exact. Detection is deterministic and local with no LLM and no network call; it is not the hosted portal's secret-recovery model. Values are stored locally and are sensitive. The binary detail view carries a Secrets panel that auto-loads the stored scan, runs the scan on demand and renders each finding redacted with a per-row reveal. |
| Threat / IOC | Implemented locally | rebrew (imports + strings) + local rules + optional LLM (OpenAI-compatible) | `reportal threat <binary-id> [--narrative]` and `POST /api/binaries/<id>/threat` run `rebrew strings` and `rebrew imports` (both standalone, no project context), extract indicators of compromise with the deterministic rules in `src/reportal/threat.py` (urls, domains, ipv4, ipv6, emails, registry_paths, file_paths, hashes; private/loopback addresses are flagged in the finding's `kind`, not dropped, an IPv4-mapped IPv6 tail stays one IPv4 finding, a zone id is not an indicator, cloud instance-metadata endpoints are flagged by provider (`cloud-aws`, `cloud-aws-ecs`, `cloud-alibaba`, `cloud-tencent`, `cloud-gcp`), bracketed URL hosts parse, and strings carrying a printf conversion are skipped), map them together with the stored `capabilities` scan onto a curated MITRE ATT&CK table (process injection, command and scripting interpreter, application layer protocol, exfiltration over C2, system information discovery, ingress tool transfer, modify registry, deobfuscate/decode, data destruction, data encrypted for impact, boot/logon autostart, obfuscated files), and store the result as the `threat` scan; `GET /api/binaries/<id>/threat` serves the stored report and answers 404 `no-scan` when none exists. Confidence is `high` when an import family matched directly and `medium` when only a capability or an IOC category did. `--narrative` (or `"narrative": true`) additionally asks the configured OpenAI-compatible endpoint for a short analyst summary, with the IOCs and techniques passed as untrusted context; without an endpoint the report is still returned, with the reason recorded in its notes. This is explicitly not the hosted portal's model-driven threat report and no external threat-intelligence source is contacted: the IOC rules and the ATT&CK table are local and fixed. |
| Threat score and software type | Implemented (reportal's own heuristic) | local store (stored `filetype`, `capabilities`, `threat`, `triage` scans) | The hosted portal's AI Agents card shows a 0-100 threat score with behaviour badges and its Threat Report carries a software-type badge. reportal derives both at read time from the scans it already stores (`threat.classify_binary`), so the `GET`/`POST /api/binaries/<id>/threat` and `.../triage` responses carry `software_type` (a closed vocabulary of `ransomware`, `keylogger`, `coinminer`, `downloader`, `installer`, `managed-application`, `packed-executable`, with the signals that fired and a confidence derived from the independent signal kinds) and `threat_score` (0-100 over packing, capabilities, indicators and ATT&CK techniques, every point named with its evidence, `null` with the reason when nothing carries evidence). The binary detail Threat report and Triage panels render the badge and the meter, and the payload says the score is reportal's own heuristic rather than the platform's model score.
| Keyboard shortcuts and cheatsheet | Implemented | local SPA | The hosted portal offers ⌘K search, a `?` cheatsheet and section jump keys. reportal's SPA registers every shortcut in one layer (`web/src/keys.ts`) and generates the `?` cheatsheet from that registry: ⌘K/Ctrl+K for the global search, `g` then a letter per sidebar view, `j`/`k` through a table's tabbable rows, `/` for the view's filter box, and Escape to close. A binding never fires while a text field or a modal dialog owns the keyboard, a conflicting registration is refused, and no shortcut is registered for a control the SPA does not have (there is no sidebar collapse, in-app history control or focused-row model to bind).
| Detect (malware family) | Implemented as local family matching | local (fingerprints + imports + strings + capabilities) | `reportal families [--json]`, `reportal family-add <reference-binary-id> <name> [--alias TEXT]... [--notes TEXT]`, `reportal family-rm <family-id>` and `reportal detect <binary-id>` back the portal's Detect surface, with `GET`/`POST /api/families`, `GET`/`DELETE /api/families/<id>` and `POST`/`GET /api/binaries/<id>/detect`. **reportal ships no external threat-intelligence feed and cannot**: a malicious-family feed is a hosted, continuously updated service, so Detect is local family matching against a user-curated signature store. The analyst registers a family from a reference binary (name unique case-insensitively, optional aliases and notes); reportal derives that binary's signature bundle once, from the engine fingerprint's `sha256`, `imphash` and `rich_header_hash`, an import hash computed locally as the sha256 of the sorted lowercased `dll:name` entries, the canonical import-name set and the capability set from `capabilities.classify`, and stores it with the family, so detection never re-runs the engine for the reference. A target's bundle is scored against every family: an exact `sha256` is `high` `exact-binary`, an exact `imphash` `high` `import-fingerprint`, an exact `rich_header_hash` `medium` `toolchain-fingerprint`, an exact import hash `high` `import-set`, an import-name Jaccard ratio at or above `IMPORT_OVERLAP_THRESHOLD` (0.8) `medium` `import-overlap`, and a capability-set Jaccard ratio at or above `CAPABILITY_OVERLAP_THRESHOLD` (0.8) `low` `capability-overlap`. A family's confidence is its strongest matched signal, every matched signal is returned with its detail (the overlap signals carry the ratio), and the payload states the scope and both thresholds in its notes; a binary that matches nothing is a valid result. The detection is stored as the `detect` scan and its `GET` is stored-only, so a stored detection answers without an engine. The hosted portal's Detect runs against its own curated families and its own models; that hosted version is coming soon upstream, and this is the local, offline equivalent over signatures the analyst curates, not the same data. |
| Remediation: YARA rules | Implemented | local + optional `yarac` | `reportal yara <binary-id> [--output PATH] [--json]` and `POST /api/binaries/<id>/remediation` read `rebrew strings`, `rebrew imports` and, when no fingerprint is stored, `rebrew fingerprints` (all standalone, no project context), select bounded sets of distinctive literals with the local denylist rules in `src/reportal/remediation.py` (data strings, plus import API names ranked longest first, with a curated generic-API denylist dropped and a shared cap), and render one complete YARA rule: a sanitized name, a meta block (`author` `reportal`, the supplied date, binary name, sha256, imphash and Rich-header hash), hex-escaped `$s1..$sN` entries (a wide literal keeps the ASCII form too) and `$i1..$iN` import-name entries, then a single condition. A PE whose fingerprint carries an imphash imports the `pe` module and anchors on `pe.imphash() == "<hash>"`, falling back to the string clause and, when they exist, the import clause; every other binary anchors on the file magic (`uint16(0) == 0x5A4D` for PE, `uint32(0) == 0x464C457F` for ELF). Both forms bound the filesize and clamp each match count to the literals carried. The payload reports `string_count`, `import_count` and a `specificity` grade (`high` with an exact fingerprint or at least `MIN_SPECIFIC_STRINGS` literals, `medium` with some, `low` with none). The rule is compiled with `yarac` when it is installed and stored as the `remediation` scan with the `snort` and `stix` artifacts beside it; `GET /api/binaries/<id>/remediation` serves the whole payload and answers 404 `no-scan` when none exists, and `GET /api/binaries/<id>/remediation/<yara|snort|stix>` serves one artifact as `text/plain` (YARA, Snort) or `application/json` (STIX), answering 404 `no-artifact` when the stored payload lacks that piece. `yarac` is optional: without it the rule is stored with `validated: false` and `validator: null`, never an error. The binary detail view's Remediation panel shows the three artifacts in collapsible sections with a copy control each and an empty state per artifact, plus a Generate control. This is local renderer output, not a hosted portal model. |
| Remediation: Snort rules | Implemented | local | `reportal snort <binary-id> [--output PATH] [--json]` and `GET /api/binaries/<id>/remediation/snort` (also rebuilt by the remediation `POST`) serve a Snort 2 rule set built by `build_snort_rule` from the stored `threat` scan's URLs, domains, IPv4 and IPv6 indicators: one `alert tcp $HOME_NET any -> $EXTERNAL_NET <port>` rule per indicator, ordered by family then value, each matching the indicator's host with `content` and `http_header` and carrying `flow:established,to_server`. The destination port comes from the indicator's own URL port or from the stored `protocols` scan (its well-known port for the matching scheme, else the scan's first port by the fixed preference order), and is `any` when nothing infers one. SIDs count up from `SNORT_SID_BASE` (1000000, Snort's local range). A binary whose threat scan names no network indicator yields empty rules and an honest note instead of an invented rule. This is a basic content rule, not a tuned signature, and it is not schema-validated against an external Snort checker. |
| Remediation: STIX bundles | Implemented | local | `reportal stix <binary-id> [--output PATH] [--json]` and `GET /api/binaries/<id>/remediation/stix` (also rebuilt by the remediation `POST`) serve a minimal STIX 2.1 bundle built by `build_stix_bundle` from the stored `threat` scan: a reportal `identity` object, one `indicator` per URL, domain, IPv4, IPv6, email and hash IOC with a STIX pattern (`[url:value = ...]`, `[network-traffic:dst_ref.type = 'domain-name' AND network-traffic:dst_ref.value = ...]`, `[ipv4-addr:value = ...]`, `[ipv6-addr:value = ...]`, `[email-addr:value = ...]`, `[file:hashes.'SHA-256' = ...]`), `pattern_type` `stix`, and `created`/`modified`/`valid_from` from the supplied date, plus a `note` object when there is no indicator or a category has no pattern (registry and file paths). Every id is a `uuid.uuid5` of the object's pattern (or a fixed key), so two builds of one input are byte-identical. It is a minimal bundle, not a full threat-intelligence export, and it is not validated against an external STIX validator. |
| Agent conversations | Implemented (optional) | local store + external LLM (OpenAI-compatible) | `reportal chat-new --function <id> \| --binary <id>` and `POST /api/conversations` open a chat scoped to one stored function or binary; `reportal chat <conversation-id> "message"` and `POST /api/conversations/<id>/messages` append the turn and call the configured chat-completions endpoint. The request is a fixed system prompt plus a context block assembled from stored local data only (the function row with its stored disassembly and decompilation, or the binary row with its stored triage summary and capability scan) and the last `HISTORY_TURN_LIMIT` turns. No engine runs, no tool is called and no MCP is involved. Conversations and their messages live in the `conversations` and `messages` tables (`GET /api/conversations?scope_kind=&scope_id=`, `GET`/`DELETE /api/conversations/<id>`), the SPA Conversations view lists, creates, opens, sends to and deletes threads, and the function and binary detail views carry a Chat about this action. A message without a configured endpoint answers 503 `llm-unavailable`; the whole feature is off by default. This is not the hosted portal's tool-calling agent: the model can only answer from the stored context. |
| Integrations inventory | Implemented | local registries | The hosted portal's Integrations page lists the plugins, SDKs and the MCP endpoint it offers. reportal answers the same question about itself: `reportal integrations` and `GET /api/integrations` read the five registries a plugin enters through (`reportal.components`, `reportal.auto_workers`, `reportal.graph_backends`, `reportal.effect_handlers`, `reportal.mcp_tools`) and report, per seam, the entry-point group, the in-tree module declaring the built-ins and one row per part the registry holds with the fields that seam exposes (a component's origin, requires and provides; a backend's availability and whether it can be queried; a worker's write plan; a handler's descriptor kind and whether it is built-in; a tool's destructive annotation). The read-only `list_integrations` MCP tool and the SPA Integrations view render the same payload. Only the component registry tracks where a part was declared, so an empty origin means the registry does not record one, never that the part is built-in. This is reportal's own seam set, not the hosted platform's plugin catalogue. |
| MCP tool server | Implemented | local + rebrew + optional LLM | The hosted portal's MCP server (`https://api.reveng.ai/mcp/`, Streamable HTTP with `Authorization: Bearer` and an `mcp-session-id`) is matched locally by `reportal mcp`, an stdio server on the official `mcp` SDK (newline-delimited JSON-RPC 2.0 on stdin/stdout) that serves `initialize`, `notifications/initialized`, `tools/list` and `tools/call` at the negotiated protocol version (currently `2025-06-18`) and reports `serverInfo` `{"name", "title", "version"}`. It exposes reportal's capabilities as 252 plugin tools declared in `src/reportal/mcp_tools.py`; a third party registers through the `reportal.mcp_tools` entry-point group. 120 tools are read-only and 132 are destructive (`destructiveHint: true`), the destructive ones covering the same engine runs and store mutations the HTTP routes do; handlers call reportal's internal functions directly and never make an HTTP request back into reportal. The read tools keep the stored-only routes stored-only. There is no auth (no OAuth, JWT or API key): the server is a local stdio process, so the pipe is the whole trust boundary; Streamable HTTP, sessions, SSE and server-side logging are not emulated. |
| Dynamic execution (sandbox detonation) | Implemented (off by default) | bubblewrap (external runner) | `reportal sandbox <binary-id> [--timeout N] [--memory-mb N] [--report|--status]`, `POST /api/binaries/<id>/dynamic-execution`, the report read on the binary and its analysis, the status read (the hosted `dynamic-execution/report` and `/status` pair) and the `run_sandbox_detonation` / `get_sandbox_report` / `get_sandbox_status` MCP tools detonate a stored sample and record what it did.  Four guards hold before any process starts: the workspace opts in (`REPORTAL_SANDBOX=enabled` or `[sandbox] enabled = true`, else 403 `sandbox-disabled`), a runner is installed (else 503 `sandbox-unavailable`), the row has a file on disk, and the bounds are inside the caps (`timeout` 1-60s, `memory_mb` 64-4096, a CPU cap no larger than the wall clock; outside them 400 `invalid-sandbox`).  The shipped runner is `bwrap` invoked with `--unshare-all`, `--die-with-parent`, `--new-session`, `--clearenv`, the host root read-only, fresh `/proc` and `/dev` and exactly one writable directory; the sample is bind-mounted read-only inside it and never executed from its stored path, the caps are applied by the shell's `ulimit` (not `preexec_fn`, which Python documents as unsafe in a threaded server), and a run that outlives its timeout is killed by process group.  A third party registers another runner through the `reportal.sandbox_runners` entry-point group.  The report is the runner, the exact argv, the caps, the exit status, the duration, bounded stdout/stderr tails and the files the sample wrote, stored in `sandbox_runs` as one journaled action (revert removes the record).  This is *not* a safe-execution product: no seccomp filter, no syscall tracing, no VM, and `docs/THREAT_MODEL.md` states each residual in full; the guarantee is that reportal runs nothing until an operator says so, in a sandbox that is installed, capped and unnetworked. |
| Auth / teams | Implemented (off by default) | local (`users`, `teams`, `team_members`) | Bearer-token auth is off until `REPORTAL_AUTH` or `[auth] required = true`, so an existing loopback install keeps answering every request as the local operator (`docs/THREAT_MODEL.md` states the boundary).  When it is on every `/api` route sits behind `Authorization: Bearer <token>`, compared in constant time against a stored SHA-256 digest, and `reportal serve --host` refuses a non-loopback bind unless the gate is on and an enabled user exists.  `reportal user-add <name> [--role viewer\|analyst\|admin]` prints a token once, `user-token`/`user-edit`/`user-rm`/`users` are the rest of the management, `teams`/`team-add`/`team-rm`/`team-member` own the teams, and `binary-scope`/`collection-scope` set an object's visibility (`public` or `team` plus an owner team) for `server._enforce_scope` and `auth.visible_clause`, the SQL rule the listings, the search and the bulk guard share.  `reportal activity [--actor] [--since]`, `feedback` and `feedback-add` are the identity-side reads, every journal entry records the `actor` the server set around the request, and the SPA Users view manages users, teams, scopes and the secret store.  This is bearer-token single-sign-on-free auth: no OIDC, no domain verification and no hosted credits. |
| Firmware | Implemented locally | local (stdlib carving + entropy) | `reportal firmware <binary-id>` and `POST /api/binaries/<id>/firmware` carve a stored image in `firmware.py`: magic-based region detection (a built-in signature table plus the filesystem and container magics), a sampled entropy map per region and a confidence per match, all offline byte work that executes nothing; `GET /api/binaries/<id>/firmware` serves the stored carve (404 `no-scan` before the first run).  `reportal firmware-extract <binary-id> [--region N]... [--collection ID]` and `POST /api/binaries/<id>/firmware/extract` carve the named regions out as binaries of their own and register them into one collection, unpacking a gzip, tar or zip region through the archive reader and storing the rest as raw members, all as one journaled action; the read-only `get_firmware_scan` and destructive `run_firmware_scan`/`extract_firmware_regions` MCP tools expose the same.  A squashfs or UBI inode reader is deliberately not written: the carve reports the region and its container magic rather than pretending to list a filesystem it cannot parse. |

## Not applicable locally

These hosted capabilities are out of scope for a local, offline tool:

- **Threat intel / VirusTotal / MalwareBazaar**: no external feed is called;
  Detect is local family matching against a store the analyst curates, and the
  one remote pull there is (the `external-sources` row's guarded VirusTotal
  lookup) is off until the workspace opts in and a key resolves.
- **Example analyses** (`/v3/analyses/examples`): the hosted portal ships a
  vendor-curated sample corpus for a hosted tenancy to browse before uploading
  anything.  reportal registers only binaries the analyst supplied and bundles
  none, so a "local example" would be a test fixture pretending to be product
  content.  `reportal import-rebrew <project-dir>` and `reportal add-binary`
  are the ways a first analysis is created, and the analyses view says so on an
  empty store.

Three capabilities that used to be listed here are shipped, with only the
hosted-specific part of each left open:

- **Sandbox detonation** (the `Dynamic execution` row above): a local runner
  installed on the host, not a VM or a hosted service.  reportal ships no seccomp
  filter and no syscall log, so syscall-level depth and containment stronger than
  namespaces are the runner's and the operator's.
- **Auth, teams and the object scope** (the `Auth / teams` row above): users,
  roles, digest-only tokens, teams, team roles, organisations and the
  per-object visibility all exist.  What is not built is single sign-on against
  an external OIDC identity provider with DNS domain verification, which needs a
  hosted identity provider to talk to.
- **Firmware carving** (the `Firmware` row above): magic-based detection,
  entropy mapping, region extraction and archive unpacking are local.  A
  squashfs or UBI inode reader is deliberately not built, because the carved
  regions already register as binaries and an inode reader is a filesystem
  implementation rather than portal parity.

## Not built

Optional items that are not implemented:

- **The hosted portal's model-driven software types this evidence cannot name** (Trojan, Backdoor, Spyware, Worm, Adware, Rootkit). reportal's classifier is limited to the types its static evidence distinguishes; it names no type rather than guessing one.
- The full DIE signature database. Detection is bundled as the curated
  `filetypes.SIGNATURES` table over data reportal already fetches; the engine's
  own toolchain detection still uses an external `diec` when one is installed,
  and the local table is a curated subset, not the complete DIE database.
- **A reconstructed re-run from the stored rows, partly.** A scan records the
  inputs the caller named (`scans.params_json`: a decompiler and its limit, a
  severity floor, a confidence floor, the other binary of a comparison, the
  scope of a related-binary run, whether a narrative was asked for), and
  `GET /api/binaries/<id>/scans`, `reportal scans <binary-id>` and the read-only
  `list_scans` MCP tool report them, so the engine call behind a stored scan can
  be replayed with the same parameters through the per-scan POSTs.
  `POST /api/analyses/<id>/requeue` still only moves the lifecycle row back to
  `pending`, clears the finish time and logs the transition, and the caller
  queues the work it wants (`POST /api/jobs` with a scan kind): reportal does
  not re-dispatch a stored scan by itself, because a scan whose producer needs
  the engine, the project context or the LLM would be a different run from the
  one recorded, and saying so is better than a replay that quietly differs.

## Gap inventory

Measured against the live RevEng.AI surface, not against a memory of it.  Three
sources, all re-runnable:

| Source | What it gives | Where |
|--------|---------------|-------|
| OpenAPI 3.1 spec, **v4.34.0** | 158 paths, 190 operations, 20 tags | `https://docs.reveng.ai/openapi.json` |
| Hosted MCP server | 36 tools, 9 destructive | `https://api.reveng.ai/mcp/` (`tools/list`) |
| Open-source survey | what is portable, what is not, and the API/auth facts | `docs/REVENGAI.md` |

reportal's own surface for the comparison is its FastAPI schema (238
paths, 331 operations) plus the MCP tool registry (252 tools).  Every row below is
a capability the hosted spec has and reportal does not, with the hosted
operations that prove it.  Batching is by cluster, not by route: one cluster is
one vertical slice (store, API, CLI, MCP, SPA, tests, docs).

The clusters below come from the published spec.  A live crawl of the
authenticated portal UI found surfaces the spec does not carry at all (debug
symbols, teams and organisations, credits, the secret store, the in-app
documentation site); those are [TODO.md](TODO.md), which also indexes the open
clusters here.

### A. Asynchronous operation workflow (hosted `Agent` tag, 35 operations)

**Status:** Closed for the operations reportal has, with its two ceilings stated.
`jobs.py` holds the `jobs` table (kind, target, status, progress, message, the
submitted params, the result or the error, and the times) and `JOB_KINDS`, whose
entries wrap the scan runner the matching route already calls, so a queued
scan is journaled through the same `journal.journaled_scan` and is revertible
exactly like a synchronous one.  `POST /api/jobs` queues one and answers `202`
with its run id, the bounded background pool (two workers, switched off with
`REPORTAL_JOBS_POOL`) drains the queue, `GET /api/jobs` and `GET /api/jobs/<id>`
report status and progress, `POST /api/jobs/<id>/cancel` cancels what has not
started, `GET /api/jobs/<id>/events` streams the state as server-sent events,
and `reportal jobs`/`job`/`job-submit`/`job-run`/`job-cancel`, the `list_jobs`,
`get_job`, `submit_job`, `cancel_job` and `run_jobs` MCP tools and the SPA Jobs
view expose the same.  The queued form of a scan is `POST /api/jobs` with its
kind rather than a flag on each scan route, which is one route for every
operation in the registry: the eight scans, the engine report, the PDF,
function matching, which is the longest operation the portal runs (it scores
every function against the corpus) and takes the match settings as its
`params`, and `ai-enrich`, the AI enrichment chain over a
binary's functions, which takes a `limit` or a `function_ids` list and stores one
pipeline run per function.

Two ceilings are deliberate and stated rather than hidden.  A job is one step
(`steps_total` is 1, so `progress` is 0 or 100): the engine calls a scan makes
cannot be interrupted, so there is nothing finer to report, and the hosted
agents that decompose into many steps are not ported.  The two exceptions are
kinds whose loop is reportal's own: `match`
reports one step per source function (`steps_total` is the function count,
`progress` the share scored), written at most every `jobs.PROGRESS_REPORT_EVERY`
functions so the row does not
cost more than the scoring, and `ai-enrich` reports one step per function of the
batch, where one step is a whole composition and several model calls rather than
one call.  And cancelling a
`running` job is refused with 409 `job-not-cancellable` rather than faked: the
scan has already entered the engine, and reporting a stop that would not happen
would leave a result written after the client was told it had stopped.

Every long-running hosted capability is queued and polled: `POST
/v3/analyses/{id}/crypto-scan:run`, `.../execution-scan:run`,
`.../filesystem-scan:run`, `.../networking-scan:run`, `.../security-scan:run`,
`.../agents/rename-unnamed-functions`, `/v2/analyses/{id}/agent/triage`,
`.../agent/capabilities`, `.../agent/remediation`, `.../agent/report-analysis`,
each with a `GET .../status`, a result read (`GET /v3/operations/<kind>/<id>`)
and a cancel (`POST .../:cancel`).  Locally the same work is one `jobs` row
submitted with the operation's kind (`POST /api/jobs`), drained by the bounded
pool the API starts at the first submit or by `reportal job-run`, and read
through `GET /api/jobs` and `GET /api/jobs/<id>` (status, progress, result,
error), `reportal jobs`/`job`/`job-submit`/`job-run`/`job-cancel` and the
`list_jobs`, `get_job`, `submit_job`, `cancel_job` and `run_jobs` MCP tools.  A
scan's own POST route stays synchronous rather than growing a `queued` form, so
one mechanism decides what a queued operation is; `GET /api/jobs/<id>/events`
streams a job's state changes as server-sent events, and the hosted agents that
decompose into many steps are not ported.

### B. AI decompilation as a first-class artifact (hosted 18 operations)

**Status:** Closed.  `src/reportal/ai_decomp.py` stores the whole artifact as one
`ai_artifacts` row of kind `ai-decompilation`, so it is journaled and revertible
through the same generic row-restore path the four flat artifacts use and is
snapshotted by the binary and analysis delete plans that already name that
table.  The hosted `agents/rename-unnamed-functions` operation is the one that
reportal composes rather than ports: the pipeline's `rename-variables` stage
runs the same `renames` suggestions over the stored decompilation inside a
composition that rewrites first and summarizes the renamed result after, and
`pipeline.run_pipeline_batch` (the `ai-enrich` job kind) is the whole-binary
form, one stored run per function.

`POST /api/functions/<id>/ai-decompilation` asks the configured bridge for a
complete rewritten function over the decompilation reportal already stored (a
function without one is the same 404 `no-decompilation` the other AI artifacts
answer) and stores, beside the rewrite and the model, the placeholder token map,
the per-line attributions, the analyst overrides, the rating and the line
comments.  The read routes are `GET .../ai-decompilation` (the rewrite rendered
with its overrides), `.../status` (counts, rating and model, without its text),
`.../events` (server-sent events), `.../tokens`, `.../rating` and
`.../inline-comments`; the write routes are `PATCH .../overrides` (a null name
clears one), `PATCH .../rating` and the per-line `POST`/`PATCH`/`DELETE
.../inline-comments[/<line>]`, which is the hosted `{line}` contract with no id
of its own: one comment per line.

Three derivations are local and deterministic rather than model-reported, and
every response that carries one says so under `derivation`:

- the token map is a regular-expression scan of the rewrite for the placeholder
  shapes the decompilers emit (`local_8`, `param_1`, `uVar2`, `DAT_...`,
  `FUN_...` and the rest), each token with its kind, its use count and its line
  numbers (bounded at `MAX_TOKEN_LINES`, the true count kept);
- an attribution is a `difflib` line diff of the rewrite against the
  decompilation the model read: a line that matches one in the source is
  `original`, an aligned line that differs is `rewritten`, and a line with no
  counterpart is `added`, each block carrying the source line numbers it paired
  with;
- the served code applies the stored overrides at read time and never mutates
  the model's rewrite, so clearing an override restores the model's own words by
  construction.

`reportal ai-decompile`, `ai-decompilation`, `ai-decompilation-status`,
`ai-tokens`, `ai-lines`, `ai-override`, `ai-rate`, `ai-line-comments`,
`ai-line-comment-add`, `ai-line-comment-edit` and `ai-line-comment-rm`; the
`run_ai_decompilation`, `get_ai_decompilation`, `get_ai_decompilation_status`,
`list_ai_decompilation_tokens`, `get_ai_line_attributions`,
`set_ai_decompilation_overrides`, `rate_ai_decompilation`,
`list_ai_line_comments`, `add_ai_line_comment`, `update_ai_line_comment` and
`delete_ai_line_comment` MCP tools;
and the function detail's AI decompilation panel, which renders the rewrite line
by line with its origin, edits an override per token, sets the rating and stores
per-line comments.

Two ceilings are stated rather than hidden.  The workflow is one model call, so
`.../events` reports the state it finds and its terminal marker instead of
narrating progress the call does not have, and a rewrite in flight cannot be
cancelled.  The hosted tokens endpoint is a model-reported analysis of what each
placeholder means; reportal's is a local scan plus the analyst's overrides.

### C. Dynamic execution and sandbox detonation (hosted `Analyses - Core`)

**Status:** Closed.  Both halves shipped: firmware carving and extraction, and
the opt-in sandbox detonation.

`src/reportal/firmware.py` finds the embedded images in a stored blob by their
magics (across read boundaries, with a fixed-offset ext superblock checked at
the file's start), reports each region's offset, size, kind, confidence, entropy
and truncation, samples the entropy map, and stores the pass as the `firmware`
scan.  `api.firmware_extract_binary` carves the regions out in one journal
action: a gzip (trimmed to the extent zlib reports), tar or zip region is
unpacked by `reportal.archive` and its members registered, every other region is
stored as a binary of its own.  `reportal firmware`/`firmware-extract`,
`POST|GET /api/binaries/<id>/firmware`, `POST .../firmware/extract`, the
`get_firmware_scan`, `run_firmware_scan` and `extract_firmware_regions` MCP
tools and the binary detail's Firmware
panel expose it.  Nothing is executed, mounted or spawned, and no external tool
is called: this is byte work over bytes reportal already stored.

The sandbox half is shipped too, and it is the one path in reportal that
executes anything: `src/reportal/sandbox.py` plus `sandbox.detonate_binary`
run a stored sample under `bwrap` with `--unshare-all` (network, PID, mount, IPC
and UTS namespaces), a read-only root, one writable directory, `ulimit` caps and
a wall-clock timeout, and record the report in `sandbox_runs` as one journaled
action.  The four guards (opt-in, installed runner, file on disk, bounds inside
the caps), the surfaces (`reportal sandbox`, the four routes, three MCP tools,
the binary detail's Sandbox detonation panel) and the residuals
(`docs/THREAT_MODEL.md`: a shared kernel, no seccomp, `RLIMIT_AS` is address
space not RSS, an unaudited external runner, a run recorded rather than undone)
are written out there.  A third party adds a runner through the
`reportal.sandbox_runners` entry-point group.

**Status:** Closed.

`GET /v2/analyses/{id}/dynamic-execution/report` and `.../status`: the hosted
portal detonates the sample and reports what it did.  reportal reads bytes and
never runs a sample (`docs/THREAT_MODEL.md` states that as a guarantee), so this
is the largest single gap and the one that moves the trust boundary.  The local
form is a sandbox run with no network, a read-only root, a separate PID and
mount namespace, a wall-clock and memory cap, and a recorded report: process
tree, opened files, writes, sockets attempted, exit status and a stdout/stderr
tail.  Off by default, refused unless the workspace opts in, and refused
outright when no sandbox runner is installed.  Firmware detonation reuses the
same runner over a carved member (`docs/REVENGAI.md` notes `mal_unpack` is
Windows-only and orthogonal; the local runner is the general case).

### D. Analysis lifecycle (hosted `Analyses - Core`, 32 operations)

**Status:** Closed.  End to end over the tables that already existed (no new
table):

- reading one analysis (`GET /api/analyses/<id>`), its lifecycle
  (`.../status`, with the scan and log counts by status and severity) and its
  recorded parameters (`.../params`: the engine label, the binary's identity and
  content hash, the rebrew project context and the scans already stored, which
  is what makes a re-run reproducible rather than guessed);
- the function map (`.../func-maps`, ordered by address);
- the import stubs with their callers
  (`GET /api/analyses/<id>/imported-functions`): every function the importer
  labelled `import` (`store.IMPORTED_NAME_SOURCE`), each with the functions
  whose stored decompilation mentions its name, the true `caller_count` beside
  the bounded list and `caller_method` naming the derivation, because reportal
  stores no call graph and a text match is reported as one;
- the raw bytes (`GET /api/analyses/<id>/bytes`), streamed by the same helper
  the binary download uses, so a caller holding only an analysis id needs no
  second lookup;
- its tags (`GET|PATCH .../tags`), which locally are the owning binary's tags,
  the only scope reportal has, journaled link by link;
- the engine relabel (`PATCH /api/analyses/<id>`), a log append
  (`POST .../logs`) and a requeue (`POST .../requeue`), each journaled and
  revertible (a requeue revert restores the status, the finish time and the log
  entry it added);
- bulk delete and bulk tag (`POST /api/analyses/bulk`, the hosted `PATCH
  /v2/analyses/delete` and `/tags/add`): one action over a bounded analysis id
  list, one journal action, and a per-id result where an unknown id is skipped
  `not found` and a binary's only analysis while it holds functions is skipped
  `only analysis with functions` (the same refusal the single delete makes,
  because the cascade would take the function table with it).

`reportal analysis`/`analysis-update`/`analysis-log`/`analysis-requeue`/
`analysis-tags`/`imported-functions`/`analysis-bulk-tag`/`analysis-bulk-delete`
and `reportal download --analysis`, the `get_analysis`,
`get_analysis_params`, `get_analysis_func_maps`, `get_imported_functions`,
`update_analysis`, `append_analysis_log`, `requeue_analysis`,
`set_analysis_tags` and `bulk_analyses` MCP tools and the analyses view (the log drawer with the lifecycle, the
imported functions and the raw bytes, plus the selection checkbox and the Bulk
actions panel) expose the same.

The one hosted read that stays out is example analyses, which is not applicable
locally with the reason in that section above.

### E. Collections (hosted 16 operations)

**Status:** Closed.  The store layer (`get_collection`,
`update_collection`, `delete_collection`, `collection_binaries`,
`collection_tags`, `replace_collection_binaries`, `set_collection_tags`), the six
HTTP routes, the seven CLI commands, the seven MCP tools and the SPA detail
panel are implemented and tested (68 tests across `tests/test_collections_api.py`
and `tests/test_collections_cli_mcp.py`), each write journaled and revertible and
the new `collection_tags` table cascading with its collection.  The SPA lists,
creates, selects a collection, edits its name/description/scope and tags, adds
and removes members and deletes it behind an inline confirm, and the list sorts
by id, name, member count, last change (`collections.updated_at`, touched by
every write that changed something) or owning team through `?order=`, filters by
scope (`?workspace=personal|team|public` over the collection's own
`visibility`/`owner_team_id`, which every row reports beside `owner_team_name`)
and keeps both in the route hash.  The hosted portal's owner column, its
Personal/Team/Public filter and its sort by owner are the three pieces of that
page reportal did not have.

### F. Users, auth and IAM (hosted 5 operations)

**Status:** Closed.  Shipped: local identity, roles, teams, the object scope and
the activity and feedback surfaces.

- users, roles and bearer tokens (`src/reportal/auth.py`, the `users` table):
  `viewer` reads, `analyst` reads and writes, `admin` also manages users, with
  the permission sets declared once in `auth.ROLE_PERMISSIONS` and the
  permission one request needs derived from its method and path
  (`auth.required_permission`).  Only a token's SHA-256 digest is stored
  (`auth.hash_token`) and the token is 256 bits of `secrets.token_urlsafe`
  randomness, shown once by the call that created or rotated it; comparison is
  `hmac.compare_digest` and a disabled user never authenticates.
- `GET /api/iam/me` and `.../permissions` answer the hosted `iam/me` pair: the
  auth mode, the caller, its role and the permissions that role carries; with
  auth off the caller is the local operator and the answer says so.
- the user surface the hosted `users/{id}` read implies: `GET /api/users`,
  `POST /api/users` (201 with the token once), `PATCH /api/users/<id>`,
  `POST /api/users/<id>/token` and `DELETE /api/users/<id>`, every write
  journaled and revertible, and never a digest in a response.
- the gate itself: the `server._reportal_headers` middleware calls
  `server.authenticate`, so every `/api` route is behind it and a route added
  later cannot opt out.  Auth is
  armed only by `REPORTAL_AUTH=required` or `[auth] required = true`, so a
  loopback install keeps working unchanged, and `reportal serve --host` refuses
  a non-loopback bind unless the gate is armed and an enabled user exists
  (`cli._require_lan_auth`).
- teams and the team-as-owner scope (`src/reportal/auth.py`, the `teams` and
  `team_members` tables): `GET|POST /api/teams`, `GET|PATCH|DELETE
  /api/teams/<id>`, `POST /api/teams/<id>/members` and `DELETE
  /api/teams/<id>/members/<user_id>`, every write journaled and revertible, and
  a team delete that returns the objects it owned to the workspace rather than
  orphaning them.  A binary or a collection carries `visibility` (`public` or
  `team`) and `owner_team_id`, set through `PATCH /api/binaries/<id>/scope` and
  `PATCH /api/collections/<id>/scope`.
- the per-object enforcement that scope needs: `server._scoped_object` resolves
  the object a path names (eleven kinds through their owning binary, the object
  a team actually owns), a non-member's read is the object's own 404 rather
  than a disclosure, a non-member's write is 403 `scope-forbidden`, and because
  the check lives in the middleware a route added later is covered without
  repeating it (`tools/audit_scope.py`, run by `make lint`, fails a new
  object-id route without coverage).  The listings, batch reads, scoped
  listings, searches, feeds and series filter their pages by
  `auth.visible_clause`, the corpus operations score only visible binaries, and
  a bulk action skips the ids outside the caller's reach with the reason `not
  permitted`.
- `reportal users`/`user-add`/`user-token`/`user-edit`/`user-rm`,
  `reportal teams`/`team-add`/`team-rm`/`team-member`/`binary-scope`/
  `collection-scope`, the `list_users`, `add_user`, `rotate_user_token`,
  `update_user`, `delete_user`, `list_teams`, `create_team`, `delete_team`,
  `add_team_member`, `remove_team_member`, `set_binary_scope` and
  `set_collection_scope` MCP tools and
  the SPA (the Users view with its identity block, the browser's bearer-token
  field, the user table and the Teams panel, plus the Binaries table's per-row
  scope select) expose the same.  `docs/THREAT_MODEL.md` records the moved
  boundary and its residual risks.

- the activity feed (`GET|POST /api/users/activity`, the hosted
  `GET /v2/users/activity`): **derived, never stored**.  `src/reportal/activity.py`
  merges one item per journaled action, each carrying the `actor` the server
  recorded the request for, with one item per analysis-log entry, newest first
  with the true total, `?actor=`/`?since=`/`?limit=`/`?sources=` filters and the
  `actors` that actually appear.  The actor comes from a `journal_entries.actor`
  column (`journal.acting_as`, set by `server.authenticate` around the request:
  the user's name, `local` while auth is off, empty for a CLI or MCP write), so
  the journal is attributable as well as revertible.
- local feedback notes (`POST|GET /api/users/feedback`, the hosted
  `POST /v2/users/feedback`): the one stored identity-side row, attributed to the
  authenticated caller, bounded at `store.MAX_FEEDBACK_CHARS` (400
  `invalid feedback`), journaled and revertible.
- `reportal activity`/`feedback`/`feedback-add`, the read-only `get_activity` and
  `list_feedback` MCP tools plus the destructive `add_feedback` and the SPA Users view's Activity panel with its
  actor select and feedback form expose the same.  Both new paths are
  self-service (`auth._SELF_PATHS`): an analyst reads its own activity and writes
  its own note without an admin role, while `/api/users` stays admin-only.

- the secret store (`GET /v2/secret-store`, the settings **API Key** tab): the
  spec does not carry it, the crawl did, and it is now shipped rather than
  planned.  `secret_store.py` holds one credential per `(name, scope, team_id)`
  at workspace or team scope; a read returns the name, scope, byte length and a
  last-four hint and never the value, `PUT`/`GET`/`DELETE /api/secrets[/<name>]`,
  `reportal secrets-list`/`secrets-set`/`secrets-rm`, the `list_secrets`,
  `set_secret` and `delete_secret` MCP tools and the SPA Users view's Secrets
  panel expose it, every write is journaled and revertible, and the bridge reads
  its key from the store when neither the environment nor `reportal.toml` has
  one.  cluster H's external source reads the same way.  `docs/TODO.md` entry 3
  is the record.

**Status:** Closed.  Organisations, groups and per-team roles are hosted
structure this model deliberately does not carry; `docs/TODO.md` entries 2 and 5
record exactly what is left there.  The hosted `GET /v2/users/{id}` single-user
read is covered by the list.

### G. Models (hosted 1 operation plus analysis parameters)

**Status:** Closed.  `src/reportal/models.py` is the registry and the upgrade.

`GET /api/models` lists every model this install can produce a stored result
with: the `rebrew` engine (kind `engine`, with the installed version), each
decompiler backend (`decompiler`), the configured bridge model (`llm`, or the
single `unconfigured` entry when no endpoint is set) and the optional
similarity extra (`similarity`).  Each entry carries its kind, version, an
`available` flag and, when it is not, a fixed reason.  `reportal models` and
the read-only `list_models` MCP tool serve the same payload, and the SPA's
Models view tabulates it.

An analysis records the model that last produced its artifacts: a `model`
column on `analyses`, written by the upgrade, and every stored AI artifact
already carries the `model` that produced it (`ai_artifacts.model`), which is
where a per-artifact model lives rather than a second copy on each scan row.
A scan that ran the engine records the analysis's engine label, so the
producer of a non-LLM scan is the analysis's own model; the closed status says
so instead of inventing a column.

`POST /api/analyses/<id>/upgrade` (body `{"model", "functions"?, "limit"?}`),
`reportal models`/`analysis-upgrade` and the destructive `upgrade_analysis_model`
MCP tool re-run the analysis's *stored* LLM artifacts (a summary, inline
comments, type suggestions, identifier renames) under the named `llm` model.
Every artifact replaced is journaled with its inverse, so the returned action
keeps the before/after pair and a revert puts the previous payloads back; a
function whose re-run fails is reported in `skipped` with its reason and keeps
its stored artifact, so one bad response never strands a half-upgraded
analysis.  The candidate set is bounded by `DEFAULT_UPGRADE_LIMIT` 25 /
`MAX_UPGRADE_LIMIT` 200, and an explicit `functions` list overrides the bound.
A model of another kind is 400 `invalid model`, an unknown name 404
`model not found`, and an unconfigured bridge 503 `llm-unavailable`.

One ceiling is stated rather than hidden: the hosted upgrade re-analyses the
binary on a newer model, and reportal cannot.  The upgrade re-runs the LLM
artifacts and never re-analyses, which is what its `note` field and the CLI
output both say.  The registry caches its built-ins the way every other plugin
registry does, so a process that configures an endpoint after its first
registry read calls `models.refresh_models()` (the other registries' `refresh_*`
pattern); the routes read the registry per request, so a configured install
sees the right entry.

### H. External sources (hosted 3 operations)

**Status:** Closed.  `src/reportal/external.py` is the source registry and the
two built-in sources.

The hosted surface pulls VirusTotal data for an analysis (`POST
/v2/analysis/{id}/external/vt`, `GET .../vt`, `GET .../vt/status`).  Locally a
*source* answers one question about one analysis: `GET /api/external/sources`
lists the registry with each source's kind and availability, `POST
/api/analyses/<id>/external/<source>` runs one and stores its answer as the
`external:<source>` scan (a re-pull replaces it, a revert removes it), `GET
.../external/<source>` serves the stored answer and `.../status` reports whether
it can run and what is stored.  `reportal external-sources`/`external`/
`external-status`, the `list_external_sources`, `get_external_report`,
`get_external_status` and `run_external_source` MCP tools (197 tools: 91
read-only, 106 destructive) and the SPA's External view expose the same, and a
third party registers a source through the `reportal.external_sources`
entry-point group in the same shape as every other seam here.

The offline source (kind `offline`, always available) derives its answer from
the rows reportal already holds: the fingerprint, the stored detection families,
the capability tags, the threat report and the secrets-scan count, each reported
as present or absent rather than inferred, so the hosted feature has a local
meaning on an install that never reaches the network.

The remote source (kind `remote`) is VirusTotal, and it is guarded three ways:
the workspace opts in (`REPORTAL_ALLOW_EXTERNAL` or `[external] allow_remote =
true`, the same gate shape `remote_ingest.py` uses), a key resolves first match
wins (`REPORTAL_VIRUSTOTAL_KEY`, then `[external] virustotal_api_key`, then the
secret store's `virustotal.api_key`, which is what the secret store was built
for), and the request itself is bounded: one fixed https host
(`www.virustotal.com`), no file path a caller can control, no redirect followed
(a 3xx is a failure rather than a hop), the body capped at `MAX_BYTES`, a
`FETCH_TIMEOUT_SECONDS` wall clock, and a normalized subset stored (the
per-engine results capped at `MAX_ENGINE_RESULTS`) rather than the whole
response.  A 404 is a *result* ("VirusTotal does not know this file") and is
stored as `found: false`; a 401, 429 or 500 is 502 `external-fetch-failed` and
stores nothing.

The ceilings are stated in the payloads rather than hidden: the offline answer
is reportal's own derivation and says so, the remote one is a third party's
normalized report and says how it was cut, and the offline answer is only as
complete as the scans this workspace has run.

### I. Config (hosted 1 operation)

`GET /v2/config` reports what the hosted instance can do.  reportal had only
`/api/health`, which reports liveness and row counts.

**Status:** Closed.  `instance.describe()` assembles the payload from the
modules that own each value (nothing is duplicated): `version`, the engine's
`available`/`origin`/`backends`/`severities`, the LLM bridge's `configured`
state and model, the database path and table count, the `features` block
(`llm`, `remote_ingest`, `similarity`, `graph_backend`, `graph_backends`,
`auth`, `sandbox`, `external_sources`), 23 entries in `limits` covering every
cap the server enforces, and the MCP tool counts.  `GET /api/config`,
`reportal config` and the read-only `get_config` MCP tool expose it, and the
SPA's Integrations view carries an Instance card.  It is a pure read: no engine
call, no write, no network request, and describing an instance without a
database does not create one (`tests/test_instance.py` pins all three).

### J. Function-level extras (hosted `Functions - Core`, 24 operations)

**Status:** Closed.

The hosted reads over a stored decompilation, and the analyst writes beside them.

- indirect call sites (`GET /v3/functions/{id}/indirect-call-sites`): `GET
  /api/functions/<id>/indirect-call-sites` scans the function's `disasm_cache`
  listing and reports each `call`/`jmp` whose operand is a register or a memory
  reference, with its line, mnemonic, operand text and full instruction.  The
  register vocabulary (`function_extras._REGISTERS`) is what separates `call rax`
  from `call sub_401000`, because both are identifier-shaped.  A function with no
  cached listing answers an empty list with `has_disassembly: false` rather than
  spawning the engine behind a read.
- per-function capabilities (`GET /v3/functions/{id}/capabilities`): `GET
  /api/functions/<id>/capabilities` feeds the imports and quoted literals the
  function's own stored decompilation mentions through
  `capabilities.classify`, the same rule table the binary-level scan uses, so a
  function and its binary cannot disagree about a rule.  The payload reports the
  input counts and `has_decompilation`, so an empty classification is
  distinguishable from an unanalysed function.
- per-function strings (`GET /v3/functions/{id}/strings`): `GET
  /api/functions/<id>/strings` reports the analyst's recorded strings and, under
  their own label, the quoted literals the stored decompilation carries, with the
  note that the derived half is a text scan.  The halves are never merged.
- manual callee edges (`POST /v3/functions/{id}/callees`): `POST
  /api/functions/<id>/callees` (and `DELETE .../callees/<edge_id>`) stores an
  analyst's claim in `function_edges` with `source: analyst`, replacing a row for
  the same `(function, callee, kind)` in place.  `GET
  /api/functions/<id>/callees` reports the declared edges and the names the
  function's text mentions that the binary also stores, separately rather than
  merged, because only the first kind is a human claim.
- name canonicalization over a batch (`POST /v3/functions/canonical-names`):
  `POST /api/functions/canonical-names` renames each function to the candidate
  the store already recorded (a `predicted-name` artifact, else the newest
  recorded rename) and reports a function with neither as `skipped` rather than
  renaming it to a guess.  `apply: false` plans, and every rename goes through
  `journal.journaled_rename`, so one action reverts the batch.
- callees/callers for many functions (`GET /v3/functions/callees-callers`, `GET
  /v2/functions/callees_callers`): `GET /api/functions/callees-callers?ids=1,2,3`
  answers in the caller's order with `found: false` for an unknown id, deriving a
  callee from the function's text and a caller from the other functions' text in
  one pass, and reporting the declared edges beside them.
- matching over an explicit function set (`GET|POST /v3/functions/matches`):
  `GET`/`POST /api/functions/matches` answers the recorded `matches` rows of each
  requested function with the derived `difference` and `band` the
  single-function route reports, under a note saying it runs no scoring and no
  engine.
- analyst-supplied strings per function and per analysis (`POST
  /v3/functions/{id}/user-provided-strings`, `POST
  /v3/analyses/{id}/user-provided-strings`, `PUT /v2/analyses/{id}/strings`):
  `POST`/`GET`/`DELETE /api/functions/<id>/strings[...]`, `POST`/`GET
  /api/analyses/<id>/strings` and `PUT /api/analyses/<id>/strings` store one
  string at a scope or replace a scope's whole list in one journaled action.
  `user_strings.replace_strings` validates every value before writing anything,
  and the journaled form snapshots the rows it replaces and journals the rows it
  creates, so a revert restores the previous list whether the scope held one or
  was empty.

`reportal indirect-calls`, `function-capabilities`, `function-strings`,
`user-string-add`/`user-string-rm`, `analysis-strings`/`analysis-strings-set`,
`callee-add`/`callee-rm`, `callees-callers`, `canonical-names` and
`function-matches`; the `get_indirect_call_sites`, `get_function_capabilities`,
`get_function_strings`, `list_analysis_strings`, `list_function_edges`,
`get_functions_callees_callers`, `get_function_matches`, `add_function_string`,
`delete_function_string`, `replace_analysis_strings`, `add_function_edge`,
`delete_function_edge` and `canonicalize_function_names` MCP tools (214 tools:
100 read-only, 114 destructive); and the function detail's indirect-call-site,
capabilities, strings, callees and canonical-name panels plus the analysis log
drawer's strings panel expose the same.

### K. Data types and signatures (hosted 11 operations)

**Status:** Closed.

The editable model, its history and its revert existed; this is the bulk half.

- copying a signature onto many functions (`POST
  /v3/analyses/{id}/signatures/copy`): `POST
  /api/analyses/<id>/signatures/copy` with `{"source_function_id", "targets"}`
  copies the source's return type, calling convention and parameters onto each
  target in one journaled action.  A target that had no signature gets the row
  it needs (`signatures.ensure_signature`), a target that is the source or is
  not in the analysis is skipped with its reason, and every target's previous
  signature and history entry are what a revert restores
  (`surface.journaled_signature_write`).
- bulk create and bulk update of an analysis's data types (`POST|PUT
  /v3/analyses/{id}/data-types`): `POST` and `PUT /api/analyses/<id>/data-types`
  take `{"types": [...]}`, where an entry is a C declaration (or a whole header,
  which `data_types.split_definitions` splits at top-level semicolons) or a
  scan-shaped object.  Each declaration goes through the same parser the structs
  import uses, so a type created here and one imported from the scan cannot
  differ; `POST` creates or updates, `PUT` updates only and skips a name the
  binary does not carry.  The batch is one journaled action
  (`surface.bulk_data_type_definitions`), a created type is deleted by a revert
  and an edited one is restored with its previous members.
- signatures for many functions in one read (`GET /v3/functions/signatures`):
  `GET /api/functions/signatures?ids=1,2,3` answers in the caller's order, with
  `signature: null` for a function that has none and `found: false` for one the
  store does not know, so the two are distinguishable.
- the functions using a data type as its own route (`GET
  /v3/analyses/{id}/data-types/{id}/functions`): `GET
  /api/analyses/<id>/data-types/<type_id>/functions` serves the stored reference
  index for one type of the analysis's binary (the same payload the
  `/api/data-types/<id>/references` route serves, so the two cannot disagree).

`reportal signature-copy`, `data-types-import` (with `--definition`, `--file`
and `--update-only`), `signatures-batch` and `data-type-functions`; the
`copy_signature`, `import_type_definitions`, `get_signature_batch` and
`get_data_type_functions` MCP tools (252 tools: 120 read-only, 132 destructive);
and the signature panel's copy control plus the data types panel's declaration
box (create or update) expose the same.

### L. Agentic conversations (hosted 7 operations)

**Status:** Closed.

The hosted conversation is an agent run: `GET /v2/conversations/{id}/events`
streams it over SSE, `POST .../cancel` stops it, and `POST .../confirm` approves
or rejects a pending tool confirmation.  A plain reportal turn was one model
call over stored context; a *run* is now the tool loop.

- the tool loop (`POST /api/conversations/<id>/runs`, `reportal
  conversation-run <id> "<message>"`): `agent.start` offers the model every tool
  the local MCP registry declares (each one's own input schema, so a plugin tool
  is offered without a second list to keep in step) and runs what it asks for,
  feeding each result back as a tool turn until the model answers in text.  A
  **read-only** tool runs automatically; a tool that changes the workspace is
  matched against `Tool.annotations` and, when it is destructive, pauses the run
  with the exact call it wants to make.  A run is bounded by
  `agent.MAX_TOOL_CALLS` (8), a tool's answer by `MAX_TOOL_RESULT_CHARS`, and the
  message list sent to the model is the conversation's own
  (`conversations.agent_messages`), so an agent turn and a plain turn cannot
  disagree about what the model is shown.
- the confirmation gate (`POST /api/conversations/<id>/confirm`, `reportal
  conversation-confirm [--reject]`): `agent.confirm` runs the pending call or
  feeds a refusal back as a tool result, then continues the loop, so a rejected
  call is answered another way instead of failing the run.  The paused state
  (the message list and the pending call) is stored on the run row, so a
  confirmation works from another process.
- cancel (`POST /api/conversations/<id>/cancel`, `reportal
  conversation-cancel`): `agent.cancel` refuses a terminal run with 409
  `run-not-cancellable` and marks a live one cancelled; the loop re-reads its own
  status at every step boundary, so a call in flight completes rather than being
  half-reported.  That is the same ceiling `jobs.py` states for a running scan.
- the event stream (`GET /api/conversations/<id>/events`, `reportal
  conversation-events`): `agent.events` streams the *run's state*, one frame per
  observed change plus the current one, ending on a terminal status and answering
  a `timeout` frame at the cap.  It is a state stream, not a token stream: the
  model's answer arrives as one event when it is complete.
- the reads (`GET /api/conversations/<id>/runs[/<run_id>]`, `reportal
  conversation-runs`, `conversation-run-status`): every run with its status,
  tool-call count, events, pending call and answer.

The run row and the messages a turn wrote are one journaled action, so a revert
removes both.  A tool the run called carries its own journal action, which the
run's action does not cover: reverting the conversation does not undo a tool's
write, and the payload says so.

`reportal conversation-run`/`conversation-runs`/`conversation-run-status`/
`conversation-confirm`/`conversation-cancel`/`conversation-events`; the
`run_conversation_agent`, `confirm_conversation_run` and
`cancel_conversation_run` destructive MCP tools with the read-only
`list_conversation_runs` and `get_conversation_run` (238 tools: 112 read-only,
126 destructive); and the conversation detail's Agent run panel (the question
box, the event list, the pending call with Approve and Reject, the cancel
control and the answer) expose the same.

### M. Reports (hosted 3 operations)

**Status:** Closed for the workflow, which is what the hosted operations are.

Hosted PDF generation is a workflow: `POST /v3/analyses/{id}/pdf` starts it,
`GET .../pdf/status` reports it and `GET .../pdf` downloads it.  reportal now
answers all three.  `report-pdf` is a job kind, so `POST /api/jobs` queues the
render and answers a run id, `GET /api/jobs/<id>` (or the event stream) reports
it, and `GET /api/binaries/<id>/report/pdf/status` reports the file and the
newest job together while `GET /api/binaries/<id>/report/pdf` downloads it.  The
route, the CLI and the queued job all call `jobs.render_pdf`, so the file is
written and journaled once, in one place, and a queued render is revertible
through the journal exactly like a direct one.  The engine's HTML report is a
job kind too (`report`), and `reportal report-pdf --queue`/`--status` plus the
SPA Report panel's Queue PDF control expose the same.

The hosted *report-analysis agent* result beside the PDF is not ported as an
agent: reportal's PDF is a deterministic layout over the stored scans rather
than a model's narrative, so there is nothing for an agent to produce that the
rendered report does not already carry.  The AI narrative that does exist is the
threat report's `narrative`, served beside the deterministic payload.

### N. Binary extras (hosted `Binaries`, 11 operations)

**Status:** Closed.  The password-protected download is closed end to end:
`zipcrypto.py` writes the traditional PKWARE scheme the stdlib reads but cannot
write (deflate member, 12-byte header with the CRC check byte, the three-key
stream cipher, verified by reading the archive back with `zipfile` plus the
password, and refusing a wrong one).  `GET /api/binaries/<id>/download-zipped`,
`reportal download --zip [--password]`, the `export_zipped_binary` MCP tool
and a Zipped link in the binaries
table expose it; the archive is deflated into a spooled temporary file so a
256 MiB binary is never held whole, and the password is documented as a shared
convention rather than a security measure.

The other two reads are closed the same way, as compositions of scans reportal
already stores rather than as engine calls (`details.py`):

- `GET /api/binaries/<id>/die-info` (the Detect-It-Easy shaped identity) with
  `reportal die-info` and the read-only `get_die_info` MCP tool.  The identity
  sits beside the packer, protector, installer, runtime and toolchain matches,
  each carrying the file-type scan's confidence and the signals that matched,
  plus the stored fingerprint's section entropy and the section-table packer
  hint.  `sources` names every input with the command that fills it, so an
  empty category reads as "nothing matched" rather than "nothing ran".  The
  bundled `filetypes.SIGNATURES` table is far smaller than DIE's database, and
  the payload states its own inputs rather than implying a detector it has not
  got.
- `GET /api/binaries/<id>/additional-details` and its
  `/additional-details/status` sibling, with `reportal additional-details
  [--status]` and the read-only `get_additional_details` and
  `get_details_status` MCP tools.  The first reports the overlay measured from
  the file against the stored section table, the Rich header's entry count and
  its build and tool ids, the debug entries, the directory presence flags, the
  counts, the Authenticode summary and the section table's shape; the second
  reports which sources exist and the command that fills a gap, and always
  answers once the binary exists, which is what the hosted asynchronous status
  route is for.

The SPA reads all three from one `DetailCoveragePanel` instead of duplicating
the identity, packer and section panels it already renders, so what is new on
screen is the overlay, the Rich header's shape and the coverage report.

### Beyond parity

Capabilities RevEng.AI advertises but has not shipped, or has no public
implementation of, each with the evidence.  Several are already done here, which
is the point of the list: a local portal can ship what a hosted one has only
announced.

| # | Capability | Evidence that it is not shipped | Status and the local shape |
|---|------------|--------------------------------|-----------|
| 1 | **Malware unpacking** (their "Unpack" agent: "unpack encrypted malware") | a "Coming Soon" card with a disabled Generate button in the portal's upcoming-agents list, and no run, status or result endpoint in either spec (`portal.reveng.ai/_next/static/chunks/1hp6wi67r3bhm.js`; changelog PRO-3218) | Done: `unpack.py` identifies a packer from the file's own stub, rebuilds the image (the engine's `lzexe` case in process, the external `upx` tool for UPX) into the workspace as a new binary, and stores that binary's provenance as its `unpack` scan |
| 2 | **Cross-architecture symbol matching** | "We will be releasing a cross-architecture model to match symbols between architectures in Q3 2026" (`reveng.ai`) | match across architectures locally by scoring the stored listings instead of a shared model, with the ISA pair recorded on every row |
| 3 | **Ventris architecture and language coverage** | "we are also planning to release a version of Ventris in the coming months that provides wider architecture support"; "expanding language coverage to Rust and Go, and supporting additional architectures such as MIPS, PowerPC, and RISC-V" (`reveng.ai/blog/introducing-wilbert-and-ventris`) | reportal already reads whatever the engine can decompile; the addition is recording the language and ISA per artifact so a coverage gap is visible instead of silent |
| 4 | **MCP destructive annotations on every writer** | 27 of the hosted server's 36 tools mutate state but only 9 carry a destructive marker (`docs.reveng.ai/mcp`) | Done: all 252 local tools carry `readOnlyHint` or `destructiveHint`, and a test pins the split |
| 5 | **Lineage, Obfuscation, Anti-Analysis and Detect agents** | all four are "Coming Soon" cards with no endpoint (`portal.reveng.ai/_next/static/chunks/1hp6wi67r3bhm.js`) | Done: `lineage.py`, `hardening.py` (anti-analysis and obfuscation domains), `families.py` (detect) and the job queue that records each run |
| 6 | **A public changelog for the API** | every error resolution points at `docs.reveng.ai/changelog`, which 404s, and `NOT_IMPLEMENTED` (501) tells the caller to check a page that does not exist (`docs.reveng.ai/errors`) | Done: `CHANGELOG.md` is served by the in-app documentation view and `GET /api/docs`, `docs/ERRORS.md` documents every code, and a test asserts it |
| 7 | **A capability manifest generated from the code, with a drift check** | their plugins carry `.revengai/features.json` and a features-drift workflow; the portal publishes nothing equivalent | Done: `GET /api/config` publishes the features, limits and every plugin seam with its parts, and a test pins the numbers against the registries |
| 8 | **HTTP message-signature auth in the SDKs** | `export type HttpSignatureConfiguration = unknown; // TODO: Implement` (`sdk-typescript/auth/auth.ts`) | Open: local token auth carries a bearer token over TLS-less loopback, so body signing buys nothing an attacker on the loopback already has.  Recorded rather than built. |
| 9 | **The documented-but-missing client flags** | `reait`'s README documents `-n` (ANN search), `--symbol`, `--start-vaddr`, `--image-base`, `-C` (open-source component identification) and "YARA++" signatures; none exist in its argparse parser, and `api.py` never calls its ANN or SBOM functions (`github.com/RevEngAI/reait`) | Done: the equivalents are answered by the typed search, the families store, the data-type model and the remediation rules, and the SBOM is `library.py` plus `GET /api/binaries/<id>/sbom`, which renders the stored library identification as CycloneDX, SPDX or CSV. |
| 10 | **Public limits** | no pricing, tier or rate-limit page exists (`reveng.ai/pricing` 404s; only `TOO_MANY_REQUESTS` with `Retry-After`) | Done: `GET /api/config` publishes every cap in force, and `docs/API.md` names each one |
| 11 | **VeriDecomp as a product surface** | "we are developing an internal benchmark called VeriDecomp" (`reveng.ai/blog/introducing-wilbert-and-ventris`) | Done: `benchmark.py` scores a match run against labelled counterpart addresses (a corpus file, or the two binaries' shared real names) and reports precision, recall, F1, mean reciprocal rank and every miss, stored as the left binary's `benchmark` scan; `benchmark.rename_report` scores the stored rename proposals against the names an ingested debug symbol file supplied (precision, recall, F1, every disagreement and every missed symbol).  Both are reachable from `reportal benchmark`/`reportal rename-benchmark`, the `/api/binaries/<id>/benchmark` and `/rename-benchmark` routes, the `run_benchmark` and `get_rename_benchmark` MCP tools and the Benchmark panel. |
| 12 | **WilBERT, Ventris and "Mega Bite" as usable models** | the names appear in their blog and FAQ but **not** in either API spec; the model enum carries only `binnet-0.7` variants | Done: the model registry records any model an artifact was produced with, including a local one, so a reportal install can point at what it has |

Effort is S (hours), M (a day or two), L (a week or more) for a vertical slice
with tests.  Rows 2 and 3 are shipped: 2 is the match settings' platform and
architecture scope (`MatchSettings.platforms`/`architectures` and the coarse
best-effort comparison `scope_notes` states), and 3 is the per-artifact model
and name-source provenance records (the model registry, the data-type source
labels and the symbols reader's `symbol` source).

Row 8 stays open on purpose, with the reason stated in its row, and it is not
a capability the hosted portal ships, so it is neither a parity gap nor tracked
in `docs/TODO.md` (no crawl entry asked for one).  Row 11 shipped both halves of
its harness: matching against labelled counterparts, and the stored rename
proposals against the names a debug symbol file supplied.  Row 1
shipped as `unpack.py`: the engine's LZEXE case runs in process, UPX goes
through the external `upx` tool (reportal ships no packer, so a machine without
it answers `no-unpacker` rather than shelling out to nothing), and the rebuilt
image lands in the workspace as a binary of its own with the packed source, the
packer and the method recorded as its `unpack` scan.  Its ceiling is detection:
a packer that rewrites its own stub carries no signature to read, which
`docs/ERRORS.md` states beside the code.

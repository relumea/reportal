# RevEng.AI open-source survey

Survey of the [github.com/RevEngAI](https://github.com/orgs/RevEngAI/repositories) repositories,
plus the live API reference at [docs.reveng.ai/api](https://docs.reveng.ai/api), for techniques,
contracts, and workflows reusable in rebrew and the sibling tooling (`resembl`, `recoverage`,
`recompile`, `relumea`). Swept 2026-09-12 against each repo's default branch and the live service.
The org publishes 17 public repositories, a full OpenAPI spec, and a hosted MCP server.

## Summary

RevEng.AI is a closed-source binary-analysis SaaS (`https://api.reveng.ai`). Its public repos are
clients, editor plugins, and forks for that service. None of the analysis intelligence (function
embeddings, the ANN matching index, the AI decompiler, the LLM agents) runs in the open, so there is
no scoring or matching algorithm to lift. What is reusable is the API contract, the result schemas,
and the client-side synchronization workflows.

Three findings drive the recommendations:

1. **"YARA++ REAI signatures" are a numeric vector, not a YARA dialect.** The service returns a
   fixed-length whole-binary embedding; the only consumer in the repos feeds it straight back into
   approximate-nearest-neighbour binary search. There is no rule grammar, feature extractor, or local
   generator. See [YARA++ and REAI signatures](#yara-and-reai-signatures).
2. **The textual `yara_rule` fields in the SDK are a different feature**: LLM-authored rules from the
   remediation/report agents, opaque and server-side.
3. **The platform ships a hosted MCP server** (`https://api.reveng.ai/mcp/`) with 36 tools, nine of
   them destructive. It is the easiest integration path for agent-driven workflows, and it exposes
   the same black-box intelligence the HTTP API does. See [Hosted MCP server](#hosted-mcp-server).

The strongest adoption candidates are the binary fingerprint bundle (rebrew lacks TLSH/ssdeep/import
hashes), the ranked match result contract for `resembl`, the function-name provenance/rename-history
schema for rebrew metadata, and the AI-decompilation provenance schema for `relumea`.

## Repository inventory

Licenses verified with `gh api repos/RevEngAI/<repo>`.

| Repo | License | Kind | Notes |
|------|---------|------|-------|
| `sdk-python` | MIT | OpenAPI-generated client | v4.20.0; ~179 ops, 566 models. Lags the live spec (v4.34.0). Safe to vendor. No algorithms. |
| `sdk-go` / `sdk-java` / `sdk-typescript` | MIT / MIT / none | OpenAPI-generated clients | Same surface, other languages. |
| `plugin-ghidra` | GPL-3.0 | Ghidra plugin (Java) | Richest client-side sync logic; no local matching. |
| `plugin-ida` | GPL-3.0 | IDA plugin (Python) | Persistent per-IDB cache (netnode KV). |
| `plugin-binary-ninja` | GPL-3.0 | Binary Ninja plugin (Python) | Prefixed search-query grammar. |
| `reai-r2` | none | radare2 plugin (C) | Auto-analyze + interactive asm/decomp diff. |
| `reai-rz` | none | Rizin/Cutter plugin (C++) | Propose-then-confirm batch rename UX. |
| `reait` | GPL-3.0 | Python toolkit/CLI | Thin API wrappers plus cosine ranking. Do not copy (copyleft). |
| `creait` | none | C toolkit | libcurl client; local Levenshtein line diff. All rights reserved. |
| `reait-java` | none | Java toolkit | Incomplete; useful only as an endpoint inventory. |
| `jingle` | MIT | Fork of `toolCHAINZ/jingle` | Stale mirror at v0.1.1, no RevEngAI commits. PCODE to Z3. |
| `ghcc` | none | Fork of `mov0xdecafe/ghcc` | RevEngAI added CMake support + output nesting. Corpus factory. |
| `mal_unpack` | BSD-2-Clause | Fork of `hasherezade/mal_unpack` | Stale at 0.9.9; Windows-only dynamic unpacker. |
| `fairseq` | MIT | Unmodified fork | No RevEngAI changes. |

## YARA++ and REAI signatures

| Claim | Evidence |
|-------|----------|
| Name appears once in prose | "generate **\"YARA++\" REAI signatures** for entire binary files", `reait/README.md:7` |
| Endpoint is `GET /signature/{sha_256_hash}` | `reait-java/.../api/ApiEndpoint.java:14` |
| Response is a float vector, not text | `ReaiApiProxyTest.java:99-105` reads the response as a `JSONArray` of doubles, then posts it to `nearestBinaries(...)` |
| No local generator anywhere in the org | No YARA++ grammar, feature extractor, or rule emitter in any of the 17 repos |

Conclusion: the "signature" is a whole-binary fingerprint vector generated server-side and consumed
for binary-to-binary ANN search. If a rebrew/resembl "signature" feature is wanted, its format has to
be designed locally; there is nothing to reverse from these repos.

`resembl` already ships `export-yara` (`resembl/cli.py:706`, `resembl/core.py:816`), but it emits the
raw assembly text as a literal YARA string (`$asm = "<asm text>" nocase ascii wide`). That is a weak
rule. A real implementation would match binary patterns (unique function byte windows, import and
string IOCs) rather than source text.

## API reference ([docs.reveng.ai/api](https://docs.reveng.ai/api))

The published reference is a live OpenAPI 3.1 document, newer than the vendored Python SDK.

| Item | Value |
|------|-------|
| Full spec | `https://docs.reveng.ai/openapi.json` (626 KB) |
| Server spec | `https://api.reveng.ai/openapi.json` (216 KB, 65 of the 158 paths) |
| Version | v4.34.0 |
| Paths / operations / tags | 158 / 190 / 24 |
| Methods | 116 GET, 51 POST, 14 PATCH, 6 DELETE, 3 PUT |
| Server | `https://api.reveng.ai` (Production) |
| Security schemes | `APIKey` (header `Authorization`), `bearerAuth` |

Operations per tag, from the full spec:

| Tag | Ops | Covers |
|-----|-----|--------|
| Agent | 35 | triage, capabilities, remediation, report-analysis, scan and explain agents |
| Analyses - Core | 32 | upload, create, status, logs, bytes, dynamic execution |
| Functions - Core | 24 | list, details, blocks, callees/callers, strings, indirect call sites |
| Functions - AI Decompilation | 18 | create/get/stream, summary, inline comments, type suggestions, line attributions |
| Collections | 16 | collections, member binaries, tags |
| Binaries | 11 | details, DIE info, related binaries, externals, downloads |
| Data Types | 11 | structs/unions/enums/signatures CRUD plus history |
| Functions - Renaming & History | 8 | rename, batch rename, history, revert, rename-unnamed-functions agent |
| Conversations | 7 | agent conversation runtime, SSE events, tool confirmation |
| Analyses - Comments | 4 | user comments per analysis |
| Analyses - Results & Metadata | 4 | analysis findings and artifacts |
| Search | 4 | functions, binaries, collections, tags |
| Authentication & Users | 3 | login, profile, keys |
| External Sources | 3 | VirusTotal, MalwareBazaar |
| Reports | 3 | PDF generate, status, download |
| Analyses - Bulk Actions | 2 | bulk tag, bulk delete |
| IAM - Users | 2 | account management |
| Analyses - XRefs | 1 | xref lookup by vaddr |
| Config | 1 | platform configuration |
| Models | 1 | available embedding models |

Four tags are declared with **no operations in the public spec**: `Firmware`, `IAM - Organisations`,
`IAM - Teams`, `Identity`. Firmware images are accepted by `POST /v3/upload` (its schema mentions the
"firmware/extraction flow"), but retrieval of unpacked binaries is not public. Treat the advertised
"firmware unpacking" as gated.

Capabilities present in the live spec that the vendored SDK does not cover:

- Scan/explain agents: `POST /v3/analyses/{id}/{crypto,security,execution,filesystem,networking}-scan:run`
  and `POST /v3/functions/{id}/{crypto,execution,networking}-explain:run` / `filesystem-analyse:run`,
  with results under `/v3/operations/{kind}/{id}`. These surface as four extra tags worth reusing in
  rebrew/relumea analysis.
- `POST /v3/analyses/{id}/upgrade-model` (re-analyse on the latest embedding model).
- `GET /v3/analyses/{id}/bytes` (serve binary bytes to a client-side decompiler).
- Edit history plus revert for data types and function signatures:
  `/v3/analyses/{id}/data-types/{dtid}/history`, `/v3/analyses/{id}/functions/{fid}/signature/history`,
  `/v3/functions/{fid}/history/{hid}/revert`.
- A `Conversations` runtime (7 operations) with SSE run events and tool-confirmation gating.

### Error model ([docs.reveng.ai/errors](https://docs.reveng.ai/errors))

Every error response carries a `doc_url`. Generic codes: 400 `BAD_REQUEST`, 401 `UNAUTHORIZED`,
402 `PAYMENT_REQUIRED`, 403 `FORBIDDEN`, 404 `NOT_FOUND`, 405 `METHOD_NOT_ALLOWED`, 406
`NOT_ACCEPTABLE`, 409 `CONFLICT`, 413 `REQUEST_ENTITY_TOO_LARGE`, 415 `UNSUPPORTED_MEDIA_TYPE`, 422
`VALIDATION_FAILED`, 429 `TOO_MANY_REQUESTS`, 500 `INTERNAL_ERROR`, 503 `SERVICE_UNAVAILABLE`, 504
`GATEWAY_TIMEOUT`. Domain codes an integration must handle: 402 `INSUFFICIENT_CREDITS`, 409
`ANALYSIS_NOT_READY` / `RUN_ALREADY_ACTIVE` / `DYNAMIC_EXECUTION_INCOMPLETE`, 401 `TOKEN_EXPIRED` /
`TOKEN_REUSED` / `EMAIL_NOT_VERIFIED`, 404 `NO_ACTIVE_RUN` / `CONVERSATION_NOT_FOUND`, 499
`CLIENT_CLOSED_REQUEST`, 501 `NOT_IMPLEMENTED`.

## Hosted MCP server

| Item | Value |
|------|-------|
| Endpoint | `https://api.reveng.ai/mcp/` |
| Transport | Streamable HTTP, SSE responses |
| Auth | `Authorization: Bearer <token>` (API key or signed JWT) |
| Server info | `reveng-ai-platform` (version `dev`) |
| Protocol | `2025-06-18`, capabilities `logging` + `tools.listChanged` |
| Session | `mcp-session-id` response header; required on later calls |
| Tools | 36, of which 9 are marked destructive |

Verified: `initialize` returns HTTP 200 over `text/event-stream`; `tools/list` returns the 36 tools
below.

| Group | Tools |
|-------|-------|
| AI decompilation | `ai_decompile_function`, `start_ai_decompilation`, `decompile_and_wait`, `get_ai_decompilation_status`, `get_ai_decompilation_summary_status`, `get_ai_decompilation_inline_comments_status`, `regenerate_ai_decompilation_summary`, `regenerate_ai_decompilation_inline_comments`, `get_function_summary` |
| Matching & naming | `get_function_matches_for_analysis`, `get_function_matches_for_functions`, `rename_functions`, `rename_and_verify`, `get_function_history`, `revert_function_name`, `resolve_ids` |
| Analysis & metadata | `get_binary_info`, `get_function_info`, `list_functions`, `read_memory`, `get_capabilities_for_analysis`, `get_triage_analysis`, `get_threat_report`, `get_remediation_rules`, `edit_function_types` |
| Collections | `create_collection`, `get_collection_by_id`, `list_collection_binaries`, `search_collections`, `update_collection`, `update_collection_binaries`, `update_collection_tags`, `delete_collection` |
| Reports | `start_pdf_report`, `generate_pdf_report_and_wait`, `get_pdf_report_status` |

Destructive (mutating) tools: `decompile_and_wait`, `edit_function_types`, `generate_pdf_report_and_wait`,
`regenerate_ai_decompilation_summary`, `regenerate_ai_decompilation_inline_comments`, `rename_and_verify`,
`revert_function_name`, `start_ai_decompilation`, `start_pdf_report`.

The server is self-documenting: tool descriptions encode the intended workflow (for example
`get_function_info` with `include=["types","disassembly","ai_decompilation",...]`, and
`edit_function_types` requiring `get_function_info` first to learn ordinals and data type ids).
`read_memory` (64 bytes default, 1024 cap, virtual address / RVA / file offset) is the local analogue
of rebrew's `asm`/`read` primitives and is read-only.

## Server-side (black box, not reimplementable from the repos)

- Function embeddings and the ANN index (`binnet-0.7`, `binnet-1.0`; per arch/platform variants).
- Match scoring: cosine similarity scaled to a percentage, plus softmax-normalized confidence over the
  candidate pool.
- Name canonicalization, auto-unstrip, rename-unnamed-functions agent.
- AI decompilation (v3): tokens/placeholders, summaries, inline comments, type suggestions, line
  attributions.
- Triage / capabilities / remediation / report-analysis / scan / explain agents, including the YARA,
  Snort, and STIX rule generation.
- Security, crypto, execution, filesystem, and networking scan execution.
- Dynamic-execution sandbox (DRAKVUF), CVE/SBOM lookups, VirusTotal/MalwareBazaar proxying.
- Firmware unpacking (advertised, not in the public spec).
- Collection/binary search ranking.

## Portable findings

Ranked by value-to-effort. Effort: S (hours), M (a day or two), L (a week or more).

| # | Idea | Target | Effort | Evidence |
|---|------|--------|--------|----------|
| 1 | Binary fingerprint bundle: TLSH, ssdeep, import/export/rich-header hashes, function-boundaries hash | rebrew (`analyze` / new `fingerprints`), resembl dedup prefilter | S | SDK binary detail models; rebrew has none of these today (only rich-header parsing in `toolchain_detect.py`) |
| 2 | Match result contract: `min_similarity` floor, `results_per_function` cap, candidate-pool filters, `confidence` (softmax over pool), top-2 margin gate | resembl | S-M | `MatchedFunction` model docs; `reait/src/reait/main.py:83-100` margin logic; resembl has MinHash/LSH but no confidence or margin |
| 3 | Function-name provenance enum plus rename history/revert | rebrew metadata | S | SDK `FunctionSourceType` (SYSTEM/USER/EXTERNAL/AUTO_UNSTRIP/AI_UNSTRIP/AI_AGENT); `/v3/functions/{id}/history/{hid}/revert`; rebrew has rename but no history/revert |
| 4 | Propose, review, apply rename flow: per-row accept, similarity colour bands, never overwrite user-authored names, dedupe, pushback suppression | rebrew (`similar` / `cross-import`) | M | `reai-rz` `RenameConfirmationDialog`; `plugin-ghidra` reconciliation (`:451-499`, `:731-751`) |
| 5 | Crypto scan: name-match functions and callees against crypto-library API tables (documented as AI-free, runs in seconds) | rebrew, relumea | S | SDK `v3_run_crypto_scan`; live `crypto-scan:run` + `crypto-explain:run`; complements `identify-library`/FLIRT |
| 6 | Capability tagging per function/analysis from imports, strings, call edges | rebrew `analyze`, relumea KG | S-M | SDK capabilities agent |
| 7 | SAST over decompiled C: check id, CWE, severity, confidence, snippet | relumea | M | `v3_run_security_scan` (Semgrep-shaped output) |
| 8 | AI-decomp provenance schema: placeholder tokens, resolved entities with confidence/provenance, suggested struct members with holes/origin, line attributions, SSE event contract | relumea KG | M | SDK AI-decomp models; most complete public schema for per-line decompiler trust |
| 9 | Prefixed search grammar (`sha_256_hash:`, `tag:`, `binary_name:`, `collection_name:`, comma lists) | rebrew catalog, resembl | S | `plugin-binary-ninja` `utils/features/matching.py:67-95` |
| 10 | Corpus-build harness: PATH-shadowing mock compiler, one `docker run` per repo batch build, content-addressed outputs, resumable DB | rebrew `tools/corpus_sweep.py`, relumea training data | M | `ghcc/ghcc/compile.py`, `ghcc/scripts/mock_path/`, `ghcc/ghcc/database.py` |
| 11 | Straight-line PCODE/IR to Z3 equivalence as a `prove` fallback where angr path explosion fails | rebrew `prove.py` | M-L | `jingle` relational formulation (`reaches`, `upholds_postcondition`, `branch_comparison`) |
| 12 | Capability manifest generated from code and checked for drift in CI | repo hygiene | S | `.revengai/features.json` + `features-drift.yml` in every plugin |
| 13 | RevEng.AI API as an opt-in candidate source: read-only metadata and names, gated behind rebrew `verify`, never auto-applied | rebrew (opt-in), relumea | S | live spec v4.34.0; auth verified |
| 14 | Hosted MCP server as a tool provider for agent workflows (36 tools) | relumea agents, rebrew agent skills | S-M | `https://api.reveng.ai/mcp/`; `initialize` + `tools/list` verified |

Supporting patterns worth adopting alongside the above:

- Boundary-size join when the remote has no VA match (`plugin-ghidra` `GhidraRevengService.java:226-249`).
- Signature-equivalence short-circuit before applying remote signatures, so repeat syncs are no-ops.
- Debounced per-function edit queue (Ghidra 400 ms, IDA 300 ms) to avoid rename storms.
- Persistent per-program remote-id map so a reopened project does not re-upload (IDA netnode store;
  BinNinja sha256-keyed settings; Ghidra property maps).
- Structured sync summary returned to the user (matched / applied / canonicalized / deduped / pushed).

## Not portable

- All embedding models, the ANN index, and the matching service.
- AI decompilation and the security/report/capabilities/scan/explain agents.
- Dynamic-execution sandbox, CVE/SBOM/VirusTotal/MalwareBazaar integrations, PDF reporting, firmware
  unpacking (not in the public spec).
- `mal_unpack`: Windows-only dynamic unpacking, orthogonal to static byte matching. rebrew already
  covers the DOS/LZEXE case with `lzexe.py`.
- `ghcc` as a drop-in: it is GCC/Linux/ELF, while rebrew builds MSVC and legacy-toolchain PE. Only its
  corpus harness pattern transfers (see item 10).

## Licensing

Copying source is the only binding constraint; calling the HTTP API imposes none.

| Source | License | Can we copy code? |
|--------|---------|-------------------|
| `sdk-python` | MIT | Yes (vendor or reuse) |
| SDKs (`go`, `java`) | MIT | Yes |
| Plugins (`ghidra`, `ida`, `binary-ninja`) | GPL-3.0 | No, would relicense MIT repos |
| `reait` | GPL-3.0 | No |
| `creait`, `reait-java` | none (all rights reserved) | No |
| `reai-r2`, `reai-rz`, `ghcc`, `sdk-typescript` | none | No |
| `jingle`, `mal_unpack`, `fairseq` | MIT / BSD-2 / MIT | Yes, but forks are stale |

rebrew and the siblings are MIT. Everything above except the SDKs must be reimplemented from observed
behavior, not copied.

## API access

Verified 2026-09-12 against the live service.

| Item | Value |
|------|-------|
| Base URL | `https://api.reveng.ai` |
| Auth header | `Authorization: <token>` (a `Bearer ` prefix is also accepted) |
| Local secret | `~/.secrets/reveng.ai`, a bare 65-byte token, mode 0644, not committed. `rebrew-revengai` reads it when the environment variable is unset, so no export is needed on this machine. |
| Preferred env var | `REVENGAI_API_KEY` (never pass the token in argv) |
| Secret-file override | `REVENGAI_SECRET_FILE` |
| SDK | `uv add revengai`; `revengai.Configuration(api_key={'APIKey': os.environ['REVENGAI_API_KEY']})` |
| MCP | `https://api.reveng.ai/mcp/` with `Authorization: Bearer <token>` |

Verified calls:

| Endpoint | Result |
|----------|--------|
| `GET /v2/iam/me` without auth | HTTP 401 |
| `GET /v2/iam/me` with the token | HTTP 200, account `role: USER`, `tier: ENTHUSIAST` |
| `GET /v2/models` with the token | HTTP 200, `{"models": ["binnet-0.7", "binnet-1.0"]}` |
| `GET /v3/functions/matches` | HTTP 400 (requires a request body) |
| `POST /mcp/` initialize | HTTP 200 SSE, `serverInfo.name = reveng-ai-platform`, `mcp-session-id` returned |
| `POST /mcp/` `tools/list` | 36 tools, 9 destructive |

Cost caution: uploads, AI decompilation, scans, and remediations consume account credits; metadata
reads are free. The crypto scan is documented as free and name-based. Do not point rebrew tooling at
the API for anything that uploads a target binary without checking the tier first, and treat the
nine destructive MCP tools as requiring explicit user confirmation.

## Verification log

Commands run on 2026-09-12 (token read from the local secret, never printed):

```bash
gh repo list RevEngAI --limit 200 --json ...
gh api repos/RevEngAI/<repo> --jq '.license.spdx_id'
curl -sS https://docs.reveng.ai/openapi.json         # OpenAPI 3.1, v4.34.0, 158 paths
curl -sS -K - <<'CFG'                                # header via config on stdin, not argv
url = "https://api.reveng.ai/v2/iam/me"
header = "Authorization: <token>"
CFG
curl -sS -X POST -K - <<'CFG'                        # MCP initialize, then tools/list
url = "https://api.reveng.ai/mcp/"
header = "Authorization: Bearer <token>"
header = "Content-Type: application/json"
header = "Accept: application/json, text/event-stream"
data = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\", ...}"
CFG
```

Spec downloads and repo checkouts used for the sweep are scratch
(`rebrew/.scratch/revengai-sweep/`) and are not part of the tree.

## Next steps

1. rebrew: binary fingerprint bundle (item 1), likely `rebrew fingerprints` plus fields in `analyze`.
2. resembl: match contract with confidence, floor, cap, and filters (item 2).
3. rebrew metadata: name provenance and rename history (item 3).
4. relumea: adopt the AI-decomp provenance schema as the knowledge-graph target model (item 8) and
   wire the hosted MCP server as a tool provider (item 14).

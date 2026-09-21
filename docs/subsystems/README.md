# Subsystems

One page per subsystem of reportal: the modules it owns, the vocabulary it
defines, how it is wired into the portal, and the invariants a change must
keep. [ARCHITECTURE.md](../ARCHITECTURE.md) describes behavior across the whole
process; a page here is the reference for one subsystem's pieces. The
[module map](../MODULE_MAP.md) is generated from the `Sources:` lines below.

Every module under `src/reportal/` is owned by exactly one page.
`tests/test_docs_structure.py` fails when a page claims a path that is not a
module, when a module is owned twice, or when a module is owned by no page.

| Page | Owns | Modules |
|------|------|---------|
| [runtime.md](runtime.md) | the composed application, the shared FastAPI server, request correlation and the instance report | `__init__.py`, `__main__.py`, `webapp.py`, `server.py`, `observability.py`, `instance.py` |
| [configuration.md](configuration.md) | settings resolution, workspace discovery, deployment profiles and the local secret store | `settings.py`, `_paths.py`, `profiles.py`, `secret_store.py` |
| [store.md](store.md) | the SQLite schema, typed CRUD, search, uploads and the analysis log | `store.py`, `analysis_log.py` |
| [identity-and-scope.md](identity-and-scope.md) | users, teams, roles, bearer tokens, object scope and tenant disclosure | `auth.py`, `disclosure.py` |
| [http-api.md](http-api.md) | every `/api/*` JSON route and the error envelope it returns | `api.py` |
| [cli.md](cli.md) | the Typer command surface and what each command writes | `cli.py` |
| [web-ui.md](web-ui.md) | the built SPA, static assets, the generated reports and the public pricing page | `ui.py`, `landing.py` |
| [documentation.md](documentation.md) | the in-app manual, the packaged copy and the error-code catalogue with its `doc_url` | `docs.py`, `error_docs.py` |
| [jobs.md](jobs.md) | queued operations, their status and cancel, and the in-process worker pool | `jobs.py` |
| [engines.md](engines.md) | the in-process `rebrew` adapter and the engine contract every caller routes through | `engines.py` |
| [components.md](components.md) | the component framework, the effect dispatcher, the action journal and plugin discovery | `components.py`, `effects.py`, `journal.py`, `plugins.py`, `integrations.py` |
| [pipeline.md](pipeline.md) | the AI decompilation pipeline as a composition of components | `pipeline.py` |
| [auto-mode.md](auto-mode.md) | auto-run orchestration, its task and attempt store, and the worker registry | `auto_mode.py`, `auto_store.py`, `auto_workers.py`, `auto_llm_worker.py` |
| [llm-bridge.md](llm-bridge.md) | the optional OpenAI-compatible bridge and the model registry | `llm.py`, `models.py` |
| [ai-artifacts.md](ai-artifacts.md) | stored AI artifacts: rewrites, triage, renames, ratings and decompiler scripts | `ai_decomp.py`, `function_triage.py`, `renames.py`, `ratings.py`, `decompiler_scripts.py` |
| [conversation.md](conversation.md) | conversations, agent runs over the MCP registry, comments and analyst strings | `conversations.py`, `agent.py`, `comments.py`, `user_strings.py` |
| [mcp.md](mcp.md) | the MCP tool registry and the stdio/HTTP server that exposes it | `mcp_server.py`, `mcp_tools.py` |
| [matching.md](matching.md) | corpus matching, assembly similarity, benchmark scoring, library identification and un-stripping | `matching.py`, `similarity.py`, `benchmark.py`, `library.py`, `flirt_sigs.py`, `unstrip.py` |
| [symbols-and-types.md](symbols-and-types.md) | symbol ingestion from PDB and symbol files, editable signatures and the data-type model | `symbols.py`, `pdb.py`, `signatures.py`, `data_types.py` |
| [diff-and-lineage.md](diff-and-lineage.md) | line alignment, the match-pair diff view and pairwise function lineage | `diffing.py`, `diffview.py`, `lineage.py` |
| [binary-detail.md](binary-detail.md) | the derived binary-detail reads, per-function extras, composition analysis, related binaries and family matches | `details.py`, `function_extras.py`, `composition.py`, `related.py`, `families.py` |
| [binary-actions.md](binary-actions.md) | journaled prepare/extract/carve/unpack writes, bulk actions and the shared surface helpers | `binary_actions.py`, `bulk_actions.py`, `surface.py` |
| [format-analysis.md](format-analysis.md) | file-type detection, firmware carving, unpacking, Go build info and archive extraction | `filetypes.py`, `firmware.py`, `unpack.py`, `gobuildinfo.py`, `archive.py`, `zipcrypto.py` |
| [static-scans.md](static-scans.md) | deterministic scans and their derived reports: behavior, capabilities, hardening, protocols, secrets, threat, attack surface, exploitability, remediation and external sources | `behavior.py`, `capabilities.py`, `hardening.py`, `protocols.py`, `secrets.py`, `threat.py`, `attack_surface.py`, `exploitability.py`, `remediation.py`, `external.py` |
| [knowledge.md](knowledge.md) | document ingestion, guarded remote ingest, the derived graph and its pluggable backends | `knowledge.py`, `remote_ingest.py`, `graph.py`, `graph_backends.py` |
| [tenancy-billing.md](tenancy-billing.md) | plans, credits, the usage ledger and Stripe billing | `plans.py`, `credits.py`, `metering.py`, `billing.py` |
| [analytics.md](analytics.md) | the time-series analytics, activity and notification feeds | `analytics.py`, `activity.py`, `notifications.py` |
| [operations.md](operations.md) | backup and restore, pre-flight readiness and the PDF report | `backup.py`, `doctor.py`, `pdf.py` |
| [sandbox.md](sandbox.md) | the guarded sample detonation seam: the opt-in, the runners and the run ledger | `sandbox.py` |

## See also

- [docs/AGENTS.md](../AGENTS.md) for the page template and the writing rules
- [MODULE_MAP.md](../MODULE_MAP.md) for the generated module-to-subsystem listing
- [COMPONENTS.md](../COMPONENTS.md) for the component model behind the
  pipeline, auto mode and the effect handler registry

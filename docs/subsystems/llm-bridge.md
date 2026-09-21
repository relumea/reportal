# LLM bridge and models

Sources: src/reportal/llm.py, src/reportal/models.py

This subsystem owns the optional OpenAI-compatible bridge and the registry that names what
produced a stored result. The contract is that reportal runs unchanged without an endpoint:
`LlmConfig.resolve` returns None, every AI route answers 503 `llm-unavailable`, and no test
touches the network.

## Vocabulary

- `LlmConfig`: `endpoint`, `api_key`, `model`; `resolve()` is first match wins over environment
  then the workspace `reportal.toml` `[llm]` table.
- `LlmClient`: `available()`, `complete`, the chat and embeddings calls. `LlmUnavailable` is the
  unconfigured bridge; `LlmError` is a bad model response. `ANONYMOUS_KEY` is the placeholder the
  SDK requires when no key is set, and a request hook strips that exact bearer again.
- Prompt caps `MAX_CODE_CHARS`, `MAX_PROMPT_CONTEXT_CHARS`, `MAX_COMPLETION_TOKENS`,
  `MAX_REWRITE_TOKENS`, `MAX_AGENT_TOKENS`; `strip_fences` is shared with the auto worker.
- Task labels `TASK_SUMMARY`, `TASK_COMMENTS`, `TASK_TYPES`, `TASK_DECOMPILE`, `TASK_RENAMES`,
  `TASK_TRIAGE`, `TASK_THREAT`, `TASK_AGENT`; artifact kinds `AI_KIND_SUMMARY`, `AI_KIND_COMMENTS`,
  `AI_KIND_TYPES`.
- `Model` (frozen dataclass): `name`, `kind`, `version`, `description`, `available()`, the
  unavailable reason, and `describe()`. Kinds `KIND_ENGINE`, `KIND_DECOMPILER`, `KIND_LLM`,
  `KIND_SIMILARITY`; `UNCONFIGURED_MODEL` is the never-available stand-in. `ModelError` with
  `UnknownModelError`, `InvalidModelError`, `NotUpgradeableError`; `UPGRADE_KINDS`,
  `MAX_MODEL_NAME`, `DEFAULT_UPGRADE_LIMIT` 25 and `MAX_UPGRADE_LIMIT` 200.

## Wiring

- Environment `REPORTAL_LLM_ENDPOINT`, `REPORTAL_LLM_API_KEY`, `REPORTAL_LLM_MODEL`; workspace
  `[llm]`; the secret store key `llm.api_key`.
- Route `GET /api/models`; the AI routes that answer `llm-unavailable`; CLI `models` and
  `ai-decompile`; MCP tools `list_models` and `upgrade_analysis_model`.
- Entry-point group `reportal.models`; `refresh_models()` re-probes after an endpoint is
  configured.

## Invariants

- With no endpoint `LlmClient.available()` is False and the AI surfaces answer 503
  `llm-unavailable` (`tests/test_llm.py`).
- `get_client` / `set_client` install the process-wide client; no AI test reaches the network
  (`tests/test_llm.py`).
- The API key is never logged or returned; a real key's authorization header is left alone.
- A response that is neither a JSON object nor a list, or that carries none of the expected
  fields, raises `LlmError` naming the field (`tests/test_llm.py`).
- A duplicate model name raises `RegistryError` and `unregister_model` refuses an unknown name
  (`tests/test_models.py`).
- `upgrade_analysis` journals each artifact it replaces, records the new model on the analysis
  row, and reports a function whose re-run failed in `skipped` leaving its artifact alone
  (`tests/test_models.py`).

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#llm-bridge)
- [ARCHITECTURE.md models](../ARCHITECTURE.md#models)
- [API.md](../API.md)

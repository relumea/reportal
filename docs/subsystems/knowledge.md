# Knowledge and the derived graph

Sources: src/reportal/knowledge.py, src/reportal/remote_ingest.py, src/reportal/graph.py, src/reportal/graph_backends.py

Document storage and ranked retrieval, the guarded URL source, the deterministic graph derived
from stored rows, and the pluggable backend that may carry that graph out of the process. Text
reaches the network only through the optional embeddings call. `remote_ingest.py` is the one
module that opens a socket to a caller-named URL, and it is off by default.

## Vocabulary

- `SCOPE_KINDS`: `binary`, `project` and `docs`. A document row carries `scope_kind`, `scope_id`,
  `title`, `source`, `mime` and `sha256`; its text lives in `chunks`.
- `KnowledgeError.code`: `unsupported-format`, `empty-text`, `binary-content`, `file-too-large`,
  `too-many-documents`, `invalid scope kind`. Chunking uses `CHUNK_CHARS`, `CHUNK_OVERLAP` and
  `MAX_CHUNKS_PER_DOCUMENT`.
- Ranking methods are `embeddings` and `tfidf`, and every hit reports its `method`. `retrieve`
  applies `RETRIEVAL_LIMIT`; `as_context` renders `[n] <title> (<source>): <text>` inside
  `RETRIEVAL_CONTEXT_CHARS`.
- `remote_ingest` codes: `remote-ingest-disabled`, `invalid-url`, `blocked-target`,
  `unresolvable-host`, `unsupported-content-type`, `fetch-failed`, `too-many-redirects`,
  `file-too-large`.
- Graph node kinds (`binary`, `function`, `document`, `struct`, `tag`, `capability`, `library`)
  and relations (`contains`, `documented-by`, `has-capability`, `has-tag`, `recovered`,
  `identifies`, `matched-with`, `mentions`). A node id is `b<binary_id>:<kind>:<key>`; an edge id
  is `<source>|<rel>|<target>`.
- `graph_backends.GraphBackend(name, description, available, sync, query)`; its refusals are
  `UnknownBackendError`, `BackendUnavailableError`, `QueryUnsupportedError` and
  `GraphNotBuiltError`.

## Wiring

- Routes: `/api/documents` and `/api/documents/{document_id}`,
  `/api/binaries/{binary_id}/documents`, `GET /api/knowledge/config`, `POST /api/knowledge/fetch`,
  `GET /api/knowledge/search`, `GET /api/functions/{function_id}/knowledge`,
  `GET /api/binaries/{binary_id}/knowledge`; `POST`/`GET /api/binaries/{binary_id}/graph`,
  `GET /api/graph/nodes/{node_id}`, `GET /api/graph/backends`,
  `POST /api/binaries/{binary_id}/graph/sync`, `GET /api/graph/query`.
- CLI: `knowledge`, `context`, `graph-build`, `graph`, `graph-backends`, `graph-sync`,
  `graph-query`.
- MCP: `ingest_document`, `ingest_url`, `list_documents`, `delete_document`, `search_knowledge`,
  `retrieve_knowledge`, `build_graph`, `get_graph`, `graph_neighbors`, `list_graph_backends`,
  `sync_graph_backend`.
- Tables `documents`, `chunks`, `graph_nodes`, `graph_edges`. Settings
  `REPORTAL_ALLOW_REMOTE_INGEST` or `[knowledge] allow_remote`, `REPORTAL_GRAPH_BACKEND` or
  `[knowledge] graph_backend` (default `sqlite`), `REPORTAL_COGNEE_DATASET` or `[knowledge]
  cognee_dataset`. Backends register through `reportal.graph_backends`.

## Invariants

- Ingest dedupes on `(scope_kind, scope_id, sha256)` and returns the stored row with `duplicate:
  true` (`tests/test_knowledge.py`).
- While remote ingest is off, `ingest_url` raises `remote-ingest-disabled` and no request is made
  (`tests/test_remote_ingest.py`).
- `validate_target` rejects a target when any resolved address is not public, and `fetch`
  re-validates every redirect hop (`tests/test_remote_ingest.py`).
- `allow_loopback=True` stays a test-only seam, never a request field
  (`tests/test_remote_ingest.py`).
- A rebuild writes identical node and edge ids, so it is idempotent, and it clears the old rows
  only after the new graph is assembled (`tests/test_graph.py`).
- `sync_graph` refuses a binary with no stored graph, and an unavailable backend answers 503
  `backend-unavailable` (`tests/test_graph_backends.py`).

## See also

- [ARCHITECTURE.md: Knowledge graph](../ARCHITECTURE.md#knowledge-graph)
- [ARCHITECTURE.md: Remote ingestion](../ARCHITECTURE.md#remote-ingestion)
- [ARCHITECTURE.md: Graph backends](../ARCHITECTURE.md#graph-backends)

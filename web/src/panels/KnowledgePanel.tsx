import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import { Button, EmptyState, ErrorNote, Field, Loading, Muted, Panel, Toolbar } from "../components";
import type { KnowledgeHit, KnowledgeSearch } from "../types";
import { useAsync } from "../useAsync";

/** The ranked hits of one knowledge query, as the Knowledge view and the
 *  function panel render them. */
export function KnowledgeResults({ hits }: { hits: KnowledgeHit[] }): ReactNode {
  if (!hits.length) {
    return <EmptyState>No matches. Try a broader phrase or ingest another document.</EmptyState>;
  }
  return (
    <ol className="hits">
      {hits.map((hit) => (
        <li className="hit" key={hit.chunk_id}>
          <div className="hit-head">
            <span className="hit-title">{hit.title}</span>
            <span className="hit-score">
              {hit.score.toFixed(4)} · {hit.method}
            </span>
          </div>
          <p className="hit-text">{hit.text}</p>
          <p className="muted">{hit.source || "n/a"}</p>
        </li>
      ))}
    </ol>
  );
}

/**
 * The documents of a function's binary retrieved against a query.
 *
 * The route resolves a blank query to the function's own name, so pressing
 * Search on an empty box is the "what is stored about this function" read.
 */
export function FunctionKnowledgePanel({ functionId }: { functionId: number }): ReactNode {
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  const search = useAsync(
    () =>
      api<KnowledgeSearch>(
        `/functions/${functionId}/knowledge?q=${encodeURIComponent(submitted ?? "")}`,
      ),
    [functionId, submitted],
    submitted !== null,
  );

  return (
    <Panel
      title="Knowledge"
      subtitle="This binary's stored documents, ranked against the query; a blank query asks about the function's own name."
    >
      <Toolbar>
        <Field label="Query">
          <input
            value={query}
            placeholder="blank searches the function's name"
            onChange={(event) => setQuery(event.target.value)}
          />
        </Field>
        <Button tone="primary" onClick={() => setSubmitted(query.trim())}>
          Search documents
        </Button>
      </Toolbar>
      {submitted === null ? (
        <Muted>Run a search to see what the stored documents say about this function.</Muted>
      ) : search.error ? (
        <ErrorNote error={search.error} onRetry={search.reload} />
      ) : search.data === undefined ? (
        <Loading label="Searching the stored documents" />
      ) : (
        <>
          <Muted>
            {search.data.count} chunk(s) for &quot;{search.data.query}&quot;.
          </Muted>
          <KnowledgeResults hits={search.data.results} />
        </>
      )}
    </Panel>
  );
}

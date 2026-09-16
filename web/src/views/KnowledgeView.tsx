import { useRef, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Button,
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Muted,
  Panel,
  Toolbar,
} from "../components";
import { DEFAULT_KNOWLEDGE_LIMIT, REMOTE_INGEST_DISABLED_DETAIL } from "../constants";
import { KnowledgeResults } from "../panels/KnowledgePanel";
import type { Binary, Document, KnowledgeConfig, KnowledgeSearch } from "../types";
import { useAsync } from "../useAsync";

/** A document as the ingest routes answer with, including the dedupe flag. */
type IngestedDocument = Document & { duplicate: boolean };

/** Knowledge documents of one binary: ingest a file or a note, list, search. */
export function KnowledgeView(): ReactNode {
  const binariesResult = useAsync(() => api<{ binaries: Binary[] }>("/binaries"), []);
  const binaries = binariesResult.data?.binaries ?? [];
  const [selectedId, setSelectedId] = useState("");
  const activeId = selectedId || (binaries[0] ? String(binaries[0].id) : "");
  const binaryId = activeId === "" ? null : Number(activeId);

  const documentsResult = useAsync(
    () => api<{ documents: Document[] }>(`/binaries/${binaryId}/documents`),
    [binaryId],
    binaryId !== null,
  );
  const fileRef = useRef<HTMLInputElement>(null);
  const [title, setTitle] = useState("");
  const [source, setSource] = useState("");
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [busy, setBusy] = useState("");
  const configResult = useAsync(() => api<KnowledgeConfig>("/knowledge/config"), []);
  const remoteEnabled = configResult.data?.allow_remote === true;
  const searchResult = useAsync(
    () =>
      api<KnowledgeSearch>(
        `/knowledge/search?q=${encodeURIComponent(submitted)}&binary_id=${binaryId}` +
          `&limit=${DEFAULT_KNOWLEDGE_LIMIT}`,
      ),
    [submitted, binaryId],
    submitted !== "" && binaryId !== null,
  );

  const report = (document: IngestedDocument): void => {
    setMessage(
      document.duplicate
        ? `Already stored as document #${document.id}.`
        : `Ingested ${document.title} as document #${document.id} (${document.chunk_count} chunks).`,
    );
    documentsResult.reload();
  };

  const upload = async (): Promise<void> => {
    const file = fileRef.current?.files?.[0];
    setActionError(null);
    setMessage("");
    if (binaryId === null) return;
    if (!file) {
      setActionError(new Error("Choose a file first."));
      return;
    }
    const body = new FormData();
    body.append("file", file);
    if (title.trim()) body.append("title", title.trim());
    setBusy("upload");
    try {
      const document = await api<IngestedDocument>(`/binaries/${binaryId}/documents`, {
        method: "POST",
        body,
      });
      if (fileRef.current) fileRef.current.value = "";
      report(document);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const saveNote = async (): Promise<void> => {
    setActionError(null);
    setMessage("");
    if (binaryId === null || !text.trim()) return;
    setBusy("note");
    try {
      const document = await api<IngestedDocument>("/documents", {
        method: "POST",
        json: {
          scope_kind: "binary",
          scope_id: binaryId,
          title: title.trim(),
          source: source.trim(),
          text,
        },
      });
      setText("");
      report(document);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const fetchFromUrl = async (): Promise<void> => {
    setActionError(null);
    setMessage("");
    if (binaryId === null || !url.trim()) return;
    setBusy("url");
    try {
      const document = await api<IngestedDocument>("/knowledge/fetch", {
        method: "POST",
        json: {
          scope_kind: "binary",
          scope_id: binaryId,
          url: url.trim(),
          title: title.trim(),
        },
      });
      setUrl("");
      report(document);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const remove = async (id: number): Promise<void> => {
    setActionError(null);
    setBusy(`delete-${id}`);
    try {
      await api(`/documents/${id}`, { method: "DELETE" });
      documentsResult.reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const documents = documentsResult.data?.documents;
  const hits = searchResult.data?.results;

  return (
    <>
      <Panel
        title="Scope"
        subtitle="Ingestion and search cover one binary's documents."
        actions={
          binaries.length > 0 ? (
            <Field label="Binary">
              <select value={activeId} onChange={(event) => setSelectedId(event.target.value)}>
                {binaries.map((binary) => (
                  <option key={binary.id} value={binary.id}>
                    {binary.name} (#{binary.id})
                  </option>
                ))}
              </select>
            </Field>
          ) : null
        }
      >
        {binariesResult.error ? (
          <ErrorNote error={binariesResult.error} onRetry={binariesResult.reload} />
        ) : null}
        {binaries.length === 0 ? (
          <EmptyState>
            No binaries yet. Import a rebrew project with{" "}
            <code>reportal import-rebrew &lt;project-dir&gt;</code> to scope knowledge to one.
          </EmptyState>
        ) : null}
      </Panel>
      <Panel
        title="Ingest"
        subtitle="Upload a file, paste a note, or fetch a URL when remote ingestion is enabled."
        actions={
          <Button
            tone="primary"
            pending={busy === "upload"}
            disabled={binaryId === null}
            onClick={() => void upload()}
          >
            Upload
          </Button>
        }
      >
        <Toolbar>
          <Field label="Title">
            <input
              placeholder="optional"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
            />
          </Field>
          <Field label="File">
            <input type="file" name="file" ref={fileRef} />
          </Field>
        </Toolbar>
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void saveNote();
          }}
        >
          <Toolbar>
            <Field label="Source">
              <input
                placeholder="optional"
                value={source}
                onChange={(event) => setSource(event.target.value)}
              />
            </Field>
            <Button tone="primary" type="submit" pending={busy === "note"} disabled={!text.trim()}>
              Save note
            </Button>
          </Toolbar>
          <textarea
            className="chat-input"
            aria-label="Note text"
            placeholder="Paste a note to store in this scope"
            value={text}
            onChange={(event) => setText(event.target.value)}
          />
        </form>
        {remoteEnabled ? (
          <form
            className="toolbar"
            onSubmit={(event) => {
              event.preventDefault();
              void fetchFromUrl();
            }}
          >
            <Field label="URL">
              <input
                type="url"
                placeholder="https://example.com/notes.md"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
              />
            </Field>
            <Button type="submit" pending={busy === "url"} disabled={!url.trim()}>
              Fetch URL
            </Button>
          </form>
        ) : (
          <Muted>URL ingestion is disabled: {REMOTE_INGEST_DISABLED_DETAIL}.</Muted>
        )}
        {message ? <Muted>{message}</Muted> : null}
        {actionError ? <ErrorNote error={actionError} /> : null}
      </Panel>
      <Panel title="Documents" subtitle="Documents stored in this scope, newest first.">
        {documentsResult.error ? (
          <ErrorNote error={documentsResult.error} onRetry={documentsResult.reload} />
        ) : null}
        {documents === undefined ? (
          <Loading label="Loading documents" />
        ) : (
          <DataTable
            columns={[
              { label: "ID", key: "id", numeric: true },
              { label: "Title", key: "title" },
              { label: "Source", key: "source", mono: true },
              { label: "Size", key: "size", numeric: true },
              { label: "Chunks", key: "chunk_count", numeric: true },
              { label: "Created", key: "created_at", mono: true },
              {
                label: "Actions",
                render: (row) => (
                  <div className="actions-cell">
                    <ConfirmButton
                      label="Delete"
                      message={`Delete document "${row.title || `#${row.id}`}"?`}
                      pending={busy === `delete-${row.id}`}
                      onConfirm={() => void remove(row.id)}
                    />
                  </div>
                ),
              },
            ]}
            rows={documents}
            rowKey={(row) => row.id}
            empty={
              <EmptyState>
                No documents in this scope. Upload one or paste a note in the Ingest panel above.
              </EmptyState>
            }
          />
        )}
      </Panel>
      <Panel
        title="Search"
        subtitle="Semantic and keyword search over this scope's documents."
        actions={
          <Toolbar>
            <Field label="Query" hint="Enter searches">
              <input
                type="search"
                placeholder="semantic search over this scope"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && query.trim()) setSubmitted(query);
                }}
              />
            </Field>
            <Button tone="primary" disabled={!query.trim()} onClick={() => setSubmitted(query)}>
              Search
            </Button>
          </Toolbar>
        }
      >
        {searchResult.error ? (
          <ErrorNote error={searchResult.error} onRetry={searchResult.reload} />
        ) : hits ? (
          <KnowledgeResults hits={hits} />
        ) : (
          <Muted>Search this scope&apos;s documents by meaning or keyword.</Muted>
        )}
      </Panel>
    </>
  );
}

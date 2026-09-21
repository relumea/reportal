import { useEffect, useState } from "react";
import { Link } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Panel,
  StatusCell,
  Toolbar,
  CopyValue,
  hex,
} from "../components";
import { SEARCH_KIND_LABELS, SEARCH_KINDS } from "../constants";
import type { SearchKind, SearchResults } from "../types";
import { useAsync } from "../useAsync";
import { collectionHref, binaryHref, functionHref, tagHref } from "./SearchResults";

export function SearchView({
  query,
  onQuery,
}: {
  query: string;
  onQuery: (query: string) => void;
}): ReactNode {
  const [draft, setDraft] = useState(query);
  const [kind, setKind] = useState<SearchKind>("all");
  const [regex, setRegex] = useState(false);

  useEffect(() => {
    setDraft(query);
  }, [query]);

  const resultsResult = useAsync(
    () =>
      api<SearchResults>(
        `/search?q=${encodeURIComponent(query)}&kind=${kind}${regex ? "&regex=true" : ""}`,
      ),
    [query, kind, regex],
    query !== "",
  );
  const results = resultsResult.data;
  const total = results
    ? results.binaries.length + results.functions.length + results.collections.length + results.tags.length
    : 0;

  return (
    <Panel
      title="Search"
      subtitle="Names, hashes, tags and paths across the whole workspace."
      actions={
        <Toolbar>
          <Field label="Query" hint="Enter searches">
            <input
              type="search"
              placeholder="name, hash, path"
              value={draft}
              onChange={(event) => {
                const next = event.target.value;
                setDraft(next);
                if (/^[0-9a-fA-F]{64}$/.test(next.trim())) setKind("sha256");
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter") onQuery(draft);
              }}
            />
          </Field>
          <Field label="Match">
            <select
              value={kind}
              onChange={(event) => setKind(event.target.value as SearchKind)}
            >
              {SEARCH_KINDS.map((option) => (
                <option key={option} value={option}>
                  {SEARCH_KIND_LABELS[option]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Pattern">
            <label className="checkbox-field">
              <input
                type="checkbox"
                checked={regex}
                disabled={kind === "sha256"}
                onChange={(event) => setRegex(event.target.checked)}
              />
              regular expression
            </label>
          </Field>
          <Button tone="primary" onClick={() => onQuery(draft)}>
            Search
          </Button>
        </Toolbar>
      }
    >
      {query === "" ? (
        <EmptyState>Search binaries, functions and collections. Try a name, a hash prefix, or a tag.</EmptyState>
      ) : resultsResult.error ? (
        <ErrorNote error={resultsResult.error} onRetry={resultsResult.reload} />
      ) : !results ? (
        <Loading label="Searching" />
      ) : total === 0 ? (
        <EmptyState>No results for &quot;{query}&quot;. Try a shorter name or a hash prefix.</EmptyState>
      ) : (
        <>
          {results.binaries.length ? (
            <>
              <h3>
                Binaries ({results.binaries.length} of {results.counts.binaries.total})
              </h3>
              <DataTable
                columns={[
                  { label: "ID", key: "id", numeric: true },
                  {
                    label: "Name",
                    render: (row) => <Link to={binaryHref(row.id)}>{row.name}</Link>,
                  },
                  { label: "Format", key: "format", mono: true },
                  { label: "Arch", key: "arch", mono: true },
                  { label: "Size", numeric: true, render: (row) => row.size.toLocaleString() },
                  {
                    label: "SHA-256",
                    render: (row) => <CopyValue value={row.sha256} compact />,
                  },
                  {
                    label: "Tags",
                    render: (row) => (row.tags.length ? row.tags.join(", ") : "n/a"),
                  },
                  { label: "Created", key: "created_at", mono: true },
                  { label: "Match", key: "match", mono: true },
                ]}
                rows={results.binaries}
                rowKey={(row) => row.id}
              />
            </>
          ) : null}
          {results.functions.length ? (
            <>
              <h3>
                Functions ({results.functions.length} of {results.counts.functions.total})
              </h3>
              <DataTable
                columns={[
                  { label: "ID", key: "id", numeric: true },
                  {
                    label: "VA",
                    mono: true,
                    render: (row) => <Link to={functionHref(row.id)}>{hex(row.va)}</Link>,
                  },
                  { label: "Name", key: "name" },
                  { label: "Status", render: (row) => <StatusCell status={row.status} /> },
                ]}
                rows={results.functions}
                rowKey={(row) => row.id}
              />
            </>
          ) : null}
          {results.collections.length ? (
            <>
              <h3>
                Collections ({results.collections.length} of {results.counts.collections.total})
              </h3>
              <DataTable
                columns={[
                  { label: "ID", key: "id", numeric: true },
                  {
                    label: "Name",
                    render: (row) => <Link to={collectionHref(row.id)}>{row.name}</Link>,
                  },
                  { label: "Description", key: "description" },
                  { label: "Scope", key: "visibility", mono: true },
                  { label: "Binaries", key: "binary_count", numeric: true },
                  { label: "Created", key: "created_at", mono: true },
                ]}
                rows={results.collections}
                rowKey={(row) => row.id}
              />
            </>
          ) : null}
          {results.tags.length ? (
            <>
              <h3>
                Tags ({results.tags.length} of {results.counts.tags.total})
              </h3>
              <DataTable
                columns={[
                  { label: "ID", key: "id", numeric: true },
                  {
                    label: "Name",
                    render: (row) => <Link to={tagHref(row.id)}>{row.name}</Link>,
                  },
                  { label: "Binaries", key: "binary_count", numeric: true },
                ]}
                rows={results.tags}
                rowKey={(row) => row.id}
              />
            </>
          ) : null}
        </>
      )}
    </Panel>
  );
}

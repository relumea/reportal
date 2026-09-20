import { useState } from "react";
import type { ReactNode } from "react";

import { BINARY_OPTIONS_PATH, api, isApiErrorCode } from "../api";
import {
  Badge,
  Button,
  CheckboxField,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Muted,
  Panel,
  Toolbar,
} from "../components";
import { GRAPH_NO_GRAPH, GRAPH_NODE_KINDS, MAX_GRAPH_ROWS_SHOWN } from "../constants";
import type {
  BinaryOption,
  GraphBackends,
  GraphBuildResult,
  GraphNeighbor,
  GraphNeighbors,
  GraphPayload,
  GraphQueryNode,
  GraphQueryResult,
  GraphSyncResult,
} from "../types";
import { useAsync } from "../useAsync";

const ALL_KINDS = "";
const DOCUMENT_KIND = "document";

/** The detail route a node has, or null when the kind has no view to link to. */
function nodeHref(node: { kind: string; key: string }): string | null {
  if (node.kind === "function") return `#/functions/${node.key}`;
  if (node.kind === "binary") return `#/binaries/${node.key}`;
  if (node.kind === DOCUMENT_KIND) return "#/knowledge";
  return null;
}

function NeighborList({ entries }: { entries: GraphNeighbor[] }): ReactNode {
  return (
    <ul className="neighbors">
      {entries.map((entry) => {
        const href = nodeHref(entry);
        return (
          <li key={entry.id}>
            <span className="muted">{entry.kind}</span>{" "}
            {href ? <a href={href}>{entry.label}</a> : entry.label}{" "}
            <span className="muted">({entry.weight.toFixed(4)})</span>
          </li>
        );
      })}
    </ul>
  );
}

function Groups({
  title,
  groups,
}: {
  title: string;
  groups: Record<string, GraphNeighbor[]>;
}): ReactNode {
  const relations = Object.keys(groups);
  if (!relations.length) return null;
  return (
    <div className="neighbor-group">
      <h3>{title}</h3>
      {relations.map((rel) => (
        <div key={rel}>
          <p className="muted">{rel}</p>
          <NeighborList entries={groups[rel]} />
        </div>
      ))}
    </div>
  );
}

/** One binary's graph: node counts, a node table with a filter, and neighbors. */
function GraphPanel({ binaryId }: { binaryId: number }): ReactNode {
  const [kind, setKind] = useState(ALL_KINDS);
  const [includeDocuments, setIncludeDocuments] = useState(false);
  const [filter, setFilter] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const path = `/binaries/${binaryId}/graph?kind=${kind}&include_documents=${includeDocuments}`;
  const graphResult = useAsync(() => api<GraphPayload>(path), [path]);
  // A node id is `b<binary>:<kind>:<key>`; those characters are legal in a
  // path segment, so it is passed through unencoded.
  const neighborsResult = useAsync(
    () => api<GraphNeighbors>(`/graph/nodes/${selectedId ?? ""}`),
    [selectedId],
    selectedId !== null,
  );

  const build = async (): Promise<void> => {
    setActionError(null);
    setMessage("");
    setBusy(true);
    try {
      const result = await api<GraphBuildResult>(`/binaries/${binaryId}/graph`, {
        method: "POST",
      });
      setMessage(`Built ${result.nodes} nodes and ${result.edges} edges.`);
      setSelectedId(null);
      graphResult.reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(false);
    }
  };

  const payload = graphResult.data;
  const needle = filter.trim().toLowerCase();
  const nodes = (payload?.nodes ?? []).filter(
    (node) => !needle || node.label.toLowerCase().includes(needle) || node.kind.includes(needle),
  );
  const shown = nodes.slice(0, MAX_GRAPH_ROWS_SHOWN);
  const detail = neighborsResult.data;

  return (
    <>
      <Panel
        title="Graph"
        subtitle="Nodes and edges built from the stored rows: binaries, functions, documents, structs, tags, capabilities and libraries."
        actions={
          <Toolbar>
            <Field label="Kind">
              <select value={kind} onChange={(event) => setKind(event.target.value)}>
                <option value={ALL_KINDS}>all kinds</option>
                {GRAPH_NODE_KINDS.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </Field>
            <CheckboxField
              label="include documents"
              checked={includeDocuments}
              onChange={setIncludeDocuments}
            />
            <Field label="Filter">
              <input
                type="search"
                placeholder="filter nodes"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              />
            </Field>
            <Button tone="primary" pending={busy} onClick={() => void build()}>
              Build graph
            </Button>
          </Toolbar>
        }
      >
        <Muted live>{message}</Muted>
        {actionError ? <ErrorNote error={actionError} /> : null}
        {graphResult.error ? (
          isApiErrorCode(graphResult.error, GRAPH_NO_GRAPH) ? (
            <EmptyState>No graph built yet. Build graph reads the stored rows.</EmptyState>
          ) : (
            <ErrorNote error={graphResult.error} onRetry={graphResult.reload} />
          )
        ) : null}
        {payload ? (
          <>
            <h3>Node counts</h3>
            <div className="chips">
              {GRAPH_NODE_KINDS.map((name) => (
                <Badge key={name} mono>
                  {name} {payload.counts[name] ?? 0}
                </Badge>
              ))}
            </div>
            <Muted>
              {payload.nodes.length} nodes, {payload.edges.length} edges
              {payload.truncated ? " (truncated at the build cap)" : ""}
            </Muted>
          </>
        ) : null}
      </Panel>
      {payload ? (
        <Panel
          title="Nodes"
          subtitle={
            nodes.length > shown.length
              ? `Showing ${shown.length} of ${nodes.length} nodes.`
              : `${shown.length} nodes.`
          }
        >
          <DataTable
            columns={[
              { label: "Kind", render: (row) => <Badge mono>{row.kind}</Badge> },
              { label: "Label", key: "label" },
              { label: "Degree", key: "degree", numeric: true },
            ]}
            rows={shown}
            rowKey={(row) => row.id}
            onRowClick={(row) => setSelectedId(row.id)}
            empty={<EmptyState>No node matches the filter.</EmptyState>}
          />
        </Panel>
      ) : null}
      {selectedId !== null ? (
        <Panel
          title="Node"
          actions={
            <Button tone="ghost" onClick={() => setSelectedId(null)}>
              Close
            </Button>
          }
        >
          {neighborsResult.error ? (
            <ErrorNote error={neighborsResult.error} onRetry={neighborsResult.reload} />
          ) : null}
          {detail ? (
            <>
              <p>
                <Badge mono>{detail.node.kind}</Badge> <strong>{detail.node.label}</strong>{" "}
                <span className="mono">{detail.node.id}</span>
              </p>
              <Groups title="incoming" groups={detail.incoming} />
              <Groups title="outgoing" groups={detail.outgoing} />
              {Object.keys(detail.incoming).length === 0 &&
              Object.keys(detail.outgoing).length === 0 ? (
                <Muted>No neighbors.</Muted>
              ) : null}
              {nodeHref(detail.node) !== null ? (
                <p>
                  <a href={nodeHref(detail.node) ?? "#"}>Open {detail.node.kind}</a>
                </p>
              ) : null}
            </>
          ) : (
            <Loading label="Loading neighbors" />
          )}
        </Panel>
      ) : null}
    </>
  );
}

/** Backend registry controls: pick one, sync the graph to it, and query it. */
function GraphBackendPanel({ binaryId }: { binaryId: number }): ReactNode {
  const backendsResult = useAsync(() => api<GraphBackends>("/graph/backends"), []);
  const [selected, setSelected] = useState("");
  const [message, setMessage] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<GraphQueryNode[] | null>(null);
  const [busy, setBusy] = useState("");

  const backends = backendsResult.data?.backends ?? [];
  const activeName = selected || backendsResult.data?.default || "";
  const active = backends.find((entry) => entry.name === activeName) ?? null;
  const canSync = active !== null && active.available;

  const sync = async (): Promise<void> => {
    if (active === null) return;
    setActionError(null);
    setMessage("");
    setBusy("sync");
    try {
      const result = await api<GraphSyncResult>(`/binaries/${binaryId}/graph/sync`, {
        method: "POST",
        json: { backend: active.name },
      });
      const dataset = result.dataset ? ` into dataset ${result.dataset}` : "";
      setMessage(
        `Synced to ${result.backend}${dataset}: ${result.nodes} nodes, ${result.edges} edges` +
          ` (${result.pushed_nodes} pushed).`,
      );
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const runQuery = async (): Promise<void> => {
    if (active === null) return;
    setActionError(null);
    setBusy("query");
    try {
      const result = await api<GraphQueryResult>(
        `/graph/query?q=${encodeURIComponent(query)}&backend=${encodeURIComponent(active.name)}`,
      );
      setHits(result.results);
    } catch (failure) {
      setActionError(failure);
      setHits(null);
    } finally {
      setBusy("");
    }
  };

  return (
    <Panel
      title="Backends"
      subtitle="Optional graph stores the node table can be synced to and queried through."
      actions={
        <Toolbar>
          <Field label="Backend">
            <select value={activeName} onChange={(event) => setSelected(event.target.value)}>
              {backends.map((entry) => (
                <option key={entry.name} value={entry.name} disabled={!entry.available}>
                  {entry.available ? entry.name : `${entry.name} (unavailable)`}
                </option>
              ))}
            </select>
          </Field>
          <Button tone="primary" pending={busy === "sync"} onClick={() => void sync()} disabled={!canSync}>
            Sync to backend
          </Button>
          {active !== null && active.supports_query ? (
            <>
              <Field label="Query">
                <input
                  type="search"
                  placeholder="node id or text"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </Field>
              <Button pending={busy === "query"} onClick={() => void runQuery()} disabled={!query.trim()}>
                Query
              </Button>
            </>
          ) : null}
        </Toolbar>
      }
    >
      {backendsResult.error ? (
        <ErrorNote error={backendsResult.error} onRetry={backendsResult.reload} />
      ) : null}
      {active !== null ? <Muted>{active.description}</Muted> : null}
      {active !== null && !active.available ? (
        <Muted>Unavailable: {active.unavailable_reason}</Muted>
      ) : null}
      <Muted live>{message}</Muted>
      {actionError ? <ErrorNote error={actionError} /> : null}
      {hits !== null ? (
        <DataTable
          columns={[
            { label: "Kind", render: (row) => <Badge mono>{row.kind}</Badge> },
            { label: "Label", key: "label" },
            { label: "Degree", key: "degree", numeric: true },
          ]}
          rows={hits}
          rowKey={(row) => row.id}
          empty={<EmptyState>No matching nodes.</EmptyState>}
        />
      ) : null}
    </Panel>
  );
}

/** Knowledge graph view: pick a binary, rebuild its graph and walk the nodes. */
export function GraphView(): ReactNode {
  const binariesResult = useAsync(() => api<{ binaries: BinaryOption[] }>(BINARY_OPTIONS_PATH), []);
  const binaries = binariesResult.data?.binaries ?? [];
  const [selectedId, setSelectedId] = useState("");
  const activeId = selectedId || (binaries[0] ? String(binaries[0].id) : "");
  const binaryId = activeId === "" ? null : Number(activeId);

  return (
    <>
      <Panel
        title="Binary"
        subtitle="The graph is built per binary from that binary's stored rows."
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
            <code>reportal import-rebrew &lt;project-dir&gt;</code> to build a graph.
          </EmptyState>
        ) : null}
      </Panel>
      {binaryId !== null ? <GraphPanel key={binaryId} binaryId={binaryId} /> : null}
      {binaryId !== null ? <GraphBackendPanel key={`backends-${binaryId}`} binaryId={binaryId} /> : null}
    </>
  );
}

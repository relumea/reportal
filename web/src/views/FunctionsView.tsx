import { useEffect, useState } from "react";
import { createSearchParams, useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Note,
  Panel,
  StatusCell,
  Toolbar,
  hex,
} from "../components";
import {
  DEFAULT_FUNCTION_ORDER,
  DEFAULT_FUNCTION_SORT,
  FUNCTION_CAPABILITIES,
  FUNCTION_MATCH_VALUES,
  FUNCTION_NAME_SOURCES,
  FUNCTION_ORDERS,
  FUNCTION_SORTS,
} from "../constants";
import type { FunctionOrder, FunctionSort } from "../constants";
import type { Binary, BulkResult, FunctionListPage, FunctionRow, HistoryRow } from "../types";
import { useAsync } from "../useAsync";

/** The function-list filters one hash carries; every one is optional. */
interface FunctionFilters {
  nameSource: string;
  capability: string;
  match: string;
  minSize: string;
  maxSize: string;
  string: string;
  /** An address whose referrers the list keeps; empty means no filter. */
  refersTo: string;
  sort: FunctionSort;
  order: FunctionOrder;
}

const DEFAULT_FILTERS: FunctionFilters = {
  nameSource: "",
  capability: "",
  match: "",
  minSize: "",
  maxSize: "",
  string: "",
  refersTo: "",
  sort: DEFAULT_FUNCTION_SORT,
  order: DEFAULT_FUNCTION_ORDER,
};

function oneOf<T extends string>(value: string | undefined, allowed: readonly string[], fallback: T): T {
  return value !== undefined && allowed.includes(value) ? (value as T) : fallback;
}

/** Read the filters from the route's hash query, dropping values the API refuses. */
function filtersFromQuery(query: Record<string, string>): FunctionFilters {
  return {
    nameSource: oneOf(query.name_source, FUNCTION_NAME_SOURCES, ""),
    capability: oneOf(query.capability, FUNCTION_CAPABILITIES, ""),
    match: oneOf(query.match, FUNCTION_MATCH_VALUES, ""),
    minSize: query.min_size ?? "",
    maxSize: query.max_size ?? "",
    string: query.string ?? "",
    refersTo: query.refers_to ?? "",
    sort: oneOf(query.sort, FUNCTION_SORTS, DEFAULT_FUNCTION_SORT),
    order: oneOf(query.order, FUNCTION_ORDERS, DEFAULT_FUNCTION_ORDER),
  };
}

/** The hash query one filter set carries, with the defaults left out. */
function filterQuery(filters: FunctionFilters): Record<string, string> {
  return {
    name_source: filters.nameSource,
    capability: filters.capability,
    match: filters.match,
    min_size: filters.minSize,
    max_size: filters.maxSize,
    string: filters.string,
    refers_to: filters.refersTo,
    sort: filters.sort === DEFAULT_FUNCTION_SORT ? "" : filters.sort,
    order: filters.order === DEFAULT_FUNCTION_ORDER ? "" : filters.order,
  };
}

/** The API path one filter set reads. */
function listPath(binaryId: number, filters: FunctionFilters): string {
  const params = new URLSearchParams();
  params.set("sort", filters.sort);
  params.set("order", filters.order);
  for (const [key, value] of Object.entries(filterQuery(filters))) {
    if (key !== "sort" && key !== "order" && value !== "") params.set(key, value);
  }
  return `/binaries/${binaryId}/functions?${params.toString()}`;
}

/** A table header that sorts the list by its column. */
function SortHeader({
  column,
  label,
  sort,
  order,
  onSort,
}: {
  column: FunctionSort;
  label: string;
  sort: FunctionSort;
  order: FunctionOrder;
  onSort: (column: FunctionSort) => void;
}): ReactNode {
  const active = sort === column;
  return (
    <Button
      size="sm"
      tone="ghost"
      title={`Sort by ${label}${active ? (order === "asc" ? " (descending)" : " (ascending)") : ""}`}
      onClick={() => onSort(column)}
    >
      {active ? `${label} ${order === "asc" ? "▲" : "▼"}` : label}
    </Button>
  );
}

export function FunctionsView({
  binaryId,
  query,
  onOpenMatches,
}: {
  binaryId: number | null;
  query: Record<string, string>;
  onOpenMatches: (functionId: number) => void;
}): ReactNode {
  const navigate = useNavigate();
  const filters = filtersFromQuery(query);
  const [selected, setSelected] = useState<number | null>(binaryId);
  const [historyFor, setHistoryFor] = useState<number | null>(null);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [actionError, setActionError] = useState<unknown>(null);
  const [checked, setChecked] = useState<Set<number>>(new Set());
  const [prefix, setPrefix] = useState("");
  const [replacePrefix, setReplacePrefix] = useState(false);
  const [bulkMessage, setBulkMessage] = useState("");
  const [bulkError, setBulkError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [drafts, setDrafts] = useState({
    minSize: filters.minSize,
    maxSize: filters.maxSize,
    string: filters.string,
  });

  useEffect(() => {
    if (binaryId !== null) setSelected(binaryId);
  }, [binaryId]);

  useEffect(() => {
    setDrafts({ minSize: filters.minSize, maxSize: filters.maxSize, string: filters.string });
    // The drafts follow the hash; a change here means the URL moved under us.
  }, [filters.minSize, filters.maxSize, filters.string]);

  const binariesResult = useAsync(() => api<{ binaries: Binary[] }>("/binaries"), []);
  const binaries = binariesResult.data?.binaries;
  const effectiveId = selected ?? binaries?.[0]?.id ?? null;

  const functionsResult = useAsync(
    () => api<FunctionListPage>(listPath(effectiveId ?? 0, filters)),
    [effectiveId, JSON.stringify(filterQuery(filters))],
    effectiveId !== null,
  );
  const functions = functionsResult.data?.functions;
  const total = functionsResult.data?.total ?? 0;
  const filtered =
    filters.nameSource !== "" ||
    filters.capability !== "" ||
    filters.match !== "" ||
    filters.minSize !== "" ||
    filters.maxSize !== "" ||
    filters.string !== "" ||
    filters.refersTo !== "";

  const path = effectiveId === null ? "/functions" : `/binaries/${effectiveId}/functions`;

  const apply = (patch: Partial<FunctionFilters>): void => {
    navigate({
      pathname: path,
      search: createSearchParams(filterQuery({ ...filters, ...patch })).toString(),
    });
  };

  const applyDrafts = (): void => {
    apply({
      minSize: drafts.minSize.trim(),
      maxSize: drafts.maxSize.trim(),
      string: drafts.string.trim(),
    });
  };

  const toggleSort = (column: FunctionSort): void => {
    const order: FunctionOrder =
      filters.sort === column && filters.order === "asc" ? "desc" : "asc";
    apply({ sort: column, order });
  };

  const clearFilters = (): void => {
    setDrafts({ minSize: "", maxSize: "", string: "" });
    navigate({
      pathname: path,
      search: createSearchParams(
        filterQuery({ ...DEFAULT_FILTERS, sort: filters.sort, order: filters.order }),
      ).toString(),
    });
  };

  const chooseBinary = (id: number): void => {
    setSelected(id);
    setHistoryFor(null);
    setChecked(new Set());
    navigate({
      pathname: `/binaries/${id}/functions`,
      search: createSearchParams(filterQuery(filters)).toString(),
    });
  };

  const toggleChecked = (functionId: number): void => {
    setChecked((current) => {
      const next = new Set(current);
      if (next.has(functionId)) next.delete(functionId);
      else next.add(functionId);
      return next;
    });
  };

  const applyPrefix = async (): Promise<void> => {
    setBulkError(null);
    setBulkMessage("");
    const ids = Array.from(checked);
    if (!ids.length) {
      setBulkError(new Error("Select at least one function."));
      return;
    }
    if (!prefix.trim()) {
      setBulkError(new Error("Enter a prefix."));
      return;
    }
    setBusy("prefix");
    try {
      const result = await api<BulkResult>("/functions/bulk", {
        method: "POST",
        json: {
          action: "rename",
          function_ids: ids,
          prefix: prefix.trim(),
          replace: replacePrefix,
        },
      });
      const skipped = result.skipped.length;
      setBulkMessage(
        `${result.applied} of ${result.requested} renamed${skipped ? `, ${skipped} skipped` : ""}.`,
      );
      setChecked(new Set());
      functionsResult.reload();
    } catch (failure) {
      setBulkError(failure);
    } finally {
      setBusy("");
    }
  };

  const showHistory = async (row: FunctionRow): Promise<void> => {
    setBusy(`history-${row.id}`);
    try {
      const result = await api<{ history: HistoryRow[] }>(`/functions/${row.id}/history`);
      setHistoryFor(row.id);
      setHistory(result.history);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const rename = async (row: FunctionRow): Promise<void> => {
    const name = window.prompt("New function name", row.name || "");
    if (!name) return;
    setActionError(null);
    setBusy(`rename-${row.id}`);
    try {
      await api(`/functions/${row.id}/rename`, { method: "POST", json: { name, actor: "spa" } });
      functionsResult.reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  if (binaries && binaries.length === 0) {
    return (
      <Panel title="Functions">
        <EmptyState>
          No binaries yet. Import a rebrew project with{" "}
          <code>reportal import-rebrew &lt;project-dir&gt;</code>.
        </EmptyState>
      </Panel>
    );
  }

  return (
    <>
      <Panel
        title="Functions"
        subtitle="Reversed functions of one binary, filtered and sorted from the server."
        actions={
          binaries && binaries.length > 0 ? (
            <Field label="Binary">
              <select
                value={effectiveId ?? ""}
                onChange={(event) => chooseBinary(Number(event.target.value))}
              >
                {(binaries ?? []).map((binary) => (
                  <option key={binary.id} value={binary.id}>
                    {binary.name} (#{binary.id})
                  </option>
                ))}
              </select>
            </Field>
          ) : null
        }
      >
        <Toolbar>
          <Field label="Name source">
            <select
              value={filters.nameSource}
              onChange={(event) => apply({ nameSource: event.target.value })}
            >
              <option value="">any source</option>
              {FUNCTION_NAME_SOURCES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Capability">
            <select
              value={filters.capability}
              onChange={(event) => apply({ capability: event.target.value })}
            >
              <option value="">any capability</option>
              {FUNCTION_CAPABILITIES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Match">
            <select
              value={filters.match}
              onChange={(event) => apply({ match: event.target.value })}
            >
              <option value="">any match state</option>
              {FUNCTION_MATCH_VALUES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Min size">
            <input
              type="number"
              min={0}
              value={drafts.minSize}
              onChange={(event) => setDrafts({ ...drafts, minSize: event.target.value })}
              onKeyDown={(event) => {
                if (event.key === "Enter") applyDrafts();
              }}
            />
          </Field>
          <Field label="Max size">
            <input
              type="number"
              min={0}
              value={drafts.maxSize}
              onChange={(event) => setDrafts({ ...drafts, maxSize: event.target.value })}
              onKeyDown={(event) => {
                if (event.key === "Enter") applyDrafts();
              }}
            />
          </Field>
          <Field label="String">
            <input
              placeholder="in the stored decompilation"
              value={drafts.string}
              onChange={(event) => setDrafts({ ...drafts, string: event.target.value })}
              onKeyDown={(event) => {
                if (event.key === "Enter") applyDrafts();
              }}
            />
          </Field>
          <Button tone="primary" onClick={applyDrafts}>
            Apply filters
          </Button>
          {filtered ? (
            <Button tone="ghost" onClick={clearFilters}>
              Clear
            </Button>
          ) : null}
        </Toolbar>
        {binariesResult.error ? (
          <ErrorNote error={binariesResult.error} onRetry={binariesResult.reload} />
        ) : null}
        {filters.refersTo !== "" ? (
          <Note>
            Referrers of {filters.refersTo}.{" "}
            <Button size="sm" tone="ghost" onClick={() => apply({ refersTo: "" })}>
              Clear referrer filter
            </Button>
          </Note>
        ) : null}
        {actionError ? <ErrorNote error={actionError} /> : null}
        {functionsResult.error ? (
          <ErrorNote error={functionsResult.error} onRetry={functionsResult.reload} />
        ) : null}
        {!functions ? null : functions.length === 0 ? (
          <EmptyState>
            {filters.refersTo !== ""
              ? `No function references ${filters.refersTo}. Clear the filter to see them all.`
              : filtered
                ? `No functions match this filter (${total} in this binary). Clear it to see them all.`
                : "This binary has no functions. Import its rebrew project or pick another binary above."}
          </EmptyState>
        ) : (
          <>
            <div className="row-between">
              <span className="muted">
                {functions.length} of {total} functions
              </span>
            </div>
            <DataTable
              columns={[
                {
                  label: "",
                  render: (row) => (
                    <input
                      type="checkbox"
                      aria-label={`select ${row.name || row.id}`}
                      checked={checked.has(row.id)}
                      onChange={() => toggleChecked(row.id)}
                    />
                  ),
                },
                { label: "ID", key: "id", numeric: true },
                {
                  label: "VA",
                  mono: true,
                  header: (
                    <SortHeader
                      column="va"
                      label="VA"
                      sort={filters.sort}
                      order={filters.order}
                      onSort={toggleSort}
                    />
                  ),
                  render: (row) => <a href={`#/functions/${row.id}`}>{hex(row.va)}</a>,
                },
                {
                  label: "Name",
                  header: (
                    <SortHeader
                      column="name"
                      label="Name"
                      sort={filters.sort}
                      order={filters.order}
                      onSort={toggleSort}
                    />
                  ),
                  render: (row) => row.name,
                },
                {
                  label: "Size",
                  numeric: true,
                  header: (
                    <SortHeader
                      column="size"
                      label="Size"
                      sort={filters.sort}
                      order={filters.order}
                      onSort={toggleSort}
                    />
                  ),
                  render: (row) => row.size,
                },
                {
                  label: "Status",
                  header: (
                    <SortHeader
                      column="status"
                      label="Status"
                      sort={filters.sort}
                      order={filters.order}
                      onSort={toggleSort}
                    />
                  ),
                  render: (row) => <StatusCell status={row.status} />,
                },
                { label: "Source", key: "name_source" },
                {
                  label: "Actions",
                  render: (row) => (
                    <div className="actions-cell">
                      <Button size="sm" onClick={() => onOpenMatches(row.id)}>
                        Matches
                      </Button>
                      <Button
                        size="sm"
                        pending={busy === `history-${row.id}`}
                        onClick={() => void showHistory(row)}
                      >
                        History
                      </Button>
                      <Button
                        size="sm"
                        pending={busy === `rename-${row.id}`}
                        onClick={() => void rename(row)}
                      >
                        Rename
                      </Button>
                    </div>
                  ),
                },
              ]}
              rows={functions}
              rowKey={(row) => row.id}
              onRowClick={(row) => navigate(`/functions/${row.id}`)}
            />
          </>
        )}
      </Panel>
      {functions && functions.length > 0 ? (
        <Panel
          title="Bulk actions"
          subtitle="Renames the functions checked above."
          actions={
            <>
              <span className="muted">{checked.size} selected</span>
              <Button tone="primary" pending={busy === "prefix"} onClick={() => void applyPrefix()}>
                Apply prefix
              </Button>
            </>
          }
        >
          <Toolbar>
            <Field label="Prefix">
              <input
                placeholder="prefix"
                value={prefix}
                onChange={(event) => setPrefix(event.target.value)}
              />
            </Field>
            <label className="checkbox-field">
              <input
                type="checkbox"
                checked={replacePrefix}
                onChange={(event) => setReplacePrefix(event.target.checked)}
              />{" "}
              replace existing prefix
            </label>
          </Toolbar>
          {bulkError ? <ErrorNote error={bulkError} /> : null}
          {bulkMessage ? <p className="muted">{bulkMessage}</p> : null}
        </Panel>
      ) : null}
      {historyFor !== null ? (
        <Panel
          title={`Rename history for function #${historyFor}`}
          actions={
            <Button tone="ghost" onClick={() => setHistoryFor(null)}>
              Close
            </Button>
          }
        >
          <DataTable
            columns={[
              { label: "When", key: "created_at", mono: true },
              { label: "Old", key: "old_name", mono: true },
              { label: "New", key: "new_name", mono: true },
              { label: "Actor", key: "actor" },
              { label: "Source", key: "source" },
            ]}
            rows={history}
            rowKey={(row) => row.id}
            empty={<EmptyState>No renames recorded for this function.</EmptyState>}
          />
        </Panel>
      ) : null}
    </>
  );
}

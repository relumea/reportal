// The Analyses view: a filtered table of analyses, each row's status badge, its
// tags, an on-demand log drawer and a journalled delete.
//
// The filters live in the URL hash (`#/analyses?status=...&order=...`), the
// convention the router already encodes route state with, so a filtered list is
// shareable and survives a reload.  Owner is not a column: reportal is a
// single-user loopback tool with no account model, and who changed what is what
// the Journal view records, which this view links to.

import { useState } from "react";
import { createSearchParams, useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  KeyValue,
  Loading,
  Muted,
  NA,
  Panel,
  StatusCell,
  Toolbar,
} from "../components";
import {
  ANALYSIS_ORDERS,
  ANALYSIS_STATUSES,
  DEFAULT_ANALYSIS_LIMIT,
  DEFAULT_ANALYSIS_LOG_LIMIT,
} from "../constants";
import { logSeverityLevel } from "../design";
import type {
  AnalysisList,
  AnalysisLogPage,
  AnalysisRow,
  AnalysisStatus,
  BulkResult,
  ImportedFunctionsPayload,
} from "../types";
import { AnalysisStringsPanel } from "../panels/FunctionExtrasPanel";
import { useAsync } from "../useAsync";

const ANALYSES_PATH = "/analyses";

/** The filter values one analyses hash carries; every one is optional. */
interface AnalysisFilters {
  status: string;
  order: string;
  search: string;
}

function filtersFromQuery(query: Record<string, string>): AnalysisFilters {
  const status = query.status ?? "";
  const order = query.order ?? "";
  return {
    status: (ANALYSIS_STATUSES as readonly string[]).includes(status) ? status : "",
    order: (ANALYSIS_ORDERS as readonly string[]).includes(order) ? order : "",
    search: query.search ?? "",
  };
}

/** The API path one filter set reads, with the page bound the view asks for. */
function listPath(filters: AnalysisFilters): string {
  const params = new URLSearchParams();
  if (filters.status) params.set("status", filters.status);
  if (filters.order) params.set("order", filters.order);
  if (filters.search) params.set("search", filters.search);
  params.set("limit", String(DEFAULT_ANALYSIS_LIMIT));
  return `/analyses?${params.toString()}`;
}

/** The lifecycle read and the two writes an analyst makes on one analysis. */
function Lifecycle({ analysisId, onChanged }: { analysisId: number; onChanged: () => void }): ReactNode {
  const { data, error, reload } = useAsync(
    () => api<AnalysisStatus>(`/analyses/${analysisId}/status`),
    [analysisId],
  );
  const [note, setNote] = useState("");
  const [severity, setSeverity] = useState("info");
  const [busy, setBusy] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const act = (work: () => Promise<unknown>): void => {
    setActionError(null);
    setBusy("run");
    void work()
      .then(() => {
        setNote("");
        reload();
        onChanged();
      })
      .catch((failure: unknown) => setActionError(failure))
      .finally(() => setBusy(""));
  };
  return (
    <>
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {data ? (
        <KeyValue
          rows={[
            [
              "status",
              data.terminal ? <Badge tone="ok">{data.status}</Badge> : <Badge tone="warn">{data.status}</Badge>,
            ],
            ["engine", data.engine || NA],
            ["created", data.created_at],
            ["finished", data.finished_at ?? NA],
            ["scans", Object.entries(data.scans_by_status).map(([key, count]) => `${key} ${count}`).join(", ") || NA],
            ["logs", Object.entries(data.logs_by_severity).map(([key, count]) => `${key} ${count}`).join(", ") || NA],
          ]}
        />
      ) : null}
      <Toolbar>
        <Field label="Log entry">
          <input placeholder="what you did" value={note} onChange={(event) => setNote(event.target.value)} />
        </Field>
        <Field label="Severity">
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            {["info", "warn", "error"].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </Field>
        <Button
          pending={busy === "run"}
          disabled={!note.trim()}
          onClick={() =>
            act(() =>
              api(`/analyses/${analysisId}/logs`, {
                method: "POST",
                json: { message: note, severity },
              }),
            )
          }
        >
          Add log entry
        </Button>
        <Button
          tone="ghost"
          pending={busy === "run"}
          onClick={() => act(() => api(`/analyses/${analysisId}/requeue`, { method: "POST" }))}
        >
          Requeue
        </Button>
        <a className="btn btn-ghost" href={`/api/analyses/${analysisId}/func-maps`}>
          Function map
        </a>
        <a className="btn btn-ghost" href={`/api/analyses/${analysisId}/params`}>
          Re-run parameters
        </a>
        <a className="btn btn-ghost" href={`/api/analyses/${analysisId}/bytes`}>
          Raw bytes
        </a>
      </Toolbar>
    </>
  );
}

/** An analysis's import stubs, each with the functions its source mentions it in. */
function ImportedFunctions({ analysisId }: { analysisId: number }): ReactNode {
  const { data, error, reload } = useAsync(
    () => api<ImportedFunctionsPayload>(`/analyses/${analysisId}/imported-functions`),
    [analysisId],
  );
  if (error) return <ErrorNote error={error} onRetry={reload} />;
  if (data === undefined) return <Loading label="Loading imported functions" />;
  if (data.functions.length === 0) {
    return <EmptyState>This analysis carries no imported function stubs.</EmptyState>;
  }
  return (
    <>
      <Muted>
        Callers come from the stored decompilation text ({data.caller_method}); reportal stores no
        call graph.
      </Muted>
      <DataTable
        columns={[
          { label: "Import", key: "name", mono: true },
          {
            label: "Address",
            mono: true,
            render: (row) => `0x${row.va.toString(16)}`,
          },
          {
            label: "Callers",
            render: (row) => (
              <span className="toolbar">
                {row.callers.map((caller) => (
                  <Badge key={caller.id} mono>
                    {caller.name || `0x${caller.va.toString(16)}`}
                  </Badge>
                ))}
                {row.caller_count > row.callers.length ? (
                  <Muted>+{row.caller_count - row.callers.length} more</Muted>
                ) : null}
              </span>
            ),
          },
        ]}
        rows={data.functions}
        rowKey={(row) => row.id}
      />
    </>
  );
}

/** One analysis's log, newest first, with the log's true total. */
function LogDrawer({ analysisId, onClose }: { analysisId: number; onClose: () => void }): ReactNode {
  const [limit, setLimit] = useState(DEFAULT_ANALYSIS_LOG_LIMIT);
  const { data, error, reload } = useAsync(
    () => api<AnalysisLogPage>(`/analyses/${analysisId}/logs?limit=${limit}`),
    [analysisId, limit],
  );
  const shown = data?.logs.length ?? 0;
  const total = data?.total ?? 0;
  return (
    <Panel
      title={`Log for analysis #${analysisId}`}
      subtitle={
        data === undefined
          ? "Newest first."
          : `Newest first, showing ${shown} of ${total} entries.`
      }
      actions={
        <>
          {total > shown ? (
            <Button size="sm" onClick={() => setLimit(limit + DEFAULT_ANALYSIS_LOG_LIMIT)}>
              Load more
            </Button>
          ) : null}
          <Button tone="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </>
      }
    >
      <Lifecycle analysisId={analysisId} onChanged={reload} />
      <ImportedFunctions analysisId={analysisId} />
      <AnalysisStringsPanel analysisId={analysisId} />
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {data === undefined && !error ? (
        <Loading label="Loading the log" />
      ) : (
        <DataTable
          columns={[
            { label: "When", key: "created_at", mono: true },
            {
              label: "Severity",
              render: (entry) => {
                const level = logSeverityLevel(entry.severity);
                return level ? (
                  <Badge hue="severity" level={level}>
                    {entry.severity}
                  </Badge>
                ) : (
                  <Badge>{entry.severity || "n/a"}</Badge>
                );
              },
            },
            { label: "Message", key: "message" },
          ]}
          rows={data?.logs ?? []}
          rowKey={(entry) => entry.id}
          empty={<EmptyState>This analysis recorded no log entries.</EmptyState>}
        />
      )}
    </Panel>
  );
}

export function AnalysesView({ query }: { query: Record<string, string> }): ReactNode {
  const navigate = useNavigate();
  const filters = filtersFromQuery(query);
  const [draft, setDraft] = useState(filters.search);
  const [logFor, setLogFor] = useState<number | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulkTag, setBulkTag] = useState("");
  const [bulkMessage, setBulkMessage] = useState("");
  const [bulkError, setBulkError] = useState<unknown>(null);
  const [bulkAction, setBulkAction] = useState("");

  const path = listPath(filters);
  const result = useAsync(() => api<AnalysisList>(path), [path]);
  const analyses = result.data?.analyses;

  const toggleSelected = (analysisId: number): void => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(analysisId)) next.delete(analysisId);
      else next.add(analysisId);
      return next;
    });
  };

  const runBulk = async (action: string, tag: string): Promise<void> => {
    setBulkError(null);
    setBulkMessage("");
    const ids = Array.from(selected);
    if (!ids.length) {
      setBulkError(new Error("Select at least one analysis."));
      return;
    }
    setBusy(action);
    try {
      const payload = await api<BulkResult>("/analyses/bulk", {
        method: "POST",
        json: { action, analysis_ids: ids, tag },
      });
      const skipped = payload.skipped.length;
      const actionLink = payload.journal_action
        ? ` Journaled as ${payload.journal_action}.`
        : "";
      setBulkMessage(
        `${payload.applied} of ${payload.requested} applied${skipped ? `, ${skipped} skipped` : ""}.${actionLink}`,
      );
      setBulkAction(payload.journal_action ?? "");
      setSelected(new Set());
      if (action === "delete" && logFor !== null && ids.includes(logFor)) setLogFor(null);
      result.reload();
    } catch (failure) {
      setBulkError(failure);
    } finally {
      setBusy("");
    }
  };

  const apply = (patch: Partial<AnalysisFilters>): void => {
    navigate({
      pathname: ANALYSES_PATH,
      search: createSearchParams({
        status: patch.status ?? filters.status,
        order: patch.order ?? filters.order,
        search: patch.search ?? filters.search,
      }).toString(),
    });
  };

  const remove = async (row: AnalysisRow): Promise<void> => {
    setActionError(null);
    setBusy(`delete-${row.id}`);
    try {
      await api(`/analyses/${row.id}`, { method: "DELETE" });
      if (logFor === row.id) setLogFor(null);
      result.reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const filtered =
    filters.status !== "" || filters.search !== "" || filters.order !== "";

  return (
    <>
      <Panel
        title="Analyses"
        subtitle="One row per analysis: the binary it belongs to, how far it got and what ran."
        actions={
          <Button tone="ghost" onClick={() => navigate("/binaries")}>
            Binaries
          </Button>
        }
      >
        <Toolbar>
          <Field label="Status">
            <select
              value={filters.status}
              onChange={(event) => apply({ status: event.target.value })}
            >
              <option value="">any status</option>
              {ANALYSIS_STATUSES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Order">
            <select value={filters.order} onChange={(event) => apply({ order: event.target.value })}>
              <option value="">newest first</option>
              {ANALYSIS_ORDERS.map((value) => (
                <option key={value} value={value}>
                  {value === "newest" ? "newest first" : "oldest first"}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Search">
            <input
              placeholder="binary or engine"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") apply({ search: draft.trim() });
              }}
            />
          </Field>
          <Button onClick={() => apply({ search: draft.trim() })}>Search</Button>
          {filtered ? (
            <Button
              tone="ghost"
              onClick={() => {
                setDraft("");
                navigate({ pathname: ANALYSES_PATH, search: "" });
              }}
            >
              Clear
            </Button>
          ) : null}
        </Toolbar>
        <Muted>
          Reportal is a single-user loopback tool, so an analysis has no owner column. The{" "}
          <a href="#/journal">Journal</a> lists who did what, entry by entry.
        </Muted>
        {result.error ? <ErrorNote error={result.error} onRetry={result.reload} /> : null}
        {actionError ? <ErrorNote error={actionError} /> : null}
        {analyses === undefined ? (
          <Loading label="Loading analyses" />
        ) : analyses.length === 0 ? (
          <EmptyState>
            {filtered
              ? `No analyses match this filter (${result.data?.total ?? 0} stored). Clear it to see them all.`
              : "No analyses yet. Import a rebrew project or create one for a binary."}
          </EmptyState>
        ) : (
          <>
            <div className="row-between">
              <span className="muted">
                {analyses.length} of {result.data?.total ?? analyses.length} analyses
              </span>
            </div>
            <DataTable
              columns={[
                {
                  label: "",
                  render: (row) => (
                    <input
                      type="checkbox"
                      aria-label={`select analysis ${row.id}`}
                      checked={selected.has(row.id)}
                      onChange={() => toggleSelected(row.id)}
                    />
                  ),
                },
                { label: "ID", key: "id", numeric: true },
                {
                  label: "Binary",
                  render: (row) => <a href={`#/binaries/${row.binary_id}`}>{row.binary_name}</a>,
                },
                {
                  label: "Platform",
                  render: (row) => (
                    <span className="toolbar">
                      <Badge mono>{row.binary_format || "n/a"}</Badge>
                      <Badge mono>{row.binary_arch || "n/a"}</Badge>
                    </span>
                  ),
                },
                {
                  label: "Size",
                  numeric: true,
                  render: (row) => row.binary_size.toLocaleString(),
                },
                { label: "Engine", key: "engine" },
                { label: "Created", key: "created_at", mono: true },
                { label: "Status", render: (row) => <StatusCell status={row.status} /> },
                {
                  label: "Tags",
                  render: (row) =>
                    row.tags.length ? (
                      <span className="toolbar">
                        {row.tags.map((tag) => (
                          <Badge key={tag}>{tag}</Badge>
                        ))}
                      </span>
                    ) : (
                      "n/a"
                    ),
                },
                {
                  label: "Actions",
                  render: (row) => (
                    <div className="actions-cell">
                      <Button
                        size="sm"
                        onClick={() => setLogFor(logFor === row.id ? null : row.id)}
                      >
                        View log
                      </Button>
                      <ConfirmButton
                        label="Delete"
                        message={`Delete analysis ${row.id}?`}
                        pending={busy === `delete-${row.id}`}
                        onConfirm={() => void remove(row)}
                      />
                    </div>
                  ),
                },
              ]}
              rows={analyses}
              rowKey={(row) => row.id}
            />
          </>
        )}
      </Panel>
      {logFor !== null ? (
        <LogDrawer analysisId={logFor} onClose={() => setLogFor(null)} />
      ) : null}
      {analyses && analyses.length > 0 ? (
        <Panel
          title="Bulk actions"
          subtitle="Applies to the rows checked in the table above; a tag writes the binaries the analyses belong to."
          actions={
            <>
              <span className="muted">{selected.size} selected</span>
              <Button
                tone="primary"
                pending={busy === "add_tag"}
                onClick={() => void runBulk("add_tag", bulkTag)}
              >
                Add tag
              </Button>
              <Button
                pending={busy === "remove_tag"}
                onClick={() => void runBulk("remove_tag", bulkTag)}
              >
                Remove tag
              </Button>
              <ConfirmButton
                label="Delete"
                message={`Delete ${selected.size}?`}
                pending={busy === "delete"}
                disabled={selected.size === 0}
                onConfirm={() => void runBulk("delete", "")}
              />
              <Button tone="ghost" onClick={() => setSelected(new Set())}>
                Clear selection
              </Button>
            </>
          }
        >
          <Toolbar>
            <Field label="Tag">
              <input
                placeholder="tag name"
                value={bulkTag}
                onChange={(event) => setBulkTag(event.target.value)}
              />
            </Field>
          </Toolbar>
          {bulkError ? <ErrorNote error={bulkError} /> : null}
          {bulkMessage ? <p className="muted">{bulkMessage}</p> : null}
          {bulkAction ? (
            <p className="muted">
              Revert this action: <a href={`#/journal/${bulkAction}`}>{bulkAction}</a>
            </p>
          ) : null}
        </Panel>
      ) : null}
    </>
  );
}

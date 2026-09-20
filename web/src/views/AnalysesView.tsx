// The Analyses view: a filtered table of analyses, each row's status badge, its
// tags, an on-demand log drawer and a journalled delete.
//
// The filters live in the URL hash (`#/analyses?status=...&order=...`), the
// convention the router already encodes route state with, so a filtered list is
// shareable and survives a reload.  Owner is not a column: reportal is a
// single-user loopback tool with no account model, and who changed what is what
// the Journal view records, which this view links to.

import { useEffect, useState } from "react";
import { createSearchParams, useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  ConfirmButton,
  CopyValue,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  HashIdenticon,
  KeyValue,
  Loading,
  Muted,
  NA,
  Panel,
  StatusCell,
  Toolbar,
} from "../components";
import {
  ANALYSIS_ORDER_LABELS,
  ANALYSIS_ORDERS,
  ANALYSIS_STATUSES,
  WORKSPACE_FILTERS,
  DEFAULT_ANALYSIS_LIMIT,
  DEFAULT_ANALYSIS_LOG_LIMIT,
  MAX_ANALYSIS_LIMIT,
  SEARCH_DEBOUNCE_MS,
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
import { AnalysisScans } from "../panels/ScansPanel";

const ANALYSES_PATH = "/analyses";

/** One removable chip naming an active list filter. */
function FilterChip({
  label,
  onClear,
}: {
  label: string;
  onClear: () => void;
}): ReactNode {
  return (
    <span className="chip">
      <span className="chip-label">{label}</span>
      <button type="button" className="chip-clear" aria-label={`Clear ${label}`} onClick={onClear}>
        x
      </button>
    </span>
  );
}

/** The filter values one analyses hash carries; every one is optional. */
interface AnalysisFilters {
  /** The status multi-select: any-of, repeated as the API takes it. */
  status: string[];
  order: string;
  search: string;
  /** The workspace control: personal, team or public. */
  workspace: string;
  /** The stored binary format, and its architecture beside it. */
  platform: string;
  arch: string;
  /** Rows to ask for, as text; a value the route refuses never reaches it. */
  limit: string;
}

/** The page bound a hash carries: a number the route accepts, else the default. */
function limitFromQuery(raw: string | undefined): string {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (Number.isNaN(parsed)) return String(DEFAULT_ANALYSIS_LIMIT);
  return String(Math.min(Math.max(parsed, 1), MAX_ANALYSIS_LIMIT));
}

function filtersFromQuery(query: Record<string, string>): AnalysisFilters {
  const order = query.order ?? "";
  const statuses = (query.status ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => (ANALYSIS_STATUSES as readonly string[]).includes(value));
  return {
    status: statuses,
    order: (ANALYSIS_ORDERS as readonly string[]).includes(order) ? order : "",
    search: query.search ?? "",
    workspace: (WORKSPACE_FILTERS as readonly string[]).includes(query.workspace ?? "")
      ? (query.workspace ?? "")
      : "",
    platform: query.platform ?? "",
    arch: query.arch ?? "",
    limit: limitFromQuery(query.limit),
  };
}

/** The API path one filter set reads, with the page bound the view asks for. */
function listPath(filters: AnalysisFilters): string {
  const params = new URLSearchParams();
  // The statuses are repeated, which is the any-of form the route accepts.
  for (const value of filters.status) params.append("status", value);
  if (filters.order) params.set("order", filters.order);
  if (filters.search) params.set("search", filters.search);
  if (filters.workspace) params.set("workspace", filters.workspace);
  if (filters.platform) params.set("platform", filters.platform);
  if (filters.arch) params.set("arch", filters.arch);
  params.set("limit", filters.limit);
  return `/analyses?${params.toString()}`;
}

/** The hash one filter set writes; the statuses are comma-joined there. */
function filterSearch(filters: AnalysisFilters): string {
  const params = new URLSearchParams();
  if (filters.status.length) params.set("status", filters.status.join(","));
  if (filters.order) params.set("order", filters.order);
  if (filters.search) params.set("search", filters.search);
  if (filters.workspace) params.set("workspace", filters.workspace);
  if (filters.platform) params.set("platform", filters.platform);
  if (filters.arch) params.set("arch", filters.arch);
  if (filters.limit !== String(DEFAULT_ANALYSIS_LIMIT)) params.set("limit", filters.limit);
  return params.toString();
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
      <AnalysisScans analysisId={analysisId} />
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

/** One row's tags: the chips with a remove control each, and a field that adds
 *  one.  A change replaces the binary's whole set through the analysis route,
 *  which is the scope reportal tags at, so the chips and the analytic's own
 *  Tags panel cannot disagree. */
function RowTags({ row, onChanged }: { row: AnalysisRow; onChanged: () => void }): ReactNode {
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  const save = (names: string[]): void => {
    setBusy(true);
    setFailure(null);
    void api(`/analyses/${row.id}/tags`, { method: "PATCH", json: { tags: names } })
      .then(() => {
        setDraft("");
        onChanged();
      })
      .catch((error: unknown) => setFailure(error))
      .finally(() => setBusy(false));
  };

  const add = (): void => {
    const name = draft.trim();
    if (name === "" || row.tags.includes(name)) return;
    save([...row.tags, name]);
  };

  return (
    <span className="row-tags">
      {row.tags.map((tag) => (
        <span key={tag} className="chip">
          <span className="chip-label">{tag}</span>
          <button
            type="button"
            className="chip-clear"
            aria-label={`Remove tag ${tag}`}
            disabled={busy}
            onClick={() => save(row.tags.filter((entry) => entry !== tag))}
          >
            x
          </button>
        </span>
      ))}
      <input
        className="tag-add"
        size={6}
        placeholder="tag"
        aria-label={`Add tag to analysis ${row.id}`}
        value={draft}
        disabled={busy}
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            add();
          }
        }}
      />
      {failure ? <ErrorNote error={failure} /> : null}
    </span>
  );
}

export function AnalysesView({ query }: { query: Record<string, string> }): ReactNode {
  const navigate = useNavigate();
  const filters = filtersFromQuery(query);
  const [draft, setDraft] = useState(filters.search);
  useEffect(() => {
    setDraft(filters.search);
  }, [filters.search]);
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
      search: createSearchParams(
        Object.fromEntries(
          new URLSearchParams(filterSearch({ ...filters, ...patch })),
        ),
      ).toString(),
    });
  };
  useEffect(() => {
    const next = draft.trim();
    if (next === filters.search) return undefined;
    const handle = window.setTimeout(() => apply({ search: next }), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(handle);
    // apply is recreated every render; the draft is the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft, filters.search]);

  /** Toggle one status in the any-of set; the last one off means any status. */
  const toggleStatus = (value: string): void => {
    const next = filters.status.includes(value)
      ? filters.status.filter((entry) => entry !== value)
      : [...filters.status, value];
    apply({ status: next });
  };

  const requeue = async (row: AnalysisRow): Promise<void> => {
    setActionError(null);
    setBusy(`requeue-${row.id}`);
    try {
      await api(`/analyses/${row.id}/requeue`, { method: "POST" });
      result.reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  /** The hashes of the selected rows, for the bulk copy control. */
  const copyHashes = async (): Promise<void> => {
    const hashes = (analyses ?? [])
      .filter((row) => selected.has(row.id))
      .map((row) => row.binary_sha256)
      .filter((hash) => hash !== "");
    setBulkMessage(hashes.join("\n"));
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(hashes.join("\n")).catch(() => undefined);
    }
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
    filters.status.length > 0 ||
    filters.search !== "" ||
    filters.order !== "" ||
    filters.workspace !== "" ||
    filters.platform !== "" ||
    filters.arch !== "";

  return (
    <>
      <Panel
        title="Analyses"
        subtitle="One row per analysis: the binary it belongs to, how far it got and what ran."
        actions={
          <Toolbar>
            <Button tone="primary" onClick={() => navigate("/binaries")}>
              Upload File
            </Button>
          </Toolbar>
        }
      >
        <Toolbar>
          <Field label="Workspace">
            <select
              value={filters.workspace}
              onChange={(event) => apply({ workspace: event.target.value })}
            >
              <option value="">any scope</option>
              {WORKSPACE_FILTERS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <div className="chip-row" role="group" aria-label="Status">
            {ANALYSIS_STATUSES.map((value) => (
              <Button
                key={value}
                size="sm"
                tone={filters.status.includes(value) ? "primary" : "ghost"}
                title={`Show ${value} analyses`}
                onClick={() => toggleStatus(value)}
              >
                {value}
              </Button>
            ))}
          </div>
          <Field label="Platform">
            <select
              value={filters.platform}
              onChange={(event) => apply({ platform: event.target.value })}
            >
              <option value="">any platform</option>
              {(result.data?.platforms ?? []).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Architecture">
            <select value={filters.arch} onChange={(event) => apply({ arch: event.target.value })}>
              <option value="">any architecture</option>
              {(result.data?.architectures ?? []).map((value) => (
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
                  {ANALYSIS_ORDER_LABELS[value]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Show" hint={`up to ${MAX_ANALYSIS_LIMIT}`}>
            <input
              type="number"
              min={1}
              max={MAX_ANALYSIS_LIMIT}
              value={filters.limit}
              onChange={(event) => apply({ limit: limitFromQuery(event.target.value) })}
            />
          </Field>
          <Field label="Search">
            <input
              placeholder="binary, engine or hash"
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
        {filtered ? (
          <div className="chips">
            {filters.search ? (
              <FilterChip
                label={`Search ${filters.search}`}
                onClear={() => {
                  setDraft("");
                  apply({ search: "" });
                }}
              />
            ) : null}
            {filters.workspace ? (
              <FilterChip
                label={`Workspace ${filters.workspace}`}
                onClear={() => apply({ workspace: "" })}
              />
            ) : null}
            {filters.status.map((value) => (
              <FilterChip
                key={value}
                label={`Status ${value}`}
                onClear={() => apply({ status: filters.status.filter((entry) => entry !== value) })}
              />
            ))}
            {filters.platform ? (
              <FilterChip
                label={`Platform ${filters.platform}`}
                onClear={() => apply({ platform: "" })}
              />
            ) : null}
            {filters.arch ? (
              <FilterChip label={`Arch ${filters.arch}`} onClear={() => apply({ arch: "" })} />
            ) : null}
            {filters.order ? (
              <FilterChip
                label={`Order ${
                  ANALYSIS_ORDER_LABELS[filters.order as (typeof ANALYSIS_ORDERS)[number]] ??
                  filters.order
                }`}
                onClear={() => apply({ order: "" })}
              />
            ) : null}
          </div>
        ) : null}
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
                {analyses.length < (result.data?.total ?? 0)
                  ? `; raise Show (up to ${MAX_ANALYSIS_LIMIT}) to list the rest`
                  : ""}
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
                  render: (row) => (
                    <span className="toolbar">
                      {row.binary_sha256 ? <HashIdenticon hash={row.binary_sha256} /> : null}
                      {row.visibility === "team" ? (
                        <Badge
                          mono
                          title={`team-scoped${row.owner_team_name ? `: ${row.owner_team_name}` : ""}`}
                        >
                          lock
                        </Badge>
                      ) : null}
                      <a href={`#/binaries/${row.binary_id}`}>{row.binary_name}</a>
                    </span>
                  ),
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
                {
                  label: "SHA-256",
                  render: (row) => <CopyValue value={row.binary_sha256} compact />,
                },
                { label: "Created", key: "created_at", mono: true },
                { label: "Status", render: (row) => <StatusCell status={row.status} /> },
                {
                  label: "Owner",
                  render: (row) =>
                    row.owner_team_name ? (
                      <Badge>{row.owner_team_name}</Badge>
                    ) : (
                      <span className="muted">personal</span>
                    ),
                },
                {
                  label: "Seen by",
                  render: (row) => <Badge mono>{row.visibility}</Badge>,
                },
                {
                  label: "Tags",
                  render: (row) => (
                    <RowTags
                      row={row}
                      onChanged={() => {
                        result.reload();
                      }}
                    />
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
                      <a
                        className="btn btn-sm btn-ghost"
                        href={`/api/binaries/${row.binary_id}/download`}
                      >
                        Download
                      </a>
                      <Button
                        size="sm"
                        pending={busy === `requeue-${row.id}`}
                        title="Back to pending with its finish time cleared"
                        onClick={() => void requeue(row)}
                      >
                        Re-analyse
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
              onRowClick={(row) => {
                if (row.status === "failed") {
                  setLogFor(row.id);
                  return;
                }
                navigate(`/binaries/${row.binary_id}`);
              }}
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
              <Button onClick={() => void copyHashes()} disabled={selected.size === 0}>
                Copy hashes
              </Button>
              <Button
                pending={busy === "remove_tag"}
                onClick={() => void runBulk("remove_tag", bulkTag)}
              >
                Remove tag
              </Button>
              <ConfirmButton
                label="Delete"
                message={`Delete ${selected.size} selected ${selected.size === 1 ? "analysis" : "analyses"}?`}
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
          <p className="muted" role="status">{bulkMessage}</p>
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

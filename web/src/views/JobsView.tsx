// The Jobs view: the async operation workflow over `jobs.JOB_KINDS`.  It
// queues one operation, lists what is queued and finished with its status and
// result, refreshes while anything is live, and cancels what has not started.
//
// The queue is the server's: this view reads `GET /api/jobs` and posts to
// `POST /api/jobs`, `POST /api/jobs/<id>/cancel` and `POST /api/jobs/run`.  It
// never runs an operation itself, so what a client sees here is what the
// server did.

import { useState } from "react";
import { createSearchParams, useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Muted,
  Panel,
  Toolbar,
} from "../components";
import type { BadgeTone } from "../components";
import type { JobsPayload, JobView } from "../types";
import { useAsync } from "../useAsync";

const STATUS_TONES: Record<string, BadgeTone> = {
  queued: "info",
  running: "warn",
  done: "ok",
  failed: "danger",
  cancelled: "neutral",
};

function jobTone(status: string): BadgeTone {
  return STATUS_TONES[status] ?? "neutral";
}

function jobSummary(job: JobView): string {
  if (job.error) return job.error;
  if (job.status === "done") return "finished";
  return job.message;
}

function JobDetail({ job }: { job: JobView }): ReactNode {
  if (job.result === null) return null;
  return (
    <details>
      <summary>Result</summary>
      <pre>{JSON.stringify(job.result, null, 2)}</pre>
    </details>
  );
}

/** The listing filters, every one optional and all of them in the route hash. */
interface JobFilters {
  status: string;
  kind: string;
  binaryId: string;
  limit: string;
}

const LIST_FILTER = "limit";

function filtersFromQuery(query: Record<string, string>): JobFilters {
  return {
    status: query.status ?? "",
    kind: query.kind ?? "",
    binaryId: query.binary_id ?? "",
    limit: query[LIST_FILTER] ?? "",
  };
}

/** The API path one filter set reads. */
function listPath(filters: JobFilters): string {
  const params = new URLSearchParams();
  if (filters.status) params.set("status", filters.status);
  if (filters.kind) params.set("kind", filters.kind);
  if (filters.binaryId.trim()) params.set("binary_id", filters.binaryId.trim());
  if (filters.limit.trim()) params.set("limit", filters.limit.trim());
  const search = params.toString();
  return search ? `/jobs?${search}` : "/jobs";
}

export function JobsView({
  query = {},
}: {
  /** The route hash, whose keys are the filters this view applies. */
  query?: Record<string, string>;
}): ReactNode {
  const navigate = useNavigate();
  const filters = filtersFromQuery(query);
  const [kind, setKind] = useState("");
  const [binaryId, setBinaryId] = useState("");
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const path = listPath(filters);
  const { data, error, reload } = useAsync(
    () => api<JobsPayload>(path),
    [path],
    true,
    (payload) => (payload && payload.queued > 0 ? 2000 : false),
  );

  const apply = (patch: Partial<JobFilters>): void => {
    const next = { ...filters, ...patch };
    const params = new URLSearchParams();
    if (next.status) params.set("status", next.status);
    if (next.kind) params.set("kind", next.kind);
    if (next.binaryId.trim()) params.set("binary_id", next.binaryId.trim());
    if (next.limit.trim()) params.set(LIST_FILTER, next.limit.trim());
    navigate({ pathname: "/jobs", search: createSearchParams(params).toString() });
  };
  const filtered =
    filters.status !== "" || filters.kind !== "" || filters.binaryId !== "" || filters.limit !== "";

  const act = (work: () => Promise<unknown>): void => {
    setActionError(null);
    setBusy(true);
    void work()
      .then(() => reload())
      .catch((failure: unknown) => setActionError(failure))
      .finally(() => setBusy(false));
  };

  const submit = (): void => {
    const id = Number(binaryId);
    if (!kind || !Number.isFinite(id) || id <= 0) return;
    const params = domain ? { domain } : {};
    act(() =>
      api("/jobs", { method: "POST", json: { kind, binary_id: id, params } }).then(() => {
        setBinaryId("");
        setDomain("");
      }),
    );
  };

  return (
    <Panel
      title="Jobs"
      subtitle="Operations queued for the server: a run id, a status, a result and a cancel."
      actions={
        <Button tone="ghost" pending={busy} onClick={() => act(() => api("/jobs/run", { method: "POST" }))}>
          Run waiting now
        </Button>
      }
    >
      <Toolbar>
        <Field label="Status filter">
          <select
            value={filters.status}
            onChange={(event) => apply({ status: event.target.value })}
          >
            <option value="">any status</option>
            {(data?.statuses ?? []).map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Kind filter">
          <select value={filters.kind} onChange={(event) => apply({ kind: event.target.value })}>
            <option value="">any kind</option>
            {(data?.kinds ?? []).map((entry) => (
              <option key={entry.name} value={entry.name}>
                {entry.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Binary filter" hint="job's binary id">
          <input
            inputMode="numeric"
            placeholder="binary id"
            value={filters.binaryId}
            onChange={(event) => apply({ binaryId: event.target.value })}
          />
        </Field>
        <Field label="Show" hint="how many jobs">
          <input
            type="number"
            min={1}
            placeholder="50"
            value={filters.limit}
            onChange={(event) => apply({ limit: event.target.value })}
          />
        </Field>
        {filtered ? (
          <Button tone="ghost" onClick={() => navigate({ pathname: "/jobs", search: "" })}>
            Clear
          </Button>
        ) : null}
      </Toolbar>
      <Toolbar>
        <Field label="Operation">
          <select value={kind} onChange={(event) => setKind(event.target.value)}>
            <option value="">choose one</option>
            {(data?.kinds ?? []).map((entry) => (
              <option key={entry.name} value={entry.name}>
                {entry.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Binary">
          <input
            placeholder="binary id"
            value={binaryId}
            onChange={(event) => setBinaryId(event.target.value)}
          />
        </Field>
        <Field label="Domain">
          <input
            placeholder="behavior or hardening domain"
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
          />
        </Field>
        <Button tone="primary" pending={busy} disabled={!kind || !binaryId} onClick={submit}>
          Queue
        </Button>
      </Toolbar>
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {data ? (
        <Muted>
          {`${data.queued} waiting, ${data.count} shown of ${data.total}`}
        </Muted>
      ) : null}
      {data === undefined ? null : (
        <DataTable
          columns={[
            { label: "Id", key: "id", numeric: true },
            { label: "Operation", key: "label" },
            { label: "Binary", key: "binary_id", numeric: true },
            {
              label: "Status",
              render: (job) => <Badge tone={jobTone(job.status)}>{job.status}</Badge>,
            },
            {
              label: "Progress",
              render: (job) => `${job.progress}/${job.steps_total}`,
            },
            { label: "Created", key: "created_at" },
            { label: "Message", render: (job) => jobSummary(job) },
            { label: "Result", render: (job) => <JobDetail job={job} /> },
            {
              label: "",
              render: (job) =>
                job.status === "queued" ? (
                  <Button
                    tone="ghost"
                    pending={busy}
                    onClick={() => act(() => api(`/jobs/${job.id}/cancel`, { method: "POST" }))}
                  >
                    Cancel
                  </Button>
                ) : null,
            },
          ]}
          rows={data.jobs}
          rowKey={(job) => job.id}
          empty={
            <EmptyState>
              Nothing queued. Choose an operation and a binary above; the server's pool runs it.
            </EmptyState>
          }
        />
      )}
    </Panel>
  );
}

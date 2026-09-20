import { useState } from "react";
import { createSearchParams, useNavigate } from "react-router";
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
  StatusCell,
  Toolbar,
} from "../components";
import { clearPanels } from "../panelCache";
import type { JournalEntry, JournalList, JournalRevertResult } from "../types";
import { useAsync } from "../useAsync";

// Entries the list view asks for; the server clamps its own hard cap.
const LIST_LIMIT = 100;

/** The listing's own filters, both in the route hash. */
interface JournalFilters {
  actor: string;
  limit: string;
}

export function JournalView({
  action,
  query = {},
}: {
  action: string | null;
  /** The route hash: the actor filter and the page size live there. */
  query?: Record<string, string>;
}): ReactNode {
  const navigate = useNavigate();
  const filters: JournalFilters = {
    actor: query.actor ?? "",
    limit: query.limit ?? "",
  };
  // One listing route answers both modes: the per-action route serves every
  // entry of an action and takes no filters, so selecting an action asks the
  // listing for that action instead and the actor and page size keep working.
  const params = new URLSearchParams();
  params.set("limit", filters.limit.trim() || String(LIST_LIMIT));
  if (action) params.set("action", action);
  if (filters.actor) params.set("actor", filters.actor);
  const path = `/journal?${params.toString()}`;
  const { data, error, reload } = useAsync(() => api<JournalList>(path), [path]);

  const apply = (patch: Partial<JournalFilters>): void => {
    const next = { ...filters, ...patch };
    const nextParams = new URLSearchParams();
    if (next.actor) nextParams.set("actor", next.actor);
    if (next.limit.trim()) nextParams.set("limit", next.limit.trim());
    navigate({
      pathname: action ? `/journal/${encodeURIComponent(action)}` : "/journal",
      search: createSearchParams(nextParams).toString(),
    });
  };
  const [message, setMessage] = useState("");
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const revertAction = async (entry: JournalEntry): Promise<void> => {
    setFailure(null);
    setMessage("");
    setBusy(`action-${entry.id}`);
    try {
      const result = await api<JournalRevertResult>("/journal/revert", {
        method: "POST",
        json: { action: entry.action },
      });
      clearPanels();
      setMessage(`Action ${entry.action}: reverted ${result.reverted ?? 0}, failed ${result.failed ?? 0}.`);
      reload();
    } catch (errorFailure) {
      setFailure(errorFailure);
    } finally {
      setBusy("");
    }
  };

  const revertEntry = async (entry: JournalEntry): Promise<void> => {
    setFailure(null);
    setMessage("");
    setBusy(`entry-${entry.id}`);
    try {
      const result = await api<JournalRevertResult>("/journal/revert", {
        method: "POST",
        json: { entry_id: entry.id },
      });
      clearPanels();
      setMessage(`Entry ${entry.id}: ${result.status ?? "unknown"}.`);
      reload();
    } catch (errorFailure) {
      setFailure(errorFailure);
    } finally {
      setBusy("");
    }
  };

  const entries = data?.entries ?? null;

  return (
    <Panel
      title="Journal"
      subtitle="Every wired mutation records its inverse here; a revert replays the action newest-first and works from another process."
      actions={
        action ? (
          <Button tone="ghost" onClick={() => navigate("/journal")}>
            Show all actions
          </Button>
        ) : null
      }
    >
      <Toolbar>
        <Field label="Actor" hint="who wrote the entry">
          <select value={filters.actor} onChange={(event) => apply({ actor: event.target.value })}>
            <option value="">any actor</option>
            {(data?.actors ?? []).map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Show" hint="how many entries">
          <input
            type="number"
            min={1}
            placeholder={String(LIST_LIMIT)}
            value={filters.limit}
            onChange={(event) => apply({ limit: event.target.value })}
          />
        </Field>
        {filters.actor !== "" || filters.limit !== "" ? (
          <Button
            tone="ghost"
            onClick={() =>
              navigate({
                pathname: action ? `/journal/${encodeURIComponent(action)}` : "/journal",
                search: "",
              })
            }
          >
            Clear filters
          </Button>
        ) : null}
      </Toolbar>
      {action ? (
        <p className="muted">
          Action <span className="mono">{action}</span>
        </p>
      ) : null}
      {failure ? <ErrorNote error={failure} /> : null}
      <Muted live>{message}</Muted>
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {entries === null ? (
        <Loading label="Loading journal entries" />
      ) : (
        <DataTable
          columns={[
            { label: "Entry", key: "id", numeric: true },
            {
              label: "Action",
              mono: true,
              render: (row) => <a href={`#/journal/${row.action}`}>{row.action}</a>,
            },
            { label: "Kind", key: "kind" },
            { label: "Status", render: (row) => <StatusCell status={row.status} /> },
            { label: "Actor", render: (row) => row.actor || "-" },
            { label: "Created", key: "created_at", mono: true },
            { label: "Description", key: "description" },
            {
              label: "Actions",
              render: (row) => (
                <div className="actions-cell">
                  <ConfirmButton
                    label="Revert entry"
                    message="Revert this entry and restore the row it changed?"
                    disabled={row.status !== "active"}
                    pending={busy === `entry-${row.id}`}
                    onConfirm={() => void revertEntry(row)}
                  />
                  <ConfirmButton
                    label="Revert action"
                    message="Revert every entry this action made?"
                    disabled={row.status !== "active"}
                    pending={busy === `action-${row.id}`}
                    onConfirm={() => void revertAction(row)}
                  />
                </div>
              ),
            },
          ]}
          rows={entries}
          rowKey={(row) => row.id}
          empty={<EmptyState>No journaled actions yet. Every mutation records its inverse here.</EmptyState>}
        />
      )}
    </Panel>
  );
}

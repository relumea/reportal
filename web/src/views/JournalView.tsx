import { useState } from "react";
import { useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Button,
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorNote,
  Loading,
  Muted,
  Panel,
  StatusCell,
} from "../components";
import { clearPanels } from "../panelCache";
import type { JournalEntry, JournalList, JournalRevertResult } from "../types";
import { useAsync } from "../useAsync";

// Entries the list view asks for; the server clamps its own hard cap.
const LIST_LIMIT = 100;

export function JournalView({ action }: { action: string | null }): ReactNode {
  const navigate = useNavigate();
  const query = action ? `/journal/${encodeURIComponent(action)}` : `/journal?limit=${LIST_LIMIT}`;
  const { data, error, reload } = useAsync(() => api<JournalList>(query), [query]);
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
      {action ? (
        <p className="muted">
          Action <span className="mono">{action}</span>
        </p>
      ) : null}
      {failure ? <ErrorNote error={failure} /> : null}
      {message ? <Muted>{message}</Muted> : null}
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
            { label: "Created", key: "created_at", mono: true },
            { label: "Description", key: "description" },
            {
              label: "Actions",
              render: (row) => (
                <div className="actions-cell">
                  <ConfirmButton
                    label="Revert entry"
                    message="Revert?"
                    disabled={row.status !== "active"}
                    pending={busy === `entry-${row.id}`}
                    onConfirm={() => void revertEntry(row)}
                  />
                  <ConfirmButton
                    label="Revert action"
                    message="Revert all?"
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

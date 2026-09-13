import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  DataTable,
  EmptyState,
  ErrorNote,
  Loading,
  Muted,
  Panel,
} from "../components";
import type {
  ComponentDeactivateResult,
  ComponentList,
  ComponentReloadAll,
  ComponentReloadResult,
  ComponentRow,
} from "../types";
import { useAsync } from "../useAsync";

export function ComponentsView(): ReactNode {
  const { data, error, reload } = useAsync(() => api<ComponentList>("/components"), []);
  const [message, setMessage] = useState("");
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const reloadOne = async (row: ComponentRow): Promise<void> => {
    setFailure(null);
    setMessage("");
    setBusy(row.name);
    try {
      const result = await api<ComponentReloadResult>("/components/reload", {
        method: "POST",
        json: { name: row.name },
      });
      setMessage(
        `${result.name}: ${result.changed ? "changed" : "unchanged"} (${result.old_origin} -> ${result.new_origin})`,
      );
      reload();
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy("");
    }
  };

  const reloadAll = async (): Promise<void> => {
    setFailure(null);
    setMessage("");
    setBusy("all");
    try {
      const report = await api<ComponentReloadAll>("/components/reload", {
        method: "POST",
        json: { all: true },
      });
      setMessage(
        `Reloaded ${report.count}, changed ${report.changed.length}, skipped ${report.skipped.length}.`,
      );
      reload();
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy("");
    }
  };

  const withdrawOne = async (row: ComponentRow): Promise<void> => {
    setFailure(null);
    setMessage("");
    setBusy(`withdraw:${row.name}`);
    try {
      const result = await api<ComponentDeactivateResult>(
        `/components/${encodeURIComponent(row.name)}/deactivate`,
        { method: "POST" },
      );
      const names = result.deactivated.map((entry) => entry.name).join(", ") || "nothing";
      const journal = result.journaled
        ? `journal ${result.journal_action ?? ""}`
        : "not journaled (process-local binding)";
      setMessage(`${result.name}: withdrew ${names} (${journal})`);
      reload();
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy("");
    }
  };

  const rows = data?.components ?? null;

  return (
    <Panel
      title="Components"
      subtitle="Reloading re-reads one component's module and swaps its live registry entry; withdrawing runs its revert and revokes the names it provided. A run already in flight keeps its own snapshot."
      actions={
        <Button tone="primary" pending={busy === "all"} onClick={() => void reloadAll()}>
          Reload all
        </Button>
      }
    >
      {failure ? <ErrorNote error={failure} /> : null}
      {message ? <Muted>{message}</Muted> : null}
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {rows === null ? (
        <Loading label="Loading components" />
      ) : (
        <DataTable
          columns={[
            { label: "Name", key: "name", mono: true },
            {
              label: "Requires",
              mono: true,
              render: (row) => (row.requires.length > 0 ? row.requires.join(", ") : "none"),
            },
            {
              label: "Provides",
              mono: true,
              render: (row) => (row.provides.length > 0 ? row.provides.join(", ") : "none"),
            },
            { label: "Origin", render: (row) => <Badge mono>{row.origin}</Badge> },
            {
              label: "Reloadable",
              render: (row) => (row.reloadable ? <Badge tone="ok">yes</Badge> : <Badge>no</Badge>),
            },
            {
              label: "Actions",
              render: (row) => (
                <div className="actions-cell">
                  <Button
                    size="sm"
                    disabled={!row.reloadable}
                    pending={busy === row.name}
                    onClick={() => void reloadOne(row)}
                  >
                    Reload
                  </Button>
                  <Button
                    size="sm"
                    disabled={!row.withdrawable}
                    title={row.withdrawable ? undefined : row.withdraw_reason}
                    pending={busy === `withdraw:${row.name}`}
                    onClick={() => void withdrawOne(row)}
                  >
                    Withdraw
                  </Button>
                </div>
              ),
            },
          ]}
          rows={rows}
          rowKey={(row) => row.name}
          empty={<EmptyState>No components registered.</EmptyState>}
        />
      )}
    </Panel>
  );
}

import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import { Button, DataTable, EmptyState, ErrorNote, Field, Panel, Toolbar } from "../components";
import type { Collection } from "../types";
import { useAsync } from "../useAsync";

export function CollectionsView(): ReactNode {
  const { data, error, reload } = useAsync(() => api<{ collections: Collection[] }>("/collections"), []);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const create = async (): Promise<void> => {
    setActionError(null);
    setBusy(true);
    try {
      await api("/collections", { method: "POST", json: { name, description } });
      setName("");
      setDescription("");
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(false);
    }
  };

  const collections = data?.collections;

  return (
    <Panel
      title="Collections"
      subtitle="Named groups of binaries a session works through together."
      actions={
        <Button tone="primary" pending={busy} disabled={!name.trim()} onClick={() => void create()}>
          Create
        </Button>
      }
    >
      <Toolbar>
        <Field label="Name">
          <input placeholder="name" value={name} onChange={(event) => setName(event.target.value)} />
        </Field>
        <Field label="Description">
          <input
            placeholder="description"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </Field>
      </Toolbar>
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {collections === undefined ? null : (
        <DataTable
          columns={[
            { label: "ID", key: "id", numeric: true },
            { label: "Name", key: "name" },
            { label: "Description", key: "description" },
            { label: "Scope", key: "scope" },
            { label: "Binaries", key: "binary_count", numeric: true },
          ]}
          rows={collections}
          rowKey={(row) => row.id}
          empty={<EmptyState>No collections yet. Name one above to start grouping binaries.</EmptyState>}
        />
      )}
    </Panel>
  );
}

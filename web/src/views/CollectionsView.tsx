// The Collections view: the list, one selected collection's members and tags,
// and the write controls the collection routes expose (rename, scope,
// description, member add/remove, tag replace, delete).

import { useState } from "react";
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
  Panel,
  Toolbar,
} from "../components";
import type { Collection, CollectionDetail } from "../types";
import { useAsync } from "../useAsync";

function CollectionDetailPanel({
  collectionId,
  onChanged,
}: {
  collectionId: number;
  onChanged: () => void;
}): ReactNode {
  const { data, error, reload } = useAsync(
    () => api<CollectionDetail>(`/collections/${collectionId}`),
    [collectionId],
  );
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scope, setScope] = useState("");
  const [tags, setTags] = useState("");
  const [binaryId, setBinaryId] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [loaded, setLoaded] = useState<number | null>(null);

  if (data !== undefined && loaded !== collectionId) {
    // Seed the edit fields once per selection, then leave the analyst's typing alone.
    setName(data.name);
    setDescription(data.description);
    setScope(data.scope);
    setTags(data.tags.map((tag) => tag.name).join(", "));
    setLoaded(collectionId);
  }

  const run = async (kind: string, work: () => Promise<unknown>): Promise<void> => {
    setActionError(null);
    setBusy(kind);
    try {
      await work();
      reload();
      onChanged();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const save = (): Promise<void> =>
    run("save", () =>
      api(`/collections/${collectionId}`, {
        method: "PATCH",
        json: { name, description, scope },
      }),
    );

  const saveTags = (): Promise<void> =>
    run("tags", () =>
      api(`/collections/${collectionId}/tags`, {
        method: "PATCH",
        json: {
          tags: tags
            .split(",")
            .map((tag) => tag.trim())
            .filter((tag) => tag !== ""),
        },
      }),
    );

  const addMember = (): Promise<void> =>
    run("add", () =>
      api(`/collections/${collectionId}/binaries`, {
        method: "POST",
        json: { binary_id: Number(binaryId) },
      }),
    ).then(() => setBinaryId(""));

  const removeMember = (id: number): Promise<void> =>
    run(`remove-${id}`, () =>
      api(`/collections/${collectionId}/binaries`, {
        method: "DELETE",
        json: { binary_ids: [id] },
      }),
    );

  return (
    <Panel
      title={data === undefined ? `Collection ${collectionId}` : `${data.name}`}
      subtitle="Rename it, edit its tags, and choose which binaries it groups."
      actions={
        <>
          <Button pending={busy === "save"} onClick={() => void save()}>
            Save
          </Button>
          <ConfirmButton
            label="Delete"
            message={`Delete collection ${collectionId} with its membership?`}
            pending={busy === "delete"}
            onConfirm={() =>
              void run("delete", () =>
                api(`/collections/${collectionId}`, { method: "DELETE" }),
              )
            }
          />
        </>
      }
    >
      <Toolbar>
        <Field label="New name">
          <input value={name} onChange={(event) => setName(event.target.value)} />
        </Field>
        <Field label="New description">
          <input value={description} onChange={(event) => setDescription(event.target.value)} />
        </Field>
        <Field label="New scope">
          <input value={scope} onChange={(event) => setScope(event.target.value)} />
        </Field>
      </Toolbar>
      <Toolbar>
        <Field label="Tags" hint="comma separated; this replaces the set">
          <input value={tags} onChange={(event) => setTags(event.target.value)} />
        </Field>
        <Button pending={busy === "tags"} onClick={() => void saveTags()}>
          Save tags
        </Button>
        <Field label="Binary id">
          <input
            inputMode="numeric"
            value={binaryId}
            onChange={(event) => setBinaryId(event.target.value)}
          />
        </Field>
        <Button
          pending={busy === "add"}
          disabled={binaryId.trim() === ""}
          onClick={() => void addMember()}
        >
          Add member
        </Button>
      </Toolbar>
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {data === undefined ? (
        <Loading label="Loading the collection" />
      ) : (
        <DataTable
          columns={[
            { label: "ID", key: "id", numeric: true },
            { label: "Name", key: "name" },
            { label: "", key: "sha256", mono: true },
            {
              label: "",
              render: (row) => (
                <Button
                  pending={busy === `remove-${row.id}`}
                  onClick={() => void removeMember(row.id)}
                >
                  Remove
                </Button>
              ),
            },
          ]}
          rows={data.binaries}
          rowKey={(row) => row.id}
          empty={<EmptyState>No binaries in this collection yet.</EmptyState>}
        />
      )}
    </Panel>
  );
}

export function CollectionsView(): ReactNode {
  const { data, error, reload } = useAsync(
    () => api<{ collections: Collection[] }>("/collections"),
    [],
  );
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const create = async (): Promise<void> => {
    setActionError(null);
    setBusy(true);
    try {
      const created = await api<{ id: number }>("/collections", {
        method: "POST",
        json: { name, description },
      });
      setName("");
      setDescription("");
      setSelected(created.id);
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(false);
    }
  };

  const collections = data?.collections;

  return (
    <>
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
            <input
              placeholder="name"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
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
            onRowClick={(row) => setSelected(selected === row.id ? null : row.id)}
            empty={
              <EmptyState>No collections yet. Name one above to start grouping binaries.</EmptyState>
            }
          />
        )}
      </Panel>
      {selected === null ? null : (
        <CollectionDetailPanel
          key={selected}
          collectionId={selected}
          onChanged={() => {
            reload();
          }}
        />
      )}
    </>
  );
}

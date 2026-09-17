// The Collections view: the list with its order and scope controls, one
// selected collection's members and tags, and the write controls the
// collection routes expose (rename, scope, description, member add/remove,
// tag replace, delete).
//
// The list's controls live in the URL hash (`#/collections?order=owner&
// workspace=team`), the convention the Analyses view uses, so a filtered list
// is a link and survives a reload.

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
  Panel,
  Toolbar,
} from "../components";
import { COLLECTION_ORDERS, DEFAULT_COLLECTION_ORDER, WORKSPACE_FILTERS } from "../constants";
import type { CollectionOrder, WorkspaceFilter } from "../constants";
import type { Collection, CollectionDetail } from "../types";
import { useAsync } from "../useAsync";

const COLLECTIONS_PATH = "/collections";

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
        <Field label="Binary id" hint="Enter adds">
          <input
            inputMode="numeric"
            value={binaryId}
            onChange={(event) => setBinaryId(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && binaryId.trim() !== "") void addMember();
            }}
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
                <ConfirmButton
                  label="Remove"
                  message={`Remove ${row.name} from this collection?`}
                  pending={busy === `remove-${row.id}`}
                  onConfirm={() => void removeMember(row.id)}
                />
              ),
            },
          ]}
          rows={data.binaries}
          rowKey={(row) => row.id}
          empty={
            <EmptyState>
              No binaries in this collection yet. Enter a binary id above and add it.
            </EmptyState>
          }
        />
      )}
    </Panel>
  );
}

/** The order and the scope filter one collections hash carries. */
interface CollectionFilters {
  order: CollectionOrder;
  workspace: WorkspaceFilter | "";
}

function filtersFromQuery(query: Record<string, string>): CollectionFilters {
  const order = query.order ?? "";
  const workspace = query.workspace ?? "";
  return {
    order: (COLLECTION_ORDERS as readonly string[]).includes(order)
      ? (order as CollectionOrder)
      : DEFAULT_COLLECTION_ORDER,
    workspace: (WORKSPACE_FILTERS as readonly string[]).includes(workspace)
      ? (workspace as WorkspaceFilter)
      : "",
  };
}

export function CollectionsView({
  query,
}: {
  query: Record<string, string>;
}): ReactNode {
  const navigate = useNavigate();
  const filters = filtersFromQuery(query);
  const params = new URLSearchParams();
  params.set("order", filters.order);
  if (filters.workspace) params.set("workspace", filters.workspace);
  const { data, error, reload } = useAsync(
    () => api<{ collections: Collection[] }>(`/collections?${params.toString()}`),
    [filters.order, filters.workspace],
  );
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const selectedFromQuery = (() => {
    const id = Number(query.id);
    return Number.isFinite(id) && id > 0 ? id : null;
  })();
  const [selected, setSelected] = useState<number | null>(selectedFromQuery);
  const [queryIdSynced, setQueryIdSynced] = useState(query.id ?? "");
  if ((query.id ?? "") !== queryIdSynced) {
    setQueryIdSynced(query.id ?? "");
    if (selectedFromQuery !== null) setSelected(selectedFromQuery);
  }
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const apply = (patch: Partial<CollectionFilters>): void => {
    const next = { ...filters, ...patch };
    const search = new URLSearchParams();
    search.set("order", next.order);
    if (next.workspace) search.set("workspace", next.workspace);
    // Keep a deep-linked selection across filter changes; dropping `id` made
    // the detail panel vanish on reload after an order or workspace change.
    if (selected !== null) search.set("id", String(selected));
    navigate({
      pathname: COLLECTIONS_PATH,
      search: createSearchParams(Object.fromEntries(search)).toString(),
    });
  };

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
  const filtered = filters.workspace !== "";

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
          <Field label="Name" hint="Enter creates">
            <input
              placeholder="name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && name.trim()) void create();
              }}
            />
          </Field>
          <Field label="Description">
            <input
              placeholder="description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </Field>
          <Field label="Sort">
            <select
              value={filters.order}
              onChange={(event) => apply({ order: event.target.value as CollectionOrder })}
            >
              {COLLECTION_ORDERS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Workspace">
            <select
              value={filters.workspace}
              onChange={(event) => apply({ workspace: event.target.value as WorkspaceFilter | "" })}
            >
              <option value="">any scope</option>
              {WORKSPACE_FILTERS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
        </Toolbar>
        {error ? <ErrorNote error={error} onRetry={reload} /> : null}
        {actionError ? <ErrorNote error={actionError} /> : null}
        {collections === undefined ? (
          <Loading label="Loading collections" />
        ) : (
          <DataTable
            columns={[
              { label: "ID", key: "id", numeric: true },
              { label: "Name", key: "name" },
              { label: "Description", key: "description" },
              { label: "Scope", key: "scope" },
              {
                label: "Owner",
                render: (row) => row.owner_team_name ?? "-",
              },
              { label: "Binaries", key: "binary_count", numeric: true },
            ]}
            rows={collections}
            rowKey={(row) => row.id}
            onRowClick={(row) => setSelected(selected === row.id ? null : row.id)}
            empty={
              <EmptyState>
                {filtered
                  ? "No collections match this filter. Clear it to see them all."
                  : "No collections yet. Name one above to start grouping binaries."}
              </EmptyState>
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

// The Tags view: every tag the register holds with how many binaries and
// collections carry it, and the two maintenance writes that keep the
// vocabulary tidy (rename, delete).
//
// A tag is created where it is applied, by the binary detail's Tags panel or a
// collection's tag field, so this view edits and prunes rather than creates:
// before it, a misspelled tag could never be renamed or removed.

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
import type { TagRow } from "../types";
import { useAsync } from "../useAsync";

/** One tag's maintenance panel: rename it everywhere, or delete it and its links. */
function TagDetailPanel({ tag, onChanged }: { tag: TagRow; onChanged: () => void }): ReactNode {
  const [name, setName] = useState(tag.name);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [renamed, setRenamed] = useState(false);

  const run = async (kind: string, work: () => Promise<unknown>): Promise<void> => {
    setActionError(null);
    setBusy(kind);
    try {
      await work();
      onChanged();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const save = (): Promise<void> =>
    run("rename", () =>
      api(`/tags/${tag.id}`, { method: "PATCH", json: { name } }),
    ).then(() => setRenamed(true));

  return (
    <Panel
      title={`Tag ${tag.name}`}
      subtitle="Renaming keeps every link; deleting takes the tag off every binary and collection."
      actions={
        <>
          <Button
            tone="primary"
            pending={busy === "rename"}
            disabled={!name.trim() || name === tag.name}
            onClick={() => void save()}
          >
            Save
          </Button>
          <ConfirmButton
            label="Delete"
            message={`Delete tag ${tag.name} and remove it from ${tag.binary_count} binary(ies) and ${tag.collection_count} collection(s)?`}
            pending={busy === "delete"}
            onConfirm={() =>
              void run("delete", () => api(`/tags/${tag.id}`, { method: "DELETE" }))
            }
          />
        </>
      }
    >
      <Toolbar>
        <Field label="Name" hint="the exact name every link keeps; Enter saves">
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            onKeyDown={(event) => {
              if (
                event.key === "Enter" &&
                name.trim() &&
                name !== tag.name
              ) {
                void save();
              }
            }}
          />
        </Field>
      </Toolbar>
      {actionError ? <ErrorNote error={actionError} /> : null}
      {renamed ? (
        <p className="muted">
          {`Renamed to ${name}. The ${tag.binary_count} binary link(s) and ${tag.collection_count} collection link(s) still point at this tag.`}
        </p>
      ) : null}
    </Panel>
  );
}

export function TagsView({
  query = {},
}: {
  query?: Record<string, string>;
}): ReactNode {
  const { data, error, reload } = useAsync(() => api<{ tags: TagRow[] }>("/tags"), []);
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

  const tags = data?.tags;
  const current = tags?.find((tag) => tag.id === selected) ?? null;

  return (
    <>
      <Panel
        title="Tags"
        subtitle="The register's tag vocabulary, with what carries each one."
      >
        {error ? <ErrorNote error={error} onRetry={reload} /> : null}
        {tags === undefined ? (
          <Loading label="Loading the tag vocabulary" />
        ) : (
          <DataTable
            columns={[
              { label: "ID", key: "id", numeric: true },
              { label: "Tag", key: "name" },
              { label: "Binaries", key: "binary_count", numeric: true },
              { label: "Collections", key: "collection_count", numeric: true },
            ]}
            rows={tags}
            rowKey={(row) => row.id}
            onRowClick={(row) => setSelected(selected === row.id ? null : row.id)}
            empty={
              <EmptyState>
                No tags yet. Tag a binary or a collection and it appears here.
              </EmptyState>
            }
          />
        )}
      </Panel>
      {current === null ? null : (
        <TagDetailPanel
          key={current.id}
          tag={current}
          onChanged={() => {
            reload();
          }}
        />
      )}
    </>
  );
}

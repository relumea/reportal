import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  ConfirmButton,
  EmptyState,
  ErrorNote,
  Field,
  Muted,
  NA,
  Panel,
  PanelBody,
  Toolbar,
} from "../components";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import type { BinaryCollections, Collection } from "../types";

/**
 * The collections one binary is a member of, from the binary's side.
 *
 * The Collections view manages membership from the collection side; this is the
 * reverse read, so an analyst looking at a binary can see and change where it
 * lives without going back to the other view.
 */
export function BinaryCollectionsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "collections");
  const load = (): Promise<BinaryCollections> => api<BinaryCollections>(`/binaries/${binaryId}/collections`);
  const entry = usePanel(key, load);
  const allEntry = usePanel(panelKey("collections", "list"), () =>
    api<{ collections: Collection[] }>("/collections"),
  );
  const [pick, setPick] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");

  const members = entry?.state === "ready" ? entry.data.collections : [];
  const memberIds = new Set(members.map((row) => row.id));
  const candidates = (allEntry?.state === "ready" ? allEntry.data.collections : []).filter(
    (row) => !memberIds.has(row.id),
  );

  useEffect(() => {
    // A row that joined or left changes the candidate list, so keep the select
    // pointing at a collection that is still on offer.
    if (pick !== "" && !candidates.some((row) => String(row.id) === pick)) setPick("");
  }, [candidates, pick]);

  const refresh = (): void => {
    refreshPanel(key, load);
    refreshPanel(panelKey("collections", "list"), () => api<{ collections: Collection[] }>("/collections"));
  };

  const act = async (label: string, action: () => Promise<unknown>, message: string): Promise<void> => {
    setActionError(null);
    setNotice("");
    setBusy(label);
    try {
      await action();
      setNotice(message);
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const add = (): void => {
    if (pick === "") return;
    const chosen = candidates.find((row) => String(row.id) === pick);
    void act(
      "add",
      () =>
        api(`/collections/${pick}/binaries`, { method: "POST", json: { binary_id: binaryId } }),
      chosen ? `Added to ${chosen.name}.` : "Added.",
    );
  };

  const count = entry?.state === "ready" ? entry.data.count : undefined;
  return (
    <Panel
      title={
        <>
          Collections <Badge>{count === undefined ? NA : String(count)}</Badge>
        </>
      }
      subtitle="The collections this binary is a member of; the Collections view manages them from the other side."
    >
      <Toolbar>
        <Field label="Add to collection">
          <select value={pick} onChange={(event) => setPick(event.target.value)}>
            <option value="">{candidates.length ? "choose one" : "none left"}</option>
            {candidates.map((row) => (
              <option key={row.id} value={row.id}>
                {row.name}
              </option>
            ))}
          </select>
        </Field>
        <Button tone="primary" pending={busy === "add"} disabled={pick === ""} onClick={add}>
          Add
        </Button>
        {notice ? <Muted>{notice}</Muted> : null}
      </Toolbar>
      {actionError ? <ErrorNote error={actionError} /> : null}
      {allEntry?.state === "error" ? (
        <ErrorNote
          error={allEntry.error}
          onRetry={() =>
            refreshPanel(panelKey("collections", "list"), () =>
              api<{ collections: Collection[] }>("/collections"),
            )
          }
        />
      ) : null}
      <PanelBody
        entry={entry}
        hint="Loading the collections"
        onRetry={() => refreshPanel(key, load)}
      >
        {(data) =>
            data.collections.length === 0 ? (
              <EmptyState>This binary is in no collection.</EmptyState>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Name</th>
                      <th>Members</th>
                      <th>Description</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {data.collections.map((row) => (
                      <tr key={row.id}>
                        <td className="num">{row.id}</td>
                        <td>{row.name}</td>
                        <td className="num">{row.binary_count}</td>
                        <td className="muted">{row.description || NA}</td>
                        <td>
                          <ConfirmButton
                            label="Remove"
                            message={`Remove this binary from ${row.name}?`}
                            pending={busy === `remove-${row.id}`}
                            onConfirm={() =>
                              void act(
                                `remove-${row.id}`,
                                () =>
                                  api(`/collections/${row.id}/binaries`, {
                                    method: "DELETE",
                                    json: { binary_ids: [binaryId] },
                                  }),
                                `Removed from ${row.name}.`,
                              )
                            }
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
      </PanelBody>
    </Panel>
  );
}

import { useRef, useState } from "react";
import { useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Panel,
  Toolbar,
} from "../components";
import {
  MAX_UPLOAD_FILES,
  UPLOAD_ARCHITECTURES,
  UPLOAD_FORMATS,
} from "../constants";
import type {
  BinaryListRow,
  BulkResult,
  Collection,
  Family,
  FamilyList,
  UploadBatchResult,
  UploadFileOptions,
} from "../types";
import { useAsync } from "../useAsync";

/** One file queued for upload, with the options its own row carries. */
interface UploadRow {
  key: string;
  file: File;
  name: string;
  tags: string[];
  format: string;
  arch: string;
}

/** The comma-or-Enter chip control one upload row applies its tags with. */
function TagChips({
  values,
  onChange,
}: {
  values: string[];
  onChange: (values: string[]) => void;
}): ReactNode {
  const [draft, setDraft] = useState("");

  const commit = (): void => {
    const trimmed = draft.trim();
    setDraft("");
    if (!trimmed || values.includes(trimmed)) return;
    onChange([...values, trimmed]);
  };

  return (
    <span className="chips">
      {values.map((tag) => (
        <span className="chip" key={tag}>
          {tag}
          <button
            type="button"
            aria-label={`remove tag ${tag}`}
            onClick={() => onChange(values.filter((value) => value !== tag))}
          >
            x
          </button>
        </span>
      ))}
      <input
        value={draft}
        placeholder="add tag"
        aria-label="Tag"
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === ",") {
            event.preventDefault();
            commit();
          }
        }}
        onBlur={commit}
      />
    </span>
  );
}

export function BinariesView(): ReactNode {
  const navigate = useNavigate();
  const { data, error, reload } = useAsync(() => api<{ binaries: BinaryListRow[] }>("/binaries"), []);
  const familyData = useAsync(() => api<FamilyList>("/families"), []);
  const collectionData = useAsync(() => api<{ collections: Collection[] }>("/collections"), []);
  const fileRef = useRef<HTMLInputElement>(null);
  const [uploadRows, setUploadRows] = useState<UploadRow[]>([]);
  const [uploadCollection, setUploadCollection] = useState("");
  const [uploadResult, setUploadResult] = useState<UploadBatchResult | null>(null);
  const [uploadError, setUploadError] = useState<unknown>(null);
  const [familyName, setFamilyName] = useState("");
  const [familyAlias, setFamilyAlias] = useState("");
  const [familyBinaryId, setFamilyBinaryId] = useState("");
  const [familyError, setFamilyError] = useState<unknown>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulkTag, setBulkTag] = useState("");
  const [bulkMessage, setBulkMessage] = useState("");
  const [bulkError, setBulkError] = useState<unknown>(null);
  const [bulkAction, setBulkAction] = useState("");
  const [busy, setBusy] = useState("");

  const toggleSelected = (binaryId: number): void => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(binaryId)) next.delete(binaryId);
      else next.add(binaryId);
      return next;
    });
  };

  const runBulk = async (action: string, tag: string): Promise<void> => {
    setBulkError(null);
    setBulkMessage("");
    const ids = Array.from(selected);
    if (!ids.length) {
      setBulkError(new Error("Select at least one binary."));
      return;
    }
    setBusy(action);
    try {
      const result = await api<BulkResult>("/binaries/bulk", {
        method: "POST",
        json: { action, binary_ids: ids, tag },
      });
      const skipped = result.skipped.length;
      const actionLink = result.journal_action ? ` Journaled as ${result.journal_action}.` : "";
      setBulkMessage(
        `${result.applied} of ${result.requested} applied${skipped ? `, ${skipped} skipped` : ""}.${actionLink}`,
      );
      setBulkAction(result.journal_action ?? "");
      setSelected(new Set());
      reload();
    } catch (failure) {
      setBulkError(failure);
    } finally {
      setBusy("");
    }
  };

  const addFiles = (picked: FileList | null): void => {
    if (!picked?.length) return;
    setUploadError(null);
    setUploadResult(null);
    setUploadRows((current) => {
      const room = MAX_UPLOAD_FILES - current.length;
      const accepted = Array.from(picked).slice(0, Math.max(room, 0));
      return [
        ...current,
        ...accepted.map((file) => ({
          key: `${file.name}-${file.lastModified}-${file.size}-${current.length + accepted.indexOf(file)}`,
          file,
          name: "",
          tags: [],
          format: "",
          arch: "",
        })),
      ];
    });
  };

  const updateRow = (key: string, patch: Partial<UploadRow>): void => {
    setUploadRows((current) =>
      current.map((row) => (row.key === key ? { ...row, ...patch } : row)),
    );
  };

  const upload = async (): Promise<void> => {
    setUploadError(null);
    setUploadResult(null);
    if (!uploadRows.length) {
      setUploadError(new Error("Choose at least one file."));
      return;
    }
    const body = new FormData();
    for (const row of uploadRows) body.append("file", row.file, row.file.name);
    const collectionIds = uploadCollection ? [Number(uploadCollection)] : [];
    const options: UploadFileOptions[] = uploadRows.map((row) => ({
      name: row.name.trim() || undefined,
      tags: row.tags,
      format: row.format || undefined,
      arch: row.arch || undefined,
      collection_ids: collectionIds,
    }));
    body.append("files", JSON.stringify(options));
    setBusy("upload");
    try {
      const result = await api<UploadBatchResult>("/binaries", { method: "POST", body });
      setUploadResult(result);
      setUploadRows([]);
      if (fileRef.current) fileRef.current.value = "";
      reload();
    } catch (failure) {
      setUploadError(failure);
    } finally {
      setBusy("");
    }
  };

  const binaries = data?.binaries ?? null;
  const families = familyData.data?.families ?? null;
  const collections = collectionData.data?.collections ?? [];

  const registerFamily = async (): Promise<void> => {
    setFamilyError(null);
    const name = familyName.trim();
    if (!name) {
      setFamilyError(new Error("Enter a family name."));
      return;
    }
    if (!familyBinaryId) {
      setFamilyError(new Error("Pick a reference binary."));
      return;
    }
    const alias = familyAlias.trim();
    setBusy("family");
    try {
      await api<Family>("/families", {
        method: "POST",
        json: {
          name,
          reference_binary_id: Number(familyBinaryId),
          aliases: alias ? [alias] : [],
        },
      });
      setFamilyName("");
      setFamilyAlias("");
      familyData.reload();
    } catch (failure) {
      setFamilyError(failure);
    } finally {
      setBusy("");
    }
  };

  const removeFamily = async (familyId: number): Promise<void> => {
    setFamilyError(null);
    setBusy(`family-delete-${familyId}`);
    try {
      await api(`/families/${familyId}`, { method: "DELETE" });
      familyData.reload();
    } catch (failure) {
      setFamilyError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <>
      <Panel
        title="Upload binaries"
        subtitle="Registered by content hash; uploading the same bytes again returns the stored row instead of a copy."
        actions={
          <Button tone="primary" pending={busy === "upload"} onClick={() => void upload()}>
            Upload
          </Button>
        }
      >
        <Toolbar>
          <Field label="Files">
            <input type="file" name="file" multiple ref={fileRef} onChange={(event) => addFiles(event.target.files)} />
          </Field>
          <Field label="Add to collection">
            <select value={uploadCollection} onChange={(event) => setUploadCollection(event.target.value)}>
              <option value="">None</option>
              {collections.map((collection) => (
                <option key={collection.id} value={collection.id}>
                  {collection.name}
                </option>
              ))}
            </select>
          </Field>
          {uploadRows.length ? (
            <Button tone="ghost" onClick={() => setUploadRows([])}>
              Clear list
            </Button>
          ) : null}
        </Toolbar>
        {uploadRows.length ? (
          <>
            <p className="muted">{uploadRows.length} selected for upload</p>
            <DataTable
              columns={[
                {
                  label: "File",
                  render: (row) => (
                    <span>
                      <span>{row.file.name}</span>
                      <span className="muted"> {row.file.size.toLocaleString()} B</span>
                    </span>
                  ),
                },
                {
                  label: "Name",
                  render: (row) => (
                    <input
                      aria-label={`name for ${row.file.name}`}
                      placeholder={row.file.name}
                      value={row.name}
                      onChange={(event) => updateRow(row.key, { name: event.target.value })}
                    />
                  ),
                },
                {
                  label: "Tags",
                  render: (row) => (
                    <TagChips
                      values={row.tags}
                      onChange={(tags) => updateRow(row.key, { tags })}
                    />
                  ),
                },
                {
                  label: "Format",
                  render: (row) => (
                    <select
                      aria-label={`format for ${row.file.name}`}
                      value={row.format}
                      onChange={(event) => updateRow(row.key, { format: event.target.value })}
                    >
                      <option value="">Auto</option>
                      {UPLOAD_FORMATS.map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                  ),
                },
                {
                  label: "ISA",
                  render: (row) => (
                    <select
                      aria-label={`ISA for ${row.file.name}`}
                      value={row.arch}
                      onChange={(event) => updateRow(row.key, { arch: event.target.value })}
                    >
                      <option value="">Auto</option>
                      {UPLOAD_ARCHITECTURES.map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                  ),
                },
                {
                  label: "",
                  render: (row) => (
                    <Button
                      size="sm"
                      tone="ghost"
                      onClick={() =>
                        setUploadRows((current) => current.filter((entry) => entry.key !== row.key))
                      }
                    >
                      Remove
                    </Button>
                  ),
                },
              ]}
              rows={uploadRows}
              rowKey={(row) => row.key}
            />
          </>
        ) : null}
        {uploadError ? <ErrorNote error={uploadError} /> : null}
        {uploadResult ? (
          <div className="upload-results">
            <p className="muted">
              {uploadResult.count} file(s): {uploadResult.duplicates} already stored,{" "}
              {uploadResult.errors} refused.
            </p>
            <ul>
              {uploadResult.files.map((entry, index) => (
                <li key={`${entry.file}-${index}`} className={entry.error ? "upload-error" : undefined}>
                  {entry.error
                    ? `${entry.file}: ${entry.error.error} (${entry.error.detail})`
                    : entry.duplicate
                      ? `Already stored ${entry.file} as binary #${entry.binary_id}.`
                      : `Uploaded ${entry.file} as binary #${entry.binary_id}.`}
                  {entry.tags.length ? ` Tags: ${entry.tags.join(", ")}.` : ""}
                </li>
              ))}
            </ul>
            {uploadResult.journal_action ? (
              <p className="muted">
                One action reverts the whole batch:{" "}
                <a href={`#/journal/${uploadResult.journal_action}`}>{uploadResult.journal_action}</a>
              </p>
            ) : null}
          </div>
        ) : null}
      </Panel>
      <Panel
        title="Malware families"
        subtitle="Families are curated locally from a reference binary. reportal bundles no external threat-intelligence feed; a detection matches a binary against these signatures only."
        actions={
          <Button tone="primary" pending={busy === "family"} onClick={() => void registerFamily()}>
            Register family
          </Button>
        }
      >
        <Toolbar>
          <Field label="Family name">
            <input
              value={familyName}
              onChange={(event) => setFamilyName(event.target.value)}
              placeholder="family name"
            />
          </Field>
          <Field label="Reference binary">
            <select
              value={familyBinaryId}
              onChange={(event) => setFamilyBinaryId(event.target.value)}
            >
              <option value="">Select a binary</option>
              {(binaries ?? []).map((binary) => (
                <option key={binary.id} value={binary.id}>
                  {binary.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Alias">
            <input
              value={familyAlias}
              onChange={(event) => setFamilyAlias(event.target.value)}
              placeholder="optional"
            />
          </Field>
        </Toolbar>
        {familyError ? <ErrorNote error={familyError} /> : null}
        {familyData.error ? <ErrorNote error={familyData.error} onRetry={familyData.reload} /> : null}
        {families === null ? (
          <EmptyState>Families load with the binaries list.</EmptyState>
        ) : (
          <DataTable
            columns={[
              { label: "ID", key: "family_id", numeric: true },
              { label: "Name", key: "name" },
              {
                label: "Aliases",
                mono: true,
                render: (row) => (row.aliases.length > 0 ? row.aliases.join(", ") : "n/a"),
              },
              { label: "Reference binary", numeric: true, render: (row) => row.reference_binary_id },
              {
                label: "Actions",
                render: (row) => (
                  <div className="actions-cell">
                    <ConfirmButton
                      label="Delete"
                      message="Delete family?"
                      pending={busy === `family-delete-${row.family_id}`}
                      onConfirm={() => void removeFamily(row.family_id)}
                    />
                  </div>
                ),
              },
            ]}
            rows={families}
            rowKey={(row) => row.family_id}
            empty={
              <EmptyState>No families registered. Register one from a reference binary above.</EmptyState>
            }
          />
        )}
      </Panel>
      <Panel
        title="Binaries"
        subtitle={`${binaries?.length ?? 0} binaries`}
        actions={
          <>
            <Button tone="ghost" onClick={() => navigate("/analyses")}>
              Browse analyses
            </Button>
            <Button tone="ghost" onClick={() => navigate("/functions")}>
              Browse functions
            </Button>
          </>
        }
      >
        {error ? <ErrorNote error={error} onRetry={reload} /> : null}
        {binaries === null ? null : (
          <DataTable
            columns={[
              {
                label: "",
                render: (row) => (
                  <input
                    type="checkbox"
                    aria-label={`select ${row.name}`}
                    checked={selected.has(row.id)}
                    onChange={() => toggleSelected(row.id)}
                  />
                ),
              },
              { label: "ID", key: "id", numeric: true },
              { label: "Name", key: "name" },
              {
                label: "Format",
                render: (row) => (
                  <span className="toolbar">
                    <Badge mono>{row.format || "n/a"}</Badge>
                    <Badge mono>{row.arch || "n/a"}</Badge>
                  </span>
                ),
              },
              {
                label: "Size",
                numeric: true,
                render: (row) => row.size.toLocaleString(),
              },
              {
                label: "SHA-256",
                mono: true,
                render: (row) => row.sha256.slice(0, 16),
              },
              { label: "Functions", key: "function_count", numeric: true },
              {
                label: "Comments",
                numeric: true,
                render: (row) => <Badge>{row.comment_count}</Badge>,
              },
              {
                label: "Actions",
                render: (row) => (
                  <div className="actions-cell">
                    <a href={`/api/binaries/${row.id}/download`}>Download</a>
                  </div>
                ),
              },
            ]}
            rows={binaries}
            rowKey={(row) => row.id}
            onRowClick={(row) => navigate(`/binaries/${row.id}`)}
            empty={
              <EmptyState>
                No binaries yet. Upload one above, or import a rebrew project with{" "}
                <code>reportal import-rebrew &lt;project-dir&gt;</code>.
              </EmptyState>
            }
          />
        )}
      </Panel>
      {binaries && binaries.length > 0 ? (
        <Panel
          title="Bulk actions"
          subtitle="Applies to the rows checked in the table above."
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
              <Button
                pending={busy === "remove_tag"}
                onClick={() => void runBulk("remove_tag", bulkTag)}
              >
                Remove tag
              </Button>
              <ConfirmButton
                label="Delete"
                message={`Delete ${selected.size}?`}
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
          {bulkMessage ? <p className="muted">{bulkMessage}</p> : null}
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

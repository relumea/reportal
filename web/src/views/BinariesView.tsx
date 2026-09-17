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
  Muted,
  Panel,
  Toolbar,
} from "../components";
import {
  BINARY_ORDERS,
  DEFAULT_BINARY_ORDER,
  MAX_UPLOAD_FILES,
  UPLOAD_ARCHITECTURES,
  UPLOAD_COMPILERS,
  UPLOAD_FORMATS,
} from "../constants";
import type {
  BinaryListPayload,
  BulkResult,
  Collection,
  Family,
  FamilyList,
  Me,
  TeamsPayload,
  ExtractResult,
  TagRow,
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
  compiler: string;
  /** The team to register the binary into; "" leaves it public and ownerless. */
  scope: string;
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

/** The register's filters, every one optional; `id` is the insertion order. */
interface BinaryFilters {
  search: string;
  tag: string;
  format: string;
  language: string;
  compiler: string;
  order: string;
}

function filtersFromQuery(query: Record<string, string>): BinaryFilters {
  const order = query.order ?? "";
  return {
    search: query.search ?? "",
    tag: query.tag ?? "",
    format: query.format ?? "",
    language: query.language ?? "",
    compiler: query.compiler ?? "",
    order: (BINARY_ORDERS as readonly string[]).includes(order) ? order : DEFAULT_BINARY_ORDER,
  };
}

/** The API path one filter set reads. */
function registerPath(filters: BinaryFilters): string {
  const params = new URLSearchParams();
  if (filters.search.trim()) params.set("search", filters.search.trim());
  if (filters.tag) params.set("tag", filters.tag);
  if (filters.format) params.set("format", filters.format);
  if (filters.language) params.set("language", filters.language);
  if (filters.compiler) params.set("compiler", filters.compiler);
  params.set("order", filters.order);
  return `/binaries?${params.toString()}`;
}

export function BinariesView({
  query = {},
}: {
  /** The route hash, whose keys are the filters this view applies. */
  query?: Record<string, string>;
}): ReactNode {
  const navigate = useNavigate();
  const filters = filtersFromQuery(query);
  const path = registerPath(filters);
  const { data, error, reload } = useAsync(
    () => api<BinaryListPayload>(path),
    [path],
  );
  const tagData = useAsync(() => api<{ tags: TagRow[] }>("/tags"), []);
  // The extract and family pickers choose from the whole register, so they read
  // it unfiltered rather than the slice the table is showing.
  const register = useAsync(() => api<BinaryListPayload>("/binaries"), []);
  const familyData = useAsync(() => api<FamilyList>("/families"), []);
  const collectionData = useAsync(() => api<{ collections: Collection[] }>("/collections"), []);
  const teamData = useAsync(() => api<TeamsPayload>("/teams"), []);
  const me = useAsync(() => api<Me>("/iam/me"), []);
  // The team the caller has selected, when the install has auth on: new rows
  // start there rather than in the whole workspace.
  const activeTeam =
    me.data?.user?.active_team_id === undefined || me.data?.user === null
      ? ""
      : String(me.data.user.active_team_id);
  const fileRef = useRef<HTMLInputElement>(null);
  const [uploadRows, setUploadRows] = useState<UploadRow[]>([]);
  const [dragging, setDragging] = useState(false);
  const [configure, setConfigure] = useState({ format: "", arch: "", compiler: "", scope: "" });
  // The stored archives this session uploaded, so the batch can be unpacked in
  // place rather than by copying a hash into another view.
  const [extractTarget, setExtractTarget] = useState("");
  const [extractCollection, setExtractCollection] = useState("");
  const [extractPassword, setExtractPassword] = useState("");
  const [extractResult, setExtractResult] = useState<ExtractResult | null>(null);
  const [extractError, setExtractError] = useState<unknown>(null);
  const [uploadCollection, setUploadCollection] = useState("");
  const [uploadResult, setUploadResult] = useState<UploadBatchResult | null>(null);
  const [uploadError, setUploadError] = useState<unknown>(null);
  const [familyName, setFamilyName] = useState("");
  const [familyAlias, setFamilyAlias] = useState("");
  const [familyBinaryId, setFamilyBinaryId] = useState("");
  const [familyError, setFamilyError] = useState<unknown>(null);
  const [draft, setDraft] = useState(filters.search);
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

  const setScope = async (binaryId: number, value: string): Promise<void> => {
    setBulkError(null);
    setBusy(`scope-${binaryId}`);
    try {
      await api(`/binaries/${binaryId}/scope`, {
        method: "PATCH",
        json:
          value === "public"
            ? { visibility: "public" }
            : { visibility: "team", team_id: Number(value) },
      });
      reload();
    } catch (failure) {
      setBulkError(failure);
    } finally {
      setBusy("");
    }
  };

  /** Apply one value to every queued row at once, the Configure all control. */
  const configureAll = (patch: Partial<UploadRow>): void => {
    setConfigure((current) => ({ ...current, ...patch }));
    setUploadRows((current) => current.map((row) => ({ ...row, ...patch })));
  };

  const extract = async (): Promise<void> => {
    setExtractError(null);
    setExtractResult(null);
    if (!extractTarget) {
      setExtractError(new Error("Select a stored archive above. If it is not listed, upload it first."));
      return;
    }
    setBusy("extract");
    try {
      const result = await api<ExtractResult>(`/binaries/${extractTarget}/extract`, {
        method: "POST",
        json: {
          password: extractPassword || undefined,
          collection_id: extractCollection ? Number(extractCollection) : 0,
        },
      });
      setExtractResult(result);
      setExtractPassword("");
      reload();
      collectionData.reload();
      register.reload();
    } catch (failure) {
      setExtractError(failure);
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
          compiler: "",
          scope: activeTeam,
        })),
      ];
    });
  };

  const apply = (patch: Partial<BinaryFilters>): void => {
    const next = { ...filters, ...patch };
    const params = new URLSearchParams();
    if (next.search.trim()) params.set("search", next.search.trim());
    if (next.tag) params.set("tag", next.tag);
    if (next.format) params.set("format", next.format);
    if (next.language) params.set("language", next.language);
    if (next.compiler) params.set("compiler", next.compiler);
    if (next.order !== DEFAULT_BINARY_ORDER) params.set("order", next.order);
    navigate({ pathname: "/binaries", search: params.toString() });
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
      compiler: row.compiler || undefined,
      collection_ids: collectionIds,
      ...(row.scope === ""
        ? {}
        : { visibility: "team" as const, team_id: Number(row.scope) }),
    }));
    body.append("files", JSON.stringify(options));
    setBusy("upload");
    try {
      const result = await api<UploadBatchResult>("/binaries", { method: "POST", body });
      setUploadResult(result);
      setUploadRows([]);
      if (fileRef.current) fileRef.current.value = "";
      reload();
      register.reload();
    } catch (failure) {
      setUploadError(failure);
    } finally {
      setBusy("");
    }
  };

  const binaries = data?.binaries ?? null;
  const teams = teamData.data?.teams ?? [];
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
        <div
          className={dragging ? "drop-zone dragging" : "drop-zone"}
          role="button"
          tabIndex={0}
          aria-label="Drop files to upload"
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            addFiles(event.dataTransfer.files);
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              fileRef.current?.click();
            }
          }}
        >
          {busy === "upload" ? (
            <span className="muted">Uploading {uploadRows.length} file(s)...</span>
          ) : (
            <span className="muted">
              Drop binaries, firmware images or archives here, or choose them above. A duplicate
              hash is reported rather than stored twice.
            </span>
          )}
        </div>
        {uploadRows.length ? (
          <>
            <p className="muted">{uploadRows.length} selected for upload</p>
            <Toolbar>
              <Field label="Configure all">
                <select
                  aria-label="Format for every file"
                  value={configure.format}
                  onChange={(event) => configureAll({ format: event.target.value })}
                >
                  <option value="">Auto</option>
                  {UPLOAD_FORMATS.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="ISA for every file">
                <select
                  aria-label="ISA for every file"
                  value={configure.arch}
                  onChange={(event) => configureAll({ arch: event.target.value })}
                >
                  <option value="">Auto</option>
                  {UPLOAD_ARCHITECTURES.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Compiler for every file">
                <select
                  aria-label="Compiler for every file"
                  value={configure.compiler}
                  onChange={(event) => configureAll({ compiler: event.target.value })}
                >
                  <option value="">Auto</option>
                  {UPLOAD_COMPILERS.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Scope for every file">
                <select
                  aria-label="Scope for every file"
                  value={configure.scope}
                  onChange={(event) => configureAll({ scope: event.target.value })}
                >
                  <option value="">Workspace</option>
                  {teams.map((team) => (
                    <option key={team.id} value={team.id}>
                      team {team.name}
                    </option>
                  ))}
                </select>
              </Field>
            </Toolbar>
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
                  label: "Plan",
                  render: (row) =>
                    // A row nobody configured stays on the automatic plan, which
                    // is what the hosted portal's dashed badge means.
                    row.format === "" && row.arch === "" && row.compiler === "" ? (
                      <Badge tone="info" title="Format, ISA and compiler are derived from the file">
                        auto
                      </Badge>
                    ) : (
                      <span className="muted">
                        {row.format || "auto"} / {row.arch || "auto"} / {row.compiler || "auto"}
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
                  label: "Compiler",
                  render: (row) => (
                    <select
                      aria-label={`compiler for ${row.file.name}`}
                      value={row.compiler}
                      onChange={(event) => updateRow(row.key, { compiler: event.target.value })}
                    >
                      <option value="">Auto</option>
                      {UPLOAD_COMPILERS.map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                  ),
                },
                {
                  label: "Scope",
                  render: (row) => (
                    <select
                      aria-label={`scope for ${row.file.name}`}
                      value={row.scope}
                      onChange={(event) => updateRow(row.key, { scope: event.target.value })}
                    >
                      <option value="">Workspace</option>
                      {teams.map((team) => (
                        <option key={team.id} value={team.id}>
                          team {team.name}
                          {String(team.id) === activeTeam ? " (active)" : ""}
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
            {uploadResult.duplicates > 0 ? (
              <p className="upload-banner">
                {uploadResult.duplicates} file(s) were already stored; the batches below name them.
              </p>
            ) : null}
            {uploadResult.errors > 0 ? (
              <p className="upload-banner upload-error">
                {uploadResult.errors} file(s) were refused; each row states why.
              </p>
            ) : null}
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
                  {entry.error
                    ? ""
                    : entry.owner_team_id === null
                      ? " Workspace scope."
                      : ` Team #${entry.owner_team_id} scope.`}
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
        title="Extract an archive"
        subtitle="Unpack a stored zip/apk, tar or gz and register every member it holds; one journal action reverts the whole extraction."
        actions={
          <Button tone="primary" pending={busy === "extract"} onClick={() => void extract()}>
            Extract
          </Button>
        }
      >
        <Toolbar>
          <Field label="Archive">
            <select
              value={extractTarget}
              onChange={(event) => setExtractTarget(event.target.value)}
            >
              <option value="">Select a stored binary</option>
              {(register.data?.binaries ?? []).map((binary) => (
                <option key={binary.id} value={binary.id}>
                  {binary.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Into collection">
            <select
              value={extractCollection}
              onChange={(event) => setExtractCollection(event.target.value)}
            >
              <option value="">One named after the archive</option>
              {collections.map((collection) => (
                <option key={collection.id} value={collection.id}>
                  {collection.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Password">
            <input
              type="password"
              value={extractPassword}
              placeholder="for an encrypted zip"
              onChange={(event) => setExtractPassword(event.target.value)}
            />
          </Field>
        </Toolbar>
        <Muted>
          The archive has to be stored first, which is what the upload panel above does. A member
          that is not a binary the portal can register is reported as skipped with its reason
          rather than dropped silently.
        </Muted>
        {extractError ? <ErrorNote error={extractError} /> : null}
        {extractResult ? (
          <div className="upload-results">
            <p className="muted">
              {extractResult.kept} of {extractResult.members.length} member(s) registered into{" "}
              {extractResult.collection_name} ({extractResult.skipped} skipped).
            </p>
            <ul>
              {extractResult.members.map((entry) => (
                <li key={entry.name} className={entry.skipped ? "upload-error" : undefined}>
                  {entry.skipped
                    ? `${entry.name}: ${entry.skipped}`
                    : entry.duplicate
                      ? `Already stored ${entry.name} as binary #${entry.binary_id}.`
                      : `Registered ${entry.name} as binary #${entry.binary_id}.`}
                </li>
              ))}
            </ul>
            {extractResult.journal_action ? (
              <p className="muted">
                One action reverts the whole extraction:{" "}
                <a href={`#/journal/${extractResult.journal_action}`}>
                  {extractResult.journal_action}
                </a>
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
              {(register.data?.binaries ?? []).map((binary) => (
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
                      message={`Delete family ${row.name}?`}
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
        subtitle={`${data?.count ?? 0} of ${data?.total ?? 0} binaries`}
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
        <Toolbar>
          <Field label="Search" hint="name, SHA-256 or notes">
            <input
              type="search"
              placeholder="name, hash or notes"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") apply({ search: draft });
              }}
            />
          </Field>
          <Button onClick={() => apply({ search: draft })}>Search</Button>
          <Field label="Tag">
            <select value={filters.tag} onChange={(event) => apply({ tag: event.target.value })}>
              <option value="">any tag</option>
              {(tagData.data?.tags ?? []).map((row) => (
                <option key={row.id} value={row.name}>
                  {row.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Format">
            <select
              value={filters.format}
              onChange={(event) => apply({ format: event.target.value })}
            >
              <option value="">any format</option>
              {(data?.formats ?? []).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Language">
            <select
              value={filters.language}
              onChange={(event) => apply({ language: event.target.value })}
            >
              <option value="">any language</option>
              {(data?.languages ?? []).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Compiler">
            <select
              value={filters.compiler}
              onChange={(event) => apply({ compiler: event.target.value })}
            >
              <option value="">any compiler</option>
              {(data?.compilers ?? []).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Order">
            <select value={filters.order} onChange={(event) => apply({ order: event.target.value })}>
              {BINARY_ORDERS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Button
            tone="ghost"
            disabled={
              filters.search === "" &&
              filters.tag === "" &&
              filters.format === "" &&
              filters.language === "" &&
              filters.compiler === "" &&
              filters.order === DEFAULT_BINARY_ORDER
            }
            onClick={() => {
              setDraft("");
              navigate({ pathname: "/binaries", search: "" });
            }}
          >
            Clear
          </Button>
        </Toolbar>
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
                    <Badge mono>{row.language || "n/a"}</Badge>
                    <Badge mono>{row.compiler || "n/a"}</Badge>
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
                render: (row) => <span title={row.sha256}>{row.sha256.slice(0, 16)}</span>,
              },
              { label: "Functions", key: "function_count", numeric: true },
              {
                label: "Comments",
                numeric: true,
                render: (row) => <Badge>{row.comment_count}</Badge>,
              },
              {
                label: "Scope",
                render: (row) => (
                  <select
                    aria-label={`scope of ${row.name}`}
                    value={row.visibility === "team" ? String(row.owner_team_id ?? "") : "public"}
                    disabled={busy === `scope-${row.id}`}
                    onChange={(event) => void setScope(row.id, event.target.value)}
                  >
                    <option value="public">public</option>
                    {(teamData.data?.teams ?? []).map((team) => (
                      <option key={team.id} value={team.id}>
                        team {team.name}
                      </option>
                    ))}
                  </select>
                ),
              },
              {
                label: "Actions",
                render: (row) => (
                  <div className="actions-cell">
                    <a href={`/api/binaries/${row.id}/download`}>Download</a>
                    <a href={`/api/binaries/${row.id}/download-zipped`}>Zipped</a>
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
                message={`Delete ${selected.size} selected ${selected.size === 1 ? "binary" : "binaries"}?`}
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

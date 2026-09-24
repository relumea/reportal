import { useEffect, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";

import { api, isApiErrorCode } from "../api";
import {
  Badge,
  Button,
  Card,
  CodeBlock,
  ConfirmButton,
  EmptyState,
  ErrorNote,
  Field,
  KeyValue,
  Loading,
  Muted,
  NameSourceDot,
  Note,
  Panel,
  Toolbar,
  TypeNameLink,
  countOf,
} from "../components";
import {
  DATA_TYPE_KIND_LABELS,
  DATA_TYPE_KIND_TAGS,
  DATA_TYPE_KINDS,
  DECOMPILER_BACKENDS,
  DEFAULT_DECOMPILER_BACKEND,
  PROGRAM_NAMESPACE,
  SEARCH_DEBOUNCE_MS,
  typeSourceLabel,
} from "../constants";
import { useNavigate } from "react-router";

import { setTypeEditRestore } from "../keys";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import { useAsync } from "../useAsync";
import type {
  DataType,
  DataTypeChange,
  DataTypeExportResult,
  DataTypeHistory,
  DataTypeImportResult,
  DataTypeKind,
  DataTypeList,
  DataTypeMember,
  DataTypeReferences,
  DataTypeRevertResult,
  DataTypeValue,
  NamespaceNode,
  SignatureExportResult,
  SignatureImportResult,
  StructResult,
} from "../types";

// Functions decompiled by the Recover control when the limit input is blank;
// mirrors DEFAULT_STRUCT_LIMIT on the API side.
const DEFAULT_STRUCT_LIMIT = 50;

/** Run *action* under a busy label; *onDone* refreshes after a success. */
function runMutation(
  setError: (error: unknown) => void,
  setBusy: (label: string) => void,
  label: string,
  action: () => Promise<unknown>,
  onDone: () => void,
): void {
  setError(null);
  setBusy(label);
  action()
    .then(() => onDone())
    .catch((failure: unknown) => {
      setError(failure);
    })
    .finally(() => setBusy(""));
}

// A type's source when the recovered structs scan created it; mirrors
// data_types.SOURCE_SCAN, the only other value being a manual edit.
const SOURCE_SCAN = "scan";

// The structs GET is stored-only; 404 no-scan means nothing was recovered yet.
const STRUCTS_NO_SCAN = "No structs recovered yet. Run the engine to recover them.";
const NO_TYPES_HINT = "No types yet. Import the stored structs scan to seed the model.";

function restoreOnFocus(
  restore: () => boolean,
): {
  onFocus: () => void;
  onBlur: () => void;
  onKeyDown: (event: ReactKeyboardEvent<HTMLInputElement>) => void;
} {
  return {
    onFocus: () => setTypeEditRestore(restore),
    onBlur: () => setTypeEditRestore(null),
    onKeyDown: (event) => {
      if (event.key !== "Escape") return;
      if (!restore()) return;
      event.preventDefault();
    },
  };
}

/** Render a member's type the way the exported C header does. */
function memberTypeText(member: DataTypeMember): string {
  const base = member.pointer ? `${member.type} *` : member.type;
  const sized = member.count === null ? base : `${base}[${member.count}]`;
  return member.bits === null ? sized : `${sized} : ${member.bits}`;
}

/**
 * The member type an input edits: the declaration without the bit width, which
 * travels as its own field.  A width folded into the type text would make the
 * declaration unparsable, so the input never carries one.
 */
function memberTypeInput(member: DataTypeMember): string {
  const base = member.pointer ? `${member.type} *` : member.type;
  return member.count === null ? base : `${base}[${member.count}]`;
}

/** Parse a bit-width input; null when it is blank, undefined when it is not a width. */
function parseBitsInput(text: string): number | null | undefined {
  const trimmed = text.trim();
  if (!trimmed) return null;
  if (!/^\d+$/.test(trimmed)) return undefined;
  const parsed = Number.parseInt(trimmed, 10);
  return parsed >= 1 ? parsed : undefined;
}

/** Parse a decimal or `0x` value input; null when it is neither. */
function parseValueInput(text: string): number | null {
  const trimmed = text.trim();
  if (!(trimmed && (/^-?\d+$/.test(trimmed) || /^0x[0-9a-f]+$/i.test(trimmed)))) return null;
  return Number(trimmed);
}

/** The kind badge's label; mirrors the API's kind vocabulary. */
function kindLabel(kind: DataTypeKind): string {
  return DATA_TYPE_KIND_LABELS[kind];
}

function targetIdent(name: string): string {
  return name.replace(/(?:\s*(?:\*+|\[\d*\]))+$/g, "").trim();
}

const CHAIN_KINDS = new Set<DataTypeKind>(["pointer", "typedef", "array"]);

/** Walk pointer/typedef/array hops until a leaf or a cycle. */
function targetChain(start: DataType, typesByName: Map<string, DataType>): DataType[] {
  const hops: DataType[] = [];
  const seen = new Set<number>([start.id]);
  let current: DataType | undefined = start;
  while (current && CHAIN_KINDS.has(current.kind) && current.target) {
    const next = typesByName.get(targetIdent(current.target));
    if (!next || seen.has(next.id)) break;
    hops.push(next);
    seen.add(next.id);
    current = next;
  }
  return hops;
}

export function DataTypesPanel({
  binaryId,
  query = {},
}: {
  binaryId: number;
  /** The route hash, whose keys are the filters this panel applies. */
  query?: Record<string, string>;
}): ReactNode {
  const structsKey = panelKey("binary", binaryId, "structs");
  const typesPath = `/binaries/${binaryId}/data-types`;
  const structsPath = `/binaries/${binaryId}/structs`;
  const structsEntry = usePanel(structsKey, () => api<StructResult>(structsPath));

  const navigate = useNavigate();
  // The filters are the route's, so the panel renders a link and a refresh
  // keeps the filtered view.  `apply` is the only writer.
  const kind = query.kind ?? "";
  const namespace = query.namespace ?? "";
  const search = query.search ?? "";
  const source = query.source ?? "";
  const sort = (TYPE_SORTS as readonly string[]).includes(query.sort ?? "")
    ? (query.sort as string)
    : "name";
  const direction = (SORT_DIRECTIONS as readonly string[]).includes(query.direction ?? "")
    ? (query.direction as string)
    : "asc";
  const filters: Record<string, string> = {
    kind,
    namespace,
    search,
    source,
    sort,
    direction,
  };
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const apply = (patch: Record<string, string>): void => {
    const next = { ...filtersRef.current, ...patch };
    filtersRef.current = next;
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(next)) {
      if (value !== "") params.set(key, value);
    }
    const search_ = params.toString();
    navigate({ pathname: `/binaries/${binaryId}`, search: search_ });
  };
  const setKind = (value: string): void => apply({ kind: value });
  const setNamespace = (value: string): void => apply({ namespace: value });
  const filterCount = [kind, namespace, source].filter(Boolean).length;
  const clearFilters = (): void => apply({ kind: "", namespace: "", source: "" });
  const [draftSearch, setDraftSearch] = useState(search);
  useEffect(() => {
    setDraftSearch(search);
  }, [search]);
  // The panel is the only writer of the published type-edit restore, so its
  // unmount withdraws it: a focused field that unmounts fires no blur, and the
  // stale closure would otherwise stay on the global Escape handler.
  useEffect(() => () => setTypeEditRestore(null), []);
  useEffect(() => {
    if (draftSearch === search) return undefined;
    const handle = window.setTimeout(() => apply({ search: draftSearch }), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(handle);
    // apply is recreated every render; the draft is the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draftSearch, search]);
  const setSource = (value: string): void => apply({ source: value });
  const setSort = (value: string): void => apply({ sort: value });
  const setDirection = (value: string): void => apply({ direction: value });
  // Progressive load: the model is fetched whole, and the list renders a page
  // at a time so a binary with thousands of types does not block the view.
  const [shown, setShown] = useState(DATA_TYPE_PAGE);
  const [backend, setBackend] = useState<string>(DEFAULT_DECOMPILER_BACKEND);
  const [limit, setLimit] = useState(String(DEFAULT_STRUCT_LIMIT));
  const [status, setStatus] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [exportPath, setExportPath] = useState("");
  const [exportResult, setExportResult] = useState<DataTypeExportResult | null>(null);
  const [exportError, setExportError] = useState<unknown>(null);
  const [forceNeeded, setForceNeeded] = useState(false);
  const [signatureStatus, setSignatureStatus] = useState("");
  const [prototypePath, setPrototypePath] = useState("");
  const [prototypeResult, setPrototypeResult] = useState<SignatureExportResult | null>(null);
  const [prototypeError, setPrototypeError] = useState<unknown>(null);
  const [prototypeForceNeeded, setPrototypeForceNeeded] = useState(false);
  const [declarations, setDeclarations] = useState("");
  const [bulkStatus, setBulkStatus] = useState("");
  const [bulkError, setBulkError] = useState<unknown>(null);

  // The list filter is the API's own: the query string names the kind, the
  // namespace path and the search needle, so one mechanism decides what a
  // filtered list means.  The panel's key carries the same string.
  const filterParams = new URLSearchParams();
  if (kind) filterParams.set("kind", kind);
  if (namespace) filterParams.set("namespace", namespace);
  if (search.trim()) filterParams.set("search", search.trim());
  if (source) filterParams.set("source", source);
  filterParams.set("sort", sort);
  filterParams.set("direction", direction);
  const queryString = filterParams.toString();
  const listPath = queryString ? `${typesPath}?${queryString}` : typesPath;
  const typesKey = panelKey("binary", binaryId, "data-types", queryString);
  const loadTypes = (): Promise<DataTypeList> => api<DataTypeList>(listPath);
  const entry = usePanel(typesKey, loadTypes);

  const recover = (): void => {
    const parsed = Number.parseInt(limit, 10);
    const bound = Number.isNaN(parsed) ? DEFAULT_STRUCT_LIMIT : parsed;
    setActionError(null);
    setBusy("recover");
    api<StructResult>(structsPath, { method: "POST", json: { decompiler: backend, limit: bound } })
      .then((result) => {
        setStatus(`recovered ${result.decompiled ?? 0} functions, skipped ${result.skipped ?? 0}`);
        refreshPanel(structsKey, () => api<StructResult>(structsPath));
      })
      .catch((error: unknown) => {
        setActionError(error);
      })
      .finally(() => setBusy(""));
  };

  const importFromScan = (): void => {
    setActionError(null);
    setBusy("import");
    api<DataTypeImportResult>(`${typesPath}/import`, { method: "POST" })
      .then((result) => {
        setStatus(`created ${result.created}, updated ${result.updated}, skipped ${result.skipped}`);
        refreshPanel(typesKey, loadTypes);
      })
      .catch((error: unknown) => {
        setActionError(error);
      })
      .finally(() => setBusy(""));
  };

  // The bulk route is analysis-scoped (the hosted one is), so the panel reads
  // the binary's latest analysis id rather than guessing one.
  const analyses = useAsync(
    () => api<{ analyses: Array<{ id: number }> }>(`/analyses?binary_id=${binaryId}&limit=1`),
    [binaryId],
  );

  const bulkTypes = (create: boolean): void => {
    const analysisId = analyses.data?.analyses?.[0]?.id;
    if (analysisId === undefined) {
      setBulkError(new Error("no analysis for this binary yet"));
      return;
    }
    if (!declarations.trim()) {
      setBulkError(new Error("paste at least one declaration"));
      return;
    }
    setBulkError(null);
    setBulkStatus("");
    setBusy(create ? "bulk-create" : "bulk-update");
    api<{ created: number; updated: number; skipped: number }>(
      `/analyses/${analysisId}/data-types`,
      { method: create ? "POST" : "PUT", json: { types: declarations } },
    )
      .then((result) => {
        setBulkStatus(
          `created ${result.created}, updated ${result.updated}, skipped ${result.skipped}`,
        );
        setDeclarations("");
        refreshPanel(typesKey, loadTypes);
      })
      .catch((error: unknown) => setBulkError(error))
      .finally(() => setBusy(""));
  };

  const doExport = (force: boolean): void => {
    setExportError(null);
    setExportResult(null);
    setBusy("export");
    api<DataTypeExportResult>(`${typesPath}/export`, {
      method: "POST",
      json: { path: exportPath, force },
    })
      .then((result) => {
        setExportResult(result);
        setForceNeeded(false);
      })
      .catch((error: unknown) => {
        if (isApiErrorCode(error, "export-exists")) {
          setForceNeeded(true);
          return;
        }
        setForceNeeded(false);
        setExportError(error);
      })
      .finally(() => setBusy(""));
  };

  const importSignatures = (): void => {
    setActionError(null);
    setSignatureStatus("");
    setBusy("signatures");
    api<SignatureImportResult>(`/binaries/${binaryId}/signatures/import`, { method: "POST" })
      .then((result) => {
        setSignatureStatus(
          `signatures: created ${result.created}, updated ${result.updated}, skipped ${result.skipped}`,
        );
      })
      .catch((error: unknown) => {
        setActionError(error);
      })
      .finally(() => setBusy(""));
  };

  const doExportPrototypes = (force: boolean): void => {
    setPrototypeError(null);
    setPrototypeResult(null);
    setBusy("prototypes");
    api<SignatureExportResult>(`/binaries/${binaryId}/signatures/export`, {
      method: "POST",
      json: { path: prototypePath, force },
    })
      .then((result) => {
        setPrototypeResult(result);
        setPrototypeForceNeeded(false);
      })
      .catch((error: unknown) => {
        if (isApiErrorCode(error, "export-exists")) {
          setPrototypeForceNeeded(true);
          return;
        }
        setPrototypeForceNeeded(false);
        setPrototypeError(error);
      })
      .finally(() => setBusy(""));
  };

  return (
    <Panel
      title="Data Types"
      subtitle="The editable type model of this binary: its structs, unions, enums, aliases and function types, plus the prototypes exported from the signature model."
      actions={
        <Toolbar>
          <Field label="Backend">
            <select value={backend} onChange={(event) => setBackend(event.target.value)}>
              {DECOMPILER_BACKENDS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Limit">
            <input
              type="number"
              min="0"
              value={limit}
              onChange={(event) => setLimit(event.target.value)}
            />
          </Field>
          <Button pending={busy === "recover"} onClick={recover}>
            Recover structs
          </Button>
          <Button pending={busy === "import"} onClick={importFromScan}>
            Import from scan
          </Button>
          <Button pending={busy === "bulk-create"} onClick={() => bulkTypes(true)}>
            Create from declarations
          </Button>
          <Button pending={busy === "bulk-update"} onClick={() => bulkTypes(false)}>
            Update from declarations
          </Button>
          <Field label="Export header">
            <input
              type="text"
              value={exportPath}
              placeholder="types.h"
              onChange={(event) => setExportPath(event.target.value)}
            />
          </Field>
          <Button pending={busy === "export"} onClick={() => doExport(false)}>
            Export header
          </Button>
          <Button pending={busy === "signatures"} onClick={importSignatures}>
            Import signatures
          </Button>
          <Field label="Export prototypes">
            <input
              type="text"
              value={prototypePath}
              placeholder="prototypes.h"
              onChange={(event) => setPrototypePath(event.target.value)}
            />
          </Field>
          <Button pending={busy === "prototypes"} onClick={() => doExportPrototypes(false)}>
            Export prototypes
          </Button>
        </Toolbar>
      }
    >
      {structsEntry?.state === "error" && isApiErrorCode(structsEntry.error, "no-scan") ? (
        <Muted>{STRUCTS_NO_SCAN}</Muted>
      ) : (
        <Muted>The type model is stored locally; import seeds it from the stored structs scan.</Muted>
      )}
      <Field
        label="Declarations"
        hint="C declarations; a struct may span lines and the server splits them."
      >
        <textarea
          rows={4}
          value={declarations}
          onChange={(event) => setDeclarations(event.target.value)}
        />
      </Field>
      {bulkError ? <ErrorNote error={bulkError} /> : null}
      {/* One region, mounted before its text, so a paste, import or signature
          edit is announced when it lands. */}
      <span role="status">
        {bulkStatus ? <Badge hue="match">{bulkStatus}</Badge> : null}
        {status ? <Badge hue="match">{status}</Badge> : null}
        {signatureStatus ? <Badge hue="match">{signatureStatus}</Badge> : null}
      </span>
      {actionError ? <ErrorNote error={actionError} /> : null}
      {forceNeeded ? (
        <Note tone="warn">
          {exportPath} already exists.{" "}
          <Button size="sm" tone="danger" pending={busy === "export"} onClick={() => doExport(true)}>
            Force overwrite
          </Button>
        </Note>
      ) : null}
      {exportError ? <ErrorNote error={exportError} /> : null}
      {exportResult ? (
        <Muted>
          wrote {exportResult.bytes} bytes ({exportResult.types} types) to {exportResult.path}
        </Muted>
      ) : null}
      {prototypeForceNeeded ? (
        <Note tone="warn">
          {prototypePath} already exists.{" "}
          <Button
            size="sm"
            tone="danger"
            pending={busy === "prototypes"}
            onClick={() => doExportPrototypes(true)}
          >
            Force overwrite
          </Button>
        </Note>
      ) : null}
      {prototypeError ? <ErrorNote error={prototypeError} /> : null}
      {prototypeResult ? (
        <Muted>
          wrote {prototypeResult.bytes} bytes ({prototypeResult.signatures} signatures) to{" "}
          {prototypeResult.path}
        </Muted>
      ) : null}
      <Toolbar>
        <Field label="Source filter">
          <select value={source} onChange={(event) => setSource(event.target.value)}>
            <option value="">All Sources</option>
            {DATA_TYPE_SOURCES.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Sort">
          <select value={sort} onChange={(event) => setSort(event.target.value)}>
            {TYPE_SORTS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Direction">
          <select value={direction} onChange={(event) => setDirection(event.target.value)}>
            {SORT_DIRECTIONS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Filter">
          <input
            type="search"
            placeholder={
              entry?.state === "ready"
                ? `Search ${entry.data.total} types or namespaces...`
                : "name, member or enum value"
            }
            value={draftSearch}
            onChange={(event) => setDraftSearch(event.target.value)}
          />
        </Field>
        {filterCount > 0 ? (
          <Button tone="ghost" onClick={clearFilters}>
            Clear all filters
          </Button>
        ) : null}
      </Toolbar>
      {!entry || entry.state === "loading" ? (
        <Loading label="Loading the type model" />
      ) : entry.state === "error" ? (
        <ErrorNote error={entry.error} onRetry={() => refreshPanel(typesKey, loadTypes)} />
      ) : (
        <>
          <NamespaceTree
            nodes={entry.data.namespaces}
            selected={namespace}
            onSelect={setNamespace}
          />
          <KindStrip
            kinds={entry.data.kinds ?? {}}
            selected={kind}
            onSelect={setKind}
          />
          <ProvenanceStrip
            sources={entry.data.sources ?? {}}
            selected={source}
            onSelect={setSource}
          />
          <TypeList
            data={{ ...entry.data, types: entry.data.types.slice(0, shown) }}
            search={search}
            namespace={namespace}
            kind={kind}
            onChanged={() => refreshPanel(typesKey, loadTypes)}
            onNote={setStatus}
          />
          {entry.data.types.length > shown ? (
            <Toolbar>
              <Button size="sm" onClick={() => setShown(shown + DATA_TYPE_PAGE)}>
                Load more types
              </Button>
              <Muted>
                Showing {Math.min(shown, entry.data.types.length)} of{" "}
                {countOf(entry.data.types.length, "matching type")}.
              </Muted>
            </Toolbar>
          ) : null}
        </>
      )}
    </Panel>
  );
}

/** How many types one page of the progressive list renders. */
const DATA_TYPE_PAGE = 50;

/** The four provenance labels the API reports, in its own order. */
const DATA_TYPE_SOURCES = ["System", "User", "Auto Unstrip", "AI"] as const;

// The orders the type list accepts and the two directions; mirrors
// `data_types.TYPE_SORTS` and `data_types.SORT_DIRECTIONS`.
const TYPE_SORTS = ["name", "size"] as const;
const SORT_DIRECTIONS = ["asc", "desc"] as const;

/**
 * The kind strip: how many types of each declaration kind, each count a
 * filter control.
 *
 * The counts are over the whole model rather than the filtered page, so a
 * reader can see that ticking `enum` will leave something before ticking it.
 */
function KindStrip({
  kinds,
  selected,
  onSelect,
}: {
  kinds: Record<string, number>;
  selected: string;
  onSelect: (kind: string) => void;
}): ReactNode {
  return (
    <Toolbar>
      {DATA_TYPE_KINDS.map((option) => (
        <Button
          key={option}
          size="sm"
          tone={selected === option ? "primary" : "ghost"}
          title={kindLabel(option)}
          aria-pressed={selected === option}
          onClick={() => onSelect(selected === option ? "" : option)}
        >
          {DATA_TYPE_KIND_TAGS[option]}: {kinds[option] ?? 0}
        </Button>
      ))}
      {selected ? (
        <Button size="sm" tone="ghost" onClick={() => onSelect("")}>
          Clear kind
        </Button>
      ) : null}
    </Toolbar>
  );
}

function ProvenanceStrip({
  sources,
  selected,
  onSelect,
}: {
  sources: Record<string, number>;
  selected: string;
  onSelect: (source: string) => void;
}): ReactNode {
  return (
    <Toolbar>
      {DATA_TYPE_SOURCES.map((label) => (
        <Button
          key={label}
          size="sm"
          tone={selected === label ? "primary" : "ghost"}
          aria-pressed={selected === label}
          onClick={() => onSelect(selected === label ? "" : label)}
        >
          {label}: {sources[label] ?? 0}
        </Button>
      ))}
      {selected ? (
        <Button size="sm" tone="ghost" onClick={() => onSelect("")}>
          Clear Source
        </Button>
      ) : null}
    </Toolbar>
  );
}

/** Keep a node when its name or any descendant matches the needle. */
function filterTree(node: NamespaceNode, needle: string): NamespaceNode | null {
  const text = needle.trim().toLowerCase();
  if (!text) return node;
  const children = node.children
    .map((child) => filterTree(child, needle))
    .filter((child): child is NamespaceNode => child !== null);
  if (node.name.toLowerCase().includes(text) || children.length > 0) {
    return { ...node, children };
  }
  return null;
}

/** The namespace tree: its own search box, a collapse control and one node per branch. */
function NamespaceTree({
  nodes,
  selected,
  onSelect,
}: {
  nodes: NamespaceNode[];
  selected: string;
  onSelect: (path: string) => void;
}): ReactNode {
  const [needle, setNeedle] = useState("");
  const [collapsed, setCollapsed] = useState(false);
  const shown = nodes
    .map((node) => filterTree(node, needle))
    .filter((node): node is NamespaceNode => node !== null);
  return (
    <div className="namespace-tree">
      <Toolbar>
        <Field label="Search namespaces">
          <input
            type="search"
            placeholder="Search namespaces..."
            value={needle}
            onChange={(event) => setNeedle(event.target.value)}
          />
        </Field>
        <Button size="sm" onClick={() => setCollapsed((value) => !value)}>
          {collapsed ? "Expand" : "Collapse"}
        </Button>
        {selected ? (
          <Button size="sm" tone="ghost" onClick={() => onSelect("")}>
            All Namespaces
          </Button>
        ) : null}
      </Toolbar>
      {shown.length === 0 ? (
        <Muted>No namespace matches {needle.trim()}.</Muted>
      ) : (
        <ul className="namespace-list">
          {shown.map((node) => (
            <NamespaceNode
              key={node.path}
              node={node}
              selected={selected}
              collapsed={collapsed}
              onSelect={onSelect}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

function NamespaceNode({
  node,
  selected,
  collapsed,
  onSelect,
}: {
  node: NamespaceNode;
  selected: string;
  collapsed: boolean;
  onSelect: (path: string) => void;
}): ReactNode {
  const covered = selected !== "" && node.path.startsWith(`${selected}::`);
  const active = selected === node.path;
  return (
    <li>
      <button
        type="button"
        className={
          covered ? "tree-node is-covered" : active ? "tree-node is-active" : "tree-node"
        }
        aria-pressed={active}
        onClick={() => onSelect(node.path)}
      >
        {node.name} <span className="muted">({node.count})</span>
      </button>
      {!collapsed && node.children.length > 0 ? (
        <ul className="namespace-list">
          {node.children.map((child) => (
            <NamespaceNode
              key={child.path}
              node={child}
              selected={selected}
              collapsed={collapsed}
              onSelect={onSelect}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/** The filtered type list with the counts the active filters produce. */
function TypeList({
  data,
  search,
  namespace,
  kind,
  onChanged,
  onNote,
}: {
  data: DataTypeList;
  search: string;
  namespace: string;
  kind: string;
  onChanged: () => void;
  onNote: (note: string) => void;
}): ReactNode {
  const members = data.types.reduce((total, dataType) => total + dataType.members.length, 0);
  const scanned = data.types.filter((dataType) => dataType.source === SOURCE_SCAN).length;
  const knownTypes = new Set(data.types.map((entry) => entry.name));
  const typesByName = new Map(data.types.map((entry) => [entry.name, entry]));
  const filterLabel = [kind, namespace, search.trim()].filter(Boolean).join(", ");
  if (data.types.length === 0) {
    return filterLabel ? (
      <EmptyState>No type matches {filterLabel}.</EmptyState>
    ) : (
      <EmptyState>{NO_TYPES_HINT}</EmptyState>
    );
  }
  return (
    <>
      <Muted>
        {data.count} of {data.total} types ({members} members; {scanned} from the recovered scan,{" "}
        {data.count - scanned} manual)
      </Muted>
      {data.types.map((dataType) => (
        <DataTypeCard
          key={dataType.id}
          binaryId={data.binary_id}
          dataType={dataType}
          knownTypes={knownTypes}
          typesByName={typesByName}
          onChange={onChanged}
          onNote={onNote}
        />
      ))}
    </>
  );
}

function DataTypeCard({
  binaryId,
  dataType,
  knownTypes,
  typesByName,
  onChange,
  onNote,
}: {
  binaryId: number;
  dataType: DataType;
  knownTypes: Set<string>;
  typesByName: Map<string, DataType>;
  onChange: () => void;
  onNote: (note: string) => void;
}): ReactNode {
  const [name, setName] = useState(dataType.name);
  const [kind, setKind] = useState<DataTypeKind>(dataType.kind);
  const [namespace, setNamespace] = useState(dataType.namespace);
  const [sizeText, setSizeText] = useState(String(dataType.size));
  const [memberName, setMemberName] = useState("");
  const [memberType, setMemberType] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [showReferences, setShowReferences] = useState(false);
  const [showHistory, setShowHistory] = useState(false);

  // A save writes a history version too, so the history section reloads with
  // the model instead of going stale until the next mount.
  const historyKey = panelKey("data-type", dataType.id, "history");
  const changed = (): void => {
    onChange();
    refreshPanel(historyKey, () => api<DataTypeHistory>(`/data-types/${dataType.id}/history`));
  };

  const mutate = (label: string, action: () => Promise<unknown>): void => {
    runMutation(setError, setBusy, label, action, changed);
  };

  const rename = (): void => {
    mutate("rename", () => api(`/data-types/${dataType.id}`, { method: "PATCH", json: { name } }));
  };

  /** Save the kind, namespace and declared size in one write and one history entry. */
  const saveFields = (): void => {
    const parsedSize = Number.parseInt(sizeText, 10);
    mutate("fields", () =>
      api(`/data-types/${dataType.id}`, {
        method: "PATCH",
        json: {
          kind,
          namespace,
          size: Number.isNaN(parsedSize) ? dataType.size : parsedSize,
        },
      }),
    );
  };

  const addMember = (): void => {
    mutate("add", () =>
      api(`/data-types/${dataType.id}/members`, {
        method: "POST",
        json: { name: memberName, type: memberType },
      }),
    );
  };

  const removeType = (): void => {
    mutate("delete", () => api(`/data-types/${dataType.id}`, { method: "DELETE" }));
  };

  const memberKind =
    dataType.kind === "struct" || dataType.kind === "union" || dataType.kind === "function";

  return (
    <Card
      title={
        <>
          <NameSourceDot label={typeSourceLabel(dataType.source || "manual")} />{" "}
          <Badge mono>{dataType.name}</Badge>{" "}
          <Badge mono title={kindLabel(dataType.kind)}>
            {DATA_TYPE_KIND_TAGS[dataType.kind]}
          </Badge>{" "}
          {dataType.namespace ? dataType.namespace : PROGRAM_NAMESPACE} · {dataType.size} bytes ·{" "}
          {dataType.kind === "enum"
            ? `${dataType.values.length} values`
            : `${dataType.members.length} members`}{" "}
          · {typeSourceLabel(dataType.source || "manual")}
        </>
      }
      actions={
        <>
          <Field label="Rename">
            <input
              type="text"
              value={name}
              onChange={(event) => setName(event.target.value)}
              {...restoreOnFocus(() => {
                if (name === dataType.name) return false;
                setName(dataType.name);
                return true;
              })}
            />
          </Field>
          <Button size="sm" pending={busy === "rename"} onClick={rename}>
            Rename type
          </Button>
          <Button size="sm" tone="ghost" onClick={() => setShowReferences((value) => !value)}>
            {showReferences ? "Hide references" : "References"}
          </Button>
          <Button size="sm" tone="ghost" onClick={() => setShowHistory((value) => !value)}>
            {showHistory ? "Hide history" : "History"}
          </Button>
          <ConfirmButton
            label="Delete type"
            message={`Delete type ${dataType.name}?`}
            pending={busy === "delete"}
            onConfirm={removeType}
          />
        </>
      }
    >
      <Toolbar>
        <Field label="Kind">
          <select value={kind} onChange={(event) => setKind(event.target.value as DataTypeKind)}>
            {DATA_TYPE_KINDS.map((option) => (
              <option key={option} value={option}>
                {kindLabel(option)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Namespace">
          <input
            type="text"
            placeholder={PROGRAM_NAMESPACE}
            value={namespace}
            onChange={(event) => setNamespace(event.target.value)}
            {...restoreOnFocus(() => {
              if (namespace === dataType.namespace) return false;
              setNamespace(dataType.namespace);
              return true;
            })}
          />
        </Field>
        <Field label="Size">
          <input
            type="number"
            min="0"
            value={sizeText}
            onChange={(event) => setSizeText(event.target.value)}
            {...restoreOnFocus(() => {
              const original = String(dataType.size);
              if (sizeText === original) return false;
              setSizeText(original);
              return true;
            })}
          />
        </Field>
        <Button size="sm" tone="primary" pending={busy === "fields"} onClick={saveFields}>
          Save fields
        </Button>
      </Toolbar>
      {dataType.size_check.match ? null : <Note tone="warn">{dataType.size_check.warning}</Note>}
      <CodeBlock text={dataType.as_c} title="As C" />
      {dataType.kind === "enum" ? (
        <EnumValues dataType={dataType} onChange={changed} onNote={onNote} />
      ) : dataType.kind === "struct" || dataType.kind === "union" || dataType.kind === "function" ? (
        <>
          {dataType.kind === "function" ? (
            <KeyValue
              rows={[
                [
                  "Returns",
                  dataType.target ? (
                    <TypeNameLink
                      binaryId={binaryId}
                      name={dataType.target}
                      knownTypes={knownTypes}
                    />
                  ) : (
                    "n/a"
                  ),
                ],
              ]}
            />
          ) : null}
          <MemberTable
            binaryId={binaryId}
            dataType={dataType}
            knownTypes={knownTypes}
            onChange={changed}
            addName={memberName}
            addType={memberType}
          />
        </>
      ) : (
        <KeyValue
          rows={[
            [
              dataType.kind === "pointer"
                ? "Points at"
                : dataType.kind === "array"
                  ? "Element type"
                  : dataType.kind === "typedef"
                    ? "Aliases"
                    : "Target",
              dataType.target ? (
                <TypeNameLink binaryId={binaryId} name={dataType.target} knownTypes={knownTypes} />
              ) : (
                "n/a"
              ),
            ],
            [
              "Chain",
              (() => {
                const hops = targetChain(dataType, typesByName);
                if (!hops.length) return "n/a";
                return (
                  <span>
                    {hops.map((hop, index) => (
                      <span key={hop.id}>
                        {index > 0 ? " then " : null}
                        <TypeNameLink
                          binaryId={binaryId}
                          name={hop.name}
                          knownTypes={knownTypes}
                        />{" "}
                        ({kindLabel(hop.kind)} · {hop.size} bytes)
                      </span>
                    ))}
                  </span>
                );
              })(),
            ],
            ["Element count", dataType.element_count === null ? "n/a" : String(dataType.element_count)],
          ]}
        />
      )}
      {memberKind ? (
        <Toolbar>
          <Field label={dataType.kind === "function" ? "Add parameter" : "Add member"}>
            <input
              type="text"
              placeholder="name"
              value={memberName}
              onChange={(event) => setMemberName(event.target.value)}
              {...restoreOnFocus(() => {
                if (memberName === "") return false;
                setMemberName("");
                return true;
              })}
            />
          </Field>
          <Field label="Type">
            <input
              type="text"
              placeholder="unsigned int"
              value={memberType}
              onChange={(event) => setMemberType(event.target.value)}
              {...restoreOnFocus(() => {
                if (memberType === "") return false;
                setMemberType("");
                return true;
              })}
            />
          </Field>
          <Button size="sm" tone="primary" pending={busy === "add"} onClick={addMember}>
            Add member
          </Button>
        </Toolbar>
      ) : null}
      {error ? <ErrorNote error={error} /> : null}
      {showHistory ? <DataTypeHistorySection dataTypeId={dataType.id} onChange={changed} /> : null}
      {showReferences ? (
        <TypeReferences dataTypeId={dataType.id} binaryId={binaryId} />
      ) : null}
    </Card>
  );
}

/** Render one recorded field value the way a history diff shows it. */
function changeText(value: DataTypeChange["before"]): string {
  if (value === null || value === "") return "n/a";
  if (Array.isArray(value)) {
    if (value.length === 0) return "none";
    return value
      .map((item) => ("type" in item ? memberTypeText(item) : `${item.name} = ${item.value}`))
      .join(", ");
  }
  return String(value);
}

/** One type's edit history: a version list with its field diff and a revert each. */
function DataTypeHistorySection({
  dataTypeId,
  onChange,
}: {
  dataTypeId: number;
  onChange: () => void;
}): ReactNode {
  const key = panelKey("data-type", dataTypeId, "history");
  const loadHistory = (): Promise<DataTypeHistory> =>
    api<DataTypeHistory>(`/data-types/${dataTypeId}/history`);
  const entry = usePanel(key, loadHistory);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const revert = (historyId: number): void => {
    setError(null);
    setBusy(`revert-${historyId}`);
    api<DataTypeRevertResult>(`/data-types/${dataTypeId}/history/${historyId}/revert`, {
      method: "POST",
    })
      .then(() => {
        refreshPanel(key, loadHistory);
        onChange();
      })
      .catch((failure: unknown) => {
        setError(failure);
      })
      .finally(() => setBusy(""));
  };

  if (!entry || entry.state === "loading") {
    return <Loading label="Loading the type history" rows={2} />;
  }
  if (entry.state === "error") {
    return <ErrorNote error={entry.error} onRetry={() => refreshPanel(key, loadHistory)} />;
  }
  const data = entry.data;
  return (
    <>
      <h4>History</h4>
      <Muted>
        {data.count} recorded {data.count === 1 ? "edit" : "edits"}; a revert restores the state a
        version replaced and is itself revertible through its journal action.
      </Muted>
      {data.count === 0 ? (
        <EmptyState>No edits recorded for this type yet.</EmptyState>
      ) : (
        <ul className="type-history">
          {data.history.map((version, index) => (
            <li key={version.id}>
              <div className="toolbar">
                <Badge mono>#{version.id}</Badge>
                {index === 0 ? <Badge tone="ok">Current</Badge> : null}
                {index === data.history.length - 1 && data.history.length > 1 ? (
                  <Badge tone="info">Original</Badge>
                ) : null}
                <Muted>
                  {version.source || "manual"} ({version.actor_name ?? version.actor ?? "manual"}
                  ){version.age ? `, ${version.age}` : ""} · {version.created_at}
                </Muted>
                <ConfirmButton
                  label="Revert"
                  message="Restore this version?"
                  pending={busy === `revert-${version.id}`}
                  onConfirm={() => revert(version.id)}
                />
              </div>
              {version.previous === null ? (
                <Muted>created this type</Muted>
              ) : version.current === null ? (
                <Muted>deleted this type</Muted>
              ) : version.changes.length === 0 ? (
                <Muted>no model field changed</Muted>
              ) : (
                <ul>
                  {version.changes.map((change) => (
                    <li key={change.field}>
                      <code>{change.field}</code> {changeText(change.before)} -&gt;{" "}
                      {changeText(change.after)}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
      {error ? <ErrorNote error={error} /> : null}
    </>
  );
}

function MemberTable({
  binaryId,
  dataType,
  knownTypes,
  onChange,
  addName,
  addType,
}: {
  binaryId: number;
  dataType: DataType;
  knownTypes: Set<string>;
  onChange: () => void;
  addName: string;
  addType: string;
}): ReactNode {
  const padding = dataType.members
    .filter((member) => member.is_gap === true)
    .reduce((total, member) => total + member.size, 0);
  const isFunction = dataType.kind === "function";
  return (
    <>
      {dataType.kind === "union" ? <Muted>All members overlap.</Muted> : null}
      {dataType.members.length === 0 ? (
        <EmptyState>
          {isFunction ? "No parameters yet. Add one below." : "No members yet. Add one below."}
        </EmptyState>
      ) : (
        <div className="table-scroll">
          <table className="data-table" aria-label={isFunction ? "Function parameters" : "Type members"}>
            <thead>
              <tr>
                {isFunction ? null : <th className="num">Offset</th>}
                <th className="num">Size</th>
                <th>{isFunction ? "Parameter" : "Member"}</th>
                <th>Type</th>
                {isFunction ? null : <th className="num">Bits</th>}
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {dataType.members.map((member, index) => (
                <MemberRow
                  key={`${member.name}-${index}`}
                  binaryId={binaryId}
                  dataTypeId={dataType.id}
                  member={member}
                  index={index}
                  count={dataType.members.length}
                  knownTypes={knownTypes}
                  onChange={onChange}
                  addName={addName}
                  addType={addType}
                  hideLayout={isFunction}
                />
              ))}
            </tbody>
          </table>
          <Muted>
            {isFunction
              ? `${dataType.members.length} parameters`
              : `${dataType.members.length} members · ${dataType.size} bytes${
                  padding > 0 ? ` · ${padding} bytes padding` : ""
                }`}
          </Muted>
        </div>
      )}
    </>
  );
}

/**
 * An enum's named constants, editable in place: a rename, a revalue and a
 * removal per row, and an add that auto-increments when the value is blank.
 */
function EnumValues({
  dataType,
  onChange,
  onNote,
}: {
  dataType: DataType;
  onChange: () => void;
  onNote: (note: string) => void;
}): ReactNode {
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const add = (): void => {
    setError(null);
    setBusy("add-value");
    const body: Record<string, unknown> = { name };
    if (value.trim()) {
      const parsed = parseValueInput(value);
      body.value = parsed === null ? value.trim() : parsed;
    }
    api<DataType & { note?: string }>(`/data-types/${dataType.id}/values`, {
      method: "POST",
      json: body,
    })
      .then((result) => {
        const added = result.values[result.values.length - 1];
        // The note goes to the panel: this card's own state does not survive
        // the model refresh the write triggers.
        onNote(result.note ?? `added ${added.name} = ${added.value}`);
        setName("");
        setValue("");
        onChange();
      })
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(""));
  };

  return (
    <>
      {dataType.values.length === 0 ? (
        <EmptyState>No enum values stored.</EmptyState>
      ) : (
        <div className="table-scroll">
          <table className="data-table" aria-label="Enum values">
            <thead>
              <tr>
                <th>Name</th>
                <th className="num">Value</th>
                <th className="num">Hex</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {dataType.values.map((entry, index) => (
                <EnumValueRow
                  key={`${entry.name}-${index}`}
                  dataTypeId={dataType.id}
                  value={entry}
                  onChange={onChange}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Toolbar>
        <Field label="Add value">
          <input
            type="text"
            placeholder="NP_FLAG_C"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field label="Value">
          <input
            type="text"
            placeholder="increments"
            value={value}
            onChange={(event) => setValue(event.target.value)}
          />
        </Field>
        <Button
          size="sm"
          tone="primary"
          pending={busy === "add-value"}
          disabled={!name.trim()}
          onClick={add}
        >
          Add value
        </Button>
      </Toolbar>
      {error ? <ErrorNote error={error} /> : null}
    </>
  );
}

function EnumValueRow({
  dataTypeId,
  value,
  onChange,
}: {
  dataTypeId: number;
  value: DataTypeValue;
  onChange: () => void;
}): ReactNode {
  const [name, setName] = useState(value.name);
  const [valueText, setValueText] = useState(String(value.value));
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const mutate = (label: string, action: () => Promise<unknown>): void => {
    runMutation(setError, setBusy, label, action, onChange);
  };

  const save = (): void => {
    const parsed = parseValueInput(valueText);
    if (parsed === null) {
      setError(new Error("value must be a decimal or 0x hex literal"));
      return;
    }
    mutate("save", () =>
      api(`/data-types/${dataTypeId}/values/${encodeURIComponent(value.name)}`, {
        method: "PATCH",
        json: { new_name: name, new_value: parsed },
      }),
    );
  };

  const remove = (): void => {
    mutate("remove", () =>
      api(`/data-types/${dataTypeId}/values/${encodeURIComponent(value.name)}`, {
        method: "DELETE",
      }),
    );
  };

  const parsed = parseValueInput(valueText);
  const hex =
    parsed === null ? "n/a" : parsed < 0 ? `-0x${(-parsed).toString(16)}` : `0x${parsed.toString(16)}`;
  return (
    <tr>
      <td>
        <input
          type="text"
          aria-label={`Name of enum value ${value.name}`}
          value={name}
          onChange={(event) => setName(event.target.value)}
          {...restoreOnFocus(() => {
            if (name === value.name) return false;
            setName(value.name);
            return true;
          })}
        />
      </td>
      <td className="num">
        <input
          type="text"
          aria-label={`Value of enum value ${value.name}`}
          value={valueText}
          onChange={(event) => setValueText(event.target.value)}
          {...restoreOnFocus(() => {
            const original = String(value.value);
            if (valueText === original) return false;
            setValueText(original);
            return true;
          })}
        />
      </td>
      <td className="num mono">{hex}</td>
      <td>
        <div className="actions-cell">
          <Button size="sm" pending={busy === "save"} onClick={save}>
            Save
          </Button>
          <ConfirmButton
            label="Remove"
            message={`Remove enum value ${value.name}?`}
            pending={busy === "remove"}
            onConfirm={remove}
          />
        </div>
        {error ? <ErrorNote error={error} /> : null}
      </td>
    </tr>
  );
}

/** The two reverse indices the API builds for one type, loaded on demand. */
function TypeReferences({
  dataTypeId,
  binaryId,
}: {
  dataTypeId: number;
  binaryId: number;
}): ReactNode {
  const key = panelKey("data-type", dataTypeId, "references");
  const entry = usePanel(key, () => api<DataTypeReferences>(`/data-types/${dataTypeId}/references`));
  if (!entry || entry.state === "loading") {
    return <Loading label="Loading type references" rows={2} />;
  }
  if (entry.state === "error") {
    return <ErrorNote error={entry.error} />;
  }
  const data = entry.data;
  return (
    <>
      <Muted>{data.note}</Muted>
      <h4>Referenced by</h4>
      {data.referenced_by.length === 0 ? (
        <EmptyState>Nothing references this type.</EmptyState>
      ) : (
        <div className="table-scroll">
          <table className="data-table" aria-label="Type references">
            <thead>
              <tr>
                <th>Type</th>
                <th>Kind</th>
                <th>Namespace</th>
                <th>Relationship</th>
              </tr>
            </thead>
            <tbody>
              {data.referenced_by.map((reference) => (
                <tr key={reference.id}>
                  <td className="mono">
                    <a
                      href={`#/binaries/${binaryId}?search=${encodeURIComponent(reference.name)}`}
                    >
                      {reference.name}
                    </a>
                  </td>
                  <td>{reference.kind}</td>
                  <td>{reference.namespace || PROGRAM_NAMESPACE}</td>
                  <td>{reference.relationships.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <h4>Used by functions</h4>
      {data.used_by_functions.length === 0 ? (
        <EmptyState>No stored signature names this type.</EmptyState>
      ) : (
        <div className="table-scroll">
          <table className="data-table" aria-label="Function usages">
            <thead>
              <tr>
                <th>Function</th>
                <th>Usage</th>
              </tr>
            </thead>
            <tbody>
              {data.used_by_functions.map((usage) => (
                <tr key={usage.function_id}>
                  <td>
                    <a href={`#/functions/${usage.function_id}`}>{usage.name}</a>
                  </td>
                  <td>{usage.usages.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function MemberRow({
  binaryId,
  dataTypeId,
  member,
  index,
  count,
  knownTypes,
  onChange,
  addName,
  addType,
  hideLayout = false,
}: {
  binaryId: number;
  dataTypeId: number;
  member: DataTypeMember;
  index: number;
  count: number;
  knownTypes: Set<string>;
  onChange: () => void;
  addName: string;
  addType: string;
  hideLayout?: boolean;
}): ReactNode {
  const [name, setName] = useState(member.name);
  const [typeText, setTypeText] = useState(memberTypeInput(member));
  const [bitsText, setBitsText] = useState(member.bits === null ? "" : String(member.bits));
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const mutate = (label: string, action: () => Promise<unknown>): void => {
    runMutation(setError, setBusy, label, action, onChange);
  };

  const save = (): void => {
    const bits = parseBitsInput(bitsText);
    if (bits === undefined) {
      setError(new Error("bit width must be a whole number of at least 1"));
      return;
    }
    mutate("save", () =>
      api(`/data-types/${dataTypeId}`, {
        method: "PATCH",
        json: {
          member: {
            name: member.name,
            new_name: name,
            new_type: typeText,
            new_bits: bits,
          },
        },
      }),
    );
  };

  const remove = (): void => {
    mutate("remove", () =>
      api(`/data-types/${dataTypeId}/members/${encodeURIComponent(member.name)}`, {
        method: "DELETE",
      }),
    );
  };

  const insertAfter = (): void => {
    mutate("insert", () =>
      api(`/data-types/${dataTypeId}/members`, {
        method: "POST",
        json: { name: addName, type: addType, after: member.name },
      }),
    );
  };

  const move = (toIndex: number): void => {
    mutate("move", () =>
      api(`/data-types/${dataTypeId}/members/${encodeURIComponent(member.name)}/move`, {
        method: "POST",
        json: { to_index: toIndex },
      }),
    );
  };

  const toGap = (): void => {
    mutate("gap", () =>
      api(`/data-types/${dataTypeId}/members/${encodeURIComponent(member.name)}/gap`, {
        method: "POST",
        json: {},
      }),
    );
  };

  const fromGap = (): void => {
    mutate("ungap", () =>
      api(`/data-types/${dataTypeId}/members/${encodeURIComponent(member.name)}/ungap`, {
        method: "POST",
        json: { name, type: typeText },
      }),
    );
  };

  const canInsert = addName.trim() !== "" && addType.trim() !== "";
  const isGap = member.is_gap === true;
  return (
    <tr>
      {hideLayout ? null : <td className="num">{`0x${member.offset.toString(16)}`}</td>}
      <td className="num">{member.size}</td>
      <td>
        <input
          type="text"
          aria-label={`Name of member ${member.name}`}
          value={name}
          onChange={(event) => setName(event.target.value)}
          {...restoreOnFocus(() => {
            if (name === member.name) return false;
            setName(member.name);
            return true;
          })}
        />
        {isGap ? <span className="muted"> padding</span> : null}
      </td>
      <td>
        <input
          type="text"
          aria-label={`Type of member ${member.name}`}
          value={typeText}
          onChange={(event) => setTypeText(event.target.value)}
          {...restoreOnFocus(() => {
            const original = memberTypeInput(member);
            if (typeText === original) return false;
            setTypeText(original);
            return true;
          })}
        />
        {knownTypes.has(member.type) ? (
          <>
            {" "}
            <TypeNameLink binaryId={binaryId} name={member.type} knownTypes={knownTypes} />
          </>
        ) : null}
        {member.note ? <span className="muted"> {member.note}</span> : null}
      </td>
      {hideLayout ? null : (
        <td className="num bits-cell">
          <input
            type="text"
            aria-label={`Bit width of member ${member.name}`}
            placeholder="-"
            value={bitsText}
            onChange={(event) => setBitsText(event.target.value)}
            {...restoreOnFocus(() => {
              const original = member.bits === null ? "" : String(member.bits);
              if (bitsText === original) return false;
              setBitsText(original);
              return true;
            })}
          />
        </td>
      )}
      <td>
        <div className="actions-cell">
          <Button size="sm" pending={busy === "save"} onClick={save}>
            Save
          </Button>
          <Button
            size="sm"
            tone="ghost"
            pending={busy === "move"}
            disabled={index === 0}
            title="Move earlier in the layout"
            aria-label={`Move member ${member.name} up`}
            onClick={() => move(index - 1)}
          >
            ↑
          </Button>
          <Button
            size="sm"
            tone="ghost"
            pending={busy === "move"}
            disabled={index === count - 1}
            title="Move later in the layout"
            aria-label={`Move member ${member.name} down`}
            onClick={() => move(index + 1)}
          >
            ↓
          </Button>
          <Button
            size="sm"
            tone="ghost"
            pending={busy === "insert"}
            disabled={!canInsert}
            title={canInsert ? undefined : "Fill the add-member name and type first"}
            onClick={insertAfter}
          >
            Insert member after
          </Button>
          {hideLayout ? null : isGap ? (
            <Button size="sm" tone="ghost" pending={busy === "ungap"} onClick={fromGap}>
              Convert to member
            </Button>
          ) : (
            <Button size="sm" tone="ghost" pending={busy === "gap"} onClick={toGap}>
              Convert to gap
            </Button>
          )}
          <ConfirmButton
            label="Remove"
            message={`Remove member ${member.name}?`}
            pending={busy === "remove"}
            onConfirm={remove}
          />
        </div>
        {error ? <ErrorNote error={error} /> : null}
      </td>
    </tr>
  );
}

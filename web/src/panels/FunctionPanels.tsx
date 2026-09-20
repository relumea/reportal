import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api, isApiErrorCode } from "../api";
import {
  Badge,
  Button,
  CheckboxField,
  CodeBlock,
  ConfirmButton,
  CopyValue,
  DataTable,
  EmptyState,
  EngineNote,
  ErrorNote,
  Field,
  Loading,
  Muted,
  NA,
  Note,
  Panel,
  PanelBody,
  StatusCell,
  Toolbar,
  hex,
} from "../components";
import {
  AI_ARTIFACT_PATHS,
  AI_NO_ARTIFACT,
  DECOMPILER_BACKENDS,
  DEFAULT_DECOMPILER_BACKEND,
  DEFAULT_FUNCTION_CODE_VIEW,
  DEFAULT_TRANSFER_MODE,
  DISASM_FORMATS,
  FUNCTION_CODE_VIEWS,
  FUNCTION_CODE_VIEW_LABELS,
  TRANSFER_MODES,
  TRANSFER_MODE_LABELS,
} from "../constants";
import type { AiArtifactKind, DisasmFormat, FunctionCodeView } from "../constants";
import { panelKey, refreshPanel, useLazyPanel, usePanel } from "../panelCache";
import type { PanelEntry } from "../panelCache";
import { setCodeViewSwitch } from "./codeViewSwitch";
import { CfgPanel } from "./CfgPanel";
import type {
  AiArtifact,
  AiCommentsPayload,
  AiDecompilation,
  AiDecompilationToken,
  AiSummaryPayload,
  AiTypeSuggestionsPayload,
  DecompilationResult,
  DisasmResult,
  FunctionReferences,
  FunctionRow,
  HistoryRow,
  MatchRow,
  RenamesApplyResult,
  RenamesPayload,
  RenameSuggestion,
  TransferMode,
  TransferRowReport,
  Xrefs,
} from "../types";

function toDisasmFormat(value: string): DisasmFormat {
  return value === "hex" ? "hex" : "nasm";
}

/** Panel key and loader of a function's rename history, shared with the panels
 * that rename a function and must refresh it. */
export function historyKey(functionId: number): string {
  return panelKey("fn", functionId, "history");
}

export function loadHistory(functionId: number): Promise<{ history: HistoryRow[] }> {
  return api<{ history: HistoryRow[] }>(`/functions/${functionId}/history`);
}

/** Panel key and loader of a function's decompilation, shared with the renames
 * panel, which rewrites the stored text and must refresh the view. */
function decompilationKey(functionId: number, backend: string): string {
  return panelKey("fn", functionId, "decompilation", backend);
}

function loadDecompilation(functionId: number, backend: string): Promise<DecompilationResult> {
  return api<DecompilationResult>(`/functions/${functionId}/decompilation?backend=${backend}`);
}

/** Refresh the decompilation panel of every backend the view can show. */
function refreshDecompilation(functionId: number): void {
  for (const backend of DECOMPILER_BACKENDS) {
    refreshPanel(decompilationKey(functionId, backend), () =>
      loadDecompilation(functionId, backend),
    );
  }
}

function DisasmPanel({
  functionId,
  toggle,
}: {
  functionId: number;
  /** The code-view toggle this panel shares with the control-flow panel. */
  toggle?: ReactNode;
}): ReactNode {
  const [format, setFormat] = useState<DisasmFormat>("nasm");
  const [busy, setBusy] = useState(false);
  const key = panelKey("fn", functionId, "disasm", format);
  const loader = (): Promise<DisasmResult> =>
    api<DisasmResult>(`/functions/${functionId}/disasm?format=${format}`);
  const entry = usePanel(key, loader);

  let body: ReactNode;
  if (!entry || entry.state === "loading") body = <Loading label="Loading disassembly" />;
  else if (entry.state === "error") body = <ErrorNote error={entry.error} />;
  else body = <CodeBlock text={entry.data.disasm} title={format} />;

  return (
    <Panel
      title="Disassembly"
      subtitle="Read from the target binary through the engine."
      actions={
        <Toolbar>
          {toggle}
          <Field label="Format">
            <select value={format} onChange={(event) => setFormat(toDisasmFormat(event.target.value))}>
              {DISASM_FORMATS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </Field>
          <Button
            pending={busy}
            onClick={() => {
              setBusy(true);
              refreshPanel(key, () => loader().finally(() => setBusy(false)));
            }}
          >
            Reload
          </Button>
        </Toolbar>
      }
    >
      {body}
    </Panel>
  );
}

/** The Disassembly / Control flow toggle both code panels carry. */
function CodeViewToggle({
  view,
  onChange,
}: {
  view: FunctionCodeView;
  onChange: (view: FunctionCodeView) => void;
}): ReactNode {
  return (
    <div className="code-view-toggle" role="group" aria-label="Function code view">
      {FUNCTION_CODE_VIEWS.map((option) => (
        <button
          key={option}
          type="button"
          className={option === view ? "btn btn-primary" : "btn"}
          aria-pressed={option === view}
          onClick={() => onChange(option)}
        >
          {FUNCTION_CODE_VIEW_LABELS[option]}
        </button>
      ))}
    </div>
  );
}

/** A function's code views, one at a time: the disassembly listing, or the
 *  basic-block control-flow graph.  The hosted portal shows the same pair. */
export function CodeSection({ functionId }: { functionId: number }): ReactNode {
  const [view, setView] = useState<FunctionCodeView>(DEFAULT_FUNCTION_CODE_VIEW);
  const toggle = <CodeViewToggle view={view} onChange={setView} />;
  // The hosted portal's `Space` toggles Disassembly and Control Flow; the
  // switch is published while this section is mounted and dropped when it
  // unmounts, so the binding never acts on a view that is not showing one.
  // The handler lives in `codeViewSwitch.ts` so App can bind Space without
  // importing this module into the entry bundle.
  useEffect(() => {
    setCodeViewSwitch(() =>
      setView((current) => (current === "cfg" ? "disassembly" : "cfg")),
    );
    return () => {
      setCodeViewSwitch(null);
    };
  }, []);
  return view === "cfg" ? (
    <CfgPanel functionId={functionId} toggle={toggle} />
  ) : (
    <DisasmPanel functionId={functionId} toggle={toggle} />
  );
}

export function DecompilationPanel({ functionId }: { functionId: number }): ReactNode {
  const [backend, setBackend] = useState<string>(DEFAULT_DECOMPILER_BACKEND);
  const [busy, setBusy] = useState(false);
  const key = decompilationKey(functionId, backend);
  const loader = (): Promise<DecompilationResult> => loadDecompilation(functionId, backend);
  const entry = usePanel(key, loader);

  let body: ReactNode;
  if (!entry || entry.state === "loading") body = <Loading label="Loading decompilation" />;
  else if (entry.state === "error") body = <ErrorNote error={entry.error} />;
  else
    body = (
      <>
        <Muted>backend: {entry.data.backend || backend}</Muted>
        <CodeBlock text={entry.data.code} title={backend} />
      </>
    );

  return (
    <Panel
      title="Decompilation"
      subtitle="Stored decompilation, or one computed through the decompiler backends."
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
          <Button
            tone="primary"
            pending={busy}
            onClick={() => {
              setBusy(true);
              refreshPanel(key, () =>
                api<DecompilationResult>(`/functions/${functionId}/decompilation`, {
                  method: "POST",
                  json: { backend },
                }).finally(() => setBusy(false)),
              );
            }}
          >
            {entry?.state === "ready" ? "Recompute" : "Decompile"}
          </Button>
        </Toolbar>
      }
    >
      {body}
    </Panel>
  );
}

interface ReferencesData {
  result: FunctionReferences;
  functionsByVa: Map<number, FunctionRow>;
}

const REFERENCES_HINT =
  "Load references to see the data this function touches and the calls into and out of it.";

/** One lazy load shared by the Globals, Callers and Callees panels. */
function useReferences(functionId: number, binaryId: number): {
  entry: PanelEntry<ReferencesData> | undefined;
  load: () => void;
  busy: boolean;
} {
  const key = panelKey("fn", functionId, "references");
  const [entry, run] = useLazyPanel<ReferencesData>(key);
  const [busy, setBusy] = useState(false);
  const loader = async (): Promise<ReferencesData> => {
    const functionsByVa = await api<{ functions: FunctionRow[] }>(
      `/binaries/${binaryId}/functions`,
    ).then(
      (data) => new Map<number, FunctionRow>(data.functions.map((row) => [row.va, row])),
      () => new Map<number, FunctionRow>(),
    );
    const result = await api<FunctionReferences>(`/functions/${functionId}/references`);
    return { result, functionsByVa };
  };
  return {
    entry,
    busy,
    load: () => {
      setBusy(true);
      run(() => loader().finally(() => setBusy(false)));
    },
  };
}

function ReferencesAction({ busy, loaded, load }: { busy: boolean; loaded: boolean; load: () => void }): ReactNode {
  return (
    <Button pending={busy} onClick={load}>
      {loaded ? "Reload references" : "Load references"}
    </Button>
  );
}

/** The Globals table: the data addresses the function reads, writes or loads. */
function GlobalsPanel({
  functionId,
  binaryId,
}: {
  functionId: number;
  binaryId: number;
}): ReactNode {
  const { entry, load, busy } = useReferences(functionId, binaryId);
  const data = entry?.state === "ready" ? entry.data : undefined;
  return (
    <Panel
      title={
        <>
          Globals{" "}
          <Badge>{data === undefined ? NA : String(data.result.counts.globals)}</Badge>
        </>
      }
      subtitle="Data addresses the disassembly references; a read or a write only when the instruction makes it clear."
      actions={<ReferencesAction busy={busy} loaded={data !== undefined} load={load} />}
    >
      <PanelBody entry={entry} hint="Loading globals">
        {(loaded) =>
          loaded.result.globals.length === 0 ? (
            <EmptyState>No data references resolved for this function.</EmptyState>
          ) : (
            <DataTable
              columns={[
                {
                  label: "Address",
                  mono: true,
                  render: (row) => (
                    <>
                      <a href={`#/binaries/${binaryId}?memory=${hex(row.address)}`}>
                        {hex(row.address)}
                      </a>
                      <CopyValue value={hex(row.address)} />
                    </>
                  ),
                },
                { label: "Section", mono: true, render: (row) => row.section ?? NA },
                {
                  label: "Access",
                  render: (row) =>
                    row.access === null ? (
                      <span className="muted" title={`Instruction kind ${row.kind} is not a clear read or write`}>
                        {NA}
                      </span>
                    ) : (
                      <Badge tone={row.access === "write" ? "warn" : "info"}>{row.access}</Badge>
                    ),
                },
                { label: "Kind", mono: true, render: (row) => row.kind },
                {
                  label: "Functions",
                  render: (row) => (
                    <a href={`#/binaries/${binaryId}/functions?refers_to=${hex(row.address)}`}>
                      Filter functions
                    </a>
                  ),
                },
              ]}
              rows={loaded.result.globals}
              rowKey={(row, index) => `${row.address}-${row.kind}-${index}`}
            />
          )
        }
      </PanelBody>
      <Muted>{REFERENCES_HINT}</Muted>
    </Panel>
  );
}

/** The Callers table: one row per call site into the function. */
function CallersPanel({
  functionId,
  binaryId,
}: {
  functionId: number;
  binaryId: number;
}): ReactNode {
  const { entry, load, busy } = useReferences(functionId, binaryId);
  const data = entry?.state === "ready" ? entry.data : undefined;
  return (
    <Panel
      title={
        <>
          Callers{" "}
          <Badge>{data === undefined ? NA : String(data.result.counts.callers)}</Badge>
        </>
      }
      subtitle="Call sites into this function; each names the function it sits in."
      actions={<ReferencesAction busy={busy} loaded={data !== undefined} load={load} />}
    >
      <PanelBody entry={entry} hint="Loading callers">
        {(loaded) =>
          loaded.result.callers.length === 0 ? (
            <EmptyState>No callers resolved for this function.</EmptyState>
          ) : (
            <DataTable
              columns={[
                {
                  label: "From VA",
                  mono: true,
                  render: (row) => fromVaLink(loaded.functionsByVa, row.from_va),
                },
                {
                  label: "Name",
                  render: (row) => functionNameLink(loaded.functionsByVa, row.from_va, row.name),
                },
              ]}
              rows={loaded.result.callers}
              rowKey={(row) => row.from_va}
            />
          )
        }
      </PanelBody>
      <Muted>{data?.result.count_note ?? REFERENCES_HINT}</Muted>
    </Panel>
  );
}

/** The Callees table: the calls the function makes, indirect ones included. */
export function CalleesPanel({
  functionId,
  binaryId,
}: {
  functionId: number;
  binaryId: number;
}): ReactNode {
  const { entry, load, busy } = useReferences(functionId, binaryId);
  const data = entry?.state === "ready" ? entry.data : undefined;
  return (
    <Panel
      title={
        <>
          Callees{" "}
          <Badge>{data === undefined ? NA : String(data.result.counts.callees)}</Badge>
        </>
      }
      subtitle="Calls this function makes; an import-slot call stays a row saying it is indirect."
      actions={<ReferencesAction busy={busy} loaded={data !== undefined} load={load} />}
    >
      <PanelBody entry={entry} hint="Loading callees">
        {(loaded) =>
          loaded.result.callees.length === 0 ? (
            <EmptyState>No callees resolved for this function.</EmptyState>
          ) : (
            <DataTable
              columns={[
                {
                  label: "Target",
                  mono: true,
                  render: (row) => {
                    const target = loaded.functionsByVa.get(row.to_va);
                    return target === undefined ? (
                      hex(row.to_va)
                    ) : (
                      <a href={`#/functions/${target.id}`}>{hex(row.to_va)}</a>
                    );
                  },
                },
                {
                  label: "Name",
                  render: (row) => {
                    if (row.name !== null) {
                      return functionNameLink(loaded.functionsByVa, row.to_va, row.name);
                    }
                    return row.indirect ? (
                      <Badge tone="info">indirect</Badge>
                    ) : (
                      <span className="muted">{NA}</span>
                    );
                  },
                },
                { label: "Kind", mono: true, render: (row) => row.kind },
              ]}
              rows={loaded.result.callees}
              rowKey={(row) => `${row.to_va}-${row.kind}`}
            />
          )
        }
      </PanelBody>
      <Muted>{data?.result.count_note ?? REFERENCES_HINT}</Muted>
    </Panel>
  );
}

/** The reference tables of one function: three share one stored dossier fetch, the cross-references panel runs the engine's own scan on demand. */
export function ReferencesSection({
  functionId,
  binaryId,
}: {
  functionId: number;
  binaryId: number;
}): ReactNode {
  return (
    <>
      <GlobalsPanel functionId={functionId} binaryId={binaryId} />
      <CallersPanel functionId={functionId} binaryId={binaryId} />
      <CalleesPanel functionId={functionId} binaryId={binaryId} />
      <XrefsPanel functionId={functionId} />
    </>
  );
}

/** The engine's own scan of the instructions that point at one address. */
function XrefsPanel({ functionId }: { functionId: number }): ReactNode {
  const key = panelKey("fn", functionId, "xrefs");
  const [entry, run] = useLazyPanel<Xrefs>(key);
  const [busy, setBusy] = useState(false);
  const load = (): void => {
    setBusy(true);
    run(() => api<Xrefs>(`/functions/${functionId}/xrefs`).finally(() => setBusy(false)));
  };
  const data = entry?.state === "ready" ? entry.data : undefined;
  return (
    <Panel
      title={
        <>
          Cross-references <Badge>{data === undefined ? NA : String(data.count)}</Badge>
        </>
      }
      subtitle="Load cross-references to scan the binary for the instructions that point at this address."
      actions={
        <Button pending={busy} onClick={load}>
          {data === undefined ? "Load cross-references" : "Reload cross-references"}
        </Button>
      }
    >
      <PanelBody entry={entry} hint="Loading cross-references">
        {(payload) =>
          payload.refs.length === 0 ? (
            <EmptyState>
              No instruction in the binary references 0x{payload.target.toString(16)}.
            </EmptyState>
          ) : (
            <>
              <table className="table" aria-label="Cross references">
                <thead>
                  <tr>
                    <th>From</th>
                    <th>Kind</th>
                    <th>Instruction</th>
                  </tr>
                </thead>
                <tbody>
                  {payload.refs.map((ref) => (
                    <tr key={`${ref.from_va}:${ref.kind}`}>
                      <td className="mono">{hex(ref.from_va)}</td>
                      <td>
                        <Badge mono>{ref.kind}</Badge>
                      </td>
                      <td className="mono">{ref.instruction ?? ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {payload.import_name === null ? null : (
                <Muted>The target is the import slot {payload.import_name}.</Muted>
              )}
            </>
          )
        }
      </PanelBody>
    </Panel>
  );
}

function functionAtVa(
  functionsByVa: Map<number, FunctionRow>,
  va: number,
): FunctionRow | undefined {
  const exact = functionsByVa.get(va);
  if (exact !== undefined) return exact;
  let best: FunctionRow | undefined;
  for (const fn of functionsByVa.values()) {
    if (va < fn.va || va >= fn.va + fn.size) continue;
    if (best === undefined || fn.va > best.va) best = fn;
  }
  return best;
}

function fromVaLink(functionsByVa: Map<number, FunctionRow>, va: number): ReactNode {
  const fn = functionAtVa(functionsByVa, va);
  if (fn === undefined) return hex(va);
  return <a href={`#/functions/${fn.id}`}>{hex(va)}</a>;
}

function functionNameLink(
  functionsByVa: Map<number, FunctionRow>,
  va: number,
  name: string | null,
): ReactNode {
  const fn = functionAtVa(functionsByVa, va);
  const label = name ?? fn?.name ?? "";
  if (fn === undefined) {
    return label === "" ? <span className="muted">{NA}</span> : label;
  }
  return <a href={`#/functions/${fn.id}`}>{label || `#${fn.id}`}</a>;
}

export function MatchesPanel({
  functionId,
  onMutated,
}: {
  functionId: number;
  onMutated: () => void;
}): ReactNode {
  const key = panelKey("fn", functionId, "matches");
  const loader = (): Promise<{ matches: MatchRow[] }> =>
    api<{ matches: MatchRow[] }>(`/functions/${functionId}/matches`);
  const entry = usePanel(key, loader);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(0);
  const [modes, setModes] = useState<Record<number, TransferMode>>({});
  const [reports, setReports] = useState<Record<number, string>>({});

  const apply = async (row: MatchRow): Promise<void> => {
    setActionError(null);
    setBusy(row.id);
    try {
      const report = await api<TransferRowReport>(`/functions/${functionId}/apply-match`, {
        method: "POST",
        json: {
          candidate_function_id: row.candidate_function_id,
          mode: modes[row.id] ?? DEFAULT_TRANSFER_MODE,
          actor: "spa",
        },
      });
      const missing = report.missing_types.length
        ? ` (missing types: ${report.missing_types.join(", ")})`
        : "";
      setReports((current) => ({ ...current, [row.id]: `${report.status}${missing}` }));
      refreshPanel(key, loader);
      onMutated();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(0);
    }
  };

  return (
    <Panel
      title="Matches"
      subtitle="Candidates recorded for this function, newest first."
      actions={
        <a className="btn btn-ghost" href={`#/matches?function=${functionId}`}>
          View function matching
        </a>
      }
    >
      {actionError ? <ErrorNote error={actionError} /> : null}
      <PanelBody entry={entry} hint="Loading matches">
        {(data) => (
          <DataTable
            columns={[
              {
                label: "Candidate",
                render: (row) => (
                  <a href={`#/functions/${row.candidate_function_id}`}>#{row.candidate_function_id}</a>
                ),
              },
              { label: "VA", mono: true, render: (row) => hex(row.candidate_va) },
              { label: "Name", key: "candidate_name" },
              {
                label: "Signature",
                render: (row) =>
                  row.candidate_prototype ? (
                    <code className="mono">{row.candidate_prototype}</code>
                  ) : (
                    NA
                  ),
              },
              { label: "Status", render: (row) => <StatusCell status={row.candidate_status} /> },
              {
                label: "Similarity",
                numeric: true,
                render: (row) => Number(row.similarity).toFixed(3),
              },
              {
                label: "Confidence",
                numeric: true,
                render: (row) => Number(row.confidence).toFixed(3),
              },
              {
                label: "Arch",
                render: (row) =>
                  row.source_arch || row.candidate_arch ? (
                    <Badge hue={row.cross_arch ? "near" : undefined}>
                      {row.source_arch || NA} / {row.candidate_arch || NA}
                    </Badge>
                  ) : (
                    NA
                  ),
              },
              {
                label: "Transfer",
                render: (row) => (
                  <div className="actions-cell">
                    <select
                      aria-label={`Transfer mode for candidate ${row.candidate_function_id}`}
                      value={modes[row.id] ?? DEFAULT_TRANSFER_MODE}
                      onChange={(event) =>
                        setModes((current) => ({
                          ...current,
                          [row.id]: event.target.value as TransferMode,
                        }))
                      }
                    >
                      {TRANSFER_MODES.map((mode) => (
                        <option key={mode} value={mode}>
                          {TRANSFER_MODE_LABELS[mode]}
                        </option>
                      ))}
                    </select>
                    <Button size="sm" pending={busy === row.id} onClick={() => void apply(row)}>
                      Apply
                    </Button>
                    <a
                      className="btn btn-sm btn-ghost"
                      href={`#/diff/${functionId}/${row.candidate_function_id}`}
                    >
                      Compare
                    </a>
                    {reports[row.id] ? <span className="muted">{reports[row.id]}</span> : null}
                  </div>
                ),
              },
            ]}
            rows={data.matches}
            rowKey={(row) => row.id}
            empty={<EmptyState>No matches recorded for this function.</EmptyState>}
          />
        )}
      </PanelBody>
    </Panel>
  );
}

export function HistoryPanel({
  functionId,
  onMutated,
}: {
  functionId: number;
  onMutated: () => void;
}): ReactNode {
  const key = historyKey(functionId);
  const loader = (): Promise<{ history: HistoryRow[] }> => loadHistory(functionId);
  const entry = usePanel(key, loader);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(0);

  const revert = async (row: HistoryRow): Promise<void> => {
    setActionError(null);
    setBusy(row.id);
    try {
      await api(`/functions/${functionId}/history/${row.id}/revert`, { method: "POST" });
      refreshPanel(key, loader);
      onMutated();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(0);
    }
  };

  return (
    <Panel title="History" subtitle="Renames applied to this function, newest first.">
      {actionError ? <ErrorNote error={actionError} /> : null}
      <PanelBody entry={entry} hint="Loading rename history">
        {(data) => (
          <DataTable
            columns={[
              { label: "When", key: "created_at", mono: true },
              { label: "Old", key: "old_name", mono: true },
              { label: "New", key: "new_name", mono: true },
              { label: "Actor", key: "actor" },
              { label: "Source", key: "source" },
              {
                label: "Actions",
                render: (row) => (
                  <div className="actions-cell">
                    <ConfirmButton
                      label="Revert"
                      message="Revert rename?"
                      pending={busy === row.id}
                      onConfirm={() => void revert(row)}
                    />
                  </div>
                ),
              },
            ]}
            rows={data.history}
            rowKey={(row) => row.id}
            empty={<EmptyState>No renames recorded for this function.</EmptyState>}
          />
        )}
      </PanelBody>
    </Panel>
  );
}

// ── AI artifacts ───────────────────────────────────────────────────

/** One AI artifact panel: stored-only auto-load, generate button, model shown. */
function AiArtifactPanel<T>({
  functionId,
  kind,
  title,
  subtitle,
  loading,
  absentHint,
  ready,
}: {
  functionId: number;
  kind: AiArtifactKind;
  title: string;
  subtitle: string;
  loading: string;
  absentHint: string;
  ready: (payload: T, artifact: AiArtifact<T>) => ReactNode;
}): ReactNode {
  const key = panelKey("fn", functionId, "ai", kind);
  const path = AI_ARTIFACT_PATHS[kind];
  const loader = (): Promise<AiArtifact<T>> =>
    api<AiArtifact<T>>(`/functions/${functionId}/${path}`);
  const entry = usePanel(key, loader);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const generate = async (): Promise<void> => {
    setActionError(null);
    setBusy(true);
    try {
      await api<AiArtifact<T>>(`/functions/${functionId}/${path}`, { method: "POST" });
      refreshPanel(key, loader);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(false);
    }
  };

  const discard = async (): Promise<void> => {
    setActionError(null);
    setBusy(true);
    try {
      await api(`/functions/${functionId}/${path}`, { method: "DELETE" });
      refreshPanel(key, loader);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(false);
    }
  };

  let body: ReactNode;
  if (!entry || entry.state === "loading") body = <Loading label={loading} />;
  else if (entry.state === "error") {
    body = isApiErrorCode(entry.error, AI_NO_ARTIFACT) ? (
      <EmptyState>{absentHint}</EmptyState>
    ) : (
      <ErrorNote error={entry.error} />
    );
  } else body = ready(entry.data.payload, entry.data);

  return (
    <Panel
      title={title}
      subtitle={subtitle}
      actions={
        <>
          <Button tone="primary" pending={busy} onClick={() => void generate()}>
            {entry?.state === "ready" ? "Regenerate" : "Generate"}
          </Button>
          {entry?.state === "ready" ? (
            <ConfirmButton
              label="Discard"
              message="Discard this stored artifact?"
              pending={busy}
              onConfirm={() => void discard()}
            />
          ) : null}
        </>
      }
    >
      {actionError ? <ErrorNote error={actionError} /> : null}
      {body}
    </Panel>
  );
}

function AiSummaryPanel({ functionId }: { functionId: number }): ReactNode {
  return (
    <AiArtifactPanel<AiSummaryPayload>
      functionId={functionId}
      kind="summary"
      title="Summary"
      subtitle="A short model-written description of what this function does."
      loading="Loading the AI summary"
      absentHint="No AI summary stored for this function. Generate one to have a model describe it."
      ready={(payload, artifact) => (
        <>
          <EngineNote model={artifact.model} />
          <p>{payload.summary}</p>
        </>
      )}
    />
  );
}

function AiCommentsPanel({ functionId }: { functionId: number }): ReactNode {
  return (
    <AiArtifactPanel<AiCommentsPayload>
      functionId={functionId}
      kind="comments"
      title="AI comments"
      subtitle="Inline comments a model proposed for the decompilation."
      loading="Loading the AI comments"
      absentHint="No AI comments stored for this function. Generate them from the stored decompilation."
      ready={(payload, artifact) => {
        const comments = Array.isArray(payload.comments) ? payload.comments : [];
        if (!comments.length) return <Muted>No inline comments.</Muted>;
        return (
          <>
            <EngineNote model={artifact.model} />
            <DataTable
              columns={[
                { label: "Line", numeric: true, render: (row) => String(row.line) },
                { label: "Comment", key: "comment" },
              ]}
              rows={comments}
              rowKey={(_row, index) => index}
            />
          </>
        );
      }}
    />
  );
}

function AiTypeSuggestionsPanel({ functionId }: { functionId: number }): ReactNode {
  return (
    <AiArtifactPanel<AiTypeSuggestionsPayload>
      functionId={functionId}
      kind="type-suggestions"
      title="Type suggestions"
      subtitle="Types a model proposed for the local variables."
      loading="Loading the type suggestions"
      absentHint="No type suggestions stored for this function. Generate them from the stored decompilation."
      ready={(payload, artifact) => {
        const suggestions = Array.isArray(payload.suggestions) ? payload.suggestions : [];
        if (!suggestions.length) return <Muted>No type suggestions.</Muted>;
        return (
          <>
            <EngineNote model={artifact.model} />
            <DataTable
              columns={[
                { label: "Name", key: "name", mono: true },
                { label: "Kind", key: "kind" },
                { label: "Type", mono: true, key: "type" },
                {
                  label: "Confidence",
                  numeric: true,
                  render: (row) => Number(row.confidence).toFixed(2),
                },
              ]}
              rows={suggestions}
              rowKey={(_row, index) => index}
            />
          </>
        );
      }}
    />
  );
}

/** Stored identifier renames of one function, with apply and revert controls. */
function AiRenamesPanel({
  functionId,
  onMutated,
}: {
  functionId: number;
  onMutated: () => void;
}): ReactNode {
  const key = panelKey("fn", functionId, "ai", "renames");
  const loader = (): Promise<AiArtifact<RenamesPayload>> =>
    api<AiArtifact<RenamesPayload>>(`/functions/${functionId}/renames`);
  const entry = usePanel(key, loader);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [renameFunction, setRenameFunction] = useState(true);
  const [actionError, setActionError] = useState<unknown>(null);
  const [note, setNote] = useState("");
  const [noteWarn, setNoteWarn] = useState(false);
  const [busy, setBusy] = useState("");

  const suggestions: RenameSuggestion[] =
    entry?.state === "ready" && Array.isArray(entry.data.payload.suggestions)
      ? entry.data.payload.suggestions
      : [];

  const toggle = (from: string): void => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(from)) next.delete(from);
      else next.add(from);
      return next;
    });
  };

  const suggest = async (): Promise<void> => {
    setActionError(null);
    setNote("");
    setBusy("suggest");
    try {
      await api(`/functions/${functionId}/renames`, { method: "POST" });
      refreshPanel(key, loader);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const apply = async (all: boolean): Promise<void> => {
    setActionError(null);
    setNote("");
    setNoteWarn(false);
    const chosen = suggestions.filter((suggestion) => selected.has(suggestion.from));
    if (!all && !chosen.length) {
      setNoteWarn(true);
      setNote("Select at least one suggestion.");
      return;
    }
    setBusy(all ? "apply-all" : "apply");
    try {
      const result = await api<RenamesApplyResult>(`/functions/${functionId}/renames/apply`, {
        method: "POST",
        json: { applied: all ? undefined : chosen, rename_function: renameFunction },
      });
      setNote(`${result.applied.length} applied, ${result.skipped.length} skipped.`);
      refreshDecompilation(functionId);
      onMutated();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const revert = async (): Promise<void> => {
    setActionError(null);
    setNote("");
    setBusy("revert");
    try {
      await api(`/functions/${functionId}/renames/revert`, { method: "POST" });
      setNote("Restored the previous decompilation.");
      refreshDecompilation(functionId);
      onMutated();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  let body: ReactNode;
  if (!entry || entry.state === "loading") body = <Loading label="Loading rename suggestions" />;
  else if (entry.state === "error") {
    body = isApiErrorCode(entry.error, AI_NO_ARTIFACT) ? (
      <EmptyState>
        No rename suggestions stored for this function. Suggest them to have a model propose names.
      </EmptyState>
    ) : (
      <ErrorNote error={entry.error} />
    );
  } else if (!suggestions.length) body = <Muted>No rename suggestions.</Muted>;
  else {
    body = (
      <>
        <EngineNote model={entry.data.model} />
        <DataTable
          columns={[
            {
              label: "",
              render: (row) => (
                <input
                  type="checkbox"
                  aria-label={`select ${row.from}`}
                  checked={selected.has(row.from)}
                  onChange={() => toggle(row.from)}
                />
              ),
            },
            { label: "From", mono: true, key: "from" },
            { label: "To", mono: true, key: "to" },
            { label: "Kind", key: "kind" },
            {
              label: "Confidence",
              numeric: true,
              render: (row) => Number(row.confidence).toFixed(2),
            },
            { label: "Reason", key: "reason" },
          ]}
          rows={suggestions}
          rowKey={(row) => row.from}
        />
      </>
    );
  }

  return (
    <Panel
      title="Renames"
      subtitle="Model-proposed identifiers; applying rewrites the stored decompilation."
      actions={
        <>
          <Button pending={busy === "suggest"} onClick={() => void suggest()}>
            {entry?.state === "ready" ? "Re-suggest" : "Suggest"}
          </Button>
          <Button tone="primary" pending={busy === "apply"} onClick={() => void apply(false)}>
            Apply selected
          </Button>
          <Button pending={busy === "apply-all"} onClick={() => void apply(true)}>
            Apply all
          </Button>
          <ConfirmButton
            label="Revert"
            message="Restore decompilation?"
            pending={busy === "revert"}
            onConfirm={() => void revert()}
          />
          <CheckboxField
            label="rename function"
            checked={renameFunction}
            onChange={setRenameFunction}
          />
        </>
      }
    >
      {actionError ? <ErrorNote error={actionError} /> : null}
      {note ? <Note tone={noteWarn ? "warn" : "info"}>{note}</Note> : null}
      {body}
    </Panel>
  );
}

/** One row of the rewrite table: a line, its origin and the comment stored on it. */
interface AiCodeRow {
  line: number;
  text: string;
  origin: string;
  comment: string;
}

/** One stored AI decompilation: the rewrite, its token overrides and the analyst's feedback. */
function AiDecompilationPanel({ functionId }: { functionId: number }): ReactNode {
  const key = panelKey("fn", functionId, "ai", "ai-decompilation");
  const loader = (): Promise<AiDecompilation> =>
    api<AiDecompilation>(`/functions/${functionId}/ai-decompilation`);
  const entry = usePanel(key, loader);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [note, setNote] = useState("");
  const [ratingNote, setRatingNote] = useState("");
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [openLine, setOpenLine] = useState<number | null>(null);
  const [commentDraft, setCommentDraft] = useState("");

  const data = entry?.state === "ready" ? entry.data : undefined;

  const run = async (
    busyKey: string,
    message: string,
    action: () => Promise<unknown>,
  ): Promise<void> => {
    setActionError(null);
    setNote("");
    setBusy(busyKey);
    try {
      await action();
      refreshPanel(key, loader);
      setNote(message);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const generate = (): Promise<void> =>
    run("generate", "Rewrite stored.", () =>
      api(`/functions/${functionId}/ai-decompilation`, { method: "POST" }),
    );

  const discard = (): Promise<void> =>
    run("discard", "Rewrite discarded.", () =>
      api(`/functions/${functionId}/ai-decompilation`, { method: "DELETE" }),
    );

  const setOverride = (token: string, name: string | null): Promise<void> =>
    run(`override:${token}`, name === null ? `Override cleared for ${token}.` : `Override set for ${token}.`, () =>
      api(`/functions/${functionId}/ai-decompilation/overrides`, {
        method: "PATCH",
        json: { overrides: { [token]: name } },
      }),
    );

  const rate = (rating: string | null): Promise<void> =>
    run(`rate:${rating ?? "clear"}`, "Rating stored.", () =>
      api(`/functions/${functionId}/ai-decompilation/rating`, {
        method: "PATCH",
        json: { rating, note: ratingNote },
      }),
    );

  const saveComment = (line: number): Promise<void> =>
    run(`comment:${line}`, `Comment saved on line ${line}.`, () =>
      api(`/functions/${functionId}/ai-decompilation/inline-comments`, {
        method: "POST",
        json: { line, body: commentDraft },
      }),
    );

  const removeComment = (line: number): Promise<void> =>
    run(`drop:${line}`, `Comment removed from line ${line}.`, () =>
      api(`/functions/${functionId}/ai-decompilation/inline-comments/${line}`, {
        method: "DELETE",
      }),
    );

  let body: ReactNode;
  if (!entry || entry.state === "loading") body = <Loading label="Loading the AI decompilation" />;
  else if (entry.state === "error") {
    body = isApiErrorCode(entry.error, AI_NO_ARTIFACT) ? (
      <EmptyState>
        No AI decompilation stored for this function. Generate one to have a model rewrite the
        stored decompilation and name its placeholders.
      </EmptyState>
    ) : (
      <ErrorNote error={entry.error} />
    );
  } else if (!data) body = <Muted>No AI decompilation stored.</Muted>;
  else {
    const lines = data.code.split("\n");
    const originByLine = new Map(data.attributions.map((row) => [row.line, row.origin]));
    const commentByLine = new Map(data.line_comments.map((row) => [row.line, row]));
    body = (
      <>
        <>
          <EngineNote model={data.model} />
          <Muted>
            {lines.length} lines, {data.tokens.length} placeholder tokens,{" "}
            {data.line_comments.length} line comments
          </Muted>
        </>
        <p className="muted">{data.derivation}</p>
        <Toolbar>
          <Field label="Rating">
            <select
              value={data.rating ?? ""}
              onChange={(event) => void rate(event.target.value || null)}
              disabled={busy !== ""}
            >
              <option value="">unrated</option>
              <option value="up">up</option>
              <option value="down">down</option>
            </select>
          </Field>
          <Field label="Rating note">
            <input
              type="text"
              value={ratingNote}
              placeholder={data.rating_note}
              onChange={(event) => setRatingNote(event.target.value)}
            />
          </Field>
        </Toolbar>
        <DataTable<AiCodeRow>
          columns={[
            { label: "Line", numeric: true, mono: true, render: (row) => String(row.line) },
            {
              label: "Origin",
              render: (row) => (
                <Badge tone={row.origin === "added" ? "warn" : "neutral"}>{row.origin}</Badge>
              ),
            },
            { label: "Code", mono: true, render: (row) => row.text },
            {
              label: "Comment",
              render: (row) => (commentByLine.has(row.line) ? row.comment : ""),
            },
          ]}
          rows={lines.map((text, index) => ({
            line: index + 1,
            text,
            origin: originByLine.get(index + 1) ?? "modified",
            comment: commentByLine.get(index + 1)?.body ?? "",
          }))}
          rowKey={(row) => row.line}
          onRowClick={(row) => {
            setOpenLine(row.line);
            setCommentDraft(commentByLine.get(row.line)?.body ?? "");
          }}
        />
        {openLine === null ? (
          <Muted>Select a line to add or edit its inline comment.</Muted>
        ) : (
          <Toolbar>
            <Field label={`Comment on line ${openLine}`}>
              <input
                type="text"
                value={commentDraft}
                onChange={(event) => setCommentDraft(event.target.value)}
              />
            </Field>
            <Button tone="primary" pending={busy === `comment:${openLine}`} onClick={() => void saveComment(openLine)}>
              Save
            </Button>
            {commentByLine.has(openLine) ? (
              <ConfirmButton
                label="Remove"
                message={`Remove comment on line ${openLine}?`}
                pending={busy === `drop:${openLine}`}
                onConfirm={() => void removeComment(openLine)}
              />
            ) : null}
          </Toolbar>
        )}
        {data.tokens.length ? (
          <DataTable<AiDecompilationToken>
            columns={[
              { label: "Token", mono: true, key: "token" },
              { label: "Kind", key: "kind" },
              { label: "Uses", numeric: true, render: (row) => String(row.count) },
              {
                label: "Lines",
                render: (row) => row.lines.join(", "),
              },
              {
                label: "Override",
                render: (row) => (
                  <>
                    <input
                      type="text"
                      aria-label={`override for ${row.token}`}
                      value={drafts[row.token] ?? row.name ?? ""}
                      onChange={(event) =>
                        setDrafts((current) => ({ ...current, [row.token]: event.target.value }))
                      }
                    />
                    <Button
                      size="sm"
                      pending={busy === `override:${row.token}`}
                      onClick={() =>
                        void setOverride(row.token, drafts[row.token] ?? row.name ?? "")
                      }
                    >
                      Set
                    </Button>
                    {row.name ? (
                      <Button size="sm" onClick={() => void setOverride(row.token, null)}>
                        Clear
                      </Button>
                    ) : null}
                  </>
                ),
              },
            ]}
            rows={data.tokens}
            rowKey={(row) => row.token}
          />
        ) : (
          <Muted>The rewrite carries no placeholder tokens.</Muted>
        )}
      </>
    );
  }

  return (
    <Panel
      title="AI decompilation"
      subtitle="A whole-function rewrite, the placeholders it still carries and the overrides that name them."
      actions={
        <>
          <Button tone="primary" pending={busy === "generate"} onClick={() => void generate()}>
            {entry?.state === "ready" ? "Rewrite again" : "Rewrite"}
          </Button>
          {entry?.state === "ready" ? (
            <ConfirmButton
              label="Discard"
              message="Discard the stored rewrite, its overrides, comments and rating?"
              pending={busy === "discard"}
              onConfirm={() => void discard()}
            />
          ) : null}
        </>
      }
    >
      {actionError ? <ErrorNote error={actionError} /> : null}
      {note ? <Note>{note}</Note> : null}
      {body}
    </Panel>
  );
}

/** The AI extras of one function, grouped under a section heading. */
export function AiSection({
  functionId,
  onMutated,
}: {
  functionId: number;
  onMutated: () => void;
}): ReactNode {
  return (
    <section>
      <h3>AI</h3>
      <AiDecompilationPanel functionId={functionId} />
      <AiSummaryPanel functionId={functionId} />
      <AiCommentsPanel functionId={functionId} />
      <AiTypeSuggestionsPanel functionId={functionId} />
      <AiRenamesPanel functionId={functionId} onMutated={onMutated} />
    </section>
  );
}

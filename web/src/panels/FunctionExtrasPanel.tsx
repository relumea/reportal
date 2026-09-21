import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  ConfirmButton,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Muted,
  Panel,
  PanelBody,
  Toolbar,
} from "../components";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import type {
  AnalysisStrings,
  AnalystString,
  FunctionCapabilities,
  FunctionCallees,
  FunctionStrings,
  IndirectCallSites,
} from "../types";

const EDGE_KINDS = ["call", "indirect"] as const;
const STRING_KINDS = ["string", "import", "export"] as const;

function siteLabel(site: { line: number; instruction: string }): string {
  return `${site.line}: ${site.instruction}`;
}

/** The analyst rows of a scope's read, whichever scope it is. */
function analystRows(data: FunctionStrings | AnalysisStrings): AnalystString[] {
  return "analyst" in data ? data.analyst : data.strings;
}

/** One row of an analyst string list, with its remove control. */
function StringRow({
  entry,
  onRemove,
  pending,
}: {
  entry: AnalystString;
  onRemove: () => void;
  pending: boolean;
}): ReactNode {
  return (
    <tr>
      <td className="mono">{entry.value}</td>
      <td>
        <Badge mono>{entry.kind}</Badge>
      </td>
      <td className="muted">{entry.note}</td>
      <td className="muted">{entry.actor || "n/a"}</td>
      <td>
        <ConfirmButton
          label="Remove"
          message="Remove this string?"
          pending={pending}
          onConfirm={onRemove}
        />
      </td>
    </tr>
  );
}

/**
 * A scope's analyst strings: the list, an add form and a remove control.
 *
 * The read the panel uses is the scope's own route, so the same panel serves a
 * function and an analysis and the two cannot drift.
 */
function StringsSection({
  path,
  key,
  load,
  derived,
  decoded,
  note,
  limit,
}: {
  path: string;
  key: string;
  load: () => Promise<FunctionStrings | AnalysisStrings>;
  derived?: Array<{ value: string; source: string }>;
  decoded?: Array<{ value: string; source: string }>;
  note?: string;
  limit: number;
}): ReactNode {
  const entry = usePanel<FunctionStrings | AnalysisStrings>(key, load);
  const [value, setValue] = useState("");
  const [kind, setKind] = useState<string>(STRING_KINDS[0]);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const rows: AnalystString[] = entry?.state === "ready" ? analystRows(entry.data) : [];

  const refresh = (): void => refreshPanel(key, load);

  const add = async (): Promise<void> => {
    setActionError(null);
    const body = value.trim();
    if (!body) return;
    setBusy("add");
    try {
      await api(path, { method: "POST", json: { value: body, kind } });
      setValue("");
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const remove = async (stringId: number): Promise<void> => {
    setActionError(null);
    setBusy(`remove-${stringId}`);
    try {
      await api(`${path}/${stringId}`, { method: "DELETE" });
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void add();
        }}
      >
        <Toolbar>
          <Field label="String">
            <input
              value={value}
              maxLength={limit}
              onChange={(event) => setValue(event.target.value)}
              placeholder="A literal the text misses, or a claim about one"
            />
          </Field>
          <Field label="Kind">
            <select value={kind} onChange={(event) => setKind(event.target.value)}>
              {STRING_KINDS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </Field>
          <Button tone="primary" type="submit" pending={busy === "add"}>
            Add string
          </Button>
        </Toolbar>
      </form>
      {actionError ? <ErrorNote error={actionError} /> : null}
      {!entry || entry.state === "loading" ? (
        <Loading label="Loading strings" />
      ) : entry.state === "error" ? (
        <ErrorNote error={entry.error} onRetry={refresh} />
      ) : (
        <>
          {rows.length === 0 ? (
            <EmptyState>No analyst strings recorded yet.</EmptyState>
          ) : (
            <table className="table" aria-label="Analyst strings">
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Kind</th>
                  <th>Note</th>
                  <th>Author</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <StringRow
                    key={row.id}
                    entry={row}
                    pending={busy === `remove-${row.id}`}
                    onRemove={() => void remove(row.id)}
                  />
                ))}
              </tbody>
            </table>
          )}
          {derived && derived.length > 0 ? (
            <>
              <Muted>The literals the stored decompilation carries; a text scan, not engine output.</Muted>
              <ul className="list">
                {derived.map((row) => (
                  <li key={row.value} className="mono">
                    {row.value}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
          {decoded && decoded.length > 0 ? (
            <>
              <Muted>
                Stack-built or single-byte-XOR strings recovered from the stored NASM listing.
              </Muted>
              <ul className="list">
                {decoded.map((row) => (
                  <li key={`${row.source}:${row.value}`} className="mono">
                    {row.value} <span className="muted">{row.source}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : null}
          {note ? <Muted>{note}</Muted> : null}
        </>
      )}
    </>
  );
}

/** The analyst strings of an analysis, with the whole-list replace box. */
export function AnalysisStringsPanel({ analysisId }: { analysisId: number }): ReactNode {
  const path = `/analyses/${analysisId}/strings`;
  const key = panelKey("analysis", analysisId, "strings");
  const load = (): Promise<AnalysisStrings> => api<AnalysisStrings>(path);
  const [draft, setDraft] = useState("");
  const [status, setStatus] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const replace = async (): Promise<void> => {
    setActionError(null);
    setStatus("");
    setBusy(true);
    try {
      const values = draft
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
      const report = await api<{ strings: AnalystString[] }>(path, {
        method: "PUT",
        json: { strings: values },
      });
      setStatus(`Stored ${report.strings.length} string(s).`);
      refreshPanel(key, load);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Analysis Strings"
      subtitle="The whole list at once, as the hosted portal stores it; a revert puts the previous list back."
    >
      <StringsSection path={path} key={key} load={load} limit={1024} />
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void replace();
        }}
      >
        <Field label="Replace the whole list">
          <textarea
            className="chat-input"
            aria-label="Replace the whole analysis string list"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            placeholder="One string per line"
          />
        </Field>
        <Toolbar>
          <Button tone="primary" type="submit" pending={busy}>
            Replace list
          </Button>
          <span className="muted" role="status">{status}</span>
        </Toolbar>
      </form>
      {actionError ? <ErrorNote error={actionError} /> : null}
    </Panel>
  );
}

/** Rename this function to the canonical name the store already recorded. */
function CanonicalNamePanel({ functionId }: { functionId: number }): ReactNode {
  const [message, setMessage] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const run = async (): Promise<void> => {
    setActionError(null);
    setMessage("");
    setBusy(true);
    try {
      const report = await api<{
        applied_count: number;
        skipped: Array<{ function_id: number; reason: string }>;
      }>("/functions/canonical-names", {
        method: "POST",
        json: { function_ids: [functionId] },
      });
      const skipped = report.skipped.length
        ? ` Skipped: ${report.skipped.map((row) => row.reason).join(", ")}.`
        : "";
      setMessage(`Renamed ${report.applied_count} function(s).${skipped}`);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Canonical Name"
      subtitle="Rename to the candidate the store already recorded: a predicted name, else the newest rename. Never a guess."
    >
      <Toolbar>
        <Button tone="primary" pending={busy} onClick={() => void run()}>
          Apply canonical name
        </Button>
        <span className="muted" role="status">{message}</span>
      </Toolbar>
      {actionError ? <ErrorNote error={actionError} /> : null}
    </Panel>
  );
}

/** The per-function extras: call sites, capabilities, strings and callees. */
export function FunctionExtrasPanel({ functionId }: { functionId: number }): ReactNode {
  const sitesKey = panelKey("function", functionId, "indirect-call-sites");
  const sites = usePanel<IndirectCallSites>(sitesKey, () =>
    api<IndirectCallSites>(`/functions/${functionId}/indirect-call-sites`),
  );
  const capsKey = panelKey("function", functionId, "capabilities");
  const capabilities = usePanel<FunctionCapabilities>(capsKey, () =>
    api<FunctionCapabilities>(`/functions/${functionId}/capabilities`),
  );

  return (
    <>
      <Panel
        title="Indirect call sites"
        subtitle="Calls and jumps through a register or a memory operand, from the cached listing."
        actions={
          <Button
            size="sm"
            tone="ghost"
            onClick={() =>
              refreshPanel(sitesKey, () =>
                api<IndirectCallSites>(`/functions/${functionId}/indirect-call-sites`),
              )
            }
          >
            Refresh
          </Button>
        }
      >
        <PanelBody entry={sites} hint="Loading the indirect call sites">
          {(data) =>
            data.sites.length === 0 ? (
              <EmptyState>
                {data.has_disassembly
                  ? "No indirect call sites in the cached listing."
                  : "No cached disassembly for this function, so the scan reports nothing."}
              </EmptyState>
            ) : (
              <>
                <table className="table" aria-label="Indirect call sites">
                  <thead>
                    <tr>
                      <th>Line</th>
                      <th>Op</th>
                      <th>Target</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.sites.map((site) => (
                      <tr key={siteLabel(site)}>
                        <td className="mono">{site.line}</td>
                        <td className="mono">{site.mnemonic}</td>
                        <td className="mono">{site.target}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Muted>{data.note}</Muted>
              </>
            )
          }
        </PanelBody>
      </Panel>
      <Panel
        title="Capabilities"
        subtitle="Classified from the imports and literals this function's stored text mentions."
      >
        <PanelBody entry={capabilities} hint="Loading the function capabilities">
          {(data) =>
            data.capabilities.length === 0 ? (
              <EmptyState>No capability rule matched this function.</EmptyState>
            ) : (
              <table className="table" aria-label="Capabilities">
                <thead>
                  <tr>
                    <th>Capability</th>
                    <th>Confidence</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.capabilities.map((row) => (
                    <tr key={row.name}>
                      <td>{row.name}</td>
                      <td>
                        <Badge mono>{row.confidence}</Badge>
                      </td>
                      <td className="mono">{row.evidence_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </PanelBody>
      </Panel>
      <FunctionStringsPanel functionId={functionId} />
      <CalleesPanel functionId={functionId} />
      <CanonicalNamePanel functionId={functionId} />
    </>
  );
}

function FunctionStringsPanel({ functionId }: { functionId: number }): ReactNode {
  const path = `/functions/${functionId}/strings`;
  const key = panelKey("function", functionId, "strings");
  const load = (): Promise<FunctionStrings> => api<FunctionStrings>(path);
  const entry = usePanel<FunctionStrings>(key, load);

  return (
    <Panel
      title="Strings"
      subtitle="What an analyst recorded for this function, and the literals beside it."
    >
      <StringsSection
        path={path}
        key={key}
        load={load}
        derived={entry?.state === "ready" ? entry.data.derived : undefined}
        decoded={entry?.state === "ready" ? entry.data.decoded : undefined}
        note={entry?.state === "ready" ? entry.data.note : undefined}
        limit={1024}
      />
    </Panel>
  );
}

function CalleesPanel({ functionId }: { functionId: number }): ReactNode {
  const path = `/functions/${functionId}/callees`;
  const key = panelKey("function", functionId, "callees");
  const load = (): Promise<FunctionCallees> => api<FunctionCallees>(path);
  const entry = usePanel<FunctionCallees>(key, load);
  const [callee, setCallee] = useState("");
  const [kind, setKind] = useState<string>(EDGE_KINDS[0]);
  const [note, setNote] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const refresh = (): void => refreshPanel(key, load);

  const add = async (): Promise<void> => {
    setActionError(null);
    const name = callee.trim();
    if (!name) return;
    setBusy("add");
    try {
      await api(path, { method: "POST", json: { callee: name, kind, note } });
      setCallee("");
      setNote("");
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const remove = async (edgeId: number): Promise<void> => {
    setActionError(null);
    setBusy(`remove-${edgeId}`);
    try {
      await api(`${path}/${edgeId}`, { method: "DELETE" });
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <Panel
      title="Callees"
      subtitle="The names the stored decompilation mentions, and the edges an analyst declared."
    >
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void add();
        }}
      >
        <Toolbar>
          <Field label="Callee">
            <input
              value={callee}
              onChange={(event) => setCallee(event.target.value)}
              placeholder="A callee the engine cannot resolve"
            />
          </Field>
          <Field label="Kind">
            <select value={kind} onChange={(event) => setKind(event.target.value)}>
              {EDGE_KINDS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Note">
            <input value={note} onChange={(event) => setNote(event.target.value)} />
          </Field>
          <Button tone="primary" type="submit" pending={busy === "add"}>
            Declare callee
          </Button>
        </Toolbar>
      </form>
      {actionError ? <ErrorNote error={actionError} /> : null}
      <PanelBody entry={entry} hint="Loading the callees">
        {(data) => (
          <>
            {data.declared.length === 0 ? (
              <EmptyState>No declared callee edges yet.</EmptyState>
            ) : (
              <table className="table" aria-label="Callees">
                <thead>
                  <tr>
                    <th>Callee</th>
                    <th>Kind</th>
                    <th>Source</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.declared.map((edge) => (
                    <tr key={edge.edge_id}>
                      <td className="mono">{edge.name}</td>
                      <td>
                        <Badge mono>{edge.kind}</Badge>
                      </td>
                      <td className="muted">{edge.source}</td>
                      <td>
                        <ConfirmButton
                          label="Remove"
                          message="Remove this declared edge?"
                          pending={busy === `remove-${edge.edge_id}`}
                          onConfirm={() => void remove(edge.edge_id)}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <Muted>
              Derived: {data.callees.map((row) => row.name).join(", ") || "none"}.
            </Muted>
            <Muted>{data.derivation}</Muted>
          </>
        )}
      </PanelBody>
    </Panel>
  );
}

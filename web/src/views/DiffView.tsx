import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import "./diff.css";
import {
  Badge,
  Button,
  CopyValue,
  ErrorNote,
  Field,
  Loading,
  NA,
  Note,
  Panel,
  Toolbar,
  hex,
} from "../components";
import {
  DEFAULT_DIFF_KIND,
  DEFAULT_DIFF_NORMALIZE,
  DEFAULT_TRANSFER_MODE,
  DIFF_KIND_LABELS,
  DIFF_KINDS,
  TRANSFER_MODE_LABELS,
  TRANSFER_MODES,
} from "../constants";
import type {
  DiffEntry,
  DiffSide,
  FunctionDiff,
  MatchRow,
  TransferMode,
  TransferRowReport,
} from "../types";
import { setCodeViewSwitch } from "../panels/codeViewSwitch";
import { useAsync } from "../useAsync";

function rowClass(op: DiffEntry["op"]): string {
  if (op === "insert" || op === "replace") return "diff-row diff-insert";
  if (op === "delete") return "diff-row diff-delete";
  return "diff-row diff-equal";
}

function SideHeader({ side }: { side: DiffSide }): ReactNode {
  const label = side.name || `Function #${side.function_id}`;
  return (
    <span className="toolbar">
      <a href={`#/functions/${side.function_id}`}>
        #{side.function_id} {label} @ {hex(side.va)}
      </a>
      <a href={`#/binaries/${side.binary_id}`}>binary #{side.binary_id}</a>
      {side.name ? <CopyValue value={side.name} /> : null}
    </span>
  );
}

function DiffCell({ line, text }: { line: number | null; text: string | null }): ReactNode {
  return (
    <>
      <span className="diff-line">{line ?? ""}</span>
      <span className="diff-text">{text ?? ""}</span>
    </>
  );
}

export function DiffView({
  functionId,
  candidateId,
}: {
  functionId: number;
  candidateId: number;
}): ReactNode {
  const [kind, setKind] = useState<string>(DEFAULT_DIFF_KIND);
  const [normalize, setNormalize] = useState(DEFAULT_DIFF_NORMALIZE);
  const [mode, setMode] = useState<TransferMode>(DEFAULT_TRANSFER_MODE);
  const [busy, setBusy] = useState(false);
  const [transferError, setTransferError] = useState<unknown>(null);
  const [transferReport, setTransferReport] = useState<TransferRowReport | null>(null);

  const transfer = async (fromId = candidateId): Promise<void> => {
    setBusy(true);
    setTransferError(null);
    try {
      const report = await api<TransferRowReport>(`/functions/${functionId}/apply-match`, {
        method: "POST",
        json: { candidate_function_id: fromId, mode: fromId === candidateId ? mode : "name", actor: "spa" },
      });
      setTransferReport(report);
    } catch (failure) {
      setTransferError(failure);
    } finally {
      setBusy(false);
    }
  };
  // Hosted Space on Match/Diff toggles Disassembly and AI decompilation.
  // CodeSection publishes the same seam for Disassembly / Control flow.
  useEffect(() => {
    setCodeViewSwitch(() =>
      setKind((current) => (current === "disasm" ? "decomp" : "disasm")),
    );
    return () => {
      setCodeViewSwitch(null);
    };
  }, []);
  const matchesResult = useAsync<{ matches: MatchRow[] }>(
    () => api(`/functions/${functionId}/matches`),
    [functionId],
  );
  const result = useAsync<FunctionDiff>(
    () =>
      api<FunctionDiff>(
        `/functions/${functionId}/diff/${candidateId}?kind=${kind}&normalize=${normalize ? "true" : "false"}`,
      ),
    [functionId, candidateId, kind, normalize],
  );
  const diff = result.data;

  let body: ReactNode;
  if (result.error) body = <ErrorNote error={result.error} onRetry={result.reload} />;
  else if (!diff) body = <Loading label="Loading the diff" rows={5} />;
  else {
    const similarity = diff.similarity === null ? NA : diff.similarity.toFixed(1);
    body = (
      <>
        <div className="diff-summary">
          <Badge tone="accent">similarity {similarity}</Badge>
          <Badge>equal {diff.summary.equal}</Badge>
          {/* A zero count is not a change: it stays neutral, not green or red. */}
          <Badge tone={diff.summary.changed > 0 ? "insert" : undefined}>
            changed {diff.summary.changed}
          </Badge>
          <Badge tone={diff.summary.insert > 0 ? "insert" : undefined}>
            insert {diff.summary.insert}
          </Badge>
          <Badge tone={diff.summary.delete > 0 ? "delete" : undefined}>
            delete {diff.summary.delete}
          </Badge>
        </div>
        <div className="table-scroll">
          <table
            className="diff-table"
            aria-label={kind === "decomp" ? "AI decompilation diff" : "Disassembly diff"}
          >
            <thead>
              <tr>
                <th>
                  <SideHeader side={diff.left} />
                </th>
                <th>
                  <SideHeader side={diff.right} />
                </th>
              </tr>
            </thead>
            <tbody>
              {diff.entries.map((entry, index) => (
                <tr key={index} className={rowClass(entry.op)}>
                  <td>
                    <DiffCell line={entry.left_line} text={entry.left} />
                  </td>
                  <td>
                    <DiffCell line={entry.right_line} text={entry.right} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </>
    );
  }

  return (
    <Panel
      title="Diff"
      subtitle={`Function #${functionId} against #${candidateId}, line by line.`}
      actions={
        <Toolbar>
          <a className="back-link" href={`#/functions/${functionId}`}>
            Back to function
          </a>
          <Field label="Kind">
            <select value={kind} onChange={(event) => setKind(event.target.value)}>
              {DIFF_KINDS.map((option) => (
                <option key={option} value={option}>
                  {DIFF_KIND_LABELS[option]}
                </option>
              ))}
            </select>
          </Field>
          <label className="checkbox-field">
            <input
              type="checkbox"
              checked={normalize}
              onChange={(event) => setNormalize(event.target.checked)}
            />
            Normalize
          </label>
          <Field label="Transfer">
            <select
              aria-label="Transfer mode"
              value={mode}
              onChange={(event) => setMode(event.target.value as TransferMode)}
            >
              {TRANSFER_MODES.map((option) => (
                <option key={option} value={option}>
                  {TRANSFER_MODE_LABELS[option]}
                </option>
              ))}
            </select>
          </Field>
          <Button pending={busy} onClick={() => void transfer()}>
            Transfer Symbol
          </Button>
          <Button onClick={result.reload}>Reload</Button>
        </Toolbar>
      }
    >
      {transferError ? <ErrorNote error={transferError} /> : null}
      {transferReport ? (
        <Note>
          {transferReport.status}
          {transferReport.detail ? `: ${transferReport.detail}` : ""}
        </Note>
      ) : null}
      {matchesResult.data?.matches.length ? (
        <details open>
          <summary>Suggested names ({matchesResult.data.matches.length})</summary>
          <Toolbar>
            {matchesResult.data.matches.map((row) => (
              <Button
                key={row.id}
                size="sm"
                pending={busy}
                onClick={() => void transfer(row.candidate_function_id)}
              >
                {row.candidate_name || `#${row.candidate_function_id}`} ({row.confidence})
              </Button>
            ))}
          </Toolbar>
        </details>
      ) : null}
      {body}
    </Panel>
  );
}

import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import { Badge, Button, ErrorNote, Field, Loading, NA, Panel, Toolbar, hex } from "../components";
import { DEFAULT_DIFF_KIND, DEFAULT_DIFF_NORMALIZE, DIFF_KINDS } from "../constants";
import type { DiffEntry, DiffSide, FunctionDiff } from "../types";
import { useAsync } from "../useAsync";

function rowClass(op: DiffEntry["op"]): string {
  if (op === "insert" || op === "replace") return "diff-row diff-insert";
  if (op === "delete") return "diff-row diff-delete";
  return "diff-row diff-equal";
}

function SideHeader({ side }: { side: DiffSide }): ReactNode {
  return (
    <a href={`#/functions/${side.function_id}`}>
      #{side.function_id} {side.name || NA} @ {hex(side.va)}
    </a>
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
          <Badge tone="insert">changed {diff.summary.changed}</Badge>
          <Badge tone="insert">insert {diff.summary.insert}</Badge>
          <Badge tone="delete">delete {diff.summary.delete}</Badge>
        </div>
        <div className="table-scroll">
          <table className="diff-table">
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
                  {option}
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
          <Button onClick={result.reload}>Reload</Button>
        </Toolbar>
      }
    >
      {body}
    </Panel>
  );
}

import { useState } from "react";
import type { ReactNode } from "react";

import { api, isApiErrorCode } from "../api";
import {
  Badge,
  Button,
  CodeBlock,
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorNote,
  Loading,
  Muted,
  NA,
  Panel,
  StatusCell,
  Toolbar,
} from "../components";
import { PIPELINE_NO_RUN } from "../constants";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import type {
  AiComment,
  PipelineArtifacts,
  PipelineRevertResult,
  PipelineRun,
  PipelineStep,
} from "../types";
import { historyKey, loadHistory } from "./FunctionPanels";

/** Merge a run's inline comments into the lines of the decompilation they name. */
export function commentedSource(code: string, comments: AiComment[]): string {
  const byLine = new Map<number, string>();
  for (const comment of comments) {
    if (!byLine.has(comment.line)) byLine.set(comment.line, comment.comment);
  }
  return code
    .split("\n")
    .map((line, index) => {
      const comment = byLine.get(index + 1);
      return comment ? `${line}  // ${comment}` : line;
    })
    .join("\n");
}

function StepsTable({ steps }: { steps: PipelineStep[] }): ReactNode {
  return (
    <DataTable
      columns={[
        { label: "Step", key: "name", mono: true },
        { label: "Status", render: (row) => <StatusCell status={row.status} /> },
        { label: "Duration", numeric: true, render: (row) => `${Number(row.duration_ms)} ms` },
        { label: "Reason", render: (row) => row.reason || NA },
        { label: "Provides", render: (row) => row.provides.join(", ") || NA },
      ]}
      rows={steps}
      rowKey={(row) => row.id}
    />
  );
}

function PredictedNameRow({
  artifacts,
  onApplyName,
  pending,
}: {
  artifacts: PipelineArtifacts;
  onApplyName: (name: string) => void;
  pending: boolean;
}): ReactNode {
  const predicted = artifacts.predicted_name;
  const name = predicted?.name ?? "";
  if (!name) {
    return (
      <Toolbar>
        <strong>Predicted name</strong>
        <Muted>none</Muted>
      </Toolbar>
    );
  }
  return (
    <Toolbar>
      <strong>Predicted name</strong>
      <Badge mono>{name}</Badge>
      <Muted>
        {predicted?.source} confidence {Number(predicted?.confidence ?? 0).toFixed(2)}
      </Muted>
      <Button size="sm" pending={pending} onClick={() => onApplyName(name)}>
        Apply rename
      </Button>
    </Toolbar>
  );
}

function RunBody({
  run,
  onApplyName,
  pendingRename,
}: {
  run: PipelineRun;
  onApplyName: (name: string) => void;
  pendingRename: boolean;
}): ReactNode {
  const artifacts = run.artifacts;
  const comments = artifacts.inline_comments?.comments ?? [];
  const code = artifacts.decompilation?.code ?? "";
  const summary = artifacts.summary?.summary ?? "";
  return (
    <>
      <div className="chips">
        <Badge mono>run #{run.id}</Badge>
        <StatusCell status={run.status} />
        <Badge mono>model {run.model || "none"}</Badge>
      </div>
      <StepsTable steps={run.steps} />
      <PredictedNameRow artifacts={artifacts} onApplyName={onApplyName} pending={pendingRename} />
      {summary ? <p>{summary}</p> : <Muted>No summary stored.</Muted>}
      {comments.length ? (
        <DataTable
          columns={[
            { label: "Line", numeric: true, render: (row) => String(row.line) },
            { label: "Comment", key: "comment" },
          ]}
          rows={comments}
          rowKey={(_row, index) => index}
        />
      ) : (
        <Muted>No inline comments stored.</Muted>
      )}
      {code ? (
        <CodeBlock text={commentedSource(code, comments)} title="decompilation" />
      ) : (
        <Muted>No decompilation stored.</Muted>
      )}
    </>
  );
}

/** The AI decompilation run of one function: its steps, artifacts and revert. */
export function PipelinePanel({
  functionId,
  onMutated,
}: {
  functionId: number;
  onMutated: () => void;
}): ReactNode {
  const key = panelKey("fn", functionId, "pipeline");
  const loader = (): Promise<PipelineRun> => api<PipelineRun>(`/functions/${functionId}/pipeline`);
  const entry = usePanel(key, loader);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");

  const reload = (): void => {
    refreshPanel(key, loader);
    refreshPanel(historyKey(functionId), () => loadHistory(functionId));
    onMutated();
  };

  const runPipeline = async (): Promise<void> => {
    setActionError(null);
    setNotice("");
    setBusy("run");
    try {
      await api<PipelineRun>(`/functions/${functionId}/pipeline`, { method: "POST" });
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const revertRun = async (runId: number): Promise<void> => {
    setActionError(null);
    setNotice("");
    setBusy("revert");
    try {
      const result = await api<PipelineRevertResult>(`/pipeline/runs/${runId}/revert`, {
        method: "POST",
      });
      setNotice(`Reverted ${result.reverted.length} artifact(s).`);
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const applyName = async (name: string): Promise<void> => {
    setActionError(null);
    setNotice("");
    setBusy("rename");
    try {
      await api(`/functions/${functionId}/rename`, {
        method: "POST",
        json: { name, actor: "pipeline" },
      });
      setNotice(`Renamed the function to ${name}.`);
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  let body: ReactNode;
  if (!entry || entry.state === "loading") {
    body = <Loading label="Loading the AI decompilation run" />;
  } else if (entry.state === "error") {
    body = isApiErrorCode(entry.error, PIPELINE_NO_RUN) ? (
      <EmptyState>
        No AI decompilation run for this function yet. Run the pipeline to create one.
      </EmptyState>
    ) : (
      <ErrorNote error={entry.error} onRetry={() => refreshPanel(key, loader)} />
    );
  } else {
    body = (
      <RunBody
        run={entry.data}
        onApplyName={(name) => void applyName(name)}
        pendingRename={busy === "rename"}
      />
    );
  }

  return (
    <Panel
      title="AI decompilation"
      subtitle="The stored model-assisted run over this function: steps, artifacts and the commented source."
      actions={
        <>
          <Button
            tone="primary"
            pending={busy === "run"}
            onClick={() => void runPipeline()}
          >
            {entry?.state === "ready" ? "Re-run" : "Run pipeline"}
          </Button>
          {entry?.state === "ready" ? (
            <ConfirmButton
              label="Revert run"
              message="Revert this run?"
              pending={busy === "revert"}
              onConfirm={() => void revertRun(entry.data.id)}
            />
          ) : null}
        </>
      }
    >
      {actionError ? <ErrorNote error={actionError} /> : null}
      {notice ? <Muted>{notice}</Muted> : null}
      {body}
    </Panel>
  );
}

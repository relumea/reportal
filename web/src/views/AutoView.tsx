import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api, isApiErrorCode } from "../api";
import {
  Badge,
  Button,
  CheckboxField,
  ConfirmButton,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Muted,
  Panel,
  Readout,
  SegmentMeter,
  StatusCell,
  UNAVAILABLE,
} from "../components";
import {
  AUTO_CONCURRENCY_MAX,
  AUTO_CONCURRENCY_MIN,
  AUTO_NO_RUN,
  AUTO_POLL_MS,
  AUTO_WORKERS,
  DEFAULT_AUTO_CONCURRENCY,
  DEFAULT_AUTO_WORKER,
} from "../constants";
import type { AutoWorker } from "../constants";
import type { AutoRun, AutoRunStarted, AutoRevertResult, AutoTask, Binary } from "../types";
import { useAsync } from "../useAsync";

/** One code reason carried by the outcome stored on a task result. */
function outcomeReason(task: AutoTask): string {
  const outcomes = task.result.outcomes;
  if (!Array.isArray(outcomes) || outcomes.length === 0) return "";
  const first: unknown = outcomes[0];
  if (typeof first !== "object" || first === null) return "";
  const reason = (first as Record<string, unknown>).reason;
  return typeof reason === "string" ? reason : "";
}

function TaskNode({ task }: { task: AutoTask }): ReactNode {
  const reason = outcomeReason(task);
  return (
    <li className="task-node">
      <div className="task-line">
        <StatusCell status={task.status} />
        <Badge mono>{task.kind}</Badge>
        <span>{task.title}</span>
        {task.worker ? <Muted>{task.worker}</Muted> : null}
        <Muted>attempts {task.attempts}</Muted>
        {reason ? <Muted>{reason}</Muted> : null}
      </div>
      {task.attempt_log.length ? (
        <ul className="task-attempts">
          {task.attempt_log.map((attempt) => {
            const detail = attempt.detail;
            const detailReason = typeof detail.reason === "string" ? detail.reason : "";
            return (
              <li key={attempt.id}>
                attempt {attempt.attempt}: {attempt.status}
                {detailReason ? ` (${detailReason})` : ""}
              </li>
            );
          })}
        </ul>
      ) : null}
      {task.children.length ? (
        <ul className="task-children">
          {task.children.map((child) => (
            <TaskNode key={child.id} task={child} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function CoverageLine({ run }: { run: AutoRun }): ReactNode {
  const before = run.coverage_before;
  const after = run.coverage_after;
  return (
    <div className="cockpit-strip">
      <SegmentMeter
        label="Coverage before"
        value={typeof before.ratio === "number" ? before.ratio : null}
        readout={`${before.matched ?? 0} / ${before.total ?? 0}`}
      />
      <SegmentMeter
        label="Coverage after"
        value={typeof after.ratio === "number" ? after.ratio : null}
        readout={`${after.matched ?? 0} / ${after.total ?? 0}`}
        missing={UNAVAILABLE}
      />
      <Readout label="Matched" value={run.matched} hue="match" />
      <Readout label="Improved" value={run.improved} hue="live" />
      <Readout label="Failed" value={run.failed} hue={run.failed > 0 ? "fail" : undefined} />
      <Readout label="Skipped" value={run.skipped} />
      <Readout label="Tasks" value={run.tasks} />
      <Readout label="Attempts" value={run.attempts} />
    </div>
  );
}

function StartForm({
  onStart,
  disabled,
  pending,
}: {
  onStart: (worker: AutoWorker, execute: boolean, concurrency: number) => void;
  disabled: boolean;
  pending: boolean;
}): ReactNode {
  const [worker, setWorker] = useState<AutoWorker>(DEFAULT_AUTO_WORKER);
  const [execute, setExecute] = useState(false);
  const [concurrency, setConcurrency] = useState(DEFAULT_AUTO_CONCURRENCY);
  return (
    <form
      className="toolbar"
      onSubmit={(event) => {
        event.preventDefault();
        onStart(worker, execute, concurrency);
      }}
    >
      <Field label="Worker">
        <select
          id="auto-worker"
          value={worker}
          disabled={disabled}
          onChange={(event) => setWorker(event.target.value as AutoWorker)}
        >
          {AUTO_WORKERS.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Concurrency">
        <input
          id="auto-concurrency"
          type="number"
          min={AUTO_CONCURRENCY_MIN}
          max={AUTO_CONCURRENCY_MAX}
          value={concurrency}
          disabled={disabled}
          onChange={(event) => setConcurrency(Number(event.target.value))}
        />
      </Field>
      <CheckboxField
        label="Execute (write C files and compile)"
        checked={execute}
        disabled={disabled}
        onChange={setExecute}
      />
      <Button tone="primary" type="submit" pending={pending} disabled={disabled}>
        Start run
      </Button>
    </form>
  );
}

function AutoRunPanel({ binaryId }: { binaryId: number }): ReactNode {
  const { data, error, reload } = useAsync(() => api<AutoRun>(`/binaries/${binaryId}/auto`), [binaryId]);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState("");
  const running = data?.status === "running";

  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(reload, AUTO_POLL_MS);
    return () => window.clearInterval(timer);
  }, [running, reload]);

  const start = async (worker: AutoWorker, execute: boolean, concurrency: number): Promise<void> => {
    setActionError(null);
    setNotice("");
    setBusy("start");
    try {
      const started = await api<AutoRunStarted>(`/binaries/${binaryId}/auto`, {
        method: "POST",
        json: { worker, execute, concurrency },
      });
      setNotice(`Started auto run #${started.run_id}.`);
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const revert = async (runId: number): Promise<void> => {
    setActionError(null);
    setNotice("");
    setBusy("revert");
    try {
      const result = await api<AutoRevertResult>(`/auto/runs/${runId}/revert`, { method: "POST" });
      setNotice(
        `Removed ${result.removed.length} file(s), restored ${result.restored.length} status(es).`,
      );
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  let body: ReactNode;
  if (!data && error && isApiErrorCode(error, AUTO_NO_RUN)) {
    body = <EmptyState>No auto run for this binary yet. Start one from the form above.</EmptyState>;
  } else if (error) {
    body = <ErrorNote error={error} onRetry={reload} />;
  } else if (!data) {
    body = <Loading label="Loading the auto run" />;
  } else {
    body = (
      <>
        <CoverageLine run={data} />
        <ul className="task-tree">
          {data.tree.map((task) => (
            <TaskNode key={task.id} task={task} />
          ))}
        </ul>
      </>
    );
  }

  return (
    <Panel
      title={`Auto-mode · binary #${binaryId}`}
      subtitle="Decomposes the binary's functions into worker batches, records every attempt, and measures coverage before and after the run."
      actions={
        <>
          <a className="back-link" href="#/auto">
            All binaries
          </a>
          {data ? (
            <ConfirmButton
              label="Revert run"
              message="Revert this run?"
              pending={busy === "revert"}
              onConfirm={() => void revert(data.run_id)}
            />
          ) : null}
        </>
      }
    >
      <StartForm
        onStart={(worker, execute, concurrency) => void start(worker, execute, concurrency)}
        disabled={running}
        pending={busy === "start"}
      />
      {running ? (
        <Muted>A run is working. This view refreshes itself.</Muted>
      ) : (
        <Muted>
          A dry run touches no source file and no function status. Execute writes candidate C files
          into the rebrew project and compiles them.
        </Muted>
      )}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {notice ? <Muted>{notice}</Muted> : null}
      {body}
    </Panel>
  );
}

function BinaryPicker(): ReactNode {
  const navigate = useNavigate();
  const { data, error, reload } = useAsync(() => api<{ binaries: Binary[] }>("/binaries"), []);
  if (error) return <ErrorNote error={error} onRetry={reload} />;
  const binaries = data?.binaries;
  if (!binaries) {
    return (
      <Panel title="Auto-mode">
        <Loading label="Loading binaries" />
      </Panel>
    );
  }
  return (
    <Panel title="Auto-mode" subtitle="Choose the binary to decompose into worker batches.">
      <DataTable
        columns={[
          { label: "ID", key: "id", numeric: true },
          { label: "Name", key: "name" },
          { label: "Functions", key: "function_count", numeric: true },
        ]}
        rows={binaries}
        rowKey={(row) => row.id}
        onRowClick={(row) => navigate(`/auto/${row.id}`)}
        empty={
          <EmptyState>
            No binaries yet. Import a rebrew project with{" "}
            <code>reportal import-rebrew &lt;project-dir&gt;</code>.
          </EmptyState>
        }
      />
    </Panel>
  );
}

/** Auto-mode: pick a binary, start a run, watch its task tree, revert it. */
export function AutoView({ binaryId }: { binaryId: number | null }): ReactNode {
  if (binaryId === null) return <BinaryPicker />;
  return <AutoRunPanel binaryId={binaryId} />;
}

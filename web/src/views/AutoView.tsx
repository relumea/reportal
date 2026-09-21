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
  AUTO_FUNCTIONS_PER_TASK_MAX,
  AUTO_FUNCTIONS_PER_TASK_MIN,
  AUTO_GOAL_MAX,
  AUTO_MAX_ATTEMPTS_MAX,
  AUTO_MAX_ATTEMPTS_MIN,
  AUTO_MAX_TASKS_MAX,
  AUTO_MAX_TASKS_MIN,
  AUTO_NO_RUN,
  AUTO_POLL_MS,
  AUTO_WORKERS,
  DEFAULT_AUTO_CONCURRENCY,
  DEFAULT_AUTO_FUNCTIONS_PER_TASK,
  DEFAULT_AUTO_MAX_ATTEMPTS,
  DEFAULT_AUTO_MAX_TASKS,
  DEFAULT_AUTO_WORKER,
} from "../constants";
import type { AutoWorker } from "../constants";
import type {
  AutoRecoverResult,
  AutoRun,
  AutoRunStarted,
  AutoRevertResult,
  AutoTask,
  Binary,
} from "../types";
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

/** The run knobs the start form sends beside the worker. */
interface AutoRunOptions {
  execute: boolean;
  concurrency: number;
  functionsPerTask: number;
  maxAttempts: number;
  maxTasks: number;
  goal: string;
}

function StartForm({
  onStart,
  disabled,
  pending,
}: {
  onStart: (worker: AutoWorker, options: AutoRunOptions) => void;
  disabled: boolean;
  pending: boolean;
}): ReactNode {
  const [worker, setWorker] = useState<AutoWorker>(DEFAULT_AUTO_WORKER);
  const [execute, setExecute] = useState(false);
  const [concurrency, setConcurrency] = useState(DEFAULT_AUTO_CONCURRENCY);
  const [functionsPerTask, setFunctionsPerTask] = useState(DEFAULT_AUTO_FUNCTIONS_PER_TASK);
  const [maxAttempts, setMaxAttempts] = useState(DEFAULT_AUTO_MAX_ATTEMPTS);
  const [maxTasks, setMaxTasks] = useState(DEFAULT_AUTO_MAX_TASKS);
  const [goal, setGoal] = useState("");
  return (
    <form
      className="toolbar"
      onSubmit={(event) => {
        event.preventDefault();
        onStart(worker, {
          execute,
          concurrency,
          functionsPerTask,
          maxAttempts,
          maxTasks,
          goal: goal.trim(),
        });
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
      <Field label="Goal" hint={`optional, at most ${AUTO_GOAL_MAX} characters; used by the llm_goal worker`}>
        <input
          id="auto-goal"
          type="text"
          maxLength={AUTO_GOAL_MAX}
          value={goal}
          disabled={disabled}
          placeholder="Extract the licence check, drop the demo timer, ..."
          onChange={(event) => setGoal(event.target.value)}
        />
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
      <Field label="Functions per task" hint={`${AUTO_FUNCTIONS_PER_TASK_MIN}-${AUTO_FUNCTIONS_PER_TASK_MAX} per leaf batch`}>
        <input
          id="auto-functions-per-task"
          type="number"
          min={AUTO_FUNCTIONS_PER_TASK_MIN}
          max={AUTO_FUNCTIONS_PER_TASK_MAX}
          value={functionsPerTask}
          disabled={disabled}
          onChange={(event) => setFunctionsPerTask(Number(event.target.value))}
        />
      </Field>
      <Field label="Max attempts" hint={`${AUTO_MAX_ATTEMPTS_MIN}-${AUTO_MAX_ATTEMPTS_MAX} per function`}>
        <input
          id="auto-max-attempts"
          type="number"
          min={AUTO_MAX_ATTEMPTS_MIN}
          max={AUTO_MAX_ATTEMPTS_MAX}
          value={maxAttempts}
          disabled={disabled}
          onChange={(event) => setMaxAttempts(Number(event.target.value))}
        />
      </Field>
      <Field label="Max tasks" hint={`at most ${AUTO_MAX_TASKS_MAX} task rows`}>
        <input
          id="auto-max-tasks"
          type="number"
          min={AUTO_MAX_TASKS_MIN}
          max={AUTO_MAX_TASKS_MAX}
          value={maxTasks}
          disabled={disabled}
          onChange={(event) => setMaxTasks(Number(event.target.value))}
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

  const start = async (worker: AutoWorker, options: AutoRunOptions): Promise<void> => {
    setActionError(null);
    setNotice("");
    setBusy("start");
    try {
      const started = await api<AutoRunStarted>(`/binaries/${binaryId}/auto`, {
        method: "POST",
        json: {
          worker,
          execute: options.execute,
          concurrency: options.concurrency,
          functions_per_task: options.functionsPerTask,
          max_attempts: options.maxAttempts,
          max_tasks: options.maxTasks,
          goal: options.goal,
        },
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

  const recover = async (runId: number): Promise<void> => {
    setActionError(null);
    setNotice("");
    setBusy("recover");
    try {
      const result = await api<AutoRecoverResult>(`/auto/runs/${runId}/recover`, { method: "POST" });
      setNotice(
        `Closed run #${result.run_id} as ${result.status}: ${result.recovered_tasks} task(s)`
          + ` interrupted, ${result.added_descriptors} descriptor(s) kept revertible`
          + (result.uncertain_intents.length
            ? `, ${result.uncertain_intents.length} write(s) possibly applied`
            : "")
          + ".",
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
    body = <EmptyState>Your first auto run is one step away. Set the worker below and press Start run.</EmptyState>;
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
              message="Revert this run and restore the statuses it replaced?"
              pending={busy === "revert"}
              onConfirm={() => void revert(data.run_id)}
            />
          ) : null}
          {data?.status === "running" ? (
            <ConfirmButton
              label="Recover run"
              message="Close this run as stale and keep its revertible writes?"
              pending={busy === "recover"}
              onConfirm={() => void recover(data.run_id)}
            />
          ) : null}
        </>
      }
    >
      <StartForm
        onStart={(worker, options) => void start(worker, options)}
        disabled={running}
        pending={busy === "start"}
      />
      {data?.goal ? (
        <Muted>
          Goal for run #{data.run_id}: {data.goal}
        </Muted>
      ) : null}
      {running ? (
        <Muted>
          A run is working. This view refreshes itself; Recover closes a run whose process died
          without finishing it.
        </Muted>
      ) : (
        <Muted>
          A dry run touches no source file and no function status. Execute writes candidate C files
          into the analysis workspace and compiles them; the llm_goal worker also writes a
          &lt;binary&gt;.patched copy holding only the byte edits the binary confirmed.
        </Muted>
      )}
      {actionError ? <ErrorNote error={actionError} /> : null}
      <Muted live>{notice}</Muted>
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
            No binaries yet. Upload one to start.
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

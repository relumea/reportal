// Dashboard: the cockpit.  One screen answers "what is the state of the whole
// system right now": instrument readouts for the headline counts, one row per
// binary with its segmented match meter and status breakdown, the live auto-mode
// run with a progress meter and its current task, and the journal tail.  Live
// signals poll at their own rate (health 2s, the running binary's run 1s, its
// coverage 4s, the journal 5s) and a changed row flashes.
//
// Every value is read from an existing endpoint; a value the source does not
// provide renders as an explicit missing state rather than a zero.

import { useEffect, useRef } from "react";
import { useNavigate } from "react-router";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  EmptyState,
  ErrorNote,
  Loading,
  NA,
  Panel,
  Readout,
  SegmentMeter,
  StatusCell,
  UNAVAILABLE,
} from "../components";
import { isMatchedStatus, statusEntity } from "../design";
import { useChangedIds } from "../live";
import type {
  AutoRun,
  AutoTask,
  BinaryListRow,
  FunctionRow,
  Health,
  JournalEntry,
  JournalList,
  PeInfo,
  PeSection,
  ReportScan,
} from "../types";
import { useAsync } from "../useAsync";

// Journal rows the tail shows before the view links out to the full journal.
const JOURNAL_TAIL = 8;

// Matched counts and the latest auto run are one request each per binary; the
// dashboard enriches the first SUMMARY_CAP binaries and states the rest.
const SUMMARY_CAP = 25;

// Stored PE details and the coverage report are two more requests per binary,
// so only the first SECTION_CAP binaries carry the per-section and byte meters.
const SECTION_CAP = 8;

// Status chips a binary row shows before it folds the rest into a +N badge.
const STATUS_CHIPS = 3;

// Poll intervals, tuned to each signal's rate: the running signal redraws fast,
// the row counts and the journal decay slowly, and the whole cockpit re-reads
// its per-binary detail on a slow tick so a run started elsewhere converges.
const HEALTH_POLL_MS = 2000;
const RUN_POLL_MS = 1000;
const COVERAGE_POLL_MS = 4000;
const JOURNAL_POLL_MS = 5000;
const SUMMARY_REFRESH_MS = 30000;

// Task states that mean the task is finished, whatever the outcome.
const TERMINAL_TASK_STATUSES = new Set(["done", "failed", "skipped"]);

const STATUS_ORDER: readonly string[] = [
  "EXACT",
  "RELOC",
  "PROVEN",
  "THUNK",
  "NEAR_MATCHING",
  "STUB",
];

const STATS: ReadonlyArray<{ key: string; label: string; unit?: string }> = [
  { key: "binaries", label: "Binaries" },
  { key: "functions", label: "Functions" },
  { key: "matched", label: "Matched" },
  { key: "matches", label: "Match records" },
  { key: "collections", label: "Collections" },
  { key: "documents", label: "Documents" },
];

const QUICK_LINKS: ReadonlyArray<{ href: string; label: string }> = [
  { href: "#/binaries", label: "Binaries" },
  { href: "#/functions", label: "Functions" },
  { href: "#/matches", label: "Matches" },
  { href: "#/auto", label: "Auto-mode" },
  { href: "#/knowledge", label: "Knowledge" },
  { href: "#/collections", label: "Collections" },
];

interface BinarySummary {
  binary: BinaryListRow;
  /** Function rows, or null when the request failed. */
  functions: FunctionRow[] | null;
  /** Latest auto run, or null when the binary has none. */
  auto: AutoRun | null;
  /** Stored PE metadata, or null when it was not fetched or is not stored. */
  pe: PeInfo | null;
  /** Matched byte share from the stored report, or null when there is none. */
  byteCoverage: number | null;
}

interface SectionMeter {
  name: string;
  ratio: number;
  covered: number;
  size: number;
}

function matchedCount(functions: FunctionRow[] | null): number | null {
  if (!functions) return null;
  return functions.filter((row) => isMatchedStatus(row.status)).length;
}

function statusChips(functions: FunctionRow[] | null): Array<[string, number]> {
  if (!functions || functions.length === 0) return [];
  const counts = new Map<string, number>();
  for (const row of functions) {
    const status = row.status || "unknown";
    counts.set(status, (counts.get(status) ?? 0) + 1);
  }
  const ordered = STATUS_ORDER.filter((status) => counts.has(status));
  const rest = [...counts.keys()].filter((status) => !STATUS_ORDER.includes(status)).sort();
  return [...ordered, ...rest].map((status) => [status, counts.get(status) ?? 0]);
}

function flattenTasks(tree: AutoTask[]): AutoTask[] {
  const flat: AutoTask[] = [];
  for (const node of tree) {
    flat.push(node, ...flattenTasks(node.children));
  }
  return flat;
}

/** The task the run is on: the first running one, else the last one visited. */
function currentTask(tree: AutoTask[]): AutoTask | null {
  let fallback: AutoTask | null = null;
  const walk = (nodes: AutoTask[]): AutoTask | null => {
    for (const node of nodes) {
      if (node.status === "running") return node;
      if (node.children.length > 0) {
        const found = walk(node.children);
        if (found) return found;
      }
      fallback = node;
    }
    return null;
  };
  return walk(tree) ?? fallback;
}

/** Finished share of a run's task tree, which is what moves while it works. */
function taskProgress(run: AutoRun): { done: number; total: number; ratio: number | null } {
  const tasks = flattenTasks(run.tree);
  const done = tasks.filter((task) => TERMINAL_TASK_STATUSES.has(task.status)).length;
  return { done, total: tasks.length, ratio: tasks.length ? done / tasks.length : null };
}

/** Matched function bytes inside each section, from VAs and the stored layout. */
function sectionMeters(summary: BinarySummary): SectionMeter[] | null {
  const sections: PeSection[] | undefined = summary.pe?.sections;
  const base = summary.pe?.image_base;
  if (!sections || sections.length === 0 || typeof base !== "number" || !summary.functions) {
    return null;
  }
  return sections
    .filter((section) => section.virtual_size > 0)
    .map((section) => {
      const start = base + section.virtual_address;
      const end = start + section.virtual_size;
      let covered = 0;
      for (const row of summary.functions ?? []) {
        if (isMatchedStatus(row.status) && row.va >= start && row.va < end) covered += row.size;
      }
      return {
        name: section.name,
        ratio: Math.min(1, covered / section.virtual_size),
        covered,
        size: section.virtual_size,
      };
    });
}

async function summarize(binary: BinaryListRow, withSections: boolean): Promise<BinarySummary> {
  const [functions, auto, pe, report] = await Promise.all([
    api<{ functions: FunctionRow[] }>(`/binaries/${binary.id}/functions`).catch(() => null),
    api<AutoRun>(`/binaries/${binary.id}/auto`).catch(() => null),
    withSections
      ? api<PeInfo>(`/binaries/${binary.id}/pe-info`).catch(() => null)
      : Promise.resolve(null),
    withSections
      ? api<ReportScan>(`/binaries/${binary.id}/report`).catch(() => null)
      : Promise.resolve(null),
  ]);
  const byteCoverage = report?.summary?.byte_coverage_pct;
  return {
    binary,
    functions: functions ? functions.functions : null,
    auto,
    pe,
    byteCoverage: typeof byteCoverage === "number" ? byteCoverage / 100 : null,
  };
}

function loadSummaries(binaries: BinaryListRow[]): Promise<BinarySummary[]> {
  return Promise.all(
    binaries.map((binary, index) =>
      index < SUMMARY_CAP
        ? summarize(binary, index < SECTION_CAP)
        : Promise.resolve({
            binary,
            functions: null,
            auto: null,
            pe: null,
            byteCoverage: null,
          }),
    ),
  );
}

// ── Panels ─────────────────────────────────────────────────────────

function SystemState({
  counts,
  changed,
}: {
  counts: Record<string, number>;
  changed: ReadonlySet<string>;
}): ReactNode {
  const total = counts.functions ?? 0;
  const matched = counts.matched ?? 0;
  return (
    <Panel
      title="System state"
      subtitle="Every registered row, refreshed while this view is open."
    >
      <div className="cockpit-strip">
        {STATS.map((stat) => (
          <Readout
            key={stat.key}
            label={stat.label}
            value={counts[stat.key] ?? 0}
            unit={stat.unit}
            hue={changed.has(`stat-${stat.key}`) ? "live" : undefined}
            className={changed.has(`stat-${stat.key}`) ? "flash" : undefined}
          />
        ))}
      </div>
      <SegmentMeter
        label="Coverage"
        value={total > 0 ? matched / total : null}
        readout={`${matched} / ${total}`}
        title={total > 0 ? undefined : "no functions registered"}
      />
    </Panel>
  );
}

function BinaryRow({
  summary,
  flashing,
}: {
  summary: BinarySummary;
  flashing: boolean;
}): ReactNode {
  const matched = matchedCount(summary.functions);
  const total = summary.functions ? summary.functions.length : null;
  const counts = statusChips(summary.functions);
  const chips = counts.slice(0, STATUS_CHIPS);
  const extra = counts.length - chips.length;
  return (
    <div className={flashing ? "cockpit-row flash" : "cockpit-row"}>
      <div className="cockpit-row-main">
        <a className="cockpit-name" href={`#/binaries/${summary.binary.id}`}>
          {summary.binary.name || `#${summary.binary.id}`}
        </a>
        <div className="cockpit-facts">
          <Badge mono>{summary.binary.format || NA}</Badge>
          <Badge mono>{summary.binary.arch || NA}</Badge>
          <span className="muted">{summary.binary.function_count} functions</span>
          {summary.auto ? <StatusCell status={summary.auto.status} /> : null}
        </div>
      </div>
      <SegmentMeter
        label="Match"
        value={total && matched !== null ? matched / total : null}
        readout={matched === null || total === null ? NA : `${matched} / ${total}`}
        title="byte-matched functions over all functions"
      />
      <div className="cockpit-status-chips">
        {chips.length === 0 ? (
          <Badge>{NA}</Badge>
        ) : (
          <>
            {chips.map(([status, count]) => (
              <Badge key={status} entity={statusEntity(status) ?? undefined} mono>
                {status} {count}
              </Badge>
            ))}
            {extra > 0 ? <Badge mono>+{extra}</Badge> : null}
          </>
        )}
      </div>
    </div>
  );
}

function BinaryPanel({
  summaries,
  changed,
}: {
  summaries: BinarySummary[];
  changed: ReadonlySet<string>;
}): ReactNode {
  const navigate = useNavigate();
  const truncated = summaries.length > SUMMARY_CAP;
  return (
    <Panel
      title="Binaries"
      subtitle={
        truncated
          ? `Function, match and status detail is loaded for the first ${SUMMARY_CAP} binaries; open Binaries for the rest.`
          : "Function counts, match meters and status breakdown per registered binary."
      }
      actions={
        <Button tone="ghost" onClick={() => navigate("/binaries")}>
          All binaries
        </Button>
      }
    >
      <div className="cockpit-binary-list">
        {summaries.map((summary) => (
          <BinaryRow
            key={summary.binary.id}
            summary={summary}
            flashing={changed.has(`binary-${summary.binary.id}`)}
          />
        ))}
      </div>
    </Panel>
  );
}

function SectionPanel({
  summary,
  flashing,
}: {
  summary: BinarySummary | null;
  flashing: boolean;
}): ReactNode {
  if (summary === null) {
    return (
      <Panel title="Section coverage" hue="stub">
        <EmptyState>No binary registered yet.</EmptyState>
      </Panel>
    );
  }
  const meters = sectionMeters(summary);
  return (
    <Panel
      title="Section coverage"
      hue="match"
      className={flashing ? "flash" : undefined}
      subtitle={`Matched function bytes inside each stored section of ${summary.binary.name}. Sections with no functions stay at zero.`}
    >
      {meters === null ? (
        <EmptyState>
          Unavailable: no stored PE details for this binary, so section bounds are unknown.
        </EmptyState>
      ) : (
        <div className="cockpit-strip">
          {meters.map((meter) => (
            <SegmentMeter
              key={meter.name}
              label={meter.name}
              value={meter.ratio}
              readout={`${meter.covered} / ${meter.size}`}
              title={`${meter.covered} matched bytes of ${meter.size}`}
            />
          ))}
        </div>
      )}
      {summary.byteCoverage === null ? (
        <p className="muted">Byte coverage: {UNAVAILABLE} (no stored report for this binary).</p>
      ) : (
        <SegmentMeter
          label="Byte coverage"
          value={summary.byteCoverage}
          readout={`${Math.round(summary.byteCoverage * 100)}%`}
          title="matched bytes over the reference text size, from the stored report"
        />
      )}
    </Panel>
  );
}

function RunPanel({
  summary,
  flashing,
}: {
  summary: BinarySummary | null;
  flashing: boolean;
}): ReactNode {
  const navigate = useNavigate();
  const run = summary?.auto ?? null;
  if (run === null) {
    return (
      <Panel title="Live run" hue="stub">
        <EmptyState>No auto run yet. Start one from Auto-mode.</EmptyState>
      </Panel>
    );
  }
  const running = run.status === "running";
  const progress = taskProgress(run);
  const task = currentTask(run.tree);
  const before = run.coverage_before;
  const after = run.coverage_after;
  return (
    <Panel
      title="Live run"
      hue={running ? "live" : run.status === "done" ? "match" : "fail"}
      className={[flashing ? "flash" : undefined, running ? "cockpit-live" : undefined]
        .filter(Boolean)
        .join(" ") || undefined}
      actions={
        <Button tone="ghost" onClick={() => navigate(`/auto/${run.binary_id}`)}>
          Open
        </Button>
      }
    >
      <div className="cockpit-run-line">
        {running ? <span className="live-dot" aria-hidden="true" /> : null}
        <StatusCell status={run.status} />
        <Badge mono>binary #{run.binary_id}</Badge>
        <Badge mono>{run.worker || NA}</Badge>
      </div>
      <SegmentMeter
        label="Run progress"
        value={progress.ratio}
        readout={`${progress.done} / ${progress.total}`}
        hue={running ? "live" : "match"}
      />
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
      <div className="cockpit-run-line">
        <span className="field-label">Current task</span>
        {task ? (
          <>
            <StatusCell status={task.status} />
            <span className="mono">{task.title}</span>
          </>
        ) : (
          <span className="muted">No task recorded.</span>
        )}
      </div>
    </Panel>
  );
}

function JournalTail({
  entries,
  changed,
}: {
  entries: JournalEntry[];
  changed: ReadonlySet<string>;
}): ReactNode {
  const navigate = useNavigate();
  return (
    <Panel
      title="Recent activity"
      subtitle="The newest journal entries, newest first."
      actions={
        <Button tone="ghost" onClick={() => navigate("/journal")}>
          Full journal
        </Button>
      }
    >
      {entries.length === 0 ? (
        <EmptyState>Nothing journaled yet. Every mutation records its inverse here.</EmptyState>
      ) : (
        <div className="journal-tail">
          {entries.map((entry) => (
            <div
              key={entry.id}
              className={
                changed.has(`journal-${entry.id}`) ? "journal-row flash" : "journal-row"
              }
            >
              <div>
                <a className="journal-action" href={`#/journal/${entry.action}`}>
                  {entry.action}
                </a>
                <div className="muted">{entry.description}</div>
              </div>
              <div className="journal-meta">
                <StatusCell status={entry.status} />
                <span>{entry.created_at}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function QuickLinks(): ReactNode {
  return (
    <Panel title="Jump to" subtitle="The main flows of a session.">
      <div className="quick-links">
        {QUICK_LINKS.map((link) => (
          <a href={link.href} key={link.href}>
            {link.label}
          </a>
        ))}
      </div>
    </Panel>
  );
}

// ── View ───────────────────────────────────────────────────────────

/**
 * One last coverage read when a run stops.  Without it the row would keep the
 * last in-flight value while the run card already shows the final one.
 */
function useCoverageSettle(active: boolean, reload: () => void): void {
  const wasActive = useRef(false);
  useEffect(() => {
    if (wasActive.current && !active) reload();
    wasActive.current = active;
  }, [active, reload]);
}

export function DashboardView(): ReactNode {
  const health = useAsync(() => api<Health>("/health"), [], true, HEALTH_POLL_MS);
  const list = useAsync(() => api<{ binaries: BinaryListRow[] }>("/binaries"), []);
  const journal = useAsync(
    () => api<JournalList>(`/journal?limit=${JOURNAL_TAIL}`),
    [],
    true,
    JOURNAL_POLL_MS,
  );
  const binaries = list.data?.binaries ?? null;
  const summaries = useAsync(
    () => loadSummaries(binaries ?? []),
    [binaries],
    binaries !== null,
    SUMMARY_REFRESH_MS,
  );

  // The run that is working right now is polled on its own, so a fast signal
  // redraws fast without refetching every binary.  The poll keeps its own view
  // of the run: once the run answers anything but `running`, polling stops even
  // though the last full summary still says it was running.
  const runningId =
    summaries.data?.find((entry) => entry.auto?.status === "running")?.binary.id ?? null;
  // Polling stops on the answer that ends the run: the interval is a function
  // of the query's own data, not of the summary the poll started from.
  const stillRunning = (status: string | undefined): boolean =>
    status === undefined || status === "running";
  const liveRun = useAsync(
    () => api<AutoRun>(`/binaries/${runningId}/auto`),
    [runningId],
    runningId !== null,
    (data) => (stillRunning(data?.status) ? RUN_POLL_MS : false),
  );
  const liveFunctions = useAsync(
    () => api<{ functions: FunctionRow[] }>(`/binaries/${runningId}/functions`),
    [runningId],
    runningId !== null,
    (data) => (data !== undefined && stillRunning(liveRun.data?.status) ? COVERAGE_POLL_MS : false),
  );
  const runIsRunning =
    runningId !== null && (liveRun.data === undefined || liveRun.data.status === "running");
  useCoverageSettle(runIsRunning, liveFunctions.reload);

  const counts = health.data?.counts ?? null;
  const entries = journal.data?.entries ?? null;

  const summaryRows: BinarySummary[] | null = summaries.data
    ? summaries.data.map((entry) => {
        if (runningId === null || entry.binary.id !== runningId) return entry;
        return {
          ...entry,
          auto: liveRun.data ?? entry.auto,
          functions: liveFunctions.data?.functions ?? entry.functions,
        };
      })
    : null;

  const changedStats = useChangedIds(
    STATS.map((stat) => [`stat-${stat.key}`, String(counts?.[stat.key] ?? "")]),
    counts !== null,
  );
  const changedBinaries = useChangedIds(
    (summaryRows ?? []).map((entry) => [
      `binary-${entry.binary.id}`,
      `${matchedCount(entry.functions)}:${entry.auto?.status ?? ""}:${entry.auto?.matched ?? ""}`,
    ]),
    summaryRows !== null,
  );
  const changedJournal = useChangedIds(
    (entries ?? []).map((entry) => [`journal-${entry.id}`, entry.status]),
    entries !== null,
  );

  const focus =
    summaryRows?.find((entry) => entry.binary.id === runningId) ?? summaryRows?.[0] ?? null;
  const focusRun =
    summaryRows?.find((entry) => entry.auto?.status === "running") ??
    summaryRows?.find((entry) => entry.auto !== null) ??
    summaryRows?.[0] ??
    null;
  const changedFocus = useChangedIds(
    [
      [
        "focus",
        focus === null
          ? ""
          : `${focus.binary.id}:${focus.byteCoverage ?? NA}:${matchedCount(focus.functions) ?? NA}`,
      ],
    ],
    focus !== null,
  );

  if (health.error) {
    return (
      <Panel title="Dashboard">
        <ErrorNote error={health.error} onRetry={health.reload} />
      </Panel>
    );
  }
  if (counts === null || summaryRows === null) {
    return (
      <Panel title="Dashboard">
        <Loading label="Loading the dashboard" rows={4} />
      </Panel>
    );
  }

  return (
    <div className="cockpit">
      <div className="cockpit-col">
        <SystemState counts={counts} changed={changedStats} />
        <BinaryPanel summaries={summaryRows} changed={changedBinaries} />
        <SectionPanel summary={focus} flashing={changedFocus.has("focus")} />
      </div>
      <div className="cockpit-col cockpit-rail">
        <QuickLinks />
        <RunPanel
          summary={focusRun}
          flashing={changedBinaries.has(`binary-${focusRun?.binary.id ?? -1}`)}
        />
        <JournalTail entries={entries ?? []} changed={changedJournal} />
      </div>
    </div>
  );
}

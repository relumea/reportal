// Shared UI primitives.  Every view builds on these: Panel, Toolbar, Button,
// Badge, Field, EmptyState, Loading, ErrorNote, Note, CodeBlock, KeyValue,
// DataTable, SegmentMeter, Readout and the small text helpers.  Styling lives
// in styles.css under the matching class names, driven by the token layer;
// the semantic hue names live in design.ts.

import {
  Fragment,
  createContext,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import type { KeyboardEvent, MouseEvent, ReactNode } from "react";

import { errorText, isApiErrorCode } from "./api";
import {
  METER_SEGMENTS,
  RAMP_STEPS,
  categoryHue,
  levelOf,
  nameSourceHue,
  statusEntity,
} from "./design";
import type { HueFamily, Level, StatusEntity } from "./design";
import type { PanelEntry } from "./panelCache";

export const NA = "n/a";

/** Value shown in place of one the source does not provide (rule 25). */
export const UNAVAILABLE = "Unavailable";

export function hex(value: number): string {
  return `0x${Number(value).toString(16)}`;
}

export function cellText(value: unknown): ReactNode {
  if (value === null || value === undefined) return null;
  if (typeof value === "string" || typeof value === "number") return value;
  return String(value);
}

// ── Text helpers ───────────────────────────────────────────────────

export function Muted({
  children,
  live = false,
}: {
  children: ReactNode;
  /** Announce this line when it appears; for the result of a write a reader cannot see. */
  live?: boolean;
}): ReactNode {
  return (
    <p className="muted" role={live ? "status" : undefined}>
      {children}
    </p>
  );
}

/**
 * The engine credit for an AI artifact, or nothing at all.
 *
 * The server redacts the backend model for a tenant (`disclosure.py`), so the
 * field is absent rather than empty for most callers: rendering "model:" with
 * nothing after it would show the redaction instead of hiding it.  An operator,
 * who does receive the name, still sees it.
 */
export function EngineNote({ model }: { model?: string | null }): ReactNode {
  if (!model) return null;
  return <Muted>engine: {model}</Muted>;
}

/** Monospace value with its own copy control; `NA` when the value is empty. */
export function CopyValue({
  value,
  compact,
}: {
  value: string | null | undefined;
  /** Show the first 12 characters; the copy control still writes the full value. */
  compact?: boolean;
}): ReactNode {
  if (!value) return NA;
  const shown = compact && value.length > 12 ? `${value.slice(0, 12)}…` : value;
  return (
    <span className="copy-row">
      <span className="mono" title={compact ? value : undefined}>
        {shown}
      </span>
      <CopyButton text={value} />
    </span>
  );
}

const IDENTICON_CELLS = 5;

function identiconBits(hash: string): boolean[] {
  const cells: boolean[] = [];
  for (let i = 0; i < IDENTICON_CELLS * 3; i += 1) {
    const nibble = Number.parseInt(hash[i] ?? "0", 16);
    cells.push((nibble & 1) === 1);
  }
  return cells;
}

/** 5×5 hash identicon from a hex digest. Symmetric so a SHA-256 looks like a face. */
export function HashIdenticon({ hash }: { hash: string }): ReactNode {
  const bits = identiconBits(hash);
  const hue = Number.parseInt(hash.slice(0, 2) || "0", 16);
  const color = `hsl(${hue} 42% 46%)`;
  const cells: ReactNode[] = [];
  for (let row = 0; row < IDENTICON_CELLS; row += 1) {
    for (let col = 0; col < IDENTICON_CELLS; col += 1) {
      const mirror = col > 2 ? 4 - col : col;
      const on = bits[row * 3 + mirror] === true;
      cells.push(
        <span
          key={`${row}-${col}`}
          className={on ? "hash-identicon-cell on" : "hash-identicon-cell"}
        />,
      );
    }
  }
  return (
    <span className="hash-identicon" aria-hidden="true" style={{ color }}>
      {cells}
    </span>
  );
}

// ── Buttons ────────────────────────────────────────────────────────

type ButtonTone = "default" | "primary" | "ghost" | "danger";

/** Tab-order controls inside *root*, skipping aria-hidden and visually empty nodes. */
export function focusableElements(root: HTMLElement): HTMLElement[] {
  const selector =
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  return Array.from(root.querySelectorAll<HTMLElement>(selector)).filter((element) => {
    if (element.closest('[aria-hidden="true"]')) return false;
    return element.getClientRects().length > 0;
  });
}

/**
 * Keep Tab cycling inside *root* (WCAG 2.1.2).  Call from a dialog's keydown;
 * Escape and other keys are the caller's.
 */
export function trapTabKey(
  event: { key: string; shiftKey: boolean; preventDefault: () => void },
  root: HTMLElement,
): void {
  if (event.key !== "Tab") return;
  const nodes = focusableElements(root);
  if (nodes.length === 0) {
    event.preventDefault();
    root.focus();
    return;
  }
  const first = nodes[0];
  const last = nodes[nodes.length - 1];
  const active = document.activeElement;
  if (event.shiftKey) {
    if (active === first || !(active instanceof Node) || !root.contains(active)) {
      event.preventDefault();
      last.focus();
    }
  } else if (active === last || !(active instanceof Node) || !root.contains(active)) {
    event.preventDefault();
    first.focus();
  }
}

export function Button({
  children,
  onClick,
  tone = "default",
  size = "md",
  type = "button",
  disabled = false,
  pending = false,
  title,
  "aria-label": ariaLabel,
}: {
  children: ReactNode;
  onClick?: () => void;
  tone?: ButtonTone;
  size?: "sm" | "md";
  type?: "button" | "submit";
  disabled?: boolean;
  /** Show a spinner and disable the control while work is in flight. */
  pending?: boolean;
  title?: string;
  "aria-label"?: string;
}): ReactNode {
  const classes = ["btn"];
  if (tone !== "default") classes.push(`btn-${tone}`);
  if (size === "sm") classes.push("btn-sm");
  if (pending) classes.push("btn-pending");
  return (
    <button
      type={type}
      className={classes.join(" ")}
      disabled={disabled || pending}
      aria-busy={pending || undefined}
      aria-label={ariaLabel}
      title={title}
      onClick={onClick}
    >
      {pending ? <span className="btn-spinner" aria-hidden="true" /> : null}
      {children}
    </button>
  );
}

function CopyButton({ text }: { text: string }): ReactNode {
  const [copied, setCopied] = useState(false);
  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <Button size="sm" tone="ghost" onClick={() => void copy()}>
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

/** A destructive action behind an inline confirmation step, never a modal. */
export function ConfirmButton({
  label,
  confirmLabel,
  message,
  onConfirm,
  pending = false,
  disabled = false,
}: {
  label: string;
  confirmLabel?: string;
  message: string;
  onConfirm: () => void;
  pending?: boolean;
  disabled?: boolean;
}): ReactNode {
  const [confirming, setConfirming] = useState(false);
  const groupRef = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!confirming) return;
    groupRef.current?.querySelector<HTMLButtonElement>("button")?.focus();
  }, [confirming]);
  if (!confirming) {
    return (
      <Button
        tone="danger"
        size="sm"
        disabled={disabled}
        pending={pending}
        onClick={() => setConfirming(true)}
      >
        {label}
      </Button>
    );
  }
  return (
    <span
      ref={groupRef}
      className="confirm"
      role="group"
      aria-label={message}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          setConfirming(false);
        }
      }}
    >
      <span className="confirm-text" role="status">
        {message}
      </span>
      <Button
        tone="danger"
        size="sm"
        pending={pending}
        onClick={() => {
          setConfirming(false);
          onConfirm();
        }}
      >
        {confirmLabel ?? label}
      </Button>
      <Button size="sm" tone="ghost" onClick={() => setConfirming(false)}>
        Cancel
      </Button>
    </span>
  );
}

// ── Badges ─────────────────────────────────────────────────────────

export type BadgeTone = "neutral" | "ok" | "warn" | "danger" | "info" | "accent" | "insert" | "delete";

/** Hue a badge may carry: a status family, or the confidence/severity scale. */
type BadgeHue = HueFamily | "confidence" | "severity";

export function Badge({
  children,
  tone = "neutral",
  mono = false,
  title,
  hue,
  entity,
  level,
}: {
  children: ReactNode;
  tone?: BadgeTone;
  mono?: boolean;
  title?: string;
  /** Family hue, or the confidence/severity scale. */
  hue?: BadgeHue;
  /** Status entity whose ink token the badge uses. */
  entity?: StatusEntity;
  /** Level on a confidence or severity scale. */
  level?: Level;
}): ReactNode {
  const classes = ["badge", `badge-${tone}`];
  if (mono) classes.push("badge-mono");
  return (
    <span
      className={classes.join(" ")}
      title={title}
      data-hue={hue}
      data-status={entity}
      data-level={level}
    >
      {children}
    </span>
  );
}

export function StatusCell({ status }: { status?: string | null }): ReactNode {
  const label = status || "unknown";
  return <Badge entity={statusEntity(label) ?? undefined}>{label}</Badge>;
}

/** Coloured name-source dot; hosted Functions list uses this beside the name. */
export function NameSourceDot({ label }: { label: string }): ReactNode {
  const hue = nameSourceHue(label);
  return (
    <span
      className={hue ? "name-source-dot" : "name-source-dot idle"}
      data-hue={hue ?? undefined}
      title={label}
      aria-label={label}
    />
  );
}

export function ConfidenceBadge({ level }: { level: string }): ReactNode {
  const key = levelOf(level);
  if (!key) return <Badge>{level || NA}</Badge>;
  return (
    <Badge hue="confidence" level={key}>
      {level}
    </Badge>
  );
}

export function SeverityBadge({ level }: { level: string }): ReactNode {
  const key = levelOf(level);
  if (!key) return <Badge>{level || NA}</Badge>;
  return (
    <Badge hue="severity" level={key}>
      {level}
    </Badge>
  );
}

export function CategoryBadge({ category }: { category: string }): ReactNode {
  const hue = categoryHue(category);
  return <Badge hue={hue ?? undefined}>{category}</Badge>;
}

// ── Instruments: meters and readouts ───────────────────────────────

/** The ramp step a lit segment sits on, 1 (cold) to RAMP_STEPS (matched). */
function rampStep(index: number): number {
  return Math.min(RAMP_STEPS, Math.floor((index * RAMP_STEPS) / METER_SEGMENTS) + 1);
}

/**
 * A quantized level meter: discrete segments, the unlit remainder always
 * visible, and a numeric readout in a fixed position beside it.  `value` is
 * 0..1, or null when the source has no value, which renders `missing` instead
 * of a zero the source never reported.
 */
export function SegmentMeter({
  label,
  value,
  readout,
  hue,
  level,
  missing = NA,
  band,
  title,
}: {
  label: string;
  value: number | null;
  /** Readout text; defaults to the value as a percentage. */
  readout?: ReactNode;
  /** Family hue for the lit segments; omitted uses the sequential ramp. */
  hue?: HueFamily;
  /**
   * Severity intensity for the lit segments, for a meter on the severity scale
   * (the threat score).  Takes precedence over `hue` when both are given.
   */
  level?: Level;
  missing?: string;
  /** Fraction range (0..1) marked as a reference band along the track bottom. */
  band?: { from: number; to: number };
  title?: string;
}): ReactNode {
  const clamped = value === null ? 0 : Math.min(1, Math.max(0, value));
  const lit = value === null || clamped <= 0 ? 0 : Math.max(1, Math.round(clamped * METER_SEGMENTS));
  const percent = Math.round(clamped * 100);
  return (
    <div
      className="meter"
      data-hue={hue}
      data-level={level}
      data-missing={value === null ? "true" : undefined}
      title={title}
    >
      <div className="meter-head">
        <span className="meter-label">{label}</span>
        <span className="meter-value">{value === null ? missing : (readout ?? `${percent}%`)}</span>
      </div>
      <div className="meter-track" aria-hidden="true">
        {Array.from({ length: METER_SEGMENTS }, (_unused, index) => {
          const on = index < lit;
          return (
            <span
              key={index}
              className="meter-seg"
              data-lit={on ? "true" : undefined}
              data-step={on && !hue ? String(rampStep(index)) : undefined}
              data-band={inBand(index, band) ? "true" : undefined}
            />
          );
        })}
      </div>
    </div>
  );
}

/** Whether segment *index* falls inside the `band` fraction range. */
function inBand(index: number, band?: { from: number; to: number }): boolean {
  if (!band) return false;
  const position = (index + 0.5) / METER_SEGMENTS;
  return position >= band.from && position <= band.to;
}

/** A headline number with its label and unit; `missing` when there is none. */
export function Readout({
  label,
  value,
  unit,
  hue,
  className,
  missing = NA,
}: {
  label: string;
  value: ReactNode | null | undefined;
  unit?: string;
  hue?: HueFamily;
  /** Extra classes, e.g. the change flash. */
  className?: string;
  missing?: string;
}): ReactNode {
  const empty = value === null || value === undefined || value === "";
  return (
    <div
      className={className ? `readout ${className}` : "readout"}
      data-hue={hue}
      data-missing={empty ? "true" : undefined}
    >
      <div className="readout-value">
        {empty ? missing : value}
        {empty || !unit ? null : <span className="readout-unit">{unit}</span>}
      </div>
      <div className="readout-label">{label}</div>
    </div>
  );
}

// ── Fields ─────────────────────────────────────────────────────────

/** A named type that exists in this binary's model, linking to `?search=`. */
export function TypeNameLink({
  binaryId,
  name,
  knownTypes,
  fallback = true,
}: {
  binaryId: number;
  name: string;
  knownTypes: Set<string>;
  /** When false, an unknown name renders nothing (an input already shows it). */
  fallback?: boolean;
}): ReactNode {
  const ident = name.replace(/(?:\s*(?:\*+|\[\d*\]))+$/g, "").trim();
  if (!ident || !knownTypes.has(ident)) return fallback ? name : null;
  return (
    <a href={`#/binaries/${binaryId}?search=${encodeURIComponent(ident)}`} title={`Show type ${ident}`}>
      {name}
    </a>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}): ReactNode {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

export function CheckboxField({
  label,
  checked,
  disabled = false,
  onChange,
}: {
  label: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}): ReactNode {
  return (
    <label className="checkbox-field">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      {label}
    </label>
  );
}

export function Toolbar({ children }: { children: ReactNode }): ReactNode {
  return <div className="toolbar">{children}</div>;
}

// ── Feedback ───────────────────────────────────────────────────────

export function Loading({ label, rows = 3 }: { label: string; rows?: number }): ReactNode {
  return (
    <div className="skeleton" role="status" aria-label={label}>
      {Array.from({ length: rows }, (_unused, index) => (
        <div className="skeleton-row" key={index} />
      ))}
    </div>
  );
}

export function Note({
  children,
  tone = "info",
}: {
  children: ReactNode;
  tone?: "info" | "warn" | "error";
}): ReactNode {
  const toneClass = tone === "info" ? "note-info" : tone === "warn" ? "note-warn" : "note-error";
  return (
    <div className={`note ${toneClass}`}>
      <p className="note-text">{children}</p>
    </div>
  );
}

export function ErrorNote({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}): ReactNode {
  return (
    <div className="note note-error" role="alert">
      <p className="note-text">{errorText(error)}</p>
      {isApiErrorCode(error, "quota-exceeded") ? (
        <p className="note-text">
          <a className="back-link" href="#/billing">
            Open Billing to upgrade.
          </a>
        </p>
      ) : null}
      {onRetry ? (
        <Button size="sm" tone="ghost" onClick={onRetry}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}

export function EmptyState({
  children,
  action,
}: {
  children: ReactNode;
  action?: ReactNode;
}): ReactNode {
  return (
    <div className="empty-state" role="status">
      <p>{children}</p>
      {action}
    </div>
  );
}

// ── Code ───────────────────────────────────────────────────────────

export function CodeBlock({ text, title }: { text: string; title?: string }): ReactNode {
  const [copied, setCopied] = useState(false);
  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="code-block">
      <div className="code-head">
        <span className="code-title">{title ?? "output"}</span>
        <CopyButton text={text} />
      </div>
      <pre
        className="code-scroll"
        title="Click to copy"
        onClick={() => void copy()}
      >
        {text}
      </pre>
      {copied ? <span className="muted">Copied</span> : null}
    </div>
  );
}

// ── Key/value ──────────────────────────────────────────────────────

export function KeyValue({ rows }: { rows: Array<[string, ReactNode]> }): ReactNode {
  return (
    <div className="kv">
      {rows.map(([field, value], index) => (
        <Fragment key={`${field}-${index}`}>
          <div className="kv-key">{field}</div>
          <div className="kv-value">{value}</div>
        </Fragment>
      ))}
    </div>
  );
}

export function RawJson({ value }: { value: unknown }): ReactNode {
  return (
    <details>
      <summary>Raw JSON</summary>
      <CodeBlock text={JSON.stringify(value, null, 2)} title="json" />
    </details>
  );
}

/** The heading id of the nearest `Panel`, which names the tables inside it. */
const PanelHeading = createContext<string | null>(null);

// ── Table ──────────────────────────────────────────────────────────

export interface Column<T> {
  label: string;
  key?: keyof T;
  /** Header content in place of `label`, e.g. a sort control; `label` stays the key. */
  header?: ReactNode;
  render?: (row: T, index: number) => ReactNode;
  /** Right-aligned tabular numerics in the monospace face. */
  numeric?: boolean;
  /** Render the raw value in the monospace face. */
  mono?: boolean;
  /**
   * The sorted state of this column, for the `aria-sort` a reader needs to hear
   * which column orders the table and in which direction.  A sort control in
   * `header` must set it, since the glyph alone is not announced.
   */
  sort?: "ascending" | "descending" | "none";
}

function isInteractive(target: EventTarget | null): boolean {
  return (
    target instanceof Element &&
    target.closest("a, button, input, select, textarea, label") !== null
  );
}

/** Rows a table renders before it starts windowing.  Below it every row is in
 *  the DOM, which is what the small tables want (their rows are found by text,
 *  by the browser's own find, and by a reader scrolling a short list). */
const WINDOW_THRESHOLD = 200;

/** Rows kept above and below the viewport, so a fast scroll shows content. */
const WINDOW_OVERSCAN = 20;

/** The height the window assumes a row has, in pixels.  A windowed table's rows
 *  are one line each; the first render measures the real height and uses it. */
const WINDOW_ROW_HEIGHT = 28;

/** The visible slice of *total* rows for a container scrolled to *top*. */
function windowRange(
  total: number,
  top: number,
  viewport: number,
  rowHeight: number,
): { start: number; end: number } {
  const visible = Math.max(1, Math.ceil(viewport / rowHeight));
  const first = Math.max(0, Math.floor(top / rowHeight) - WINDOW_OVERSCAN);
  return { start: first, end: Math.min(total, first + visible + WINDOW_OVERSCAN * 2) };
}

export function DataTable<T>({
  columns,
  rows,
  onRowClick,
  rowKey,
  rowClassName,
  empty,
  windowed = false,
  label,
}: {
  columns: Array<Column<T>>;
  rows: T[];
  onRowClick?: (row: T) => void;
  rowKey?: (row: T, index: number) => string | number;
  /** Extra classes for a row, e.g. the change flash. */
  rowClassName?: (row: T, index: number) => string | undefined;
  /** Rendered in place of the table when there are no rows. */
  empty?: ReactNode;
  /** Render only the visible rows.  For a table whose rows are one line and
   *  whose list can be thousands long: a 20k-row binary otherwise puts 20k rows
   *  and 300k nodes in the DOM.  Requires uniform row heights, so it is opt-in
   *  per table rather than the default. */
  windowed?: boolean;
  /** The table's accessible name; the enclosing `Panel` heading when omitted. */
  label?: string;
}): ReactNode {
  const active = windowed && rows.length > WINDOW_THRESHOLD;
  const panelHeading = useContext(PanelHeading);
  const scroll = useRef<HTMLDivElement | null>(null);
  const [rowHeight, setRowHeight] = useState(WINDOW_ROW_HEIGHT);
  const [range, setRange] = useState({ start: 0, end: Math.min(rows.length, WINDOW_THRESHOLD) });

  // Measure one rendered row, so the window follows the stylesheet rather than
  // a number kept in two places.  A spacer carries the height of the rows it
  // stands in for, so it is skipped: only a real row is the unit to measure.
  useLayoutEffect(() => {
    if (!active) return;
    const row = scroll.current?.querySelector("tbody tr:not([aria-hidden])");
    const height = row?.getBoundingClientRect().height ?? 0;
    if (height >= 8 && Math.abs(height - rowHeight) > 0.5) setRowHeight(height);
  }, [active, rowHeight, rows]);

  useEffect(() => {
    if (!active) return;
    const container = scroll.current;
    if (container === null) return;
    const update = (): void => {
      setRange(
        windowRange(rows.length, container.scrollTop, container.clientHeight, rowHeight),
      );
    };
    update();
    container.addEventListener("scroll", update, { passive: true });
    const observer = new ResizeObserver(update);
    observer.observe(container);
    return () => {
      container.removeEventListener("scroll", update);
      observer.disconnect();
    };
  }, [active, rows.length, rowHeight]);

  if (!rows.length && empty !== undefined) return empty;
  const start = active ? range.start : 0;
  const end = active ? range.end : rows.length;
  const visible = rows.slice(start, end);
  const pad = (height: number): ReactNode =>
    height <= 0 ? null : (
      <tr aria-hidden="true">
        <td colSpan={columns.length} style={{ height, padding: 0, border: 0 }} />
      </tr>
    );
  return (
    <div className="table-scroll" ref={scroll}>
      {/* The window leaves most rows out of the DOM, so the count tells a
          reader how long the list is and each row says where it sits in it.
          The name comes from the panel heading unless the call site names it. */}
      <table
        className="data-table"
        aria-rowcount={rows.length + 1}
        aria-label={label}
        aria-labelledby={label === undefined ? (panelHeading ?? undefined) : undefined}
      >
        <thead>
          <tr aria-rowindex={1}>
            {columns.map((column) => (
              <th
                key={column.label}
                className={column.numeric ? "num" : undefined}
                aria-sort={column.sort}
              >
                {column.header ?? column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {active ? pad(start * rowHeight) : null}
          {visible.map((row, offset) => {
            const index = start + offset;
            return (
            <tr
              key={rowKey ? rowKey(row, index) : index}
              className={
                [onRowClick ? "clickable" : undefined, rowClassName?.(row, index)]
                  .filter(Boolean)
                  .join(" ") || undefined
              }
              tabIndex={onRowClick ? 0 : undefined}
              aria-rowindex={index + 2}
              onClick={
                onRowClick
                  ? (event: MouseEvent<HTMLTableRowElement>) => {
                      if (isInteractive(event.target)) return;
                      onRowClick(row);
                    }
                  : undefined
              }
              onKeyDown={
                onRowClick
                  ? (event: KeyboardEvent<HTMLTableRowElement>) => {
                      if (event.key !== "Enter" && event.key !== " ") return;
                      if (isInteractive(event.target)) return;
                      event.preventDefault();
                      onRowClick(row);
                    }
                  : undefined
              }
            >
              {columns.map((column) => {
                const classes: string[] = [];
                if (column.numeric) classes.push("num");
                if (column.mono) classes.push("mono-cell");
                return (
                  <td key={column.label} className={classes.length ? classes.join(" ") : undefined}>
                    {column.render
                      ? column.render(row, index)
                      : cellText(column.key ? row[column.key] : null)}
                  </td>
                );
              })}
            </tr>
            );
          })}
          {active ? pad((rows.length - end) * rowHeight) : null}
        </tbody>
      </table>
    </div>
  );
}

// ── Panels ─────────────────────────────────────────────────────────

export function Panel({
  title,
  subtitle,
  actions,
  hue,
  className,
  collapsible = false,
  children,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  /** Tints the card border with the panel's own data hue. */
  hue?: HueFamily;
  /** Extra classes, e.g. the change flash or a cockpit column span. */
  className?: string;
  /** Start folded; the heading and actions stay visible. */
  collapsible?: boolean;
  children?: ReactNode;
}): ReactNode {
  // The heading names the tables inside the panel, so a reader entering one
  // hears which list it is without the call site repeating the title.
  const titleId = useId();
  const [open, setOpen] = useState(!collapsible);
  return (
    <section
      className={className ? `panel ${className}` : "panel"}
      data-hue={hue}
      tabIndex={-1}
    >
      <div className="panel-head">
        <div className="panel-heading">
          <h2 className="panel-title" id={titleId}>
            {collapsible ? (
              <button
                type="button"
                className="panel-fold"
                aria-expanded={open}
                onClick={() => setOpen((value) => !value)}
              >
                {title}
              </button>
            ) : (
              title
            )}
          </h2>
          {subtitle ? <div className="panel-subtitle">{subtitle}</div> : null}
        </div>
        {actions ? <div className="panel-actions">{actions}</div> : null}
      </div>
      {open ? (
        <div className="panel-body">
          <PanelHeading.Provider value={titleId}>{children}</PanelHeading.Provider>
        </div>
      ) : null}
    </section>
  );
}

/** A nested card for repeated records inside a panel (one data type, one run). */
export function Card({
  title,
  actions,
  hue,
  className,
  children,
}: {
  title: ReactNode;
  actions?: ReactNode;
  /** Tints the card border with the card's own data hue. */
  hue?: HueFamily;
  className?: string;
  children: ReactNode;
}): ReactNode {
  // A table inside the card is named by the card's own title, which is closer
  // to it than the panel heading outside.
  const titleId = useId();
  return (
    <div className={className ? `card ${className}` : "card"} data-hue={hue}>
      <div className="card-head">
        <div className="card-title" id={titleId}>
          {title}
        </div>
        {actions ? <div className="panel-actions">{actions}</div> : null}
      </div>
      <PanelHeading.Provider value={titleId}>{children}</PanelHeading.Provider>
    </div>
  );
}

export function PanelBody<T>({
  entry,
  hint,
  noScanHint,
  onRetry,
  children,
}: {
  entry: PanelEntry<T> | undefined;
  hint: string;
  noScanHint?: string;
  onRetry?: () => void;
  children: (data: T) => ReactNode;
}): ReactNode {
  if (!entry || entry.state === "loading") return <Loading label={hint || "Loading"} />;
  if (entry.state === "error") {
    if (noScanHint && isApiErrorCode(entry.error, "no-scan")) {
      return <EmptyState>{noScanHint}</EmptyState>;
    }
    return <ErrorNote error={entry.error} onRetry={onRetry} />;
  }
  return children(entry.data);
}

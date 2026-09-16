import { useEffect, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";

import { api } from "../api";
import {
  Button,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  KeyValue,
  Muted,
  NA,
  Note,
  Panel,
  PanelBody,
  Toolbar,
  hex,
} from "../components";
import {
  MEMORY_ADDRESS_KINDS,
  MEMORY_BYTES_PER_ROW,
  MEMORY_COLUMN_STORAGE_KEY,
  MEMORY_PAGE_DEFAULT,
  MEMORY_PAGE_MAX,
  MEMORY_READ_DEFAULT,
  MEMORY_READ_MAX,
  MEMORY_SCROLL_OVERSCAN,
  MEMORY_SCROLL_WINDOW,
  type MemoryAddressKind,
} from "../constants";
import { panelKey, useLazyPanel } from "../panelCache";
import type { MemoryPage, MemoryPageRow, MemoryPageSection, MemoryWindow } from "../types";

// Printable ASCII range the gutter renders literally; everything else is a dot.
const PRINTABLE_MIN = 0x20;
const PRINTABLE_MAX = 0x7e;

// The full-file view's addressing kinds, spelled the way the hosted portal
// labels them: a virtual address or a raw file offset.
type GotoKind = "va" | "file";
const GOTO_KINDS: readonly { value: GotoKind; label: string }[] = [
  { value: "va", label: "Virtual" },
  { value: "file", label: "Offset" },
];

// A read is on demand, so the panel starts with the address it needs rather
// than a guess or a fabricated zero window.
const NO_READ_HINT = "Enter an address and read a window of this binary's bytes.";
const ADDRESS_REQUIRED = "An address is required before reading";

/** Parse a lowercase hex window into its bytes. */
function bytesOf(hexText: string): number[] {
  const bytes: number[] = [];
  for (let index = 0; index + 1 < hexText.length; index += 2) {
    const value = Number.parseInt(hexText.slice(index, index + 2), 16);
    bytes.push(Number.isNaN(value) ? 0 : value);
  }
  return bytes;
}

/** The gutter character for one byte: itself when printable, else a dot. */
function gutterOf(byte: number): string {
  return byte >= PRINTABLE_MIN && byte <= PRINTABLE_MAX ? String.fromCharCode(byte) : ".";
}

/** One grid row: its virtual address when the read was addressed by one, bytes, gutter. */
interface MemoryRow {
  address: number | null;
  hex: string;
  gutter: string;
}

/** Split a window into 16-byte rows, numbering them from the window's VA. */
function gridRows(window: MemoryWindow): MemoryRow[] {
  const bytes = bytesOf(window.bytes);
  const start = window.va === null ? null : Number.parseInt(window.va, 16);
  const rows: MemoryRow[] = [];
  for (let offset = 0; offset < bytes.length; offset += MEMORY_BYTES_PER_ROW) {
    const slice = bytes.slice(offset, offset + MEMORY_BYTES_PER_ROW);
    rows.push({
      address: start === null || Number.isNaN(start) ? null : start + offset,
      hex: slice.map((byte) => byte.toString(16).padStart(2, "0")).join(" "),
      gutter: slice.map(gutterOf).join(""),
    });
  }
  return rows;
}

/** One byte of a page's bytes rows, with the address it sits at. */
interface PageByte {
  address: number;
  value: number;
}

/** The page's addressed bytes, in row order; gap rows contribute nothing. */
function pageBytes(page: MemoryPage): PageByte[] {
  const bytes: PageByte[] = [];
  for (const row of page.rows) {
    if (row.kind !== "bytes" || row.hex === undefined) continue;
    const start = Number.parseInt(row.address, 16);
    for (const [offset, value] of bytesOf(row.hex).entries()) {
      bytes.push({ address: start + offset, value });
    }
  }
  return bytes;
}

/** Render a byte list as space-separated hex pairs (`4d 5a 90`). */
export function hexCopy(bytes: number[]): string {
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join(" ");
}

/** Render a byte list as a C array initializer (`0x4d, 0x5a, 0x90`). */
export function cArrayCopy(bytes: number[]): string {
  return bytes.map((byte) => `0x${byte.toString(16).padStart(2, "0")}`).join(", ");
}

export function MemoryPanel({
  binaryId,
  focus,
}: {
  binaryId: number;
  /** An address from the route hash, linked from the section table. */
  focus?: string;
}): ReactNode {
  const [mode, setMode] = useState<"window" | "file" | "continuous">(
    focus === undefined ? "window" : "continuous",
  );
  // A section address linked from the same page changes the hash without
  // remounting the view, so the mode follows the link rather than only the
  // first render.
  useEffect(() => {
    if (focus !== undefined) setMode("continuous");
  }, [focus]);
  return (
    <Panel
      title="Memory"
      subtitle="Read a window of this binary's bytes at an address, page through the whole file, or scroll one continuous dump, all located through the engine's own section table."
    >
      <Toolbar>
        <Field label="Mode">
          <select
            value={mode}
            onChange={(event) => {
              const next = event.target.value;
              setMode(next === "file" ? "file" : next === "continuous" ? "continuous" : "window");
            }}
          >
            <option value="window">Window</option>
            <option value="file">Full file</option>
            <option value="continuous">Whole binary</option>
          </select>
        </Field>
      </Toolbar>
      {mode === "window" ? (
        <WindowMode binaryId={binaryId} />
      ) : mode === "file" ? (
        <FileMode binaryId={binaryId} />
      ) : (
        <ContinuousMode binaryId={binaryId} focus={focus} />
      )}
    </Panel>
  );
}

function WindowMode({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "memory");
  const [entry, load] = useLazyPanel<MemoryWindow>(key);
  const [address, setAddress] = useState("");
  const [kind, setKind] = useState<MemoryAddressKind>("va");
  const [length, setLength] = useState(String(MEMORY_READ_DEFAULT));
  const [attempted, setAttempted] = useState(false);

  const read = (): Promise<MemoryWindow> => {
    const size = Number.parseInt(length, 10);
    const bounded = Number.isNaN(size) ? MEMORY_READ_DEFAULT : size;
    const query = `va=${encodeURIComponent(address.trim())}&length=${bounded}&kind=${kind}`;
    return api<MemoryWindow>(`/binaries/${binaryId}/memory?${query}`);
  };

  const missingAddress = address.trim() === "";

  return (
    <>
      <Toolbar>
        <Field label="Address">
          <input
            type="text"
            placeholder="0x401000"
            value={address}
            onChange={(event) => setAddress(event.target.value)}
          />
        </Field>
        <Field label="Kind">
          <select value={kind} onChange={(event) => setKind(event.target.value as MemoryAddressKind)}>
            {MEMORY_ADDRESS_KINDS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Length">
          <input
            type="number"
            min="1"
            max={String(MEMORY_READ_MAX)}
            value={length}
            onChange={(event) => setLength(event.target.value)}
          />
        </Field>
        <Button
          tone="primary"
          disabled={missingAddress}
          title={missingAddress ? ADDRESS_REQUIRED : undefined}
          onClick={() => {
            setAttempted(true);
            load(read);
          }}
        >
          Read
        </Button>
      </Toolbar>
      {!attempted ? (
        <Note>{NO_READ_HINT}</Note>
      ) : (
        <PanelBody entry={entry} hint="Reading the window" onRetry={() => load(read)}>
          {(window) =>
            window.length === 0 ? (
              <EmptyState>The engine returned no bytes for that address.</EmptyState>
            ) : (
              <MemoryBody window={window} />
            )
          }
        </PanelBody>
      )}
      <Muted>
        At most {MEMORY_READ_MAX} bytes per read, located through the engine&apos;s section table. An
        address without backing bytes, a header-only RVA or a section&apos;s uninitialized tail is
        refused rather than filled in.
      </Muted>
    </>
  );
}

function MemoryBody({ window }: { window: MemoryWindow }): ReactNode {
  const rows = gridRows(window);
  return (
    <>
      <KeyValue
        rows={[
          ["address", window.address],
          ["kind", window.kind],
          ["virtual address", window.va ?? NA],
          ["section", window.section ?? NA],
          ["bytes", String(window.length)],
        ]}
      />
      <DataTable
        columns={[
          {
            label: "Address",
            mono: true,
            numeric: true,
            render: (row) => (row.address === null ? NA : `0x${row.address.toString(16)}`),
          },
          { label: "Bytes", mono: true, render: (row) => row.hex },
          { label: "ASCII", mono: true, render: (row) => row.gutter },
        ]}
        rows={rows}
        rowKey={(row, index) => `${row.address ?? "file"}-${index}`}
      />
    </>
  );
}

/** A byte range of the page selected by its addresses. */
interface Selection {
  start: number;
  end: number;
}

/** Shift-extend from *anchor*, or start a new one-byte selection at *address*. */
function extendSelection(
  anchor: number | null,
  address: number,
  extend: boolean,
): { anchor: number; selection: Selection } {
  if (anchor === null || !extend) {
    return { anchor: address, selection: { start: address, end: address } };
  }
  return {
    anchor,
    selection: { start: Math.min(anchor, address), end: Math.max(anchor, address) },
  };
}

function FileMode({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "memory-page");
  const [entry, load] = useLazyPanel<MemoryPage>(key);
  const [start, setStart] = useState("");
  const [goto, setGoto] = useState("");
  const [gotoKind, setGotoKind] = useState<GotoKind>("va");
  const [anchor, setAnchor] = useState<number | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [copied, setCopied] = useState("");

  const page = entry?.state === "ready" ? entry.data : undefined;

  const loadPage = (value: string, kind: GotoKind): Promise<MemoryPage> => {
    const params = new URLSearchParams();
    if (value.trim() !== "") params.set("va", value.trim());
    if (kind !== "va") params.set("kind", kind);
    params.set("length", String(MEMORY_PAGE_DEFAULT));
    return api<MemoryPage>(`/binaries/${binaryId}/memory/page?${params.toString()}`);
  };

  const request = (value: string, kind: GotoKind): void => {
    setStart(value);
    setAnchor(null);
    setSelection(null);
    setCopied("");
    load(() => loadPage(value, kind));
  };

  const selectByte = (address: number, extend: boolean): void => {
    const next = extendSelection(anchor, address, extend);
    setAnchor(next.anchor);
    setSelection(next.selection);
  };

  const selectedBytes = (): number[] => {
    if (selection === null || page === undefined) return [];
    return pageBytes(page)
      .filter((byte) => byte.address >= selection.start && byte.address <= selection.end)
      .map((byte) => byte.value);
  };

  const copy = async (label: "hex" | "c") => {
    const bytes = selectedBytes();
    const text = label === "hex" ? hexCopy(bytes) : cArrayCopy(bytes);
    setCopied(text);
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text).catch(() => undefined);
    }
  };

  const gotoRequested = goto.trim() !== "";
  const sectionVa = page?.sections[0]?.va ?? "";
  const atStart = page?.prev === null;

  return (
    <>
      <Toolbar>
        <Field label="Section">
          <select
            value={sectionVa}
            disabled={page === undefined}
            onChange={(event) => request(event.target.value, "va")}
          >
            {(page?.sections ?? []).map((section) => (
              <option key={section.va} value={section.va}>
                {section.name} ({section.va})
              </option>
            ))}
          </select>
        </Field>
        <Field label="Go to">
          <input
            type="text"
            placeholder="0x401000"
            value={goto}
            onChange={(event) => setGoto(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && gotoRequested) request(goto, gotoKind);
            }}
          />
        </Field>
        <Field label="Address kind">
          <select value={gotoKind} onChange={(event) => setGotoKind(event.target.value as GotoKind)}>
            {GOTO_KINDS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </Field>
        <Button
          tone="primary"
          disabled={!gotoRequested}
          title={gotoRequested ? undefined : ADDRESS_REQUIRED}
          onClick={() => request(goto, gotoKind)}
        >
          Go
        </Button>
        <Button onClick={() => request(start, gotoKind)}>
          {page === undefined ? "Load page" : "Reload"}
        </Button>
      </Toolbar>
      {page === undefined ? (
        <Note>
          The full-file view walks the binary&apos;s own section map. Load a page to start at the
          first section, or jump to a virtual address or a file offset. A region no section backs is
          shown as a gap, never as zero bytes.
        </Note>
      ) : (
        <PanelBody entry={entry} hint="Reading the page">
          {() => (
            <>
              <Toolbar>
                <Button disabled={atStart} onClick={() => page.prev && request(page.prev, "va")}>
                  Previous page
                </Button>
                <Button disabled={page.next === null} onClick={() => request(page.next ?? "", "va")}>
                  Next page
                </Button>
                <Muted>
                  {page.start} .. {page.mapped} mapped bytes, {page.gaps} in gaps, page size{" "}
                  {page.length}
                </Muted>
              </Toolbar>
              {selection === null ? (
                <Muted>Click a byte to select it; shift-click extends the range.</Muted>
              ) : (
                <Toolbar>
                  <Muted>
                    Selected {hex(selection.start)} .. {hex(selection.end)} (
                    {selectedBytes().length} bytes)
                  </Muted>
                  <Button onClick={() => void copy("hex")}>Copy hex</Button>
                  <Button onClick={() => void copy("c")}>Copy C array</Button>
                  <Button
                    tone="ghost"
                    onClick={() => {
                      setAnchor(null);
                      setSelection(null);
                      setCopied("");
                    }}
                  >
                    Clear selection
                  </Button>
                </Toolbar>
              )}
              {copied ? <Note>Copied: {copied}</Note> : null}
              <PageRows page={page} selection={selection} onSelect={selectByte} />
            </>
          )}
        </PanelBody>
      )}
      <Muted>
        At most {MEMORY_PAGE_MAX} bytes per page, located through the engine&apos;s section table. A
        gap states what the engine refused to serve, so nothing is invented.
      </Muted>
    </>
  );
}

function PageRows({
  page,
  selection,
  onSelect,
}: {
  page: MemoryPage;
  selection: Selection | null;
  onSelect: (address: number, extend: boolean) => void;
}): ReactNode {
  return (
    <div className="memory-grid">
      {page.rows.map((row, index) => (
        <PageRow
          key={`${row.kind}-${row.address}-${index}`}
          row={row}
          selection={selection}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}

function PageRow({
  row,
  selection,
  onSelect,
}: {
  row: MemoryPageRow;
  selection: Selection | null;
  onSelect: (address: number, extend: boolean) => void;
}): ReactNode {
  if (row.kind === "gap") {
    return (
      <div className="memory-row memory-gap">
        <span className="memory-address">{row.address}</span>
        <span className="memory-offset">{NA}</span>
        <span className="memory-bytes">gap: {row.length} bytes the engine has no backing for</span>
        <span className="memory-ascii" />
      </div>
    );
  }
  const start = Number.parseInt(row.address, 16);
  const bytes = bytesOf(row.hex ?? "");
  return (
    <div className="memory-row">
      <span className="memory-address">{row.address}</span>
      <span className="memory-offset">{row.offset ?? NA}</span>
      <span className="memory-bytes">
        {bytes.map((byte, offset) => {
          const address = start + offset;
          const selected =
            selection !== null && address >= selection.start && address <= selection.end;
          const classes = ["byte"];
          if (byte === 0) classes.push("byte-zero");
          if (selected) classes.push("byte-selected");
          return (
            <button
              key={address}
              type="button"
              className={classes.join(" ")}
              aria-label={`byte ${hex(address)}`}
              onClick={(event) => onSelect(address, event.shiftKey)}
            >
              {byte.toString(16).padStart(2, "0")}
            </button>
          );
        })}
      </span>
      <span className="memory-ascii">{bytes.map(gutterOf).join("")}</span>
    </div>
  );
}
// ── Continuous hex view ────────────────────────────────────────────
//
// One scrollable dump of the whole binary in virtual-address order.  The
// section map is the anchor: the span runs from the first backed section to the
// last, a region no section backs is a stated gap (the same rows the paged view
// renders), and the bytes arrive from the same 256-byte page the paged view
// reads, walked forward through the engine's own `next` address as the viewport
// approaches a window.  The scroll container is the whole span and the rows are
// absolutely positioned inside it, so only the rows on screen are rendered.  A
// row whose bytes have not arrived renders as placeholders rather than zeros.

/** Rows rendered before and after the visible ones. */
const CONTINUOUS_OVERSCAN = MEMORY_SCROLL_OVERSCAN;

/** Addresses one read covers. */
const CONTINUOUS_WINDOW = MEMORY_SCROLL_WINDOW;

/** Row height in pixels; the stylesheet's row height is the same number. */
const ROW_HEIGHT = 18;

/** Windows one batch reads, so the first paint does not walk the whole file. */
const CONTINUOUS_BATCH = 4;

/** One row of the dump: where it starts, its bytes if read, its gap if stated. */
interface DumpRow {
  address: number;
  bytes: number[] | null;
  gap: number | null;
}

/** The file offset an address maps to, or null when no section backs it. */
function offsetOfAddress(sections: MemoryPageSection[], address: number): number | null {
  for (const section of sections) {
    const va = Number.parseInt(section.va, 16);
    const raw = Math.min(section.raw_size, section.virtual_size);
    if (address < va || address >= va + raw) continue;
    return Number.parseInt(section.offset, 16) + (address - va);
  }
  return null;
}

function storedColumnKind(): MemoryAddressKind {
  try {
    const stored = window.localStorage.getItem(MEMORY_COLUMN_STORAGE_KEY);
    if (stored === "file" || stored === "va" || stored === "rva") return stored;
  } catch {
    // Storage disabled: the dump still works, it just forgets the choice.
  }
  return "va";
}

export function ContinuousMode({
  binaryId,
  focus,
}: {
  binaryId: number;
  focus?: string;
}): ReactNode {
  const [column, setColumn] = useState<MemoryAddressKind>(storedColumnKind);
  const [bytes, setBytes] = useState<Map<number, number>>(new Map());
  const [gaps, setGaps] = useState<Array<{ address: number; length: number }>>([]);
  const [sections, setSections] = useState<MemoryPageSection[]>([]);
  const [span, setSpan] = useState<{ low: number; high: number } | null>(null);
  const [edge, setEdge] = useState(0);
  const [failure, setFailure] = useState<unknown>(null);
  const [pending, setPending] = useState(false);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(320);
  const [goto, setGoto] = useState(focus ?? "");
  const [anchor, setAnchor] = useState<number | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [copied, setCopied] = useState("");
  const container = useRef<HTMLDivElement | null>(null);
  const gotoRef = useRef<HTMLInputElement | null>(null);
  const running = useRef(false);
  const generation = useRef(0);

  const fetchPage = (start: string, kind: MemoryAddressKind): Promise<MemoryPage> => {
    const params = new URLSearchParams();
    params.set("va", start);
    params.set("kind", kind);
    params.set("length", String(CONTINUOUS_WINDOW));
    return api<MemoryPage>(`/binaries/${binaryId}/memory/page?${params.toString()}`);
  };

  // One walk reads page after page along the engine's own `next` address, which
  // is what steps over a gap in one hop, and stops when it has covered the
  // viewport or the engine has no data left.  A jump bumps the generation,
  // which stops an older walk from writing anything.
  const load = (start: string, budget: number): void => {
    if (running.current) return;
    running.current = true;
    setPending(true);
    setFailure(null);
    const mine = generation.current;
    const collected = new Map<number, number>();
    const collectedGaps = new Map<number, number>();
    const commit = (error: unknown): void => {
      running.current = false;
      if (mine !== generation.current) return;
      setBytes((current) => new Map([...current, ...collected]));
      setGaps((current) => {
        const merged = new Map(current.map((entry) => [entry.address, entry.length]));
        for (const [address, length] of collectedGaps) merged.set(address, length);
        return [...merged.entries()]
          .map(([address, length]) => ({ address, length }))
          .sort((left, right) => left.address - right.address);
      });
      const addresses = [...collected.keys(), ...collectedGaps.keys()];
      if (addresses.length) {
        const high = Math.max(
          ...collected.keys(),
          ...[...collectedGaps.entries()].map(([address, length]) => address + length - 1),
        );
        setEdge(high + 1);
      }
      setPending(false);
      setFailure(error);
    };
    const step = (from: string, remaining: number, collectedAny: boolean): void => {
      fetchPage(from, column)
        .then((page) => {
          if (mine !== generation.current) {
            running.current = false;
            return;
          }
          if (sections.length === 0 && page.sections.length) {
            setSections(page.sections);
            setSpan(spanOf(page.sections));
          }
          collectPage(page, collected, collectedGaps);
          const next = page.next;
          if (next === null || remaining <= 1) {
            commit(null);
            return;
          }
          step(next, remaining - 1, true);
        })
        .catch((error: unknown) => {
          if (mine !== generation.current) {
            running.current = false;
            return;
          }
          if (!collectedAny) {
            running.current = false;
            setPending(false);
            setFailure(error);
            return;
          }
          commit(error);
        });
    };
    step(start, Math.max(1, budget), false);
  };

  const restart = (start: string, kind: MemoryAddressKind): void => {
    generation.current += 1;
    running.current = false;
    setBytes(new Map());
    setGaps([]);
    setSections([]);
    setSpan(null);
    setEdge(0);
    setAnchor(null);
    setSelection(null);
    setCopied("");
    setFailure(null);
    setPending(true);
    // One batch on the anchor, then the scroll position drives the rest.
    load(start, CONTINUOUS_BATCH);
    void kind;
  };

  useEffect(() => {
    restart(focus !== undefined && /^0x/i.test(focus) ? focus : "", column);
    // The dump re-anchors on the column and on a linked address.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [binaryId, column, focus]);

  useEffect(() => {
    const node = container.current;
    if (node === null) return;
    const measure = (): void => {
      setViewport(node.clientHeight || 320);
      setScrollTop(node.scrollTop);
    };
    measure();
    node.addEventListener("scroll", measure, { passive: true });
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => {
      node.removeEventListener("scroll", measure);
      observer.disconnect();
    };
  }, [span]);

  const low = span?.low ?? 0;
  const totalRows = span === null ? 0 : Math.ceil((span.high - span.low) / MEMORY_BYTES_PER_ROW);
  const lastRow = Math.min(
    totalRows,
    Math.ceil((scrollTop + viewport) / ROW_HEIGHT) + CONTINUOUS_OVERSCAN,
  );
  const visibleEnd = span === null ? 0 : low + lastRow * MEMORY_BYTES_PER_ROW;

  // Read on once the viewport comes within an overscan of the loaded edge.
  useEffect(() => {
    if (span === null || pending) return;
    if (visibleEnd + CONTINUOUS_OVERSCAN * ROW_HEIGHT <= edge) return;
    if (edge >= span.high) return;
    const wanted = Math.max(
      1,
      Math.ceil((visibleEnd + CONTINUOUS_WINDOW - edge) / CONTINUOUS_WINDOW),
    );
    load(hex(edge), Math.min(wanted, CONTINUOUS_BATCH));
    // `load` continues from the loaded edge; `pending` guards one walk.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scrollTop, viewport, edge, span, pending, visibleEnd]);

  const remember = (kind: MemoryAddressKind): void => {
    setColumn(kind);
    try {
      window.localStorage.setItem(MEMORY_COLUMN_STORAGE_KEY, kind);
    } catch {
      // See storedColumnKind.
    }
  };

  const select = (address: number, extend: boolean): void => {
    const next = extendSelection(anchor, address, extend);
    setAnchor(next.anchor);
    setSelection(next.selection);
  };

  const selectedBytes = (): number[] => {
    if (selection === null) return [];
    const found: number[] = [];
    for (let address = selection.start; address <= selection.end; address += 1) {
      const value = bytes.get(address);
      if (value !== undefined) found.push(value);
    }
    return found;
  };

  const copy = async (form: "hex" | "c" | "ascii"): Promise<void> => {
    const found = selectedBytes();
    const text =
      form === "hex"
        ? hexCopy(found)
        : form === "c"
          ? cArrayCopy(found)
          : found.map(gutterOf).join("");
    setCopied(text);
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text).catch(() => undefined);
    }
  };

  // A typed address jumps, in whichever kind the column names.  A target the
  // engine refuses is reported rather than rendered as invented bytes.
  const jump = (): void => {
    const target = goto.trim();
    if (target === "") return;
    const start = /^0x/i.test(target) ? target : `0x${target}`;
    const parsed = Number.parseInt(start, 16);
    if (Number.isNaN(parsed)) return;
    generation.current += 1;
    running.current = false;
    setBytes(new Map());
    setGaps([]);
    setSpan(null);
    setEdge(0);
    setPending(true);
    setFailure(null);
    setAnchor(null);
    setSelection(null);
    load(start, Number.MAX_SAFE_INTEGER);
    const node = container.current;
    if (node !== null) {
      // The span is unknown until the first page lands, so the row is computed
      // from the target itself; the first page anchors the dump there.
      node.scrollTop = 0;
      setScrollTop(0);
    }
  };

  // The hosted portal's `G` focuses the address box and `Tab` toggles the
  // Offset and Virtual columns.  The bindings live on the dump, not in the
  // global keyboard layer, because only this panel has an address box.
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>): void => {
    if (event.key === "g" || event.key === "G") {
      event.preventDefault();
      gotoRef.current?.focus();
    } else if (event.key === "Tab") {
      event.preventDefault();
      remember(column === "file" ? "va" : "file");
    }
  };

  // A linked address (the section table's virtual-address column) opens on its
  // own row, selected, so the section table and a byte range are one click
  // apart.  The ref keeps a later re-render from dragging the reader back.
  const landed = useRef(false);
  useEffect(() => {
    if (focus === undefined || landed.current || span === null) return;
    landed.current = true;
    const parsed = Number.parseInt(/^0x/i.test(focus) ? focus : `0x${focus}`, 16);
    if (Number.isNaN(parsed)) return;
    const row = Math.floor((parsed - span.low) / MEMORY_BYTES_PER_ROW);
    if (row < 0) return;
    const node = container.current;
    if (node !== null) node.scrollTop = row * ROW_HEIGHT;
    setScrollTop(row * ROW_HEIGHT);
    setAnchor(parsed);
    setSelection({ start: parsed, end: parsed });
  }, [focus, span]);

  const firstRow = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - CONTINUOUS_OVERSCAN);
  const rows: DumpRow[] = [];
  for (let index = firstRow; index < lastRow; index += 1) {
    const address = low + index * MEMORY_BYTES_PER_ROW;
    const gap = gaps.find(
      (entry) => address >= entry.address && address < entry.address + entry.length,
    );
    if (gap !== undefined) {
      rows.push({ address, bytes: null, gap: gap.length });
      continue;
    }
    const found: number[] = [];
    let complete = true;
    for (let step = 0; step < MEMORY_BYTES_PER_ROW; step += 1) {
      const value = bytes.get(address + step);
      if (value === undefined) complete = false;
      found.push(value ?? 0);
    }
    rows.push({ address, bytes: complete ? found : null, gap: null });
  }

  return (
    <>
      <Toolbar>
        <Field label="Go to address">
          <input
            ref={gotoRef}
            type="text"
            aria-label="Go to address"
            placeholder={column === "file" ? "0x600" : "0x1001000"}
            value={goto}
            onChange={(event) => setGoto(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") jump();
            }}
          />
        </Field>
        <Field label="Columns">
          <select
            value={column}
            onChange={(event) => remember(event.target.value as MemoryAddressKind)}
          >
            <option value="va">virtual address</option>
            <option value="rva">rva</option>
            <option value="file">file offset</option>
          </select>
        </Field>
        <Button tone="primary" onClick={jump} disabled={goto.trim() === ""}>
          Go
        </Button>
        <Button onClick={() => restart("", column)}>Reload</Button>
        <Muted>
          {span === null
            ? "reading the section map"
            : `${hex(span.low)} .. ${hex(span.high)} (${totalRows} rows, ${bytes.size} bytes loaded${pending ? ", reading" : ""})`}
        </Muted>
      </Toolbar>
      {failure !== null ? (
        <ErrorNote error={failure} onRetry={() => restart("", column)} />
      ) : null}
      {selection === null ? (
        <Muted>
          Click a byte to select it and shift-click to extend; the copy controls follow the
          selection.
        </Muted>
      ) : (
        <Toolbar>
          <Muted>
            Selected {hex(selection.start)} .. {hex(selection.end)} ({selectedBytes().length} bytes)
          </Muted>
          <Button onClick={() => void copy("hex")}>Copy hex</Button>
          <Button onClick={() => void copy("c")}>Copy C array</Button>
          <Button onClick={() => void copy("ascii")}>Copy ASCII</Button>
          <Button
            tone="ghost"
            onClick={() => {
              setAnchor(null);
              setSelection(null);
              setCopied("");
            }}
          >
            Clear selection
          </Button>
        </Toolbar>
      )}
      {copied ? <Note>Copied: {copied}</Note> : null}
      <div
        className="memory-scroll"
        ref={container}
        tabIndex={0}
        role="region"
        aria-label="Whole binary hex dump"
        onKeyDown={onKeyDown}
      >
        <div className="memory-scroll-inner" style={{ height: `${totalRows * ROW_HEIGHT}px` }}>
          {rows.map((row) => (
            <DumpLine
              key={row.address}
              row={row}
              top={((row.address - low) / MEMORY_BYTES_PER_ROW) * ROW_HEIGHT}
              sections={sections}
              selection={selection}
              onSelect={select}
            />
          ))}
        </div>
      </div>
      <Muted>
        Press G to focus the address box and Tab to switch the offset and virtual columns; the
        choice is remembered across sessions. Only the rows on screen are rendered and the bytes
        arrive {CONTINUOUS_WINDOW} at a time, so a large binary scrolls without loading whole.
      </Muted>
    </>
  );
}

/**
 * The address span the section map covers: the first backed byte to the last.
 * The page payload's section addresses are already absolute virtual addresses
 * (the engine resolved the image base), so nothing is added here.
 */
function spanOf(sections: MemoryPageSection[]): { low: number; high: number } | null {
  if (sections.length === 0) return null;
  const lows = sections.map((section) => Number.parseInt(section.va, 16));
  const highs = sections.map(
    (section) => Number.parseInt(section.va, 16) + Math.max(section.virtual_size, section.raw_size),
  );
  return { low: Math.min(...lows), high: Math.max(...highs) };
}

/** Add one page's bytes and gaps to a walk's accumulators. */
function collectPage(
  page: MemoryPage,
  bytes: Map<number, number>,
  gaps: Map<number, number>,
): void {
  for (const row of page.rows) {
    const address = Number.parseInt(row.address, 16);
    if (row.kind === "gap") {
      gaps.set(address, row.length);
      continue;
    }
    for (const [index, value] of bytesOf(row.hex ?? "").entries()) {
      bytes.set(address + index, value);
    }
  }
}

/** One absolutely positioned line of the continuous dump. */
function DumpLine({
  row,
  top,
  sections,
  selection,
  onSelect,
}: {
  row: DumpRow;
  top: number;
  sections: MemoryPageSection[];
  selection: Selection | null;
  onSelect: (address: number, extend: boolean) => void;
}): ReactNode {
  // The rows are named by their virtual address, which is what a decompiler or
  // a disassembly prints, and the second column is the file offset beside it,
  // so a virtual read is citable as a byte in the file.
  const address = hex(row.address);
  const secondary = offsetOfAddress(sections, row.address);
  if (row.gap !== null) {
    return (
      <div className="memory-row memory-gap memory-scroll-row" style={{ top }}>
        <span className="memory-address">{address}</span>
        <span className="memory-offset">{secondary === null ? NA : hex(secondary)}</span>
        <span className="memory-bytes">gap: {row.gap} bytes the engine has no backing for</span>
        <span className="memory-ascii" />
      </div>
    );
  }
  if (row.bytes === null) {
    return (
      <div className="memory-row memory-scroll-row memory-pending" style={{ top }}>
        <span className="memory-address">{address}</span>
        <span className="memory-offset">{secondary === null ? NA : hex(secondary)}</span>
        <span className="memory-bytes">reading...</span>
        <span className="memory-ascii" />
      </div>
    );
  }
  const values = row.bytes;
  return (
    <div className="memory-row memory-scroll-row" style={{ top }}>
      <span className="memory-address">{address}</span>
      <span className="memory-offset">{secondary === null ? NA : hex(secondary)}</span>
      <span className="memory-bytes">
        {values.map((byte, index) => {
          const at = row.address + index;
          const selected = selection !== null && at >= selection.start && at <= selection.end;
          const classes = ["byte"];
          if (byte === 0) classes.push("byte-zero");
          if (selected) classes.push("byte-selected");
          return (
            <button
              key={at}
              type="button"
              className={classes.join(" ")}
              aria-label={`byte ${hex(at)}`}
              onClick={(event) => onSelect(at, event.shiftKey)}
            >
              {byte.toString(16).padStart(2, "0")}
            </button>
          );
        })}
      </span>
      <span className="memory-ascii">{values.map(gutterOf).join("")}</span>
    </div>
  );
}

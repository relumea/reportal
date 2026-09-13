import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Button,
  DataTable,
  EmptyState,
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
  MEMORY_PAGE_DEFAULT,
  MEMORY_PAGE_MAX,
  MEMORY_READ_DEFAULT,
  MEMORY_READ_MAX,
  type MemoryAddressKind,
} from "../constants";
import { panelKey, useLazyPanel } from "../panelCache";
import type { MemoryPage, MemoryPageRow, MemoryWindow } from "../types";

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

export function MemoryPanel({ binaryId }: { binaryId: number }): ReactNode {
  const [mode, setMode] = useState<"window" | "file">("window");
  return (
    <Panel
      title="Memory"
      subtitle="Read a window of this binary's bytes at an address, or page through the whole file, located through the engine's own section table."
    >
      <Toolbar>
        <Field label="Mode">
          <select
            value={mode}
            onChange={(event) => setMode(event.target.value === "file" ? "file" : "window")}
          >
            <option value="window">Window</option>
            <option value="file">Full file</option>
          </select>
        </Field>
      </Toolbar>
      {mode === "window" ? (
        <WindowMode binaryId={binaryId} />
      ) : (
        <FileMode binaryId={binaryId} />
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
    if (anchor === null || !extend) {
      setAnchor(address);
      setSelection({ start: address, end: address });
      return;
    }
    setSelection({ start: Math.min(anchor, address), end: Math.max(anchor, address) });
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

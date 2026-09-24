import { useRef, useState } from "react";
import type { ReactNode } from "react";

import { CopyButton, hex } from "../components";
import { FLASH_MS } from "../design";
import type { FunctionRow } from "../types";
import "./listing.css";

/** One instruction of an engine listing. */
interface Instruction {
  va: number;
  bytes: string;
  mnemonic: string;
  operands: string;
  /** The engine's own annotation (a callee name), when the hex listing has one. */
  comment: string;
}

// NASM source (32-bit targets): `    <instruction>   ; <VA>  <hex bytes>`.  An
// instruction NASM cannot reassemble byte-exact is emitted as `db 0x.., 0x..`
// with the decoded text in the comment instead of the bytes.
const NASM_LINE = /^\s+(\S.*?)\s*;\s*([0-9a-f]{8})\s+(.*)$/iu;
// The hex listing (every target): `  0x<va>:  <bytes>  <mnemonic> <operands>[ ; note]`.
const HEX_LINE = /^\s*0x([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*)$/iu;
const DB_BYTE = /0x([0-9a-f]{2})/giu;

// Operand tokens worth their own colour.  Anything else (punctuation, spaces)
// renders as plain text between them.
const TOKEN =
  /(0x[0-9a-f]+|\b\d+\b|\b(?:byte|word|dword|qword|tword|tbyte|fword|oword|yword|xmmword|ymmword|zmmword)(?: ptr)?\b|\b(?:[re]?[abcd]x|[abcd][lh]|[re]?(?:si|di|bp|sp|ip)|r(?:[89]|1[0-5])[dwb]?|[cdefgs]s|[xyz]mm\d+|mm\d|st(?:\(\d\))?|cr\d|dr\d)\b)/giu;

const SIZE = /^(?:byte|word|dword|qword|tword|tbyte|fword|oword|yword|xmmword|ymmword|zmmword)/iu;

/** Bytes shown before the column truncates; the full run is in the tooltip. */
const BYTES_SHOWN = 8;

type MnemonicKind = "call" | "jump" | "ret" | "stack" | "nop" | "plain";

function mnemonicKind(mnemonic: string): MnemonicKind {
  const m = mnemonic.toLowerCase();
  if (m === "call") return "call";
  if (m.startsWith("ret") || m === "iret" || m === "iretd") return "ret";
  if (m.startsWith("j") || m.startsWith("loop")) return "jump";
  if (m === "push" || m === "pop" || m === "leave" || m === "enter") return "stack";
  if (m === "nop" || m === "int3" || m === "hlt") return "nop";
  return "plain";
}

function parseLine(line: string): Instruction | null {
  const hexMatch = HEX_LINE.exec(line);
  if (hexMatch !== null) {
    const [, va, bytes, mnemonic, rest] = hexMatch;
    const [operands, ...note] = rest.split(";");
    return {
      va: Number.parseInt(va, 16),
      bytes: bytes.toLowerCase(),
      mnemonic,
      operands: operands.trim(),
      comment: note.join(";").trim(),
    };
  }
  const match = NASM_LINE.exec(line);
  if (match === null) return null;
  const [, source, va, comment] = match;
  const emittedAsBytes = source.startsWith("db ") && !/^[0-9a-f]+$/iu.test(comment);
  const instruction = emittedAsBytes ? comment : source;
  const bytes = emittedAsBytes
    ? Array.from(source.matchAll(DB_BYTE), (byte) => byte[1]).join("")
    : comment;
  const [mnemonic, ...operands] = instruction.trim().split(/\s+/u);
  return {
    va: Number.parseInt(va, 16),
    bytes: bytes.toLowerCase(),
    mnemonic,
    operands: operands.join(" "),
    comment: "",
  };
}

function parse(text: string): Instruction[] {
  return text
    .split("\n")
    .map(parseLine)
    .filter((row): row is Instruction => row !== null);
}

function tokenClass(token: string): string {
  if (/^(0x[0-9a-f]+|\d+)$/iu.test(token)) return "asm-imm";
  if (SIZE.test(token)) return "asm-size";
  return "asm-reg";
}

function label(va: number): string {
  return `loc_${va.toString(16)}`;
}

/**
 * A function's disassembly as an address / bytes / instruction listing, the way
 * a disassembler shows it: branch targets inside the function get a label and
 * jump there, a call to a known function links to it, and clicking a register
 * or constant highlights every use of it.  Falls back to the raw text when no
 * line is in the listing shape.
 */
export function DisasmListing({
  text,
  functionsByVa,
}: {
  text: string;
  functionsByVa: Map<number, FunctionRow>;
}): ReactNode {
  const [highlight, setHighlight] = useState<string | null>(null);
  const rowsRef = useRef<HTMLDivElement>(null);
  const rows = parse(text);
  if (rows.length === 0) {
    return <pre className="code-scroll listing-raw">{text}</pre>;
  }
  const inside = new Set(rows.map((row) => row.va));
  const targets = new Set<number>();
  for (const row of rows) {
    const kind = mnemonicKind(row.mnemonic);
    if (kind !== "jump") continue;
    const target = Number.parseInt(row.operands, 16);
    if (/^0x[0-9a-f]+$/iu.test(row.operands) && inside.has(target)) targets.add(target);
  }

  const jump = (va: number): void => {
    const row = rowsRef.current?.querySelector<HTMLElement>(`[data-va="${va}"]`);
    if (!row) return;
    row.scrollIntoView({ block: "center" });
    row.classList.add("flash");
    window.setTimeout(() => row.classList.remove("flash"), FLASH_MS);
  };

  const token = (value: string, className: string, key: number): ReactNode => {
    const normalized = value.toLowerCase();
    return (
      <button
        type="button"
        key={key}
        className={`asm-tok ${className}${highlight === normalized ? " asm-hl" : ""}`}
        onClick={() => setHighlight((current) => (current === normalized ? null : normalized))}
      >
        {value}
      </button>
    );
  };

  const operands = (row: Instruction, kind: MnemonicKind): ReactNode => {
    if (/^0x[0-9a-f]+$/iu.test(row.operands)) {
      const target = Number.parseInt(row.operands, 16);
      if (kind === "jump" && targets.has(target)) {
        return (
          <button type="button" className="asm-target" onClick={() => jump(target)}>
            {label(target)}
          </button>
        );
      }
      const callee = functionsByVa.get(target);
      if ((kind === "call" || kind === "jump") && callee) {
        return (
          <a className="asm-target" href={`#/functions/${callee.id}`} title={hex(target)}>
            {callee.name || `sub_${target.toString(16)}`}
          </a>
        );
      }
    }
    const parts = row.operands.split(TOKEN);
    return parts.map((part, index) =>
      index % 2 === 1 ? token(part, tokenClass(part), index) : part,
    );
  };

  return (
    <div className="listing">
      <div className="code-head">
        <span className="code-title">
          {rows.length} {rows.length === 1 ? "instruction" : "instructions"}
        </span>
        <CopyButton text={text} />
      </div>
      <div className="listing-rows" ref={rowsRef}>
        {rows.map((row) => {
          const kind = mnemonicKind(row.mnemonic);
          const bytes = row.bytes.match(/../gu) ?? [];
          return (
            <div key={row.va} className="listing-line">
              {targets.has(row.va) ? <div className="asm-label">{label(row.va)}:</div> : null}
              <div className={`listing-row asm-${kind}`} data-va={row.va}>
                <span className="asm-addr">{row.va.toString(16).padStart(8, "0")}</span>
                <span className="asm-bytes" title={bytes.join(" ")}>
                  {bytes.slice(0, BYTES_SHOWN).join(" ")}
                  {bytes.length > BYTES_SHOWN ? "…" : ""}
                </span>
                <span className="asm-mnem">{row.mnemonic}</span>
                <span className="asm-ops">
                  {operands(row, kind)}
                  {row.comment ? <span className="asm-comment">{`  ; ${row.comment}`}</span> : null}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

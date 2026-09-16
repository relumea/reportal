import { useState } from "react";
import type { ReactNode } from "react";

import { Link } from "react-router";

import { api } from "../api";
import {
  Badge,
  Button,
  CategoryBadge,
  CheckboxField,
  CodeBlock,
  ConfidenceBadge,
  ConfirmButton,
  CopyValue,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  KeyValue,
  Loading,
  Muted,
  NA,
  Note,
  Panel,
  PanelBody,
  RawJson,
  Readout,
  SegmentMeter,
  SeverityBadge,
  StatusCell,
  Toolbar,
  cellText,
  hex,
} from "../components";
import { ENTROPY_MAX, PACKED_ENTROPY_THRESHOLD, qualityHue, statusEntity } from "../design";
import type { HueFamily } from "../design";
import { panelKey, refreshPanel, useLazyPanel, usePanel } from "../panelCache";
import { useAsync } from "../useAsync";
import {
  BEHAVIOR_CONFIDENCES,
  BEHAVIOR_DOMAINS,
  CAPABILITY_CONFIDENCES,
  DEFAULT_BEHAVIOR_DOMAIN,
  DEFAULT_FUNCTION_ORDER,
  DEFAULT_FUNCTION_TRIAGE_LIMIT,
  DEFAULT_HARDENING_DOMAIN,
  DEFAULT_MIN_CONFIDENCE,
  DEFAULT_SECURITY_SEVERITY,
  DEFAULT_STRING_SORT,
  DETECT_CONFIDENCES,
  FILETYPE_CATEGORIES,
  FUNCTION_ORDERS,
  HARDENING_CONFIDENCES,
  HARDENING_DOMAINS,
  LINEAGE_ROW_STATUSES,
  MAX_COMPOSITION_ROWS_SHOWN,
  MAX_LINEAGE_ROWS_SHOWN,
  MITRE_TECHNIQUE_URL,
  PROTOCOL_CONFIDENCES,
  RATING_NOTE_MAX_CHARS,
  SECRET_CONFIDENCES,
  SECURITY_SEVERITIES,
  STRING_SORTS,
  THREAT_BAND_LEVELS,
  THREAT_IOC_CATEGORIES,
  type BehaviorDomain,
  type FunctionOrder,
  type HardeningDomain,
  type SecuritySeverity,
  type StringSort,
} from "../constants";
import type {
  AdditionalDetails,
  AnalysisList,
  ArtifactRatings,
  BehaviorScan,
  Binary,
  CapabilitiesResult,
  CompositionFunctionRow,
  CompositionCategory,
  CompositionResult,
  LibraryResult,
  CryptoResult,
  DetectResult,
  DetailsStatus,
  DieInfo,
  FileTypeMatch,
  FileTypeResult,
  Fingerprint,
  FirmwareExtraction,
  FirmwareRegion,
  FirmwareScan,
  FunctionListPage,
  FunctionRow,
  FunctionTriageResult,
  HardeningScan,
  ImportTable,
  LineageComparison,
  LineageList,
  JobView,
  PdfReportResult,
  PdfStatus,
  PeExport,
  PeInfo,
  PeSection,
  PeSecurityItem,
  ProtocolsResult,
  RelatedResult,
  SandboxRun,
  SandboxStatus,
  RemediationResult,
  ReportResult,
  SecretsResult,
  SecurityResult,
  Exploitability,
  SectionCoverage,
  SoftwareTypeClassification,
  StringTable,
  Tag,
  ThreatReport,
  ThreatScore,
  AttackSurface,
  AttackSurfaceRow,
  TriageDossier,
  BenchmarkResult,
  RenameBenchmarkResult,
  UnpackProvenance,
  UnpackResult,
  UnstripProposal,
  UnstripResult,
} from "../types";

// Strings rendered per load; the engine can return tens of thousands.  The
// panel always states the true total.
const MAX_STRINGS_SHOWN = 500;

// Raw-file digests the hashes card renders, in display order.
const HASH_FIELDS = [
  "md5",
  "sha1",
  "sha256",
  "sha512",
  "sha3_224",
  "sha3_256",
  "sha3_384",
  "sha3_512",
] as const;

// Build-identity hashes the hashes card adds after the raw-file digests.
const BUILD_HASH_FIELDS = ["crc32", "rich_header_hash"] as const;

// The portal's 11-item security checklist in display order: key → label.
const SECURITY_ITEMS = [
  ["aslr", "Address Space Layout Randomization (ASLR)"],
  ["dep", "Data Execution Prevention (DEP)"],
  ["cfg", "Control Flow Guard (CFG)"],
  ["driver_model", "Driver Model"],
  ["app_container", "App Container"],
  ["terminal_server_aware", "Terminal Server Aware"],
  ["image_isolation", "Image Isolation"],
  ["code_integrity", "Code Integrity"],
  ["high_entropy", "High Entropy"],
  ["seh", "Structured Exception Handlers (SEH)"],
  ["bound_image", "Bound Image"],
] as const;

// Packer verdicts the card derives from the file-type matches.
const PACKER_VERDICT_PACKED = "Likely to be packed";
const PACKER_VERDICT_POSSIBLE = "Possibly packed";
const PACKER_VERDICT_UNLIKELY = "Unlikely to be packed";

const TRIAGE_META_FIELDS = ["format", "image_base", "text_va", "text_size"] as const;
const TRIAGE_HEX_FIELDS = new Set(["image_base", "text_va"]);
const TRIAGE_COUNT_SECTIONS = ["strings", "imports", "references", "functions"] as const;

const REPORT_SUMMARY_FIELDS = [
  "total_functions",
  "covered_functions",
  "coverage_pct",
  "matched_pct",
  "byte_coverage_pct",
] as const;

// Friendly text per scan kind when a stored scan GET answers 404 `no-scan`:
// nothing is stored yet, and the engine runs only from the run control.
const NO_SCAN_MESSAGES = {
  triage: "No triage stored yet. Run the engine to produce one.",
  functionTriage:
    "No function triage stored yet. Run it to score and summarize the binary's functions.",
  report: "No report stored yet. Run the engine to generate one.",
  crypto: "No crypto scan yet. Run the scan to detect crypto constants and APIs.",
  peInfo:
    "No PE details stored yet. Run the scan to inspect the identity, sections and security flags.",
  filetype:
    "No file-type detection yet. Run the detector to match packer, protector and runtime signatures.",
  security: "No security scan yet. Run the scan to look for unsafe API use in the reversed sources.",
  unstrip: "No unstrip proposals stored yet. Run auto-unstrip to identify library functions.",
  capabilities: "No capability scan yet. Run the scan to classify the binary's imports and strings.",
  secrets: "No secrets scan yet. Run the scan to look for credentials and high-entropy values.",
  protocols:
    "No protocols scan yet. Run the scan to infer the protocols from APIs, schemes and literals.",
  threat: "No threat report yet. Run the report to extract IOCs and map ATT&CK techniques.",
  remediation: "No remediation artifacts yet. Generate the YARA, Snort and STIX outputs.",
  detect: "No family detection yet. Register a family, then run Detect to match this binary.",
  related: "No related-binary scan yet. Run the scan to rank the other binaries against this one.",
  composition:
    "No composition analysis yet. Run it to read how this binary's functions match the corpus.",
  firmware:
    "No firmware carve yet. Run it to find the images embedded in this file.",
  sandbox: "No detonation report yet. Run the sample to record what it does.",
} as const;

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
}

/** Detail header of one binary: identity, key facts and the way back. */
export function BinaryHeader({ binary }: { binary: Binary }): ReactNode {
  return (
    <header className="detail-head">
      <div className="detail-heading">
        <a className="back-link" href="#/binaries">
          Back to binaries
        </a>
        <h2 className="detail-title">{binary.name}</h2>
        <p className="detail-subtitle">
          Binary #{binary.id} · {binary.path || NA}
        </p>
        <div className="detail-facts">
          <Badge tone="accent" mono>
            {binary.format || NA}
          </Badge>
          <Badge mono>{binary.arch || NA}</Badge>
          <Badge mono>{binary.size.toLocaleString()} bytes</Badge>
          <Badge mono>{binary.function_count} functions</Badge>
        </div>
        <div className="detail-facts">
          <CopyValue value={binary.sha256} />
        </div>
        {binary.rebrew_project === undefined ? null : binary.rebrew_project ? (
          <Muted>rebrew project: {binary.rebrew_project}</Muted>
        ) : (
          <Muted>
            No rebrew project context, so this binary&apos;s engine-backed reads answer
            no-engine-context. Set one with <code>reportal import-rebrew &lt;project-dir&gt;</code>.
          </Muted>
        )}
      </div>
      <div className="panel-actions">
        <a className="btn btn-ghost" href={`#/binaries/${binary.id}/functions`}>
          Functions
        </a>
        <a className="btn btn-ghost" href={`/reports/${binary.id}/index.html`}>
          Report site
        </a>
      </div>
    </header>
  );
}

export function IdentityPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "pe-info");
  const path = `/binaries/${binaryId}/pe-info`;
  const entry = usePanel(key, () => api<PeInfo>(path));
  const fingerprintKey = panelKey("binary", binaryId, "fingerprint");
  const fingerprint = usePanel(fingerprintKey, () =>
    api<Fingerprint>(`/binaries/${binaryId}/fingerprint`),
  );
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Binary details"
      subtitle="Identity, export hashes and the stored PE scan this page is built from."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<PeInfo>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Run PE details
        </Button>
      }
    >
      <PanelBody entry={entry} hint="Loading the PE details" noScanHint={NO_SCAN_MESSAGES.peInfo}>
        {(data) => (
          <IdentityBody
            result={data}
            fingerprint={fingerprint?.state === "ready" ? fingerprint.data : undefined}
          />
        )}
      </PanelBody>
    </Panel>
  );
}

function IdentityBody({
  result,
  fingerprint,
}: {
  result: PeInfo;
  fingerprint?: Fingerprint;
}): ReactNode {
  const debug = Array.isArray(result.debug) ? result.debug : [];
  const richHeader = result.rich_header;
  const richEntries = richHeader && Array.isArray(richHeader.entries) ? richHeader.entries : [];
  const rows: Array<[string, ReactNode]> = [
    ["type", result.type ? <Badge mono>{result.type}</Badge> : NA],
    [
      "architecture",
      result.arch || result.bits ? `${result.arch ?? NA} · ${result.bits ?? NA}-bit` : NA,
    ],
    ["base address", result.image_base === undefined ? NA : hex(result.image_base)],
    ["image base", result.image_base === undefined ? NA : hex(result.image_base)],
    ["entry point", result.entry_point === undefined ? NA : hex(result.entry_point)],
    ["checksum", result.checksum === undefined ? NA : hex(result.checksum)],
    ["number of resources", result.resource_count ?? NA],
    ["import hash", <CopyValue value={fingerprint?.imphash} />],
    ["export hash", <CopyValue value={fingerprint?.export_hash} />],
    ["subsystem", result.subsystem ?? NA],
    ["timestamp", result.timestamp_iso ?? NA],
    ["size", result.size ?? NA],
  ];
  return (
    <>
      <KeyValue rows={rows} />
      {result.note ? <Muted>{result.note}</Muted> : null}
      <Muted>
        Debug directories: {debug.length > 0 ? debug.map((entry) => entry.type).join(", ") : "none"}
      </Muted>
      <Muted>
        Rich header: {richHeader?.present ? `present (${richEntries.length} entries)` : "absent"}
      </Muted>
      <RawJson value={result} />
    </>
  );
}

export function HashesPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "fingerprint");
  const path = `/binaries/${binaryId}/fingerprint`;
  const entry = usePanel(key, () => api<Fingerprint>(path));
  const [busy, setBusy] = useState(false);
  const recompute = (): void => {
    setBusy(true);
    refreshPanel(key, () =>
      api<Fingerprint>(path, { method: "POST" }).finally(() => setBusy(false)),
    );
  };
  return (
    <Panel
      title="Hashes"
      subtitle="Raw-file digests and build-identity hashes, computed through the engine."
      actions={
        <Button tone="primary" pending={busy} onClick={recompute}>
          {entry?.state === "ready" ? "Recompute" : "Compute"}
        </Button>
      }
    >
      <PanelBody entry={entry} hint="Loading the hashes">
        {(data) => <HashesBody fingerprint={data} />}
      </PanelBody>
    </Panel>
  );
}

function HashesBody({ fingerprint }: { fingerprint: Fingerprint }): ReactNode {
  const fields: Array<keyof Fingerprint> = [...HASH_FIELDS, ...BUILD_HASH_FIELDS];
  const rows = fields.map((field) => {
    const value = fingerprint[field];
    return [field, <CopyValue value={typeof value === "string" ? value : null} />] as [
      string,
      ReactNode,
    ];
  });
  return <KeyValue rows={rows} />;
}

/** The analyses stored for this binary.  An analysis is what a scan, a report
 *  and a match hang off, and the binary detail was a dead end for finding one:
 *  it listed nothing and the analyses view has no binary-scoped control.  This
 *  reads `GET /api/analyses?binary_id=` (the CLI's `analyses --binary` and the
 *  `list_analyses` MCP tool's `binary_id`). */
export function BinaryAnalysesPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "analyses");
  const entry = usePanel(key, () => api<AnalysisList>(`/analyses?binary_id=${binaryId}`));
  return (
    <Panel
      title="Analyses"
      subtitle="Every run stored for this binary, newest first."
      actions={
        <Link className="btn btn-ghost" to="/analyses">
          All analyses
        </Link>
      }
    >
      <PanelBody entry={entry} hint="Loading the analyses">
        {(data) =>
          data.analyses.length === 0 ? (
            <EmptyState>
              No analysis yet. Create one from the analyses view, or import the binary's rebrew
              project, which registers one.
            </EmptyState>
          ) : (
            <>
              <Muted>
                {data.count} of {data.total} analyses
              </Muted>
              <DataTable
                columns={[
                  { label: "ID", key: "id", numeric: true },
                  { label: "Engine", key: "engine" },
                  { label: "Created", key: "created_at", mono: true },
                  { label: "Finished", render: (row) => row.finished_at ?? NA },
                  { label: "Status", render: (row) => <StatusCell status={row.status} /> },
                  { label: "Note", render: (row) => cellText(row.log) },
                ]}
                rows={data.analyses}
                rowKey={(row) => String(row.id)}
              />
            </>
          )
        }
      </PanelBody>
    </Panel>
  );
}

export function SecurityMitigationsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "pe-info");
  const entry = usePanel(key, () => api<PeInfo>(`/binaries/${binaryId}/pe-info`));
  return (
    <Panel
      title="Security mitigations"
      subtitle="The loader checks the portal scores, with the raw DllCharacteristics flag behind each."
      hue="near"
    >
      <PanelBody
        entry={entry}
        hint="Loading the security checklist"
        noScanHint={NO_SCAN_MESSAGES.peInfo}
      >
        {(data) => <SecurityMitigationsBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function SecurityMitigationsBody({ result }: { result: PeInfo }): ReactNode {
  const checklist = result.security;
  if (!checklist) {
    return (
      <EmptyState>
        The stored PE details carry no security checklist. Run PE details to refresh them.
      </EmptyState>
    );
  }
  const score = result.security_score;
  const items = SECURITY_ITEMS.map(([key, label]) => ({
    key,
    label,
    item: checklist[key],
  }));
  return (
    <>
      <Readout
        label="Mitigations enabled"
        value={score ? `${score.enabled}/${score.total}` : null}
        hue="near"
      />
      <DataTable
        columns={[
          { label: "Mitigation", render: (row) => row.label },
          { label: "State", render: (row) => <SecurityState item={row.item} /> },
          {
            label: "Source flag",
            mono: true,
            render: (row) => <SecurityFlag item={row.item} boundImage={row.key === "bound_image"} />,
          },
        ]}
        rows={items}
        rowKey={(row) => row.key}
      />
      <Muted>dll_characteristics {hex(result.security_flags?.dll_characteristics ?? 0)}</Muted>
    </>
  );
}

/** One checklist item's state; an item with no source value renders `n/a`. */
function SecurityState({ item }: { item: PeSecurityItem | undefined }): ReactNode {
  if (!item || item.enabled === null || item.enabled === undefined) {
    return <Badge title="The stored scan carries no value for this item">{NA}</Badge>;
  }
  return item.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>disabled</Badge>;
}

/** The raw flag behind a checklist item, or the directory size for bound_image. */
function SecurityFlag({
  item,
  boundImage,
}: {
  item: PeSecurityItem | undefined;
  boundImage: boolean;
}): ReactNode {
  if (!item || !item.flag_name) return NA;
  if (boundImage) {
    return item.flag === null ? item.flag_name : `${item.flag_name} ${item.flag}`;
  }
  return item.flag === null ? item.flag_name : `${item.flag_name} ${hex(item.flag)}`;
}

export function ExportsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "pe-info");
  const entry = usePanel(key, () => api<PeInfo>(`/binaries/${binaryId}/pe-info`));
  return (
    <Panel title="Exports" subtitle="The PE export table; a forwarded export keeps its target.">
      <PanelBody entry={entry} hint="Loading the exports" noScanHint={NO_SCAN_MESSAGES.peInfo}>
        {(data) => <ExportsBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function ExportsBody({ result }: { result: PeInfo }): ReactNode {
  const [filter, setFilter] = useState("");
  const exports = Array.isArray(result.exports) ? result.exports : null;
  if (exports === null) {
    return (
      <EmptyState>
        The stored PE details carry no export table. Run PE details to refresh them.
      </EmptyState>
    );
  }
  const needle = filter.trim().toLowerCase();
  const shown = exports.filter((entry) => matchesExport(entry, needle));
  return (
    <>
      <Toolbar>
        <Field label="Filter">
          <input
            type="search"
            placeholder="name or ordinal"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
        </Field>
      </Toolbar>
      <Muted>
        {shown.length} of {exports.length} exports
      </Muted>
      <DataTable
        columns={[
          { label: "Name", mono: true, render: (row) => row.name || "(ordinal only)" },
          {
            label: "Address",
            mono: true,
            render: (row) => (row.va === null ? NA : hex(row.va)),
          },
          { label: "Ordinal", numeric: true, render: (row) => row.ordinal ?? NA },
          { label: "Forwarder", mono: true, render: (row) => row.forwarder ?? NA },
        ]}
        rows={shown}
        rowKey={(_row, index) => index}
        empty={
          <Muted>
            {exports.length === 0 ? "This binary exports nothing." : "No exports match the filter."}
          </Muted>
        }
      />
    </>
  );
}

function matchesExport(entry: PeExport, needle: string): boolean {
  if (!needle) return true;
  if (entry.name.toLowerCase().includes(needle)) return true;
  if (entry.forwarder?.toLowerCase().includes(needle)) return true;
  return entry.ordinal !== null && String(entry.ordinal).includes(needle);
}

export function SectionsPanel({
  binaryId,
  basePath,
}: {
  binaryId: number;
  /** The view's path, so a section address links to the memory dump. */
  basePath?: string;
}): ReactNode {
  const key = panelKey("binary", binaryId, "pe-info");
  const coverageKey = panelKey("binary", binaryId, "section-coverage");
  const entry = usePanel(key, () => api<PeInfo>(`/binaries/${binaryId}/pe-info`));
  // Stored-only, and a binary without a stored pe-info scan answers 404
  // no-scan; the coverage column is then simply absent rather than zero.
  const coverageEntry = usePanel(coverageKey, () =>
    api<SectionCoverage>(`/binaries/${binaryId}/section-coverage`),
  );
  const coverage = coverageEntry?.state === "ready" ? coverageEntry.data : undefined;
  return (
    <Panel
      title="Sections"
      subtitle="Section geometry, entropy and the full IMAGE_SCN_* characteristics."
    >
      <PanelBody entry={entry} hint="Loading the sections" noScanHint={NO_SCAN_MESSAGES.peInfo}>
        {(data) => <SectionsBody result={data} coverage={coverage} basePath={basePath} />}
      </PanelBody>
    </Panel>
  );
}

/** The share of one section's bytes the stored function table accounts for. */
function SectionCoverageCell({
  section,
  coverage,
}: {
  section: PeSection;
  coverage?: SectionCoverage;
}): ReactNode {
  const row = coverage?.sections.find((entry) => entry.name === section.name);
  if (row === undefined) {
    return <span className="muted">{NA}</span>;
  }
  if (row.coverage_pct === null) {
    return (
      <span className="muted" title="No stored functions, so byte coverage is undefined">
        {NA}
      </span>
    );
  }
  return (
    <span title={`${row.covered} of ${row.size} bytes covered by stored functions`}>
      {row.coverage_pct}%
    </span>
  );
}

function SectionsBody({
  result,
  coverage,
  basePath,
}: {
  result: PeInfo;
  coverage?: SectionCoverage;
  basePath?: string;
}): ReactNode {
  const [filter, setFilter] = useState("");
  const sections = Array.isArray(result.sections) ? result.sections : [];
  const needle = filter.trim().toLowerCase();
  const shown = sections.filter((section) => !needle || section.name.toLowerCase().includes(needle));
  return (
    <>
      <Toolbar>
        <Field label="Filter">
          <input
            type="search"
            placeholder="section name"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
        </Field>
      </Toolbar>
      <Muted>
        {shown.length} of {sections.length} sections
      </Muted>
      {coverage === undefined ? null : (
        <>
          <SegmentMeter
            label="Function coverage"
            value={coverage.totals.coverage_pct === null ? null : coverage.totals.coverage_pct / 100}
            readout={
              coverage.totals.coverage_pct === null
                ? NA
                : `${coverage.totals.covered} / ${coverage.totals.size} bytes (${coverage.totals.coverage_pct}%)`
            }
            title="Bytes inside a section that a stored function accounts for; reportal's own metric, not a portal field"
          />
          <Muted>{coverage.note}</Muted>
        </>
      )}
      <DataTable
        columns={[
          { label: "Name", key: "name", mono: true },
          {
            label: "Virtual address",
            mono: true,
            // The stored section address is an RVA; the memory reads take an
            // absolute virtual address, so the link (and the shown address)
            // add the image base.  That is what makes a section row and a byte
            // range in the dump the same number.
            render: (row) => {
              const va = (result.image_base ?? 0) + row.virtual_address;
              if (basePath === undefined) return hex(va);
              return (
                <Link className="address-link" to={`${basePath}?memory=${hex(va)}`}>
                  {hex(va)}
                </Link>
              );
            },
          },
          { label: "File offset", mono: true, render: (row) => hex(row.raw_offset) },
          { label: "Virtual size", key: "virtual_size", numeric: true },
          { label: "Raw size", key: "raw_size", numeric: true },
          { label: "Entropy", render: (row) => <SectionEntropyCell section={row} /> },
          {
            label: "Covered",
            numeric: true,
            render: (row) => <SectionCoverageCell section={row} coverage={coverage} />,
          },
          { label: "Prot", mono: true, render: (row) => sectionProtections(row) },
          {
            label: "Characteristics",
            mono: true,
            render: (row) => (row.characteristics?.length ? row.characteristics.join(", ") : NA),
          },
        ]}
        rows={shown}
        rowKey={(_row, index) => index}
        empty={
          <Muted>
            {sections.length === 0 ? "No section table." : "No sections match the filter."}
          </Muted>
        }
      />
    </>
  );
}

/** A section's Shannon entropy on a small meter (0..ENTROPY_MAX bits/byte). */
function SectionEntropyCell({ section }: { section: PeSection }): ReactNode {
  const entropy = typeof section.entropy === "number" ? section.entropy : null;
  return (
    <SegmentMeter
      label=""
      value={entropy === null ? null : entropy / ENTROPY_MAX}
      readout={entropy === null ? NA : entropy.toFixed(4)}
      title={entropy === null ? "entropy unavailable" : `${entropy.toFixed(4)} bits/byte`}
    />
  );
}

// Coverage map geometry: the smallest cell, and the most cells one section may
// draw.  A section past the cap widens its cells instead of adding nodes, so
// the whole map stays a bounded number of elements whatever the binary's size.
// ponytail: one cap for every viewport, size the cell from the measured width
// if a section ever crowds a narrow screen.
const COVERAGE_CELL_BYTES_MIN = 16;
const COVERAGE_CELLS_MAX = 512;

/** One coverage-map cell: an address range and the function whose extent covers it. */
interface CoverageCell {
  va: number;
  bytes: number;
  /** The stored function covering the cell's start, or null when none does. */
  fn: FunctionRow | null;
}

/**
 * Split one section into cells, each carrying the function that covers its
 * start address.  *functions* is sorted by VA by the caller; the cell walk is
 * one pass over it, so a section with thousands of cells stays linear.
 */
function coverageCells(
  section: PeSection,
  imageBase: number,
  functions: FunctionRow[],
): CoverageCell[] {
  const start = imageBase + section.virtual_address;
  const size = section.virtual_size;
  if (size <= 0) return [];
  const bytes = Math.max(COVERAGE_CELL_BYTES_MIN, Math.ceil(size / COVERAGE_CELLS_MAX));
  const cells: CoverageCell[] = [];
  let index = 0;
  for (let offset = 0; offset < size; offset += bytes) {
    const va = start + offset;
    while (
      index < functions.length &&
      functions[index].va + Math.max(functions[index].size, 1) <= va
    ) {
      index += 1;
    }
    const covering = index < functions.length ? functions[index] : undefined;
    cells.push({
      va,
      bytes: Math.min(bytes, size - offset),
      fn: covering !== undefined && covering.va <= va ? covering : null,
    });
  }
  return cells;
}

export function CoverageMapPanel({ binaryId }: { binaryId: number }): ReactNode {
  const peKey = panelKey("binary", binaryId, "pe-info");
  const pe = usePanel(peKey, () => api<PeInfo>(`/binaries/${binaryId}/pe-info`));
  const functionKey = panelKey("binary", binaryId, "functions");
  const functions = usePanel(functionKey, () =>
    api<FunctionListPage>(`/binaries/${binaryId}/functions`),
  );
  return (
    <Panel
      title="Coverage map"
      subtitle="Every stored section as one cell per address range, coloured by the status of the function covering it: where this binary is reversed, and where it is still a stub."
    >
      <PanelBody entry={pe} hint="Loading the section geometry" noScanHint={NO_SCAN_MESSAGES.peInfo}>
        {(info) => (
          <PanelBody entry={functions} hint="Loading the stored functions">
            {(page) => <CoverageMapBody info={info} functions={page.functions} binaryId={binaryId} />}
          </PanelBody>
        )}
      </PanelBody>
    </Panel>
  );
}

/** The status entities the map paints, in the order its legend lists them. */
const COVERAGE_LEGEND: ReadonlyArray<{ state: string; label: string }> = [
  { state: "exact", label: "exact" },
  { state: "reloc", label: "reloc" },
  { state: "proven", label: "proven" },
  { state: "thunk", label: "thunk" },
  { state: "near", label: "near-match" },
  { state: "stub", label: "stub" },
  { state: "idle", label: "other" },
  { state: "empty", label: "no function" },
];

function CoverageMapBody({
  info,
  functions,
  binaryId,
}: {
  info: PeInfo;
  functions: FunctionRow[];
  binaryId: number;
}): ReactNode {
  const sections = (Array.isArray(info.sections) ? info.sections : []).filter(
    (section) => section.virtual_size > 0,
  );
  if (sections.length === 0) {
    return <EmptyState>The stored PE details carry no section with a virtual size.</EmptyState>;
  }
  const imageBase = info.image_base ?? 0;
  // The cell walk below advances one pointer through the functions, so the
  // order is a precondition of the derivation rather than the route's default.
  const ordered = [...functions].sort((left, right) => left.va - right.va);
  // A section cell's state comes from the function table, so the map is
  // undefined without one rather than a uniformly empty grid.
  const zeroFunctions = functions.length === 0;
  return (
    <>
      {zeroFunctions ? (
        <Note tone="warn">
          This binary has no stored functions, so every cell reads as no function. Run
          import-rebrew on its project.
        </Note>
      ) : null}
      <div className="covmap-legend">
        {COVERAGE_LEGEND.map((entry) => (
          <span className="covmap-key" key={entry.state}>
            <span className="covmap-cell" data-state={entry.state} aria-hidden="true" />
            {entry.label}
          </span>
        ))}
      </div>
      <div className="covmap">
        {sections.map((section) => {
          const cells = coverageCells(section, imageBase, ordered);
          const covered = cells.filter((cell) => cell.fn !== null).length;
          return (
            <div className="covmap-section" key={section.name}>
              <div className="covmap-head">
                <span className="covmap-name">{section.name}</span>
                <Muted>
                  {`${hex(imageBase + section.virtual_address)} ${section.virtual_size} bytes, ${covered} of ${cells.length} cells carry a stored function`}
                </Muted>
              </div>
              <div className="covmap-grid" role="group" aria-label={`${section.name} coverage map`}>
                {cells.map((cell) => {
                  const state = cell.fn === null ? "empty" : (statusEntity(cell.fn.status) ?? "idle");
                  const end = cell.va + cell.bytes;
                  const name = cell.fn === null ? "no stored function" : cell.fn.name || "unnamed";
                  return (
                    <Link
                      className="covmap-cell"
                      data-state={state}
                      key={cell.va}
                      // The grid is a map, not a list of tab stops: a section
                      // can carry hundreds of cells and the Sections table
                      // above is the keyboard path through the same addresses.
                      tabIndex={-1}
                      aria-label={`${name} at ${hex(cell.va)}`}
                      title={`${hex(cell.va)}..${hex(end)} ${name} (${state})`}
                      to={
                        cell.fn === null
                          ? `/binaries/${binaryId}?memory=${hex(cell.va)}`
                          : `/functions/${cell.fn.id}`
                      }
                    />
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
}

export function CodeSignaturePanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "pe-info");
  const entry = usePanel(key, () => api<PeInfo>(`/binaries/${binaryId}/pe-info`));
  return (
    <Panel title="Code signature" subtitle="Authenticode state and the signers LIEF exposes.">
      <PanelBody entry={entry} hint="Loading the code signature" noScanHint={NO_SCAN_MESSAGES.peInfo}>
        {(data) => <CodeSignatureBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function CodeSignatureBody({ result }: { result: PeInfo }): ReactNode {
  const authenticode = result.authenticode;
  if (!authenticode) {
    return <EmptyState>The stored PE details carry no signature state. Run PE details.</EmptyState>;
  }
  const signers = Array.isArray(authenticode.signers) ? authenticode.signers : [];
  return (
    <KeyValue
      rows={[
        [
          "signature",
          authenticode.present ? <Badge tone="ok">signed</Badge> : <Badge>not signed</Badge>,
        ],
        ["signatures", authenticode.signature_count ?? 0],
        ["signers", signers.length > 0 ? signers.join(", ") : NA],
      ]}
    />
  );
}

// Section access flags the panel renders as letters, in display order.
const SECTION_ACCESS = [
  ["read", "R"],
  ["write", "W"],
  ["execute", "X"],
] as const;

function sectionProtections(section: PeSection): string {
  return SECTION_ACCESS.map(([access, letter]) => (section[access] ? letter : "-")).join("");
}

export function PackerPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "filetype");
  const path = `/binaries/${binaryId}/filetype`;
  const entry = usePanel(key, () => api<FileTypeResult>(path));
  const peKey = panelKey("binary", binaryId, "pe-info");
  const pe = usePanel(peKey, () => api<PeInfo>(`/binaries/${binaryId}/pe-info`));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Packer detection"
      subtitle="Packer verdict, peak section entropy, section count and the toolchain signature."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<FileTypeResult>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Run detector
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the packer detection"
        noScanHint={NO_SCAN_MESSAGES.filetype}
      >
        {(data) => <PackerBody result={data} peInfo={pe?.state === "ready" ? pe.data : undefined} />}
      </PanelBody>
    </Panel>
  );
}

function PackerBody({ result, peInfo }: { result: FileTypeResult; peInfo?: PeInfo }): ReactNode {
  const matches = Array.isArray(result.matches) ? result.matches : [];
  const notes = Array.isArray(result.notes) ? result.notes : [];
  const packers = matches.filter((match) => match.category === "packer");
  const toolchains = matches.filter((match) => match.category === "toolchain");
  const sections = peInfo?.sections ?? [];
  const entropies = sections
    .map((section) => (typeof section.entropy === "number" ? section.entropy : null))
    .filter((entropy): entropy is number => entropy !== null);
  const peak = entropies.length > 0 ? Math.max(...entropies) : null;
  const verdict = packers.some((match) => match.confidence === "high") ? (
    <Badge tone="danger">{PACKER_VERDICT_PACKED}</Badge>
  ) : packers.length > 0 ? (
    <Badge tone="warn">{PACKER_VERDICT_POSSIBLE}</Badge>
  ) : (
    <Badge tone="ok">{PACKER_VERDICT_UNLIKELY}</Badge>
  );
  return (
    <>
      <KeyValue
        rows={[
          ["verdict", verdict],
          ["section count", peInfo ? sections.length : NA],
          ["compiler", toolchains[0]?.name ?? NA],
        ]}
      />
      <SegmentMeter
        label="Peak section entropy"
        value={peak === null ? null : peak / ENTROPY_MAX}
        readout={peak === null ? NA : `${peak.toFixed(2)} / ${ENTROPY_MAX}`}
        band={{ from: PACKED_ENTROPY_THRESHOLD / ENTROPY_MAX, to: 1 }}
        hue="near"
        title={`marked band: ${PACKED_ENTROPY_THRESHOLD} bits/byte and above, where a section reads as compressed or packed`}
      />
      <Muted>
        {result.count ?? matches.length} matches (
        {FILETYPE_CATEGORIES.map(
          (category) => `${category} ${result.by_category?.[category] ?? 0}`,
        ).join(", ")}
        )
      </Muted>
      {matches.length === 0 ? (
        <EmptyState>
          No signatures matched. Run the detector after importing the binary's project.
        </EmptyState>
      ) : (
        <DataTable
          columns={[
            { label: "Category", render: (match) => <CategoryBadge category={match.category} /> },
            { label: "Name", key: "name" },
            {
              label: "Confidence",
              render: (match) => <ConfidenceBadge level={match.confidence} />,
            },
            { label: "Signals", mono: true, render: (match) => signalSummary(match) },
          ]}
          rows={matches}
          rowKey={(match, index) => `${match.category}-${match.name}-${index}`}
        />
      )}
      {notes.map((note) => (
        <Muted key={note}>{note}</Muted>
      ))}
      <RawJson value={result} />
    </>
  );
}

function signalSummary(match: FileTypeMatch): string {
  if (!match.signals.length) return NA;
  return match.signals.map((signal) => `${signal.kind}: ${signal.value}`).join(", ");
}

/** The composed detail reads: which stored scans back them, and what the
 *  pe-info-derived fields say that no other panel shows (the overlay and the
 *  Rich header's shape).  The status read always answers, so a binary whose
 *  scans are missing reports the gap with the command that fills it rather
 *  than rendering an empty panel. */
export function DetailCoveragePanel({ binaryId }: { binaryId: number }): ReactNode {
  const statusKey = panelKey("binary", binaryId, "details-status");
  const status = usePanel(statusKey, () =>
    api<DetailsStatus>(`/binaries/${binaryId}/additional-details/status`),
  );
  const detailPath = `/binaries/${binaryId}/additional-details`;
  const detailKey = panelKey("binary", binaryId, "additional-details");
  const entry = usePanel(detailKey, () => api<AdditionalDetails>(detailPath));
  const dieKey = panelKey("binary", binaryId, "die-info");
  const die = usePanel(dieKey, () => api<DieInfo>(`/binaries/${binaryId}/die-info`));
  return (
    <Panel
      title="Detail coverage"
      subtitle="Which stored scans back the detail reads, the overlay past the last section and the Rich header."
    >
      <PanelBody entry={status} hint="Loading the detail coverage">
        {(data) => (
          <>
            <KeyValue
              rows={[
                [
                  "status",
                  data.status === "ready" ? (
                    <Badge tone="ok">ready</Badge>
                  ) : (
                    <Badge tone="warn">{`missing ${data.missing.length}`}</Badge>
                  ),
                ],
                [
                  "sources",
                  Object.entries(data.sources)
                    .map(([kind, source]) => `${kind} ${source.present ? "yes" : "no"}`)
                    .join(", "),
                ],
              ]}
            />
            {data.hint ? <Muted>{`Fills the gap: ${data.hint}`}</Muted> : null}
          </>
        )}
      </PanelBody>
      <PanelBody entry={entry} hint="Loading the overlay and Rich header">
        {(data) => (
          <KeyValue
            rows={[
              [
                "overlay",
                data.overlay.present ? `${data.overlay.bytes} bytes` : "none",
              ],
              ["overlay offset", data.overlay.offset === null ? NA : hex(data.overlay.offset)],
              [
                "rich header",
                data.rich_header.present
                  ? `${data.rich_header.entries} entries, builds ${data.rich_header.build_ids.join(", ") || NA}`
                  : "absent",
              ],
              ["debug entries", data.debug.length],
              ["packer hint", data.packer_section_hint.join(", ") || NA],
            ]}
          />
        )}
      </PanelBody>
      <PanelBody entry={die} hint="Loading the Detect-It-Easy identity">
        {(data) => (
          <KeyValue
            rows={[
              ["format", data.identity.format ?? NA],
              ["architecture", data.identity.arch ?? NA],
              [
                "categories",
                Object.entries(data.by_category)
                  .map(([category, count]) => `${category} ${count}`)
                  .join(", ") || NA,
              ],
              ["entropy", data.entropy.packed ? "packed" : NA],
            ]}
          />
        )}
      </PanelBody>
    </Panel>
  );
}

export function BenchmarkPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "benchmark");
  const path = `/binaries/${binaryId}/benchmark`;
  const entry = usePanel(key, () => api<BenchmarkResult>(path));
  const candidatesEntry = usePanel(panelKey("binary", binaryId, "benchmark-candidates"), () =>
    api<{ binaries: Binary[] }>("/binaries"),
  );
  const renameKey = panelKey("binary", binaryId, "rename-benchmark");
  const renameEntry = usePanel(renameKey, () =>
    api<RenameBenchmarkResult>(`/binaries/${binaryId}/rename-benchmark`),
  );
  const [partnerId, setPartnerId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);

  const candidates = (
    candidatesEntry?.state === "ready" ? candidatesEntry.data.binaries : []
  ).filter((binary) => binary.id !== binaryId);
  const stored = entry?.state === "ready" ? entry.data : null;
  const partner = partnerId ?? stored?.right?.binary_id ?? null;

  const run = (): void => {
    if (partner === null) return;
    setActionError(null);
    setBusy(true);
    refreshPanel(key, async () => {
      try {
        await api<BenchmarkResult>(path, {
          method: "POST",
          json: { right_binary_id: partner },
        });
        return await api<BenchmarkResult>(path);
      } catch (failure) {
        setActionError(failure);
        throw failure;
      } finally {
        setBusy(false);
      }
    });
  };

  return (
    <Panel
      title="Benchmark"
      subtitle="Precision and recall of a match run against counterpart addresses an analyst knows."
      actions={
        <Toolbar>
          <Field
            label="Partner"
            hint="Candidates come from this binary; labels come from the two binaries' shared real names."
          >
            <select
              value={partner ?? ""}
              onChange={(event) => {
                const value = event.target.value;
                setPartnerId(value === "" ? null : Number(value));
              }}
            >
              <option value="">Select a binary</option>
              {candidates.map((binary) => (
                <option key={binary.id} value={binary.id}>
                  {binary.name}
                </option>
              ))}
            </select>
          </Field>
          <Button tone="primary" pending={busy} onClick={run} disabled={partner === null}>
            Run benchmark
          </Button>
        </Toolbar>
      }
    >
      {actionError ? <ErrorNote error={actionError} /> : null}
      <PanelBody
        entry={entry}
        hint="Loading the stored benchmark"
        onRetry={() => refreshPanel(key, () => api<BenchmarkResult>(path))}
      >
        {(data) =>
          !data.stored || data.metrics === null ? (
            <EmptyState>
              Nothing measured yet. Pick a partner binary and run the benchmark: the labels are
              the two binaries&apos; shared real function names unless a corpus supplies them, and
              an unidentified binary still scores zero rather than guessing.
            </EmptyState>
          ) : (
            <BenchmarkBody result={data} />
          )
        }
      </PanelBody>
      <h3>Rename proposals</h3>
      {renameEntry === undefined ? (
        <Loading label="Loading the rename proposals" rows={2} />
      ) : renameEntry.state === "error" ? (
        <ErrorNote
          error={renameEntry.error}
          onRetry={() =>
            refreshPanel(renameKey, () =>
              api<RenameBenchmarkResult>(`/binaries/${binaryId}/rename-benchmark`),
            )
          }
        />
      ) : renameEntry.state !== "ready" ? null : renameEntry.data.stored === false ||
        renameEntry.data.metrics === null ? (
        <Muted>{renameEntry.data.notes[0] ?? "Nothing to score yet."}</Muted>
      ) : (
        <RenameBenchmarkBody result={renameEntry.data} />
      )}
    </Panel>
  );
}

function RenameBenchmarkBody({ result }: { result: RenameBenchmarkResult }): ReactNode {
  const scored = result.metrics;
  if (scored === null) return null;
  return (
    <>
      <Muted>
        {result.labels.count} symbol name(s) against {result.proposals.count} stored proposal(s)
        from the {result.proposal_source} reading
      </Muted>
      <KeyValue
        rows={[
          ["scored", String(scored.proposed)],
          ["correct", String(scored.correct)],
          ["close", String(scored.close)],
          ["precision", scored.precision.toFixed(4)],
          ["recall", scored.recall.toFixed(4)],
          ["f1", scored.f1.toFixed(4)],
          ["unscored", String(result.proposals.unscored)],
        ]}
      />
      {(result.notes ?? []).map((note) => (
        <Muted key={note}>{note}</Muted>
      ))}
      <DataTable
        columns={[
          { label: "Symbol", key: "name", mono: true },
          { label: "VA", mono: true, render: (row) => hex(row.va) },
          {
            label: "Proposed",
            render: (row) => (row.proposed ? row.proposed : <Muted>nothing</Muted>),
          },
          { label: "Module", render: (row) => row.module ?? NA },
        ]}
        rows={[...scored.wrong, ...scored.missing]}
        rowKey={(row) => `${row.va}-${row.name}`}
        empty={<Muted>Every symbol name was proposed exactly.</Muted>}
      />
    </>
  );
}

function BenchmarkBody({ result }: { result: BenchmarkResult }): ReactNode {
  const scored = result.metrics;
  if (scored === null) return null;
  return (
    <>
      <Muted>
        {result.left?.name} against {result.right?.name}, {result.label_source} labels (
        {result.labels?.count ?? scored.queries} scored
        {result.labels?.unmatched.length
          ? `, ${result.labels.unmatched.length} unresolved`
          : ""}
        )
      </Muted>
      <KeyValue
        rows={[
          ["queries", String(scored.queries)],
          ["retrieved", String(scored.retrieved)],
          ["hits", String(scored.hits)],
          ["precision", scored.precision.toFixed(4)],
          ["recall", scored.recall.toFixed(4)],
          ["f1", scored.f1.toFixed(4)],
          ["mrr", scored.mrr.toFixed(4)],
          ["mean rank", scored.mean_rank === null ? "n/a" : String(scored.mean_rank)],
          ["top", String(scored.top)],
          ["recorded pairs", result.matching ? String(result.matching.pairs) : "n/a"],
        ]}
      />
      {(result.notes ?? []).map((note) => (
        <Muted key={note}>{note}</Muted>
      ))}
      <DataTable
        columns={[
          { label: "Label", key: "name", mono: true },
          { label: "Left VA", mono: true, render: (row) => hex(row.left_va) },
          { label: "Right VA", mono: true, render: (row) => hex(row.right_va) },
          {
            label: "Rank",
            numeric: true,
            render: (row) => (row.rank === null ? <Badge tone="warn">miss</Badge> : String(row.rank)),
          },
          {
            label: "Similarity",
            numeric: true,
            render: (row) => (row.similarity === null ? NA : row.similarity.toFixed(1)),
          },
          { label: "Candidates", numeric: true, render: (row) => row.candidates },
        ]}
        rows={scored.detail}
        rowKey={(row) => `${row.left_va}-${row.right_va}`}
        empty={<Muted>No label was scored.</Muted>}
      />
    </>
  );
}

export function UnpackedFilesPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "unpack");
  const path = `/binaries/${binaryId}/unpack`;
  const entry = usePanel(key, () => api<UnpackProvenance>(path));
  const [packer, setPacker] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<UnpackResult | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const run = async (): Promise<void> => {
    setBusy(true);
    setActionError(null);
    setResult(null);
    try {
      const payload = await api<UnpackResult>(path, {
        method: "POST",
        json: packer ? { packer } : {},
      });
      setResult(payload);
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Unpacked files"
      subtitle="Rebuild the image a packer replaced and register it as a binary of its own. Nothing is executed."
      actions={
        <Button tone="primary" pending={busy} onClick={() => void run()}>
          Run unpack
        </Button>
      }
    >
      {actionError ? <ErrorNote error={actionError} /> : null}
      <Toolbar>
        <Field
          label="Packer"
          hint="Detected from the file's own stub when left on Auto. UPX needs the upx tool installed."
        >
          <select value={packer} onChange={(event) => setPacker(event.target.value)}>
            <option value="">Auto</option>
            <option value="lzexe">LZEXE (in process)</option>
            <option value="upx">UPX (external upx)</option>
          </select>
        </Field>
      </Toolbar>
      {entry === undefined ? (
        <Loading label="Loading the unpack provenance" rows={2} />
      ) : entry.state === "error" ? (
        <ErrorNote
          error={entry.error}
          onRetry={() => refreshPanel(key, () => api<UnpackProvenance>(path))}
        />
      ) : entry.state !== "ready" ? null : entry.data.stored ? (
        <UnpackProvenanceRows provenance={entry.data} title="This binary was unpacked from" />
      ) : (
        <Note tone="info">
          {entry.data.notes[0] ?? "This binary did not come from an unpack."} A packed file's own
          bytes name the packer: the LZEXE stub at the entry point, or the UPX marker.
        </Note>
      )}
      {result ? (
        <>
          <Note tone="info">
            Unpacked with {result.packer} ({result.method}).
          </Note>
          <UnpackProvenanceRows provenance={result.provenance} title="Rebuilt from" />
          <KeyValue
            rows={[
              [
                "New binary",
                result.unpacked.binary_id === null ? (
                  <Muted>none</Muted>
                ) : (
                  <a href={`#/binaries/${result.unpacked.binary_id}`}>
                    #{result.unpacked.binary_id} {result.unpacked.name}
                  </a>
                ),
              ],
              ["sha256", <span className="mono">{result.unpacked.sha256}</span>],
              ["Already stored", result.unpacked.duplicate ? "yes" : "no"],
              ["Identified by", result.detected.map((found) => found.detail).join(", ")],
            ]}
          />
          {result.notes.map((note) => (
            <Muted key={note}>{note}</Muted>
          ))}
        </>
      ) : null}
    </Panel>
  );
}

/** The provenance of an unpacked binary, read from its `unpack` scan. */
function UnpackProvenanceRows({
  provenance,
  title,
}: {
  provenance: UnpackProvenance;
  title: string;
}): ReactNode {
  const source = provenance.source;
  return (
    <KeyValue
      rows={[
        [title, source ? `${source.name} (#${source.binary_id})` : <Muted>unknown</Muted>],
        ["Source sha256", <span className="mono">{source?.sha256 ?? "not recorded"}</span>],
        ["Packer", `${provenance.packer} (${provenance.detected ?? provenance.method ?? ""})`],
        [
          "Sizes",
          provenance.image_size != null
            ? `${provenance.image_size.toLocaleString()} image bytes, ${(
                provenance.file_size ?? 0
              ).toLocaleString()} file bytes`
            : `${(provenance.file_size ?? 0).toLocaleString()} file bytes`,
        ],
        ["Unpacked at", provenance.unpacked_at ?? "unknown"],
      ]}
    />
  );
}

/**
 * Analyst feedback on the binary's stored agent artifacts.
 *
 * One control per stored artifact: thumbs up, thumbs down, or clear.  An
 * artifact that was never produced is not listed, and the panel says how many
 * of the stored ones carry a verdict.  A verdict takes an optional note through
 * the same endpoint the CLI's `--note` and the MCP tool's `note` use.
 */
export function ArtifactRatingsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const { data, error, reload } = useAsync(
    () => api<ArtifactRatings>(`/binaries/${binaryId}/ratings`),
    [binaryId],
  );
  const [busy, setBusy] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [noting, setNoting] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [draftVerdict, setDraftVerdict] = useState("up");

  const rate = async (kind: string, rating: string, note?: string): Promise<void> => {
    setBusy(`${kind}-${rating}`);
    setActionError(null);
    try {
      await api(`/binaries/${binaryId}/ratings/${kind}`, {
        method: "PUT",
        json: note === undefined ? { rating } : { rating, note },
      });
      setNoting(null);
      reload();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <Panel
      title="Agent feedback"
      subtitle="Thumbs up or down on a stored agent artifact; the verdict survives a re-run of the scan."
    >
      {error ? <ErrorNote error={error} onRetry={reload} /> : null}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {!data ? (
        <Loading label="Loading the artifact ratings" rows={2} />
      ) : data.artifacts.length === 0 ? (
        <EmptyState>No stored agent artifact to rate yet.</EmptyState>
      ) : (
        <>
          <Muted>
            {data.rated} of {data.count} stored artifact(s) rated.
          </Muted>
          <table className="table">
            <thead>
              <tr>
                <th>Artifact</th>
                <th>Verdict</th>
                <th>Note</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.artifacts.map((entry) => (
                <tr key={entry.kind}>
                  <td className="mono">{entry.kind}</td>
                  <td>{entry.rating ? entry.rating.rating : "unrated"}</td>
                  <td className="muted">{entry.rating ? entry.rating.note : ""}</td>
                  <td>
{noting === entry.kind ? (
                      <span className="toolbar">
                        <Field label="Verdict">
                          <select
                            value={draftVerdict}
                            onChange={(event) => setDraftVerdict(event.target.value)}
                          >
                            <option value="up">up</option>
                            <option value="down">down</option>
                          </select>
                        </Field>
                        <Field label={`Note for ${entry.kind}`}>
                          <input
                            value={draft}
                            maxLength={RATING_NOTE_MAX_CHARS}
                            onChange={(event) => setDraft(event.target.value)}
                            placeholder="Why this verdict"
                          />
                        </Field>
                        <Button
                          size="sm"
                          tone="primary"
                          pending={busy === `${entry.kind}-${draftVerdict}`}
                          disabled={!draft.trim()}
                          onClick={() => void rate(entry.kind, draftVerdict, draft)}
                        >
                          Save note
                        </Button>{" "}
                        <Button
                          size="sm"
                          tone="ghost"
                          onClick={() => {
                            setNoting(null);
                            setDraft("");
                          }}
                        >
                          Cancel
                        </Button>
                      </span>
                    ) : (
                      <>
                        <Button
                          size="sm"
                          pending={busy === `${entry.kind}-up`}
                          onClick={() => void rate(entry.kind, "up")}
                        >
                          Up
                        </Button>{" "}
                        <Button
                          size="sm"
                          pending={busy === `${entry.kind}-down`}
                          onClick={() => void rate(entry.kind, "down")}
                        >
                          Down
                        </Button>{" "}
                        <Button
                          size="sm"
                          tone="ghost"
                          onClick={() => {
                            setNoting(entry.kind);
                            setDraft(entry.rating ? entry.rating.note : "");
                            setDraftVerdict(entry.rating?.rating === "down" ? "down" : "up");
                          }}
                        >
                          Note
                        </Button>{" "}
                        <Button
                          size="sm"
                          tone="ghost"
                          pending={busy === `${entry.kind}-`}
                          onClick={() => void rate(entry.kind, "")}
                        >
                          Clear
                        </Button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Panel>
  );
}

export function TagsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "tags");
  const path = `/binaries/${binaryId}/tags`;
  const entry = usePanel(key, () => api<{ tags: Tag[] }>(path));
  const [name, setName] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [journalAction, setJournalAction] = useState("");
  const [busy, setBusy] = useState("");

  const refresh = (): void => refreshPanel(key, () => api<{ tags: Tag[] }>(path));

  const add = async (): Promise<void> => {
    const trimmed = name.trim();
    if (!trimmed) return;
    setActionError(null);
    setJournalAction("");
    setBusy("add");
    try {
      const result = await api<{ journal_action?: string }>(path, {
        method: "POST",
        json: { name: trimmed },
      });
      setJournalAction(result.journal_action ?? "");
      setName("");
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const remove = async (tag: Tag): Promise<void> => {
    setActionError(null);
    setJournalAction("");
    setBusy(`remove-${tag.id}`);
    try {
      const result = await api<{ journal_action?: string }>(`/binaries/${binaryId}/tags/${tag.id}`, {
        method: "DELETE",
      });
      setJournalAction(result.journal_action ?? "");
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <Panel
      title="Tags"
      subtitle="Free-form labels stored locally with the binary."
      actions={
        <Toolbar>
          <Field label="Tag" hint="Enter adds">
            <input
              placeholder="tag name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && name.trim()) void add();
              }}
            />
          </Field>
          <Button tone="primary" pending={busy === "add"} onClick={() => void add()}>
            Add tag
          </Button>
        </Toolbar>
      }
    >
      <PanelBody entry={entry} hint="Loading tags">
        {(data) => (
          <DataTable
            columns={[
              { label: "Tag", key: "name" },
              {
                label: "Actions",
                render: (tag) => (
                  <div className="actions-cell">
                    <ConfirmButton
                      label="Remove"
                      message={`Remove tag ${tag.name}?`}
                      pending={busy === `remove-${tag.id}`}
                      onConfirm={() => void remove(tag)}
                    />
                  </div>
                ),
              },
            ]}
            rows={data.tags}
            rowKey={(tag) => tag.id}
            empty={<EmptyState>No tags yet. Add one from the field above.</EmptyState>}
          />
        )}
      </PanelBody>
      {actionError ? <ErrorNote error={actionError} /> : null}
      {journalAction ? (
        <p className="muted">
          Journaled as <a href={`#/journal/${journalAction}`}>{journalAction}</a>.
        </p>
      ) : null}
    </Panel>
  );
}

export function ImportsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "imports");
  const [entry, run] = useLazyPanel<ImportTable>(key);
  const [busy, setBusy] = useState(false);
  const load = (): Promise<ImportTable> => api<ImportTable>(`/binaries/${binaryId}/imports`);
  return (
    <Panel
      title="Imports"
      subtitle="The import table, read from the engine on demand."
      actions={
        <Button
          pending={busy}
          onClick={() => {
            setBusy(true);
            run(() => load().finally(() => setBusy(false)));
          }}
        >
          {entry?.state === "ready" ? "Reload imports" : "Load imports"}
        </Button>
      }
    >
      <PanelBody entry={entry} hint="Loading imports">
        {(data) => <ImportsBody data={data} />}
      </PanelBody>
    </Panel>
  );
}

function ImportsBody({ data }: { data: ImportTable }): ReactNode {
  const [filter, setFilter] = useState("");
  const imports = Array.isArray(data.imports) ? data.imports : [];
  if (!imports.length) return <Muted>No imports.</Muted>;
  const needle = filter.trim().toLowerCase();
  const shown = imports.filter(
    (row) =>
      !needle ||
      row.dll.toLowerCase().includes(needle) ||
      row.name.toLowerCase().includes(needle),
  );
  return (
    <>
      <Toolbar>
        <Field label="Filter">
          <input
            type="search"
            placeholder="library or function"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
        </Field>
      </Toolbar>
      <Muted>
        {shown.length} of {imports.length} imports
      </Muted>
      <DataTable
        columns={[
          { label: "Library", key: "dll" },
          { label: "Function", key: "name", mono: true },
          { label: "IAT", mono: true, render: (row) => row.iat_va || NA },
        ]}
        rows={shown}
        rowKey={(_row, index) => index}
        empty={<Muted>No imports match the filter.</Muted>}
      />
    </>
  );
}

export function StringsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "strings");
  const [entry, run] = useLazyPanel<StringTable>(key);
  const [busy, setBusy] = useState(false);
  const [sort, setSort] = useState<StringSort>(DEFAULT_STRING_SORT);
  const [order, setOrder] = useState<FunctionOrder>(DEFAULT_FUNCTION_ORDER);
  const path = (nextSort: StringSort, nextOrder: FunctionOrder): string =>
    `/binaries/${binaryId}/strings?sort=${nextSort}&order=${nextOrder}`;
  const load = (nextSort: StringSort, nextOrder: FunctionOrder): Promise<StringTable> =>
    api<StringTable>(path(nextSort, nextOrder));
  const changeSort = (nextSort: StringSort, nextOrder: FunctionOrder): void => {
    setSort(nextSort);
    setOrder(nextOrder);
    run(() => load(nextSort, nextOrder));
  };
  return (
    <Panel
      title="Strings"
      subtitle="Printable runs read from the data sections on demand, sorted server-side."
      actions={
        <Button
          pending={busy}
          onClick={() => {
            setBusy(true);
            run(() =>
              load(sort, order).finally(() => setBusy(false)),
            );
          }}
        >
          {entry?.state === "ready" ? "Reload strings" : "Load strings"}
        </Button>
      }
    >
      <Toolbar>
        <Field label="Sort">
          <select
            value={sort}
            onChange={(event) => changeSort(event.target.value as StringSort, order)}
          >
            {STRING_SORTS.map((option) => (
              <option key={option} value={option}>
                {option === "value" ? "Value" : "String length"}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Direction">
          <select
            value={order}
            onChange={(event) => changeSort(sort, event.target.value as FunctionOrder)}
          >
            {FUNCTION_ORDERS.map((option) => (
              <option key={option} value={option}>
                {option === "asc" ? "Ascending" : "Descending"}
              </option>
            ))}
          </select>
        </Field>
      </Toolbar>
      <PanelBody entry={entry} hint="Loading strings">
        {(data) => <StringsBody data={data} binaryId={binaryId} />}
      </PanelBody>
    </Panel>
  );
}

function StringsBody({ data, binaryId }: { data: StringTable; binaryId: number }): ReactNode {
  const [filter, setFilter] = useState("");
  const strings = Array.isArray(data.strings) ? data.strings : [];
  const total = typeof data.count === "number" ? data.count : strings.length;
  const needle = filter.trim().toLowerCase();
  const matching = needle ? strings.filter((row) => row.text.toLowerCase().includes(needle)) : strings;
  const shown = matching.slice(0, MAX_STRINGS_SHOWN);
  return (
    <>
      <Toolbar>
        <Field label="Filter">
          <input
            type="search"
            placeholder="substring"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
        </Field>
      </Toolbar>
      <Muted>
        {shown.length} of {matching.length} matching ({total} total)
      </Muted>
      <DataTable
        columns={[
          {
            label: "VA",
            mono: true,
            render: (row) =>
              row.va === null ? (
                <span className="muted">{NA}</span>
              ) : (
                <a href={`#/binaries/${binaryId}/functions?refers_to=${hex(row.va)}`}>
                  {hex(row.va)}
                </a>
              ),
          },
          { label: "Section", mono: true, render: (row) => row.section ?? NA },
          { label: "Length", numeric: true, render: (row) => row.size },
          {
            label: "String",
            mono: true,
            render: (row) =>
              row.va === null ? (
                <span title="The engine reported no address, so there is nothing to navigate to">
                  {row.text}
                </span>
              ) : (
                <a
                  href={`#/binaries/${binaryId}/functions?refers_to=${hex(row.va)}`}
                  title="Show the functions that reference this string"
                >
                  {row.text}
                </a>
              ),
          },
        ]}
        rows={shown}
        rowKey={(_row, index) => index}
        empty={<Muted>{needle ? "No strings match the filter." : "No strings."}</Muted>}
      />
      <Muted>Click a string to open the functions that reference its address.</Muted>
    </>
  );
}

export function TriagePanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "triage");
  const [entry, run] = useLazyPanel<TriageDossier>(key);
  const path = `/binaries/${binaryId}/triage`;
  const [busy, setBusy] = useState("");
  return (
    <Panel
      title="Triage"
      subtitle="One-shot dossier: toolchain, strings, imports, references and function counts."
      actions={
        <>
          <Button
            pending={busy === "view"}
            onClick={() => {
              setBusy("view");
              run(() => api<TriageDossier>(path).finally(() => setBusy("")));
            }}
          >
            View triage
          </Button>
          <Button
            tone="primary"
            pending={busy === "run"}
            onClick={() => {
              setBusy("run");
              run(() => api<TriageDossier>(path, { method: "POST" }).finally(() => setBusy("")));
            }}
          >
            Run triage
          </Button>
        </>
      }
    >
      <PanelBody entry={entry} hint="Loading the triage dossier" noScanHint={NO_SCAN_MESSAGES.triage}>
        {(data) => <TriageBody dossier={data} />}
      </PanelBody>
    </Panel>
  );
}

/**
 * The software-type badge and the threat-score meter both the triage and the
 * threat payload carry, with the signals that named the type, the points each
 * contribution added and the payload's own notes.  A `null` score renders the
 * meter's missing state rather than a zero, and the notes carry the reason.
 */
function ThreatVerdict({
  softwareType,
  score,
}: {
  softwareType?: SoftwareTypeClassification | null;
  score?: ThreatScore | null;
}): ReactNode {
  if (!softwareType && !score) return null;
  const contributions = score?.contributions ?? [];
  const bandLevel = score?.band ? THREAT_BAND_LEVELS[score.band] : undefined;
  const max = score?.max ?? 100;
  const notes = [...(softwareType?.notes ?? []), ...(score?.notes ?? [])];
  return (
    <>
      <div className="verdict">
        {softwareType ? (
          <div className="verdict-cell">
            {softwareType.type ? (
              <p className="verdict-type">
                <Badge title={softwareType.description ?? undefined}>{softwareType.type}</Badge>
                {softwareType.confidence ? (
                  <ConfidenceBadge level={softwareType.confidence} />
                ) : null}
              </p>
            ) : (
              <Muted>No software type named.</Muted>
            )}
            {softwareType.signals.length ? (
              <details>
                <summary>signals ({softwareType.signals.length})</summary>
                <ul>
                  {softwareType.signals.map((signal, index) => (
                    <li key={`${signal.kind}-${index}`} className="mono">
                      {signal.kind}: {signal.value}
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </div>
        ) : null}
        {score ? (
          <div className="verdict-cell">
            <SegmentMeter
              label="Threat score"
              value={score.score === null ? null : score.score / max}
              readout={`${score.score ?? NA} / ${max}`}
              level={bandLevel}
              title={score.notes.join(" ")}
            />
          </div>
        ) : null}
      </div>
      {contributions.length ? (
        <DataTable
          columns={[
            { label: "Contribution", key: "name" },
            { label: "Points", numeric: true, render: (row) => row.points },
            { label: "Evidence", render: (row) => row.evidence.join("; ") },
          ]}
          rows={contributions}
          rowKey={(row) => row.name}
        />
      ) : null}
      {notes.map((note) => (
        <Muted key={note}>{note}</Muted>
      ))}
    </>
  );
}

function TriageBody({ dossier }: { dossier: TriageDossier }): ReactNode {
  const rows: Array<[string, ReactNode]> = [];
  const meta = asRecord(dossier.meta) ?? {};
  for (const field of TRIAGE_META_FIELDS) {
    const value = meta[field];
    if (value === undefined || value === null) continue;
    rows.push([field, TRIAGE_HEX_FIELDS.has(field) ? hex(Number(value)) : cellText(value)]);
  }
  const toolchain = asRecord(dossier.toolchain) ?? {};
  const summary = `${String(toolchain.family ?? "")} ${String(toolchain.version_hint ?? "")}`.trim();
  if (summary) rows.push(["toolchain", summary]);
  for (const section of TRIAGE_COUNT_SECTIONS) {
    const data = asRecord(dossier[section]);
    if (!data) continue;
    const count = data.count !== undefined ? data.count : data.total;
    if (typeof count === "number") rows.push([section, String(count)]);
  }
  return (
    <>
      <ThreatVerdict softwareType={dossier.software_type} score={dossier.threat_score} />
      <KeyValue rows={rows} />
      <RawJson value={dossier} />
    </>
  );
}

export function FunctionTriagePanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "function-triage");
  const path = `/binaries/${binaryId}/function-triage`;
  const entry = usePanel(key, () => api<FunctionTriageResult>(path));
  const [limit, setLimit] = useState(String(DEFAULT_FUNCTION_TRIAGE_LIMIT));
  const [busy, setBusy] = useState(false);

  const run = (): void => {
    const parsed = Number.parseInt(limit, 10);
    const bound = Number.isNaN(parsed) ? DEFAULT_FUNCTION_TRIAGE_LIMIT : parsed;
    setBusy(true);
    refreshPanel(key, () =>
      api<FunctionTriageResult>(path, { method: "POST", json: { limit: bound } }).finally(() =>
        setBusy(false),
      ),
    );
  };

  return (
    <Panel
      title="Function triage"
      subtitle="Scores and summarizes the binary's functions, most interesting first."
      actions={
        <Toolbar>
          <Field label="Limit">
            <input
              type="number"
              min="1"
              value={limit}
              onChange={(event) => setLimit(event.target.value)}
            />
          </Field>
          <Button tone="primary" pending={busy} onClick={run}>
            Run function triage
          </Button>
        </Toolbar>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the function triage"
        noScanHint={NO_SCAN_MESSAGES.functionTriage}
      >
        {(data) => <FunctionTriageBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function FunctionTriageBody({ result }: { result: FunctionTriageResult }): ReactNode {
  const entries = Array.isArray(result.functions) ? result.functions : [];
  const skipped = Array.isArray(result.skipped) ? result.skipped : [];
  const notes = Array.isArray(result.notes) ? result.notes : [];
  const byMethod = result.by_method ?? {};
  return (
    <>
      <Muted>
        llm {byMethod.llm ?? 0}, heuristic {byMethod.heuristic ?? 0}
      </Muted>
      {entries.length === 0 ? (
        <Muted>No functions triaged.</Muted>
      ) : (
        <DataTable
          columns={[
            { label: "Score", numeric: true, render: (row) => row.score.toFixed(2) },
            { label: "Name", key: "name" },
            { label: "VA", mono: true, render: (row) => hex(row.va) },
            { label: "Size", key: "size", numeric: true },
            { label: "Status", render: (row) => <StatusCell status={row.status} /> },
            { label: "Method", render: (row) => <StatusCell status={row.method} /> },
            { label: "Summary", key: "summary" },
            {
              label: "Capabilities",
              render: (row) => (row.capabilities.length === 0 ? NA : row.capabilities.join(", ")),
            },
          ]}
          rows={entries}
          rowKey={(row) => row.function_id}
        />
      )}
      {skipped.length ? (
        <details>
          <summary>{skipped.length} skipped</summary>
          <ul>
            {skipped.map((row) => (
              <li key={row.function_id} className="mono">
                {row.name || hex(row.va)}: {row.reason}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      {notes.map((note) => (
        <Muted key={note}>{note}</Muted>
      ))}
    </>
  );
}

export function ReportPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "report");
  const [entry, run] = useLazyPanel<ReportResult>(key);
  const [pdf, setPdf] = useState<PdfReportResult | null>(null);
  const [pdfError, setPdfError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [queued, setQueued] = useState<number | null>(null);
  const path = `/binaries/${binaryId}/report`;
  const pdfPath = `${path}/pdf`;
  // The queued render: the job is the thing to watch, and the status route is
  // where the file and the job are read together.
  const jobStatus = useAsync(
    () => api<PdfStatus>(`${pdfPath}/status`),
    [queued ?? 0],
    queued !== null,
    (payload) => (payload?.job?.live ? 1500 : false),
  );
  const queuePdf = async (): Promise<void> => {
    setPdfError(null);
    setBusy("queue");
    try {
      const job = await api<JobView>("/jobs", {
        method: "POST",
        json: { kind: "report-pdf", binary_id: binaryId },
      });
      setQueued(job.id);
    } catch (error) {
      setPdfError(error);
    } finally {
      setBusy("");
    }
  };
  const generatePdf = async (): Promise<void> => {
    setPdfError(null);
    setBusy("pdf");
    try {
      setPdf(await api<PdfReportResult>(pdfPath, { method: "POST" }));
    } catch (error) {
      setPdfError(error);
    } finally {
      setBusy("");
    }
  };
  return (
    <Panel
      title="Report"
      subtitle="The coverage report and its printable PDF."
      actions={
        <>
          <Button
            pending={busy === "view"}
            onClick={() => {
              setBusy("view");
              run(() => api<ReportResult>(path).finally(() => setBusy("")));
            }}
          >
            View report
          </Button>
          <Button
            pending={busy === "run"}
            onClick={() => {
              setBusy("run");
              run(() => api<ReportResult>(path, { method: "POST" }).finally(() => setBusy("")));
            }}
          >
            Run report
          </Button>
          <Button tone="primary" pending={busy === "pdf"} onClick={() => void generatePdf()}>
            Generate PDF
          </Button>
          <Button pending={busy === "queue"} onClick={() => void queuePdf()}>
            Queue PDF
          </Button>
          <a className="btn btn-ghost" href={`/api${pdfPath}`}>
            Download PDF
          </a>
        </>
      }
    >
      <PanelBody entry={entry} hint="Loading the report" noScanHint={NO_SCAN_MESSAGES.report}>
        {(data) => <ReportBody binaryId={binaryId} result={data} />}
      </PanelBody>
      {pdfError ? <ErrorNote error={pdfError} /> : null}
      {jobStatus.error ? <ErrorNote error={jobStatus.error} /> : null}
      {jobStatus.data?.job ? (
        <Muted>
          {`PDF job ${jobStatus.data.job.id}: ${jobStatus.data.job.status}`}
          {jobStatus.data.job.error ? ` (${jobStatus.data.job.error})` : ""}
          {jobStatus.data.exists ? ` · ${jobStatus.data.pages} page(s) on disk` : ""}{" "}
          <a href={jobStatus.data.download_url}>Download PDF</a>
        </Muted>
      ) : null}
      {pdf ? (
        <Muted>
          PDF ready: {pdf.pages} page(s), {pdf.bytes} bytes.{" "}
          <a href={pdf.download_url}>Download PDF</a>
        </Muted>
      ) : null}
    </Panel>
  );
}

function ReportBody({ binaryId, result }: { binaryId: number; result: ReportResult }): ReactNode {
  const summaryRecord: Record<string, unknown> = { ...result.summary };
  const statusCounts = result.summary?.status_counts;
  return (
    <>
      <p>
        <a href={`/reports/${binaryId}/index.html`}>Open generated report site</a>
      </p>
      {result.out ? <p className="mono">out: {result.out}</p> : null}
      {Array.isArray(result.pages) ? <p className="mono">pages: {result.pages.join(", ")}</p> : null}
      <KeyValue
        rows={REPORT_SUMMARY_FIELDS.filter((field) => summaryRecord[field] !== undefined).map(
          (field) => [field, cellText(summaryRecord[field])] as [string, ReactNode],
        )}
      />
      {statusCounts && typeof statusCounts === "object" ? (
        <>
          <h3>Status counts</h3>
          <DataTable
            columns={[
              { label: "Status", render: (row) => <StatusCell status={row[0]} /> },
              { label: "Count", numeric: true, render: (row) => row[1] },
            ]}
            rows={Object.entries(statusCounts)}
            rowKey={(row) => row[0]}
          />
        </>
      ) : null}
      <RawJson value={result} />
    </>
  );
}

export function CryptoPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "crypto");
  const path = `/binaries/${binaryId}/crypto-scan`;
  const entry = usePanel(key, () => api<CryptoResult>(path));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Crypto"
      subtitle="Constant tables and crypto APIs found in the binary."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<CryptoResult>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Run crypto scan
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the crypto scan"
        noScanHint={NO_SCAN_MESSAGES.crypto}
      >
        {(data) => <CryptoBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function CryptoBody({ result }: { result: CryptoResult }): ReactNode {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const byConfidence = result.by_confidence ?? {};
  return (
    <>
      <Muted>
        {result.count || findings.length} findings (high {byConfidence.high || 0}, medium{" "}
        {byConfidence.medium || 0})
      </Muted>
      {findings.length === 0 ? (
        <Muted>No crypto indicators.</Muted>
      ) : (
        <DataTable
          columns={[
            { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
            { label: "Kind", key: "kind" },
            { label: "Name", key: "name" },
            { label: "Detail", key: "detail" },
          ]}
          rows={findings}
          rowKey={(_row, index) => index}
        />
      )}
    </>
  );
}

export function SecurityPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "security");
  const path = `/binaries/${binaryId}/security-scan`;
  const entry = usePanel(key, () => api<SecurityResult>(path));
  const [minSeverity, setMinSeverity] = useState<SecuritySeverity>(DEFAULT_SECURITY_SEVERITY);
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Security"
      subtitle="Unsafe API use and unsafe patterns in the reversed sources."
      actions={
        <Toolbar>
          <Field label="Min severity">
            <select
              value={minSeverity}
              onChange={(event) => setMinSeverity(event.target.value as SecuritySeverity)}
            >
              {SECURITY_SEVERITIES.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </Field>
          <Button
            tone="primary"
            pending={busy}
            onClick={() => {
              setBusy(true);
              refreshPanel(key, () =>
                api<SecurityResult>(path, {
                  method: "POST",
                  json: { min_severity: minSeverity },
                }).finally(() => setBusy(false)),
              );
            }}
          >
            Run security scan
          </Button>
        </Toolbar>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the security scan"
        noScanHint={NO_SCAN_MESSAGES.security}
      >
        {(data) => <SecurityBody result={data} />}
      </PanelBody>
      <ExploitabilitySection binaryId={binaryId} />
    </Panel>
  );
}

function SecurityBody({ result }: { result: SecurityResult }): ReactNode {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const bySeverity = result.by_severity ?? {};
  return (
    <>
      <Muted>
        {result.count || findings.length} findings across {result.files_scanned || 0} files (high{" "}
        {bySeverity.high || 0}, medium {bySeverity.medium || 0}, low {bySeverity.low || 0})
      </Muted>
      {findings.length === 0 ? (
        <Muted>No security findings.</Muted>
      ) : (
        <DataTable
          columns={[
            { label: "Severity", render: (row) => <SeverityBadge level={row.severity} /> },
            { label: "Rule", key: "rule" },
            { label: "CWE", key: "cwe", mono: true },
            { label: "Location", mono: true, render: (row) => `${row.file}:${row.line}` },
            { label: "Function", key: "function" },
            { label: "Snippet", mono: true, key: "snippet" },
          ]}
          rows={findings}
          rowKey={(_row, index) => index}
        />
      )}
      <RawJson value={result} />
    </>
  );
}

function ExploitabilitySection({ binaryId }: { binaryId: number }): ReactNode {
  const path = `/binaries/${binaryId}/exploitability`;
  const key = panelKey("binary", binaryId, "exploitability");
  const entry = usePanel(key, () => api<Exploitability>(path));
  if (!entry || entry.state === "loading") return <Loading label="Loading exploitability" />;
  if (entry.state === "error") {
    return String(entry.error).includes("no-scan") ? (
      <Muted>Exploitability ranks the stored security findings once a scan exists.</Muted>
    ) : (
      <ErrorNote error={entry.error} />
    );
  }
  if (!entry.data) return null;
  const rows = entry.data.rows ?? [];
  return (
    <>
      <h3>
        Exploitability ({entry.data.reachable ?? 0} reachable, {entry.data.unreachable ?? 0}{" "}
        unreachable)
      </h3>
      {rows.length === 0 ? (
        <Muted>No ranked findings.</Muted>
      ) : (
        <DataTable
          columns={[
            { label: "Severity", render: (row) => <SeverityBadge level={row.severity} /> },
            {
              label: "Reachability",
              render: (row) => (
                <>
                  {row.reachability}
                  {row.network_adjacent ? " · network" : ""}
                </>
              ),
            },
            { label: "Function", key: "function", mono: true },
            { label: "Rule", key: "rule" },
            { label: "CWE", key: "cwe", mono: true },
          ]}
          rows={rows}
          rowKey={(row) => `${row.function}:${row.rule}`}
        />
      )}
    </>
  );
}

export function CapabilitiesPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "capabilities");
  const path = `/binaries/${binaryId}/capabilities`;
  const entry = usePanel(key, () => api<CapabilitiesResult>(path));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Capabilities"
      subtitle="What the imports and strings let the binary do."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<CapabilitiesResult>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Run capability scan
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the capability scan"
        noScanHint={NO_SCAN_MESSAGES.capabilities}
      >
        {(data) => <CapabilitiesBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function CapabilitiesBody({ result }: { result: CapabilitiesResult }): ReactNode {
  const entries = Array.isArray(result.capabilities) ? result.capabilities : [];
  if (entries.length === 0) return <Muted>No capabilities detected.</Muted>;
  const summary = CAPABILITY_CONFIDENCES.map((level) => {
    const count = entries.filter((entry) => entry.confidence === level).length;
    return `${level} ${count}`;
  }).join(", ");
  return (
    <>
      <Muted>
        {result.count || entries.length} capabilities ({summary})
      </Muted>
      <DataTable
        columns={[
          { label: "Category", key: "name" },
          { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
          {
            label: "Evidence",
            render: (row) => (
              <details>
                <summary>{row.evidence_count} items</summary>
                <ul>
                  {row.evidence.map((item, index) => (
                    <li key={`${item.kind}-${index}`} className="mono">
                      {item.kind}: {item.value}
                    </li>
                  ))}
                </ul>
              </details>
            ),
          },
          { label: "Description", key: "description" },
        ]}
        rows={entries}
        rowKey={(row) => row.name}
      />
    </>
  );
}

export function BehaviorPanel({ binaryId }: { binaryId: number }): ReactNode {
  const [domain, setDomain] = useState<BehaviorDomain>(DEFAULT_BEHAVIOR_DOMAIN);
  const key = panelKey("binary", binaryId, "behavior", domain);
  const path = `/binaries/${binaryId}/behavior/${domain}`;
  const entry = usePanel(key, () => api<BehaviorScan>(path));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Behavior"
      subtitle="Execution, networking and filesystem indicators."
      actions={
        <Toolbar>
          <Field label="Domain">
            <select
              value={domain}
              onChange={(event) => setDomain(event.target.value as BehaviorDomain)}
            >
              {BEHAVIOR_DOMAINS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </Field>
          <Button
            tone="primary"
            pending={busy}
            onClick={() => {
              setBusy(true);
              refreshPanel(key, () =>
                api<BehaviorScan>(path, { method: "POST" }).finally(() => setBusy(false)),
              );
            }}
          >
            Run behavior scan
          </Button>
        </Toolbar>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the behavior scan"
        noScanHint={`No ${domain} behavior scan yet. Run the scan to match the binary's imports and strings.`}
      >
        {(data) => <BehaviorBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function BehaviorBody({ result }: { result: BehaviorScan }): ReactNode {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const byConfidence = result.by_confidence ?? {};
  const summary = BEHAVIOR_CONFIDENCES.map((level) => `${level} ${byConfidence[level] ?? 0}`).join(", ");
  return (
    <>
      <Muted>
        {result.count || findings.length} findings ({summary})
      </Muted>
      {findings.length === 0 ? (
        <Muted>No behavior found.</Muted>
      ) : (
        <DataTable
          columns={[
            { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
            { label: "Kind", key: "kind" },
            { label: "Name", key: "name" },
            { label: "Detail", key: "detail" },
          ]}
          rows={findings}
          rowKey={(_row, index) => index}
        />
      )}
    </>
  );
}

export function HardeningPanel({ binaryId }: { binaryId: number }): ReactNode {
  const [domain, setDomain] = useState<HardeningDomain>(DEFAULT_HARDENING_DOMAIN);
  const key = panelKey("binary", binaryId, "hardening", domain);
  const path = `/binaries/${binaryId}/hardening/${domain}`;
  const entry = usePanel(key, () => api<HardeningScan>(path));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Hardening"
      subtitle="Anti-analysis and obfuscation heuristics applied to imports, strings and the fingerprint."
      actions={
        <Toolbar>
          <Field label="Domain">
            <select
              value={domain}
              onChange={(event) => setDomain(event.target.value as HardeningDomain)}
            >
              {HARDENING_DOMAINS.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </Field>
          <Button
            tone="primary"
            pending={busy}
            onClick={() => {
              setBusy(true);
              refreshPanel(key, () =>
                api<HardeningScan>(path, { method: "POST" }).finally(() => setBusy(false)),
              );
            }}
          >
            Run hardening scan
          </Button>
        </Toolbar>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the hardening scan"
        noScanHint={`No ${domain} scan yet. Run the scan to apply the ${domain} heuristics.`}
      >
        {(data) => <HardeningBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function HardeningBody({ result }: { result: HardeningScan }): ReactNode {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const byConfidence = result.by_confidence ?? {};
  const summary = HARDENING_CONFIDENCES.map((level) => `${level} ${byConfidence[level] ?? 0}`).join(
    ", ",
  );
  const likelihood = result.packer_likelihood;
  const notes = Array.isArray(result.notes) ? result.notes : [];
  return (
    <>
      {result.domain === "obfuscation" ? (
        <p>
          packer likelihood: <SeverityBadge level={likelihood ?? "low"} />
        </p>
      ) : null}
      <Muted>
        {result.count || findings.length} findings ({summary})
      </Muted>
      {findings.length === 0 ? (
        <Muted>No hardening findings.</Muted>
      ) : (
        <DataTable
          columns={[
            { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
            { label: "Category", render: (row) => <CategoryBadge category={row.category} /> },
            { label: "Name", key: "name" },
            { label: "Detail", key: "detail" },
          ]}
          rows={findings}
          rowKey={(_row, index) => index}
        />
      )}
      {notes.map((note) => (
        <Muted key={note}>{note}</Muted>
      ))}
    </>
  );
}

export function SecretsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "secrets");
  const path = `/binaries/${binaryId}/secrets`;
  const entry = usePanel(key, () => api<SecretsResult>(path));
  const [revealed, setRevealed] = useState<readonly number[]>([]);
  const [busy, setBusy] = useState(false);

  const toggle = (index: number): void => {
    setRevealed((shown) =>
      shown.includes(index) ? shown.filter((item) => item !== index) : [...shown, index],
    );
  };

  return (
    <Panel
      title="Secrets"
      subtitle="Credentials and high-entropy values found in the stored strings."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<SecretsResult>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Run secrets scan
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the secrets scan"
        noScanHint={NO_SCAN_MESSAGES.secrets}
      >
        {(data) => <SecretsBody result={data} revealed={revealed} onToggle={toggle} />}
      </PanelBody>
    </Panel>
  );
}

function SecretsBody({
  result,
  revealed,
  onToggle,
}: {
  result: SecretsResult;
  revealed: readonly number[];
  onToggle: (index: number) => void;
}): ReactNode {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const byConfidence = result.by_confidence ?? {};
  const summary = SECRET_CONFIDENCES.map((level) => `${level} ${byConfidence[level] ?? 0}`).join(", ");
  return (
    <>
      <Note tone="warn">
        Found values are live secrets and are sensitive. They are stored locally and shown redacted
        until revealed.
      </Note>
      <Muted>
        {result.count || findings.length} findings ({summary}), {result.scanned || 0} strings scanned
      </Muted>
      {findings.length === 0 ? (
        <Muted>No secrets found.</Muted>
      ) : (
        <DataTable
          columns={[
            { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
            { label: "Kind", key: "kind" },
            { label: "Name", key: "name" },
            {
              label: "Value",
              mono: true,
              render: (row, index) => (
                <span className="toolbar">
                  <span className="mono">
                    {revealed.includes(index) ? row.value : row.redacted}
                  </span>
                  <Button size="sm" onClick={() => onToggle(index)}>
                    {revealed.includes(index) ? "Hide" : "Reveal"}
                  </Button>
                </span>
              ),
            },
            {
              label: "VA",
              mono: true,
              render: (row) => (row.va === null || row.va === undefined ? NA : hex(row.va)),
            },
          ]}
          rows={findings}
          rowKey={(_row, index) => index}
        />
      )}
      <RawJson value={result} />
    </>
  );
}

export function ProtocolsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "protocols");
  const path = `/binaries/${binaryId}/protocols`;
  const entry = usePanel(key, () => api<ProtocolsResult>(path));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Protocols"
      subtitle="Protocols inferred from APIs, URL schemes, ports and literals."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<ProtocolsResult>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Run protocol scan
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the protocol inference"
        noScanHint={NO_SCAN_MESSAGES.protocols}
      >
        {(data) => <ProtocolsBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function ProtocolsBody({ result }: { result: ProtocolsResult }): ReactNode {
  const entries = Array.isArray(result.protocols) ? result.protocols : [];
  const byConfidence = result.by_confidence ?? {};
  const summary = PROTOCOL_CONFIDENCES.map((level) => `${level} ${byConfidence[level] ?? 0}`).join(", ");
  if (entries.length === 0) return <Muted>No protocols inferred.</Muted>;
  return (
    <>
      <Muted>
        {result.count || entries.length} protocols ({summary})
      </Muted>
      <DataTable
        columns={[
          { label: "Protocol", key: "protocol" },
          { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
          {
            label: "Ports",
            mono: true,
            render: (row) => (row.ports.length === 0 ? NA : row.ports.join(", ")),
          },
          {
            label: "Evidence",
            render: (row) => (
              <details>
                <summary>{row.evidence.length} items</summary>
                <ul>
                  {row.evidence.map((item, index) => (
                    <li key={`${item.kind}-${index}`} className="mono">
                      {item.kind}: {item.value}
                    </li>
                  ))}
                </ul>
              </details>
            ),
          },
          { label: "Description", key: "description" },
        ]}
        rows={entries}
        rowKey={(row) => row.protocol}
      />
    </>
  );
}

export function ThreatPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "threat");
  const path = `/binaries/${binaryId}/threat`;
  const entry = usePanel(key, () => api<ThreatReport>(path));
  const [narrative, setNarrative] = useState(false);
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Threat report"
      subtitle="Indicators of compromise extracted from strings, imports and references."
      actions={
        <Toolbar>
          <CheckboxField
            label="Ask the LLM for a narrative"
            checked={narrative}
            onChange={setNarrative}
          />
          <Button
            tone="primary"
            pending={busy}
            onClick={() => {
              setBusy(true);
              refreshPanel(key, () =>
                api<ThreatReport>(path, { method: "POST", json: { narrative } }).finally(() =>
                  setBusy(false),
                ),
              );
            }}
          >
            Run threat report
          </Button>
        </Toolbar>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the threat report"
        noScanHint={NO_SCAN_MESSAGES.threat}
      >
        {(data) => <ThreatBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

/** The attack surface, composed at read time from the binary's stored scans. */
export function AttackSurfacePanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "attack-surface");
  const path = `/binaries/${binaryId}/attack-surface`;
  const entry = usePanel(key, () => api<AttackSurface>(path));
  return (
    <Panel
      title="Attack surface"
      subtitle="Network entries, local input handlers and crypto use, read off the stored scans."
      actions={
        <Button size="sm" tone="ghost" onClick={() => refreshPanel(key, () => api(path))}>
          Refresh
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the attack surface"
        noScanHint="No attack-surface source scan yet. Run a capabilities, protocols, threat, behavior or crypto scan first."
      >
        {(data) => <AttackSurfaceBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function AttackSurfaceGroup({
  title,
  rows,
  total,
}: {
  title: string;
  rows: AttackSurfaceRow[];
  total: number;
}): ReactNode {
  if (!total) return <Muted>No {title.toLowerCase()} entries in the stored scans.</Muted>;
  return (
    <>
      <h3>
        {title} ({total})
      </h3>
      <DataTable
        columns={[
          { label: "Name", mono: true, render: (row) => row.name },
          { label: "Source", mono: true, render: (row) => row.source },
          { label: "Confidence", render: (row) => row.confidence || "—" },
          {
            label: "Evidence",
            numeric: true,
            render: (row) => String(row.evidence_count),
          },
        ]}
        rows={rows}
        rowKey={(row) => `${row.source}:${row.name}`}
      />
    </>
  );
}

function AttackSurfaceBody({ result }: { result: AttackSurface }): ReactNode {
  return (
    <>
      <Muted>
        {result.binary_name}: {result.network.count} network, {result.local_input.count} local
        input, {result.crypto.count} crypto.
      </Muted>
      <AttackSurfaceGroup title="Network" rows={result.network.rows} total={result.network.count} />
      <AttackSurfaceGroup
        title="Local input"
        rows={result.local_input.rows}
        total={result.local_input.count}
      />
      <AttackSurfaceGroup title="Crypto" rows={result.crypto.rows} total={result.crypto.count} />
      <Muted>
        Sources:{" "}
        {result.sources
          .map((source) => `${source.scan} (${source.stored ? "stored" : source.command})`)
          .join(", ")}
        .
      </Muted>
    </>
  );
}

function ThreatBody({ result }: { result: ThreatReport }): ReactNode {
  const iocs = result.iocs ?? {};
  const counts = result.ioc_counts ?? {};
  const techniques = Array.isArray(result.techniques) ? result.techniques : [];
  const total = THREAT_IOC_CATEGORIES.reduce(
    (sum, category) => sum + (counts[category] ?? (iocs[category]?.length || 0)),
    0,
  );
  return (
    <>
      <ThreatVerdict softwareType={result.software_type} score={result.threat_score} />
      {result.narrative?.summary ? (
        <>
          <h3>Summary</h3>
          <p>{result.narrative.summary}</p>
        </>
      ) : null}
      <Muted>{total} indicators of compromise</Muted>
      {THREAT_IOC_CATEGORIES.map((category) => {
        const findings = iocs[category] ?? [];
        return (
          <details key={category}>
            <summary>
              {category} ({counts[category] ?? findings.length})
            </summary>
            {findings.length === 0 ? (
              <Muted>None.</Muted>
            ) : (
              <ul>
                {findings.map((finding, index) => (
                  <li key={`${finding.value}-${index}`} className="mono">
                    {finding.value} <span className="muted">({finding.kind})</span>
                  </li>
                ))}
              </ul>
            )}
          </details>
        );
      })}
      <h3>Techniques</h3>
      {techniques.length === 0 ? (
        <Muted>No ATT&amp;CK techniques mapped.</Muted>
      ) : (
        <DataTable
          columns={[
            {
              label: "ID",
              mono: true,
              render: (row) => (
                <a
                  href={`${MITRE_TECHNIQUE_URL}${encodeURIComponent(row.id)}/`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {row.id}
                </a>
              ),
            },
            { label: "Technique", key: "name" },
            { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
            {
              label: "Evidence",
              render: (row) => (
                <details>
                  <summary>{row.evidence.length} items</summary>
                  <ul>
                    {row.evidence.map((item, index) => (
                      <li key={`${item.kind}-${index}`} className="mono">
                        {item.kind}: {item.value}
                      </li>
                    ))}
                  </ul>
                </details>
              ),
            },
          ]}
          rows={techniques}
          rowKey={(row) => row.id}
        />
      )}
      {result.notes?.length ? <Muted>{result.notes.join("; ")}</Muted> : null}
      <RawJson value={result} />
    </>
  );
}

export function RemediationPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "remediation");
  const path = `/binaries/${binaryId}/remediation`;
  const entry = usePanel(key, () => api<RemediationResult>(path));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Remediation"
      subtitle="Detection artifacts generated from the threat report."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<RemediationResult>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Generate
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the remediation artifacts"
        noScanHint={NO_SCAN_MESSAGES.remediation}
      >
        {(data) => <RemediationBody binaryId={binaryId} result={data} />}
      </PanelBody>
    </Panel>
  );
}

/** The stored artifact of one remediation format, as the raw read serves it. */
function remediationArtifact(binaryId: number, format: string): string {
  return `/api/binaries/${binaryId}/remediation/${format}`;
}

function RemediationBody({
  binaryId,
  result,
}: {
  binaryId: number;
  result: RemediationResult;
}): ReactNode {
  const validation = result.validated
    ? `validated by ${result.validator ?? "yarac"}`
    : result.validator
      ? "validation failed"
      : "not validated (yarac unavailable)";
  const snortText = result.snort?.text ?? "";
  const stix = result.stix;
  const stixText = stix ? JSON.stringify(stix, null, 2) : "";
  const snortNotes = result.snort?.notes ?? [];
  return (
    <>
      <Muted>
        {result.rule_name} · {result.string_count} strings · {result.import_count} imports ·
        specificity {result.specificity} · {validation}
      </Muted>
      <details open>
        <summary>
          YARA{" "}
          {result.rule ? (
            <a className="btn btn-ghost btn-sm" href={remediationArtifact(binaryId, "yara")}>
              Download
            </a>
          ) : null}
        </summary>
        {result.rule ? (
          <CodeBlock text={result.rule} title="yara" />
        ) : (
          <Muted>No YARA rule in this scan.</Muted>
        )}
      </details>
      <details open>
        <summary>
          Snort{" "}
          {snortText ? (
            <a className="btn btn-ghost btn-sm" href={remediationArtifact(binaryId, "snort")}>
              Download
            </a>
          ) : null}
        </summary>
        {snortText ? (
          <CodeBlock text={snortText} title="snort" />
        ) : (
          <Muted>No Snort rules: the stored threat scan names no network indicator.</Muted>
        )}
      </details>
      <details>
        <summary>
          STIX{" "}
          {stixText ? (
            <a className="btn btn-ghost btn-sm" href={remediationArtifact(binaryId, "stix")}>
              Download
            </a>
          ) : null}
        </summary>
        {stixText ? (
          <CodeBlock text={stixText} title="stix" />
        ) : (
          <Muted>No STIX bundle in this scan.</Muted>
        )}
      </details>
      {snortNotes.length ? <Muted>{snortNotes.join("; ")}</Muted> : null}
      {result.notes.length ? <Muted>{result.notes.join("; ")}</Muted> : null}
    </>
  );
}

export function UnstripPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "unstrip");
  const binaryKey = panelKey("binary", binaryId);
  const path = `/binaries/${binaryId}/unstrip`;
  const loader = (): Promise<UnstripResult> => api<UnstripResult>(path);
  const entry = usePanel(key, loader);
  const [minConfidence, setMinConfidence] = useState(String(DEFAULT_MIN_CONFIDENCE));
  const [applied, setApplied] = useState<number[]>([]);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const run = (): void => {
    const parsed = Number.parseFloat(minConfidence);
    const bound = Number.isNaN(parsed) ? DEFAULT_MIN_CONFIDENCE : parsed;
    setBusy("run");
    refreshPanel(key, () =>
      api<UnstripResult>(path, { method: "POST", json: { min_confidence: bound } }).finally(() =>
        setBusy(""),
      ),
    );
  };

  const apply = async (proposal: UnstripProposal): Promise<void> => {
    setActionError(null);
    setBusy(`apply-${proposal.function_id}`);
    try {
      await api(`/binaries/${binaryId}/unstrip/apply`, {
        method: "POST",
        json: { function_id: proposal.function_id },
      });
      setApplied((ids) => (ids.includes(proposal.function_id) ? ids : [...ids, proposal.function_id]));
      refreshPanel(binaryKey, () => api<Binary>(`/binaries/${binaryId}`));
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  const applyAll = async (proposals: UnstripProposal[]): Promise<void> => {
    setActionError(null);
    setBusy("apply-all");
    try {
      for (const proposal of proposals) {
        await api(`/binaries/${binaryId}/unstrip/apply`, {
          method: "POST",
          json: { function_id: proposal.function_id },
        });
        setApplied((ids) => [...ids, proposal.function_id]);
      }
      refreshPanel(binaryKey, () => api<Binary>(`/binaries/${binaryId}`));
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <Panel
      title="Auto-unstrip"
      subtitle="Library functions identified from FLIRT signatures, imports and CRT cross-references."
      actions={
        <Toolbar>
          <Field label="Min confidence">
            <input
              type="number"
              min="0"
              max="1"
              step="0.05"
              value={minConfidence}
              onChange={(event) => setMinConfidence(event.target.value)}
            />
          </Field>
          <Button tone="primary" pending={busy === "run"} onClick={run}>
            Run auto-unstrip
          </Button>
        </Toolbar>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the unstrip proposals"
        noScanHint={NO_SCAN_MESSAGES.unstrip}
      >
        {(data) => {
          const proposals = (Array.isArray(data.proposals) ? data.proposals : []).filter(
            (proposal) => !applied.includes(proposal.function_id),
          );
          return (
            <>
              <Muted>
                {data.candidates || 0} candidates, {proposals.length} proposals
              </Muted>
              {proposals.length === 0 ? (
                <Muted>No unstrip proposals.</Muted>
              ) : (
                <>
                  <Toolbar>
                    <ConfirmButton
                      label={`Apply all listed (${proposals.length})`}
                      message={`Apply ${proposals.length}?`}
                      pending={busy === "apply-all"}
                      onConfirm={() => void applyAll(proposals)}
                    />
                  </Toolbar>
                  <DataTable
                    columns={[
                      { label: "VA", mono: true, render: (row) => hex(row.va) },
                      { label: "Current", key: "current_name", mono: true },
                      { label: "Proposed", key: "proposed_name", mono: true },
                      { label: "Module", key: "module" },
                      { label: "Kind", key: "kind" },
                      {
                        label: "Confidence",
                        numeric: true,
                        render: (row) => Number(row.confidence).toFixed(2),
                      },
                      {
                        label: "Actions",
                        render: (row) => (
                          <div className="actions-cell">
                            <Button
                              size="sm"
                              pending={busy === `apply-${row.function_id}`}
                              onClick={() => void apply(row)}
                            >
                              Apply
                            </Button>
                          </div>
                        ),
                      },
                    ]}
                    rows={proposals}
                    rowKey={(row) => row.function_id}
                  />
                </>
              )}
            </>
          );
        }}
      </PanelBody>
      {actionError ? <ErrorNote error={actionError} /> : null}
    </Panel>
  );
}

export function LineagePanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "lineage");
  const path = `/binaries/${binaryId}/lineage`;
  const entry = usePanel(key, () => api<LineageList>(path));
  const candidatesEntry = usePanel(panelKey("binary", binaryId, "lineage-candidates"), () =>
    api<{ binaries: Binary[] }>("/binaries"),
  );
  const [otherId, setOtherId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  const comparisons = entry?.state === "ready" ? entry.data.comparisons : [];
  const activeId = otherId ?? comparisons[0]?.right_binary_id ?? null;
  const comparison =
    activeId === null
      ? null
      : (comparisons.find((item) => item.right_binary_id === activeId) ?? null);
  const candidates = (candidatesEntry?.state === "ready" ? candidatesEntry.data.binaries : []).filter(
    (binary) => binary.id !== binaryId,
  );

  const run = (): void => {
    if (activeId === null) return;
    setOtherId(activeId);
    setBusy(true);
    refreshPanel(key, async () => {
      await api<LineageComparison>(path, {
        method: "POST",
        json: { other_binary_id: activeId },
      });
      const list = await api<LineageList>(path);
      setBusy(false);
      return list;
    });
  };

  return (
    <Panel
      title="Lineage"
      subtitle="Function-level comparison against another registered copy of this binary."
      actions={
        <Toolbar>
          <Field label="Compare with">
            <select
              value={activeId ?? ""}
              onChange={(event) => {
                const value = event.target.value;
                setOtherId(value === "" ? null : Number(value));
              }}
            >
              <option value="">Select a binary</option>
              {candidates.map((binary) => (
                <option key={binary.id} value={binary.id}>
                  {binary.name}
                </option>
              ))}
            </select>
          </Field>
          <Button tone="primary" pending={busy} onClick={run} disabled={activeId === null}>
            Run comparison
          </Button>
        </Toolbar>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the lineage comparisons"
        onRetry={() => refreshPanel(key, () => api<LineageList>(path))}
      >
        {() =>
          comparison === null ? (
            <EmptyState>
              Nothing compared yet. Pick another binary and run the comparison.
            </EmptyState>
          ) : (
            <LineageBody comparison={comparison} />
          )
        }
      </PanelBody>
    </Panel>
  );
}

function LineageFunctionCell({
  functionId,
  name,
  va,
}: {
  functionId: number | null;
  name: string | null;
  va: number | null;
}): ReactNode {
  if (functionId === null) return NA;
  const label = name?.trim() || `#${functionId}`;
  return (
    <a href={`#/functions/${functionId}`} className="mono">
      {label}
      {va === null ? "" : ` @ ${hex(va)}`}
    </a>
  );
}

function LineageBody({ comparison }: { comparison: LineageComparison }): ReactNode {
  const summary = comparison.summary;
  return (
    <>
      <Muted>
        {comparison.left_name} vs {comparison.right_name}
      </Muted>
      <KeyValue
        rows={[
          ["unchanged", String(summary.unchanged)],
          ["changed", String(summary.changed)],
          ["removed", String(summary.removed)],
          ["added", String(summary.added)],
          ["matched percent", `${summary.matched_percent}%`],
          [
            "refined",
            comparison.refined ? "yes (structural similarity)" : "no (name and size only)",
          ],
        ]}
      />
      {LINEAGE_ROW_STATUSES.map((status) => {
        const rows = comparison.rows.filter((row) => row.status === status);
        if (rows.length === 0) return null;
        const shown = rows.slice(0, MAX_LINEAGE_ROWS_SHOWN);
        return (
          <div key={status}>
            <h3>{status}</h3>
            <Muted>
              {rows.length} functions
              {shown.length < rows.length ? `, showing ${shown.length}` : ""}
            </Muted>
            <DataTable
              columns={[
                {
                  label: "Left",
                  render: (row) => (
                    <LineageFunctionCell
                      functionId={row.left_function_id}
                      name={row.left_name}
                      va={row.left_va}
                    />
                  ),
                },
                {
                  label: "Right",
                  render: (row) => (
                    <LineageFunctionCell
                      functionId={row.right_function_id}
                      name={row.right_name}
                      va={row.right_va}
                    />
                  ),
                },
                {
                  label: "Size",
                  render: (row) => `${row.left_size ?? NA} -> ${row.right_size ?? NA}`,
                },
                {
                  label: "Similarity",
                  numeric: true,
                  render: (row) => (row.similarity === null ? NA : row.similarity.toFixed(1)),
                },
              ]}
              rows={shown}
              rowKey={(row) => `${row.left_function_id ?? "none"}-${row.right_function_id ?? "none"}`}
            />
          </div>
        );
      })}
    </>
  );
}

export function DetectPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "detect");
  const path = `/binaries/${binaryId}/detect`;
  const entry = usePanel(key, () => api<DetectResult>(path));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Detect"
      subtitle="Matches this binary against the locally registered malware families."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<DetectResult>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Run detect
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the family detection"
        noScanHint={NO_SCAN_MESSAGES.detect}
      >
        {(data) => <DetectBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

function DetectNotes({ notes }: { notes: string[] }): ReactNode {
  if (!Array.isArray(notes) || notes.length === 0) return null;
  return <Muted>{notes.join(" · ")}</Muted>;
}

function DetectBody({ result }: { result: DetectResult }): ReactNode {
  const matches = Array.isArray(result.matches) ? result.matches : [];
  if (matches.length === 0) {
    return (
      <>
        <Muted>
          No registered family matched this binary ({result.families_checked} checked).
        </Muted>
        <DetectNotes notes={result.notes} />
      </>
    );
  }
  const summary = DETECT_CONFIDENCES.map((level) => {
    const count = matches.filter((match) => match.confidence === level).length;
    return `${level} ${count}`;
  }).join(", ");
  return (
    <>
      <Muted>
        {result.count} matches of {result.families_checked} families ({summary})
      </Muted>
      <DataTable
        columns={[
          {
            label: "Family",
            render: (row) =>
              row.aliases.length > 0 ? `${row.name} (${row.aliases.join(", ")})` : row.name,
          },
          { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
          {
            label: "Signals",
            render: (row) => (
              <ul>
                {row.signals.map((signal, index) => (
                  <li key={`${signal.kind}-${index}`} className="mono">
                    {signal.kind} ({signal.confidence}): {signal.detail}
                  </li>
                ))}
              </ul>
            ),
          },
        ]}
        rows={matches}
        rowKey={(row) => row.family_id}
      />
      <DetectNotes notes={result.notes} />
    </>
  );
}

export function RelatedPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "related");
  const path = `/binaries/${binaryId}/related`;
  const entry = usePanel(key, () => api<RelatedResult>(path));
  const [busy, setBusy] = useState(false);
  return (
    <Panel
      title="Related binaries"
      subtitle="Other registered binaries ranked by fingerprint, imports, toolchain and structure."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<RelatedResult>(path, { method: "POST" }).finally(() => setBusy(false)),
            );
          }}
        >
          Run scan
        </Button>
      }
    >
      <PanelBody
        entry={entry}
        hint="Loading the related binaries"
        noScanHint={NO_SCAN_MESSAGES.related}
      >
        {(data) => <RelatedBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

/** The notes any stored scan carries, joined for one dim line. */
function ScanNotes({ notes }: { notes: string[] }): ReactNode {
  if (!Array.isArray(notes) || notes.length === 0) return null;
  return <Muted>{notes.join(" · ")}</Muted>;
}

function RelatedBody({ result }: { result: RelatedResult }): ReactNode {
  const rows = Array.isArray(result.related) ? result.related : [];
  if (rows.length === 0) {
    return (
      <>
        <Muted>No related binary found among the {result.candidates_considered} candidates.</Muted>
        <ScanNotes notes={result.notes} />
      </>
    );
  }
  return (
    <>
      <Muted>
        {result.count} related of {result.candidates_considered} candidates
      </Muted>
      <DataTable
        columns={[
          {
            label: "Classification",
            render: (row) => <StatusCell status={row.classification} />,
          },
          { label: "Confidence", render: (row) => <ConfidenceBadge level={row.confidence} /> },
          {
            label: "Binary",
            render: (row) => <a href={`#/binaries/${row.binary_id}`}>{row.name}</a>,
          },
          { label: "Similarity", numeric: true, render: (row) => row.similarity.toFixed(3) },
          {
            label: "Signals",
            render: (row) => (
              <ul>
                {row.signals.map((signal, index) => (
                  <li key={`${signal.kind}-${index}`} className="mono">
                    {signal.kind} ({signal.confidence}): {signal.detail}
                  </li>
                ))}
              </ul>
            ),
          },
        ]}
        rows={rows}
        rowKey={(row) => row.binary_id}
      />
      <ScanNotes notes={result.notes} />
    </>
  );
}

export function FirmwarePanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "firmware");
  const path = `/binaries/${binaryId}/firmware`;
  const entry = usePanel(key, () => api<FirmwareScan>(path));
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState<unknown>(null);
  const carve = (): void => {
    setBusy(true);
    setError(null);
    setMessage("");
    refreshPanel(key, () =>
      api<FirmwareScan>(path, { method: "POST" }).finally(() => setBusy(false)),
    );
  };
  const extract = (index: number): void => {
    setBusy(true);
    setError(null);
    setMessage("");
    void api<FirmwareExtraction>(`${path}/extract`, {
      method: "POST",
      json: { regions: [index] },
    })
      .then((result) => {
        const kept = result.members
          .filter((member) => member.binary_id !== null)
          .map((member) => member.name);
        setMessage(
          kept.length
            ? `Carved into collection ${result.collection_name}: ${kept.join(", ")}`
            : `Nothing registered from region ${index}.`,
        );
        refreshPanel(key, () => api<FirmwareScan>(path));
      })
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(false));
  };
  return (
    <Panel
      title="Firmware carving"
      subtitle="The embedded images this file carries, found by their magics. Nothing is executed."
      actions={
        <Button tone="primary" pending={busy} onClick={carve}>
          Carve
        </Button>
      }
    >
      {error ? <ErrorNote error={error} /> : null}
      {message ? <Muted>{message}</Muted> : null}
      <PanelBody entry={entry} hint="Loading the carve" noScanHint={NO_SCAN_MESSAGES.firmware}>
        {(data) => {
          const regions: FirmwareRegion[] = Array.isArray(data.regions) ? data.regions : [];
          const samples: { entropy: number }[] = Array.isArray(data.entropy) ? data.entropy : [];
          const peak = samples.reduce((high, sample) => Math.max(high, sample.entropy), 0);
          if (regions.length === 0) {
            return <Muted>No embedded image magic matched in {data.size} bytes.</Muted>;
          }
          return (
            <>
              <Muted>
                {data.region_count} region(s) in {data.size} bytes, {data.signatures} signature(s)
                matched; entropy sampled per {data.entropy_window} bytes, peak {peak.toFixed(2)}.
              </Muted>
              <DataTable
                columns={[
                  { label: "#", key: "index", numeric: true },
                  { label: "Offset", mono: true, render: (row) => `0x${row.offset.toString(16)}` },
                  { label: "Size", numeric: true, render: (row) => row.size.toLocaleString() },
                  { label: "Kind", render: (row) => <Badge mono>{row.kind}</Badge> },
                  { label: "Label", key: "label" },
                  { label: "Confidence", key: "confidence" },
                  { label: "Entropy", numeric: true, render: (row) => row.entropy.toFixed(2) },
                  {
                    label: "Actions",
                    render: (row) => (
                      <Button size="sm" pending={busy} onClick={() => extract(row.index)}>
                        Carve out
                      </Button>
                    ),
                  },
                ]}
                rows={regions}
                rowKey={(row) => row.index}
              />
              <Muted>{data.note}</Muted>
            </>
          );
        }}
      </PanelBody>
    </Panel>
  );
}

export function SandboxPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "sandbox");
  const statusPath = `/binaries/${binaryId}/dynamic-execution/status`;
  const status = usePanel(key, () => api<SandboxStatus>(statusPath));
  const reportPath = `/binaries/${binaryId}/dynamic-execution`;
  const [report, setReport] = useState<SandboxRun | null>(null);
  const [timeout, setTimeoutSeconds] = useState("10");
  const [memory, setMemory] = useState("512");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const current: SandboxStatus | undefined = status?.state === "ready" ? status.data : undefined;
  const detonate = (): void => {
    setError(null);
    setBusy(true);
    void api<SandboxRun>(reportPath, {
      method: "POST",
      json: { timeout: Number(timeout), memory_mb: Number(memory) },
    })
      .then((run) => {
        setReport(run);
        refreshPanel(key, () => api<SandboxStatus>(statusPath));
      })
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(false));
  };
  return (
    <Panel
      title="Sandbox detonation"
      subtitle="Run the sample under bwrap: no network, a read-only root, capped memory and CPU, and a recorded report."
      actions={
        <>
          <Field label="Seconds">
            <input
              size={4}
              value={timeout}
              onChange={(event) => setTimeoutSeconds(event.target.value)}
            />
          </Field>
          <Field label="Memory (MiB)">
            <input size={5} value={memory} onChange={(event) => setMemory(event.target.value)} />
          </Field>
          <Button
            tone="primary"
            pending={busy}
            disabled={!current?.enabled || !current?.available}
            onClick={detonate}
          >
            Detonate
          </Button>
        </>
      }
    >
      {status?.state === "error" ? (
        <ErrorNote
          error={status.error}
          onRetry={() => refreshPanel(key, () => api<SandboxStatus>(statusPath))}
        />
      ) : null}
      {error ? <ErrorNote error={error} /> : null}
      {current ? (
        <KeyValue
          rows={[
            ["opt-in", current.enabled ? <Badge tone="warn">enabled</Badge> : <Badge>off</Badge>],
            ["runner", current.runner ?? "none installed"],
            ["runners", current.runners.map((entry) => `${entry.name}${entry.available ? "" : " (missing)"}`).join(", ") || NA],
            ["runs", current.runs],
            ["last", current.last ? `${current.last.status} (exit ${current.last.exit_code ?? "n/a"})` : NA],
          ]}
        />
      ) : null}
      {current && !current.enabled ? (
        <Muted>
          Detonation is off. Set <code>REPORTAL_SANDBOX=enabled</code> or{" "}
          <code>[sandbox] enabled = true</code> to allow it.
        </Muted>
      ) : null}
      {current && current.enabled && !current.available ? (
        <Muted>No sandbox runner is installed: {current.runners.map((entry) => entry.name).join(", ") || "none declared"}.</Muted>
      ) : null}
      {report === null ? (
        <EmptyState>{NO_SCAN_MESSAGES.sandbox}</EmptyState>
      ) : (
        <SandboxReport run={report} />
      )}
    </Panel>
  );
}

/** One stored detonation report: the caps, the exit status, the output and the files. */
function SandboxReport({ run }: { run: SandboxRun }): ReactNode {
  const caps = Object.entries(run.caps)
    .map(([name, value]) => `${name} ${value}`)
    .join(", ");
  return (
    <>
      <KeyValue
        rows={[
          [
            "status",
            run.timed_out ? (
              <Badge tone="warn">timed out</Badge>
            ) : (
              <Badge tone="ok">{run.status}</Badge>
            ),
          ],
          ["runner", run.runner],
          ["exit", run.exit_code ?? NA],
          ["duration", `${run.duration_ms} ms`],
          ["caps", caps],
          ["sha256", run.sha256],
          [
            "wrote",
            run.files.length
              ? run.files.map((entry) => `${entry.path} (${entry.size})`).join(", ")
              : NA,
          ],
        ]}
      />
      {run.notes.map((note: string) => (
        <Muted key={note}>{note}</Muted>
      ))}
      {run.stdout ? <CodeBlock text={run.stdout} title="stdout" /> : null}
      {run.stderr ? <CodeBlock text={run.stderr} title="stderr" /> : null}
    </>
  );
}

export function CompositionPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "composition");
  const path = `/binaries/${binaryId}/composition`;
  const entry = usePanel(key, () => api<CompositionResult>(path));
  const [busy, setBusy] = useState(false);
  // The candidate scope, in the same vocabulary the Match Settings sheet uses:
  // a comma-separated id list each, empty meaning the whole register.
  const [binaryScope, setBinaryScope] = useState("");
  const [collectionScope, setCollectionScope] = useState("");
  const scopeBody = (): Record<string, number[]> => {
    const ids = (value: string): number[] =>
      value
        .split(",")
        .map((part) => Number(part.trim()))
        .filter((id) => Number.isFinite(id) && id > 0);
    return { binary_ids: ids(binaryScope), collection_ids: ids(collectionScope) };
  };
  return (
    <Panel
      title="Composition analysis"
      subtitle="How this binary's functions match the other registered binaries, from the stored matches."
      actions={
        <Button
          tone="primary"
          pending={busy}
          onClick={() => {
            setBusy(true);
            refreshPanel(key, () =>
              api<CompositionResult>(path, { method: "POST", json: scopeBody() }).finally(() =>
                setBusy(false),
              ),
            );
          }}
        >
          Run analysis
        </Button>
      }
    >
      <Toolbar>
        <Field label="Scope to binaries">
          <input
            placeholder="ids, comma separated"
            value={binaryScope}
            onChange={(event) => setBinaryScope(event.target.value)}
          />
        </Field>
        <Field label="Scope to collections">
          <input
            placeholder="ids, comma separated"
            value={collectionScope}
            onChange={(event) => setCollectionScope(event.target.value)}
          />
        </Field>
        <Muted>
          Empty means the whole register. Only the stored edges are read either way, so a scope
          narrows the reading, never the matching.
        </Muted>
      </Toolbar>
      <PanelBody
        entry={entry}
        hint="Loading the composition analysis"
        noScanHint={NO_SCAN_MESSAGES.composition}
        onRetry={() => refreshPanel(key, () => api<CompositionResult>(path))}
      >
        {(data) => <CompositionBody result={data} />}
      </PanelBody>
    </Panel>
  );
}

/** The hosted composition categories, each with the binaries it most matched. */
function CompositionCategories({
  categories,
}: {
  categories: CompositionCategory[];
}): ReactNode {
  if (!categories?.length) return null;
  return (
    <>
      <h3>Categories</h3>
      <DataTable
        columns={[
          { label: "Category", key: "label" },
          { label: "Functions", numeric: true, render: (row) => row.count },
          {
            label: "Percent",
            numeric: true,
            render: (row) => (row.percent === null ? NA : `${row.percent}%`),
          },
          {
            label: "Top binaries",
            render: (row) =>
              row.binaries.length
                ? row.binaries.map((entry) => `${entry.name} (${entry.count})`).join(", ")
                : NA,
          },
        ]}
        rows={categories}
        rowKey={(row) => row.category}
      />
    </>
  );
}

/** One count/percent breakdown rendered as a meter per label. */
function CompositionBreakdown({
  title,
  entries,
  hueFor,
}: {
  title: string;
  entries: Array<{ label: string; count: number; percent: number | null }>;
  hueFor?: (label: string) => HueFamily | null;
}): ReactNode {
  return (
    <>
      <h3>{title}</h3>
      {entries.map((entry) => (
        <SegmentMeter
          key={entry.label}
          label={entry.label}
          value={entry.percent === null ? null : entry.percent / 100}
          readout={`${entry.count}${entry.percent === null ? "" : ` (${entry.percent}%)`}`}
          hue={hueFor?.(entry.label) ?? undefined}
        />
      ))}
    </>
  );
}

function CompositionFunctionCell({ row }: { row: CompositionFunctionRow }): ReactNode {
  const label = row.name.trim() || `#${row.function_id}`;
  return (
    <a href={`#/functions/${row.function_id}`} className="mono">
      {label}
    </a>
  );
}

function CompositionBody({ result }: { result: CompositionResult }): ReactNode {
  const total = result.total_functions;
  const matched = result.matched_functions;
  const percent = result.matched_percent;
  const fraction = total > 0 ? matched / total : null;
  const readout = percent === null ? `${matched} / ${total}` : `${matched} / ${total} (${percent}%)`;
  const rows = Array.isArray(result.functions) ? result.functions : [];
  const shown = rows.slice(0, MAX_COMPOSITION_ROWS_SHOWN);
  return (
    <>
      <SegmentMeter
        label="Matched"
        value={fraction}
        readout={readout}
        title="Functions with at least one stored match against another binary"
      />
      <KeyValue
        rows={[
          ["total functions", String(total)],
          ["matched functions", String(matched)],
          ["matched percent", percent === null ? NA : `${percent}%`],
          ["refined", result.refined ? "yes (stored matches)" : "no (no stored matches)"],
        ]}
      />
      <CompositionBreakdown title="Function name sources" entries={result.name_sources} />
      <CompositionBreakdown
        title="Match quality"
        entries={result.match_quality}
        hueFor={qualityHue}
      />
      <CompositionCategories categories={result.categories} />
      <h3>Composition</h3>
      <DataTable
        columns={[
          {
            label: "Binary",
            render: (row) => <a href={`#/binaries/${row.binary_id}`}>{row.name}</a>,
          },
          { label: "sha256", mono: true, render: (row) => row.sha256 ?? NA },
          { label: "Functions", numeric: true, render: (row) => row.count },
          {
            label: "Percent",
            numeric: true,
            render: (row) => (row.percent === null ? NA : `${row.percent}%`),
          },
        ]}
        rows={result.composition}
        rowKey={(row) => row.binary_id}
        empty={<Muted>No function matched another registered binary.</Muted>}
      />
      <h3>Functions</h3>
      <DataTable
        columns={[
          { label: "Function", render: (row) => <CompositionFunctionCell row={row} /> },
          { label: "VA", mono: true, render: (row) => hex(row.va) },
          { label: "Size", numeric: true, render: (row) => row.size },
          {
            label: "Band",
            render: (row) => (
              <Badge hue={qualityHue(row.band) ?? undefined}>{row.band}</Badge>
            ),
          },
          {
            label: "Similarity",
            numeric: true,
            render: (row) => (row.similarity === null ? NA : `${row.similarity.toFixed(1)}%`),
          },
          {
            label: "Matched binary",
            render: (row) =>
              row.matched_binary_id === null ? (
                <Badge>No match</Badge>
              ) : (
                <a href={`#/binaries/${row.matched_binary_id}`}>
                  {row.matched_binary_name ?? `#${row.matched_binary_id}`}
                </a>
              ),
          },
        ]}
        rows={shown}
        rowKey={(row) => row.function_id}
        empty={<EmptyState>This binary has no functions to compare.</EmptyState>}
      />
      {shown.length < rows.length ? (
        <Muted>
          Showing {shown.length} of {rows.length} function rows.
        </Muted>
      ) : null}
      <ScanNotes notes={result.notes} />
    </>
  );
}

// ── Library identification and the bill of materials ───────────────
//
// The engine's signature match says which libraries a binary is built from.
// The panel shows the module rollup, exports the same reading as CycloneDX,
// SPDX or CSV, and links each identified function back to the function view.

export function LibraryPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "library");
  const path = `/binaries/${binaryId}/library`;
  const entry = usePanel(key, () => api<LibraryResult>(path));
  const [minConfidence, setMinConfidence] = useState("0");
  const [format, setFormat] = useState("cyclonedx");
  const [busy, setBusy] = useState("");
  const [exported, setExported] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);

  const run = (): void => {
    const parsed = Number.parseFloat(minConfidence);
    const bound = Number.isNaN(parsed) ? 0 : parsed;
    setBusy("run");
    refreshPanel(key, () =>
      api<LibraryResult>(path, { method: "POST", json: { min_confidence: bound } }).finally(() =>
        setBusy(""),
      ),
    );
  };

  const download = async (): Promise<void> => {
    setActionError(null);
    setBusy("export");
    try {
      const response = await fetch(`/api/binaries/${binaryId}/sbom?format=${format}`);
      if (!response.ok) throw new Error(`export failed: ${response.status}`);
      const text = await response.text();
      setExported(text.slice(0, 4000));
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <Panel
      title="Library identification"
      subtitle="Which libraries the engine's signature match found in this binary, and the bill of materials it feeds."
      actions={
        <Button tone="primary" pending={busy === "run"} onClick={run}>
          Identify libraries
        </Button>
      }
    >
      {actionError ? <ErrorNote error={actionError} /> : null}
      <Toolbar>
        <Field label="Minimum confidence" hint="0 keeps every candidate the engine reports.">
          <input
            type="number"
            min="0"
            max="1"
            step="0.05"
            value={minConfidence}
            onChange={(event) => setMinConfidence(event.target.value)}
          />
        </Field>
        <Field label="Export format">
          <select value={format} onChange={(event) => setFormat(event.target.value)}>
            <option value="cyclonedx">CycloneDX</option>
            <option value="spdx">SPDX</option>
            <option value="csv">CSV</option>
          </select>
        </Field>
        <Button pending={busy === "export"} onClick={() => void download()}>
          Export
        </Button>
      </Toolbar>
      {entry === undefined ? (
        <Loading label="Loading the library reading" rows={3} />
      ) : entry.state === "error" ? (
        <ErrorNote
          error={entry.error}
          onRetry={() => refreshPanel(key, () => api<LibraryResult>(path))}
        />
      ) : entry.state !== "ready" ? null : entry.data.stored === false ? (
        <Muted>{entry.data.notes[0] ?? "No stored library reading."}</Muted>
      ) : (
        <>
          <Muted>
            {entry.data.candidates} identified function(s) in {entry.data.count} module(s).
            {entry.data.already_annotated
              ? ` ${entry.data.already_annotated} already annotated.`
              : ""}
          </Muted>
          {(entry.data.notes ?? []).map((note) => (
            <Muted key={note}>{note}</Muted>
          ))}
          <DataTable
            columns={[
              { label: "Module", key: "module", mono: true },
              { label: "Kinds", render: (row) => row.kinds.join(", ") },
              { label: "Functions", numeric: true, render: (row) => row.functions },
              { label: "Bytes", numeric: true, render: (row) => row.size.toLocaleString() },
              {
                label: "Confidence",
                numeric: true,
                render: (row) => row.confidence.toFixed(2),
              },
              { label: "Linkage", render: (row) => row.linkage },
            ]}
            rows={entry.data.components}
            rowKey={(row) => row.module}
            empty={<Muted>No library module was identified.</Muted>}
          />
          {entry.data.functions?.length ? (
            <DataTable
              columns={[
                { label: "VA", mono: true, render: (row) => row.va },
                { label: "Identified name", key: "name", mono: true },
                { label: "Module", key: "module", mono: true },
                { label: "Kind", key: "kind" },
                {
                  label: "Confidence",
                  numeric: true,
                  render: (row) => row.confidence.toFixed(2),
                },
                {
                  label: "Function",
                  render: (row) =>
                    row.function_id === null ? (
                      <Muted>not a stored function</Muted>
                    ) : (
                      <a href={`#/functions/${row.function_id}`}>
                        #{row.function_id}
                      </a>
                    ),
                },
              ]}
              rows={entry.data.functions}
              rowKey={(row) => row.va}
              empty={<Muted>No candidate survived the threshold.</Muted>}
            />
          ) : null}
        </>
      )}
      {exported ? <CodeBlock text={exported} title={format} /> : null}
    </Panel>
  );
}

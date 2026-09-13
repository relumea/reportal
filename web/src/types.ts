export interface Binary {
  id: number;
  sha256: string;
  name: string;
  path: string;
  size: number;
  format: string;
  arch: string;
  function_count: number;
  /** `public` to every authenticated caller, `team` to the owners' members. */
  visibility: "public" | "team";
  /** The team that owns it while `visibility` is `team`. */
  owner_team_id: number | null;
}

export interface FunctionRow {
  id: number;
  analysis_id: number;
  binary_id: number;
  va: number;
  name: string;
  size: number;
  status: string;
  name_source: string;
}

/** One analysis row, as `GET /api/analyses` returns it. */
export interface AnalysisRow {
  id: number;
  binary_id: number;
  status: string;
  engine: string;
  created_at: string;
  finished_at: string | null;
  /** The importer's summary sentence; the structured log is `logs`. */
  log: string;
  binary_name: string;
  binary_size: number;
  binary_format: string;
  binary_arch: string;
  binary_sha256: string | null;
  /** Tag names of the owning binary, name order. */
  tags: string[];
  /** The owning binary's scope: the object reportal stores a team on. */
  visibility: string;
  owner_team_id: number | null;
  owner_team_name: string | null;
}

/** `GET /api/analyses`: the page, its size and the unfiltered total. */
export interface AnalysisList {
  analyses: AnalysisRow[];
  count: number;
  total: number;
}

/** One structured log entry of an analysis, newest first. */
export interface AnalysisLogEntry {
  id: number;
  analysis_id: number;
  severity: string;
  message: string;
  created_at: string;
}

/** `GET /api/analyses/<id>/logs`: a bounded page and the log's true total. */
export interface AnalysisLogPage {
  logs: AnalysisLogEntry[];
  count: number;
  total: number;
  limit: number;
  offset: number;
}

/** `GET /api/binaries/<id>/functions`: the page and the unfiltered total. */
export interface FunctionListPage {
  functions: FunctionRow[];
  count: number;
  total: number;
}

/** The metric a match row is ranked and labelled by; difference is derived. */
export type MatchMetric = "similarity" | "confidence" | "difference";

/** What one symbol transfer copies onto the target function. */
export type TransferMode = "name" | "signature" | "both";

/** The scope a match run used; mirrors reportal.matching.MatchSettings. */
export interface MatchRunSettings {
  min_similarity: number;
  min_confidence: number;
  include_self: boolean;
  top: number;
  platforms: string[];
  architectures: string[];
  binary_ids: number[];
  collection_ids: number[];
}

export interface MatchRow {
  id: number;
  function_id: number;
  candidate_function_id: number;
  candidate_va: number;
  candidate_name: string;
  candidate_status: string;
  similarity: number;
  confidence: number;
  /** The complement `100 - similarity`, derived by the server, never stored. */
  difference: number;
  /** The quality band the similarity falls into. */
  band: string;
  settings: MatchRunSettings | null;
}

/** One recorded edge of a binary, as `GET /api/binaries/<id>/matches` returns it. */
export interface BinaryMatchRow {
  source_function_id: number;
  source_name: string;
  source_va: number;
  candidate_function_id: number;
  candidate_name: string;
  candidate_va: number;
  similarity: number;
  confidence: number;
  difference: number;
  band: string;
  settings: MatchRunSettings | null;
}

/** The stored matches of one binary plus the settings of the run that wrote them. */
export interface BinaryMatchesPayload {
  binary_id: number;
  count: number;
  settings: MatchRunSettings | null;
  notes: string[];
  matches: BinaryMatchRow[];
}

/** The response of `POST /api/binaries/<id>/match`. */
export interface MatchRunPayload {
  binary_id: number;
  functions: number;
  matched: number;
  pairs: number;
  settings: MatchRunSettings;
  notes: string[];
  journal_action?: string;
}

/** One row of the bulk transfer report. */
export interface TransferRowReport {
  function_id: number;
  candidate_function_id: number;
  mode: TransferMode;
  status: "applied" | "skipped" | "failed";
  reason: string;
  detail: string;
  name_changed: boolean;
  old_name: string;
  new_name: string;
  signature_changed: boolean;
  missing_types: string[];
}

/** The response of `POST /api/binaries/<id>/matches/transfer` and apply-match. */
export interface TransferReport {
  requested: number;
  applied: number;
  skipped: number;
  failed: number;
  dry_run: boolean;
  transfers: TransferRowReport[];
  journal_action?: string;
}

/** One aligned line of a function diff; a side is null where it has no line. */
export interface DiffEntry {
  op: "equal" | "insert" | "delete" | "replace";
  left_line: number | null;
  right_line: number | null;
  left: string | null;
  right: string | null;
}

export interface DiffSide {
  function_id: number;
  name: string;
  va: number;
}

export interface DiffSummary {
  equal: number;
  insert: number;
  delete: number;
  changed: number;
}

/** The side-by-side alignment `GET /api/functions/<id>/diff/<candidate>` returns. */
export interface FunctionDiff {
  left: DiffSide;
  right: DiffSide;
  kind: string;
  normalized: boolean;
  similarity: number | null;
  entries: DiffEntry[];
  summary: DiffSummary;
}

export interface HistoryRow {
  id: number;
  function_id: number;
  old_name: string;
  new_name: string;
  actor: string;
  source: string;
  created_at: string;
}

export interface Tag {
  id: number;
  name: string;
}

export interface Collection {
  id: number;
  name: string;
  description: string;
  scope: string;
  binary_count: number;
  /** When the collection's fields, members or tags last changed. */
  updated_at: string;
}

/** One collection's members and tags, the shape `GET /api/collections/<id>` answers. */
export interface CollectionDetail extends Collection {
  binaries: Array<{ id: number; name: string; sha256: string; size: number }>;
  tags: Array<{ id: number; name: string }>;
}

export interface Health {
  status: string;
  version: string;
  db: string;
  counts: Record<string, number>;
}

export interface SectionEntropy {
  name: string;
  va: number;
  vsize: number;
  raw_size: number;
  entropy: number;
}

export interface Fingerprint {
  md5?: string;
  sha1?: string;
  sha256?: string;
  sha512?: string;
  sha3_224?: string;
  sha3_256?: string;
  sha3_384?: string;
  sha3_512?: string;
  crc32?: string;
  format?: string;
  arch?: string;
  size?: number;
  imphash?: string | null;
  /** SHA-256 over the sorted `ordinal:name` export lines; null when unreadable. */
  export_hash?: string | null;
  rich_header_hash?: string | null;
  section_entropies?: SectionEntropy[];
}

export interface ImportEntry {
  dll: string;
  name: string;
  iat_va?: string | number | null;
}

export interface ImportTable {
  binary?: string;
  imports?: ImportEntry[];
  stubs?: unknown[];
}

/** One string as the route normalizes it: identity plus its text. */
export interface StringEntry {
  /** Virtual address, or null when the engine did not report one. */
  va: number | null;
  section: string | null;
  kind: string | null;
  size: number;
  text: string;
}

export interface StringTable {
  binary?: string;
  count?: number;
  strings?: StringEntry[];
  binary_id?: number;
  /** The order the route applied: `value` or `length`. */
  sort?: string;
  /** `asc` or `desc`. */
  order?: string;
}

export interface CountSection {
  count?: number;
  total?: number;
}

export interface TriageDossier {
  meta?: Record<string, unknown>;
  toolchain?: Record<string, unknown>;
  strings?: CountSection;
  imports?: CountSection;
  references?: CountSection;
  functions?: CountSection;
  software_type?: SoftwareTypeClassification | null;
  threat_score?: ThreatScore | null;
  [key: string]: unknown;
}

/** How one function's triage row was produced; mirrors function_triage's labels. */
export type FunctionTriageMethod = "llm" | "heuristic";

/** One function's stored triage: its score, summary and capability tags. */
export interface FunctionTriageEntry {
  function_id: number;
  name: string;
  va: number;
  size: number;
  status: string;
  score: number;
  summary: string;
  capabilities: string[];
  method: FunctionTriageMethod;
}

/** One selected function a triage run could not summarize, and why. */
export interface FunctionTriageSkipped {
  function_id: number;
  name: string;
  va: number;
  reason: string;
}

/** The run `GET`/`POST /api/binaries/<id>/function-triage` returns. */
export interface FunctionTriageResult {
  binary_id?: number;
  model?: string;
  functions?: FunctionTriageEntry[];
  count?: number;
  by_method?: Record<string, number>;
  skipped?: FunctionTriageSkipped[];
  notes?: string[];
}

export interface ReportSummary {
  total_functions?: number;
  covered_functions?: number;
  coverage_pct?: number;
  matched_pct?: number;
  byte_coverage_pct?: number;
  status_counts?: Record<string, number>;
  [key: string]: unknown;
}

export interface ReportResult {
  out?: string;
  pages?: string[];
  summary?: ReportSummary;
}

export interface PdfReportResult {
  path: string;
  bytes: number;
  pages: number;
  download_url: string;
}

export interface StructEntry {
  name: string;
  va: number;
  definition: string;
}

export interface StructResult {
  decompiled?: number;
  skipped?: number;
  structs?: StructEntry[];
}

export interface DataTypeMember {
  name: string;
  type: string;
  pointer: boolean;
  count: number | null;
  /** Bit width when the member is a bitfield; null otherwise. */
  bits: number | null;
  offset: number;
  size: number;
  note: string;
  /**
   * True when the member is the recovered `char gap_XXXX[N]` padding convention.
   * The encoded type payload derives it; a recorded history state does not carry it.
   */
  is_gap?: boolean;
}

/** Declaration kinds the model carries; mirrors the API's data_types.KINDS. */
export type DataTypeKind =
  | "struct"
  | "union"
  | "enum"
  | "typedef"
  | "pointer"
  | "array"
  | "function";

/** One named enum constant with its decimal value and hex echo. */
export interface DataTypeValue {
  name: string;
  value: number;
  hex: string;
}

/** The declared size against the extent the member list implies. */
export interface DataTypeSizeCheck {
  declared: number;
  extent: number;
  match: boolean;
  /** The disagreement, naming both numbers; null when they agree. */
  warning: string | null;
}

export interface DataType {
  id: number;
  binary_id: number;
  name: string;
  kind: DataTypeKind;
  /** Empty for a program-defined type; otherwise a `::`-separated path. */
  namespace: string;
  /** The declared size; a member write recomputes it, a Size edit stores it. */
  size: number;
  members: DataTypeMember[];
  values: DataTypeValue[];
  /** The aliased, pointed-at, element or return type text. */
  target: string;
  /** The element count of an array type; null for every other kind. */
  element_count: number | null;
  /** The padded "As C" declaration the detail pane shows. */
  as_c: string;
  size_check: DataTypeSizeCheck;
  source: string;
  created_at: string;
  updated_at: string;
}

/** One node of the namespace tree over a binary's types. */
export interface NamespaceNode {
  name: string;
  path: string;
  count: number;
  children: NamespaceNode[];
}

export interface DataTypeList {
  binary_id: number;
  count: number;
  total: number;
  types: DataType[];
  namespaces: NamespaceNode[];
  /** The count per provenance label over the whole model. */
  sources: Record<string, number>;
}

/** One type that mentions another, with the relationship it carries. */
export interface DataTypeReference {
  id: number;
  name: string;
  namespace: string;
  kind: DataTypeKind;
  relationships: string[];
}

/** One function whose stored signature names a type. */
export interface DataTypeFunctionUsage {
  function_id: number;
  name: string;
  usages: string[];
}

/** A type's reverse indices, with the note that matching is by name. */
export interface DataTypeReferences {
  data_type_id: number;
  binary_id: number;
  name: string;
  namespace: string;
  referenced_by: DataTypeReference[];
  used_by_functions: DataTypeFunctionUsage[];
  count: number;
  function_count: number;
  note: string;
}

export interface DataTypeImportResult {
  binary_id: number;
  created: number;
  updated: number;
  skipped: number;
  skipped_types: Array<{ name: string; reason: string }>;
}

export interface DataTypeExportResult {
  path: string;
  bytes: number;
  types: number;
}

/** One enum constant as a history entry records it (the stored value, no hex echo). */
export interface DataTypeHistoryValue {
  name: string;
  value: number;
}

/** One model field two history states differ in, with both values. */
export interface DataTypeChange {
  field: string;
  before: string | number | DataTypeMember[] | DataTypeHistoryValue[] | null;
  after: string | number | DataTypeMember[] | DataTypeHistoryValue[] | null;
}

/** The model state one history entry recorded, as the server stores it. */
export interface DataTypeState {
  name: string;
  kind: DataTypeKind;
  namespace: string;
  size: number;
  members: DataTypeMember[];
  values: DataTypeHistoryValue[];
  target: string;
  element_count: number | null;
  source: string;
}

/** One recorded mutation of a type, with the diff between its two states. */
export interface DataTypeHistoryEntry {
  id: number;
  data_type_id: number;
  binary_id: number;
  /** The state the mutation replaced; null when it created the type. */
  previous: DataTypeState | null;
  /** The state the mutation wrote; null when it deleted the type. */
  current: DataTypeState | null;
  source: string;
  actor: string;
  created_at: string;
  changes: DataTypeChange[];
}

/** A type's edit history; a deleted type's history is still listed. */
export interface DataTypeHistory {
  data_type_id: number;
  binary_id: number | null;
  exists: boolean;
  count: number;
  history: DataTypeHistoryEntry[];
}

/** A stored model row as the write routes return it (no derived `as_c` block). */
export interface DataTypeRow {
  id: number;
  binary_id: number;
  name: string;
  kind: DataTypeKind;
  namespace: string;
  size: number;
  members: DataTypeMember[];
  values: DataTypeHistoryValue[];
  target: string;
  element_count: number | null;
  source: string;
  created_at: string;
  updated_at: string;
}

/** What one history revert did, with the row the type now holds (or null). */
export interface DataTypeRevertResult {
  data_type_id: number;
  history_id: number;
  changed: boolean;
  reason: string;
  data_type: DataTypeRow | null;
}

/** One ordered parameter of an editable function signature. */
export interface SignatureParameter {
  index: number;
  type: string;
  name: string;
  /** Argument location the model carries: a register or a stack slot, or null. */
  at: string | null;
  /** What the argument is, or null when nobody set it. */
  kind: string | null;
  /** Width in bits, or null when nobody set it. */
  bits: number | null;
  /** Where the calling convention would pass it; derived, never stored. */
  default_at?: string | null;
}

/** An editable per-function signature parsed from the stored decompilation. */
export interface FunctionSignature {
  function_id: number;
  name: string;
  return_type: string;
  calling_convention: string;
  parameters: SignatureParameter[];
  source: string;
  created_at: string;
  updated_at: string;
}

/** A signature as its own GET returns it: the model plus the rendered prototype. */
export interface FunctionSignatureDetail extends FunctionSignature {
  prototype: string;
}

export interface SignatureImportResult {
  binary_id: number;
  created: number;
  updated: number;
  skipped: number;
  skipped_functions: Array<{ function_id: number; name: string; reason: string }>;
}

export interface SignatureExportResult {
  path: string;
  bytes: number;
  signatures: number;
}

export interface CryptoFinding {
  confidence: string;
  kind: string;
  name: string;
  detail?: string;
}

export interface CryptoResult {
  count?: number;
  findings?: CryptoFinding[];
  by_confidence?: Record<string, number>;
}

export interface SecurityFinding {
  rule: string;
  cwe: string;
  severity: string;
  confidence: string;
  file: string;
  line: number;
  function: string;
  snippet: string;
  message?: string;
}

export interface SecurityResult {
  root?: string;
  files_scanned?: number;
  count?: number;
  findings?: SecurityFinding[];
  by_severity?: Record<string, number>;
}

export interface UnstripProposal {
  function_id: number;
  va: number;
  current_name: string;
  proposed_name: string;
  module: string;
  kind: string;
  confidence: number;
}

export interface UnstripResult {
  candidates?: number;
  proposals?: UnstripProposal[];
  applied?: boolean;
}

export interface CapabilityEvidence {
  kind: string;
  value: string;
}

export interface CapabilityEntry {
  name: string;
  description: string;
  confidence: string;
  evidence: CapabilityEvidence[];
  evidence_count: number;
}

export interface CapabilitiesResult {
  binary_id?: number;
  capabilities?: CapabilityEntry[];
  count?: number;
}

/** One behavior finding the execution/networking/filesystem scan reports. */
export interface BehaviorFinding {
  kind: string;
  name: string;
  detail: string;
  confidence: string;
  count: number;
}

/** One domain's stored behavior scan as its GET/POST route returns it. */
export interface BehaviorScan {
  binary_id?: number;
  domain?: string;
  findings?: BehaviorFinding[];
  count?: number;
  by_confidence?: Record<string, number>;
}

/** One credential or high-entropy value a secrets scan found. */
export interface SecretFinding {
  kind: string;
  name: string;
  value: string;
  redacted: string;
  va: number | null;
  confidence: string;
}

/** The secrets scan `GET`/`POST /api/binaries/<id>/secrets` returns. */
export interface SecretsResult {
  binary_id?: number;
  findings?: SecretFinding[];
  count?: number;
  by_confidence?: Record<string, number>;
  scanned?: number;
}

/** One piece of evidence a protocol inference carries. */
export interface ProtocolEvidence {
  kind: string;
  value: string;
}

/** One protocol a scan inferred, with its evidence and well-known ports. */
export interface ProtocolEntry {
  protocol: string;
  description: string;
  confidence: string;
  evidence: ProtocolEvidence[];
  ports: number[];
}

/** The protocols scan `GET`/`POST /api/binaries/<id>/protocols` returns. */
export interface ProtocolsResult {
  binary_id?: number;
  protocols?: ProtocolEntry[];
  count?: number;
  by_confidence?: Record<string, number>;
  notes?: string[];
}

/** One anti-analysis or obfuscation finding a hardening scan reports. */
export interface HardeningFinding {
  category: string;
  name: string;
  detail: string;
  confidence: string;
}

/** One domain's stored hardening scan as its GET/POST route returns it. */
export interface HardeningScan {
  binary_id?: number;
  domain?: string;
  findings?: HardeningFinding[];
  count?: number;
  by_confidence?: Record<string, number>;
  packer_likelihood?: string | null;
  notes?: string[];
}

/** One indicator of compromise a threat report extracted. */
export interface ThreatIocFinding {
  value: string;
  kind: string;
  source_va: number | null;
}

/** One piece of local evidence that activates an ATT&CK technique. */
export interface ThreatTechniqueEvidence {
  kind: string;
  value: string;
}

export interface ThreatTechnique {
  id: string;
  name: string;
  evidence: ThreatTechniqueEvidence[];
  confidence: string;
}

/** One piece of local evidence that named a software type. */
export interface SoftwareTypeSignal {
  kind: string;
  value: string;
}

/**
 * The software-type classification the threat and triage payloads carry.
 * `type` is null when no rule fired: the classification is a positive match,
 * so an empty result says nothing about whether the binary is benign.
 */
export interface SoftwareTypeClassification {
  type: string | null;
  description: string | null;
  confidence: string | null;
  signals: SoftwareTypeSignal[];
  evidence_sources: string[];
  notes: string[];
}

/** One named contribution to the threat score, with the points it added. */
export interface ThreatScoreContribution {
  name: string;
  points: number;
  evidence: string[];
}

/**
 * The analysis-level 0-100 threat score. `score` is null when no stored scan
 * carried any evidence, which is why the meter renders its missing state
 * rather than a zero.
 */
export interface ThreatScore {
  score: number | null;
  max: number;
  band: string | null;
  contributions: ThreatScoreContribution[];
  evidence_sources: string[];
  notes: string[];
}

/** The threat report `GET`/`POST /api/binaries/<id>/threat` returns. */
export interface ThreatReport {
  binary_id?: number;
  iocs?: Record<string, ThreatIocFinding[]>;
  ioc_counts?: Record<string, number>;
  techniques?: ThreatTechnique[];
  narrative?: { summary: string } | null;
  notes?: string[];
  software_type?: SoftwareTypeClassification | null;
  threat_score?: ThreatScore | null;
}

/** One Snort 2 rule a remediation scan carries. */
export interface SnortRule {
  sid: number;
  family: string;
  value: string;
  host: string;
  port: number | null;
  text: string;
}

/** The Snort rule set `build_remediation` stores under `snort`. */
export interface SnortArtifact {
  rules: SnortRule[];
  text: string;
  notes: string[];
}

/** One STIX 2.1 object; only the fields the panel reads are typed. */
export interface StixObject {
  type: string;
  id: string;
  name?: string;
  pattern?: string;
  pattern_type?: string;
  valid_from?: string;
  created?: string;
  modified?: string;
  content?: string;
  [key: string]: unknown;
}

/** The STIX 2.1 bundle `build_remediation` stores under `stix`. */
export interface StixBundle {
  type: string;
  id: string;
  spec_version?: string;
  objects: StixObject[];
}

/** The remediation artifacts `GET`/`POST /api/binaries/<id>/remediation` returns. */
export interface RemediationResult {
  binary_id?: number;
  rule: string;
  rule_name: string;
  string_count: number;
  import_count: number;
  specificity: "high" | "medium" | "low";
  validated: boolean;
  validator: string | null;
  meta: Record<string, string>;
  notes: string[];
  snort?: SnortArtifact;
  stix?: StixBundle;
}

export interface DisasmResult {
  va: number;
  size: number;
  format: string;
  disasm: string;
}

/** One basic block of a function's control-flow graph, in address order. */
export interface CfgBlock {
  va: number;
  size: number;
  instruction_count: number;
  /** First instruction text of the block. */
  first: string;
  /** Last instruction text; equal to `first` for a one-instruction block. */
  last: string;
}

/** One directed edge between two basic blocks. */
export interface CfgEdge {
  from: number;
  to: number;
  /** True when the edge targets a lower address, i.e. closes a loop. */
  back_edge: boolean;
}

/** `GET /api/functions/<id>/cfg`: the engine's basic-block segmentation. */
export interface CfgResult {
  function_id: number;
  /** The extent's first address the engine segmented. */
  va: number;
  /** The byte extent the engine segmented; 0 when it resolved none. */
  size: number;
  blocks: CfgBlock[];
  edges: CfgEdge[];
  /** Blocks the payload returns; `block_total` is the engine's true count. */
  block_count: number;
  /** The engine's true block count, larger than `block_count` when truncated. */
  block_total: number;
  /** The engine's per-function block cap. */
  block_cap: number;
  /** True when the cap stopped the segmentation. */
  truncated: boolean;
  /** The engine's reason when it segmented nothing or less than everything. */
  note: string | null;
}

export interface DecompilationResult {
  va: number;
  backend: string;
  named: boolean;
  code: string;
}

export interface AiSummaryPayload {
  summary: string;
}

export interface AiComment {
  line: number;
  comment: string;
}

export interface AiCommentsPayload {
  comments: AiComment[];
}

export interface AiTypeSuggestion {
  name: string;
  kind: string;
  type: string;
  confidence: number;
}

export interface AiTypeSuggestionsPayload {
  suggestions: AiTypeSuggestion[];
}

/** One stored AI artifact as the GET and POST routes return it. */
export interface AiArtifact<T> {
  function_id: number;
  kind: string;
  payload: T;
  model: string;
  created_at?: string;
}

/** One entry of the external-source registry. */
export interface ExternalSource {
  name: string;
  kind: string;
  available: boolean;
  unavailable_reason: string;
  description: string;
}

/** The external-source registry as its route serves it. */
export interface ExternalSourcesPayload {
  sources: ExternalSource[];
  count: number;
  remote_enabled: boolean;
  key_configured: boolean;
  note: string;
}

/** One stored external report, as its route serves it. */
export interface ExternalReport {
  analysis_id: number;
  binary_id: number;
  source: string;
  kind: string;
  fetched_at: string;
  payload: Record<string, unknown>;
  journal_action?: string;
}

/** One stored credential, redacted: the value is never part of a payload. */
export interface SecretRow {
  name: string;
  scope: string;
  team_id: number | null;
  length: number;
  hint: string;
  created_at: string;
  updated_at: string;
}

/** The secret store as its route serves it. */
export interface SecretsPayload {
  secrets: SecretRow[];
  count: number;
}

/** One entry of the model registry. */
export interface ModelEntry {
  name: string;
  kind: string;
  version: string;
  available: boolean;
  unavailable_reason: string;
  description: string;
}

/** The model registry as its route serves it. */
export interface ModelsPayload {
  models: ModelEntry[];
  count: number;
  kinds: string[];
  upgrade_kinds: string[];
  note: string;
}

/** What one analysis upgrade re-ran. */
export interface UpgradeResult {
  analysis_id: number;
  from: string;
  to: string;
  candidates: number;
  applied: Array<{ function_id: number; kinds: string[] }>;
  skipped: Array<{ function_id: number; reason: string }>;
  upgraded: number;
  note: string;
  journal_action?: string;
}

/** One placeholder token of a stored AI decompilation. */
export interface AiDecompilationToken {
  token: string;
  kind: string;
  count: number;
  lines: number[];
  line_count: number;
  name: string | null;
}

/** One rewritten line's attribution to the decompilation the model read. */
export interface AiLineAttribution {
  line: number;
  origin: string;
  source_lines: number[];
}

/** One inline comment stored at a line of a stored AI decompilation. */
export interface AiLineComment {
  line: number;
  body: string;
  author: string;
  created_at: string;
  updated_at: string;
}

/** One stored AI decompilation, as its routes serve it. */
export interface AiDecompilation {
  function_id: number;
  kind: string;
  model: string;
  created_at: string;
  code: string;
  rewritten_code: string;
  tokens: AiDecompilationToken[];
  attributions: AiLineAttribution[];
  overrides: Record<string, string>;
  rating: string | null;
  rating_note: string;
  line_comments: AiLineComment[];
  derivation: string;
  journal_action?: string;
}

/** The AI decompilation's workflow state, without its text. */
export interface AiDecompilationStatus {
  function_id: number;
  state: string;
  model: string;
  created_at: string;
  line_count: number;
  token_count: number;
  overridden_count: number;
  attribution_counts: Record<string, number>;
  rating: string | null;
  line_comment_count: number;
}

/** One LLM identifier rename suggestion. */
export interface RenameSuggestion {
  from: string;
  to: string;
  kind: string;
  reason: string;
  confidence: number;
}

export interface RenamesPayload {
  suggestions: RenameSuggestion[];
}

/** One suggestion an apply refused, with the reason it was skipped. */
export interface SkippedRename extends RenameSuggestion {
  reason: string;
}

export interface RenamesApplyResult {
  function_id: number;
  applied: RenameSuggestion[];
  skipped: SkippedRename[];
  decompilation_updated: boolean;
}


/** The query types the search route accepts; mirrors store.SEARCH_KINDS. */
export type SearchKind = "all" | "sha256" | "binary" | "collection" | "tag";

/** One result group's returned count against the total the query matched. */
export interface SearchCount {
  count: number;
  total: number;
}

/** One binary a search matched, with the metadata the store holds. */
export interface SearchBinaryRow {
  id: number;
  name: string;
  sha256: string;
  path: string;
  size: number;
  format: string;
  arch: string;
  created_at: string;
  /** Tag names of the binary, name order. */
  tags: string[];
  /** The field the query matched: sha256, binary or path. */
  match: string;
}

/** One function a search matched. */
export interface SearchFunctionRow {
  id: number;
  va: number;
  name: string;
  status: string;
  binary_id: number;
  match: string;
}

/** One collection a search matched, with its member count. */
export interface SearchCollectionRow {
  id: number;
  name: string;
  description: string;
  created_at: string;
  binary_count: number;
  /** The field the query matched: name or description. */
  match: string;
}

/** One tag a search matched, with its tagged-binary count. */
export interface SearchTagRow {
  id: number;
  name: string;
  binary_count: number;
  match: string;
}

/** The groups `GET /api/search` answers, in the order the SPA renders them. */
export interface SearchResults {
  query: string;
  kind: SearchKind;
  binaries: SearchBinaryRow[];
  functions: SearchFunctionRow[];
  collections: SearchCollectionRow[];
  tags: SearchTagRow[];
  counts: {
    binaries: SearchCount;
    functions: SearchCount;
    collections: SearchCount;
    tags: SearchCount;
  };
}

/** Per-file options a batch upload carries beside each `file` part. */
export interface UploadFileOptions {
  name?: string;
  tags?: string[];
  /** Explicit file format, else the suffix-derived value. */
  format?: string;
  /** Explicit architecture, else the suffix-derived value. */
  arch?: string;
  collection_ids?: number[];
}

/** One uploaded part's outcome, as the batch response reports it. */
export interface UploadFileEntry {
  file: string;
  binary_id: number | null;
  duplicate: boolean;
  tags: string[];
  collections: number[];
  error: { error: string; detail: string; status?: number } | null;
}

/** The response of a batch upload; one entry per `file` part. */
export interface UploadBatchResult {
  files: UploadFileEntry[];
  count: number;
  duplicates: number;
  errors: number;
  journal_action?: string;
}

/** One archive member's outcome, as the extract route reports it. */

/** The response of `POST /api/binaries/<id>/extract`. */

export interface Conversation {
  id: number;
  scope_kind: string;
  scope_id: number;
  title: string;
  created_at: string;
  message_count: number;
}

export interface ConversationMessage {
  id: number;
  conversation_id: number;
  role: string;
  content: string;
  created_at: string;
}

/** One conversation as the detail route returns it: the row plus its messages. */
export interface ConversationThread extends Conversation {
  messages: ConversationMessage[];
}

/** The stored exchange `POST /api/conversations/<id>/messages` answers with. */
export interface ConversationReply {
  conversation_id: number;
  user: ConversationMessage;
  assistant: ConversationMessage;
  sources: KnowledgeHit[];
}

/** One step of an AI decompilation pipeline run. */
export interface PipelineStep {
  id: number;
  run_id: number;
  name: string;
  status: string;
  reason: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  provides: string[];
}

/** The name a run predicted for the function, with its evidence. */
export interface PredictedName {
  name: string | null;
  source: string;
  confidence: number;
  evidence: Record<string, unknown>;
}

/** The durable artifacts a run left on the function. */
export interface PipelineArtifacts {
  decompilation: { code: string; backend: string } | null;
  summary: AiSummaryPayload | null;
  inline_comments: AiCommentsPayload | null;
  type_suggestions: AiTypeSuggestionsPayload | null;
  predicted_name: PredictedName | null;
}

/** One journaled write of a run, as its undo plan carries it. */
export interface PipelineEffect {
  kind: string;
  function_id: number;
  artifact_kind?: string;
  previous?: unknown;
}

/** One stored AI decompilation run as the API returns it. */
export interface PipelineRun {
  id: number;
  function_id: number;
  status: string;
  started_at: string;
  finished_at: string | null;
  model: string;
  created_at: string;
  effects: PipelineEffect[];
  steps: PipelineStep[];
  artifacts: PipelineArtifacts;
}

/** One artifact a revert removed or restored. */
export interface PipelineRevertEntry {
  kind: string;
  function_id: number;
  description: string;
  status: string;
  detail?: string;
}

/** The result `POST /api/pipeline/runs/<id>/revert` answers with. */
export interface PipelineRevertResult {
  run_id: number;
  function_id: number;
  reverted: PipelineRevertEntry[];
}

/** One worker call recorded against an auto task. */
export interface AutoAttempt {
  id: number;
  task_id: number;
  attempt: number;
  worker: string;
  status: string;
  detail: Record<string, unknown>;
  created_at: string;
}

/** One node of an auto run's task tree. */
export interface AutoTask {
  id: number;
  run_id: number;
  parent_id: number | null;
  depth: number;
  kind: string;
  title: string;
  function_id: number | null;
  va: number | null;
  status: string;
  worker: string;
  attempts: number;
  result: Record<string, unknown>;
  created_at: string;
  finished_at: string | null;
  attempt_log: AutoAttempt[];
  children: AutoTask[];
}

/** Whether matched/total functions of the binary, at one point of the run. */
export interface AutoCoverage {
  matched?: number;
  total?: number;
  ratio?: number;
}

/** One stored auto run with its task tree and coverage delta. */
export interface AutoRun {
  run_id: number;
  binary_id: number;
  status: string;
  worker: string;
  config: Record<string, unknown>;
  created_at: string;
  finished_at: string | null;
  tasks: number;
  attempts: number;
  matched: number;
  improved: number;
  failed: number;
  skipped: number;
  coverage_before: AutoCoverage;
  coverage_after: AutoCoverage;
  tree: AutoTask[];
}

/** The id `POST /api/binaries/<id>/auto` answers with before the run finishes. */
export interface AutoRunStarted {
  run_id: number;
  binary_id: number;
  status: string;
}

/** One file or status a revert removed or restored. */
export interface AutoRevertResult {
  run_id: number;
  status: string;
  removed: Array<{ path: string; status: string }>;
  restored: Array<{ function_id: number; status: string }>;
}

/** One stored knowledge document as the list and ingest routes return it. */
export interface Document {
  id: number;
  scope_kind: string;
  scope_id: number;
  title: string;
  source: string;
  mime: string;
  sha256: string;
  size: number;
  created_at: string;
  chunk_count: number;
}

/** One ranked chunk `GET /api/knowledge/search` answers with. */
export interface KnowledgeHit {
  document_id: number;
  chunk_id: number;
  title: string;
  source: string;
  text: string;
  score: number;
  /** Ranking that produced the score: `embeddings` or `tfidf`. */
  method: string;
}

export interface KnowledgeSearch {
  query: string;
  count: number;
  results: KnowledgeHit[];
}

/** `GET /api/knowledge/config`: whether guarded URL ingestion is enabled. */
export interface KnowledgeConfig {
  allow_remote: boolean;
}

/** One node of a binary's stored knowledge graph. */
export interface GraphNode {
  id: string;
  kind: string;
  key: string;
  label: string;
  degree: number;
  meta: Record<string, unknown>;
}

/** One directed edge between two graph nodes. */
export interface GraphEdge {
  source: string;
  target: string;
  rel: string;
  weight: number;
}

/** A binary's stored graph as `GET /api/binaries/<id>/graph` returns it. */
export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
  counts: Record<string, number>;
  truncated: boolean;
}

/** One neighbor of a graph node, as the node route reports it. */
export interface GraphNeighbor {
  id: string;
  kind: string;
  key: string;
  label: string;
  weight: number;
}

/** One node with its edges grouped by relation. */
export interface GraphNeighbors {
  node: GraphNode;
  incoming: Record<string, GraphNeighbor[]>;
  outgoing: Record<string, GraphNeighbor[]>;
}

/** The counts `POST /api/binaries/<id>/graph` answers with. */
export interface GraphBuildResult {
  binary_id: number;
  nodes: number;
  edges: number;
  truncated: boolean;
  built_at: string;
}

/** One registered knowledge-graph backend, as `GET /api/graph/backends` reports it. */
export interface GraphBackendInfo {
  name: string;
  available: boolean;
  description: string;
  unavailable_reason: string;
  supports_query: boolean;
}

/** `GET /api/graph/backends`: the registry plus the configured default name. */
export interface GraphBackends {
  backends: GraphBackendInfo[];
  default: string;
}

/** The report `POST /api/binaries/<id>/graph/sync` answers with. */
export interface GraphSyncResult {
  backend: string;
  binary_id: number;
  nodes: number;
  edges: number;
  pushed_nodes: number;
  pushed_edges: number;
  dataset?: string;
}

/** One node a graph query matched. */
export interface GraphQueryNode {
  id: string;
  kind: string;
  key: string;
  label: string;
  degree: number;
}

/** `GET /api/graph/query` result. */
export interface GraphQueryResult {
  backend: string;
  query: string;
  count: number;
  results: GraphQueryNode[];
}

/** One function pairing a lineage comparison classified. */
export interface LineageRow {
  status: string;
  left_function_id: number | null;
  left_name: string | null;
  left_va: number | null;
  left_size: number | null;
  right_function_id: number | null;
  right_name: string | null;
  right_va: number | null;
  right_size: number | null;
  confidence: number | null;
  similarity: number | null;
}

/** The exact status counts of a lineage comparison. */
export interface LineageSummary {
  unchanged: number;
  changed: number;
  added: number;
  removed: number;
  matched_percent: number;
}

/** The comparison `POST`/`GET /api/binaries/<id>/lineage?other_binary_id=` returns. */
export interface LineageComparison {
  left_binary_id: number;
  right_binary_id: number;
  left_name: string;
  right_name: string;
  refined: boolean;
  summary: LineageSummary;
  rows: LineageRow[];
}

/** The stored comparisons `GET /api/binaries/<id>/lineage` lists. */
export interface LineageList {
  binary_id: number;
  comparisons: LineageComparison[];
}

/** One signal a family detection matched, with the confidence it carries. */
export interface DetectSignal {
  kind: string;
  confidence: string;
  detail: string;
}

/** One family a detection matched; `signals` lists every signal that fired. */
export interface DetectMatch {
  family_id: number;
  name: string;
  aliases: string[];
  confidence: string;
  signals: DetectSignal[];
  similarity: number;
}

/** The signature bundle a family stores from its reference binary. */
export interface FamilySignatures {
  sha256: string | null;
  imphash: string | null;
  rich_header_hash: string | null;
  import_hash: string;
  import_names: string[];
  capabilities: string[];
}

/** One locally registered malware family. */
export interface Family {
  family_id: number;
  name: string;
  aliases: string[];
  notes: string;
  reference_binary_id: number;
  created_at: string;
  signatures: FamilySignatures;
}

/** The list `GET /api/families` returns. */
export interface FamilyList {
  families: Family[];
}

/** The detection `GET`/`POST /api/binaries/<id>/detect` returns. */
export interface DetectResult {
  binary_id: number;
  families_checked: number;
  matches: DetectMatch[];
  count: number;
  notes: string[];
}

/** One signal a related-binary relationship matched. */
export interface RelatedSignal {
  kind: string;
  confidence: string;
  detail: string;
}

/** One ranked binary in a relationship scan's `related` list. */
export interface RelatedCandidate {
  binary_id: number;
  name: string;
  classification: string;
  confidence: string;
  signals: RelatedSignal[];
  similarity: number;
}

/** The ranking `GET`/`POST /api/binaries/<id>/related` returns. */
export interface RelatedResult {
  binary_id: number;
  candidates_considered: number;
  related: RelatedCandidate[];
  count: number;
  notes: string[];
}

/** One bucket of a composition analysis's name-source breakdown. */
export interface CompositionNameSource {
  label: string;
  count: number;
  percent: number | null;
}

/** One band of a composition analysis's match-quality distribution. */
export interface CompositionQualityBand {
  label: string;
  count: number;
  percent: number | null;
}

/** One other binary a composition analysis's functions matched to. */
export interface CompositionBinary {
  binary_id: number;
  name: string;
  sha256: string | null;
  count: number;
  percent: number | null;
}

/** One function row of a composition analysis; a null matched binary is No Match. */
export interface CompositionFunctionRow {
  function_id: number;
  name: string;
  va: number;
  size: number;
  band: string;
  similarity: number | null;
  matched_binary_id: number | null;
  matched_binary_name: string | null;
}

/** The payload `GET`/`POST /api/binaries/<id>/composition` returns. */
export interface CompositionResult {
  binary_id: number;
  binary_name: string;
  sha256: string | null;
  total_functions: number;
  matched_functions: number;
  matched_percent: number | null;
  refined: boolean;
  name_sources: CompositionNameSource[];
  match_quality: CompositionQualityBand[];
  composition: CompositionBinary[];
  functions: CompositionFunctionRow[];
  notes: string[];
}

/** One analyst comment stored on a binary or function. */
export interface Comment {
  id: number;
  scope_kind: string;
  scope_id: number;
  author: string;
  body: string;
  created_at: string;
  updated_at: string;
}

/** The list `GET /api/{binaries,functions}/<id>/comments` returns. */
export interface CommentList {
  comments: Comment[];
}

/** A binaries-list row, which additionally carries its analyst comment count. */
export interface BinaryListRow extends Binary {
  comment_count: number;
}

/** One id a bulk action did not touch, with the reason. */
export interface BulkSkipped {
  id: number;
  reason: string;
}

/** The per-id result a bulk action returns. */
export interface BulkResult {
  action: string;
  requested: number;
  applied: number;
  skipped: BulkSkipped[];
  /** Present when the request journaled at least one write. */
  journal_action?: string;
}

/** One recorded action-journal entry, without its descriptor payload. */
export interface JournalEntry {
  id: number;
  action: string;
  kind: string;
  description: string;
  created_at: string;
  status: string;
}

/** `GET /api/journal` and `GET /api/journal/<action>`. */
export interface JournalList {
  entries: JournalEntry[];
  count: number;
}

/** One entry of a revert report. */
export interface JournalRevertEntry extends JournalEntry {
  detail: string;
}

/** The report a journal revert returns. */
export interface JournalRevertResult {
  action?: string;
  entries?: JournalRevertEntry[];
  reverted?: number;
  failed?: number;
  entry?: JournalEntry;
  status?: string;
  detail?: string;
}

/** One section of a PE's section table, with its memory protections. */
export interface PeSection {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_size: number;
  raw_offset: number;
  /** Shannon entropy in bits per byte; null when LIEF could not derive it. */
  entropy?: number | null;
  /** The raw IMAGE_SCN_* characteristics dword. */
  characteristics_value?: number;
  /** Full IMAGE_SCN_* name list for the characteristics dword. */
  characteristics?: string[];
  read: boolean;
  write: boolean;
  execute: boolean;
}

/** One export of the PE export table. */
export interface PeExport {
  name: string;
  /** Absolute VA, or null for a forwarder (the target resolves elsewhere). */
  va: number | null;
  ordinal: number | null;
  /** `DLL.Function` target for a forwarded export, else null. */
  forwarder: string | null;
}

/** One mitigation of the portal's 11-item security checklist. */
export interface PeSecurityItem {
  /** null when the source value is unavailable (unknown, not disabled). */
  enabled: boolean | null;
  /** Raw DllCharacteristics bit (bound-import directory size for bound_image). */
  flag: number | null;
  /** The winnt.h name the flag comes from. */
  flag_name: string | null;
}

/** Enabled count and fixed total of the portal security checklist. */
export interface PeSecurityScore {
  enabled: number;
  total: number;
}

/** The DLL characteristics word and the hardening booleans the engine derives. */
export interface PeSecurityFlags {
  dll_characteristics: number;
  aslr: boolean;
  nx: boolean;
  cfg: boolean;
  gs: boolean;
  safe_seh: boolean;
  seh: boolean;
  high_entropy_va: boolean;
  force_integrity: boolean;
  isolation: boolean;
  certificate_table: boolean;
}

export interface PeAuthenticode {
  present: boolean;
  signature_count: number;
  signers: string[];
}

export interface PeDebugEntry {
  type: string;
}

export interface PeRichHeaderEntry {
  id: number;
  build_id: number;
  count: number;
}

export interface PeRichHeader {
  present: boolean;
  key?: number;
  entries: PeRichHeaderEntry[];
}

export interface PePresence {
  tls_directory: boolean;
  load_config: boolean;
  resources: boolean;
  relocations: boolean;
  exports: boolean;
  imports: boolean;
}

export interface PeCounts {
  exports: number;
  imports: number;
  import_dlls: number;
  relocations: number;
}

/** The `GET`/`POST /api/binaries/<id>/pe-info` payload.  A binary whose format
 *  carries no PE metadata answers the identity fields plus a `note`. */
export interface PeInfo {
  format?: string;
  arch?: string;
  bits?: number;
  /** `exe` / `dll`; absent when neither file-header bit is set. */
  type?: string;
  image_base?: number;
  entry_point?: number;
  subsystem?: string;
  timestamp?: number;
  timestamp_iso?: string;
  checksum?: number;
  size?: number;
  /** Leaf entries of the resource tree; 0 when the image has none. */
  resource_count?: number;
  sections?: PeSection[];
  security_flags?: PeSecurityFlags;
  /** The portal's 11-item mitigation checklist, keyed by item name. */
  security?: PeSecurity;
  security_score?: PeSecurityScore;
  flags_summary?: string[];
  exports?: PeExport[];
  export_count?: number;
  authenticode?: PeAuthenticode;
  debug?: PeDebugEntry[];
  rich_header?: PeRichHeader;
  presence?: PePresence;
  counts?: PeCounts;
  note?: string;
}

/** One composed source of a detail read: whether it is stored, and the command
 *  that fills it in. */
export interface DetailSource {
  present: boolean;
  command: string;
}

/** The `GET /api/binaries/<id>/additional-details/status` payload.  Always
 *  answers once the binary exists, so it reports a gap instead of refusing. */
export interface DetailsStatus {
  binary_id: number;
  status: "ready" | "incomplete";
  missing: string[];
  hint: string;
  sources: Record<string, DetailSource>;
}

/** The `GET /api/binaries/<id>/additional-details` payload, composed from the
 *  stored pe-info scan.  404 `no-scan` without one. */
export interface AdditionalDetails {
  binary_id: number;
  available: boolean;
  format?: string;
  arch?: string;
  bits?: number;
  size?: number;
  overlay: { present: boolean; bytes: number; offset: number | null };
  rich_header: {
    present: boolean;
    entries: number;
    build_ids: number[];
    tool_ids: number[];
  };
  sections: { count: number; names: string[]; executable: string[]; writable: string[] };
  debug: Array<Record<string, unknown>>;
  presence: Record<string, boolean>;
  counts: Record<string, number>;
  authenticode: Record<string, unknown>;
  packer_section_hint: string[];
  sources: Record<string, DetailSource>;
}

/** The `GET /api/binaries/<id>/die-info` payload: the Detect-It-Easy shaped
 *  identity and category matches, composed from the stored scans. */
export interface DieInfo {
  binary_id: number;
  available: boolean;
  identity: {
    format?: string;
    arch?: string;
    bits?: number;
    mode?: string;
    entry_point?: number;
    image_base?: number;
    size?: number;
  };
  file_type?: string;
  packer: FileTypeMatch[];
  protector: FileTypeMatch[];
  installer: FileTypeMatch[];
  runtime: FileTypeMatch[];
  toolchain: FileTypeMatch[];
  by_category: Record<string, number>;
  entropy: { sections: Array<{ name?: string; entropy?: number }>; packed: boolean };
  sections: { count: number; names: string[] };
  packer_section_hint: string[];
  notes: string[];
  sources: Record<string, DetailSource>;
}

/** One team and, on the detail read, its members. */
export interface TeamRow {
  id: number;
  name: string;
  description: string;
  created_at: string;
  member_count: number;
  /** Present on `GET /api/teams/<id>` only. */
  members?: { id: number; name: string; role: string }[];
}

/** `GET /api/teams`: every team and the count. */
export interface TeamsPayload {
  teams: TeamRow[];
  count: number;
}

/** One registered sandbox runner and whether it is installed. */
export interface SandboxRunnerInfo {
  name: string;
  available: boolean;
  describe: string;
}

/** `GET /api/binaries/<id>/dynamic-execution/status`: can this install detonate? */
export interface SandboxStatus {
  analysis_id: number;
  enabled: boolean;
  available: boolean;
  runner: string | null;
  runners: SandboxRunnerInfo[];
  caps: {
    timeout_seconds: number;
    max_timeout_seconds: number;
    memory_mb: number;
    max_memory_mb: number;
  };
  runs: number;
  last: {
    id: number;
    status: string;
    timed_out: boolean;
    exit_code: number | null;
    duration_ms: number;
    created_at: string;
  } | null;
  note: string;
}

/** One stored detonation report. */
export interface SandboxRun {
  id: number;
  analysis_id: number;
  binary_id: number;
  sha256: string;
  status: string;
  runner: string;
  argv: string[];
  caps: Record<string, string | number>;
  exit_code: number | null;
  timed_out: boolean;
  duration_ms: number;
  stdout: string;
  stderr: string;
  files: { path: string; size: number }[];
  notes: string[];
  created_at: string;
  finished_at: string | null;
  detonation?: SandboxStatus;
  journal_action?: string;
}

/** One embedded region a firmware carve found. */
export interface FirmwareRegion {
  index: number;
  offset: number;
  size: number;
  kind: string;
  label: string;
  confidence: string;
  entropy: number;
  truncated: boolean;
}

/** `GET|POST /api/binaries/<id>/firmware`: the carve pass over a stored image. */
export interface FirmwareScan {
  binary_id: number;
  analysis_id: number;
  size: number;
  signatures: number;
  regions: FirmwareRegion[];
  region_count: number;
  truncated: boolean;
  entropy: { offset: number; length: number; entropy: number }[];
  entropy_window: number;
  max_region_bytes: number;
  extractable_kinds: string[];
  note: string;
}

/** `POST /api/binaries/<id>/firmware/extract`: what one carve registered. */
export interface FirmwareExtraction {
  binary_id: number;
  collection_id: number;
  collection_name: string;
  regions: FirmwareRegion[];
  members: {
    region: number;
    kind: string;
    name: string;
    size: number;
    binary_id: number | null;
    duplicate: boolean;
    skipped: string;
  }[];
  kept: number;
  skipped: number;
  note: string;
  journal_action?: string;
}

/** One item of the activity feed, derived from the journal or the analysis log. */
export interface ActivityItem {
  /** Stable per source row (or action); a client keys its rendering on it. */
  id: string;
  kind: "action" | "log";
  /** Who made it: a user name, `local`, or empty for a write no request made. */
  actor: string;
  at: string;
  action: string;
  description: string;
  status: string;
  entries: number;
  severity?: string;
}

/** `GET /api/users/activity`: the feed plus the actors that appear in it. */
export interface ActivityPayload {
  items: ActivityItem[];
  count: number;
  total: number;
  since: string | null;
  actor: string | null;
  sources: string[];
  latest: string | null;
  actors: { actor: string; actions: number; at: string }[];
}

/** One stored feedback note about reportal itself. */
export interface FeedbackNote {
  id: number;
  user_id: number | null;
  actor: string;
  body: string;
  created_at: string;
}

/** `GET /api/users/feedback`: a bounded page and the true total. */
export interface FeedbackPayload {
  feedback: FeedbackNote[];
  count: number;
  total: number;
}

/** One local user; the token digest is never part of the answer. */
export interface UserRow {
  id: number;
  name: string;
  role: string;
  created_at: string;
  disabled: boolean;
  has_token: boolean;
}

/** `GET /api/users`: every user and the count. */
export interface UsersPayload {
  users: UserRow[];
  count: number;
}

/** `GET /api/iam/me`: the caller's identity and the permissions it carries. */
export interface Me {
  /** `open` while token auth is off, `required` when a token has to be sent. */
  auth: "open" | "required";
  user: UserRow | null;
  role: string | null;
  permissions: string[];
  /** The teams the caller belongs to; empty while auth is off. */
  teams: TeamRow[];
}

/** The `GET /api/analyses/<id>/status` payload. */
export interface AnalysisStatus {
  analysis_id: number;
  binary_id: number;
  status: string;
  engine: string;
  created_at: string;
  finished_at: string | null;
  terminal: boolean;
  scans: number;
  scans_by_status: Record<string, number>;
  logs: number;
  logs_by_severity: Record<string, number>;
}

/** One caller of an import stub: a function whose decompilation mentions it. */
export interface ImportedCaller {
  id: number;
  va: number;
  name: string;
}

/** One import stub of an analysis, with the functions its source mentions it in. */
export interface ImportedFunction {
  id: number;
  va: number;
  name: string;
  size: number;
  status: string;
  name_source: string;
  /** Bounded by the payload's `caller_limit`; `caller_count` is the true total. */
  callers: ImportedCaller[];
  caller_count: number;
}

/** The `GET /api/analyses/<id>/imported-functions` payload. */
export interface ImportedFunctionsPayload {
  analysis_id: number;
  binary_id: number;
  functions: ImportedFunction[];
  count: number;
  total: number;
  /** How the callers were derived; reportal stores no call graph. */
  caller_method: string;
  caller_limit: number;
}

/** One item of the notification feed, derived from the journal or the log. */
export interface NotificationItem {
  /** Stable per source row (or action); what a client keys its dismissal on. */
  id: string;
  kind: "action" | "log";
  severity: "info" | "warn" | "error";
  message: string;
  at: string;
  /** Journaled-action items only. */
  action?: string;
  status?: string;
  entries?: number;
  revertible?: boolean;
  /** Analysis-log items only. */
  analysis_id?: number;
  binary_id?: number | null;
  binary_name?: string | null;
}

/** One queued or finished operation, the shape `GET /api/jobs/<id>` answers. */
export interface JobView {
  id: number;
  kind: string;
  label: string;
  binary_id: number | null;
  status: "queued" | "running" | "done" | "failed" | "cancelled";
  progress: number;
  steps_total: number;
  message: string;
  params: Record<string, unknown>;
  error: string;
  result: Record<string, unknown> | null;
  created_at: string;
  started_at: string;
  finished_at: string;
  live: boolean;
}

/** The `GET /api/binaries/<id>/report/pdf/status` payload: the stored file and
 *  the newest job that renders it. */
export interface PdfStatus {
  binary_id: number;
  exists: boolean;
  path: string;
  bytes: number;
  pages: number;
  generated_at: string | null;
  job: JobView | null;
  download_url: string;
}

/** The `GET /api/jobs` payload, with the operations that may be queued. */
export interface JobsPayload {
  jobs: JobView[];
  count: number;
  total: number;
  queued: number;
  kinds: Array<{ name: string; label: string; params: string[] }>;
}

/** The `GET /api/notifications` payload. */
export interface NotificationsPayload {
  notifications: NotificationItem[];
  count: number;
  total: number;
  since: string | null;
  sources: string[];
  latest: string | null;
}

/** The portal security checklist, keyed by item name in portal order. */
export interface PeSecurity {
  aslr?: PeSecurityItem;
  dep?: PeSecurityItem;
  cfg?: PeSecurityItem;
  driver_model?: PeSecurityItem;
  app_container?: PeSecurityItem;
  terminal_server_aware?: PeSecurityItem;
  image_isolation?: PeSecurityItem;
  code_integrity?: PeSecurityItem;
  high_entropy?: PeSecurityItem;
  seh?: PeSecurityItem;
  bound_image?: PeSecurityItem;
}

/** One piece of evidence a file-type signature matched. */
export interface FileTypeSignal {
  kind: string;
  value: string;
}

/** One file-type, packer or protector signature a detection matched. */
export interface FileTypeMatch {
  name: string;
  category: string;
  confidence: string;
  signals: FileTypeSignal[];
}

/** The `GET`/`POST /api/binaries/<id>/filetype` payload. */
export interface FileTypeResult {
  binary_id?: number;
  matches?: FileTypeMatch[];
  count?: number;
  by_category?: Record<string, number>;
  notes?: string[];
}

/** One registry entry of the pipeline component composition. */
export interface ComponentRow {
  name: string;
  requires: string[];
  provides: string[];
  origin: string;
  reloadable: boolean;
  withdrawable: boolean;
  withdraw_reason: string;
}

/** The `GET /api/components` payload. */
export interface ComponentList {
  components: ComponentRow[];
  count: number;
}

/** One entry of a `POST /api/components/<name>/deactivate` result. */
export interface ComponentDeactivateEntry {
  name: string;
  status: string;
  reason: string;
  reverted: boolean | null;
  detail: string;
}

/** One context binding change a withdrawal reported. */
export interface ComponentContextChange {
  name: string;
  change: string;
  applied: boolean;
  detail: string;
}

/** The `POST /api/components/<name>/deactivate` payload. */
export interface ComponentDeactivateResult {
  name: string;
  deactivated: ComponentDeactivateEntry[];
  context_changes: ComponentContextChange[];
  active: string[];
  journaled: boolean;
  journal_action?: string;
}

/** The `POST /api/components/reload` payload for one component. */
export interface ComponentReloadResult {
  name: string;
  reloaded: boolean;
  old_origin: string;
  new_origin: string;
  module: string;
  changed: boolean;
}

/** A reloadable component `reload_all` skipped, with the reason it could not run. */
export interface ComponentReloadSkip {
  name: string;
  reason: string;
}

/** The `POST /api/components/reload` payload for `{"all": true}`. */
export interface ComponentReloadAll {
  reloaded: ComponentReloadResult[];
  skipped: ComponentReloadSkip[];
  count: number;
  changed: string[];
}

/** The report scan `GET /api/binaries/<id>/report` returns. */
export interface ReportScan {
  out?: string;
  pages?: string[];
  summary?: ReportSummary;
}

/**
 * One memory window, `GET /api/binaries/<id>/memory?va=&length=&kind=`.
 *
 * `bytes` is the window's lowercase hex; `va` and `section` are null for a
 * `file`-offset read, which needs no section map.  `address` is the address as
 * the caller gave it, echoed back as hex.
 */
export interface MemoryWindow {
  binary_id: number;
  kind: string;
  address: string;
  va: string | null;
  section: string | null;
  length: number;
  bytes: string;
}

/** One section the full-file memory page's map carries. */
export interface MemoryPageSection {
  name: string;
  va: string;
  offset: string;
  raw_size: number;
  virtual_size: number;
}

/**
 * One page row: a run of backed bytes or a stated gap.
 *
 * A `bytes` row carries its address, file offset and lowercase hex; a `gap`
 * row carries its address and byte length and no bytes at all, because the
 * engine refused the read it cannot serve.
 */
export interface MemoryPageRow {
  kind: "bytes" | "gap";
  address: string;
  offset?: string;
  length: number;
  hex?: string;
}

/** One page of the full-file hex view, `GET /api/binaries/<id>/memory/page`. */
export interface MemoryPage {
  binary_id: number;
  kind: string;
  address: string | null;
  start: string;
  length: number;
  next: string | null;
  prev: string | null;
  sections: MemoryPageSection[];
  rows: MemoryPageRow[];
  mapped: number;
  gaps: number;
}

/** One data address a function reads, writes or loads. */
export interface GlobalReference {
  address: number;
  kind: string;
  /** `read`, `write`, or null when the instruction does not make it clear. */
  access: string | null;
  /** Owning section, or null when the stored section table does not know it. */
  section: string | null;
}

/** One call site into a function. */
export interface CallerReference {
  from_va: number;
  name: string | null;
}

/** One call a function makes; `indirect` marks an import-slot call. */
export interface CalleeReference {
  to_va: number;
  name: string | null;
  kind: string;
  indirect: boolean;
}

/** A function's globals, callers and callees, `GET /api/functions/<id>/references`. */
export interface FunctionReferences {
  function_id: number;
  va: number;
  globals: GlobalReference[];
  callers: CallerReference[];
  callees: CalleeReference[];
  counts: { globals: number; callers: number; callees: number };
  /** What each count means: call sites for callers, (target, kind) pairs for callees. */
  count_note: string;
}

/** One row of `GET /api/binaries/<id>/section-coverage`. */
export interface SectionCoverageRow {
  name: string;
  va: number;
  size: number;
  covered: number;
  uncovered: number;
  coverage_pct: number | null;
}

/** The per-section byte coverage, reportal's own metric over the stored rows. */
export interface SectionCoverage {
  binary_id: number;
  image_base: number;
  function_count: number;
  sections: SectionCoverageRow[];
  totals: {
    size: number;
    covered: number;
    uncovered: number;
    coverage_pct: number | null;
  };
  note: string;
}

/** One registered part of a plugin seam, from `GET /api/integrations`. */
export interface IntegrationPart {
  name: string;
  detail: string;
  /** Where the part was declared; empty when the registry does not track it. */
  origin: string;
  reloadable?: boolean;
  plans_writes?: boolean;
  available?: boolean;
  unavailable_reason?: string;
  queryable?: boolean;
  builtin?: boolean;
  destructive?: boolean;
}

/** One plugin seam: its entry-point group and the parts it currently holds. */
export interface IntegrationSeam {
  name: string;
  group: string;
  module: string;
  contributes: string;
  parts: IntegrationPart[];
  count: number;
}

/** `GET /api/integrations`. */
export interface IntegrationInventory {
  seams: IntegrationSeam[];
  count: number;
}

/** One instance's capabilities, the shape `GET /api/config` answers. */
export interface InstanceConfig {
  name: string;
  version: string;
  engine: { available: boolean; origin: string | null; backends: string[]; severities: string[] };
  llm: { configured: boolean; model: string; kinds: string[] };
  database: { path: string; exists: boolean; tables: number };
  features: Record<string, boolean | string | string[]>;
  limits: Record<string, number>;
  mcp: { total: number; read_only: number; destructive: number };
}

/** One indirect call or jump in a function's cached disassembly listing. */
export interface IndirectCallSite {
  line: number;
  kind: string;
  mnemonic: string;
  target: string;
  instruction: string;
}

/** `GET /api/functions/<id>/indirect-call-sites`. */
export interface IndirectCallSites {
  function_id: number;
  sites: IndirectCallSite[];
  count: number;
  has_disassembly: boolean;
  derivation: string;
  note: string;
}

/** One capability rule a function's stored text matched. */
export interface FunctionCapability {
  name: string;
  confidence: string;
  evidence_count: number;
  evidence?: string[];
}

/** `GET /api/functions/<id>/capabilities`. */
export interface FunctionCapabilities {
  function_id: number;
  capabilities: FunctionCapability[];
  count: number;
  inputs: { imports: number; strings: number };
  has_decompilation: boolean;
  derivation: string;
}

/** One analyst-recorded string, at function or analysis scope. */
export interface AnalystString {
  id: number;
  scope_kind: string;
  scope_id: number;
  value: string;
  kind: string;
  note: string;
  actor: string;
  created_at: string;
}

/** `GET /api/functions/<id>/strings`: the analyst's and the derived literals. */
export interface FunctionStrings {
  function_id: number;
  analyst: AnalystString[];
  derived: Array<{ value: string; source: string }>;
  counts: { analyst: number; derived: number };
  note: string;
}

/** `GET /api/analyses/<id>/strings`. */
export interface AnalysisStrings {
  analysis_id: number;
  strings: AnalystString[];
  count: number;
}

/** A derived callee or a caller of a function. */
export interface DerivedCallee {
  name: string;
  function_id: number;
  derivation: string;
}

/** One callee edge an analyst declared. */
export interface DeclaredEdge {
  name: string;
  kind: string;
  source: string;
  edge_id: number;
}

/** `GET /api/functions/<id>/callees`. */
export interface FunctionCallees {
  function_id: number;
  name?: string;
  callees: DerivedCallee[];
  declared: DeclaredEdge[];
  count: number;
  declared_count: number;
  has_decompilation: boolean;
  derivation: string;
}

/** One event an agent run recorded. */
export interface AgentRunEvent {
  at: string;
  kind: string;
  tool?: string;
  name?: string;
  failed?: boolean;
  arguments?: Record<string, unknown>;
  result?: string;
  error?: string;
  detail?: string;
  approved?: boolean;
  content?: string;
}

/** The tool call an agent run paused on, awaiting confirmation. */
export interface AgentPendingCall {
  name: string;
  arguments: Record<string, unknown>;
  id: string;
}

/** `POST /api/conversations/<id>/runs` and the run reads. */
export interface AgentRun {
  conversation_id: number;
  run_id: number;
  status: string;
  tool_calls: number;
  pending: AgentPendingCall | null;
  content: string;
  error: string;
  events: AgentRunEvent[];
  live: boolean;
  sources?: KnowledgeHit[];
}

/** `GET /api/conversations/<id>/runs`. */
export interface AgentRunList {
  conversation_id: number;
  runs: AgentRun[];
  count: number;
}

/** One symbol a debug symbol file declares. */
export interface SymbolEntry {
  name: string;
  va: number | null;
  size: number;
  kind: string;
  source: string;
}

/** One aggregate type a symbol file declares. */
export interface SymbolType {
  name: string;
  kind: string;
  size: number;
  namespace: string;
  members: Array<{ name: string; type: string; offset: number }>;
}

/** The parse one symbol file produced. */
export interface SymbolParse {
  kind?: string;
  symbols?: SymbolEntry[];
  types?: SymbolType[];
  notes?: string[];
  counts?: { symbols: number; types: number };
}

/** One ingested symbol file. */
export interface SymbolFile {
  id: number;
  binary_id: number;
  sha256: string;
  kind: string;
  size: number;
  path: string;
  parsed: SymbolParse;
  symbols: number;
  types: number;
  applied: number;
  created_at: string;
}

/** `GET /api/binaries/<id>/symbols`. */
export interface SymbolFileList {
  binary_id: number;
  symbol_files: SymbolFile[];
  count: number;
}

/** One day of the dashboard series. */
export interface StatsSeriesDay {
  date: string;
  analyses: number;
  auto_runs: number;
  actions: number;
}

/** `GET /api/stats/series`. */
export interface StatsSeries {
  days: number;
  range: { from: string; to: string };
  series: StatsSeriesDay[];
  software_types: Array<{ date: string; counts: Record<string, number> }>;
  totals: {
    analyses: number;
    auto_runs: number;
    actions: number;
    software_types: Record<string, number>;
  };
  notes: string[];
}

/** One agent artifact of a binary with the analyst's verdict on it. */
export interface ArtifactRating {
  binary_id: number;
  kind: string;
  rating: string;
  note: string;
  actor: string;
  created_at: string;
  updated_at: string;
}

/** One stored agent artifact, rated or not. */
export interface ArtifactEntry {
  kind: string;
  stored: boolean;
  rating: ArtifactRating | null;
}

/** `GET /api/binaries/<id>/ratings`. */
export interface ArtifactRatings {
  binary_id: number;
  artifacts: ArtifactEntry[];
  count: number;
  rated: number;
  kinds: string[];
}

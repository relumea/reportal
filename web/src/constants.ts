// Values shared between the binary and function panels; each mirrors a set the
// API validates (engines.DECOMPILER_BACKENDS and engines.DISASM_FORMATS).

import type { DataTypeKind, MatchMetric, SearchKind, TransferMode } from "./types";

export const DECOMPILER_BACKENDS = ["kuna", "r2ghidra", "r2dec", "ghidra", "auto"] as const;
export const DEFAULT_DECOMPILER_BACKEND = DECOMPILER_BACKENDS[0];

export const DISASM_FORMATS = ["nasm", "hex"] as const;
export type DisasmFormat = (typeof DISASM_FORMATS)[number];

// The two views of a function's code the Disassembly panel toggles between:
// the engine's text listing and its basic-block control-flow graph.  The
// values are internal; the labels are what the toggle renders.
export const FUNCTION_CODE_VIEWS = ["disassembly", "cfg"] as const;
export type FunctionCodeView = (typeof FUNCTION_CODE_VIEWS)[number];
export const DEFAULT_FUNCTION_CODE_VIEW: FunctionCodeView = "disassembly";
export const FUNCTION_CODE_VIEW_LABELS: Record<FunctionCodeView, string> = {
  disassembly: "Disassembly",
  cfg: "Control Flow",
};

// Minimum confidence an Auto-unstrip run accepts; mirrors the API's
// unstrip.DEFAULT_MIN_CONFIDENCE.
export const DEFAULT_MIN_CONFIDENCE = 0.0;

// Severity floor a Security scan accepts, most severe first; mirrors the API's
// engines.SECURITY_SEVERITIES.  The default collects every finding.
export const SECURITY_SEVERITIES = ["high", "medium", "low"] as const;
export type SecuritySeverity = (typeof SECURITY_SEVERITIES)[number];
export const DEFAULT_SECURITY_SEVERITY: SecuritySeverity = "low";

// Confidence labels a Capability result carries, most confident first; mirrors
// the API's capabilities.CONFIDENCE_HIGH / CONFIDENCE_MEDIUM.
export const CAPABILITY_CONFIDENCES = ["high", "medium"] as const;

// Behavior domains the Behavior panel scans, in panel order; mirrors the API's
// behavior.BEHAVIOR_DOMAINS.
export const BEHAVIOR_DOMAINS = ["execution", "networking", "filesystem"] as const;
export type BehaviorDomain = (typeof BEHAVIOR_DOMAINS)[number];
export const DEFAULT_BEHAVIOR_DOMAIN: BehaviorDomain = BEHAVIOR_DOMAINS[0];

// Confidence labels a behavior finding carries, most confident first; mirrors
// the API's capabilities.CONFIDENCE_HIGH / CONFIDENCE_MEDIUM.
export const BEHAVIOR_CONFIDENCES = ["high", "medium"] as const;

// Hardening domains the Hardening panel scans, in panel order; mirrors the
// API's hardening.HARDENING_DOMAINS.
export const HARDENING_DOMAINS = ["anti-analysis", "obfuscation"] as const;
export type HardeningDomain = (typeof HARDENING_DOMAINS)[number];
export const DEFAULT_HARDENING_DOMAIN: HardeningDomain = HARDENING_DOMAINS[0];

// Confidence labels a hardening finding carries, most confident first; mirrors
// the API's hardening.CONFIDENCE_HIGH / CONFIDENCE_MEDIUM.
export const HARDENING_CONFIDENCES = ["high", "medium"] as const;


// Confidence labels a secrets finding carries, most confident first; mirrors
// the API's secrets.CONFIDENCE_HIGH / CONFIDENCE_MEDIUM.
export const SECRET_CONFIDENCES = ["high", "medium"] as const;

// Confidence labels a protocol entry carries, most confident first; mirrors
// the API's capabilities.CONFIDENCE_HIGH / CONFIDENCE_MEDIUM.
export const PROTOCOL_CONFIDENCES = ["high", "medium"] as const;

// IOC categories a threat report carries, in the order the panel renders them;
// mirrors the API's threat.IOC_CATEGORIES.
export const THREAT_IOC_CATEGORIES = [
  "urls",
  "domains",
  "ipv4",
  "ipv6",
  "emails",
  "registry_paths",
  "file_paths",
  "hashes",
] as const;

// The stored ATT&CK row keeps a plain technique id; only the rendered output
// links out, so the payload stays a local fact and the anchor is built here.
export const MITRE_TECHNIQUE_URL = "https://attack.mitre.org/techniques/";

// Threat-score bands the API reports, mapped onto the design language's three
// severity intensities (the top two bands share the strongest).  Mirrors the
// API's threat.SCORE_BAND_*.
export const THREAT_BAND_LEVELS: Record<string, "high" | "medium" | "low"> = {
  critical: "high",
  high: "high",
  moderate: "medium",
  low: "low",
};

// Candidate functions a Function triage run summarizes when the limit input is
// blank or unparsable; mirrors the API's function_triage.DEFAULT_LIMIT.
export const DEFAULT_FUNCTION_TRIAGE_LIMIT = 10;

// AI artifact kinds exposed on the function detail view; mirrors the API's
// llm.AI_KINDS (the stored artifact kind is also the payload's `kind`).
export type AiArtifactKind = "summary" | "comments" | "type-suggestions";

// URL segment per AI artifact kind.  The inline-comments artifact keeps the
// kind `comments`, but the analyst Comments panel owns `/comments`, so its
// wire path is `ai-comments`.
export const AI_ARTIFACT_PATHS: Record<AiArtifactKind, string> = {
  summary: "summary",
  comments: "ai-comments",
  "type-suggestions": "type-suggestions",
};

// Comment scope kinds the analyst Comments panel handles; mirrors the API's
// comments.SCOPE_KINDS.
export type CommentScopeKind = "binary" | "function";

// Longest comment body the API accepts; mirrors comments.MAX_COMMENT_CHARS.
export const COMMENT_MAX_CHARS = 4000;

// Longest verdict note the API accepts; mirrors ratings.MAX_NOTE_CHARS, the
// bound the input below enforces before the request fires.
export const RATING_NOTE_MAX_CHARS = 500;

// Author recorded when the SPA's comment form names none; mirrors the API's
// comments.DEFAULT_AUTHOR.
export const DEFAULT_COMMENT_AUTHOR = "analyst";

// localStorage key holding the SPA's own comment author, so the edit and
// delete controls appear only on comments this browser wrote.
export const COMMENT_AUTHOR_STORAGE_KEY = "reportal.commentAuthor";

// Error code the stored-only AI artifact GET answers when nothing is stored;
// mirrors the API's 404 no-artifact.
export const AI_NO_ARTIFACT = "no-artifact";

// Error code the stored-only pipeline GET answers when the function has no run;
// mirrors the API's 404 no-run.
export const PIPELINE_NO_RUN = "no-run";

// Calling conventions the signature model accepts; mirrors the API's
// signatures.CALLING_CONVENTIONS.  The empty value leaves the convention
// unspecified and renders no keyword.
export const CALLING_CONVENTIONS = ["cdecl", "stdcall", "fastcall", "thiscall", "vectorcall"] as const;

// Error code the stored-only signature GET answers when the function has none;
// mirrors the API's 404 signature-not-found.
export const SIGNATURE_NOT_FOUND = "signature-not-found";

// Listing kinds the diff route accepts, decompilation first; mirrors
// diffview.DIFF_KINDS and diffview.DEFAULT_KIND.
export const DIFF_KINDS = ["decomp", "disasm"] as const;
type DiffKind = (typeof DIFF_KINDS)[number];
export const DEFAULT_DIFF_KIND: DiffKind = DIFF_KINDS[0];

// Whether the diff strips addresses, bytes and comments by default; mirrors
// diffview.DEFAULT_NORMALIZE.
export const DEFAULT_DIFF_NORMALIZE = true;

// Conversation scope kinds the API accepts; mirrors conversations.SCOPE_KINDS.
export const CONVERSATION_SCOPE_KINDS = ["function", "binary", "docs"] as const;
export type ConversationScopeKind = (typeof CONVERSATION_SCOPE_KINDS)[number];

// Auto-mode workers exposed in the start form; mirrors the built-in names in
// auto_workers (a third party can register more).
export const AUTO_WORKERS = ["offline", "llm_c_source", "llm_goal"] as const;
export type AutoWorker = (typeof AUTO_WORKERS)[number];
export const DEFAULT_AUTO_WORKER: AutoWorker = AUTO_WORKERS[0];

// Longest goal the start form sends; mirrors auto_mode.MAX_GOAL_CHARS.
export const AUTO_GOAL_MAX = 2000;

// Error code the stored-only auto GET answers when a binary has no run;
// mirrors the API's 404 no-run.
export const AUTO_NO_RUN = "no-run";

// Poll interval while an auto run is still working, in milliseconds.
export const AUTO_POLL_MS = 1000;

// Concurrency bounds the start form accepts; mirrors auto_mode's floor and
// ceiling.
export const AUTO_CONCURRENCY_MIN = 1;
export const AUTO_CONCURRENCY_MAX = 32;
export const DEFAULT_AUTO_CONCURRENCY = 4;

// The other three run knobs the form sends, each with the bound auto_mode
// validates against and the default the route would use without it.
export const AUTO_FUNCTIONS_PER_TASK_MIN = 1;
export const AUTO_FUNCTIONS_PER_TASK_MAX = 64;
export const DEFAULT_AUTO_FUNCTIONS_PER_TASK = 1;
export const AUTO_MAX_ATTEMPTS_MIN = 1;
export const AUTO_MAX_ATTEMPTS_MAX = 10;
export const DEFAULT_AUTO_MAX_ATTEMPTS = 2;
export const AUTO_MAX_TASKS_MIN = 1;
export const AUTO_MAX_TASKS_MAX = 5000;
export const DEFAULT_AUTO_MAX_TASKS = 200;

// Results the Knowledge view's search asks for; mirrors the API's
// knowledge.DEFAULT_SEARCH_LIMIT.
export const DEFAULT_KNOWLEDGE_LIMIT = 10;

// Detail the API answers while remote URL ingestion is disabled; mirrors
// remote_ingest.DISABLED_DETAIL.  The URL field stays hidden in that state.
export const REMOTE_INGEST_DISABLED_DETAIL =
  "set REPORTAL_ALLOW_REMOTE_INGEST=1 or [knowledge] allow_remote = true to enable URL ingestion";

// Node kinds a knowledge graph carries, in the order the API rebuilds them;
// mirrors the API's graph.GRAPH_NODE_KINDS.
export const GRAPH_NODE_KINDS = [
  "binary",
  "function",
  "document",
  "struct",
  "tag",
  "capability",
  "library",
] as const;

// Error code the stored-only graph GET answers before the first build;
// mirrors the API's 404 no-graph.
export const GRAPH_NO_GRAPH = "no-graph";

// Node rows the Graph view renders before it stops and states the true total;
// a large binary's graph holds far more than this.
export const MAX_GRAPH_ROWS_SHOWN = 500;

// Orders the binary register accepts; the server sorts and echoes the value,
// and `id` is the insertion order it always used.  The names match the
// analyses list's, where the two controls mean the same thing.
export const BINARY_ORDERS = ["id", "newest", "name", "name-desc", "size", "size-desc"] as const;
type BinaryOrder = (typeof BINARY_ORDERS)[number];
// Mirrors store.DEFAULT_BINARY_ORDER.
export const DEFAULT_BINARY_ORDER: BinaryOrder = "id";

// Orders the collections list accepts; the server sorts and echoes the value,
// and `id` is the creation order it used before the control existed.  `owner`
// sorts by the owning team's name, the personal collections first.
export const COLLECTION_ORDERS = ["id", "name", "size", "updated", "owner"] as const;
export type CollectionOrder = (typeof COLLECTION_ORDERS)[number];
// Mirrors store.DEFAULT_COLLECTION_ORDER: the control falls back to the order
// the route uses when none is named.
export const DEFAULT_COLLECTION_ORDER: CollectionOrder = "id";

// Statuses the Lineage panel groups into tables; unchanged rows are only
// counted, since a version pair is usually mostly unchanged.
export const LINEAGE_ROW_STATUSES = ["changed", "removed", "added"] as const;

// Lineage rows the panel renders per status group before it stops and states
// the true count for that group.
export const MAX_LINEAGE_ROWS_SHOWN = 200;

// Confidence labels a family detection match carries, strongest first; mirrors
// the API's capabilities.CONFIDENCE_HIGH/_MEDIUM plus families.CONFIDENCE_LOW.
export const DETECT_CONFIDENCES = ["high", "medium", "low"] as const;

// Signature categories a file-type detection carries, in panel order; mirrors
// the API's filetypes.FILE_CATEGORIES.
export const FILETYPE_CATEGORIES = [
  "packer",
  "protector",
  "installer",
  "runtime",
  "toolchain",
] as const;


// Function rows the composition panel renders before it stops; the summary
// counts stay exact and the panel states the true total.  The API caps the
// payload at composition.MAX_ROWS, and the panel renders fewer than that.
export const MAX_COMPOSITION_ROWS_SHOWN = 200;


// A memory window's default and maximum length; mirrors the engine's
// MEMORY_READ_DEFAULT / MEMORY_READ_MAX, which are the hosted portal's
// read_memory bounds.
export const MEMORY_READ_DEFAULT = 64;
export const MEMORY_READ_MAX = 1024;

// The full-file view's page size bounds; mirrors the engine's
// MEMORY_PAGE_DEFAULT / MEMORY_PAGE_MAX.
export const MEMORY_PAGE_DEFAULT = 256;
export const MEMORY_PAGE_MAX = 4096;

// Address kinds a memory read accepts, in panel order; mirrors the engine's
// MEMORY_ADDRESS_KINDS.
export const MEMORY_ADDRESS_KINDS = ["va", "rva", "file"] as const;
export type MemoryAddressKind = (typeof MEMORY_ADDRESS_KINDS)[number];

// Bytes one row of the memory grid holds.
export const MEMORY_BYTES_PER_ROW = 16;

// The continuous hex view's read size and the rows it renders around the
// viewport.  The window is the same page the paged view reads, so one fetch
// serves both, and the overscan is what stops a fast scroll from showing
// nothing before the next window lands.
export const MEMORY_SCROLL_WINDOW = MEMORY_PAGE_DEFAULT;
export const MEMORY_SCROLL_OVERSCAN = 6;

// Where the continuous view remembers its address kind (`Offset` or
// `Virtual`), which the hosted portal keeps across sessions too.
export const MEMORY_COLUMN_STORAGE_KEY = "reportal.memory.column";

// Analysis statuses, in lifecycle order; mirrors the API's
// store.ANALYSIS_STATUSES.  The empty select value means "any status".
export const ANALYSIS_STATUSES = [
  "pending",
  "processing",
  "done",
  "failed",
  "cancelled",
] as const;

// Sort orders the analyses listing accepts; mirrors store.ANALYSIS_ORDERS.
export const ANALYSIS_ORDERS = ["newest", "oldest", "name", "name-desc", "size", "size-desc"] as const;

/** The labels the order control shows for those values. */
export const ANALYSIS_ORDER_LABELS: Record<(typeof ANALYSIS_ORDERS)[number], string> = {
  newest: "newest first",
  oldest: "oldest first",
  name: "name (A to Z)",
  "name-desc": "name (Z to A)",
  size: "size (small first)",
  "size-desc": "size (large first)",
};

/** The workspace filter's labels; mirrors store.WORKSPACE_FILTERS.  The
 *  Analyses and Collections lists both filter by it. */
export const WORKSPACE_FILTERS = ["personal", "team", "public"] as const;
export type WorkspaceFilter = (typeof WORKSPACE_FILTERS)[number];

// Rows one analyses request asks for, and the most the route accepts; both
// mirror store.DEFAULT_ANALYSIS_LIMIT and store.MAX_ANALYSIS_LIMIT.
export const DEFAULT_ANALYSIS_LIMIT = 100;
export const MAX_ANALYSIS_LIMIT = 1000;

// A log page's size when the drawer opens and when "Load more" is pressed;
// mirrors analysis_log.DEFAULT_LOG_LIMIT.
export const DEFAULT_ANALYSIS_LOG_LIMIT = 200;

// Name-source labels the function filter offers, in the portal's order;
// mirrors the API's composition.NAME_SOURCE_LABELS.
export const FUNCTION_NAME_SOURCES = [
  "System",
  "Auto Unstrip",
  "AI Agent",
  "User",
  "No Debug Info",
] as const;

const NAME_SOURCE_MAP: Record<string, (typeof FUNCTION_NAME_SOURCES)[number]> = {
  import: "System",
  rebrew: "System",
  symbol: "System",
  flirt: "System",
  unstrip: "Auto Unstrip",
  renames: "AI Agent",
};
const PLACEHOLDER_PREFIXES = ["sub_", "fcn_", "FUN_", "FUNC_"] as const;

/** Portal label for a stored function name and source. */
export function nameSourceLabel(
  name: string,
  source: string,
): (typeof FUNCTION_NAME_SOURCES)[number] {
  const stripped = name.trim();
  if (!stripped || PLACEHOLDER_PREFIXES.some((prefix) => stripped.startsWith(prefix))) {
    return "No Debug Info";
  }
  const key = source.trim().toLowerCase();
  return NAME_SOURCE_MAP[key] ?? (key.startsWith("ai") ? "AI Agent" : "User");
}

const TYPE_SOURCE_MAP: Record<string, string> = {
  scan: "System",
  symbol: "System",
  manual: "User",
  unstrip: "Auto Unstrip",
  ai: "AI",
};

/** Portal provenance label for a stored data-type source. */
export function typeSourceLabel(source: string): string {
  const key = source.trim().toLowerCase();
  if (TYPE_SOURCE_MAP[key]) return TYPE_SOURCE_MAP[key];
  if (key.startsWith("ai") && key.length > 2) return "AI";
  return "User";
}

// Capability names the function filter offers, in the rule table's order;
// mirrors the API's capabilities.CAPABILITIES.  The API refuses any other
// value, so the panel offers exactly these.
export const FUNCTION_CAPABILITIES = [
  "networking",
  "crypto",
  "file-io",
  "registry",
  "process-execution",
  "threading",
  "memory",
  "dynamic-loading",
  "anti-debug",
  "persistence",
  "synchronization",
  "compression",
  "ui",
  "console",
] as const;

// Columns the functions table sorts by; mirrors the API's
// store.FUNCTION_SORT_COLUMNS.
export const FUNCTION_SORTS = ["va", "size", "name", "status"] as const;
export type FunctionSort = (typeof FUNCTION_SORTS)[number];
export const DEFAULT_FUNCTION_SORT: FunctionSort = "va";

// Sort directions the functions listing accepts; mirrors
// store.FUNCTION_ORDERS.
export const FUNCTION_ORDERS = ["asc", "desc"] as const;
export type FunctionOrder = (typeof FUNCTION_ORDERS)[number];
export const DEFAULT_FUNCTION_ORDER: FunctionOrder = "asc";

// Orders the strings panel accepts; mirrors store.STRING_SORTS.
export const STRING_SORTS = ["value", "length"] as const;
export type StringSort = (typeof STRING_SORTS)[number];
export const DEFAULT_STRING_SORT: StringSort = "value";

// What a signature parameter is; mirrors signatures.PARAMETER_KINDS.
export const PARAMETER_KINDS = ["value", "pointer", "array", "struct"] as const;
export type ParameterKind = (typeof PARAMETER_KINDS)[number];

// Stored match-state values the function filter accepts; mirrors
// store.FUNCTION_MATCH_VALUES.
export const FUNCTION_MATCH_VALUES = ["matched", "unmatched"] as const;

// Match metrics the matches view ranks by.  Difference is the derived
// complement `100 - similarity`, so the badge it renders is never a stored
// value.
export const MATCH_METRICS = ["similarity", "confidence", "difference"] as const satisfies readonly MatchMetric[];
export const MATCH_METRIC_LABELS: Record<MatchMetric, string> = {
  similarity: "Similarity",
  confidence: "Confidence",
  difference: "Difference (100 - similarity)",
};
export const DEFAULT_MATCH_METRIC: MatchMetric = "similarity";

// Transfer modes the apply paths accept; mirrors matching.TRANSFER_MODES.
export const TRANSFER_MODES = ["name", "signature", "both"] as const satisfies readonly TransferMode[];
export const TRANSFER_MODE_LABELS: Record<TransferMode, string> = {
  name: "Name",
  signature: "Signature",
  both: "Name and signature",
};
export const DEFAULT_TRANSFER_MODE: TransferMode = "name";

// Platform and architecture labels the Match Settings sheet offers; mirrors
// matching.PLATFORMS and matching.ARCHITECTURES.  The scope is a coarse filter
// over the stored fingerprint (else the suffix-derived format/arch columns),
// which the sheet states beside the controls.
export const MATCH_PLATFORMS = ["windows", "linux", "android"] as const;
export const MATCH_ARCHITECTURES = ["x86_64", "x86_32", "arm64"] as const;
export const MATCH_PLATFORM_LABELS: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  android: "Android",
};
export const MATCH_ARCHITECTURE_LABELS: Record<string, string> = {
  x86_64: "x86 (64-bit)",
  x86_32: "x86 (32-bit)",
  arm64: "ARM (64-bit)",
};

// Defaults the Match Settings sheet starts from; they reproduce reportal's run
// before the settings existed.  Mirrors matching.DEFAULT_*.
export const DEFAULT_MIN_SIMILARITY = 80;
export const DEFAULT_MIN_MATCH_CONFIDENCE = 0.0;
export const DEFAULT_INCLUDE_SELF = true;
export const DEFAULT_MATCH_TOP = 10;

// Declaration kinds the type model carries; mirrors the API's
// data_types.KINDS.  The panel offers exactly these, since the API refuses
// any other value with 400 invalid kind.
export const DATA_TYPE_KINDS = [
  "struct",
  "union",
  "enum",
  "typedef",
  "pointer",
  "array",
  "function",
] as const;

/** Empty namespace: the binary's own types. Mirrors `data_types.PROGRAM_NAMESPACE`. */
export const PROGRAM_NAMESPACE = "Binary";

// Kind labels the filter and the per-type card show.
export const DATA_TYPE_KIND_LABELS: Record<DataTypeKind, string> = {
  struct: "struct",
  union: "union",
  enum: "enum",
  typedef: "Type alias",
  pointer: "pointer *",
  array: "array []",
  function: "function ()",
};

// Compact C tags the kind strip shows; hover uses DATA_TYPE_KIND_LABELS.
export const DATA_TYPE_KIND_TAGS: Record<DataTypeKind, string> = {
  struct: "struct",
  union: "union",
  enum: "enum",
  typedef: "typedef",
  pointer: "*",
  array: "[]",
  function: "fn",
};

// Search query types, in the order the modal's toggles offer them; mirrors the
// API's store.SEARCH_KINDS.  `all` is the substring search the route always
// had, so a caller that picks nothing keeps today's behaviour.
export const SEARCH_KINDS = ["all", "sha256", "binary", "collection", "tag"] as const;
export const SEARCH_KIND_LABELS: Record<SearchKind, string> = {
  all: "All",
  sha256: "SHA-256 Hash",
  binary: "Binary",
  collection: "Collection",
  tag: "Tag",
};

// Wait before a typed query reaches the API, in milliseconds.
export const SEARCH_DEBOUNCE_MS = 220;

// Explicit per-file upload hints the upload form offers; mirrors the API's
// UPLOAD_FORMATS, UPLOAD_ARCHITECTURES and UPLOAD_COMPILERS (the arch
// spellings are the engine's, matching.ARCHITECTURES; compilers are the
// filetype toolchain names).  The empty value leaves recovery in place,
// which is the hosted portal's Auto.
export const UPLOAD_FORMATS = ["pe", "elf", "blob"] as const;
export const UPLOAD_ARCHITECTURES = ["x86_32", "x86_64", "arm64"] as const;
export const UPLOAD_COMPILERS = ["Microsoft Visual C++", "MinGW GCC"] as const;

// Files one batch upload may carry; mirrors the API's MAX_UPLOAD_FILES.
export const MAX_UPLOAD_FILES = 64;

// Roles a user may carry; mirrors auth.ROLES.
export const ROLES = ["viewer", "analyst", "admin"] as const;

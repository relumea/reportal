// Instrument design tokens, in one place.  The colours live in styles.css; this
// module names the semantic entities a component picks with `data-hue` /
// `data-status`, so the same concept keeps the same hue in every view.  Adding
// an entity means adding its token pair in styles.css and its name here, never
// a colour in a view.
//
// The language is described in docs/ARCHITECTURE.md; its source is
// ~/Desktop/tmog/DESIGN_RULES.md.

/** Hue families a `data-hue` container exposes as `--hue-ink/-soft/-line`. */
export type HueFamily = "match" | "near" | "stub" | "thunk" | "fail" | "live";

/** Function status entities; each maps to one ink token. */
export type StatusEntity =
  | "exact"
  | "reloc"
  | "proven"
  | "thunk"
  | "near"
  | "stub"
  | "idle"
  | "live"
  | "fail";

/** Confidence and severity levels; the ordinal scales of those two concepts. */
export type Level = "high" | "medium" | "low";

// Status spellings the API reports, folded onto the entities.  An unlisted
// status is neutral, so a new one renders instead of disappearing.
const STATUS_ENTITIES: Record<string, StatusEntity> = {
  exact: "exact",
  matched: "exact",
  identical: "exact",
  done: "exact",
  complete: "exact",
  succeeded: "exact",
  verified: "exact",
  active: "exact",
  reloc: "reloc",
  proven: "proven",
  thunk: "thunk",
  near_match: "near",
  near_matching: "near",
  "near-matching": "near",
  matching: "near",
  partial: "near",
  stub: "stub",
  missing_size: "stub",
  "missing-size": "stub",
  skipped: "idle",
  queued: "idle",
  pending: "idle",
  cancelled: "idle",
  unknown: "idle",
  unrelated: "idle",
  "same-imports": "idle",
  "same-toolchain": "idle",
  "similar-size": "idle",
  "similar-capabilities": "idle",
  "similar-lifecycle": "idle",
  running: "live",
  in_progress: "live",
  "in-progress": "live",
  processing: "live",
  failed: "fail",
  error: "fail",
  unavailable: "fail",
  size_mismatch: "fail",
  "size-mismatch": "fail",
  missing: "fail",
};

/** The status entity a reported status folds onto, or null when neutral. */
export function statusEntity(status: string): StatusEntity | null {
  return STATUS_ENTITIES[status.trim().toLowerCase()] ?? null;
}

// Log severities folded onto the severity scale: an error reads as the top of
// the scale, a warning as its middle, an informational row at the bottom.  The
// vocabulary is analysis_log.SEVERITIES, a different one from a confidence or
// severity label, so it gets its own table rather than widening `levelOf`.
const LOG_SEVERITY_LEVELS: Record<string, Level> = {
  error: "high",
  warn: "medium",
  info: "low",
};

/** The severity-scale level a log entry's severity renders at, or null. */
export function logSeverityLevel(severity: string): Level | null {
  return LOG_SEVERITY_LEVELS[severity.trim().toLowerCase()] ?? null;
}

/** The level a confidence or severity label maps to, or null when unlabelled. */
export function levelOf(label: string): Level | null {
  const key = label.trim().toLowerCase();
  if (key === "high" || key === "medium" || key === "low") return key;
  return null;
}

// File-type categories are distinct entities, not a magnitude, so each keeps
// its own family hue.
const CATEGORY_HUES: Record<string, HueFamily> = {
  packer: "near",
  protector: "fail",
  installer: "live",
  runtime: "thunk",
  toolchain: "stub",
};

/** The family hue a file-type category keeps across views. */
export function categoryHue(category: string): HueFamily | null {
  return CATEGORY_HUES[category.trim().toLowerCase()] ?? null;
}

// Match-quality bands are an ordinal scale, not a status, so each matched band
// keeps a family hue.  No Match carries none: it is the absence of a match, and
// the panel renders it as an explicit labelled state rather than a lit meter.
const QUALITY_HUES: Record<string, HueFamily> = {
  "strong match": "match",
  match: "match",
  "partial match": "near",
  "weak match": "stub",
};

/** The family hue a match-quality band keeps across views, or null for No Match. */
export function qualityHue(band: string): HueFamily | null {
  return QUALITY_HUES[band.trim().toLowerCase()] ?? null;
}

// ── Instrument geometry ────────────────────────────────────────────

/** Quantized steps of a level meter; discrete steps stay readable at distance. */
export const METER_SEGMENTS = 20;

/** Steps of the sequential magnitude ramp (cold to matched). */
export const RAMP_STEPS = 5;

/** Top of the Shannon entropy scale the packer card measures, in bits per byte. */
export const ENTROPY_MAX = 8;

/** Section entropy at or above this reads as compressed or packed; mirrors the
 *  engine-side filetypes.HIGH_ENTROPY_THRESHOLD and hardening rule. */
export const PACKED_ENTROPY_THRESHOLD = 7.0;

// Must match --flash-duration in styles.css: the class is dropped when the
// animation has finished, so a longer CSS duration would cut the fade short.
export const FLASH_MS = 1100;

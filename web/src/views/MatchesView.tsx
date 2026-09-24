import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import type { ReactNode } from "react";

import { BINARY_OPTIONS_PATH, api } from "../api";
import "./matches.css";
import {
  Badge,
  Button,
  CheckboxField,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  FilterChip,
  Loading,
  Muted,
  NA,
  Note,
  Panel,
  Toolbar,
  hex,
} from "../components";
import {
  DEFAULT_INCLUDE_SELF,
  DEFAULT_MATCH_METRIC,
  DEFAULT_MATCH_TOP,
  DEFAULT_MIN_MATCH_CONFIDENCE,
  DEFAULT_MIN_SIMILARITY,
  DEFAULT_TRANSFER_MODE,
  FUNCTION_NAME_SOURCES,
  MATCH_ARCHITECTURES,
  MATCH_ARCHITECTURE_LABELS,
  MATCH_METRICS,
  MATCH_METRIC_LABELS,
  MATCH_PLATFORMS,
  MATCH_PLATFORM_LABELS,
  TRANSFER_MODES,
  TRANSFER_MODE_LABELS,
  isPlaceholderName,
  nameSourceLabel,
} from "../constants";
import { METER_SEGMENTS, nameSourceHue, qualityHue } from "../design";
import type {
  BinaryMatchesPayload,
  BinaryMatchRow,
  BinaryOption,
  Collection,
  FunctionListPage,
  FunctionRow,
  MatchMetric,
  MatchRunPayload,
  MatchRunSettings,
  TransferMode,
  TransferReport,
  TransferRowReport,
} from "../types";
import { useAsync } from "../useAsync";

// The five quality bands the matcher's similarity partitions into, strongest
// first; mirrors composition.QUALITY_BANDS.
const QUALITY_BANDS = ["Strong Match", "Match", "Partial Match", "Weak Match", "No Match"];

// Confidence carries two decimals (a softmax fraction); the similarity and its
// derived difference carry one, since the server rounds them to one.
const CONFIDENCE_DECIMALS = 2;

function rowKey(row: BinaryMatchRow): string {
  return `${row.source_function_id}:${row.candidate_function_id}`;
}

function unmatchedRow(fn: FunctionRow): BinaryMatchRow {
  return {
    source_function_id: fn.id,
    source_name: fn.name,
    source_va: fn.va,
    source_name_source: fn.name_source,
    candidate_function_id: 0,
    candidate_name: "",
    candidate_va: 0,
    candidate_binary_id: 0,
    candidate_binary_name: "",
    similarity: 0,
    confidence: 0,
    difference: 100,
    band: "No Match",
    source_arch: "",
    candidate_arch: "",
    cross_arch: false,
    settings: null,
  };
}

function hasCandidate(row: BinaryMatchRow): boolean {
  return row.candidate_function_id > 0;
}

/** A recorded candidate whose name is generated (`fcn_…`): applying it names nothing. */
function unnamedCandidate(row: BinaryMatchRow): boolean {
  return hasCandidate(row) && isPlaceholderName(row.candidate_name);
}

function sourceLabel(row: BinaryMatchRow): string {
  return nameSourceLabel(row.source_name, row.source_name_source);
}

/** The band a stacked-bar segment belongs to, by cumulative share of *total*. */
function bandAt(counts: Map<string, number>, total: number, index: number): string | null {
  if (total <= 0) return null;
  const position = (index + 0.5) / METER_SEGMENTS;
  let cumulative = 0;
  for (const band of QUALITY_BANDS) {
    cumulative += (counts.get(band) ?? 0) / total;
    if (position <= cumulative) return band;
  }
  return null;
}

/** The stacked quality bar: one segment per band, the unlit remainder empty. */
function QualityBar({
  counts,
  total,
  selected,
  onSelect,
}: {
  counts: Map<string, number>;
  total: number;
  selected: string;
  onSelect: (band: string) => void;
}): ReactNode {
  return (
    <div className="quality-bar">
      <div className="meter-head">
        <span className="meter-label">Match quality</span>
        <span className="meter-value">
          {total} candidate{total === 1 ? "" : "s"}
        </span>
      </div>
      <div className="meter-track" role="img" aria-label={`Match quality over ${total} candidates`}>
        {Array.from({ length: METER_SEGMENTS }, (_unused, index) => {
          const band = bandAt(counts, total, index);
          const hue = band ? qualityHue(band) : null;
          return (
            <span
              key={index}
              className="meter-seg"
              data-hue={hue ?? undefined}
              data-lit={band ? "true" : undefined}
              title={band ?? "unlit"}
            />
          );
        })}
      </div>
      <div className="quality-legend" role="group" aria-label="Filter by match quality">
        {QUALITY_BANDS.map((band) => {
          const count = counts.get(band) ?? 0;
          return (
            <button
              key={band}
              type="button"
              className="quality-legend-item"
              data-hue={qualityHue(band) ?? undefined}
              data-empty={count === 0 ? "true" : undefined}
              data-selected={selected === band ? "true" : undefined}
              aria-pressed={selected === band}
              onClick={() => onSelect(selected === band ? "" : band)}
            >
              <span className="quality-swatch" aria-hidden="true" />
              {band} <span className="num">{count}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function SourceBar({
  counts,
  selected,
  onSelect,
}: {
  counts: Map<string, number>;
  selected: string;
  onSelect: (label: string) => void;
}): ReactNode {
  return (
    <div className="quality-bar">
      <div className="meter-head">
        <span className="meter-label">Function name sources</span>
      </div>
      <div className="quality-legend" role="group" aria-label="Filter by name source">
        {FUNCTION_NAME_SOURCES.map((label) => {
          const count = counts.get(label) ?? 0;
          return (
            <button
              key={label}
              type="button"
              className="quality-legend-item"
              data-hue={nameSourceHue(label) ?? undefined}
              data-empty={count === 0 ? "true" : undefined}
              data-selected={selected === label ? "true" : undefined}
              aria-pressed={selected === label}
              onClick={() => onSelect(selected === label ? "" : label)}
            >
              <span className="quality-swatch" aria-hidden="true" />
              {label} <span className="num">{count}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

/** The metric value a match row is labelled with, in its own units. */
function metricText(row: BinaryMatchRow, metric: MatchMetric): string {
  if (metric === "confidence") return row.confidence.toFixed(CONFIDENCE_DECIMALS);
  if (metric === "difference") return `${row.difference.toFixed(1)}%`;
  return `${row.similarity.toFixed(1)}%`;
}

export function MatchesView({
  functionId,
  onSelectFunction,
}: {
  functionId: number | null;
  onSelectFunction: (functionId: number | null) => void;
}): ReactNode {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [draft, setDraft] = useState(functionId === null ? "" : String(functionId));

  // Syncs an externally chosen function (a `?function=` link) into the box.
  // Clearing on the way out happens in the All functions handler below, not
  // here: an effect clearing after the click races a refill typed into the
  // same box and silently drops it.
  useEffect(() => {
    if (functionId !== null) setDraft(String(functionId));
  }, [functionId]);

  const [suggestions, setSuggestions] = useState<Array<{ id: number; label: string }>>([]);

  // A typed name narrows the global function search, so a reader who knows the
  // name never needs the id: the picked option carries the name and the id.
  useEffect(() => {
    const text = draft.trim();
    if (text === "" || /^\d+$/.test(text)) {
      setSuggestions([]);
      return undefined;
    }
    let active = true;
    const timer = window.setTimeout(() => {
      void api<{ functions: Array<{ id: number; name: string }> }>(
        `/search?q=${encodeURIComponent(text)}&limit=10`,
      )
        .then((results) => {
          if (!active) return;
          setSuggestions(
            results.functions.slice(0, 10).map((row) => ({
              id: row.id,
              label: `${row.name} (#${row.id})`,
            })),
          );
        })
        .catch(() => {
          if (active) setSuggestions([]);
        });
    }, 250);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [draft]);

  /** The function the box names: a bare id, else the picked suggestion's row. */
  const draftFunctionId = (): number | null => {
    const text = draft.trim();
    if (/^\d+$/.test(text)) return Number(text);
    return suggestions.find((item) => item.label === text)?.id ?? null;
  };

  const functionResult = useAsync<FunctionRow>(
    () => api<FunctionRow>(`/functions/${functionId}`),
    [functionId],
    functionId !== null,
  );
  // The binary whose match rows these are: named by the loaded function, or
  // picked on its own when the reader wants every function's rows at once.
  // Kept in `?binary=` so a binary's matches can be linked to and survive a reload.
  const [binaryChoice, setBinaryChoice] = useState<number | null>(
    () => Number(params.get("binary")) || null,
  );
  const chooseBinary = (id: number | null): void => {
    setBinaryChoice(id);
    setParams(
      (next) => {
        if (id === null) next.delete("binary");
        else next.set("binary", String(id));
        return next;
      },
      { replace: true },
    );
  };
  const binaryId = functionResult.data?.binary_id ?? binaryChoice;
  useEffect(() => {
    const loaded = functionResult.data?.binary_id;
    if (typeof loaded === "number") setBinaryChoice(loaded);
  }, [functionResult.data]);

  const matchesResult = useAsync<BinaryMatchesPayload>(
    () => api<BinaryMatchesPayload>(`/binaries/${binaryId}/matches`),
    [binaryId],
    binaryId !== null,
  );
  const functionsResult = useAsync<FunctionListPage>(
    () => api<FunctionListPage>(`/binaries/${binaryId}/functions?limit=1`),
    [binaryId],
    binaryId !== null,
  );
  const unmatchedResult = useAsync<FunctionListPage>(
    () => api<FunctionListPage>(`/binaries/${binaryId}/functions?match=unmatched`),
    [binaryId],
    binaryId !== null,
  );
  const binariesResult = useAsync<{ binaries: BinaryOption[] }>(() => api(BINARY_OPTIONS_PATH), []);
  const collectionsResult = useAsync<{ collections: Collection[] }>(() => api(`/collections`), []);

  const [bandFilter, setBandFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [showUnnamed, setShowUnnamed] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [minSimilarity, setMinSimilarity] = useState(DEFAULT_MIN_SIMILARITY);
  const [minConfidence, setMinConfidence] = useState(DEFAULT_MIN_MATCH_CONFIDENCE);
  const [includeSelf, setIncludeSelf] = useState(DEFAULT_INCLUDE_SELF);
  const [top, setTop] = useState(DEFAULT_MATCH_TOP);
  const [platforms, setPlatforms] = useState<string[]>([]);
  const [architectures, setArchitectures] = useState<string[]>([]);
  const [nameSources, setNameSources] = useState<string[]>([]);
  const [scopeBinaries, setScopeBinaries] = useState<number[]>(() =>
    (params.get("binary_ids") ?? "")
      .split(",")
      .map((part) => Number(part.trim()))
      .filter((id) => Number.isFinite(id) && id > 0),
  );
  const [scopeCollections, setScopeCollections] = useState<number[]>([]);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<unknown>(null);
  const [runResult, setRunResult] = useState<MatchRunPayload | null>(null);

  const [metric, setMetric] = useState<MatchMetric>(DEFAULT_MATCH_METRIC);
  const [rowModes, setRowModes] = useState<Record<string, TransferMode>>({});
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [rowError, setRowError] = useState<unknown>(null);
  const [rowReports, setRowReports] = useState<Record<string, TransferRowReport>>({});

  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkNames, setBulkNames] = useState<Record<string, boolean>>({});
  const [bulkSignatures, setBulkSignatures] = useState<Record<string, boolean>>({});
  const [bulkPending, setBulkPending] = useState(false);
  const [bulkError, setBulkError] = useState<unknown>(null);
  const [bulkReport, setBulkReport] = useState<TransferReport | null>(null);

  const recorded = matchesResult.data?.matches ?? [];
  const rows = useMemo(
    () => [...recorded, ...(unmatchedResult.data?.functions ?? []).map(unmatchedRow)],
    [recorded, unmatchedResult.data],
  );

  const ranked = useMemo(() => {
    const filtered = rows.filter((row) => {
      if (!showUnnamed && unnamedCandidate(row)) return false;
      if (bandFilter !== "" && row.band !== bandFilter) return false;
      if (sourceFilter !== "" && sourceLabel(row) !== sourceFilter) return false;
      return true;
    });
    const sorted = [...filtered];
    sorted.sort((left, right) => {
      if (metric === "confidence") return right.confidence - left.confidence;
      if (metric === "difference") return left.difference - right.difference;
      return right.similarity - left.similarity;
    });
    return sorted;
  }, [rows, metric, bandFilter, sourceFilter, showUnnamed]);
  const unnamedCount = useMemo(() => rows.filter(unnamedCandidate).length, [rows]);

  const bandCounts = useMemo(() => {
    const counts = new Map<string, number>(QUALITY_BANDS.map((band) => [band, 0]));
    for (const row of rows) counts.set(row.band, (counts.get(row.band) ?? 0) + 1);
    return counts;
  }, [rows]);

  const sourceCounts = useMemo(() => {
    const counts = new Map<string, number>(FUNCTION_NAME_SOURCES.map((label) => [label, 0]));
    for (const row of rows) {
      const label = sourceLabel(row);
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
    return counts;
  }, [rows]);

  const matchedCount = useMemo(() => {
    return new Set(recorded.map((row) => row.source_function_id)).size;
  }, [recorded]);
  const foundCount = useMemo(() => {
    if (functionId === null) return 0;
    return recorded.filter((row) => row.source_function_id === functionId).length;
  }, [recorded, functionId]);
  const functionTotal = functionsResult.data?.total ?? null;
  const matchedPercent =
    functionTotal === null || functionTotal === 0
      ? 0
      : Math.round((100 * matchedCount) / functionTotal);

  const toggleValue = (
    values: string[],
    value: string,
    setter: (next: string[]) => void,
    on: boolean,
  ): void => {
    setter(on ? [...values.filter((item) => item !== value), value] : values.filter((item) => item !== value));
  };

  const toggleId = (
    values: number[],
    value: number,
    setter: (next: number[]) => void,
    on: boolean,
  ): void => {
    setter(on ? [...values.filter((item) => item !== value), value] : values.filter((item) => item !== value));
  };

  const applySettings = (settings: MatchRunSettings): void => {
    setMinSimilarity(settings.min_similarity);
    setMinConfidence(settings.min_confidence);
    setIncludeSelf(settings.include_self);
    setTop(settings.top);
    setPlatforms(settings.platforms);
    setArchitectures(settings.architectures);
    setScopeBinaries(settings.binary_ids);
    setScopeCollections(settings.collection_ids);
    setNameSources(settings.name_sources ?? []);
  };

  const clearSettings = (): void => {
    applySettings({
      min_similarity: DEFAULT_MIN_SIMILARITY,
      min_confidence: DEFAULT_MIN_MATCH_CONFIDENCE,
      include_self: DEFAULT_INCLUDE_SELF,
      top: DEFAULT_MATCH_TOP,
      platforms: [],
      architectures: [],
      binary_ids: [],
      collection_ids: [],
      name_sources: [],
    });
  };

  const runMatch = async (): Promise<void> => {
    if (binaryId === null) return;
    setRunning(true);
    setRunError(null);
    try {
      const payload = await api<MatchRunPayload>(`/binaries/${binaryId}/match`, {
        method: "POST",
        json: {
          min_similarity: minSimilarity,
          min_confidence: minConfidence,
          include_self: includeSelf,
          top,
          platforms,
          architectures,
          binary_ids: scopeBinaries,
          collection_ids: scopeCollections,
          name_sources: nameSources,
        },
      });
      setRunResult(payload);
      applySettings(payload.settings);
      // A run changes which functions are matched, so the unmatched list
      // reloads with the matches instead of keeping the previous split.
      matchesResult.reload();
      unmatchedResult.reload();
    } catch (failure) {
      setRunError(failure);
    } finally {
      setRunning(false);
    }
  };

  const applyRow = async (row: BinaryMatchRow): Promise<void> => {
    const key = rowKey(row);
    setRowBusy(key);
    setRowError(null);
    try {
      const report = await api<TransferRowReport>(`/functions/${row.source_function_id}/apply-match`, {
        method: "POST",
        json: {
          candidate_function_id: row.candidate_function_id,
          mode: rowModes[key] ?? DEFAULT_TRANSFER_MODE,
          actor: "spa",
        },
      });
      setRowReports((current) => ({ ...current, [key]: report }));
      matchesResult.reload();
    } catch (failure) {
      setRowError(failure);
    } finally {
      setRowBusy(null);
    }
  };

  const openBulk = (): void => {
    const names: Record<string, boolean> = {};
    const signatures: Record<string, boolean> = {};
    for (const row of recorded) {
      const key = rowKey(row);
      names[key] = row.candidate_name.trim() !== "" && row.candidate_name !== row.source_name;
      signatures[key] = false;
    }
    setBulkNames(names);
    setBulkSignatures(signatures);
    setBulkReport(null);
    setBulkError(null);
    setBulkOpen(true);
  };

  const bulkRequests = (): Array<{
    function_id: number;
    candidate_function_id: number;
    mode: TransferMode;
  }> => {
    const requests: Array<{
      function_id: number;
      candidate_function_id: number;
      mode: TransferMode;
    }> = [];
    for (const row of recorded) {
      const key = rowKey(row);
      const wantsName = bulkNames[key] ?? false;
      const wantsSignature = bulkSignatures[key] ?? false;
      if (!wantsName && !wantsSignature) continue;
      const mode: TransferMode =
        wantsName && wantsSignature ? "both" : wantsName ? "name" : "signature";
      requests.push({
        function_id: row.source_function_id,
        candidate_function_id: row.candidate_function_id,
        mode,
      });
    }
    return requests;
  };

  const transferBulk = async (dryRun: boolean): Promise<void> => {
    if (binaryId === null) return;
    setBulkPending(true);
    setBulkError(null);
    try {
      const report = await api<TransferReport>(`/binaries/${binaryId}/matches/transfer`, {
        method: "POST",
        json: { transfers: bulkRequests(), dry_run: dryRun, actor: "spa" },
      });
      setBulkReport(report);
      if (!dryRun) matchesResult.reload();
    } catch (failure) {
      setBulkError(failure);
    } finally {
      setBulkPending(false);
    }
  };

  const activeCount = bulkRequests().length;
  const activeNames = recorded.filter((row) => bulkNames[rowKey(row)] ?? false).length;
  const activeSignatures = recorded.filter((row) => bulkSignatures[rowKey(row)] ?? false).length;

  const chips: ReactNode[] = [];
  if (minSimilarity !== DEFAULT_MIN_SIMILARITY) {
    chips.push(
      <FilterChip
        key="min-similarity"
        label={`\u2265 ${minSimilarity}%`}
        onClear={() => setMinSimilarity(DEFAULT_MIN_SIMILARITY)}
      />,
    );
  }
  if (minConfidence !== DEFAULT_MIN_MATCH_CONFIDENCE) {
    chips.push(
      <FilterChip
        key="min-confidence"
        label={`Confidence >= ${minConfidence}`}
        onClear={() => setMinConfidence(DEFAULT_MIN_MATCH_CONFIDENCE)}
      />,
    );
  }
  if (!includeSelf) {
    chips.push(
      <FilterChip
        key="include-self"
        label="No self matches"
        onClear={() => setIncludeSelf(DEFAULT_INCLUDE_SELF)}
      />,
    );
  }
  if (top !== DEFAULT_MATCH_TOP) {
    chips.push(
      <FilterChip
        key="top"
        label={`Top ${top} per function`}
        onClear={() => setTop(DEFAULT_MATCH_TOP)}
      />,
    );
  }
  for (const platform of platforms) {
    chips.push(
      <FilterChip
        key={`platform-${platform}`}
        label={MATCH_PLATFORM_LABELS[platform] ?? platform}
        onClear={() => setPlatforms(platforms.filter((item) => item !== platform))}
      />,
    );
  }
  for (const architecture of architectures) {
    chips.push(
      <FilterChip
        key={`arch-${architecture}`}
        label={MATCH_ARCHITECTURE_LABELS[architecture] ?? architecture}
        onClear={() => setArchitectures(architectures.filter((item) => item !== architecture))}
      />,
    );
  }
  for (const nameSource of nameSources) {
    chips.push(
      <FilterChip
        key={`name-source-${nameSource}`}
        label={nameSource}
        onClear={() => setNameSources(nameSources.filter((item) => item !== nameSource))}
      />,
    );
  }
  for (const scopeBinary of scopeBinaries) {
    chips.push(
      <FilterChip
        key={`binary-${scopeBinary}`}
        label={`binary ${scopeBinary}`}
        onClear={() => setScopeBinaries(scopeBinaries.filter((item) => item !== scopeBinary))}
      />,
    );
  }
  for (const scopeCollection of scopeCollections) {
    chips.push(
      <FilterChip
        key={`collection-${scopeCollection}`}
        label={`collection ${scopeCollection}`}
        onClear={() =>
          setScopeCollections(scopeCollections.filter((item) => item !== scopeCollection))
        }
      />,
    );
  }

  return (
    <Panel
      title="Match / Diff"
      subtitle="Cross-function candidates recorded for one binary's functions."
      actions={
        <Toolbar>
          <Field label="Function" hint="Name or id, Enter to load">
            <input
              type="text"
              list="function-suggestions"
              placeholder="name or function id"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") onSelectFunction(draftFunctionId());
              }}
            />
            <datalist id="function-suggestions">
              {suggestions.map((item) => (
                <option key={item.id} value={item.label} />
              ))}
            </datalist>
          </Field>
          {functionId === null ? (
            <Field label="Binary" hint="Whose rows to show">
              <select
                aria-label="Binary whose matches to show"
                value={binaryChoice === null ? "" : String(binaryChoice)}
                onChange={(event) => chooseBinary(Number(event.target.value) || null)}
              >
                <option value="">Pick a binary</option>
                {(binariesResult.data?.binaries ?? []).map((binary) => (
                  <option key={binary.id} value={binary.id}>
                    {`#${binary.id} ${binary.name}`}
                  </option>
                ))}
              </select>
            </Field>
          ) : null}
          <div className="toolbar" role="group" aria-label="Match scope">
            <Button
              tone={functionId === null ? "primary" : "ghost"}
              aria-pressed={functionId === null}
              onClick={() => {
                onSelectFunction(null);
                setDraft("");
                navigate("/matches");
              }}
            >
              All functions
            </Button>
            <Button
              tone={functionId === null ? "ghost" : "primary"}
              aria-pressed={functionId !== null}
              onClick={() => onSelectFunction(draftFunctionId())}
            >
              Selected function
            </Button>
          </div>
          <Button
            disabled={binaryId === null}
            onClick={() => setSettingsOpen((open) => !open)}
          >
            Settings
          </Button>
          <Button
            disabled={binaryId === null || functionResult.data === undefined}
            pending={running}
            onClick={() => void runMatch()}
          >
            Match
          </Button>
          <Button disabled={binaryId === null || recorded.length === 0} onClick={openBulk}>
            Bulk transfer
          </Button>
          {functionId !== null ? (
            <Badge hue="match">
              Found: {foundCount} match{foundCount === 1 ? "" : "es"}
            </Badge>
          ) : null}
          {functionTotal !== null ? (
            <Badge hue="match" title={`${matchedCount} of this binary's ${functionTotal} functions have a recorded candidate`}>
              Matched: {matchedCount} / {functionTotal} ({matchedPercent}%)
            </Badge>
          ) : null}
        </Toolbar>
      }
    >
      {functionResult.error ? (
        <ErrorNote error={functionResult.error} onRetry={functionResult.reload} />
      ) : functionId !== null && functionResult.data === undefined ? (
        <Loading label="Loading function" />
      ) : binaryId === null ? (
        <EmptyState
          action={
            <a className="btn btn-primary" href="#/functions">
              Browse functions
            </a>
          }
        >
          Matches are recorded per binary. Pick a binary above to see every recorded pair, or type a
          function name or id to open one function&apos;s binary with its own candidates first.
        </EmptyState>
      ) : (
        <>
          {runError ? <ErrorNote error={runError} /> : null}
          {runResult ? (
            <Note>
              Match run recorded: {runResult.matched}/{runResult.functions} functions matched,{" "}
              {runResult.pairs} candidate pairs.
              {runResult.notes.map((text) => (
                <span key={text}> {text}.</span>
              ))}
            </Note>
          ) : null}
          {chips.length ? <div className="chips">{chips}</div> : null}
          {settingsOpen ? (
            <Panel
              title="Settings"
              subtitle="The scope the next match run uses. Every setting defaults to the unscoped run."
            >
              <Toolbar>
                <Field label="Min similarity" hint="0-100 percent floor for a candidate">
                  <input
                    type="number"
                    min="0"
                    max="100"
                    step="1"
                    value={minSimilarity}
                    onChange={(event) => setMinSimilarity(Number(event.target.value))}
                  />
                </Field>
                <Field label="Min confidence" hint="0-1 softmax floor for a candidate">
                  <input
                    type="number"
                    min="0"
                    max="1"
                    step="0.05"
                    value={minConfidence}
                    onChange={(event) => setMinConfidence(Number(event.target.value))}
                  />
                </Field>
                <Field label="Top candidates" hint="Most candidates kept per function">
                  <input
                    type="number"
                    min="1"
                    step="1"
                    value={top}
                    onChange={(event) => setTop(Number(event.target.value))}
                  />
                </Field>
                <CheckboxField
                  label="Allow this binary's own functions as candidates"
                  checked={includeSelf}
                  onChange={setIncludeSelf}
                />
              </Toolbar>
              <div className="settings-grid">
                <fieldset className="settings-group">
                  <legend>Platform</legend>
                  {MATCH_PLATFORMS.map((value) => (
                    <CheckboxField
                      key={value}
                      label={MATCH_PLATFORM_LABELS[value] ?? value}
                      checked={platforms.includes(value)}
                      onChange={(on) => toggleValue(platforms, value, setPlatforms, on)}
                    />
                  ))}
                </fieldset>
                <fieldset className="settings-group">
                  <legend>Architecture</legend>
                  {MATCH_ARCHITECTURES.map((value) => (
                    <CheckboxField
                      key={value}
                      label={MATCH_ARCHITECTURE_LABELS[value] ?? value}
                      checked={architectures.includes(value)}
                      onChange={(on) => toggleValue(architectures, value, setArchitectures, on)}
                    />
                  ))}
                </fieldset>
                <fieldset className="settings-group">
                  <legend>Debug Data</legend>
                  {FUNCTION_NAME_SOURCES.map((value) => (
                    <CheckboxField
                      key={value}
                      label={value}
                      checked={nameSources.includes(value)}
                      onChange={(on) => toggleValue(nameSources, value, setNameSources, on)}
                    />
                  ))}
                </fieldset>
                <fieldset className="settings-group settings-scroll">
                  <legend>Binaries</legend>
                  {(binariesResult.data?.binaries ?? []).map((binary) => (
                    <CheckboxField
                      key={binary.id}
                      label={`#${binary.id} ${binary.name}`}
                      checked={scopeBinaries.includes(binary.id)}
                      onChange={(on) => toggleId(scopeBinaries, binary.id, setScopeBinaries, on)}
                    />
                  ))}
                </fieldset>
                <fieldset className="settings-group settings-scroll">
                  <legend>Collections</legend>
                  {(collectionsResult.data?.collections ?? []).map((collection) => (
                    <CheckboxField
                      key={collection.id}
                      label={`#${collection.id} ${collection.name}`}
                      checked={scopeCollections.includes(collection.id)}
                      onChange={(on) =>
                        toggleId(scopeCollections, collection.id, setScopeCollections, on)
                      }
                    />
                  ))}
                </fieldset>
              </div>
              <Note tone="info">
                The platform and architecture scope is best-effort: it compares a binary&apos;s
                stored fingerprint when it has one, else its suffix-derived format/arch columns, so
                it is a coarse filter and not a guarantee.
              </Note>
              <div className="actions-cell">
                <Button tone="primary" pending={running} onClick={() => void runMatch()}>
                  Match
                </Button>
                <Button onClick={clearSettings}>Clear settings</Button>
              </div>
            </Panel>
          ) : null}
          {matchesResult.error ? (
            <ErrorNote error={matchesResult.error} onRetry={matchesResult.reload} />
          ) : matchesResult.data === undefined ? (
            <Loading label="Loading matches" />
          ) : (
            <>
              <Toolbar>
                {MATCH_METRICS.map((value) => (
                  <Button
                    key={value}
                    tone={metric === value ? "primary" : "default"}
                    size="sm"
                    onClick={() => setMetric(value)}
                  >
                    {value === "difference"
                      ? "Show Difference"
                      : `Show ${MATCH_METRIC_LABELS[value]}`}
                  </Button>
                ))}
                <span className="muted">
                  {recorded.length} candidate{recorded.length === 1 ? "" : "s"} recorded
                </span>
              </Toolbar>
              {recorded.length > 0 ? (
                <>
                  <Toolbar>
                    <Muted>
                      {ranked.length} / {rows.length} rows match the filters
                    </Muted>
                    {unnamedCount > 0 ? (
                      <CheckboxField
                        label={`Show ${unnamedCount} unnamed candidate${unnamedCount === 1 ? "" : "s"}`}
                        checked={showUnnamed}
                        onChange={setShowUnnamed}
                      />
                    ) : null}
                    {bandFilter !== "" || sourceFilter !== "" ? (
                      <Button
                        tone="ghost"
                        size="sm"
                        onClick={() => {
                          setBandFilter("");
                          setSourceFilter("");
                        }}
                      >
                        Clear all
                      </Button>
                    ) : null}
                  </Toolbar>
                  <SourceBar
                    counts={sourceCounts}
                    selected={sourceFilter}
                    onSelect={setSourceFilter}
                  />
                  <QualityBar
                    counts={bandCounts}
                    total={rows.length}
                    selected={bandFilter}
                    onSelect={setBandFilter}
                  />
                </>
              ) : null}
              {bulkOpen ? (
                <Panel
                  title="Bulk transfer"
                  subtitle="Copy names and signatures from the chosen candidates in one journaled action."
                >
                  {bulkError ? <ErrorNote error={bulkError} /> : null}
                  <Toolbar>
                    <CheckboxField
                      label="All names"
                      checked={rows.length > 0 && rows.every((row) => bulkNames[rowKey(row)])}
                      onChange={(on) =>
                        setBulkNames(
                          Object.fromEntries(rows.map((row) => [rowKey(row), on])),
                        )
                      }
                    />
                    <CheckboxField
                      label="All signatures"
                      checked={rows.length > 0 && rows.every((row) => bulkSignatures[rowKey(row)])}
                      onChange={(on) =>
                        setBulkSignatures(
                          Object.fromEntries(rows.map((row) => [rowKey(row), on])),
                        )
                      }
                    />
                    <Button pending={bulkPending} onClick={() => void transferBulk(true)}>
                      Preview
                    </Button>
                    <Button
                      tone="primary"
                      pending={bulkPending}
                      disabled={activeCount === 0}
                      onClick={() => void transferBulk(false)}
                    >
                      Transfer ({activeNames} name{activeNames === 1 ? "" : "s"},{" "}
                      {activeSignatures} signature{activeSignatures === 1 ? "" : "s"})
                    </Button>
                    <span className="muted">
                      {activeCount} row{activeCount === 1 ? "" : "s"} selected
                    </span>
                    <Button tone="ghost" onClick={() => setBulkOpen(false)}>
                      Close
                    </Button>
                  </Toolbar>
                  <DataTable
                    columns={[
                      {
                        label: "Names",
                        render: (row) => {
                          const key = rowKey(row);
                          return (
                            <CheckboxField
                              label="Names"
                              checked={bulkNames[key] ?? false}
                              onChange={(on) =>
                                setBulkNames((current) => ({ ...current, [key]: on }))
                              }
                            />
                          );
                        },
                      },
                      {
                        label: "Signature",
                        render: (row) => {
                          const key = rowKey(row);
                          return (
                            <CheckboxField
                              label="Signature"
                              checked={bulkSignatures[key] ?? false}
                              onChange={(on) =>
                                setBulkSignatures((current) => ({ ...current, [key]: on }))
                              }
                            />
                          );
                        },
                      },
                      {
                        label: "Change",
                        render: (row) => (
                          <span className="mono">
                            {row.source_name} &lt;- {row.candidate_name}
                          </span>
                        ),
                      },
                      {
                        label: "Similarity",
                        numeric: true,
                        render: (row) => `${row.similarity.toFixed(1)}%`,
                      },
                      {
                        label: "Source binary",
                        render: (row) => (
                          <a href={`#/binaries/${row.candidate_binary_id}`}>
                            {row.candidate_binary_name}
                          </a>
                        ),
                      },
                    ]}
                    rows={rows}
                    rowKey={(row) => rowKey(row)}
                    empty={<EmptyState>No candidates to transfer.</EmptyState>}
                  />
                  {Object.values(bulkSignatures).some(Boolean) ? (
                    <Note tone="warn">
                      Copied signatures replace same-named types in place.
                    </Note>
                  ) : null}
                  {bulkReport ? (
                    <Note tone={bulkReport.failed ? "warn" : "info"}>
                      {bulkReport.dry_run ? "Preview: " : ""}
                      {bulkReport.applied} applied, {bulkReport.skipped} skipped,{" "}
                      {bulkReport.failed} failed of {bulkReport.requested}.
                      {bulkReport.transfers
                        .filter((row) => row.status !== "applied")
                        .map((row) => (
                          <span key={`${row.function_id}:${row.candidate_function_id}`}>
                            {" "}
                            #{row.function_id} {row.status}: {row.detail || row.reason}
                          </span>
                        ))}
                    </Note>
                  ) : null}
                </Panel>
              ) : null}
              {rowError ? <ErrorNote error={rowError} /> : null}
              <DataTable
                columns={[
                  {
                    label: "Function",
                    render: (row) => (
                      <a href={`#/functions/${row.source_function_id}`}>
                        {row.source_name} @ {hex(row.source_va)}
                      </a>
                    ),
                  },
                  {
                    label: "Candidate",
                    render: (row) =>
                      hasCandidate(row) ? (
                        <a href={`#/functions/${row.candidate_function_id}`}>
                          {row.candidate_name} @ {hex(row.candidate_va)}
                        </a>
                      ) : (
                        <Badge>No match</Badge>
                      ),
                  },
                  {
                    label: "Binary",
                    render: (row) =>
                      hasCandidate(row) ? (
                        <a href={`#/binaries/${row.candidate_binary_id}`}>
                          {row.candidate_binary_name}
                        </a>
                      ) : (
                        NA
                      ),
                  },
                  {
                    label: MATCH_METRIC_LABELS[metric],
                    numeric: true,
                    render: (row) => (
                      <Badge hue={qualityHue(row.band) ?? undefined}>
                        {metricText(row, metric)}
                      </Badge>
                    ),
                  },
                  { label: "Band", render: (row) => row.band },
                  {
                    label: "Arch",
                    render: (row) =>
                      row.source_arch || row.candidate_arch ? (
                        <Badge hue={row.cross_arch ? "near" : undefined}>
                          {row.source_arch || NA} / {row.candidate_arch || NA}
                        </Badge>
                      ) : (
                        NA
                      ),
                  },
                  {
                    label: "Transfer",
                    render: (row) => {
                      if (!hasCandidate(row)) return NA;
                      const key = rowKey(row);
                      const report = rowReports[key];
                      return (
                        <div className="actions-cell">
                          <select
                            aria-label={`Transfer mode for ${row.candidate_name}`}
                            value={rowModes[key] ?? DEFAULT_TRANSFER_MODE}
                            onChange={(event) =>
                              setRowModes((current) => ({
                                ...current,
                                [key]: event.target.value as TransferMode,
                              }))
                            }
                          >
                            {TRANSFER_MODES.map((mode) => (
                              <option key={mode} value={mode}>
                                {TRANSFER_MODE_LABELS[mode]}
                              </option>
                            ))}
                          </select>
                          <Button
                            size="sm"
                            pending={rowBusy === key}
                            onClick={() => void applyRow(row)}
                          >
                            Apply
                          </Button>
                          <a
                            className="btn btn-sm btn-ghost"
                            href={`#/diff/${row.source_function_id}/${row.candidate_function_id}`}
                          >
                            Compare
                          </a>
                          {report ? (
                            <span className="muted">
                              {report.status}
                              {report.missing_types.length
                                ? ` (missing types: ${report.missing_types.join(", ")})`
                                : ""}
                            </span>
                          ) : null}
                        </div>
                      );
                    },
                  },
                ]}
                rows={ranked}
                windowed
                rowKey={(row) => rowKey(row)}
                onRowClick={(row, event) => {
                  if (!hasCandidate(row)) return;
                  const href = `#/diff/${row.source_function_id}/${row.candidate_function_id}`;
                  if (event?.ctrlKey || event?.metaKey) {
                    window.open(href, "_blank", "noopener");
                    return;
                  }
                  navigate(`/diff/${row.source_function_id}/${row.candidate_function_id}`);
                }}
                empty={
                  <EmptyState>
                    No matches recorded yet. Your binary's functions are already
                    listed below; press Run match to score candidates.
                  </EmptyState>
                }
              />
            </>
          )}
        </>
      )}
    </Panel>
  );
}

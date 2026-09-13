// The Models view: what can produce a stored result, and the analysis upgrade.
//
// A stored result comes from the engine, one decompiler backend, the configured
// bridge model or the optional similarity extra, and this view reads
// `GET /api/models` to name them.  The upgrade form posts to
// `POST /api/analyses/<id>/upgrade`, which re-runs an analysis's stored LLM
// artifacts under a named model; reportal never re-analyses the binary, and the
// view says so rather than implying a re-analysis.

import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import { Badge, Button, DataTable, ErrorNote, Field, Loading, Muted, Note, Panel, Toolbar } from "../components";
import type { ModelEntry, ModelsPayload, UpgradeResult } from "../types";
import { useAsync } from "../useAsync";

function availability(row: ModelEntry): ReactNode {
  if (row.available) return <Badge tone="ok">available</Badge>;
  return <Badge tone="warn" title={row.unavailable_reason}>unavailable</Badge>;
}

function UpgradeForm({ models }: { models: ModelEntry[] }): ReactNode {
  const [analysisId, setAnalysisId] = useState("");
  const [model, setModel] = useState("");
  const [limit, setLimit] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<UpgradeResult | null>(null);

  const candidates = models.filter((entry) => entry.kind === "llm" && entry.available);

  const submit = (): void => {
    const id = Number(analysisId);
    if (!model || !Number.isFinite(id) || id <= 0) return;
    setBusy(true);
    setError(null);
    setResult(null);
    api<UpgradeResult>(`/analyses/${id}/upgrade`, {
      method: "POST",
      json: { model, limit: limit ? Number(limit) : undefined },
    })
      .then(setResult)
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(false));
  };

  return (
    <Panel
      title="Upgrade an analysis"
      subtitle="Re-run one analysis's stored AI artifacts under a different model."
    >
      <Toolbar>
        <Field label="Analysis">
          <input
            placeholder="analysis id"
            value={analysisId}
            onChange={(event) => setAnalysisId(event.target.value)}
          />
        </Field>
        <Field label="Model" hint="Only an llm model can re-run an artifact.">
          <select value={model} onChange={(event) => setModel(event.target.value)}>
            <option value="">choose one</option>
            {candidates.map((entry) => (
              <option key={entry.name} value={entry.name}>
                {entry.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Functions">
          <input
            placeholder="bound"
            value={limit}
            onChange={(event) => setLimit(event.target.value)}
          />
        </Field>
        <Button tone="primary" pending={busy} disabled={!model || !analysisId} onClick={submit}>
          Upgrade
        </Button>
      </Toolbar>
      {error ? <ErrorNote error={error} onRetry={submit} /> : null}
      {result ? (
        <>
          <Note>
            {result.from || "no model recorded"} to {result.to}: {result.upgraded} of{" "}
            {result.candidates} function(s) re-run. {result.note}
          </Note>
          {result.applied.length ? (
            <DataTable
              columns={[
                { label: "Function", numeric: true, render: (row) => String(row.function_id) },
                { label: "Artifacts", render: (row) => row.kinds.join(", ") },
              ]}
              rows={result.applied}
              rowKey={(row) => row.function_id}
            />
          ) : (
            <Muted>No function had a stored artifact to re-run.</Muted>
          )}
          {result.skipped.length ? (
            <DataTable
              columns={[
                { label: "Function", numeric: true, render: (row) => String(row.function_id) },
                { label: "Reason", key: "reason" },
              ]}
              rows={result.skipped}
              rowKey={(row, index) => `${row.function_id}-${index}`}
            />
          ) : null}
        </>
      ) : null}
    </Panel>
  );
}

export function ModelsView(): ReactNode {
  const { data, error, reload } = useAsync(() => api<ModelsPayload>("/models"), []);

  if (error) return <ErrorNote error={error} onRetry={reload} />;
  if (!data) {
    return (
      <Panel title="Models">
        <Loading label="Loading the model registry" rows={3} />
      </Panel>
    );
  }

  return (
    <>
      <Panel
        title="Models"
        subtitle="What can produce a stored result, and whether it is available here."
        actions={
          <Button tone="ghost" onClick={() => reload()}>
            Refresh
          </Button>
        }
      >
        <Muted>{data.note}</Muted>
        <DataTable
          columns={[
            { label: "Name", mono: true, key: "name" },
            { label: "Kind", key: "kind" },
            { label: "Version", mono: true, key: "version" },
            { label: "Availability", render: availability },
            { label: "Description", key: "description" },
          ]}
          rows={data.models}
          rowKey={(row) => row.name}
        />
      </Panel>
      <UpgradeForm models={data.models} />
    </>
  );
}

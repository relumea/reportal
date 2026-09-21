// The External sources view: what a third party says about a stored binary.
//
// The offline `local` source derives its answer from rows reportal already
// holds; the remote `virustotal` one is off until the workspace opts in and a
// key resolves (`GET /api/external/sources` reports both).  Pulling a report is
// `POST /api/analyses/<id>/external/<source>`, reading it back
// `GET .../external/<source>`, and the panel renders whatever the source
// returned rather than a shape it assumes.

import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Muted,
  Note,
  Panel,
  Toolbar,
} from "../components";
import type {
  ExternalReport,
  ExternalSource,
  ExternalSourcesPayload,
  ExternalStatus,
} from "../types";
import { useAsync } from "../useAsync";

function availability(row: ExternalSource): ReactNode {
  if (row.available) return <Badge tone="ok">available</Badge>;
  return (
    <Badge tone="warn" title={row.unavailable_reason}>
      unavailable
    </Badge>
  );
}

export function ExternalView(): ReactNode {
  const registry = useAsync(() => api<ExternalSourcesPayload>("/external/sources"), []);
  const [analysisId, setAnalysisId] = useState("");
  const [source, setSource] = useState("local");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [report, setReport] = useState<ExternalReport | null>(null);

  const sources = registry.data?.sources ?? [];
  const status = useAsync(
    () =>
      api<ExternalStatus>(
        `/analyses/${Number(analysisId)}/external/${encodeURIComponent(source)}/status`,
      ),
    [analysisId, source],
    Number(analysisId) > 0,
  );
  // A remote re-pull inside the hour answers 429, so the Pull control stays
  // disabled while the stored answer is fresh instead of spending the click.
  // An unparseable stamp never blocks: the server is the gate, this is a hint.
  const fetchedAt = status.data?.kind === "remote" ? status.data?.fetched_at : null;
  const fetchedMs = fetchedAt === null || fetchedAt === undefined ? NaN : Date.parse(fetchedAt);
  const cooledDown = Number.isNaN(fetchedMs) || Date.now() - fetchedMs >= 3600_000;

  const pull = (): void => {
    const id = Number(analysisId);
    if (!Number.isFinite(id) || id <= 0) {
      setError(new Error("Enter a positive analysis id."));
      return;
    }
    setBusy(true);
    setError(null);
    setReport(null);
    api<ExternalReport>(`/analyses/${id}/external/${encodeURIComponent(source)}`, {
      method: "POST",
    })
      .then((result) => {
        setReport(result);
        status.reload();
      })
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(false));
  };

  const read = (): void => {
    const id = Number(analysisId);
    if (!Number.isFinite(id) || id <= 0) {
      setError(new Error("Enter a positive analysis id."));
      return;
    }
    setBusy(true);
    setError(null);
    api<ExternalReport>(`/analyses/${id}/external/${encodeURIComponent(source)}`)
      .then(setReport)
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <Panel
        title="External sources"
        subtitle="Third-party answers for a stored binary. The offline source never leaves this machine."
      >
        {registry.error ? <ErrorNote error={registry.error} onRetry={registry.reload} /> : null}
        {registry.data === undefined ? (
          <Loading label="Loading the source registry" />
        ) : (
          <>
            <Muted>
              remote sources {registry.data.remote_enabled ? "enabled" : "disabled"}, a VirusTotal
              key {registry.data.key_configured ? "is configured" : "is not configured"}
            </Muted>
            <DataTable
              columns={[
                { label: "Source", mono: true, key: "name" },
                { label: "Kind", key: "kind" },
                { label: "Availability", render: availability },
                { label: "Description", key: "description" },
              ]}
              rows={sources}
              rowKey={(row) => row.name}
            />
          </>
        )}
      </Panel>
      <Panel
        title="Pull a report"
        subtitle="An answer is stored as the analysis's external scan, so a re-pull replaces it."
      >
        <Toolbar>
          <Field label="Analysis">
            <input
              placeholder="analysis id"
              value={analysisId}
              onChange={(event) => setAnalysisId(event.target.value)}
            />
          </Field>
          <Field label="Source">
            <select value={source} onChange={(event) => setSource(event.target.value)}>
              {sources.map((entry) => (
                <option key={entry.name} value={entry.name}>
                  {entry.name}
                </option>
              ))}
            </select>
          </Field>
          <Button
            tone="primary"
            pending={busy}
            disabled={!analysisId || !cooledDown}
            title={cooledDown ? undefined : "Remote re-pulls are limited to once an hour"}
            onClick={pull}
          >
            Pull
          </Button>
          <Button pending={busy} disabled={!analysisId} onClick={read}>
            Read stored
          </Button>
        </Toolbar>
        {status.error ? (
          <ErrorNote error={status.error} onRetry={status.reload} />
        ) : status.data === undefined ? (
          <Muted>Name an analysis to see whether {source} can run for it.</Muted>
        ) : (
          <Muted>
            analysis #{status.data.analysis_id} (binary #{status.data.binary_id}):{" "}
            {status.data.available ? "available" : `unavailable (${status.data.unavailable_reason})`}
            ,{" "}
            {status.data.stored
              ? `stored, fetched ${status.data.fetched_at}`
              : "nothing stored for this source yet"}
            .
          </Muted>
        )}
        {error ? <ErrorNote error={error} onRetry={pull} /> : null}
        {report ? (
          <>
            <Note>
              {report.source} ({report.kind}) fetched {report.fetched_at}
            </Note>
            <pre>{JSON.stringify(report.payload, null, 2)}</pre>
          </>
        ) : (
          <EmptyState>
            Nothing pulled yet. The offline source answers from the scans this workspace already
            holds; a remote source needs the opt-in and a key.
          </EmptyState>
        )}
      </Panel>
    </>
  );
}

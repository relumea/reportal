import type { ReactNode } from "react";

import { api } from "../api";
import { Badge, EmptyState, NA, Panel, PanelBody, StatusCell } from "../components";
import { panelKey, usePanel } from "../panelCache";
import type { AnalysisScans, BinaryScan, BinaryScans } from "../types";

/** The inputs a scan ran with, as one line; a scan that recorded none says so. */
function scanInputs(params: Record<string, unknown>): string {
  const entries = Object.entries(params).filter(([, value]) => value !== null && value !== "");
  if (entries.length === 0) return "none recorded";
  return entries
    .map(([name, value]) => `${name}=${Array.isArray(value) ? value.join("/") : String(value)}`)
    .join(", ");
}

/** The stored scans of one analysis: what ran, with what, and when. */
function ScansTable({ scans }: { scans: BinaryScan[] }): ReactNode {
  if (scans.length === 0) {
    return <EmptyState>No scan is stored for this analysis yet.</EmptyState>;
  }
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Status</th>
            <th>Inputs</th>
            <th>Ran</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td>
                <Badge mono>{scan.kind}</Badge>
              </td>
              <td>
                <StatusCell status={scan.status} />
              </td>
              <td className="mono">{scanInputs(scan.params)}</td>
              <td className="muted">{scan.created_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Every stored scan of the binary's newest analysis, with the inputs it ran with. */
export function ScansPanel({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId, "scans");
  const entry = usePanel(key, () => api<BinaryScans>(`/binaries/${binaryId}/scans`));
  const count = entry?.state === "ready" ? entry.data.count : undefined;
  return (
    <Panel
      title={
        <>
          Scans <Badge>{count === undefined ? NA : String(count)}</Badge>
        </>
      }
      subtitle="Every stored scan of the newest analysis, with the inputs each ran with; the result itself is read where that scan is shown."
    >
      <PanelBody entry={entry} hint="Loading the stored scans">
        {(data) => <ScansTable scans={data.scans} />}
      </PanelBody>
    </Panel>
  );
}

/**
 * The scans of one named analysis, for the log drawer.
 *
 * The binary detail's panel serves the newest analysis; this serves whichever
 * analysis the drawer is open on, which is what makes an older one inspectable.
 */
export function AnalysisScans({ analysisId }: { analysisId: number }): ReactNode {
  const entry = usePanel(panelKey("analysis", analysisId, "scans"), () =>
    api<AnalysisScans>(`/analyses/${analysisId}/scans`),
  );
  return (
    <>
      <h4>Scans</h4>
      <PanelBody entry={entry} hint="Loading the stored scans">
        {(data) => <ScansTable scans={data.scans} />}
      </PanelBody>
    </>
  );
}

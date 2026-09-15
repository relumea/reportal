import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import { Button, EmptyState, ErrorNote, Loading, Muted, Panel, Toolbar } from "../components";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import type { SymbolFile, SymbolFileList } from "../types";

/** The symbols one ingested file carries, summarised. */
function noteList(notes: string[]): ReactNode {
  if (!notes.length) return null;
  return (
    <ul className="list">
      {notes.map((note) => (
        <li key={note} className="muted">
          {note}
        </li>
      ))}
    </ul>
  );
}

/**
 * Debug symbol ingestion: upload a PDB or an ELF/DWARF file and apply it.
 *
 * The upload is a multipart POST, so the panel sends a `FormData` body rather
 * than JSON.  A function whose VA matches a symbol is renamed with the `symbol`
 * name source and every aggregate type the file declares is added to the
 * editable type model, as one journaled action; `Store only` ingests the parse
 * without touching either.
 */
export function SymbolsPanel({ binaryId }: { binaryId: number }): ReactNode {
  const apiPath = `/binaries/${binaryId}/symbols`;
  const key = panelKey("binary", binaryId, "symbols");
  const load = (): Promise<SymbolFileList> => api<SymbolFileList>(apiPath);
  const entry = usePanel<SymbolFileList>(key, load);
  const [file, setFile] = useState<File | null>(null);
  const [apply, setApply] = useState(true);
  const [actionError, setActionError] = useState<unknown>(null);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState("");

  const refresh = (): void => refreshPanel(key, load);

  const upload = async (): Promise<void> => {
    if (!file) return;
    setBusy("upload");
    setActionError(null);
    setStatus("");
    try {
      const body = new FormData();
      body.append("file", file);
      body.append("apply", apply ? "true" : "false");
      const report = await api<SymbolFile>(apiPath, { method: "POST", body });
      setStatus(
        `Ingested ${report.kind}: ${report.symbols} symbol(s), ${report.types} type(s), ` +
          `${report.applied} name(s) applied.`,
      );
      setFile(null);
      refresh();
    } catch (failure) {
      setActionError(failure);
    } finally {
      setBusy("");
    }
  };

  return (
    <Panel
      title="Debug symbols"
      subtitle="A PDB or an ELF/DWARF file: its names are applied to matching functions and its types are added to the type model."
      actions={
        <Button size="sm" tone="ghost" onClick={refresh}>
          Refresh
        </Button>
      }
    >
      <Toolbar>
        <input
          type="file"
          aria-label="Symbol file"
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
        />
        <label className="checkbox-field">
          <input
            type="checkbox"
            checked={apply}
            onChange={(event) => setApply(event.target.checked)}
          />
          Apply names and types
        </label>
        <Button tone="primary" pending={busy === "upload"} disabled={!file} onClick={() => void upload()}>
          Ingest symbols
        </Button>
        {status ? <span className="muted">{status}</span> : null}
      </Toolbar>
      <Toolbar>
        <span className="muted">Stored renames as a script:</span>
        <a
          className="btn btn-ghost btn-sm"
          href={`/api/binaries/${binaryId}/decompiler-script?format=ghidra`}
        >
          Ghidra
        </a>{" "}
        <a
          className="btn btn-ghost btn-sm"
          href={`/api/binaries/${binaryId}/decompiler-script?format=ida`}
        >
          IDA
        </a>{" "}
        <a
          className="btn btn-ghost btn-sm"
          href={`/api/binaries/${binaryId}/decompiler-script?format=binja`}
        >
          Binja
        </a>
      </Toolbar>
      {actionError ? <ErrorNote error={actionError} /> : null}
      {!entry || entry.state === "loading" ? (
        <Loading label="Loading the symbol files" rows={2} />
      ) : entry.state === "error" ? (
        entry.error === "no-symbols" || String(entry.error).includes("no-symbols") ? (
          <EmptyState>No symbol file ingested for this binary yet.</EmptyState>
        ) : (
          <ErrorNote error={entry.error} onRetry={refresh} />
        )
      ) : (
        <>
          <table className="table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Symbols</th>
                <th>Types</th>
                <th>Applied</th>
                <th>Ingested</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {entry.data.symbol_files.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.kind}</td>
                  <td className="mono">{row.symbols}</td>
                  <td className="mono">{row.types}</td>
                  <td className="mono">{row.applied}</td>
                  <td className="muted">{row.created_at}</td>
                  <td>
                    <a
                      className="btn btn-ghost btn-sm"
                      href={`/api${apiPath}/export?format=c&file_id=${row.id}`}
                    >
                      C header
                    </a>{" "}
                    <a
                      className="btn btn-ghost btn-sm"
                      href={`/api${apiPath}/export?format=json&file_id=${row.id}`}
                    >
                      JSON
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {noteList(entry.data.symbol_files[0]?.parsed?.notes ?? [])}
          <Muted>
            A PDB reader recovers names only; the ELF/DWARF reader recovers names and aggregate
            types. Each note above names what the reader did not do.
          </Muted>
        </>
      )}
    </Panel>
  );
}

import { useRef, useState } from "react";
import type { ReactNode } from "react";

import { api, isApiErrorCode } from "../api";
import {
  Badge,
  CopyValue,
  ErrorNote,
  Loading,
  NameSourceDot,
  Panel,
  StatusCell,
  TypeNameLink,
  hex,
} from "../components";
import { SIGNATURE_NOT_FOUND, nameSourceLabel } from "../constants";
import {
  AiSection,
  CodeSection,
  DecompilationPanel,
  HistoryPanel,
  MatchesPanel,
  ReferencesSection,
} from "../panels/FunctionPanels";
import { CommentsPanel } from "../panels/CommentsPanel";
import { FunctionExtrasPanel } from "../panels/FunctionExtrasPanel";
import { FunctionKnowledgePanel } from "../panels/KnowledgePanel";
import { PipelinePanel } from "../panels/PipelinePanel";
import { SignaturePanel } from "../panels/SignaturePanel";
import { panelKey, usePanel } from "../panelCache";
import type { DataTypeList, FunctionRow, FunctionSignatureDetail } from "../types";
import { useAsync } from "../useAsync";
import { ChatAboutButton } from "./ConversationsView";

function FunctionHeader({ fn, onRenamed }: { fn: FunctionRow; onRenamed: () => void }): ReactNode {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(fn.name);
  const [busy, setBusy] = useState(false);
  const [renameError, setRenameError] = useState<unknown>(null);
  const skipBlur = useRef(false);
  const signatureKey = panelKey("fn", fn.id, "signature");
  const signature = usePanel<FunctionSignatureDetail>(signatureKey, () =>
    api<FunctionSignatureDetail>(`/functions/${fn.id}/signature`),
  );
  const typesKey = panelKey("binary", fn.binary_id, "data-types", "");
  const types = usePanel<DataTypeList>(typesKey, () =>
    api<DataTypeList>(`/binaries/${fn.binary_id}/data-types`),
  );
  const knownTypes = new Set(
    types?.state === "ready" ? types.data.types.map((entry) => entry.name) : [],
  );
  const prototype =
    signature?.state === "ready"
      ? signature.data.prototype
      : signature?.state === "error" && isApiErrorCode(signature.error, SIGNATURE_NOT_FOUND)
        ? "Unknown signature"
        : null;
  const shown = fn.name || `Function #${fn.id}`;
  const save = async (): Promise<void> => {
    const name = draft.trim();
    if (!name || name === fn.name) {
      setEditing(false);
      setDraft(fn.name);
      return;
    }
    setBusy(true);
    setRenameError(null);
    try {
      await api(`/functions/${fn.id}/rename`, { method: "POST", json: { name, actor: "spa" } });
      setEditing(false);
      onRenamed();
    } catch (failure) {
      setRenameError(failure);
    } finally {
      setBusy(false);
    }
  };
  return (
    <header className="detail-head">
      <div className="detail-heading">
        <a className="back-link" href={`#/binaries/${fn.binary_id}/functions`}>
          Back to functions
        </a>
        <h2 className="detail-title">
          <NameSourceDot label={nameSourceLabel(fn.name, fn.name_source)} />
          {editing ? (
            <input
              aria-label="Function name"
              value={draft}
              disabled={busy}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  skipBlur.current = true;
                  void save();
                }
                if (event.key === "Escape") {
                  event.preventDefault();
                  skipBlur.current = true;
                  setEditing(false);
                  setDraft(fn.name);
                }
              }}
              onBlur={() => {
                if (skipBlur.current) {
                  skipBlur.current = false;
                  return;
                }
                void save();
              }}
            />
          ) : (
            <button
              type="button"
              className="detail-title-name"
              title="Rename"
              onClick={() => {
                setDraft(fn.name);
                setEditing(true);
              }}
            >
              {shown}
            </button>
          )}
          {fn.name ? <CopyValue value={fn.name} /> : null}
        </h2>
        {renameError ? <ErrorNote error={renameError} /> : null}
        <p className="detail-subtitle">
          Function #{fn.id} · {hex(fn.va)} · {fn.size} bytes
        </p>
        {prototype ? (
          <p className="detail-subtitle">
            <CopyValue value={prototype} />
            {signature?.state === "ready" ? (
              <span className="sig-hover" title="Signature breakdown">
                {signature.data.parameters.length === 0 ? (
                  "Takes no arguments"
                ) : (
                  signature.data.parameters.map((parameter, index) => (
                    <span key={parameter.index}>
                      {index > 0 ? "; " : null}
                      <TypeNameLink
                        binaryId={fn.binary_id}
                        name={parameter.type}
                        knownTypes={knownTypes}
                      />
                      {parameter.name ? ` ${parameter.name}` : ""}
                      {parameter.at ? ` ${parameter.at}` : ""}
                    </span>
                  ))
                )}
                {signature.data.calling_convention
                  ? ` · ${signature.data.calling_convention}`
                  : ""}
                {signature.data.return_type ? (
                  <>
                    {" · returns "}
                    <TypeNameLink
                      binaryId={fn.binary_id}
                      name={signature.data.return_type}
                      knownTypes={knownTypes}
                    />
                  </>
                ) : null}
              </span>
            ) : null}
          </p>
        ) : null}
        <div className="detail-facts">
          <StatusCell status={fn.status} />
          <Badge mono>{nameSourceLabel(fn.name, fn.name_source)}</Badge>
          <Badge mono>binary #{fn.binary_id}</Badge>
        </div>
        <div className="detail-facts">
          <CopyValue value={hex(fn.va)} />
        </div>
      </div>
      <div className="panel-actions">
        <a className="btn btn-ghost" href={`#/binaries/${fn.binary_id}`}>
          Binary
        </a>
        <a className="btn btn-ghost" href={`#/binaries/${fn.binary_id}/functions`}>
          Function list
        </a>
      </div>
    </header>
  );
}

export function FunctionDetail({ functionId }: { functionId: number }): ReactNode {
  const [nonce, setNonce] = useState(0);
  const result = useAsync(() => api<FunctionRow>(`/functions/${functionId}`), [functionId, nonce]);

  if (result.error) return <ErrorNote error={result.error} onRetry={result.reload} />;
  if (!result.data) {
    return (
      <Panel title="Function">
        <Loading label="Loading the function" rows={3} />
      </Panel>
    );
  }
  const fn = result.data;
  const onMutated = (): void => setNonce((value) => value + 1);

  return (
    <>
      <FunctionHeader fn={fn} onRenamed={onMutated} />
      <SignaturePanel
        functionId={functionId}
        analysisId={fn.analysis_id}
        binaryId={fn.binary_id}
      />
      <CodeSection functionId={functionId} />
      <DecompilationPanel functionId={functionId} />
      <ReferencesSection functionId={functionId} binaryId={fn.binary_id} />
      <FunctionKnowledgePanel functionId={functionId} />
      <FunctionExtrasPanel functionId={functionId} />
      <MatchesPanel functionId={functionId} onMutated={onMutated} />
      <HistoryPanel functionId={functionId} onMutated={onMutated} />
      <CommentsPanel scopeKind="function" scopeId={functionId} />
      <PipelinePanel functionId={functionId} onMutated={onMutated} />
      <AiSection functionId={functionId} onMutated={onMutated} />
      <Panel
        title="Conversations"
        subtitle="Ask the portal about this function, grounded in its stored knowledge."
      >
        <ChatAboutButton scopeKind="function" scopeId={functionId} />
      </Panel>
    </>
  );
}

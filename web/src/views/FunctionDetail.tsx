import { useState } from "react";
import type { ReactNode } from "react";

import { api, isApiErrorCode, isNotFound } from "../api";
import {
  Badge,
  Button,
  CopyButton,
  CopyValue,
  ErrorNote,
  Loading,
  NameSourceDot,
  Panel,
  StatusCell,
  TypeNameLink,
  hex,
  useViewTitle,
} from "../components";
import { sentenceLabel } from "../labels";
import { MissingNote, NameEditor } from "../detailParts";
import { Icon } from "../icons";
import {
  SIGNATURE_NOT_FOUND,
  isPlaceholderName,
  nameSourceLabel,
} from "../constants";
import {
  AiSection,
  CodeSection,
  DecompilationPanel,
  HistoryPanel,
  MatchesPanel,
  ReferencesSection,
  SimilarFunctionsPanel,
  applyMatch,
  historyKey,
  loadHistory,
  loadMatches,
  matchesKey,
} from "../panels/FunctionPanels";
import { CommentsPanel } from "../panels/CommentsPanel";
import { FunctionExtrasPanel } from "../panels/FunctionExtrasPanel";
import { NoModelNote } from "../modelReady";
import { FunctionKnowledgePanel } from "../panels/KnowledgePanel";
import { PipelinePanel } from "../panels/PipelinePanel";
import { SignaturePanel } from "../panels/SignaturePanel";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import { Tabs } from "../tabs";
import type { Binary, DataTypeList, FunctionRow, FunctionSignatureDetail } from "../types";
import { useAsync } from "../useAsync";
import { ChatAboutButton } from "./ConversationsView";

// The band `composition.BAND_STRONG_MATCH` names; its similarity floor lives server-side.
const STRONG_MATCH_BAND = "Strong Match";

/**
 * The best recorded candidate that carries a real name, with Apply: the one
 * answer an analyst opening a stripped function wants first.  Placeholder
 * candidates (`fcn_…`) name nothing, so they are passed over.
 */
function BestMatch({ fn, onApplied }: { fn: FunctionRow; onApplied: () => void }): ReactNode {
  const matches = usePanel(matchesKey(fn.id), () => loadMatches(fn.id));
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  if (matches?.state !== "ready") return null;
  const best = matches.data.matches.find((row) => !isPlaceholderName(row.candidate_name));
  if (!best || best.candidate_name === fn.name) return null;
  const apply = async (): Promise<void> => {
    setBusy(true);
    setFailure(null);
    try {
      await applyMatch(fn.id, best.candidate_function_id, "name");
      refreshPanel(matchesKey(fn.id), () => loadMatches(fn.id));
      refreshPanel(historyKey(fn.id), () => loadHistory(fn.id));
      onApplied();
    } catch (error) {
      setFailure(error);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="best-match">
      <span className="best-match-label">Best match</span>
      <a href={`#/functions/${best.candidate_function_id}`}>{best.candidate_name}</a>
      <Badge mono tone={best.band === STRONG_MATCH_BAND ? "ok" : undefined} title={best.band}>
        {`${best.similarity.toFixed(1)}%`}
      </Badge>
      <Button size="sm" tone="primary" pending={busy} onClick={() => void apply()}>
        Apply name
      </Button>
      <a className="btn btn-ghost btn-sm" href={`#/matches?function=${fn.id}`}>
        All candidates
      </a>
      {failure ? <ErrorNote error={failure} /> : null}
    </div>
  );
}

function FunctionHeader({ fn, onRenamed }: { fn: FunctionRow; onRenamed: () => void }): ReactNode {
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [renameError, setRenameError] = useState<unknown>(null);
  const signatureKey = panelKey("fn", fn.id, "signature");
  const signature = usePanel<FunctionSignatureDetail>(signatureKey, () =>
    api<FunctionSignatureDetail>(`/functions/${fn.id}/signature`),
  );
  const typesKey = panelKey("binary", fn.binary_id, "data-types", "");
  const types = usePanel<DataTypeList>(typesKey, () =>
    api<DataTypeList>(`/binaries/${fn.binary_id}/data-types`),
  );
  const binary = usePanel(panelKey("binary", fn.binary_id), () =>
    api<Binary>(`/binaries/${fn.binary_id}`),
  );
  const knownTypes = new Set(
    types?.state === "ready" ? types.data.types.map((entry) => entry.name) : [],
  );
  const prototype = signature?.state === "ready" ? signature.data.prototype : null;
  const unknownSignature =
    signature?.state === "error" && isApiErrorCode(signature.error, SIGNATURE_NOT_FOUND);
  const shown = fn.name || `Function #${fn.id}`;
  useViewTitle(shown);
  const save = async (draft: string): Promise<void> => {
    const name = draft.trim();
    if (!name || name === fn.name) {
      setEditing(false);
      return;
    }
    setBusy(true);
    setRenameError(null);
    try {
      await api(`/functions/${fn.id}/rename`, { method: "POST", json: { name, actor: "spa" } });
      setEditing(false);
      // Match rows join the live function name elsewhere, but this page's
      // panels read the candidate side and the signature keeps its own stored
      // name, so only the history needs a refresh here.
      refreshPanel(historyKey(fn.id), () => loadHistory(fn.id));
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
            <NameEditor
              label="Function name"
              initial={fn.name}
              busy={busy}
              onSave={(name) => void save(name)}
              onCancel={() => setEditing(false)}
            />
          ) : (
            <button
              type="button"
              className="detail-title-name"
              title="Rename"
              onClick={() => setEditing(true)}
            >
              {shown}
              <Icon name="edit" />
            </button>
          )}
          {fn.name ? <CopyButton text={fn.name} /> : null}
        </h2>
        {renameError ? <ErrorNote error={renameError} /> : null}
        <p className="detail-subtitle">
          Function #{fn.id} · <CopyValue value={hex(fn.va)} /> · {fn.size} bytes
          {unknownSignature ? <span className="detail-prose"> · unknown signature</span> : null}
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
          <Badge mono>{sentenceLabel(nameSourceLabel(fn.name, fn.name_source))}</Badge>
          <a className="badge badge-mono" href={`#/binaries/${fn.binary_id}`}>
            {binary?.state === "ready" ? binary.data.name : `binary #${fn.binary_id}`}
          </a>
        </div>
        <BestMatch fn={fn} onApplied={onRenamed} />
      </div>
    </header>
  );
}

export function FunctionDetail({ functionId }: { functionId: number }): ReactNode {
  const [nonce, setNonce] = useState(0);
  const result = useAsync(() => api<FunctionRow>(`/functions/${functionId}`), [functionId, nonce]);

  if (isNotFound(result.error)) {
    return <MissingNote what="Function" listHref="#/functions" listLabel="functions" />;
  }
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
      <Tabs
        label="Function sections"
        param="tab"
        fallback="code"
        tabs={[
          {
            id: "code",
            label: "Code",
            content: (
              <>
                <div className="code-split">
                  <CodeSection functionId={functionId} binaryId={fn.binary_id} />
                  <DecompilationPanel functionId={functionId} />
                </div>
                <SignaturePanel
                  functionId={functionId}
                  analysisId={fn.analysis_id}
                  binaryId={fn.binary_id}
                />
              </>
            ),
          },
          {
            id: "references",
            label: "References",
            content: (
              <>
                <ReferencesSection functionId={functionId} binaryId={fn.binary_id} />
                <FunctionKnowledgePanel functionId={functionId} />
                <FunctionExtrasPanel functionId={functionId} />
              </>
            ),
          },
          {
            id: "matches",
            label: "Matches and history",
            content: (
              <>
                <MatchesPanel functionId={functionId} onMutated={onMutated} />
                <SimilarFunctionsPanel functionId={functionId} />
                <HistoryPanel functionId={functionId} onMutated={onMutated} />
                <CommentsPanel scopeKind="function" scopeId={functionId} />
              </>
            ),
          },
          {
            id: "ai",
            label: "AI and automation",
            content: (
              <>
                <NoModelNote />
                <PipelinePanel functionId={functionId} onMutated={onMutated} />
                <AiSection functionId={functionId} onMutated={onMutated} />
                <Panel
                  title="Conversations"
                  subtitle="Ask about this function; answers draw on what the workspace stores for it."
                >
                  <ChatAboutButton scopeKind="function" scopeId={functionId} />
                </Panel>
              </>
            ),
          },
        ]}
      />
    </>
  );
}

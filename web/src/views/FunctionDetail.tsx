import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import { Badge, CopyValue, ErrorNote, Loading, Panel, StatusCell, hex } from "../components";
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
import type { FunctionRow } from "../types";
import { useAsync } from "../useAsync";
import { ChatAboutButton } from "./ConversationsView";

function FunctionHeader({ fn }: { fn: FunctionRow }): ReactNode {
  return (
    <header className="detail-head">
      <div className="detail-heading">
        <a className="back-link" href={`#/binaries/${fn.binary_id}/functions`}>
          Back to functions
        </a>
        <h2 className="detail-title">{fn.name || `Function #${fn.id}`}</h2>
        <p className="detail-subtitle">
          Function #{fn.id} · {hex(fn.va)} · {fn.size} bytes
        </p>
        <div className="detail-facts">
          <StatusCell status={fn.status} />
          <Badge mono>{fn.name_source || "n/a"}</Badge>
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
      <FunctionHeader fn={fn} />
      <SignaturePanel functionId={functionId} analysisId={fn.analysis_id} />
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

import type { ReactNode } from "react";

import { api } from "../api";
import { Panel, PanelBody } from "../components";
import {
  BehaviorPanel,
  BinaryHeader,
  CapabilitiesPanel,
  CodeSignaturePanel,
  CompositionPanel,
  CryptoPanel,
  DetailCoveragePanel,
  DetectPanel,
  ExportsPanel,
  FunctionTriagePanel,
  HardeningPanel,
  HashesPanel,
  IdentityPanel,
  ImportsPanel,
  LineagePanel,
  PackerPanel,
  ProtocolsPanel,
  FirmwarePanel,
  SandboxPanel,
  RelatedPanel,
  RemediationPanel,
  ReportPanel,
  SecretsPanel,
  SectionsPanel,
  SecurityMitigationsPanel,
  SecurityPanel,
  StringsPanel,
  TagsPanel,
  ThreatPanel,
  TriagePanel,
  UnpackedFilesPanel,
  UnstripPanel,
} from "../panels/BinaryPanels";
import { DataTypesPanel } from "../panels/DataTypesPanel";
import { CommentsPanel } from "../panels/CommentsPanel";
import { MemoryPanel } from "../panels/MemoryPanel";
import { SymbolsPanel } from "../panels/SymbolsPanel";
import { panelKey, usePanel } from "../panelCache";
import type { Binary } from "../types";
import { ChatAboutButton } from "./ConversationsView";

export function BinaryDetail({ binaryId }: { binaryId: number }): ReactNode {
  const key = panelKey("binary", binaryId);
  const entry = usePanel(key, () => api<Binary>(`/binaries/${binaryId}`));
  return (
    <PanelBody entry={entry} hint="Loading binary…">
      {(binary) => (
        <>
          <BinaryHeader binary={binary} />
          <IdentityPanel binaryId={binary.id} />
          <HashesPanel binaryId={binary.id} />
          <SecurityMitigationsPanel binaryId={binary.id} />
          <ImportsPanel binaryId={binary.id} />
          <ExportsPanel binaryId={binary.id} />
          <SectionsPanel binaryId={binary.id} />
          <MemoryPanel binaryId={binary.id} />
          <CodeSignaturePanel binaryId={binary.id} />
          <DetailCoveragePanel binaryId={binary.id} />
          <PackerPanel binaryId={binary.id} />
          <UnpackedFilesPanel />
          <StringsPanel binaryId={binary.id} />
          <TagsPanel binaryId={binary.id} />
          <CommentsPanel scopeKind="binary" scopeId={binary.id} />
          <LineagePanel binaryId={binary.id} />
          <FirmwarePanel binaryId={binary.id} />
          <SandboxPanel binaryId={binary.id} />
          <RelatedPanel binaryId={binary.id} />
          <CompositionPanel binaryId={binary.id} />
          <TriagePanel binaryId={binary.id} />
          <FunctionTriagePanel binaryId={binary.id} />
          <DetectPanel binaryId={binary.id} />
          <CapabilitiesPanel binaryId={binary.id} />
          <BehaviorPanel binaryId={binary.id} />
          <HardeningPanel binaryId={binary.id} />
          <ReportPanel binaryId={binary.id} />
          <CryptoPanel binaryId={binary.id} />
          <SecurityPanel binaryId={binary.id} />
          <SecretsPanel binaryId={binary.id} />
          <ProtocolsPanel binaryId={binary.id} />
          <ThreatPanel binaryId={binary.id} />
          <RemediationPanel binaryId={binary.id} />
          <DataTypesPanel binaryId={binary.id} />
          <SymbolsPanel binaryId={binary.id} />
          <UnstripPanel binaryId={binary.id} />
          <Panel
            title="Conversations"
            subtitle="Ask the portal about this binary, grounded in its stored knowledge."
          >
            <ChatAboutButton scopeKind="binary" scopeId={binary.id} />
          </Panel>
        </>
      )}
    </PanelBody>
  );
}

import type { ReactNode } from "react";

import { api, isNotFound } from "../api";
import { Panel, PanelBody } from "../components";
import { MissingNote } from "../detailParts";
import {
  AttackSurfacePanel,
  BehaviorPanel,
  BinaryAnalysesPanel,
  BinaryHeader,
  CapabilitiesPanel,
  CodeSignaturePanel,
  CompositionPanel,
  CoverageMapPanel,
  LibraryPanel,
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
  DebugPanel,
  RelatedPanel,
  RelocationsPanel,
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
  BenchmarkPanel,
  UnpackedFilesPanel,
  UnstripPanel,
} from "../panels/BinaryPanels";
import { DataTypesPanel } from "../panels/DataTypesPanel";
import { BinaryCollectionsPanel } from "../panels/CollectionsPanel";
import { CommentsPanel } from "../panels/CommentsPanel";
import { ScansPanel } from "../panels/ScansPanel";
import { MemoryPanel } from "../panels/MemoryPanel";
import { ArtifactRatingsPanel } from "../panels/BinaryPanels";
import { SymbolsPanel } from "../panels/SymbolsPanel";
import { panelKey, usePanel } from "../panelCache";
import { Tabs } from "../tabs";
import type { Binary } from "../types";
import { ChatAboutButton } from "./ConversationsView";

// Route query keys the Memory and Data types panels read: a link carrying one
// (a memory jump, a type filter) opens on their tab.
const MEMORY_TAB_KEYS = ["memory", "memoryKind", "kind", "namespace", "search", "source", "sort"];

function opensMemory(query: Record<string, string>): boolean {
  return MEMORY_TAB_KEYS.some((key) => key in query);
}

export function BinaryDetail({
  binaryId,
  query = {},
}: {
  binaryId: number;
  /** The route hash, which carries the data-type filters and the memory jump. */
  query?: Record<string, string>;
}): ReactNode {
  const key = panelKey("binary", binaryId);
  const entry = usePanel(key, () => api<Binary>(`/binaries/${binaryId}`));
  if (entry?.state === "error" && isNotFound(entry.error)) {
    return <MissingNote what="Binary" listHref="#/binaries" listLabel="binaries" />;
  }
  return (
    <PanelBody entry={entry} hint="Loading binary…">
      {(binary) => (
        <>
          <BinaryHeader binary={binary} />
          <Tabs
            label="Binary sections"
            param="tab"
            fallback={opensMemory(query) ? "memory" : "overview"}
            tabs={[
              {
                id: "overview",
                label: "Overview",
                content: (
                  <>
                    <BinaryAnalysesPanel binaryId={binary.id} />
                    <IdentityPanel binaryId={binary.id} />
                    <HashesPanel binaryId={binary.id} />
                    <SectionsPanel binaryId={binary.id} basePath={`/binaries/${binary.id}`} />
                    <CoverageMapPanel binaryId={binary.id} />
                    <DetailCoveragePanel binaryId={binary.id} />
                    <ScansPanel binaryId={binary.id} />
                  </>
                ),
              },
              {
                id: "format",
                label: "Format",
                content: (
                  <>
                    <ImportsPanel binaryId={binary.id} />
                    <ExportsPanel binaryId={binary.id} />
                    <RelocationsPanel binaryId={binary.id} />
                    <CodeSignaturePanel binaryId={binary.id} />
                    <DebugPanel binaryId={binary.id} />
                    <PackerPanel binaryId={binary.id} />
                    <UnpackedFilesPanel binaryId={binary.id} />
                    <SymbolsPanel binaryId={binary.id} />
                    <StringsPanel binaryId={binary.id} />
                  </>
                ),
              },
              {
                id: "memory",
                label: "Memory and types",
                content: (
                  <>
                    <MemoryPanel binaryId={binary.id} focus={query.memory} focusKind={query.memoryKind} />
                    <DataTypesPanel binaryId={binary.id} query={query} />
                  </>
                ),
              },
              {
                id: "security",
                label: "Security",
                content: (
                  <>
                    <SecurityMitigationsPanel binaryId={binary.id} />
                    <SecurityPanel binaryId={binary.id} />
                    <SecretsPanel binaryId={binary.id} />
                    <CryptoPanel binaryId={binary.id} />
                    <ProtocolsPanel binaryId={binary.id} />
                    <ThreatPanel binaryId={binary.id} />
                    <AttackSurfacePanel binaryId={binary.id} />
                    <BehaviorPanel binaryId={binary.id} />
                    <CapabilitiesPanel binaryId={binary.id} />
                    <HardeningPanel binaryId={binary.id} />
                    <SandboxPanel binaryId={binary.id} />
                    <DetectPanel binaryId={binary.id} />
                    <RemediationPanel binaryId={binary.id} />
                  </>
                ),
              },
              {
                id: "provenance",
                label: "Provenance",
                content: (
                  <>
                    <LineagePanel binaryId={binary.id} />
                    <FirmwarePanel binaryId={binary.id} />
                    <RelatedPanel binaryId={binary.id} />
                    <LibraryPanel binaryId={binary.id} />
                    <CompositionPanel binaryId={binary.id} />
                    <BenchmarkPanel binaryId={binary.id} />
                  </>
                ),
              },
              {
                id: "review",
                label: "Review",
                content: (
                  <>
                    <TagsPanel binaryId={binary.id} />
                    <BinaryCollectionsPanel binaryId={binary.id} />
                    <CommentsPanel scopeKind="binary" scopeId={binary.id} />
                    <TriagePanel binaryId={binary.id} />
                    <FunctionTriagePanel binaryId={binary.id} />
                    <ReportPanel binaryId={binary.id} />
                    <ArtifactRatingsPanel binaryId={binary.id} />
                    <UnstripPanel binaryId={binary.id} />
                    <Panel
                      title="Conversations"
                      subtitle="Ask about this binary; answers draw on what the workspace stores for it."
                    >
                      <ChatAboutButton scopeKind="binary" scopeId={binary.id} />
                    </Panel>
                  </>
                ),
              },
            ]}
          />
        </>
      )}
    </PanelBody>
  );
}

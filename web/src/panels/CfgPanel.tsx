// The function's control-flow graph panel.  The engine segments the function
// into basic blocks and reports the edges between them; this renders that
// graph as an address-ordered block list with each block's outgoing edges.
//
// No graph or charting library: an address-ordered list is the layout the
// engine's own order implies, and an edge is a jump control that scrolls to
// its target block rather than a drawn line.  A block the engine did not
// decode is never invented, and a graph the engine capped or could not resolve
// states that in the panel.

import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import "./cfg.css";
import {
  Badge,
  Button,
  EmptyState,
  ErrorNote,
  Loading,
  Muted,
  Note,
  Panel,
  Toolbar,
  hex,
} from "../components";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import type { CfgBlock, CfgEdge, CfgResult } from "../types";

/** DOM id of one block: the anchor an edge's jump control targets. */
function blockId(va: number): string {
  return `cfg-block-${va.toString(16)}`;
}

/**
 * Scroll to a block and focus it.  A plain `#fragment` link would fight the
 * hash router (every route is a hash), so the jump stays in the panel: the
 * block is focused, which moves the keyboard position with the viewport.
 */
function jumpToBlock(va: number): void {
  const target = document.getElementById(blockId(va));
  if (target === null) return;
  target.scrollIntoView({ block: "center" });
  target.focus({ preventScroll: true });
}

/** One block's outgoing edges, each a navigable jump when the target is a block. */
function EdgeList({
  block,
  edges,
  blockIndex,
}: {
  block: CfgBlock;
  edges: CfgEdge[];
  blockIndex: Map<number, number>;
}): ReactNode {
  if (!edges.length) {
    return (
      <p className="cfg-no-edge muted">
        No outgoing edge: the engine reports no successor for this block (a return, or a jump out
        of the segmented extent).
      </p>
    );
  }
  return (
    <ul className="cfg-edges">
      {edges.map((edge) => {
        const target = blockIndex.get(edge.to);
        return (
          <li
            className="cfg-edge"
            data-back={edge.back_edge ? "true" : undefined}
            key={`${block.va}-${edge.to}`}
          >
            <span className="cfg-edge-arrow" aria-hidden="true">
              &rarr;
            </span>
            {target === undefined ? (
              <span className="mono">{hex(edge.to)}</span>
            ) : (
              <button
                type="button"
                className="cfg-edge-jump mono"
                aria-label={`Go to block B${target} at ${hex(edge.to)}`}
                onClick={() => jumpToBlock(edge.to)}
              >
                {hex(edge.to)}
              </button>
            )}
            <span className="muted">
              {target === undefined ? "no block for this target in the payload" : `B${target}`}
            </span>
            {edge.back_edge ? <Badge tone="warn">back edge</Badge> : null}
          </li>
        );
      })}
    </ul>
  );
}

/** The graph itself: the summary, the cap and note states, then the blocks. */
function CfgBlocks({ data }: { data: CfgResult }): ReactNode {
  const blockIndex = new Map<number, number>();
  data.blocks.forEach((block, index) => blockIndex.set(block.va, index));
  const outgoing = new Map<number, CfgEdge[]>();
  for (const edge of data.edges) {
    const list = outgoing.get(edge.from);
    if (list === undefined) outgoing.set(edge.from, [edge]);
    else list.push(edge);
  }
  const cap = data.block_cap > 0 ? ` (engine cap: ${data.block_cap} blocks per function)` : "";
  const summary = `${data.block_count} basic blocks, ${data.edges.length} ${data.edges.length === 1 ? "edge" : "edges"}${cap}.`;

  if (!data.blocks.length) {
    return (
      <>
        <Muted>{summary}</Muted>
        <EmptyState>
          {data.note ?? "The engine reported no basic blocks for this function."}
        </EmptyState>
      </>
    );
  }
  return (
    <>
      <Muted>{summary}</Muted>
      {data.truncated ? (
        <Note tone="warn">
          The engine capped this function at {data.block_cap} basic blocks. It reports{" "}
          {data.block_total} in total, so this payload carries the first {data.block_count}.
        </Note>
      ) : null}
      {data.note ? <Note tone="warn">{data.note}</Note> : null}
      <ol className="cfg-blocks">
        {data.blocks.map((block, index) => (
          <li
            className="cfg-block"
            id={blockId(block.va)}
            key={block.va}
            tabIndex={-1}
            aria-label={`Basic block B${index} at ${hex(block.va)}`}
          >
            <div className="cfg-block-head">
              <span className="cfg-block-index">B{index}</span>
              <span className="mono">{hex(block.va)}</span>
              <span className="muted">{block.size} bytes</span>
              <span className="muted">
                {block.instruction_count} {block.instruction_count === 1 ? "instruction" : "instructions"}
              </span>
            </div>
            <div className="cfg-instrs">
              <span className="cfg-instr-label muted">first</span>
              <span className="mono cfg-instr">{block.first}</span>
              {block.last !== block.first ? (
                <>
                  <span className="cfg-instr-label muted">last</span>
                  <span className="mono cfg-instr">{block.last}</span>
                </>
              ) : null}
            </div>
            <EdgeList
              block={block}
              edges={outgoing.get(block.va) ?? []}
              blockIndex={blockIndex}
            />
          </li>
        ))}
      </ol>
    </>
  );
}

/** The function's basic-block control-flow graph, derived by the engine. */
export function CfgPanel({
  functionId,
  toggle,
}: {
  functionId: number;
  /** The code-view toggle this panel shares with the disassembly panel. */
  toggle?: ReactNode;
}): ReactNode {
  const key = panelKey("fn", functionId, "cfg");
  const loader = (): Promise<CfgResult> => api<CfgResult>(`/functions/${functionId}/cfg`);
  const entry = usePanel(key, loader);
  const [busy, setBusy] = useState(false);

  let body: ReactNode;
  if (!entry || entry.state === "loading") {
    body = <Loading label="Loading the control-flow graph" />;
  } else if (entry.state === "error") {
    body = <ErrorNote error={entry.error} onRetry={() => refreshPanel(key, loader)} />;
  } else {
    body = <CfgBlocks data={entry.data} />;
  }

  return (
    <Panel
      title="Control flow"
      subtitle="Basic blocks in address order; a back edge closes a loop."
      actions={
        <Toolbar>
          {toggle}
          <Button
            pending={busy}
            onClick={() => {
              setBusy(true);
              refreshPanel(key, () => loader().finally(() => setBusy(false)));
            }}
          >
            Reload
          </Button>
        </Toolbar>
      }
    >
      {body}
    </Panel>
  );
}

import { useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  Card,
  CodeBlock,
  DataTable,
  ErrorNote,
  Loading,
  Muted,
  NA,
  Panel,
  Toolbar,
} from "../components";
import { KeyValue } from "../components";
import type {
  InstanceConfig,
  IntegrationInventory,
  IntegrationPart,
  IntegrationSeam,
} from "../types";
import { useAsync } from "../useAsync";

// The flag columns a part may carry, with the reader-facing label and hue.
const PART_FLAGS: Array<{ key: keyof IntegrationPart; label: string }> = [
  { key: "reloadable", label: "Reloadable" },
  { key: "plans_writes", label: "Plans writes" },
  { key: "queryable", label: "Queryable" },
  { key: "builtin", label: "Built-in" },
  { key: "destructive", label: "Destructive" },
];

/** A boolean part flag: yes/no when the seam declares it, n/a when it does not. */
function flagCell(part: IntegrationPart, key: keyof IntegrationPart): ReactNode {
  const value = part[key];
  if (value === undefined) {
    return <span className="muted">{NA}</span>;
  }
  return value ? "yes" : "no";
}

function SeamCard({ seam }: { seam: IntegrationSeam }): ReactNode {
  return (
    <Card
      title={
        <>
          {seam.name} <Badge mono>{seam.count}</Badge>
        </>
      }
    >
      <Muted>
        {seam.contributes}. Registered through <span className="mono">{seam.group}</span>; the
        built-ins are declared in <span className="mono">{seam.module}</span>.
      </Muted>
      <DataTable
        columns={[
          { label: "Part", mono: true, render: (part) => part.name },
          { label: "Detail", render: (part) => part.detail },
          {
            label: "Origin",
            mono: true,
            render: (part) => part.origin || <span className="muted">{NA}</span>,
          },
          ...PART_FLAGS.map((flag) => ({
            label: flag.label,
            render: (part: IntegrationPart) => flagCell(part, flag.key),
          })),
          {
            label: "Unavailable reason",
            render: (part) =>
              part.available === false && part.unavailable_reason ? (
                part.unavailable_reason
              ) : (
                <span className="muted">{NA}</span>
              ),
          },
        ]}
        rows={seam.parts}
        rowKey={(part) => `${seam.name}:${part.name}`}
        empty={<Muted>No part is registered in this seam.</Muted>}
      />
    </Card>
  );
}

/** What this install can do, read from `GET /api/config`. */
function InstanceCard(): ReactNode {
  const { data, error } = useAsync(() => api<InstanceConfig>("/config"), []);
  if (error) {
    return (
      <Card title="Instance">
        <Muted>{String(error)}</Muted>
      </Card>
    );
  }
  if (data === undefined) {
    return (
      <Card title="Instance">
        <Loading label="Reading the instance config" rows={2} />
      </Card>
    );
  }
  const features = Object.entries(data.features).map(
    ([name, value]): [string, string] => [
      name,
      Array.isArray(value) ? value.join(", ") : String(value),
    ],
  );
  return (
    <Card title="Instance">
      <KeyValue
        rows={[
          ["version", data.version],
          ["engine", data.engine.available ? `available (${data.engine.origin ?? "?"})` : "unavailable"],
          ["decompilers", data.engine.backends.join(", ")],
          ["LLM", data.llm.configured ? `configured (${data.llm.model})` : "not configured"],
          ["database", `${data.database.tables} tables at ${data.database.path}`],
          ["MCP tools", `${data.mcp.total} (${data.mcp.read_only} read-only, ${data.mcp.destructive} destructive)`],
          ...features,
        ]}
      />
      <DataTable
        columns={[
          { label: "Limit", mono: true, render: (row) => row.name },
          { label: "Value", numeric: true, render: (row) => row.value.toLocaleString() },
        ]}
        rows={Object.entries(data.limits).map(([name, value]) => ({ name, value }))}
        rowKey={(row) => row.name}
      />
    </Card>
  );
}

/**
 * How to connect an MCP client to this workspace.
 *
 * The card renders the one-liner and the client JSON an MCP client needs, with
 * the tool counts read from `/api/config` so the card cannot promise a registry
 * the server does not have.  The workspace path is the page's own runtime
 * value rather than a guess: a config file with a wrong path is worse than none.
 */
function McpCard(): ReactNode {
  const { data, error } = useAsync(() => api<InstanceConfig>("/config"), []);
  const [copied, setCopied] = useState("");

  const copy = async (label: string, text: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
    } catch {
      // A browser that refuses the clipboard still shows the text to copy.
      setCopied("");
    }
  };

  if (error) {
    return (
      <Panel title="Connect an MCP client">
        <ErrorNote error={error} />
      </Panel>
    );
  }
  if (!data) {
    return (
      <Panel title="Connect an MCP client">
        <Loading label="Reading the instance config" rows={2} />
      </Panel>
    );
  }
  const workspace = window.location.origin;
  const command = `claude mcp add reportal -- reportal mcp`;
  const config = JSON.stringify(
    { mcpServers: { reportal: { command: "reportal", args: ["mcp"] } } },
    null,
    2,
  );
  return (
    <Panel
      title="Connect an MCP client"
      subtitle={`${data.mcp.total} tools (${data.mcp.read_only} read-only, ${data.mcp.destructive} destructive) over stdio, no auth: the pipe is the trust boundary.`}
    >
      <Muted>
        reportal's MCP server speaks newline-delimited JSON-RPC on stdin/stdout, so any MCP
        client runs it from its own config. The workspace is resolved the way every other command
        resolves it, by walking up to the nearest reportal.toml, so run the client from a workspace
        (or pass a path it can start in).
      </Muted>
      <CodeBlock text={command} title="One-liner" />
      <Toolbar>
        <Button size="sm" onClick={() => void copy("command", command)}>
          Copy the one-liner
        </Button>
        <Button size="sm" tone="ghost" onClick={() => void copy("config", config)}>
          Copy the config
        </Button>
        {copied ? <Muted>Copied the {copied}.</Muted> : null}
      </Toolbar>
      <CodeBlock text={config} title="~/.claude.json" />
      <Muted>This page is served from {workspace}.</Muted>
    </Panel>
  );
}

export function IntegrationsView(): ReactNode {
  const { data, error } = useAsync(() => api<IntegrationInventory>("/integrations"), []);

  return (
    <Panel
      title="Integrations"
      subtitle="Every seam a third party extends reportal through, read from the live registries."
    >
      {error ? (
        <Muted>{String(error)}</Muted>
      ) : data === undefined ? (
        <Loading label="Reading the registries" rows={4} />
      ) : (
        <>
          <Muted>
            {data.count} seams. An empty origin means the registry does not track where that part
            was declared; a part whose seam is not from its group is a plugin.
          </Muted>
          {data.seams.map((seam) => (
            <SeamCard key={seam.name} seam={seam} />
          ))}
          <InstanceCard />
          <McpCard />
        </>
      )}
    </Panel>
  );
}

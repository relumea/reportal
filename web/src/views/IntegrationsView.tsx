import type { ReactNode } from "react";

import { api } from "../api";
import { Badge, Card, DataTable, Loading, Muted, NA, Panel } from "../components";
import type { IntegrationInventory, IntegrationPart, IntegrationSeam } from "../types";
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
        </>
      )}
    </Panel>
  );
}

// The Billing view: the plan an organisation is on, what it has used, and the
// way to change it.
//
// Three reads back it: `GET /api/plans` is the catalog (code, so it is the same
// for everyone), `GET /api/organisations` names the tenants this install has,
// and `GET /api/organisations/<id>/billing` is the one that varies: the plan,
// the quota state per metered dimension, the mirrored subscription and whether
// billing is configured at all.  Upgrading posts to `.../billing/checkout` and
// follows the URL the provider returns; managing an existing subscription posts
// to `.../billing/portal`.
//
// The view is honest about an install that has no billing configured, which is
// the default: it says so and still shows the usage, because a self-hosted
// operator wants the meter even when nobody is charging for it.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import {
  Badge,
  Button,
  DataTable,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Muted,
  NA,
  Note,
  Panel,
  Readout,
  SegmentMeter,
  Toolbar,
} from "../components";
import "./billing.css";
import type { BadgeTone } from "../components";
import type {
  BillingPayload,
  CheckoutSession,
  OrganisationRow,
  OrganisationsPayload,
  Plan,
  PlansPayload,
  QuotaState,
  TaskPrice,
} from "../types";
import { useAsync } from "../useAsync";

/** A limit the plan does not apply. */
const UNLIMITED = -1;

/** Billable dimensions, in the order the quota panel shows them. */
const DIMENSIONS: ReadonlyArray<readonly [string, string]> = [
  ["credits", "Credits"],
  ["auto_run", "Auto runs"],
];

function compact(value: number): string {
  if (value === UNLIMITED) return "Unlimited";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(value % 1_000_000 === 0 ? 0 : 1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(value % 1_000 === 0 ? 0 : 1)}K`;
  return String(value);
}

function money(usd: number): string {
  return usd >= 100 || Number.isInteger(usd) ? `$${usd.toFixed(0)}` : `$${usd.toFixed(2)}`;
}

function statusTone(status: string): BadgeTone {
  if (status === "active" || status === "trialing") return "ok";
  if (status === "past_due") return "danger";
  return "warn";
}

/** One metered dimension as a meter, or a plain readout when it is unmetered. */
function QuotaMeter({ label, quota }: { label: string; quota: QuotaState }): ReactNode {
  if (!quota.metered || quota.limit === UNLIMITED) {
    return <Readout label={label} value="Unlimited" />;
  }
  const fraction = quota.limit > 0 ? quota.used / quota.limit : 0;
  const over = quota.used > quota.limit;
  return (
    <SegmentMeter
      label={label}
      value={Math.min(1, fraction)}
      readout={`${compact(quota.used)} / ${compact(quota.limit)}`}
      level={over ? "high" : fraction > 0.8 ? "medium" : undefined}
      title={
        over
          ? `${compact(quota.overage_units)} over the allowance (${money(quota.overage_usd)})`
          : `${compact(quota.remaining)} remaining this period`
      }
    />
  );
}

/** The catalog, with the tier the organisation is on marked. */
function PlanCards({
  plans,
  currentPlanId,
  purchasable,
  onChoose,
  busy,
}: {
  plans: Plan[];
  currentPlanId: string;
  purchasable: string[];
  onChoose: (planId: string) => void;
  busy: string;
}): ReactNode {
  return (
    <div className="plan-grid">
      {plans.map((plan) => {
        const current = plan.id === currentPlanId;
        const canBuy = purchasable.includes(plan.id) && !current;
        return (
          <article key={plan.id} className="plan-card" data-current={current ? "true" : undefined}>
            <div className="plan-card-head">
              <h3>{plan.name}</h3>
              {current ? <Badge tone="ok">current</Badge> : null}
            </div>
            <div className="plan-card-price">
              {plan.price_cents === 0 ? "Free" : money(plan.price_usd)}
              {plan.price_cents === 0 ? null : <small>/{plan.interval}</small>}
            </div>
            <Muted>{plan.tagline}</Muted>
            <ul className="plan-card-features">
              {plan.features.map((feature) => (
                <li key={feature}>{feature}</li>
              ))}
            </ul>
            {canBuy ? (
              <Button onClick={() => onChoose(plan.id)} disabled={busy !== ""}>
                {busy === plan.id ? "Starting..." : plan.trial_days > 0 ? "Start trial" : "Choose plan"}
              </Button>
            ) : null}
          </article>
        );
      })}
    </div>
  );
}

/** What each AI task costs, so a user can budget before running one. */
function TaskPrices({ tasks }: { tasks: TaskPrice[] }): ReactNode {
  return (
    <DataTable<TaskPrice>
      rows={tasks}
      rowKey={(row) => row.task}
      columns={[
        { key: "label", label: "Task" },
        { key: "describe", label: "What you get" },
        {
          label: "Credits",
          numeric: true,
          render: (row) => (row.per_function ? `${row.credits} / function` : row.credits),
        },
        {
          label: "Large input",
          numeric: true,
          render: (row) => {
            const large = row.bands[1];
            if (!large) return NA;
            const ceiling = large.max_input_tokens;
            if (ceiling == null) return `${large.credits}`;
            return `${large.credits} over ${ceiling.toLocaleString()} tok`;
          },
        },
      ]}
    />
  );
}

export function BillingView(): ReactNode {
  const [organisationId, setOrganisationId] = useState<number | null>(null);
  const [busy, setBusy] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);

  const organisations = useAsync<OrganisationsPayload>(
    () => api<OrganisationsPayload>("/organisations"),
    [],
  );
  const catalog = useAsync<PlansPayload>(() => api<PlansPayload>("/plans"), []);

  const rows: OrganisationRow[] = organisations.data?.organisations ?? [];
  // Default to the first tenant rather than making the operator pick one to see
  // anything; an install with none shows the empty state below.
  useEffect(() => {
    if (organisationId === null && rows.length > 0) setOrganisationId(Number(rows[0].id));
  }, [organisationId, rows]);

  const billing = useAsync<BillingPayload>(
    () => api<BillingPayload>(`/organisations/${organisationId}/billing`),
    [organisationId],
    organisationId !== null,
  );

  const startCheckout = (planId: string): void => {
    if (organisationId === null) return;
    setBusy(planId);
    setActionError(null);
    api<CheckoutSession>(`/organisations/${organisationId}/billing/checkout`, {
      method: "POST",
      json: { plan_id: planId },
    })
      .then((session) => {
        // Manual mode returns an in-app URL and Stripe an external one; both are
        // just followed, so the view needs no per-provider branch.
        window.location.assign(session.url);
      })
      .catch((failure: unknown) => setActionError(failure))
      .finally(() => setBusy(""));
  };

  const openPortal = (): void => {
    if (organisationId === null) return;
    setBusy("portal");
    setActionError(null);
    api<{ url: string }>(`/organisations/${organisationId}/billing/portal`, { method: "POST" })
      .then((session) => window.location.assign(session.url))
      .catch((failure: unknown) => setActionError(failure))
      .finally(() => setBusy(""));
  };

  if (organisations.error) return <ErrorNote error={organisations.error} />;
  if (!organisations.data || !catalog.data) return <Loading label="Loading billing" />;

  if (rows.length === 0) {
    return (
      <EmptyState
        action={
          <a className="back-link" href="#/users">
            Open Users
          </a>
        }
      >
        Billing is scoped to an organisation, and this install has none. Create one in Users,
        then come back.
      </EmptyState>
    );
  }

  const config = catalog.data.billing;
  const payload = billing.data;

  return (
    <>
      <Toolbar>
        <Field label="Organisation">
          <select
            value={organisationId ?? ""}
            onChange={(event) => setOrganisationId(Number(event.target.value))}
          >
            {rows.map((row) => (
              <option key={row.id} value={row.id}>
                {row.name}
              </option>
            ))}
          </select>
        </Field>
        {payload?.subscription && config.enabled ? (
          <Button onClick={openPortal} disabled={busy !== ""}>
            {busy === "portal" ? "Opening..." : "Manage subscription"}
          </Button>
        ) : null}
      </Toolbar>

      {config.enabled ? null : (
        <Note tone="info">
          Billing is not configured on this install, so no plan can be purchased here. Usage is
          still metered and shown below. Set REPORTAL_STRIPE_SECRET_KEY to enable checkout.
        </Note>
      )}
      {actionError ? <ErrorNote error={actionError} /> : null}
      {billing.error ? <ErrorNote error={billing.error} /> : null}

      {payload ? (
        <>
          <Panel
            title="This period"
            subtitle={
              payload.period_started_at
                ? `Since ${payload.period_started_at}`
                : "Since this workspace began"
            }
          >
            <div className="cockpit-strip">
              <Readout label="Plan" value={payload.plan.name} />
              <Readout
                label="Price"
                value={payload.plan.price_cents === 0 ? "Free" : money(payload.plan.price_usd)}
              />
              <Readout label="Credits used" value={payload.usage.credits?.used ?? 0} />
              {payload.subscription ? (
                <Readout
                  label="Subscription"
                  value={
                    <Badge tone={statusTone(payload.subscription.status)}>
                      {payload.subscription.status}
                    </Badge>
                  }
                />
              ) : null}
            </div>
            <div className="cockpit-strip">
              {DIMENSIONS.map(([kind, label]) => {
                const quota = payload.usage[kind];
                return quota ? <QuotaMeter key={kind} label={label} quota={quota} /> : null;
              })}
            </div>
            {Object.values(payload.usage).some((quota) => !quota.allowed) ? (
              <Note tone="warn">
                {Object.values(payload.usage).find((quota) => !quota.allowed)?.reason ??
                  "A quota is exhausted."}{" "}
                {config.enabled ? (
                  <a className="back-link" href="#billing-plans">
                    See plans below to upgrade.
                  </a>
                ) : (
                  "Billing is not configured on this install, so no plan can be purchased here."
                )}
              </Note>
            ) : null}
          </Panel>

          {payload.subscription?.cancel_at_period_end ? (
            <Note tone="warn">
              This subscription is set to cancel at the end of the period
              {payload.subscription.current_period_end
                ? ` (${payload.subscription.current_period_end})`
                : ""}
              . It will fall back to the free plan.
            </Note>
          ) : null}

          <Panel
            title="What a task costs"
            subtitle={
              catalog.data.tasks[0]
                ? `One credit is one ${catalog.data.tasks[0].label.toLowerCase()}, measured` +
                  "; a larger function costs more."
                : "Measured per task; a larger function costs more."
            }
          >
            <TaskPrices tasks={catalog.data.tasks} />
          </Panel>

          <Panel
            title="Plans"
            subtitle={`Extra credits are billed at $${catalog.data.overage_usd_per_credit.toFixed(2)} each.`}
          >
            <span id="billing-plans" />
            <PlanCards
              plans={catalog.data.plans}
              currentPlanId={payload.plan.id}
              purchasable={config.enabled ? catalog.data.checkout_plans : []}
              onChoose={startCheckout}
              busy={busy}
            />
          </Panel>
        </>
      ) : (
        <Loading label="Loading usage" />
      )}
    </>
  );
}

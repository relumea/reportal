"""Tenant metering: the usage ledger and the quota checks.

Every metered event lands one append-only row in ``usage_events`` keyed by
organisation: LLM tokens a run spent, auto runs a tenant started.  Quotas sum
the open period and compare against the organisation's plan, which is what
gates metered work.  The ledger is append-only on purpose: a bill a customer
disputes has to be reconstructable from rows nothing rewrites, so
:func:`record_usage` inserts and there is no update or delete path.

An organisation without a row (a pre-billing database, or id 0 for a
single-tenant install) reads as the ``internal`` plan: unmetered, so upgrading
an existing install never locks out the operator who was already using it.
This is the property that keeps the self-hosted case working unchanged, and
``tests/test_metering.py`` pins it.

Cost attribution
----------------

A token row carries the model that spent it, so the ledger can be summed two
ways: units, which is what the quota compares, and dollars, which is what
:func:`period_cost_usd` reports for the margin read.  The two differ because a
tenant on Haiku costs a third of one on Opus for the same token count, and a
plan's allowance is priced against the middle model (:data:`reportal.plans.COST_MODEL`).
"""

from __future__ import annotations

import sqlite3
from types import ModuleType
from typing import Any

from reportal import auth, plans

# The metered dimensions.  Credits are what a tenant spends and what a plan
# grants; auto runs gate the batch worker; everything static (disassembly,
# xrefs, struct recovery, the scans) is unmetered because it costs CPU rather
# than inference.
#
# Tokens are recorded but are not a customer-facing dimension: the row is the
# internal cost-of-goods read (`period_cost_usd`), so an operator can prove the
# credit price still covers what the inference cost, and a customer never sees
# a number that moves because a model got chattier.  `CUSTOMER_KINDS` is what a
# quota and the usage panel show; `KINDS` is everything the ledger holds.
KIND_TOKENS = "llm_tokens"
KIND_AUTO_RUN = "auto_run"
KIND_CREDITS = "credits"
CUSTOMER_KINDS: tuple[str, ...] = (KIND_CREDITS, KIND_AUTO_RUN)
KINDS: tuple[str, ...] = (KIND_CREDITS, KIND_AUTO_RUN, KIND_TOKENS)

# The organisation id meaning "no tenant": a single-install or self-hosted
# workspace that is not billed.
NO_ORG = 0

# The ledger and the per-organisation billing state.
USAGE_TABLE = "usage_events"
SUBSCRIPTION_TABLE = "subscriptions"
EVENT_TABLE = "billing_events"

# Subscription status vocabulary, mirrored from the provider rather than
# invented: a status reportal does not know reads as `past_due`, because an
# unrecognized state must fail closed.
STATUS_ACTIVE = "active"
STATUS_TRIALING = "trialing"
STATUS_PAST_DUE = "past_due"
STATUS_CANCELED = "canceled"
# The statuses that entitle a tenant to its plan.  Anything else drops it to
# the fallback tier at the period boundary.
ENTITLING_STATUSES: frozenset[str] = frozenset({STATUS_ACTIVE, STATUS_TRIALING})

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {USAGE_TABLE} (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    organisation_id INTEGER NOT NULL,
    kind            TEXT NOT NULL,
    units           INTEGER NOT NULL,
    model           TEXT NOT NULL DEFAULT '',
    cost_micro_usd  INTEGER NOT NULL DEFAULT 0,
    detail          TEXT NOT NULL DEFAULT '',
    occurred_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_usage_org_kind_time
    ON {USAGE_TABLE} (organisation_id, kind, occurred_at);

CREATE TABLE IF NOT EXISTS {SUBSCRIPTION_TABLE} (
    organisation_id      INTEGER PRIMARY KEY,
    provider             TEXT NOT NULL DEFAULT '',
    customer_id          TEXT NOT NULL DEFAULT '',
    subscription_id      TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT '',
    current_period_end   TEXT NOT NULL DEFAULT '',
    cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
    updated_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS {EVENT_TABLE} (
    event_id        TEXT PRIMARY KEY,
    provider        TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL DEFAULT '',
    organisation_id INTEGER,
    applied         INTEGER NOT NULL DEFAULT 0,
    payload         TEXT NOT NULL DEFAULT '',
    received_at     TEXT NOT NULL
);
"""

# Columns added to `organisations` for billing.  The table is auth's, so the
# billing columns are an upgrade rather than part of its CREATE: an existing
# workspace gets them added, and a fresh one gets them the same way.
_ORG_COLUMNS: tuple[tuple[str, str], ...] = (
    ("plan_id", f"TEXT NOT NULL DEFAULT '{plans.DEFAULT_PLAN_ID}'"),
    ("period_started_at", "TEXT NOT NULL DEFAULT ''"),
    ("status", f"TEXT NOT NULL DEFAULT '{STATUS_ACTIVE}'"),
)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the metering tables and add the billing columns to organisations."""
    conn.executescript(_SCHEMA)
    existing = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({auth.ORG_TABLE})")}
    for column, declaration in _ORG_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE {auth.ORG_TABLE} ADD COLUMN {column} {declaration}")
    conn.commit()


def _credits_mod() -> ModuleType:
    """The credit catalog, imported at call time.

    :mod:`reportal.credits` reads :mod:`reportal.plans` for its rates and this
    module reads both, so the import runs here rather than at module scope.
    """
    from reportal import credits as credits_mod

    return credits_mod


def charge_task(
    conn: sqlite3.Connection,
    organisation_id: int,
    task: str,
    *,
    input_tokens: int = 0,
    calls: int = 1,
    detail: str = "",
    commit: bool = True,
) -> int:
    """Charge a tenant for *calls* of *task* and return the credits taken.

    This is the one write a billable operation makes: the credit price comes
    from the task catalog with its size band applied, so a caller names what it
    did rather than computing a price, and a task's price can only be changed
    in one place.  A run with no tenant charges nothing and returns zero.
    """
    if organisation_id == NO_ORG:
        return 0
    amount = int(_credits_mod().cost_of(task, input_tokens)) * max(0, int(calls))
    if amount:
        record_usage(
            conn,
            organisation_id,
            KIND_CREDITS,
            amount,
            detail=detail or task,
            commit=commit,
        )
    return amount


def record_usage(
    conn: sqlite3.Connection,
    organisation_id: int,
    kind: str,
    units: int,
    *,
    model: str = "",
    detail: str = "",
    commit: bool = True,
) -> None:
    """Append one usage row; never updates, never deletes.

    Organisation 0 (no tenant) records nothing: single-install use is unmetered
    by definition, and the ledger holds billable rows only.  A negative unit
    count is clamped to zero rather than refused, because a miscounted usage
    report must not be able to credit a tenant's quota back.
    """
    if organisation_id == NO_ORG:
        return
    units = max(0, int(units))
    cost_micro = 0
    if kind == KIND_TOKENS and units:
        # USD/MTok equals micro-USD per token; round into the ledger unit rather
        # than truncating ``usd_for_tokens * 1e6``, which under-counts (1 token
        # at the Sonnet blend stores 3 instead of 4).
        cost_micro = plans.micro_usd_for_tokens(units, model or plans.COST_MODEL)
    conn.execute(
        f"INSERT INTO {USAGE_TABLE} "
        "(organisation_id, kind, units, model, cost_micro_usd, detail, occurred_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (organisation_id, kind, units, model, cost_micro, detail[:500], auth.now()),
    )
    if commit:
        conn.commit()


def _org_row(conn: sqlite3.Connection, organisation_id: int) -> dict[str, Any] | None:
    """The organisation's billing columns, or None when it has no row."""
    if organisation_id == NO_ORG:
        return None
    try:
        row = conn.execute(
            f"SELECT plan_id, period_started_at, status FROM {auth.ORG_TABLE} WHERE id = ?",
            (organisation_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    return dict(row) if row is not None else None


def organisation_plan(conn: sqlite3.Connection, organisation_id: int) -> plans.Plan:
    """The organisation's plan, ``internal`` when there is no tenant.

    A workspace with no organisation row is a self-hosted or single-operator
    install: unmetered, because nobody is billing it.
    """
    row = _org_row(conn, organisation_id)
    if row is None:
        return plans.get_plan(plans.SELF_HOST_PLAN_ID)
    return plans.get_plan(str(row.get("plan_id") or ""))


def period_started_at(conn: sqlite3.Connection, organisation_id: int) -> str:
    """When the organisation's open billing period began; empty for all time."""
    row = _org_row(conn, organisation_id)
    return str(row.get("period_started_at") or "") if row is not None else ""


def period_usage(conn: sqlite3.Connection, organisation_id: int, kind: str) -> int:
    """Units of *kind* the organisation used since its period started."""
    started = period_started_at(conn, organisation_id)
    row = conn.execute(
        f"SELECT COALESCE(SUM(units), 0) AS total FROM {USAGE_TABLE} "
        "WHERE organisation_id = ? AND kind = ? AND occurred_at >= ?",
        (organisation_id, kind, started),
    ).fetchone()
    return int(row["total"]) if row is not None else 0


def period_cost_usd(conn: sqlite3.Connection, organisation_id: int) -> float:
    """Inference dollars the organisation's open period has actually cost.

    This is the margin read: what reportal paid Anthropic for this tenant, as
    against what the tenant pays for its plan.
    """
    started = period_started_at(conn, organisation_id)
    row = conn.execute(
        f"SELECT COALESCE(SUM(cost_micro_usd), 0) AS total FROM {USAGE_TABLE} "
        "WHERE organisation_id = ? AND occurred_at >= ?",
        (organisation_id, started),
    ).fetchone()
    return (int(row["total"]) if row is not None else 0) / 1_000_000


def start_period(conn: sqlite3.Connection, organisation_id: int, *, commit: bool = True) -> None:
    """Open a fresh billing period; the ledger stays, the window moves.

    Nothing is deleted: the rows before the new start stay in the ledger for the
    invoice that already covered them, and only the quota window moves.
    """
    if organisation_id == NO_ORG:
        return
    conn.execute(
        f"UPDATE {auth.ORG_TABLE} SET period_started_at = ? WHERE id = ?",
        (auth.now(), organisation_id),
    )
    if commit:
        conn.commit()


def _limit_for(plan: plans.Plan, kind: str) -> int:
    """The plan's allowance for one metered dimension.

    Tokens carry no allowance: they are recorded for the internal cost read and
    never gate a request, so they answer UNLIMITED here and the credit
    dimension is what a quota actually stops on.
    """
    return {
        KIND_CREDITS: plan.monthly_credits,
        KIND_AUTO_RUN: plan.monthly_auto_runs,
    }.get(kind, plans.UNLIMITED)


def quota_check(
    conn: sqlite3.Connection, organisation_id: int, kind: str, units: int = 0
) -> dict[str, Any]:
    """Whether *units* of *kind* fit the organisation's remaining allowance.

    Returns the whole quota state rather than a bool, because every caller that
    refuses work also has to say what it refused and what the tenant should do:
    the plan, the limit, what is used, what is left, and whether an overage
    covers the difference.  ``allowed`` is what a caller branches on.

    A past-due organisation is refused whatever its allowance says: an unpaid
    subscription is the one case where remaining quota is not entitlement.
    """
    plan = organisation_plan(conn, organisation_id)
    limit = _limit_for(plan, kind)
    if limit == plans.UNLIMITED:
        return {
            "allowed": True,
            "plan_id": plan.id,
            "kind": kind,
            "limit": plans.UNLIMITED,
            "used": 0,
            "remaining": plans.UNLIMITED,
            "metered": False,
            "overage_units": 0,
            "overage_usd": 0.0,
            "reason": "",
        }
    used = period_usage(conn, organisation_id, kind)
    remaining = max(0, limit - used)
    row = _org_row(conn, organisation_id)
    status = str((row or {}).get("status") or STATUS_ACTIVE)
    if status == STATUS_PAST_DUE:
        return {
            "allowed": False,
            "plan_id": plan.id,
            "kind": kind,
            "limit": limit,
            "used": used,
            "remaining": remaining,
            "metered": True,
            "overage_units": 0,
            "overage_usd": 0.0,
            "reason": "subscription past due",
        }
    over = max(0, units - remaining)
    # An overage is billable capacity, not a refusal: a paid plan keeps working
    # past its allowance and is invoiced for the difference.  The free tier has
    # nothing to invoice against, so it is the one tier that actually stops.
    billable = plan.price_cents > 0
    allowed = over == 0 or billable
    return {
        "allowed": allowed,
        "plan_id": plan.id,
        "kind": kind,
        "limit": limit,
        "used": used,
        "remaining": remaining,
        "metered": True,
        "overage_units": over if billable else 0,
        "overage_usd": (
            (over * _credits_mod().OVERAGE_CENTS_PER_CREDIT) / 100
            if billable and kind == KIND_CREDITS
            else 0.0
        ),
        "reason": "" if allowed else f"{kind} quota exhausted on the {plan.name} plan",
    }


def usage_summary(conn: sqlite3.Connection, organisation_id: int) -> dict[str, Any]:
    """Every customer-facing dimension's state, plus the period and the internals.

    ``usage`` carries only what a tenant is billed on.  ``tokens_used`` and
    ``cost_usd`` are the internal pair: what the period actually spent and what
    it cost, which an operator reads to check the credit price still covers the
    inference, and which the customer-facing panels do not show.
    """
    plan = organisation_plan(conn, organisation_id)
    return {
        "organisation_id": organisation_id,
        "plan": plan.describe(),
        "period_started_at": period_started_at(conn, organisation_id),
        "cost_usd": round(period_cost_usd(conn, organisation_id), 4),
        "tokens_used": period_usage(conn, organisation_id, KIND_TOKENS),
        "usage": {kind: quota_check(conn, organisation_id, kind) for kind in CUSTOMER_KINDS},
    }

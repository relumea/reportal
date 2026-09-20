"""Subscription plan catalog: what each tier may do, and what it costs to serve.

The catalog is code, not operator configuration: quotas are a product decision,
and a typo in a plan definition must not silently hand out unmetered LLM spend.
Prices live here too, while the Stripe *price ids* stay in the environment
(``REPORTAL_STRIPE_PRICE_*``) so test keys and live keys can point at different
catalogs without a code change.

``internal`` is the staff/self-host tier: it removes the metered limits.  Give
it only to organisations that are not billed, never to a self-serve signup.

What a plan grants, and why
---------------------------

A plan grants **credits**, not tokens.  A credit is one reference task (see
:mod:`reportal.credits`), so a tenant reads its allowance as "2,000 triage
calls, or 1,000 summaries, or 125 AI decompilations" rather than as a token
count it cannot predict or compare.  Tokens stay behind the counter: the ledger
still records them, and that record is what proves the credit price covers the
inference it buys.

The allowances are derived rather than chosen, because reportal resells
inference and a credit allowance is a direct cost of goods sold.  The chain is:
:data:`MODEL_RATES` gives the published per-million rates,
:func:`reportal.credits.credit_cogs_usd` prices one credit at those rates, and
a tier may spend at most :data:`MAX_COGS_SHARE` of its price on inference.  So
a ``$39`` tier carries ``39 * 0.20 / credit_cogs_usd()`` credits, rounded to a
friendly 2,000.  ``tests/test_plans.py`` asserts that ceiling rather than the
literal numbers, so raising an allowance is allowed and raising it past what
the price supports fails the gate.

Two pressure valves keep the ceiling from being a wall.  An organisation past
its allowance buys more at :data:`reportal.credits.OVERAGE_USD_PER_CREDIT`
rather than stopping, and an organisation that configures its own model
endpoint spends its own inference budget, so :func:`metered` reports False and
the allowance does not apply at all.  Self-hosted installs are the second case
by construction.

:data:`INPUT_SHARE` and :func:`blended_usd_per_mtok` remain as the internal
margin arithmetic: they are what :mod:`reportal.metering` prices a recorded
token row with, and they are not a customer-facing number.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal

# A limit that does not apply.  Negative rather than None so a comparison
# against a count is always a number-to-number check.
UNLIMITED = -1


# ── The cost model ─────────────────────────────────────────────────

# Anthropic's published list prices, USD per million tokens, as
# (input, output) pairs.  Source: https://platform.claude.com/docs/en/about-claude/pricing
# These are list rates for the models reportal's bridge is pointed at in
# practice; an install that points at something else is priced by whoever runs
# it, which is what `metered()` covers.
MODEL_RATES: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-5": (2.0, 10.0),
    "claude-haiku-4.5": (1.0, 5.0),
}

# The model the cost model prices against.  Sonnet is the default working model
# for reportal's AI extras: Haiku is cheaper but weaker at reading decompiler
# output, and Opus is reserved for the whole-function rewrite.  Pricing against
# the middle model is the conservative choice, because a tenant that leans on
# Haiku costs less than its plan assumes and one that leans on Opus is the case
# the margin has to absorb.
COST_MODEL = "claude-sonnet-5"

# Share of a metered token that is input rather than output.  Reverse
# engineering is input-heavy: a prompt carries a decompiled function plus its
# context and the answer is a summary, a comment block or a rename list.
INPUT_SHARE = 0.8

# The largest share of a tier's price its inference may cost at full quota use.
# The remainder covers hosting, storage, support and margin.  A tenant that
# actually burns its whole allowance every month is the worst case, not the
# median: most run well under it, so realized margin is wider than this bound.
MAX_COGS_SHARE = 0.20

# What the free tier may cost to serve, in USD per organisation per month.  It
# has no price to take a share of, so it is bounded outright: this is customer
# acquisition spend and is capped like it.
MAX_FREE_COGS_USD = 1.00


def blended_usd_per_mtok(model: str = COST_MODEL) -> float:
    """Cost of one million metered tokens, USD, at :data:`INPUT_SHARE`.

    A metered token is a token either way, so one number has to stand for a mix
    of the two rates.  An unknown model prices at the most expensive one in the
    catalog rather than falling back to something cheap, because an unpriced
    model must never read as free.
    """
    return float(_blended_rate(model))


def _blended_rate(model: str) -> Decimal:
    if model in MODEL_RATES:
        input_rate, output_rate = MODEL_RATES[model]
    else:
        input_rate, output_rate = max(MODEL_RATES.values(), key=lambda pair: pair[1])
    share = Decimal(str(INPUT_SHARE))
    return Decimal(str(input_rate)) * share + Decimal(str(output_rate)) * (1 - share)


def tokens_for_budget(usd: float, model: str = COST_MODEL) -> int:
    """How many tokens *usd* buys at the blended rate, rounded down."""
    if not isinstance(usd, (int, float)) or isinstance(usd, bool):
        return 0
    if not math.isfinite(usd) or usd <= 0:
        return 0
    return int(Decimal(str(usd)) * 1_000_000 / _blended_rate(model))


def usd_for_tokens(tokens: int, model: str = COST_MODEL) -> float:
    """What *tokens* cost to serve at the blended rate."""
    if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens <= 0:
        return 0.0
    return float(Decimal(tokens) * _blended_rate(model) / Decimal(1_000_000))


def micro_usd_for_tokens(tokens: int, model: str = COST_MODEL) -> int:
    """What *tokens* cost in micro-USD at the blended rate, rounded half-up.

    The usage ledger stores this integer so a bill reconstructs without binary
    float drift; :func:`usd_for_tokens` is the display form of the same rate.
    """
    if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens <= 0:
        return 0
    return int((Decimal(tokens) * _blended_rate(model)).to_integral_value(rounding=ROUND_HALF_UP))


def _overage_usd_per_credit() -> float:
    """The per-credit overage price, read from the credit module.

    A function rather than a constant for the same reason as
    :meth:`Plan.credit_cogs_usd`: the credit module reads this one's rates, so
    the import runs in the other direction at call time.
    """
    from reportal import credits as credits_mod

    return credits_mod.OVERAGE_USD_PER_CREDIT


@dataclass(frozen=True)
class Plan:
    """One subscription tier."""

    id: str
    name: str
    tagline: str
    price_cents: int
    monthly_credits: int
    monthly_auto_runs: int
    max_binaries: int
    max_api_keys: int
    max_seats: int
    features: tuple[str, ...] = field(default=())
    self_serve: bool = False
    currency: str = "usd"
    interval: str = "month"
    trial_days: int = 0

    @property
    def price_usd(self) -> float:
        """The tier's price in dollars."""
        return self.price_cents / 100

    def credit_cogs_usd(self) -> float:
        """Inference cost, USD, if the tier burned its whole credit allowance.

        Imported here rather than at module scope because :mod:`reportal.credits`
        reads this module's rates: the dependency runs catalog to credits, and a
        module-level import back would close the cycle.
        """
        from reportal import credits as credits_mod

        if self.monthly_credits == UNLIMITED:
            return float("inf")
        return self.monthly_credits * credits_mod.credit_cogs_usd()

    def cogs_share(self) -> float:
        """Inference cost as a share of price; ``inf`` for a tier with no price."""
        if self.price_cents <= 0:
            return float("inf") if self.monthly_credits != 0 else 0.0
        return self.credit_cogs_usd() / self.price_usd

    def metered(self) -> bool:
        """Whether this tier's credit use counts against an allowance."""
        return self.monthly_credits != UNLIMITED

    def describe(self) -> dict[str, object]:
        """The public shape: what a pricing page and the SPA render."""
        return {
            "id": self.id,
            "name": self.name,
            "tagline": self.tagline,
            "price_cents": self.price_cents,
            "price_usd": self.price_usd,
            "currency": self.currency,
            "interval": self.interval,
            "trial_days": self.trial_days,
            "monthly_credits": self.monthly_credits,
            "monthly_auto_runs": self.monthly_auto_runs,
            "max_binaries": self.max_binaries,
            "max_api_keys": self.max_api_keys,
            "max_seats": self.max_seats,
            "features": list(self.features),
            "self_serve": self.self_serve,
            "metered": self.metered(),
            "overage_usd_per_credit": _overage_usd_per_credit(),
        }


# The catalog, cheapest first.  Every credit allowance here is
# `price_usd * MAX_COGS_SHARE / credits.credit_cogs_usd()` rounded down to a
# friendly number, which is what keeps `cogs_share()` under the ceiling.  The
# feature lines say what the credits buy rather than repeating the number,
# because "125 AI decompilations" is the thing a customer is actually deciding
# about.
PLANS: tuple[Plan, ...] = (
    Plan(
        id="free",
        name="Free",
        tagline="Evaluate the workbench on one binary.",
        price_cents=0,
        monthly_credits=260,
        monthly_auto_runs=5,
        max_binaries=3,
        max_api_keys=1,
        max_seats=1,
        features=(
            "260 credits / month",
            "About 260 triage calls or 16 AI decompilations",
            "5 auto runs / month",
            "3 binaries, 1 seat",
            "Full static analysis, unmetered",
        ),
        self_serve=False,
    ),
    Plan(
        id="analyst",
        name="Analyst",
        tagline="For solo reverse engineers and toolchain research.",
        price_cents=3900,
        monthly_credits=2_000,
        monthly_auto_runs=100,
        max_binaries=25,
        max_api_keys=5,
        max_seats=1,
        features=(
            "2,000 credits / month",
            "About 125 AI decompilations or 2,000 triage calls",
            "100 auto runs / month",
            "25 binaries, 1 seat",
            "14-day free trial",
            "Extra credits at $0.04 each",
        ),
        self_serve=True,
        trial_days=14,
    ),
    Plan(
        id="team",
        name="Team",
        tagline="Shared seats, collections and scoping for a product-security team.",
        price_cents=14900,
        monthly_credits=7_700,
        monthly_auto_runs=500,
        max_binaries=200,
        max_api_keys=25,
        max_seats=5,
        features=(
            "7,700 credits / month",
            "About 480 AI decompilations, pooled across the team",
            "500 auto runs / month",
            "200 binaries, 5 seats",
            "Shared collections and team scoping",
            "Priority email support",
        ),
        self_serve=True,
    ),
    Plan(
        id="enterprise",
        name="Enterprise",
        tagline="Dedicated capacity, custom retention, invoicing.",
        price_cents=74900,
        monthly_credits=39_000,
        monthly_auto_runs=3000,
        max_binaries=UNLIMITED,
        max_api_keys=UNLIMITED,
        max_seats=UNLIMITED,
        features=(
            "39,000 credits / month",
            "About 2,400 AI decompilations",
            "3,000 auto runs / month",
            "Unlimited binaries, seats and API keys",
            "Bring your own model endpoint (unmetered)",
            "Invoice billing and support SLA",
        ),
        self_serve=True,
    ),
    Plan(
        id="internal",
        name="Internal",
        tagline="Staff and self-hosted installs; not billed.",
        price_cents=0,
        monthly_credits=UNLIMITED,
        monthly_auto_runs=UNLIMITED,
        max_binaries=UNLIMITED,
        max_api_keys=UNLIMITED,
        max_seats=UNLIMITED,
        features=("Everything, unmetered",),
        self_serve=False,
    ),
)

# The plan a new organisation starts on, and the one a cancelled subscription
# falls back to.  Both are `free`: a lapsed tenant keeps its data and loses the
# metered capacity, rather than losing access to what it already analysed.
DEFAULT_PLAN_ID = "free"
FALLBACK_PLAN_ID = "free"

# The plan an install with no tenancy reads as.  A single-operator or
# self-hosted install is not billed, so it is unmetered by definition.
SELF_HOST_PLAN_ID = "internal"

_BY_ID: dict[str, Plan] = {plan.id: plan for plan in PLANS}


def get_plan(plan_id: str | None) -> Plan:
    """The named plan, falling back to :data:`DEFAULT_PLAN_ID` for an unknown id.

    Never raises: a database row naming a plan a later release removed must
    degrade to the free tier rather than break every request the tenant makes.
    """
    return _BY_ID.get(str(plan_id or ""), _BY_ID[DEFAULT_PLAN_ID])


def plan_exists(plan_id: str) -> bool:
    """Whether *plan_id* names a plan in the catalog."""
    return plan_id in _BY_ID


def public_plans() -> list[Plan]:
    """Every plan a pricing page may show, cheapest first.

    ``internal`` is withheld: it is the unmetered staff tier and showing it
    would advertise a way around the quota.
    """
    return [plan for plan in PLANS if plan.id != "internal"]


def checkout_plans() -> list[Plan]:
    """The subset a customer may buy without talking to anyone."""
    return [plan for plan in PLANS if plan.self_serve]


def price_env_name(plan_id: str) -> str:
    """The environment variable holding *plan_id*'s Stripe price id."""
    suffix = re.sub(r"[^A-Z0-9]+", "_", plan_id.upper())
    return f"REPORTAL_STRIPE_PRICE_{suffix}"


def stripe_price_id(plan_id: str) -> str:
    """The configured Stripe price id for *plan_id*, or the empty string."""
    return os.environ.get(price_env_name(plan_id), "").strip()


def plan_for_price_id(price_id: str) -> Plan | None:
    """The plan a Stripe price id maps back to, or None.

    This is how a webhook turns a subscription line item into an entitlement
    without trusting the metadata the checkout set.
    """
    wanted = price_id.strip()
    if not wanted:
        return None
    for plan in PLANS:
        if stripe_price_id(plan.id) == wanted:
            return plan
    return None

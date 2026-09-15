"""Subscription plan catalog: what each tier may do, and what it costs to serve.

The catalog is code, not operator configuration: quotas are a product decision,
and a typo in a plan definition must not silently hand out unmetered LLM spend.
Prices live here too, while the Stripe *price ids* stay in the environment
(``REPORTAL_STRIPE_PRICE_*``) so test keys and live keys can point at different
catalogs without a code change.

``internal`` is the staff/self-host tier: it removes the metered limits.  Give
it only to organisations that are not billed, never to a self-serve signup.

Why the token allowances look small
-----------------------------------

reportal resells inference.  Every AI extra (the whole-function rewrite, the
summaries, the comments, the type and rename suggestions, the auto workers)
spends Claude tokens that Anthropic bills at the rates in :data:`MODEL_RATES`,
so a plan's token allowance is a direct cost of goods sold and not a number to
pick for marketing.  The allowances below are derived from those rates rather
than chosen: :func:`plan_token_cogs_usd` states what a tier costs to serve at
full utilization, and :data:`MAX_COGS_SHARE` is the ceiling that share may
reach.  ``tests/test_plans.py`` fails the gate for a catalog that breaks it,
which is the guard against a well-meaning edit that reprices the product into a
loss.

The arithmetic, in one place:

* the default workload model is :data:`INPUT_SHARE` input to output, because
  reverse-engineering prompts send a decompiled function and get back a smaller
  annotation;
* at Claude Sonnet's ``$2``/``$10`` per MTok that blends to
  :func:`blended_usd_per_mtok` = ``$3.60`` per million tokens;
* a tier may spend at most :data:`MAX_COGS_SHARE` of its price on that, so a
  ``$39`` tier carries ``39 * 0.20 / 3.60`` = ``2.1`` million tokens.

Two pressure valves keep the ceiling from being a wall.  An organisation past
its allowance buys more at :data:`OVERAGE_USD_PER_MTOK` rather than stopping,
and an organisation that configures its own Anthropic key spends its own
inference budget, so :func:`metered` reports False and the allowance does not
apply at all.  Self-hosted installs are the second case by construction.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

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

# Price of tokens past the allowance, USD per million.  Above the blended cost
# by design: an overage is unplanned capacity and carries a thinner margin than
# a subscription, but never a negative one.
OVERAGE_USD_PER_MTOK = 6.0


def blended_usd_per_mtok(model: str = COST_MODEL) -> float:
    """Cost of one million metered tokens, USD, at :data:`INPUT_SHARE`.

    A metered token is a token either way, so one number has to stand for a mix
    of the two rates.  An unknown model prices at the most expensive one in the
    catalog rather than falling back to something cheap, because an unpriced
    model must never read as free.
    """
    if model in MODEL_RATES:
        input_rate, output_rate = MODEL_RATES[model]
    else:
        input_rate, output_rate = max(MODEL_RATES.values(), key=lambda pair: pair[1])
    return input_rate * INPUT_SHARE + output_rate * (1.0 - INPUT_SHARE)


def tokens_for_budget(usd: float, model: str = COST_MODEL) -> int:
    """How many tokens *usd* buys at the blended rate, rounded down."""
    return int(usd * 1_000_000 / blended_usd_per_mtok(model))


def usd_for_tokens(tokens: int, model: str = COST_MODEL) -> float:
    """What *tokens* cost to serve at the blended rate."""
    return tokens * blended_usd_per_mtok(model) / 1_000_000


@dataclass(frozen=True)
class Plan:
    """One subscription tier."""

    id: str
    name: str
    tagline: str
    price_cents: int
    monthly_tokens: int
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

    def token_cogs_usd(self) -> float:
        """Inference cost, USD, if the tier burned its whole token allowance."""
        if self.monthly_tokens == UNLIMITED:
            return float("inf")
        return usd_for_tokens(self.monthly_tokens)

    def cogs_share(self) -> float:
        """Inference cost as a share of price; ``inf`` for a tier with no price."""
        if self.price_cents <= 0:
            return float("inf") if self.monthly_tokens != 0 else 0.0
        return self.token_cogs_usd() / self.price_usd

    def metered(self) -> bool:
        """Whether this tier's token use counts against an allowance."""
        return self.monthly_tokens != UNLIMITED

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
            "monthly_tokens": self.monthly_tokens,
            "monthly_auto_runs": self.monthly_auto_runs,
            "max_binaries": self.max_binaries,
            "max_api_keys": self.max_api_keys,
            "max_seats": self.max_seats,
            "features": list(self.features),
            "self_serve": self.self_serve,
            "metered": self.metered(),
            "overage_usd_per_mtok": OVERAGE_USD_PER_MTOK,
        }


# The catalog, cheapest first.  Every token allowance here is
# `tokens_for_budget(price_usd * MAX_COGS_SHARE)` rounded down to a round
# number, which is what keeps `cogs_share()` under the ceiling.
PLANS: tuple[Plan, ...] = (
    Plan(
        id="free",
        name="Free",
        tagline="Evaluate the workbench on one binary.",
        price_cents=0,
        monthly_tokens=250_000,
        monthly_auto_runs=5,
        max_binaries=3,
        max_api_keys=1,
        max_seats=1,
        features=(
            "250K LLM tokens / month",
            "5 auto runs / month",
            "3 binaries",
            "1 seat",
            "Full static analysis, unmetered",
        ),
        self_serve=False,
    ),
    Plan(
        id="analyst",
        name="Analyst",
        tagline="For solo reverse engineers and toolchain research.",
        price_cents=3900,
        monthly_tokens=2_000_000,
        monthly_auto_runs=100,
        max_binaries=25,
        max_api_keys=5,
        max_seats=1,
        features=(
            "2M LLM tokens / month",
            "100 auto runs / month",
            "25 binaries",
            "1 seat",
            "14-day free trial",
            "Overage at $6 / M tokens",
        ),
        self_serve=True,
        trial_days=14,
    ),
    Plan(
        id="team",
        name="Team",
        tagline="For SOCs and product-security teams at scale.",
        price_cents=14900,
        monthly_tokens=8_000_000,
        monthly_auto_runs=500,
        max_binaries=200,
        max_api_keys=25,
        max_seats=5,
        features=(
            "8M LLM tokens / month",
            "500 auto runs / month",
            "200 binaries",
            "5 seats",
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
        monthly_tokens=40_000_000,
        monthly_auto_runs=3000,
        max_binaries=UNLIMITED,
        max_api_keys=UNLIMITED,
        max_seats=UNLIMITED,
        features=(
            "40M LLM tokens / month",
            "3,000 auto runs / month",
            "Unlimited binaries, seats and API keys",
            "Bring your own Anthropic key (unmetered)",
            "Invoice billing and support SLA",
        ),
        self_serve=True,
    ),
    Plan(
        id="internal",
        name="Internal",
        tagline="Staff and self-hosted installs; not billed.",
        price_cents=0,
        monthly_tokens=UNLIMITED,
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


def _price_env_name(plan_id: str) -> str:
    """The environment variable holding *plan_id*'s Stripe price id."""
    suffix = re.sub(r"[^A-Z0-9]+", "_", plan_id.upper())
    return f"REPORTAL_STRIPE_PRICE_{suffix}"


def stripe_price_id(plan_id: str) -> str:
    """The configured Stripe price id for *plan_id*, or the empty string."""
    return os.environ.get(_price_env_name(plan_id), "").strip()


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

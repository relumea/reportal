"""The plan catalog has to stay solvent.

These are the tests that fail the gate when an edit reprices the product into a
loss.  The catalog is code, so a plausible-looking edit ("bump the Analyst tier
to 50M tokens, it sounds better") is a one-line change that costs 180 dollars a
month per customer on a 39 dollar plan.  The arithmetic below is the thing that
catches it, which is why these assertions are about margin rather than about
the literal numbers: raising an allowance is allowed, raising it past what the
price supports is not.
"""

from __future__ import annotations

import pytest

from reportal import credits as credits_mod
from reportal import plans


class TestCostModel:
    """The blended rate the allowances are derived from."""

    def test_the_blend_sits_between_the_input_and_output_rates(self) -> None:
        """A blended token costs more than an input one and less than an output one."""
        input_rate, output_rate = plans.MODEL_RATES[plans.COST_MODEL]
        blended = plans.blended_usd_per_mtok()
        assert input_rate < blended < output_rate

    def test_the_blend_matches_the_declared_input_share(self) -> None:
        """The number is the stated mix, not a hand-tuned constant."""
        input_rate, output_rate = plans.MODEL_RATES[plans.COST_MODEL]
        expected = input_rate * plans.INPUT_SHARE + output_rate * (1 - plans.INPUT_SHARE)
        assert plans.blended_usd_per_mtok() == pytest.approx(expected)

    def test_an_unknown_model_prices_at_the_most_expensive_rate(self) -> None:
        """An unpriced model must never read as free, or it bills as free."""
        priciest = max(plans.blended_usd_per_mtok(name) for name in plans.MODEL_RATES)
        assert plans.blended_usd_per_mtok("some-model-we-never-heard-of") == pytest.approx(priciest)

    def test_tokens_and_dollars_round_trip(self) -> None:
        """The two directions of the same rate agree."""
        assert plans.usd_for_tokens(plans.tokens_for_budget(10.0)) == pytest.approx(10.0, rel=1e-6)

    def test_a_non_positive_budget_buys_no_tokens(self) -> None:
        """A negative or non-finite budget must not invent a negative allowance."""
        assert plans.tokens_for_budget(0.0) == 0
        assert plans.tokens_for_budget(-1.0) == 0
        assert plans.tokens_for_budget(float("nan")) == 0
        assert plans.tokens_for_budget(float("-inf")) == 0
        assert plans.tokens_for_budget(float("inf")) == 0


class TestMargin:
    """Every priced tier has to cost less to serve than it charges."""

    @pytest.mark.parametrize("plan", [p for p in plans.PLANS if p.price_cents > 0])
    def test_a_paid_tier_stays_under_the_cogs_ceiling(self, plan: plans.Plan) -> None:
        """Inference at full quota use stays inside its share of the price."""
        assert plan.cogs_share() <= plans.MAX_COGS_SHARE, (
            f"{plan.id} spends {plan.cogs_share():.1%} of its price on inference, "
            f"over the {plans.MAX_COGS_SHARE:.0%} ceiling"
        )

    @pytest.mark.parametrize("plan", [p for p in plans.PLANS if p.price_cents > 0])
    def test_a_paid_tier_is_gross_margin_positive(self, plan: plans.Plan) -> None:
        """The obvious half of the same property, stated so a failure reads plainly."""
        assert plan.credit_cogs_usd() < plan.price_usd

    def test_the_free_tier_is_capped_acquisition_spend(self) -> None:
        """Free has no price to take a share of, so it is bounded outright."""
        free = plans.get_plan("free")
        assert free.price_cents == 0
        assert free.credit_cogs_usd() <= plans.MAX_FREE_COGS_USD

    def test_overage_is_sold_above_cost(self) -> None:
        """Unplanned capacity is thinner margin, never negative margin."""
        assert credits_mod.credit_cogs_usd() < credits_mod.OVERAGE_USD_PER_CREDIT

    def test_price_rises_with_the_allowance(self) -> None:
        """A bigger allowance costs more; an inversion would be an arbitrage."""
        paid = [p for p in plans.PLANS if p.price_cents > 0 and p.metered()]
        ordered = sorted(paid, key=lambda p: p.price_cents)
        allowances = [p.monthly_credits for p in ordered]
        assert allowances == sorted(allowances)


class TestCatalog:
    """The shape the rest of the product reads."""

    def test_plan_ids_are_unique(self) -> None:
        ids = [plan.id for plan in plans.PLANS]
        assert len(ids) == len(set(ids))

    def test_the_default_and_fallback_plans_exist(self) -> None:
        assert plans.plan_exists(plans.DEFAULT_PLAN_ID)
        assert plans.plan_exists(plans.FALLBACK_PLAN_ID)
        assert plans.plan_exists(plans.SELF_HOST_PLAN_ID)

    def test_an_unknown_plan_degrades_to_the_default(self) -> None:
        """A row naming a removed plan must not break every request a tenant makes."""
        assert plans.get_plan("a-plan-from-a-later-release").id == plans.DEFAULT_PLAN_ID
        assert plans.get_plan(None).id == plans.DEFAULT_PLAN_ID

    def test_the_internal_tier_is_never_advertised(self) -> None:
        """Showing the unmetered tier would advertise a way around the quota."""
        assert "internal" not in {plan.id for plan in plans.public_plans()}
        assert "internal" not in {plan.id for plan in plans.checkout_plans()}

    def test_the_internal_tier_is_unmetered(self) -> None:
        internal = plans.get_plan("internal")
        assert internal.monthly_credits == plans.UNLIMITED
        assert not internal.metered()

    def test_public_plans_are_cheapest_first(self) -> None:
        prices = [plan.price_cents for plan in plans.public_plans()]
        assert prices == sorted(prices)

    def test_every_purchasable_plan_costs_something(self) -> None:
        """A self-serve checkout for a free plan would be a payment for nothing."""
        for plan in plans.checkout_plans():
            assert plan.price_cents > 0

    def test_describe_carries_what_a_pricing_page_renders(self) -> None:
        described = plans.get_plan("analyst").describe()
        assert described["id"] == "analyst"
        assert described["price_usd"] == pytest.approx(39.0)
        assert described["metered"] is True
        assert isinstance(described["features"], list)


class TestStripePriceIds:
    """The mapping a webhook trusts instead of caller-supplied metadata."""

    def test_a_price_id_maps_back_to_its_plan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REPORTAL_STRIPE_PRICE_ANALYST", "price_abc123")
        assert plans.stripe_price_id("analyst") == "price_abc123"
        found = plans.plan_for_price_id("price_abc123")
        assert found is not None
        assert found.id == "analyst"

    def test_an_unconfigured_price_maps_to_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty configured price must not match an empty lookup."""
        monkeypatch.delenv("REPORTAL_STRIPE_PRICE_ANALYST", raising=False)
        assert plans.stripe_price_id("analyst") == ""
        assert plans.plan_for_price_id("") is None
        assert plans.plan_for_price_id("price_nobody_configured") is None

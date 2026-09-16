"""The credit price list has to stay derived, and has to stay solvent.

Credits are what a customer actually spends, so these are the tests that fail
the gate when an edit would sell a task for less than it costs to serve, or
when the published price stops following the measured profile it claims to come
from.  As in ``tests/test_plans.py`` the assertions are about the derivation
rather than the literal numbers: repricing is allowed, repricing into a loss is
not.
"""

from __future__ import annotations

import sqlite3

import pytest

from reportal import auth, llm, metering, plans
from reportal import credits as credits_mod


class TestTheUnit:
    """One credit is one reference task, and everything follows from that."""

    def test_the_reference_task_costs_exactly_one_credit(self) -> None:
        assert credits_mod.base_credits(credits_mod.REFERENCE_TASK) == 1

    def test_the_reference_task_is_the_cheapest_one(self) -> None:
        """If something got cheaper, the unit is wrong and prices are inflated."""
        reference = credits_mod.TASK_PROFILES[credits_mod.REFERENCE_TASK].cogs_usd()
        for profile in credits_mod.TASK_PROFILES.values():
            assert profile.cogs_usd() >= reference

    def test_a_credit_is_priced_from_the_model_rates(self) -> None:
        """The unit moves when the rates move, rather than being a fixed guess."""
        expected = credits_mod.TASK_PROFILES[credits_mod.REFERENCE_TASK].cogs_usd()
        assert credits_mod.credit_cogs_usd() == pytest.approx(expected)

    def test_every_task_costs_at_least_one_credit(self) -> None:
        for task in credits_mod.TASK_PROFILES:
            assert credits_mod.base_credits(task) >= 1


class TestMeasuredProfiles:
    """The profiles are observations, and the shape of one has to stay honest."""

    def test_output_is_visible_answer_times_thinking(self) -> None:
        """A profile states what a reader sees and what the model spent getting there."""
        for profile in credits_mod.TASK_PROFILES.values():
            assert profile.output_tokens == round(profile.visible_tokens * profile.thinking_ratio)

    def test_no_profile_claims_a_model_thinks_less_than_nothing(self) -> None:
        """A ratio below 1 would mean invisible output, which cannot happen."""
        for profile in credits_mod.TASK_PROFILES.values():
            assert profile.thinking_ratio >= 1.0

    def test_every_profile_carries_a_real_prompt_size(self) -> None:
        for profile in credits_mod.TASK_PROFILES.values():
            assert profile.input_tokens > 0
            assert profile.visible_tokens > 0

    def test_the_rewrite_is_the_most_deliberated_task(self) -> None:
        """Measured: a whole-function rewrite thinks far longer than a triage line.

        Pinned because it is the counter-intuitive result the benchmark found,
        and the one an edit is most likely to undo by "tidying" the table.
        """
        rewrite = credits_mod.TASK_PROFILES[credits_mod.TASK_DECOMPILE]
        triage = credits_mod.TASK_PROFILES[credits_mod.TASK_TRIAGE]
        assert rewrite.thinking_ratio > triage.thinking_ratio * 2


class TestSolvency:
    """A task must never be sold for less than it costs to serve."""

    @pytest.mark.parametrize("task", sorted(credits_mod.TASK_PROFILES))
    def test_a_task_charges_at_least_its_cost(self, task: str) -> None:
        """Rounding up is what guarantees this; rounding down would not."""
        charged = credits_mod.base_credits(task) * credits_mod.credit_cogs_usd()
        assert charged >= credits_mod.TASK_PROFILES[task].cogs_usd()

    def test_overage_is_sold_above_cost(self) -> None:
        assert credits_mod.credit_cogs_usd() < credits_mod.OVERAGE_USD_PER_CREDIT

    def test_a_dearer_task_never_costs_fewer_credits(self) -> None:
        """Price order has to follow cost order, or the cheap task is a loophole."""
        ordered = sorted(credits_mod.TASK_PROFILES.values(), key=lambda p: p.cogs_usd())
        charges = [credits_mod.base_credits(p.name) for p in ordered]
        assert charges == sorted(charges)

    def test_an_unknown_task_is_priced_at_the_dearest_profile(self) -> None:
        """An unpriced task must never be a way to spend inference for free."""
        dearest = max(credits_mod.base_credits(name) for name in credits_mod.TASK_PROFILES)
        assert credits_mod.base_credits("a-task-from-a-later-release") == dearest


class TestSizeBands:
    """A published price still has to survive a very large function."""

    def test_a_standard_input_costs_the_base_price(self) -> None:
        task = credits_mod.TASK_DECOMPILE
        assert credits_mod.cost_of(task, 500) == credits_mod.base_credits(task)

    def test_a_larger_input_costs_more(self) -> None:
        task = credits_mod.TASK_DECOMPILE
        small = credits_mod.cost_of(task, 500)
        large = credits_mod.cost_of(task, 5_000)
        huge = credits_mod.cost_of(task, 15_000)
        assert small < large < huge

    def test_bands_are_ordered_and_rise(self) -> None:
        ceilings = [ceiling for _, ceiling, _ in credits_mod.SIZE_BANDS]
        multipliers = [multiplier for _, _, multiplier in credits_mod.SIZE_BANDS]
        assert ceilings == sorted(ceilings)
        assert multipliers == sorted(multipliers)

    def test_an_oversize_input_costs_the_most(self) -> None:
        """Past the last band there is still a price, not a free pass."""
        beyond = credits_mod.SIZE_BANDS[-1][1] + 1
        assert credits_mod.band_for(beyond) == ("oversize", credits_mod.OVERSIZE_MULTIPLIER)

    def test_a_normal_function_is_never_surcharged(self) -> None:
        """The first ceiling sits above the reference corpus, by design."""
        profile = credits_mod.TASK_PROFILES[credits_mod.TASK_DECOMPILE]
        assert profile.input_tokens < credits_mod.SIZE_BANDS[0][1]

    def test_a_negative_size_is_treated_as_empty(self) -> None:
        task = credits_mod.TASK_SUMMARY
        assert credits_mod.cost_of(task, -100) == credits_mod.base_credits(task)


class TestCatalogShape:
    """What the price list and the pricing page read."""

    def test_the_catalog_covers_every_task(self) -> None:
        assert {row["task"] for row in credits_mod.catalog()} == set(credits_mod.TASK_PROFILES)

    def test_the_catalog_is_cheapest_first(self) -> None:
        charges = [credits_mod.base_credits(str(row["task"])) for row in credits_mod.catalog()]
        assert charges == sorted(charges)

    def test_every_row_says_what_it_is(self) -> None:
        """A price with no explanation is a support ticket."""
        for row in credits_mod.catalog():
            assert str(row["label"]).strip()
            assert str(row["describe"]).strip()

    def test_the_catalog_includes_the_oversize_band(self) -> None:
        """Past the last ceiling still has a price; the published row must say so."""
        for row in credits_mod.catalog():
            bands = row["bands"]
            assert isinstance(bands, list) and bands
            last = bands[-1]
            assert last["name"] == "oversize"
            assert last["max_input_tokens"] is None
            assert last["credits"] == credits_mod.base_credits(str(row["task"])) * (
                credits_mod.OVERSIZE_MULTIPLIER
            )

    def test_triage_is_charged_per_function(self) -> None:
        """A binary-wide run multiplies, so the row has to say so."""
        assert credits_mod.TASK_PROFILES[credits_mod.TASK_TRIAGE].per_function is True

    def test_task_names_come_from_the_module_that_runs_them(self) -> None:
        """The price list cannot drift from the tasks that actually exist."""
        assert credits_mod.TASK_SUMMARY == llm.TASK_SUMMARY
        assert credits_mod.TASK_DECOMPILE == llm.TASK_DECOMPILE
        assert credits_mod.TASK_TRIAGE == llm.TASK_TRIAGE


class TestCharging:
    """What a billable operation actually writes."""

    def _organisation(self, conn: sqlite3.Connection, plan_id: str = "analyst") -> int:
        created = auth.create_organisation(conn, name=f"org-{plan_id}", description="")
        organisation_id = int(created["id"])
        conn.execute(
            f"UPDATE {auth.ORG_TABLE} SET plan_id = ?, period_started_at = ? WHERE id = ?",
            (plan_id, auth.now(), organisation_id),
        )
        conn.commit()
        return organisation_id

    def test_a_charge_debits_the_credit_dimension(self, conn: sqlite3.Connection) -> None:
        organisation_id = self._organisation(conn)
        charged = metering.charge_task(conn, organisation_id, credits_mod.TASK_DECOMPILE)
        assert charged == credits_mod.base_credits(credits_mod.TASK_DECOMPILE)
        used = metering.period_usage(conn, organisation_id, metering.KIND_CREDITS)
        assert used == charged

    def test_a_charge_scales_with_the_call_count(self, conn: sqlite3.Connection) -> None:
        """A binary-wide triage charges per function, which is what calls says."""
        organisation_id = self._organisation(conn)
        charged = metering.charge_task(conn, organisation_id, credits_mod.TASK_TRIAGE, calls=10)
        assert charged == credits_mod.base_credits(credits_mod.TASK_TRIAGE) * 10

    def test_a_charge_scales_with_the_size_band(self, conn: sqlite3.Connection) -> None:
        organisation_id = self._organisation(conn)
        small = metering.charge_task(
            conn, organisation_id, credits_mod.TASK_DECOMPILE, input_tokens=100
        )
        large = metering.charge_task(
            conn, organisation_id, credits_mod.TASK_DECOMPILE, input_tokens=10_000
        )
        assert large > small

    def test_no_tenant_is_never_charged(self, conn: sqlite3.Connection) -> None:
        """A self-hosted install spends nothing, which is the whole promise."""
        assert metering.charge_task(conn, metering.NO_ORG, credits_mod.TASK_DECOMPILE) == 0
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {metering.USAGE_TABLE}").fetchone()
        assert int(row["n"]) == 0

    def test_a_charge_counts_against_the_plan_allowance(self, conn: sqlite3.Connection) -> None:
        organisation_id = self._organisation(conn, "free")
        allowance = plans.get_plan("free").monthly_credits
        metering.charge_task(conn, organisation_id, credits_mod.TASK_SUMMARY, calls=allowance)
        checked = metering.quota_check(conn, organisation_id, metering.KIND_CREDITS, 1)
        assert checked["allowed"] is False


class TestTheChargeSink:
    """The seam that makes every AI route billable without editing it."""

    def test_a_completion_reports_its_task_and_size(self) -> None:
        seen: list[tuple[str, int]] = []
        with llm.charging(lambda task, size: seen.append((task, size))):
            llm._report_charge("summary", [{"role": "user", "content": "x" * 360}])
        assert seen == [("summary", 100)]

    def test_nothing_is_reported_without_a_sink(self) -> None:
        """An install with no tenant pays one attribute read and nothing else."""
        llm._report_charge("summary", [{"role": "user", "content": "x"}])

    def test_the_sink_does_not_outlive_its_block(self) -> None:
        seen: list[tuple[str, int]] = []
        with llm.charging(lambda task, size: seen.append((task, size))):
            pass
        llm._report_charge("summary", [{"role": "user", "content": "x"}])
        assert seen == []

    def test_a_failing_sink_never_breaks_the_call(self) -> None:
        """Billing is not allowed to take down the feature it bills for."""

        def broken(task: str, size: int) -> None:
            raise RuntimeError("ledger is down")

        with llm.charging(broken):
            llm._report_charge("summary", [{"role": "user", "content": "x"}])

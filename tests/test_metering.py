"""Tests for reportal.metering: the usage ledger and the quota checks."""

from __future__ import annotations

import sqlite3

import pytest

from reportal import auth, metering, plans
from reportal import credits as credits_mod


def _organisation(conn: sqlite3.Connection, plan_id: str = "analyst") -> int:
    """An organisation on *plan_id* with an open period."""
    created = auth.create_organisation(conn, name=f"org-{plan_id}", description="")
    organisation_id = int(created["id"])
    conn.execute(
        f"UPDATE {auth.ORG_TABLE} SET plan_id = ?, period_started_at = ? WHERE id = ?",
        (plan_id, auth.now(), organisation_id),
    )
    conn.commit()
    return organisation_id


class TestSelfHostedStaysUnmetered:
    """The property that keeps an existing install working after an upgrade."""

    def test_no_tenant_reads_as_the_unmetered_plan(self, conn: sqlite3.Connection) -> None:
        assert metering.organisation_plan(conn, metering.NO_ORG).id == plans.SELF_HOST_PLAN_ID

    def test_no_tenant_is_never_refused(self, conn: sqlite3.Connection) -> None:
        checked = metering.quota_check(conn, metering.NO_ORG, metering.KIND_CREDITS, 10**9)
        assert checked["allowed"] is True
        assert checked["metered"] is False

    def test_no_tenant_records_nothing(self, conn: sqlite3.Connection) -> None:
        """The ledger holds billable rows only."""
        metering.record_usage(conn, metering.NO_ORG, metering.KIND_TOKENS, 5000)
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {metering.USAGE_TABLE}").fetchone()
        assert int(row["n"]) == 0


class TestLedger:
    """Append-only rows, and what they sum to."""

    def test_a_token_row_records_its_cost(self, conn: sqlite3.Connection) -> None:
        organisation_id = _organisation(conn)
        metering.record_usage(
            conn, organisation_id, metering.KIND_TOKENS, 1_000_000, model=plans.COST_MODEL
        )
        cost = metering.period_cost_usd(conn, organisation_id)
        assert cost == pytest.approx(plans.blended_usd_per_mtok(), rel=1e-3)

    def test_usage_accumulates(self, conn: sqlite3.Connection) -> None:
        organisation_id = _organisation(conn)
        for _ in range(3):
            metering.record_usage(conn, organisation_id, metering.KIND_TOKENS, 1000)
        assert metering.period_usage(conn, organisation_id, metering.KIND_TOKENS) == 3000

    def test_a_negative_count_cannot_credit_the_quota_back(self, conn: sqlite3.Connection) -> None:
        """A miscounted report must not be able to refund tokens."""
        organisation_id = _organisation(conn)
        metering.record_usage(conn, organisation_id, metering.KIND_TOKENS, 1000)
        metering.record_usage(conn, organisation_id, metering.KIND_TOKENS, -5000)
        assert metering.period_usage(conn, organisation_id, metering.KIND_TOKENS) == 1000

    def test_a_new_period_moves_the_window_without_deleting_history(
        self, conn: sqlite3.Connection
    ) -> None:
        """The invoice that already covered those rows still has them."""
        organisation_id = _organisation(conn)
        metering.record_usage(conn, organisation_id, metering.KIND_TOKENS, 4000)
        conn.execute(
            f"UPDATE {metering.USAGE_TABLE} SET occurred_at = '2000-01-01T00:00:00+00:00' "
            "WHERE organisation_id = ?",
            (organisation_id,),
        )
        conn.commit()
        metering.start_period(conn, organisation_id)
        assert metering.period_usage(conn, organisation_id, metering.KIND_TOKENS) == 0
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM {metering.USAGE_TABLE} WHERE organisation_id = ?",
            (organisation_id,),
        ).fetchone()
        assert int(total["n"]) == 1

    def test_the_ledger_separates_dimensions(self, conn: sqlite3.Connection) -> None:
        organisation_id = _organisation(conn)
        metering.record_usage(conn, organisation_id, metering.KIND_TOKENS, 1000)
        metering.record_usage(conn, organisation_id, metering.KIND_AUTO_RUN, 1)
        assert metering.period_usage(conn, organisation_id, metering.KIND_TOKENS) == 1000
        assert metering.period_usage(conn, organisation_id, metering.KIND_AUTO_RUN) == 1


class TestQuota:
    """What gates metered work."""

    def test_use_inside_the_allowance_is_allowed(self, conn: sqlite3.Connection) -> None:
        organisation_id = _organisation(conn, "analyst")
        checked = metering.quota_check(conn, organisation_id, metering.KIND_CREDITS, 100)
        assert checked["allowed"] is True
        assert checked["overage_units"] == 0

    def test_a_paid_plan_past_its_allowance_bills_rather_than_stops(
        self, conn: sqlite3.Connection
    ) -> None:
        """An overage is billable capacity; work continues."""
        organisation_id = _organisation(conn, "analyst")
        allowance = plans.get_plan("analyst").monthly_credits
        metering.record_usage(conn, organisation_id, metering.KIND_CREDITS, allowance)
        checked = metering.quota_check(conn, organisation_id, metering.KIND_CREDITS, 100)
        assert checked["allowed"] is True
        assert checked["overage_units"] == 100
        assert checked["overage_usd"] == pytest.approx(100 * credits_mod.OVERAGE_USD_PER_CREDIT)

    def test_the_free_plan_actually_stops(self, conn: sqlite3.Connection) -> None:
        """Free has nothing to invoice an overage against."""
        organisation_id = _organisation(conn, "free")
        allowance = plans.get_plan("free").monthly_credits
        metering.record_usage(conn, organisation_id, metering.KIND_CREDITS, allowance)
        checked = metering.quota_check(conn, organisation_id, metering.KIND_CREDITS, 1)
        assert checked["allowed"] is False
        assert checked["overage_units"] == 0
        assert "quota" in checked["reason"]

    def test_past_due_is_refused_whatever_the_allowance_says(
        self, conn: sqlite3.Connection
    ) -> None:
        """An unpaid subscription is the one case remaining quota is not entitlement."""
        organisation_id = _organisation(conn, "team")
        conn.execute(
            f"UPDATE {auth.ORG_TABLE} SET status = ? WHERE id = ?",
            (metering.STATUS_PAST_DUE, organisation_id),
        )
        conn.commit()
        checked = metering.quota_check(conn, organisation_id, metering.KIND_CREDITS, 1)
        assert checked["allowed"] is False
        assert checked["reason"] == "subscription past due"

    def test_an_unmetered_plan_reports_unlimited(self, conn: sqlite3.Connection) -> None:
        organisation_id = _organisation(conn, "internal")
        checked = metering.quota_check(conn, organisation_id, metering.KIND_CREDITS, 10**9)
        assert checked["allowed"] is True
        assert checked["limit"] == plans.UNLIMITED

    def test_auto_runs_are_metered_on_their_own_dimension(self, conn: sqlite3.Connection) -> None:
        organisation_id = _organisation(conn, "free")
        allowance = plans.get_plan("free").monthly_auto_runs
        metering.record_usage(conn, organisation_id, metering.KIND_AUTO_RUN, allowance)
        assert (
            metering.quota_check(conn, organisation_id, metering.KIND_AUTO_RUN, 1)["allowed"]
            is False
        )
        assert metering.quota_check(conn, organisation_id, metering.KIND_TOKENS, 1)["allowed"]


class TestSummary:
    """The shape the usage route serves."""

    def test_the_summary_covers_every_metered_dimension(self, conn: sqlite3.Connection) -> None:
        organisation_id = _organisation(conn, "team")
        summary = metering.usage_summary(conn, organisation_id)
        assert set(summary["usage"]) == set(metering.CUSTOMER_KINDS)
        assert summary["plan"]["id"] == "team"
        assert summary["organisation_id"] == organisation_id

    def test_the_summary_reports_the_cost_to_serve(self, conn: sqlite3.Connection) -> None:
        organisation_id = _organisation(conn, "team")
        metering.record_usage(
            conn, organisation_id, metering.KIND_TOKENS, 2_000_000, model=plans.COST_MODEL
        )
        summary = metering.usage_summary(conn, organisation_id)
        assert summary["cost_usd"] > 0

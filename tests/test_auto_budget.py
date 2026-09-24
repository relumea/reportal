"""Auto-run budgets: a run stops starting attempts once its model spend is used up."""

from __future__ import annotations

import math
import sqlite3
from types import SimpleNamespace

import pytest
from auto_helpers import seed_rows

from reportal import auto_mode, auto_workers, llm
from reportal.auto_workers import WORKER_FAILED, Worker, WorkerContext, WorkerResult

ROWS: tuple[tuple[int, str, int, str], ...] = (
    (0x1000, "First", 8, "STUB"),
    (0x2000, "Second", 8, "STUB"),
    (0x3000, "Third", 8, "STUB"),
)
TOKENS_PER_CALL = 1000


def _spending_worker(ctx: WorkerContext) -> WorkerResult:
    """A worker whose one model call costs TOKENS_PER_CALL, reported the way a
    real completion reports it."""
    completion = SimpleNamespace(usage=SimpleNamespace(prompt_tokens=600, completion_tokens=400))
    llm._report_usage(completion, "probe-model")
    return WorkerResult(status=WORKER_FAILED, detail={"reason": "probe"})


@pytest.fixture()
def spender() -> str:
    name = "budget-probe"
    auto_workers.register_worker(
        Worker(name=name, description="spends tokens", run=_spending_worker), origin="test"
    )
    return name


class TestParams:
    def test_zero_is_no_budget(self) -> None:
        params = auto_mode.build_params()
        assert (params.max_tokens, params.max_usd, params.usd_per_mtok) == (0, 0.0, 0.0)
        assert auto_mode.RunBudget(params).exhausted() is False

    @pytest.mark.parametrize(
        ("knobs", "message"),
        [
            ({"max_usd": 1.0}, "max_usd needs usd_per_mtok"),
            ({"max_usd": -1.0, "usd_per_mtok": 1.0}, "max_usd must be between"),
            ({"max_usd": math.nan, "usd_per_mtok": 1.0}, "max_usd must be between"),
            ({"usd_per_mtok": math.inf}, "usd_per_mtok must be between"),
            ({"max_tokens": -5}, "max_tokens must be between"),
        ],
    )
    def test_bad_knobs_are_refused(self, knobs: dict[str, float], message: str) -> None:
        with pytest.raises(ValueError, match=message):
            auto_mode.build_params(**knobs)  # type: ignore[arg-type]

    def test_the_spend_cap_prices_the_tokens(self) -> None:
        budget = auto_mode.RunBudget(auto_mode.build_params(max_usd=0.002, usd_per_mtok=1.0))
        budget.add(1500, 0, "m")
        assert budget.exhausted() is False
        budget.add(500, 0, "m")
        assert budget.snapshot() == {
            "tokens": 2000,
            "usd": 0.002,
            "max_tokens": 0,
            "max_usd": 0.002,
            "usd_per_mtok": 1.0,
            "exhausted": True,
        }


class TestRun:
    def test_a_spent_budget_skips_the_rest(self, conn: sqlite3.Connection, spender: str) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run = auto_mode.run_auto(
            conn,
            binary_id=ids["binary"],
            worker=spender,
            concurrency=1,
            functions_per_task=len(ROWS),
            max_attempts=1,
            max_tokens=1500,
        )
        # The first call spends 1000 (under the cap), the second takes it to
        # 2000, and the third function is never tried.
        assert run["attempts"] == 2
        assert run["skipped"] == 1
        assert run["budget"]["tokens"] == 2 * TOKENS_PER_CALL
        assert run["budget"]["exhausted"] is True
        [root] = run["tree"]
        outcomes = root["children"][0]["result"]["outcomes"]
        assert [outcome["reason"] for outcome in outcomes] == [
            "probe",
            "probe",
            auto_mode.REASON_BUDGET,
        ]

    def test_without_a_budget_every_function_is_tried(
        self, conn: sqlite3.Connection, spender: str
    ) -> None:
        ids = seed_rows(conn, rows=ROWS)
        run = auto_mode.run_auto(
            conn,
            binary_id=ids["binary"],
            worker=spender,
            concurrency=1,
            functions_per_task=len(ROWS),
            max_attempts=1,
        )
        assert run["attempts"] == len(ROWS)
        assert run["budget"] == {
            "tokens": len(ROWS) * TOKENS_PER_CALL,
            "usd": 0.0,
            "max_tokens": 0,
            "max_usd": 0.0,
            "usd_per_mtok": 0.0,
            "exhausted": False,
        }

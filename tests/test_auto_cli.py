"""Tests for the auto-mode CLI commands."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from auto_helpers import seed_rows, writer_worker
from typer.testing import CliRunner

from reportal import auto_store, auto_workers, cli, store
from reportal._paths import DB_ENV

runner = CliRunner()

# One marked function and one address placeholder, so an offline run reports
# both a match and a failure.
CLI_ROWS: tuple[tuple[int, str, int, str], ...] = (
    (0x1000, "Work", 8, "STUB"),
    (0x1100, "sub_1100", 4, "STUB"),
)


def _seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    rows: tuple[tuple[int, str, int, str], ...] = CLI_ROWS,
) -> dict[str, int]:
    """Create a portal DB with a binary and the given outstanding functions."""
    db = tmp_path / "reportal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        ids = seed_rows(conn, rows=rows)
        analysis = int(ids["analysis"])
        binary = int(ids["binary"])
    return {"binary": binary, "analysis": analysis}


class TestAutoCommand:
    def test_json_prints_the_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["auto", str(ids["binary"]), "--worker", "offline", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["binary_id"] == ids["binary"]
        assert payload["status"] == auto_store.AUTO_RUN_PARTIAL
        assert payload["worker"] == auto_workers.WORKER_OFFLINE
        assert payload["matched"] == 1
        assert payload["failed"] == 1
        assert payload["coverage_before"] == {"matched": 0, "total": 2, "ratio": 0.0}
        assert payload["coverage_after"]["matched"] == 1
        assert payload["tree"][0]["kind"] == auto_store.AUTO_TASK_ROOT
        assert len(payload["tree"][0]["children"]) == 2

    def test_json_leaves_the_function_rows_alone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["auto", str(ids["binary"]), "--json"])
        with contextlib.closing(store.connect(tmp_path / "reportal.db")) as conn:
            statuses = {
                row["name"]: row["status"]
                for row in store.list_functions(conn, binary_id=ids["binary"])
            }
        assert statuses == {"Work": "STUB", "sub_1100": "STUB"}

    def test_human_prints_the_tree_and_coverage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["auto", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "auto run 1" in result.output
        assert "coverage 0/2 -> 1/2" in result.output
        assert "matched 1" in result.output
        assert "root" in result.output
        assert "Work @ 0x1000" in result.output
        assert "attempts 1" in result.output

    def test_execute_prints_a_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        auto_workers.register_worker(writer_worker(tmp_path / "Work.c"), origin="test")
        result = runner.invoke(
            cli.app, ["auto", str(ids["binary"]), "--worker", "writer", "--execute"]
        )
        assert result.exit_code == 0, result.output
        assert "--execute writes candidate C files" in result.output

    def test_an_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["auto", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.output

    def test_an_out_of_range_bound_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["auto", str(ids["binary"]), "--concurrency", "0"])
        assert result.exit_code == 1
        assert "concurrency must be between" in result.output

    def test_an_unknown_worker_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["auto", str(ids["binary"]), "--worker", "nope", "--json"])
        assert result.exit_code == 1
        assert "unknown worker" in result.output


class TestAutoRevertCommand:
    def _run(self, tmp_path: Path, ids: dict[str, int]) -> int:
        result = runner.invoke(cli.app, ["auto", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        return int(json.loads(result.stdout)["run_id"])

    def test_json_reports_what_it_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, rows=((0x1000, "Work", 8, "STUB"),))
        auto_workers.register_worker(writer_worker(tmp_path / "Work.c"), origin="test")
        run = runner.invoke(
            cli.app,
            ["auto", str(ids["binary"]), "--worker", "writer", "--execute", "--json"],
        )
        assert run.exit_code == 0, run.output
        run_id = int(json.loads(run.stdout)["run_id"])
        result = runner.invoke(cli.app, ["auto-revert", str(run_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["status"] == auto_store.AUTO_RUN_REVERTED
        assert payload["removed"] == [{"path": str(tmp_path / "Work.c"), "status": "removed"}]
        assert payload["restored"][0]["status"] == "STUB"
        with contextlib.closing(store.connect(tmp_path / "reportal.db")) as conn:
            assert auto_store.get_auto_run(conn, run_id) is None

    def test_human_reports_nothing_to_revert(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        run_id = self._run(tmp_path, ids)
        result = runner.invoke(cli.app, ["auto-revert", str(run_id)])
        assert result.exit_code == 0, result.output
        assert "Nothing to revert." in result.output

    def test_an_unknown_run_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["auto-revert", "4242", "--json"])
        assert result.exit_code == 1
        assert "no auto run with id 4242" in result.output

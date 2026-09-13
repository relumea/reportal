"""Tests for the `analyses`, `analysis-logs` and `analysis-delete` CLI commands."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from conftest import wsgi_request
from typer.testing import CliRunner

from reportal import analysis_log, cli, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Create a portal DB with one binary, two analyses and two functions."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe")
        first = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        second = store.create_analysis(conn, binary_id=binary_id, engine="rebrew-import")
        store.add_function(conn, analysis_id=first, va=0x1000, name="sub_1000", size=16)
        store.add_function(conn, analysis_id=second, va=0x2000, name="sub_2000", size=32)
        store.set_scan(conn, second, store.SCAN_KIND_TRIAGE, {"toolchain": {}})
    return {"binary": binary_id, "first": first, "second": second}


class TestAnalysesCommand:
    def test_lists_rows_and_counts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["analyses", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["count"] == 2
        assert payload["total"] == 2
        assert [row["id"] for row in payload["analyses"]] == [ids["second"], ids["first"]]

    def test_status_and_order_filters(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["analyses", "--status", "done", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert [row["id"] for row in payload["analyses"]] == [ids["second"]]
        assert payload["total"] == 2

        result = runner.invoke(cli.app, ["analyses", "--order", "oldest", "--limit", "1", "--json"])
        assert result.exit_code == 0, result.output
        assert [row["id"] for row in json.loads(result.output)["analyses"]] == [ids["first"]]

    def test_search_filter(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["analyses", "--search", "import", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["count"] == 1

    def test_unknown_values_fail(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        for argv in (
            ["analyses", "--status", "finished"],
            ["analyses", "--order", "random"],
            ["analyses", "--limit", "0"],
        ):
            result = runner.invoke(cli.app, [*argv, "--json"])
            assert result.exit_code == 1
            assert "error" in json.loads(result.output)


class TestAnalysisLogsCommand:
    def test_prints_the_log_with_its_total(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["analysis-logs", str(ids["second"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["total"] >= 2
        assert payload["offset"] == 0
        messages = [entry["message"] for entry in payload["logs"]]
        assert f"{store.SCAN_KIND_TRIAGE} scan finished" in messages

    def test_limit_and_offset_bound_the_page(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            for index in range(4):
                analysis_log.append_entry(conn, ids["first"], message=f"entry {index}")
        result = runner.invoke(
            cli.app,
            ["analysis-logs", str(ids["first"]), "--limit", "2", "--offset", "1", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["count"] == 2
        assert payload["total"] == 5
        assert [entry["message"] for entry in payload["logs"]] == ["entry 2", "entry 1"]

    def test_unknown_analysis_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["analysis-logs", "4242", "--json"])
        assert result.exit_code == 1
        assert "no analysis" in json.loads(result.output)["error"]

    def test_out_of_range_limit_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["analysis-logs", str(ids["first"]), "--limit", "0", "--json"]
        )
        assert result.exit_code == 1

    def test_human_output_names_the_severity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["analysis-logs", str(ids["second"])])
        assert result.exit_code == 0
        assert "scan finished" in result.output


class TestAnalysisDeleteCommand:
    def test_delete_is_journaled_and_revertible(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["analysis-delete", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        action = payload["journal_action"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_analysis(conn, ids["first"]) is None
            assert store.list_functions(conn, analysis_id=ids["first"]) == []

        wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_analysis(conn, ids["first"]) is not None
            assert len(store.list_functions(conn, analysis_id=ids["first"])) == 1

    def test_unknown_analysis_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["analysis-delete", "4242", "--json"])
        assert result.exit_code == 1
        assert "no analysis" in json.loads(result.output)["error"]

    def test_the_last_analysis_of_a_binary_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.delete_analysis(conn, ids["first"])
        result = runner.invoke(cli.app, ["analysis-delete", str(ids["second"]), "--json"])
        assert result.exit_code == 1
        assert "only analysis" in json.loads(result.output)["error"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_analysis(conn, ids["second"]) is not None

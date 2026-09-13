"""Tests for the knowledge-graph CLI commands: ``graph-build`` and ``graph``."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from graph_helpers import FUNCTION_NAME, LIBRARY_MODULE, node_id, seed_corpus
from typer.testing import CliRunner

from reportal import cli, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Create a portal DB holding the shared graph corpus, and return its ids."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        return seed_corpus(conn)


def _stored(db_path: Path) -> dict[str, int]:
    """Current node and edge row counts of the seeded binary."""
    with contextlib.closing(store.connect(db_path)) as conn:
        return {
            "nodes": store.count_graph_nodes(conn, 1),
            "edges": store.count_graph_edges(conn, 1),
        }


class TestGraphBuild:
    def test_json_reports_the_counts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-build", "1", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["binary_id"] == 1
        assert payload["nodes"] > 0
        assert payload["edges"] > 0
        assert payload["truncated"] is False

    def test_stored_rows_match_the_reported_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-build", "1", "--json"])
        payload = json.loads(result.stdout)
        stored = _stored(tmp_path / "portal.db")
        assert payload["nodes"] == stored["nodes"]
        assert payload["edges"] == stored["edges"]

    def test_human_output_names_the_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-build", "1"])
        assert result.exit_code == 0, result.output
        assert "Built" in result.output
        assert "nodes" in result.output

    def test_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-build", "404"])
        assert result.exit_code == 1
        assert "no binary with id 404" in result.output


class TestGraph:
    def test_json_reports_the_counts_by_kind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["graph-build", "1", "--json"])
        result = runner.invoke(cli.app, ["graph", "1", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["counts"]["function"] == 2
        assert payload["counts"]["library"] == 2
        assert len(payload["nodes"]) > 0

    def test_json_holds_the_whole_stored_graph(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["graph-build", "1", "--json"])
        result = runner.invoke(cli.app, ["graph", "1", "--json"])
        payload = json.loads(result.stdout)
        assert payload["counts"]["document"] == 1
        assert "mentions" in {edge["rel"] for edge in payload["edges"]}

    def test_human_output_prints_the_kind_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["graph-build", "1", "--json"])
        result = runner.invoke(cli.app, ["graph", "1"])
        assert result.exit_code == 0, result.output
        assert "Nodes" in result.output
        assert "capability" in result.output
        assert "edges" in result.output

    def test_before_a_build_it_fails_with_the_hint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph", "1"])
        assert result.exit_code == 1
        assert "no graph for binary 1" in result.output
        assert "graph-build 1" in result.output

    def test_node_json_returns_the_groups(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["graph-build", "1", "--json"])
        target = node_id(ids["binary"], "function", ids["first"])
        result = runner.invoke(cli.app, ["graph", "1", "--node", target, "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["node"]["label"] == FUNCTION_NAME
        assert set(payload["incoming"]) == {"contains", "mentions"}

    def test_node_human_output_prints_the_groups(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["graph-build", "1", "--json"])
        target = node_id(ids["binary"], "library", LIBRARY_MODULE)
        result = runner.invoke(cli.app, ["graph", "1", "--node", target])
        assert result.exit_code == 0, result.output
        assert "incoming" in result.output
        assert "identifies" in result.output

    def test_unknown_node_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["graph-build", "1", "--json"])
        result = runner.invoke(cli.app, ["graph", "1", "--node", "b1:function:999"])
        assert result.exit_code == 1
        assert "no graph node b1:function:999" in result.output

    def test_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph", "404"])
        assert result.exit_code == 1
        assert "no binary with id 404" in result.output

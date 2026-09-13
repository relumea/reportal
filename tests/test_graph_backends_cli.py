"""Tests for the graph-backend CLI commands."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from graph_backend_helpers import recording_backend
from graph_helpers import FUNCTION_NAME, seed_corpus
from typer.testing import CliRunner

from reportal import cli, graph, graph_backends, store
from reportal._paths import DB_ENV
from reportal.graph_backends import COGNEE_INSTALL_HINT

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_graph_backends() -> Iterator[None]:
    """Reload the registry around each test, whatever a test registered."""
    graph_backends.refresh_graph_backends()
    yield
    graph_backends.refresh_graph_backends()


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Create a portal DB holding the shared graph corpus, and return its ids."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        ids = seed_corpus(conn)
        graph.build_graph(conn, binary_id=ids["binary"])
        return ids


def _without_graph(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Create a portal DB holding the corpus without building its graph."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        return seed_corpus(conn)


class TestGraphBackendsCommand:
    def test_json_lists_the_registry_and_the_default(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["graph-backends", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert [entry["name"] for entry in payload["backends"]] == ["sqlite", "cognee"]
        assert payload["default"] == "sqlite"

    def test_json_reports_the_install_hint_when_cognee_is_absent(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        result = runner.invoke(cli.app, ["graph-backends", "--json"])
        payload = json.loads(result.stdout)
        cognee = next(entry for entry in payload["backends"] if entry["name"] == "cognee")
        assert cognee["available"] is False
        assert cognee["unavailable_reason"] == COGNEE_INSTALL_HINT

    def test_human_output_prints_the_table(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["graph-backends"])
        assert result.exit_code == 0, result.output
        assert "Graph backends" in result.output
        assert "sqlite" in result.output
        assert "default: sqlite" in result.output

    def test_env_names_the_default_backend(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(graph_backends.BACKEND_ENV, "cognee")
        result = runner.invoke(cli.app, ["graph-backends", "--json"])
        assert json.loads(result.stdout)["default"] == "cognee"


class TestGraphSyncCommand:
    def test_sqlite_sync_reports_the_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-sync", "1", "--backend", "sqlite", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["backend"] == "sqlite"
        assert payload["nodes"] > 0
        assert payload["edges"] > 0
        assert payload["pushed_nodes"] == 0

    def test_sync_of_a_fresh_binary_reports_the_stored_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-sync", "1", "--json"])
        payload = json.loads(result.stdout)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert payload["nodes"] == store.count_graph_nodes(conn, 1)
            assert payload["edges"] == store.count_graph_edges(conn, 1)

    def test_env_configured_backend_is_used(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        backend, recorded = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        monkeypatch.setenv(graph_backends.BACKEND_ENV, "probe")
        result = runner.invoke(cli.app, ["graph-sync", "1", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["backend"] == "probe"
        assert len(recorded) == 1

    def test_human_output_names_the_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-sync", "1", "--backend", "sqlite"])
        assert result.exit_code == 0, result.output
        assert "Synced" in result.output
        assert "nodes" in result.output

    def test_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-sync", "404", "--backend", "sqlite"])
        assert result.exit_code == 1
        assert "no binary with id 404" in result.output

    def test_unknown_backend_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-sync", "1", "--backend", "nope"])
        assert result.exit_code == 1
        assert "unknown graph backend" in result.output

    def test_without_a_graph_fails_with_the_build_hint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without_graph(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-sync", "1", "--backend", "sqlite"])
        assert result.exit_code == 1
        assert "graph-build 1" in result.output

    def test_unavailable_cognee_fails_with_the_hint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        result = runner.invoke(cli.app, ["graph-sync", "1", "--backend", "cognee"])
        assert result.exit_code == 1
        assert "backend-unavailable" in result.output
        assert "uv sync --extra cognee" in result.output


class TestGraphQueryCommand:
    def test_json_returns_the_matching_nodes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["graph-query", FUNCTION_NAME, "--backend", "sqlite", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["backend"] == "sqlite"
        assert payload["count"] == 1
        assert payload["results"][0]["label"] == FUNCTION_NAME

    def test_human_output_prints_the_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-query", FUNCTION_NAME, "--backend", "sqlite"])
        assert result.exit_code == 0, result.output
        assert FUNCTION_NAME in result.output
        assert "degree" in result.output

    def test_blank_query_prints_the_empty_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-query", "  ", "--backend", "sqlite"])
        assert result.exit_code == 0, result.output
        assert "No matching nodes" in result.output

    def test_unknown_backend_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["graph-query", FUNCTION_NAME, "--backend", "nope"])
        assert result.exit_code == 1
        assert "unknown graph backend" in result.output

    def test_backend_without_query_support_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        backend, _ = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        result = runner.invoke(cli.app, ["graph-query", FUNCTION_NAME, "--backend", "probe"])
        assert result.exit_code == 1
        assert "query-unsupported" in result.output

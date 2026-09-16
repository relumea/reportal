"""Tests for the knowledge-graph backend HTTP routes."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from graph_backend_helpers import recording_backend
from graph_helpers import FUNCTION_NAME, seed_corpus

from reportal import auth, graph, graph_backends, store
from reportal.graph_backends import COGNEE_INSTALL_HINT


@pytest.fixture(autouse=True)
def _isolate_graph_backends() -> Iterator[None]:
    """Reload the registry around each test, whatever a test registered."""
    graph_backends.refresh_graph_backends()
    yield
    graph_backends.refresh_graph_backends()


def _build(conn: sqlite3.Connection) -> int:
    ids = seed_corpus(conn)
    graph.build_graph(conn, binary_id=ids["binary"])
    return ids["binary"]


def _sync(binary_id: int, body: dict[str, Any] | None = None) -> tuple[str, dict[str, str], bytes]:
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    headers = {} if body is None else {"Content-Type": "application/json"}
    return wsgi_request("POST", f"/api/binaries/{binary_id}/graph/sync", body=raw, headers=headers)


def _query(query: str = "", backend: str = "") -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("GET", f"/api/graph/query?q={query}&backend={backend}")


class TestBackendsRoute:
    def test_lists_each_backend_with_availability(self, portal_db: Path) -> None:
        status, headers, raw = wsgi_request("GET", "/api/graph/backends")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        names = [entry["name"] for entry in payload["backends"]]
        assert names == ["sqlite", "cognee"]
        assert payload["default"] == "sqlite"
        sqlite = next(entry for entry in payload["backends"] if entry["name"] == "sqlite")
        assert sqlite["available"] is True
        assert sqlite["supports_query"] is True

    def test_cognee_is_reported_unavailable_with_the_hint(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        status, headers, raw = wsgi_request("GET", "/api/graph/backends")
        payload = json_body(raw, headers)
        cognee = next(entry for entry in payload["backends"] if entry["name"] == "cognee")
        assert cognee["available"] is False
        assert cognee["unavailable_reason"] == COGNEE_INSTALL_HINT


class TestSyncRoute:
    def test_sqlite_sync_reports_the_stored_counts(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = _build(conn)
        status, headers, raw = _sync(binary_id, {"backend": "sqlite"})
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["backend"] == "sqlite"
        assert payload["nodes"] == store.count_graph_nodes(conn, binary_id)
        assert payload["edges"] == store.count_graph_edges(conn, binary_id)
        assert payload["pushed_nodes"] == 0

    def test_absent_body_uses_the_configured_backend(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = _build(conn)
        status, headers, raw = _sync(binary_id)
        assert status.startswith("200")
        assert json_body(raw, headers)["backend"] == "sqlite"

    def test_env_configured_backend_is_used(
        self, conn: sqlite3.Connection, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _build(conn)
        backend, recorded = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        monkeypatch.setenv(graph_backends.BACKEND_ENV, "probe")
        status, headers, raw = _sync(binary_id)
        assert status.startswith("200")
        assert json_body(raw, headers)["backend"] == "probe"
        assert len(recorded) == 1

    def test_unknown_binary_is_404(self, portal_db: Path) -> None:
        status, headers, raw = _sync(4242, {"backend": "sqlite"})
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"

    def test_unknown_backend_is_404(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _build(conn)
        status, headers, raw = _sync(binary_id, {"backend": "nope"})
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "backend not found"

    def test_invalid_body_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _build(conn)
        status, headers, raw = _sync(binary_id, {"backend": 17})
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid body"

    def test_without_a_graph_is_404_no_graph(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        ids = seed_corpus(conn)
        status, headers, raw = _sync(ids["binary"], {"backend": "sqlite"})
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "no-graph"

    def test_unavailable_backend_is_503_with_the_hint(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = _build(conn)
        backend, _ = recording_backend(available=False, reason=COGNEE_INSTALL_HINT)
        graph_backends.register_graph_backend(backend, origin="test")
        status, headers, raw = _sync(binary_id, {"backend": "probe"})
        assert status.startswith("503")
        payload = json_body(raw, headers)
        assert payload["error"] == "backend-unavailable"
        assert "uv sync --extra cognee" in payload["detail"]

    def test_cognee_without_the_package_is_503_with_the_hint(
        self, conn: sqlite3.Connection, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _build(conn)
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        status, headers, raw = _sync(binary_id, {"backend": "cognee"})
        assert status.startswith("503")
        payload = json_body(raw, headers)
        assert payload["error"] == "backend-unavailable"
        assert payload["detail"] == COGNEE_INSTALL_HINT


class TestQueryRoute:
    def test_sqlite_query_returns_matching_nodes(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        _build(conn)
        status, headers, raw = _query(FUNCTION_NAME, "sqlite")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["backend"] == "sqlite"
        assert payload["count"] == 1
        assert payload["results"][0]["label"] == FUNCTION_NAME

    def test_query_defaults_to_the_configured_backend(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        _build(conn)
        status, headers, raw = _query(FUNCTION_NAME)
        assert status.startswith("200")
        assert json_body(raw, headers)["backend"] == "sqlite"

    def test_blank_query_returns_no_results(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        _build(conn)
        status, headers, raw = _query("", "sqlite")
        assert status.startswith("200")
        assert json_body(raw, headers)["count"] == 0

    def test_a_non_member_queries_no_team_nodes(
        self, conn: sqlite3.Connection, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _build(conn)
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, binary_id, visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _status, headers, raw = wsgi_request(
            "GET",
            f"/api/graph/query?q={FUNCTION_NAME}&backend=sqlite",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert json_body(raw, headers)["count"] == 0

        _status, headers, raw = wsgi_request(
            "GET",
            f"/api/graph/query?q={FUNCTION_NAME}&backend=sqlite",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert json_body(raw, headers)["count"] == 1

    def test_an_exact_hidden_id_answers_no_hits(
        self, conn: sqlite3.Connection, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _build(conn)
        nodes = store.list_graph_nodes(conn, binary_id)
        assert nodes, "the built graph holds nodes to query exactly"
        target = str(nodes[0]["id"])
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, binary_id, visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _status, headers, raw = wsgi_request(
            "GET",
            f"/api/graph/query?q={target}&backend=sqlite",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert json_body(raw, headers)["count"] == 0

        _status, headers, raw = wsgi_request(
            "GET",
            f"/api/graph/query?q={target}&backend=sqlite",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert json_body(raw, headers)["count"] == 1

    def test_unknown_backend_is_404(self, portal_db: Path) -> None:
        status, headers, raw = _query("x", "nope")
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "backend not found"

    def test_backend_without_query_support_is_400(self, portal_db: Path) -> None:
        backend, _ = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        status, headers, raw = _query("x", "probe")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "query-unsupported"

    def test_unavailable_backend_is_503(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        status, headers, raw = _query("x", "cognee")
        assert status.startswith("503")
        payload = json_body(raw, headers)
        assert payload["error"] == "backend-unavailable"
        assert payload["detail"] == COGNEE_INSTALL_HINT

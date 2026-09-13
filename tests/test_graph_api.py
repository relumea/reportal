"""Tests for the knowledge-graph HTTP routes."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request
from graph_helpers import (
    FLIRT_NAME,
    FUNCTION_NAME,
    LIBRARY_MODULE,
    SECOND_FUNCTION_NAME,
    STRUCT_NAME,
    node_id,
    seed_corpus,
)

from reportal import graph, store


def _build(binary_id: int) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("POST", f"/api/binaries/{binary_id}/graph")


def _get(binary_id: int, query: str = "") -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("GET", f"/api/binaries/{binary_id}/graph{query}")


def _node(node_id_value: str) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("GET", f"/api/graph/nodes/{node_id_value}")


class TestBuildRoute:
    def test_post_builds_and_returns_the_counts(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        ids = seed_corpus(conn)
        status, headers, raw = _build(ids["binary"])
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["binary_id"] == ids["binary"]
        assert payload["nodes"] == len(store.list_graph_nodes(conn, ids["binary"]))
        assert payload["edges"] == len(store.list_graph_edges(conn, ids["binary"]))
        assert payload["truncated"] is False
        assert payload["built_at"]

    def test_post_of_an_unknown_binary_is_404(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        status, headers, raw = _build(4242)
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"

    def test_rebuild_is_idempotent(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        ids = seed_corpus(conn)
        _, first_headers, first_raw = _build(ids["binary"])
        _, second_headers, second_raw = _build(ids["binary"])
        first = json_body(first_raw, first_headers)
        second = json_body(second_raw, second_headers)
        assert first["nodes"] == second["nodes"]
        assert first["edges"] == second["edges"]

    def test_post_reports_truncation(
        self,
        conn: sqlite3.Connection,
        portal_db: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ids = seed_corpus(conn)
        monkeypatch.setattr(graph, "MAX_GRAPH_NODES", 2)
        _, headers, raw = _build(ids["binary"])
        assert json_body(raw, headers)["truncated"] is True


class TestGetRoute:
    def test_before_a_build_answers_404_with_the_hint(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        ids = seed_corpus(conn)
        status, headers, raw = _get(ids["binary"])
        assert status.startswith("404")
        payload = json_body(raw, headers)
        assert payload["error"] == "no-graph"
        assert f"POST /api/binaries/{ids['binary']}/graph" in payload["detail"]

    def test_unknown_binary_is_404(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = _get(4242)
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"

    def test_payload_leaves_out_documents(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        ids = seed_corpus(conn)
        _build(ids["binary"])
        _, headers, raw = _get(ids["binary"])
        payload = json_body(raw, headers)
        assert {node["kind"] for node in payload["nodes"]} == {
            "binary",
            "function",
            "struct",
            "tag",
            "capability",
            "library",
        }
        assert payload["counts"]["document"] == 0

    def test_include_documents_adds_them(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        ids = seed_corpus(conn)
        _build(ids["binary"])
        _, headers, raw = _get(ids["binary"], "?include_documents=true")
        payload = json_body(raw, headers)
        assert payload["counts"]["document"] == 1
        assert "mentions" in {edge["rel"] for edge in payload["edges"]}

    def test_kind_filter_keeps_one_kind(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        ids = seed_corpus(conn)
        _build(ids["binary"])
        _, headers, raw = _get(ids["binary"], "?kind=struct")
        payload = json_body(raw, headers)
        assert [node["label"] for node in payload["nodes"]] == [STRUCT_NAME]

    def test_unknown_kind_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        ids = seed_corpus(conn)
        _build(ids["binary"])
        status, headers, raw = _get(ids["binary"], "?kind=widget")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid kind"

    def test_non_boolean_include_documents_is_400(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        ids = seed_corpus(conn)
        _build(ids["binary"])
        status, headers, raw = _get(ids["binary"], "?include_documents=maybe")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "include_documents must be a boolean"


class TestNodeRoute:
    def test_returns_the_node_and_its_groups(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        ids = seed_corpus(conn)
        _build(ids["binary"])
        status, headers, raw = _node(node_id(ids["binary"], "function", ids["first"]))
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["node"]["label"] == FUNCTION_NAME
        assert set(payload["incoming"]) == {"contains", "mentions"}
        assert payload["outgoing"]["matched-with"][0]["label"] == SECOND_FUNCTION_NAME

    def test_colons_in_the_node_id_route_correctly(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        ids = seed_corpus(conn)
        _build(ids["binary"])
        status, headers, raw = _node(node_id(ids["binary"], "library", LIBRARY_MODULE))
        assert status.startswith("200")
        assert json_body(raw, headers)["node"]["label"] == LIBRARY_MODULE

    def test_flirt_library_node_resolves(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        ids = seed_corpus(conn)
        _build(ids["binary"])
        status, headers, raw = _node(node_id(ids["binary"], "library", FLIRT_NAME))
        assert status.startswith("200")
        assert json_body(raw, headers)["incoming"]["identifies"][0]["kind"] == "binary"

    def test_unknown_node_is_404(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = _node("b1:function:999")
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "node not found"

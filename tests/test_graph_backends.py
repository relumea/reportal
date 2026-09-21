"""Tests for the pluggable graph-backend registry and its built-in backends."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from graph_backend_helpers import recording_backend
from graph_helpers import FUNCTION_NAME, seed_corpus
from plugin_helpers import EntryPoint as _EntryPoint
from plugin_helpers import patch_entry_points as _patch_entry_points

from reportal import graph, graph_backends, mcp_server, store
from reportal.graph_backends import (
    COGNEE_INSTALL_HINT,
    COGNEE_MODEL_REQUIRED_REASON,
    DEFAULT_BACKEND,
    DEFAULT_COGNEE_DATASET,
)


@pytest.fixture(autouse=True)
def _isolate_graph_backends() -> Iterator[None]:
    """Reload the registry around each test, whatever a test registered."""
    graph_backends.refresh_graph_backends()
    yield
    graph_backends.refresh_graph_backends()


def _built_graph(conn: sqlite3.Connection) -> int:
    """Seed the shared corpus, build its graph and return the binary id."""
    ids = seed_corpus(conn)
    graph.build_graph(conn, binary_id=ids["binary"])
    return ids["binary"]


def _mcp_call(name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
    """Run one MCP tool through the stdio server; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestRegistry:
    def test_builtin_backends_register_in_tree(self) -> None:
        names = [backend.name for backend in graph_backends.graph_backends()]
        assert names == ["sqlite", "cognee"]

    def test_register_graph_backend_adds_it(self) -> None:
        backend, _ = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        assert "probe" in [entry.name for entry in graph_backends.graph_backends()]

    def test_unregister_withdraws_one_entry(self) -> None:
        backend, _ = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        graph_backends.unregister_graph_backend("probe")
        names = [entry.name for entry in graph_backends.graph_backends()]
        assert "probe" not in names
        assert "sqlite" in names

    def test_unregister_unknown_name_raises(self) -> None:
        with pytest.raises(graph_backends.RegistryError):
            graph_backends.unregister_graph_backend("nope")

    def test_duplicate_name_raises_naming_both_origins(self) -> None:
        backend, _ = recording_backend()
        graph_backends.register_graph_backend(backend, origin="probe-plugin")
        with pytest.raises(graph_backends.RegistryError) as excinfo:
            graph_backends.register_graph_backend(backend, origin="rival-plugin")
        message = str(excinfo.value)
        assert "probe" in message
        assert "probe-plugin" in message
        assert "rival-plugin" in message

    def test_registering_a_non_backend_raises(self) -> None:
        with pytest.raises(graph_backends.RegistryError):
            graph_backends.register_graph_backend("nope")  # type: ignore[arg-type]

    def test_registering_an_empty_name_raises(self) -> None:
        backend, _ = recording_backend(name="")
        with pytest.raises(graph_backends.RegistryError):
            graph_backends.register_graph_backend(backend)

    def test_get_graph_backend_returns_the_registration(self) -> None:
        assert graph_backends.get_graph_backend("sqlite").name == "sqlite"

    def test_get_graph_backend_unknown_name_raises_with_known_names(self) -> None:
        with pytest.raises(graph_backends.UnknownBackendError) as excinfo:
            graph_backends.get_graph_backend("nope")
        error = excinfo.value
        assert isinstance(error, LookupError)
        assert error.name == "nope"
        assert "cognee" in error.known
        assert "sqlite" in str(error)

    def test_refresh_drops_a_directly_registered_backend(self) -> None:
        backend, _ = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        assert "probe" in [entry.name for entry in graph_backends.graph_backends()]
        assert "probe" not in [entry.name for entry in graph_backends.refresh_graph_backends()]

    def test_entry_point_backend_is_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(
            monkeypatch, _EntryPoint("plugin-probe", "graph_backend_plugins:PROBE_BACKEND")
        )
        assert "plugin-probe" in [entry.name for entry in graph_backends.refresh_graph_backends()]

    def test_entry_point_factory_is_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(
            monkeypatch, _EntryPoint("plugin-probe", "graph_backend_plugins:PROBE_FACTORY")
        )
        assert "plugin-probe" in [entry.name for entry in graph_backends.refresh_graph_backends()]

    def test_entry_point_broken_registration_is_skipped_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "graph_backend_plugins:NOT_A_BACKEND"))
        with caplog.at_level(logging.WARNING):
            names = [entry.name for entry in graph_backends.refresh_graph_backends()]
        assert "skipping bad reportal.graph_backends registration" in caplog.text
        assert "sqlite" in names

    def test_entry_point_without_a_module_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", ""))
        assert "sqlite" in [entry.name for entry in graph_backends.refresh_graph_backends()]

    def test_entry_point_with_an_unimportable_module_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "no_such_plugin_module:thing"))
        assert "sqlite" in [entry.name for entry in graph_backends.refresh_graph_backends()]

    def test_entry_point_with_a_missing_attribute_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "graph_backend_plugins:absent_attr"))
        assert "sqlite" in [entry.name for entry in graph_backends.refresh_graph_backends()]

    def test_entry_point_duplicating_a_builtin_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(
            monkeypatch, _EntryPoint("dup", "graph_backend_plugins:IMPOSTOR_BACKEND")
        )
        with pytest.raises(graph_backends.RegistryError):
            graph_backends.refresh_graph_backends()

    def test_refresh_picks_up_a_newly_registered_entry_point(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert "plugin-probe" not in [entry.name for entry in graph_backends.graph_backends()]
        _patch_entry_points(
            monkeypatch, _EntryPoint("plugin-probe", "graph_backend_plugins:PROBE_BACKEND")
        )
        assert "plugin-probe" in [entry.name for entry in graph_backends.refresh_graph_backends()]


class TestConfiguration:
    def test_default_backend_is_sqlite(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(graph_backends.BACKEND_ENV, raising=False)
        assert graph_backends.configured_backend_name() == DEFAULT_BACKEND

    def test_backend_env_overrides_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(graph_backends.BACKEND_ENV, "cognee")
        assert graph_backends.configured_backend_name() == "cognee"

    def test_dataset_default_and_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(graph_backends.COGNEE_DATASET_ENV, raising=False)
        assert graph_backends.cognee_dataset_name() == DEFAULT_COGNEE_DATASET
        monkeypatch.setenv(graph_backends.COGNEE_DATASET_ENV, "notepad")
        assert graph_backends.cognee_dataset_name() == "notepad"


class TestSqliteBackend:
    def test_describe_reports_available_and_query_support(self) -> None:
        report = graph_backends.get_graph_backend("sqlite").describe()
        assert report["name"] == "sqlite"
        assert report["available"] is True
        assert report["supports_query"] is True
        assert report["unavailable_reason"] == ""

    def test_sync_reports_the_stored_counts(self, conn: sqlite3.Connection) -> None:
        binary_id = _built_graph(conn)
        report = graph_backends.sync_graph(conn, binary_id=binary_id, backend_name="sqlite")
        assert report["backend"] == "sqlite"
        assert report["nodes"] == store.count_graph_nodes(conn, binary_id)
        assert report["edges"] == store.count_graph_edges(conn, binary_id)
        assert report["pushed_nodes"] == 0
        assert report["pushed_edges"] == 0

    def test_query_by_node_id_returns_its_degree(self, conn: sqlite3.Connection) -> None:
        binary_id = _built_graph(conn)
        target = f"b{binary_id}:function:1"
        result = graph_backends.run_query(
            graph_backends.get_graph_backend("sqlite"),
            conn,
            query=target,
            limit=graph_backends.DEFAULT_QUERY_LIMIT,
        )
        assert result["count"] == 1
        assert result["results"][0]["id"] == target
        assert result["results"][0]["degree"] > 0

    def test_query_by_text_matches_labels_across_binaries(self, conn: sqlite3.Connection) -> None:
        _built_graph(conn)
        result = graph_backends.run_query(
            graph_backends.get_graph_backend("sqlite"),
            conn,
            query=FUNCTION_NAME,
            limit=graph_backends.DEFAULT_QUERY_LIMIT,
        )
        assert result["count"] == 1
        assert result["results"][0]["label"] == FUNCTION_NAME

    def test_query_blank_returns_no_results(self, conn: sqlite3.Connection) -> None:
        _built_graph(conn)
        result = graph_backends.run_query(
            graph_backends.get_graph_backend("sqlite"),
            conn,
            query="   ",
            limit=graph_backends.DEFAULT_QUERY_LIMIT,
        )
        assert result["count"] == 0

    def test_query_wildcard_matches_literally(self, conn: sqlite3.Connection) -> None:
        binary_id = _built_graph(conn)
        store.add_graph_node(
            conn,
            node_id=f"b{binary_id}:tag:100%",
            binary_id=binary_id,
            kind="tag",
            key="100%",
            label="100%_tag",
        )
        backend = graph_backends.get_graph_backend("sqlite")
        hit = graph_backends.run_query(
            backend, conn, query="100%", limit=graph_backends.DEFAULT_QUERY_LIMIT
        )
        missed = graph_backends.run_query(
            backend, conn, query="0%t", limit=graph_backends.DEFAULT_QUERY_LIMIT
        )
        assert [row["label"] for row in hit["results"]] == ["100%_tag"]
        assert missed["count"] == 0


class TestCogneeBackend:
    def test_available_false_without_the_package(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        assert graph_backends.cognee_available() is False

    def test_available_true_when_the_spec_is_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: object())
        assert graph_backends.cognee_available() is True

    def test_describe_reports_the_install_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        report = graph_backends.get_graph_backend("cognee").describe()
        assert report["available"] is False
        assert report["supports_query"] is False
        assert report["unavailable_reason"] == COGNEE_INSTALL_HINT
        assert "uv sync --extra cognee" in report["unavailable_reason"]

    def test_sync_raises_backend_unavailable_with_the_hint(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _built_graph(conn)
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        with pytest.raises(graph_backends.BackendUnavailableError) as excinfo:
            graph_backends.get_graph_backend("cognee").sync(
                conn, binary_id=binary_id, payload={"nodes": [], "edges": []}
            )
        assert excinfo.value.reason == COGNEE_INSTALL_HINT
        assert excinfo.value.backend == "cognee"

    def test_translate_graph_maps_nodes_and_edges(self) -> None:
        payload = {
            "nodes": [
                {"id": "b1:binary:1", "kind": "binary", "key": "1", "label": "demo.exe"},
                {"id": "b1:function:2", "kind": "function", "key": "2", "label": "sub_1000"},
            ],
            "edges": [
                {
                    "source": "b1:binary:1",
                    "target": "b1:function:2",
                    "rel": "contains",
                    "weight": 1.0,
                }
            ],
        }
        translation = graph_backends.translate_graph(payload, binary_id=1)
        assert len(translation["nodes"]) == 2
        assert len(translation["edges"]) == 1
        assert translation["nodes"][1] == {
            "id": "b1:function:2",
            "kind": "function",
            "key": "2",
            "label": "sub_1000",
            "binary_id": 1,
        }
        assert translation["edges"][0]["rel"] == "contains"

    def test_cognee_records_serializes_each_record_as_json(self) -> None:
        translation: dict[str, Any] = {
            "nodes": [{"id": "b1:function:2", "kind": "function", "key": "2", "label": "sub_1000"}],
            "edges": [
                {
                    "source": "b1:binary:1",
                    "target": "b1:function:2",
                    "rel": "contains",
                    "weight": 1.0,
                }
            ],
        }
        records = graph_backends.cognee_records(translation, binary_id=1)
        assert len(records) == 2
        node = json.loads(records[0])
        edge = json.loads(records[1])
        assert node["record"] == "node"
        assert node["binary_id"] == 1
        assert node["label"] == "sub_1000"
        assert edge["record"] == "edge"
        assert edge["rel"] == "contains"

    def test_sync_pushes_through_a_fake_cognee_module(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _built_graph(conn)
        calls: list[tuple[str, Any]] = []
        module = types.ModuleType("cognee")

        class _MissingModelError(Exception):
            """Stand-in for cognee's missing-model error; no real import runs."""

        def add(records: list[str], *, dataset_name: str) -> None:
            calls.append(("add", {"dataset": dataset_name, "records": records}))

        def cognify(*, datasets: list[str]) -> None:
            calls.append(("cognify", {"datasets": datasets}))

        module.add = add  # type: ignore[attr-defined]
        module.cognify = cognify  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "cognee", module)
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: object())
        monkeypatch.setattr(
            graph_backends, "_cognee_missing_model_error", lambda: _MissingModelError
        )

        report = graph_backends.sync_graph(conn, binary_id=binary_id, backend_name="cognee")
        assert report["dataset"] == DEFAULT_COGNEE_DATASET
        assert report["pushed_nodes"] == report["nodes"]
        assert report["pushed_edges"] == report["edges"]
        assert [call[0] for call in calls] == ["add", "cognify"]
        records = calls[0][1]["records"]
        assert len(records) == report["nodes"] + report["edges"]
        assert all(isinstance(record, str) for record in records)
        assert json.loads(records[0])["record"] == "node"


class TestSyncGraph:
    def test_unknown_backend_raises(self, conn: sqlite3.Connection) -> None:
        binary_id = _built_graph(conn)
        with pytest.raises(graph_backends.UnknownBackendError):
            graph_backends.sync_graph(conn, binary_id=binary_id, backend_name="nope")

    def test_unavailable_backend_raises_with_its_reason(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _built_graph(conn)
        backend, _ = recording_backend(available=False, reason="needs a token")
        graph_backends.register_graph_backend(backend, origin="test")
        with pytest.raises(graph_backends.BackendUnavailableError) as excinfo:
            graph_backends.sync_graph(conn, binary_id=binary_id, backend_name="probe")
        assert excinfo.value.reason == "needs a token"

    def test_without_a_built_graph_raises(self, conn: sqlite3.Connection) -> None:
        ids = seed_corpus(conn)
        with pytest.raises(graph_backends.GraphNotBuiltError):
            graph_backends.sync_graph(conn, binary_id=ids["binary"], backend_name="sqlite")

    def test_defaults_to_the_configured_backend(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _built_graph(conn)
        backend, recorded = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        monkeypatch.setenv(graph_backends.BACKEND_ENV, "probe")
        report = graph_backends.sync_graph(conn, binary_id=binary_id, backend_name=None)
        assert report["backend"] == "probe"
        assert len(recorded) == 1

    def test_fake_backend_receives_the_translated_graph(self, conn: sqlite3.Connection) -> None:
        binary_id = _built_graph(conn)
        backend, recorded = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        report = graph_backends.sync_graph(conn, binary_id=binary_id, backend_name="probe")
        payload = recorded[0]
        assert len(payload["nodes"]) == report["nodes"]
        assert len(payload["edges"]) == report["edges"]
        labels = {node["label"] for node in payload["nodes"]}
        assert FUNCTION_NAME in labels
        sample = next(node for node in payload["nodes"] if node["label"] == FUNCTION_NAME)
        assert sample["kind"] == "function"
        assert sample["id"].startswith(f"b{binary_id}:function:")


class TestQueryDispatch:
    def test_backend_without_query_raises(self, conn: sqlite3.Connection) -> None:
        backend, _ = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        with pytest.raises(graph_backends.QueryUnsupportedError):
            graph_backends.run_query(backend, conn, query="x", limit=10)
        assert graph_backends.backend_supports_query(backend) is False

    def test_backend_with_query_is_dispatched(self, conn: sqlite3.Connection) -> None:
        backend, _ = recording_backend(supports_query=True)
        result = graph_backends.run_query(backend, conn, query="x", limit=10)
        assert result == {"backend": "probe", "query": "x", "count": 0, "results": []}


class TestMcpTools:
    def test_list_graph_backends_reports_the_registry(self, conn: sqlite3.Connection) -> None:
        payload, is_error = _mcp_call("list_graph_backends", {})
        assert is_error is False
        names = [entry["name"] for entry in payload["backends"]]
        assert names == ["sqlite", "cognee"]
        assert payload["default"] == DEFAULT_BACKEND

    def test_sync_graph_backend_syncs_through_a_fake(self, conn: sqlite3.Connection) -> None:
        binary_id = _built_graph(conn)
        backend, recorded = recording_backend()
        graph_backends.register_graph_backend(backend, origin="test")
        payload, is_error = _mcp_call(
            "sync_graph_backend", {"binary_id": binary_id, "backend": "probe"}
        )
        assert is_error is False
        assert payload["backend"] == "probe"
        assert payload["nodes"] == len(recorded[0]["nodes"])

    def test_sync_graph_backend_reports_a_binary_not_found(self, conn: sqlite3.Connection) -> None:
        payload, is_error = _mcp_call("sync_graph_backend", {"binary_id": 4242})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_sync_graph_backend_reports_backend_unavailable(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _built_graph(conn)
        monkeypatch.setattr(graph_backends, "find_spec", lambda name: None)
        payload, is_error = _mcp_call(
            "sync_graph_backend", {"binary_id": binary_id, "backend": "cognee"}
        )
        assert is_error is True
        assert payload["error"] == "backend-unavailable"
        assert "uv sync --extra cognee" in payload["detail"]


_COGNEE_REAL_ENV_KEYS = (
    "DATA_ROOT_DIRECTORY",
    "SYSTEM_ROOT_DIRECTORY",
    "CACHE_ROOT_DIRECTORY",
    "COGNEE_LOGS_DIR",
    "ENABLE_BACKEND_ACCESS_CONTROL",
    "CACHING",
    "COGNEE_SKIP_CONNECTION_TEST",
    "LLM_PROVIDER",
    "LLM_MODEL",
    "LLM_API_KEY",
)


def _cognee_env(root: Path) -> dict[str, str]:
    """The storage and no-model settings the real cognee package is imported with."""
    return {
        "DATA_ROOT_DIRECTORY": str(root / "data"),
        "SYSTEM_ROOT_DIRECTORY": str(root / "system"),
        "CACHE_ROOT_DIRECTORY": str(root / "cache"),
        "COGNEE_LOGS_DIR": str(root / "logs"),
        "ENABLE_BACKEND_ACCESS_CONTROL": "false",
        "CACHING": "false",
        "COGNEE_SKIP_CONNECTION_TEST": "true",
        "LLM_PROVIDER": "openai",
        "LLM_MODEL": "openai/gpt-5-mini",
    }


def _restore_env(saved: dict[str, str | None]) -> None:
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture(scope="module")
def real_cognee(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Any]:
    """Import cognee with its storage in a temporary root; skip when it is absent.

    No model is configured and the connection test is skipped, so ingestion
    runs while the graph build cannot.  The environment is restored afterwards.
    """
    root = tmp_path_factory.mktemp("cognee")
    saved = {key: os.environ.get(key) for key in _COGNEE_REAL_ENV_KEYS}
    os.environ.update(_cognee_env(root))
    os.environ.pop("LLM_API_KEY", None)
    try:
        module = pytest.importorskip("cognee")
    except BaseException:
        _restore_env(saved)
        raise
    yield module
    _restore_env(saved)


class TestCogneeRealPackage:
    def test_real_add_ingests_the_translated_records(self, real_cognee: Any) -> None:
        """A real ``cognee.add`` accepts the serialized records as documents.

        The connection test is skipped and no model is configured, so only
        ingestion is asserted here; the graph build needs a model and is
        asserted to fail through the backend in the sibling test.
        """
        translation = graph_backends.translate_graph(
            {
                "nodes": [
                    {"id": "b7:binary:1", "kind": "binary", "key": "1", "label": "demo.exe"},
                    {"id": "b7:function:2", "kind": "function", "key": "2", "label": "sub_1000"},
                ],
                "edges": [
                    {
                        "source": "b7:binary:1",
                        "target": "b7:function:2",
                        "rel": "contains",
                        "weight": 1.0,
                    }
                ],
            },
            binary_id=7,
        )
        records = graph_backends.cognee_records(translation, binary_id=7)
        report = asyncio.run(real_cognee.add(records, dataset_name="reportal_real"))
        assert report.status == "PipelineRunCompleted"
        assert report.dataset_name == "reportal_real"
        assert len(report.data_ingestion_info) == len(records)

    def test_real_sync_without_a_model_reports_the_named_failure(
        self, real_cognee: Any, conn: sqlite3.Connection
    ) -> None:
        """A real graph build needs a model; the backend reports that, not a traceback.

        With no LLM key configured, ``cognify`` raises cognee's missing-key
        error; ``cognee_sync`` turns it into ``BackendUnavailableError``, which
        the API and CLI already answer as ``backend-unavailable``.
        """
        binary_id = _built_graph(conn)
        with pytest.raises(graph_backends.BackendUnavailableError) as excinfo:
            graph_backends.sync_graph(conn, binary_id=binary_id, backend_name="cognee")
        assert excinfo.value.backend == "cognee"
        assert excinfo.value.reason == COGNEE_MODEL_REQUIRED_REASON
        assert "model" in excinfo.value.reason

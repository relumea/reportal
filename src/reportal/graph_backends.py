"""Pluggable knowledge-graph backends for the derived local graph.

:mod:`reportal.graph` owns the graph itself: it derives a deterministic node and
edge set from rows the store already holds.  This module is the seam that lets
that graph leave the process.  The local store is the built-in backend and the
default; an optional Cognee backend pushes the same payload into a Cognee
dataset, and it is active only when the ``cognee`` package is installed (the
``cognee`` extra).  The Cognee call is verified against the installed release
(cognee 1.5.4): ``add`` ingests the records as text documents and ``cognify``
builds cognee's graph, which needs a configured model.  Without one the backend
fails with :class:`BackendUnavailableError`, which every surface reports as
``backend-unavailable``.  A live model run and a hosted Cognee service are
outside what the tests exercise.

A backend is a :class:`GraphBackend`: a name, an ``available()`` check, a
``describe()`` report, a ``sync(conn, *, binary_id, payload)`` call and an
optional ``query(conn, *, query, limit)`` for backends that can answer node
lookups.  :func:`sync_graph` assembles the graph payload and hands it to the
selected backend; :func:`run_query` dispatches a query to a backend that
supports one.

The registry mirrors :mod:`reportal.components`: built-ins are declared in-tree
by :func:`builtin_graph_backends`, and a third party declares an entry point in
the :data:`GRAPH_BACKEND_ENTRY_POINT_GROUP` group whose value is
``module:attr`` naming a :class:`GraphBackend` or a zero-argument factory that
returns one.  A broken registration is skipped with a warning, and a duplicate
name raises :class:`RegistryError`.

A backend that is registered but not installed raises
:class:`BackendUnavailableError` carrying its install hint, which the API, CLI
and MCP surfaces report as ``backend-unavailable`` rather than a traceback.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import logging
import os
import sqlite3
import tomllib
from collections.abc import Callable, Coroutine, Iterable, Mapping
from dataclasses import dataclass
from importlib.util import find_spec
from typing import Any, Protocol, cast

from reportal import graph, plugins, store
from reportal._paths import MARKER, WorkspaceNotFound, project_root
from reportal.plugins import RegistryError as RegistryError

# Entry-point group third-party graph backends register in.
GRAPH_BACKEND_ENTRY_POINT_GROUP = "reportal.graph_backends"

# Origin label a built-in registration reports.
BUILTIN_ORIGIN = plugins.BUILTIN_ORIGIN

# Backend names reportal ships in-tree.
SQLITE_BACKEND_NAME = "sqlite"
COGNEE_BACKEND_NAME = "cognee"

# Import name the optional backend resolves, and the fixed hint every
# unavailable path reports.
COGNEE_MODULE = "cognee"
COGNEE_INSTALL_HINT = "install the optional extra: uv sync --extra cognee"

# Cognee builds its graph with an LLM; every sync without a configured model
# reports this instead of the library's traceback.
COGNEE_MODEL_REQUIRED_REASON = (
    "cognee needs a configured model to build the graph: set its LLM provider "
    "and API key (see https://docs.cognee.ai/)"
)

# Workspace reportal.toml table that carries the graph settings.
CONFIG_TABLE = "knowledge"

# Environment variables and reportal.toml keys selecting the default backend
# and the Cognee dataset.
BACKEND_ENV = "REPORTAL_GRAPH_BACKEND"
CONFIG_BACKEND = "graph_backend"
COGNEE_DATASET_ENV = "REPORTAL_COGNEE_DATASET"
CONFIG_COGNEE_DATASET = "cognee_dataset"

# The backend a sync defaults to when nothing configures one, and the Cognee
# dataset name the optional backend writes to.
DEFAULT_BACKEND = SQLITE_BACKEND_NAME
DEFAULT_COGNEE_DATASET = "reportal"

# Node matches a backend query returns when the caller names no limit.
DEFAULT_QUERY_LIMIT = 20

# Hard cap on a backend query, so a text search cannot scan a whole corpus.
MAX_QUERY_LIMIT = 200

_log = logging.getLogger(__name__)


class UnknownBackendError(LookupError):
    """No backend is registered under a requested name."""

    def __init__(self, name: str, known: Iterable[str]) -> None:
        self.name = name
        self.known = tuple(sorted(known))
        known_text = ", ".join(self.known) if self.known else "none"
        super().__init__(f"unknown graph backend {name!r}; known backends: {known_text}")


class BackendUnavailableError(RuntimeError):
    """A registered backend is not installed or not configured.

    ``reason`` is the fixed, actionable detail every surface reports; ``backend``
    names the registration the caller asked for.
    """

    def __init__(self, backend: str, reason: str) -> None:
        self.backend = backend
        self.reason = reason
        super().__init__(f"backend {backend!r} is unavailable: {reason}")


class QueryUnsupportedError(LookupError):
    """A backend was asked for a query it does not implement."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"graph backend {name!r} does not support query")


class GraphNotBuiltError(LookupError):
    """A binary has no stored graph to sync."""

    def __init__(self, binary_id: int) -> None:
        self.binary_id = binary_id
        super().__init__(
            f"no graph for binary {binary_id}; "
            f"run 'reportal graph-build {binary_id}' or POST /api/binaries/{binary_id}/graph"
        )


class SyncHandler(Protocol):
    """The ``sync`` call a backend performs: push one binary's graph payload."""

    def __call__(
        self, conn: sqlite3.Connection, *, binary_id: int, payload: dict[str, Any]
    ) -> dict[str, Any]: ...


class QueryHandler(Protocol):
    """The ``query`` call a backend supports, or None when it supports none."""

    def __call__(
        self,
        conn: sqlite3.Connection,
        *,
        query: str,
        limit: int,
        visible_to: Mapping[str, Any] | None = ...,
    ) -> dict[str, Any]: ...


def _no_unavailable_reason() -> str:
    """The reason an always-available backend reports; it is never used."""
    return ""


@dataclass(frozen=True)
class GraphBackend:
    """One knowledge-graph backend: how to check it, describe it and use it.

    ``available`` reports whether the backend can run; ``describe`` builds the
    wire report the registry surfaces, including ``unavailable_reason`` when it
    cannot.  ``sync`` pushes one binary's graph payload and returns a report.
    ``query`` is optional: it is None for a backend that cannot answer node
    lookups.
    """

    name: str
    description: str
    available: Callable[[], bool]
    sync: SyncHandler
    query: QueryHandler | None = None
    unavailable_reason: Callable[[], str] = _no_unavailable_reason

    def describe(self) -> dict[str, Any]:
        """The registry report: name, availability, description and query support."""
        is_available = self.available()
        return {
            "name": self.name,
            "available": is_available,
            "description": self.description,
            "unavailable_reason": "" if is_available else self.unavailable_reason(),
            "supports_query": self.query is not None,
        }


def _knowledge_table() -> dict[str, Any]:
    """The workspace ``reportal.toml`` ``[knowledge]`` table, or an empty object."""
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return {}
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    table = document.get(CONFIG_TABLE)
    return table if isinstance(table, dict) else {}


def configured_backend_name() -> str:
    """The backend a sync defaults to: the environment, then the config, then sqlite."""
    value = os.environ.get(BACKEND_ENV, "").strip()
    if value:
        return value
    value = str(_knowledge_table().get(CONFIG_BACKEND) or "").strip()
    return value or DEFAULT_BACKEND


def cognee_dataset_name() -> str:
    """The Cognee dataset name: the environment, then the config, then the default."""
    value = os.environ.get(COGNEE_DATASET_ENV, "").strip()
    if value:
        return value
    value = str(_knowledge_table().get(CONFIG_COGNEE_DATASET) or "").strip()
    return value or DEFAULT_COGNEE_DATASET


# ── The sqlite backend ─────────────────────────────────────────────


def sqlite_available() -> bool:
    """The local store is always available; it is what builds the graph."""
    return True


def sqlite_sync(
    conn: sqlite3.Connection, *, binary_id: int, payload: dict[str, Any]
) -> dict[str, Any]:
    """Report the graph the local store already holds; writes nothing.

    The store is the storage of record, so there is nothing to push: the report
    is the stored node and edge counts, with zero rows pushed.
    """
    return {
        "backend": SQLITE_BACKEND_NAME,
        "binary_id": binary_id,
        "nodes": store.count_graph_nodes(conn, binary_id),
        "edges": store.count_graph_edges(conn, binary_id),
        "pushed_nodes": 0,
        "pushed_edges": 0,
    }


def _node_result(node: dict[str, Any], degree: int) -> dict[str, Any]:
    """One query hit: the node's identity plus its stored edge count."""
    return {
        "id": node["id"],
        "kind": node["kind"],
        "key": node["key"],
        "label": node["label"],
        "degree": degree,
    }


def sqlite_query(
    conn: sqlite3.Connection,
    *,
    query: str,
    limit: int,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Query the stored local graph: an exact node id, else a label/key search.

    An exact node id adds nothing to the graph the GET node route does not:
    the one-hit result carries its stored degree.  Any other query is a
    substring match over every binary's node labels, keys and ids, capped at
    *limit*.  ``visible_to`` drops nodes on binaries the caller may not see,
    like the other scoped reads; an exact hidden id answers no hits.
    """
    from reportal import auth

    text = query.strip()
    bounded = min(max(limit, 1), MAX_QUERY_LIMIT)
    if not text:
        return {"backend": SQLITE_BACKEND_NAME, "query": text, "count": 0, "results": []}
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    visible: set[int] | None = None
    if scope is not None:
        clause, params = scope
        visible = {
            int(row["id"])
            for row in conn.execute(f"SELECT b.id AS id FROM binaries b WHERE {clause}", params)
        }
    exact = store.get_graph_node(conn, text)
    if exact is not None:
        if visible is not None and int(exact["binary_id"]) not in visible:
            return {"backend": SQLITE_BACKEND_NAME, "query": text, "count": 0, "results": []}
        degree = store.count_graph_edges_for_node(conn, text)
        results = [_node_result(exact, degree)]
        return {
            "backend": SQLITE_BACKEND_NAME,
            "query": text,
            "count": len(results),
            "results": results,
        }
    matches = store.search_graph_nodes(conn, needle=text, limit=bounded)
    if visible is not None:
        matches = [node for node in matches if int(node["binary_id"]) in visible]
    results = [
        _node_result(node, store.count_graph_edges_for_node(conn, str(node["id"])))
        for node in matches
    ]
    return {
        "backend": SQLITE_BACKEND_NAME,
        "query": text,
        "count": len(results),
        "results": results,
    }


def sqlite_backend() -> GraphBackend:
    """The built-in backend over the local SQLite graph."""
    return GraphBackend(
        name=SQLITE_BACKEND_NAME,
        description="the local deterministic graph in reportal's SQLite store (default)",
        available=sqlite_available,
        sync=sqlite_sync,
        query=sqlite_query,
    )


# ── The optional Cognee backend ────────────────────────────────────


def cognee_available() -> bool:
    """True when the optional ``cognee`` package is importable."""
    return find_spec(COGNEE_MODULE) is not None


def cognee_unavailable_reason() -> str:
    """The install hint an unavailable Cognee backend reports."""
    return COGNEE_INSTALL_HINT


def translate_graph(payload: dict[str, Any], *, binary_id: int) -> dict[str, list[dict[str, Any]]]:
    """Translate a graph payload into cognee node and edge records.

    One node per graph node carrying its id, kind, key and label, and one edge
    per relation carrying its endpoints, relation and weight.  The translation
    is pure and deterministic, so it is testable with no package installed and
    the same payload always produces the same records.
    """
    nodes = [
        {
            "id": str(node["id"]),
            "kind": str(node["kind"]),
            "key": str(node["key"]),
            "label": str(node["label"]),
            "binary_id": binary_id,
        }
        for node in payload.get("nodes", [])
    ]
    edges = [
        {
            "source": str(edge["source"]),
            "target": str(edge["target"]),
            "rel": str(edge["rel"]),
            "weight": float(edge["weight"]),
        }
        for edge in payload.get("edges", [])
    ]
    return {"nodes": nodes, "edges": edges}


def cognee_records(translation: dict[str, list[dict[str, Any]]], *, binary_id: int) -> list[str]:
    """Serialize translated node and edge records into cognee text documents.

    ``cognee.add`` ingests text, file handles and DataItems; a bare dict raises
    ``IngestionError: Data type not supported`` (verified against cognee
    1.5.4), so every record becomes one JSON document tagged with the binary
    and its record kind.
    """
    records: list[dict[str, Any]] = [
        {"record": "node", "binary_id": binary_id, **node} for node in translation["nodes"]
    ]
    records.extend(
        {"record": "edge", "binary_id": binary_id, **edge} for edge in translation["edges"]
    )
    return [json.dumps(record) for record in records]


def _maybe_await(value: Any) -> Any:
    """Run an awaitable cognee call to completion; pass anything else through."""
    if inspect.isawaitable(value):
        return asyncio.run(cast(Coroutine[Any, Any, Any], value))
    return value


def _cognee_missing_model_error() -> type[Exception]:
    """The error the installed cognee raises when no model is configured.

    Imported lazily so this module never imports the optional package until a
    sync needs it.
    """
    from cognee.infrastructure.llm.exceptions import LLMAPIKeyNotSetError

    return cast(type[Exception], LLMAPIKeyNotSetError)


def _push_to_cognee(module: Any, *, dataset: str, records: list[str]) -> None:
    """Hand the serialized graph to cognee as one dataset and build its graph.

    ``add`` stores the records as documents; ``cognify`` then builds cognee's
    graph, which needs a configured model.  Without one cognee raises its
    missing-key error, reported as an unavailable backend so the API and CLI
    answer ``backend-unavailable`` instead of a traceback.
    """
    missing_model = _cognee_missing_model_error()
    try:
        _maybe_await(module.add(records, dataset_name=dataset))
        _maybe_await(module.cognify(datasets=[dataset]))
    except missing_model as exc:
        raise BackendUnavailableError(COGNEE_BACKEND_NAME, COGNEE_MODEL_REQUIRED_REASON) from exc


def cognee_sync(
    conn: sqlite3.Connection, *, binary_id: int, payload: dict[str, Any]
) -> dict[str, Any]:
    """Push one binary's graph payload into a Cognee dataset.

    Raises :class:`BackendUnavailableError` carrying the install hint when the
    optional package is absent, and the model requirement when cognee has no
    model configured; importing nothing until then.
    """
    if not cognee_available():
        raise BackendUnavailableError(COGNEE_BACKEND_NAME, COGNEE_INSTALL_HINT)
    dataset = cognee_dataset_name()
    translation = translate_graph(payload, binary_id=binary_id)
    records = cognee_records(translation, binary_id=binary_id)
    module = importlib.import_module(COGNEE_MODULE)
    _push_to_cognee(module, dataset=dataset, records=records)
    nodes = len(translation["nodes"])
    edges = len(translation["edges"])
    return {
        "backend": COGNEE_BACKEND_NAME,
        "binary_id": binary_id,
        "dataset": dataset,
        "nodes": nodes,
        "edges": edges,
        "pushed_nodes": nodes,
        "pushed_edges": edges,
    }


def cognee_backend() -> GraphBackend:
    """The optional Cognee backend: no query, and unavailable until installed."""
    return GraphBackend(
        name=COGNEE_BACKEND_NAME,
        description="push the graph into a Cognee dataset (optional cognee extra)",
        available=cognee_available,
        sync=cognee_sync,
        unavailable_reason=cognee_unavailable_reason,
    )


def builtin_graph_backends() -> tuple[GraphBackend, ...]:
    """The in-tree backends, the local store first."""
    return (sqlite_backend(), cognee_backend())


# ── Registry ───────────────────────────────────────────────────────

_registry: dict[str, GraphBackend] = {}
_origins: dict[str, str] = {}
_builtins_loaded = False
_entry_points_loaded = False


def register_graph_backend(backend: GraphBackend, *, origin: str = BUILTIN_ORIGIN) -> None:
    """Register *backend* under its own name.

    Raises :class:`RegistryError` for a malformed value or a name that is
    already taken, naming both origins (single-source discipline).
    """
    if not isinstance(backend, GraphBackend):
        raise RegistryError(
            f"bad graph backend registration from {origin}: expected a GraphBackend,"
            f" got {type(backend).__name__}"
        )
    if not backend.name.strip():
        raise RegistryError(f"bad graph backend registration from {origin}: empty name")
    if not callable(backend.available) or not callable(backend.sync):
        raise RegistryError(
            f"bad graph backend registration {backend.name!r} from {origin}:"
            " available and sync must be callable"
        )
    if backend.name in _registry:
        raise RegistryError(
            f"duplicate graph backend registration {backend.name!r}: {origin} conflicts"
            f" with {_origins[backend.name]} (single-source discipline)"
        )
    _registry[backend.name] = backend
    _origins[backend.name] = origin


def graph_backends() -> tuple[GraphBackend, ...]:
    """Every registered backend, built-ins first, in registration order."""
    _ensure_builtins()
    _ensure_entry_points()
    return tuple(_registry.values())


def unregister_graph_backend(name: str) -> None:
    """Withdraw the graph backend registered as *name*.

    Raises :class:`RegistryError` for a name nothing holds, and
    :class:`UnknownBackendError` is left to lookups.  Withdrawing a built-in
    lasts until the next :func:`refresh_graph_backends`.
    """
    _ensure_builtins()
    _ensure_entry_points()
    if name not in _registry:
        raise RegistryError(f"no graph backend registration {name!r} to withdraw")
    del _registry[name]
    _origins.pop(name, None)


def refresh_graph_backends() -> tuple[GraphBackend, ...]:
    """Discard discovered backends and re-run discovery.

    Built-ins are re-declared and the entry-point group is scanned again, which
    is how a long-lived process picks up a plugin installed after startup.
    """
    global _builtins_loaded, _entry_points_loaded
    _registry.clear()
    _origins.clear()
    _builtins_loaded = False
    _entry_points_loaded = False
    return graph_backends()


def get_graph_backend(name: str) -> GraphBackend:
    """The backend registered under *name*; raises :class:`UnknownBackendError`."""
    _ensure_builtins()
    _ensure_entry_points()
    backend = _registry.get(name)
    if backend is None:
        raise UnknownBackendError(name, _registry)
    return backend


def backend_supports_query(backend: GraphBackend) -> bool:
    """True when *backend* implements the optional query call."""
    return backend.query is not None


def run_query(
    backend: GraphBackend,
    conn: sqlite3.Connection,
    *,
    query: str,
    limit: int,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run *query* against *backend*; raises :class:`QueryUnsupportedError`.

    ``visible_to`` is forwarded to handlers that accept it (the built-in
    sqlite one does); a third-party handler keeps its own signature and
    receives only what it declares.
    """
    handler = backend.query
    if handler is None:
        raise QueryUnsupportedError(backend.name)
    try:
        return handler(conn, query=query, limit=limit, visible_to=visible_to)
    except TypeError:
        return handler(conn, query=query, limit=limit)


def sync_graph(
    conn: sqlite3.Connection, *, binary_id: int, backend_name: str | None = None
) -> dict[str, Any]:
    """Hand one binary's stored graph to a backend and return its report.

    *backend_name* defaults to :func:`configured_backend_name`.  Raises
    :class:`UnknownBackendError` for an unknown name,
    :class:`BackendUnavailableError` for a backend that is not installed and
    :class:`GraphNotBuiltError` when the binary has no stored graph yet.  The
    payload carries every node kind, document nodes included, so a backend sees
    the whole graph rather than the view the HTTP GET defaults to.
    """
    backend = get_graph_backend(backend_name or configured_backend_name())
    if not backend.available():
        raise BackendUnavailableError(backend.name, backend.unavailable_reason())
    if store.count_graph_nodes(conn, binary_id) == 0:
        raise GraphNotBuiltError(binary_id)
    payload = graph.graph_payload(conn, binary_id=binary_id, include_documents=True)
    return backend.sync(conn, binary_id=binary_id, payload=payload)


def _ensure_builtins() -> None:
    """Load the in-tree backends once."""
    global _builtins_loaded
    if _builtins_loaded:
        return
    _builtins_loaded = True
    for backend in builtin_graph_backends():
        register_graph_backend(backend, origin=BUILTIN_ORIGIN)


def _ensure_entry_points() -> None:
    """Load third-party backends once, skipping a broken registration."""
    global _entry_points_loaded
    if _entry_points_loaded:
        return
    _entry_points_loaded = True
    for name, value, backend in plugins.load(
        GRAPH_BACKEND_ENTRY_POINT_GROUP, GraphBackend, "GraphBackend"
    ):
        # A duplicate name is not skipped: two backends claiming one name is a
        # registry error, and the RegistryError says which registration lost.
        register_graph_backend(backend, origin=plugins.origin(name, value))

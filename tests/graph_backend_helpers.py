"""Shared fakes for the graph-backend tests."""

from __future__ import annotations

import sqlite3
from typing import Any

from reportal.graph_backends import GraphBackend


def recording_backend(
    name: str = "probe",
    *,
    available: bool = True,
    reason: str = "",
    supports_query: bool = False,
) -> tuple[GraphBackend, list[dict[str, Any]]]:
    """A backend that records every payload it is handed, for in-process tests.

    Returns the backend and the list its ``sync`` appends each received graph
    payload to, so a test can assert the exact translation a backend saw.  The
    report it returns is shaped like the built-ins': node and edge counts plus
    the pushed counts.
    """
    recorded: list[dict[str, Any]] = []

    def _available() -> bool:
        return available

    def _reason() -> str:
        return reason

    def _sync(
        conn: sqlite3.Connection, *, binary_id: int, payload: dict[str, Any]
    ) -> dict[str, Any]:
        recorded.append(payload)
        nodes = len(payload["nodes"])
        edges = len(payload["edges"])
        return {
            "backend": name,
            "binary_id": binary_id,
            "nodes": nodes,
            "edges": edges,
            "pushed_nodes": nodes,
            "pushed_edges": edges,
        }

    def _query(conn: sqlite3.Connection, *, query: str, limit: int) -> dict[str, Any]:
        return {"backend": name, "query": query, "count": 0, "results": []}

    return (
        GraphBackend(
            name=name,
            description="a recording backend",
            available=_available,
            sync=_sync,
            query=_query if supports_query else None,
            unavailable_reason=_reason,
        ),
        recorded,
    )

"""Plugin surface the graph-backend registry tests load through entry points."""

from __future__ import annotations

import sqlite3
from typing import Any

from reportal.graph_backends import GraphBackend


def _available() -> bool:
    return True


def _sync(conn: sqlite3.Connection, *, binary_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {"backend": "plugin-probe", "binary_id": binary_id, "nodes": 0, "edges": 0}


def probe_backend() -> GraphBackend:
    """A registered backend the entry-point tests resolve, directly or as a factory."""
    return GraphBackend(
        name="plugin-probe",
        description="a plugin backend",
        available=_available,
        sync=_sync,
    )


PROBE_BACKEND = probe_backend()

# A factory named by an entry point; discovery calls it.
PROBE_FACTORY = probe_backend

# A backend claiming a built-in name: the registry must reject it.
IMPOSTOR_BACKEND = GraphBackend(
    name="sqlite",
    description="claims the built-in name",
    available=_available,
    sync=_sync,
)

# A bare value that is not a backend.
NOT_A_BACKEND = 42

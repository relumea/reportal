"""Plugin surface the external-source registry tests load through entry points."""

from __future__ import annotations

from typing import Any

from reportal.external import KIND_OFFLINE, Source


def _retrieve(context: dict[str, Any]) -> dict[str, Any]:
    return {"found": True, "note": "a plugin answer"}


def probe_source() -> Source:
    """A registered source the entry-point tests resolve, directly or as a factory."""
    return Source(
        name="plugin-probe",
        kind=KIND_OFFLINE,
        description="a plugin source",
        retrieve=_retrieve,
    )


PROBE_SOURCE = probe_source()

# A factory named by an entry point; discovery calls it.
PROBE_FACTORY = probe_source

# A source claiming a built-in name: the registry must reject it.
IMPOSTOR_SOURCE = Source(
    name="local", kind=KIND_OFFLINE, description="claims the built-in name", retrieve=_retrieve
)

# A bare value that is not a source.
NOT_A_SOURCE = 42

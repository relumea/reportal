"""The plugin seams this portal exposes, read from the live registries.

reportal is assembled from replaceable parts, and every kind of part registers
through its own entry-point group, so a third party extends the portal without
editing its source.  :func:`inventory` is the inventory of those seams: one row
per seam naming the group, the module that declares the built-ins, what the
group contributes, and one row per part the registry currently holds.

Every value comes from the registry itself rather than a list kept here, so the
inventory cannot describe parts this process did not load.  A registry that
tracks where a part came from reports its origin; one that does not reports no
origin rather than guessing, and ``module`` names the in-tree declaration for
the built-ins so a reader can tell a built-in from a third-party part by its
absence from that module.

Nothing here starts a part, changes one or touches a binary: the inventory is a
read of five registries, and each part's own ``describe``-style fields
(availability, reloadability, a write plan, an annotation) are what a reader
sees.
"""

from __future__ import annotations

from typing import Any

from reportal import (
    auto_workers,
    components,
    effects,
    external,
    graph_backends,
    mcp_tools,
    models,
    sandbox,
)

# The module that declares each seam's built-in parts, and the entry-point group
# a third party registers through.  Both come from the registry modules, so a
# renamed group is a rename here too.
SEAMS: tuple[dict[str, str], ...] = (
    {
        "name": "pipeline components",
        "group": components.COMPONENT_ENTRY_POINT_GROUP,
        "module": "reportal.pipeline",
        "contributes": "steps a pipeline run can activate, each with the names it requires and "
        "provides",
    },
    {
        "name": "auto-mode workers",
        "group": auto_workers.WORKER_ENTRY_POINT_GROUP,
        "module": "reportal.auto_workers",
        "contributes": "strategies one auto-mode task can run a batch of functions with",
    },
    {
        "name": "graph backends",
        "group": graph_backends.GRAPH_BACKEND_ENTRY_POINT_GROUP,
        "module": "reportal.graph_backends",
        "contributes": "stores a knowledge graph can be synced to and queried from",
    },
    {
        "name": "effect handlers",
        "group": effects.EFFECT_ENTRY_POINT_GROUP,
        "module": "reportal.effects",
        "contributes": "the inverse of one undo-descriptor kind, which is how a third-party "
        "write becomes revertible",
    },
    {
        "name": "MCP tools",
        "group": mcp_tools.TOOL_ENTRY_POINT_GROUP,
        "module": "reportal.mcp_tools",
        "contributes": "tools an MCP client can call, annotated read-only or destructive",
    },
    {
        "name": "external sources",
        "group": external.SOURCE_ENTRY_POINT_GROUP,
        "module": "reportal.external",
        "contributes": "one third-party answer about a stored binary, offline or fetched",
    },
    {
        "name": "models",
        "group": models.MODEL_ENTRY_POINT_GROUP,
        "module": "reportal.models",
        "contributes": "one thing that can produce a stored result, with its kind and availability",
    },
    {
        "name": "sandbox runners",
        "group": sandbox.RUNNER_ENTRY_POINT_GROUP,
        "module": "reportal.sandbox",
        "contributes": "an isolated way to run one stored sample, off unless the workspace opts in",
    },
)


def _component_parts() -> list[dict[str, Any]]:
    """One row per registered component, with its origin and reloadability."""
    return [
        {
            "name": entry.component.name,
            "detail": (
                f"requires {', '.join(sorted(entry.component.requires)) or 'nothing'};"
                f" provides {', '.join(sorted(entry.component.provides)) or 'nothing'}"
            ),
            "origin": entry.origin,
            "reloadable": entry.reloadable,
        }
        for entry in components.registrations()
    ]


def _worker_parts() -> list[dict[str, Any]]:
    """One row per registered worker, naming whether it plans its own writes."""
    return [
        {
            "name": worker.name,
            "detail": worker.description,
            "origin": "",
            "plans_writes": worker.planned_paths is not None,
        }
        for worker in auto_workers.workers()
    ]


def _backend_parts() -> list[dict[str, Any]]:
    """One row per registered graph backend, with its availability."""
    return [
        {
            "name": backend.name,
            "detail": backend.description,
            "origin": "",
            "available": backend.available(),
            "unavailable_reason": backend.unavailable_reason(),
            "queryable": backend.query is not None,
        }
        for backend in graph_backends.graph_backends()
    ]


def _effect_parts() -> list[dict[str, Any]]:
    """One row per registered effect handler, naming the kind it reverses."""
    builtin = set(effects.builtin_effect_handlers())
    return [
        {
            "name": kind,
            "detail": "reverses one descriptor of this kind",
            "origin": "",
            "builtin": kind in builtin,
        }
        for kind in effects.effect_handlers()
    ]


def _source_parts() -> list[dict[str, Any]]:
    """One row per registered external source, with its kind and availability."""
    return [
        {
            "name": source.name,
            "detail": source.description,
            "origin": "",
            "kind": source.kind,
            "available": source.available(),
            "unavailable_reason": "" if source.available() else source.unavailable_reason(),
        }
        for source in external.sources()
    ]


def _model_parts() -> list[dict[str, Any]]:
    """One row per registered model, with its kind and availability."""
    return [
        {
            "name": model.name,
            "detail": model.description,
            "origin": "",
            "kind": model.kind,
            "version": model.version,
            "available": model.available(),
            "unavailable_reason": "" if model.available() else model.unavailable_reason(),
        }
        for model in models.models()
    ]


def _runner_parts() -> list[dict[str, Any]]:
    """One row per registered sandbox runner, with its availability."""
    return [
        {
            "name": runner.name,
            "detail": runner.describe,
            "origin": "",
            "available": runner.available(),
            "unavailable_reason": "" if runner.available() else runner.hint,
        }
        for runner in sandbox.registered_runners()
    ]


def _tool_parts() -> list[dict[str, Any]]:
    """One row per MCP tool, with its destructive annotation."""
    return [
        {
            "name": tool.name,
            "detail": tool.description,
            "origin": "",
            "destructive": bool(tool.annotations.destructive_hint),
        }
        for tool in mcp_tools.builtin_tools()
    ]


# The part reader each seam's rows come from, keyed by the seam's name.
PART_READERS = {
    "pipeline components": _component_parts,
    "auto-mode workers": _worker_parts,
    "graph backends": _backend_parts,
    "effect handlers": _effect_parts,
    "MCP tools": _tool_parts,
    "external sources": _source_parts,
    "models": _model_parts,
    "sandbox runners": _runner_parts,
}

# A seam's name is the key of :data:`PART_READERS`, so the two cannot disagree.
for _seam in SEAMS:
    if _seam["name"] not in PART_READERS:
        raise RuntimeError(f"seam {_seam['name']!r} has no part reader")


def inventory() -> dict[str, Any]:
    """Every plugin seam and the parts each registry currently holds."""
    seams: list[dict[str, Any]] = []
    for seam in SEAMS:
        parts = PART_READERS[seam["name"]]()
        seams.append({**seam, "parts": parts, "count": len(parts)})
    return {"seams": seams, "count": len(seams)}


def tool_totals() -> dict[str, int]:
    """MCP tool counts by annotation, the numbers the README states."""
    tools = mcp_tools.builtin_tools()
    destructive = sum(1 for tool in tools if tool.annotations.destructive_hint)
    return {"total": len(tools), "read_only": len(tools) - destructive, "destructive": destructive}

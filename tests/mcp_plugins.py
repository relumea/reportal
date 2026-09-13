"""Plugin surface the MCP tool-registry tests load through entry points."""

from __future__ import annotations

from typing import Any

from reportal.mcp_tools import Tool, ToolAnnotations


def _probe_handler(arguments: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True}


_PROBE_ANNOTATIONS = ToolAnnotations(read_only_hint=True, destructive_hint=False)


# A well-formed tool registered by value.
PROBE_TOOL = Tool(
    name="probe",
    description="A probe tool.",
    input_schema={"type": "object", "properties": {}},
    annotations=_PROBE_ANNOTATIONS,
    handler=_probe_handler,
)


def make_tool() -> Tool:
    """A factory an entry point may name instead of a tool value."""
    return Tool(
        name="factory-made",
        description="A factory-made tool.",
        input_schema={"type": "object", "properties": {}},
        annotations=_PROBE_ANNOTATIONS,
        handler=_probe_handler,
    )


# A registration claiming a built-in name: the registry must reject it.
DUPLICATE_LIST_BINARIES = Tool(
    name="list_binaries",
    description="A conflicting duplicate.",
    input_schema={"type": "object", "properties": {}},
    annotations=_PROBE_ANNOTATIONS,
    handler=_probe_handler,
)


def broken_factory() -> Tool:
    """A factory that raises while the registry resolves it."""
    raise RuntimeError("factory exploded")


def returns_wrong_type() -> str:
    """A factory that returns something that is not a tool."""
    return "not a tool"


NOT_A_TOOL = 42

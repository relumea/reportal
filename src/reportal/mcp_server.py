"""Stdio MCP server for reportal.

The protocol is the official ``mcp`` SDK's: it owns the JSON-RPC 2.0 framing,
the stdio transport, ``initialize`` and its version negotiation, the tool
catalogue and the tool call.  reportal supplies what only reportal knows -- the
tool registry in :mod:`reportal.mcp_tools` -- through the two handlers below, so
the wire behaviour is the SDK's while the tools stay the portal's.

The tools call reportal's internal functions directly and never make an HTTP
request back into reportal.  Every server message goes to stdout, which is the
SDK's; diagnostics go to stderr through the logging module.  ``run_server``
drives the transport from one ``anyio`` run, so the CLI stays synchronous.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from reportal import __version__, mcp_tools
from reportal.mcp_tools import Tool, ToolError

# Identity reported by ``initialize``.  The hosted portal reports the same
# three-key shape (``reveng-ai-platform``, version ``dev``); this local server
# names itself reportal.
SERVER_NAME = "reportal"
SERVER_TITLE = "reportal"
SERVER_VERSION = __version__

# One-line primer an MCP client may surface to its user.
SERVER_INSTRUCTIONS = (
    "reportal exposes a local reverse-engineering portal: binaries, functions,"
    " disassembly, decompilation, scans, matching and scoped conversations."
)

_log = logging.getLogger(__name__)


def tool_descriptor(tool: Tool) -> types.Tool:
    """Serialize one registry tool as the SDK's ``Tool``."""
    return types.Tool(
        name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        annotations=types.ToolAnnotations(
            read_only_hint=tool.annotations.read_only_hint,
            destructive_hint=tool.annotations.destructive_hint,
        ),
    )


def call_tool(name: str, arguments: Mapping[str, Any] | None = None) -> tuple[Any, bool]:
    """Run one registered tool: its payload and whether it failed.

    A request the protocol refuses -- an unknown tool, an argument that is not
    an object, a missing required one -- raises :class:`mcp.shared.exceptions.MCPError`
    with ``INVALID_PARAMS``, which the SDK answers as a JSON-RPC error.  A
    handler's own failure is a *tool* error instead: the payload says so and the
    caller sets ``isError``, so one bad call never ends the session.
    """
    tool = mcp_tools.get_tool(name)
    if tool is None:
        raise MCPError(INVALID_PARAMS, f"Unknown tool: {name}")
    if arguments is None:
        given: dict[str, Any] = {}
    elif isinstance(arguments, Mapping):
        given = dict(arguments)
    else:
        raise MCPError(INVALID_PARAMS, "tools/call arguments must be an object")
    required = tool.input_schema.get("required", [])
    missing = [key for key in required if key not in given]
    if missing:
        raise MCPError(
            INVALID_PARAMS, f"Invalid params: missing required argument(s): {', '.join(missing)}"
        )
    try:
        return tool.handler(given), False
    except ToolError as exc:
        return {"error": exc.error, "detail": exc.detail}, True
    except Exception as exc:  # a failing handler is a tool error, not a crashed loop
        _log.warning("tool %s raised", name, exc_info=exc)
        return {"error": "internal-error", "detail": str(exc)}, True


def _result(payload: Any, is_error: bool) -> types.CallToolResult:
    """Wrap a tool payload in the MCP result an agent reads."""
    return types.CallToolResult(
        content=[
            types.TextContent(type="text", text=json.dumps(payload, indent=2, sort_keys=True))
        ],
        is_error=is_error,
    )


async def _list_tools(context: Any, params: Any) -> types.ListToolsResult:
    """The whole registry, as ``tools/list``."""
    return types.ListToolsResult(tools=[tool_descriptor(tool) for tool in mcp_tools.tools()])


async def _call_tool(context: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    """Run one tool, as ``tools/call``."""
    payload, is_error = call_tool(params.name, params.arguments)
    return _result(payload, is_error)


def build_server() -> Server:
    """Build the MCP server over the live tool registry."""
    return Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        title=SERVER_TITLE,
        instructions=SERVER_INSTRUCTIONS,
        on_list_tools=_list_tools,
        on_call_tool=_call_tool,
    )


async def serve(
    instream: anyio.AsyncFile[str] | None = None,
    outstream: anyio.AsyncFile[str] | None = None,
) -> None:
    """Serve the session over *instream*/*outstream*, or the process streams."""
    server = build_server()
    async with stdio_server(stdin=instream, stdout=outstream) as (read, write):
        await server.run(read, write, server.create_initialization_options())


def run_server() -> int:
    """Run the stdio loop until the client closes it."""
    anyio.run(serve)
    return 0

"""MCP server for reportal.

The protocol is the official ``mcp`` SDK's: it owns the JSON-RPC 2.0 framing,
the transports, ``initialize`` and its version negotiation, the tool
catalogue and the tool call.  reportal supplies what only reportal knows -- the
tool registry in :mod:`reportal.mcp_tools` -- through the two handlers below, so
the wire behaviour is the SDK's while the tools stay the portal's.

The tools call reportal's internal functions directly and never make an HTTP
request back into reportal.  Stdio is the local pipe (`reportal mcp`);
Streamable HTTP is the same registry at ``/mcp``, gated by the portal bearer
when auth is on.  POST answers JSON; GET with ``Accept: text/event-stream``
is the SSE session stream, resumed through :class:`MemoryEventStore`.
Diagnostics go to stderr through the logging module.  ``run_server`` drives
the stdio transport from one ``anyio`` run, so the CLI stays synchronous.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http import EventCallback, EventId, EventMessage, EventStore, StreamId
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, JSONRPCMessage

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

# HTTP path the Streamable HTTP transport is mounted at.  Auth is the same
# bearer as ``/api`` (loopback operator while auth is off).
HTTP_PATH = "/mcp"

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


class MemoryEventStore(EventStore):
    """In-process event log so a GET stream can resume after ``Last-Event-ID``.

    Process-local, unbounded.  A restart drops the log, which is the same
    lifetime as the Streamable HTTP session manager.  Priming events
    (``message is None``) are stored for id continuity and skipped on
    replay: the SDK's live GET stream sends those as empty-data SSE, and
    ``EventMessage.message`` cannot be None.  Replay stays on the stream
    ``last_event_id`` belongs to.
    """

    def __init__(self) -> None:
        self._events: list[tuple[EventId, StreamId, JSONRPCMessage | None]] = []
        self._next = 1
        self._lock = asyncio.Lock()
        # ponytail: unbounded process-local log; ring-buffer if a long-lived
        # process retains sessions.

    async def store_event(self, stream_id: StreamId, message: JSONRPCMessage | None) -> EventId:
        async with self._lock:
            event_id = str(self._next)
            self._next += 1
            self._events.append((event_id, stream_id, message))
            return event_id

    async def replay_events_after(
        self, last_event_id: EventId, send_callback: EventCallback
    ) -> StreamId | None:
        async with self._lock:
            snapshot = list(self._events)
        started = False
        stream_id: StreamId | None = None
        for event_id, sid, message in snapshot:
            if not started:
                if event_id == last_event_id:
                    started = True
                    stream_id = sid
                continue
            if sid != stream_id:
                continue
            if message is None:
                continue
            await send_callback(EventMessage(message, event_id))
        return stream_id


def http_session_manager() -> StreamableHTTPSessionManager:
    """A Streamable HTTP manager over the live tool registry.

    POST stays one JSON-RPC reply so a bearer client can collect the body
    without an open stream.  GET with ``Accept: text/event-stream`` is the
    SDK's SSE session stream, resumed through :class:`MemoryEventStore`.
    """
    return StreamableHTTPSessionManager(
        build_server(), json_response=True, event_store=MemoryEventStore()
    )


@asynccontextmanager
async def http_lifespan() -> AsyncIterator[StreamableHTTPSessionManager]:
    """Run the HTTP session manager for the life of the FastAPI app."""
    manager = http_session_manager()
    async with manager.run():
        yield manager

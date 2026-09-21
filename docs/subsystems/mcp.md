# MCP server and tool registry

Sources: src/reportal/mcp_server.py, src/reportal/mcp_tools.py

This subsystem owns the Model Context Protocol surface: the tool registry and the stdio and
Streamable HTTP transports that expose it. The `mcp` SDK owns the wire protocol (framing, version
negotiation, dispatch); reportal supplies the tool catalogue and the handlers, which call reportal
internals directly and never make an HTTP request back into reportal.

## Vocabulary

- `mcp_tools.Tool`: a frozen dataclass of `name`, `description`, `input_schema`, `annotations` and
  `handler`. The schema is what the registry validates, so the model is offered exactly the
  arguments a call accepts.
- `mcp_tools.ToolAnnotations`: `read_only_hint` and `destructive_hint`, the gate an agent run reads.
- `mcp_tools.ToolError`: a fixed `error` code plus a `detail`; the server serializes it as an MCP
  tool error (`isError: true`).
- `mcp_tools.TOOL_ENTRY_POINT_GROUP` (`reportal.mcp_tools`) and `BUILTIN_ORIGIN` name where a
  registration came from. `register_tool`, `tools`, `get_tool`, `unregister_tool` and
  `refresh_tools` are the sub-registry.
- `mcp_server.MemoryEventStore`: in-process SSE replay, bounded by `MAX_REPLAY_EVENTS`. The HTTP
  mount path is `server.MCP_PATH` (`/mcp`).
- `mcp_server.build_server`, `run_server`, `call_tool` and `tool_descriptor` are the SDK facing
  seam. `logging/setLevel` sets the `reportal` stderr logger; `notifications/message` is not
  pushed.

## Wiring

- CLI: `reportal mcp [--json]`, newline-delimited JSON-RPC 2.0 on stdin and stdout. The readiness
  line goes to stderr.
- HTTP: `POST /mcp` (JSON replies) and `GET /mcp` (SSE session stream, `Last-Event-ID` resume),
  bearer gated when auth is on, because the registry mixes readers and writers.
- Registration: `builtin_tools()` declares the in-tree set; a third party declares an entry point in
  `reportal.mcp_tools` naming a `Tool` or a zero-argument factory.
- Counts: `tests/test_mcp.py` pins 267 built-in tools, 124 read-only and 143 destructive.

## Invariants

- Only protocol JSON reaches stdout; diagnostics go to stderr through the logging module.
  `logging/setLevel` sets that logger's floor. `tests/test_mcp.py`.
- A broken entry-point registration is skipped with a warning; a duplicate name raises
  `RegistryError`. `tests/test_mcp.py`.
- A read tool stays stored-only and never runs an engine the matching `GET` route would not.
  `tests/test_mcp.py`.
- A handler's own failure is a tool error and does not end the session; an unknown tool, bad
  arguments or a missing required one is a JSON-RPC `INVALID_PARAMS` error. `tests/test_mcp.py`.
- The pinned counts move only with the registry, in the same change that adds or removes a tool.
  `tests/test_mcp.py`.

## See also

- [ARCHITECTURE.md, MCP server](../ARCHITECTURE.md#mcp-server)
- [ARCHITECTURE.md, Components](../ARCHITECTURE.md#components)
- [MCP_TOOLS.md](../MCP_TOOLS.md) (generated: every registered tool and its access hint)
- [CLI.md](../CLI.md)

# Adding an MCP tool

Prerequisites: read the registry in [mcp_tools.py](../../src/reportal/mcp_tools.py) (`Tool`,
`ToolAnnotations`, `register_tool`, `builtin_tools`), the shared discovery in
[plugins.py](../../src/reportal/plugins.py), and
[ARCHITECTURE.md](../ARCHITECTURE.md#mcp-server).

## Steps

1. Write the handler as a module-level function taking one argument and returning a payload:

   ```python
   def _tool_get_unpack(arguments: dict[str, Any]) -> dict[str, Any]:
   ```

   A refusal raises `ToolError(error, detail)` with a fixed code; an unknown id uses the same code
   the HTTP route uses (`"binary not found"`).
2. Call the internals directly (`store.get_binary(conn, ...)`, `firmware.carve(...)`). Never call
   back into the HTTP API.
3. Declare the tool in `builtin_tools()` in `src/reportal/mcp_tools.py`, read tools first:

   ```python
   Tool(
       "get_unpack",
       "Return the stored unpack pass of one binary, with each member it extracted.",
       _object({"binary_id": _BINARY_ID}, ("binary_id",)),
       _READ,
       _tool_get_unpack,
   ),
   ```

   `_object(properties, required)` builds the input schema. `_int`, `_str`, `_bool`, `_number` and
   `_string_map` build property schemas.
4. Annotate the tool with `_READ` when it only reads stored rows, and `_WRITE` when it writes.
   `_WRITE` carries `destructive_hint=True`; `_READ` carries `read_only_hint=True`.
5. Add the tool name to `_READ_ONLY_TOOLS` or `_DESTRUCTIVE_TOOLS` in `tests/test_mcp.py` and raise
   the pinned counts in `test_builtin_tools_cover_every_capability`: `280` total, `132` read-only,
   `148` destructive.
6. Add the name to `_EXPECTED_TOOLS` in the same test. The description must say what the tool does,
   not restate its name: the test fails a description whose words are all in the name.

A third-party tool registers through the `reportal.mcp_tools` entry-point group whose value is
`module:attr` naming a `Tool` or a zero-argument factory returning one. A duplicate name raises
`RegistryError`; a broken registration is skipped with a warning.

## Verify

1. `.venv/bin/python -m pytest tests/test_mcp.py -q` proves the registry is well formed, the counts
   are pinned, the annotations match the read/write split and the stdio server answers
   `tools/list`.
2. `.venv/bin/python -m pytest tests/test_api_docs.py -q` proves a tool that adds no route left the
   reference honest.
3. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#mcp-server)
- [API.md](../API.md)

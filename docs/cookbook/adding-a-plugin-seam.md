# Adding a plugin seam

Prerequisites: read [plugins.py](../../src/reportal/plugins.py) (`items`, `origin`, `load`,
`resolve`, `expects`, `RegistryError`, `BUILTIN_ORIGIN`) and one existing seam end to end, such as
[graph_backends.py](../../src/reportal/graph_backends.py) (`GraphBackend`,
`GRAPH_BACKEND_ENTRY_POINT_GROUP`, `register_graph_backend`, `refresh_graph_backends`,
`builtin_graph_backends`).
[ARCHITECTURE.md](../ARCHITECTURE.md#graph-backends) and
[COMPONENTS.md](../COMPONENTS.md) describe the parts already shipped.

## Steps

1. Define the part as a frozen dataclass or a `Protocol`, with a `name` and the behavior the
   registry dispatches to: `GraphBackend` carries `name`, `available()`, `describe()` and
   `sync(...)`. The seam's value is the part itself, not its behavior.
2. Declare the entry-point group as a module constant named `<THING>_ENTRY_POINT_GROUP`, whose value
   is `reportal.<thing>` (`GRAPH_BACKEND_ENTRY_POINT_GROUP = "reportal.graph_backends"`).
3. Keep the built-ins in the module and return them from a `builtin_<thing>s()` function. A built-in
   registers with `origin=BUILTIN_ORIGIN`.
4. Register through one function that validates before it stores:
   `register_graph_backend(backend, *, origin=BUILTIN_ORIGIN)` refuses a value of the wrong type, an
   empty name and a duplicate name, and raises `RegistryError`. A duplicate names both origins
   (`plugins.origin(name, value)` builds the plugin's), because two parts claiming one name is a
   composition error rather than a broken plugin.
5. Load the built-ins once and the entry points once, with the same shape as the existing seams:
   `_ensure_builtins()` registers the in-tree set, and `_ensure_entry_points()` walks
   `plugins.load(GROUP, PartType, "PartType")`. A broken registration is skipped with a warning by
   `plugins.resolve`; only a duplicate reaches `RegistryError`.
6. Expose the read and lifecycle functions: `graph_backends()` (built-ins first, in declaration
   order), `get_graph_backend(name)`, `unregister_graph_backend(name)` and
   `refresh_graph_backends()` (clears both loaded flags and re-runs discovery, which is how a
   long-lived process picks up an installed plugin).
7. Declare the seam in `SEAMS` in [integrations.py](../../src/reportal/integrations.py) with its
   `name`, `group`, the `module` that declares the built-ins and what it `contributes`. That is what
   `GET /api/integrations` and the `list_integrations` MCP tool report.
8. A seam whose discovery should be reloadable records the declaring module and entry-point key in
   its registration, as `components.register_component` does for `reload_component`; an
   in-process registration passes neither and is not reloadable.

## Verify

1. `.venv/bin/python -m pytest tests/test_graph_backends.py -q` is the seam's own suite; copy its
   shape into a new `tests/test_<thing>.py`. It patches `plugins.entry_points` and asserts a plugin
   value registers, a factory is called, a duplicate raises and each broken value is skipped.
2. `.venv/bin/python -m pytest tests/test_integrations.py -q` proves every seam group in `SEAMS`
   resolves to a live registry.
3. `.venv/bin/python -m pytest tests/test_import_order.py -q` proves the new module still imports in
   a fresh interpreter.
4. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#graph-backends)
- [COMPONENTS.md](../COMPONENTS.md)

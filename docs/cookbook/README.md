# Cookbook

Step-by-step guides for one change each: the seam to extend, the files to
touch, and the numbered command that proves the change. Every guide ends at the
gate command that covers it. The rationale for a seam lives in
[ARCHITECTURE.md](../ARCHITECTURE.md); a guide links it instead of restating it.

| Guide | Adds |
|-------|------|
| [adding-an-http-route.md](adding-an-http-route.md) | a `/api/*` JSON route with its scope check and docs row |
| [adding-an-mcp-tool.md](adding-an-mcp-tool.md) | one MCP tool in the registry, read-only or destructive |
| [adding-a-component.md](adding-a-component.md) | a pipeline component with its context, journal and revert |
| [adding-an-effect-handler.md](adding-an-effect-handler.md) | one effect kind and the handler that reverts it |
| [adding-an-auto-worker.md](adding-an-auto-worker.md) | a worker that turns one function into a result |
| [adding-a-pipeline-stage.md](adding-a-pipeline-stage.md) | a stage in the AI decompilation pipeline |
| [adding-a-cli-command.md](adding-a-cli-command.md) | a Typer command with `--json` on stdout |
| [adding-an-spa-view.md](adding-an-spa-view.md) | a lazily loaded view in the SPA |
| [adding-a-setting.md](adding-a-setting.md) | one setting with its environment variable and `reportal.toml` key |
| [adding-an-error-code.md](adding-an-error-code.md) | one error code, its `doc_url` anchor and its catalogue row |
| [adding-a-store-table.md](adding-a-store-table.md) | a table with its schema, CRUD and data-model row |
| [adding-a-plugin-seam.md](adding-a-plugin-seam.md) | a registry backed by entry points, with its built-ins |

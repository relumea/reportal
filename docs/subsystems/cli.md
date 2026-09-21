# CLI

Sources: src/reportal/cli.py, src/reportal/customer_cli.py

The `reportal` Typer surface: every command and what it reads or writes. Human chrome goes to
stderr through `Console(stderr=True)`; `--json` writes one JSON object to stdout. Pipeable text
bodies (`disasm`, `decompile`, `ai-decompile`, `ai-decompilation`, `yara`, `snort`, `stix`,
`sbom`, `symbols-export`, `decompiler-script`, `conversation-events`) also go to stdout in
human mode. A refusal prints the error and exits non-zero. `reportal-customer` is the thin
platform client: `upload`, `binaries`, `functions`, reads and notes over HTTP only.

## Vocabulary

- `app`: the `typer.Typer` instance; `main()` is what `python -m reportal` calls.
- `_MARKER_TEMPLATE`: the commented `reportal.toml` `init` writes.
- `_require_lan_auth(portal_db)`: refuses a non-loopback `serve` bind unless `auth.required()` and
  an enabled user with a token exist.
- `console`: the stderr Rich console.
- Shared helpers: `_print_settings`, `_print_doctor`, `_print_journal_action`, `_print_doc_block`,
  `_db_path`, `_fail`, `_require_confirmation`, `_emit_export_body`.

## Wiring

`init`, `serve`, `config`, `doctor`, `mcp`, `backup`/`restore`/`backup-info`/`backup-prune`, `stats`,
`import-rebrew`, ingest and search, the scan family (`triage` through `flirt-apply`, `detect`,
`related`, `composition`, `function-triage`), identity (`user-*`, `team-*`, `organisation-*`,
`*-scope`), and secrets (`secrets-set`/`list`/`rm`). `docs --json` prints `docs.pages()` or one
`docs.page(slug)`; `config --json` merges `instance.describe()` with `settings.report()`.

## Invariants

- `init` writes the marker, `store.init_db`, and `_paths.WORKSPACE_DIRS`; existing ones stay
  (`tests/test_cli.py`).
- `serve --host` refuses non-loopback without auth and an enabled token user (`tests/test_cli.py`).
- `serve`, `mcp` and `config` refuse when `settings.failing()` is set; `config` exits 1
  (`tests/test_settings.py`, `tests/test_cli.py`).
- Every command and option is in `docs/CLI.md`, with no extras (`tests/test_cli_docs.py`).
- Human status stays on stderr; pipeable bodies are the only human-mode stdout
  (`tests/test_cli.py`, `tests/test_remediation.py`).
- Confirmed deletes (`team-rm`, `user-rm`, `organisation-rm`, `bulk-delete`,
  `analysis-bulk-delete`, `restore`) refuse under `--json` without `--yes`
  (`tests/test_teams.py`, `tests/test_backup.py`).
- `sandbox --report` and `--status` refuse each other (`tests/test_sandbox.py`).

## See also

- [CLI.md](../CLI.md)
- [ARCHITECTURE.md section](../ARCHITECTURE.md#process-layout)

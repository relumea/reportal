# Adding a CLI command

Prerequisites: read [cli.py](../../src/reportal/cli.py) (`app`, `console`, `json_body` helpers
`_db_path`, `_fail`, `_cli_fail`, `_cli_require_binary`, `_print_journal_action`), the Typer section
of [ARCHITECTURE.md](../ARCHITECTURE.md#process-layout), and
[CLI.md](../CLI.md).

## Steps

1. Write the command beside its siblings in `src/reportal/cli.py`:

   ```python
   @app.command("analysis-tags")
   def analysis_tags_command(
       analysis_id: int = typer.Argument(..., help="Analysis id"),
       json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
   ) -> None:
   ```

   The docstring becomes the command help, so it says what the command does and what it writes.
   `activity_command` is a full reference: it opens the store, builds a payload and prints it two
   ways.
2. Give every option a `typer.Option` with an explicit `--name` and a `help` string. A boolean that
   turns something off is written `--no-<x>`; `tests/test_cli_docs.py` treats `--no-x` as the same
   option stem as `--x`.
3. Accept `--json` on the command. Human output goes to `console` (`Console(stderr=True)`);
   machine output goes to stdout with `typer.echo(json.dumps(payload))`, then `return`.
4. Resolve the workspace with `_db_path(json_output)`, and refuse a missing database with
   `_fail(...)`. Refuse a bad value with `_cli_fail(status, error=..., detail=..., json_output=...)`
   so the JSON mode prints the error envelope instead of prose.
5. Journal a write with `journal.new_action()` and `journal.journaled(conn, action)`, then print the
   action id with `_print_journal_action(log, json_output)`.
6. Add a synopsis line to `docs/CLI.md` under the `# Command reference` heading, in the fenced
   block, naming every option:

   ```text
   reportal analysis-tags <id> [--json]       # the tags on the analysis's binary
   ```

   The line must start with `reportal <command path>`, and its indented continuation lines carry
   the rest of the option list.

## Verify

1. `.venv/bin/python -m pytest tests/test_cli_docs.py -q` proves every command has a synopsis line
   in `docs/CLI.md` and every option appears in that line.
2. `.venv/bin/python -m pytest tests/test_cli.py -q` exercises the command through the Typer test
   runner.
3. `.venv/bin/reportal <command> --help` prints the usage to stdout with no escape codes while
   `tests/test_cli_docs.py` checks the same property for every command.
4. `make check-fast` is the gate for the change.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#process-layout)
- [CLI.md](../CLI.md)

"""The customer CLI is a thin platform client, never a workspace tool."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from reportal import customer_cli


class TestHelp:
    def test_help_lists_the_customer_path(self) -> None:
        result = CliRunner().invoke(customer_cli.app, ["--help"])
        assert result.exit_code == 0
        assert "upload" in result.stdout
        assert "binaries" in result.stdout
        assert "import-rebrew" not in result.stdout
        assert "rebrew" not in result.stdout.lower()

    def test_every_command_help_is_pipeable(self) -> None:
        for name in (
            "binaries",
            "binary",
            "upload",
            "functions",
            "function",
            "matches",
            "scans",
            "rename",
            "comment-add",
            "collections",
        ):
            result = CliRunner().invoke(customer_cli.app, [name, "--help"])
            assert result.exit_code == 0, name
            assert "Usage:" in result.stdout, name


class TestNoLocalState:
    def test_missing_token_fails_without_touching_a_workspace(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            customer_cli.app,
            ["binaries", "--server", "http://127.0.0.1:1", "--json"],
            env={},
        )
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert "token" in payload["error"]

    def test_unreachable_server_is_one_error(self) -> None:
        result = CliRunner().invoke(
            customer_cli.app,
            ["binary", "1", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert "error" in payload

    def test_module_imports_no_server_logic(self) -> None:
        import ast

        source = Path(customer_cli.__file__ or "").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for name in ("reportal.store", "reportal.engines", "reportal.server", "reportal.api"):
            assert name not in imported, name

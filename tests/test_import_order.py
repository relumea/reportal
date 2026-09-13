"""Every entry module must import first, in a fresh interpreter.

A circular import is invisible to a suite that always loads the same module
first.  ``reportal.mcp_tools`` builds the tool registry and
``reportal.integrations`` reads that registry, so a module-level import of one
from the other made ``from reportal import mcp_server`` fail with a partially
initialized module in any process where nothing had loaded ``integrations``
first — the MCP server could not start, while every test in this suite passed
because they import ``reportal.api`` first.

The only honest check is a fresh interpreter per module, which is what this
test does.
"""

from __future__ import annotations

import subprocess
import sys

# The entry points a user reaches plus the modules that were circular.
MODULES: tuple[str, ...] = (
    "reportal.api",
    "reportal.cli",
    "reportal.mcp_server",
    "reportal.mcp_tools",
    "reportal.integrations",
    "reportal.webapp",
)

IMPORT_TIMEOUT_SECONDS = 60


class TestFreshInterpreterImports:
    def test_each_module_imports_first(self) -> None:
        for module in MODULES:
            result = subprocess.run(
                [sys.executable, "-c", f"import {module}"],
                capture_output=True,
                text=True,
                timeout=IMPORT_TIMEOUT_SECONDS,
                check=False,
            )
            assert result.returncode == 0, (
                f"importing {module} first failed with {result.returncode}:"
                f"\n{result.stderr.strip()}"
            )

    def test_the_mcp_server_starts_and_lists_the_integrations_tool(self) -> None:
        """The MCP chain answers a tools/list that includes the seam inventory."""
        script = (
            "from reportal import mcp_server;"
            "payload, is_error = mcp_server.call_tool('list_integrations', {});"
            "print(is_error, payload['count'] > 0)"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=IMPORT_TIMEOUT_SECONDS,
            check=False,
        )
        assert result.returncode == 0, result.stderr.strip()
        assert result.stdout.strip() == "False True"

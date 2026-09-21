"""Tests for the plugin-seam inventory (module, HTTP route, CLI and MCP tool)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import (
    auto_workers,
    cli,
    components,
    debug,
    effects,
    external,
    graph_backends,
    integrations,
    mcp_tools,
    models,
    sandbox,
)

runner = CliRunner()


def _seam(payload: dict[str, Any], name: str) -> dict[str, Any]:
    seams = payload["seams"]
    assert isinstance(seams, list)
    for seam in seams:
        assert isinstance(seam, dict)
        if seam["name"] == name:
            return seam
    raise AssertionError(f"no seam named {name!r}")


class TestInventory:
    def test_every_seam_is_a_registered_group(self) -> None:
        groups = {entry["group"] for entry in integrations.SEAMS}
        assert groups == {
            components.COMPONENT_ENTRY_POINT_GROUP,
            auto_workers.WORKER_ENTRY_POINT_GROUP,
            graph_backends.GRAPH_BACKEND_ENTRY_POINT_GROUP,
            effects.EFFECT_ENTRY_POINT_GROUP,
            mcp_tools.TOOL_ENTRY_POINT_GROUP,
            sandbox.RUNNER_ENTRY_POINT_GROUP,
            models.MODEL_ENTRY_POINT_GROUP,
            external.SOURCE_ENTRY_POINT_GROUP,
            debug.BACKEND_ENTRY_POINT_GROUP,
        }

    def test_counts_match_the_registries(self) -> None:
        payload = integrations.inventory()
        assert payload["count"] == len(integrations.SEAMS)
        for seam in payload["seams"]:
            parts = seam["parts"]
            assert seam["count"] == len(parts)
            for part in parts:
                assert part["name"]
                assert isinstance(part["detail"], str)

    def test_pipeline_seam_reports_every_registered_component(self) -> None:
        payload = integrations.inventory()
        expected = {entry.component.name for entry in components.registrations()}
        assert {part["name"] for part in _seam(payload, "pipeline components")["parts"]} == expected

    def test_component_parts_carry_their_origin(self) -> None:
        """Only the component registry tracks origins; the rest report none."""
        payload = integrations.inventory()
        parts = _seam(payload, "pipeline components")["parts"]
        assert all(part["origin"] for part in parts)
        for part in _seam(payload, "auto-mode workers")["parts"]:
            assert part["origin"] == ""

    def test_effect_handler_parts_name_a_kind_and_its_registration(self) -> None:
        payload = integrations.inventory()
        parts = {part["name"]: part for part in _seam(payload, "effect handlers")["parts"]}
        assert set(parts) == set(effects.effect_handlers())
        assert parts[effects.EFFECT_FILE_WRITE]["builtin"] is True

    def test_backend_parts_report_availability_and_queryability(self) -> None:
        payload = integrations.inventory()
        parts = {part["name"]: part for part in _seam(payload, "graph backends")["parts"]}
        assert parts[graph_backends.DEFAULT_BACKEND]["available"] is True
        assert parts[graph_backends.DEFAULT_BACKEND]["queryable"] is True

    def test_tool_totals_match_the_registry_annotations(self) -> None:
        totals = integrations.tool_totals()
        tools = mcp_tools.builtin_tools()
        assert totals["total"] == len(tools)
        assert totals["read_only"] + totals["destructive"] == len(tools)
        payload = integrations.inventory()
        parts = _seam(payload, "MCP tools")["parts"]
        assert len(parts) == len(tools)
        assert sum(1 for part in parts if part["destructive"]) == totals["destructive"]

    def test_inventory_is_json_serializable(self) -> None:
        assert json.loads(json.dumps(integrations.inventory()))["count"] == len(integrations.SEAMS)


class TestRoute:
    def test_get_returns_the_inventory(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        del conn, tmp_path
        status, headers, body = wsgi_request("GET", "/api/integrations")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == len(integrations.SEAMS)
        assert _seam(payload, "MCP tools")["count"] == len(mcp_tools.builtin_tools())

    def test_get_keeps_no_journal_entry(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        """A read carries no undo id, and the same probe finds one on a write."""
        del tmp_path
        status, headers, body = wsgi_request("GET", "/api/integrations")
        assert status.startswith("200")
        assert "journal_action" not in json_body(body, headers)

        created = wsgi_request(
            "POST",
            "/api/tags",
            body=json.dumps({"name": "integrations-probe"}),
            headers={"Content-Type": "application/json"},
        )
        assert created[0].startswith("2")
        assert "journal_action" in json_body(created[2], created[1])
        del conn


class TestCli:
    def test_json_output_matches_the_module(self) -> None:
        result = runner.invoke(cli.app, ["integrations", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload == integrations.inventory()

    def test_terminal_output_names_a_seam_and_its_group(self) -> None:
        result = runner.invoke(cli.app, ["integrations"])
        assert result.exit_code == 0
        assert "pipeline components" in result.output
        assert components.COMPONENT_ENTRY_POINT_GROUP in result.output


class TestMcpTool:
    def test_list_integrations_is_read_only(self) -> None:
        tool = next(tool for tool in mcp_tools.builtin_tools() if tool.name == "list_integrations")
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False

    def test_tool_returns_the_inventory(self) -> None:
        from reportal import mcp_server

        payload, is_error = mcp_server.call_tool("list_integrations", {})
        assert is_error is False
        assert payload["count"] == len(integrations.SEAMS)

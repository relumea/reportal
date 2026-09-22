"""Tests for the composed attack-surface read."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import attack_surface, cli, journal, mcp_tools, store

runner = CliRunner()

CAPABILITIES = {
    "binary_id": 1,
    "capabilities": [
        {
            "name": "networking",
            "description": "Opens or accepts network connections",
            "confidence": "high",
            "evidence": [{"kind": "import", "value": "connect"}],
            "evidence_count": 1,
        },
        {
            "name": "file-io",
            "description": "Reads or writes files",
            "confidence": "high",
            "evidence": [{"kind": "import", "value": "CreateFileW"}],
            "evidence_count": 1,
        },
        {
            "name": "crypto",
            "description": "Uses cryptographic algorithms or APIs",
            "confidence": "medium",
            "evidence": [{"kind": "string", "value": "AES"}],
            "evidence_count": 1,
        },
    ],
    "count": 3,
}

PROTOCOLS = {
    "binary_id": 1,
    "protocols": [
        {
            "protocol": "https",
            "description": "HTTP over TLS",
            "confidence": "high",
            "evidence": [{"kind": "import", "value": "HttpSendRequestW"}],
            "ports": [443],
        }
    ],
    "count": 1,
    "by_confidence": {"high": 1, "medium": 0},
    "notes": [],
}

FILESYSTEM = {
    "binary_id": 1,
    "findings": [
        {
            "kind": "import",
            "name": "CreateFileW",
            "detail": "file-create",
            "confidence": "high",
            "count": 1,
        }
    ],
    "count": 1,
    "by_confidence": {"high": 1, "medium": 0},
}

THREAT = {
    "binary_id": 1,
    "iocs": {
        "urls": [{"value": "http://evil.example/x", "kind": "url", "source_va": 1}],
        "domains": [],
        "ipv4": [{"value": "203.0.113.7", "kind": "ipv4", "source_va": 2}],
        "emails": [],
        "registry_paths": [],
        "file_paths": [],
        "hashes": [],
    },
    "ioc_counts": {},
    "techniques": [],
    "narrative": None,
    "notes": [],
}


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, scans: bool = True) -> int:
    """A stored binary with (optionally) the attack-surface source scans."""
    source = tmp_path / "sample.exe"
    source.write_bytes(b"MZ" + b"\x00" * 4096)
    binary_id = store.add_binary(
        conn,
        sha256="d" * 64,
        name="sample.exe",
        path=str(source),
        size=source.stat().st_size,
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    if scans:
        store.set_scan(conn, analysis_id, store.SCAN_KIND_CAPABILITIES, dict(CAPABILITIES))
        store.set_scan(conn, analysis_id, store.SCAN_KIND_PROTOCOLS, dict(PROTOCOLS))
        store.set_scan(conn, analysis_id, store.SCAN_KIND_EXECUTION, dict(FILESYSTEM))
        store.set_scan(conn, analysis_id, store.SCAN_KIND_THREAT, dict(THREAT))
    return binary_id


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


class TestComposition:
    def test_network_carries_protocols_capabilities_and_iocs(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = attack_surface.attack_surface(conn, binary_id)

        assert payload["available"] is True
        names = [row["name"] for row in payload["network"]["rows"]]
        assert "https" in names
        assert "networking" in names
        assert "http://evil.example/x" in names
        assert "203.0.113.7" in names

    def test_local_input_carries_behavior_and_capabilities(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = attack_surface.attack_surface(conn, binary_id)

        names = [row["name"] for row in payload["local_input"]["rows"]]
        assert "CreateFileW" in names
        assert "file-io" in names

    def test_crypto_carries_the_capability(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = attack_surface.attack_surface(conn, binary_id)

        assert [row["name"] for row in payload["crypto"]["rows"]] == ["crypto"]

    def test_every_row_names_its_source_scan(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = attack_surface.attack_surface(conn, binary_id)

        for group in ("network", "local_input", "crypto"):
            for row in payload[group]["rows"]:
                assert row["source"]

    def test_a_binary_with_no_scans_is_not_available(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        payload = attack_surface.attack_surface(conn, binary_id)

        assert payload["available"] is False
        assert payload["network"]["count"] == 0
        missing = [entry["scan"] for entry in payload["sources"] if not entry["stored"]]
        assert set(missing) == {"protocols", "behavior", "capabilities", "threat", "crypto"}

    def test_an_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        try:
            attack_surface.attack_surface(conn, 4242)
        except KeyError:
            pass
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown binary must raise KeyError")


class TestRoutes:
    def test_attack_surface_answers_the_composition(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        status, payload = _get(f"/api/binaries/{binary_id}/attack-surface")

        assert status.startswith("200")
        assert payload["available"] is True
        assert payload["network"]["count"] == 4

    def test_attack_surface_without_scans_is_404_no_scan(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        status, payload = _get(f"/api/binaries/{binary_id}/attack-surface")

        assert status.startswith("404")
        assert payload["error"] == "no-scan"

    def test_attack_surface_of_an_unknown_binary_is_404(self, portal_db: Path) -> None:
        status, payload = _get("/api/binaries/4242/attack-surface")

        assert status.startswith("404")
        assert payload["error"] == "binary not found"


class TestCli:
    def test_attack_surface_json(self, portal_db: Path, conn: Any, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)

        result = runner.invoke(cli.app, ["attack-surface", str(binary_id), "--json"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["available"] is True

    def test_attack_surface_human_output_names_the_groups(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        result = runner.invoke(cli.app, ["attack-surface", str(binary_id)])

        assert result.exit_code == 0
        assert "network" in result.output

    def test_attack_surface_without_scans_fails(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        result = runner.invoke(cli.app, ["attack-surface", str(binary_id)])

        assert result.exit_code != 0
        assert "no stored attack-surface source scan" in result.output


class TestMcp:
    def test_the_tool_is_read_only(self) -> None:
        tool = mcp_tools.get_tool("get_attack_surface")
        assert tool is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False

    def test_get_attack_surface_returns_the_composition(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        tool = mcp_tools.get_tool("get_attack_surface")
        assert tool is not None

        payload = tool.handler({"binary_id": binary_id})

        assert payload["available"] is True
        assert "journal_action" not in payload

    def test_get_attack_surface_without_scans_is_a_tool_error(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)
        tool = mcp_tools.get_tool("get_attack_surface")
        assert tool is not None

        try:
            tool.handler({"binary_id": binary_id})
        except mcp_tools.ToolError as exc:
            assert exc.error == "no-scan"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a binary with no scans must be a tool error")


class TestReads:
    def test_the_read_writes_nothing(self, portal_db: Path, conn: Any, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)

        attack_surface.attack_surface(conn, binary_id)
        _get(f"/api/binaries/{binary_id}/attack-surface")

        with contextlib.closing(store.connect(portal_db)) as probe:
            assert journal.list_entries(probe) == [], "the read never journals a write"


class TestAttackSurfaceEdges:
    def test_non_dict_entries_are_skipped(self) -> None:
        assert attack_surface._capability_rows({"findings": ["nope"]}, frozenset()) == []
        assert attack_surface._protocol_rows({"protocols": ["nope"]}) == []
        assert attack_surface._finding_rows({"findings": ["nope"]}, "s") == []
        assert attack_surface._ioc_rows({"iocs": ["nope"]}) == []

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="424242"):
            attack_surface.attack_surface(conn, 424242)

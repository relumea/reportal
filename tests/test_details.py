"""Tests for the composed binary-detail reads: die-info, additional details, status."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from conftest import PE_INFO, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, details, journal, mcp_tools, store

runner = CliRunner()

FILETYPE = {
    "file_type": "pe",
    "arch": "x86_32",
    "matches": [
        {
            "name": "UPX",
            "category": "packer",
            "confidence": "high",
            "signals": [{"kind": "section", "value": "UPX0"}],
        },
        {
            "name": "Microsoft Visual C++",
            "category": "toolchain",
            "confidence": "medium",
            "signals": [{"kind": "string", "value": "Rich"}],
        },
    ],
    "count": 2,
    "by_category": {"packer": 1, "toolchain": 1},
    "notes": [],
}


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, scans: bool = True) -> int:
    """A stored binary with (optionally) the pe-info and filetype scans."""
    source = tmp_path / "notepad.exe"
    source.write_bytes(b"MZ" + b"\x00" * 4096)
    binary_id = store.add_binary(
        conn,
        sha256="c" * 64,
        name="notepad.exe",
        path=str(source),
        size=source.stat().st_size,
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    if scans:
        store.set_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO, dict(PE_INFO))
        store.set_scan(conn, analysis_id, store.SCAN_KIND_FILETYPE, dict(FILETYPE))
        store.set_fingerprint(
            conn,
            binary_id,
            {
                "format": "pe",
                "arch": "x86_32",
                "section_entropies": [{"name": ".text", "entropy": 6.4}],
            },
        )
    return binary_id


def _rescan(conn: sqlite3.Connection, binary_id: int, pe_info: dict[str, Any]) -> None:
    """Replace the binary's stored pe-info scan, on its latest analysis."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    assert analysis_id is not None
    store.set_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO, pe_info)


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


class TestDieInfo:
    def test_it_composes_the_filetype_categories(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = details.die_info(conn, binary_id)

        assert payload["available"] is True
        assert payload["identity"]["format"] == "pe"
        assert payload["identity"]["arch"] == "x86_32"
        assert [row["name"] for row in payload["packer"]] == ["UPX"]
        assert payload["packer"][0]["signals"] == [{"kind": "section", "value": "UPX0"}]
        assert [row["name"] for row in payload["toolchain"]] == ["Microsoft Visual C++"]
        assert payload["protector"] == []

    def test_it_reports_every_source_and_its_command(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = details.die_info(conn, binary_id)

        assert set(payload["sources"]) == {"pe-info", "filetype", "fingerprint"}
        assert all(row["present"] for row in payload["sources"].values())
        assert payload["sources"]["filetype"]["command"] == "reportal filetype"

    def test_the_entropy_comes_from_the_stored_fingerprint(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = details.die_info(conn, binary_id)

        assert payload["entropy"]["sections"][0]["name"] == ".text"
        assert payload["entropy"]["packed"] is False

    def test_without_a_fingerprint_the_source_is_marked_missing(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        conn.execute("DELETE FROM binary_fingerprints WHERE binary_id = ?", (binary_id,))
        conn.commit()

        payload = details.die_info(conn, binary_id)

        assert payload["entropy"]["sections"] == []
        assert payload["sources"]["fingerprint"]["present"] is False
        assert payload["available"] is True, "the other sources still answer"

    def test_a_binary_with_no_scans_is_not_available(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        payload = details.die_info(conn, binary_id)

        assert payload["available"] is False
        assert payload["identity"]["format"] is None
        assert payload["packer"] == []

    def test_a_binary_with_no_analysis_at_all_reports_no_scans(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        source = tmp_path / "fresh.exe"
        source.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="d" * 64, name="fresh.exe", path=str(source), size=2
        )

        assert details.status(conn, binary_id)["status"] == "incomplete"
        assert details.die_info(conn, binary_id)["available"] is False

    def test_a_packer_looking_section_name_is_reported_as_a_hint(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        pe_info = dict(PE_INFO)
        pe_info["sections"] = [
            {"name": "UPX0", "virtual_address": 0x1000, "virtual_size": 10, "raw_size": 0},
            {"name": ".data", "virtual_address": 0x2000, "virtual_size": 10, "raw_size": 512},
        ]
        _rescan(conn, binary_id, pe_info)

        payload = details.die_info(conn, binary_id)

        assert payload["packer_section_hint"] == ["UPX0"]


class TestAdditionalDetails:
    def test_it_reports_the_sections_the_rich_header_and_the_presence(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = details.additional_details(conn, binary_id)

        assert payload["available"] is True
        assert payload["format"] == "pe"
        assert payload["sections"]["names"] == [".text", ".data"]
        assert payload["sections"]["executable"] == [".text"]
        assert payload["sections"]["writable"] == [".data"]
        assert payload["rich_header"]["present"] is True
        assert payload["rich_header"]["entries"] == 1
        assert payload["rich_header"]["build_ids"] == [0]
        assert payload["presence"]["resources"] is True
        assert payload["presence"]["tls_directory"] is False
        assert payload["counts"]["imports"] == 183
        assert payload["debug"] == [{"type": "MISC"}]

    def test_the_overlay_is_the_bytes_past_the_last_section(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = details.additional_details(conn, binary_id)

        # The stored file is 4098 bytes; the fixture's last section ends at 29184.
        assert payload["overlay"]["present"] is False
        assert payload["overlay"]["bytes"] == 0
        assert payload["overlay"]["offset"] == 29184

    def test_an_overlay_is_measured_from_the_file(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        pe_info = dict(PE_INFO)
        pe_info["sections"] = [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 10,
                "raw_size": 16,
                "raw_offset": 0,
            }
        ]
        _rescan(conn, binary_id, pe_info)

        payload = details.additional_details(conn, binary_id)

        assert payload["overlay"]["bytes"] == 4098 - 16
        assert payload["overlay"]["present"] is True
        assert payload["overlay"]["offset"] == 16

    def test_without_the_scan_it_is_not_available(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        payload = details.additional_details(conn, binary_id)

        assert payload["available"] is False
        assert payload["sections"]["count"] == 0
        assert payload["sources"]["pe-info"]["present"] is False


class TestStatus:
    def test_a_fully_scanned_binary_is_ready(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        payload = details.status(conn, binary_id)

        assert payload["status"] == "ready"
        assert payload["missing"] == []
        assert payload["hint"] == ""

    def test_a_bare_binary_names_every_gap_and_its_command(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        payload = details.status(conn, binary_id)

        assert payload["status"] == "incomplete"
        assert payload["missing"] == ["pe-info", "filetype", "fingerprint"]
        assert f"reportal pe-info {binary_id}" in payload["hint"]
        assert f"reportal enrich {binary_id}" in payload["hint"]


class TestRoutes:
    def test_die_info_answers_the_composition(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        status, payload = _get(f"/api/binaries/{binary_id}/die-info")

        assert status.startswith("200")
        assert payload["identity"]["format"] == "pe"
        assert [row["name"] for row in payload["packer"]] == ["UPX"]

    def test_die_info_without_scans_is_404_no_scan(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        status, payload = _get(f"/api/binaries/{binary_id}/die-info")

        assert status.startswith("404")
        assert payload["error"] == "no-scan"
        assert "filetype" in payload["detail"]

    def test_die_info_of_an_unknown_binary_is_404(self, portal_db: Path) -> None:
        status, payload = _get("/api/binaries/4242/die-info")

        assert status.startswith("404")
        assert payload["error"] == "binary not found"

    def test_additional_details_answers_the_read(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        status, payload = _get(f"/api/binaries/{binary_id}/additional-details")

        assert status.startswith("200")
        assert payload["rich_header"]["present"] is True

    def test_additional_details_without_the_scan_is_404_no_scan(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        status, payload = _get(f"/api/binaries/{binary_id}/additional-details")

        assert status.startswith("404")
        assert payload["error"] == "no-scan"

    def test_the_status_route_answers_even_without_a_scan(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        status, payload = _get(f"/api/binaries/{binary_id}/additional-details/status")

        assert status.startswith("200")
        assert payload["status"] == "incomplete"
        assert "pe-info" in payload["missing"]

    def test_the_status_route_of_an_unknown_binary_is_404(self, portal_db: Path) -> None:
        status, payload = _get("/api/binaries/4242/additional-details/status")

        assert status.startswith("404")
        assert payload["error"] == "binary not found"


class TestCli:
    def test_die_info_json(self, portal_db: Path, conn: Any, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)

        result = runner.invoke(cli.app, ["die-info", str(binary_id), "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["identity"]["format"] == "pe"

    def test_die_info_human_output_names_the_categories(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        result = runner.invoke(cli.app, ["die-info", str(binary_id)])

        assert result.exit_code == 0
        assert "UPX" in result.output
        assert "toolchain" in result.output

    def test_die_info_without_scans_fails(self, portal_db: Path, conn: Any, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        result = runner.invoke(cli.app, ["die-info", str(binary_id)])

        assert result.exit_code != 0
        assert "no stored filetype or pe-info scan" in result.output

    def test_additional_details_json(self, portal_db: Path, conn: Any, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)

        result = runner.invoke(cli.app, ["additional-details", str(binary_id), "--json"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["format"] == "pe"

    def test_additional_details_status_needs_no_scan(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        result = runner.invoke(
            cli.app, ["additional-details", str(binary_id), "--status", "--json"]
        )

        assert result.exit_code == 0
        assert json.loads(result.stdout)["status"] == "incomplete"

    def test_additional_details_without_the_scan_fails(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)

        result = runner.invoke(cli.app, ["additional-details", str(binary_id)])

        assert result.exit_code != 0
        assert "no stored pe-info scan" in result.output


class TestMcp:
    def test_the_tools_are_read_only(self) -> None:
        for name in ("get_die_info", "get_additional_details", "get_details_status"):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.read_only_hint is True
            assert tool.annotations.destructive_hint is False

    def test_get_die_info_returns_the_composition(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        tool = mcp_tools.get_tool("get_die_info")
        assert tool is not None

        payload = tool.handler({"binary_id": binary_id})

        assert payload["identity"]["format"] == "pe"
        assert "journal_action" not in payload

    def test_get_die_info_without_scans_is_a_tool_error(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, scans=False)
        tool = mcp_tools.get_tool("get_die_info")
        assert tool is not None

        try:
            tool.handler({"binary_id": binary_id})
        except mcp_tools.ToolError as exc:
            assert exc.error == "no-scan"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a binary with no scans must be a tool error")

    def test_get_additional_details_and_status(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        details_tool = mcp_tools.get_tool("get_additional_details")
        status_tool = mcp_tools.get_tool("get_details_status")
        assert details_tool is not None and status_tool is not None

        assert details_tool.handler({"binary_id": binary_id})["format"] == "pe"
        assert status_tool.handler({"binary_id": binary_id})["status"] == "ready"

    def test_an_unknown_binary_is_a_tool_error(self, portal_db: Path) -> None:
        tool = mcp_tools.get_tool("get_details_status")
        assert tool is not None

        try:
            tool.handler({"binary_id": 4242})
        except mcp_tools.ToolError as exc:
            assert exc.error == "binary not found"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown binary must be a tool error")


class TestReads:
    def test_none_of_the_reads_writes_anything(
        self, portal_db: Path, conn: Any, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)

        details.die_info(conn, binary_id)
        details.additional_details(conn, binary_id)
        details.status(conn, binary_id)
        _get(f"/api/binaries/{binary_id}/die-info")

        with contextlib.closing(store.connect(portal_db)) as probe:
            assert journal.list_entries(probe) == [], "the detail reads never journal a write"

"""Tests for the inputs a stored scan records, and the reads that report them.

A scan's result is its own; the inputs the caller named (a decompiler, a
severity floor, the other binary of a comparison) are recorded beside it, so a
reading can be run again the same way.  These tests exercise the storage, the
recording each domain module does, and the three reads.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from conftest import FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, journal, library, mcp_server, related, store, threat, unstrip

runner = CliRunner()


def _get(path: str) -> Any:
    """Issue a GET and return its JSON body, asserting the 200."""
    status, headers, body = wsgi_request("GET", path)
    assert status.startswith("200"), body
    return json_body(body, headers)


def _post(path: str, payload: dict[str, Any]) -> tuple[str, Any]:
    """Issue a POST with a JSON body and return its status and JSON body."""
    status, headers, body = wsgi_request(
        "POST",
        path,
        body=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    return status, json_body(body, headers)


def _seed(conn: sqlite3.Connection, tmp_path: Path) -> dict[str, int]:
    """One binary with a project context, so the engine routes can run."""
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ" + b"\x00" * 62)
    binary_id = store.add_binary(
        conn,
        sha256="ee" * 32,
        name="demo.exe",
        path=str(target),
        size=64,
        fmt="PE",
        arch="x86_32",
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    store.set_rebrew_context(conn, binary_id, str(tmp_path))
    for va in (0x1000, 0x1010):
        store.add_function(
            conn, analysis_id=analysis_id, va=va, name=f"sub_{va:x}", size=32, status="STUB"
        )
    return {"binary": binary_id, "analysis": analysis_id}


class TestStorage:
    def test_a_scan_records_the_inputs_it_ran_with(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, "structs", {"a": 1}, params={"limit": 3})
        assert store.get_scan_params(conn, analysis_id, "structs") == {"limit": 3}

    def test_a_scan_that_records_none_answers_an_empty_object(
        self, conn: sqlite3.Connection
    ) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, "triage", {"a": 1})
        assert store.get_scan_params(conn, analysis_id, "triage") == {}

    def test_the_inputs_are_not_inside_the_result(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(
            conn, analysis_id, "security", {"findings": []}, params={"min_severity": "high"}
        )
        assert store.get_scan(conn, analysis_id, "security") == {"findings": []}

    def test_an_unknown_scan_has_no_inputs(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        assert store.get_scan_params(conn, analysis_id, "never-ran") == {}

    def test_a_corrupt_input_row_reads_as_empty(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, "triage", {"a": 1})
        conn.execute(
            "UPDATE scans SET params_json = ? WHERE analysis_id = ? AND kind = ?",
            ("not json", analysis_id, "triage"),
        )
        assert store.get_scan_params(conn, analysis_id, "triage") == {}


def _seed_analysis(conn: sqlite3.Connection) -> tuple[int, int]:
    """A binary and an analysis, with no engine context needed."""
    binary_id = store.add_binary(conn, sha256="dd" * 32, name="plain.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    return binary_id, analysis_id


class TestRecording:
    """The domain modules record the inputs their callers named."""

    def test_unstrip_records_its_confidence_floor(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)

        def identify(_project: str | Path) -> dict[str, Any]:
            return {
                "identified": 1,
                "candidates": [
                    {"va": "0x1000", "name": "memcpy", "module": "msvcrt", "kind": "CRT"}
                ],
            }

        unstrip.run_unstrip(
            conn, binary_id=ids["binary"], engine=FakeEngine(), ident=identify, min_confidence=0.5
        )
        assert store.get_scan_params(conn, ids["analysis"], store.SCAN_KIND_UNSTRIP) == {
            "min_confidence": 0.5
        }

    def test_library_records_its_confidence_floor(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)

        def identify(_project: str | Path) -> dict[str, Any]:
            return {"identified": 1, "candidates": [{"va": "0x1000", "name": "memcpy"}]}

        library.run_library(
            conn, binary_id=ids["binary"], engine=None, ident=identify, min_confidence=0.25
        )
        assert store.get_scan_params(conn, ids["analysis"], library.SCAN_KIND) == {
            "min_confidence": 0.25
        }

    def test_related_records_its_limit(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _seed_analysis(conn)
        related.find_related(conn, binary_id=binary_id, limit=4)
        assert store.get_scan_params(conn, analysis_id, store.SCAN_KIND_RELATED) == {
            "limit": 4,
            "include_unrelated": False,
        }

    def test_threat_records_whether_a_narrative_was_asked_for(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn, tmp_path)
        binary_id, analysis_id = ids["binary"], ids["analysis"]
        threat.build_threat_report(conn, binary_id=binary_id, engine=FakeEngine(), narrative=True)
        assert store.get_scan_params(conn, analysis_id, store.SCAN_KIND_THREAT) == {
            "narrative": True
        }

    def test_the_structs_route_records_the_decompiler_and_limit(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, tmp_path)
        status, payload = _post(
            f"/api/binaries/{ids['binary']}/structs",
            {"decompiler": "kuna", "limit": 7},
        )
        assert status.startswith("200"), payload
        assert store.get_scan_params(conn, ids["analysis"], store.SCAN_KIND_STRUCTS) == {
            "decompiler": "kuna",
            "limit": 7,
        }

    def test_the_security_route_records_the_severity_floor(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, tmp_path)
        status, payload = _post(
            f"/api/binaries/{ids['binary']}/security-scan", {"min_severity": "low"}
        )
        assert status.startswith("200"), payload
        assert store.get_scan_params(conn, ids["analysis"], store.SCAN_KIND_SECURITY) == {
            "min_severity": "low"
        }

    def test_the_benchmark_route_records_the_partner_and_settings(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, tmp_path)
        other = store.add_binary(conn, sha256="cc" * 32, name="other.exe")
        other_analysis = store.create_analysis(conn, binary_id=other, engine="manual")
        store.add_function(
            conn,
            analysis_id=other_analysis,
            va=0x1000,
            name="sub_1000",
            size=32,
            status="STUB",
        )
        status, payload = _post(
            f"/api/binaries/{ids['binary']}/benchmark",
            {
                "right_binary_id": other,
                "min_similarity": 0,
                "labels": [{"left_va": 0x1000, "right_va": 0x1000}],
            },
        )
        assert status.startswith("200"), payload
        params = store.get_scan_params(conn, ids["analysis"], store.SCAN_KIND_BENCHMARK)
        assert params["right_binary_id"] == other
        assert params["min_similarity"] == 0

    def test_a_journaled_scan_records_the_inputs(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(conn, log, 1, "structs", {"a": 1}, params={"limit": 2})
        assert store.get_scan_params(conn, analysis_id, "structs") == {"limit": 2}


class TestRoutes:
    def test_the_binary_listing_carries_every_scan_and_its_inputs(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, tmp_path)
        _post(f"/api/binaries/{ids['binary']}/structs", {"limit": 3})
        _post(f"/api/binaries/{ids['binary']}/pe-info", {})
        payload = _get(f"/api/binaries/{ids['binary']}/scans")
        assert payload["binary_id"] == ids["binary"]
        assert payload["analysis_id"] == ids["analysis"]
        assert payload["count"] == len(payload["scans"])
        by_kind = {scan["kind"]: scan for scan in payload["scans"]}
        from reportal import engines

        assert by_kind[store.SCAN_KIND_STRUCTS]["params"] == {
            "decompiler": engines.DEFAULT_DECOMPILER_BACKEND,
            "limit": 3,
        }
        assert by_kind[store.SCAN_KIND_PE_INFO]["params"] == {}
        assert all("result_json" not in scan for scan in payload["scans"])

    def test_a_binary_with_no_analysis_answers_an_empty_list(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="empty.exe")
        payload = _get(f"/api/binaries/{binary_id}/scans")
        assert payload == {
            "binary_id": binary_id,
            "analysis_id": None,
            "scans": [],
            "count": 0,
        }

    def test_an_unknown_binary_is_a_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/9999/scans")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_the_analysis_listing_carries_the_inputs_too(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, "structs", {}, params={"limit": 2})
        payload = _get(f"/api/analyses/{analysis_id}/scans")
        assert payload["scans"][0]["params"] == {"limit": 2}


class TestMcp:
    def test_the_read_answers(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, "security", {}, params={"min_severity": "high"})
        payload, failed = mcp_server.call_tool("list_scans", {"binary_id": 1})
        assert failed is False
        assert payload["scans"][0]["params"] == {"min_severity": "high"}

    def test_an_unknown_binary_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        payload, failed = mcp_server.call_tool("list_scans", {"binary_id": 9999})
        assert failed is True
        assert payload["error"] == "binary not found"


class TestCli:
    def test_the_command_prints_the_inputs(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, "security", {}, params={"min_severity": "medium"})
        store.set_scan(conn, analysis_id, "triage", {})
        conn.commit()
        result = runner.invoke(cli.app, ["scans", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "security" in result.output
        assert "min_severity=medium" in result.output
        assert "not recorded" in result.output

    def test_the_json_flag_prints_the_payload(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        binary_id, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, "structs", {}, params={"limit": 6})
        conn.commit()
        result = runner.invoke(cli.app, ["scans", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["scans"][0]["params"] == {"limit": 6}

    def test_a_binary_with_no_scan_says_so(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="ba" * 32, name="empty.exe")
        conn.commit()
        result = runner.invoke(cli.app, ["scans", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "has no stored scan" in result.output

    def test_an_unknown_binary_fails_loud(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        conn.commit()
        result = runner.invoke(cli.app, ["scans", "9999"])
        assert result.exit_code == 1
        assert "no binary with id 9999" in result.output

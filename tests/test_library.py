"""Tests for library identification and the bill of materials it feeds.

The engine call is injected, so no test runs rebrew: the candidate payload is
the shape `RebrewEngine.identify_library` returns, and the tests check the join
to the stored functions, the module rollup and the three export shapes.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import IDENTIFY, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import api, cli, library, mcp_server, store

runner = CliRunner()

# The engine's candidate shape, with two modules so the rollup has something to
# group and a confidence spread so a threshold can drop one.
CANDIDATES: list[dict[str, Any]] = [
    {"va": "0x1000", "name": "memcpy", "module": "msvcrt", "kind": "CRT", "confidence": 0.9},
    {"va": "0x1010", "name": "strlen", "module": "msvcrt", "kind": "CRT", "confidence": 0.8},
    {"va": "0x2000", "name": "inflate", "module": "zlib", "kind": "FLIRT", "confidence": 0.55},
]


def _identify(_project: str | Path) -> dict[str, Any]:
    """The engine's own dry-run answer, with the candidates above."""
    return {"identified": 3, "to_write": 3, "already_annotated": 0, "candidates": CANDIDATES}


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, context: bool = True) -> int:
    """One binary with a project context and three functions at the VAs."""
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ" + b"\x00" * 30)
    binary_id = store.add_binary(
        conn,
        sha256="aa" * 32,
        name="demo.exe",
        path=str(target),
        size=4096,
        fmt="PE",
        arch="x86_32",
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    for index, va in enumerate((0x1000, 0x1010, 0x2000)):
        store.add_function(
            conn, analysis_id=analysis_id, va=va, name=f"sub_{va:x}", size=64 + index, status="STUB"
        )
    if context:
        store.set_rebrew_context(conn, binary_id, str(tmp_path))
    return binary_id


def _run(conn: sqlite3.Connection, binary_id: int, **kwargs: Any) -> dict[str, Any]:
    """Run the identification with the injected engine, for the tests."""
    return library.run_library(conn, binary_id=binary_id, engine=None, ident=_identify, **kwargs)


class TestProposals:
    def test_a_candidate_joins_the_stored_function(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        found = library.proposals(
            _identify(tmp_path), store.list_functions(conn, binary_id=binary_id)
        )
        assert [entry["name"] for entry in found] == ["memcpy", "strlen", "inflate"]
        assert found[0]["function_id"] is not None
        assert found[0]["size"] == 64

    def test_a_candidate_outside_the_function_table_is_kept(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = {"candidates": [{"va": "0xff00", "name": "x", "module": "m", "confidence": 0.5}]}
        found = library.proposals(payload, store.list_functions(conn, binary_id=binary_id))
        assert found[0]["function_id"] is None
        assert found[0]["size"] == 0

    def test_a_candidate_without_a_module_is_unknown(self) -> None:
        found = library.proposals({"candidates": [{"va": 0x10, "name": "f"}]}, [])
        assert found[0]["module"] == library.UNKNOWN_MODULE
        assert found[0]["kind"] == "unknown"
        assert found[0]["confidence"] == 0.0

    def test_an_unparsable_candidate_is_dropped(self) -> None:
        payload = {"candidates": [{"va": "not-hex"}, "junk", {"name": "no va"}]}
        assert library.proposals(payload, []) == []

    def test_a_confidence_outside_the_range_is_clamped(self) -> None:
        found = library.proposals({"candidates": [{"va": 1, "confidence": 7.5}]}, [])
        assert found[0]["confidence"] == 1.0

    def test_a_non_finite_confidence_reads_as_zero(self) -> None:
        found = library.proposals({"candidates": [{"va": 1, "confidence": float("nan")}]}, [])
        assert found[0]["confidence"] == 0.0

    def test_a_missing_candidate_list_reads_as_empty(self) -> None:
        assert library.proposals({}, []) == []


class TestComponents:
    def test_a_module_rolls_up_its_candidates(self) -> None:
        found = library.components(library.proposals({"candidates": CANDIDATES}, []))
        assert [entry["module"] for entry in found] == ["msvcrt", "zlib"]
        msvcrt = found[0]
        assert msvcrt["functions"] == 2
        assert msvcrt["kinds"] == ["CRT"]
        assert msvcrt["confidence"] == 0.9
        assert msvcrt["linkage"] == "static"

    def test_the_list_is_capped_with_the_most_functions_first(self) -> None:
        candidates = [
            {"va": index, "module": f"m{index}", "confidence": 0.5} for index in range(10)
        ]
        assert (
            len(library.components(library.proposals({"candidates": candidates}, []), limit=3)) == 3
        )


class TestRunLibrary:
    def test_it_stores_the_reading(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = _run(conn, binary_id)
        assert payload["stored"] is True
        assert payload["count"] == 2
        assert payload["candidates"] == 3
        stored = library.describe(conn, binary_id)
        assert stored["count"] == 2
        assert stored["components"][0]["module"] == "msvcrt"

    def test_the_threshold_drops_candidates_before_the_rollup(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = _run(conn, binary_id, min_confidence=0.7)
        assert [entry["module"] for entry in payload["components"]] == ["msvcrt"]
        assert payload["candidates"] == 2
        assert any("dropped" in note for note in payload["notes"])

    def test_a_missing_context_is_refused(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path, context=False)
        with pytest.raises(library.LibraryError) as failure:
            _run(conn, binary_id)
        assert failure.value.code == "no-engine-context"

    def test_an_unknown_binary_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(library.LibraryError):
            library.describe(conn, 999)

    def test_an_unidentified_binary_reads_as_empty(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = library.describe(conn, binary_id)
        assert payload["stored"] is False
        assert payload["components"] == []
        assert "reportal library" in payload["notes"][0]

    def test_the_engine_itself_answers_when_no_stub_is_injected(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: Any
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = library.run_library(conn, binary_id=binary_id, engine=fake_engine)
        assert fake_engine.calls[-1] == "identify_library"
        assert payload["count"] == 1
        assert payload["components"][0]["module"] == "COMDLG32"
        assert payload["candidates"] == len(IDENTIFY["candidates"])


class TestSbom:
    def _identified(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        binary_id = _seed(conn, tmp_path)
        _run(conn, binary_id)
        return binary_id

    def test_cyclonedx_names_the_binary_and_its_modules(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._identified(conn, tmp_path)
        document = library.sbom(conn, binary_id, fmt=library.FORMAT_CYCLONEDX)["document"]
        assert document["bomFormat"] == "CycloneDX"
        assert document["metadata"]["component"]["name"] == "demo.exe"
        assert [entry["name"] for entry in document["components"]] == ["msvcrt", "zlib"]
        properties = {
            entry["name"]: entry["value"] for entry in document["components"][0]["properties"]
        }
        assert properties["reportal:functions"] == "2"
        assert properties["reportal:kinds"] == "CRT"

    def test_spdx_carries_one_package_per_module(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._identified(conn, tmp_path)
        document = library.sbom(conn, binary_id, fmt=library.FORMAT_SPDX)["document"]
        assert document["spdxVersion"] == library.SPDX_VERSION
        assert [package["name"] for package in document["packages"]] == [
            "demo.exe",
            "msvcrt",
            "zlib",
        ]

    def test_csv_is_one_row_per_module(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = self._identified(conn, tmp_path)
        payload = library.sbom(conn, binary_id, fmt=library.FORMAT_CSV)
        lines = library.render_csv(payload).strip().splitlines()
        assert lines[0].startswith("module,kinds,functions,size,confidence,linkage")
        assert len(lines) == 3
        assert lines[1].startswith("msvcrt,CRT,2,")

    def test_an_unknown_format_is_refused(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = self._identified(conn, tmp_path)
        with pytest.raises(ValueError):
            library.sbom(conn, binary_id, fmt="xml")

    def test_go_dependencies_join_every_shape(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        from reportal import gobuildinfo

        binary_id = self._identified(conn, tmp_path)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert analysis_id is not None
        store.set_scan(
            conn,
            analysis_id,
            gobuildinfo.SCAN_KIND,
            {
                "binary_id": binary_id,
                "version": "go1.27.1",
                "module": "example.com/demo",
                "dependencies": [{"module": "github.com/google/uuid", "version": "v1.6.0"}],
                "settings": {},
                "build_id": "",
            },
        )

        cyclonedx = library.sbom(conn, binary_id, fmt=library.FORMAT_CYCLONEDX)["document"]
        go = cyclonedx["components"][-1]
        assert go["name"] == "github.com/google/uuid"
        assert go["version"] == "v1.6.0"
        assert go["purl"] == "pkg:golang/github.com/google/uuid@v1.6.0"

        spdx = library.sbom(conn, binary_id, fmt=library.FORMAT_SPDX)["document"]
        assert [package["name"] for package in spdx["packages"]] == [
            "demo.exe",
            "msvcrt",
            "zlib",
            "github.com/google/uuid",
        ]
        assert spdx["packages"][-1]["versionInfo"] == "v1.6.0"

        payload = library.sbom(conn, binary_id, fmt=library.FORMAT_CSV)
        lines = library.render_csv(payload).strip().splitlines()
        assert len(lines) == 4
        assert lines[-1].startswith("github.com/google/uuid,go-module,0,0,1.0,static")

    def test_no_gobuildinfo_scan_changes_nothing(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._identified(conn, tmp_path)
        document = library.sbom(conn, binary_id, fmt=library.FORMAT_CYCLONEDX)["document"]
        assert [entry["name"] for entry in document["components"]] == ["msvcrt", "zlib"]

    def test_an_unidentified_binary_exports_empty(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        document = library.sbom(conn, binary_id, fmt=library.FORMAT_CYCLONEDX)["document"]
        assert document["components"] == []

    def test_an_unknown_binary_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(library.LibraryError) as failure:
            library.sbom(conn, 999)
        assert failure.value.code == "binary not found"


class TestRoutes:
    def test_the_read_answers_empty_before_the_first_run(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/library")
        assert status.startswith("200"), body
        assert json_body(body, headers)["stored"] is False

    def test_an_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/library")
        assert status.startswith("404"), body
        assert json_body(body, headers)["error"] == "binary not found"

    def test_the_run_stores_and_the_read_serves_it(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        monkeypatch.setattr(api, "_engine", lambda: fake_engine)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/library")
        assert status.startswith("200"), body
        assert json_body(body, headers)["journal_action"]
        read = wsgi_request("GET", f"/api/binaries/{binary_id}/library")
        payload = json_body(read[2], read[1])
        assert payload["stored"] is True
        assert payload["components"][0]["module"] == "COMDLG32"

    def test_a_binary_without_a_context_is_400(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, context=False)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/library")
        assert status.startswith("400"), body
        assert json_body(body, headers)["error"] == "no-engine-context"

    def test_the_sbom_route_answers_json_and_csv(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _run(conn, binary_id)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/sbom")
        assert status.startswith("200"), body
        assert json_body(body, headers)["document"]["bomFormat"] == "CycloneDX"

        csv_response = wsgi_request("GET", f"/api/binaries/{binary_id}/sbom?format=csv")
        assert csv_response[0].startswith("200"), csv_response[2]
        assert csv_response[2].decode().startswith("module,")

    def test_an_unknown_sbom_format_is_400(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/sbom?format=xml")
        assert status.startswith("400"), body
        assert json_body(body, headers)["error"] == "invalid format"

    def test_an_unknown_sbom_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/sbom")
        assert status.startswith("404"), body
        assert json_body(body, headers)["error"] == "binary not found"


class TestCli:
    def test_the_library_command_prints_the_modules(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path, fake_engine: Any
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        conn.commit()
        result = runner.invoke(cli.app, ["library", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "COMDLG32" in result.output

    def test_the_library_command_fails_without_a_context(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, context=False)
        conn.commit()
        result = runner.invoke(cli.app, ["library", str(binary_id)])
        assert result.exit_code == 1
        assert "no-engine-context" in result.output

    def test_the_sbom_command_writes_a_file(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _run(conn, binary_id)
        conn.commit()
        target = tmp_path / "out.json"
        result = runner.invoke(cli.app, ["sbom", str(binary_id), "--output", str(target), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(target.read_text())["bomFormat"] == "CycloneDX"
        assert json.loads(result.stdout)["bytes"] > 0

    def test_the_sbom_command_prints_csv(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _run(conn, binary_id)
        conn.commit()
        result = runner.invoke(cli.app, ["sbom", str(binary_id), "--format", "csv"])
        assert result.exit_code == 0, result.output
        assert result.stdout.startswith("module,")

    def test_the_sbom_command_json_wraps_stdout_body(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _run(conn, binary_id)
        conn.commit()
        result = runner.invoke(cli.app, ["sbom", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["format"] == library.FORMAT_CYCLONEDX
        assert json.loads(payload["text"])["bomFormat"] == "CycloneDX"

    def test_an_unknown_format_fails_loud(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        conn.commit()
        result = runner.invoke(cli.app, ["sbom", str(binary_id), "--format", "xml"])
        assert result.exit_code == 1
        assert "format must be one of" in result.output


class TestMcp:
    def test_the_reads_and_the_export_answer(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload, failed = mcp_server.call_tool("get_library", {"binary_id": binary_id})
        assert failed is False
        assert payload["stored"] is False

        exported, failed = mcp_server.call_tool(
            "export_sbom", {"binary_id": binary_id, "format": "spdx"}
        )
        assert failed is False
        assert exported["document"]["spdxVersion"] == library.SPDX_VERSION

        csv_payload, failed = mcp_server.call_tool(
            "export_sbom", {"binary_id": binary_id, "format": "csv"}
        )
        assert failed is False
        assert csv_payload["csv"].startswith("module,")

        bad, failed = mcp_server.call_tool("export_sbom", {"binary_id": binary_id, "format": "xml"})
        assert failed is True
        assert bad["error"] == "invalid format"

    def test_the_run_stores_through_the_tool(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: Any
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload, failed = mcp_server.call_tool("run_library", {"binary_id": binary_id})
        assert failed is False, payload
        assert payload["stored"] is True
        assert payload["components"][0]["module"] == "COMDLG32"

    def test_a_missing_context_is_a_tool_error(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, context=False)
        payload, failed = mcp_server.call_tool("run_library", {"binary_id": binary_id})
        assert failed is True
        assert payload["error"] == "no-engine-context"

    def test_an_unknown_binary_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        payload, failed = mcp_server.call_tool("get_library", {"binary_id": 999})
        assert failed is True
        assert payload["error"] == "binary not found"

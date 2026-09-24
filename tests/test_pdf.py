"""Tests for the dependency-free PDF report writer and its stored-scan sections."""

from __future__ import annotations

import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from conftest import REPORT, FakeEngine

from reportal import gobuildinfo, llm, mcp_tools, pdf, store
from reportal._paths import DB_ENV

PDFINFO = shutil.which("pdfinfo")
PDFTOTEXT = shutil.which("pdftotext")

GENERATED = "2026-01-02T03:04:05+00:00"


def _binary(conn: sqlite3.Connection, *, name: str = "demo.exe") -> tuple[int, int]:
    """Register one binary with an analysis and return ``(binary_id, analysis_id)``."""
    binary_id = store.add_binary(
        conn,
        sha256="ab" * 32,
        name=name,
        path=f"/x/{name}",
        size=1024,
        fmt="PE",
        arch="x86_32",
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    return binary_id, analysis_id


def _seed_scans(conn: sqlite3.Connection, analysis_id: int, binary_id: int) -> None:
    """Store one of every scan the report renders."""
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_REPORT,
        {
            "out": "/reports",
            "pages": ["index.html"],
            "summary": {
                "total_functions": 2,
                "covered_functions": 2,
                "coverage_pct": 100.0,
                "matched_pct": 50.0,
                "byte_coverage_pct": 25.0,
                "status_counts": {"EXACT": 1, "STUB": 1},
            },
        },
    )
    store.set_fingerprint(conn, binary_id, {"sha256": "ab" * 32, "imphash": "cd" * 16})
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_CAPABILITIES,
        {
            "binary_id": binary_id,
            "count": 1,
            "capabilities": [
                {
                    "name": "network",
                    "description": "sockets",
                    "confidence": "high",
                    "evidence": [],
                    "evidence_count": 3,
                }
            ],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_TRIAGE,
        {
            "toolchain": {"family": "msvc", "version_hint": "MSVC 6.0", "confidence": "high"},
            "meta": {
                "format": "pe",
                "image_base": 0x400000,
                "text_va": 0x401000,
                "text_size": 4096,
            },
            "strings": {"count": 3},
            "imports": {"count": 2},
            "references": {"total": 5},
            "functions": {"total": 2, "covered": 1},
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_FUNCTION_TRIAGE,
        {
            "binary_id": binary_id,
            "model": "heuristic",
            "functions": [
                {
                    "function_id": 1,
                    "name": "sub_1000",
                    "va": 0x1000,
                    "size": 16,
                    "status": "STUB",
                    "score": 0.5,
                    "summary": "reads a file",
                    "capabilities": ["file-io"],
                    "method": "heuristic",
                }
            ],
            "count": 1,
            "by_method": {"llm": 0, "heuristic": 1},
            "skipped": [],
            "notes": [],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_SECURITY,
        {
            "findings": [],
            "count": 2,
            "by_severity": {"high": 1, "medium": 0, "low": 1},
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_CRYPTO,
        {"findings": [], "count": 2, "by_confidence": {"high": 1, "medium": 1}},
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_THREAT,
        {
            "binary_id": binary_id,
            "iocs": {},
            "ioc_counts": {"urls": 2, "domains": 1, "ipv4": 0},
            "techniques": [
                {
                    "id": "T1071",
                    "name": "Application Layer Protocol",
                    "evidence": [],
                    "confidence": "high",
                }
            ],
            "narrative": None,
            "notes": [],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_SECRETS,
        {
            "binary_id": binary_id,
            "findings": [
                {
                    "kind": "pattern",
                    "name": "aws-access-key",
                    "value": "AKIAIOSFODNN7EXAMPLE",
                    "redacted": "AKIA...MPLE",
                    "va": 0x1000,
                    "confidence": "high",
                }
            ],
            "count": 1,
            "by_confidence": {"high": 1, "medium": 0},
            "scanned": 12,
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_EXECUTION,
        {
            "binary_id": binary_id,
            "domain": "execution",
            "findings": [],
            "count": 1,
            "by_confidence": {"high": 1, "medium": 0},
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_PROTOCOLS,
        {
            "binary_id": binary_id,
            "protocols": [
                {
                    "protocol": "http",
                    "description": "Hypertext Transfer Protocol",
                    "confidence": "high",
                    "evidence": [],
                    "ports": [80, 443],
                }
            ],
            "count": 1,
            "by_confidence": {"high": 1, "medium": 0},
            "notes": [],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_OBFUSCATION,
        {
            "binary_id": binary_id,
            "domain": "obfuscation",
            "findings": [],
            "count": 1,
            "by_confidence": {"high": 1, "medium": 0},
            "packer_likelihood": "low",
            "notes": [],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_REMEDIATION,
        {
            "binary_id": binary_id,
            "rule": 'rule demo {\n strings:\n  $a = "x"\n condition:\n  $a\n}\n',
            "rule_name": "demo_rule",
            "string_count": 1,
            "import_count": 0,
            "specificity": "weak",
            "validated": True,
            "validator": "yarac",
            "meta": {},
            "notes": [],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_LINEAGE,
        {
            "comparisons": {
                "7": {
                    "left_binary_id": binary_id,
                    "right_binary_id": 7,
                    "left_name": "demo.exe",
                    "right_name": "other.exe",
                    "refined": False,
                    "summary": {
                        "unchanged": 3,
                        "changed": 1,
                        "removed": 0,
                        "added": 2,
                        "matched_percent": 66.67,
                    },
                    "rows": [],
                }
            }
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_PROTOCOLS,
        {
            "binary_id": binary_id,
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
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_SECURITY,
        {
            "binary_id": binary_id,
            "findings": [
                {
                    "rule": "unbounded-copy",
                    "cwe": "CWE-120",
                    "severity": "high",
                    "confidence": "high",
                    "file": "a.c",
                    "line": 3,
                    "function": "vuln_copy",
                }
            ],
            "count": 1,
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        gobuildinfo.SCAN_KIND,
        {
            "binary_id": binary_id,
            "version": "go1.27.1",
            "module": "example.com/demo",
            "dependencies": [{"module": "github.com/google/uuid", "version": "v1.6.0"}],
            "settings": {"GOOS": "linux"},
            "build_id": "",
        },
    )


def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point reportal at a fresh database and workspace under *tmp_path*."""
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(DB_ENV, str(tmp_path / "reportal.db"))
    store.init_db(tmp_path / "reportal.db")
    return tmp_path


def _render(data: bytes, tmp_path: Path) -> str | None:
    """Extract the PDF text with pdftotext, or None when it is not installed."""
    if PDFTOTEXT is None:
        return None
    target = tmp_path / "extract.pdf"
    target.write_bytes(data)
    result = subprocess.run(
        [PDFTOTEXT, str(target), "-"], capture_output=True, text=True, check=False
    )
    return result.stdout


def _xref_offsets(data: bytes) -> tuple[dict[int, int], int]:
    """Return the xref object offsets and the ``startxref`` value."""
    start = data.index(b"xref\n")
    end = data.index(b"trailer\n", start)
    lines = data[start:end].decode("ascii").splitlines()
    assert lines[0] == "xref"
    offsets: dict[int, int] = {}
    for index, line in enumerate(lines[2:]):
        offsets[index] = int(line[:10])
    match = re.search(rb"startxref\n(\d+)\n", data)
    assert match is not None
    startxref = int(match.group(1))
    return offsets, startxref


class TestPdfStructure:
    def test_header_and_eof(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _binary(conn)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert data.startswith(b"%PDF-1.4\n")
        assert data.endswith(b"%%EOF\n")

    def test_xref_offsets_point_at_objects(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _binary(conn)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        offsets, startxref = _xref_offsets(data)
        assert data[startxref : startxref + 4] == b"xref"
        assert offsets[0] == 0
        for number, offset in offsets.items():
            if number == 0:
                continue
            assert data[offset:].startswith(f"{number} 0 obj".encode("ascii"))

    def test_catalog_and_page_tree_objects(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _binary(conn)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert b"/Type /Catalog" in data
        assert b"/Type /Pages" in data
        assert b"/BaseFont /Helvetica" in data
        assert b"/BaseFont /Helvetica-Bold" in data

    def test_empty_binary_is_one_valid_page(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _binary(conn)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert pdf.page_count(data) == 1
        assert b"/Count 1" in data

    def test_page_count_helper_counts_page_objects(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert pdf.page_count(data) == len(re.findall(rb"/Type /Page\b", data))

    def test_unknown_binary_raises_keyerror(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            pdf.render_report(conn, binary_id=999)


class TestPageCountAndText:
    def test_page_count_grows_with_content(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, analysis_id = _binary(conn)
        small = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_CAPABILITIES,
            {
                "binary_id": binary_id,
                "count": pdf.MAX_ROWS_PER_SECTION,
                "capabilities": [
                    {
                        "name": f"capability-{index}-" + "x" * 400,
                        "confidence": "high",
                        "evidence_count": index,
                    }
                    for index in range(pdf.MAX_ROWS_PER_SECTION)
                ],
            },
        )
        large = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert pdf.page_count(large) > pdf.page_count(small)

    def test_pdfinfo_reports_same_page_count(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        if PDFINFO is None:
            pytest.skip("pdfinfo not installed")
        binary_id, _ = _binary(conn)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        target = tmp_path / "report.pdf"
        target.write_bytes(data)
        result = subprocess.run([PDFINFO, str(target)], capture_output=True, text=True, check=False)
        match = re.search(r"^Pages:\s+(\d+)", result.stdout, re.MULTILINE)
        assert match is not None
        assert int(match.group(1)) == pdf.page_count(data)

    def test_fallback_streams_hold_expected_strings(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        for marker in (b"Coverage", b"Fingerprint", b"Capabilities", b"Security", b"Crypto"):
            assert marker in data

    def test_pdftotext_lists_sections(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        if PDFTOTEXT is None:
            pytest.skip("pdftotext not installed")
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        text = _render(pdf.render_report(conn, binary_id=binary_id, generated=GENERATED), tmp_path)
        assert text is not None
        for marker in (
            "Coverage",
            "Fingerprint",
            "Capabilities",
            "Security",
            "Crypto",
            "Attack surface",
            "Exploitability",
            "Go build",
        ):
            assert marker in text

    def test_new_sections_render_stored_rows(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        if PDFTOTEXT is None:
            pytest.skip("pdftotext not installed")
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        text = _render(pdf.render_report(conn, binary_id=binary_id, generated=GENERATED), tmp_path)
        assert text is not None
        assert "https" in text
        assert "vuln_copy" in text
        assert "go1.27.1" in text
        assert "github.com/google/uuid" in text

    def test_renames_section_lists_a_named_function(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        if PDFTOTEXT is None:
            pytest.skip("pdftotext not installed")
        binary_id, analysis_id = _binary(conn)
        store.add_function(
            conn,
            analysis_id=analysis_id,
            name="main",
            va=0x401000,
            size=64,
            status="analyzed",
        )
        text = _render(pdf.render_report(conn, binary_id=binary_id, generated=GENERATED), tmp_path)
        assert text is not None
        assert "Renames" in text
        assert "main" in text

    def test_pdftotext_shows_title_block(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        if PDFTOTEXT is None:
            pytest.skip("pdftotext not installed")
        binary_id, _ = _binary(conn, name="notepad.exe")
        text = _render(pdf.render_report(conn, binary_id=binary_id, generated=GENERATED), tmp_path)
        assert text is not None
        assert "notepad.exe" in text
        assert GENERATED in text

    def test_header_and_footer_on_every_page(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        layout = pdf.PdfLayout(header="demo.exe")
        for index in range(200):
            layout.text(f"line {index} of a long section body")
        pages = layout.page_count
        data = layout.build()
        assert pages > 1
        assert pdf.page_count(data) == pages
        assert data.count(b"demo.exe") >= pages
        for index in range(1, pages + 1):
            assert f"Page {index} of {pages}".encode() in data


class TestSectionOmission:
    def test_absent_scans_leave_sections_out(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _binary(conn)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        for heading in (b"Coverage", b"Fingerprint", b"Capabilities", b"Security", b"Crypto"):
            assert heading not in data

    def test_coverage_omitted_without_stored_report(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _binary(conn)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert b"Coverage" not in data

    def test_coverage_from_engine_when_report_absent(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class AvailableEngine(FakeEngine):
            def available(self) -> bool:
                return True

        _project(tmp_path, monkeypatch)
        binary_id, _ = _binary(conn)
        store.set_rebrew_context(conn, binary_id, "/projects/demo")
        engine = AvailableEngine()
        data = pdf.render_report(conn, binary_id=binary_id, engine=engine, generated=GENERATED)
        assert b"Coverage" in data
        assert engine.calls == ["report"]

    def test_stored_report_wins_and_skips_engine(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class AvailableEngine(FakeEngine):
            def available(self) -> bool:
                return True

        _project(tmp_path, monkeypatch)
        binary_id, analysis_id = _binary(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_REPORT, REPORT)
        engine = AvailableEngine()
        pdf.render_report(conn, binary_id=binary_id, engine=engine, generated=GENERATED)
        assert engine.calls == []


class TestCapsAndEscaping:
    def test_capability_rows_are_capped(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_CAPABILITIES,
            {
                "binary_id": binary_id,
                "count": 60,
                "capabilities": [
                    {"name": f"cap-{index:02d}", "confidence": "high", "evidence_count": index}
                    for index in range(60)
                ],
            },
        )
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        shown = [f"cap-{index:02d}" for index in range(60) if f"cap-{index:02d}".encode() in data]
        assert len(shown) == pdf.MAX_ROWS_PER_SECTION

    def test_remediation_rule_body_is_capped(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        body = "\n".join(f"rule line {index}" for index in range(60))
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_REMEDIATION,
            {
                "binary_id": binary_id,
                "rule": body,
                "rule_name": "demo_rule",
                "specificity": "weak",
                "string_count": 1,
                "import_count": 0,
                "validated": False,
            },
        )
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert f"rule line {pdf.RULE_BODY_LINE_CAP - 1}".encode() in data
        assert f"rule line {pdf.RULE_BODY_LINE_CAP}".encode() not in data
        assert b"more line" in data

    def test_secret_values_are_never_written(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert b"AKIAIOSFODNN7EXAMPLE" not in data
        assert b"Secrets" in data

    def test_escaped_text_survives_extraction(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, analysis_id = _binary(conn)
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_CAPABILITIES,
            {
                "binary_id": binary_id,
                "count": 1,
                "capabilities": [
                    {"name": "socket (raw) \\ pipe", "confidence": "high", "evidence_count": 1}
                ],
            },
        )
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert b"socket \\(raw\\) \\\\ pipe" in data
        if PDFTOTEXT is not None:
            text = _render(data, tmp_path)
            assert text is not None
            assert "socket (raw) \\ pipe" in text


class TestLayoutHelpers:
    def test_wrap_text_keeps_lines_within_width(self) -> None:
        lines = pdf.wrap_text("alpha beta gamma delta epsilon zeta", 60.0, 9.0)
        assert len(lines) > 1
        for line in lines:
            assert pdf.text_width(line, 9.0) <= 60.0

    def test_wrap_text_hard_splits_long_word(self) -> None:
        lines = pdf.wrap_text("x" * 120, 60.0, 9.0)
        assert len(lines) > 1
        assert "".join(lines) == "x" * 120
        for line in lines:
            assert pdf.text_width(line, 9.0) <= 60.0

    def test_wrap_text_collapses_blank_input(self) -> None:
        assert pdf.wrap_text("", 100.0) == [""]
        assert pdf.wrap_text("   ", 100.0) == [""]

    def test_layout_paginates_past_bottom_margin(self) -> None:
        layout = pdf.PdfLayout(header="hdr")
        for index in range(5):
            layout.text(f"row {index}")
        assert layout.page_count == 1
        for index in range(200):
            layout.text(f"row {index}")
        assert layout.page_count > 1

    def test_layout_records_sections(self) -> None:
        layout = pdf.PdfLayout(header="hdr")
        layout.heading("Alpha")
        layout.text("body")
        layout.heading("Beta")
        assert layout.sections == ("Alpha", "Beta")

    def test_table_columns_stay_inside_the_frame(self) -> None:
        layout = pdf.PdfLayout(header="hdr")
        layout.table(["a", "b"], [["x" * 50, "y" * 50]], [0.5, 0.5])
        data = layout.build()
        x_positions = [float(match) for match in re.findall(rb"1 0 0 1 ([\d.]+) [\d.]+ Tm", data)]
        assert x_positions
        assert min(x_positions) >= pdf.MARGIN_LEFT
        assert max(x_positions) < pdf.PAGE_WIDTH - pdf.MARGIN_RIGHT


class TestSections:
    def test_all_stored_scans_render(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        for heading in (
            b"Coverage",
            b"Fingerprint",
            b"Capabilities",
            b"Triage",
            b"Function triage",
            b"Security",
            b"Crypto",
            b"Threat",
            b"Secrets",
            b"Behavior",
            b"Protocols",
            b"Hardening",
            b"Remediation",
            b"Lineage",
        ):
            assert heading in data

    def test_threat_ioc_and_technique_rows(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert b"urls" in data
        assert b"T1071" in data

    def test_lineage_counts(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        data = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert b"other.exe" in data
        assert b"66.67" in data


class TestDeterminismAndWrite:
    def test_same_input_same_bytes(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        first = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        second = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        assert first == second

    def test_different_date_changes_bytes(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _binary(conn)
        first = pdf.render_report(conn, binary_id=binary_id, generated=GENERATED)
        second = pdf.render_report(conn, binary_id=binary_id, generated="2026-02-03T00:00:00+00:00")
        assert first != second

    def test_write_report_returns_summary(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        target = tmp_path / "out" / "report.pdf"
        result = pdf.write_report(conn, binary_id=binary_id, path=target, generated=GENERATED)
        assert result["path"] == str(target)
        assert target.read_bytes().startswith(b"%PDF-1.4")
        assert result["bytes"] == len(target.read_bytes())
        assert result["pages"] == pdf.page_count(target.read_bytes())
        assert "Coverage" in result["sections"]

    def test_write_report_leaves_no_temp_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = _binary(conn)
        target = tmp_path / "report.pdf"
        pdf.write_report(conn, binary_id=binary_id, path=target, generated=GENERATED)
        assert target.is_file()
        assert not [path for path in tmp_path.iterdir() if path.name.endswith(".tmp")]

    @pytest.mark.parametrize("filename", ["report.pdf", "r" * 246 + ".pdf"])
    def test_write_report_overwrites_atomically(
        self, conn: sqlite3.Connection, tmp_path: Path, filename: str
    ) -> None:
        binary_id, _ = _binary(conn)
        target = tmp_path / filename
        first = pdf.write_report(conn, binary_id=binary_id, path=target, generated=GENERATED)
        second = pdf.write_report(conn, binary_id=binary_id, path=target, generated="other")
        assert first["bytes"] != second["bytes"]
        assert target.read_bytes() == pdf.render_report(
            conn, binary_id=binary_id, generated="other"
        )


class TestMcpTools:
    def test_tool_annotations(self) -> None:
        status = mcp_tools.get_tool("get_pdf_status")
        generate = mcp_tools.get_tool("generate_pdf_report")
        assert status is not None
        assert generate is not None
        assert status.annotations.read_only_hint
        assert not status.annotations.destructive_hint
        assert generate.annotations.destructive_hint
        assert not generate.annotations.read_only_hint

    def test_status_absent(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, monkeypatch)
        binary_id, _ = _binary(conn)
        tool = mcp_tools.get_tool("get_pdf_status")
        assert tool is not None
        payload = tool.handler({"binary_id": binary_id})
        assert payload["exists"] is False
        assert payload["bytes"] == 0
        assert payload["pages"] == 0

    def test_generate_then_status(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, monkeypatch)
        binary_id, analysis_id = _binary(conn)
        _seed_scans(conn, analysis_id, binary_id)
        generate = mcp_tools.get_tool("generate_pdf_report")
        status = mcp_tools.get_tool("get_pdf_status")
        assert generate is not None
        assert status is not None
        written = generate.handler({"binary_id": binary_id})
        assert Path(written["path"]).is_file()
        payload = status.handler({"binary_id": binary_id})
        assert payload["exists"] is True
        assert payload["pages"] == written["pages"]
        assert payload["bytes"] == written["bytes"]

    def test_generate_unknown_binary(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, monkeypatch)
        generate = mcp_tools.get_tool("generate_pdf_report")
        assert generate is not None
        with pytest.raises(mcp_tools.ToolError):
            generate.handler({"binary_id": 999})


class TestPdfSectionGuards:
    def test_empty_sections_render_nothing(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="ab" * 32, name="demo.exe", path=str(target), size=2
        )
        layout = pdf.PdfLayout(header="report")
        pdf._capabilities_section(layout, conn, binary_id)
        pdf._triage_section(layout, conn, binary_id)
        pdf._protocols_section(layout, conn, binary_id)
        assert isinstance(layout.build(), bytes)


class TestPdfUnknownBinary:
    def test_unknown_binary_sections_render_nothing(self, conn: sqlite3.Connection) -> None:
        layout = pdf.PdfLayout(header="report")
        pdf._attack_surface_section(layout, conn, 424242)
        pdf._exploitability_section(layout, conn, 424242)
        pdf._renames_section(layout, conn, 424242)
        assert isinstance(layout.build(), bytes)


STORED_SECTIONS = ("Family detection", "Related binaries", "Composition", "AI summaries")


def _seed_stored_analysis(conn: sqlite3.Connection, analysis_id: int, binary_id: int) -> None:
    """Store a detect, related and composition scan and one AI summary."""
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_DETECT,
        {
            "binary_id": binary_id,
            "families_checked": 3,
            "matches": [
                {
                    "family_id": 1,
                    "name": "Emotet",
                    "aliases": [],
                    "confidence": "high",
                    "signals": [{"kind": "imphash"}, {"kind": "strings"}],
                    "similarity": 0.91,
                }
            ],
            "count": 1,
            "notes": [],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_RELATED,
        {
            "binary_id": binary_id,
            "candidates_considered": 4,
            "related": [
                {
                    "binary_id": 9,
                    "name": "sibling-dropper.exe",
                    "classification": "variant",
                    "confidence": "medium",
                    "signals": [],
                    "similarity": 0.72,
                }
            ],
            "count": 1,
            "notes": [],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_COMPOSITION,
        {
            "binary_id": binary_id,
            "total_functions": 10,
            "matched_functions": 4,
            "matched_percent": 40.0,
            "categories": [
                {"category": "library", "label": "Library", "count": 3, "percent": 30.0},
                {"category": "unique", "label": "Unique", "count": 7, "percent": 70.0},
            ],
            "composition": [
                {"binary_id": 9, "name": "zlib-reference.dll", "count": 4, "percent": 40.0}
            ],
        },
    )
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x401000, name="decode_config", size=64
    )
    store.set_ai_artifact(
        conn, function_id, llm.AI_KIND_SUMMARY, {"summary": "XOR-decodes the C2 list."}, "m"
    )


class TestStoredAnalysisSections:
    def test_sections_render_when_stored(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, analysis_id = _binary(conn)
        _seed_stored_analysis(conn, analysis_id, binary_id)
        report = pdf.write_report(
            conn, binary_id=binary_id, path=tmp_path / "r.pdf", generated=GENERATED
        )
        for heading in STORED_SECTIONS:
            assert heading in report["sections"]
        text = _render((tmp_path / "r.pdf").read_bytes(), tmp_path)
        if text is None:
            pytest.skip("pdftotext not installed")
        for value in (
            "Emotet",
            "sibling-dropper.exe",
            "variant",
            "zlib-reference.dll",
            "Library",
            "decode_config",
            "0x401000",
            "XOR-decodes the C2 list.",
        ):
            assert value in text

    def test_sections_are_omitted_when_absent(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, analysis_id = _binary(conn)
        store.add_function(conn, analysis_id=analysis_id, va=0x401000, name="main", size=8)
        report = pdf.write_report(
            conn, binary_id=binary_id, path=tmp_path / "r.pdf", generated=GENERATED
        )
        for heading in STORED_SECTIONS:
            assert heading not in report["sections"]

    def test_a_blank_summary_is_not_a_section(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _binary(conn)
        function_id = store.add_function(conn, analysis_id=analysis_id, va=0x10, name="f")
        store.set_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY, {"summary": "  "}, "m")
        layout = pdf.PdfLayout(header="report")
        pdf._ai_summary_section(layout, conn, binary_id)
        assert "AI summaries" not in layout.sections

    def test_summaries_of_another_binary_are_not_shown(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _binary(conn)
        other_id = store.add_binary(conn, sha256="cd" * 32, name="other.exe")
        other_analysis = store.create_analysis(conn, binary_id=other_id, engine="manual")
        function_id = store.add_function(conn, analysis_id=other_analysis, va=0x10, name="g")
        store.set_ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY, {"summary": "other"}, "m")
        layout = pdf.PdfLayout(header="report")
        pdf._ai_summary_section(layout, conn, binary_id)
        assert "AI summaries" not in layout.sections

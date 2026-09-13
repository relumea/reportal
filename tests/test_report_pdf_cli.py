"""Tests for the `reportal report-pdf` command."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reportal import cli, pdf, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    """Create a workspace with one binary and one stored capability scan."""
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "reportal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="ef" * 32, name="demo.exe", path="/x/demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_CAPABILITIES,
            {
                "binary_id": binary_id,
                "count": 1,
                "capabilities": [{"name": "network", "confidence": "high", "evidence_count": 1}],
            },
        )
    return binary_id


class TestReportPdfCommand:
    def test_default_output_lands_in_workspace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["report-pdf", str(binary_id)])
        assert result.exit_code == 0, result.output
        target = tmp_path / "reports" / str(binary_id) / pdf.REPORT_PDF_NAME
        assert target.is_file()
        assert target.read_bytes().startswith(b"%PDF-1.4")
        assert "page(s)" in result.output
        assert "Sections:" in result.output

    def test_json_payload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["report-pdf", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["path"] == str(tmp_path / "reports" / str(binary_id) / pdf.REPORT_PDF_NAME)
        assert payload["bytes"] > 0
        assert payload["pages"] >= 1
        assert "Capabilities" in payload["sections"]

    def test_output_writes_elsewhere(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = _seed(tmp_path, monkeypatch)
        target = tmp_path / "elsewhere" / "custom.pdf"
        result = runner.invoke(cli.app, ["report-pdf", str(binary_id), "--output", str(target)])
        assert result.exit_code == 0, result.output
        assert target.is_file()
        assert not (tmp_path / "reports" / str(binary_id) / pdf.REPORT_PDF_NAME).exists()

    def test_output_refuses_overwrite_without_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed(tmp_path, monkeypatch)
        target = tmp_path / "custom.pdf"
        target.write_bytes(b"keep me")
        result = runner.invoke(cli.app, ["report-pdf", str(binary_id), "--output", str(target)])
        assert result.exit_code == 1
        assert "exists" in result.output
        assert target.read_bytes() == b"keep me"

    def test_output_overwrites_with_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed(tmp_path, monkeypatch)
        target = tmp_path / "custom.pdf"
        target.write_bytes(b"keep me")
        result = runner.invoke(
            cli.app, ["report-pdf", str(binary_id), "--output", str(target), "--force"]
        )
        assert result.exit_code == 0, result.output
        assert target.read_bytes().startswith(b"%PDF-1.4")

    def test_default_output_regenerates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed(tmp_path, monkeypatch)
        first = runner.invoke(cli.app, ["report-pdf", str(binary_id), "--json"])
        second = runner.invoke(cli.app, ["report-pdf", str(binary_id), "--json"])
        assert first.exit_code == 0, first.output
        assert second.exit_code == 0, second.output

    def test_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["report-pdf", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_missing_database_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(DB_ENV, str(tmp_path / "reportal.db"))
        result = runner.invoke(cli.app, ["report-pdf", "1", "--json"])
        assert result.exit_code == 1
        assert "no reportal database" in result.stdout

    def test_renders_stored_scans_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["report-pdf", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert "Capabilities" in payload["sections"]
        assert "Fingerprint" not in payload["sections"]

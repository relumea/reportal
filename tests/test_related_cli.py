"""Tests for the `related` CLI command."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reportal import cli, engines, store

runner = CliRunner()

SHA = "aa" * 32


def _binary(
    conn: sqlite3.Connection, tmp_path: Path, *, name: str, sha: str, size: int = 1000
) -> int:
    path = tmp_path / name
    path.write_bytes(b"MZ" + name.encode())
    return store.add_binary(conn, sha256=sha, name=name, path=str(path), size=size, fmt="EXE")


def _fingerprint(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    sha256: str,
    fmt: str = "pe",
    arch: str = "x86_32",
    size: int = 1000,
) -> None:
    store.set_fingerprint(
        conn,
        binary_id,
        {
            "sha256": sha256,
            "imphash": None,
            "rich_header_hash": None,
            "format": fmt,
            "arch": arch,
            "size": size,
        },
    )


def _seed(conn: sqlite3.Connection, tmp_path: Path) -> tuple[int, int]:
    target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
    other = _binary(conn, tmp_path, name="other.exe", sha="bb" * 32)
    _fingerprint(conn, target, sha256=SHA)
    _fingerprint(conn, other, sha256=SHA)
    return target, other


class TestRelatedCommand:
    def test_human_output_shows_the_ranking(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        target, other = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["related", str(target)])
        assert result.exit_code == 0, result.output
        assert "1 related of 1 candidates" in result.output
        assert "identical" in result.output
        assert "other.exe" in result.output

    def test_json_stores_the_scan(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        target, other = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["related", str(target), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["related"][0]["binary_id"] == other
        assert payload["related"][0]["classification"] == "identical"
        analysis_id = store.latest_analysis_for_binary(conn, target)
        payload.pop("journal_action", None)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_RELATED) == payload

    def test_no_related_binary_says_so(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        result = runner.invoke(cli.app, ["related", str(target)])
        assert result.exit_code == 0, result.output
        assert "No related binary found" in result.output

    def test_all_includes_unrelated(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA, size=1)
        _fingerprint(conn, target, sha256=SHA, fmt="elf", arch="x86_64", size=1)
        other = _binary(conn, tmp_path, name="other.exe", sha="bb" * 32, size=999999)
        _fingerprint(conn, other, sha256="bb" * 32, fmt="elf", arch="x86_64", size=999999)
        result = runner.invoke(cli.app, ["related", str(target), "--all", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["related"][0]["classification"] == "unrelated"

    def test_limit_caps_the_rows(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        for index in range(3):
            other = _binary(conn, tmp_path, name=f"other{index}.exe", sha=f"b{index}" * 32)
            _fingerprint(conn, other, sha256=SHA)
        result = runner.invoke(cli.app, ["related", str(target), "--limit", "1", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["candidates_considered"] == 3
        assert payload["count"] == 1

    def test_unknown_binary_fails(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["related", "999", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 999" in result.stdout

    def test_bad_limit_fails(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        result = runner.invoke(cli.app, ["related", str(target), "--limit", "0", "--json"])
        assert result.exit_code == 1
        assert "must be positive" in result.stdout

    def test_missing_database_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portal_db: Path
    ) -> None:
        monkeypatch.setenv("REPORTAL_DB", str(tmp_path / "absent.db"))
        result = runner.invoke(cli.app, ["related", "1", "--json"])
        assert result.exit_code == 1
        assert "no reportal database" in result.stdout

"""Tests for the `families`, `family-add`, `family-rm` and `detect` CLI commands."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

import pytest
from conftest import FakeEngine
from typer.testing import CliRunner

from reportal import cli, engines, store

runner = CliRunner()

NAME = "DemoFamily"


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, name: str = "demo.exe") -> int:
    target = tmp_path / name
    target.write_bytes(b"MZ" + b"\x00" * 30)
    sha = name.encode().hex().ljust(64, "0")
    return store.add_binary(conn, sha256=sha, name=name, path=str(target))


def _register(binary_id: int, *extra: str) -> int:
    result = runner.invoke(cli.app, ["family-add", str(binary_id), NAME, *extra, "--json"])
    assert result.exit_code == 0, result.output
    return int(json.loads(result.stdout)["family_id"])


class TestFamiliesCommand:
    def test_lists_registered_families(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _register(binary_id)
        result = runner.invoke(cli.app, ["families"])
        assert result.exit_code == 0, result.output
        assert NAME in result.output
        assert str(binary_id) in result.output

    def test_json_lists_registered_families(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        family_id = _register(binary_id)
        result = runner.invoke(cli.app, ["families", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert [row["family_id"] for row in payload["families"]] == [family_id]

    def test_empty_list_says_so(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["families"])
        assert result.exit_code == 0, result.output
        assert "No families registered" in result.output


class TestFamilyAddCommand:
    def test_registers_and_prints_the_signatures(
        self,
        conn: sqlite3.Connection,
        portal_db: Path,
        tmp_path: Path,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = runner.invoke(
            cli.app,
            [
                "family-add",
                str(binary_id),
                NAME,
                "--alias",
                "DEMO.A",
                "--notes",
                "first",
            ],
        )
        assert result.exit_code == 0, result.output
        assert NAME in result.output
        assert "sha256" in result.output
        with contextlib.closing(store.connect(portal_db)) as fresh:
            stored = store.list_families(fresh)
        assert stored[0]["name"] == NAME
        assert stored[0]["aliases"] == ["DEMO.A"]
        assert stored[0]["notes"] == "first"

    def test_json_prints_the_family(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = runner.invoke(cli.app, ["family-add", str(binary_id), NAME, "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["name"] == NAME
        assert payload["signatures"]["import_hash"]

    def test_duplicate_name_fails(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _register(binary_id)
        result = runner.invoke(cli.app, ["family-add", str(binary_id), NAME.lower(), "--json"])
        assert result.exit_code == 1
        assert "already exists" in result.stdout

    def test_unknown_binary_fails(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        result = runner.invoke(cli.app, ["family-add", "999", NAME, "--json"])
        assert result.exit_code == 1
        assert "no binary with id 999" in result.stdout

    def test_without_engine_fails(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["family-add", str(binary_id), NAME, "--json"])
        assert result.exit_code == 1
        assert "analysis engine unavailable" in result.stdout


class TestFamilyRmCommand:
    def test_deletes_a_family(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        family_id = _register(binary_id)
        result = runner.invoke(cli.app, ["family-rm", str(family_id)])
        assert result.exit_code == 0, result.output
        assert store.list_families(conn) == []

    def test_json_reports_the_deletion(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        family_id = _register(binary_id)
        result = runner.invoke(cli.app, ["family-rm", str(family_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        payload.pop("journal_action", None)
        assert payload == {"family_id": family_id, "deleted": True}

    def test_unknown_family_fails(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["family-rm", "404", "--json"])
        assert result.exit_code == 1
        assert "no family with id 404" in result.stdout


class TestDetectCommand:
    def test_human_output_shows_the_match_and_its_signals(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        reference = _seed(conn, tmp_path, name="reference.exe")
        _register(reference)
        target = _seed(conn, tmp_path, name="target.exe")
        result = runner.invoke(cli.app, ["detect", str(target)])
        assert result.exit_code == 0, result.output
        assert NAME in result.output
        assert "exact-binary" in result.output
        assert "1 matches" in result.output

    def test_json_stores_the_scan(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        reference = _seed(conn, tmp_path, name="reference.exe")
        _register(reference)
        target = _seed(conn, tmp_path, name="target.exe")
        result = runner.invoke(cli.app, ["detect", str(target), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["matches"][0]["name"] == NAME
        analysis_id = store.latest_analysis_for_binary(conn, target)
        payload.pop("journal_action", None)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_DETECT) == payload

    def test_unknown_binary_fails(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        result = runner.invoke(cli.app, ["detect", "999", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 999" in result.stdout

    def test_without_engine_fails(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["detect", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "analysis engine unavailable" in result.stdout

    def test_no_match_is_a_success(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        monkeypatch.setattr(
            fake_engine,
            "fingerprint",
            lambda binary: {"sha256": "00" * 32, "imphash": None, "rich_header_hash": None},
        )
        monkeypatch.setattr(fake_engine, "imports", lambda binary: {"imports": []})
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": []})
        result = runner.invoke(cli.app, ["detect", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "No family matched" in result.output

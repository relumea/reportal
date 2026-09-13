"""Tests for reportal._paths workspace resolution."""

from __future__ import annotations

from pathlib import Path

import pytest
from rebrew.workspace import sqlite_ro_uri
from typer.testing import CliRunner

from reportal import cli
from reportal._paths import DB_ENV, WorkspaceNotFound, db_path, project_root

runner = CliRunner()


class TestProjectRoot:
    def test_finds_marker_by_walking_up(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        monkeypatch.chdir(nested)
        assert project_root() == tmp_path

    def test_raises_without_marker(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        with pytest.raises(WorkspaceNotFound, match="no reportal workspace found"):
            project_root()

    def test_nearest_marker_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        inner = tmp_path / "inner"
        inner.mkdir()
        (inner / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(inner)
        assert project_root() == inner.resolve()


class TestDbPath:
    def test_defaults_to_project_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(DB_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        assert db_path() == tmp_path.resolve() / "reportal.db"

    def test_env_override_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        override = tmp_path / "elsewhere" / "custom.db"
        monkeypatch.setenv(DB_ENV, str(override))
        monkeypatch.chdir(tmp_path)
        assert db_path() == override.resolve()

    def test_raises_outside_workspace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(DB_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        with pytest.raises(WorkspaceNotFound, match="run 'reportal init'"):
            db_path()


class TestInitOutsideWorkspace:
    def test_init_from_unrelated_cwd_targets_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        target = tmp_path / "workspace"
        monkeypatch.delenv(DB_ENV, raising=False)
        monkeypatch.chdir(elsewhere)

        result = runner.invoke(cli.app, ["init", "--dir", str(target)])
        assert result.exit_code == 0, result.output
        assert (target / "reportal.toml").is_file()
        assert (target / "reportal.db").is_file()
        assert not (elsewhere / "reportal.db").exists()


class TestSqliteUri:
    def test_read_only_uri(self, tmp_path: Path) -> None:
        uri = sqlite_ro_uri(tmp_path / "portal.db")
        assert uri.endswith("?mode=ro")
        assert uri.startswith("file://")

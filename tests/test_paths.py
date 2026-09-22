"""Tests for reportal._paths workspace resolution."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from rebrew.workspace import sqlite_ro_uri
from typer.testing import CliRunner

from reportal import _paths, cli
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
        monkeypatch.setenv(_paths.DB_ENV, str(override))
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


class TestAtomicWriters:
    def test_round_trip(self, tmp_path: Path) -> None:
        target = tmp_path / "sub" / "f.bin"
        assert _paths.write_bytes_atomic(target, b"data") == target
        assert target.read_bytes() == b"data"
        text = tmp_path / "t.txt"
        assert _paths.write_text_atomic(text, "hi") == text
        assert text.read_text(encoding="utf-8") == "hi"

    def test_fdopen_failure_closes_the_fd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        closed: list[int] = []
        real_close = os.close

        def boom(handle: int, *args: object, **kwargs: object) -> object:
            raise OSError("denied")

        monkeypatch.setattr("os.fdopen", boom)
        monkeypatch.setattr("os.close", lambda handle: closed.append(handle))
        try:
            with pytest.raises(OSError):
                _paths.write_bytes_atomic(tmp_path / "f.bin", b"x")
        finally:
            monkeypatch.setattr("os.close", real_close)
        assert closed

    def test_replace_failure_removes_the_temp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(src: object, dst: object, *args: object, **kwargs: object) -> None:
            raise OSError("denied")

        monkeypatch.setattr("os.replace", boom)
        with pytest.raises(OSError):
            _paths.write_text_atomic(tmp_path / "f.txt", "x")
        assert list(tmp_path.glob("*.tmp")) == []


class TestPathValidation:
    def test_stored_binary_path_checks_under_binaries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "reportal.toml").write_text("[portal]\n")
        monkeypatch.chdir(tmp_path)
        binaries = tmp_path / "binaries"
        binaries.mkdir()
        inside = binaries / "a.bin"
        inside.write_bytes(b"x")
        assert _paths.stored_binary_path(inside) is True
        assert _paths.stored_binary_path(tmp_path / "outside.bin") is False

    def test_workspace_root_uses_db_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_paths.DB_ENV, str(tmp_path / "sub" / "reportal.db"))
        assert _paths.workspace_root() == (tmp_path / "sub").resolve()

    def test_under_workspace_checks_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_paths.DB_ENV, str(tmp_path / "reportal.db"))
        inside = tmp_path / "reports" / "x.pdf"
        assert _paths.under_workspace(inside) is True
        assert _paths.under_workspace("/etc/passwd") is False

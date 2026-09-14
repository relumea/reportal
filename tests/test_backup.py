"""Tests for the workspace backup and restore.

Every test works in a temporary workspace, so nothing here touches the real one.
The round trip is the interesting case: an archive is made in one directory and
read back into another, which is what a movable install means.
"""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import tarfile
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from reportal import backup, cli, store

runner = CliRunner()


def _workspace(root: Path) -> Path:
    """A real workspace with one binary whose file is on disk."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "reportal.toml").write_text("", encoding="utf-8")
    db = root / "reportal.db"
    store.init_db(db)
    stored = root / "binaries" / ("aa" * 32)
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_bytes(b"MZ" + b"\x00" * 30)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(
            conn, sha256="aa" * 32, name="demo.exe", path=str(stored), size=32
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16, status="STUB"
        )
    reports = root / "reports" / str(binary_id)
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "report.html").write_text("<html></html>", encoding="utf-8")
    return root


def _paths(db: Path) -> dict[int, str]:
    connection = sqlite3.connect(db)
    connection.row_factory = sqlite3.Row
    try:
        return {
            int(row["id"]): str(row["path"])
            for row in connection.execute("SELECT id, path FROM binaries")
        }
    finally:
        connection.close()


def _names(archive: Path) -> list[str]:
    with tarfile.open(archive, "r:gz") as tar:
        return sorted(tar.getnames())


def _rewrite(archive: Path, mutate: Any) -> Path:
    """One archive rebuilt through *mutate* on its member list, for the refusals."""
    target = archive.with_name("mutated.tar.gz")
    with tarfile.open(archive, "r:gz") as source, tarfile.open(target, "w:gz") as sink:
        for member in source.getmembers():
            handle = source.extractfile(member) if member.isfile() else None
            payload = handle.read() if handle is not None else None
            changed = mutate(member, payload)
            if changed is None:
                continue
            name, data = changed
            member.name = name
            if data is None:
                sink.addfile(member)
            else:
                member.size = len(data)
                sink.addfile(member, io.BytesIO(data))
    return target


class TestCreate:
    def test_the_archive_carries_the_workspace(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        result = backup.create(workspace=root)
        archive = Path(result["path"])
        assert archive.is_file()
        names = _names(archive)
        assert "reportal.db" in names
        assert "reportal.toml" in names
        assert f"binaries/{'aa' * 32}" in names
        assert f"reports/{result['manifest']['counts']['binaries'] or 1}/report.html" in names
        manifest = result["manifest"]
        assert manifest["format"] == backup.FORMAT
        assert manifest["counts"]["binaries"] == 1
        assert manifest["counts"]["reports"] == 1
        assert manifest["root"] == str(root.resolve())

    def test_an_explicit_output_is_honoured(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        target = tmp_path / "elsewhere" / "snapshot.tar.gz"
        result = backup.create(output=target, workspace=root)
        assert Path(result["path"]) == target
        assert target.is_file()

    def test_a_directory_without_a_database_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(backup.BackupError) as failure:
            backup.create(workspace=tmp_path / "empty")
        assert failure.value.code == backup.ERROR_NOT_A_WORKSPACE

    def test_the_database_in_the_archive_is_readable(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        result = backup.create(workspace=root)
        with contextlib.closing(store.connect(Path(result["path"]))) as _unused:
            pass
        with tarfile.open(result["path"], "r:gz") as tar:
            extracted = tar.extractfile("reportal.db")
            assert extracted is not None
            staged = tmp_path / "staged.db"
            staged.write_bytes(extracted.read())
        with contextlib.closing(store.connect(staged)) as conn:
            rows = store.list_binaries(conn)
            assert [row["name"] for row in rows] == ["demo.exe"]


class TestRestore:
    def test_a_round_trip_into_another_directory(self, tmp_path: Path) -> None:
        source = _workspace(tmp_path / "one")
        archive = Path(backup.create(workspace=source)["path"])
        before = _paths(source / "reportal.db")

        target = tmp_path / "two"
        target.mkdir()
        result = backup.restore(archive, workspace=target)
        assert result["rewritten"] == 1
        assert result["external"] == 0
        after = _paths(target / "reportal.db")
        assert list(after.values())[0] == str(target / "binaries" / ("aa" * 32))
        assert list(before.values())[0] != list(after.values())[0]
        assert (target / "binaries" / ("aa" * 32)).read_bytes() == b"MZ" + b"\x00" * 30
        with contextlib.closing(store.connect(target / "reportal.db")) as conn:
            assert [row["name"] for row in store.list_binaries(conn)] == ["demo.exe"]

    def test_a_path_outside_the_workspace_is_left_alone(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        outside = tmp_path / "myproject" / "demo.exe"
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.write_bytes(b"MZ")
        with contextlib.closing(store.connect(root / "reportal.db")) as conn:
            store.add_binary(conn, sha256="bb" * 32, name="imported.exe", path=str(outside), size=2)
        archive = Path(backup.create(workspace=root)["path"])
        target = tmp_path / "two"
        target.mkdir()
        result = backup.restore(archive, workspace=target)
        assert result["external"] == 1
        assert result["rewritten"] == 1
        assert str(outside) in _paths(target / "reportal.db").values()

    def test_an_existing_workspace_needs_overwrite(self, tmp_path: Path) -> None:
        source = _workspace(tmp_path / "one")
        archive = Path(backup.create(workspace=source)["path"])
        target = _workspace(tmp_path / "two")
        with pytest.raises(backup.BackupError) as failure:
            backup.restore(archive, workspace=target)
        assert failure.value.code == backup.ERROR_NOT_A_WORKSPACE

    def test_overwrite_replaces_the_state(self, tmp_path: Path) -> None:
        source = _workspace(tmp_path / "one")
        archive = Path(backup.create(workspace=source)["path"])
        target = tmp_path / "two"
        target.mkdir()
        backup.restore(archive, workspace=target)
        with contextlib.closing(store.connect(target / "reportal.db")) as conn:
            store.add_binary(conn, sha256="cc" * 32, name="extra.exe", size=1)
        backup.restore(archive, workspace=target, overwrite=True)
        with contextlib.closing(store.connect(target / "reportal.db")) as conn:
            assert [row["name"] for row in store.list_binaries(conn)] == ["demo.exe"]

    def test_a_refused_archive_leaves_the_workspace_alone(self, tmp_path: Path) -> None:
        source = _workspace(tmp_path / "one")
        archive = Path(backup.create(workspace=source)["path"])
        broken = _rewrite(
            archive,
            lambda member, payload: (
                ("../escape.txt", b"boom")
                if member.name == "reportal.toml"
                else (member.name, payload)
            ),
        )
        target = tmp_path / "two"
        target.mkdir()
        with pytest.raises(backup.BackupError) as failure:
            backup.restore(broken, workspace=target)
        assert failure.value.code == backup.ERROR_UNSAFE_ARCHIVE
        assert not (target / "reportal.db").exists()
        assert not (tmp_path / "escape.txt").exists()


class TestManifest:
    def test_a_plain_tar_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "not-a-backup.tar.gz"
        with tarfile.open(target, "w:gz") as tar:
            tar.add(tmp_path, arcname="junk")
        with pytest.raises(backup.BackupError) as failure:
            backup.read_manifest(target)
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

    def test_a_member_the_manifest_does_not_name_is_refused(self, tmp_path: Path) -> None:
        archive = Path(backup.create(workspace=_workspace(tmp_path / "one"))["path"])
        extra = archive.with_name("extra.tar.gz")
        with tarfile.open(archive, "r:gz") as source, tarfile.open(extra, "w:gz") as sink:
            for member in source.getmembers():
                handle = source.extractfile(member) if member.isfile() else None
                payload = handle.read() if handle is not None else None
                sink.addfile(member, io.BytesIO(payload) if payload is not None else None)
            info = tarfile.TarInfo("binaries/extra")
            info.size = 1
            sink.addfile(info, io.BytesIO(b"x"))
        with pytest.raises(backup.BackupError) as failure:
            backup.read_manifest(extra)
        assert failure.value.code == backup.ERROR_UNSAFE_ARCHIVE

    def test_an_unknown_format_version_is_refused(self, tmp_path: Path) -> None:
        archive = Path(backup.create(workspace=_workspace(tmp_path / "one"))["path"])

        def bump(member: tarfile.TarInfo, payload: bytes | None) -> tuple[str, bytes | None]:
            if member.name != backup.MANIFEST_NAME or payload is None:
                return (member.name, payload)
            manifest = json.loads(payload.decode("utf-8"))
            manifest["format_version"] = 99
            return (member.name, json.dumps(manifest).encode("utf-8"))

        with pytest.raises(backup.BackupError) as failure:
            backup.read_manifest(_rewrite(archive, bump))
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

    def test_a_missing_archive_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(backup.BackupError):
            backup.describe(tmp_path / "nope.tar.gz")

    def test_describe_reports_the_manifest(self, tmp_path: Path) -> None:
        archive = Path(backup.create(workspace=_workspace(tmp_path / "one"))["path"])
        described = backup.describe(archive)
        assert described["path"] == str(archive)
        assert described["counts"]["binaries"] == 1


class TestCli:
    def test_backup_then_restore_round_trips(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _workspace(tmp_path / "one")
        monkeypatch.chdir(source)
        archive = tmp_path / "snapshot.tar.gz"
        made = runner.invoke(cli.app, ["backup", "--output", str(archive), "--json"])
        assert made.exit_code == 0, made.output
        assert json.loads(made.stdout)["manifest"]["counts"]["binaries"] == 1

        info = runner.invoke(cli.app, ["backup-info", str(archive), "--json"])
        assert info.exit_code == 0, info.output
        assert json.loads(info.stdout)["format"] == backup.FORMAT

        target = tmp_path / "two"
        target.mkdir()
        (target / "reportal.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(target)
        restored = runner.invoke(cli.app, ["restore", str(archive), "--yes", "--json"])
        assert restored.exit_code == 0, restored.output
        payload = json.loads(restored.stdout)
        assert payload["rewritten"] == 1
        assert (target / "reportal.db").is_file()

    def test_restore_refuses_an_existing_workspace(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _workspace(tmp_path / "one")
        monkeypatch.chdir(source)
        archive = tmp_path / "snapshot.tar.gz"
        runner.invoke(cli.app, ["backup", "--output", str(archive)])
        result = runner.invoke(cli.app, ["restore", str(archive), "--yes"])
        assert result.exit_code == 1
        assert "--overwrite" in result.output

    def test_restore_needs_confirmation(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _workspace(tmp_path / "one")
        monkeypatch.chdir(source)
        archive = tmp_path / "snapshot.tar.gz"
        runner.invoke(cli.app, ["backup", "--output", str(archive)])
        target = tmp_path / "two"
        target.mkdir()
        monkeypatch.chdir(target)
        declined = runner.invoke(cli.app, ["restore", str(archive)], input="n\n")
        assert declined.exit_code == 1
        assert not (target / "reportal.db").exists()

    def test_backup_without_a_workspace_fails_loud(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli.app, ["backup", "--json"])
        assert result.exit_code == 1
        assert backup.ERROR_NOT_A_WORKSPACE in result.output

    def test_a_broken_archive_fails_loud(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.chdir(tmp_path)
        broken = tmp_path / "broken.tar.gz"
        broken.write_bytes(b"not a tar")
        result = runner.invoke(cli.app, ["backup-info", str(broken), "--json"])
        assert result.exit_code == 1
        assert backup.ERROR_INVALID_ARCHIVE in result.output

"""Tests for the workspace backup and restore.

Every test works in a temporary workspace, so nothing here touches the real one.
The round trip is the interesting case: an archive is made in one directory and
read back into another, which is what a movable install means.
"""

from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import sqlite3
import tarfile
import time
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from reportal import backup, cli, clock, journal, store, symbols

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
        result = backup.create(workspace=root, output=tmp_path / "snapshot.tar.gz")
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
        assert manifest["database"] == str((root / "reportal.db").resolve())

    def test_an_explicit_output_is_honoured(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        target = tmp_path / "elsewhere" / "snapshot.tar.gz"
        result = backup.create(output=target, workspace=root)
        assert Path(result["path"]) == target
        assert target.is_file()

    def test_publication_stays_on_the_output_filesystem(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _workspace(tmp_path / "one")
        target = tmp_path / "backups" / "snapshot.tar.gz"
        target.parent.mkdir()
        target.write_bytes(b"previous backup")
        real_replace = os.replace
        publications: list[Path] = []

        def replace(source: str | Path, destination: str | Path) -> None:
            staged = Path(source)
            assert staged.parent.parent == target.parent
            assert Path(destination) == target
            assert target.read_bytes() == b"previous backup"
            assert "reportal.db" in _names(staged)
            publications.append(staged)
            real_replace(source, destination)

        monkeypatch.setattr(os, "replace", replace)
        result = backup.create(workspace=root, output=target)
        assert len(publications) == 1
        assert backup.read_manifest(target) == result["manifest"]
        assert list(target.parent.iterdir()) == [target]

    @pytest.mark.parametrize("existing", [False, True])
    def test_failed_publication_leaves_the_destination_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
    ) -> None:
        root = _workspace(tmp_path / "one")
        target = tmp_path / "backups" / "snapshot.tar.gz"
        target.parent.mkdir()
        if existing:
            target.write_bytes(b"previous backup")

        def replace(source: str | Path, destination: str | Path) -> None:
            assert "reportal.db" in _names(Path(source))
            raise OSError(errno.ENOSPC, "disk full")

        monkeypatch.setattr(os, "replace", replace)
        with pytest.raises(backup.BackupError) as failure:
            backup.create(workspace=root, output=target)
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE
        if existing:
            assert target.read_bytes() == b"previous backup"
        else:
            assert not target.exists()
        assert list(target.parent.iterdir()) == ([target] if existing else [])

    def test_the_default_output_lands_outside_the_workspace(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        result = backup.create(workspace=root)
        archive = Path(result["path"])
        assert archive.is_file()
        assert archive.parent == (tmp_path / "reportal-backups")
        assert not archive.is_relative_to(root.resolve())

    def test_suggest_name_uses_the_utc_clock_not_the_host_tz(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A store stamp already in UTC must not be re-interpreted through the
        # host zone: the filename is the absolute instant, fixed-width.
        monkeypatch.setattr(clock, "now", lambda: "2026-03-08T07:30:00+00:00")
        assert backup.suggest_name() == "reportal-backup-20260308T073000.tar.gz"

    def test_suggest_name_treats_a_naive_stamp_as_utc(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # US spring-forward day: datetime(...).astimezone(UTC) on a naive value
        # would read the host zone (America/New_York) and shift the filename by
        # four hours.  store.as_utc treats naive as UTC instead.
        monkeypatch.setenv("TZ", "America/New_York")
        time.tzset()
        monkeypatch.setattr(clock, "now", lambda: "2026-03-08T07:30:00")
        try:
            assert backup.suggest_name() == "reportal-backup-20260308T073000.tar.gz"
        finally:
            monkeypatch.delenv("TZ", raising=False)
            time.tzset()

    def test_an_output_inside_the_workspace_is_refused(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        with pytest.raises(backup.BackupError) as failure:
            backup.create(workspace=root, output=root / "inside.tar.gz")
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

    def test_snapshot_closes_source_when_target_open_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "source.db"
        store.init_db(source)
        opened: list[sqlite3.Connection] = []
        real_connect = sqlite3.connect

        def connect(path: object, *args: object, **kwargs: object) -> sqlite3.Connection:
            conn = real_connect(path, *args, **kwargs)  # type: ignore[call-overload]
            opened.append(conn)
            if len(opened) == 2:
                conn.close()
                raise sqlite3.OperationalError("target open failed")
            return conn  # type: ignore[no-any-return]

        monkeypatch.setattr(sqlite3, "connect", connect)
        with pytest.raises(sqlite3.OperationalError, match="target open failed"):
            backup._snapshot(source, tmp_path / "target.db")
        assert len(opened) == 2
        with pytest.raises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")

    def test_a_directory_without_a_database_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(backup.BackupError) as failure:
            backup.create(workspace=tmp_path / "empty", output=tmp_path / "out.tar.gz")
        assert failure.value.code == backup.ERROR_NOT_A_WORKSPACE

    def test_a_configured_database_path_is_backed_up(self, tmp_path: Path) -> None:
        root = tmp_path / "one"
        root.mkdir(parents=True)
        (root / "reportal.toml").write_text('[portal]\ndb = "state/portal.db"\n', encoding="utf-8")
        db = root / "state" / "portal.db"
        db.parent.mkdir(parents=True)
        store.init_db(db)
        stored = root / "binaries" / ("aa" * 32)
        stored.parent.mkdir(parents=True)
        stored.write_bytes(b"MZ")
        with contextlib.closing(store.connect(db)) as conn:
            store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path=str(stored), size=2)
        archive = Path(backup.create(workspace=root, output=tmp_path / "cfg.tar.gz")["path"])
        assert "reportal.db" in _names(archive)
        target = tmp_path / "two"
        target.mkdir()
        result = backup.restore(archive, workspace=target)
        assert Path(result["database"]) == target / "state" / "portal.db"
        assert (target / "state" / "portal.db").is_file()
        assert not (target / "reportal.db").exists()
        with contextlib.closing(store.connect(target / "state" / "portal.db")) as conn:
            assert [row["name"] for row in store.list_binaries(conn)] == ["demo.exe"]

    def test_the_database_in_the_archive_is_readable(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        result = backup.create(workspace=root, output=tmp_path / "readable.tar.gz")
        with tarfile.open(result["path"], "r:gz") as tar:
            extracted = tar.extractfile("reportal.db")
            assert extracted is not None
            staged = tmp_path / "staged.db"
            staged.write_bytes(extracted.read())
        with contextlib.closing(store.connect(staged)) as conn:
            rows = store.list_binaries(conn)
            assert [row["name"] for row in rows] == ["demo.exe"]


class TestRestore:
    @pytest.mark.parametrize("relative", [False, True])
    def test_symbol_files_survive_instance_loss(self, tmp_path: Path, relative: bool) -> None:
        source = _workspace(tmp_path / "one")
        data = b"debug symbols"
        digest = symbols.digest(data)
        local = Path(symbols.SYMBOLS_DIR) / digest[:2] / digest
        stored = source / local
        stored.parent.mkdir(parents=True)
        stored.write_bytes(data)
        with contextlib.closing(store.connect(source / "reportal.db")) as conn:
            binary_id = store.list_binaries(conn)[0]["id"]
            with journal.journaled(conn, journal.new_action()) as log:
                symbols.import_symbols(
                    conn,
                    log,
                    binary_id=binary_id,
                    data=data,
                    parsed={"kind": "pdb", "symbols": [], "types": []},
                    path=str(local if relative else stored),
                    apply=False,
                )
        archive = Path(backup.create(workspace=source, output=tmp_path / "symbols.tar.gz")["path"])
        assert local.as_posix() in _names(archive)
        assert backup.describe(archive)["counts"]["symbols"] == 1
        stored.unlink()
        target = tmp_path / "two"
        backup.restore(archive, workspace=target)
        with contextlib.closing(store.connect(target / "reportal.db")) as conn:
            restored = symbols.get_file(conn, binary_id=binary_id)
        assert restored["path"] == str(target / local)
        assert Path(restored["path"]).read_bytes() == data
        assert restored["sha256"] == digest

    def test_a_round_trip_into_another_directory(self, tmp_path: Path) -> None:
        source = _workspace(tmp_path / "one")
        archive = Path(backup.create(workspace=source, output=tmp_path / "round.tar.gz")["path"])
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
        archive = Path(backup.create(workspace=root, output=tmp_path / "ext.tar.gz")["path"])
        target = tmp_path / "two"
        target.mkdir()
        result = backup.restore(archive, workspace=target)
        assert result["external"] == 1
        assert result["rewritten"] == 1
        assert str(outside) in _paths(target / "reportal.db").values()

    def test_a_relative_path_under_the_workspace_is_rewritten(self, tmp_path: Path) -> None:
        """Relative paths were stored against the workspace, not the process cwd."""
        root = _workspace(tmp_path / "one")
        rel = "binaries/relative.exe"
        (root / rel).write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(root / "reportal.db")) as conn:
            binary_id = store.add_binary(
                conn, sha256="dd" * 32, name="relative.exe", path=rel, size=32
            )
        archive = Path(backup.create(workspace=root, output=tmp_path / "rel.tar.gz")["path"])
        target = tmp_path / "two"
        target.mkdir()
        result = backup.restore(archive, workspace=target)
        assert result["rewritten"] == 2
        assert result["external"] == 0
        paths = _paths(target / "reportal.db")
        assert paths[binary_id] == str(target.resolve() / rel)
        assert Path(paths[binary_id]).read_bytes() == b"MZ" + b"\x00" * 30

    def test_an_existing_workspace_needs_overwrite(self, tmp_path: Path) -> None:
        source = _workspace(tmp_path / "one")
        archive = Path(backup.create(workspace=source, output=tmp_path / "need.tar.gz")["path"])
        target = _workspace(tmp_path / "two")
        with pytest.raises(backup.BackupError) as failure:
            backup.restore(archive, workspace=target)
        assert failure.value.code == backup.ERROR_NOT_A_WORKSPACE

    def test_overwrite_replaces_the_state(self, tmp_path: Path) -> None:
        source = _workspace(tmp_path / "one")
        archive = Path(backup.create(workspace=source, output=tmp_path / "ow.tar.gz")["path"])
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
        archive = Path(backup.create(workspace=source, output=tmp_path / "safe.tar.gz")["path"])
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
    @pytest.mark.parametrize("missing", ["reportal.db", "reportal.toml", "reports/1/report.html"])
    def test_missing_declared_files_leave_existing_state_untouched(
        self, tmp_path: Path, missing: str
    ) -> None:
        source = _workspace(tmp_path / "one")
        archive = Path(backup.create(workspace=source, output=tmp_path / "base.tar.gz")["path"])
        broken = _rewrite(
            archive,
            lambda member, payload: None if member.name == missing else (member.name, payload),
        )
        target = _workspace(tmp_path / "two")
        before = (target / "reportal.db").read_bytes()
        with pytest.raises(backup.BackupError, match="missing"):
            backup.restore(broken, workspace=target, overwrite=True)
        assert (target / "reportal.db").read_bytes() == before
        assert (target / "reports/1/report.html").read_text() == "<html></html>"

    def test_a_plain_tar_is_refused(self, tmp_path: Path) -> None:
        target = tmp_path / "not-a-backup.tar.gz"
        with tarfile.open(target, "w:gz") as tar:
            tar.add(tmp_path, arcname="junk")
        with pytest.raises(backup.BackupError) as failure:
            backup.read_manifest(target)
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

    def test_a_member_the_manifest_does_not_name_is_refused(self, tmp_path: Path) -> None:
        archive = Path(
            backup.create(workspace=_workspace(tmp_path / "one"), output=tmp_path / "base.tar.gz")[
                "path"
            ]
        )
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
        archive = Path(
            backup.create(workspace=_workspace(tmp_path / "one"), output=tmp_path / "ver.tar.gz")[
                "path"
            ]
        )

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
        archive = Path(
            backup.create(workspace=_workspace(tmp_path / "one"), output=tmp_path / "desc.tar.gz")[
                "path"
            ]
        )
        described = backup.describe(archive)
        assert described["path"] == str(archive)
        assert described["counts"]["binaries"] == 1


class TestCli:
    def test_backup_uses_the_default_destination(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _workspace(tmp_path / "one")
        monkeypatch.chdir(source)
        made = runner.invoke(cli.app, ["backup", "--json"])
        assert made.exit_code == 0, made.output
        payload = json.loads(made.stdout)
        archive = Path(payload["path"])
        assert archive.parent == tmp_path / "reportal-backups"
        assert archive.is_file()
        assert payload["manifest"]["counts"]["binaries"] == 1

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
        (target / "reportal.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(target)
        declined = runner.invoke(cli.app, ["restore", str(archive)], input="n\n")
        assert declined.exit_code == 1
        assert "aborted" in declined.stderr
        assert "Continue?" in declined.stderr
        assert "Continue?" not in declined.stdout
        assert not (target / "reportal.db").exists()

    def test_restore_json_still_needs_yes(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _workspace(tmp_path / "one")
        monkeypatch.chdir(source)
        archive = tmp_path / "snapshot.tar.gz"
        runner.invoke(cli.app, ["backup", "--output", str(archive)])
        target = tmp_path / "two"
        target.mkdir()
        (target / "reportal.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(target)
        declined = runner.invoke(cli.app, ["restore", str(archive), "--json"])
        assert declined.exit_code == 1
        assert json.loads(declined.stdout)["error"] == "confirmation required; pass --yes"
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

    def test_prune_removes_only_stale_reportal_archives(self, tmp_path: Path) -> None:
        directory = tmp_path / "backups"
        directory.mkdir()
        stale = directory / "reportal-20200101T000000Z.tar.gz"
        fresh = directory / "reportal-backup-fresh.tar.gz"
        other = directory / "other-app.tar.gz"
        stale.write_bytes(b"stale")
        fresh.write_bytes(b"fresh")
        other.write_bytes(b"leave me")
        old = time.time() - (backup.DEFAULT_KEEP_DAYS + 2) * 86400
        os.utime(stale, (old, old))
        result = backup.prune(directory=directory, keep_days=backup.DEFAULT_KEEP_DAYS)
        assert result["removed_count"] == 1
        assert result["kept_count"] == 1
        assert result["keep_min"] == backup.DEFAULT_KEEP_MIN
        assert not stale.exists()
        assert fresh.exists()
        assert other.exists()

    def test_prune_cutoff_follows_a_pinned_store_now(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        directory = tmp_path / "backups"
        directory.mkdir()
        stale = directory / "reportal-20200101T000000Z.tar.gz"
        fresh = directory / "reportal-20200110T000000Z.tar.gz"
        stale.write_bytes(b"stale")
        fresh.write_bytes(b"fresh")
        # Pin the process clock to 2020-01-20; keep_days=14 makes mtimes before
        # 2020-01-06 the cutoff.  The stale file sits on Jan 1, the fresh one
        # on Jan 10, so only the older archive is pruned.
        monkeypatch.setattr(clock, "now", lambda: "2020-01-20T00:00:00+00:00")
        os.utime(stale, (1577836800.0, 1577836800.0))  # 2020-01-01
        os.utime(fresh, (1578614400.0, 1578614400.0))  # 2020-01-10
        result = backup.prune(directory=directory, keep_days=14, keep_min=0)
        assert result["removed_count"] == 1
        assert result["kept_count"] == 1
        assert not stale.exists()
        assert fresh.exists()

    def test_prune_keeps_the_newest_archive_when_all_are_stale(self, tmp_path: Path) -> None:
        directory = tmp_path / "backups"
        directory.mkdir()
        older = directory / "reportal-20200101T000000Z.tar.gz"
        newer = directory / "reportal-20200102T000000Z.tar.gz"
        older.write_bytes(b"older")
        newer.write_bytes(b"newer")
        old = time.time() - (backup.DEFAULT_KEEP_DAYS + 5) * 86400
        newer_age = time.time() - (backup.DEFAULT_KEEP_DAYS + 2) * 86400
        os.utime(older, (old, old))
        os.utime(newer, (newer_age, newer_age))
        result = backup.prune(directory=directory, keep_days=backup.DEFAULT_KEEP_DAYS, keep_min=1)
        assert result["removed_count"] == 1
        assert result["kept_count"] == 1
        assert not older.exists()
        assert newer.exists()

    def test_prune_refuses_the_workspace_directory(self, tmp_path: Path) -> None:
        root = _workspace(tmp_path / "one")
        inside = root / "binaries"
        with pytest.raises(backup.BackupError) as failure:
            backup.prune(directory=inside, workspace=root)
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

    def test_backup_prune_cli_dry_run(self, tmp_path: Path, monkeypatch: Any) -> None:
        source = _workspace(tmp_path / "one")
        monkeypatch.chdir(source)
        directory = tmp_path / "reportal-backups"
        directory.mkdir()
        stale = directory / "reportal-old.tar.gz"
        newer = directory / "reportal-newer.tar.gz"
        stale.write_bytes(b"stale")
        newer.write_bytes(b"newer")
        old = time.time() - (backup.DEFAULT_KEEP_DAYS + 2) * 86400
        os.utime(stale, (old, old))
        os.utime(newer, (old + 60, old + 60))
        result = runner.invoke(
            cli.app,
            ["backup-prune", "--dir", str(directory), "--dry-run", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["dry_run"] is True
        assert payload["removed_count"] == 1
        assert payload["keep_min"] == backup.DEFAULT_KEEP_MIN
        assert stale.exists()
        assert newer.exists()


class TestManifestRefusals:
    def _base(self, tmp_path: Path) -> Path:
        return Path(
            backup.create(workspace=_workspace(tmp_path / "one"), output=tmp_path / "m.tar.gz")[
                "path"
            ]
        )

    def test_an_archive_without_a_manifest_is_refused(self, tmp_path: Path) -> None:
        archive = self._base(tmp_path)

        def drop(member: tarfile.TarInfo, payload: bytes | None) -> tuple[str, bytes | None] | None:
            if member.name == backup.MANIFEST_NAME:
                return None
            return (member.name, payload)

        with pytest.raises(backup.BackupError) as failure:
            backup.read_manifest(_rewrite(archive, drop))
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

    def test_a_foreign_format_is_refused(self, tmp_path: Path) -> None:
        archive = self._base(tmp_path)

        def foreign(member: tarfile.TarInfo, payload: bytes | None) -> tuple[str, bytes | None]:
            if member.name != backup.MANIFEST_NAME or payload is None:
                return (member.name, payload)
            manifest = json.loads(payload.decode("utf-8"))
            manifest["format"] = "other-tool"
            return (member.name, json.dumps(manifest).encode("utf-8"))

        with pytest.raises(backup.BackupError) as failure:
            backup.read_manifest(_rewrite(archive, foreign))
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

    def test_a_member_list_of_the_wrong_shape_is_refused(self, tmp_path: Path) -> None:
        archive = self._base(tmp_path)

        def shapeless(member: tarfile.TarInfo, payload: bytes | None) -> tuple[str, bytes | None]:
            if member.name != backup.MANIFEST_NAME or payload is None:
                return (member.name, payload)
            manifest = json.loads(payload.decode("utf-8"))
            manifest["members"] = {"not": "a list"}
            return (member.name, json.dumps(manifest).encode("utf-8"))

        with pytest.raises(backup.BackupError) as failure:
            backup.read_manifest(_rewrite(archive, shapeless))
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

    def test_a_manifest_naming_a_missing_member_is_refused(self, tmp_path: Path) -> None:
        archive = self._base(tmp_path)

        def ghost(member: tarfile.TarInfo, payload: bytes | None) -> tuple[str, bytes | None]:
            if member.name != backup.MANIFEST_NAME or payload is None:
                return (member.name, payload)
            manifest = json.loads(payload.decode("utf-8"))
            manifest["members"] = [*manifest["members"], "binaries/ghost"]
            return (member.name, json.dumps(manifest).encode("utf-8"))

        with pytest.raises(backup.BackupError) as failure:
            backup.read_manifest(_rewrite(archive, ghost))
        assert failure.value.code == backup.ERROR_INVALID_ARCHIVE

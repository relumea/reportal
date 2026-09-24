"""Tests for the reportal CLI, including rebrew import idempotency."""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import threading
import zipfile
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    AI_COMMENTS_RESPONSE,
    AI_SUMMARY_RESPONSE,
    AI_TYPES_RESPONSE,
    FINGERPRINT,
    SECURITY,
    FailingLlmClient,
    FakeEngine,
    FakeLlmClient,
)
from typer.testing import CliRunner

from reportal import (
    __version__,
    _paths,
    auth,
    cli,
    engines,
    jobs,
    llm,
    rebrew_import,
    similarity,
    store,
)
from reportal._paths import DB_ENV

runner = CliRunner()


def _drop_action(payload: dict[str, Any]) -> dict[str, Any]:
    """Return *payload* without the journal action id a wired command adds."""
    payload.pop("journal_action", None)
    return payload


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Create a portal DB with one binary, one analysis and two named functions."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(
            conn, sha256="ab" * 32, name="demo.exe", path=str(tmp_path / "demo.exe")
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        first = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16
        )
        second = store.add_function(
            conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16
        )
    return {"binary": binary_id, "analysis": analysis_id, "first": first, "second": second}


def _make_rebrew_project(root: Path, *, with_binary: bool = True) -> Path:
    """Build a minimal rebrew workspace: config, target binary, coverage.db."""
    project = root / "rebrew-project"
    (project / "db").mkdir(parents=True)
    if with_binary:
        (project / "demo.exe").write_bytes(b"MZ" + b"\x00" * 30)
    (project / "rebrew-project.toml").write_text(
        '[project]\nname = "demo"\ndb_dir = "db"\n\n[targets.demo]\nbinary = "demo.exe"\n',
        encoding="utf-8",
    )
    conn = sqlite3.connect(project / "db" / "coverage.db")
    try:
        conn.execute(
            "CREATE TABLE functions ("
            " target TEXT, va INTEGER, name TEXT, size INTEGER,"
            " status TEXT, markerType TEXT)"
        )
        conn.executemany(
            "INSERT INTO functions VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("demo", 0x1000, "sub_1000", 32, "EXACT", "FUNCTION"),
                ("demo", 0x2000, "sub_2000", 16, "STUB", "FUNCTION"),
                ("demo", 0x3000, "g_counter", 4, "", "GLOBAL"),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return project


class TestHelpAndVersion:
    def test_help_lists_commands(self) -> None:
        result = runner.invoke(cli.app, ["--help"])
        assert result.exit_code == 0
        for command in (
            "init",
            "serve",
            "stats",
            "add-binary",
            "enrich",
            "decompile",
            "triage",
            "report",
            "import-rebrew",
        ):
            assert command in result.stdout

    def test_version(self) -> None:
        result = runner.invoke(cli.app, ["--version"])
        assert result.exit_code == 0
        assert f"reportal {__version__}" in result.output


class TestServe:
    def test_a_failed_bind_cancels_the_browser_opener(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The opener is the command's own effect, so a failed serve undoes it."""
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        opened: list[str] = []
        monkeypatch.setattr(cli.webbrowser, "open", opened.append)

        import reportal.webapp  # noqa: F401
        from reportal import server as _server

        def refuse(host: str, port: int) -> None:
            raise OSError(98, "Address already in use")

        monkeypatch.setattr(_server, "run", refuse)

        # Long interval so the callback cannot fire before cancel; assert that
        # cancel ran rather than sleeping past the production 0.5s window.
        timers: list[Any] = []

        class TrackingTimer(threading.Timer):
            def __init__(
                self,
                interval: float,
                function: Any,
                args: tuple[Any, ...] | None = None,
                kwargs: dict[str, Any] | None = None,
            ) -> None:
                super().__init__(3600.0, function, args=args or (), kwargs=kwargs or {})
                self.cancel_called = False
                timers.append(self)

            def cancel(self) -> None:
                self.cancel_called = True
                super().cancel()

        monkeypatch.setattr(cli.threading, "Timer", TrackingTimer)
        try:
            result = runner.invoke(cli.app, ["serve", "--port", "8099"])
            assert result.exit_code == 1
            assert opened == []
            assert len(timers) == 1
            assert timers[0].cancel_called
            timers[0].join(timeout=1.0)
            assert not timers[0].is_alive()
        finally:
            for timer in timers:
                timer.cancel()

    def test_an_existing_database_gains_later_tables(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opening the DB upgrades a file that predates later tables."""
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        with sqlite3.connect(db) as raw:
            raw.execute("CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT)")
            raw.commit()

        from reportal import server as _server

        with contextlib.closing(_server.db()) as conn:
            names = {
                str(row[0])
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        assert "feedback" in names
        assert "users" in names


class TestInit:
    def test_init_writes_marker_and_db(self, tmp_path: Path) -> None:
        result = runner.invoke(cli.app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / "reportal.toml").is_file()
        assert (tmp_path / "reportal.db").is_file()
        assert "Next steps" in result.output

    def test_init_creates_workspace_folders(self, tmp_path: Path) -> None:
        result = runner.invoke(cli.app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        for name in _paths.WORKSPACE_DIRS:
            assert (tmp_path / name).is_dir()
        assert "binaries/" in result.output

    def test_init_leaves_existing_folders_alone(self, tmp_path: Path) -> None:
        keep = tmp_path / _paths.BINARIES_DIR / "keep"
        keep.parent.mkdir(parents=True)
        keep.write_text("stored", encoding="utf-8")
        result = runner.invoke(cli.app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert keep.read_text(encoding="utf-8") == "stored"
        assert f"{_paths.BINARIES_DIR}/" not in result.output

    def test_init_is_idempotent(self, tmp_path: Path) -> None:
        runner.invoke(cli.app, ["init", "--dir", str(tmp_path)])
        result = runner.invoke(cli.app, ["init", "--dir", str(tmp_path)])
        assert result.exit_code == 0
        assert "untouched" in result.output


class TestStats:
    def test_stats_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        conn = store.connect(db)
        try:
            binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo")
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
            store.add_function(conn, analysis_id=analysis_id, va=1, name="a", status="EXACT")
        finally:
            conn.close()

        result = runner.invoke(cli.app, ["stats", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["binaries"] == 1
        assert payload["functions"] == 1
        assert payload["matched"] == 1

    def test_stats_missing_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "absent.db"))
        result = runner.invoke(cli.app, ["stats", "--json"])
        assert result.exit_code == 1
        assert "no reportal database" in result.stdout

    def test_stats_outside_workspace_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(DB_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli.app, ["stats", "--json"])
        assert result.exit_code == 1
        assert "no reportal workspace found" in result.stdout


class TestImportRebrew:
    def test_import_registers_binary_and_functions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(DB_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        summary = json.loads(result.stdout)
        assert summary["created_functions"] == 2
        assert summary["targets"][0]["name"] == "demo"

        with sqlite3.connect(tmp_path / "reportal.db") as conn:
            conn.row_factory = sqlite3.Row
            assert conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 2
            expected = hashlib.sha256((project / "demo.exe").read_bytes()).hexdigest()
            assert conn.execute("SELECT sha256 FROM binaries").fetchone()[0] == expected

    def test_build_db_builds_first_and_a_refusal_stops_the_import(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(DB_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        built: list[Path] = []

        class BuildingEngine(engines.RebrewEngine):
            def build_coverage_db(self, project_dir: str | Path) -> None:
                built.append(Path(project_dir))

        engines.set_engine(BuildingEngine(enabled=True))
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--build-db", "--json"])
        assert result.exit_code == 0, result.output
        assert built == [project]

        class RefusingEngine(engines.RebrewEngine):
            def build_coverage_db(self, project_dir: str | Path) -> None:
                raise engines.EngineError("rebrew build-db failed: no sources")

        engines.set_engine(RefusingEngine(enabled=True))
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--build-db", "--json"])
        assert result.exit_code == 1
        assert "no sources" in result.stdout

    def test_import_twice_does_not_duplicate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(DB_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        second = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert second.exit_code == 0
        summary = json.loads(second.stdout)
        assert summary["created_functions"] == 0
        assert summary["updated_functions"] == 2

        with sqlite3.connect(tmp_path / "reportal.db") as conn:
            assert conn.execute("SELECT COUNT(*) FROM binaries").fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 2
            assert conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 1

    def test_import_cells_fallback(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        project = tmp_path / "cells-project"
        (project / "db").mkdir(parents=True)
        conn = sqlite3.connect(project / "db" / "coverage.db")
        try:
            conn.execute(
                "CREATE TABLE cells ("
                " target TEXT, start INTEGER, end INTEGER, state TEXT, functions TEXT)"
            )
            conn.execute("INSERT INTO cells VALUES ('demo', 4096, 4128, 'exact', '[\"sub_1000\"]')")
            conn.execute("INSERT INTO cells VALUES ('demo', 8192, 8192, 'none', '[]')")
            conn.commit()
        finally:
            conn.close()
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        summary = json.loads(result.stdout)
        assert summary["created_functions"] == 1
        with sqlite3.connect(tmp_path / "portal.db") as db:
            assert db.execute("SELECT COUNT(*) FROM functions").fetchone()[0] == 1

    def test_import_unknown_schema(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        project = tmp_path / "weird-project"
        (project / "db").mkdir(parents=True)
        conn = sqlite3.connect(project / "db" / "coverage.db")
        try:
            conn.execute("CREATE TABLE unrelated (x INTEGER)")
            conn.commit()
        finally:
            conn.close()
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 1
        assert "unrecognized coverage.db schema" in result.stdout

    def test_import_missing_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        result = runner.invoke(cli.app, ["import-rebrew", str(tmp_path), "--json"])
        assert result.exit_code == 1
        assert "no coverage.db" in result.stdout

    def test_import_fingerprints_when_engine_available(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.delenv(DB_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        assert fake_engine.calls == ["fingerprint", "imports"]
        with contextlib.closing(store.connect(tmp_path / "reportal.db")) as conn:
            assert store.get_fingerprint(conn, 1) == FINGERPRINT

    def test_import_succeeds_without_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_fingerprint(conn, 1) is None

    def test_import_stores_context_without_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_rebrew_context(conn, 1) == str(project.resolve())

    def test_import_stores_context_with_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_rebrew_context(conn, 1) == str(project.resolve())

    def test_import_ingests_import_stubs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        summary = json.loads(result.stdout)
        assert summary["stubs"] == 2
        assert summary["targets"][0]["stubs"] == 2
        assert fake_engine.calls == ["fingerprint", "imports"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            rows = store.list_functions(conn, binary_id=1)
        by_va = {row["va"]: row for row in rows}
        stub = by_va[0x010030C6]
        assert stub["name"] == "ChooseFontW"
        assert stub["name_source"] == "import"
        assert stub["status"] == rebrew_import.THUNK_STATUS
        assert stub["size"] == rebrew_import.THUNK_SIZE == 6
        assert stub["source_path"] == str(project.resolve())

    def test_import_stub_rows_are_not_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            counts = store.counts(conn)
            rows = store.list_functions(conn, binary_id=1)
        by_va = {row["va"]: row for row in rows}
        assert counts["functions"] == 4
        assert counts["matched"] == 1
        assert by_va[0x010030C6]["confidence"] == 0.0

    def test_import_with_empty_stub_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        monkeypatch.setattr(fake_engine, "imports", lambda binary: {"stubs": []})
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["stubs"] == 0
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert len(store.list_functions(conn, binary_id=1)) == 2

    def test_import_stub_does_not_overwrite_coverage_row(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        monkeypatch.setattr(
            fake_engine,
            "imports",
            lambda binary: {"stubs": [{"va": "0x1000", "name": "ChooseFontW"}]},
        )
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["stubs"] == 0
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            functions = store.list_functions(conn, binary_id=1)
        assert len(functions) == 2
        covered = functions[0]
        assert covered["va"] == 0x1000
        assert covered["name"] == "sub_1000"
        assert covered["status"] == "EXACT"
        assert covered["name_source"] == "rebrew"

    def test_import_stubs_are_idempotent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        first = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert first.exit_code == 0, first.output
        assert json.loads(first.stdout)["stubs"] == 2

        second = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert second.exit_code == 0, second.output
        summary = json.loads(second.stdout)
        assert summary["stubs"] == 0
        assert summary["created_functions"] == 0
        assert summary["updated_functions"] == 2
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert len(store.list_functions(conn, binary_id=1)) == 4

    def test_import_stubs_skipped_without_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["stubs"] == 0
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert len(store.list_functions(conn, binary_id=1)) == 2

    def test_import_stub_engine_error_keeps_import(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)

        def boom(binary: str | Path) -> dict[str, object]:
            raise engines.EngineError("rebrew imports exited with code 1")

        monkeypatch.setattr(fake_engine, "imports", boom)
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["stubs"] == 0
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert len(store.list_functions(conn, binary_id=1)) == 2

    def test_import_stub_with_malformed_va_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        monkeypatch.setattr(
            fake_engine,
            "imports",
            lambda binary: {
                "stubs": [
                    {"va": "not-hex", "name": "Bogus"},
                    {"name": "NoVa"},
                    42,
                    {"va": "0x010030c6", "name": "ChooseFontW"},
                ]
            },
        )
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["stubs"] == 1
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            functions = store.list_functions(conn, binary_id=1)
        assert [function["name"] for function in functions] == [
            "sub_1000",
            "sub_2000",
            "ChooseFontW",
        ]

    def test_import_stub_accepts_integer_va(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        monkeypatch.setattr(
            fake_engine,
            "imports",
            lambda binary: {"stubs": [{"va": 0x010030C6, "name": "ChooseFontW"}]},
        )
        result = runner.invoke(cli.app, ["import-rebrew", str(project), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["stubs"] == 1
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            functions = store.list_functions(conn, binary_id=1)
        assert functions[2]["va"] == 0x010030C6

    def test_import_human_output_shows_stub_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        project = _make_rebrew_project(tmp_path)
        result = runner.invoke(cli.app, ["import-rebrew", str(project)])
        assert result.exit_code == 0, result.output
        assert "Stubs" in result.output
        assert "2" in result.output


class TestJobsCommand:
    def test_lists_the_queue_and_filters_by_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            jobs.submit(conn, kind="composition", binary_id=ids["binary"])
            other = store.add_binary(conn, sha256="cd" * 32, name="other.exe")
            jobs.submit(conn, kind="composition", binary_id=other)

        listed = runner.invoke(cli.app, ["jobs", "--json"])
        assert listed.exit_code == 0, listed.output
        assert json.loads(listed.stdout)["count"] == 2

        filtered = runner.invoke(cli.app, ["jobs", "--binary-id", str(ids["binary"]), "--json"])
        assert filtered.exit_code == 0, filtered.output
        payload = json.loads(filtered.stdout)
        assert payload["count"] == 1
        assert payload["jobs"][0]["binary_id"] == ids["binary"]
        assert payload["total"] == 1


class TestFunctionsCommand:
    def test_lists_the_binary_functions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["functions", str(ids["binary"]), "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 2
        assert payload["total"] == 2
        assert payload["sort"] == "va"
        assert [row["name"] for row in payload["functions"]] == ["sub_1000", "sub_2000"]

    def test_filters_by_name_and_address(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)

        by_name = runner.invoke(
            cli.app, ["functions", str(ids["binary"]), "--name", "2000", "--json"]
        )
        assert [row["name"] for row in json.loads(by_name.stdout)["functions"]] == ["sub_2000"]

        by_address = runner.invoke(
            cli.app, ["functions", str(ids["binary"]), "--va", "0x2000", "--json"]
        )
        payload = json.loads(by_address.stdout)
        assert [row["name"] for row in payload["functions"]] == ["sub_2000"]
        assert payload["va"] == 0x2000

    def test_a_bad_address_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app, ["functions", str(ids["binary"]), "--va", "somewhere", "--json"]
        )

        assert result.exit_code == 1
        assert "invalid va" in json.loads(result.stdout)["error"]


class TestFingerprintCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path=str(target))

    def test_a_live_compute_is_not_stored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["fingerprint", str(binary_id), "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["stored"] is False
        assert payload["sha256"] == FINGERPRINT["sha256"]
        assert fake_engine.calls == ["fingerprint"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_fingerprint(conn, binary_id) is None

    def test_a_stored_bundle_answers_without_the_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["enrich", str(binary_id), "--json"])
        fake_engine.calls.clear()

        result = runner.invoke(cli.app, ["fingerprint", str(binary_id), "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["stored"] is True
        assert fake_engine.calls == []

    def test_the_human_output_names_the_digests(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["fingerprint", str(binary_id)])

        assert result.exit_code == 0, result.output
        assert FINGERPRINT["md5"] in result.output
        assert "reportal enrich" in result.output

    def test_an_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["fingerprint", "4242", "--json"])

        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout


class TestDisasmCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, int]:
        """One binary with a rebrew context and one function; returns their ids."""
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.set_rebrew_context(conn, ids["binary"], "/projects/demo")
        return ids["binary"], ids["first"]

    def test_prints_the_nasm_listing_and_caches_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _binary, function_id = self._seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["disasm", str(function_id), "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["format"] == "nasm"
        assert payload["cached"] is False
        assert payload["va"] == 0x1000
        assert "func_1000:" in payload["disasm"]
        assert fake_engine.calls == ["disassemble"]

        # The second read answers from the cache the route also reads.
        again = runner.invoke(cli.app, ["disasm", str(function_id), "--json"])
        assert json.loads(again.stdout)["cached"] is True
        assert fake_engine.calls == ["disassemble"]

    def test_the_human_output_is_the_listing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _binary, function_id = self._seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["disasm", str(function_id)])

        assert result.exit_code == 0, result.output
        assert "func_1000:" in result.stdout
        assert "func_1000:" not in result.stderr
        assert "@ 0x1000" in result.stderr

    def test_hex_is_not_cached(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _binary, function_id = self._seed(tmp_path, monkeypatch)

        first = runner.invoke(cli.app, ["disasm", str(function_id), "--format", "hex", "--json"])
        second = runner.invoke(cli.app, ["disasm", str(function_id), "--format", "hex", "--json"])

        assert json.loads(first.stdout)["cached"] is False
        assert json.loads(second.stdout)["cached"] is False
        assert fake_engine.calls == ["disassemble", "disassemble"]

    def test_an_unknown_format_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _binary, function_id = self._seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["disasm", str(function_id), "--format", "nope"])

        assert result.exit_code == 1
        assert "--format must be one of" in result.output

    def test_without_a_project_context_it_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["disasm", str(ids["first"])])

        assert result.exit_code == 1
        assert "no analysis context yet" in result.output


class TestImportsCommand:
    def test_lists_the_import_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        # The route reads the stored bytes, so the row's file has to exist.
        (tmp_path / "demo.exe").write_bytes(b"MZ" + b"\x00" * 30)

        result = runner.invoke(cli.app, ["imports", str(ids["binary"]), "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["imports"][0]["name"] == "GetTickCount"
        assert payload["imports"][0]["dll"] == "KERNEL32.dll"
        assert fake_engine.calls == ["imports"]

    def test_the_human_table_names_the_library(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        (tmp_path / "demo.exe").write_bytes(b"MZ" + b"\x00" * 30)

        result = runner.invoke(cli.app, ["imports", str(ids["binary"])])

        assert result.exit_code == 0, result.output
        assert "KERNEL32.dll" in result.output
        assert "GetTickCount" in result.output

    def test_an_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["imports", "4242", "--json"])

        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout


class TestBinariesCommand:
    def test_lists_the_register_with_its_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["binaries", "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["total"] == 1
        assert payload["order"] == "id"
        assert payload["binaries"][0]["id"] == ids["binary"]
        assert payload["binaries"][0]["function_count"] == 2

    def test_lists_the_effective_format(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.set_binary_format_override(conn, ids["binary"], format_override="elf")

        result = runner.invoke(cli.app, ["binaries"])

        assert result.exit_code == 0, result.output
        assert "elf" in result.output

    def test_filters_by_search_tag_and_format(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.add_binary(conn, sha256="cd" * 32, name="other.exe", size=99, fmt="ELF")
            store.add_binary_tag(conn, ids["binary"], store.create_tag(conn, "packed"))

        by_search = runner.invoke(cli.app, ["binaries", "--search", "ab", "--json"])
        assert [row["name"] for row in json.loads(by_search.stdout)["binaries"]] == ["demo.exe"]
        by_tag = runner.invoke(cli.app, ["binaries", "--tag", "packed", "--json"])
        assert [row["name"] for row in json.loads(by_tag.stdout)["binaries"]] == ["demo.exe"]
        by_format = runner.invoke(cli.app, ["binaries", "--format", "ELF", "--json"])
        assert [row["name"] for row in json.loads(by_format.stdout)["binaries"]] == ["other.exe"]
        by_order = runner.invoke(cli.app, ["binaries", "--order", "name-desc", "--json"])
        assert [row["name"] for row in json.loads(by_order.stdout)["binaries"]] == [
            "other.exe",
            "demo.exe",
        ]

    def test_an_unknown_order_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["binaries", "--order", "biggest", "--json"])

        assert result.exit_code == 1
        assert "unknown binary order" in result.stdout

    def test_without_a_database_it_fails(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing.db"))

        result = runner.invoke(cli.app, ["binaries", "--json"])

        assert result.exit_code == 1
        assert "no reportal database" in result.stdout


class TestBinaryCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        store.init_db(tmp_path / "portal.db")
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            return store.add_binary(conn, sha256="cc" * 32, name="demo.exe", fmt="PE")

    def test_it_prints_the_rebrew_project_or_the_hint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)

        bare = runner.invoke(cli.app, ["binary", str(binary_id)])
        assert bare.exit_code == 0, bare.output
        assert "no analysis context" in bare.output

        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.set_rebrew_context(conn, binary_id, "/projects/demo-rebrew")
        named = runner.invoke(cli.app, ["binary", str(binary_id), "--json"])

        assert named.exit_code == 0, named.output
        payload = json.loads(named.stdout)
        assert payload["rebrew_project"] == "/projects/demo-rebrew"
        assert payload["name"] == "demo.exe"

    def test_an_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["binary", "999"])

        assert result.exit_code == 1
        assert "no binary with id 999" in result.output


class TestAddBinary:
    def test_registers_and_dedupes_by_sha256(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        first = runner.invoke(cli.app, ["add-binary", str(target), "--json"])
        assert first.exit_code == 0, first.output
        payload = json.loads(first.stdout)
        assert payload["binary_id"] == 1
        assert payload["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()

        second = runner.invoke(cli.app, ["add-binary", str(target), "--name", "again", "--json"])
        assert second.exit_code == 0, second.output
        assert json.loads(second.stdout)["binary_id"] == 1

        with sqlite3.connect(tmp_path / "portal.db") as db:
            assert db.execute("SELECT COUNT(*) FROM binaries").fetchone()[0] == 1

    def test_missing_file_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        result = runner.invoke(cli.app, ["add-binary", str(tmp_path / "absent.exe")])
        assert result.exit_code == 1
        assert "not a file" in result.output

    def test_team_registers_into_that_scope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        store.init_db(tmp_path / "portal.db")
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            team_id = int(auth.create_team(conn, name="Blue")["id"])
        target = tmp_path / "scoped.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)

        result = runner.invoke(
            cli.app, ["add-binary", str(target), "--team", str(team_id), "--json"]
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["visibility"] == "team"
        assert payload["owner_team_id"] == team_id
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            stored = store.get_binary(conn, int(payload["binary_id"]))
        assert stored is not None
        assert int(stored["owner_team_id"]) == team_id

    def test_an_unknown_team_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)

        result = runner.invoke(cli.app, ["add-binary", str(target), "--team", "99"])

        assert result.exit_code == 1
        assert "team-not-found" in result.output

    def test_compiler_hint_stamps_the_row(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        result = runner.invoke(
            cli.app, ["add-binary", str(target), "--compiler", "MinGW GCC", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            stored = store.get_binary(conn, int(payload["binary_id"]))
        assert stored is not None
        assert stored["compiler"] == "MinGW GCC"

    def test_an_unknown_compiler_fails_before_open(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        result = runner.invoke(cli.app, ["add-binary", str(target), "--compiler", "clang"])
        assert result.exit_code == 1
        assert "compiler must be one of" in result.output
        assert not db.exists()


class TestExtract:
    def _seed_archive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, name: str = "bundle.zip"
    ) -> int:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        store.init_db(tmp_path / "portal.db")
        source = tmp_path / name
        with zipfile.ZipFile(source, "w") as zf:
            zf.writestr("one.bin", b"first member")
            zf.writestr("two.bin", b"second member")
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            return store.add_binary(
                conn,
                sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                name=name,
                path=str(source),
                size=source.stat().st_size,
            )

    def test_extract_registers_the_members(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed_archive(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["extract", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["kept"] == 2
        assert payload["collection_name"] == "bundle.zip extraction"
        assert {member["name"] for member in payload["members"]} == {"one.bin", "two.bin"}
        assert payload["journal_action"]

    def test_extract_prints_a_table(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed_archive(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["extract", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "one.bin" in result.output
        assert "Extracted" in result.output

    def test_extract_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        store.init_db(tmp_path / "portal.db")
        result = runner.invoke(cli.app, ["extract", "99"])
        assert result.exit_code == 1
        assert "no binary with id 99" in result.output

    def test_extract_refuses_an_external_format(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "portal.db"))
        monkeypatch.chdir(tmp_path)
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        store.init_db(tmp_path / "portal.db")
        source = tmp_path / "sample.rar"
        source.write_bytes(b"Rar!\x1a\x07\x00")
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            binary_id = store.add_binary(
                conn, sha256="ee" * 32, name="sample.rar", path=str(source), size=4
            )
        result = runner.invoke(cli.app, ["extract", str(binary_id)])
        assert result.exit_code == 1
        assert "unrar" in result.output


class TestEnrich:
    def _seed_binary(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path=str(target))

    def test_enrich_stores_fingerprint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed_binary(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["enrich", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        assert _drop_action(json.loads(result.stdout)) == FINGERPRINT
        assert fake_engine.calls == ["fingerprint"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_fingerprint(conn, binary_id) == FINGERPRINT

    def test_enrich_without_engine_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed_binary(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["enrich", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_enrich_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed_binary(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["enrich", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout


class TestMatch:
    def _seed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, context: bool = True
    ) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(
                conn, sha256="ab" * 32, name="demo.exe", path=str(tmp_path / "demo.exe")
            )
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
            store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="a1", size=16)
            store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="a2", size=16)
            if context:
                store.set_rebrew_context(conn, binary_id, str(tmp_path))
            return binary_id

    def test_match_with_fake_engine_and_scorer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        monkeypatch.setattr(similarity, "available", lambda: True)
        monkeypatch.setattr(similarity, "similarity", lambda left, right: 90.0)
        result = runner.invoke(cli.app, ["match", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["functions"] == 2
        assert payload["matched"] == 2
        assert payload["pairs"] == 2
        assert payload["matches"][0]["similarity"] == pytest.approx(90.0)

    def test_match_without_similarity_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        monkeypatch.setattr(similarity, "available", lambda: False)
        result = runner.invoke(cli.app, ["match", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "uv sync --extra similarity" in result.stdout

    def test_match_without_engine_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["match", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_match_without_context_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch, context=False)
        result = runner.invoke(cli.app, ["match", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no analysis context yet" in result.stdout

    def test_match_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["match", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_match_records_the_settings_it_ran_with(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        monkeypatch.setattr(similarity, "available", lambda: True)
        monkeypatch.setattr(similarity, "similarity", lambda left, right: 90.0)
        result = runner.invoke(
            cli.app,
            ["match", str(binary_id), "--min-confidence", "0.0", "--top", "1", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["settings"]["min_confidence"] == 0.0
        assert payload["settings"]["top"] == 1
        assert payload["matches"][0]["settings"] == payload["settings"]

    def test_match_unknown_platform_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["match", str(binary_id), "--platform", "beos", "--json"])
        assert result.exit_code == 1
        assert "beos" in result.stdout

    def test_match_name_source_scope_reaches_the_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        monkeypatch.setattr(similarity, "available", lambda: True)
        monkeypatch.setattr(similarity, "similarity", lambda left, right: 90.0)
        result = runner.invoke(
            cli.app, ["match", str(binary_id), "--name-source", "User", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["settings"]["name_sources"] == ["User"]


class TestDecompile:
    def _seed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, context: bool = True
    ) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(
                conn, sha256="ab" * 32, name="demo.exe", path=str(tmp_path / "demo.exe")
            )
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
            function_id = store.add_function(
                conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16
            )
            if context:
                store.set_rebrew_context(conn, binary_id, str(tmp_path))
        return function_id

    def test_decompile_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        function_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["decompile", str(function_id)])
        assert result.exit_code == 0, result.output
        assert "return;" in result.stdout
        assert "backend: kuna" in result.stderr
        assert "backend: kuna" not in result.stdout
        assert fake_engine.calls == ["decompile"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            stored = store.get_decompilation(conn, function_id)
        assert stored is not None
        assert stored["backend"] == "kuna"
        assert "return;" in stored["code"]

    def test_decompile_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        function_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["decompile", str(function_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["va"] == 0x1000
        assert payload["backend"] == "kuna"
        assert payload["named"] is False
        assert "return;" in payload["code"]

    def test_decompile_flags_reach_the_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        function_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["decompile", str(function_id), "--backend", "r2ghidra", "--named", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["backend"] == "r2ghidra"
        assert payload["named"] is True
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            stored = store.get_decompilation(conn, function_id)
        assert stored is not None and stored["backend"] == "r2ghidra"

    def test_decompile_without_engine_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        function_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["decompile", str(function_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_decompile_unknown_backend_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        function_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["decompile", str(function_id), "--backend", "ida", "--json"]
        )
        assert result.exit_code == 1
        assert "unknown decompiler backend" in result.stdout
        assert fake_engine.calls == []

    def test_decompile_without_context_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        function_id = self._seed(tmp_path, monkeypatch, context=False)
        result = runner.invoke(cli.app, ["decompile", str(function_id), "--json"])
        assert result.exit_code == 1
        assert "no analysis context yet" in result.stdout

    def test_decompile_unknown_function_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["decompile", "4242", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout

    def test_decompile_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew decompile exited with code 1")

        monkeypatch.setattr(fake_engine, "decompile", boom)
        function_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["decompile", str(function_id), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestTriageCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path=str(target))

    def test_triage_stores_and_prints_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["triage", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["toolchain"]["family"] == "msvc"
        assert payload["binary"] == str(tmp_path / "demo.exe")
        assert fake_engine.calls == ["analyze"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            assert analysis_id is not None
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE)
        assert stored is not None
        assert stored["toolchain"]["family"] == "msvc"

    def test_triage_human_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["triage", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "toolchain" in result.output
        assert "0x401000" in result.output
        assert "msvc" in result.output

    def test_triage_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["triage", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_triage_missing_file_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="cd" * 32, name="ghost.exe")
        result = runner.invoke(cli.app, ["triage", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no readable file" in result.stdout

    def test_triage_without_engine_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["triage", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_triage_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew analyze exited with code 1")

        monkeypatch.setattr(fake_engine, "analyze", boom)
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["triage", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestReportCommand:
    def _seed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, context: bool = True
    ) -> int:
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="ef" * 32, name="demo.exe")
            if context:
                store.set_rebrew_context(conn, binary_id, "/projects/notepad-rebrew")
            return binary_id

    def test_report_stores_and_prints_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["report", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["summary"]["status_counts"] == {"EXACT": 1, "STUB": 1}
        assert payload["out"] == str(tmp_path / "reports" / str(binary_id))
        assert fake_engine.calls == ["report"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            assert analysis_id is not None
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_REPORT)
        assert stored == _drop_action(payload)

    def test_report_human_shows_summary_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["report", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "coverage_pct" in result.output
        assert "status EXACT" in result.output

    def test_report_without_context_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch, context=False)
        result = runner.invoke(cli.app, ["report", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no analysis context yet" in result.stdout
        assert fake_engine.calls == []

    def test_report_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["report", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_report_without_engine_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["report", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_report_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew report exited with code 2")

        monkeypatch.setattr(fake_engine, "report", boom)
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["report", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "exited with code 2" in result.stdout


class TestRevertCommand:
    def test_revert_restores_name(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.rename_function(conn, ids["first"], new_name="parse_header", actor="tester")
            history_id = int(store.list_name_history(conn, ids["first"])[0]["id"])
        result = runner.invoke(cli.app, ["revert", str(ids["first"]), str(history_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload.pop("journal_action")
        assert payload == {
            "function_id": ids["first"],
            "history_id": history_id,
            "name": "sub_1000",
        }
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            function = store.get_function(conn, ids["first"])
        assert function is not None
        assert function["name"] == "sub_1000"

    def test_revert_unknown_function_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["revert", "4242", "1", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout

    def test_revert_mismatched_history_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.rename_function(conn, ids["first"], new_name="parse_header", actor="tester")
            history_id = int(store.list_name_history(conn, ids["first"])[0]["id"])
        result = runner.invoke(cli.app, ["revert", str(ids["second"]), str(history_id), "--json"])
        assert result.exit_code == 1
        assert "no history" in result.stdout


class TestTagsCommand:
    def test_tag_add_list_remove(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        added = runner.invoke(cli.app, ["tag", str(ids["binary"]), "release", "--json"])
        assert added.exit_code == 0, added.output
        payload = json.loads(added.stdout)
        assert payload["name"] == "release"
        assert payload["added"] is True

        listed = runner.invoke(cli.app, ["tags", "--json"])
        assert listed.exit_code == 0, listed.output
        tags = json.loads(listed.stdout)["tags"]
        assert tags[0]["name"] == "release"
        assert tags[0]["binary_count"] == 1

        removed = runner.invoke(
            cli.app, ["tag", str(ids["binary"]), "release", "--remove", "--json"]
        )
        assert removed.exit_code == 0, removed.output
        assert json.loads(removed.stdout)["removed"] is True

        after = runner.invoke(cli.app, ["tags", "--json"])
        assert json.loads(after.stdout)["tags"][0]["binary_count"] == 0

    def test_tag_remove_unknown_name_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["tag", str(ids["binary"]), "absent", "--remove", "--json"])
        assert result.exit_code == 1
        assert "no tag named" in result.stdout

    def test_tag_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["tag", "4242", "release", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_tag_rename_keeps_the_links_then_tag_rm_prunes_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["tag", str(ids["binary"]), "relase", "--json"])
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            tag_id = int(store.find_tag(conn, "relase")["id"])  # type: ignore[index]

        renamed = runner.invoke(cli.app, ["tag-rename", str(tag_id), "release", "--json"])
        assert renamed.exit_code == 0, renamed.output
        assert json.loads(renamed.stdout)["name"] == "release"

        listed = runner.invoke(cli.app, ["tags", "--json"])
        tags = json.loads(listed.stdout)["tags"]
        assert [(tag["name"], tag["binary_count"]) for tag in tags] == [("release", 1)]

        removed = runner.invoke(cli.app, ["tag-rm", str(tag_id), "--json"])
        assert removed.exit_code == 0, removed.output
        assert json.loads(removed.stdout)["deleted"] is True
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_tag(conn, tag_id) is None
            assert store.get_binary_tags(conn, ids["binary"]) == []

    def test_tag_rename_to_a_taken_name_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["tag", "1", "release", "--json"])
        runner.invoke(cli.app, ["tag", "1", "triage", "--json"])
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            other = int(store.find_tag(conn, "triage")["id"])  # type: ignore[index]

        result = runner.invoke(cli.app, ["tag-rename", str(other), "release", "--json"])

        assert result.exit_code == 1
        assert "already exists" in result.stdout

    def test_tag_rm_unknown_tag_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["tag-rm", "4242", "--json"])
        assert result.exit_code == 1
        assert "no tag with id 4242" in result.stdout


class TestApplyMatchCommand:
    def test_apply_match_renames(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.record_match(
                conn,
                function_id=ids["first"],
                candidate_function_id=ids["second"],
                similarity=0.9,
                confidence=0.9,
            )
        result = runner.invoke(
            cli.app, ["apply-match", str(ids["first"]), str(ids["second"]), "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload.pop("journal_action")
        assert payload == {
            "function_id": ids["first"],
            "candidate_function_id": ids["second"],
            "mode": "name",
            "status": "applied",
            "reason": "",
            "detail": "",
            "name_changed": True,
            "old_name": "sub_1000",
            "new_name": "sub_2000",
            "signature_changed": False,
            "missing_types": [],
        }
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            function = store.get_function(conn, ids["first"])
            history = store.list_name_history(conn, ids["first"])
        assert function is not None
        assert function["name"] == "sub_2000"
        assert history[0]["source"] == "match"
        assert history[0]["actor"] == "cli"

    def test_apply_match_signature_mode_copies_and_reports_missing_types(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.record_match(
                conn,
                function_id=ids["first"],
                candidate_function_id=ids["second"],
                similarity=0.9,
                confidence=0.9,
            )
            store.upsert_signature(
                conn,
                function_id=ids["second"],
                name="sub_2000",
                return_type="int",
                calling_convention="cdecl",
                parameters=[{"index": 0, "type": "NP_ENTRY *", "name": "entry"}],
                source="decompilation",
            )
        result = runner.invoke(
            cli.app,
            ["apply-match", str(ids["first"]), str(ids["second"]), "--mode", "signature", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["signature_changed"] is True
        assert payload["name_changed"] is False
        assert payload["missing_types"] == ["NP_ENTRY"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            signature = store.get_signature(conn, ids["first"])
            function = store.get_function(conn, ids["first"])
        assert signature is not None
        assert signature["return_type"] == "int"
        assert function is not None
        assert function["name"] == "sub_1000"

    def test_apply_match_unknown_mode_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "apply-match",
                str(ids["first"]),
                str(ids["second"]),
                "--mode",
                "everything",
                "--json",
            ],
        )
        assert result.exit_code == 1
        assert "everything" in result.stdout

    def test_apply_match_without_recorded_match_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["apply-match", str(ids["first"]), str(ids["second"]), "--json"]
        )
        assert result.exit_code == 1
        assert "no recorded match" in result.stdout

    def test_apply_match_unknown_function_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["apply-match", "4242", "1", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout


def _seed_with_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Seed the portal and give its binary a stored rebrew project context."""
    ids = _seed_portal(tmp_path, monkeypatch)
    with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
        store.set_rebrew_context(conn, ids["binary"], str(tmp_path))
    return ids


class TestXrefsCommand:
    def test_xrefs_json_prints_payload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["xrefs", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 2
        assert fake_engine.calls == ["xrefs"]
        assert fake_engine.xrefs_args == (str(tmp_path), 0x1000, ())

    def test_kind_options_reach_the_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["xrefs", str(ids["first"]), "--kind", "call", "--kind", "data", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["count"] == 1
        assert fake_engine.xrefs_args == (str(tmp_path), 0x1000, ("call", "data"))

    def test_human_output_lists_refs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["xrefs", str(ids["first"])])
        assert result.exit_code == 0, result.output
        assert "call" in result.output
        assert "0x1100" in result.output
        assert "call 0x1000" in result.output

    def test_unknown_function_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["xrefs", "4242", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout

    def test_without_context_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["xrefs", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "no analysis context yet" in result.stdout
        assert fake_engine.calls == []

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["xrefs", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout


class TestStructsCommand:
    def test_structs_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["structs", str(ids["binary"]), "--limit", "10", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["structs"][0]["name"] == "PlayerInfo"
        assert fake_engine.structs_args == (str(tmp_path), "kuna", 10)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, ids["binary"])
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_STRUCTS)
        assert stored == _drop_action(payload)

    def test_structs_human_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["structs", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "PlayerInfo" in result.output
        assert "decompiled 12" in result.output

    def test_default_backend_and_no_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["structs", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        assert fake_engine.structs_args == (str(tmp_path), "kuna", 0)

    def test_backend_reaches_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["structs", str(ids["binary"]), "--decompiler", "r2ghidra", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert fake_engine.structs_args == (str(tmp_path), "r2ghidra", 0)

    def test_unknown_backend_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["structs", str(ids["binary"]), "--decompiler", "ida", "--json"]
        )
        assert result.exit_code == 1
        assert "unknown decompiler backend" in result.stdout
        assert fake_engine.calls == []

    def test_negative_limit_usage_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["structs", str(ids["binary"]), "--limit", "-1"])
        assert result.exit_code == 2
        assert fake_engine.calls == []

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["structs", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_without_context_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["structs", str(ids["binary"]), "--json"])
        assert result.exit_code == 1
        assert "no analysis context yet" in result.stdout
        assert fake_engine.calls == []

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["structs", str(ids["binary"]), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout


class TestCryptoScanCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path=str(target))

    def test_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 2
        assert payload["findings"][0]["name"] == "AES S-box"
        assert fake_engine.calls == ["crypto_scan"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_CRYPTO)
        assert stored == _drop_action(payload)

    def test_human_output_shows_table_and_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "AES S-box" in result.output
        assert "CryptEncrypt" in result.output
        assert "high 1" in result.output
        assert "medium 1" in result.output

    def test_empty_result_human_shows_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        empty = {
            "binary": "demo.exe",
            "findings": [],
            "count": 0,
            "by_confidence": {"high": 0, "medium": 0},
        }
        monkeypatch.setattr(
            fake_engine,
            "crypto_scan",
            lambda binary: {**empty, "binary": str(binary)},
        )
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "No crypto indicators" in result.output

    def test_empty_result_json_still_stores(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        empty = {
            "binary": "demo.exe",
            "findings": [],
            "count": 0,
            "by_confidence": {"high": 0, "medium": 0},
        }
        monkeypatch.setattr(
            fake_engine,
            "crypto_scan",
            lambda binary: {**empty, "binary": str(binary)},
        )
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["findings"] == []
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_CRYPTO)
        assert stored is not None and stored["findings"] == []

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["crypto-scan", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout
        assert fake_engine.calls == []

    def test_missing_file_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="cd" * 32, name="ghost.exe")
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no readable file" in result.stdout
        assert fake_engine.calls == []

    def test_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew crypto-scan exited with code 1")

        monkeypatch.setattr(fake_engine, "crypto_scan", boom)
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestPeInfoCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ef" * 32, name="demo.exe", path=str(target))

    def test_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["pe-info", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["format"] == "pe"
        assert payload["flags_summary"] == ["SEH", "Isolation"]
        assert fake_engine.calls == ["pe_info"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_PE_INFO)
        assert stored == _drop_action(payload)

    def test_human_output_shows_identity_flags_sections_and_presence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["pe-info", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "pe x86_32 32-bit" in result.output
        assert "WINDOWS_GUI" in result.output
        assert "security flags: SEH, Isolation" in result.output
        assert "dll_characteristics 0x8000" in result.output
        assert ".text" in result.output
        assert "R-X" in result.output
        assert "RW-" in result.output
        assert "debug info: MISC" in result.output
        assert "rich header: present (1 entries)" in result.output
        assert "authenticode: not signed" in result.output

    def test_human_output_without_pe_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setattr(
            fake_engine,
            "pe_info",
            lambda binary: {
                "format": "elf",
                "arch": "x86_64",
                "bits": 64,
                "size": 1024,
                "note": "PE-only metadata is unavailable for elf binaries",
            },
        )
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["pe-info", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "elf x86_64 64-bit" in result.output
        assert "PE-only metadata is unavailable" in result.output
        assert "security flags: none" in result.output
        assert "debug info: none" in result.output

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["pe-info", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["pe-info", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout
        assert fake_engine.calls == []

    def test_missing_file_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="e0" * 32, name="ghost.exe")
        result = runner.invoke(cli.app, ["pe-info", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no readable file" in result.stdout
        assert fake_engine.calls == []

    def test_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew pe-info exited with code 1")

        monkeypatch.setattr(fake_engine, "pe_info", boom)
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["pe-info", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestCapabilitiesCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ca" * 32, name="demo.exe", path=str(target))

    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        *,
        imports: list[dict[str, object]],
        strings: list[dict[str, object]],
    ) -> None:
        monkeypatch.setattr(
            fake_engine, "imports", lambda binary: {"imports": imports, "stubs": []}
        )
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": strings})

    def test_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[{"dll": "WS2_32.dll", "name": "WSAStartup", "iat_va": "0x401000"}],
            strings=[{"text": "https://example.test/beacon", "va": "0x402000"}],
        )
        result = runner.invoke(cli.app, ["capabilities", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["binary_id"] == binary_id
        assert payload["count"] == 1
        assert payload["capabilities"][0]["name"] == "networking"
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_CAPABILITIES)
        assert stored == _drop_action(payload)

    def test_human_output_shows_table_and_total(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[
                {"dll": "WS2_32.dll", "name": "WSAStartup", "iat_va": "0x401000"},
                {"dll": "KERNEL32.dll", "name": "CreateFileA", "iat_va": "0x401004"},
            ],
            strings=[],
        )
        result = runner.invoke(cli.app, ["capabilities", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "networking" in result.output
        assert "file-io" in result.output
        assert "2 capabilities" in result.output

    def test_empty_result_human_shows_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine, imports=[], strings=[])
        result = runner.invoke(cli.app, ["capabilities", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "No capabilities detected" in result.output

    def test_empty_result_json_still_stores(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine, imports=[], strings=[])
        result = runner.invoke(cli.app, ["capabilities", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["capabilities"] == []
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_CAPABILITIES)
        assert stored is not None and stored["capabilities"] == []

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["capabilities", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["capabilities", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_missing_file_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="cb" * 32, name="ghost.exe")
        result = runner.invoke(cli.app, ["capabilities", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no readable file" in result.stdout

    def test_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew imports exited with code 1")

        monkeypatch.setattr(fake_engine, "imports", boom)
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["capabilities", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestSecretsCommand:
    GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ef" * 32, name="demo.exe", path=str(target))

    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        *,
        strings: list[dict[str, object]],
    ) -> None:
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": strings})

    def test_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            strings=[{"text": self.GITHUB_TOKEN, "va": "0x402000"}],
        )
        result = runner.invoke(cli.app, ["secrets", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["binary_id"] == binary_id
        assert payload["count"] == 1
        assert payload["findings"][0]["name"] == "github-token"
        assert payload["findings"][0]["value"] == self.GITHUB_TOKEN
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECRETS)
        assert stored == _drop_action(payload)

    def test_human_output_warns_and_shows_the_redacted_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            strings=[{"text": self.GITHUB_TOKEN, "va": "0x402000"}],
        )
        result = runner.invoke(cli.app, ["secrets", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "live secrets" in result.output
        assert "github-token" in result.output
        assert "high" in result.output
        assert "Redacted" in result.output
        assert "0x402000" in result.output
        assert self.GITHUB_TOKEN not in result.output

    def test_empty_result_human_shows_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine, strings=[])
        result = runner.invoke(cli.app, ["secrets", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "No secrets found" in result.output

    def test_empty_result_json_still_stores(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine, strings=[])
        result = runner.invoke(cli.app, ["secrets", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["findings"] == []
        assert payload["scanned"] == 0
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECRETS)
        assert stored is not None and stored["findings"] == []

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["secrets", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["secrets", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_missing_file_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="ee" * 32, name="ghost.exe")
        result = runner.invoke(cli.app, ["secrets", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no readable file" in result.stdout

    def test_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew strings exited with code 1")

        monkeypatch.setattr(fake_engine, "strings", boom)
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["secrets", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestFileTypeCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ed" * 32, name="demo.exe", path=str(target))

    def _stub_packed(self, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine) -> None:
        monkeypatch.setattr(
            fake_engine,
            "pe_info",
            lambda binary: {
                "format": "pe",
                "sections": [{"name": "UPX0"}, {"name": "UPX1", "execute": True}],
            },
        )
        monkeypatch.setattr(
            fake_engine,
            "strings",
            lambda binary: {"strings": [{"text": "UPX!", "va": "0x402000"}]},
        )

    def test_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub_packed(monkeypatch, fake_engine)
        result = runner.invoke(cli.app, ["filetype", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["binary_id"] == binary_id
        assert payload["matches"][0]["name"] == "UPX"
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_FILETYPE)
        assert stored == _drop_action(payload)

    def test_human_output_shows_counts_table_and_signals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub_packed(monkeypatch, fake_engine)
        result = runner.invoke(cli.app, ["filetype", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "packer 1" in result.output
        assert "UPX" in result.output
        assert "high" in result.output
        assert "section: UPX1" in result.output

    def test_empty_result_human_shows_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        monkeypatch.setattr(fake_engine, "pe_info", lambda binary: {"format": "pe", "sections": []})
        result = runner.invoke(cli.app, ["filetype", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "No signatures matched." in result.output

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["filetype", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_a_failing_engine_call_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(binary: str | Path) -> dict[str, Any]:
            raise engines.EngineError("rebrew pe-info failed: not a PE")

        for name in ("pe_info", "fingerprint", "imports", "strings"):
            monkeypatch.setattr(fake_engine, name, boom)
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["filetype", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "not a PE" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["filetype", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_missing_file_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="ec" * 32, name="ghost.exe")
        result = runner.invoke(cli.app, ["filetype", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no readable file" in result.stdout


class TestBehaviorCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="bf" * 32, name="demo.exe", path=str(target))

    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        *,
        imports: list[dict[str, object]],
        strings: list[dict[str, object]],
    ) -> None:
        monkeypatch.setattr(
            fake_engine, "imports", lambda binary: {"imports": list(imports), "stubs": []}
        )
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": list(strings)})

    def test_json_single_domain_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[{"dll": "KERNEL32.dll", "name": "CreateProcessA", "iat_va": "0x401000"}],
            strings=[],
        )
        result = runner.invoke(cli.app, ["behavior", str(binary_id), "execution", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["domain"] == "execution"
        assert payload["count"] == 1
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_EXECUTION)
        assert stored == _drop_action(payload)

    def test_json_all_runs_and_stores_every_domain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[
                {"dll": "KERNEL32.dll", "name": "CreateProcessA", "iat_va": "0x401000"},
                {"dll": "WS2_32.dll", "name": "WSAStartup", "iat_va": "0x401004"},
                {"dll": "KERNEL32.dll", "name": "CreateFileA", "iat_va": "0x401008"},
            ],
            strings=[],
        )
        result = runner.invoke(cli.app, ["behavior", str(binary_id), "--all", "--json"])
        assert result.exit_code == 0, result.output
        payload = _drop_action(json.loads(result.stdout))
        assert set(payload) == {"execution", "networking", "filesystem"}
        assert payload["execution"]["count"] == 1
        assert payload["networking"]["count"] == 1
        assert payload["filesystem"]["count"] == 1
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            for kind in (
                store.SCAN_KIND_EXECUTION,
                store.SCAN_KIND_NETWORKING,
                store.SCAN_KIND_FILESYSTEM,
            ):
                assert store.get_scan(conn, analysis_id or 0, kind) is not None

    def test_human_output_shows_counts_and_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[{"dll": "KERNEL32.dll", "name": "CreateProcessA", "iat_va": "0x401000"}],
            strings=[],
        )
        result = runner.invoke(cli.app, ["behavior", str(binary_id), "execution"])
        assert result.exit_code == 0, result.output
        assert "1 findings" in result.output
        assert "CreateProcessA" in result.output
        assert "process-launch" in result.output

    def test_all_human_prints_every_domain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine, imports=[], strings=[])
        result = runner.invoke(cli.app, ["behavior", str(binary_id), "--all"])
        assert result.exit_code == 0, result.output
        for domain in ("execution", "networking", "filesystem"):
            assert f"No {domain} behavior found" in result.output

    def test_unknown_domain_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["behavior", str(binary_id), "registry", "--json"])
        assert result.exit_code == 1
        assert "unknown behavior domain: registry" in result.stdout

    def test_requires_a_domain_or_all(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["behavior", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "provide a behavior domain or --all" in result.stdout

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["behavior", str(binary_id), "execution", "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["behavior", "4242", "execution", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout


class TestHardeningCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(
                conn, sha256="hb" * 32, name="demo.exe", path=str(target), size=1024
            )

    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        *,
        imports: list[dict[str, object]],
        strings: list[dict[str, object]],
        sections: list[dict[str, object]] | None = None,
    ) -> None:
        monkeypatch.setattr(
            fake_engine, "imports", lambda binary: {"imports": list(imports), "stubs": []}
        )
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": list(strings)})
        monkeypatch.setattr(
            fake_engine,
            "fingerprint",
            lambda binary: {
                "format": "pe",
                "size": 1024,
                "section_entropies": list(sections or []),
            },
        )

    def test_json_single_domain_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[{"dll": "KERNEL32.dll", "name": "IsDebuggerPresent", "iat_va": "0x401000"}],
            strings=[],
        )
        result = runner.invoke(cli.app, ["hardening", str(binary_id), "anti-analysis", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["domain"] == "anti-analysis"
        assert payload["count"] == 1
        assert payload["packer_likelihood"] is None
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_ANTI_ANALYSIS)
        assert stored == _drop_action(payload)

    def test_json_all_runs_and_stores_both_domains(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[],
            strings=[],
            sections=[{"name": ".text", "entropy": 7.8, "raw_size": 512, "vsize": 512}],
        )
        result = runner.invoke(cli.app, ["hardening", str(binary_id), "--all", "--json"])
        assert result.exit_code == 0, result.output
        payload = _drop_action(json.loads(result.stdout))
        assert set(payload) == {"anti-analysis", "obfuscation"}
        assert payload["obfuscation"]["packer_likelihood"] == "medium"
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            for kind in (store.SCAN_KIND_ANTI_ANALYSIS, store.SCAN_KIND_OBFUSCATION):
                assert store.get_scan(conn, analysis_id or 0, kind) is not None

    def test_human_output_shows_counts_and_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[{"dll": "KERNEL32.dll", "name": "IsDebuggerPresent", "iat_va": "0x401000"}],
            strings=[],
        )
        result = runner.invoke(cli.app, ["hardening", str(binary_id), "anti-analysis"])
        assert result.exit_code == 0, result.output
        assert "1 findings" in result.output
        assert "anti-debug-api" in result.output

    def test_human_output_shows_the_packer_likelihood(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(
            monkeypatch,
            fake_engine,
            imports=[],
            strings=[],
            sections=[{"name": ".text", "entropy": 7.8, "raw_size": 512, "vsize": 512}],
        )
        result = runner.invoke(cli.app, ["hardening", str(binary_id), "obfuscation"])
        assert result.exit_code == 0, result.output
        assert "packer likelihood: medium" in result.output
        assert "2 findings" in result.output
        assert ".text" in result.output

    def test_all_human_prints_every_domain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine, imports=[], strings=[])
        result = runner.invoke(cli.app, ["hardening", str(binary_id), "--all"])
        assert result.exit_code == 0, result.output
        assert "No anti-analysis findings" in result.output
        assert "No obfuscation findings" in result.output

    def test_unknown_domain_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["hardening", str(binary_id), "packing", "--json"])
        assert result.exit_code == 1
        assert "unknown hardening domain: packing" in result.stdout

    def test_requires_a_domain_or_all(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["hardening", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "provide a hardening domain or --all" in result.stdout

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["hardening", str(binary_id), "anti-analysis", "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["hardening", "4242", "anti-analysis", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout


class TestSecurityScanCommand:
    def test_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["security-scan", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == SECURITY["count"]
        assert payload["by_severity"] == SECURITY["by_severity"]
        assert fake_engine.calls == ["security_scan"]
        assert fake_engine.security_scan_args == (str(tmp_path), "low")
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, ids["binary"])
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECURITY)
        assert stored == _drop_action(payload)

    def test_min_severity_reaches_the_engine(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["security-scan", str(ids["binary"]), "--min-severity", "high", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert fake_engine.security_scan_args == (str(tmp_path), "high")

    def test_human_output_shows_table_and_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["security-scan", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "2 findings across 70 files" in result.output
        assert "CWE-120" in result.output
        assert "high 1" in result.output
        assert "low 1" in result.output

    def test_empty_result_human_shows_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        empty = {
            "root": "",
            "files_scanned": 0,
            "findings": [],
            "count": 0,
            "by_severity": {"high": 0, "medium": 0, "low": 0},
        }
        monkeypatch.setattr(
            fake_engine,
            "security_scan",
            lambda project_dir, min_severity="low": {**empty, "root": str(project_dir)},
        )
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["security-scan", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "No security findings" in result.output

    def test_empty_result_json_still_stores(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        empty = {
            "root": "",
            "files_scanned": 0,
            "findings": [],
            "count": 0,
            "by_severity": {"high": 0, "medium": 0, "low": 0},
        }
        monkeypatch.setattr(
            fake_engine,
            "security_scan",
            lambda project_dir, min_severity="low": {**empty, "root": str(project_dir)},
        )
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["security-scan", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["findings"] == []
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, ids["binary"])
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_SECURITY)
        assert stored is not None and stored["findings"] == []

    def test_invalid_severity_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["security-scan", str(ids["binary"]), "--min-severity", "critical", "--json"]
        )
        assert result.exit_code == 1
        assert "unknown severity" in result.stdout
        assert fake_engine.calls == []

    def test_without_context_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["security-scan", str(ids["binary"]), "--json"])
        assert result.exit_code == 1
        assert "no analysis context yet" in result.stdout
        assert fake_engine.calls == []

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["security-scan", str(ids["binary"]), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["security-scan", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout
        assert fake_engine.calls == []

    def test_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew security-scan exited with code 1")

        monkeypatch.setattr(fake_engine, "security_scan", boom)
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["security-scan", str(ids["binary"]), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestThreatCommand:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        with contextlib.closing(store.connect(db)) as conn:
            return store.add_binary(conn, sha256="ff" * 32, name="demo.exe", path=str(target))

    def _stub(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        *,
        url: str = "https://c2.example.com/beacon",
    ) -> None:
        monkeypatch.setattr(
            fake_engine,
            "imports",
            lambda binary: {
                "imports": [{"dll": "WS2_32.dll", "name": "WSAStartup", "iat_va": "0x401000"}],
                "stubs": [],
            },
        )
        monkeypatch.setattr(
            fake_engine,
            "strings",
            lambda binary: {
                "strings": [{"text": url, "va": 0x402000, "size": len(url), "kind": "ascii"}]
            },
        )

    def test_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine)
        result = runner.invoke(cli.app, ["threat", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["ioc_counts"]["urls"] == 1
        assert {item["id"] for item in payload["techniques"]} >= {"T1071"}
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_THREAT)
        assert stored == _drop_action(payload)

    def test_human_output_shows_counts_sample_and_techniques(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine)
        result = runner.invoke(cli.app, ["threat", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "urls" in result.output
        assert "https://c2.example.com/beacon" in result.output
        assert "T1071" in result.output
        assert "Application Layer Protocol" in result.output

    def test_narrative_flag_prints_the_summary(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
        fake_llm: FakeLlmClient,
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        self._stub(monkeypatch, fake_engine)
        result = runner.invoke(cli.app, ["threat", str(binary_id), "--narrative"])
        assert result.exit_code == 0, result.output
        assert "Reads a file into a buffer" in result.output
        assert fake_llm.calls

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["threat", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["threat", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_missing_file_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="fe" * 32, name="ghost.exe")
        result = runner.invoke(cli.app, ["threat", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no readable file" in result.stdout

    def test_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew strings exited with code 1")

        monkeypatch.setattr(fake_engine, "strings", boom)
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["threat", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestUnstripCommand:
    def test_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["unstrip", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["candidates"] == 2
        assert [proposal["proposed_name"] for proposal in payload["proposals"]] == [
            "ChooseFontW",
            "GetOpenFileNameW",
        ]
        assert fake_engine.calls == ["identify_library"]
        assert fake_engine.identify_arg == str(tmp_path)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            analysis_id = store.latest_analysis_for_binary(conn, ids["binary"])
            stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_UNSTRIP)
        assert stored == _drop_action(payload)

    def test_human_output_lists_proposals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["unstrip", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "ChooseFontW" in result.output
        assert "2 candidates, 2 proposals" in result.output

    def test_min_confidence_filters_proposals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setattr(
            fake_engine,
            "identify_library",
            lambda project_dir: {"candidates": [{"va": "0x1000", "name": "X", "confidence": 0.3}]},
        )
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["unstrip", str(ids["binary"]), "--min-confidence", "0.5", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["candidates"] == 1
        assert payload["proposals"] == []

    def test_empty_proposals_human_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        monkeypatch.setattr(fake_engine, "identify_library", lambda project_dir: {"candidates": []})
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["unstrip", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "No unstrip proposals" in result.output

    def test_without_context_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["unstrip", str(ids["binary"]), "--json"])
        assert result.exit_code == 1
        assert "no analysis context yet" in result.stdout
        assert fake_engine.calls == []

    def test_without_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["unstrip", str(ids["binary"]), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["unstrip", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout
        assert fake_engine.calls == []

    def test_engine_error_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew identify-library exited with code 1")

        monkeypatch.setattr(fake_engine, "identify_library", boom)
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["unstrip", str(ids["binary"]), "--json"])
        assert result.exit_code == 1
        assert "exited with code 1" in result.stdout


class TestUnstripApplyCommand:
    def test_renames_from_stored_proposal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["unstrip", str(ids["binary"]), "--json"])
        result = runner.invoke(cli.app, ["unstrip-apply", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload.pop("journal_action")
        assert payload == {
            "function_id": ids["first"],
            "old_name": "sub_1000",
            "new_name": "ChooseFontW",
        }
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            function = store.get_function(conn, ids["first"])
            history = store.list_name_history(conn, ids["first"])
        assert function is not None
        assert function["name"] == "ChooseFontW"
        assert function["name_source"] == "unstrip"
        assert history[0]["source"] == "unstrip"
        assert history[0]["old_name"] == "sub_1000"

    def test_name_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["unstrip", str(ids["binary"]), "--json"])
        result = runner.invoke(
            cli.app, ["unstrip-apply", str(ids["first"]), "--name", "Custom", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["new_name"] == "Custom"

    def test_without_stored_proposal_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["unstrip-apply", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "no stored unstrip proposal" in result.stdout

    def test_unknown_function_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_with_context(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["unstrip-apply", "4242", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout

    def test_blank_name_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["unstrip", str(ids["binary"]), "--json"])
        result = runner.invoke(
            cli.app, ["unstrip-apply", str(ids["first"]), "--name", "   ", "--json"]
        )
        assert result.exit_code == 1
        assert "must not be empty" in result.stdout

    def test_human_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        ids = _seed_with_context(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["unstrip", str(ids["binary"]), "--json"])
        result = runner.invoke(cli.app, ["unstrip-apply", str(ids["first"])])
        assert result.exit_code == 0, result.output
        assert "ChooseFontW" in result.output


def _seed_with_decompilation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Seed the portal and store a decompilation for its first function."""
    ids = _seed_portal(tmp_path, monkeypatch)
    with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
        store.set_decompilation(conn, ids["first"], "int f(void) { return 1; }", "kuna")
    return ids


class TestAiCommands:
    def test_summary_json_stores_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = AI_SUMMARY_RESPONSE
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["summary", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["function_id"] == ids["first"]
        assert payload["kind"] == "summary"
        assert payload["model"] == "fake-model"
        assert payload["payload"]["summary"].startswith("Reads a file")
        assert fake_llm.calls and "int f(void)" in fake_llm.calls[0][1]["content"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            stored = store.get_ai_artifact(conn, ids["first"], "summary")
        assert stored is not None
        assert stored["model"] == "fake-model"

    def test_summary_human_prints_the_paragraph(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = AI_SUMMARY_RESPONSE
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["summary", str(ids["first"])])
        assert result.exit_code == 0, result.output
        assert "Reads a file into a buffer" in result.output

    def test_comments_human_lists_lines(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = AI_COMMENTS_RESPONSE
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["ai-comments", str(ids["first"])])
        assert result.exit_code == 0, result.output
        assert "open the target file" in result.output
        assert "3" in result.output
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            stored = store.get_ai_artifact(conn, ids["first"], "comments")
        assert stored is not None
        assert stored["payload"]["comments"][0]["line"] == 3

    def test_comments_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = AI_COMMENTS_RESPONSE
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["ai-comments", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["kind"] == "comments"
        assert len(payload["payload"]["comments"]) == 2

    def test_suggest_types_human_lists_types(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = AI_TYPES_RESPONSE
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["suggest-types", str(ids["first"])])
        assert result.exit_code == 0, result.output
        assert "const char *" in result.output
        assert "parameter" in result.output

    def test_suggest_types_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = AI_TYPES_RESPONSE
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["suggest-types", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["kind"] == "type-suggestions"
        assert payload["payload"]["suggestions"][0]["kind"] == "parameter"

    def test_without_a_client_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["summary", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "llm-unavailable" in result.stdout
        assert "REPORTAL_LLM_ENDPOINT" in result.stdout

    def test_without_a_client_human_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["ai-comments", str(ids["first"])])
        assert result.exit_code == 1
        assert "llm-unavailable" in result.output

    def test_without_a_decompilation_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["summary", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "has no stored decompilation" in result.stdout
        assert fake_llm.calls == []

    def test_unknown_function_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["suggest-types", "4242", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout

    def test_malformed_model_response_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = "not json at all"
        ids = _seed_with_decompilation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["summary", str(ids["first"]), "--json"])
        assert result.exit_code == 1
        assert "llm-error" in result.stdout
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert store.get_ai_artifact(conn, ids["first"], "summary") is None


def _seed_conversation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, scope_kind: str = "function"
) -> dict[str, int]:
    """Seed the portal and store one conversation with a single user message."""
    ids = _seed_portal(tmp_path, monkeypatch)
    scope_id = ids["first"] if scope_kind == "function" else ids["binary"]
    with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
        conversation_id = store.create_conversation(
            conn, scope_kind=scope_kind, scope_id=scope_id, title="seeded chat"
        )
        store.add_message(
            conn, conversation_id=conversation_id, role="user", content="what is this?"
        )
    return {**ids, "conversation": conversation_id}


class TestConversationCommands:
    def test_list_json_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["conversations", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout) == {"conversations": []}

    def test_list_json_shows_a_conversation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_conversation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["conversations", "--json"])
        assert result.exit_code == 0, result.output
        rows = json.loads(result.stdout)["conversations"]
        assert len(rows) == 1
        assert rows[0]["id"] == ids["conversation"]
        assert rows[0]["title"] == "seeded chat"
        assert rows[0]["scope_kind"] == "function"
        assert rows[0]["scope_id"] == ids["first"]
        assert rows[0]["message_count"] == 1

    def test_list_human_prints_the_title(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_conversation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["conversations"])
        assert result.exit_code == 0, result.output
        assert "seeded chat" in result.output

    def test_chat_new_function_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["chat-new", "--function", str(ids["first"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["scope_kind"] == "function"
        assert payload["scope_id"] == ids["first"]
        assert payload["title"] == "sub_1000 @ 0x1000"

    def test_chat_new_binary_with_title(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["chat-new", "--binary", str(ids["binary"]), "--title", "Entry point", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["scope_kind"] == "binary"
        assert payload["scope_id"] == ids["binary"]
        assert payload["title"] == "Entry point"

    def test_chat_new_requires_exactly_one_scope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        neither = runner.invoke(cli.app, ["chat-new", "--json"])
        assert neither.exit_code == 1
        assert "exactly one of --function or --binary" in neither.stdout
        both = runner.invoke(
            cli.app,
            ["chat-new", "--function", str(ids["first"]), "--binary", str(ids["binary"]), "--json"],
        )
        assert both.exit_code == 1
        assert "exactly one of --function or --binary" in both.stdout

    def test_chat_new_unknown_function_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["chat-new", "--function", "4242", "--json"])
        assert result.exit_code == 1
        assert "no function with id 4242" in result.stdout

    def test_chat_human_prints_the_exchange(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = "It reads a file."
        ids = _seed_conversation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["chat", str(ids["conversation"]), "explain this"])
        assert result.exit_code == 0, result.output
        assert "explain this" in result.output
        assert "It reads a file." in result.output
        assert len(fake_llm.calls) == 1
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert [row["role"] for row in store.list_messages(conn, ids["conversation"])] == [
                "user",
                "user",
                "assistant",
            ]

    def test_chat_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        fake_llm.response = "It reads a file."
        ids = _seed_conversation(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["chat", str(ids["conversation"]), "explain this", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["conversation_id"] == ids["conversation"]
        assert payload["user"]["content"] == "explain this"
        assert payload["assistant"]["content"] == "It reads a file."

    def test_chat_unknown_conversation_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_llm: FakeLlmClient
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["chat", "4242", "hello", "--json"])
        assert result.exit_code == 1
        assert "no conversation with id 4242" in result.stdout
        assert fake_llm.calls == []

    def test_chat_without_a_client_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_conversation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["chat", str(ids["conversation"]), "hello", "--json"])
        assert result.exit_code == 1
        assert "llm-unavailable" in result.stdout
        assert "REPORTAL_LLM_ENDPOINT" in result.stdout

    def test_chat_model_error_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        llm.set_client(FailingLlmClient("model exploded"))
        ids = _seed_conversation(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["chat", str(ids["conversation"]), "hello", "--json"])
        assert result.exit_code == 1
        assert "llm-error: model exploded" in result.stdout

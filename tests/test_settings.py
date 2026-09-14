"""Tests for the settings report: resolution, origin, redaction and ignored keys.

Every setting is checked against the module that reads it, so the registry
cannot drift from the code: a value the module resolves must be the value the
report shows, and an environment variable the report names must be the one that
changes it.  The report is a read of the workspace file, so the tests write the
file they want and assert what reportal says about it.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import _paths, auth, cli, doctor, external, graph_backends, llm, settings

runner = CliRunner()


def _workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str = "") -> None:
    """Make *tmp_path* the workspace, with *body* as its reportal.toml text."""
    (tmp_path / "reportal.toml").write_text(body, encoding="utf-8")
    monkeypatch.chdir(tmp_path)


def _row(name: str, tables: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """One resolved setting row, by name."""
    for row in settings.resolve(tables):
        if row["name"] == name:
            return row
    raise AssertionError(f"no setting named {name}")


class TestSurface:
    def test_every_setting_names_a_reader_and_a_place_it_comes_from(self) -> None:
        for setting in settings.SETTINGS:
            assert setting.name.count(".") == 1, setting.name
            assert setting.describe.strip()
            assert setting.default.strip()
            assert callable(setting.read)
            assert setting.env or setting.table, setting.name
            if setting.table:
                assert setting.key, setting.name

    def test_the_names_are_unique(self) -> None:
        names = [setting.name for setting in settings.SETTINGS]
        assert len(names) == len(set(names))
        assert set(names) == set(settings.BY_NAME)

    def test_the_workspace_keys_are_unique(self) -> None:
        seen: set[tuple[str, str]] = set()
        for setting in settings.SETTINGS:
            if not setting.table:
                continue
            pair = (setting.table, setting.key)
            assert pair not in seen, pair
            seen.add(pair)

    def test_the_registry_covers_every_variable_the_package_reads(self) -> None:
        """A REPORTAL_* variable no setting names would be an undocumented knob."""
        import re

        source = Path(__file__).resolve().parents[1] / "src" / "reportal"
        declared = {setting.env for setting in settings.SETTINGS if setting.env}
        found: set[str] = set()
        for path in source.glob("*.py"):
            found.update(re.findall(r'"(REPORTAL_[A-Z_]+)"', path.read_text(encoding="utf-8")))
        assert found - declared == set(), f"not in the registry: {sorted(found - declared)}"


class TestAgreement:
    """Each resolved value is the one the module that reads it resolves."""

    def test_the_flags_agree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_AUTH", "required")
        monkeypatch.setenv("REPORTAL_SANDBOX", "enabled")
        monkeypatch.setenv("REPORTAL_ALLOW_EXTERNAL", "1")
        monkeypatch.setenv("REPORTAL_ALLOW_REMOTE_INGEST", "on")

        assert _row("auth.required")["value"] is auth.required() is True
        assert _row("sandbox.enabled")["value"] is sandbox_enabled()
        assert _row("external.allow_remote")["value"] is external.remote_enabled() is True
        assert _row("knowledge.allow_remote")["value"] is True

    def test_a_falsey_flag_falls_through_to_the_file_but_the_report_says_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, "[sandbox]\nenabled = true\n")
        monkeypatch.setenv("REPORTAL_SANDBOX", "0")

        # The reader tests the environment for truth and then the file, so the
        # file wins over a falsey value; the origin has to say the file.
        row = _row("sandbox.enabled")
        assert row["value"] is sandbox_enabled() is True
        assert row["origin"] == settings.ORIGIN_WORKSPACE

    def test_the_job_pool_reads_its_falsey_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_JOBS_POOL", "off")

        row = _row("jobs.pool")
        assert row["value"] is False
        assert row["origin"] == settings.ORIGIN_ENVIRONMENT

    def test_the_texts_agree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_LLM_ENDPOINT", "http://127.0.0.1:1234/v1")
        monkeypatch.setenv("REPORTAL_LLM_MODEL", "local-model")
        monkeypatch.setenv("REPORTAL_GRAPH_BACKEND", "sqlite")
        monkeypatch.setenv("REPORTAL_GRAPH_COGNEE", "")

        assert _row("llm.endpoint")["value"] == "http://127.0.0.1:1234/v1"
        assert llm.LlmConfig.resolve() is not None
        assert _row("llm.model")["value"] == llm.get_client().model == "local-model"
        assert _row("knowledge.graph_backend")["value"] == graph_backends.configured_backend_name()
        assert _row("knowledge.cognee_dataset")["value"] == graph_backends.cognee_dataset_name()

    def test_the_database_path_agrees(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[portal]\ndb = "state.db"\n')
        assert _row("database.path")["value"] == str(_paths.db_path())
        assert _paths.database_path(tmp_path) == tmp_path / "state.db"
        assert _row("database.path")["value"] == str(tmp_path / "state.db")
        assert _row("database.path")["origin"] == settings.ORIGIN_WORKSPACE

    def test_the_pipeline_list_agrees(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[pipeline]\ndisabled = ["summarize", "types"]\n')

        from reportal import pipeline

        row = _row("pipeline.disabled")
        assert row["value"] == sorted(pipeline.configured_disabled())
        assert row["value"] == ["summarize", "types"]


def sandbox_enabled() -> bool:
    from reportal import sandbox

    return sandbox.enabled()


class TestOrigin:
    def test_a_default_is_reported_as_a_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        for name in ("auth.required", "llm.model", "knowledge.graph_backend"):
            assert _row(name)["origin"] == settings.ORIGIN_DEFAULT, name

    def test_the_environment_wins_and_is_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[knowledge]\ngraph_backend = "cognee"\n')
        monkeypatch.setenv("REPORTAL_GRAPH_BACKEND", "sqlite")

        row = _row("knowledge.graph_backend")
        assert row["value"] == "sqlite"
        assert row["origin"] == settings.ORIGIN_ENVIRONMENT

    def test_the_workspace_file_is_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(
            tmp_path,
            monkeypatch,
            '[llm]\nendpoint = "http://127.0.0.1:1234/v1"\nmodel = "workspace-model"\n',
        )
        monkeypatch.delenv("REPORTAL_LLM_MODEL", raising=False)
        monkeypatch.delenv("REPORTAL_LLM_ENDPOINT", raising=False)

        row = _row("llm.model")
        assert row["value"] == "workspace-model"
        assert row["origin"] == settings.ORIGIN_WORKSPACE
        assert row["table_key"] == "[llm] model"

    def test_a_secret_from_the_store_is_named_without_its_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conn: sqlite3.Connection
    ) -> None:
        from reportal import journal, secret_store

        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_LLM_ENDPOINT", "http://127.0.0.1:1234/v1")
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            secret_store.journaled_set(
                conn,
                log,
                name="llm.api_key",
                value="sk-" + "a" * 30,
                description="store the bridge key",
            )

        row = _row("llm.api_key")
        assert row["origin"] == settings.ORIGIN_SECRET_STORE
        assert row["secret"] is True
        assert row["display"] == "set (33 bytes)"
        assert "value" not in row
        assert "sk-" not in json.dumps(settings.report())

    def test_no_workspace_is_not_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        payload = settings.report()
        assert payload["workspace"] == ""
        assert any(problem["level"] == settings.LEVEL_WARN for problem in payload["problems"])


class TestProblems:
    def test_a_clean_file_has_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _workspace(tmp_path, monkeypatch, '[portal]\ndb = "reportal.db"\n[llm]\nmodel = "m"\n')
        assert settings.problems() == []

    def test_an_unknown_key_suggests_the_nearest_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[llm]\nendpoind = "http://x"\n')
        problems = settings.problems()
        assert len(problems) == 1
        assert problems[0]["level"] == settings.LEVEL_WARN
        assert problems[0]["where"] == "[llm] endpoind"
        assert "endpoint" in problems[0]["hint"]

    def test_an_unknown_table_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[llms]\nmodel = "m"\n')
        problems = settings.problems()
        assert problems[0]["where"] == "[llms]"
        assert "llm" in problems[0]["hint"]

    def test_a_quoted_boolean_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[auth]\nrequired = "true"\n')
        problems = settings.problems()
        assert problems[0]["where"] == "[auth] required"
        assert "must be true or false" in problems[0]["problem"]
        # And the value really is ignored: the reader tests for a boolean.
        assert auth.required() is False

    def test_a_wrong_type_on_a_text_key_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, "[llm]\nmodel = 7\n")
        assert "must be a string" in settings.problems()[0]["problem"]

    def test_a_wrong_type_on_a_list_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[pipeline]\ndisabled = "summarize"\n')
        assert "list of strings" in settings.problems()[0]["problem"]

    def test_an_unparsable_file_is_a_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, "[llm\nmodel = 'm'\n")
        problems = settings.problems()
        assert [problem["level"] for problem in problems] == [settings.LEVEL_FAIL]
        assert "falls back to its default" in problems[0]["problem"]
        assert len(settings.failing()) == 1

    def test_a_top_level_key_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, 'model = "m"\n')
        assert "is not a table" in settings.problems()[0]["problem"]


class TestCli:
    def test_the_command_prints_the_settings_and_the_origin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(
            tmp_path,
            monkeypatch,
            '[llm]\nendpoint = "http://127.0.0.1:1234/v1"\nmodel = "workspace-model"\n',
        )
        result = runner.invoke(cli.app, ["config"])
        assert result.exit_code == 0, result.output
        assert "llm.model" in result.output
        assert "workspace-model" in result.output
        assert "workspace" in result.output
        assert "every key and value is one reportal reads" in result.output

    def test_the_json_flag_carries_both_halves(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["config", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["name"] == "reportal"  # the instance description
        assert payload["count"] == len(settings.SETTINGS)  # and the settings
        assert any(row["name"] == "database.path" for row in payload["settings"])

    def test_an_ignored_key_prints_and_does_not_fail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[llm]\nendpoind = "http://x"\n')
        result = runner.invoke(cli.app, ["config"])
        assert result.exit_code == 0, result.output
        assert "[llm] endpoind" in result.output

    def test_an_unparsable_file_exits_nonzero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, "[llm\nmodel = 'm'\n")
        result = runner.invoke(cli.app, ["config"])
        assert result.exit_code == 1
        assert "fail" in result.output


class TestDoctor:
    def test_a_clean_file_is_ok(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        payload = doctor.report()
        row = next(check for check in payload["checks"] if check["name"] == "config")
        assert row["status"] == "ok"
        assert str(len(settings.SETTINGS)) in row["detail"]

    def test_an_ignored_key_warns(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[llm]\nendpoind = "http://x"\n')
        payload = doctor.report()
        row = next(check for check in payload["checks"] if check["name"] == "config")
        assert row["status"] == "warn"
        assert "[llm] endpoind" in row["detail"]
        # A warning never fails the run.
        assert payload["status"] == "ok"

    def test_an_unparsable_file_fails(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, "[llm\nmodel = 'm'\n")
        payload = doctor.report()
        row = next(check for check in payload["checks"] if check["name"] == "config")
        assert row["status"] == "fail"
        assert "config" in payload["failures"]


class TestDatabaseName:
    def test_a_relative_name_resolves_against_the_workspace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[portal]\ndb = "state/portal.db"\n')
        monkeypatch.delenv(_paths.DB_ENV, raising=False)
        assert _paths.db_path() == tmp_path / "state" / "portal.db"
        assert _paths.configured_db_name() == "state/portal.db"

    def test_an_absolute_name_is_used_as_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        elsewhere = tmp_path / "elsewhere" / "portal.db"
        _workspace(tmp_path, monkeypatch, f'[portal]\ndb = "{elsewhere}"\n')
        monkeypatch.delenv(_paths.DB_ENV, raising=False)
        assert _paths.db_path() == elsewhere

    def test_the_environment_still_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        override = tmp_path / "override.db"
        _workspace(tmp_path, monkeypatch, '[portal]\ndb = "state.db"\n')
        monkeypatch.setenv(_paths.DB_ENV, str(override))
        assert _paths.db_path() == override

    def test_a_file_without_the_key_reads_the_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, "[auth]\n")
        monkeypatch.delenv(_paths.DB_ENV, raising=False)
        assert _paths.db_path() == tmp_path / _paths.DB_NAME
        assert _paths.configured_db_name() == ""

    def test_an_unparsable_file_reads_the_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, "[portal\n")
        monkeypatch.delenv(_paths.DB_ENV, raising=False)
        assert _paths.db_path() == tmp_path / _paths.DB_NAME

    def test_the_named_database_is_the_one_a_command_uses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[portal]\ndb = "state.db"\n')
        monkeypatch.delenv(_paths.DB_ENV, raising=False)
        result = runner.invoke(cli.app, ["init"])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "state.db").is_file()
        assert not (tmp_path / "reportal.db").exists()

    def test_the_health_route_reports_the_named_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch, '[portal]\ndb = "state.db"\n')
        monkeypatch.delenv(_paths.DB_ENV, raising=False)
        from reportal import store

        store.init_db(tmp_path / "state.db")
        status, headers, body = wsgi_request("GET", "/api/health")
        assert status.startswith("200")
        assert json_body(body, headers)["db"] == str(tmp_path / "state.db")


def test_the_report_is_one_read_of_the_workspace_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A report passes the tables it read, so nothing re-reads the file per setting."""
    _workspace(tmp_path, monkeypatch, '[llm]\nmodel = "m"\n')
    calls = {"n": 0}
    original = settings.workspace_tables

    def counted() -> dict[str, dict[str, Any]]:
        calls["n"] += 1
        return original()

    monkeypatch.setattr(settings, "workspace_tables", counted)
    settings.report()
    assert calls["n"] == 1

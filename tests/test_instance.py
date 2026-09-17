"""Tests for the instance description: `GET /api/config`, its CLI and its MCP tool."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import (
    __version__,
    analysis_log,
    api,
    archive,
    bulk_actions,
    cli,
    comments,
    external,
    instance,
    integrations,
    journal,
    knowledge,
    mcp_tools,
    profiles,
    sandbox,
    store,
)
from reportal._paths import DB_ENV

runner = CliRunner()


def _config() -> tuple[str, dict[str, Any]]:
    status, headers, payload = wsgi_request("GET", "/api/config")
    return status, json_body(payload, headers)


class TestPayload:
    def test_it_names_the_instance_and_its_version(self) -> None:
        payload = instance.describe()

        assert payload["name"] == "reportal"
        assert payload["version"] == __version__

    def test_the_limits_are_the_modules_own_values(self) -> None:
        limits = instance.limits()

        assert limits["max_upload_bytes"] == api.MAX_UPLOAD_BYTES
        assert limits["max_upload_files"] == api.MAX_UPLOAD_FILES
        assert limits["max_search_limit"] == store.MAX_SEARCH_LIMIT
        assert limits["max_bulk_ids"] == bulk_actions.MAX_BULK_IDS
        assert limits["max_comment_chars"] == comments.MAX_COMMENT_CHARS
        assert limits["max_log_limit"] == analysis_log.MAX_LOG_LIMIT
        assert limits["max_journal_file_bytes"] == journal.MAX_FILE_BYTES
        assert limits["max_document_bytes"] == knowledge.MAX_DOCUMENT_BYTES
        assert limits["max_archive_members"] == archive.MAX_MEMBERS

    def test_the_mcp_counts_are_the_registrys_own_totals(self) -> None:
        payload = instance.describe()

        assert payload["mcp"] == integrations.tool_totals()
        assert payload["mcp"]["total"] == len(mcp_tools.tools())

    def test_the_guarded_paths_are_off_by_default(self, monkeypatch: Any) -> None:
        monkeypatch.delenv("REPORTAL_ALLOW_REMOTE_INGEST", raising=False)

        features = instance.features()

        assert features["llm"] is False
        assert features["remote_ingest"] is False
        assert features["sandbox"] is False
        assert features["external_sources"] is False
        assert features["auth"] == "single-user"

    def test_a_configured_bridge_is_reported_as_on(self, fake_llm: Any) -> None:
        assert instance.features()["llm"] is True
        assert instance.describe()["llm"]["model"] == "fake-model"

    def test_an_enabled_remote_ingest_is_reported_as_on(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("REPORTAL_ALLOW_REMOTE_INGEST", "1")

        assert instance.features()["remote_ingest"] is True

    def test_an_enabled_detonation_is_reported_as_on(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("REPORTAL_SANDBOX", "enabled")

        assert instance.features()["sandbox"] is True

    def test_enabled_remote_sources_are_reported_as_on(self, monkeypatch: Any) -> None:
        monkeypatch.setenv("REPORTAL_ALLOW_EXTERNAL", "1")

        assert instance.features()["external_sources"] is True

    def test_the_features_are_the_opt_ins_the_paths_read(self, monkeypatch: Any) -> None:
        # Each flag is the gate the path itself checks, so the config read and
        # the route that refuses cannot disagree.
        monkeypatch.setenv("REPORTAL_SANDBOX", "1")
        monkeypatch.setenv("REPORTAL_ALLOW_EXTERNAL", "yes")

        features = instance.features()

        assert features["sandbox"] is sandbox.enabled()
        assert features["external_sources"] is external.remote_enabled()

    def test_it_reports_the_engine_and_its_backends(self, fake_engine: Any) -> None:
        engine = instance.describe()["engine"]

        assert engine["available"] is True
        assert engine["origin"] == "/fake/bin/rebrew"
        assert "kuna" in engine["backends"]

    def test_a_workspace_without_a_database_reports_none(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        missing = tmp_path / "nothing" / "portal.db"
        monkeypatch.setenv(DB_ENV, str(missing))

        payload = instance.describe()

        assert payload["database"]["exists"] is False
        assert payload["database"]["tables"] == 0
        assert missing.exists() is False, "describing the instance must not create a database"

    def test_the_table_count_is_read_from_the_schema(self, portal_db: Path) -> None:
        payload = instance.describe()

        assert payload["database"]["exists"] is True
        assert payload["database"]["tables"] > 0

    @pytest.mark.parametrize("query_fails", [False, True])
    def test_table_count_closes_connection(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch, query_fails: bool
    ) -> None:
        conn = sqlite3.connect(portal_db)
        if query_fails:
            conn.set_authorizer(lambda *_args: sqlite3.SQLITE_DENY)
        monkeypatch.setattr(instance.sqlite3, "connect", lambda _path: conn)
        try:
            if query_fails:
                with pytest.raises(sqlite3.DatabaseError):
                    instance.describe()
            else:
                assert instance.describe()["database"]["tables"] > 0
            with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
                conn.execute("SELECT 1")
        finally:
            conn.close()


class TestProfiles:
    @pytest.mark.parametrize(
        ("environment", "workspace", "expected"),
        [
            (None, "", profiles.PROFILE_PERSONAL),
            (None, '[deployment]\nprofile = "saas"', profiles.PROFILE_SAAS),
            ("personal", '[deployment]\nprofile = "saas"', profiles.PROFILE_PERSONAL),
            (" SAAS ", "", profiles.PROFILE_SAAS),
            (" ", '[deployment]\nprofile = "saas"', profiles.PROFILE_SAAS),
            ("unknown", '[deployment]\nprofile = "saas"', profiles.PROFILE_PERSONAL),
            (None, '[deployment]\nprofile = "unknown"', profiles.PROFILE_PERSONAL),
            (None, "[deployment]\nprofile = 1", profiles.PROFILE_PERSONAL),
            (None, 'deployment = "saas"', profiles.PROFILE_PERSONAL),
            (None, "[broken", profiles.PROFILE_PERSONAL),
        ],
    )
    def test_resolution(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        environment: str | None,
        workspace: str,
        expected: str,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        if environment is None:
            monkeypatch.delenv(profiles.PROFILE_ENV, raising=False)
        else:
            monkeypatch.setenv(profiles.PROFILE_ENV, environment)
        (tmp_path / "reportal.toml").write_text(workspace)

        assert profiles.current() == expected
        assert profiles.is_saas() is (expected == profiles.PROFILE_SAAS)

    def test_without_workspace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv(profiles.PROFILE_ENV, raising=False)

        assert profiles.current() == profiles.PROFILE_PERSONAL
        assert profiles.is_saas() is False


class TestRoute:
    def test_it_answers_200_with_the_payload(self, portal_db: Path) -> None:
        status, payload = _config()

        assert status.startswith("200")
        assert payload["name"] == "reportal"
        assert payload["version"] == __version__
        assert set(payload) >= {
            "name",
            "version",
            "engine",
            "llm",
            "database",
            "features",
            "limits",
            "mcp",
        }

    def test_it_lists_every_limit_as_an_integer(self, portal_db: Path) -> None:
        _status, payload = _config()

        assert payload["limits"]
        assert all(isinstance(value, int) for value in payload["limits"].values())

    def test_it_writes_nothing(self, portal_db: Path) -> None:
        before = portal_db.stat().st_mtime_ns

        _config()

        assert portal_db.stat().st_mtime_ns == before


class TestCli:
    def test_json_prints_the_payload(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["config", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["name"] == "reportal"
        assert payload["mcp"]["total"] == len(mcp_tools.tools())

    def test_human_output_names_the_version_and_a_feature(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["config"])

        assert result.exit_code == 0
        assert __version__ in result.output
        assert "feature:" in result.output
        assert "limit:" in result.output

    def test_it_needs_no_workspace(self, tmp_path: Path, monkeypatch: Any) -> None:
        """The description is a read of this process, not of a database."""
        monkeypatch.setenv(DB_ENV, str(tmp_path / "absent" / "portal.db"))

        result = runner.invoke(cli.app, ["config", "--json"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["database"]["exists"] is False


class TestMcp:
    def test_the_tool_is_registered_and_read_only(self) -> None:
        tool = mcp_tools.get_tool("get_config")

        assert tool is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.input_schema["properties"] == {}

    def test_the_handler_returns_the_payload(self, portal_db: Path) -> None:
        tool = mcp_tools.get_tool("get_config")
        assert tool is not None

        payload = tool.handler({})

        assert payload["name"] == "reportal"
        assert payload["version"] == __version__
        assert "journal_action" not in payload, "a read never journals"

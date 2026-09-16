"""Tests for the local secret store and the bridge's use of it.

The store's one contract is asserted everywhere it can be: a read returns the
name, scope, length and hint, and never the value.  The value is reachable only
through the internal readers, which the bridge test drives end to end.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import auth, cli, journal, llm, mcp_server, secret_store, store
from reportal._paths import DB_ENV

runner = CliRunner()

API_KEY = "vt-" + "abcdefghijklmnop" * 2


def _send(
    method: str, path: str, *, token: str = "", body: dict[str, Any] | None = None
) -> tuple[str, Any]:
    raw = b"" if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    status, response_headers, payload = wsgi_request(method, path, body=raw, headers=headers)
    return status, json_body(payload, response_headers)


def _api_key(conn: sqlite3.Connection, value: str = API_KEY) -> dict[str, Any]:
    """Store one local secret and return its redacted row."""
    return secret_store.set_secret(conn, name="virustotal.api_key", value=value)


class TestStore:
    def test_the_table_is_created_on_first_use(self, conn: sqlite3.Connection) -> None:
        assert (
            conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (secret_store.TABLE,),
            ).fetchone()
            is None
        )
        _api_key(conn)
        assert (
            conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (secret_store.TABLE,),
            ).fetchone()
            is not None
        )

    def test_a_read_never_carries_the_value(self, conn: sqlite3.Connection) -> None:
        row = _api_key(conn)
        assert API_KEY not in json.dumps(row)
        assert sorted(row) == [
            "created_at",
            "hint",
            "length",
            "name",
            "scope",
            "team_id",
            "updated_at",
        ]

    def test_the_hint_is_the_last_four_and_the_length_the_bytes(
        self, conn: sqlite3.Connection
    ) -> None:
        row = secret_store.set_secret(conn, name="llm.api_key", value="sk-1234567890")
        assert row["hint"] == "7890"
        assert row["length"] == len("sk-1234567890")
        assert row["scope"] == secret_store.SCOPE_LOCAL
        assert row["team_id"] is None

    def test_a_short_value_gets_no_hint(self, conn: sqlite3.Connection) -> None:
        row = secret_store.set_secret(conn, name="llm.api_key", value="abc")
        assert row["hint"] == secret_store.NO_HINT

    def test_a_replace_keeps_the_row_and_moves_the_time(self, conn: sqlite3.Connection) -> None:
        first = _api_key(conn)
        second = _api_key(conn, "vt-" + "zyxwvutsrqponmlk" * 2)
        assert second["created_at"] == first["created_at"]
        assert second["updated_at"] >= first["updated_at"]
        assert len(secret_store.list_secrets(conn)) == 1

    def test_get_and_delete(self, conn: sqlite3.Connection) -> None:
        _api_key(conn)
        found = secret_store.get_secret(conn, name="virustotal.api_key")
        assert found["name"] == "virustotal.api_key"
        removed = secret_store.delete_secret(conn, name="virustotal.api_key")
        assert removed["name"] == "virustotal.api_key"
        assert secret_store.list_secrets(conn) == []
        with pytest.raises(secret_store.UnknownSecretError):
            secret_store.get_secret(conn, name="virustotal.api_key")

    def test_list_filters_by_scope_and_team(self, conn: sqlite3.Connection) -> None:
        _api_key(conn)
        team = auth.create_team(conn, name="blue")
        secret_store.set_secret(
            conn,
            name="virustotal.api_key",
            value="team-key-value-0123",
            scope=secret_store.SCOPE_TEAM,
            team_id=int(team["id"]),
        )
        assert len(secret_store.list_secrets(conn)) == 2
        local = secret_store.list_secrets(conn, scope=secret_store.SCOPE_LOCAL)
        assert [row["scope"] for row in local] == [secret_store.SCOPE_LOCAL]
        scoped = secret_store.list_secrets(
            conn, scope=secret_store.SCOPE_TEAM, team_id=int(team["id"])
        )
        assert [row["team_id"] for row in scoped] == [int(team["id"])]

    def test_a_local_and_a_team_secret_of_one_name_coexist(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="blue")
        _api_key(conn)
        secret_store.set_secret(
            conn,
            name="virustotal.api_key",
            value="team-key-value-0123",
            scope=secret_store.SCOPE_TEAM,
            team_id=int(team["id"]),
        )
        assert len(secret_store.list_secrets(conn)) == 2


class TestValidation:
    def test_a_name_must_be_a_lowercase_dotted_path(self, conn: sqlite3.Connection) -> None:
        for bad in (None, "", "   ", "VirusTotal", "has space", "a" * 65):
            with pytest.raises(secret_store.InvalidSecretError):
                secret_store.set_secret(conn, name=bad, value="x")

    def test_a_value_must_be_a_bounded_non_empty_string(self, conn: sqlite3.Connection) -> None:
        for bad in (None, "", 5):
            with pytest.raises(secret_store.InvalidSecretError):
                secret_store.set_secret(conn, name="llm.api_key", value=bad)
        with pytest.raises(secret_store.InvalidSecretError):
            secret_store.set_secret(
                conn, name="llm.api_key", value="x" * (secret_store.MAX_VALUE_BYTES + 1)
            )

    def test_a_scope_is_local_team_or_implied_by_a_team_id(self, conn: sqlite3.Connection) -> None:
        assert secret_store.normalize_scope(None, None) == (secret_store.SCOPE_LOCAL, 0)
        assert secret_store.normalize_scope(None, 4) == (secret_store.SCOPE_TEAM, 4)
        assert secret_store.normalize_scope("local", 4) == (secret_store.SCOPE_LOCAL, 0)
        for bad in ("workspace", "team", 5):
            with pytest.raises(secret_store.InvalidSecretError):
                secret_store.normalize_scope(bad, None)
        with pytest.raises(secret_store.InvalidSecretError):
            secret_store.normalize_scope(secret_store.SCOPE_TEAM, None)
        with pytest.raises(secret_store.InvalidSecretError):
            secret_store.normalize_scope(secret_store.SCOPE_TEAM, True)

    def test_an_unknown_secret_is_a_lookup_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(secret_store.UnknownSecretError) as excinfo:
            secret_store.get_secret(conn, name="nope.missing")
        assert excinfo.value.code == secret_store.ERROR_NOT_FOUND


class TestInternalReads:
    def test_value_of_returns_the_raw_value(self, conn: sqlite3.Connection) -> None:
        _api_key(conn)
        assert secret_store.value_of(conn, "virustotal.api_key") == API_KEY

    def test_value_of_is_none_for_an_unknown_name(self, conn: sqlite3.Connection) -> None:
        assert secret_store.value_of(conn, "nope.missing") is None

    def test_a_team_value_wins_over_the_local_one(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="blue")
        _api_key(conn)
        secret_store.set_secret(
            conn,
            name="virustotal.api_key",
            value="team-key-value-0123",
            scope=secret_store.SCOPE_TEAM,
            team_id=int(team["id"]),
        )
        assert secret_store.value_of(conn, "virustotal.api_key") == API_KEY
        assert (
            secret_store.value_of(conn, "virustotal.api_key", team_id=int(team["id"]))
            == "team-key-value-0123"
        )
        assert secret_store.value_of(conn, "virustotal.api_key", team_id=999) == API_KEY, (
            "a team with no secret of its own falls back to the workspace one"
        )

    def test_resolve_from_workspace_reads_the_workspace_db(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _api_key(conn)
        assert secret_store.resolve_from_workspace("virustotal.api_key") == API_KEY

    def test_resolve_from_workspace_is_none_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        assert secret_store.resolve_from_workspace("virustotal.api_key") is None

    def test_resolve_from_workspace_is_none_without_a_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(path))
        store.init_db(path)
        with contextlib.closing(store.connect(path)) as fresh:
            fresh.execute("DROP TABLE IF EXISTS secrets")
            fresh.commit()
        assert secret_store.resolve_from_workspace("virustotal.api_key") is None


class TestPermissions:
    def test_an_off_install_may_do_everything(self) -> None:
        assert secret_store.may_read(None, {"scope": secret_store.SCOPE_LOCAL}, team_ids=[])
        assert secret_store.may_write(
            None, team_ids=[], scope=secret_store.SCOPE_LOCAL, team_id=None
        )

    def test_a_local_secret_needs_an_admin_to_write(self) -> None:
        analyst = {"id": 1, "role": auth.ROLE_ANALYST}
        admin = {"id": 2, "role": auth.ROLE_ADMIN}
        assert not secret_store.may_write(
            analyst, team_ids=[], scope=secret_store.SCOPE_LOCAL, team_id=None
        )
        assert secret_store.may_write(
            admin, team_ids=[], scope=secret_store.SCOPE_LOCAL, team_id=None
        )

    def test_a_team_secret_needs_that_team(self) -> None:
        member = {"id": 1, "role": auth.ROLE_ANALYST}
        assert secret_store.may_write(
            member, team_ids=[7], scope=secret_store.SCOPE_TEAM, team_id=7
        )
        assert not secret_store.may_write(
            member, team_ids=[7], scope=secret_store.SCOPE_TEAM, team_id=8
        )
        assert not secret_store.may_write(
            member, team_ids=[], scope=secret_store.SCOPE_TEAM, team_id=None
        )

    def test_a_team_secret_is_only_readable_by_its_team(self) -> None:
        row = {"scope": secret_store.SCOPE_TEAM, "team_id": 7}
        outsider = {"id": 1, "role": auth.ROLE_ANALYST}
        assert secret_store.may_read(outsider, row, team_ids=[7])
        assert not secret_store.may_read(outsider, row, team_ids=[8])
        # A local secret's existence is workspace knowledge; its value never is.
        assert secret_store.may_read(outsider, {"scope": "local"}, team_ids=[])


class TestJournaling:
    def test_a_set_is_journaled_and_reverts(self, conn: sqlite3.Connection) -> None:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            secret_store.journaled_set(
                conn, log, name="llm.api_key", value="sk-first-value", description="stored it"
            )
        assert secret_store.value_of(conn, "llm.api_key") == "sk-first-value"

        rotated = journal.new_action()
        with journal.journaled(conn, rotated) as log:
            secret_store.journaled_set(
                conn, log, name="llm.api_key", value="sk-second-value", description="rotated it"
            )
        assert secret_store.value_of(conn, "llm.api_key") == "sk-second-value"

        assert journal.revert_action(conn, rotated)["reverted"] > 0
        assert secret_store.value_of(conn, "llm.api_key") == "sk-first-value"

        assert journal.revert_action(conn, action)["reverted"] > 0
        assert secret_store.value_of(conn, "llm.api_key") is None

    def test_a_delete_is_journaled_and_reverts(self, conn: sqlite3.Connection) -> None:
        _api_key(conn)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            secret_store.journaled_delete(
                conn, log, name="virustotal.api_key", description="deleted it"
            )
        assert secret_store.value_of(conn, "virustotal.api_key") is None
        assert journal.revert_action(conn, action)["reverted"] > 0
        assert secret_store.value_of(conn, "virustotal.api_key") == API_KEY


class TestBridge:
    def test_the_store_is_the_last_place_the_key_is_looked_for(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_store.set_secret(conn, name=llm.API_KEY_SECRET, value=API_KEY)
        monkeypatch.setenv(llm.ENDPOINT_ENV, "http://127.0.0.1:9/v1")
        monkeypatch.delenv(llm.API_KEY_ENV, raising=False)

        config = llm.LlmConfig.resolve()

        assert config is not None
        assert config.api_key == API_KEY

    def test_an_exported_key_still_wins(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_store.set_secret(conn, name=llm.API_KEY_SECRET, value=API_KEY)
        monkeypatch.setenv(llm.ENDPOINT_ENV, "http://127.0.0.1:9/v1")
        monkeypatch.setenv(llm.API_KEY_ENV, "exported-key")

        config = llm.LlmConfig.resolve()

        assert config is not None
        assert config.api_key == "exported-key"

    def test_no_store_and_no_key_is_still_anonymous(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(llm.ENDPOINT_ENV, "http://127.0.0.1:9/v1")
        monkeypatch.delenv(llm.API_KEY_ENV, raising=False)

        config = llm.LlmConfig.resolve()

        assert config is not None
        assert config.api_key == ""


class TestRoutes:
    def test_the_list_is_redacted(self, conn: sqlite3.Connection) -> None:
        _api_key(conn)
        status, payload = _send("GET", "/api/secrets")
        assert status.startswith("200")
        assert payload["count"] == 1
        assert API_KEY not in json.dumps(payload)
        assert payload["secrets"][0]["hint"] == API_KEY[-4:]

    def test_a_set_then_a_delete(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("PUT", "/api/secrets/virustotal.api_key", body={"value": API_KEY})
        assert status.startswith("200"), payload
        assert payload["name"] == "virustotal.api_key"
        assert payload["journal_action"]
        assert API_KEY not in json.dumps(payload)

        status, payload = _send("GET", "/api/secrets")
        assert payload["count"] == 1

        status, payload = _send("DELETE", "/api/secrets/virustotal.api_key")
        assert status.startswith("200")
        status, payload = _send("GET", "/api/secrets")
        assert payload["count"] == 0

    def test_a_team_scope_needs_a_team(self, conn: sqlite3.Connection) -> None:
        status, payload = _send(
            "PUT",
            "/api/secrets/virustotal.api_key",
            body={"value": API_KEY, "scope": "team", "team_id": 99},
        )
        assert status.startswith("404")
        assert payload["error"] == auth.ERROR_TEAM_NOT_FOUND

    def test_a_team_scope_round_trips(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="blue")
        status, payload = _send(
            "PUT",
            "/api/secrets/virustotal.api_key",
            body={"value": API_KEY, "scope": "team", "team_id": int(team["id"])},
        )
        assert status.startswith("200"), payload
        assert payload["team_id"] == int(team["id"])
        status, payload = _send("GET", f"/api/secrets?scope=team&team_id={team['id']}")
        assert payload["count"] == 1

    def test_an_invalid_name_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("PUT", "/api/secrets/VirusTotal", body={"value": API_KEY})
        assert status.startswith("400")
        assert payload["error"] == secret_store.ERROR_INVALID

    def test_a_blank_value_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("PUT", "/api/secrets/llm.api_key", body={"value": ""})
        assert status.startswith("400")
        assert payload["error"] == secret_store.ERROR_INVALID

    def test_a_missing_value_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("PUT", "/api/secrets/llm.api_key", body={})
        assert status.startswith("400")
        assert payload["error"] == secret_store.ERROR_INVALID
        assert "value" in payload["detail"]

    def test_an_unknown_secret_delete_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("DELETE", "/api/secrets/nope.missing")
        assert status.startswith("404")
        assert payload["error"] == secret_store.ERROR_NOT_FOUND

    def test_a_bad_scope_filter_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("GET", "/api/secrets?scope=workspace")
        assert status.startswith("400")
        assert payload["error"] == secret_store.ERROR_INVALID

    def test_a_bad_team_filter_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("GET", "/api/secrets?team_id=abc")
        assert status.startswith("400")

    def test_a_workspace_secret_needs_an_admin(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        status, payload = _send(
            "PUT", "/api/secrets/llm.api_key", token=token, body={"value": API_KEY}
        )
        assert status.startswith("403")
        assert payload["error"] == secret_store.ERROR_FORBIDDEN

    def test_a_team_secret_is_writable_by_its_member(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        team = auth.create_team(conn, name="blue")
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        auth.add_member(conn, int(team["id"]), int(user["id"]))
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        status, payload = _send(
            "PUT",
            "/api/secrets/virustotal.api_key",
            token=token,
            body={"value": API_KEY, "scope": "team", "team_id": int(team["id"])},
        )
        assert status.startswith("200"), payload

    def test_a_team_secret_is_not_writable_by_an_outsider(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        other = auth.create_team(conn, name="red")
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        auth.add_member(conn, int(other["id"]), int(user["id"]))
        target = auth.create_team(conn, name="blue")
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        status, payload = _send(
            "PUT",
            "/api/secrets/virustotal.api_key",
            token=token,
            body={"value": API_KEY, "scope": "team", "team_id": int(target["id"])},
        )
        assert status.startswith("403")
        assert payload["error"] == secret_store.ERROR_FORBIDDEN

    def test_a_team_secret_is_hidden_from_an_outsider(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        team = auth.create_team(conn, name="blue")
        secret_store.set_secret(
            conn,
            name="virustotal.api_key",
            value=API_KEY,
            scope=secret_store.SCOPE_TEAM,
            team_id=int(team["id"]),
        )
        _, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        status, payload = _send("GET", "/api/secrets", token=token)
        assert status.startswith("200")
        assert payload["count"] == 0


class TestCli:
    def test_a_set_then_a_list_then_a_remove(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        result = runner.invoke(
            cli.app,
            ["secrets-set", "virustotal.api_key", "--stdin", "--json"],
            input=f"{API_KEY}\n",
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["name"] == "virustotal.api_key"
        assert API_KEY not in result.output

        listed = runner.invoke(cli.app, ["secrets-list", "--json"])
        assert listed.exit_code == 0, listed.output
        assert json.loads(listed.output)["count"] == 1

        removed = runner.invoke(cli.app, ["secrets-rm", "virustotal.api_key", "--json"])
        assert removed.exit_code == 0, removed.output
        listed = runner.invoke(cli.app, ["secrets-list", "--json"])
        assert json.loads(listed.output)["count"] == 0

    def test_the_value_can_come_from_stdin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        result = runner.invoke(
            cli.app, ["secrets-set", "llm.api_key", "--stdin", "--json"], input=f"{API_KEY}\n"
        )
        assert result.exit_code == 0, result.output
        with contextlib.closing(store.connect(db)) as conn:
            assert secret_store.value_of(conn, "llm.api_key") == API_KEY

    def test_omitting_stdin_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        result = runner.invoke(cli.app, ["secrets-set", "llm.api_key", "--json"])
        assert result.exit_code == 1
        assert "pass --stdin" in json.loads(result.stdout)["error"]

    def test_a_positional_value_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        result = runner.invoke(
            cli.app,
            ["secrets-set", "llm.api_key", API_KEY, "--stdin", "--json"],
            input=f"{API_KEY}\n",
        )
        assert result.exit_code == 1
        assert "refuse a positional value" in json.loads(result.stdout)["error"]

    def test_the_human_output_lists_the_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        runner.invoke(
            cli.app, ["secrets-set", "virustotal.api_key", "--stdin"], input=f"{API_KEY}\n"
        )
        listed = runner.invoke(cli.app, ["secrets-list"])
        assert listed.exit_code == 0, listed.output
        assert "virustotal.api_key" in listed.output
        empty = runner.invoke(cli.app, ["secrets-rm", "virustotal.api_key"])
        assert empty.exit_code == 0, empty.output
        none = runner.invoke(cli.app, ["secrets-list"])
        assert "No secrets stored." in none.output

    def test_a_team_scope_and_an_unknown_team(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            team = auth.create_team(conn, name="blue")
        stored = runner.invoke(
            cli.app,
            [
                "secrets-set",
                "virustotal.api_key",
                "--stdin",
                "--scope",
                "team",
                "--team-id",
                str(team["id"]),
                "--json",
            ],
            input=f"{API_KEY}\n",
        )
        assert stored.exit_code == 0, stored.output
        missing = runner.invoke(
            cli.app,
            [
                "secrets-set",
                "virustotal.api_key",
                "--stdin",
                "--scope",
                "team",
                "--team-id",
                "999",
            ],
            input=f"{API_KEY}\n",
        )
        assert missing.exit_code == 1
        assert "no team with id 999" in missing.output

    def test_an_invalid_name_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        result = runner.invoke(
            cli.app, ["secrets-set", "VirusTotal", "--stdin"], input=f"{API_KEY}\n"
        )
        assert result.exit_code == 1
        assert "invalid secret" in result.output

    def test_the_commands_fail_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        for argv in (
            ["secrets-list"],
            ["secrets-set", "llm.api_key", "--stdin"],
            ["secrets-rm", "llm.api_key"],
        ):
            result = runner.invoke(cli.app, argv, input="value\n")
            assert result.exit_code == 1, argv
            assert "no reportal database" in result.output


class TestMcp:
    def test_a_set_then_a_list_then_a_delete(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        payload, failed = mcp_server.call_tool(
            "set_secret", {"name": "virustotal.api_key", "value": API_KEY}
        )
        assert not failed, payload
        assert payload["journal_action"]
        assert API_KEY not in json.dumps(payload)

        listed, failed = mcp_server.call_tool("list_secrets", {})
        assert not failed
        assert listed["count"] == 1
        assert API_KEY not in json.dumps(listed)

        removed, failed = mcp_server.call_tool("delete_secret", {"name": "virustotal.api_key"})
        assert not failed
        assert removed["name"] == "virustotal.api_key"

    def test_the_tools_report_their_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        payload, failed = mcp_server.call_tool(
            "set_secret", {"name": "VirusTotal", "value": API_KEY}
        )
        assert failed
        assert payload["error"] == "invalid secret"

        payload, failed = mcp_server.call_tool(
            "set_secret",
            {"name": "virustotal.api_key", "value": API_KEY, "scope": "team", "team_id": 99},
        )
        assert failed
        assert payload["error"] == auth.ERROR_TEAM_NOT_FOUND

        payload, failed = mcp_server.call_tool("delete_secret", {"name": "nope.missing"})
        assert failed
        assert payload["error"] == secret_store.ERROR_NOT_FOUND

        payload, failed = mcp_server.call_tool("list_secrets", {"scope": "workspace"})
        assert failed
        assert payload["error"] == secret_store.ERROR_INVALID

    def test_a_team_scoped_secret_round_trips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            team = auth.create_team(conn, name="blue")
        payload, failed = mcp_server.call_tool(
            "set_secret",
            {
                "name": "virustotal.api_key",
                "value": API_KEY,
                "scope": "team",
                "team_id": int(team["id"]),
            },
        )
        assert not failed, payload
        listed, failed = mcp_server.call_tool("list_secrets", {"team_id": int(team["id"])})
        assert not failed
        assert listed["secrets"][0]["team_id"] == int(team["id"])


def test_the_environment_override_points_at_the_seeded_database(
    conn: sqlite3.Connection,
) -> None:
    """The routes and the CLI read the same database the fixtures seeded."""
    assert os.environ[DB_ENV]

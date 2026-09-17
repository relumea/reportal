"""Tests for the local identity: users, roles, bearer tokens and the auth gate."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import auth, cli, journal, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _send(
    method: str, path: str, *, token: str = "", body: dict[str, Any] | None = None
) -> tuple[str, Any]:
    status, _headers, payload = _send_raw(method, path, token=token, body=body)
    return status, payload


def _send_raw(
    method: str, path: str, *, token: str = "", body: dict[str, Any] | None = None
) -> tuple[str, Any, Any]:
    raw = b"" if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    status, response_headers, payload = wsgi_request(method, path, body=raw, headers=headers)
    return status, response_headers, json_body(payload, response_headers)


class TestStore:
    def test_now_follows_store_now(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(store, "now", lambda: "2026-03-01T00:00:00+00:00")
        assert auth.now() == "2026-03-01T00:00:00+00:00"

    def test_new_token_uses_the_token_urlsafe_seam(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(auth, "_token_urlsafe", lambda _n: "pinned-token-bytes")
        assert auth.new_token() == f"{auth.TOKEN_PREFIX}pinned-token-bytes"

    def test_a_token_is_shown_once_and_only_its_digest_is_stored(
        self, conn: sqlite3.Connection
    ) -> None:
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ADMIN)

        assert token.startswith(auth.TOKEN_PREFIX)
        assert user["has_token"] is True
        stored = conn.execute("SELECT token_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        assert stored is not None
        assert stored["token_hash"] == auth.hash_token(token)
        assert token not in stored["token_hash"]
        assert "token" not in user

    def test_authenticate_accepts_the_token_and_refuses_a_wrong_one(
        self, conn: sqlite3.Connection
    ) -> None:
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        assert user["last_used_at"] == ""

        got = auth.authenticate(conn, token)
        assert got is not None
        assert got["id"] == user["id"]
        assert got["last_used_at"]
        assert auth.authenticate(conn, "reportal_nope") is None
        assert auth.authenticate(conn, "") is None

    def test_a_disabled_user_never_authenticates(self, conn: sqlite3.Connection) -> None:
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)

        auth.update_user(conn, int(user["id"]), disabled=True)

        assert auth.authenticate(conn, token) is None

    def test_rotating_invalidates_the_previous_token(self, conn: sqlite3.Connection) -> None:
        user, first = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)

        second = auth.rotate_token(conn, int(user["id"]))

        assert second is not None and second != first
        assert auth.authenticate(conn, first) is None
        assert auth.authenticate(conn, second) is not None

    def test_a_named_key_authenticates_as_the_user(self, conn: sqlite3.Connection) -> None:
        user, login = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        key, extra = auth.create_api_key(conn, int(user["id"]), "ci")

        assert extra.startswith(auth.TOKEN_PREFIX)
        assert extra != login
        assert "token_hash" not in key
        assert key["last_used_at"] == ""
        assert user["last_used_at"] == ""
        assert auth.authenticate(conn, extra) == user
        assert auth.count_api_keys(conn, int(user["id"])) == 2
        listed = auth.list_api_keys(conn, int(user["id"]))
        assert [row["name"] for row in listed] == ["ci"]
        assert listed[0]["last_used_at"]
        key_stamp = listed[0]["last_used_at"]
        assert auth.get_user(conn, int(user["id"])) == user
        login_hit = auth.authenticate(conn, login)
        assert login_hit is not None
        assert login_hit["last_used_at"]
        assert login_hit["id"] == user["id"]
        assert auth.list_api_keys(conn, int(user["id"]))[0]["last_used_at"] == key_stamp

        auth.rotate_token(conn, int(user["id"]))
        rotated = auth.get_user(conn, int(user["id"]))
        assert rotated is not None
        assert rotated["last_used_at"] == ""
        assert auth.authenticate(conn, extra) == rotated
        assert auth.authenticate(conn, login) is None

        auth.update_user(conn, int(user["id"]), disabled=True)
        assert auth.authenticate(conn, extra) is None

    def test_a_named_key_refuses_a_blank_or_duplicate_name(self, conn: sqlite3.Connection) -> None:
        user, _ = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        auth.create_api_key(conn, int(user["id"]), "ci")
        with pytest.raises(auth.InvalidUserError):
            auth.create_api_key(conn, int(user["id"]), "   ")
        with pytest.raises(auth.InvalidUserError):
            auth.create_api_key(conn, int(user["id"]), "CI")

    def test_a_duplicate_name_is_refused_case_insensitively(self, conn: sqlite3.Connection) -> None:
        auth.add_user(conn, name="Ana", role=auth.ROLE_ANALYST)

        with pytest.raises(auth.UserExistsError):
            auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)

    def test_a_blank_name_and_an_unknown_role_are_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(auth.InvalidUserError):
            auth.add_user(conn, name="   ")
        with pytest.raises(auth.InvalidUserError):
            auth.add_user(conn, name="ana", role="root")

    def test_a_name_with_a_control_character_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(auth.InvalidUserError, match="control characters"):
            auth.add_user(conn, name="ana\nadmin", role=auth.ROLE_ANALYST)
        with pytest.raises(auth.InvalidTeamError, match="control characters"):
            auth.create_team(conn, name="ops\rroot")
        with pytest.raises(auth.InvalidUserError, match="control characters"):
            auth.create_organisation(conn, name="corp\x00inc")
        with pytest.raises(auth.InvalidUserError, match="control characters"):
            auth.add_user(conn, name="ana\u200badmin", role=auth.ROLE_ANALYST)

    def test_nfd_and_nfc_user_names_collapse(self, conn: sqlite3.Connection) -> None:
        nfc = "Jos\u00e9"
        nfd = "Jose\u0301"
        assert nfc != nfd
        user, _token = auth.add_user(conn, name=nfd, role=auth.ROLE_ANALYST)
        assert user["name"] == nfc
        assert auth.find_user(conn, nfd) is not None
        assert auth.find_user(conn, nfc) is not None
        with pytest.raises(auth.UserExistsError):
            auth.add_user(conn, name=nfc, role=auth.ROLE_ANALYST)

    def test_unknown_ids_change_nothing(self, conn: sqlite3.Connection) -> None:
        assert auth.update_user(conn, 4242, role=auth.ROLE_ADMIN) is None
        assert auth.rotate_token(conn, 4242) is None
        assert auth.delete_user(conn, 4242) is False

    def test_the_role_permission_sets_are_the_documented_ones(self) -> None:
        assert auth.permissions_for(auth.ROLE_VIEWER) == ("read",)
        assert auth.permissions_for(auth.ROLE_ANALYST) == ("read", "write")
        assert auth.permissions_for(auth.ROLE_ADMIN) == ("read", "write", "admin")
        assert auth.permissions_for("root") == ()

    def test_the_required_permission_follows_the_method_and_the_path(self) -> None:
        assert auth.required_permission("GET", "/api/binaries") == "read"
        assert auth.required_permission("POST", "/api/binaries") == "write"
        assert auth.required_permission("GET", "/api/users") == "admin"
        assert auth.required_permission("DELETE", "/api/users/3") == "admin"
        assert auth.required_permission("GET", "/api/iam/me") == "read"
        assert auth.required_permission("GET", "/mcp") == "write"
        assert auth.required_permission("POST", "/mcp") == "write"

    def test_token_of_reads_only_a_bearer_header(self) -> None:
        assert auth.token_of("Bearer reportal_abc") == "reportal_abc"
        assert auth.token_of("bearer reportal_abc") == "reportal_abc"
        assert auth.token_of("Basic reportal_abc") == ""
        assert auth.token_of(None) == ""

    def test_required_follows_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(auth.REQUIRED_ENV, raising=False)
        assert auth.required() is False

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        assert auth.required() is True

    def test_required_follows_the_workspace_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(auth.REQUIRED_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("[auth]\nrequired = true\n")
        monkeypatch.chdir(tmp_path)

        assert auth.required() is True

    def test_an_unreadable_workspace_config_logs_before_falling_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.delenv(auth.REQUIRED_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("this is not [toml\n")
        monkeypatch.chdir(tmp_path)

        with caplog.at_level("WARNING", logger="reportal.auth"):
            assert auth.required() is False

        assert any("auth.required falls back to off" in record.message for record in caplog.records)


class TestApiGate:
    @pytest.fixture(autouse=True)
    def _reset_write_limiter(self) -> None:
        auth._write_states.clear()

    def test_auth_off_leaves_the_api_open_and_says_so(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("GET", "/api/iam/me")

        assert status.startswith("200")
        assert payload["auth"] == "open"
        assert payload["user"] is None
        assert payload["permissions"] == ["read", "write", "admin"]

    def test_a_request_without_a_token_is_401(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        auth.add_user(conn, name="ana", role=auth.ROLE_ADMIN)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send("GET", "/api/binaries")

        assert status.startswith("401")
        assert payload["error"] == "unauthorized"
        assert payload["detail"] == auth.UNAUTHORIZED_DETAIL

    def test_an_unknown_token_is_401(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        auth.add_user(conn, name="ana", role=auth.ROLE_ADMIN)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send("GET", "/api/iam/me", token="reportal_wrong")

        assert status.startswith("401")
        assert payload["error"] == "unauthorized"

    def test_me_reports_the_authenticated_user(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send("GET", "/api/iam/me", token=token)

        assert status.startswith("200")
        assert payload["auth"] == "required"
        assert payload["user"]["name"] == "ana"
        assert payload["user"]["last_used_at"]
        assert payload["role"] == auth.ROLE_ANALYST
        assert payload["permissions"] == ["read", "write"]

        _, permissions = _send("GET", "/api/iam/me/permissions", token=token)
        assert permissions["role"] == auth.ROLE_ANALYST
        assert permissions["permissions"] == ["read", "write"]
        assert permissions["roles"] == list(auth.ROLES)

    def test_named_keys_mint_authenticate_and_revoke(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        minted, payload = _send("POST", "/api/iam/keys", token=token, body={"name": "ci"})
        assert minted.startswith("201")
        extra = str(payload["token"])
        assert extra.startswith(auth.TOKEN_PREFIX)
        assert payload["last_used_at"] == ""
        listed, keys = _send("GET", "/api/iam/keys", token=token)
        assert listed.startswith("200")
        assert keys["count"] == 1
        assert keys["used"] == 2
        assert "token" not in keys["keys"][0]
        assert keys["keys"][0]["last_used_at"] == ""

        me, who = _send("GET", "/api/iam/me", token=extra)
        assert me.startswith("200")
        assert who["user"]["name"] == "ana"
        stamped, after = _send("GET", "/api/iam/keys", token=token)
        assert stamped.startswith("200")
        assert after["keys"][0]["last_used_at"]

        revoked, gone = _send("DELETE", f"/api/iam/keys/{payload['id']}", token=token)
        assert revoked.startswith("200")
        assert gone["deleted"] is True
        status, missing = _send("GET", "/api/iam/me", token=extra)
        assert status.startswith("401")
        assert missing["error"] == auth.ERROR_UNAUTHORIZED

    def test_a_viewer_may_read_but_not_write(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, token = auth.add_user(conn, name="vic", role=auth.ROLE_VIEWER)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        read_status, _ = _send("GET", "/api/binaries", token=token)
        write_status, payload = _send(
            "POST", "/api/binaries", token=token, body={"sha256": "a" * 64, "name": "x"}
        )

        assert read_status.startswith("200")
        assert write_status.startswith("403")
        assert payload["error"] == "forbidden"
        mcp_status, mcp_payload = _send("POST", "/mcp", token=token, body={"jsonrpc": "2.0"})
        assert mcp_status.startswith("403")
        assert mcp_payload["error"] == "forbidden"

    def test_http_writes_are_capped_per_user(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        monkeypatch.setattr(auth, "WRITE_MAX_HITS", 3)
        auth._write_states.clear()

        statuses = [
            _send("POST", "/api/users/feedback", token=token, body={"message": f"n{i}"})[0]
            for i in range(3)
        ]
        assert all(status.startswith("201") for status in statuses)
        limited, headers, payload = _send_raw(
            "POST", "/api/users/feedback", token=token, body={"message": "late"}
        )
        assert limited.startswith("429")
        assert payload["error"] == auth.ERROR_RATE_LIMITED
        wait = int(headers["Retry-After"])
        assert 1 <= wait <= int(auth.WRITE_WINDOW_S)
        listed, payload = _send("GET", "/api/users/feedback", token=token)
        assert listed.startswith("200")
        assert payload["count"] == 3

    def test_retry_after_seconds_rounds_up_and_never_zero(self) -> None:
        assert auth.retry_after_seconds([], 60.0, 0.0) == 60
        assert auth.retry_after_seconds([10.0], 60.0, 10.5) == 60
        assert auth.retry_after_seconds([10.0], 60.0, 70.0) == 1

    def test_mcp_without_a_token_is_401(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        auth.add_user(conn, name="ana", role=auth.ROLE_ADMIN)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send("POST", "/mcp")

        assert status.startswith("401")
        assert payload["error"] == "unauthorized"

    def test_only_an_admin_reaches_the_user_table(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, analyst = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        _, admin = auth.add_user(conn, name="ada", role=auth.ROLE_ADMIN)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        analyst_status, _ = _send("GET", "/api/users", token=analyst)
        admin_status, payload = _send("GET", "/api/users", token=admin)

        assert analyst_status.startswith("403")
        assert admin_status.startswith("200")
        assert [user["name"] for user in payload["users"]] == ["ana", "ada"]
        assert all("token_hash" not in user for user in payload["users"])

    def test_a_disabled_user_is_refused_at_the_gate(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ADMIN)
        auth.update_user(conn, int(user["id"]), disabled=True)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send("GET", "/api/binaries", token=token)

        assert status.startswith("401")
        assert payload["error"] == "unauthorized"


class TestUserRoutes:
    def test_create_returns_the_token_once_and_reverts(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("POST", "/api/users", body={"name": "ana", "role": "admin"})

        assert status.startswith("201")
        assert payload["name"] == "ana"
        assert payload["role"] == auth.ROLE_ADMIN
        assert payload["token"].startswith(auth.TOKEN_PREFIX)
        assert auth.authenticate(conn, payload["token"]) is not None

        journal.revert_action(conn, payload["journal_action"])

        assert auth.count_users(conn) == 0

    def test_a_duplicate_name_is_409(self, conn: sqlite3.Connection) -> None:
        _send("POST", "/api/users", body={"name": "ana"})

        status, payload = _send("POST", "/api/users", body={"name": "ana"})

        assert status.startswith("409")
        assert payload["error"] == auth.ERROR_USER_EXISTS

    def test_a_blank_name_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("POST", "/api/users", body={"name": "  "})

        assert status.startswith("400")
        assert "name" in payload["error"]

    def test_an_unknown_role_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("POST", "/api/users", body={"name": "ana", "role": "root"})

        assert status.startswith("400")
        assert payload["error"] == auth.ERROR_INVALID_USER
        assert "unknown role" in payload["detail"]

    def test_update_sets_the_role_and_reverts(self, conn: sqlite3.Connection) -> None:
        _, created = _send("POST", "/api/users", body={"name": "ana"})

        status, payload = _send(
            "PATCH", f"/api/users/{created['id']}", body={"role": "admin", "disabled": True}
        )

        assert status.startswith("200")
        assert payload["role"] == auth.ROLE_ADMIN
        assert payload["disabled"] is True

        journal.revert_action(conn, payload["journal_action"])

        restored = auth.get_user(conn, int(created["id"]))
        assert restored is not None
        assert restored["role"] == auth.ROLE_ANALYST
        assert restored["disabled"] is False

    def test_update_with_neither_field_is_400(self, conn: sqlite3.Connection) -> None:
        _, created = _send("POST", "/api/users", body={"name": "ana"})

        status, payload = _send("PATCH", f"/api/users/{created['id']}", body={})

        assert status.startswith("400")
        assert payload["error"] == auth.ERROR_INVALID_USER

    def test_rotate_replaces_the_token_and_reverts(self, conn: sqlite3.Connection) -> None:
        _, created = _send("POST", "/api/users", body={"name": "ana"})

        status, payload = _send("POST", f"/api/users/{created['id']}/token")

        assert status.startswith("200")
        assert auth.authenticate(conn, created["token"]) is None
        assert auth.authenticate(conn, payload["token"]) is not None

        journal.revert_action(conn, payload["journal_action"])

        assert auth.authenticate(conn, created["token"]) is not None

    def test_delete_removes_the_user_and_reverts(self, conn: sqlite3.Connection) -> None:
        _, created = _send("POST", "/api/users", body={"name": "ana"})

        status, payload = _send("DELETE", f"/api/users/{created['id']}")

        assert status.startswith("200")
        assert auth.get_user(conn, int(created["id"])) is None

        journal.revert_action(conn, payload["journal_action"])

        assert auth.get_user(conn, int(created["id"])) is not None

    def test_the_user_routes_404_on_an_unknown_id(self, conn: sqlite3.Connection) -> None:
        assert _send("PATCH", "/api/users/4242", body={"role": "admin"})[0].startswith("404")
        assert _send("POST", "/api/users/4242/token")[0].startswith("404")
        assert _send("DELETE", "/api/users/4242")[0].startswith("404")


class TestCli:
    def _portal(self, tmp_path: Path, monkeypatch: Any) -> Path:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        return db

    def test_user_add_prints_the_token_once(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["user-add", "ana", "--role", "admin", "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["role"] == "admin"
        assert payload["token"].startswith(auth.TOKEN_PREFIX)
        with contextlib.closing(store.connect(db)) as conn:
            assert auth.authenticate(conn, payload["token"]) is not None

        human = runner.invoke(cli.app, ["user-add", "bob"])
        assert human.exit_code == 0
        assert "only time the token is shown" in human.output

    def test_users_lists_them_and_says_auth_is_off(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            auth.add_user(conn, name="ana", role=auth.ROLE_ADMIN)

        result = runner.invoke(cli.app, ["users", "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["auth_required"] is False
        assert payload["users"][0]["name"] == "ana"

        human = runner.invoke(cli.app, ["users"])
        assert human.exit_code == 0
        assert "Token auth is off" in human.output

    def test_api_keys_mint_list_and_revoke(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            user, _ = auth.add_user(conn, name="ana")

        minted = runner.invoke(cli.app, ["api-key-add", str(user["id"]), "--name", "ci", "--json"])
        assert minted.exit_code == 0, minted.output
        payload = json.loads(minted.stdout)
        assert payload["name"] == "ci"
        assert payload["token"].startswith(auth.TOKEN_PREFIX)
        with contextlib.closing(store.connect(db)) as conn:
            assert auth.authenticate(conn, payload["token"]) is not None

        listed = runner.invoke(cli.app, ["api-keys", str(user["id"]), "--json"])
        assert listed.exit_code == 0, listed.output
        keys = json.loads(listed.stdout)
        assert keys["count"] == 1
        assert keys["used"] == 2
        assert "token" not in keys["keys"][0]

        revoked = runner.invoke(cli.app, ["api-key-rm", str(payload["id"]), "--json"])
        assert revoked.exit_code == 0, revoked.output
        assert json.loads(revoked.stdout)["deleted"] is True
        with contextlib.closing(store.connect(db)) as conn:
            assert auth.authenticate(conn, payload["token"]) is None

    def test_the_commands_refuse_an_unknown_user(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._portal(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["user-token", "4242"]).exit_code == 1
        assert runner.invoke(cli.app, ["user-edit", "4242", "--role", "admin"]).exit_code == 1
        assert runner.invoke(cli.app, ["user-rm", "4242", "--yes"]).exit_code == 1
        assert runner.invoke(cli.app, ["api-keys", "4242"]).exit_code == 1
        assert runner.invoke(cli.app, ["api-key-add", "4242", "--name", "ci"]).exit_code == 1
        assert runner.invoke(cli.app, ["api-key-rm", "4242"]).exit_code == 1

    def test_user_edit_sets_the_role_and_disables(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            user, token = auth.add_user(conn, name="ana")

        changed = runner.invoke(
            cli.app, ["user-edit", str(user["id"]), "--role", "admin", "--json"]
        )
        assert changed.exit_code == 0, changed.output
        assert json.loads(changed.stdout)["role"] == "admin"

        disabled = runner.invoke(cli.app, ["user-edit", str(user["id"]), "--disable"])
        assert disabled.exit_code == 0
        with contextlib.closing(store.connect(db)) as conn:
            assert auth.authenticate(conn, token) is None

    def test_user_edit_sets_and_clears_the_active_team(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            user, _token = auth.add_user(conn, name="ana")
            team = auth.create_team(conn, name="blue")
            auth.add_member(conn, int(team["id"]), int(user["id"]))

        switched = runner.invoke(
            cli.app, ["user-edit", str(user["id"]), "--active-team", str(team["id"]), "--json"]
        )
        assert switched.exit_code == 0, switched.output
        assert json.loads(switched.stdout)["active_team_id"] == int(team["id"])

        cleared = runner.invoke(
            cli.app, ["user-edit", str(user["id"]), "--clear-active-team", "--json"]
        )
        assert cleared.exit_code == 0, cleared.output
        assert json.loads(cleared.stdout)["active_team_id"] is None

    def test_user_edit_refuses_a_team_the_user_is_not_in(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            user, _token = auth.add_user(conn, name="ana")
            team = auth.create_team(conn, name="blue")

        result = runner.invoke(
            cli.app, ["user-edit", str(user["id"]), "--active-team", str(team["id"])]
        )

        assert result.exit_code == 1
        assert "not-a-team-member" in result.output

    def test_user_edit_refuses_two_active_team_flags(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            user, _token = auth.add_user(conn, name="ana")

        result = runner.invoke(
            cli.app,
            ["user-edit", str(user["id"]), "--active-team", "1", "--clear-active-team"],
        )

        assert result.exit_code == 1
        assert "mutually exclusive" in result.output

    def test_user_token_rotates(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            user, first = auth.add_user(conn, name="ana")

        result = runner.invoke(cli.app, ["user-token", str(user["id"]), "--json"])

        assert result.exit_code == 0, result.output
        rotated = json.loads(result.stdout)["token"]
        assert rotated != first
        with contextlib.closing(store.connect(db)) as conn:
            assert auth.authenticate(conn, first) is None
            assert auth.authenticate(conn, rotated) is not None

    def test_user_rm_needs_yes(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            user, _ = auth.add_user(conn, name="ana")

        aborted = runner.invoke(cli.app, ["user-rm", str(user["id"])], input="n\n")
        assert aborted.exit_code == 1
        with contextlib.closing(store.connect(db)) as conn:
            assert auth.get_user(conn, int(user["id"])) is not None

        removed = runner.invoke(cli.app, ["user-rm", str(user["id"]), "--yes", "--json"])
        assert removed.exit_code == 0, removed.output
        with contextlib.closing(store.connect(db)) as conn:
            assert auth.get_user(conn, int(user["id"])) is None


class TestRemoteBindGuard:
    def test_a_remote_bind_without_auth_is_refused(self, tmp_path: Path, monkeypatch: Any) -> None:
        monkeypatch.delenv(auth.REQUIRED_ENV, raising=False)
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)

        result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0", "--no-open"])

        assert result.exit_code == 1
        assert "refusing to bind beyond loopback" in result.output
        assert auth.REQUIRED_ENV in result.output

    def test_a_remote_bind_with_auth_but_no_user_is_refused(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)

        result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0", "--no-open"])

        assert result.exit_code == 1
        assert "no user token exists" in result.output

    def test_a_disabled_user_does_not_count_as_a_token(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            user, _ = auth.add_user(conn, name="ana")
            auth.update_user(conn, int(user["id"]), disabled=True)

        result = runner.invoke(cli.app, ["serve", "--host", "0.0.0.0", "--no-open"])

        assert result.exit_code == 1
        assert "no user token exists" in result.output


class TestAttribution:
    def test_rename_records_server_identity_not_body_actor(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        other, _ = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="t")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=1, name="f")

        status, payload = _send(
            "POST",
            f"/api/functions/{function_id}/rename",
            token=token,
            body={"name": "g", "actor": "bob"},
        )

        assert status.startswith("200")
        history = store.list_name_history(conn, function_id)
        ana_row = auth.find_user(conn, "ana")
        assert ana_row is not None
        assert history[0]["actor"] == "ana"
        assert history[0]["actor_user_id"] == ana_row["id"]
        assert payload["journal_action"]
        entries = journal.list_entries(conn, action=payload["journal_action"])
        assert entries[0]["actor"] == "ana"
        assert entries[0]["actor_user_id"] == ana_row["id"]
        bob_row = auth.find_user(conn, "bob")
        assert bob_row is not None
        assert bob_row["id"] == int(other["id"])

    def test_rename_without_auth_keeps_body_actor(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="cd" * 32, name="b.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="t")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=1, name="f")

        status, _ = _send(
            "POST", f"/api/functions/{function_id}/rename", body={"name": "g", "actor": "cli-x"}
        )

        assert status.startswith("200")
        assert store.list_name_history(conn, function_id)[0]["actor"] == "cli-x"

    def test_comment_carries_caller_identity(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        binary_id = store.add_binary(conn, sha256="ef" * 32, name="b.exe")

        status, payload = _send(
            "POST",
            f"/api/binaries/{binary_id}/comments",
            token=token,
            body={"body": "hi", "author": "mallory"},
        )

        assert status.startswith("201")
        assert payload["author"] == "ana"
        assert payload["author_user_id"] == int(user["id"])


class TestRevertOwnership:
    def test_analyst_cannot_revert_another_action(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        _, bob = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        _, admin = auth.add_user(conn, name="ada", role=auth.ROLE_ADMIN)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="t")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=1, name="f")

        _, renamed = _send(
            "POST", f"/api/functions/{function_id}/rename", token=ana, body={"name": "g"}
        )
        action = renamed["journal_action"]

        forbidden, payload = _send(
            "POST", "/api/journal/revert", token=bob, body={"action": action}
        )
        assert forbidden.startswith("403")
        assert payload["error"] == "forbidden"

        ok, _ = _send("POST", "/api/journal/revert", token=admin, body={"action": action})
        assert ok.startswith("200")
        function = store.get_function(conn, function_id)
        assert function is not None
        assert function["name"] == "f"

    def test_analyst_reverts_own_action(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="t")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=1, name="f")

        _, renamed = _send(
            "POST", f"/api/functions/{function_id}/rename", token=ana, body={"name": "g"}
        )
        status, _ = _send(
            "POST", "/api/journal/revert", token=ana, body={"action": renamed["journal_action"]}
        )

        assert status.startswith("200")

    def test_comment_owner_guard(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        _, bob = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="b.exe")

        _, created = _send(
            "POST", f"/api/binaries/{binary_id}/comments", token=ana, body={"body": "mine"}
        )
        comment_id = int(created["id"])

        forbidden, _ = _send(
            "PATCH", f"/api/comments/{comment_id}", token=bob, body={"body": "theirs"}
        )
        assert forbidden.startswith("403")

        ok, updated = _send(
            "PATCH", f"/api/comments/{comment_id}", token=ana, body={"body": "edited"}
        )
        assert ok.startswith("200")
        assert updated["body"] == "edited"

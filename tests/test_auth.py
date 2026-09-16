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
    raw = b"" if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    status, response_headers, payload = wsgi_request(method, path, body=raw, headers=headers)
    return status, json_body(payload, response_headers)


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

        assert auth.authenticate(conn, token) == user
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

    def test_a_duplicate_name_is_refused_case_insensitively(self, conn: sqlite3.Connection) -> None:
        auth.add_user(conn, name="Ana", role=auth.ROLE_ANALYST)

        with pytest.raises(auth.UserExistsError):
            auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)

    def test_a_blank_name_and_an_unknown_role_are_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(auth.InvalidUserError):
            auth.add_user(conn, name="   ")
        with pytest.raises(auth.InvalidUserError):
            auth.add_user(conn, name="ana", role="root")

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
        assert payload["role"] == auth.ROLE_ANALYST
        assert payload["permissions"] == ["read", "write"]

        _, permissions = _send("GET", "/api/iam/me/permissions", token=token)
        assert permissions["role"] == auth.ROLE_ANALYST
        assert permissions["permissions"] == ["read", "write"]
        assert permissions["roles"] == list(auth.ROLES)

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

    def test_the_commands_refuse_an_unknown_user(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._portal(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["user-token", "4242"]).exit_code == 1
        assert runner.invoke(cli.app, ["user-edit", "4242", "--role", "admin"]).exit_code == 1
        assert runner.invoke(cli.app, ["user-rm", "4242", "--yes"]).exit_code == 1

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

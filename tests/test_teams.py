"""Tests for teams, object visibility and the scope the API gate enforces."""

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
    method: str,
    path: str,
    *,
    token: str = "",
    body: dict[str, Any] | None = None,
) -> tuple[str, Any]:
    raw = b"" if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    status, response_headers, payload = wsgi_request(method, path, body=raw, headers=headers)
    return status, json_body(payload, response_headers)


def _member(conn: sqlite3.Connection, name: str, role: str = auth.ROLE_ANALYST) -> str:
    _, token = auth.add_user(conn, name=name, role=role)
    return token


class TestTeamStore:
    def test_create_list_and_find(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="Blue", description="Windows work")

        assert team["name"] == "Blue"
        assert team["description"] == "Windows work"
        assert [row["name"] for row in auth.list_teams(conn)] == ["Blue"]
        assert auth.list_teams(conn)[0]["member_count"] == 0
        assert auth.find_team(conn, "blue") is not None

    def test_a_duplicate_or_blank_name_is_refused(self, conn: sqlite3.Connection) -> None:
        auth.create_team(conn, name="Blue")

        with pytest.raises(auth.TeamExistsError):
            auth.create_team(conn, name="blue")
        with pytest.raises(auth.InvalidTeamError):
            auth.create_team(conn, name="   ")

    def test_update_and_delete(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="Blue")
        team_id = int(team["id"])

        renamed = auth.update_team(conn, team_id, name="Cyan", description="still blue")

        assert renamed is not None
        assert renamed["name"] == "Cyan"
        assert auth.update_team(conn, 4242, name="Nope") is None
        assert auth.delete_team(conn, team_id) is True
        assert auth.get_team(conn, team_id) is None
        assert auth.delete_team(conn, team_id) is False

    def test_membership_add_remove_and_teams_of_user(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="Blue")
        team_id = int(team["id"])
        user, _ = auth.add_user(conn, name="ana")

        assert auth.add_member(conn, team_id, int(user["id"])) is True
        assert auth.add_member(conn, team_id, int(user["id"])) is False, "already a member"
        assert auth.add_member(conn, 4242, int(user["id"])) is False, "unknown team"
        assert auth.add_member(conn, team_id, 4242) is False, "unknown user"
        assert [row["name"] for row in auth.teams_of_user(conn, int(user["id"]))] == ["Blue"]
        assert auth.get_team(conn, team_id)["member_count"] == 1  # type: ignore[index]

        assert auth.remove_member(conn, team_id, int(user["id"])) is True
        assert auth.remove_member(conn, team_id, int(user["id"])) is False

    def test_deleting_a_team_returns_its_objects_to_the_workspace(
        self, conn: sqlite3.Connection
    ) -> None:
        team = auth.create_team(conn, name="Blue")
        team_id = int(team["id"])
        binary_id = store.add_binary(conn, sha256="a" * 64, name="demo.exe")
        store.set_binary_scope(conn, binary_id, owner_team_id=team_id, visibility="team")

        auth.delete_team(conn, team_id)

        binary = store.get_binary(conn, binary_id)
        assert binary is not None
        assert binary["owner_team_id"] is None
        assert binary["visibility"] == "public"

    def test_scope_of_validates_the_request(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="Blue")

        assert auth.scope_of(conn, team_id=int(team["id"]), visibility="team") == (
            int(team["id"]),
            "team",
        )
        assert auth.scope_of(conn, team_id=int(team["id"]), visibility="public") == (None, "public")
        with pytest.raises(auth.UnknownTeamError):
            auth.scope_of(conn, team_id=4242, visibility="team")
        with pytest.raises(auth.InvalidTeamError):
            auth.scope_of(conn, team_id=None, visibility="team")
        with pytest.raises(auth.InvalidTeamError):
            auth.scope_of(conn, team_id=None, visibility="secret")

    def test_may_write_follows_membership(self, conn: sqlite3.Connection) -> None:
        team = auth.create_team(conn, name="Blue")
        team_id = int(team["id"])
        ana, _ = auth.add_user(conn, name="ana")
        bob, _ = auth.add_user(conn, name="bob")
        auth.add_member(conn, team_id, int(ana["id"]))
        scoped = {"visibility": "team", "owner_team_id": team_id}
        public = {"visibility": "public", "owner_team_id": None}

        assert auth.may_write(None, scoped, team_ids=[]) is True, "auth off is the operator"
        assert auth.may_write(ana, scoped, team_ids=[team_id]) is True
        assert auth.may_write(bob, scoped, team_ids=[]) is False
        assert auth.may_write(bob, public, team_ids=[]) is True
        assert auth.may_write({"id": 3, "role": auth.ROLE_ADMIN}, scoped, team_ids=[]) is True


class TestScopeGate:
    def _scoped(self, conn: sqlite3.Connection) -> dict[str, Any]:
        """Ana and Bob, a team Ana is in, and a binary that team owns."""
        ana = _member(conn, "ana")
        bob = _member(conn, "bob")
        team = auth.create_team(conn, name="Blue")
        team_id = int(team["id"])
        ana_user = auth.find_user(conn, "ana")
        assert ana_user is not None
        auth.add_member(conn, team_id, int(ana_user["id"]))
        binary_id = store.add_binary(conn, sha256="b" * 64, name="team.exe")
        store.set_binary_scope(conn, binary_id, owner_team_id=team_id, visibility="team")
        public_id = store.add_binary(conn, sha256="c" * 64, name="public.exe")
        return {
            "ana": ana,
            "bob": bob,
            "team": team_id,
            "binary": binary_id,
            "public": public_id,
        }

    def test_a_member_reaches_the_object_and_an_outsider_gets_404(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._scoped(conn)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        member = _send("GET", f"/api/binaries/{ids['binary']}", token=ids["ana"])
        outsider = _send("GET", f"/api/binaries/{ids['binary']}", token=ids["bob"])

        assert member[0].startswith("200")
        assert outsider[0].startswith("404")
        assert outsider[1]["error"] == "binary not found"

    def test_an_outsider_may_write_a_public_object_and_not_a_scoped_one(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._scoped(conn)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        allowed = _send("PATCH", f"/api/binaries/{ids['public']}/scope", token=ids["bob"], body={})
        refused = _send("PATCH", f"/api/binaries/{ids['binary']}/scope", token=ids["bob"], body={})

        assert allowed[0].startswith("200"), "a public object is any writer's to scope"
        assert refused[0].startswith("403")
        assert refused[1]["error"] == auth.ERROR_SCOPE_FORBIDDEN

    def test_the_lists_and_the_search_hide_a_scoped_object(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._scoped(conn)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        member_list = _send("GET", "/api/binaries", token=ids["ana"])
        outsider_list = _send("GET", "/api/binaries", token=ids["bob"])
        outsider_search = _send("GET", "/api/search?q=team", token=ids["bob"])

        assert {row["name"] for row in member_list[1]["binaries"]} == {"team.exe", "public.exe"}
        assert {row["name"] for row in outsider_list[1]["binaries"]} == {"public.exe"}
        assert outsider_search[1]["binaries"] == []

    def test_an_admin_sees_everything(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._scoped(conn)
        admin = _member(conn, "ada", auth.ROLE_ADMIN)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send("GET", f"/api/binaries/{ids['binary']}", token=admin)

        assert status.startswith("200")
        assert payload["name"] == "team.exe"

    def test_a_function_of_a_scoped_binary_is_refused_too(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._scoped(conn)
        analysis_id = store.ensure_analysis_for_binary(conn, ids["binary"], engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=8
        )
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        member = _send("GET", f"/api/functions/{function_id}", token=ids["ana"])
        outsider = _send("GET", f"/api/functions/{function_id}", token=ids["bob"])

        assert member[0].startswith("200")
        assert outsider[0].startswith("404")
        assert outsider[1]["error"] == "function not found"

    def test_a_bulk_action_skips_what_the_caller_cannot_reach(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._scoped(conn)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send(
            "POST",
            "/api/binaries/bulk",
            token=ids["ana"],
            body={"action": "add_tag", "binary_ids": [ids["binary"], ids["public"]], "tag": "x"},
        )

        assert status.startswith("200")
        assert payload["applied"] == 2, "a member reaches its team's binary"

        _, outsider = _send(
            "POST",
            "/api/binaries/bulk",
            token=ids["bob"],
            body={"action": "delete", "binary_ids": [ids["binary"]]},
        )

        assert outsider["applied"] == 0
        assert outsider["skipped"] == [{"id": ids["binary"], "reason": "not permitted"}]
        assert store.get_binary(conn, ids["binary"]) is not None

    def test_adding_a_scoped_binary_to_a_public_collection_is_refused(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._scoped(conn)
        collection_id = store.create_collection(conn, name="shared", description="")
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _send(
            "POST",
            f"/api/collections/{collection_id}/binaries",
            token=ids["bob"],
            body={"binary_id": ids["binary"]},
        )

        assert status.startswith("403")
        assert payload["error"] == auth.ERROR_SCOPE_FORBIDDEN

    def test_auth_off_leaves_every_scope_open(self, conn: sqlite3.Connection) -> None:
        ids = self._scoped(conn)

        status, payload = _send("GET", f"/api/binaries/{ids['binary']}")

        assert status.startswith("200")
        assert payload["name"] == "team.exe"


class TestTeamRoutes:
    def test_create_list_update_delete_and_revert(self, conn: sqlite3.Connection) -> None:
        status, created = _send("POST", "/api/teams", body={"name": "Blue"})

        assert status.startswith("201")
        assert created["name"] == "Blue"
        assert created["journal_action"]

        listed = _send("GET", "/api/teams")
        assert listed[1]["count"] == 1

        updated = _send("PATCH", f"/api/teams/{created['id']}", body={"description": "win"})
        assert updated[1]["description"] == "win"

        deleted = _send("DELETE", f"/api/teams/{created['id']}")
        assert deleted[0].startswith("200")
        assert _send("GET", f"/api/teams/{created['id']}")[0].startswith("404")

        journal.revert_action(conn, deleted[1]["journal_action"])
        assert auth.get_team(conn, int(created["id"])) is not None

    def test_a_duplicate_name_is_409(self, conn: sqlite3.Connection) -> None:
        _send("POST", "/api/teams", body={"name": "Blue"})

        status, payload = _send("POST", "/api/teams", body={"name": "blue"})

        assert status.startswith("409")
        assert payload["error"] == auth.ERROR_TEAM_EXISTS

    def test_membership_routes(self, conn: sqlite3.Connection) -> None:
        _, created = _send("POST", "/api/teams", body={"name": "Blue"})
        _, user = _send("POST", "/api/users", body={"name": "ana"})

        added = _send("POST", f"/api/teams/{created['id']}/members", body={"user_id": user["id"]})
        assert added[0].startswith("201")
        assert added[1]["member_count"] == 1

        removed = _send("DELETE", f"/api/teams/{created['id']}/members/{user['id']}")
        assert removed[0].startswith("200")
        assert removed[1]["member_count"] == 0

        journal.revert_action(conn, removed[1]["journal_action"])
        team = auth.get_team(conn, int(created["id"]))
        assert team is not None and team["member_count"] == 1

    def test_an_unknown_membership_is_404(self, conn: sqlite3.Connection) -> None:
        _, created = _send("POST", "/api/teams", body={"name": "Blue"})

        status, payload = _send("DELETE", f"/api/teams/{created['id']}/members/4242")

        assert status.startswith("404")
        assert payload["error"] == auth.ERROR_NOT_A_MEMBER

    def test_add_member_rejects_an_unknown_user(self, conn: sqlite3.Connection) -> None:
        _, created = _send("POST", "/api/teams", body={"name": "Blue"})

        status, payload = _send("POST", f"/api/teams/{created['id']}/members", body={"user_id": 9})

        assert status.startswith("400")
        assert payload["error"] == auth.ERROR_INVALID_TEAM

    def test_the_scope_routes_set_and_revert(self, conn: sqlite3.Connection) -> None:
        _, created = _send("POST", "/api/teams", body={"name": "Blue"})
        binary_id = store.add_binary(conn, sha256="d" * 64, name="demo.exe")

        status, payload = _send(
            "PATCH",
            f"/api/binaries/{binary_id}/scope",
            body={"visibility": "team", "team_id": created["id"]},
        )

        assert status.startswith("200")
        assert payload["visibility"] == "team"
        assert payload["owner_team_id"] == created["id"]

        journal.revert_action(conn, payload["journal_action"])
        restored = store.get_binary(conn, binary_id)
        assert restored is not None and restored["visibility"] == "public"

    def test_a_team_visibility_without_a_team_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="e" * 64, name="demo.exe")

        status, payload = _send(
            "PATCH", f"/api/binaries/{binary_id}/scope", body={"visibility": "team"}
        )

        assert status.startswith("400")
        assert payload["error"] == auth.ERROR_INVALID_TEAM

    def test_an_unknown_team_in_the_scope_is_404(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="f" * 64, name="demo.exe")

        status, payload = _send(
            "PATCH",
            f"/api/binaries/{binary_id}/scope",
            body={"visibility": "team", "team_id": 4242},
        )

        assert status.startswith("404")
        assert payload["error"] == auth.ERROR_TEAM_NOT_FOUND

    def test_an_unknown_object_is_404(self, conn: sqlite3.Connection) -> None:
        assert _send("PATCH", "/api/binaries/4242/scope", body={})[0].startswith("404")
        assert _send("PATCH", "/api/collections/4242/scope", body={})[0].startswith("404")


class TestCli:
    def _portal(self, tmp_path: Path, monkeypatch: Any) -> Path:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        return db

    def test_team_add_members_and_rm(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            user, _ = auth.add_user(conn, name="ana")

        added = runner.invoke(cli.app, ["team-add", "Blue", "--json"])
        assert added.exit_code == 0, added.output
        team_id = json.loads(added.stdout)["id"]

        member = runner.invoke(cli.app, ["team-member", str(team_id), str(user["id"]), "--json"])
        assert member.exit_code == 0, member.output
        assert json.loads(member.stdout)["member_count"] == 1

        listed = runner.invoke(cli.app, ["teams", "--json"])
        assert listed.exit_code == 0
        assert json.loads(listed.stdout)["count"] == 1

        human = runner.invoke(cli.app, ["teams"])
        assert human.exit_code == 0
        assert "Blue" in human.output

        removed = runner.invoke(cli.app, ["team-member", str(team_id), str(user["id"]), "--remove"])
        assert removed.exit_code == 0, removed.output

        deleted = runner.invoke(cli.app, ["team-rm", str(team_id), "--yes", "--json"])
        assert deleted.exit_code == 0, deleted.output
        with contextlib.closing(store.connect(db)) as conn:
            assert auth.get_team(conn, int(team_id)) is None

    def test_an_unknown_team_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._portal(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["team-rm", "4242", "--yes"]).exit_code == 1
        assert runner.invoke(cli.app, ["team-member", "4242", "1"]).exit_code == 1

    def test_binary_scope_sets_and_clears(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            team = auth.create_team(conn, name="Blue")
            binary_id = store.add_binary(conn, sha256="9" * 64, name="demo.exe")

        scoped = runner.invoke(
            cli.app,
            [
                "binary-scope",
                str(binary_id),
                "--visibility",
                "team",
                "--team",
                str(team["id"]),
                "--json",
            ],
        )
        assert scoped.exit_code == 0, scoped.output
        assert json.loads(scoped.stdout)["visibility"] == "team"

        cleared = runner.invoke(cli.app, ["binary-scope", str(binary_id), "--json"])
        assert cleared.exit_code == 0
        assert json.loads(cleared.stdout)["visibility"] == "public"

    def test_an_unknown_object_or_team_exits_non_zero(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        self._portal(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["binary-scope", "4242"]).exit_code == 1
        assert runner.invoke(cli.app, ["collection-scope", "4242"]).exit_code == 1
        assert (
            runner.invoke(
                cli.app, ["binary-scope", "1", "--visibility", "team", "--team", "4242"]
            ).exit_code
            == 1
        )


class TestMcp:
    def test_list_and_create_team(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        from reportal import mcp_tools

        create = mcp_tools.get_tool("create_team")
        listing = mcp_tools.get_tool("list_teams")
        assert create is not None and listing is not None

        created = create.handler({"name": "Blue", "description": "win"})

        assert created["name"] == "Blue"
        assert created["journal_action"]
        assert listing.handler({})["count"] == 1
        assert listing.annotations.read_only_hint is True
        assert create.annotations.destructive_hint is True

    def test_set_binary_scope_and_delete_team(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        from reportal import mcp_tools

        team = auth.create_team(conn, name="Blue")
        binary_id = store.add_binary(conn, sha256="7" * 64, name="demo.exe")
        scope = mcp_tools.get_tool("set_binary_scope")
        delete = mcp_tools.get_tool("delete_team")
        assert scope is not None and delete is not None

        scoped = scope.handler(
            {"binary_id": binary_id, "visibility": "team", "team_id": int(team["id"])}
        )

        assert scoped["visibility"] == "team"
        assert delete.handler({"team_id": int(team["id"])})["deleted"] == int(team["id"])
        restored = store.get_binary(conn, binary_id)
        assert restored is not None and restored["visibility"] == "public"

    def test_an_unknown_team_is_a_tool_error(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        from reportal import mcp_tools

        tool = mcp_tools.get_tool("set_binary_scope")
        assert tool is not None
        binary_id = store.add_binary(conn, sha256="6" * 64, name="demo.exe")

        try:
            tool.handler({"binary_id": binary_id, "visibility": "team", "team_id": 4242})
        except mcp_tools.ToolError as exc:
            assert exc.error == auth.ERROR_TEAM_NOT_FOUND
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown team must be a tool error")

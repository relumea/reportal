"""Tests for the identity-side reads: the activity feed and the feedback notes."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import activity, auth, cli, journal, notifications, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _log(conn: sqlite3.Connection, actor: str, key: int, description: str) -> str:
    """One journaled action by *actor*, flushed so the feed can read it."""
    with journal.acting_as(actor):
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_create(log, table="tags", key=key, description=description)
        return action


def _get(path: str, *, token: str = "") -> tuple[str, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    status, response_headers, body = wsgi_request("GET", path, headers=headers)
    return status, json_body(body, response_headers)


def _post(path: str, body: dict[str, Any] | None = None, *, token: str = "") -> tuple[str, Any]:
    raw = b"" if body is None else json.dumps(body).encode()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    status, response_headers, payload = wsgi_request("POST", path, body=raw, headers=headers)
    return status, json_body(payload, response_headers)


class TestActor:
    def test_an_entry_records_the_actor_the_context_names(self, conn: sqlite3.Connection) -> None:
        _log(conn, "ana", 1, "created tag 1")

        assert journal.list_entries(conn)[0]["actor"] == "ana"

    def test_the_actor_is_restored_after_the_block(self, conn: sqlite3.Connection) -> None:
        _log(conn, "ana", 1, "created tag 1")
        _log(conn, "", 2, "created tag 2")

        actors = [entry["actor"] for entry in journal.list_entries(conn)]
        assert actors == ["", "ana"]

    def test_a_request_records_who_made_it(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = store.add_binary(conn, sha256="a" * 64, name="x.exe")
        _, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, _ = _post(f"/api/binaries/{binary_id}/comments", {"body": "hi"}, token=token)

        assert status.startswith("201")
        assert journal.list_entries(conn)[0]["actor"] == "ana"

    def test_a_request_with_auth_off_records_the_local_operator(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = store.add_binary(conn, sha256="b" * 64, name="x.exe")

        _post(f"/api/binaries/{binary_id}/comments", {"body": "hi"})

        assert journal.list_entries(conn)[0]["actor"] == journal.LOCAL_ACTOR

    def test_a_database_without_the_column_gains_it(self, tmp_path: Path) -> None:
        db = tmp_path / "old.db"
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            conn.execute(
                "CREATE TABLE journal_entries (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " action TEXT NOT NULL, kind TEXT NOT NULL, description TEXT NOT NULL,"
                " descriptor_json TEXT NOT NULL, created_at TEXT NOT NULL,"
                " status TEXT NOT NULL DEFAULT 'active')"
            )
            conn.execute(
                "INSERT INTO journal_entries (action, kind, description, descriptor_json,"
                " created_at, status) VALUES ('a', 'row-delete', 'd', '{}', '2024', 'active')"
            )
            conn.commit()

            journal.ensure_schema(conn)

            entries = journal.list_entries(conn)
            assert entries[0]["actor"] == "", "a write nobody recorded an actor for stays empty"


class TestFeed:
    def test_it_merges_the_journal_and_the_log(self, conn: sqlite3.Connection) -> None:
        _log(conn, "ana", 1, "created tag 1")
        binary_id = store.add_binary(conn, sha256="c" * 64, name="x.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")

        payload = activity.feed(conn)

        kinds = {item["kind"] for item in payload["items"]}
        assert kinds == {activity.SOURCE_ACTION, activity.SOURCE_LOG}
        assert payload["total"] == len(payload["items"])
        assert any(str(analysis_id) in item["description"] for item in payload["items"])

    def test_the_actor_filter_narrows_the_feed(self, conn: sqlite3.Connection) -> None:
        _log(conn, "ana", 1, "created tag 1")
        _log(conn, "bob", 2, "created tag 2")

        ana = activity.feed(conn, actor="ana")
        nobody = activity.feed(conn, actor="")

        assert [item["actor"] for item in ana["items"]] == ["ana"]
        assert nobody["items"] == []
        assert ana["actor"] == "ana"

    def test_the_actor_filter_drops_the_log_items(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="d" * 64, name="x.exe")
        store.create_analysis(conn, binary_id=binary_id, engine="manual")
        _log(conn, "ana", 1, "created tag 1")

        payload = activity.feed(conn, actor="ana")

        assert all(item["kind"] == activity.SOURCE_ACTION for item in payload["items"])

    def test_a_non_member_sees_no_team_log_items(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import analysis_log

        binary_id = store.add_binary(conn, sha256="e" * 64, name="team.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        analysis_log.append_entry(conn, analysis_id, message="engine failed", severity="error")
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        stranger = auth.find_user(conn, "bob")
        assert stranger is not None
        store.set_binary_scope(conn, binary_id, visibility="team", owner_team_id=team_id)

        member = activity.feed(conn, sources=(activity.SOURCE_LOG,), visible_to=ana)
        assert any("engine failed" in item["description"] for item in member["items"])
        hidden = activity.feed(conn, sources=(activity.SOURCE_LOG,), visible_to=stranger)
        assert hidden["items"] == []

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _status, outsider_feed = _get("/api/users/activity?sources=log", token=outsider)
        assert outsider_feed["items"] == []
        _status, member_feed = _get("/api/users/activity?sources=log", token=token)
        assert any("engine failed" in item["description"] for item in member_feed["items"])

    def test_the_limit_bounds_the_page_and_the_total_stays_true(
        self, conn: sqlite3.Connection
    ) -> None:
        for key in range(1, 5):
            _log(conn, "ana", key, f"created tag {key}")

        payload = activity.feed(conn, limit=2)

        assert payload["count"] == 2
        assert len(payload["items"]) == 2
        assert payload["total"] == 4

    def test_since_is_inclusive(self, conn: sqlite3.Connection) -> None:
        _log(conn, "ana", 1, "created tag 1")
        latest = notifications.latest(conn)

        payload = activity.feed(conn, since=latest)

        assert payload["total"] == 1

    def test_an_unknown_source_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError):
            activity.feed(conn, sources=("nope",))
        with pytest.raises(ValueError):
            activity.feed(conn, limit=0)

    def test_a_non_positive_log_limit_is_refused(self, conn: sqlite3.Connection) -> None:
        from reportal import analysis_log

        with pytest.raises(ValueError, match="limit must be positive"):
            analysis_log.list_recent(conn, limit=0)

    def test_actors_reports_what_appears(self, conn: sqlite3.Connection) -> None:
        _log(conn, "ana", 1, "created tag 1")
        _log(conn, "ana", 2, "created tag 2")
        _log(conn, "", 3, "created tag 3")

        rows = activity.actors(conn)

        assert {row["actor"]: row["actions"] for row in rows} == {"": 1, "ana": 2}


class TestFeedbackStore:
    def test_add_list_and_count(self, conn: sqlite3.Connection) -> None:
        first = store.add_feedback(conn, body="  hello  ", actor="ana")

        assert first == 1
        stored = store.get_feedback(conn, first)
        assert stored is not None
        assert stored["body"] == "hello", "the note is trimmed"
        assert stored["actor"] == "ana"
        assert store.count_feedback(conn) == 1
        assert [note["id"] for note in store.list_feedback(conn)] == [1]

    def test_list_and_count_narrow_by_owner(self, conn: sqlite3.Connection) -> None:
        ana, _ = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        bob, _ = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.add_feedback(conn, body="ana note", actor="ana", user_id=int(ana["id"]))
        store.add_feedback(conn, body="bob note", actor="bob", user_id=int(bob["id"]))

        assert store.count_feedback(conn, user_id=int(ana["id"])) == 1
        assert [note["body"] for note in store.list_feedback(conn, user_id=int(ana["id"]))] == [
            "ana note"
        ]
        assert store.count_feedback(conn, user_id=int(bob["id"])) == 1
        assert store.count_feedback(conn) == 2

    def test_a_blank_or_oversized_note_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(store.InvalidFeedbackError):
            store.add_feedback(conn, body="   ")
        with pytest.raises(store.InvalidFeedbackError):
            store.add_feedback(conn, body="x" * (store.MAX_FEEDBACK_CHARS + 1))

    def test_an_unknown_note_is_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_feedback(conn, 4242) is None


class TestActivityRoute:
    def test_the_feed_answers_the_items_and_the_actors(self, conn: sqlite3.Connection) -> None:
        _log(conn, "ana", 1, "created tag 1")

        status, payload = _get("/api/users/activity")

        assert status.startswith("200")
        assert payload["count"] == 1
        assert payload["items"][0]["actor"] == "ana"
        assert payload["actors"] == [
            {"actor": "ana", "actions": 1, "at": payload["items"][0]["at"]}
        ]

    def test_the_actor_filter_and_a_bad_limit(self, conn: sqlite3.Connection) -> None:
        _log(conn, "ana", 1, "created tag 1")

        filtered = _get("/api/users/activity?actor=ana")
        assert filtered[1]["count"] == 1
        assert _get("/api/users/activity?actor=bob")[1]["count"] == 0

        status, payload = _get("/api/users/activity?limit=0")
        assert status.startswith("400")
        assert payload["error"] == "invalid limit"

    def test_a_bad_since_or_source_is_400(self, conn: sqlite3.Connection) -> None:
        assert _get("/api/users/activity?since=not-a-time")[1]["error"] == "invalid since"
        assert _get("/api/users/activity?sources=nope")[1]["error"] == "invalid sources"

    def test_an_analyst_may_read_its_own_activity(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, _ = _get("/api/users/activity", token=token)

        assert status.startswith("200")
        assert _get("/api/users", token=token)[0].startswith("403"), "the user table stays admin"

    def test_an_analyst_only_sees_its_own_actions(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _log(conn, "ana", 1, "created tag 1")
        _log(conn, "bob", 2, "created tag 2")
        _, ana_token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        _, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        _, admin_token = auth.add_user(conn, name="root", role=auth.ROLE_ADMIN)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _get("/api/users/activity?sources=action", token=ana_token)
        assert status.startswith("200")
        assert payload["count"] == 1
        assert payload["items"][0]["actor"] == "ana"
        assert all(row["actor"] == "ana" for row in payload["actors"])

        status, refused = _get("/api/users/activity?actor=bob", token=ana_token)
        assert status.startswith("403")
        assert refused["error"] == auth.ERROR_FORBIDDEN

        status, admin_feed = _get("/api/users/activity?sources=action", token=admin_token)
        assert status.startswith("200")
        assert admin_feed["count"] == 2
        assert {row["actor"] for row in admin_feed["actors"]} >= {"ana", "bob"}

        status, bob_feed = _get("/api/users/activity?sources=action", token=bob_token)
        assert status.startswith("200")
        assert bob_feed["count"] == 1
        assert bob_feed["items"][0]["actor"] == "bob"


class TestFeedbackRoute:
    def test_it_stores_an_attributed_note_and_reverts(self, conn: sqlite3.Connection) -> None:
        status, payload = _post("/api/users/feedback", {"message": "more docs please"})

        assert status.startswith("201")
        assert payload["body"] == "more docs please"
        assert payload["actor"] == journal.LOCAL_ACTOR
        assert payload["journal_action"]

        status, listing = _get("/api/users/feedback")
        assert listing["total"] == 1
        assert listing["count"] == 1

        journal.revert_action(conn, payload["journal_action"])

        assert store.get_feedback(conn, int(payload["id"])) is None
        assert store.count_feedback(conn) == 0

    def test_a_blank_message_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _post("/api/users/feedback", {"message": "   "})

        assert status.startswith("400")
        assert payload["error"] == "invalid feedback"

    def test_a_non_string_message_is_400(self, conn: sqlite3.Connection) -> None:
        assert _post("/api/users/feedback", {"message": 3})[1]["error"] == "invalid feedback"

    def test_the_listing_bounds_its_page(self, conn: sqlite3.Connection) -> None:
        store.add_feedback(conn, body="one")
        store.add_feedback(conn, body="two")

        status, payload = _get("/api/users/feedback?limit=1")
        assert payload["count"] == 1
        assert payload["total"] == 2

        assert _get("/api/users/feedback?limit=0")[1]["error"] == "invalid limit"

    def test_an_analyst_may_write_its_own_note(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        status, payload = _post("/api/users/feedback", {"message": "hi"}, token=token)

        assert status.startswith("201")
        assert payload["actor"] == "ana"
        assert payload["user_id"] is not None, "the note names the authenticated user"

    def test_an_analyst_only_lists_its_own_notes(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, ana_token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        _, bob_token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        _, admin_token = auth.add_user(conn, name="root", role=auth.ROLE_ADMIN)
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")

        assert _post("/api/users/feedback", {"message": "from ana"}, token=ana_token)[0].startswith(
            "201"
        )
        assert _post("/api/users/feedback", {"message": "from bob"}, token=bob_token)[0].startswith(
            "201"
        )

        status, ana_list = _get("/api/users/feedback", token=ana_token)
        assert status.startswith("200")
        assert ana_list["total"] == 1
        assert ana_list["feedback"][0]["body"] == "from ana"

        status, bob_list = _get("/api/users/feedback", token=bob_token)
        assert status.startswith("200")
        assert bob_list["total"] == 1
        assert bob_list["feedback"][0]["body"] == "from bob"

        status, admin_list = _get("/api/users/feedback", token=admin_token)
        assert status.startswith("200")
        assert admin_list["total"] == 2
        bodies = {note["body"] for note in admin_list["feedback"]}
        assert bodies == {"from ana", "from bob"}


class TestCli:
    def _portal(self, tmp_path: Path, monkeypatch: Any) -> Path:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        return db

    def test_activity_prints_the_feed(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(db)) as conn:
            _log(conn, "ana", 1, "created tag 1")

        result = runner.invoke(cli.app, ["activity", "--json"])

        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["items"][0]["actor"] == "ana"

        human = runner.invoke(cli.app, ["activity", "--actor", "ana"])
        assert human.exit_code == 0, human.output
        assert "created tag 1" in human.output

    def test_activity_refuses_a_bad_limit_or_since(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._portal(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["activity", "--limit", "0"]).exit_code == 1
        assert runner.invoke(cli.app, ["activity", "--since", "nope"]).exit_code == 1

    def test_feedback_add_lists_and_reverts(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = self._portal(tmp_path, monkeypatch)

        added = runner.invoke(cli.app, ["feedback-add", "the CLI is fine", "--json"])
        assert added.exit_code == 0, added.output
        payload = json.loads(added.stdout)
        assert payload["body"] == "the CLI is fine"
        assert payload["journal_action"]

        listed = runner.invoke(cli.app, ["feedback", "--json"])
        assert listed.exit_code == 0
        assert json.loads(listed.stdout)["total"] == 1

        human = runner.invoke(cli.app, ["feedback"])
        assert human.exit_code == 0
        assert "the CLI is fine" in human.output

        with contextlib.closing(store.connect(db)) as conn:
            journal.revert_action(conn, payload["journal_action"])
            assert store.count_feedback(conn) == 0

    def test_feedback_add_refuses_a_blank_message(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._portal(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["feedback-add", "   "]).exit_code == 1


class TestMcp:
    def test_get_activity_reads_the_feed(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        from reportal import mcp_tools

        _log(conn, "ana", 1, "created tag 1")
        tool = mcp_tools.get_tool("get_activity")
        assert tool is not None
        assert tool.annotations.read_only_hint is True

        payload = tool.handler({})

        assert payload["count"] == 1
        assert payload["actors"][0]["actor"] == "ana"
        assert tool.handler({"actor": "bob"})["count"] == 0

    def test_add_and_list_feedback(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        from reportal import mcp_tools

        add = mcp_tools.get_tool("add_feedback")
        listing = mcp_tools.get_tool("list_feedback")
        assert add is not None and listing is not None
        assert listing.annotations.read_only_hint is True
        assert add.annotations.destructive_hint is True

        stored = add.handler({"message": "an MCP note"})

        assert stored["body"] == "an MCP note"
        assert stored["journal_action"]
        assert listing.handler({})["total"] == 1

        journal.revert_action(conn, stored["journal_action"])
        assert listing.handler({})["total"] == 0

    def test_a_blank_message_is_a_tool_error(self, portal_db: Path) -> None:
        """The argument reader refuses a blank string before the store sees it."""
        from reportal import mcp_tools

        tool = mcp_tools.get_tool("add_feedback")
        assert tool is not None

        try:
            tool.handler({"message": "  "})
        except mcp_tools.ToolError as exc:
            assert exc.error == "invalid params"
            assert exc.detail
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a blank note must be a tool error")

    def test_a_bad_activity_query_is_a_tool_error(self, portal_db: Path) -> None:
        from reportal import mcp_tools

        tool = mcp_tools.get_tool("get_activity")
        assert tool is not None

        try:
            tool.handler({"since": "nope"})
        except mcp_tools.ToolError as exc:
            assert exc.error == "invalid since"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a bad timestamp must be a tool error")

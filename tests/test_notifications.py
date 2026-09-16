"""Tests for the notification feed: the derivation, its surfaces and its bounds."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import analysis_log, auth, cli, journal, mcp_tools, notifications, store

runner = CliRunner()


def _binary(conn: sqlite3.Connection, name: str = "t.exe") -> int:
    return store.add_binary(
        conn, sha256=f"{name:0<64}"[:64], name=name, path=f"/tmp/{name}", size=16
    )


def _analysis(conn: sqlite3.Connection, name: str = "t.exe") -> tuple[int, int]:
    binary_id = _binary(conn, name)
    return binary_id, store.create_analysis(conn, binary_id=binary_id, engine="manual")


def _action(conn: sqlite3.Connection, description: str = "created a thing") -> None:
    with journal.journaled(conn, journal.new_action()) as log:
        journal.journaled_create(log, table="binaries", key=4242, description=description)


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


class TestFeed:
    def test_a_journaled_action_is_one_item(self, conn: sqlite3.Connection) -> None:
        _action(conn, "created a thing")
        _action(conn, "renamed a function")

        payload = notifications.feed(conn, sources=(notifications.SOURCE_JOURNAL,))

        assert payload["total"] == 2
        messages = [item["message"] for item in payload["notifications"]]
        assert messages == ["renamed a function", "created a thing"]
        first = payload["notifications"][0]
        assert first["kind"] == "action"
        assert first["severity"] == notifications.ACTION_SEVERITY
        assert first["entries"] == 1
        assert first["revertible"] is True
        assert first["id"].startswith("action:")

    def test_the_newest_action_supplies_the_item(self, conn: sqlite3.Connection) -> None:
        with journal.journaled(conn, journal.new_action()) as log:
            journal.journaled_create(log, table="binaries", key=1, description="first")
            journal.journaled_create(log, table="binaries", key=2, description="second")

        payload = notifications.feed(conn, sources=(notifications.SOURCE_JOURNAL,))

        assert payload["total"] == 1
        item = payload["notifications"][0]
        assert item["message"] == "second", "the newest entry describes the action"
        assert item["entries"] == 2

    def test_an_analysis_log_entry_is_one_item_with_its_binary(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id, analysis_id = _analysis(conn, "victim.exe")
        analysis_log.append_entry(conn, analysis_id, message="engine failed", severity="error")

        payload = notifications.feed(conn, sources=(notifications.SOURCE_LOG,))

        item = payload["notifications"][0]
        assert item["severity"] == "error"
        assert item["message"] == "engine failed"
        assert item["binary_id"] == binary_id
        assert item["binary_name"] == "victim.exe"
        assert item["analysis_id"] == analysis_id

    def test_a_non_member_sees_no_team_log_entries(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id, analysis_id = _analysis(conn, "victim.exe")
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

        member = notifications.feed(conn, sources=(notifications.SOURCE_LOG,), visible_to=ana)
        assert "engine failed" in [item["message"] for item in member["notifications"]]
        hidden = notifications.feed(conn, sources=(notifications.SOURCE_LOG,), visible_to=stranger)
        assert hidden["notifications"] == []
        assert hidden["total"] == 0

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _status, headers, body = wsgi_request(
            "GET",
            "/api/notifications?sources=log",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert json_body(body, headers)["notifications"] == []
        _status, headers, body = wsgi_request(
            "GET",
            "/api/notifications?sources=log",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert "engine failed" in [
            item["message"] for item in json_body(body, headers)["notifications"]
        ]

    def test_both_sources_merge_into_one_newest_first_feed(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _analysis(conn)
        analysis_log.append_entry(conn, analysis_id, message="first", severity="info")
        _action(conn, "then a write")

        payload = notifications.feed(conn)

        kinds = {item["kind"] for item in payload["notifications"]}
        assert kinds == {notifications.SOURCE_JOURNAL, notifications.SOURCE_LOG}
        times = [str(item["at"]) for item in payload["notifications"]]
        assert times == sorted(times, reverse=True), "newest first"

    def test_since_excludes_what_precedes_it_and_keeps_the_named_second(
        self, conn: sqlite3.Connection
    ) -> None:
        # Timestamps have second resolution, so an item written at the named
        # second is returned again (the caller de-duplicates by id) and only an
        # older one is filtered out; the backdated row makes that unambiguous.
        _, analysis_id = _analysis(conn)
        analysis_log.append_entry(conn, analysis_id, message="old", severity="info")
        conn.execute(f"UPDATE {analysis_log.TABLE} SET created_at = '2000-01-01T00:00:00+00:00'")
        conn.commit()
        _action(conn, "new")
        cutoff = notifications.latest(conn)
        assert cutoff is not None

        payload = notifications.feed(conn, since=cutoff)

        assert [item["message"] for item in payload["notifications"]] == ["new"]
        assert payload["since"] == cutoff

    def test_the_latest_time_covers_both_sources(self, conn: sqlite3.Connection) -> None:
        assert notifications.latest(conn) is None
        _, analysis_id = _analysis(conn)
        analysis_log.append_entry(conn, analysis_id, message="a", severity="info")
        logged = notifications.latest(conn)
        assert logged is not None
        _action(conn, "b")

        assert str(notifications.latest(conn)) >= str(logged)

    def test_limit_bounds_the_page_and_says_so(self, conn: sqlite3.Connection) -> None:
        for index in range(4):
            _action(conn, f"write {index}")

        payload = notifications.feed(conn, limit=2)

        assert len(payload["notifications"]) == 2
        assert payload["count"] == 2
        assert payload["total"] == 4

    def test_the_sources_can_be_narrowed(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _analysis(conn)
        analysis_log.append_entry(conn, analysis_id, message="logged", severity="warn")
        _action(conn, "written")
        analysis_log.append_entry(conn, analysis_id, message="logged again", severity="info")

        payload = notifications.feed(conn, sources=(notifications.SOURCE_LOG,))

        assert payload["sources"] == ["log"]
        assert {item["kind"] for item in payload["notifications"]} == {"log"}

    def test_an_unknown_source_is_refused(self, conn: sqlite3.Connection) -> None:
        try:
            notifications.feed(conn, sources=("mail",))
        except ValueError as exc:
            assert "unknown notification source" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown source must be refused")

    def test_an_out_of_range_limit_is_refused(self, conn: sqlite3.Connection) -> None:
        for bad in (0, notifications.MAX_FEED_LIMIT + 1):
            try:
                notifications.feed(conn, limit=bad)
            except ValueError as exc:
                assert "limit must be between" in str(exc)
            else:  # pragma: no cover - the assertion is the point
                raise AssertionError("an out-of-range limit must be refused")

    def test_parse_since_accepts_iso_and_refuses_anything_else(self) -> None:
        assert notifications.parse_since("2026-09-13T12:00:00+00:00") == "2026-09-13T12:00:00+00:00"
        # Z and a bare date must normalize to the store's +00:00 form so a
        # lexicographic created_at >= since still keeps the inclusive second.
        assert notifications.parse_since("2026-09-13T12:00:00Z") == "2026-09-13T12:00:00+00:00"
        assert notifications.parse_since("2026-09-13") == "2026-09-13T00:00:00+00:00"
        row = "2026-09-13T12:00:00+00:00"
        assert row >= notifications.parse_since("2026-09-13T12:00:00Z")

        try:
            notifications.parse_since("yesterday")
        except ValueError as exc:
            assert "ISO timestamp" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a non-ISO timestamp must be refused")

    def test_the_feed_writes_nothing(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        _action(conn, "one write")

        notifications.feed(conn)
        assert len(journal.list_entries(conn)) == 1, "reading the feed journals nothing"


class TestRoute:
    def test_the_route_answers_the_feed(self, conn: sqlite3.Connection) -> None:
        _action(conn, "created a thing")

        status, payload = _get("/api/notifications")

        assert status.startswith("200")
        assert payload["count"] == 1
        assert payload["notifications"][0]["message"] == "created a thing"
        assert payload["sources"] == list(notifications.SOURCES)
        assert "latest" in payload

    def test_a_bad_since_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/notifications?since=yesterday")

        assert status.startswith("400")
        assert payload["error"] == "invalid since"

    def test_an_out_of_range_limit_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _get(f"/api/notifications?limit={notifications.MAX_FEED_LIMIT + 1}")

        assert status.startswith("400")
        assert payload["error"] == "invalid limit"

    def test_an_unknown_source_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/notifications?sources=mail")

        assert status.startswith("400")
        assert payload["error"] == "invalid sources"

    def test_sources_narrows_the_route(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _analysis(conn)
        analysis_log.append_entry(conn, analysis_id, message="logged", severity="warn")
        _action(conn, "written")

        status, payload = _get("/api/notifications?sources=action")

        assert status.startswith("200")
        assert payload["sources"] == ["action"]
        assert {item["kind"] for item in payload["notifications"]} == {"action"}

    def test_since_filters_the_route(self, conn: sqlite3.Connection) -> None:
        _action(conn, "old")
        conn.execute("UPDATE journal_entries SET created_at = '2000-01-01T00:00:00+00:00'")
        conn.commit()
        _action(conn, "new")
        cutoff = notifications.latest(conn)
        assert cutoff is not None

        # An ISO timestamp carries a `+` offset, which is a space in a query
        # string unless the caller encodes it, so the contract is percent-encoded.
        status, payload = _get(f"/api/notifications?since={urllib.parse.quote(cutoff)}")

        assert status.startswith("200")
        assert [item["message"] for item in payload["notifications"]] == ["new"]


class TestCli:
    def test_notifications_json(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            _action(conn, "created a thing")

        result = runner.invoke(cli.app, ["notifications", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["notifications"][0]["message"] == "created a thing"
        assert "latest" in payload

    def test_the_table_lists_the_items(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            _action(conn, "created a thing")

        result = runner.invoke(cli.app, ["notifications"])

        assert result.exit_code == 0
        assert "created a thing" in result.output

    def test_a_bad_since_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)

        result = runner.invoke(cli.app, ["notifications", "--since", "yesterday"])

        assert result.exit_code == 1
        assert "ISO timestamp" in result.output


class TestMcp:
    def test_the_tool_is_read_only(self) -> None:
        tool = mcp_tools.get_tool("list_notifications")
        assert tool is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False

    def test_list_notifications_returns_the_feed(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        _action(conn, "created a thing")
        tool = mcp_tools.get_tool("list_notifications")
        assert tool is not None

        payload = tool.handler({})

        assert payload["notifications"][0]["message"] == "created a thing"
        assert "journal_action" not in payload

    def test_a_bad_since_is_a_tool_error(self, portal_db: Path) -> None:
        tool = mcp_tools.get_tool("list_notifications")
        assert tool is not None

        try:
            tool.handler({"since": "yesterday"})
        except mcp_tools.ToolError as exc:
            assert exc.error == "invalid notification query"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a bad since must be a tool error")

"""Tests for the collection CLI commands and MCP tools."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from reportal import cli, journal, mcp_tools, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _seed(tmp_path: Path, monkeypatch: Any) -> dict[str, Any]:
    """A workspace with one collection holding one binary."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        collection_id = store.create_collection(conn, name="games", description="targets")
        binary_id = store.add_binary(
            conn, sha256="a" * 64, name="first.exe", path="/tmp/first.exe", size=16
        )
        store.add_collection_binary(conn, collection_id, binary_id)
    return {"db": db, "collection": collection_id, "binary": binary_id}


class TestCli:
    def test_collections_lists_members_and_tags(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["collection-tags", str(ids["collection"]), "pe"])

        result = runner.invoke(cli.app, ["collections"])

        assert result.exit_code == 0
        assert "games" in result.output

    def test_collection_show_reports_the_members(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["collection-show", str(ids["collection"])])

        assert result.exit_code == 0
        assert "first.exe" in result.output

    def test_collection_new_prints_the_action_id(self, tmp_path: Path, monkeypatch: Any) -> None:
        _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["collection-new", "second", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["name"] == "second"
        assert payload["journal_action"]

    def test_collection_edit_renames(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app, ["collection-edit", str(ids["collection"]), "--name", "renamed"]
        )

        assert result.exit_code == 0
        with contextlib.closing(store.connect(ids["db"])) as conn:
            collection = store.get_collection(conn, ids["collection"])
        assert collection is not None
        assert collection["name"] == "renamed"

    def test_collection_edit_without_a_field_fails(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["collection-edit", str(ids["collection"])])

        assert result.exit_code != 0
        assert "nothing to change" in result.output

    def test_collection_rm_deletes_and_reverts(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["collection-rm", str(ids["collection"]), "--json"])
        payload = json.loads(result.stdout)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            assert store.get_collection(conn, ids["collection"]) is None
            journal.revert_action(conn, payload["journal_action"])
            restored = store.get_collection(conn, ids["collection"])
        assert restored is not None
        assert [row["id"] for row in restored["binaries"]] == [ids["binary"]]

    def test_collection_add_and_remove_a_member(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            second = store.add_binary(
                conn, sha256="b" * 64, name="second.exe", path="/tmp/second.exe", size=16
            )

        added = runner.invoke(
            cli.app, ["collection-add", str(ids["collection"]), str(second), "--json"]
        )
        assert json.loads(added.stdout)["added"] == [second]

        removed = runner.invoke(
            cli.app, ["collection-remove", str(ids["collection"]), str(second), "--json"]
        )
        assert json.loads(removed.stdout)["removed"] == [second]

    def test_collection_tags_replaces_the_set(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app, ["collection-tags", str(ids["collection"]), "one", "two", "--json"]
        )

        assert result.exit_code == 0
        assert json.loads(result.stdout)["added"] == ["one", "two"]
        with contextlib.closing(store.connect(ids["db"])) as conn:
            names = [tag["name"] for tag in store.collection_tags(conn, ids["collection"])]
        assert names == ["one", "two"]

    def test_an_unknown_collection_fails(self, tmp_path: Path, monkeypatch: Any) -> None:
        _seed(tmp_path, monkeypatch)

        result = runner.invoke(cli.app, ["collection-show", "4242"])

        assert result.exit_code != 0
        assert "no collection with id 4242" in result.output


class TestMcp:
    def test_the_collection_tools_are_registered(self) -> None:
        names = {tool.name for tool in mcp_tools.tools()}
        for name in (
            "list_collections",
            "get_collection",
            "create_collection",
            "update_collection",
            "delete_collection",
            "set_collection_members",
            "set_collection_tags",
        ):
            assert name in names

    def test_get_collection_returns_members(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        collection_id = store.create_collection(conn, name="mcp")
        binary_id = store.add_binary(
            conn, sha256="c" * 64, name="member.exe", path="/tmp/member.exe", size=8
        )
        store.add_collection_binary(conn, collection_id, binary_id)

        tool = mcp_tools.get_tool("get_collection")
        assert tool is not None
        result = tool.handler({"collection_id": collection_id})

        assert result["name"] == "mcp"
        assert [row["id"] for row in result["binaries"]] == [binary_id]

    def test_create_then_set_members_and_tags(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        binary_id = store.add_binary(
            conn, sha256="d" * 64, name="one.exe", path="/tmp/one.exe", size=8
        )
        create = mcp_tools.get_tool("create_collection")
        members = mcp_tools.get_tool("set_collection_members")
        tags = mcp_tools.get_tool("set_collection_tags")
        assert create is not None and members is not None and tags is not None

        created = create.handler({"name": "made", "description": "via mcp"})
        collection_id = created["id"]
        changed = members.handler({"collection_id": collection_id, "binary_ids": [binary_id]})
        tagged = tags.handler({"collection_id": collection_id, "tags": ["mcp"]})

        assert changed["added"] == [binary_id]
        assert tagged["added"] == ["mcp"]
        stored = store.get_collection(conn, collection_id)
        assert stored is not None
        assert [tag["name"] for tag in stored["tags"]] == ["mcp"]

    def test_update_and_delete(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="before")
        update = mcp_tools.get_tool("update_collection")
        delete = mcp_tools.get_tool("delete_collection")
        assert update is not None and delete is not None

        renamed = update.handler({"collection_id": collection_id, "name": "after"})
        assert renamed["name"] == "after"
        assert delete.handler({"collection_id": collection_id})["deleted"] is True
        assert store.get_collection(conn, collection_id) is None

    def test_an_unknown_collection_is_a_tool_error(self, portal_db: Path) -> None:
        tool = mcp_tools.get_tool("get_collection")
        assert tool is not None

        try:
            tool.handler({"collection_id": 4242})
        except mcp_tools.ToolError as exc:
            assert exc.error == "collection not found"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown collection must be a tool error")

    def test_a_missing_member_list_is_a_tool_error(self, portal_db: Path) -> None:
        tool = mcp_tools.get_tool("set_collection_members")
        assert tool is not None

        try:
            tool.handler({"collection_id": 1})
        except mcp_tools.ToolError as exc:
            assert exc.detail == "binary_ids is required"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a missing list must be a tool error")

    def test_the_write_tools_are_marked_destructive(self) -> None:
        for name in (
            "create_collection",
            "update_collection",
            "delete_collection",
            "set_collection_members",
            "set_collection_tags",
        ):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.destructive_hint is True
        read = mcp_tools.get_tool("list_collections")
        assert read is not None
        assert read.annotations.read_only_hint is True

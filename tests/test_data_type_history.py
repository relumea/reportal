"""Tests for data-type edit history and revert: domain, API, CLI and MCP."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, data_types, journal, mcp_server, mcp_tools, store
from reportal._paths import DB_ENV

runner = CliRunner()

DEFINITION = (
    "typedef struct PlayerInfo_s {\n\tchar gap_0000[0x17];\n\tint field_C;\n} PlayerInfo;\n"
)

# The model fields a history entry records, in the order the module projects
# them; the two write stamps are not part of a recorded state.
STATE_KEYS = (
    "name",
    "kind",
    "namespace",
    "size",
    "members",
    "values",
    "target",
    "element_count",
    "source",
)


def _seed_binary(conn: sqlite3.Connection, *, sha256: str = "ab" * 32) -> int:
    return store.add_binary(conn, sha256=sha256, name="demo.exe")


def _seed_scan(conn: sqlite3.Connection, binary_id: int) -> None:
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_STRUCTS,
        {
            "decompiled": 1,
            "skipped": 0,
            "structs": [{"name": "PlayerInfo", "va": 0x1000, "definition": DEFINITION}],
        },
    )


def _imported(conn: sqlite3.Connection) -> tuple[int, int]:
    """A binary and the type the stored structs scan imported, with its creation recorded."""
    binary_id = _seed_binary(conn)
    _seed_scan(conn, binary_id)
    data_types.import_types(conn, binary_id=binary_id)
    row = store.find_data_type_by_name(conn, binary_id, "PlayerInfo")
    assert row is not None
    return binary_id, int(row["id"])


def _legacy(conn: sqlite3.Connection) -> tuple[int, int]:
    """A binary and a type row written straight through the store, with no history."""
    binary_id = _seed_binary(conn)
    parsed = data_types.parse_definition(DEFINITION)
    data_type_id = store.add_data_type(
        conn,
        binary_id=binary_id,
        name=parsed["name"],
        size=parsed["size"],
        members=parsed["members"],
        source=data_types.SOURCE_SCAN,
    )
    return binary_id, data_type_id


def _state_of(row: dict[str, Any]) -> dict[str, Any]:
    """The recorded state of a stored row, discarding the write stamps."""
    return {key: row[key] for key in STATE_KEYS}


def _state(conn: sqlite3.Connection, data_type_id: int) -> dict[str, Any]:
    """The recorded state of a type that is still stored."""
    row = store.get_data_type(conn, data_type_id)
    assert row is not None
    return _state_of(row)


def _call(name: str, arguments: dict[str, Any] | None = None) -> tuple[Any, bool]:
    """Run one MCP tool through ``tools/call``; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestHistoryRecording:
    def test_the_import_records_the_creation(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        history = data_types.list_history(conn, data_type_id)
        assert len(history) == 1
        assert history[0]["previous"] is None
        assert history[0]["current"]["name"] == "PlayerInfo"
        assert history[0]["source"] == data_types.SOURCE_SCAN
        assert history[0]["changes"] == []

    def test_a_rename_records_a_name_change(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        before = _state(conn, data_type_id)

        data_types.rename_type(conn, data_type_id, name="Player")

        entry = data_types.list_history(conn, data_type_id)[0]
        assert entry["previous"] == before
        assert entry["current"]["name"] == "Player"
        assert entry["changes"] == [{"field": "name", "before": "PlayerInfo", "after": "Player"}]
        assert entry["source"] == data_types.SOURCE_MANUAL

    def test_a_namespace_change_records_that_field(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        data_types.set_namespace(conn, data_type_id, namespace="winnt")
        entry = data_types.list_history(conn, data_type_id)[0]
        assert [change["field"] for change in entry["changes"]] == ["namespace"]

    def test_every_member_edit_shape_records_the_members_field(
        self, conn: sqlite3.Connection
    ) -> None:
        _, data_type_id = _imported(conn)
        data_types.add_member(conn, data_type_id, name="flags", type_text="unsigned int")
        data_types.update_member(conn, data_type_id, name="field_C", new_type="short")
        data_types.remove_member(conn, data_type_id, name="gap_0000")

        history = data_types.list_history(conn, data_type_id)
        assert len(history) == 4
        assert [[change["field"] for change in entry["changes"]] for entry in history] == [
            ["size", "members"],
            ["size", "members"],
            ["size", "members"],
            [],
        ]

    def test_an_unchanged_import_records_nothing(self, conn: sqlite3.Connection) -> None:
        binary_id, data_type_id = _imported(conn)
        before = len(data_types.list_history(conn, data_type_id))
        data_types.import_types(conn, binary_id=binary_id)
        assert len(data_types.list_history(conn, data_type_id)) == before

    def test_delete_records_the_deleted_row(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        before = _state(conn, data_type_id)

        assert data_types.delete_type(conn, data_type_id) is True

        entry = data_types.list_history(conn, data_type_id)[0]
        assert entry["previous"] == before
        assert entry["current"] is None
        assert entry["changes"] == []
        assert store.get_data_type(conn, data_type_id) is None
        assert data_types.delete_type(conn, data_type_id) is False


class TestRevert:
    def test_revert_restores_the_stored_row(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        before = _state(conn, data_type_id)
        data_types.add_member(conn, data_type_id, name="flags", type_text="unsigned int")
        assert _state(conn, data_type_id) != before

        target = data_types.list_history(conn, data_type_id)[0]["id"]
        result = data_types.revert_history(conn, data_type_id, target)

        assert result["changed"] is True
        assert result["reason"] == ""
        assert _state(conn, data_type_id) == before
        assert [member["name"] for member in result["data_type"]["members"]] == [
            "gap_0000",
            "field_C",
        ]

    def test_revert_of_a_delete_puts_the_row_back_under_its_id(
        self, conn: sqlite3.Connection
    ) -> None:
        _, data_type_id = _imported(conn)
        before = _state(conn, data_type_id)
        data_types.delete_type(conn, data_type_id)
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]

        result = data_types.revert_history(conn, data_type_id, entry_id)

        assert result["changed"] is True
        restored = store.get_data_type(conn, data_type_id)
        assert restored is not None
        assert int(restored["id"]) == data_type_id
        assert _state_of(restored) == before

    def test_second_revert_is_a_no_op(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        data_types.rename_type(conn, data_type_id, name="Player")
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]

        first = data_types.revert_history(conn, data_type_id, entry_id)
        assert first["changed"] is True
        count_after_first = len(data_types.list_history(conn, data_type_id))

        second = data_types.revert_history(conn, data_type_id, entry_id)
        assert second["changed"] is False
        assert second["reason"] == "the type already holds that state"
        assert second["data_type"] == first["data_type"]
        assert len(data_types.list_history(conn, data_type_id)) == count_after_first

    def test_reverting_a_creation_removes_the_type(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]

        result = data_types.revert_history(conn, data_type_id, entry_id)

        assert result["changed"] is True
        assert result["data_type"] is None
        assert store.get_data_type(conn, data_type_id) is None

    def test_reverting_a_creation_whose_type_is_gone_is_a_no_op(
        self, conn: sqlite3.Connection
    ) -> None:
        _, data_type_id = _imported(conn)
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]
        store.delete_data_type(conn, data_type_id)

        result = data_types.revert_history(conn, data_type_id, entry_id)

        assert result["changed"] is False
        assert result["reason"] == "the type this entry created is already gone"

    def test_unknown_history_raises(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        with pytest.raises(data_types.UnknownHistoryError):
            data_types.revert_history(conn, data_type_id, 999)

    def test_history_of_another_type_raises(self, conn: sqlite3.Connection) -> None:
        binary_id, first = _imported(conn)
        data_types.rename_type(conn, first, name="Other")
        parsed = data_types.parse_definition(DEFINITION)
        second = store.add_data_type(
            conn,
            binary_id=binary_id,
            name="Second",
            size=parsed["size"],
            members=parsed["members"],
            source=data_types.SOURCE_MANUAL,
        )
        entry_id = data_types.list_history(conn, first)[0]["id"]
        with pytest.raises(data_types.UnknownHistoryError):
            data_types.revert_history(conn, second, entry_id)

    def test_a_name_now_held_by_another_row_refuses_the_restore(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id, data_type_id = _imported(conn)
        data_types.rename_type(conn, data_type_id, name="Zed")
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]
        parsed = data_types.parse_definition(DEFINITION)
        store.add_data_type(
            conn,
            binary_id=binary_id,
            name="PlayerInfo",
            size=parsed["size"],
            members=parsed["members"],
            source=data_types.SOURCE_MANUAL,
        )

        with pytest.raises(data_types.DuplicateNameError):
            data_types.revert_history(conn, data_type_id, entry_id)


class TestDeletedType:
    def test_a_deleted_types_history_stays_readable_and_revertible(
        self, conn: sqlite3.Connection
    ) -> None:
        _, data_type_id = _imported(conn)
        data_types.rename_type(conn, data_type_id, name="Player")
        data_types.delete_type(conn, data_type_id)

        history = data_types.list_history(conn, data_type_id)
        assert len(history) == 3
        assert [entry["changes"][0]["field"] if entry["changes"] else "" for entry in history] == [
            "",
            "name",
            "",
        ]

        result = data_types.revert_history(conn, data_type_id, history[0]["id"])
        assert result["changed"] is True
        restored = store.get_data_type(conn, data_type_id)
        assert restored is not None
        assert restored["name"] == "Player"


class TestLegacyRow:
    def test_legacy_row_reads_with_empty_history(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _legacy(conn)
        assert store.get_data_type(conn, data_type_id) is not None
        assert data_types.list_history(conn, data_type_id) == []

    def test_a_database_predating_the_table_picks_it_up(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        conn.execute("DROP TABLE data_type_history")
        conn.commit()

        data_types.rename_type(conn, data_type_id, name="Player")
        history = data_types.list_history(conn, data_type_id)

        assert len(history) == 1
        assert history[0]["changes"][0]["field"] == "name"

    def test_legacy_row_records_its_own_state_as_the_previous_one(
        self, conn: sqlite3.Connection
    ) -> None:
        _, data_type_id = _legacy(conn)
        legacy = _state(conn, data_type_id)

        data_types.rename_type(conn, data_type_id, name="Renamed")
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]
        result = data_types.revert_history(conn, data_type_id, entry_id)

        assert result["changed"] is True
        assert _state(conn, data_type_id) == legacy


class TestApiRoutes:
    def test_history_route_lists_the_edits_with_diffs(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        data_types.rename_type(conn, data_type_id, name="Player")

        status, headers, body = wsgi_request("GET", f"/api/data-types/{data_type_id}/history")

        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["data_type_id"] == data_type_id
        assert payload["exists"] is True
        assert payload["count"] == 2
        assert payload["history"][0]["changes"] == [
            {"field": "name", "before": "PlayerInfo", "after": "Player"}
        ]

    def test_history_route_answers_for_a_deleted_type(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        data_types.rename_type(conn, data_type_id, name="Player")
        data_types.delete_type(conn, data_type_id)

        status, headers, body = wsgi_request("GET", f"/api/data-types/{data_type_id}/history")

        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["exists"] is False
        assert payload["count"] == 3

    def test_history_route_answers_for_an_unknown_id(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/data-types/4242/history")

        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["exists"] is False
        assert payload["binary_id"] is None
        assert payload["history"] == []

    def test_revert_route_restores_and_journals(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        before = _state(conn, data_type_id)
        data_types.add_member(conn, data_type_id, name="flags", type_text="unsigned int")
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]

        status, headers, body = wsgi_request(
            "POST", f"/api/data-types/{data_type_id}/history/{entry_id}/revert"
        )

        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["changed"] is True
        assert payload["journal_action"]
        assert _state(conn, data_type_id) == before

    def test_revert_route_journal_action_reverts_the_revert(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        data_types.rename_type(conn, data_type_id, name="Player")
        edited = _state(conn, data_type_id)
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]

        _status, headers, body = wsgi_request(
            "POST", f"/api/data-types/{data_type_id}/history/{entry_id}/revert"
        )
        payload = json_body(body, headers)
        action = payload["journal_action"]
        count_after_revert = len(data_types.list_history(conn, data_type_id))

        journal.revert_action(conn, action)

        assert _state(conn, data_type_id) == edited
        assert len(data_types.list_history(conn, data_type_id)) == count_after_revert - 1

    def test_a_delete_revert_puts_the_row_back_and_journals_it(
        self, conn: sqlite3.Connection
    ) -> None:
        _, data_type_id = _imported(conn)
        before = _state(conn, data_type_id)
        data_types.delete_type(conn, data_type_id)
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]

        status, headers, body = wsgi_request(
            "POST", f"/api/data-types/{data_type_id}/history/{entry_id}/revert"
        )

        assert status.startswith("200")
        action = json_body(body, headers)["journal_action"]
        assert _state(conn, data_type_id) == before

        journal.revert_action(conn, action)

        assert store.get_data_type(conn, data_type_id) is None
        assert len(data_types.list_history(conn, data_type_id)) == 2

    def test_revert_route_unknown_history_404(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/data-types/{data_type_id}/history/999/revert"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "history not found"

    def test_edit_route_journal_action_drops_the_history_it_appended(
        self, conn: sqlite3.Connection
    ) -> None:
        _, data_type_id = _imported(conn)
        before = _state(conn, data_type_id)
        count_before = len(data_types.list_history(conn, data_type_id))

        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/data-types/{data_type_id}",
            body=json.dumps({"name": "Player"}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("200")
        action = json_body(body, headers)["journal_action"]
        assert _state(conn, data_type_id) != before

        journal.revert_action(conn, action)

        assert _state(conn, data_type_id) == before
        assert len(data_types.list_history(conn, data_type_id)) == count_before


class TestCli:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            _, data_type_id = _imported(conn)
        return {"type": data_type_id}

    def test_history_command(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            data_types.rename_type(conn, ids["type"], name="Player")

        result = runner.invoke(cli.app, ["types-history", str(ids["type"]), "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["count"] == 2
        assert payload["history"][0]["changes"][0]["field"] == "name"

    def test_history_command_without_history(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.delete_data_type(conn, ids["type"])
        result = runner.invoke(cli.app, ["types-history", "4242"])
        assert result.exit_code == 0
        assert "No history for data type 4242" in result.output

    def test_revert_command_restores(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            before = _state(conn, ids["type"])
            data_types.rename_type(conn, ids["type"], name="Player")
            entry_id = data_types.list_history(conn, ids["type"])[0]["id"]

        result = runner.invoke(cli.app, ["types-revert", str(ids["type"]), str(entry_id), "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["changed"] is True
        assert payload["journal_action"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert _state(conn, ids["type"]) == before

    def test_revert_command_unknown_history_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["types-revert", str(ids["type"]), "999"])
        assert result.exit_code != 0
        assert "999" in result.output


class TestMcp:
    def test_history_tool_lists_the_edit(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        data_types.rename_type(conn, data_type_id, name="Player")
        payload, is_error = _call("get_data_type_history", {"data_type_id": data_type_id})
        assert is_error is False
        assert payload["count"] == 2
        assert payload["history"][0]["changes"][0]["field"] == "name"

    def test_revert_tool_reaches_the_same_domain_call(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        before = _state(conn, data_type_id)
        data_types.rename_type(conn, data_type_id, name="Player")
        entry_id = data_types.list_history(conn, data_type_id)[0]["id"]

        payload, is_error = _call(
            "revert_data_type_history",
            {"data_type_id": data_type_id, "history_id": entry_id},
        )

        assert is_error is False
        assert payload["changed"] is True
        assert _state(conn, data_type_id) == before

    def test_revert_tool_unknown_history_is_an_error(self, conn: sqlite3.Connection) -> None:
        _, data_type_id = _imported(conn)
        payload, is_error = _call(
            "revert_data_type_history", {"data_type_id": data_type_id, "history_id": 999}
        )
        assert is_error is True
        assert payload["error"] == "history not found"

    def test_the_history_tools_are_registered(self) -> None:
        names = {tool.name for tool in mcp_tools.tools()}
        assert {"get_data_type_history", "revert_data_type_history"} <= names

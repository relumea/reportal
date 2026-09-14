"""Tests for signature-edit history and revert: domain, API, CLI and MCP."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, journal, mcp_server, mcp_tools, signatures, store
from reportal._paths import DB_ENV

runner = CliRunner()

PLAIN = "unsigned int sub_1005640(unsigned int a0, unsigned int a1)\n{\n  return 0;\n}\n"


def _without_timestamp(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """A signature row without ``updated_at``, which a revert rewrites by design.

    The row is otherwise the state the revert restored; comparing the whole row
    would fail whenever the write and its revert land in different seconds.
    """
    if row is None:
        return None
    return {key: value for key, value in row.items() if key != "updated_at"}


def _seed_binary(conn: sqlite3.Connection, *, sha256: str = "ab" * 32) -> int:
    return store.add_binary(conn, sha256=sha256, name="demo.exe")


def _seed_function(conn: sqlite3.Connection, binary_id: int, *, code: str | None = PLAIN) -> int:
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16, status="STUB"
    )
    if code is not None:
        store.set_decompilation(conn, function_id, code, "kuna")
    return function_id


def _seeded(conn: sqlite3.Connection) -> tuple[int, int]:
    """A binary and function whose signature was seeded from a decompilation."""
    binary_id = _seed_binary(conn)
    function_id = _seed_function(conn, binary_id)
    signatures.seed_signatures(conn, binary_id=binary_id)
    return binary_id, function_id


def _legacy(conn: sqlite3.Connection) -> tuple[int, int]:
    """A binary and function whose signature row predates the history table."""
    binary_id = _seed_binary(conn)
    function_id = _seed_function(conn, binary_id)
    store.upsert_signature(
        conn,
        function_id=function_id,
        name="legacy",
        return_type="int",
        calling_convention="stdcall",
        parameters=[{"index": 0, "type": "int", "name": "arg"}],
        source="",
    )
    return binary_id, function_id


def _call(name: str, arguments: dict[str, Any] | None = None) -> tuple[Any, bool]:
    """Run one MCP tool through ``tools/call``; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestHistoryRecording:
    def test_seeding_records_the_creation(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        history = signatures.list_history(conn, function_id)
        assert len(history) == 1
        assert history[0]["previous"] is None
        assert history[0]["source"] == signatures.SOURCE_DECOMPILATION

    def test_a_mutation_records_the_previous_state(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        before = store.get_signature(conn, function_id)
        assert before is not None

        signatures.set_return_type(conn, function_id, return_type="char *")

        history = signatures.list_history(conn, function_id)
        assert len(history) == 2
        assert history[0]["previous"] == {
            "name": before["name"],
            "return_type": before["return_type"],
            "calling_convention": before["calling_convention"],
            "parameters": before["parameters"],
            "source": before["source"],
        }
        assert history[0]["source"] == signatures.SOURCE_MANUAL

    def test_every_edit_shape_records_history(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        signatures.set_calling_convention(conn, function_id, calling_convention="stdcall")
        signatures.set_parameter(conn, function_id, index=0, name="count")
        signatures.add_parameter(conn, function_id, type_text="char *", name="buffer")
        signatures.remove_parameter(conn, function_id, index=1)
        assert len(signatures.list_history(conn, function_id)) == 5

    def test_delete_records_the_deleted_row(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        assert signatures.delete_signature(conn, function_id) is True
        history = signatures.list_history(conn, function_id)
        assert history[0]["previous"] is not None
        assert history[0]["previous"]["name"] == "sub_1005640"

    def test_a_history_row_carries_the_prototype_it_replaced(
        self, conn: sqlite3.Connection
    ) -> None:
        _, function_id = _seeded(conn)
        before = signatures.get_signature(conn, function_id)
        assert before is not None

        signatures.set_return_type(conn, function_id, return_type="char *")

        history = signatures.list_history(conn, function_id)
        # Rendered through the same renderer the CLI and the header export use.
        assert history[0]["prototype"] == signatures.render_prototype(before)
        assert history[0]["prototype"].startswith("unsigned int sub_1005640(")
        # The seeding row replaced no state, so it has nothing to render.
        assert history[1]["prototype"] is None


class TestRevert:
    def test_revert_restores_the_stored_row_exactly(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        before = store.get_signature(conn, function_id)
        assert before is not None
        signatures.add_parameter(conn, function_id, type_text="int", name="extra")
        edited = store.get_signature(conn, function_id)
        assert edited is not None
        assert edited != before

        target = signatures.list_history(conn, function_id)[0]["id"]
        result = signatures.revert_history(conn, function_id, target)
        assert result["changed"] is True

        restored = store.get_signature(conn, function_id)
        assert _without_timestamp(restored) == _without_timestamp(before)

    def test_revert_of_a_delete_puts_the_row_back(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        before = store.get_signature(conn, function_id)
        signatures.delete_signature(conn, function_id)
        history = signatures.list_history(conn, function_id)
        entry_id = history[0]["id"]

        result = signatures.revert_history(conn, function_id, entry_id)

        assert result["changed"] is True
        assert _without_timestamp(store.get_signature(conn, function_id)) == _without_timestamp(
            before
        )

    def test_second_revert_is_a_no_op(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        signatures.set_return_type(conn, function_id, return_type="char *")
        entry_id = signatures.list_history(conn, function_id)[0]["id"]

        first = signatures.revert_history(conn, function_id, entry_id)
        assert first["changed"] is True
        count_after_first = len(signatures.list_history(conn, function_id))

        second = signatures.revert_history(conn, function_id, entry_id)
        assert second["changed"] is False
        assert second["signature"] == first["signature"]
        assert len(signatures.list_history(conn, function_id)) == count_after_first

    def test_unknown_history_raises(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.UnknownHistoryError):
            signatures.revert_history(conn, function_id, 999)

    def test_history_of_another_function_raises(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        first = _seed_function(conn, binary_id)
        second = _seed_function(conn, binary_id)
        signatures.seed_signatures(conn, binary_id=binary_id)
        entry_id = signatures.list_history(conn, first)[0]["id"]
        with pytest.raises(signatures.UnknownHistoryError):
            signatures.revert_history(conn, second, entry_id)


class TestLegacyRow:
    def test_legacy_row_reads_with_empty_history(self, conn: sqlite3.Connection) -> None:
        _, function_id = _legacy(conn)
        assert signatures.get_signature(conn, function_id) is not None
        assert signatures.list_history(conn, function_id) == []

    def test_legacy_row_reverts_to_its_original_state(self, conn: sqlite3.Connection) -> None:
        _, function_id = _legacy(conn)
        legacy = signatures.get_signature(conn, function_id)
        assert legacy is not None

        signatures.set_return_type(conn, function_id, return_type="unsigned long")
        entry_id = signatures.list_history(conn, function_id)[0]["id"]
        result = signatures.revert_history(conn, function_id, entry_id)

        assert result["changed"] is True
        # `updated_at` is stamped by the write this test makes, so it is the one
        # field a revert cannot restore to the second; every field that
        # describes the signature itself has to come back unchanged.
        assert _without_timestamp(
            signatures.get_signature(conn, function_id)
        ) == _without_timestamp(legacy)


class TestApiRoutes:
    def test_history_route_lists_the_edit(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        _, function_id = _seeded(conn)
        signatures.set_return_type(conn, function_id, return_type="char *")
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/signature/history"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["function_id"] == function_id
        assert payload["count"] == 2
        assert payload["history"][0]["previous"]["return_type"] == "unsigned int"
        assert payload["history"][0]["prototype"].startswith("unsigned int sub_1005640(")
        assert payload["history"][1]["prototype"] is None

    def test_history_route_unknown_function_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/signature/history")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_history_route_empty_for_a_legacy_row(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        _, function_id = _legacy(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{function_id}/signature/history"
        )
        assert status.startswith("200")
        assert json_body(body, headers)["history"] == []

    def test_revert_route_restores_and_journals(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        _, function_id = _seeded(conn)
        before = store.get_signature(conn, function_id)
        signatures.set_return_type(conn, function_id, return_type="char *")
        entry_id = signatures.list_history(conn, function_id)[0]["id"]

        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{function_id}/signature/history/{entry_id}/revert"
        )

        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["changed"] is True
        assert _without_timestamp(payload["signature"]) == _without_timestamp(before)
        assert payload["journal_action"]
        assert _without_timestamp(store.get_signature(conn, function_id)) == _without_timestamp(
            before
        )

    def test_revert_route_journal_action_reverts_the_revert(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        _, function_id = _seeded(conn)
        signatures.set_return_type(conn, function_id, return_type="char *")
        edited = store.get_signature(conn, function_id)
        entry_id = signatures.list_history(conn, function_id)[0]["id"]

        _, headers, body = wsgi_request(
            "POST", f"/api/functions/{function_id}/signature/history/{entry_id}/revert"
        )
        payload = json_body(body, headers)
        action = payload["journal_action"]
        count_after_revert = len(signatures.list_history(conn, function_id))

        journal.revert_action(conn, action)

        assert store.get_signature(conn, function_id) == edited
        assert len(signatures.list_history(conn, function_id)) == count_after_revert - 1

    def test_revert_route_unknown_history_404(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        _, function_id = _seeded(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{function_id}/signature/history/999/revert"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "history not found"

    def test_edit_journal_action_restores_the_row_and_drops_the_history(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        _, function_id = _seeded(conn)
        before = store.get_signature(conn, function_id)
        count_before = len(signatures.list_history(conn, function_id))

        status, headers, body = wsgi_request(
            "PATCH",
            f"/api/functions/{function_id}/signature",
            body=json.dumps({"return_type": "char *"}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("200")
        action = json_body(body, headers)["journal_action"]
        assert store.get_signature(conn, function_id) != before

        journal.revert_action(conn, action)

        assert _without_timestamp(store.get_signature(conn, function_id)) == _without_timestamp(
            before
        )
        assert len(signatures.list_history(conn, function_id)) == count_before

    def test_revert_route_unknown_function_404(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        _seeded(conn)
        status, headers, body = wsgi_request(
            "POST", "/api/functions/999/signature/history/1/revert"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"


class TestCli:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id, function_id = _seeded(conn)
        return {"binary": binary_id, "function": function_id}

    def test_history_command(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            signatures.set_return_type(conn, ids["function"], return_type="char *")

        result = runner.invoke(cli.app, ["signature-history", str(ids["function"]), "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["count"] == 2
        assert payload["history"][0]["previous"]["return_type"] == "unsigned int"

    def test_revert_command_restores(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            before = store.get_signature(conn, ids["function"])
            signatures.set_return_type(conn, ids["function"], return_type="char *")
            entry_id = signatures.list_history(conn, ids["function"])[0]["id"]

        result = runner.invoke(
            cli.app,
            ["signature-revert", str(ids["function"]), str(entry_id), "--json"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["changed"] is True
        assert payload["journal_action"]
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            assert _without_timestamp(
                store.get_signature(conn, ids["function"])
            ) == _without_timestamp(before)

    def test_history_command_unknown_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature-history", "999"])
        assert result.exit_code != 0
        assert "no function with id 999" in result.output


class TestMcp:
    def test_history_tool_lists_the_edit(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        signatures.set_return_type(conn, function_id, return_type="char *")
        payload, is_error = _call("get_signature_history", {"function_id": function_id})
        assert is_error is False
        assert payload["count"] == 2

    def test_revert_tool_reaches_the_same_domain_call(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        before = store.get_signature(conn, function_id)
        signatures.set_return_type(conn, function_id, return_type="char *")
        entry_id = signatures.list_history(conn, function_id)[0]["id"]

        payload, is_error = _call(
            "revert_signature_history",
            {"function_id": function_id, "history_id": entry_id},
        )

        assert is_error is False
        assert payload["changed"] is True
        assert _without_timestamp(payload["signature"]) == _without_timestamp(before)
        assert _without_timestamp(store.get_signature(conn, function_id)) == _without_timestamp(
            before
        )

    def test_revert_tool_unknown_history_is_an_error(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        payload, is_error = _call(
            "revert_signature_history", {"function_id": function_id, "history_id": 999}
        )
        assert is_error is True
        assert payload["error"] == "history not found"


class TestRegistry:
    def test_the_history_tools_are_registered(self) -> None:
        names = {tool.name for tool in mcp_tools.tools()}
        assert {"get_signature_history", "revert_signature_history"} <= names

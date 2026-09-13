"""Tests for the persisted action journal and the writers wired through it."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any, cast

import pytest
from conftest import FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import (
    cli,
    effects,
    engines,
    journal,
    knowledge,
    llm,
    mcp_server,
    pdf,
    store,
)

runner = CliRunner()

# Boundary used by the multipart upload builder.
BOUNDARY = "----reportal-journal-test"


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16, status="STUB"
    )
    second = store.add_function(
        conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=8, status="EXACT"
    )
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id, "second": second}


def _log_with(
    conn: sqlite3.Connection, action: str, *records: tuple[str, str, dict[str, Any]]
) -> journal.Journal:
    log = journal.Journal(conn, action)
    for kind, description, descriptor in records:
        log.record(kind, description, descriptor)
    log.flush()
    return log


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A reportal workspace marker in *tmp_path* with the cwd moved there."""
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _multipart(content: bytes) -> tuple[bytes, dict[str, str]]:
    part = b'Content-Disposition: form-data; name="file"; filename="demo.exe"\r\n\r\n' + content
    body = f"--{BOUNDARY}\r\n".encode() + part + b"\r\n" + f"--{BOUNDARY}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}


def _call_tool(name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
    """Run one MCP tool through ``tools/call``; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestRowHelpers:
    def test_snapshot_returns_the_matching_rows(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        rows = journal.snapshot_rows(
            conn, table="functions", where="analysis_id = ?", params=(ids["analysis"],)
        )
        assert [row["va"] for row in rows] == [0x1000, 0x2000]

    def test_row_restore_descriptor_restores_an_update(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        before = journal.snapshot_rows(
            conn, table="functions", where="id = ?", params=(ids["function"],)
        )
        conn.execute(
            "UPDATE functions SET name = ?, status = ? WHERE id = ?",
            ("renamed", "EXACT", ids["function"]),
        )
        conn.commit()
        effects.apply_descriptor(conn, journal.row_restore_descriptor("functions", before))
        row = store.get_function(conn, ids["function"])
        assert row is not None
        assert row["name"] == "sub_1000"
        assert row["status"] == "STUB"

    def test_row_restore_re_inserts_a_deleted_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        rows = journal.snapshot_rows(conn, table="comments", where="1 = 0")
        assert rows == []
        comment = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="note"
        )
        snapshot = journal.snapshot_rows(
            conn, table="comments", where="id = ?", params=(comment["id"],)
        )
        store.delete_comment(conn, int(comment["id"]))
        effects.apply_descriptor(conn, journal.row_restore_descriptor("comments", snapshot))
        restored = store.get_comment(conn, int(comment["id"]))
        assert restored is not None
        assert restored["body"] == "note"

    def test_row_delete_descriptor_removes_an_inserted_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        comment = store.add_comment(
            conn, scope_kind="function", scope_id=ids["function"], author="a", body="note"
        )
        entry = effects.apply_descriptor(
            conn, journal.row_delete_descriptor("comments", int(comment["id"]))
        )
        assert entry["status"] == effects.EFFECT_REVERTED
        assert store.get_comment(conn, int(comment["id"])) is None

    def test_row_delete_descriptor_accepts_a_composite_key(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        tag_id = store.create_tag(conn, "release")
        store.add_binary_tag(conn, ids["binary"], tag_id)
        effects.apply_descriptor(
            conn,
            journal.row_delete_descriptor(
                "binary_tags", {"binary_id": ids["binary"], "tag_id": tag_id}
            ),
        )
        assert store.get_binary_tags(conn, ids["binary"]) == []

    def test_row_restore_rejects_a_bad_table_name(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError):
            effects.apply_descriptor(
                conn,
                {
                    "kind": effects.EFFECT_ROW_RESTORE,
                    "table": "functions; drop",
                    "columns": ["id"],
                    "rows": [{"id": 1}],
                },
            )

    def test_quote_identifier_rejects_a_bad_name(self) -> None:
        assert journal.quote_identifier("functions") == '"functions"'
        with pytest.raises(ValueError):
            journal.quote_identifier("bad name")


class TestFileHelpers:
    def test_file_delete_descriptor_removes_the_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        written = tmp_path / "stored.bin"
        written.write_bytes(b"payload")
        entry = effects.apply_descriptor(conn, journal.file_delete_descriptor(str(written)))
        assert entry["status"] == effects.EFFECT_REMOVED
        assert not written.exists()

    def test_file_delete_reports_a_file_already_gone(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        entry = effects.apply_descriptor(
            conn, journal.file_delete_descriptor(str(tmp_path / "absent.bin"))
        )
        assert entry["status"] == effects.EFFECT_MISSING

    def test_file_restore_descriptor_writes_the_bytes_back(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = tmp_path / "restored.bin"
        effects.apply_descriptor(conn, journal.file_restore_descriptor(str(target), b"payload"))
        assert target.read_bytes() == b"payload"

    def test_oversized_file_restore_is_partial(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(journal, "MAX_FILE_BYTES", 4)
        target = tmp_path / "big.bin"
        descriptor = journal.file_restore_descriptor(str(target), b"0123456789")
        assert descriptor["partial"] is True
        assert "data_b64" not in descriptor
        entry = effects.apply_descriptor(conn, descriptor)
        assert entry["status"] == effects.EFFECT_PARTIAL
        assert not target.exists()

    def test_read_bounded_stops_at_the_cap(self, tmp_path: Path) -> None:
        target = tmp_path / "big.bin"
        target.write_bytes(b"x" * 10)
        assert len(journal.read_bounded(target, 4)) == 5


class TestJournalRecordFlush:
    def test_flush_writes_the_pending_entries(self, conn: sqlite3.Connection) -> None:
        log = journal.Journal(conn, "act-1")
        log.record(
            effects.EFFECT_ROW_DELETE, "delete row 1", journal.row_delete_descriptor("tags", 1)
        )
        assert log.flush() == 1
        entries = journal.list_entries(conn)
        assert [(entry["action"], entry["status"]) for entry in entries] == [("act-1", "active")]
        assert entries[0]["kind"] == effects.EFFECT_ROW_DELETE

    def test_flush_with_nothing_pending_writes_nothing(self, conn: sqlite3.Connection) -> None:
        log = journal.Journal(conn, "act-1")
        assert log.flush() == 0
        assert journal.list_entries(conn) == []

    def test_record_rejects_an_unserializable_descriptor(self, conn: sqlite3.Connection) -> None:
        log = journal.Journal(conn, "act-1")
        with pytest.raises(TypeError):
            log.record("probe", "bad", {"value": {1, 2}})

    def test_attach_adds_the_field_only_after_a_write(self, conn: sqlite3.Connection) -> None:
        empty = journal.Journal(conn, "act-empty")
        assert empty.attach({"ok": True}) == {"ok": True}
        log = journal.Journal(conn, "act-2")
        log.record(effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1))
        assert log.attach({"ok": True}) == {"ok": True, "journal_action": "act-2"}


class TestRevert:
    def test_revert_applies_newest_first(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        first = journal.snapshot_rows(
            conn, table="functions", where="id = ?", params=(ids["function"],)
        )
        renamed = dict(first[0])
        renamed["name"] = "second-name"
        _log_with(
            conn,
            "act-order",
            (
                effects.EFFECT_ROW_RESTORE,
                "restore sub_1000",
                journal.row_restore_descriptor("functions", first),
            ),
            (
                effects.EFFECT_ROW_RESTORE,
                "restore second-name",
                journal.row_restore_descriptor("functions", [renamed]),
            ),
        )
        conn.execute("UPDATE functions SET name = 'current' WHERE id = ?", (ids["function"],))
        conn.commit()
        report = journal.revert_action(conn, "act-order")
        assert report["reverted"] == 2
        row = store.get_function(conn, ids["function"])
        assert row is not None
        assert row["name"] == "sub_1000"

    def test_revert_marks_the_entries_reverted(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        journal.revert_action(conn, "act-1")
        assert [entry["status"] for entry in journal.list_entries(conn)] == ["reverted"]

    def test_revert_is_idempotent(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        assert journal.revert_action(conn, "act-1")["reverted"] == 1
        again = journal.revert_action(conn, "act-1")
        assert again == {
            "action": "act-1",
            "entries": [],
            "reverted": 0,
            "partial": 0,
            "failed": 0,
        }

    def test_revert_unknown_action_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(journal.UnknownActionError):
            journal.revert_action(conn, "never-recorded")

    def test_revert_from_a_fresh_connection(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        ids = _seed(conn)
        comment = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="note"
        )
        _log_with(
            conn,
            "act-cross",
            (
                effects.EFFECT_ROW_DELETE,
                f"stored comment {comment['id']}",
                journal.row_delete_descriptor("comments", int(comment["id"])),
            ),
        )
        with contextlib.closing(store.connect(portal_db)) as fresh:
            report = journal.revert_action(fresh, "act-cross")
        assert report["reverted"] == 1
        assert store.get_comment(conn, int(comment["id"])) is None

    def test_one_failed_inverse_does_not_strand_the_rest(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        comment = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="note"
        )
        _log_with(
            conn,
            "act-fail",
            (
                effects.EFFECT_ROW_DELETE,
                f"stored comment {comment['id']}",
                journal.row_delete_descriptor("comments", int(comment["id"])),
            ),
            (
                effects.EFFECT_ROW_DELETE,
                "bad",
                {"kind": effects.EFFECT_ROW_DELETE, "table": "nope"},
            ),
        )
        report = journal.revert_action(conn, "act-fail")
        assert report["failed"] == 1
        assert report["reverted"] == 1
        assert store.get_comment(conn, int(comment["id"])) is None

    def test_partial_file_restore_marks_the_entry_partial(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(journal, "MAX_FILE_BYTES", 2)
        _log_with(
            conn,
            "act-partial",
            (
                effects.EFFECT_FILE_RESTORE,
                "deleted file",
                journal.file_restore_descriptor(str(tmp_path / "big.bin"), b"123456"),
            ),
        )
        report = journal.revert_action(conn, "act-partial")
        assert report["partial"] == 1
        assert report["reverted"] == 0
        assert report["failed"] == 0
        assert [entry["status"] for entry in journal.list_entries(conn)] == ["partial"]


class TestEntryRevert:
    def test_revert_entry_applies_one(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        comment = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="note"
        )
        _log_with(
            conn,
            "act-1",
            (
                effects.EFFECT_ROW_DELETE,
                "stored comment",
                journal.row_delete_descriptor("comments", int(comment["id"])),
            ),
        )
        entry_id = int(journal.list_entries(conn)[0]["id"])
        report = journal.revert_entry(conn, entry_id)
        assert report["status"] == journal.STATUS_REVERTED
        assert store.get_comment(conn, int(comment["id"])) is None

    def test_revert_entry_unknown_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(journal.UnknownEntryError):
            journal.revert_entry(conn, 4242)

    def test_revert_entry_already_reverted_raises(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        entry_id = int(journal.list_entries(conn)[0]["id"])
        journal.revert_entry(conn, entry_id)
        with pytest.raises(journal.EntryNotActiveError):
            journal.revert_entry(conn, entry_id)

    def test_revert_entry_unknown_kind_reports_failure(self, conn: sqlite3.Connection) -> None:
        _log_with(conn, "act-1", ("no-such-kind", "d", {"kind": "no-such-kind"}))
        entry_id = int(journal.list_entries(conn)[0]["id"])
        report = journal.revert_entry(conn, entry_id)
        assert report["status"] == journal.STATUS_ACTIVE
        assert report["detail"]
        assert journal.list_entries(conn)[0]["status"] == "active"


class TestListAndPrune:
    def test_list_entries_is_newest_first(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "first", journal.row_delete_descriptor("tags", 1)),
        )
        _log_with(
            conn,
            "act-2",
            (effects.EFFECT_ROW_DELETE, "second", journal.row_delete_descriptor("tags", 2)),
        )
        descriptions = [entry["description"] for entry in journal.list_entries(conn)]
        assert descriptions == ["second", "first"]

    def test_list_entries_filters_by_action(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "first", journal.row_delete_descriptor("tags", 1)),
        )
        _log_with(
            conn,
            "act-2",
            (effects.EFFECT_ROW_DELETE, "second", journal.row_delete_descriptor("tags", 2)),
        )
        entries = journal.list_entries(conn, action="act-1")
        assert [entry["description"] for entry in entries] == ["first"]

    def test_list_entries_honours_the_limit(self, conn: sqlite3.Connection) -> None:
        for index in range(3):
            _log_with(
                conn,
                f"act-{index}",
                (
                    effects.EFFECT_ROW_DELETE,
                    f"entry {index}",
                    journal.row_delete_descriptor("tags", index + 1),
                ),
            )
        assert len(journal.list_entries(conn, limit=2)) == 2

    def test_list_entries_rejects_a_non_positive_limit(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError):
            journal.list_entries(conn, limit=0)

    def test_list_entries_omits_the_descriptor(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        entry = journal.list_entries(conn)[0]
        assert "descriptor_json" not in entry
        assert "descriptor" not in entry

    def test_prune_entries_keeps_the_newest(self, conn: sqlite3.Connection) -> None:
        for index in range(3):
            _log_with(
                conn,
                f"act-{index}",
                (
                    effects.EFFECT_ROW_DELETE,
                    f"entry {index}",
                    journal.row_delete_descriptor("tags", index + 1),
                ),
            )
        assert journal.prune_entries(conn, keep=1) == 2
        assert [entry["action"] for entry in journal.list_entries(conn)] == ["act-2"]

    def test_prune_entries_keep_zero_empties_the_table(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        assert journal.prune_entries(conn, keep=0) == 1
        assert journal.list_entries(conn) == []


class TestContextManager:
    def test_flushes_on_clean_exit(self, conn: sqlite3.Connection) -> None:
        with journal.journaled(conn, "act-1") as log:
            log.record(effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1))
        assert len(journal.list_entries(conn, action="act-1")) == 1

    def test_does_not_flush_on_exception(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(RuntimeError), journal.journaled(conn, "act-1") as log:
            log.record(effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1))
            raise RuntimeError("boom")
        assert journal.list_entries(conn, action="act-1") == []


class TestApiRoutes:
    def test_list_route_answers_entries(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        status, headers, body = wsgi_request("GET", "/api/journal?limit=5")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["entries"][0]["action"] == "act-1"

    def test_list_route_rejects_a_bad_limit(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/journal?limit=0")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "limit must be positive"

    def test_action_route_unknown_is_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/journal/never")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "action not found"

    def test_action_route_answers_one_action(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        status, headers, body = wsgi_request("GET", "/api/journal/act-1")
        assert status.startswith("200")
        assert json_body(body, headers)["action"] == "act-1"

    def test_revert_rejects_an_empty_body(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/journal/revert", body=json.dumps({}))
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid body"

    def test_revert_rejects_both_selectors(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST",
            "/api/journal/revert",
            body=json.dumps({"action": "act-1", "entry_id": 1}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid body"

    def test_revert_unknown_entry_is_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"entry_id": 4242})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "entry not found"

    def test_revert_unknown_action_is_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"action": "never"})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "action not found"

    def test_upload_revert_removes_the_row_and_file(
        self, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        body, headers = _multipart(b"fresh upload")
        status, headers, raw = wsgi_request("POST", "/api/binaries", body=body, headers=headers)
        assert status.startswith("200")
        uploaded = json_body(raw, headers)
        action = uploaded["journal_action"]
        path = Path(str(uploaded["path"]))
        assert path.is_file()
        assert store.get_binary(conn, int(uploaded["id"])) is not None

        status, _, raw = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"action": action})
        )
        assert status.startswith("200")
        assert store.get_binary(conn, int(uploaded["id"])) is None
        assert not path.exists()

    def test_bulk_delete_revert_restores_binaries_and_tags(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        tag_id = store.create_tag(conn, "release")
        store.add_binary_tag(conn, ids["binary"], tag_id)
        status, headers, body = wsgi_request(
            "POST",
            "/api/binaries/bulk",
            body=json.dumps({"action": "delete", "binary_ids": [ids["binary"]]}),
        )
        assert status.startswith("200")
        action = json_body(body, headers)["journal_action"]
        assert store.get_binary(conn, ids["binary"]) is None

        status, headers, body = wsgi_request(
            "POST", "/api/journal/revert", body=json.dumps({"action": action})
        )
        assert status.startswith("200")
        assert store.get_binary(conn, ids["binary"]) is not None
        assert [tag["name"] for tag in store.get_binary_tags(conn, ids["binary"])] == ["release"]
        assert store.get_function(conn, ids["function"]) is not None

    def test_bulk_delete_revert_restores_an_uploaded_file(
        self, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        directory = workspace / "binaries"
        directory.mkdir()
        stored = directory / "stored.bin"
        stored.write_bytes(b"stored bytes")
        binary_id = store.add_binary(
            conn, sha256="ee" * 32, name="stored.bin", path=str(stored), size=12
        )
        status, headers, body = wsgi_request(
            "POST",
            "/api/binaries/bulk",
            body=json.dumps({"action": "delete", "binary_ids": [binary_id]}),
        )
        assert status.startswith("200")
        action = json_body(body, headers)["journal_action"]
        assert not stored.exists()

        wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        assert stored.read_bytes() == b"stored bytes"
        assert store.get_binary(conn, binary_id) is not None

    def test_comment_delete_revert_restores_the_comment(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/comments",
            body=json.dumps({"body": "keep me"}),
        )
        assert status.startswith("201")
        comment_id = int(json_body(body, headers)["id"])
        status, headers, body = wsgi_request("DELETE", f"/api/comments/{comment_id}")
        assert status.startswith("200")
        action = json_body(body, headers)["journal_action"]

        wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        restored = store.get_comment(conn, comment_id)
        assert restored is not None
        assert restored["body"] == "keep me"

    def test_rename_revert_restores_name_and_drops_history(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/functions/{ids['function']}/rename",
            body=json.dumps({"name": "parse_header", "actor": "tester"}),
        )
        assert status.startswith("200")
        action = json_body(body, headers)["journal_action"]
        assert len(store.list_name_history(conn, ids["function"])) == 1

        wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        row = store.get_function(conn, ids["function"])
        assert row is not None
        assert row["name"] == "sub_1000"
        assert store.list_name_history(conn, ids["function"]) == []

    def test_history_revert_is_itself_revertible(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.rename_function(conn, ids["function"], new_name="parse_header", actor="tester")
        history_id = int(store.list_name_history(conn, ids["function"])[0]["id"])
        status, headers, body = wsgi_request(
            "POST", f"/api/functions/{ids['function']}/history/{history_id}/revert"
        )
        assert status.startswith("200")
        action = json_body(body, headers)["journal_action"]
        assert cast(dict[str, Any], store.get_function(conn, ids["function"]))["name"] == "sub_1000"

        wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        row = store.get_function(conn, ids["function"])
        assert row is not None
        assert row["name"] == "parse_header"
        assert len(store.list_name_history(conn, ids["function"])) == 1

    def test_scan_revert_restores_the_previous_row(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: FakeEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        binary_id = store.add_binary(conn, sha256="e1" * 32, name="demo.exe", path=str(target))
        payloads = iter(
            [
                {"format": "pe", "counts": {"sections": 1}, "marker": "first"},
                {"format": "pe", "counts": {"sections": 2}, "marker": "second"},
            ]
        )
        monkeypatch.setattr(fake_engine, "pe_info", lambda binary: dict(next(payloads)))
        engines.set_engine(fake_engine)

        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("200")
        first = json_body(body, headers)
        first.pop("journal_action")

        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/pe-info")
        assert status.startswith("200")
        second = json_body(body, headers)
        action = second["journal_action"]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert (
            cast(dict[str, Any], store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_PE_INFO))[
                "marker"
            ]
            == "second"
        )

        wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        restored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_PE_INFO)
        assert restored is not None
        assert restored["marker"] == "first"
        assert restored["counts"] == first["counts"]

    def test_first_scan_revert_removes_the_row(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        fake_engine: FakeEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        binary_id = store.add_binary(conn, sha256="e2" * 32, name="demo.exe", path=str(target))
        monkeypatch.setattr(fake_engine, "pe_info", lambda binary: {"format": "pe"})
        engines.set_engine(fake_engine)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/pe-info")
        action = json_body(body, headers)["journal_action"]

        wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        # The action created the analysis, so its revert removes the carrier too.
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_knowledge_ingest_revert_removes_documents_and_chunks(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            "/api/documents",
            body=json.dumps(
                {
                    "scope_kind": "binary",
                    "scope_id": ids["binary"],
                    "title": "notes",
                    "text": "a note about the binary",
                }
            ),
        )
        assert status.startswith("201")
        ingested = json_body(body, headers)
        document_id = int(ingested["id"])
        action = ingested["journal_action"]
        assert store.list_chunks(conn, document_id)

        wsgi_request("POST", "/api/journal/revert", body=json.dumps({"action": action}))
        assert store.get_document(conn, document_id) is None
        assert store.list_chunks(conn, document_id) == []

    def test_wired_routes_carry_the_action_field(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['binary']}/comments",
            body=json.dumps({"body": "note"}),
        )
        assert json_body(body, headers)["journal_action"]

        _, headers, body = wsgi_request(
            "POST",
            "/api/binaries/bulk",
            body=json.dumps({"action": "add_tag", "binary_ids": [ids["binary"]], "tag": "t"}),
        )
        assert json_body(body, headers)["journal_action"]

        _, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['binary']}/tags", body=json.dumps({"name": "linked"})
        )
        assert json_body(body, headers)["journal_action"]


class TestCli:
    def test_journal_lists_entries_as_json(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        result = runner.invoke(cli.app, ["journal", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["entries"][0]["action"] == "act-1"

    def test_journal_prints_a_table(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "deleted a row", journal.row_delete_descriptor("tags", 1)),
        )
        result = runner.invoke(cli.app, ["journal"])
        assert result.exit_code == 0, result.output
        assert "deleted a row" in result.output

    def test_journal_revert_action(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        comment = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="note"
        )
        _log_with(
            conn,
            "act-1",
            (
                effects.EFFECT_ROW_DELETE,
                "stored comment",
                journal.row_delete_descriptor("comments", int(comment["id"])),
            ),
        )
        result = runner.invoke(cli.app, ["journal-revert", "--action", "act-1", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["reverted"] == 1
        assert store.get_comment(conn, int(comment["id"])) is None

    def test_journal_revert_entry(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        entry_id = int(journal.list_entries(conn)[0]["id"])
        result = runner.invoke(cli.app, ["journal-revert", "--entry", str(entry_id), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["status"] == "reverted"

    def test_journal_revert_requires_one_selector(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["journal-revert"])
        assert result.exit_code == 1
        assert "exactly one of --action or --entry" in result.output

    def test_journal_revert_unknown_action_fails(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["journal-revert", "--action", "never"])
        assert result.exit_code == 1
        assert "no journal action" in result.output

    def test_bulk_command_reports_a_revertible_action(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = runner.invoke(cli.app, ["bulk-tag", "reviewed", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        action = payload["journal_action"]
        assert action
        assert [tag["name"] for tag in store.get_binary_tags(conn, ids["binary"])] == ["reviewed"]

        revert = runner.invoke(cli.app, ["journal-revert", "--action", action, "--json"])
        assert revert.exit_code == 0, revert.output
        assert store.get_binary_tags(conn, ids["binary"]) == []

    def test_comment_command_prints_the_action_to_stderr(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        result = runner.invoke(cli.app, ["comment-add", "--binary", str(ids["binary"]), "note"])
        assert result.exit_code == 0, result.output
        assert "journal action" in result.output


class TestMcp:
    def test_list_journal_reads_the_entries(self, conn: sqlite3.Connection) -> None:
        _log_with(
            conn,
            "act-1",
            (effects.EFFECT_ROW_DELETE, "d", journal.row_delete_descriptor("tags", 1)),
        )
        payload, is_error = _call_tool("list_journal", {"limit": 5})
        assert not is_error
        assert payload["entries"][0]["action"] == "act-1"

    def test_revert_journal_entry_reverts_an_action(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        comment = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="note"
        )
        _log_with(
            conn,
            "act-1",
            (
                effects.EFFECT_ROW_DELETE,
                "stored comment",
                journal.row_delete_descriptor("comments", int(comment["id"])),
            ),
        )
        payload, is_error = _call_tool("revert_journal_entry", {"action": "act-1"})
        assert not is_error
        assert payload["reverted"] == 1
        assert store.get_comment(conn, int(comment["id"])) is None

    def test_revert_journal_entry_requires_one_selector(self, portal_db: Path) -> None:
        payload, is_error = _call_tool("revert_journal_entry", {})
        assert is_error
        assert payload["error"] == "invalid body"

    def test_revert_journal_entry_unknown_action(self, portal_db: Path) -> None:
        payload, is_error = _call_tool("revert_journal_entry", {"action": "never"})
        assert is_error
        assert payload["error"] == "action not found"


# ── Newly wired writers ────────────────────────────────────────────


def _file_binary(conn: sqlite3.Connection, tmp_path: Path, name: str = "demo.exe") -> int:
    """Register a binary whose file exists on disk, for the engine-backed writers."""
    path = tmp_path / name
    path.write_bytes(b"MZ" + b"\x00" * 30)
    return store.add_binary(conn, sha256=(name + "0" * 64)[:64], name=name, path=str(path))


def _post_json(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """POST a JSON body through the WSGI app, asserting a 2xx and returning the payload."""
    raw = json.dumps(body) if body is not None else ""
    status, headers, data = wsgi_request("POST", path, body=raw)
    assert status.startswith("2"), data
    return cast(dict[str, Any], json_body(data, headers))


def _delete_json(path: str) -> dict[str, Any]:
    status, headers, data = wsgi_request("DELETE", path)
    assert status.startswith("2"), data
    return cast(dict[str, Any], json_body(data, headers))


class TestWiringHelpers:
    def test_journaled_rows_records_a_restore_descriptor(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        log = journal.Journal(conn, "helper-1")
        rows = journal.journaled_rows(
            conn,
            log,
            table="functions",
            where="id = ?",
            params=(ids["function"],),
            description="edited the function",
        )
        assert [row["id"] for row in rows] == [ids["function"]]
        log.flush()
        raw = conn.execute(
            "SELECT descriptor_json FROM journal_entries WHERE action = ?", ("helper-1",)
        ).fetchone()
        descriptor = json.loads(raw["descriptor_json"])
        assert descriptor["kind"] == effects.EFFECT_ROW_RESTORE
        assert descriptor["table"] == "functions"
        assert descriptor["columns"]
        assert descriptor["rows"][0]["name"] == "sub_1000"

    def test_journaled_rows_without_a_match_records_nothing(self, conn: sqlite3.Connection) -> None:
        log = journal.Journal(conn, "helper-2")
        rows = journal.journaled_rows(conn, log, table="functions", where="id = ?", params=(404,))
        assert rows == []
        assert log.recorded() == 0

    def test_journaled_create_records_a_delete_descriptor(self, conn: sqlite3.Connection) -> None:
        log = journal.Journal(conn, "helper-3")
        journal.journaled_create(log, table="tags", key=7, description="created tag 7")
        log.flush()
        raw = conn.execute(
            "SELECT descriptor_json FROM journal_entries WHERE action = ?", ("helper-3",)
        ).fetchone()
        descriptor = json.loads(raw["descriptor_json"])
        assert descriptor["kind"] == effects.EFFECT_ROW_DELETE
        assert descriptor["keys"] == {"id": 7}

    def test_journaled_new_rows_records_only_the_new_rows(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        log = journal.Journal(conn, "helper-4")
        before = journal.journaled_rows(
            conn, log, table="comments", where="scope_kind = ?", params=("binary",)
        )
        store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="note"
        )
        conn.execute("UPDATE journal_entries SET status = 'reverted' WHERE action = 'helper-4'")
        journal.journaled_new_rows(
            conn,
            log,
            table="comments",
            where="scope_kind = ?",
            params=("binary",),
            before=before,
            key=("id",),
        )
        log.flush()
        kinds = [
            row["kind"]
            for row in conn.execute(
                "SELECT kind FROM journal_entries WHERE action = 'helper-4' ORDER BY id"
            )
        ]
        assert kinds == [effects.EFFECT_ROW_DELETE]

    def test_second_revert_is_idempotent(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn, log, table="functions", where="id = ?", params=(ids["function"],)
            )
            store.rename_function(conn, ids["function"], new_name="renamed", actor="t", source="s")
        first = journal.revert_action(conn, action)
        second = journal.revert_action(conn, action)
        assert cast(dict[str, Any], store.get_function(conn, ids["function"]))["name"] == "sub_1000"
        assert first["reverted"] == 1
        assert second["entries"] == []
        assert second["reverted"] == 0

    def test_entries_revert_newest_first(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="functions",
                where="id = ?",
                params=(ids["function"],),
                description="first",
            )
            store.rename_function(conn, ids["function"], new_name="renamed", actor="t", source="s")
            journal.journaled_create(log, table="tags", key=7, description="second")
        report = journal.revert_action(conn, action)
        assert [entry["description"] for entry in report["entries"]] == ["second", "first"]


class TestTagRoutes:
    def test_tag_creation_revert_removes_the_tag(self, conn: sqlite3.Connection) -> None:
        payload = _post_json("/api/tags", {"name": "demo"})
        assert payload["journal_action"]
        journal.revert_action(conn, payload["journal_action"])
        assert store.find_tag(conn, "demo") is None

    def test_existing_tag_creation_records_nothing(self, conn: sqlite3.Connection) -> None:
        store.create_tag(conn, "demo")
        payload = _post_json("/api/tags", {"name": "demo"})
        assert "journal_action" not in payload


class TestAnalysisRoutes:
    def test_analysis_creation_revert_removes_the_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _post_json("/api/analyses", {"binary_id": ids["binary"], "engine": "manual"})
        analysis_id = payload["id"]
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_analysis(conn, analysis_id) is None


class TestCollectionRoutes:
    def test_collection_create_revert_removes_it(self, conn: sqlite3.Connection) -> None:
        payload = _post_json("/api/collections", {"name": "Group"})
        collection_id = payload["id"]
        journal.revert_action(conn, payload["journal_action"])
        assert all(row["id"] != collection_id for row in store.list_collections(conn))

    def test_collection_add_revert_removes_the_link(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        collection_id = store.create_collection(conn, name="Group", description="", scope="")
        payload = _post_json(
            f"/api/collections/{collection_id}/binaries", {"binary_id": ids["binary"]}
        )
        assert payload["added"] is True
        journal.revert_action(conn, payload["journal_action"])
        rows = conn.execute(
            "SELECT 1 FROM collection_binaries WHERE collection_id = ? AND binary_id = ?",
            (collection_id, ids["binary"]),
        ).fetchone()
        assert rows is None

    def test_collection_add_of_a_known_pair_records_nothing(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        collection_id = store.create_collection(conn, name="Group", description="", scope="")
        store.add_collection_binary(conn, collection_id, ids["binary"])
        payload = _post_json(
            f"/api/collections/{collection_id}/binaries", {"binary_id": ids["binary"]}
        )
        assert "journal_action" not in payload


class TestDocumentRoutes:
    def test_document_delete_revert_restores_document_and_chunks(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        payload = knowledge.ingest_document(
            conn,
            scope_kind="binary",
            scope_id=ids["binary"],
            title="notes",
            source="notes.txt",
            mime="",
            data=b"a note about the binary",
        )
        document_id = int(payload["id"])
        assert store.list_chunks(conn, document_id)
        result = _delete_json(f"/api/documents/{document_id}")
        assert store.get_document(conn, document_id) is None
        journal.revert_action(conn, result["journal_action"])
        restored = store.get_document(conn, document_id)
        assert restored is not None
        assert restored["title"] == "notes"
        assert store.list_chunks(conn, document_id)


class TestFamilyRoutes:
    def test_family_register_revert_removes_it(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        payload = _post_json("/api/families", {"name": "Demo", "reference_binary_id": binary_id})
        family_id = payload["family_id"]
        journal.revert_action(conn, payload["journal_action"])
        assert all(row["id"] != family_id for row in store.list_families(conn))

    def test_family_delete_revert_restores_it(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        registered = _post_json("/api/families", {"name": "Demo", "reference_binary_id": binary_id})
        family_id = registered["family_id"]
        payload = _delete_json(f"/api/families/{family_id}")
        assert store.get_family(conn, family_id) is None
        journal.revert_action(conn, payload["journal_action"])
        restored = store.get_family(conn, family_id)
        assert restored is not None
        assert restored["name"] == "Demo"


class TestModelRoutes:
    def test_data_type_edit_revert_restores_the_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        data_type_id = store.add_data_type(
            conn,
            binary_id=ids["binary"],
            name="Player",
            size=4,
            members=[{"name": "field_0", "type": "int", "offset": 0, "size": 4}],
        )
        status, headers, raw = wsgi_request(
            "PATCH", f"/api/data-types/{data_type_id}", body=json.dumps({"name": "PlayerInfo"})
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert cast(dict[str, Any], store.get_data_type(conn, data_type_id))["name"] == "PlayerInfo"
        journal.revert_action(conn, payload["journal_action"])
        assert cast(dict[str, Any], store.get_data_type(conn, data_type_id))["name"] == "Player"

    def test_data_type_member_add_revert_restores_the_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        data_type_id = store.add_data_type(
            conn,
            binary_id=ids["binary"],
            name="Player",
            size=4,
            members=[{"name": "field_0", "type": "int", "offset": 0, "size": 4}],
        )
        payload = _post_json(
            f"/api/data-types/{data_type_id}/members", {"name": "field_4", "type": "int"}
        )
        assert len(cast(dict[str, Any], store.get_data_type(conn, data_type_id))["members"]) == 2
        journal.revert_action(conn, payload["journal_action"])
        assert [
            m["name"]
            for m in cast(dict[str, Any], store.get_data_type(conn, data_type_id))["members"]
        ] == ["field_0"]

    def test_data_type_export_revert_removes_the_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = _seed(conn)
        store.add_data_type(
            conn,
            binary_id=ids["binary"],
            name="Player",
            size=4,
            members=[{"name": "field_0", "type": "int", "offset": 0, "size": 4}],
        )
        target = tmp_path / "types.h"
        payload = _post_json(
            f"/api/binaries/{ids['binary']}/data-types/export", {"path": str(target)}
        )
        assert target.is_file()
        journal.revert_action(conn, payload["journal_action"])
        assert not target.exists()

    def test_signature_edit_revert_restores_the_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.upsert_signature(
            conn,
            function_id=ids["function"],
            name="sub_1000",
            return_type="void",
            calling_convention="cdecl",
            parameters=[],
        )
        status, headers, raw = wsgi_request(
            "PATCH",
            f"/api/functions/{ids['function']}/signature",
            body=json.dumps({"return_type": "int"}),
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert (
            cast(dict[str, Any], store.get_signature(conn, ids["function"]))["return_type"] == "int"
        )
        journal.revert_action(conn, payload["journal_action"])
        assert (
            cast(dict[str, Any], store.get_signature(conn, ids["function"]))["return_type"]
            == "void"
        )

    def test_signature_parameter_add_revert_restores_the_row(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        store.upsert_signature(
            conn,
            function_id=ids["function"],
            name="sub_1000",
            return_type="void",
            calling_convention="cdecl",
            parameters=[],
        )
        payload = _post_json(
            f"/api/functions/{ids['function']}/signature/parameters",
            {"type": "int", "name": "count"},
        )
        assert [
            p["name"]
            for p in cast(dict[str, Any], store.get_signature(conn, ids["function"]))["parameters"]
        ] == ["count"]
        journal.revert_action(conn, payload["journal_action"])
        assert cast(dict[str, Any], store.get_signature(conn, ids["function"]))["parameters"] == []

    def test_ai_artifact_write_revert_removes_it(
        self, conn: sqlite3.Connection, fake_llm: Any
    ) -> None:
        ids = _seed(conn)
        store.set_decompilation(conn, ids["function"], "int f(void) { return 0; }", "kuna")
        payload = _post_json(f"/api/functions/{ids['function']}/summary")
        assert payload["journal_action"]
        assert store.get_ai_artifact(conn, ids["function"], llm.AI_KIND_SUMMARY) is not None
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_ai_artifact(conn, ids["function"], llm.AI_KIND_SUMMARY) is None


class TestGraphRoute:
    def test_graph_rebuild_revert_restores_the_prior_graph(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        first = _post_json(f"/api/binaries/{ids['binary']}/graph")
        node_id = f"b{ids['binary']}:function:{ids['function']}"
        label = conn.execute("SELECT label FROM graph_nodes WHERE id = ?", (node_id,)).fetchone()
        assert label["label"] == "sub_1000"
        store.rename_function(conn, ids["function"], new_name="renamed", actor="t", source="s")
        second = _post_json(f"/api/binaries/{ids['binary']}/graph")
        assert second["journal_action"]
        changed = conn.execute("SELECT label FROM graph_nodes WHERE id = ?", (node_id,)).fetchone()
        assert changed["label"] == "renamed"
        journal.revert_action(conn, second["journal_action"])
        restored = conn.execute("SELECT label FROM graph_nodes WHERE id = ?", (node_id,)).fetchone()
        assert restored["label"] == "sub_1000"
        assert first["nodes"] == second["nodes"]

    def test_first_graph_rebuild_revert_removes_every_node(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _post_json(f"/api/binaries/{ids['binary']}/graph")
        assert store.count_graph_nodes(conn, ids["binary"]) > 0
        journal.revert_action(conn, payload["journal_action"])
        assert store.count_graph_nodes(conn, ids["binary"]) == 0


class TestPdfRoute:
    def test_pdf_write_revert_removes_the_file(
        self, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        ids = _seed(conn)
        payload = _post_json(f"/api/binaries/{ids['binary']}/report/pdf")
        target = Path(payload["path"])
        assert target.is_file()
        journal.revert_action(conn, payload["journal_action"])
        assert not target.exists()

    def test_pdf_revert_restores_a_previous_file(
        self, conn: sqlite3.Connection, tmp_path: Path, workspace: Path
    ) -> None:
        ids = _seed(conn)
        first = _post_json(f"/api/binaries/{ids['binary']}/report/pdf")
        target = Path(first["path"])
        previous = target.read_bytes()
        second = _post_json(f"/api/binaries/{ids['binary']}/report/pdf")
        assert second["journal_action"]
        journal.revert_action(conn, second["journal_action"])
        assert target.read_bytes() == previous
        assert pdf.page_count(target.read_bytes()) >= 1


class TestConversationRoutes:
    def test_conversation_create_revert_removes_it(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload = _post_json(
            "/api/conversations", {"scope_kind": "binary", "scope_id": ids["binary"]}
        )
        conversation_id = payload["id"]
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_conversation(conn, conversation_id) is None

    def test_conversation_delete_revert_restores_messages(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        conversation_id = store.create_conversation(
            conn, scope_kind="binary", scope_id=ids["binary"], title="chat"
        )
        store.add_message(conn, conversation_id=conversation_id, role="user", content="hello")
        payload = _delete_json(f"/api/conversations/{conversation_id}")
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_conversation(conn, conversation_id) is not None
        assert [m["content"] for m in store.list_messages(conn, conversation_id)] == ["hello"]

    def test_message_send_revert_removes_the_exchange(
        self, conn: sqlite3.Connection, fake_llm: Any
    ) -> None:
        ids = _seed(conn)
        conversation_id = store.create_conversation(
            conn, scope_kind="binary", scope_id=ids["binary"], title="chat"
        )
        payload = _post_json(
            f"/api/conversations/{conversation_id}/messages", {"content": "what is this?"}
        )
        assert payload["journal_action"]
        assert len(store.list_messages(conn, conversation_id)) == 2
        journal.revert_action(conn, payload["journal_action"])
        assert store.list_messages(conn, conversation_id) == []
        assert store.get_conversation(conn, conversation_id) is not None


class TestScanCli:
    def test_scan_cli_journals_and_reverts(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        action = payload["journal_action"]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert analysis_id is not None
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO) is not None
        journal.revert_action(conn, action)
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_scan_cli_leaves_an_existing_analysis(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        seeded = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        result = runner.invoke(cli.app, ["crypto-scan", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        action = json.loads(result.stdout)["journal_action"]
        journal.revert_action(conn, action)
        assert store.latest_analysis_for_binary(conn, binary_id) == seeded
        assert store.get_scan(conn, seeded, store.SCAN_KIND_CRYPTO) is None


class TestMcpWriters:
    def test_tag_binary_revert_removes_tag_and_link(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, is_error = _call_tool("tag_binary", {"binary_id": ids["binary"], "name": "demo"})
        assert not is_error
        action = payload["journal_action"]
        journal.revert_action(conn, action)
        assert store.find_tag(conn, "demo") is None
        assert store.get_binary_tags(conn, ids["binary"]) == []

    def test_untag_binary_revert_restores_the_link(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        tag_id = store.create_tag(conn, "demo")
        store.add_binary_tag(conn, ids["binary"], tag_id)
        payload, is_error = _call_tool(
            "untag_binary", {"binary_id": ids["binary"], "tag_id": tag_id}
        )
        assert not is_error
        journal.revert_action(conn, payload["journal_action"])
        assert [tag["id"] for tag in store.get_binary_tags(conn, ids["binary"])] == [tag_id]

    def test_create_tag_revert_removes_the_tag(self, conn: sqlite3.Connection) -> None:
        payload, is_error = _call_tool("create_tag", {"name": "demo"})
        assert not is_error
        journal.revert_action(conn, payload["journal_action"])
        assert store.find_tag(conn, "demo") is None

    def test_rename_function_revert_restores_name_and_history(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        payload, is_error = _call_tool(
            "rename_function", {"function_id": ids["function"], "name": "renamed"}
        )
        assert not is_error
        assert cast(dict[str, Any], store.get_function(conn, ids["function"]))["name"] == "renamed"
        journal.revert_action(conn, payload["journal_action"])
        assert cast(dict[str, Any], store.get_function(conn, ids["function"]))["name"] == "sub_1000"
        assert store.list_name_history(conn, ids["function"]) == []

    def test_ingest_document_revert_removes_the_document(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, is_error = _call_tool(
            "ingest_document",
            {
                "scope_kind": "binary",
                "scope_id": ids["binary"],
                "title": "notes",
                "text": "a note about the binary",
            },
        )
        assert not is_error
        document_id = int(payload["id"])
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_document(conn, document_id) is None
        assert store.list_chunks(conn, document_id) == []

    def test_delete_document_revert_restores_it(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        seeded = knowledge.ingest_document(
            conn,
            scope_kind="binary",
            scope_id=ids["binary"],
            title="notes",
            source="notes.txt",
            mime="",
            data=b"a note about the binary",
        )
        document_id = int(seeded["id"])
        payload, is_error = _call_tool("delete_document", {"document_id": document_id})
        assert not is_error
        assert store.get_document(conn, document_id) is None
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_document(conn, document_id) is not None
        assert store.list_chunks(conn, document_id)

    def test_create_conversation_revert_removes_it(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, is_error = _call_tool(
            "create_conversation", {"scope_kind": "binary", "scope_id": ids["binary"]}
        )
        assert not is_error
        conversation_id = payload["id"]
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_conversation(conn, conversation_id) is None

    def test_add_comment_revert_removes_it(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        payload, is_error = _call_tool(
            "add_comment",
            {"scope_kind": "binary", "scope_id": ids["binary"], "body": "note"},
        )
        assert not is_error
        comment_id = int(payload["id"])
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_comment(conn, comment_id) is None

    def test_edit_data_type_revert_restores_the_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        data_type_id = store.add_data_type(
            conn,
            binary_id=ids["binary"],
            name="Player",
            size=4,
            members=[{"name": "field_0", "type": "int", "offset": 0, "size": 4}],
        )
        payload, is_error = _call_tool(
            "edit_data_type", {"data_type_id": data_type_id, "name": "PlayerInfo"}
        )
        assert not is_error
        assert cast(dict[str, Any], store.get_data_type(conn, data_type_id))["name"] == "PlayerInfo"
        journal.revert_action(conn, payload["journal_action"])
        assert cast(dict[str, Any], store.get_data_type(conn, data_type_id))["name"] == "Player"

    def test_edit_signature_revert_restores_the_row(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.upsert_signature(
            conn,
            function_id=ids["function"],
            name="sub_1000",
            return_type="void",
            calling_convention="cdecl",
            parameters=[],
        )
        payload, is_error = _call_tool(
            "edit_signature", {"function_id": ids["function"], "return_type": "int"}
        )
        assert not is_error
        assert (
            cast(dict[str, Any], store.get_signature(conn, ids["function"]))["return_type"] == "int"
        )
        journal.revert_action(conn, payload["journal_action"])
        assert (
            cast(dict[str, Any], store.get_signature(conn, ids["function"]))["return_type"]
            == "void"
        )

    def test_run_summary_revert_removes_the_artifact(
        self, conn: sqlite3.Connection, fake_llm: Any
    ) -> None:
        ids = _seed(conn)
        store.set_decompilation(conn, ids["function"], "int f(void) { return 0; }", "kuna")
        payload, is_error = _call_tool("run_summary", {"function_id": ids["function"]})
        assert not is_error
        assert store.get_ai_artifact(conn, ids["function"], llm.AI_KIND_SUMMARY) is not None
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_ai_artifact(conn, ids["function"], llm.AI_KIND_SUMMARY) is None

    def test_run_fingerprint_revert_removes_the_row(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        payload, is_error = _call_tool("run_fingerprint", {"binary_id": binary_id})
        assert not is_error
        assert store.get_fingerprint(conn, binary_id) is not None
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_fingerprint(conn, binary_id) is None

    def test_delete_conversation_revert_restores_it(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        conversation_id = store.create_conversation(
            conn, scope_kind="binary", scope_id=ids["binary"], title="chat"
        )
        payload, is_error = _call_tool("delete_conversation", {"conversation_id": conversation_id})
        assert not is_error
        journal.revert_action(conn, payload["journal_action"])
        assert store.get_conversation(conn, conversation_id) is not None

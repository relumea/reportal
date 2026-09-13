"""Tests for the analyst comment store and its validation layer."""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path

import pytest

from reportal import comments, store


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=48, status="STUB"
    )
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id}


class TestCommentStore:
    def test_add_and_get_round_trip(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        created = store.add_comment(
            conn,
            scope_kind="binary",
            scope_id=ids["binary"],
            author="alice",
            body="first look",
        )
        assert created["id"] > 0
        assert created["created_at"] == created["updated_at"]
        assert store.get_comment(conn, created["id"]) == created

    def test_get_missing_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_comment(conn, 404) is None

    def test_add_rejects_blank_body(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(ValueError):
            store.add_comment(
                conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="   "
            )

    def test_list_filters_by_scope(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_comment(conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="b1")
        store.add_comment(
            conn, scope_kind="function", scope_id=ids["function"], author="a", body="f1"
        )
        assert [row["body"] for row in store.list_comments(conn, scope_kind="binary")] == ["b1"]
        assert [
            row["body"]
            for row in store.list_comments(conn, scope_kind="function", scope_id=ids["function"])
        ] == ["f1"]

    def test_list_without_filter_returns_every_comment(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_comment(conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="b1")
        store.add_comment(
            conn, scope_kind="function", scope_id=ids["function"], author="a", body="f1"
        )
        assert len(store.list_comments(conn)) == 2

    def test_list_is_oldest_first(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        for body in ("one", "two", "three"):
            store.add_comment(
                conn, scope_kind="binary", scope_id=ids["binary"], author="a", body=body
            )
        rows = store.list_comments(conn, scope_kind="binary", scope_id=ids["binary"])
        assert [row["body"] for row in rows] == ["one", "two", "three"]

    def test_update_changes_body_and_timestamp(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        stamps = iter(["2020-01-01T00:00:00+00:00", "2020-01-02T00:00:00+00:00"])
        monkeypatch.setattr(store, "now", lambda: next(stamps))
        created = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="before"
        )
        updated = store.update_comment(conn, created["id"], body="after")
        assert updated is not None
        assert updated["body"] == "after"
        assert updated["created_at"] != updated["updated_at"]

    def test_update_missing_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.update_comment(conn, 404, body="x") is None

    def test_update_rejects_blank_body(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        created = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="body"
        )
        with pytest.raises(ValueError):
            store.update_comment(conn, created["id"], body="   ")

    def test_delete_reports_whether_the_row_existed(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        created = store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="body"
        )
        assert store.delete_comment(conn, created["id"]) is True
        assert store.delete_comment(conn, created["id"]) is False

    def test_list_binaries_carries_the_comment_count(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_comment(conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="b1")
        rows = store.list_binaries(conn)
        assert rows[0]["comment_count"] == 1

    def test_counts_includes_comments(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_comment(conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="b1")
        assert store.counts(conn)["comments"] == 1


class TestCommentValidation:
    def test_default_author(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        created = comments.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], body="note"
        )
        assert created["author"] == comments.DEFAULT_AUTHOR

    def test_explicit_author_is_trimmed(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        created = comments.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], body="note", author="  alice  "
        )
        assert created["author"] == "alice"

    def test_body_is_trimmed(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        created = comments.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], body="  spaced  "
        )
        assert created["body"] == "spaced"

    def test_blank_body_is_invalid(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(comments.InvalidCommentError):
            comments.add_comment(conn, scope_kind="binary", scope_id=ids["binary"], body="  ")

    def test_oversized_body_is_invalid(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        oversized = "x" * (comments.MAX_COMMENT_CHARS + 1)
        with pytest.raises(comments.InvalidCommentError):
            comments.add_comment(conn, scope_kind="binary", scope_id=ids["binary"], body=oversized)

    def test_body_at_the_cap_is_accepted(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        at_cap = "x" * comments.MAX_COMMENT_CHARS
        created = comments.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], body=at_cap
        )
        assert len(created["body"]) == comments.MAX_COMMENT_CHARS

    def test_unknown_scope_kind_is_invalid(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(comments.InvalidCommentError):
            comments.add_comment(conn, scope_kind="analysis", scope_id=1, body="note")

    def test_unknown_binary_scope_is_not_found(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(comments.UnknownScopeError):
            comments.add_comment(conn, scope_kind="binary", scope_id=999, body="note")

    def test_unknown_function_scope_is_not_found(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(comments.UnknownScopeError):
            comments.add_comment(conn, scope_kind="function", scope_id=999, body="note")

    def test_list_unknown_scope_is_not_found(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(comments.UnknownScopeError):
            comments.list_comments(conn, scope_kind="binary", scope_id=999)

    def test_get_unknown_comment_is_not_found(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(comments.UnknownCommentError):
            comments.get_comment(conn, 404)

    def test_update_unknown_comment_is_not_found(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(comments.UnknownCommentError):
            comments.update_comment(conn, 404, body="note")

    def test_delete_unknown_comment_is_not_found(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(comments.UnknownCommentError):
            comments.delete_comment(conn, 404)


class TestDeleteBinaryCascade:
    def test_delete_binary_removes_scoped_rows(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_comment(
            conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="on binary"
        )
        store.add_comment(
            conn, scope_kind="function", scope_id=ids["function"], author="a", body="on function"
        )
        store.create_conversation(
            conn, scope_kind="binary", scope_id=ids["binary"], title="binary chat"
        )
        store.create_conversation(
            conn, scope_kind="function", scope_id=ids["function"], title="function chat"
        )
        store.add_document(
            conn,
            scope_kind="binary",
            scope_id=ids["binary"],
            title="notes",
            source="note.txt",
            mime="text/plain",
            sha256="ab" * 32,
            size=4,
            text="text",
        )
        deleted = store.delete_binary(conn, ids["binary"])
        assert deleted is not None
        assert deleted["functions"] == 1
        assert deleted["comments"] == 2
        assert deleted["conversations"] == 2
        assert deleted["documents"] == 1
        assert store.get_binary(conn, ids["binary"]) is None
        assert store.get_function(conn, ids["function"]) is None
        assert store.list_comments(conn) == []
        assert store.list_conversations(conn) == []
        assert store.list_documents(conn, scope_kind="binary", scope_id=ids["binary"]) == []

    def test_delete_unknown_binary_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.delete_binary(conn, 999) is None

    def test_delete_binary_keeps_other_binaries(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        other = store.add_binary(conn, sha256="bb" * 32, name="other.exe", path="/x/other.exe")
        store.add_comment(conn, scope_kind="binary", scope_id=other, author="a", body="keep")
        assert store.delete_binary(conn, ids["binary"]) is not None
        assert store.get_binary(conn, other) is not None
        assert len(store.list_comments(conn)) == 1


def test_delete_binary_is_hermetic(tmp_path: Path) -> None:
    db = tmp_path / "portal.db"
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        ids = _seed(conn)
        store.add_comment(conn, scope_kind="binary", scope_id=ids["binary"], author="a", body="b")
        store.delete_binary(conn, ids["binary"])
        assert store.counts(conn)["comments"] == 0

"""Tests for the analyst string store.

The module functions are the shared path the routes, the CLI and the MCP tools
all call, so they are asserted directly: validation, the dedupe rule, the scope
bounds, the whole-list replace and the derived half the read reports beside
what a human recorded.
"""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import auth, journal, store, user_strings
from reportal._paths import DB_ENV


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_0")
        store.set_decompilation(
            conn,
            function_id,
            'char *a = "/etc/passwd";\nchar *b = "second";\nchar *c = "/etc/passwd";\n',
            "kuna",
        )
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id, "db": db}


class TestValidation:
    def test_a_value_a_kind_and_a_note_are_validated(self) -> None:
        assert user_strings.normalize_value("  x  ") == "x"
        assert user_strings.normalize_kind(None) == user_strings.KIND_STRING
        assert user_strings.normalize_note(None) == ""
        for value in ("", "   ", 42, None, "x" * (user_strings.MAX_STRING_CHARS + 1)):
            with pytest.raises(user_strings.InvalidStringError):
                user_strings.normalize_value(value)
        with pytest.raises(user_strings.InvalidStringError):
            user_strings.normalize_kind("symbol")
        with pytest.raises(user_strings.InvalidStringError):
            user_strings.normalize_note("x" * (user_strings.MAX_NOTE_CHARS + 1))
        with pytest.raises(user_strings.InvalidStringError):
            user_strings.normalize_note(42)

    def test_a_scope_must_be_a_known_scope_with_a_positive_id(self) -> None:
        assert user_strings.normalize_scope("function", 3) == ("function", 3)
        for scope_kind, scope_id in (("binary", 1), ("function", 0), ("function", True)):
            with pytest.raises(user_strings.InvalidStringError):
                user_strings.normalize_scope(scope_kind, scope_id)

    def test_an_unknown_scope_row_is_a_not_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(user_strings.UnknownStringError),
        ):
            user_strings.check_scope(conn, scope_kind="function", scope_id=999)


class TestStore:
    def test_a_string_is_added_listed_and_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            row = user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="hello",
                note="why",
                actor="me",
            )
            assert row["kind"] == user_strings.KIND_STRING
            assert row["actor"] == "me"
            assert user_strings.list_strings(
                conn, scope_kind=user_strings.SCOPE_FUNCTION, scope_id=ids["function"]
            ) == [row]
            assert user_strings.get_string(conn, string_id=int(row["id"])) == row
            assert (
                user_strings.delete_string(
                    conn,
                    scope_kind=user_strings.SCOPE_FUNCTION,
                    scope_id=ids["function"],
                    string_id=int(row["id"]),
                )
                == row
            )
            assert (
                user_strings.list_strings(
                    conn, scope_kind=user_strings.SCOPE_FUNCTION, scope_id=ids["function"]
                )
                == []
            )

    def test_re_adding_a_value_keeps_its_row_and_updates_the_note(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            first = user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="hello",
            )
            again = user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="hello",
                note="later",
            )
            same = user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="hello",
            )
        assert first["id"] == again["id"] == same["id"]
        assert again["note"] == "later"
        assert same["note"] == "later"

    def test_duplicate_scope_value_kind_is_rejected_by_the_schema(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            user_strings.ensure_schema(conn)
            user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="hello",
            )
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO user_strings"
                    " (scope_kind, scope_id, value, kind, note, actor, created_at)"
                    " VALUES (?, ?, 'hello', 'string', '', '', ?)",
                    (user_strings.SCOPE_FUNCTION, ids["function"], store.now()),
                )

    def test_a_journaled_re_add_snapshots_and_reverts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import journal

        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                first = user_strings.journaled_add(
                    conn,
                    log,
                    scope_kind=user_strings.SCOPE_FUNCTION,
                    scope_id=ids["function"],
                    value="hello",
                )
                again = user_strings.journaled_add(
                    conn,
                    log,
                    scope_kind=user_strings.SCOPE_FUNCTION,
                    scope_id=ids["function"],
                    value="hello",
                    note="later",
                )
            assert first["id"] == again["id"]
            assert again["note"] == "later"
            journal.revert_action(conn, action)
            assert (
                user_strings.list_strings(
                    conn,
                    scope_kind=user_strings.SCOPE_FUNCTION,
                    scope_id=ids["function"],
                )
                == []
            )

    def test_a_different_kind_is_a_different_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="GetProcAddress",
                kind="import",
            )
            user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="GetProcAddress",
            )
            rows = user_strings.list_strings(
                conn, scope_kind=user_strings.SCOPE_FUNCTION, scope_id=ids["function"]
            )
        assert sorted(entry["kind"] for entry in rows) == ["import", "string"]

    def test_the_scope_bound_is_enforced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            for index in range(user_strings.MAX_STRINGS_PER_SCOPE):
                user_strings.add_string(
                    conn,
                    scope_kind=user_strings.SCOPE_ANALYSIS,
                    scope_id=ids["analysis"],
                    value=f"value-{index}",
                )
            with pytest.raises(user_strings.InvalidStringError):
                user_strings.add_string(
                    conn,
                    scope_kind=user_strings.SCOPE_ANALYSIS,
                    scope_id=ids["analysis"],
                    value="one too many",
                )

    def test_a_string_cannot_be_removed_from_another_scope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            row = user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="hello",
            )
            with pytest.raises(user_strings.UnknownStringError):
                user_strings.delete_string(
                    conn,
                    scope_kind=user_strings.SCOPE_ANALYSIS,
                    scope_id=ids["analysis"],
                    string_id=int(row["id"]),
                )
            with pytest.raises(user_strings.UnknownStringError):
                user_strings.get_string(conn, string_id=999)

    def test_the_scope_error_names_what_is_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(user_strings.UnknownStringError) as caught,
        ):
            user_strings.add_string(
                conn, scope_kind=user_strings.SCOPE_ANALYSIS, scope_id=999, value="x"
            )
        assert "no analysis with id 999" in str(caught.value)


class TestReplace:
    def test_the_whole_list_is_replaced_in_order(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_ANALYSIS,
                scope_id=ids["analysis"],
                value="old",
            )
            report = user_strings.replace_strings(
                conn,
                scope_kind=user_strings.SCOPE_ANALYSIS,
                scope_id=ids["analysis"],
                values=["b", "a", "c"],
            )
        assert report["removed"] == 1
        assert [entry["value"] for entry in report["strings"]] == ["b", "a", "c"]

    def test_one_bad_value_leaves_the_store_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_ANALYSIS,
                scope_id=ids["analysis"],
                value="old",
            )
            with pytest.raises(user_strings.InvalidStringError):
                user_strings.replace_strings(
                    conn,
                    scope_kind=user_strings.SCOPE_ANALYSIS,
                    scope_id=ids["analysis"],
                    values=["fine", ""],
                )
            rows = user_strings.list_strings(
                conn, scope_kind=user_strings.SCOPE_ANALYSIS, scope_id=ids["analysis"]
            )
        assert [entry["value"] for entry in rows] == ["old"]

    def test_a_string_or_an_over_long_list_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            for values in ("abc", ["x"] * (user_strings.MAX_STRINGS_PER_SCOPE + 1)):
                with pytest.raises(user_strings.InvalidStringError):
                    user_strings.replace_strings(
                        conn,
                        scope_kind=user_strings.SCOPE_ANALYSIS,
                        scope_id=ids["analysis"],
                        values=values,
                    )

    def test_the_journaled_replace_reverts_to_the_previous_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_ANALYSIS,
                scope_id=ids["analysis"],
                value="old",
            )
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                report = user_strings.journaled_replace(
                    conn,
                    log,
                    scope_kind=user_strings.SCOPE_ANALYSIS,
                    scope_id=ids["analysis"],
                    values=["new"],
                )
                assert log.attach(report)["journal_action"] == action
            assert journal.revert_action(conn, action)["reverted"] > 0
            rows = user_strings.list_strings(
                conn, scope_kind=user_strings.SCOPE_ANALYSIS, scope_id=ids["analysis"]
            )
        assert [entry["value"] for entry in rows] == ["old"]

    def test_the_journaled_replace_on_an_empty_scope_is_revertible(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                user_strings.journaled_replace(
                    conn,
                    log,
                    scope_kind=user_strings.SCOPE_ANALYSIS,
                    scope_id=ids["analysis"],
                    values=["a", "b"],
                )
            assert journal.revert_action(conn, action)["reverted"] > 0
            rows = user_strings.list_strings(
                conn, scope_kind=user_strings.SCOPE_ANALYSIS, scope_id=ids["analysis"]
            )
        assert rows == []


class TestDerivedAndFunctionRead:
    def test_the_literals_are_deduped_and_first_seen_ordered(self) -> None:
        code = 'a("/one"); b("two"); c("/one"); d(\'x\'); e("");\n'
        assert user_strings.derived_literals(code) == ["/one", "two"]
        assert user_strings.derived_literals("") == []
        assert user_strings.derived_literals('"a" "b" "c"', limit=2) == ["a", "b"]

    def test_the_derived_half_drops_what_the_analyst_already_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="/etc/passwd",
                note="why",
            )
            payload = user_strings.function_strings(conn, ids["function"])
        assert payload["counts"] == {"analyst": 1, "derived": 2, "decoded": 0}
        assert [entry["value"] for entry in payload["analyst"]] == ["/etc/passwd"]
        assert [entry["value"] for entry in payload["derived"]] == ["second"]
        assert payload["derived"][0]["source"] == user_strings.SOURCE_DERIVED
        assert payload["decoded"] == []

    def test_a_function_with_no_decompilation_derives_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            other = store.add_function(conn, analysis_id=ids["analysis"], va=0x2000, name="sub_1")
            payload = user_strings.function_strings(conn, other)
        assert payload == {
            "function_id": other,
            "analyst": [],
            "derived": [],
            "decoded": [],
            "counts": {"analyst": 0, "derived": 0, "decoded": 0},
            "note": payload["note"],
        }

    def test_a_stack_built_listing_is_decoded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        listing = (
            "mov byte [rbp-0x10], 0x68\n"
            "mov byte [rbp-0xf], 0x74\n"
            "mov byte [rbp-0xe], 0x74\n"
            "mov byte [rbp-0xd], 0x70\n"
            "mov byte [rbp-0xc], 0x00\n"
        )
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.set_disasm(conn, ids["function"], listing)
            payload = user_strings.function_strings(conn, ids["function"])
        assert {"value": "http", "source": user_strings.SOURCE_STACK} in payload["decoded"]

    def test_a_register_xor_listing_is_decoded(self) -> None:
        listing = (
            "mov al, 0x2a\n"
            "xor al, 0x42\n"
            "mov [rbp-0x8], al\n"
            "mov al, 0x36\n"
            "xor al, 0x42\n"
            "mov [rbp-0x7], al\n"
            "mov al, 0x36\n"
            "xor al, 0x42\n"
            "mov [rbp-0x6], al\n"
            "mov al, 0x32\n"
            "xor al, 0x42\n"
            "mov [rbp-0x5], al\n"
            "mov al, 0x42\n"
            "xor al, 0x42\n"
            "mov [rbp-0x4], al\n"
        )
        assert user_strings.decoded_strings(listing) == [
            {"value": "http", "source": user_strings.SOURCE_XOR}
        ]

    def test_an_unknown_function_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(user_strings.UnknownStringError),
        ):
            user_strings.function_strings(conn, 999)

    def test_a_hidden_function_reads_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            user_strings.add_string(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                value="/etc/passwd",
                note="why",
            )
            owner, _token = auth.add_user(conn, name="owner", role="admin")
            team_id = int(auth.create_team(conn, name="blue")["id"])
            auth.add_member(conn, team_id, int(owner["id"]))
            _member, _token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
            ana = auth.find_user(conn, "ana")
            assert ana is not None
            auth.add_member(conn, team_id, int(ana["id"]))
            _outsider, _token = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
            stranger = auth.find_user(conn, "bob")
            assert stranger is not None
            store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)
            hidden = user_strings.function_strings(conn, ids["function"], visible_to=stranger)
            assert hidden["analyst"] == []
            assert hidden["derived"] == []
            assert hidden["decoded"] == []
            member = user_strings.function_strings(conn, ids["function"], visible_to=ana)
            assert [entry["value"] for entry in member["analyst"]] == ["/etc/passwd"]
            listed = user_strings.list_strings(
                conn,
                scope_kind=user_strings.SCOPE_FUNCTION,
                scope_id=ids["function"],
                visible_to=stranger,
            )
            assert listed == []
            hidden_analysis = user_strings.list_strings(
                conn,
                scope_kind=user_strings.SCOPE_ANALYSIS,
                scope_id=ids["analysis"],
                visible_to=stranger,
            )
            assert hidden_analysis == []
            member_analysis = user_strings.list_strings(
                conn,
                scope_kind=user_strings.SCOPE_ANALYSIS,
                scope_id=ids["analysis"],
                visible_to=ana,
            )
            assert member_analysis == []

"""Tests for reportal.store schema and CRUD."""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import store


def _seed_function(conn: sqlite3.Connection, *, va: int = 0x1000, name: str = "func_a") -> int:
    binary_id = store.add_binary(conn, sha256=None, name="demo.exe", path="/tmp/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    return store.add_function(conn, analysis_id=analysis_id, va=va, name=name, size=32)


def _seed_analysis(conn: sqlite3.Connection) -> tuple[int, int]:
    binary_id = store.add_binary(conn, sha256="7a" * 32, name="demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    return binary_id, analysis_id


class TestSchemaUpgrade:
    def test_init_db_adds_a_column_an_existing_database_predates(self, tmp_path: Path) -> None:
        path = tmp_path / "old.db"
        with contextlib.closing(sqlite3.connect(path)) as old:
            old.execute(
                "CREATE TABLE auto_runs (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " binary_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'running',"
                " config_json TEXT NOT NULL DEFAULT '{}',"
                " stats_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,"
                " finished_at TEXT)"
            )
            old.commit()
        store.init_db(path)
        with contextlib.closing(store.connect(path)) as conn:
            columns = {str(row["name"]) for row in conn.execute("PRAGMA table_info(auto_runs)")}
        assert "effects_json" in columns


class TestBinaries:
    def test_add_and_list(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(
            conn,
            sha256="ab" * 32,
            name="demo.exe",
            path="/x/demo.exe",
            size=10,
            fmt="PE",
            arch="x86",
        )
        binaries = store.list_binaries(conn)
        assert [b["id"] for b in binaries] == [binary_id]
        assert binaries[0]["format"] == "PE"
        assert binaries[0]["function_count"] == 0

    def test_dedupe_by_sha256(self, conn: sqlite3.Connection) -> None:
        first = store.add_binary(conn, sha256="cd" * 32, name="a.exe")
        second = store.add_binary(conn, sha256="cd" * 32, name="renamed.exe", path="/other")
        assert first == second
        assert len(store.list_binaries(conn)) == 1

    def test_dedupe_by_name_and_path_without_hash(self, conn: sqlite3.Connection) -> None:
        first = store.add_binary(conn, sha256=None, name="a.exe", path="/p/a.exe")
        same = store.add_binary(conn, sha256=None, name="a.exe", path="/p/a.exe")
        other = store.add_binary(conn, sha256=None, name="a.exe", path="/q/a.exe")
        assert first == same
        assert other != first
        assert len(store.list_binaries(conn)) == 2

    def test_get_missing_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_binary(conn, 999) is None

    def test_the_register_filters_by_search_tag_and_format(self, conn: sqlite3.Connection) -> None:
        store.add_binary(conn, sha256="aa" * 32, name="beta.exe", size=30, fmt="PE")
        tagged = store.add_binary(conn, sha256="bb" * 32, name="alpha.exe", size=10, fmt="ELF")
        store.add_binary(conn, sha256="cc" * 32, name="gamma.exe", size=20, fmt="PE")
        store.add_binary_tag(conn, tagged, store.create_tag(conn, "packed"))

        def names(**kwargs: Any) -> list[str]:
            return [row["name"] for row in store.list_binaries(conn, **kwargs)]

        assert names(search="alpha") == ["alpha.exe"]
        # A hash prefix is what an analyst has for a sample they know by hash.
        assert names(search="bb") == ["alpha.exe"]
        assert names(tag="packed") == ["alpha.exe"]
        assert names(tag="absent") == []
        assert names(fmt="PE") == ["beta.exe", "gamma.exe"]
        # The LIKE wildcards stay literal, as every other search's do.
        assert names(search="%") == []

    def test_the_register_orders_by_id_name_size_and_newest(self, conn: sqlite3.Connection) -> None:
        first = store.add_binary(conn, sha256="aa" * 32, name="beta.exe", size=30, fmt="PE")
        second = store.add_binary(conn, sha256="bb" * 32, name="alpha.exe", size=10, fmt="ELF")
        third = store.add_binary(conn, sha256="cc" * 32, name="gamma.exe", size=20, fmt="PE")

        def names(**kwargs: Any) -> list[str]:
            return [row["name"] for row in store.list_binaries(conn, **kwargs)]

        assert names(order="id") == ["beta.exe", "alpha.exe", "gamma.exe"]
        assert names(order="name") == ["alpha.exe", "beta.exe", "gamma.exe"]
        assert names(order="name-desc") == ["gamma.exe", "beta.exe", "alpha.exe"]
        assert names(order="size") == ["alpha.exe", "gamma.exe", "beta.exe"]
        assert names(order="size-desc") == ["beta.exe", "gamma.exe", "alpha.exe"]
        assert [row["id"] for row in store.list_binaries(conn, order="newest")] == [
            third,
            second,
            first,
        ]

    def test_an_unknown_register_order_is_a_value_error(self, conn: sqlite3.Connection) -> None:
        try:
            store.list_binaries(conn, order="biggest")
        except ValueError as exc:
            assert "unknown binary order" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown order must be refused")

    def test_the_format_facet_names_what_the_register_holds(self, conn: sqlite3.Connection) -> None:
        store.add_binary(conn, sha256="aa" * 32, name="a.exe", fmt="PE")
        store.add_binary(conn, sha256="bb" * 32, name="b.exe", fmt="ELF")
        store.add_binary(conn, sha256="cc" * 32, name="c.exe", fmt="PE")
        store.add_binary(conn, sha256="dd" * 32, name="d.exe")

        assert store.binary_filter_values(conn) == {"formats": ["ELF", "PE"]}


class TestFingerprints:
    def test_round_trip(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="11" * 32, name="demo.exe")
        assert store.get_fingerprint(conn, binary_id) is None
        store.set_fingerprint(conn, binary_id, {"md5": "bb", "imphash": "cc"})
        assert store.get_fingerprint(conn, binary_id) == {"md5": "bb", "imphash": "cc"}

    def test_set_overwrites(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="22" * 32, name="demo.exe")
        store.set_fingerprint(conn, binary_id, {"md5": "first"})
        store.set_fingerprint(conn, binary_id, {"md5": "second"})
        assert store.get_fingerprint(conn, binary_id) == {"md5": "second"}
        row = conn.execute("SELECT COUNT(*) FROM binary_fingerprints").fetchone()
        assert row is not None and row[0] == 1

    def test_unknown_binary_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_fingerprint(conn, 999) is None

    def test_init_db_adds_table_to_existing_database(self, tmp_path: Path) -> None:
        db = tmp_path / "legacy.db"
        with sqlite3.connect(db) as raw:
            raw.execute("CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, path TEXT)")
            raw.execute("INSERT INTO binaries VALUES (1, 'demo.exe', '/x/demo.exe')")
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            store.set_fingerprint(conn, 1, {"md5": "aa"})
            assert store.get_fingerprint(conn, 1) == {"md5": "aa"}


class TestRebrewContext:
    def test_round_trip(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="31" * 32, name="demo.exe")
        assert store.get_rebrew_context(conn, binary_id) is None
        store.set_rebrew_context(conn, binary_id, "/projects/notepad-rebrew")
        assert store.get_rebrew_context(conn, binary_id) == "/projects/notepad-rebrew"

    def test_set_overwrites(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="32" * 32, name="demo.exe")
        store.set_rebrew_context(conn, binary_id, "/first")
        store.set_rebrew_context(conn, binary_id, "/second")
        assert store.get_rebrew_context(conn, binary_id) == "/second"
        row = conn.execute("SELECT COUNT(*) FROM rebrew_contexts").fetchone()
        assert row is not None and row[0] == 1

    def test_a_changed_project_drops_the_disasm_cache(self, conn: sqlite3.Connection) -> None:
        """The project directory is the engine input, so a new path cannot keep old listings."""
        binary_id = store.add_binary(conn, sha256="3a" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(conn, analysis_id=analysis_id, va=0x1000, size=16)
        store.set_rebrew_context(conn, binary_id, "/first")
        store.set_disasm(conn, function_id, "bits 32\n")
        store.set_rebrew_context(conn, binary_id, "/first")
        assert store.get_disasm(conn, function_id) == "bits 32\n"
        store.set_rebrew_context(conn, binary_id, "/second")
        assert store.get_disasm(conn, function_id) is None

    def test_unknown_binary_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_rebrew_context(conn, 999) is None


class TestAnalyses:
    def test_create_and_finish(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="ef" * 32, name="demo")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="rebrew-import")
        analysis = store.get_analysis(conn, analysis_id)
        assert analysis is not None
        assert analysis["status"] == "pending"
        assert analysis["finished_at"] is None

        assert store.update_analysis_status(conn, analysis_id, status="done") is True
        finished = store.get_analysis(conn, analysis_id)
        assert finished is not None
        assert finished["status"] == "done"
        assert finished["finished_at"] is not None

    def test_update_unknown_returns_false(self, conn: sqlite3.Connection) -> None:
        assert store.update_analysis_status(conn, 4242, status="done") is False

    def test_find_analysis_is_engine_scoped(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="12" * 32, name="demo")
        store.create_analysis(conn, binary_id=binary_id, engine="manual")
        assert store.find_analysis(conn, binary_id=binary_id, engine="rebrew-import") is None
        assert store.find_analysis(conn, binary_id=binary_id, engine="manual") is not None


class TestFunctions:
    def test_upsert_is_idempotent(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="34" * 32, name="demo")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        first_id, created = store.upsert_function(
            conn, analysis_id=analysis_id, va=0x1000, name="a", status="EXACT"
        )
        second_id, created_again = store.upsert_function(
            conn, analysis_id=analysis_id, va=0x1000, name="b", status="RELOC"
        )
        assert created is True
        assert created_again is False
        assert first_id == second_id
        functions = store.list_functions(conn, analysis_id=analysis_id)
        assert len(functions) == 1
        assert functions[0]["name"] == "b"
        assert functions[0]["status"] == "RELOC"

    def test_upsert_size_change_drops_the_disasm_cache(self, conn: sqlite3.Connection) -> None:
        """A wider or narrower extent is a different listing; drop the old cache."""
        binary_id = store.add_binary(conn, sha256="35" * 32, name="demo")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id, _ = store.upsert_function(
            conn, analysis_id=analysis_id, va=0x1000, name="a", size=16
        )
        store.set_disasm(conn, function_id, "bits 32\n")
        store.upsert_function(conn, analysis_id=analysis_id, va=0x1000, name="a", size=16)
        assert store.get_disasm(conn, function_id) == "bits 32\n"
        store.upsert_function(conn, analysis_id=analysis_id, va=0x1000, name="a", size=32)
        assert store.get_disasm(conn, function_id) is None

    def test_list_by_binary(self, conn: sqlite3.Connection) -> None:
        _seed_function(conn)
        binary_id = store.list_binaries(conn)[0]["id"]
        assert len(store.list_functions(conn, binary_id=binary_id)) == 1

    def test_limit_and_offset_page_the_listing(self, conn: sqlite3.Connection) -> None:
        """The page is a window over the same order, and the bounds are checked."""
        binary_id = store.add_binary(conn, sha256="77" * 32, name="paged")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        for index in range(5):
            store.add_function(
                conn,
                analysis_id=analysis_id,
                va=0x1000 + index * 0x10,
                name=f"fn_{index}",
                size=8,
                status="STUB",
            )
        every = [row["id"] for row in store.list_functions(conn, binary_id=binary_id)]

        page = store.list_functions(conn, binary_id=binary_id, limit=2, offset=1)

        assert [row["id"] for row in page] == every[1:3]
        assert len(store.list_functions(conn, binary_id=binary_id)) == 5, "no limit means every row"
        assert [row["id"] for row in store.list_functions(conn, binary_id=binary_id, offset=3)] == (
            every[3:]
        )
        for bad in ({"limit": 0}, {"limit": store.MAX_FUNCTION_LIMIT + 1}, {"offset": -1}):
            with pytest.raises(ValueError):
                store.list_functions(conn, binary_id=binary_id, **bad)  # type: ignore[arg-type]

    def test_rollup_counts_what_the_rows_would_say(self, conn: sqlite3.Connection) -> None:
        """The rollup is the same answer as counting the listing, without reading it."""
        binary_id = store.add_binary(conn, sha256="88" * 32, name="rolled")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        for index, status in enumerate(("STUB", "EXACT", "EXACT", "RELOC")):
            store.add_function(
                conn,
                analysis_id=analysis_id,
                va=0x2000 + index * 0x10,
                name=f"fn_{index}",
                size=8,
                status=status,
            )
        rows = store.list_functions(conn, binary_id=binary_id)

        rollup = store.function_rollup(conn, binary_id)

        assert rollup["total"] == len(rows)
        assert rollup["matched"] == sum(
            1 for row in rows if row["status"] in store.MATCHED_STATUSES
        )
        assert rollup["by_status"] == {"EXACT": 2, "RELOC": 1, "STUB": 1}
        assert list(rollup["by_status"]) == ["EXACT", "RELOC", "STUB"], "ordered by count then name"

    def test_matching_count_agrees_with_the_listing(self, conn: sqlite3.Connection) -> None:
        """A page's match count is the count of the rows the same filters keep."""
        binary_id = store.add_binary(conn, sha256="99" * 32, name="counted")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        for index, name in enumerate(("alpha", "alpine", "beta")):
            store.add_function(
                conn,
                analysis_id=analysis_id,
                va=0x3000 + index * 0x10,
                name=name,
                size=8,
                status="STUB",
            )

        assert store.count_matching_functions(conn, binary_id=binary_id, name="alp") == 2
        assert store.count_matching_functions(conn, binary_id=binary_id) == 3
        assert store.count_matching_functions(conn, binary_id=binary_id, name="alp") == len(
            store.list_functions(conn, binary_id=binary_id, name="alp")
        )


class TestAddFunctionIfAbsent:
    def test_inserts_when_absent(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        function_id = store.add_function_if_absent(
            conn,
            analysis_id=analysis_id,
            va=0x1000,
            name="ChooseFontW",
            size=6,
            status="THUNK",
            name_source="import",
            source_path="/projects/notepad-rebrew",
        )
        assert function_id is not None
        function = store.get_function(conn, function_id)
        assert function is not None
        assert function["va"] == 0x1000
        assert function["name"] == "ChooseFontW"
        assert function["size"] == 6
        assert function["status"] == "THUNK"
        assert function["name_source"] == "import"
        assert function["source_path"] == "/projects/notepad-rebrew"

    def test_keeps_existing_row(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        existing = store.add_function(
            conn,
            analysis_id=analysis_id,
            va=0x1000,
            name="sub_1000",
            size=32,
            status="EXACT",
            name_source="rebrew",
        )
        inserted = store.add_function_if_absent(
            conn,
            analysis_id=analysis_id,
            va=0x1000,
            name="ChooseFontW",
            size=6,
            status="THUNK",
            name_source="import",
        )
        assert inserted is None
        function = store.get_function(conn, existing)
        assert function is not None
        assert function["name"] == "sub_1000"
        assert function["status"] == "EXACT"
        assert function["size"] == 32
        assert function["name_source"] == "rebrew"
        assert len(store.list_functions(conn, analysis_id=analysis_id)) == 1

    def test_scoped_to_the_analysis(self, conn: sqlite3.Connection) -> None:
        binary_id, first = _seed_analysis(conn)
        second = store.create_analysis(conn, binary_id=binary_id, engine="second")
        store.add_function(conn, analysis_id=first, va=0x1000, name="a")
        assert (
            store.add_function_if_absent(conn, analysis_id=second, va=0x1000, name="b") is not None
        )
        assert len(store.list_functions(conn, analysis_id=first)) == 1
        assert len(store.list_functions(conn, analysis_id=second)) == 1


class TestRenameHistory:
    def test_rename_records_history(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn, name="sub_1000")
        change = store.rename_function(conn, function_id, new_name="parse_header", actor="alice")
        assert change == {
            "function_id": function_id,
            "old_name": "sub_1000",
            "new_name": "parse_header",
        }
        function = store.get_function(conn, function_id)
        assert function is not None
        assert function["name"] == "parse_header"
        assert function["name_source"] == "manual"

        history = store.list_name_history(conn, function_id)
        assert len(history) == 1
        assert history[0]["old_name"] == "sub_1000"
        assert history[0]["actor"] == "alice"

    def test_revert_restores_and_records(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn, name="sub_1000")
        store.rename_function(conn, function_id, new_name="parse_header", actor="alice")
        history = store.list_name_history(conn, function_id)
        reverted = store.revert_name(conn, history[0]["id"], actor="bob")
        assert reverted == function_id
        function = store.get_function(conn, function_id)
        assert function is not None
        assert function["name"] == "sub_1000"
        assert len(store.list_name_history(conn, function_id)) == 2

    def test_rename_same_name_is_noop(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn, name="same")
        store.rename_function(conn, function_id, new_name="same", actor="alice")
        assert store.list_name_history(conn, function_id) == []

    def test_rename_rejects_blank(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        with pytest.raises(ValueError, match="must not be empty"):
            store.rename_function(conn, function_id, new_name="  ", actor="alice")

    def test_rename_unknown_function(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            store.rename_function(conn, 9999, new_name="x", actor="alice")

    def test_get_name_history_round_trip(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn, name="sub_1000")
        store.rename_function(conn, function_id, new_name="parse_header", actor="alice")
        history_id = store.list_name_history(conn, function_id)[0]["id"]
        row = store.get_name_history(conn, history_id)
        assert row is not None
        assert row["function_id"] == function_id
        assert row["old_name"] == "sub_1000"
        assert store.get_name_history(conn, 999) is None


class TestMatches:
    def test_record_and_list(self, conn: sqlite3.Connection) -> None:
        first = _seed_function(conn, va=0x1000, name="a")
        second = _seed_function(conn, va=0x2000, name="b")
        store.record_match(
            conn, function_id=first, candidate_function_id=second, similarity=0.91, confidence=0.8
        )
        matches = store.list_matches(conn, first)
        assert len(matches) == 1
        assert matches[0]["candidate_name"] == "b"
        assert matches[0]["similarity"] == pytest.approx(0.91)

    def test_rerecord_updates(self, conn: sqlite3.Connection) -> None:
        first = _seed_function(conn, va=0x1000, name="a")
        second = _seed_function(conn, va=0x2000, name="b")
        store.record_match(
            conn, function_id=first, candidate_function_id=second, similarity=0.5, confidence=0.5
        )
        store.record_match(
            conn, function_id=first, candidate_function_id=second, similarity=0.9, confidence=0.9
        )
        matches = store.list_matches(conn, first)
        assert len(matches) == 1
        assert matches[0]["similarity"] == pytest.approx(0.9)

    def test_clear_matches_for_removes_only_source(self, conn: sqlite3.Connection) -> None:
        first = _seed_function(conn, va=0x1000, name="a")
        second = _seed_function(conn, va=0x2000, name="b")
        store.record_match(
            conn, function_id=first, candidate_function_id=second, similarity=1.0, confidence=1.0
        )
        store.record_match(
            conn, function_id=second, candidate_function_id=first, similarity=0.5, confidence=0.5
        )
        store.clear_matches_for(conn, first)
        assert store.list_matches(conn, first) == []
        assert len(store.list_matches(conn, second)) == 1

    def test_has_match_is_directional(self, conn: sqlite3.Connection) -> None:
        first = _seed_function(conn, va=0x1000, name="a")
        second = _seed_function(conn, va=0x2000, name="b")
        assert store.has_match(conn, first, second) is False
        store.record_match(
            conn, function_id=first, candidate_function_id=second, similarity=0.9, confidence=0.9
        )
        assert store.has_match(conn, first, second) is True
        assert store.has_match(conn, second, first) is False

    def test_list_matches_for_functions_batches(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _seed_analysis(conn)
        first = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="a", size=16)
        second = store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="b", size=16)
        third = store.add_function(conn, analysis_id=analysis_id, va=0x3000, name="c", size=16)
        store.record_match(
            conn, function_id=first, candidate_function_id=second, similarity=0.9, confidence=0.8
        )
        store.record_match(
            conn, function_id=first, candidate_function_id=third, similarity=0.7, confidence=0.6
        )
        store.record_match(
            conn, function_id=second, candidate_function_id=third, similarity=0.5, confidence=0.4
        )
        grouped = store.list_matches_for_functions(conn, [first, second, 999])
        assert [row["candidate_name"] for row in grouped[first]] == ["b", "c"]
        assert [row["candidate_name"] for row in grouped[second]] == ["c"]
        assert 999 not in grouped
        assert store.list_matches(conn, first) == grouped[first]
        binary_rows = store.list_matches_for_binary(conn, binary_id)
        assert [row["source_name"] for row in binary_rows] == ["a", "a", "b"]
        assert store.match_counts_for_binary(conn, binary_id) == {first: 2, second: 1}

    def test_functions_by_ids_and_decompilations(self, conn: sqlite3.Connection) -> None:
        binary_id, analysis_id = _seed_analysis(conn)
        first = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="a", size=16)
        second = store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="b", size=16)
        store.set_decompilation(conn, first, "int a(void) { return 1; }", "r2ghidra")
        by_id = store.functions_by_ids(conn, [first, second, 999])
        assert set(by_id) == {first, second}
        assert by_id[first]["name"] == "a"
        assert store.decompilation_ids_for_binary(conn, binary_id) == {first}
        codes = store.decompilations_for_binary(conn, binary_id)
        assert set(codes) == {first}
        assert codes[first]["backend"] == "r2ghidra"
        assert store.get_decompilation(conn, first) == codes[first]


class TestDisasmCache:
    def test_only_nasm_is_the_cacheable_format(self) -> None:
        # The route, the MCP tool and the CLI read the cache under this one rule.
        assert store.CACHEABLE_DISASM_FORMAT == "nasm"

    def test_round_trip_and_overwrite(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        assert store.get_disasm(conn, function_id) is None
        store.set_disasm(conn, function_id, "bits 32\n")
        assert store.get_disasm(conn, function_id) == "bits 32\n"
        store.set_disasm(conn, function_id, "bits 16\n")
        assert store.get_disasm(conn, function_id) == "bits 16\n"
        row = conn.execute("SELECT COUNT(*) FROM disasm_cache").fetchone()
        assert row is not None and row[0] == 1

    def test_unknown_function_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_disasm(conn, 999) is None

    def test_cascade_on_function_delete(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_disasm(conn, function_id, "bits 32\n")
        conn.execute("DELETE FROM functions WHERE id = ?", (function_id,))
        conn.commit()
        assert store.get_disasm(conn, function_id) is None

    def test_clear_for_binary_drops_every_listing(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="3b" * 32, name="demo")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        first = store.add_function(conn, analysis_id=analysis_id, va=0x1000, size=8)
        second = store.add_function(conn, analysis_id=analysis_id, va=0x2000, size=8)
        other = _seed_function(conn)
        store.set_disasm(conn, first, "one\n")
        store.set_disasm(conn, second, "two\n")
        store.set_disasm(conn, other, "other\n")
        assert store.clear_disasm_for_binary(conn, binary_id) == 2
        assert store.get_disasm(conn, first) is None
        assert store.get_disasm(conn, second) is None
        assert store.get_disasm(conn, other) == "other\n"


class TestDecompilations:
    def test_round_trip(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        assert store.get_decompilation(conn, function_id) is None
        store.set_decompilation(conn, function_id, "int f(void) { return 0; }", "kuna")
        stored = store.get_decompilation(conn, function_id)
        assert stored is not None
        assert stored["code"] == "int f(void) { return 0; }"
        assert stored["backend"] == "kuna"
        assert stored["created_at"]

    def test_set_overwrites(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_decompilation(conn, function_id, "first", "kuna")
        store.set_decompilation(conn, function_id, "second", "r2ghidra")
        stored = store.get_decompilation(conn, function_id)
        assert stored is not None
        assert stored["code"] == "second"
        assert stored["backend"] == "r2ghidra"
        row = conn.execute("SELECT COUNT(*) FROM decompilations").fetchone()
        assert row is not None and row[0] == 1

    def test_unknown_function_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_decompilation(conn, 999) is None

    def test_cascade_on_function_delete(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_decompilation(conn, function_id, "int f(void) {}", "kuna")
        conn.execute("DELETE FROM functions WHERE id = ?", (function_id,))
        conn.commit()
        assert store.get_decompilation(conn, function_id) is None


class TestAiArtifacts:
    def test_round_trip(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        assert store.get_ai_artifact(conn, function_id, "summary") is None
        store.set_ai_artifact(conn, function_id, "summary", {"summary": "does a thing"}, "m1")
        stored = store.get_ai_artifact(conn, function_id, "summary")
        assert stored is not None
        assert stored["kind"] == "summary"
        assert stored["payload"] == {"summary": "does a thing"}
        assert stored["model"] == "m1"
        assert stored["created_at"]

    def test_set_overwrites_same_kind(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_ai_artifact(conn, function_id, "comments", {"comments": []}, "m1")
        store.set_ai_artifact(conn, function_id, "comments", {"comments": [{"line": 1}]}, "m2")
        stored = store.get_ai_artifact(conn, function_id, "comments")
        assert stored is not None
        assert stored["payload"] == {"comments": [{"line": 1}]}
        assert stored["model"] == "m2"
        row = conn.execute("SELECT COUNT(*) FROM ai_artifacts").fetchone()
        assert row is not None and row[0] == 1

    def test_kinds_are_independent(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_ai_artifact(conn, function_id, "summary", {"summary": "s"}, "m")
        store.set_ai_artifact(conn, function_id, "comments", {"comments": []}, "m")
        assert store.get_ai_artifact(conn, function_id, "summary") is not None
        assert store.get_ai_artifact(conn, function_id, "comments") is not None
        assert store.get_ai_artifact(conn, function_id, "type-suggestions") is None

    def test_list_orders_by_kind(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_ai_artifact(conn, function_id, "summary", {"summary": "s"}, "m")
        store.set_ai_artifact(conn, function_id, "comments", {"comments": []}, "m")
        rows = store.list_ai_artifacts(conn, function_id)
        assert [row["kind"] for row in rows] == ["comments", "summary"]
        assert rows[0]["payload"] == {"comments": []}

    def test_unknown_function_returns_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_ai_artifact(conn, 999, "summary") is None
        assert store.list_ai_artifacts(conn, 999) == []

    def test_cascade_on_function_delete(self, conn: sqlite3.Connection) -> None:
        function_id = _seed_function(conn)
        store.set_ai_artifact(conn, function_id, "summary", {"summary": "s"}, "m")
        conn.execute("DELETE FROM functions WHERE id = ?", (function_id,))
        conn.commit()
        assert store.get_ai_artifact(conn, function_id, "summary") is None


class TestCollectionsAndTags:
    def test_collection_lifecycle(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="56" * 32, name="demo")
        collection_id = store.create_collection(conn, name="winsock", description="networking")
        assert store.add_collection_binary(conn, collection_id, binary_id) is True
        assert store.add_collection_binary(conn, collection_id, binary_id) is False
        collections = store.list_collections(conn)
        assert collections[0]["binary_count"] == 1
        assert store.remove_collection_binary(conn, collection_id, binary_id) is True
        assert store.list_collections(conn)[0]["binary_count"] == 0

    def test_duplicate_collection_rejected(self, conn: sqlite3.Connection) -> None:
        store.create_collection(conn, name="winsock")
        with pytest.raises(ValueError, match="already exists"):
            store.create_collection(conn, name="winsock")

    def test_collection_name_is_stripped(self, conn: sqlite3.Connection) -> None:
        collection_id = store.create_collection(conn, name="  winsock  ")
        row = store.get_collection(conn, collection_id)
        assert row is not None
        assert row["name"] == "winsock"
        with pytest.raises(ValueError, match="already exists"):
            store.create_collection(conn, name="\twinsock\n")
        updated = store.update_collection(conn, collection_id, name="  sockets  ")
        assert updated is not None
        assert updated["name"] == "sockets"

    def test_tags_reuse_and_tag(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="78" * 32, name="demo")
        tag_id = store.create_tag(conn, "malware")
        assert store.create_tag(conn, "malware") == tag_id
        assert store.add_binary_tag(conn, binary_id, tag_id) is True
        assert store.add_binary_tag(conn, binary_id, tag_id) is False
        assert store.list_tags(conn)[0]["binary_count"] == 1


class TestTags:
    def test_get_binary_tags_orders_by_name(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="8a" * 32, name="demo")
        for name in ("zeta", "alpha", "mid"):
            store.add_binary_tag(conn, binary_id, store.create_tag(conn, name))
        assert [tag["name"] for tag in store.get_binary_tags(conn, binary_id)] == [
            "alpha",
            "mid",
            "zeta",
        ]

    def test_get_binary_tags_empty(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="8b" * 32, name="demo")
        assert store.get_binary_tags(conn, binary_id) == []
        assert store.get_binary_tags(conn, 999) == []

    def test_remove_binary_tag_true_then_false(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="8c" * 32, name="demo")
        tag_id = store.create_tag(conn, "release")
        assert store.add_binary_tag(conn, binary_id, tag_id) is True
        assert store.remove_binary_tag(conn, binary_id, tag_id) is True
        assert store.remove_binary_tag(conn, binary_id, tag_id) is False
        assert store.get_binary_tags(conn, binary_id) == []

    def test_rename_tag_keeps_the_links_and_refuses_a_taken_name(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = store.add_binary(conn, sha256="8d" * 32, name="demo")
        tag_id = store.create_tag(conn, "relase")
        store.add_binary_tag(conn, binary_id, tag_id)
        store.create_tag(conn, "triage")

        renamed = store.rename_tag(conn, tag_id, "release")

        assert renamed == {"id": tag_id, "name": "release"}
        assert [tag["name"] for tag in store.get_binary_tags(conn, binary_id)] == ["release"]
        try:
            store.rename_tag(conn, tag_id, "triage")
        except ValueError as exc:
            assert "already exists" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a taken name must be refused")
        try:
            store.rename_tag(conn, tag_id, "  ")
        except ValueError as exc:
            assert "must not be empty" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a blank name must be refused")
        assert store.rename_tag(conn, 4242, "release") is None

    def test_rename_tag_to_its_own_name_is_allowed(self, conn: sqlite3.Connection) -> None:
        tag_id = store.create_tag(conn, "release")

        assert store.rename_tag(conn, tag_id, "release") == {"id": tag_id, "name": "release"}

    def test_delete_tag_takes_the_links_with_it(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="8e" * 32, name="demo")
        collection_id = store.create_collection(conn, name="triage-set")
        tag_id = store.create_tag(conn, "release")
        store.add_binary_tag(conn, binary_id, tag_id)
        store.set_collection_tags(conn, collection_id, ["release"])

        assert store.delete_tag(conn, tag_id) is True

        assert store.get_tag(conn, tag_id) is None
        assert store.get_binary_tags(conn, binary_id) == []
        assert store.collection_tags(conn, collection_id) == []
        assert store.delete_tag(conn, tag_id) is False

    def test_find_tag_does_not_create(self, conn: sqlite3.Connection) -> None:
        assert store.find_tag(conn, "absent") is None
        tag_id = store.create_tag(conn, "release")
        found = store.find_tag(conn, "release")
        assert found is not None
        assert found["id"] == tag_id
        assert store.list_tags(conn) == [
            {"id": tag_id, "name": "release", "binary_count": 0, "collection_count": 0}
        ]

    def test_get_tag(self, conn: sqlite3.Connection) -> None:
        tag_id = store.create_tag(conn, "release")
        assert store.get_tag(conn, tag_id) == {"id": tag_id, "name": "release"}
        assert store.get_tag(conn, 999) is None

    def test_create_tag_strips_padding_and_reuses(self, conn: sqlite3.Connection) -> None:
        tag_id = store.create_tag(conn, "  malware  ")
        assert store.get_tag(conn, tag_id) == {"id": tag_id, "name": "malware"}
        assert store.create_tag(conn, "\tmalware\n") == tag_id
        assert store.find_tag(conn, "  malware  ") == {
            "id": tag_id,
            "name": "malware",
        }


class TestAnalysisLookup:
    def test_latest_is_none_without_analyses(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="1a" * 32, name="demo")
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_latest_returns_newest(self, conn: sqlite3.Connection) -> None:
        binary_id, first = _seed_analysis(conn)
        second = store.create_analysis(conn, binary_id=binary_id, engine="second")
        assert store.latest_analysis_for_binary(conn, binary_id) == second != first

    def test_ensure_reuses_newest(self, conn: sqlite3.Connection) -> None:
        binary_id, first = _seed_analysis(conn)
        second = store.create_analysis(conn, binary_id=binary_id, engine="second")
        assert store.ensure_analysis_for_binary(conn, binary_id, engine="scan") == second
        assert len(store.list_analyses(conn, binary_id=binary_id)) == 2

    def test_ensure_creates_with_engine_label(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="1b" * 32, name="demo")
        analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="scan")
        analysis = store.get_analysis(conn, analysis_id)
        assert analysis is not None
        assert analysis["engine"] == "scan"
        assert analysis["binary_id"] == binary_id


class TestScans:
    def test_round_trip(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE) is None
        store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"toolchain": {"family": "msvc"}})
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE) == {
            "toolchain": {"family": "msvc"}
        }

    def test_set_overwrites_same_kind(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_REPORT, {"summary": {"total": 1}})
        store.set_scan(conn, analysis_id, store.SCAN_KIND_REPORT, {"summary": {"total": 2}})
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_REPORT) == {
            "summary": {"total": 2}
        }
        row = conn.execute("SELECT COUNT(*) FROM scans WHERE analysis_id = ?", (analysis_id,))
        assert row.fetchone()[0] == 1

    def test_kinds_coexist(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"kind": "triage"})
        store.set_scan(conn, analysis_id, store.SCAN_KIND_REPORT, {"kind": "report"})
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE) == {"kind": "triage"}
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_REPORT) == {"kind": "report"}

    def test_same_kind_on_two_analyses(self, conn: sqlite3.Connection) -> None:
        binary_id, first = _seed_analysis(conn)
        second = store.create_analysis(conn, binary_id=binary_id, engine="second")
        store.set_scan(conn, first, store.SCAN_KIND_TRIAGE, {"which": "first"})
        store.set_scan(conn, second, store.SCAN_KIND_TRIAGE, {"which": "second"})
        assert store.get_scan(conn, first, store.SCAN_KIND_TRIAGE) == {"which": "first"}
        assert store.get_scan(conn, second, store.SCAN_KIND_TRIAGE) == {"which": "second"}

    def test_list_is_newest_first_without_payload(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"a": 1})
        store.set_scan(conn, analysis_id, store.SCAN_KIND_REPORT, {"b": 2})
        store.set_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS, {"c": 3}, params={"limit": 5})
        scans = store.list_scans(conn, analysis_id)
        assert [scan["kind"] for scan in scans] == [
            store.SCAN_KIND_STRUCTS,
            store.SCAN_KIND_REPORT,
            "triage",
        ]
        assert set(scans[0]) == {
            "id",
            "analysis_id",
            "kind",
            "status",
            "created_at",
            "params",
        }
        assert {scan["status"] for scan in scans} == {store.SCAN_STATUS_DONE}
        assert all("result_json" not in scan for scan in scans)
        # The recorded inputs come back with the row, and a scan that recorded
        # none answers an empty object rather than a missing key.
        assert scans[0]["params"] == {"limit": 5}
        assert scans[1]["params"] == {}
        assert store.get_scan_params(conn, analysis_id, store.SCAN_KIND_STRUCTS) == {"limit": 5}
        assert store.get_scan_params(conn, analysis_id, store.SCAN_KIND_REPORT) == {}

    def test_a_replaced_scan_replaces_its_inputs(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS, {"a": 1}, params={"limit": 5})
        store.set_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS, {"a": 2}, params={"limit": 9})
        assert store.get_scan_params(conn, analysis_id, store.SCAN_KIND_STRUCTS) == {"limit": 9}
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS) == {"a": 2}

    def test_list_unknown_analysis_is_empty(self, conn: sqlite3.Connection) -> None:
        assert store.list_scans(conn, 999) == []

    def test_get_unknown_kind_is_none(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"a": 1})
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_REPORT) is None

    def test_structs_kind_round_trip(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        assert store.SCAN_KIND_STRUCTS == "structs"
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS) is None
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_STRUCTS,
            {"decompiled": 1, "skipped": 0, "structs": []},
        )
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS) == {
            "decompiled": 1,
            "skipped": 0,
            "structs": [],
        }

    def test_structs_kind_coexists_with_other_scans(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"kind": "triage"})
        store.set_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS, {"kind": "structs"})
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE) == {"kind": "triage"}
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS) == {"kind": "structs"}

    def test_crypto_kind_round_trip(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        assert store.SCAN_KIND_CRYPTO == "crypto"
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO) is None
        payload = {"findings": [], "count": 0, "by_confidence": {"high": 0, "medium": 0}}
        store.set_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO, payload)
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO) == payload

    def test_crypto_kind_coexists_with_other_scans(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"kind": "triage"})
        store.set_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO, {"kind": "crypto"})
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE) == {"kind": "triage"}
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO) == {"kind": "crypto"}

    def test_pe_info_kind_round_trip(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        assert store.SCAN_KIND_PE_INFO == "pe-info"
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO) is None
        payload = {
            "format": "pe",
            "sections": [{"name": ".text", "read": True, "write": False, "execute": True}],
            "flags_summary": ["SEH", "Isolation"],
        }
        store.set_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO, payload)
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO) == payload

    def test_security_kind_round_trip(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        assert store.SCAN_KIND_SECURITY == "security"
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_SECURITY) is None
        payload = {
            "files_scanned": 3,
            "findings": [{"rule": "unbounded-copy"}],
            "count": 1,
            "by_severity": {"high": 1, "medium": 0, "low": 0},
        }
        store.set_scan(conn, analysis_id, store.SCAN_KIND_SECURITY, payload)
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_SECURITY) == payload

    def test_security_kind_coexists_with_other_scans(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO, {"kind": "crypto"})
        store.set_scan(conn, analysis_id, store.SCAN_KIND_SECURITY, {"kind": "security"})
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO) == {"kind": "crypto"}
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_SECURITY) == {"kind": "security"}

    def test_unstrip_kind_round_trip(self, conn: sqlite3.Connection) -> None:
        _, analysis_id = _seed_analysis(conn)
        assert store.SCAN_KIND_UNSTRIP == "unstrip"
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_UNSTRIP) is None
        payload = {"candidates": 1, "proposals": [], "applied": False}
        store.set_scan(conn, analysis_id, store.SCAN_KIND_UNSTRIP, payload)
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_UNSTRIP) == payload

    def test_init_db_adds_unique_index_to_existing_database(self, tmp_path: Path) -> None:
        db = tmp_path / "legacy.db"
        with sqlite3.connect(db) as raw:
            raw.execute(
                "CREATE TABLE scans ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER NOT NULL,"
                " kind TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',"
                " result_json TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)"
            )
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            # `set_scan` logs the finish against the analysis, so the row the
            # foreign key points at has to exist.
            binary_id = store.add_binary(conn, sha256="aa" * 32, name="legacy.exe")
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
            store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"a": 1})
            store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"a": 2})
            assert store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE) == {"a": 2}
            assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1

    def test_init_db_adds_lookup_indexes_used_by_queries(self, tmp_path: Path) -> None:
        db = tmp_path / "indexed.db"
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            names = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                ).fetchall()
            }
        assert "idx_analyses_binary" in names
        assert "idx_matches_candidate" in names
        assert "idx_collection_binaries_binary" in names
        assert "idx_binaries_owner_team" in names
        assert "idx_collections_owner_team" in names
        assert "idx_feedback_user" in names
        assert "idx_users_active_team" in names

    def test_connect_sets_busy_timeout(self, tmp_path: Path) -> None:
        db = tmp_path / "busy.db"
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            assert int(conn.execute("PRAGMA busy_timeout").fetchone()[0]) == store.BUSY_TIMEOUT_MS


class TestSearchAndCounts:
    def test_search_spans_entities(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="9a" * 32, name="target.dll")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.add_function(conn, analysis_id=analysis_id, va=1, name="parse_target")
        store.create_collection(conn, name="target-collection")
        results = store.search(conn, "target")
        assert [b["name"] for b in results["binaries"]] == ["target.dll"]
        assert [f["name"] for f in results["functions"]] == ["parse_target"]
        assert [c["name"] for c in results["collections"]] == ["target-collection"]

    def test_search_escapes_wildcards(self, conn: sqlite3.Connection) -> None:
        store.add_binary(conn, sha256="bc" * 32, name="e%vil")
        store.add_binary(conn, sha256="de" * 32, name="plain")
        results = store.search(conn, "%")
        assert [b["name"] for b in results["binaries"]] == ["e%vil"]

    def test_counts(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="ff" * 32, name="demo")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.add_function(conn, analysis_id=analysis_id, va=1, name="m", status="EXACT")
        store.add_function(conn, analysis_id=analysis_id, va=2, name="u", status="STUB")
        counts = store.counts(conn)
        assert counts["binaries"] == 1
        assert counts["functions"] == 2
        assert counts["matched"] == 1


class TestConversations:
    def test_create_and_get(self, conn: sqlite3.Connection) -> None:
        conversation_id = store.create_conversation(
            conn, scope_kind="function", scope_id=7, title="About sub_1000"
        )
        row = store.get_conversation(conn, conversation_id)
        assert row is not None
        assert row["scope_kind"] == "function"
        assert row["scope_id"] == 7
        assert row["title"] == "About sub_1000"
        assert row["created_at"]
        assert row["message_count"] == 0

    def test_create_rejects_a_blank_title(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError):
            store.create_conversation(conn, scope_kind="binary", scope_id=1, title="   ")

    def test_get_unknown_is_none(self, conn: sqlite3.Connection) -> None:
        assert store.get_conversation(conn, 999) is None

    def test_list_orders_by_id_and_counts_messages(self, conn: sqlite3.Connection) -> None:
        first = store.create_conversation(conn, scope_kind="function", scope_id=1, title="f1")
        second = store.create_conversation(conn, scope_kind="binary", scope_id=1, title="b1")
        store.add_message(conn, conversation_id=second, role="user", content="hi")
        rows = store.list_conversations(conn)
        assert [row["id"] for row in rows] == [first, second]
        assert [row["message_count"] for row in rows] == [0, 1]

    def test_list_filters_by_scope(self, conn: sqlite3.Connection) -> None:
        first = store.create_conversation(conn, scope_kind="function", scope_id=1, title="f1")
        second = store.create_conversation(conn, scope_kind="binary", scope_id=1, title="b1")
        assert [row["id"] for row in store.list_conversations(conn, scope_kind="binary")] == [
            second
        ]
        assert [row["id"] for row in store.list_conversations(conn, scope_id=1)] == [first, second]
        filtered = store.list_conversations(conn, scope_kind="function", scope_id=1)
        assert [row["id"] for row in filtered] == [first]
        assert store.list_conversations(conn, scope_kind="function", scope_id=2) == []

    def test_add_message_returns_the_row_in_order(self, conn: sqlite3.Connection) -> None:
        conversation_id = store.create_conversation(
            conn, scope_kind="binary", scope_id=3, title="b"
        )
        user = store.add_message(conn, conversation_id=conversation_id, role="user", content="q")
        assistant = store.add_message(
            conn, conversation_id=conversation_id, role="assistant", content="a"
        )
        assert user["id"]
        assert user["conversation_id"] == conversation_id
        assert user["role"] == "user"
        assert user["content"] == "q"
        assert user["created_at"]
        assert assistant["role"] == "assistant"
        messages = store.list_messages(conn, conversation_id)
        assert [message["content"] for message in messages] == ["q", "a"]
        assert [message["role"] for message in messages] == ["user", "assistant"]

    def test_add_message_to_unknown_conversation_fails(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            store.add_message(conn, conversation_id=999, role="user", content="q")

    def test_delete_cascades_to_messages(self, conn: sqlite3.Connection) -> None:
        conversation_id = store.create_conversation(
            conn, scope_kind="binary", scope_id=3, title="b"
        )
        store.add_message(conn, conversation_id=conversation_id, role="user", content="q")
        assert store.delete_conversation(conn, conversation_id) is True
        assert store.get_conversation(conn, conversation_id) is None
        assert store.list_messages(conn, conversation_id) == []
        row = conn.execute("SELECT COUNT(*) FROM messages").fetchone()
        assert row is not None and row[0] == 0

    def test_delete_unknown_is_false(self, conn: sqlite3.Connection) -> None:
        assert store.delete_conversation(conn, 999) is False


def _second_binary(conn: sqlite3.Connection) -> int:
    """A second binary row, distinct from the one :func:`_seed_analysis` makes."""
    return store.add_binary(conn, sha256="7b" * 32, name="other.exe")


class TestGraphStore:
    def test_init_db_adds_the_graph_tables_to_an_existing_database(self, tmp_path: Path) -> None:
        db = tmp_path / "legacy.db"
        with sqlite3.connect(db) as raw:
            raw.execute("CREATE TABLE binaries (id INTEGER PRIMARY KEY, name TEXT, path TEXT)")
            raw.execute("INSERT INTO binaries VALUES (1, 'demo.exe', '/x/demo.exe')")
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            store.add_graph_node(
                conn, node_id="b1:binary:1", binary_id=1, kind="binary", key="1", label="demo.exe"
            )
            assert store.count_graph_nodes(conn, 1) == 1

    def test_node_round_trip(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_analysis(conn)
        node_id = f"b{binary_id}:function:7"
        store.add_graph_node(
            conn,
            node_id=node_id,
            binary_id=binary_id,
            kind="function",
            key="7",
            label="parse_target",
            meta={"va": 0x1000},
        )
        node = store.get_graph_node(conn, node_id)
        assert node is not None
        assert node["kind"] == "function"
        assert node["key"] == "7"
        assert node["label"] == "parse_target"
        assert node["meta"] == {"va": 0x1000}
        assert store.get_graph_node(conn, "missing") is None

    def test_node_upsert_replaces_the_row(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_analysis(conn)
        node_id = f"b{binary_id}:tag:3"
        store.add_graph_node(
            conn, node_id=node_id, binary_id=binary_id, kind="tag", key="3", label="first"
        )
        store.add_graph_node(
            conn, node_id=node_id, binary_id=binary_id, kind="tag", key="3", label="second"
        )
        assert store.get_graph_node(conn, node_id) == {
            "id": node_id,
            "binary_id": binary_id,
            "kind": "tag",
            "key": "3",
            "label": "second",
            "meta": {},
        }

    def test_nodes_list_sorted_by_kind_label_and_id(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_analysis(conn)
        store.add_graph_node(
            conn,
            node_id=f"b{binary_id}:function:2",
            binary_id=binary_id,
            kind="function",
            key="2",
            label="beta",
        )
        store.add_graph_node(
            conn,
            node_id=f"b{binary_id}:function:1",
            binary_id=binary_id,
            kind="function",
            key="1",
            label="alpha",
        )
        store.add_graph_node(
            conn,
            node_id=f"b{binary_id}:binary:{binary_id}",
            binary_id=binary_id,
            kind="binary",
            key=str(binary_id),
            label="demo.exe",
        )
        assert [node["label"] for node in store.list_graph_nodes(conn, binary_id)] == [
            "demo.exe",
            "alpha",
            "beta",
        ]

    def test_edges_are_scoped_and_listed_for_a_node(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_analysis(conn)
        other = _second_binary(conn)
        source = f"b{binary_id}:binary:{binary_id}"
        target = f"b{binary_id}:function:1"
        store.add_graph_edge(
            conn,
            edge_id=f"{source}|contains|{target}",
            binary_id=binary_id,
            source=source,
            target=target,
            rel="contains",
            weight=1.0,
            meta={"note": "kept"},
        )
        store.add_graph_edge(
            conn,
            edge_id=f"b{other}:binary:{other}|contains|b{other}:function:9",
            binary_id=other,
            source=f"b{other}:binary:{other}",
            target=f"b{other}:function:9",
            rel="contains",
        )
        assert store.count_graph_edges(conn, binary_id) == 1
        stored = store.list_graph_edges(conn, binary_id)
        assert stored[0]["weight"] == 1.0
        assert stored[0]["meta"] == {"note": "kept"}
        assert len(store.list_graph_edges_for_node(conn, target)) == 1
        assert store.list_graph_edges_for_node(conn, "missing") == []

    def test_delete_graph_removes_only_that_binary(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_analysis(conn)
        other = _second_binary(conn)
        for owner in (binary_id, other):
            store.add_graph_node(
                conn,
                node_id=f"b{owner}:binary:{owner}",
                binary_id=owner,
                kind="binary",
                key=str(owner),
                label="demo.exe",
            )
        assert store.delete_graph(conn, binary_id) == 1
        assert store.count_graph_nodes(conn, binary_id) == 0
        assert store.count_graph_nodes(conn, other) == 1


class TestStringRows:
    """The pure string-row helpers the strings route and `reportal strings` share."""

    def test_normalizes_objects_and_bare_text(self) -> None:
        rows = store.normalize_string_entries(
            {
                "strings": [
                    {
                        "va": 0x402010,
                        "section": ".rdata",
                        "kind": "ascii",
                        "size": 3,
                        "text": "abc",
                    },
                    {"va": "0x402020", "text": "hex va"},
                    {"va": "not a number", "text": "bad va"},
                    "bare text",
                ]
            }
        )
        assert rows[0] == {
            "va": 0x402010,
            "section": ".rdata",
            "kind": "ascii",
            "size": 3,
            "text": "abc",
        }
        assert rows[1]["va"] == 0x402020
        assert rows[1]["size"] == len("hex va")
        assert rows[2]["va"] is None
        assert rows[2]["section"] is None
        assert rows[3] == {
            "va": None,
            "section": None,
            "kind": None,
            "size": len("bare text"),
            "text": "bare text",
        }

    def test_a_payload_without_strings_is_empty(self) -> None:
        assert store.normalize_string_entries({}) == []
        assert store.normalize_string_entries({"strings": "nope"}) == []

    def test_length_ties_break_on_the_text_then_the_address(self) -> None:
        rows = store.normalize_string_entries(
            {
                "strings": [
                    {"va": 0x10, "text": "zzz"},
                    {"va": 0x20, "text": "aaa"},
                    {"va": 0x30, "text": "aaa"},
                ]
            }
        )
        ordered = store.sort_string_entries(rows, sort="length", order="asc")
        assert [(row["text"], row["va"]) for row in ordered] == [
            ("aaa", 0x20),
            ("aaa", 0x30),
            ("zzz", 0x10),
        ]

    def test_an_unknown_sort_or_order_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown string sort"):
            store.sort_string_entries([], sort="entropy", order="asc")
        with pytest.raises(ValueError, match="unknown string order"):
            store.sort_string_entries([], sort="value", order="sideways")

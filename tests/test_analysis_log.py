"""Tests for the structured analysis log, its lifecycle writers and the analysis listing."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from reportal import analysis_log, clock, store


def _binary(conn: sqlite3.Connection, name: str = "demo.exe") -> int:
    return store.add_binary(conn, sha256=name.encode().hex().ljust(64, "0"), name=name)


def _analysis(conn: sqlite3.Connection, binary_id: int, engine: str = "manual") -> int:
    return store.create_analysis(conn, binary_id=binary_id, engine=engine)


def _function(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    va: int = 0x1000,
    name: str = "sub_1000",
    size: int = 32,
    status: str = "STUB",
    name_source: str = "rebrew",
) -> int:
    return store.add_function(
        conn,
        analysis_id=analysis_id,
        va=va,
        name=name,
        size=size,
        status=status,
        name_source=name_source,
    )


class TestAppendAndRead:
    def test_now_follows_store_now(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(clock, "now", lambda: "2026-04-01T00:00:00+00:00")
        assert analysis_log.now() == "2026-04-01T00:00:00+00:00"

    def test_round_trip_preserves_severity(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        analysis_log.append_entry(conn, analysis_id, message="first")
        analysis_log.append_entry(
            conn, analysis_id, severity=analysis_log.SEVERITY_WARN, message="second"
        )
        analysis_log.append_entry(
            conn, analysis_id, severity=analysis_log.SEVERITY_ERROR, message="third"
        )

        entries, total = analysis_log.list_entries(conn, analysis_id)
        assert total == 4  # the creation entry plus the three appended
        assert [entry["message"] for entry in entries[:3]] == ["third", "second", "first"]
        assert [entry["severity"] for entry in entries[:3]] == ["error", "warn", "info"]
        assert all(entry["analysis_id"] == analysis_id for entry in entries)
        assert all(entry["created_at"] for entry in entries)

    def test_newest_first(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        ids = [
            analysis_log.append_entry(conn, analysis_id, message=f"entry {index}")
            for index in range(3)
        ]
        entries, _total = analysis_log.list_entries(conn, analysis_id)
        assert [entry["id"] for entry in entries[:3]] == list(reversed(ids))

    def test_unknown_severity_rejected(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        with pytest.raises(analysis_log.UnknownSeverityError):
            analysis_log.append_entry(conn, analysis_id, severity="fatal", message="nope")

    def test_blank_message_rejected(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        with pytest.raises(ValueError):
            analysis_log.append_entry(conn, analysis_id, message="   ")

    def test_message_is_one_line_and_bounded(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        long_line = "x" * (analysis_log.MAX_MESSAGE_CHARS * 2)
        entry_id = analysis_log.append_entry(
            conn, analysis_id, message=f"  broken\n  line {long_line}"
        )
        entries, _total = analysis_log.list_entries(conn, analysis_id)
        stored = next(entry for entry in entries if entry["id"] == entry_id)
        assert "\n" not in stored["message"]
        assert stored["message"].startswith("broken line")
        assert len(stored["message"]) == analysis_log.MAX_MESSAGE_CHARS
        assert stored["message"].endswith(analysis_log.TRUNCATION_MARKER)

    def test_bound_and_true_total(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        for index in range(5):
            analysis_log.append_entry(conn, analysis_id, message=f"entry {index}")

        page, total = analysis_log.list_entries(conn, analysis_id, limit=2)
        assert len(page) == 2
        assert total == 6
        second_page, _total = analysis_log.list_entries(conn, analysis_id, limit=2, offset=2)
        assert [entry["id"] for entry in second_page] == [entry["id"] - 2 for entry in page]

    def test_limit_out_of_range_rejected(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        with pytest.raises(ValueError):
            analysis_log.list_entries(conn, analysis_id, limit=0)
        with pytest.raises(ValueError):
            analysis_log.list_entries(conn, analysis_id, limit=analysis_log.MAX_LOG_LIMIT + 1)

    def test_offset_must_not_be_negative(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        with pytest.raises(ValueError):
            analysis_log.list_entries(conn, analysis_id, offset=-1)

    def test_entries_cascade_with_the_analysis(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        analysis_id = _analysis(conn, binary_id)
        analysis_log.append_entry(conn, analysis_id, message="one")
        store.delete_analysis(conn, analysis_id)
        assert analysis_log.count_entries(conn, analysis_id) == 0

    def test_count_is_the_whole_log(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        assert analysis_log.count_entries(conn, analysis_id) == 1
        analysis_log.append_entry(conn, analysis_id, message="extra")
        assert analysis_log.count_entries(conn, analysis_id) == 2


class TestAnalysisLifecycle:
    def test_create_analysis_records_the_creation(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        entries, _total = analysis_log.list_entries(conn, analysis_id)
        assert any("analysis created" in entry["message"] for entry in entries)
        assert any(entry["severity"] == analysis_log.SEVERITY_INFO for entry in entries)

    def test_create_analysis_records_the_importer_summary(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        analysis_id = store.create_analysis(
            conn, binary_id=binary_id, engine="rebrew-import", status="done", log="imported"
        )
        entries, _total = analysis_log.list_entries(conn, analysis_id)
        assert any(entry["message"] == "imported" for entry in entries)

    def test_create_analysis_stamps_a_terminal_status(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        done = store.create_analysis(
            conn, binary_id=binary_id, engine="rebrew-import", status="done"
        )
        open_one = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        finished = store.get_analysis(conn, done)
        pending = store.get_analysis(conn, open_one)
        assert finished is not None and finished["finished_at"] is not None
        assert pending is not None and pending["finished_at"] is None

    def test_create_analysis_rejects_unknown_status(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError):
            store.create_analysis(conn, binary_id=_binary(conn), engine="manual", status="queued")

    def test_create_analysis_shares_one_commit_with_its_log(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _binary(conn)
        before_analyses = int(conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0])
        before_log = int(conn.execute("SELECT COUNT(*) FROM analysis_log_entries").fetchone()[0])
        calls = {"n": 0}
        real = analysis_log.append_entry

        def boom(
            connection: sqlite3.Connection,
            analysis_id: int,
            *,
            message: str,
            severity: str = analysis_log.SEVERITY_INFO,
            commit: bool = True,
        ) -> int:
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("log write failed")
            return real(connection, analysis_id, message=message, severity=severity, commit=commit)

        monkeypatch.setattr(analysis_log, "append_entry", boom)
        with pytest.raises(RuntimeError, match="log write failed"):
            store.create_analysis(conn, binary_id=binary_id, engine="rebrew-import", log="imported")
        conn.rollback()
        assert int(conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]) == before_analyses
        assert (
            int(conn.execute("SELECT COUNT(*) FROM analysis_log_entries").fetchone()[0])
            == before_log
        )

    def test_set_scan_records_the_finish_and_completes(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        store.set_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE, {"toolchain": {}})

        analysis = store.get_analysis(conn, analysis_id)
        assert analysis is not None
        assert analysis["status"] == store.ANALYSIS_STATUS_DONE
        assert analysis["finished_at"] is not None
        entries, _total = analysis_log.list_entries(conn, analysis_id)
        assert any(
            entry["message"] == f"{store.SCAN_KIND_TRIAGE} scan finished" for entry in entries
        )

    def test_update_status_clears_finished_at_when_reopening(
        self, conn: sqlite3.Connection
    ) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        assert store.update_analysis_status(conn, analysis_id, status=store.ANALYSIS_STATUS_DONE)
        finished = store.get_analysis(conn, analysis_id)
        assert finished is not None and finished["finished_at"] is not None

        store.begin_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE)

        reopened = store.get_analysis(conn, analysis_id)
        assert reopened is not None
        assert reopened["status"] == store.ANALYSIS_STATUS_PROCESSING
        assert reopened["finished_at"] is None

    def test_update_status_records_each_transition(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        assert store.update_analysis_status(
            conn, analysis_id, status=store.ANALYSIS_STATUS_PROCESSING
        )
        assert store.update_analysis_status(conn, analysis_id, status=store.ANALYSIS_STATUS_FAILED)
        entries, _total = analysis_log.list_entries(conn, analysis_id)
        changes = [entry for entry in entries if "status changed" in entry["message"]]
        assert [entry["message"] for entry in changes] == [
            "status changed to failed (was processing)",
            "status changed to processing (was pending)",
        ]
        assert changes[0]["severity"] == analysis_log.SEVERITY_ERROR
        assert changes[1]["severity"] == analysis_log.SEVERITY_INFO

    def test_update_status_is_quiet_when_unchanged(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        before = analysis_log.count_entries(conn, analysis_id)
        assert store.update_analysis_status(conn, analysis_id, status=store.ANALYSIS_STATUS_PENDING)
        assert analysis_log.count_entries(conn, analysis_id) == before

    def test_update_status_rejects_unknown_value(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        with pytest.raises(ValueError):
            store.update_analysis_status(conn, analysis_id, status="finished")

    def test_update_unknown_analysis_returns_false(self, conn: sqlite3.Connection) -> None:
        assert store.update_analysis_status(conn, 4242, status=store.ANALYSIS_STATUS_DONE) is False

    def test_scan_span_records_start_and_failure(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        with (
            pytest.raises(RuntimeError),
            store.scan_span(conn, binary_id=binary_id, kind=store.SCAN_KIND_TRIAGE),
        ):
            raise RuntimeError("engine exploded")

        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert analysis_id is not None
        analysis = store.get_analysis(conn, analysis_id)
        assert analysis is not None
        assert analysis["status"] == store.ANALYSIS_STATUS_FAILED
        entries, _total = analysis_log.list_entries(conn, analysis_id)
        messages = [entry["message"] for entry in entries]
        assert f"{store.SCAN_KIND_TRIAGE} scan started" in messages
        failed = [entry for entry in entries if entry["severity"] == analysis_log.SEVERITY_ERROR]
        assert any("engine exploded" in entry["message"] for entry in failed)

    def test_scan_span_success_waits_for_the_store_write(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        with store.scan_span(conn, binary_id=binary_id, kind=store.SCAN_KIND_TRIAGE):
            pass
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert analysis_id is not None
        analysis = store.get_analysis(conn, analysis_id)
        assert analysis is not None
        assert analysis["status"] == store.ANALYSIS_STATUS_PROCESSING

    def test_scan_span_leaves_no_row_for_an_unknown_binary(self, conn: sqlite3.Connection) -> None:
        with (
            pytest.raises(RuntimeError),
            store.scan_span(conn, binary_id=999, kind=store.SCAN_KIND_TRIAGE),
        ):
            raise RuntimeError("no binary")
        assert store.count_analyses(conn) == 0

    def test_scan_span_reuses_an_existing_analysis(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        first = _analysis(conn, binary_id)
        with store.scan_span(conn, binary_id=binary_id, kind=store.SCAN_KIND_TRIAGE):
            pass
        assert store.latest_analysis_for_binary(conn, binary_id) == first
        assert store.count_analyses(conn, binary_id=binary_id) == 1


class TestAnalysisListing:
    def test_status_filter(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        pending = _analysis(conn, binary_id)
        done = _analysis(conn, binary_id)
        store.update_analysis_status(conn, done, status=store.ANALYSIS_STATUS_DONE)

        assert [row["id"] for row in store.list_analyses(conn, status="pending")] == [pending]
        assert [row["id"] for row in store.list_analyses(conn, status="done")] == [done]

    def test_search_matches_the_binary_name_and_the_engine(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn, "notepad.exe")
        analysis_id = _analysis(conn, binary_id, engine="rebrew-import")
        assert [row["id"] for row in store.list_analyses(conn, search="notepad")] == [analysis_id]
        assert [row["id"] for row in store.list_analyses(conn, search="IMPORT")] == [analysis_id]
        assert store.list_analyses(conn, search="nothing") == []

    def test_order_and_limit(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        first = _analysis(conn, binary_id)
        second = _analysis(conn, binary_id)
        assert [row["id"] for row in store.list_analyses(conn)] == [second, first]
        assert [row["id"] for row in store.list_analyses(conn, order="oldest")] == [first, second]
        assert [row["id"] for row in store.list_analyses(conn, limit=1)] == [second]

    def test_unknown_filters_rejected(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError):
            store.list_analyses(conn, status="finished")
        with pytest.raises(ValueError):
            store.list_analyses(conn, order="random")
        with pytest.raises(ValueError):
            store.list_analyses(conn, limit=0)
        with pytest.raises(ValueError):
            store.list_analyses(conn, limit=store.MAX_ANALYSIS_LIMIT + 1)

    def test_rows_carry_the_binary_and_its_tags(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        _analysis(conn, binary_id)
        tag_id = store.create_tag(conn, "windows")
        store.add_binary_tag(conn, binary_id, tag_id)
        row = store.list_analyses(conn, binary_id=binary_id)[0]
        assert row["binary_name"] == "demo.exe"
        assert row["tags"] == ["windows"]

    def test_an_analysis_without_tags_reports_an_empty_list(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        _analysis(conn, binary_id)
        row = store.list_analyses(conn, binary_id=binary_id)[0]
        assert row["tags"] == []

    def test_count_analyses(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        _analysis(conn, binary_id)
        _analysis(conn, binary_id)
        assert store.count_analyses(conn) == 2
        assert store.count_analyses(conn, binary_id=binary_id) == 2
        assert store.count_analyses(conn, binary_id=999) == 0


class TestAnalysisDelete:
    def test_delete_removes_dependents(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        first = _analysis(conn, binary_id)
        second = _analysis(conn, binary_id)
        function_id = _function(conn, first)
        store.set_decompilation(conn, function_id, "void sub_1000(void) {}", "kuna")
        store.set_scan(conn, first, store.SCAN_KIND_TRIAGE, {"toolchain": {}})

        assert store.delete_analysis(conn, first) is True
        assert store.get_analysis(conn, first) is None
        assert store.list_functions(conn, analysis_id=first) == []
        assert analysis_log.count_entries(conn, first) == 0
        assert store.get_decompilation(conn, function_id) is None
        # The other analysis of the binary is untouched.
        assert store.get_analysis(conn, second) is not None

    def test_delete_unknown_returns_false(self, conn: sqlite3.Connection) -> None:
        assert store.delete_analysis(conn, 4242) is False

    def test_last_analysis_with_functions_is_flagged(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        only = _analysis(conn, binary_id)
        assert store.is_last_analysis_with_functions(conn, only) is False
        _function(conn, only)
        assert store.is_last_analysis_with_functions(conn, only) is True
        _analysis(conn, binary_id)
        assert store.is_last_analysis_with_functions(conn, only) is False

    def test_unknown_analysis_is_not_flagged(self, conn: sqlite3.Connection) -> None:
        assert store.is_last_analysis_with_functions(conn, 4242) is False


class TestFunctionListing:
    def _rows(self, conn: sqlite3.Connection, binary_id: int, **filters: object) -> list[int]:
        return [
            int(row["id"])
            for row in store.list_functions(conn, binary_id=binary_id, **filters)  # type: ignore[arg-type]
        ]

    def test_sort_by_size_is_stable_on_ties(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        small = _function(conn, analysis_id, va=0x1000, size=8)
        first_large = _function(conn, analysis_id, va=0x2000, size=64)
        second_large = _function(conn, analysis_id, va=0x3000, size=64)
        assert self._rows(conn, 1, sort="size", order="desc") == [
            first_large,
            second_large,
            small,
        ]
        assert self._rows(conn, 1, sort="size", order="asc") == [small, first_large, second_large]

    def test_size_range_is_inclusive(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        exact = _function(conn, analysis_id, va=0x1000, size=16)
        _function(conn, analysis_id, va=0x2000, size=1024)
        assert self._rows(conn, 1, min_size=16) == [exact, 2]
        assert self._rows(conn, 1, max_size=16) == [exact]
        assert self._rows(conn, 1, min_size=17, max_size=1024) == [2]

    def test_string_filter_reads_the_stored_decompilation(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        with_literal = _function(conn, analysis_id, va=0x1000)
        without = _function(conn, analysis_id, va=0x2000)
        store.set_decompilation(conn, with_literal, 'printf("unique marker\\n");', "kuna")
        assert self._rows(conn, 1, string="unique marker") == [with_literal]
        assert self._rows(conn, 1, string="missing") == []
        assert without not in self._rows(conn, 1, string="unique marker")

    def test_match_filter_reads_the_matches_table(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        source = _function(conn, analysis_id, va=0x1000)
        candidate = _function(conn, analysis_id, va=0x2000)
        store.record_match(
            conn,
            function_id=source,
            candidate_function_id=candidate,
            similarity=90.0,
            confidence=0.9,
        )

        assert self._rows(conn, 1, match="matched") == [source]
        assert self._rows(conn, 1, match="unmatched") == [candidate]

    def test_name_filter_is_a_case_insensitive_substring(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        header = _function(conn, analysis_id, va=0x1000, name="NP_HEADER")
        entry = _function(conn, analysis_id, va=0x2000, name="NP_ENTRY")
        other = _function(conn, analysis_id, va=0x3000, name="WIN_MAIN")

        assert self._rows(conn, 1, name="NP_") == [header, entry]
        assert self._rows(conn, 1, name="np_entry") == [entry]
        assert self._rows(conn, 1, name="absent") == []
        assert other not in self._rows(conn, 1, name="NP_")
        # The LIKE wildcards stay literal, as every other search's do.
        assert self._rows(conn, 1, name="%") == []

    def test_va_filter_keeps_one_exact_address(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        first = _function(conn, analysis_id, va=0x1000)
        _function(conn, analysis_id, va=0x2000)

        assert self._rows(conn, 1, va=0x1000) == [first]
        assert self._rows(conn, 1, va=0x1001) == []

    def test_name_and_va_compose_with_each_other(self, conn: sqlite3.Connection) -> None:
        analysis_id = _analysis(conn, _binary(conn))
        first = _function(conn, analysis_id, va=0x1000, name="NP_HEADER")
        _function(conn, analysis_id, va=0x2000, name="NP_ENTRY")

        assert self._rows(conn, 1, name="NP_", va=0x1000) == [first]
        assert self._rows(conn, 1, name="NP_", va=0x9999) == []

    def test_unknown_sort_order_and_match_rejected(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError):
            store.list_functions(conn, sort="similarity")
        with pytest.raises(ValueError):
            store.list_functions(conn, order="sideways")
        with pytest.raises(ValueError):
            store.list_functions(conn, match="maybe")

    def test_count_functions_ignores_the_filters(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        analysis_id = _analysis(conn, binary_id)
        _function(conn, analysis_id, va=0x1000, size=8)
        _function(conn, analysis_id, va=0x2000, size=1024)
        assert store.count_functions(conn, binary_id=binary_id) == 2
        assert store.count_functions(conn, analysis_id=analysis_id) == 2
        assert store.count_functions(conn, binary_id=999) == 0

    def test_scope_is_unchanged_without_filters(self, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn)
        analysis_id = _analysis(conn, binary_id)
        first = _function(conn, analysis_id, va=0x2000)
        second = _function(conn, analysis_id, va=0x1000)
        assert [row["id"] for row in store.list_functions(conn, binary_id=binary_id)] == [
            second,
            first,
        ]


class TestSchemaUpgrade:
    def test_init_db_creates_the_log_table(self, tmp_path: Path) -> None:
        db = tmp_path / "reportal.db"
        store.init_db(db)
        tables = {
            str(row[0])
            for row in sqlite3.connect(db).execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert analysis_log.TABLE in tables

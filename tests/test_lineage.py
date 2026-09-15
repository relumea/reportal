"""Tests for the pairwise function lineage comparison."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, decode, json_body, wsgi_request
from mcp.shared.exceptions import MCPError
from typer.testing import CliRunner

from reportal import auth, cli, engines, lineage, mcp_server, mcp_tools, similarity, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _fn(function_id: int, name: str, va: int, size: int) -> dict[str, Any]:
    """One function row shaped like ``store.list_functions`` returns it."""
    return {"id": function_id, "name": name, "va": va, "size": size}


def _fixed(value: float | None) -> lineage.FunctionScorer:
    """A scorer that returns *value* for every pair."""

    def score(left: dict[str, Any], right: dict[str, Any]) -> float | None:
        return value

    return score


def _statuses(payload: dict[str, Any]) -> list[str]:
    return [str(row["status"]) for row in payload["rows"]]


def _seed_binary(
    conn: sqlite3.Connection,
    *,
    sha256: str,
    name: str,
    functions: list[tuple[int, str, int]],
) -> int:
    """Register one binary with an analysis and its ``(va, name, size)`` functions."""
    binary_id = store.add_binary(conn, sha256=sha256, name=name, path=f"/x/{name}")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    for va, function_name, size in functions:
        store.add_function(conn, analysis_id=analysis_id, va=va, name=function_name, size=size)
    return binary_id


def _seed_pair(
    conn: sqlite3.Connection,
    *,
    left: list[tuple[int, str, int]],
    right: list[tuple[int, str, int]],
) -> dict[str, int]:
    return {
        "left": _seed_binary(conn, sha256="aa" * 32, name="left.exe", functions=left),
        "right": _seed_binary(conn, sha256="bb" * 32, name="right.exe", functions=right),
    }


class TestNamePass:
    """Pass 1: exact name matching, preferring the closest size."""

    def test_same_name_same_size_is_unchanged(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "ReadFile", 0x1000, 48)], [_fn(2, "ReadFile", 0x2000, 48)]
        )
        assert _statuses(payload) == ["unchanged"]
        row = payload["rows"][0]
        assert row["left_function_id"] == 1
        assert row["right_function_id"] == 2
        assert row["left_name"] == "ReadFile"
        assert row["confidence"] == lineage.NAME_MATCH_CONFIDENCE
        assert row["similarity"] is None

    def test_same_name_different_size_is_changed(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "ReadFile", 0x1000, 48)], [_fn(2, "ReadFile", 0x2000, 64)]
        )
        assert _statuses(payload) == ["changed"]
        assert payload["rows"][0]["left_size"] == 48
        assert payload["rows"][0]["right_size"] == 64

    def test_name_match_prefers_the_closest_size(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "ReadFile", 0x1000, 40)],
            [_fn(2, "ReadFile", 0x2000, 100), _fn(3, "ReadFile", 0x3000, 41)],
        )
        rows = {row["right_function_id"]: row for row in payload["rows"]}
        assert rows[3]["status"] == "changed"
        assert rows[2]["status"] == "added"

    def test_name_match_is_case_sensitive(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "ReadFile", 0x1000, 48)], [_fn(2, "readfile", 0x2000, 48)]
        )
        assert _statuses(payload) == ["removed", "added"]

    def test_unmatched_left_is_removed_and_right_is_added(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "OnlyLeft", 0x1000, 8)], [_fn(2, "OnlyRight", 0x2000, 8)]
        )
        removed, added = payload["rows"]
        assert removed["status"] == "removed"
        assert removed["right_function_id"] is None
        assert removed["right_name"] is None
        assert added["status"] == "added"
        assert added["left_function_id"] is None
        assert added["left_va"] is None

    def test_placeholder_names_do_not_pair_on_name(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 48)], [_fn(2, "sub_1000", 0x2000, 48)]
        )
        assert _statuses(payload) == ["removed", "added"]

    def test_a_named_function_is_never_re_paired_structurally(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "OldName", 0x1000, 48)],
            [_fn(2, "NewName", 0x1000, 48)],
            score=_fixed(99.0),
        )
        assert _statuses(payload) == ["removed", "added"]


class TestStructuralPass:
    """Pass 2: placeholder names paired by structural score inside a size bucket."""

    def test_pairs_a_placeholder_with_a_high_score(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 48)],
            [_fn(2, "sub_2000", 0x2000, 48)],
            score=_fixed(99.0),
        )
        assert _statuses(payload) == ["unchanged"]
        row = payload["rows"][0]
        assert row["similarity"] == 99.0
        assert row["confidence"] == 1.0

    def test_a_mid_range_score_is_changed(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 48)],
            [_fn(2, "sub_2000", 0x2000, 48)],
            score=_fixed(80.0),
        )
        assert _statuses(payload) == ["changed"]
        assert payload["rows"][0]["confidence"] == 0.8

    def test_exactly_at_the_unchanged_threshold_is_unchanged(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 48)],
            [_fn(2, "sub_2000", 0x2000, 48)],
            score=_fixed(lineage.UNCHANGED_THRESHOLD),
        )
        assert _statuses(payload) == ["unchanged"]

    def test_exactly_at_the_changed_threshold_is_changed(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 48)],
            [_fn(2, "sub_2000", 0x2000, 48)],
            score=_fixed(lineage.CHANGED_THRESHOLD),
        )
        assert _statuses(payload) == ["changed"]

    def test_below_the_changed_threshold_is_no_match(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 48)],
            [_fn(2, "sub_2000", 0x2000, 48)],
            score=_fixed(lineage.CHANGED_THRESHOLD - 0.1),
        )
        assert _statuses(payload) == ["removed", "added"]

    def test_a_none_score_is_no_match(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 48)],
            [_fn(2, "sub_2000", 0x2000, 48)],
            score=_fixed(None),
        )
        assert _statuses(payload) == ["removed", "added"]

    def test_candidates_outside_the_size_bucket_are_never_scored(self) -> None:
        scored: list[int] = []

        def score(left: dict[str, Any], right: dict[str, Any]) -> float | None:
            scored.append(int(right["id"]))
            return 99.0

        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 100)],
            [_fn(2, "sub_2000", 0x2000, 100), _fn(3, "sub_3000", 0x3000, 300)],
            score=score,
        )
        assert scored == [2]
        rows = {row["right_function_id"]: row for row in payload["rows"]}
        assert rows[2]["status"] == "unchanged"
        assert rows[3]["status"] == "added"

    def test_the_best_score_wins_over_the_closest_size(self) -> None:
        def score(left: dict[str, Any], right: dict[str, Any]) -> float | None:
            return 96.0 if right["id"] == 2 else 80.0

        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 100)],
            [_fn(2, "sub_2000", 0x2000, 109), _fn(3, "sub_3000", 0x3000, 100)],
            score=score,
        )
        assert payload["rows"][0]["right_function_id"] == 2
        assert payload["rows"][0]["status"] == "unchanged"
        assert payload["summary"]["added"] == 1

    def test_a_score_tie_falls_to_the_closer_size(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 100)],
            [_fn(2, "sub_2000", 0x2000, 108), _fn(3, "sub_3000", 0x3000, 100)],
            score=_fixed(90.0),
        )
        assert payload["rows"][0]["right_function_id"] == 3

    def test_a_score_and_size_tie_falls_to_the_lower_va(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 100)],
            [_fn(2, "sub_2000", 0x4000, 100), _fn(3, "sub_3000", 0x3000, 100)],
            score=_fixed(90.0),
        )
        assert [row["right_function_id"] for row in payload["rows"]] == [3, 2]
        assert payload["summary"]["added"] == 1
        assert payload["summary"]["changed"] == 1

    def test_max_candidates_bounds_the_scored_pairs(self) -> None:
        scored: list[int] = []

        def score(left: dict[str, Any], right: dict[str, Any]) -> float | None:
            scored.append(int(right["size"]))
            return None

        right = [
            _fn(1000 + index, "sub_0", 0x2000 + index * 16, 1000 + index) for index in range(51)
        ]
        lineage.compare_functions([_fn(1, "sub_1000", 0x1000, 1000)], right, score=score)
        assert scored == list(range(1000, 1000 + lineage.MAX_CANDIDATES))

    def test_a_claimed_right_function_is_not_reused(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "sub_1000", 0x1000, 48), _fn(2, "sub_2000", 0x2000, 48)],
            [_fn(3, "sub_3000", 0x3000, 48)],
            score=_fixed(99.0),
        )
        assert _statuses(payload) == ["unchanged", "removed"]
        assert payload["rows"][0]["right_function_id"] == 3


class TestSummaryAndRows:
    def test_rows_sort_by_status_then_left_va(self) -> None:
        payload = lineage.compare_functions(
            [
                _fn(1, "RemovedA", 0x2000, 8),
                _fn(2, "Changed", 0x3000, 16),
                _fn(3, "Same", 0x1000, 8),
                _fn(4, "RemovedB", 0x1000, 8),
            ],
            [
                _fn(5, "Changed", 0x3000, 32),
                _fn(6, "Same", 0x1000, 8),
                _fn(7, "AddedB", 0x1000, 8),
                _fn(8, "AddedA", 0x2000, 8),
            ],
        )
        assert _statuses(payload) == [
            "unchanged",
            "changed",
            "removed",
            "removed",
            "added",
            "added",
        ]
        removed = [row["left_va"] for row in payload["rows"] if row["status"] == "removed"]
        added = [row["right_va"] for row in payload["rows"] if row["status"] == "added"]
        assert removed == [0x1000, 0x2000]
        assert added == [0x1000, 0x2000]

    def test_matched_percent_counts_the_paired_share(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "Same", 0x1000, 8), _fn(2, "Gone", 0x2000, 8)],
            [
                _fn(3, "Same", 0x1000, 8),
                _fn(4, "New", 0x2000, 8),
                _fn(5, "Newer", 0x3000, 8),
            ],
        )
        assert payload["summary"] == {
            "unchanged": 1,
            "changed": 0,
            "removed": 1,
            "added": 2,
            "matched_percent": 25.0,
        }

    def test_matched_percent_with_an_empty_left_side(self) -> None:
        payload = lineage.compare_functions([], [_fn(1, "New", 0x1000, 8)])
        assert payload["summary"] == {
            "unchanged": 0,
            "changed": 0,
            "removed": 0,
            "added": 1,
            "matched_percent": 0.0,
        }

    def test_matched_percent_with_an_empty_right_side(self) -> None:
        payload = lineage.compare_functions([_fn(1, "Gone", 0x1000, 8)], [])
        assert payload["summary"] == {
            "unchanged": 0,
            "changed": 0,
            "removed": 1,
            "added": 0,
            "matched_percent": 0.0,
        }

    def test_two_empty_sides(self) -> None:
        payload = lineage.compare_functions([], [])
        assert payload["summary"]["matched_percent"] == 0.0
        assert payload["rows"] == []

    def test_a_full_match_scores_one_hundred_percent(self) -> None:
        payload = lineage.compare_functions(
            [_fn(1, "Same", 0x1000, 8)], [_fn(2, "Same", 0x1000, 8)]
        )
        assert payload["summary"]["matched_percent"] == 100.0

    def test_the_row_cap_keeps_the_exact_summary_counts(self) -> None:
        left = [_fn(index, f"func_{index}", 0x1000 + index * 16, 8) for index in range(600)]
        payload = lineage.compare_functions(left, [])
        assert len(payload["rows"]) == lineage.MAX_ROWS
        assert payload["summary"]["removed"] == 600
        assert payload["summary"]["unchanged"] == 0


class TestCompareBinaries:
    def test_injected_scorer_pairs_and_reports_refined(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(
            conn,
            left=[(0x1000, "sub_1000", 48)],
            right=[(0x2000, "sub_2000", 48)],
        )
        payload = lineage.compare_binaries(
            conn,
            left_binary_id=ids["left"],
            right_binary_id=ids["right"],
            score=_fixed(100.0),
        )
        assert payload["left_binary_id"] == ids["left"]
        assert payload["right_binary_id"] == ids["right"]
        assert payload["left_name"] == "left.exe"
        assert payload["right_name"] == "right.exe"
        assert payload["refined"] is True
        assert _statuses(payload) == ["unchanged"]

    def test_without_a_scorer_the_comparison_is_name_only(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(similarity, "available", lambda: False)
        ids = _seed_pair(
            conn,
            left=[(0x1000, "sub_1000", 48)],
            right=[(0x2000, "sub_2000", 48)],
        )
        payload = lineage.compare_binaries(
            conn, left_binary_id=ids["left"], right_binary_id=ids["right"]
        )
        assert payload["refined"] is False
        assert _statuses(payload) == ["removed", "added"]

    def test_an_injected_scorer_runs_even_when_refine_is_false(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(similarity, "available", lambda: True)
        ids = _seed_pair(
            conn,
            left=[(0x1000, "sub_1000", 48)],
            right=[(0x2000, "sub_2000", 48)],
        )
        payload = lineage.compare_binaries(
            conn,
            left_binary_id=ids["left"],
            right_binary_id=ids["right"],
            score=_fixed(100.0),
            refine=False,
        )
        assert payload["refined"] is True
        assert _statuses(payload) == ["unchanged"]

    def test_an_injected_disassembler_drives_the_scorer(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(
            conn,
            left=[(0x1000, "sub_1000", 48)],
            right=[(0x2000, "sub_2000", 48)],
        )
        payload = lineage.compare_binaries(
            conn,
            left_binary_id=ids["left"],
            right_binary_id=ids["right"],
            disassembler=lambda function: "bits 32\nret\n",
        )
        assert payload["refined"] is True
        assert payload["summary"]["removed"] == 0
        assert payload["rows"][0]["similarity"] == 100.0

    def test_a_missing_listing_is_not_a_match(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(
            conn,
            left=[(0x1000, "sub_1000", 48)],
            right=[(0x2000, "sub_2000", 48)],
        )
        payload = lineage.compare_binaries(
            conn,
            left_binary_id=ids["left"],
            right_binary_id=ids["right"],
            disassembler=lambda function: None,
        )
        assert payload["refined"] is True
        assert _statuses(payload) == ["removed", "added"]

    def test_an_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        with pytest.raises(KeyError):
            lineage.compare_binaries(conn, left_binary_id=ids["left"], right_binary_id=999)
        with pytest.raises(KeyError):
            lineage.compare_binaries(conn, left_binary_id=999, right_binary_id=ids["right"])

    def test_comparing_a_binary_with_itself_raises(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        with pytest.raises(lineage.SameBinaryError):
            lineage.compare_binaries(conn, left_binary_id=ids["left"], right_binary_id=ids["left"])

    def test_named_functions_pair_across_two_stored_binaries(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed_pair(
            conn,
            left=[(0x1000, "DoThing", 32), (0x2000, "OnlyLeft", 16)],
            right=[(0x1000, "DoThing", 32), (0x3000, "OnlyRight", 16)],
        )
        payload = lineage.compare_binaries(
            conn,
            left_binary_id=ids["left"],
            right_binary_id=ids["right"],
            score=None,
            refine=False,
        )
        assert payload["refined"] is False
        assert payload["summary"] == {
            "unchanged": 1,
            "changed": 0,
            "removed": 1,
            "added": 1,
            "matched_percent": 33.3,
        }


class TestStoredComparisons:
    def test_round_trip_per_pair(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[(0x1000, "DoThing", 32)], right=[])
        third = _seed_binary(conn, sha256="cc" * 32, name="third.exe", functions=[])
        for right_id in (ids["right"], third):
            comparison = lineage.compare_binaries(
                conn,
                left_binary_id=ids["left"],
                right_binary_id=right_id,
                refine=False,
            )
            lineage.store_comparison(conn, comparison)

        assert lineage.stored_comparison(conn, ids["left"], ids["right"]) is not None
        assert lineage.stored_comparison(conn, ids["left"], third) is not None
        listed = lineage.stored_comparisons(conn, ids["left"])
        assert [entry["right_binary_id"] for entry in listed] == [ids["right"], third]

    def test_a_stored_comparison_keeps_one_scan_of_the_kind(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[(0x1000, "DoThing", 32)], right=[])
        comparison = lineage.compare_binaries(
            conn, left_binary_id=ids["left"], right_binary_id=ids["right"], refine=False
        )
        lineage.store_comparison(conn, comparison)
        lineage.store_comparison(conn, {**comparison, "refined": True})
        analysis_id = store.latest_analysis_for_binary(conn, ids["left"])
        assert analysis_id is not None
        scans = [
            scan
            for scan in store.list_scans(conn, analysis_id)
            if scan["kind"] == store.SCAN_KIND_LINEAGE
        ]
        assert len(scans) == 1
        stored = lineage.stored_comparison(conn, ids["left"], ids["right"])
        assert stored is not None
        assert stored["refined"] is True

    def test_nothing_stored_answers_none(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        assert lineage.stored_comparison(conn, ids["left"], ids["right"]) is None
        assert lineage.stored_comparisons(conn, ids["left"]) == []

    def test_an_unparsable_scan_payload_is_ignored(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        analysis_id = store.ensure_analysis_for_binary(conn, ids["left"], engine=store.SCAN_ENGINE)
        store.set_scan(conn, analysis_id, store.SCAN_KIND_LINEAGE, {"comparisons": []})
        assert lineage.stored_comparisons(conn, ids["left"]) == []

    def test_a_malformed_comparison_entry_is_skipped(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        analysis_id = store.ensure_analysis_for_binary(conn, ids["left"], engine=store.SCAN_ENGINE)
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_LINEAGE,
            {"comparisons": {"2": {"refined": False}, "3": "not a comparison"}},
        )
        assert lineage.stored_comparisons(conn, ids["left"]) == []
        assert lineage.stored_comparison(conn, ids["left"], 2) is None


class TestLineageRoutes:
    """`POST`/`GET /api/binaries/<id>/lineage`."""

    def _seed(self, conn: sqlite3.Connection) -> dict[str, int]:
        return _seed_pair(
            conn,
            left=[(0x1000, "DoThing", 32), (0x2000, "sub_2000", 16)],
            right=[(0x1000, "DoThing", 32), (0x2000, "sub_2000", 16)],
        )

    def test_post_stores_then_get_serves_stored(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": ids["right"], "refine": False}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload.pop("journal_action")
        assert payload["refined"] is False
        assert payload["summary"] == {
            "unchanged": 1,
            "changed": 0,
            "removed": 1,
            "added": 1,
            "matched_percent": 33.3,
        }
        assert payload["left_binary_id"] == ids["left"]

        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['left']}/lineage?other_binary_id={ids['right']}"
        )
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_lists_the_stored_comparisons(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        third = _seed_binary(conn, sha256="cc" * 32, name="third.exe", functions=[])
        for right_id in (ids["right"], third):
            wsgi_request(
                "POST",
                f"/api/binaries/{ids['left']}/lineage",
                body=json.dumps({"other_binary_id": right_id, "refine": False}),
            )
        status, headers, body = wsgi_request("GET", f"/api/binaries/{ids['left']}/lineage")
        assert status.startswith("200")
        listing = json_body(body, headers)
        assert listing["binary_id"] == ids["left"]
        assert [entry["right_binary_id"] for entry in listing["comparisons"]] == [
            ids["right"],
            third,
        ]

    def test_get_lists_nothing_for_a_binary_without_a_comparison(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{ids['left']}/lineage")
        assert status.startswith("200")
        assert json_body(body, headers) == {"binary_id": ids["left"], "comparisons": []}

    def test_post_404_unknown_binary(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST", "/api/binaries/999/lineage", body=json.dumps({"other_binary_id": 1})
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": 999}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_get_404_unknown_binary(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/lineage")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_missing_other_binary_id(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{ids['left']}/lineage", body="{}"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid other_binary_id"

    def test_post_400_non_integer_other_binary_id(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": "two"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid other_binary_id"

    def test_post_400_same_binary(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": ids["left"]}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "same binary"

    def test_post_400_non_boolean_refine(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": ids["right"], "refine": "yes"}),
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "refine must be a boolean"

    def test_get_404_without_a_stored_comparison(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['left']}/lineage?other_binary_id={ids['right']}"
        )
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"lineage {ids['left']} {ids['right']}" in payload["detail"]

    def test_post_404_hidden_other_binary(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(conn)
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, ids["right"], visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": ids["right"], "refine": False}),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "binary not found"

        member_status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": ids["right"], "refine": False}),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), body

    def test_get_400_non_integer_other_binary_id(self, conn: sqlite3.Connection) -> None:
        ids = self._seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['left']}/lineage?other_binary_id=two"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid other_binary_id"

    def test_post_refinement_pairs_placeholders_through_the_engine(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_pair(
            conn,
            left=[(0x1000, "sub_1000", 48)],
            right=[(0x2000, "sub_2000", 48)],
        )
        store.set_rebrew_context(conn, ids["left"], "/projects/left")
        store.set_rebrew_context(conn, ids["right"], "/projects/right")
        monkeypatch.setattr(
            fake_engine,
            "disassemble",
            lambda project_dir, va, size, fmt="nasm": "bits 32\nret\n",
        )
        monkeypatch.setattr(similarity, "available", lambda: True)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": ids["right"]}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["refined"] is True
        assert payload["summary"]["unchanged"] == 1
        assert payload["rows"][0]["similarity"] == 100.0

    def test_post_without_an_engine_is_not_an_error(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(conn)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        monkeypatch.setattr(similarity, "available", lambda: True)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": ids["right"]}),
        )
        assert status.startswith("200")
        assert json_body(body, headers)["refined"] is False


class TestLineageCli:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            return _seed_pair(
                conn,
                left=[(0x1000, "DoThing", 32), (0x2000, "OnlyLeft", 16)],
                right=[(0x1000, "DoThing", 32), (0x3000, "OnlyRight", 16)],
            )

    def test_json_prints_the_comparison(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        monkeypatch.setattr(similarity, "available", lambda: False)
        result = runner.invoke(cli.app, ["lineage", str(ids["left"]), str(ids["right"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["summary"]["unchanged"] == 1
        assert payload["summary"]["removed"] == 1
        assert payload["summary"]["added"] == 1
        assert payload["refined"] is False

    def test_human_output_shows_the_counts_and_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        monkeypatch.setattr(similarity, "available", lambda: False)
        result = runner.invoke(cli.app, ["lineage", str(ids["left"]), str(ids["right"])])
        assert result.exit_code == 0, result.output
        assert "unchanged 1" in result.output
        assert "matched 33.3%" in result.output
        assert "refined: no" in result.output
        assert "OnlyLeft" in result.output
        assert "OnlyRight" in result.output
        assert "DoThing" not in result.output

    def test_no_refine_flag_forces_name_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        monkeypatch.setattr(similarity, "available", lambda: True)
        result = runner.invoke(
            cli.app,
            ["lineage", str(ids["left"]), str(ids["right"]), "--no-refine", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["refined"] is False

    def test_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["lineage", str(ids["left"]), "999", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 999" in result.stdout

    def test_same_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["lineage", str(ids["left"]), str(ids["left"]), "--json"])
        assert result.exit_code == 1
        assert "cannot be compared with itself" in result.stdout

    def test_missing_database_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "absent.db"))
        result = runner.invoke(cli.app, ["lineage", "1", "2", "--json"])
        assert result.exit_code == 1
        assert "no reportal database" in result.stdout


class TestLineageMcpTools:
    def _call(self, name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
        return mcp_server.call_tool(name, arguments)

    def test_get_lineage_without_a_stored_comparison(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        payload, is_error = self._call("get_lineage", {"binary_id": ids["left"]})
        assert is_error is False
        assert payload == {"binary_id": ids["left"], "comparisons": []}

        payload, is_error = self._call(
            "get_lineage", {"binary_id": ids["left"], "other_binary_id": ids["right"]}
        )
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_lineage" in payload["detail"]

    def test_get_lineage_404_style_error_for_an_unknown_binary(
        self, conn: sqlite3.Connection
    ) -> None:
        payload, is_error = self._call("get_lineage", {"binary_id": 999})
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_run_lineage_stores_the_comparison(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(
            conn,
            left=[(0x1000, "DoThing", 32)],
            right=[(0x1000, "DoThing", 32)],
        )
        payload, is_error = self._call(
            "run_lineage",
            {"binary_id": ids["left"], "other_binary_id": ids["right"], "refine": False},
        )
        assert is_error is False
        assert payload["refined"] is False
        assert payload["summary"]["unchanged"] == 1

        stored, is_error = self._call(
            "get_lineage", {"binary_id": ids["left"], "other_binary_id": ids["right"]}
        )
        assert is_error is False
        payload.pop("journal_action", None)
        assert stored == payload

    def test_run_lineage_requires_the_other_binary_id(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        with pytest.raises(MCPError):
            mcp_server.call_tool("run_lineage", {"binary_id": ids["left"]})

    def test_run_lineage_same_binary_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        payload, is_error = self._call(
            "run_lineage", {"binary_id": ids["left"], "other_binary_id": ids["left"]}
        )
        assert is_error is True
        assert payload["error"] == "same binary"

    def test_run_lineage_unknown_binary_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[], right=[])
        payload, is_error = self._call(
            "run_lineage", {"binary_id": ids["left"], "other_binary_id": 999}
        )
        assert is_error is True
        assert payload["error"] == "binary not found"

    def test_the_tools_are_registered_with_the_right_annotations(self) -> None:
        by_name = {tool.name: tool for tool in mcp_tools.tools()}
        assert by_name["get_lineage"].annotations.read_only_hint is True
        assert by_name["get_lineage"].annotations.destructive_hint is False
        assert by_name["run_lineage"].annotations.read_only_hint is False
        assert by_name["run_lineage"].annotations.destructive_hint is True


class TestGzipAndDecode:
    def test_a_comparison_response_round_trips(self, conn: sqlite3.Connection) -> None:
        ids = _seed_pair(conn, left=[(0x1000, "DoThing", 32)], right=[(0x1000, "DoThing", 32)])
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{ids['left']}/lineage",
            body=json.dumps({"other_binary_id": ids["right"], "refine": False}),
            headers={"Accept-Encoding": "gzip"},
        )
        assert status.startswith("200")
        assert json.loads(decode(body, headers))["summary"]["unchanged"] == 1

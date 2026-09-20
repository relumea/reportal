"""Tests for the composition analysis: module, store round trip and routes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import auth, cli, composition, matching, store

runner = CliRunner()

SHA = "aa" * 32


def _binary(
    conn: sqlite3.Connection, tmp_path: Path, *, name: str, sha: str, size: int = 1000
) -> int:
    path = tmp_path / name
    path.write_bytes(b"MZ" + name.encode())
    return store.add_binary(
        conn, sha256=sha, name=name, path=str(path), size=size, fmt="PE", arch="x86_32"
    )


def _analysis(conn: sqlite3.Connection, binary_id: int) -> int:
    return store.create_analysis(conn, binary_id=binary_id, engine="rebrew-import", status="done")


def _matched_pair(conn: sqlite3.Connection) -> tuple[int, int, int]:
    """Left binary with one function matched to right's; returns (left, right, source)."""
    left = store.add_binary(conn, sha256="aa" * 32, name="left.exe")
    right = store.add_binary(conn, sha256="bb" * 32, name="right.exe")
    analysis = store.create_analysis(conn, binary_id=left, engine="manual")
    source = store.add_function(
        conn, analysis_id=analysis, va=0x1000, name="sub_1000", size=16, status="STUB"
    )
    other = store.create_analysis(conn, binary_id=right, engine="manual")
    candidate = store.add_function(
        conn, analysis_id=other, va=0x1000, name="sub_1000", size=16, status="STUB"
    )
    store.record_match(
        conn,
        function_id=source,
        candidate_function_id=candidate,
        similarity=99.0,
        confidence=0.9,
    )
    return left, right, source


def _function(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    va: int,
    name: str = "",
    size: int = 64,
    name_source: str = "",
    status: str = "STUB",
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


def _candidate_binary(
    conn: sqlite3.Connection, tmp_path: Path, *, name: str, sha: str, vases: list[int]
) -> tuple[int, list[int]]:
    """Register another binary with one function per VA; returns its ids."""
    binary_id = _binary(conn, tmp_path, name=name, sha=sha)
    analysis_id = _analysis(conn, binary_id)
    function_ids = [
        _function(conn, analysis_id, va=va, name=f"{name}_{va:x}", name_source="rebrew")
        for va in vases
    ]
    return binary_id, function_ids


def _payload(conn: sqlite3.Connection, tmp_path: Path) -> tuple[int, dict[str, Any]]:
    """A target binary with one function, and its computed composition."""
    target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
    analysis_id = _analysis(conn, target)
    _function(conn, analysis_id, va=0x1000, name="sub_1000")
    return target, composition.compute_composition(conn, binary_id=target)


def _labelled(entries: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(entry["label"]): entry for entry in entries}


class TestNameSources:
    def test_five_buckets_from_the_stored_vocabulary(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        analysis_id = _analysis(conn, target)
        rows = [
            ("imported_fn", "import", composition.NAME_SOURCE_SYSTEM),
            ("crt_fn", "rebrew", composition.NAME_SOURCE_SYSTEM),
            ("unstripped_fn", "unstrip", composition.NAME_SOURCE_AUTO_UNSTRIP),
            ("renamed_fn", "renames", composition.NAME_SOURCE_AI_AGENT),
            ("ai_helper", "ai-inline", composition.NAME_SOURCE_AI_AGENT),
            ("hand_named_fn", "manual", composition.NAME_SOURCE_USER),
            ("mystery_fn", "mystery-source", composition.NAME_SOURCE_USER),
            ("sub_1000", "import", composition.NAME_SOURCE_NO_DEBUG_INFO),
            ("", "", composition.NAME_SOURCE_NO_DEBUG_INFO),
        ]
        for index, (name, source, _label) in enumerate(rows):
            _function(conn, analysis_id, va=0x1000 + index * 0x10, name=name, name_source=source)

        payload = composition.compute_composition(conn, binary_id=target)

        assert payload["total_functions"] == 9
        assert [entry["label"] for entry in payload["name_sources"]] == list(
            composition.NAME_SOURCE_LABELS
        )
        buckets = _labelled(payload["name_sources"])
        assert buckets[composition.NAME_SOURCE_SYSTEM]["count"] == 2
        assert buckets[composition.NAME_SOURCE_AUTO_UNSTRIP]["count"] == 1
        assert buckets[composition.NAME_SOURCE_AI_AGENT]["count"] == 2
        assert buckets[composition.NAME_SOURCE_USER]["count"] == 2
        assert buckets[composition.NAME_SOURCE_NO_DEBUG_INFO]["count"] == 2
        assert buckets[composition.NAME_SOURCE_SYSTEM]["percent"] == pytest.approx(22.2)

    def test_placeholder_name_is_no_debug_info_whatever_the_source(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        analysis_id = _analysis(conn, target)
        _function(conn, analysis_id, va=0x1000, name="sub_1000", name_source="import")
        payload = composition.compute_composition(conn, binary_id=target)
        buckets = _labelled(payload["name_sources"])
        assert buckets[composition.NAME_SOURCE_NO_DEBUG_INFO]["count"] == 1
        assert buckets[composition.NAME_SOURCE_SYSTEM]["count"] == 0


class TestQualityBands:
    def test_each_band_including_no_match(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        analysis_id = _analysis(conn, target)
        sources = [
            _function(conn, analysis_id, va=0x1000 + index * 0x10, name=f"fn_{index}")
            for index in range(5)
        ]
        _other_id, candidates = _candidate_binary(
            conn, tmp_path, name="other.dll", sha="bb" * 32, vases=[0x2000, 0x2010, 0x2020, 0x2030]
        )
        for source, candidate, similarity in zip(
            sources[:4], candidates, [96.0, 85.0, 72.0, 55.0], strict=True
        ):
            store.record_match(
                conn,
                function_id=source,
                candidate_function_id=candidate,
                similarity=similarity,
                confidence=0.5,
            )

        payload = composition.compute_composition(conn, binary_id=target)

        assert payload["total_functions"] == 5
        assert payload["matched_functions"] == 4
        assert payload["matched_percent"] == pytest.approx(80.0)
        bands = _labelled(payload["match_quality"])
        assert [entry["label"] for entry in payload["match_quality"]] == list(
            composition.QUALITY_BANDS
        )
        assert bands[composition.BAND_STRONG_MATCH]["count"] == 1
        assert bands[composition.BAND_MATCH]["count"] == 1
        assert bands[composition.BAND_PARTIAL_MATCH]["count"] == 1
        assert bands[composition.BAND_WEAK_MATCH]["count"] == 1
        assert bands[composition.BAND_NO_MATCH]["count"] == 1
        assert bands[composition.BAND_NO_MATCH]["percent"] == pytest.approx(20.0)

        rows = {int(row["function_id"]): row for row in payload["functions"]}
        assert rows[sources[0]]["band"] == composition.BAND_STRONG_MATCH
        assert rows[sources[0]]["similarity"] == pytest.approx(96.0)
        assert rows[sources[0]]["matched_binary_name"] == "other.dll"
        assert rows[sources[3]]["band"] == composition.BAND_WEAK_MATCH
        assert rows[sources[4]]["band"] == composition.BAND_NO_MATCH
        assert rows[sources[4]]["similarity"] is None
        assert rows[sources[4]]["matched_binary_id"] is None

    def test_self_matches_are_excluded(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        analysis_id = _analysis(conn, target)
        first = _function(conn, analysis_id, va=0x1000, name="fn_0")
        second = _function(conn, analysis_id, va=0x1010, name="fn_1")
        other_id, (candidate,) = _candidate_binary(
            conn, tmp_path, name="other.dll", sha="bb" * 32, vases=[0x2000]
        )
        store.record_match(
            conn, function_id=first, candidate_function_id=second, similarity=99.0, confidence=1.0
        )
        store.record_match(
            conn,
            function_id=first,
            candidate_function_id=candidate,
            similarity=90.0,
            confidence=0.5,
        )
        store.record_match(
            conn, function_id=second, candidate_function_id=first, similarity=99.0, confidence=1.0
        )

        payload = composition.compute_composition(conn, binary_id=target)

        assert payload["matched_functions"] == 1
        rows = {int(row["function_id"]): row for row in payload["functions"]}
        assert rows[first]["matched_binary_id"] == other_id
        assert rows[second]["band"] == composition.BAND_NO_MATCH
        assert any("matched only within this binary" in note for note in payload["notes"])


class TestCompositionRollup:
    def test_counts_sort_by_count_then_binary_id(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        analysis_id = _analysis(conn, target)
        sources = [
            _function(conn, analysis_id, va=0x1000 + index * 0x10, name=f"fn_{index}")
            for index in range(4)
        ]
        first_id, (first_candidate,) = _candidate_binary(
            conn, tmp_path, name="first.dll", sha="bb" * 32, vases=[0x2000]
        )
        second_id, (second_candidate,) = _candidate_binary(
            conn, tmp_path, name="second.dll", sha="cc" * 32, vases=[0x3000]
        )
        third_id, (third_candidate,) = _candidate_binary(
            conn, tmp_path, name="third.dll", sha="dd" * 32, vases=[0x4000]
        )
        for source, candidate, similarity in (
            (sources[0], first_candidate, 90.0),
            (sources[1], first_candidate, 88.0),
            (sources[2], second_candidate, 92.0),
            (sources[3], third_candidate, 91.0),
        ):
            store.record_match(
                conn,
                function_id=source,
                candidate_function_id=candidate,
                similarity=similarity,
                confidence=0.5,
            )

        payload = composition.compute_composition(conn, binary_id=target)

        rollup = payload["composition"]
        assert [entry["binary_id"] for entry in rollup] == [first_id, second_id, third_id]
        assert rollup[0]["name"] == "first.dll"
        assert rollup[0]["sha256"] == "bb" * 32
        assert rollup[0]["count"] == 2
        assert rollup[0]["percent"] == pytest.approx(50.0)
        assert rollup[1]["count"] == 1
        assert rollup[1]["percent"] == pytest.approx(25.0)

    def test_no_matches_refines_false_with_the_run_hint(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target, payload = _payload(conn, tmp_path)
        assert payload["refined"] is False
        assert payload["matched_functions"] == 0
        assert payload["match_quality"][-1]["label"] == composition.BAND_NO_MATCH
        assert payload["match_quality"][-1]["count"] == 1
        assert payload["composition"] == []
        assert any("reportal match" in note for note in payload["notes"])
        assert target > 0


class TestCapsAndEdges:
    def test_function_rows_are_capped_but_counts_stay_exact(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        analysis_id = _analysis(conn, target)
        total = composition.MAX_ROWS + 1
        for index in range(total):
            _function(
                conn,
                analysis_id,
                va=0x1000 + index * 0x10,
                name=f"fn_{index}",
                name_source="rebrew",
            )

        payload = composition.compute_composition(conn, binary_id=target)

        assert payload["total_functions"] == total
        assert len(payload["functions"]) == composition.MAX_ROWS
        buckets = _labelled(payload["name_sources"])
        assert buckets[composition.NAME_SOURCE_SYSTEM]["count"] == total
        assert sum(entry["count"] for entry in payload["match_quality"]) == total
        assert any("showing" in note for note in payload["notes"])

    def test_empty_binary_percentages_are_missing(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="empty.exe", sha=SHA)
        _analysis(conn, target)
        payload = composition.compute_composition(conn, binary_id=target)
        assert payload["total_functions"] == 0
        assert payload["matched_percent"] is None
        assert all(entry["percent"] is None for entry in payload["name_sources"])
        assert all(entry["percent"] is None for entry in payload["match_quality"])

    def test_unknown_binary_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(composition.NoCompositionError) as excinfo:
            composition.compute_composition(conn, binary_id=999)
        assert excinfo.value.args[0] == "no binary with id 999"


class TestStoreRoundTrip:
    def test_run_stores_the_payload_under_the_scan_kind(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        analysis_id = _analysis(conn, target)
        _function(conn, analysis_id, va=0x1000, name="sub_1000")

        payload = composition.run_composition(conn, binary_id=target)

        assert payload["binary_id"] == target
        assert composition.stored_composition(conn, target) == payload
        latest_analysis_id = store.latest_analysis_for_binary(conn, target)
        assert store.get_scan(conn, latest_analysis_id or 0, store.SCAN_KIND_COMPOSITION) == payload

    def test_stored_composition_is_none_before_the_first_run(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        _analysis(conn, target)
        assert composition.stored_composition(conn, target) is None


class TestCompositionRoutes:
    def test_post_serves_and_get_round_trips(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        analysis_id = _analysis(conn, target)
        _function(conn, analysis_id, va=0x1000, name="sub_1000")

        status, headers, body = wsgi_request("POST", f"/api/binaries/{target}/composition")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == target
        assert payload["total_functions"] == 1
        assert payload["refined"] is False
        assert payload.pop("journal_action")

        status, headers, body = wsgi_request("GET", f"/api/binaries/{target}/composition")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_before_post_is_404_no_scan(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        _analysis(conn, target)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{target}/composition")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no composition scan for binary {target}" in payload["detail"]
        assert f"reportal composition {target}" in payload["detail"]

    def test_cli_json_stores_the_scan(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        target, _ = _payload(conn, tmp_path)
        result = runner.invoke(cli.app, ["composition", str(target), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["binary_id"] == target
        assert payload["refined"] is False
        analysis_id = store.latest_analysis_for_binary(conn, target)
        payload.pop("journal_action", None)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_COMPOSITION) == payload

    def test_cli_human_output_shows_the_breakdowns(
        self, conn: sqlite3.Connection, portal_db: Path, tmp_path: Path
    ) -> None:
        target, _ = _payload(conn, tmp_path)
        result = runner.invoke(cli.app, ["composition", str(target)])
        assert result.exit_code == 0, result.output
        assert "Function name sources" in result.output
        assert "Match quality" in result.output
        assert "No match" in result.output

    def test_cli_unknown_binary_fails(self, portal_db: Path) -> None:
        result = runner.invoke(cli.app, ["composition", "999", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 999" in result.stdout

    def test_unknown_binary_is_404_on_both_methods(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/composition")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        status, headers, body = wsgi_request("GET", "/api/binaries/999/composition")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


class TestCategories:
    """The hosted categories: a second grouping beside the buckets (entry 15)."""

    def test_every_category_is_present_even_when_empty(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        payload = composition.compute_composition(conn, binary_id=binary_id)
        assert [entry["category"] for entry in payload["categories"]] == list(
            composition.CATEGORIES
        )
        assert all(entry["count"] == 0 for entry in payload["categories"])
        assert payload["category_notes"]

    def test_a_library_name_is_a_library_function(self) -> None:
        assert composition.category_of("import", matched=True) == composition.CATEGORY_LIBRARY
        assert composition.category_of("symbol", matched=False) == composition.CATEGORY_LIBRARY

    def test_an_unmatched_function_is_unique_and_a_matched_one_malware(self) -> None:
        assert composition.category_of("user", matched=False) == composition.CATEGORY_UNIQUE
        assert composition.category_of("user", matched=True) == composition.CATEGORY_MALWARE

    def test_the_top_binaries_are_the_categorys_own_matches(self, conn: sqlite3.Connection) -> None:
        left, right, _source = _matched_pair(conn)
        payload = composition.compute_composition(conn, binary_id=left)
        categories = {entry["category"]: entry for entry in payload["categories"]}
        assert categories[composition.CATEGORY_MALWARE]["count"] == 1
        assert categories[composition.CATEGORY_MALWARE]["binaries"] == [
            {"binary_id": right, "name": "right.exe", "count": 1}
        ]

    def test_tags_come_from_the_matched_binaries(self, conn: sqlite3.Connection) -> None:
        left, right, _source = _matched_pair(conn)
        tag_id = store.create_tag(conn, "library")
        store.add_binary_tag(conn, right, tag_id)
        payload = composition.compute_composition(conn, binary_id=left)
        assert payload["tags"] == [{"id": tag_id, "name": "library", "count": 1}]


class TestCompositionScope:
    """The candidate scope the hosted settings sheet offers (entry 15)."""

    def test_a_scoped_run_keeps_only_the_named_candidates(self, conn: sqlite3.Connection) -> None:
        left, right, _source = _matched_pair(conn)
        scoped = composition.compute_composition(conn, binary_id=left, binary_ids=[right])
        assert scoped["matched_functions"] == 1
        assert scoped["scope"] == {"binary_ids": [right], "collection_ids": [], "binaries": 1}
        assert any("scoped to" in note for note in scoped["notes"])

        # A scope that names nobody the binary matched reads as no matches.
        empty = composition.compute_composition(conn, binary_id=left, binary_ids=[left])
        assert empty["matched_functions"] == 0

    def test_a_collection_scope_resolves_to_its_members(self, conn: sqlite3.Connection) -> None:
        left, right, _source = _matched_pair(conn)
        collection_id = store.create_collection(conn, name="corpus")
        store.add_collection_binary(conn, collection_id, right)
        scoped = composition.compute_composition(
            conn, binary_id=left, collection_ids=[collection_id]
        )
        assert scoped["matched_functions"] == 1
        assert scoped["scope"]["binaries"] == 1

    def test_an_unknown_scope_id_is_refused(self, conn: sqlite3.Connection) -> None:
        left, _right, _source = _matched_pair(conn)
        with pytest.raises(matching.InvalidSettingsError):
            composition.compute_composition(conn, binary_id=left, binary_ids=[999])
        with pytest.raises(matching.InvalidSettingsError):
            composition.compute_composition(conn, binary_id=left, collection_ids=[999])

    def test_the_scan_stores_the_scope_it_ran_under(self, conn: sqlite3.Connection) -> None:
        left, right, _source = _matched_pair(conn)
        payload = composition.run_composition(conn, binary_id=left, binary_ids=[right])
        stored = composition.stored_composition(conn, left)
        assert stored is not None
        assert stored["scope"]["binary_ids"] == [right]
        assert payload["scope"] == stored["scope"]

    def test_a_non_member_composes_only_against_visible_binaries(
        self, conn: sqlite3.Connection
    ) -> None:
        left, right, _source = _matched_pair(conn)
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
        store.set_binary_scope(conn, right, visibility="team", owner_team_id=team_id)

        hidden = composition.compute_composition(conn, binary_id=left, visible_to=stranger)
        assert hidden["matched_functions"] == 0
        member = composition.compute_composition(conn, binary_id=left, visible_to=ana)
        assert member["matched_functions"] == 1


class TestCompositionScopeSurfaces:
    """The scope reaches the route, the CLI and the tool."""

    def test_the_route_takes_the_scope(self, conn: sqlite3.Connection) -> None:
        left, right, _source = _matched_pair(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{left}/composition",
            body=json.dumps({"binary_ids": [right]}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["scope"]["binary_ids"] == [right]
        assert payload["categories"]

    def test_the_route_refuses_an_unknown_scope_id(self, conn: sqlite3.Connection) -> None:
        left, _right, _source = _matched_pair(conn)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{left}/composition",
            body=json.dumps({"binary_ids": [999]}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("400"), body
        assert json_body(body, headers)["error"] == "unknown binary"

    def test_the_route_rejects_a_bad_id_list(self, conn: sqlite3.Connection) -> None:
        left, _right, _source = _matched_pair(conn)
        status, _headers, body = wsgi_request(
            "POST",
            f"/api/binaries/{left}/composition",
            body=json.dumps({"binary_ids": "all"}),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("400"), body

    def test_the_cli_takes_the_scope(self, portal_db: Path, conn: sqlite3.Connection) -> None:
        left, right, _source = _matched_pair(conn)
        conn.commit()
        result = runner.invoke(
            cli.app, ["composition", str(left), "--binary-id", str(right), "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["scope"]["binary_ids"] == [right]

    def test_an_unknown_scope_id_fails_the_command(
        self, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        left, _right, _source = _matched_pair(conn)
        conn.commit()
        result = runner.invoke(cli.app, ["composition", str(left), "--binary-id", "999", "--json"])
        assert result.exit_code == 1, result.output
        assert "unknown binary" in result.output

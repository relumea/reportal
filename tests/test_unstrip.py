"""Tests for reportal.unstrip: proposal building and the scan orchestrators."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine

from reportal import store, unstrip

CONTEXT = "/projects/demo"


def _seed(
    conn: sqlite3.Connection,
    functions: list[tuple[int, str, str]],
    *,
    context: bool = True,
) -> dict[str, int]:
    """Seed a binary, an analysis and functions; return their ids.

    ``functions`` rows are ``(va, name, name_source)`` and are keyed in the
    result by the function's id.
    """
    binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    ids = {"binary": binary_id, "analysis": analysis_id}
    for index, (va, name, name_source) in enumerate(functions):
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=va, name=name, name_source=name_source
        )
        ids[f"fn{index}"] = function_id
    if context:
        store.set_rebrew_context(conn, binary_id, CONTEXT)
    return ids


def _candidate(va: int, name: str, *, confidence: float = 0.3) -> dict[str, Any]:
    return {
        "va": hex(va),
        "name": name,
        "module": "COMDLG32",
        "kind": "import",
        "confidence": confidence,
    }


def _function(function_id: int, va: int, name: str, source: str = "rebrew") -> dict[str, Any]:
    return {"id": function_id, "va": va, "name": name, "name_source": source}


class TestBuildProposals:
    def test_joins_on_va_and_builds_proposal(self) -> None:
        proposals = unstrip.build_proposals(
            [_candidate(0x1000, "ChooseFontW")], [_function(7, 0x1000, "sub_1000")]
        )
        assert proposals == [
            {
                "function_id": 7,
                "va": 0x1000,
                "current_name": "sub_1000",
                "proposed_name": "ChooseFontW",
                "module": "COMDLG32",
                "kind": "import",
                "confidence": pytest.approx(0.3),
            }
        ]

    def test_skips_candidate_without_a_function(self) -> None:
        assert unstrip.build_proposals([_candidate(0x1000, "ChooseFontW")], []) == []

    def test_skips_name_already_equal(self) -> None:
        proposals = unstrip.build_proposals(
            [_candidate(0x1000, "ChooseFontW")], [_function(7, 0x1000, "ChooseFontW")]
        )
        assert proposals == []

    def test_skips_user_authored_name(self) -> None:
        proposals = unstrip.build_proposals(
            [_candidate(0x1000, "ChooseFontW")], [_function(7, 0x1000, "my_name", "manual")]
        )
        assert proposals == []

    def test_engine_sourced_real_name_is_eligible(self) -> None:
        proposals = unstrip.build_proposals(
            [_candidate(0x1000, "ChooseFontW")], [_function(7, 0x1000, "OldName", "rebrew")]
        )
        assert [proposal["proposed_name"] for proposal in proposals] == ["ChooseFontW"]

    def test_applied_match_name_is_user_authored(self) -> None:
        proposals = unstrip.build_proposals(
            [_candidate(0x1000, "ChooseFontW")], [_function(7, 0x1000, "OldName", "match")]
        )
        assert proposals == []

    def test_placeholder_names_are_eligible_whatever_the_source(self) -> None:
        functions = [
            _function(1, 0x1000, "sub_1000", "manual"),
            _function(2, 0x2000, "fcn_2000", "manual"),
            _function(3, 0x3000, "FUN_3000", "manual"),
            _function(4, 0x4000, "", "manual"),
        ]
        candidates = [
            _candidate(0x1000, "A"),
            _candidate(0x2000, "B"),
            _candidate(0x3000, "C"),
            _candidate(0x4000, "D"),
        ]
        assert unstrip.build_proposals(candidates, functions) != []
        assert len(unstrip.build_proposals(candidates, functions)) == 4

    def test_sorts_by_confidence_then_va(self) -> None:
        candidates = [
            _candidate(0x3000, "Low", confidence=0.3),
            _candidate(0x2000, "High", confidence=0.9),
            _candidate(0x1000, "High", confidence=0.9),
        ]
        functions = [
            _function(1, 0x1000, "sub_1000"),
            _function(2, 0x2000, "sub_2000"),
            _function(3, 0x3000, "sub_3000"),
        ]
        proposals = unstrip.build_proposals(candidates, functions)
        assert [proposal["va"] for proposal in proposals] == [0x1000, 0x2000, 0x3000]

    def test_skips_candidate_with_unparsable_va(self) -> None:
        candidates = [{"va": "not-hex", "name": "X", "confidence": 0.3}]
        assert unstrip.build_proposals(candidates, [_function(1, 0x1000, "sub_1000")]) == []

    def test_skips_candidate_without_a_name(self) -> None:
        candidates = [{"va": "0x1000", "name": "  ", "confidence": 0.3}]
        assert unstrip.build_proposals(candidates, [_function(1, 0x1000, "sub_1000")]) == []


class TestRunUnstrip:
    def test_stores_scan_and_returns_payload(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew"), (0x2000, "sub_2000", "rebrew")])
        payload = unstrip.run_unstrip(conn, binary_id=ids["binary"], engine=fake_engine)
        assert payload["candidates"] == 2
        assert [proposal["proposed_name"] for proposal in payload["proposals"]] == [
            "ChooseFontW",
            "GetOpenFileNameW",
        ]
        assert payload["applied"] is False
        assert fake_engine.calls == ["identify_library"]
        assert fake_engine.identify_arg == CONTEXT
        stored = store.get_scan(conn, ids["analysis"], store.SCAN_KIND_UNSTRIP)
        assert stored == payload

    def test_raises_without_project_context(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")], context=False)
        with pytest.raises(unstrip.NoRebrewContextError, match="no analysis context yet"):
            unstrip.run_unstrip(conn, binary_id=ids["binary"], engine=fake_engine)
        assert fake_engine.calls == []

    def test_min_confidence_filters_proposals(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew"), (0x2000, "sub_2000", "rebrew")])

        def identify(project_dir: str | Path) -> dict[str, Any]:
            return {
                "candidates": [
                    _candidate(0x1000, "Low", confidence=0.3),
                    _candidate(0x2000, "High", confidence=0.9),
                ]
            }

        payload = unstrip.run_unstrip(
            conn, binary_id=ids["binary"], engine=fake_engine, ident=identify, min_confidence=0.5
        )
        assert payload["candidates"] == 2
        assert [proposal["proposed_name"] for proposal in payload["proposals"]] == ["High"]

    def test_injected_ident_keeps_the_engine_idle(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")])
        seen: list[str | Path] = []

        def identify(project_dir: str | Path) -> dict[str, Any]:
            seen.append(project_dir)
            return {"candidates": [_candidate(0x1000, "ChooseFontW")]}

        unstrip.run_unstrip(conn, binary_id=ids["binary"], engine=fake_engine, ident=identify)
        assert seen == [CONTEXT]
        assert fake_engine.calls == []

    def test_empty_candidates_store_an_empty_scan(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")])
        payload = unstrip.run_unstrip(
            conn,
            binary_id=ids["binary"],
            engine=fake_engine,
            ident=lambda project_dir: {"candidates": []},
        )
        assert payload == {
            "candidates": 0,
            "candidates_fingerprint": unstrip._candidates_fingerprint([]),
            "proposals": [],
            "applied": False,
        }
        assert store.get_scan(conn, ids["analysis"], store.SCAN_KIND_UNSTRIP) == payload

    def test_missing_candidates_key_is_empty(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")])
        payload = unstrip.run_unstrip(
            conn, binary_id=ids["binary"], engine=fake_engine, ident=lambda project_dir: {}
        )
        assert payload["candidates"] == 0

    def test_repeat_run_with_identical_candidates_is_a_noop(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")])
        candidates = {"candidates": [_candidate(0x1000, "ChooseFontW")]}
        first = unstrip.run_unstrip(
            conn,
            binary_id=ids["binary"],
            engine=fake_engine,
            ident=lambda project_dir: candidates,
        )
        assert first.get("unchanged") is None
        calls = list(fake_engine.calls)
        second = unstrip.run_unstrip(
            conn,
            binary_id=ids["binary"],
            engine=fake_engine,
            ident=lambda project_dir: candidates,
        )
        assert second["unchanged"] is True
        assert second["candidates_fingerprint"] == first["candidates_fingerprint"]
        assert second["proposals"] == first["proposals"]
        _ = calls


class TestApplyProposal:
    def test_applies_stored_proposal_and_records_history(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")])
        unstrip.run_unstrip(conn, binary_id=ids["binary"], engine=fake_engine)
        change = unstrip.apply_proposal(conn, function_id=ids["fn0"])
        assert change == {
            "function_id": ids["fn0"],
            "old_name": "sub_1000",
            "new_name": "ChooseFontW",
        }
        function = store.get_function(conn, ids["fn0"])
        assert function is not None
        assert function["name"] == "ChooseFontW"
        assert function["name_source"] == unstrip.UNSTRIP_SOURCE
        history = store.list_name_history(conn, ids["fn0"])
        assert len(history) == 1
        assert history[0]["source"] == "unstrip"
        assert history[0]["old_name"] == "sub_1000"

    def test_override_name_wins(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")])
        unstrip.run_unstrip(conn, binary_id=ids["binary"], engine=fake_engine)
        change = unstrip.apply_proposal(conn, function_id=ids["fn0"], new_name="CustomName")
        assert change["new_name"] == "CustomName"
        function = store.get_function(conn, ids["fn0"])
        assert function is not None
        assert function["name"] == "CustomName"

    def test_rejects_blank_name(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")])
        unstrip.run_unstrip(conn, binary_id=ids["binary"], engine=fake_engine)
        with pytest.raises(ValueError, match="must not be empty"):
            unstrip.apply_proposal(conn, function_id=ids["fn0"], new_name="   ")
        assert store.list_name_history(conn, ids["fn0"]) == []

    def test_unknown_function_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            unstrip.apply_proposal(conn, function_id=4242)

    def test_without_a_stored_proposal_raises(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew")])
        with pytest.raises(unstrip.NoProposalError, match="no stored unstrip proposal"):
            unstrip.apply_proposal(conn, function_id=ids["fn0"])

    def test_proposal_for_another_function_does_not_apply(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, [(0x1000, "sub_1000", "rebrew"), (0x2000, "sub_2000", "rebrew")])
        unstrip.run_unstrip(conn, binary_id=ids["binary"], engine=fake_engine)
        store.set_scan(
            conn,
            ids["analysis"],
            store.SCAN_KIND_UNSTRIP,
            {"candidates": 0, "proposals": [], "applied": False},
        )
        with pytest.raises(unstrip.NoProposalError):
            unstrip.apply_proposal(conn, function_id=ids["fn0"])

"""Tests for reportal.matching.MatchSettings: scope filtering and validation.

A deterministic scorer and disassembler mean no engine and no optional extra
are required.  The scored corpus is built with distinguishable format/arch
evidence so each scope provably changes the candidate set.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from reportal import auth, engines, matching, store

# Deterministic pair scores for the scoped corpus; an absent pair scores 0.
SCOPED_SCORES: dict[tuple[str, str], float] = {
    ("asm:a1", "asm:a2"): 95.0,
    ("asm:a1", "asm:b1"): 85.0,
    ("asm:a1", "asm:b2"): 70.0,
    ("asm:a2", "asm:a1"): 90.0,
    ("asm:a2", "asm:b1"): 40.0,
}


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    """The three-binary scoped corpus, with one function name per binary."""
    a = store.add_binary(conn, sha256="aa" * 32, name="a.exe", fmt="EXE", arch="x86_32")
    analysis_a = store.create_analysis(conn, binary_id=a, engine="manual")
    a1 = store.add_function(conn, analysis_id=analysis_a, va=0x1000, name="a1", size=16)
    a2 = store.add_function(conn, analysis_id=analysis_a, va=0x2000, name="a2", size=16)
    b = store.add_binary(conn, sha256="bb" * 32, name="b.so", fmt="ELF", arch="x86_64")
    analysis_b = store.create_analysis(conn, binary_id=b, engine="manual")
    b1 = store.add_function(conn, analysis_id=analysis_b, va=0x3000, name="b1", size=16)
    b2 = store.add_function(conn, analysis_id=analysis_b, va=0x4000, name="b2", size=16)
    c = store.add_binary(conn, sha256="cc" * 32, name="c.dll", fmt="ELF", arch="x86_64")
    store.set_fingerprint(conn, c, {"format": "pe", "arch": "x86_32"})
    analysis_c = store.create_analysis(conn, binary_id=c, engine="manual")
    c1 = store.add_function(conn, analysis_id=analysis_c, va=0x5000, name="c1", size=16)
    return {"a": a, "b": b, "c": c, "a1": a1, "a2": a2, "b1": b1, "b2": b2, "c1": c1}


def _disassembler(function: dict[str, Any]) -> str | None:
    return f"asm:{function['name']}"


def _scorer(left: str, right: str) -> float:
    return SCOPED_SCORES.get((left, right), 0.0)


def _run(
    conn: sqlite3.Connection,
    binary_id: int,
    settings: matching.MatchSettings | None = None,
    visible_to: Any | None = None,
) -> dict[str, int]:
    return matching.match_binary(
        conn,
        binary_id=binary_id,
        engine=engines.RebrewEngine(enabled=False),
        disassembler=_disassembler,
        scorer=_scorer,
        settings=settings,
        visible_to=visible_to,
    )


def _names(conn: sqlite3.Connection, function_id: int) -> list[str]:
    return [str(match["candidate_name"]) for match in store.list_matches(conn, function_id)]


class TestDefaults:
    def test_defaults_reproduce_the_unscoped_run(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        implicit = _run(conn, ids["a"])
        implicit_rows = {ids["a1"]: _names(conn, ids["a1"]), ids["a2"]: _names(conn, ids["a2"])}
        explicit = _run(conn, ids["a"], settings=matching.MatchSettings())
        assert explicit == implicit
        assert _names(conn, ids["a1"]) == implicit_rows[ids["a1"]]
        assert _names(conn, ids["a2"]) == implicit_rows[ids["a2"]]

    def test_defaults_keep_the_binarys_own_functions(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _run(conn, ids["a"], matching.MatchSettings(min_similarity=0.0))
        assert _names(conn, ids["a1"]) == ["a2", "b1", "b2", "c1"]

    def test_recorded_settings_round_trip(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        settings = matching.MatchSettings(min_similarity=80.0, top=2)
        _run(conn, ids["a"], settings)
        for match in store.list_matches(conn, ids["a1"]):
            assert match["settings"] == settings.payload()
        rows = matching.binary_match_rows(conn, ids["a"])
        assert rows
        assert rows[0]["settings"] == settings.payload()


class TestScopeFilters:
    def test_include_self_false_drops_the_binarys_own_functions(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        _run(
            conn,
            ids["a"],
            matching.MatchSettings(include_self=False, min_similarity=0.0),
        )
        # Only the binary's own function a2 is dropped; the other binaries stay.
        assert _names(conn, ids["a1"]) == ["b1", "b2", "c1"]

    def test_min_confidence_floor_keeps_only_the_confident_candidate(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        _run(conn, ids["a"], matching.MatchSettings(min_confidence=0.5))
        assert _names(conn, ids["a1"]) == ["a2"]

    def test_platform_scope_keeps_one_platform(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _run(conn, ids["a"], matching.MatchSettings(platforms=("windows",), min_similarity=50.0))
        assert _names(conn, ids["a1"]) == ["a2"]
        _run(conn, ids["a"], matching.MatchSettings(platforms=("linux",), min_similarity=0.0))
        assert _names(conn, ids["a1"]) == ["b1", "b2"]

    def test_platform_scope_prefers_the_stored_fingerprint(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        # Binary c's format column says ELF; its fingerprint says PE.  The
        # windows scope must admit it on the header-derived value.
        _run(conn, ids["a"], matching.MatchSettings(platforms=("windows",), min_similarity=0.0))
        assert _names(conn, ids["a1"]) == ["a2", "c1"]
        # The linux scope excludes it for the same reason.
        _run(conn, ids["a"], matching.MatchSettings(platforms=("linux",), min_similarity=0.0))
        assert _names(conn, ids["a1"]) == ["b1", "b2"]

    def test_architecture_scope_filters_candidates(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _run(conn, ids["a"], matching.MatchSettings(architectures=("x86_64",), min_similarity=0.0))
        assert _names(conn, ids["a1"]) == ["b1", "b2"]
        _run(conn, ids["a"], matching.MatchSettings(architectures=("arm64",), min_similarity=0.0))
        assert _names(conn, ids["a1"]) == []

    def test_binary_scope_restricts_the_corpus(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _run(
            conn,
            ids["a"],
            matching.MatchSettings(binary_ids=(ids["b"],), min_similarity=0.0),
        )
        assert _names(conn, ids["a1"]) == ["b1", "b2"]

    def test_collection_scope_restricts_the_corpus(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        collection = store.create_collection(conn, name="linux samples")
        store.add_collection_binary(conn, collection, ids["b"])
        _run(
            conn,
            ids["a"],
            matching.MatchSettings(collection_ids=(collection,), min_similarity=0.0),
        )
        assert _names(conn, ids["a1"]) == ["b1", "b2"]

    def test_empty_collection_scope_keeps_no_candidates(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        collection = store.create_collection(conn, name="empty")
        _run(
            conn,
            ids["a"],
            matching.MatchSettings(collection_ids=(collection,), min_similarity=0.0),
        )
        assert _names(conn, ids["a1"]) == []

    def test_a_non_member_matches_only_against_visible_binaries(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
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
        store.set_binary_scope(conn, ids["b"], visibility="team", owner_team_id=team_id)

        _run(
            conn,
            ids["a"],
            matching.MatchSettings(min_similarity=0.0),
            visible_to=stranger,
        )
        assert _names(conn, ids["a1"]) == ["a2", "c1"]
        _run(
            conn,
            ids["a"],
            matching.MatchSettings(min_similarity=0.0),
            visible_to=ana,
        )
        assert _names(conn, ids["a1"]) == ["a2", "b1", "b2", "c1"]


class TestRefusals:
    def test_unknown_platform(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.MatchSettings.from_request({"platforms": ["beos"]})
        assert raised.value.error == "invalid platform"
        assert "beos" in raised.value.detail

    def test_unknown_architecture(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.MatchSettings.from_request({"architectures": ["mips"]})
        assert raised.value.error == "invalid architecture"

    def test_min_similarity_out_of_range(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.MatchSettings.from_request({"min_similarity": 120.0})
        assert raised.value.error == "invalid min_similarity"

    def test_min_confidence_out_of_range(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.MatchSettings.from_request({"min_confidence": 1.5})
        assert raised.value.error == "invalid min_confidence"

    def test_include_self_must_be_boolean(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.MatchSettings.from_request({"include_self": "yes"})
        assert raised.value.error == "include_self must be a boolean"

    def test_binary_scope_rejects_a_non_list(self) -> None:
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.MatchSettings.from_request({"binary_ids": 3})
        assert raised.value.error == "binary_ids must be a list of integers"

    def test_unknown_binary_id(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.match_binary(
                conn,
                binary_id=1,
                engine=engines.RebrewEngine(enabled=False),
                disassembler=_disassembler,
                scorer=_scorer,
                settings=matching.MatchSettings(binary_ids=(999,)),
            )
        assert raised.value.error == "unknown binary"

    def test_unknown_collection_id(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(matching.InvalidSettingsError) as raised:
            matching.match_binary(
                conn,
                binary_id=ids["a"],
                engine=engines.RebrewEngine(enabled=False),
                disassembler=_disassembler,
                scorer=_scorer,
                settings=matching.MatchSettings(collection_ids=(999,)),
            )
        assert raised.value.error == "unknown collection"


class TestScopeNotes:
    def test_no_platform_scope_carries_no_note(self) -> None:
        assert matching.scope_notes(matching.MatchSettings()) == []

    def test_platform_scope_carries_the_coarse_filter_note(self) -> None:
        notes = matching.scope_notes(matching.MatchSettings(platforms=("windows",)))
        assert notes == [matching.PLATFORM_SCOPE_NOTE]

    def test_android_scope_names_the_linux_overlap(self) -> None:
        notes = matching.scope_notes(matching.MatchSettings(platforms=("android",)))
        assert matching.ANDROID_SCOPE_NOTE in notes

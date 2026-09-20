"""Tests for reportal.matching: ranking, floors, caching and summary counts.

Every test injects a deterministic scorer and disassembler, so no engine and
no optional extra are required.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest
from conftest import FakeEngine

from reportal import engines, matching, similarity, store

HAS_SIMILARITY = similarity.available()
requires_similarity = pytest.mark.skipif(
    not HAS_SIMILARITY, reason="similarity extra not installed"
)

# Deterministic pair scores; an absent pair is dissimilar.
PAIR_SCORES: dict[tuple[str, str], float] = {
    ("asm:a1", "asm:a2"): 95.0,
    ("asm:a1", "asm:b1"): 85.0,
    ("asm:a1", "asm:b2"): 70.0,
    ("asm:a2", "asm:a1"): 90.0,
    ("asm:a2", "asm:b1"): 60.0,
    ("asm:a2", "asm:b2"): 55.0,
}


def _disassembler(function: dict[str, Any]) -> str | None:
    return f"asm:{function['name']}"


def _scorer(left: str, right: str) -> float:
    return PAIR_SCORES.get((left, right), 0.0)


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    binary_a = store.add_binary(conn, sha256="aa" * 32, name="a.exe")
    analysis_a = store.create_analysis(conn, binary_id=binary_a, engine="manual")
    a1 = store.add_function(conn, analysis_id=analysis_a, va=0x1000, name="a1", size=16)
    a2 = store.add_function(conn, analysis_id=analysis_a, va=0x2000, name="a2", size=16)
    binary_b = store.add_binary(conn, sha256="bb" * 32, name="b.exe")
    analysis_b = store.create_analysis(conn, binary_id=binary_b, engine="manual")
    b1 = store.add_function(conn, analysis_id=analysis_b, va=0x3000, name="b1", size=16)
    b2 = store.add_function(conn, analysis_id=analysis_b, va=0x4000, name="b2", size=16)
    return {"a": binary_a, "b": binary_b, "a1": a1, "a2": a2, "b1": b1, "b2": b2}


def _seed_scoped(conn: sqlite3.Connection) -> dict[str, int]:
    """A corpus whose binaries carry distinguishable format/arch evidence.

    Binary ``a`` is a Windows PE, ``b`` a Linux ELF, and ``c`` carries suffix
    columns that disagree with its stored fingerprint: its ``format`` column
    says ELF while the fingerprint says PE, so a scoped run proves the
    fingerprint wins.
    """
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


def _candidate_names(conn: sqlite3.Connection, function_id: int) -> list[str]:
    """The candidate names of one source function, best similarity first."""
    return [str(match["candidate_name"]) for match in store.list_matches(conn, function_id)]


def _run(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    settings: matching.MatchSettings | None = None,
    disassembler: matching.Disassembler | None = None,
    progress: Any = None,
) -> dict[str, int]:
    return matching.match_binary(
        conn,
        binary_id=binary_id,
        engine=engines.RebrewEngine(enabled=False),
        disassembler=disassembler or _disassembler,
        scorer=_scorer,
        settings=settings,
        progress=progress,
    )


# Real listings for the prefilter tests: a1 and b1 are identical, a1 and a2
# differ by one immediate, and the rest share no structure at all.
REAL_TEXTS: dict[str, str] = {
    "a1": "push ebp\nmov ebp, esp\nmov eax, [ebp+8]\nadd eax, 1\npop ebp\nret",
    "a2": "push ebp\nmov ebp, esp\nmov eax, [ebp+8]\nadd eax, 2\npop ebp\nret",
    "a3": "xor eax, eax\nret",
    "b1": "push ebp\nmov ebp, esp\nmov eax, [ebp+8]\nadd eax, 1\npop ebp\nret",
    "b2": "call 0x401000\ntest eax, eax\njz 0x401020\nmov ecx, 3\nloop 0x401010",
    "b3": "int3\nint3\nint3\nint3",
}


def _real_disassembler(function: dict[str, Any]) -> str | None:
    return REAL_TEXTS.get(str(function["name"]))


def _seed_real(conn: sqlite3.Connection) -> dict[str, int]:
    """Two binaries whose functions carry real listings, for the real scorer."""
    ids: dict[str, int] = {}
    for name, sha, names in (
        ("a", "aa" * 32, ("a1", "a2", "a3")),
        ("b", "bb" * 32, ("b1", "b2", "b3")),
    ):
        binary_id = store.add_binary(conn, sha256=sha, name=f"{name}.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        ids[name] = binary_id
        for index, function_name in enumerate(names):
            ids[function_name] = store.add_function(
                conn,
                analysis_id=analysis_id,
                va=0x1000 + index * 0x100,
                name=function_name,
                size=16,
            )
    return ids


def _run_default_scorer(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    settings: matching.MatchSettings | None = None,
    disassembler: matching.Disassembler | None = None,
) -> dict[str, int]:
    """Run with the module's own scorer, which is what engages the prefilter."""
    return matching.match_binary(
        conn,
        binary_id=binary_id,
        engine=engines.RebrewEngine(enabled=False),
        disassembler=disassembler or _real_disassembler,
        settings=settings,
    )


def _match_rows(conn: sqlite3.Connection) -> list[tuple[int, int, float]]:
    cur = conn.execute(
        "SELECT function_id, candidate_function_id, similarity FROM matches"
        " ORDER BY function_id, candidate_function_id"
    )
    return [(int(row[0]), int(row[1]), float(row[2])) for row in cur.fetchall()]


class TestProgress:
    """The one granularity a run has: one report per source function."""

    def test_it_reports_every_source_function_in_order(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        seen: list[tuple[int, int]] = []

        _run(conn, ids["a"], progress=lambda done, total: seen.append((done, total)))

        assert seen == [(1, 2), (2, 2)]

    def test_a_run_without_a_sink_reports_nothing(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        summary = _run(conn, ids["a"])

        assert summary["functions"] == 2


class TestPrefilter:
    """The exact prefilter: fewer comparisons, the same recorded rows."""

    def test_a_pair_below_the_floor_is_never_scored(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        scored: list[tuple[str, str]] = []

        def fake_scorer(left: str, right: str) -> float:
            scored.append((left, right))
            return PAIR_SCORES.get((left, right), 0.0)

        def fake_jaccard(left: str, right: str) -> float:
            # Only a1 and a2 are close enough to be worth a real score.
            return 1.0 if {left, right} == {"asm:a1", "asm:a2"} else 0.0

        monkeypatch.setattr(similarity, "similarity", fake_scorer)
        monkeypatch.setattr(similarity, "jaccard", fake_jaccard)

        _run_default_scorer(
            conn,
            ids["a"],
            settings=matching.MatchSettings(min_similarity=80.0),
            disassembler=_disassembler,
        )

        assert sorted(scored) == [("asm:a1", "asm:a2"), ("asm:a2", "asm:a1")]
        assert _candidate_names(conn, ids["a1"]) == ["a2"]

    def test_the_floor_does_not_engage_for_a_caller_s_scorer(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)

        def boom(left: str, right: str) -> float:
            raise AssertionError("a caller's scorer must not carry the blended floor")

        monkeypatch.setattr(similarity, "jaccard", boom)

        # `_run` injects `_scorer`, so the floor is not applied at all.
        summary = _run(conn, ids["a"], settings=matching.MatchSettings(min_similarity=80.0))

        assert summary["pairs"] == 3

    @requires_similarity
    def test_it_records_the_same_rows_with_fewer_comparisons(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_real(conn)
        real = similarity.similarity
        calls: list[tuple[str, str]] = []

        def counting(left: str, right: str) -> float:
            calls.append((left, right))
            return real(left, right)

        monkeypatch.setattr(similarity, "similarity", counting)
        settings = matching.MatchSettings(min_similarity=80.0)

        # A floor of zero proves nothing, which is the full sweep.
        monkeypatch.setattr(similarity, "jaccard_floor", lambda score: 0.0)
        _run_default_scorer(conn, ids["a"], settings=settings)
        swept_rows = _match_rows(conn)
        swept_calls = len(calls)

        calls.clear()
        monkeypatch.undo()
        monkeypatch.setattr(similarity, "similarity", counting)
        _run_default_scorer(conn, ids["a"], settings=settings)

        assert _match_rows(conn) == swept_rows
        assert 0 < len(calls) < swept_calls, "the floor must skip work, not all of it"


class TestMatchBinary:
    def test_ranks_and_filters(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        summary = _run(conn, ids["a"])
        assert summary == {"functions": 2, "matched": 2, "pairs": 3}
        matches = store.list_matches(conn, ids["a1"])
        assert [m["candidate_name"] for m in matches] == ["a2", "b1"]
        assert matches[0]["similarity"] == pytest.approx(95.0)
        assert matches[0]["confidence"] > matches[1]["confidence"]

    def test_corpus_excludes_source_function(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _run(conn, ids["a"])
        for match in store.list_matches(conn, ids["a1"]):
            assert match["candidate_function_id"] != ids["a1"]

    def test_min_similarity_floor(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        summary = _run(conn, ids["a"], settings=matching.MatchSettings(min_similarity=90.0))
        assert summary["pairs"] == 2
        assert [m["candidate_name"] for m in store.list_matches(conn, ids["a1"])] == ["a2"]

    def test_top_caps_candidates(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        summary = _run(conn, ids["a"], settings=matching.MatchSettings(top=1))
        assert summary["pairs"] == 2
        assert [m["candidate_name"] for m in store.list_matches(conn, ids["a1"])] == ["a2"]

    def test_rerun_replaces_rows(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _run(conn, ids["a"], settings=matching.MatchSettings(min_similarity=80.0))
        assert len(store.list_matches(conn, ids["a1"])) == 2
        _run(conn, ids["a"], settings=matching.MatchSettings(min_similarity=95.0))
        assert [m["candidate_name"] for m in store.list_matches(conn, ids["a1"])] == ["a2"]

    def test_skips_functions_without_text(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        def partial(function: dict[str, Any]) -> str | None:
            return None if function["name"] == "b2" else f"asm:{function['name']}"

        summary = _run(conn, ids["a"], disassembler=partial)
        assert summary == {"functions": 2, "matched": 2, "pairs": 3}
        for function_id in (ids["a1"], ids["a2"]):
            for match in store.list_matches(conn, function_id):
                assert match["candidate_name"] != "b2"

    def test_scorer_none_without_extra_raises(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        monkeypatch.setattr(similarity, "available", lambda: False)
        with pytest.raises(similarity.SimilarityUnavailable):
            matching.match_binary(
                conn,
                binary_id=ids["a"],
                engine=engines.RebrewEngine(enabled=False),
                disassembler=_disassembler,
            )

    def test_binary_without_functions(self, conn: sqlite3.Connection) -> None:
        _seed(conn)
        empty = store.add_binary(conn, sha256="cc" * 32, name="c.exe")
        assert _run(conn, empty) == {"functions": 0, "matched": 0, "pairs": 0}

    def test_binary_match_rows(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        _run(conn, ids["a"])
        rows = matching.binary_match_rows(conn, ids["a"])
        assert rows[0]["similarity"] == pytest.approx(95.0)
        assert rows[0]["source_name"] == "a1"
        assert rows[0]["source_name_source"] == ""
        assert rows[0]["candidate_name"] == "a2"
        assert rows[0]["candidate_binary_id"] == ids["a"]
        assert rows[0]["candidate_binary_name"] == "a.exe"
        assert set(rows[0]) >= {"source_va", "candidate_va", "confidence"}
        assert rows[0]["source_arch"] == ""
        assert rows[0]["candidate_arch"] == ""
        assert rows[0]["cross_arch"] is False

    def test_records_the_isa_pair(self, conn: sqlite3.Connection) -> None:
        ids = _seed_scoped(conn)
        _run(conn, ids["a"])
        matches = {row["candidate_name"]: row for row in store.list_matches(conn, ids["a1"])}
        assert matches["a2"]["source_arch"] == "x86_32"
        assert matches["a2"]["candidate_arch"] == "x86_32"
        assert matches["b1"]["source_arch"] == "x86_32"
        assert matches["b1"]["candidate_arch"] == "x86_64"
        rows = {row["candidate_name"]: row for row in matching.binary_match_rows(conn, ids["a"])}
        assert rows["a2"]["cross_arch"] is False
        assert rows["b1"]["cross_arch"] is True


class TestCachedDisassembler:
    def test_engine_result_is_cached(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["a"], "/projects/a")
        function = store.get_function(conn, ids["a1"])
        assert function is not None
        disassemble = matching.cached_disassembler(conn, fake_engine)
        first = disassemble(function)
        second = disassemble(function)
        assert first == second
        assert fake_engine.calls == ["disassemble"]
        assert store.get_disasm(conn, ids["a1"]) == first

    def test_cache_hit_skips_engine(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        store.set_disasm(conn, ids["a1"], "cached listing")
        function = store.get_function(conn, ids["a1"])
        assert function is not None
        disassemble = matching.cached_disassembler(conn, fake_engine)
        assert disassemble(function) == "cached listing"
        assert fake_engine.calls == []

    def test_missing_context_returns_none(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        function = store.get_function(conn, ids["a1"])
        assert function is not None
        disassemble = matching.cached_disassembler(conn, fake_engine)
        assert disassemble(function) is None
        assert fake_engine.calls == []

    def test_engine_error_returns_none(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["a"], "/projects/a")

        def boom(*args: object, **kwargs: object) -> str:
            raise engines.EngineError("bad va")

        monkeypatch.setattr(fake_engine, "disassemble", boom)
        function = store.get_function(conn, ids["a1"])
        assert function is not None
        assert matching.cached_disassembler(conn, fake_engine)(function) is None
        assert store.get_disasm(conn, ids["a1"]) is None


# Real listings for the equivalence check, one per seeded function name.  They
# differ enough that the real scorer produces a spread of scores and a
# non-empty ranking.
LISTINGS: dict[str, str] = {
    "a1": "push ebp\nmov ebp, esp\nmov eax, [ebp+8]\nadd eax, 3\npop ebp\nret\n",
    "a2": "push ebp\nmov ebp, esp\nmov eax, [ebp+8]\nadd eax, 5\npop ebp\nret\n",
    "b1": "push ebx\nmov ebx, 2\nsub ebx, 1\nmov eax, ebx\npop ebx\nret\n",
    "b2": "xor ecx, ecx\ntest eax, eax\nje 0x401020\ninc ecx\nmov eax, ecx\nret\n",
}


def _listing_disassembler(function: dict[str, Any]) -> str | None:
    return LISTINGS[str(function["name"])]


@requires_similarity
class TestMatchBinaryEquivalence:
    def test_cached_and_uncached_scorers_store_identical_rows(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        similarity.clear_cache()
        matching.match_binary(
            conn,
            binary_id=ids["a"],
            engine=engines.RebrewEngine(enabled=False),
            disassembler=_listing_disassembler,
            scorer=similarity.similarity,
            settings=matching.MatchSettings(min_similarity=0.0, top=3),
        )
        cached_rows = matching.binary_match_rows(conn, ids["a"])
        assert cached_rows
        # __wrapped__ is lru_cache's uncached function, so this run prepares
        # both sides of every pair exactly like the pre-cache scorer did.
        monkeypatch.setattr(similarity, "_prepare", similarity._prepare.__wrapped__)
        matching.match_binary(
            conn,
            binary_id=ids["a"],
            engine=engines.RebrewEngine(enabled=False),
            disassembler=_listing_disassembler,
            scorer=similarity.similarity,
            settings=matching.MatchSettings(min_similarity=0.0, top=3),
        )
        uncached_rows = matching.binary_match_rows(conn, ids["a"])
        assert uncached_rows == cached_rows

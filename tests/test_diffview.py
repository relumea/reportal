"""Tests for the shared match-pair diff helper in reportal.diffview."""

from __future__ import annotations

import sqlite3

import pytest
from conftest import FakeEngine

from reportal import diffview, engines, similarity, store

LEFT_CODE = "void sub_1000(void)\n{\n  return;\n}\n"
RIGHT_CODE = "void sub_2000(void)\n{\n  int x = 1;\n  return;\n}\n"


def _seed(
    conn: sqlite3.Connection,
    *,
    context: bool = True,
    match: bool = True,
    decomp: bool = False,
) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    left = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16)
    right = store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16)
    if context:
        store.set_rebrew_context(conn, binary_id, "/projects/notepad-rebrew")
    if match:
        store.record_match(
            conn,
            function_id=left,
            candidate_function_id=right,
            similarity=88.0,
            confidence=0.5,
        )
    if decomp:
        store.set_decompilation(conn, left, LEFT_CODE, "kuna")
        store.set_decompilation(conn, right, RIGHT_CODE, "kuna")
    return {"binary": binary_id, "analysis": analysis_id, "left": left, "right": right}


class TestResolution:
    def test_unknown_function_raises_404(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(diffview.DiffError) as excinfo:
            diffview.function_diff(conn, engines.RebrewEngine(enabled=False), function_id=999)
        assert excinfo.value.status == 404
        assert excinfo.value.code == "function not found"

    def test_unknown_candidate_raises_404(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        with pytest.raises(diffview.DiffError) as excinfo:
            diffview.function_diff(conn, fake_engine, function_id=ids["left"], candidate_id=999)
        assert excinfo.value.status == 404
        assert excinfo.value.code == "candidate not found"

    def test_invalid_kind_raises_400(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(diffview.DiffError) as excinfo:
            diffview.function_diff(
                conn, engines.RebrewEngine(enabled=False), function_id=1, kind="bytes"
            )
        assert excinfo.value.status == 400
        assert excinfo.value.code == "invalid kind"

    def test_omitted_candidate_uses_best_recorded_match(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, decomp=True)
        payload = diffview.function_diff(conn, fake_engine, function_id=ids["left"])
        assert payload["right"]["function_id"] == ids["right"]
        assert payload["left"]["binary_id"] == ids["binary"]
        assert payload["right"]["binary_id"] == ids["binary"]

    def test_omitted_candidate_without_a_match_raises_404(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, match=False)
        with pytest.raises(diffview.DiffError) as excinfo:
            diffview.function_diff(
                conn, engines.RebrewEngine(enabled=False), function_id=ids["left"]
            )
        assert excinfo.value.status == 404
        assert excinfo.value.code == "no-match"


class TestSimilarity:
    def test_recorded_similarity_is_used(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, decomp=True)
        payload = diffview.function_diff(
            conn, fake_engine, function_id=ids["left"], candidate_id=ids["right"]
        )
        assert payload["similarity"] == 88.0

    def test_live_score_when_the_extra_is_available(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, match=False, decomp=True)
        monkeypatch.setattr(similarity, "available", lambda: True)
        monkeypatch.setattr(similarity, "similarity", lambda left, right: 42.0)
        payload = diffview.function_diff(
            conn, fake_engine, function_id=ids["left"], candidate_id=ids["right"]
        )
        assert payload["similarity"] == 42.0

    def test_similarity_is_null_without_a_stored_match_or_the_extra(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, match=False, decomp=True)
        monkeypatch.setattr(similarity, "available", lambda: False)
        payload = diffview.function_diff(
            conn, fake_engine, function_id=ids["left"], candidate_id=ids["right"]
        )
        assert payload["similarity"] is None


class TestListings:
    def test_decomp_uses_stored_rows_without_an_engine(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, decomp=True)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        payload = diffview.function_diff(
            conn, engines.get_engine(), function_id=ids["left"], candidate_id=ids["right"]
        )
        assert payload["kind"] == "decomp"
        assert payload["normalized"] is True
        assert payload["summary"]["insert"] > 0

    def test_decomp_computes_live_without_storing(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        payload = diffview.function_diff(
            conn, fake_engine, function_id=ids["left"], candidate_id=ids["right"]
        )
        assert payload["left"]["function_id"] == ids["left"]
        assert store.get_decompilation(conn, ids["left"]) is None
        assert fake_engine.calls == ["decompile", "decompile"]

    def test_disasm_reads_and_fills_the_cache(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        payload = diffview.function_diff(
            conn,
            fake_engine,
            function_id=ids["left"],
            candidate_id=ids["right"],
            kind="disasm",
        )
        assert payload["kind"] == "disasm"
        assert fake_engine.calls == ["disassemble", "disassemble"]
        assert store.get_disasm(conn, ids["left"]) is not None
        assert store.get_disasm(conn, ids["right"]) is not None

    def test_disasm_second_call_uses_the_cache(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        store.set_disasm(conn, ids["left"], "bits 32\nfunc_1000:")
        store.set_disasm(conn, ids["right"], "bits 32\nfunc_2000:")
        diffview.function_diff(
            conn,
            fake_engine,
            function_id=ids["left"],
            candidate_id=ids["right"],
            kind="disasm",
        )
        assert fake_engine.calls == []

    def test_no_engine_context_raises_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, context=False)
        with pytest.raises(diffview.DiffError) as excinfo:
            diffview.function_diff(
                conn,
                engines.RebrewEngine(enabled=False),
                function_id=ids["left"],
                candidate_id=ids["right"],
                kind="disasm",
            )
        assert excinfo.value.status == 400
        assert excinfo.value.code == "no-engine-context"

    def test_unavailable_engine_raises_503(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        with pytest.raises(diffview.DiffError) as excinfo:
            diffview.function_diff(
                conn,
                engines.RebrewEngine(enabled=False),
                function_id=ids["left"],
                candidate_id=ids["right"],
                kind="disasm",
            )
        assert excinfo.value.status == 503
        assert excinfo.value.code == "engine-unavailable"

    def test_engine_failure_raises_500(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)

        def boom(*args: object, **kwargs: object) -> str:
            raise engines.EngineError("rebrew asm exited with code 1")

        monkeypatch.setattr(fake_engine, "disassemble", boom)
        with pytest.raises(diffview.DiffError) as excinfo:
            diffview.function_diff(
                conn,
                fake_engine,
                function_id=ids["left"],
                candidate_id=ids["right"],
                kind="disasm",
            )
        assert excinfo.value.status == 500
        assert excinfo.value.code == "engine-error"

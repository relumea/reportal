"""Tests for reportal.function_triage: the heuristic, the run and its surfaces."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, FakeLlmClient, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, engines, function_triage, llm, mcp_server, store
from reportal._paths import DB_ENV
from reportal.function_triage import (
    FUNCTION_TRIAGE_KIND,
    HEURISTIC_NOTE,
    MAX_LIMIT,
    METHOD_HEURISTIC,
    METHOD_LLM,
    NO_ENGINE_REASON,
    NO_PROJECT_REASON,
    NO_SIZE_REASON,
    score_candidates,
)

runner = CliRunner()

TRIAGE_RESPONSE = (
    '{"summary": "Decrypts a buffer with a hardcoded key.", "score": 0.82,'
    ' "capabilities": ["crypto", "memory"]}'
)

DECOMPILED = "void sub_1000(void)\n{\n  return;\n}\n"


def _seed_binary(conn: sqlite3.Connection, tmp_path: Path, *, on_disk: bool = True) -> int:
    target = tmp_path / "demo.exe"
    if on_disk:
        target.write_bytes(b"MZ" + b"\x00" * 30)
    return store.add_binary(
        conn,
        sha256="a1" * 32,
        name="demo.exe",
        path=str(target) if on_disk else "",
    )


def _seed_functions(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    rows: list[tuple[int, str, int, str]],
) -> list[int]:
    """Seed one analysis with ``(va, name, size, status)`` function rows."""
    analysis_id = store.create_analysis(
        conn, binary_id=binary_id, engine="rebrew-import", status="done"
    )
    return [
        store.add_function(
            conn,
            analysis_id=analysis_id,
            va=va,
            name=name,
            size=size,
            status=status,
            name_source="rebrew",
        )
        for va, name, size, status in rows
    ]


def _project_context(conn: sqlite3.Connection, tmp_path: Path, binary_id: int) -> None:
    project = tmp_path / "rebrew-project"
    project.mkdir(exist_ok=True)
    (project / "rebrew-project.toml").write_text("[project]\n", encoding="utf-8")
    store.set_rebrew_context(conn, binary_id, str(project))


def _mcp_call(name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
    """Run one MCP tool through `tools/call`; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestScoreCandidates:
    def test_empty_input_ranks_nothing(self) -> None:
        assert score_candidates([]) == []

    def test_is_deterministic(self) -> None:
        rows = [
            {"function_id": 2, "name": "sub_2", "va": 0x2000, "size": 400, "status": "STUB"},
            {"function_id": 1, "name": "Named", "va": 0x1000, "size": 64, "status": "EXACT"},
        ]
        assert score_candidates(rows) == score_candidates(rows)

    def test_the_signals_are_named_reasons(self) -> None:
        ranked = score_candidates(
            [
                {
                    "function_id": 7,
                    "name": "sub_7",
                    "va": 0x1000,
                    "size": 8192,
                    "status": "NEAR_MATCHING",
                    "has_decompilation": True,
                    "match_count": 2,
                }
            ]
        )
        reasons = ranked[0]["reasons"]
        assert "size 8192 bytes" in reasons
        assert "status NEAR_MATCHING is not a byte match" in reasons
        assert "stored decompilation" in reasons
        assert "placeholder name 'sub_7'" in reasons
        assert "2 stored matches" in reasons

    def test_every_signal_saturates_at_one(self) -> None:
        ranked = score_candidates(
            [
                {
                    "function_id": 7,
                    "name": "sub_7",
                    "va": 0x1000,
                    "size": 1_000_000,
                    "status": "STUB",
                    "has_decompilation": True,
                    "match_count": 100,
                }
            ]
        )
        assert ranked[0]["heuristic_score"] == 1.0

    def test_a_matched_named_small_function_scores_zero(self) -> None:
        ranked = score_candidates(
            [
                {
                    "function_id": 1,
                    "name": "KnownFunction",
                    "va": 0x1000,
                    "size": 0,
                    "status": "EXACT",
                }
            ]
        )
        assert ranked[0]["heuristic_score"] == 0.0
        assert ranked[0]["reasons"] == []

    def test_the_bigger_unmatched_function_ranks_first(self) -> None:
        ranked = score_candidates(
            [
                {"function_id": 1, "name": "Named", "va": 0x1000, "size": 64, "status": "EXACT"},
                {
                    "function_id": 2,
                    "name": "sub_2000",
                    "va": 0x2000,
                    "size": 4096,
                    "status": "STUB",
                },
            ]
        )
        assert [row["function_id"] for row in ranked] == [2, 1]

    def test_equal_scores_sort_by_va(self) -> None:
        ranked = score_candidates(
            [
                {"function_id": 2, "name": "sub_2000", "va": 0x2000, "size": 64, "status": "STUB"},
                {"function_id": 1, "name": "sub_1000", "va": 0x1000, "size": 64, "status": "STUB"},
            ]
        )
        assert [row["va"] for row in ranked] == [0x1000, 0x2000]

    def test_placeholder_names_are_recognized(self) -> None:
        assert function_triage.is_placeholder_name("") is True
        assert function_triage.is_placeholder_name("sub_1000") is True
        assert function_triage.is_placeholder_name("FUNC_4") is True
        assert function_triage.is_placeholder_name("deadbeef") is True
        assert function_triage.is_placeholder_name("FreePrintSetup") is False

    def test_missing_signals_default_to_absent(self) -> None:
        ranked = score_candidates([{"function_id": 1, "name": "Named", "va": 0x10, "status": ""}])
        assert ranked[0]["has_decompilation"] is False
        assert ranked[0]["match_count"] == 0
        assert ranked[0]["heuristic_score"] == 0.0


class TestCandidateRows:
    def test_reads_the_store_signals(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")]
        )
        store.set_decompilation(conn, function_ids[0], DECOMPILED, "kuna")
        other = _seed_functions(conn, binary_id=binary_id, rows=[(0x2000, "Other", 64, "EXACT")])[0]
        store.record_match(
            conn,
            function_id=function_ids[0],
            candidate_function_id=other,
            similarity=80.0,
            confidence=0.5,
        )
        rows = function_triage.candidate_rows(conn, binary_id=binary_id)
        first = next(row for row in rows if row["function_id"] == function_ids[0])
        assert first["has_decompilation"] is True
        assert first["match_count"] == 1
        assert first["va"] == 0x1000
        assert first["size"] == 512


class TestHeuristicRun:
    def test_a_stored_decompilation_runs_without_an_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")]
        )
        store.set_decompilation(conn, function_ids[0], DECOMPILED, "kuna")
        result = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=False),
        )
        assert result["model"] == ""
        assert result["count"] == 1
        assert result["by_method"] == {METHOD_LLM: 0, METHOD_HEURISTIC: 1}
        entry = result["functions"][0]
        assert entry["method"] == METHOD_HEURISTIC
        assert entry["function_id"] == function_ids[0]
        assert entry["summary"].startswith("sub_1000 (STUB, 512 bytes, 0 stored matches):")
        assert entry["capabilities"] == []
        assert result["notes"] == [HEURISTIC_NOTE]

    def test_the_fallback_is_deterministic(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn,
            binary_id=binary_id,
            rows=[(0x1000, "sub_1000", 512, "STUB"), (0x2000, "Named", 64, "EXACT")],
        )
        store.set_decompilation(conn, function_ids[0], DECOMPILED, "kuna")
        first = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=False),
        )
        second = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=False),
        )
        assert first == second

    def test_a_function_with_neither_is_skipped(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")]
        )
        _project_context(conn, tmp_path, binary_id)
        result = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=False),
        )
        assert result["count"] == 0
        assert result["functions"] == []
        assert result["skipped"] == [
            {
                "function_id": function_ids[0],
                "name": "sub_1000",
                "va": 0x1000,
                "reason": NO_ENGINE_REASON,
            }
        ]
        assert store.get_ai_artifact(conn, function_ids[0], FUNCTION_TRIAGE_KIND) is None

    def test_a_binary_without_a_project_context_names_that_reason(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        _seed_functions(conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")])
        result = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=True),
        )
        assert result["skipped"][0]["reason"] == NO_PROJECT_REASON

    def test_a_zero_sized_function_names_that_reason(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        _seed_functions(conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 0, "STUB")])
        _project_context(conn, tmp_path, binary_id)
        result = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=True),
        )
        assert result["skipped"][0]["reason"] == NO_SIZE_REASON

    def test_disassembly_fills_in_for_a_missing_decompilation(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        _seed_functions(conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")])
        _project_context(conn, tmp_path, binary_id)
        result = function_triage.summarize_functions(conn, binary_id=binary_id)
        assert result["count"] == 1
        assert fake_engine.calls == ["disassemble"]


class TestLlmRun:
    def _seed(self, conn: sqlite3.Connection, tmp_path: Path) -> tuple[int, list[int]]:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn,
            binary_id=binary_id,
            rows=[(0x1000, "sub_1000", 512, "STUB"), (0x2000, "Named", 4096, "EXACT")],
        )
        store.set_decompilation(conn, function_ids[0], DECOMPILED, "kuna")
        store.set_decompilation(conn, function_ids[1], DECOMPILED, "kuna")
        return binary_id, function_ids

    def test_the_model_answers_every_function(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, function_ids = self._seed(conn, tmp_path)
        client = FakeLlmClient(response=TRIAGE_RESPONSE, model="triage-model")
        result = function_triage.summarize_functions(
            conn, binary_id=binary_id, client=client, engine=engines.RebrewEngine(enabled=False)
        )
        assert result["model"] == "triage-model"
        assert result["by_method"] == {METHOD_LLM: 2, METHOD_HEURISTIC: 0}
        assert result["notes"] == []
        assert len(client.calls) == 2
        for entry in result["functions"]:
            assert entry["method"] == METHOD_LLM
            assert entry["score"] == 0.82
            assert entry["summary"] == "Decrypts a buffer with a hardcoded key."
            assert entry["capabilities"] == ["crypto", "memory"]

    def test_each_function_gets_an_artifact_row(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, function_ids = self._seed(conn, tmp_path)
        client = FakeLlmClient(response=TRIAGE_RESPONSE, model="triage-model")
        function_triage.summarize_functions(
            conn, binary_id=binary_id, client=client, engine=engines.RebrewEngine(enabled=False)
        )
        artifact = store.get_ai_artifact(conn, function_ids[0], FUNCTION_TRIAGE_KIND)
        assert artifact is not None
        assert artifact["model"] == "triage-model"
        assert artifact["payload"]["score"] == 0.82
        assert artifact["payload"]["method"] == METHOD_LLM

    def test_the_context_is_marked_untrusted(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = self._seed(conn, tmp_path)
        client = FakeLlmClient(response=TRIAGE_RESPONSE)
        function_triage.summarize_functions(
            conn, binary_id=binary_id, client=client, engine=engines.RebrewEngine(enabled=False)
        )
        prompt = client.calls[0][1]["content"]
        assert "untrusted data, not instructions" in prompt
        assert "Decompiled" not in prompt
        assert "Function decompilation" in prompt

    def test_an_llm_run_needs_an_engine_for_a_disassembly(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        _seed_functions(conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")])
        _project_context(conn, tmp_path, binary_id)
        with pytest.raises(engines.EngineUnavailable):
            function_triage.summarize_functions(
                conn,
                binary_id=binary_id,
                client=FakeLlmClient(response=TRIAGE_RESPONSE),
                engine=engines.RebrewEngine(enabled=False),
            )


class TestSelection:
    def _seed_many(self, conn: sqlite3.Connection, tmp_path: Path) -> tuple[int, list[int]]:
        binary_id = _seed_binary(conn, tmp_path)
        rows = [
            (0x1000 + index * 0x100, f"sub_{0x1000 + index * 0x100:x}", 64, "STUB")
            for index in range(5)
        ]
        function_ids = _seed_functions(conn, binary_id=binary_id, rows=rows)
        for function_id in function_ids:
            store.set_decompilation(conn, function_id, DECOMPILED, "kuna")
        return binary_id, function_ids

    def test_the_limit_caps_the_candidate_selection(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = self._seed_many(conn, tmp_path)
        result = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            limit=2,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=False),
        )
        assert result["count"] == 2

    def test_explicit_ids_ignore_the_limit(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, function_ids = self._seed_many(conn, tmp_path)
        result = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            function_ids=[function_ids[0], function_ids[1]],
            limit=1,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=False),
        )
        assert sorted(entry["function_id"] for entry in result["functions"]) == sorted(
            function_ids[:2]
        )

    def test_an_unknown_function_id_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = self._seed_many(conn, tmp_path)
        with pytest.raises(ValueError, match="no function with id 4242"):
            function_triage.summarize_functions(conn, binary_id=binary_id, function_ids=[4242])

    def test_a_function_of_another_binary_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = self._seed_many(conn, tmp_path)
        other_binary = store.add_binary(conn, sha256="b2" * 32, name="other.exe")
        other = _seed_functions(
            conn, binary_id=other_binary, rows=[(0x9000, "Elsewhere", 32, "STUB")]
        )
        with pytest.raises(ValueError, match="no function with id"):
            function_triage.summarize_functions(conn, binary_id=binary_id, function_ids=[other[0]])

    def test_the_limit_is_bounded(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, _ = self._seed_many(conn, tmp_path)
        for bad in (0, MAX_LIMIT + 1):
            with pytest.raises(ValueError, match="limit must be between"):
                function_triage.summarize_functions(conn, binary_id=binary_id, limit=bad)

    def test_an_unknown_binary_is_a_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            function_triage.summarize_functions(conn, binary_id=4242)

    def test_entries_sort_by_score_then_va(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn,
            binary_id=binary_id,
            rows=[
                (0x1000, "SmallNamed", 32, "EXACT"),
                (0x2000, "sub_2000", 4096, "STUB"),
                (0x3000, "sub_3000", 4096, "STUB"),
            ],
        )
        for function_id in function_ids:
            store.set_decompilation(conn, function_id, DECOMPILED, "kuna")
        result = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=False),
        )
        scores = [entry["score"] for entry in result["functions"]]
        assert scores == sorted(scores, reverse=True)
        assert [entry["va"] for entry in result["functions"]] == [0x2000, 0x3000, 0x1000]


class TestStoredRoundTrip:
    def test_the_aggregate_is_stored_and_read_back(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")]
        )
        store.set_decompilation(conn, function_ids[0], DECOMPILED, "kuna")
        result = function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            client=llm.LlmClient(None),
            engine=engines.RebrewEngine(enabled=False),
        )
        assert function_triage.stored_function_triage(conn, binary_id=binary_id) == result
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_FUNCTION_TRIAGE) == result

    def test_no_scan_reads_back_none(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        assert function_triage.stored_function_triage(conn, binary_id=binary_id) is None
        assert function_triage.stored_function_triage(conn, binary_id=4242) is None


class TestFunctionTriageRoutes:
    def _seed(self, conn: sqlite3.Connection, tmp_path: Path) -> tuple[int, list[int]]:
        binary_id = _seed_binary(conn, tmp_path)
        rows = [
            (0x1000, "sub_1000", 512, "STUB"),
            (0x2000, "sub_2000", 4096, "STUB"),
        ]
        function_ids = _seed_functions(conn, binary_id=binary_id, rows=rows)
        for function_id in function_ids:
            store.set_decompilation(conn, function_id, DECOMPILED, "kuna")
        return binary_id, function_ids

    def test_post_without_an_llm_stores_the_heuristic_run(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id, _ = self._seed(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body="{}"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["model"] == ""
        assert payload["by_method"] == {METHOD_LLM: 0, METHOD_HEURISTIC: 2}
        assert payload.pop("journal_action")
        assert function_triage.stored_function_triage(conn, binary_id=binary_id) == payload

    def test_post_with_an_llm_uses_the_model(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id, _ = self._seed(conn, tmp_path)
        llm.set_client(FakeLlmClient(response=TRIAGE_RESPONSE, model="route-model"))
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body='{"limit": 1}'
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["model"] == "route-model"
        assert payload["count"] == 1
        assert payload["functions"][0]["score"] == 0.82

    def test_post_passes_explicit_function_ids(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id, function_ids = self._seed(conn, tmp_path)
        body = json.dumps({"function_ids": [function_ids[1]]})
        status, headers, raw = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body=body
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert [entry["function_id"] for entry in payload["functions"]] == [function_ids[1]]

    def test_get_serves_the_stored_run(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id, _ = self._seed(conn, tmp_path)
        status, headers, raw = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body="{}"
        )
        stored = json_body(raw, headers)
        assert stored.pop("journal_action")
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, raw = wsgi_request("GET", f"/api/binaries/{binary_id}/function-triage")
        assert status.startswith("200")
        assert json_body(raw, headers) == stored
        assert fake_engine.calls == []

    def test_get_without_a_run_is_404_no_scan(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/function-triage")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert "reportal function-triage" in payload["detail"]

    def test_get_404_unknown_binary(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/function-triage")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_404_unknown_binary(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/function-triage", body="{}")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_on_a_non_list_function_ids(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body='{"function_ids": 3}'
        )
        assert status.startswith("400")
        assert "list of integers" in json_body(body, headers)["error"]

    def test_post_400_on_an_unknown_function_id(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body='{"function_ids": [77]}'
        )
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid body"
        assert "no function with id 77" in payload["detail"]

    def test_post_400_on_a_bad_limit(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id, _ = self._seed(conn, tmp_path)
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body='{"limit": 0}'
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid body"
        assert fake_engine.calls == []

    def test_post_503_when_the_llm_path_needs_a_missing_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        _seed_functions(conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")])
        _project_context(conn, tmp_path, binary_id)
        llm.set_client(FakeLlmClient(response=TRIAGE_RESPONSE))
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body="{}"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        assert function_triage.stored_function_triage(conn, binary_id=binary_id) is None

    def test_post_succeeds_without_an_engine_and_no_llm(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")]
        )
        store.set_decompilation(conn, function_ids[0], DECOMPILED, "kuna")
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request(
            "POST", f"/api/binaries/{binary_id}/function-triage", body="{}"
        )
        assert status.startswith("200")
        assert json_body(body, headers)["count"] == 1


def _cli_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    with_decompilation: bool = True,
) -> tuple[int, list[int]]:
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ" + b"\x00" * 30)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="c3" * 32, name="demo.exe", path=str(target))
        function_ids = _seed_functions(
            conn,
            binary_id=binary_id,
            rows=[(0x1000, "sub_1000", 512, "STUB"), (0x2000, "Named", 4096, "EXACT")],
        )
        if with_decompilation:
            for function_id in function_ids:
                store.set_decompilation(conn, function_id, DECOMPILED, "kuna")
    return binary_id, function_ids


class TestFunctionTriageCommand:
    def test_json_without_a_client_prints_the_heuristic_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id, _ = _cli_seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["function-triage", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["model"] == ""
        assert payload["by_method"] == {METHOD_LLM: 0, METHOD_HEURISTIC: 2}
        assert all(entry["method"] == METHOD_HEURISTIC for entry in payload["functions"])

    def test_json_with_a_client_prints_the_model_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id, _ = _cli_seed(tmp_path, monkeypatch)
        llm.set_client(FakeLlmClient(response=TRIAGE_RESPONSE, model="cli-model"))
        result = runner.invoke(cli.app, ["function-triage", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["model"] == "cli-model"
        assert payload["functions"][0]["summary"] == ("Decrypts a buffer with a hardcoded key.")

    def test_human_output_carries_the_method_line_and_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id, _ = _cli_seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["function-triage", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "model none" in result.output
        assert "heuristic 2" in result.output
        assert "sub_1000" in result.output
        assert "Summary" in result.output

    def test_human_output_shows_the_model_and_capabilities(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id, _ = _cli_seed(tmp_path, monkeypatch)
        llm.set_client(FakeLlmClient(response=TRIAGE_RESPONSE, model="cli-model"))
        result = runner.invoke(cli.app, ["function-triage", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "model cli-model" in result.output
        assert "llm 2" in result.output
        assert "crypto, memory" in result.output

    def test_the_function_option_selects_one_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id, function_ids = _cli_seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["function-triage", str(binary_id), "--function", str(function_ids[1]), "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert [entry["function_id"] for entry in payload["functions"]] == [function_ids[1]]

    def test_an_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _cli_seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["function-triage", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.output

    def test_a_bad_limit_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id, _ = _cli_seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["function-triage", str(binary_id), "--limit", "0", "--json"]
        )
        assert result.exit_code == 1
        assert "limit must be between" in result.output


class TestFunctionTriageMcpTools:
    def test_get_without_a_run_is_a_structured_error(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        payload, is_error = _mcp_call("get_function_triage", {"binary_id": binary_id})
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_function_triage" in payload["detail"]

    def test_run_then_get_serves_the_stored_run(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")]
        )
        store.set_decompilation(conn, function_ids[0], DECOMPILED, "kuna")
        payload, is_error = _mcp_call("run_function_triage", {"binary_id": binary_id})
        assert is_error is False
        assert payload["count"] == 1
        assert payload["functions"][0]["method"] == METHOD_HEURISTIC

        stored, is_error = _mcp_call("get_function_triage", {"binary_id": binary_id})
        assert is_error is False
        payload.pop("journal_action", None)
        assert stored == payload

    def test_run_with_an_explicit_id(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        function_ids = _seed_functions(
            conn, binary_id=binary_id, rows=[(0x1000, "sub_1000", 512, "STUB")]
        )
        store.set_decompilation(conn, function_ids[0], DECOMPILED, "kuna")
        payload, is_error = _mcp_call(
            "run_function_triage",
            {"binary_id": binary_id, "function_ids": [function_ids[0]]},
        )
        assert is_error is False
        assert [entry["function_id"] for entry in payload["functions"]] == [function_ids[0]]

    def test_run_rejects_a_bad_limit(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn, tmp_path)
        payload, is_error = _mcp_call("run_function_triage", {"binary_id": binary_id, "limit": 0})
        assert is_error is True
        assert payload["error"] == "invalid params"

    def test_unknown_binary_is_a_tool_error(self, portal_db: Path) -> None:
        payload, is_error = _mcp_call("get_function_triage", {"binary_id": 4242})
        assert is_error is True
        assert payload["error"] == "binary not found"

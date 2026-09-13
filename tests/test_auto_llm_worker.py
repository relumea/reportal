"""Tests for the engine-verified ``llm_c_source`` auto worker."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from auto_helpers import (
    CANDIDATE_SOURCE,
    AutoFakeEngine,
    SourceLlmClient,
    get_function,
    make_context,
    seed_rows,
    write_rebrew_project,
)

from reportal import auto_llm_worker, auto_mode, auto_workers, engines, store
from reportal.auto_workers import WorkerContext, WorkerResult


@pytest.fixture(autouse=True)
def _no_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run retries without waiting; the delay schedule is asserted in test_auto_retry."""
    monkeypatch.setattr(auto_mode, "_sleep", lambda _seconds: None)


def _worker() -> auto_workers.Worker:
    worker = auto_workers.get_worker(auto_workers.WORKER_LLM_C_SOURCE)
    assert worker is not None
    return worker


def _context(
    conn: sqlite3.Connection,
    function_id: int,
    tmp_path: Path,
    *,
    engine: engines.RebrewEngine | None = None,
    llm_client: Any = None,
    execute: bool = False,
    keep_failures: bool = False,
    previous: dict[str, Any] | None = None,
    project: bool = True,
) -> WorkerContext:
    return make_context(
        conn,
        get_function(conn, function_id),
        project_dir=str(tmp_path) if project else None,
        engine=engine,
        llm_client=llm_client,
        execute=execute,
        keep_failures=keep_failures,
        previous=previous,
    )


class TestTargetConfig:
    def test_marker_and_reversed_dir_come_from_the_default_target(self, tmp_path: Path) -> None:
        write_rebrew_project(tmp_path)
        target = auto_llm_worker.target_config(str(tmp_path))
        assert target is not None
        assert target["marker"] == "NP"
        assert Path(str(target["reversed_dir"])) == tmp_path / "src" / "NP"

    def test_an_explicit_marker_wins(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            "[project]\n"
            'default_target = "notepad"\n'
            "\n"
            '[targets."notepad"]\n'
            'marker = "NOTEPAD"\n'
            'reversed_dir = "src/notepad"\n',
            encoding="utf-8",
        )
        target = auto_llm_worker.target_config(str(tmp_path))
        assert target is not None
        assert target["marker"] == "NOTEPAD"
        assert Path(str(target["reversed_dir"])) == tmp_path / "src" / "notepad"

    def test_defaults_mirror_rebrew_rules(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "server.dll"\n\n[targets."server.dll"]\n',
            encoding="utf-8",
        )
        target = auto_llm_worker.target_config(str(tmp_path))
        assert target is not None
        assert target["marker"] == "SERVERDLL"
        assert Path(str(target["reversed_dir"])) == tmp_path / "src" / "server.dll"

    def test_missing_config_is_none(self, tmp_path: Path) -> None:
        assert auto_llm_worker.target_config(str(tmp_path)) is None

    def test_config_without_targets_is_none(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text("[project]\n", encoding="utf-8")
        assert auto_llm_worker.target_config(str(tmp_path)) is None


class TestMarkerAndSlug:
    def test_marker_line_matches_the_rebrew_format(self) -> None:
        assert auto_llm_worker.marker_line("NP", 0x1000) == "// FUNCTION: NP 0x1000"

    def test_ensure_marker_prepends_the_canonical_line(self) -> None:
        text = auto_llm_worker.ensure_marker(CANDIDATE_SOURCE, "NP", 0x1000)
        assert text.splitlines()[0] == "// FUNCTION: NP 0x1000"
        assert text.endswith("\n")

    def test_ensure_marker_keeps_an_existing_one(self) -> None:
        source = "// FUNCTION: NP 0x1000\n\nint f(void) { return 0; }\n"
        text = auto_llm_worker.ensure_marker(source, "NP", 0x1000)
        assert text.count("// FUNCTION: NP 0x1000") == 1

    def test_ensure_marker_strips_a_fence(self) -> None:
        text = auto_llm_worker.ensure_marker("```c\nint f(void) {}\n```", "NP", 0x10)
        assert "```" not in text
        assert text.splitlines()[0] == "// FUNCTION: NP 0x10"

    def test_slug_sanitizes_the_symbol(self) -> None:
        assert auto_llm_worker.source_slug({"name": "My Func!", "va": 0x1000}) == "My_Func_"

    def test_slug_falls_back_to_the_address(self) -> None:
        assert auto_llm_worker.source_slug({"name": "sub_1000", "va": 0x1000}) == "func_1000"

    def test_slug_falls_back_when_nameless(self) -> None:
        assert auto_llm_worker.source_slug({"name": "", "va": 0xABC}) == "func_abc"


class TestPrompt:
    def test_prompt_carries_the_marker_listing_and_decompilation(self) -> None:
        messages = auto_llm_worker.build_messages(
            function={"name": "Work", "va": 0x1000, "size": 8},
            marker="NP",
            disassembly="bits 32\n",
            decompilation="int Work(void);\n",
            previous=None,
        )
        prompt = messages[-1]["content"]
        assert "// FUNCTION: NP 0x1000" in prompt
        assert "bits 32" in prompt
        assert "int Work(void);" in prompt

    def test_prompt_feeds_back_the_previous_delta(self) -> None:
        messages = auto_llm_worker.build_messages(
            function={"name": "Work", "va": 0x1000, "size": 8},
            marker="NP",
            disassembly="bits 32\n",
            decompilation="int Work(void);\n",
            previous={
                "engine_result": {
                    "status": "NEAR_MATCHING",
                    "match_count": 3,
                    "total": 4,
                    "mismatches": [{"offset": 2, "target": "0x90", "got": "0x91"}],
                }
            },
        )
        prompt = messages[-1]["content"]
        assert "NEAR_MATCHING" in prompt
        assert "3 of 4" in prompt
        assert "offset 2" in prompt


class TestDryRun:
    def test_a_dry_run_returns_the_candidate_without_writing(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        client = SourceLlmClient()
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=AutoFakeEngine(),
                llm_client=client,
            )
        )
        assert result.status == auto_workers.WORKER_IMPROVED
        assert result.verified is False
        assert "// FUNCTION: NP 0x1000" in str(result.detail["source"])
        assert result.written_files == []
        assert not (tmp_path / "src" / "NP" / "Work.c").exists()

    def test_a_dry_run_reaches_the_model_once(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        client = SourceLlmClient()
        _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=AutoFakeEngine(),
                llm_client=client,
            )
        )
        assert len(client.calls) == 1

    def test_a_dry_run_needs_no_engine_when_the_context_is_stored(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        function_id = ids["functions"][0]
        store.set_disasm(conn, function_id, "bits 32\n")
        store.set_decompilation(conn, function_id, "int Work(void);\n", "kuna")
        result = _worker().run(
            _context(
                conn,
                function_id,
                tmp_path,
                engine=engines.RebrewEngine(enabled=False),
                llm_client=SourceLlmClient(),
            )
        )
        assert result.status == auto_workers.WORKER_IMPROVED


class TestSkips:
    def test_without_an_llm_it_skips_with_llm_unavailable(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        result = _worker().run(_context(conn, ids["functions"][0], tmp_path))
        assert result.status == auto_workers.WORKER_SKIPPED
        assert result.detail["reason"] == auto_workers.REASON_LLM_UNAVAILABLE

    def test_without_a_project_context_it_skips(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),))
        result = _worker().run(
            _context(
                conn, ids["functions"][0], tmp_path, llm_client=SourceLlmClient(), project=False
            )
        )
        assert result.status == auto_workers.WORKER_SKIPPED
        assert result.detail["reason"] == auto_workers.REASON_NO_ENGINE_CONTEXT

    def test_without_a_target_config_it_skips(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        result = _worker().run(
            _context(conn, ids["functions"][0], tmp_path, llm_client=SourceLlmClient())
        )
        assert result.status == auto_workers.WORKER_SKIPPED
        assert result.detail["reason"] == auto_llm_worker.REASON_NO_MARKER

    def test_execute_without_an_engine_skips(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=engines.RebrewEngine(enabled=False),
                llm_client=SourceLlmClient(),
                execute=True,
            )
        )
        assert result.status == auto_workers.WORKER_SKIPPED
        assert result.detail["reason"] == auto_workers.REASON_ENGINE_UNAVAILABLE

    def test_a_taken_path_is_a_collision(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        existing = tmp_path / "src" / "NP" / "Work.c"
        existing.write_text("// someone else's file\n", encoding="utf-8")
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=AutoFakeEngine(),
                llm_client=SourceLlmClient(),
                execute=True,
            )
        )
        assert result.status == auto_workers.WORKER_SKIPPED
        assert result.detail["reason"] == auto_llm_worker.REASON_FILE_EXISTS
        assert existing.read_text(encoding="utf-8") == "// someone else's file\n"

    def test_a_model_error_is_a_failure(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        from conftest import FailingLlmClient

        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=AutoFakeEngine(),
                llm_client=FailingLlmClient(),
            )
        )
        assert result.status == auto_workers.WORKER_FAILED
        assert result.detail["reason"] == auto_llm_worker.REASON_LLM_ERROR


class TestExecute:
    def test_an_exact_verdict_matches_and_records_the_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        engine = AutoFakeEngine(statuses=("EXACT",))
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=engine,
                llm_client=SourceLlmClient(),
                execute=True,
            )
        )
        path = tmp_path / "src" / "NP" / "Work.c"
        assert result.status == auto_workers.WORKER_MATCHED
        assert result.verified is True
        assert result.status_after == "EXACT"
        assert result.written_files == [str(path)]
        assert result.status_changes == [
            {"function_id": ids["functions"][0], "before": "STUB", "after": "EXACT"}
        ]
        assert path.is_file()
        assert path.read_text(encoding="utf-8").splitlines()[0] == "// FUNCTION: NP 0x1000"
        assert engine.test_calls == [str(path)]

    def test_a_non_matching_status_fails_and_removes_the_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=AutoFakeEngine(statuses=("NEAR_MATCHING",)),
                llm_client=SourceLlmClient(),
                execute=True,
            )
        )
        assert result.status == auto_workers.WORKER_FAILED
        assert result.detail["reason"] == auto_llm_worker.REASON_NO_MATCHING_STATUS
        assert result.detail["engine_result"]["status"] == "NEAR_MATCHING"
        assert result.written_files == []
        assert not (tmp_path / "src" / "NP" / "Work.c").exists()

    def test_a_kept_failure_stays_recorded(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=AutoFakeEngine(statuses=("NEAR_MATCHING",)),
                llm_client=SourceLlmClient(),
                execute=True,
                keep_failures=True,
            )
        )
        path = tmp_path / "src" / "NP" / "Work.c"
        assert result.status == auto_workers.WORKER_FAILED
        assert result.written_files == [str(path)]
        assert path.is_file()

    def test_an_engine_error_is_a_failure_and_removes_the_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=_ExplodingEngine(),
                llm_client=SourceLlmClient(),
                execute=True,
            )
        )
        assert result.status == auto_workers.WORKER_FAILED
        assert result.detail["reason"] == auto_llm_worker.REASON_ENGINE_ERROR

    def test_nothing_back_from_the_model_is_a_failure(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=AutoFakeEngine(),
                llm_client=SourceLlmClient(response="   "),
                execute=True,
            )
        )
        assert result.status == auto_workers.WORKER_FAILED
        assert result.detail["reason"] == auto_llm_worker.REASON_NO_CANDIDATE


class TestRetry:
    def test_the_second_attempt_sees_the_first_delta(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        engine = AutoFakeEngine(statuses=("NEAR_MATCHING", "EXACT"))
        client = SourceLlmClient()
        run = auto_mode.run_auto(
            conn,
            binary_id=ids["binary"],
            worker=auto_workers.WORKER_LLM_C_SOURCE,
            execute=True,
            engine=engine,
            llm_client=client,
            max_attempts=2,
        )
        assert run["matched"] == 1
        assert run["attempts"] == 2
        prompts = [call[-1]["content"] for call in client.calls]
        assert "NEAR_MATCHING" in prompts[1]
        assert store.get_function(conn, ids["functions"][0])["status"] == "EXACT"  # type: ignore[index]

    def test_a_kept_failed_attempt_may_be_overwritten(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        path = tmp_path / "src" / "NP" / "Work.c"
        previous = {"written_files": [str(path)], "engine_result": {"status": "NEAR_MATCHING"}}
        result = _worker().run(
            _context(
                conn,
                ids["functions"][0],
                tmp_path,
                engine=AutoFakeEngine(statuses=("EXACT",)),
                llm_client=SourceLlmClient(),
                execute=True,
                keep_failures=True,
                previous=previous,
            )
        )
        assert result.status == auto_workers.WORKER_MATCHED

    def test_a_failure_removes_the_file_so_the_retry_starts_clean(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        engine = AutoFakeEngine(statuses=("NEAR_MATCHING", "NEAR_MATCHING"))
        run = auto_mode.run_auto(
            conn,
            binary_id=ids["binary"],
            worker=auto_workers.WORKER_LLM_C_SOURCE,
            execute=True,
            engine=engine,
            llm_client=SourceLlmClient(),
            max_attempts=2,
        )
        assert run["failed"] == 1
        assert not (tmp_path / "src" / "NP" / "Work.c").exists()
        batch = run["tree"][0]["children"][0]
        assert batch["result"]["written_files"] == []


class TestDryRunThroughTheOrchestrator:
    def test_a_dry_run_never_writes_a_file(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        ids = seed_rows(conn, rows=((0x1000, "Work", 8, "STUB"),), project_dir=str(tmp_path))
        write_rebrew_project(tmp_path)
        run = auto_mode.run_auto(
            conn,
            binary_id=ids["binary"],
            worker=auto_workers.WORKER_LLM_C_SOURCE,
            engine=AutoFakeEngine(),
            llm_client=SourceLlmClient(),
        )
        assert run["improved"] == 1
        assert run["matched"] == 0
        assert not (tmp_path / "src" / "NP" / "Work.c").exists()


class _ExplodingEngine(engines.RebrewEngine):
    """An engine whose verification call always fails."""

    def __init__(self) -> None:
        super().__init__()

    def available(self) -> bool:
        return True

    def test_source(self, project_dir: str | Path, source: str | Path) -> dict[str, Any]:
        raise engines.EngineError("compile failed")


def test_the_worker_is_registered() -> None:
    names = [worker.name for worker in auto_workers.workers()]
    assert auto_workers.WORKER_LLM_C_SOURCE in names


def test_a_result_defaults_to_no_writes() -> None:
    result = WorkerResult(status=auto_workers.WORKER_SKIPPED)
    assert result.written_files == []
    assert result.status_changes == []
    assert result.artifacts == []


@pytest.mark.parametrize(
    ("status", "accepted"),
    [("EXACT", True), ("RELOC", True), ("PROVEN", True), ("NEAR_MATCHING", False), ("STUB", False)],
)
def test_only_matching_statuses_are_terminal(status: str, accepted: bool) -> None:
    assert auto_workers.is_matching_status(status) is accepted

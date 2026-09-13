"""Shared seeding and stubs for the auto-mode test modules."""

from __future__ import annotations

import contextlib
import sqlite3
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, FakeLlmClient

from reportal import auto_workers, engines, store
from reportal._paths import DB_ENV
from reportal.auto_workers import Worker, WorkerContext, WorkerResult

# Function rows `seed_auto_portal` stores by default: one name-based symbol, one
# address placeholder, one already-matched function and one with no name.
DEFAULT_ROWS: tuple[tuple[int, str, int, str], ...] = (
    (0x1000, "FreePrintSetup", 47, "STUB"),
    (0x1100, "sub_1100", 16, "STUB"),
    (0x1200, "AlreadyMatches", 24, "EXACT"),
    (0x1300, "NeedsWork", 8, "NEAR_MATCHING"),
)

# A NASM listing and a decompilation shaped like the engine's own output, so
# the prompts a fake client receives read like a real worker's.
DISASSEMBLY = "bits 32\norg 0x00001000\n\nfunc_00001000:\n    ret\n"
DECOMPILATION = "int func_1000(void)\n{\n  return 0;\n}\n"

# A candidate source a fake client answers with, carrying no marker: the worker
# is expected to add the canonical one.
CANDIDATE_SOURCE = "int FreePrintSetup(void)\n{\n  return 0;\n}\n"

# The marker module `write_rebrew_project` configures.
PROJECT_MARKER = "NP"


def seed_rows(
    conn: sqlite3.Connection,
    *,
    rows: Sequence[tuple[int, str, int, str]] = DEFAULT_ROWS,
    project_dir: str | None = None,
) -> dict[str, Any]:
    """Add a binary, an analysis and the given functions to an existing connection.

    The path matches the ``portal_db`` fixture's database, so a test that takes
    the ``conn`` fixture can seed through this helper and read the rows back.
    """
    binary_id = store.add_binary(
        conn, sha256="cd" * 32, name="demo.exe", path=str(Path("/nonexistent/demo.exe"))
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_ids = [
        store.add_function(
            conn, analysis_id=analysis_id, va=va, name=name, size=size, status=status
        )
        for va, name, size, status in rows
    ]
    if project_dir is not None:
        store.set_rebrew_context(conn, binary_id, project_dir)
    return {
        "binary": binary_id,
        "analysis": analysis_id,
        "functions": function_ids,
    }


def seed_auto_portal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    rows: Sequence[tuple[int, str, int, str]] = DEFAULT_ROWS,
    project: bool = True,
) -> dict[str, Any]:
    """Create a portal DB with a binary, an analysis and the given functions."""
    db = tmp_path / "reportal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        project_dir = None
        if project:
            write_rebrew_project(tmp_path)
            project_dir = str(tmp_path)
        ids = seed_rows(conn, rows=rows, project_dir=project_dir)
    return {"db": str(db), **ids}


def write_rebrew_project(root: Path) -> Path:
    """Write a minimal rebrew project config with a marker and a source directory."""
    (root / "rebrew-project.toml").write_text(
        "[project]\n"
        'name = "demo"\n'
        'default_target = "NP"\n'
        "\n"
        '[targets."NP"]\n'
        'binary = "demo.exe"\n'
        'reversed_dir = "src/NP"\n',
        encoding="utf-8",
    )
    (root / "src" / "NP").mkdir(parents=True, exist_ok=True)
    return root


def get_function(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """One stored function row, raising when it is missing."""
    row = store.get_function(conn, function_id)
    if row is None:
        raise AssertionError(f"no function with id {function_id}")
    return row


def make_context(
    conn: sqlite3.Connection,
    function: dict[str, Any],
    *,
    project_dir: str | None = None,
    engine: Any = None,
    llm_client: Any = None,
    execute: bool = False,
    keep_failures: bool = False,
    previous: dict[str, Any] | None = None,
) -> WorkerContext:
    """A worker context for one function, with everything else defaulted."""
    return WorkerContext(
        conn=conn,
        function=function,
        project_dir=project_dir,
        engine=engine,
        llm_client=llm_client,
        execute=execute,
        keep_failures=keep_failures,
        previous=previous,
    )


class AutoFakeEngine(FakeEngine):
    """Engine stub with a scripted ``rebrew test`` verdict per call.

    ``statuses`` is consumed one entry per ``test_source`` call, so a test can
    script "NEAR_MATCHING first, EXACT on the retry"; the last entry repeats
    once the list runs out.
    """

    def __init__(self, *, statuses: Sequence[str] = ("EXACT",)) -> None:
        super().__init__()
        self.statuses = list(statuses)
        self.test_calls: list[str] = []
        self.test_sources: list[str] = []

    def disassemble(self, project_dir: str | Path, va: int, size: int, fmt: str = "nasm") -> str:
        self.calls.append("disassemble")
        return DISASSEMBLY

    def decompile(
        self,
        project_dir: str | Path,
        va: int,
        decompiler: str = engines.DEFAULT_DECOMPILER_BACKEND,
        named: bool = False,
    ) -> dict[str, Any]:
        self.calls.append("decompile")
        return {"va": hex(va), "backend": decompiler, "named": named, "code": DECOMPILATION}

    def test_source(self, project_dir: str | Path, source: str | Path) -> dict[str, Any]:
        self.calls.append("test_source")
        self.test_calls.append(str(source))
        path = Path(source)
        self.test_sources.append(path.read_text(encoding="utf-8") if path.is_file() else "")
        if not self.statuses:
            status = "NEAR_MATCHING"
        elif len(self.statuses) == 1:
            status = self.statuses[0]
        else:
            status = self.statuses.pop(0)
        return {
            "status": status,
            "match_count": 2 if status in store.MATCHED_STATUSES else 1,
            "total": 4,
            "mismatches": [{"offset": 1, "target": "0x55", "got": "0x56"}],
        }


class SourceLlmClient(FakeLlmClient):
    """A fake LLM that answers every prompt with a canned C source."""

    def __init__(self, response: str = CANDIDATE_SOURCE) -> None:
        super().__init__(response=response, model="auto-model")


class WorkerProbe:
    """A worker factory that records calls and the peak number of live calls."""

    def __init__(
        self,
        *,
        sleep: float = 0.0,
        status: str = auto_workers.WORKER_MATCHED,
        verified: bool = True,
        status_after: str = "EXACT",
        artifacts: bool = False,
    ) -> None:
        self.sleep = sleep
        self.status = status
        self.verified = verified
        self.status_after = status_after
        self.artifacts = artifacts
        self.calls: list[int] = []
        self.peak_live = 0
        self._live = 0
        self._lock = threading.Lock()

    def make(self, name: str = "probe") -> Worker:
        """Build the probe worker under *name*."""

        def run(ctx: WorkerContext) -> WorkerResult:
            with self._lock:
                self._live += 1
                self.peak_live = max(self.peak_live, self._live)
            try:
                if self.sleep:
                    time.sleep(self.sleep)
                function_id = int(ctx.function["id"])
                with self._lock:
                    self.calls.append(function_id)
                after = self.status_after if self.status == auto_workers.WORKER_MATCHED else ""
                return WorkerResult(
                    status=self.status,
                    function_id=function_id,
                    status_before=str(ctx.function["status"]),
                    status_after=after,
                    verified=self.verified,
                    detail={"reason": "probe"},
                    artifacts=[{"kind": "c-source", "source": CANDIDATE_SOURCE}]
                    if self.artifacts
                    else [],
                )
            finally:
                with self._lock:
                    self._live -= 1

        return Worker(name=name, description="test probe worker", run=run)


@pytest.fixture()
def fake_auto_engine() -> AutoFakeEngine:
    """A scripted auto engine installed process-wide, with an EXACT verdict."""
    engine = AutoFakeEngine()
    engines.set_engine(engine)
    return engine


def writer_worker(path: Path, name: str = "writer") -> Worker:
    """A worker that writes a source file and claims a verified match.

    It honours ``execute`` the way the real worker does: a dry run returns the
    candidate as an artifact without touching the disk.  Registered under
    ``name``, it also records the file and the status it replaced, which is what
    a revert replays.
    """

    def run(ctx: WorkerContext) -> WorkerResult:
        function_id = int(ctx.function["id"])
        before = str(ctx.function["status"])
        source = (
            f"// FUNCTION: NP {hex(int(ctx.function['va']))}\n\nint Work(void) {{ return 0; }}\n"
        )
        if not ctx.execute:
            return WorkerResult(
                status=auto_workers.WORKER_IMPROVED,
                function_id=function_id,
                status_before=before,
                detail={"reason": "dry-run", "source": source},
                artifacts=[{"kind": "c-source", "source": source}],
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return WorkerResult(
            status=auto_workers.WORKER_MATCHED,
            function_id=function_id,
            status_before=before,
            status_after="EXACT",
            verified=True,
            detail={"path": str(path)},
            artifacts=[{"kind": "c-source", "path": str(path)}],
            written_files=[str(path)],
            status_changes=[{"function_id": function_id, "before": before, "after": "EXACT"}],
        )

    return Worker(name=name, description="Writes a candidate source file.", run=run)

"""Analysing an uploaded binary: intake into a generated project, then the import."""

from __future__ import annotations

import contextlib
import hashlib
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request

from reportal import engines, jobs, rebrew_import, store
from reportal._paths import db_path

BINARY_BYTES = b"MZ" + b"\x90" * 62


class ProjectWritingEngine(engines.RebrewEngine):
    """An engine whose intake writes the project the real one would: config,
    the copied binary and a coverage.db with two functions."""

    def __init__(self) -> None:
        super().__init__(enabled=True)
        self.calls: list[tuple[Path, Path, str]] = []

    def intake(self, binary: str | Path, project_dir: str | Path, *, target: str) -> dict[str, Any]:
        root = Path(project_dir)
        self.calls.append((Path(binary), root, target))
        (root / "original").mkdir(parents=True, exist_ok=True)
        (root / "db").mkdir(exist_ok=True)
        shutil.copyfile(binary, root / "original" / f"{target}.exe")
        (root / "rebrew-project.toml").write_text(
            f'[project]\nname = "{target}"\ndb_dir = "db"\n\n'
            f'[targets.{target}]\nbinary = "original/{target}.exe"\n'
            'arch = "x86_64"\nformat = "elf"\n',
            encoding="utf-8",
        )
        coverage = sqlite3.connect(root / "db" / "coverage.db")
        try:
            coverage.execute(
                "CREATE TABLE IF NOT EXISTS functions ("
                " target TEXT, va INTEGER, name TEXT, size INTEGER,"
                " status TEXT, markerType TEXT)"
            )
            coverage.execute("DELETE FROM functions")
            coverage.executemany(
                "INSERT INTO functions VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (target, 0x1000, "fcn_00001000", 32, "STUB", "FUNCTION"),
                    (target, 0x1020, "fcn_00001020", 16, "STUB", "FUNCTION"),
                ],
            )
            coverage.commit()
        finally:
            coverage.close()
        return {"target": target, "functions": 2, "family": "msvc"}


class FailingEngine(engines.RebrewEngine):
    def __init__(self) -> None:
        super().__init__(enabled=True)

    def intake(self, binary: str | Path, project_dir: str | Path, *, target: str) -> dict[str, Any]:
        raise engines.EngineError("rebrew intake failed: no functions discovered")


@pytest.fixture()
def projects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "projects"
    monkeypatch.setattr(rebrew_import, "projects_dir", lambda: directory)
    return directory


def _stored_binary(conn: sqlite3.Connection, tmp_path: Path, name: str = "holiday.exe") -> int:
    path = tmp_path / "binaries" / "upload.exe"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(BINARY_BYTES)
    return store.add_binary(
        conn,
        sha256=hashlib.sha256(BINARY_BYTES).hexdigest(),
        name=name,
        path=str(path),
        size=len(BINARY_BYTES),
        fmt="EXE",
    )


class TestTargetName:
    @pytest.mark.parametrize(
        ("display", "expected"),
        [
            ("holiday.exe", "holiday"),
            ("win2k calc.exe", "win2k_calc"),
            ("2k-calc.exe", "t_2k_calc"),
            ("...", "target"),
            ("libfoo.so.1", "libfoo_so"),
        ],
    )
    def test_names_are_rebrew_safe(self, display: str, expected: str) -> None:
        assert rebrew_import.target_name(display) == expected


class TestAnalyseBinary:
    def test_imports_the_generated_project_onto_the_uploaded_row(
        self, conn: sqlite3.Connection, tmp_path: Path, projects: Path
    ) -> None:
        binary_id = _stored_binary(conn, tmp_path)
        engine = ProjectWritingEngine()
        engines.set_engine(engine)

        summary = rebrew_import.analyse_binary(binary_id)

        sha256 = hashlib.sha256(BINARY_BYTES).hexdigest()
        stored = tmp_path / "binaries" / "upload.exe"
        assert engine.calls == [(stored, projects / sha256, "holiday")]
        assert summary["intake"]["functions"] == 2
        assert [target["binary_id"] for target in summary["targets"]] == [binary_id]
        binary = store.get_binary(conn, binary_id)
        assert binary is not None
        assert binary["name"] == "holiday.exe"
        assert binary["function_count"] == 2
        assert store.get_rebrew_context(conn, binary_id) == str((projects / sha256).resolve())

    def test_the_import_fills_a_blank_format_and_isa_only(
        self, conn: sqlite3.Connection, tmp_path: Path, projects: Path
    ) -> None:
        engines.set_engine(ProjectWritingEngine())
        suffixed = _stored_binary(conn, tmp_path)
        rebrew_import.analyse_binary(suffixed)
        binary = store.get_binary(conn, suffixed)
        assert binary is not None
        # The upload's suffix-derived format stands; the blank ISA is filled.
        assert (binary["format"], binary["arch"]) == ("EXE", "x86_64")
        conn.execute("UPDATE binaries SET format = '', arch = '' WHERE id = ?", (suffixed,))
        conn.commit()
        rebrew_import.analyse_binary(suffixed)
        binary = store.get_binary(conn, suffixed)
        assert binary is not None
        assert (binary["format"], binary["arch"]) == ("elf", "x86_64")

    def test_a_second_run_refreshes_instead_of_duplicating(
        self, conn: sqlite3.Connection, tmp_path: Path, projects: Path
    ) -> None:
        binary_id = _stored_binary(conn, tmp_path)
        engines.set_engine(ProjectWritingEngine())
        rebrew_import.analyse_binary(binary_id)
        again = rebrew_import.analyse_binary(binary_id)
        assert again["created_functions"] == 0
        assert again["updated_functions"] == 2
        binary = store.get_binary(conn, binary_id)
        assert binary is not None and binary["function_count"] == 2

    def test_unknown_binary_and_missing_file_are_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, projects: Path
    ) -> None:
        engines.set_engine(ProjectWritingEngine())
        with pytest.raises(rebrew_import.RebrewImportError, match="no binary with id 999"):
            rebrew_import.analyse_binary(999)
        binary_id = _stored_binary(conn, tmp_path)
        (tmp_path / "binaries" / "upload.exe").unlink()
        with pytest.raises(rebrew_import.RebrewImportError, match="no stored file"):
            rebrew_import.analyse_binary(binary_id)


class DeletingEngine(ProjectWritingEngine):
    """Writes the project, and the binary is deleted before the import runs."""

    def intake(self, binary: str | Path, project_dir: str | Path, *, target: str) -> dict[str, Any]:
        report = super().intake(binary, project_dir, target=target)
        with contextlib.closing(store.connect(db_path())) as conn:
            conn.execute("DELETE FROM binaries")
            conn.commit()
        return report


class TestDeletedDuringAnalysis:
    def test_a_deleted_binary_is_not_registered_again(
        self, conn: sqlite3.Connection, tmp_path: Path, projects: Path
    ) -> None:
        binary_id = _stored_binary(conn, tmp_path)
        engines.set_engine(DeletingEngine())
        with pytest.raises(rebrew_import.RebrewImportError, match="deleted while it was analysed"):
            rebrew_import.analyse_binary(binary_id)
        assert store.list_binaries(conn) == []


class TestAnalyseJob:
    def test_the_job_imports_and_records_the_summary(
        self, conn: sqlite3.Connection, tmp_path: Path, projects: Path
    ) -> None:
        binary_id = _stored_binary(conn, tmp_path)
        engines.set_engine(ProjectWritingEngine())
        job = jobs.submit(conn, kind=jobs.ANALYSE_KIND, binary_id=binary_id)
        [finished] = jobs.run_pending(conn, limit=1)
        assert finished["id"] == job["id"]
        assert finished["status"] == jobs.STATUS_DONE
        assert finished["result"]["created_functions"] == 2
        # The fake project names no ISA or format, so only the universal scans follow.
        queued = [jobs.get_job(conn, job_id) for job_id in finished["result"]["follow_up_jobs"]]
        assert [(job["kind"], job["params"].get("domain")) for job in queued if job] == [
            (kind, params.get("domain")) for kind, params in jobs.ANALYSIS_FOLLOW_UPS
        ]
        assert all(job and job["status"] == jobs.STATUS_QUEUED for job in queued)
        # Placeholder-named functions of the new binary name nothing: not candidates.
        assert [job["params"] for job in queued if job and job["kind"] == "match"] == [
            {"include_self": False}
        ]

    @pytest.mark.parametrize(
        ("fmt", "extra"),
        [("ne", ()), ("elf", ()), ("pe", ("related",))],
    )
    def test_follow_ups_fit_the_target(self, fmt: str, extra: tuple[str, ...]) -> None:
        kinds = [kind for kind, _params in jobs.analysis_follow_ups(fmt)]
        universal = [kind for kind, _params in jobs.ANALYSIS_FOLLOW_UPS]
        # Every ISA is triaged and matched: both read the cached listing format.
        assert universal[-2:] == ["function-triage", "match"]
        assert kinds == universal + list(extra)

    def test_an_engine_refusal_fails_the_job_with_its_reason(
        self, conn: sqlite3.Connection, tmp_path: Path, projects: Path
    ) -> None:
        binary_id = _stored_binary(conn, tmp_path)
        engines.set_engine(FailingEngine())
        jobs.submit(conn, kind=jobs.ANALYSE_KIND, binary_id=binary_id)
        [finished] = jobs.run_pending(conn, limit=1)
        assert finished["status"] == jobs.STATUS_FAILED
        assert "no functions discovered" in finished["error"]


class TestUploadQueuesAnalysis:
    def test_a_new_binary_queues_one_analyse_job(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        boundary = "reportal-test"
        body = (
            (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="holiday.exe"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + BINARY_BYTES
            + f"\r\n--{boundary}--\r\n".encode()
        )
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}

        status, response_headers, raw = wsgi_request(
            "POST", "/api/binaries", body=body, headers=headers
        )
        assert status.startswith("200")
        payload = json_body(raw, response_headers)
        assert payload["analysis_job"]["status"] == jobs.STATUS_QUEUED
        with contextlib.closing(store.connect(portal_db)) as conn:
            job = jobs.get_job(conn, payload["analysis_job"]["id"])
            assert job is not None
            assert job["kind"] == jobs.ANALYSE_KIND
            assert job["binary_id"] == payload["id"]

        # The same bytes again are a duplicate: nothing new to analyse.
        status, response_headers, raw = wsgi_request(
            "POST", "/api/binaries", body=body, headers=headers
        )
        again = json_body(raw, response_headers)
        assert (again["duplicate"], again["analysis_job"]) == (True, None)


class TestEngineIntake:
    def test_an_unanalysable_binary_is_a_named_engine_error(self, tmp_path: Path) -> None:
        # The real child process: a stub with no code has no functions to
        # discover, and the engine's refusal comes back bounded.
        binary = tmp_path / "empty.exe"
        binary.write_bytes(BINARY_BYTES)
        engine = engines.RebrewEngine(enabled=True)
        if not engine.available():  # pragma: no cover - rebrew is a base dependency
            pytest.skip("rebrew is not importable")
        with pytest.raises(engines.EngineError, match="rebrew intake failed"):
            engine.intake(binary, tmp_path / "project", target="empty")

    def test_a_wedged_intake_times_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary = tmp_path / "a.exe"
        binary.write_bytes(BINARY_BYTES)

        def wedged(*_args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd="rebrew intake", timeout=kwargs["timeout"])

        monkeypatch.setattr(engines.subprocess, "run", wedged)
        with pytest.raises(engines.EngineError, match="did not finish within 600 seconds"):
            engines.RebrewEngine(enabled=True).intake(binary, tmp_path / "p", target="a")

    def test_output_that_is_not_a_report_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary = tmp_path / "a.exe"
        binary.write_bytes(BINARY_BYTES)
        answers = iter(["not json", "[1, 2]"])

        def answer(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args, 0, stdout=next(answers), stderr="")

        monkeypatch.setattr(engines.subprocess, "run", answer)
        engine = engines.RebrewEngine(enabled=True)
        with pytest.raises(engines.EngineError, match="no JSON report"):
            engine.intake(binary, tmp_path / "p", target="a")
        with pytest.raises(engines.EngineError, match="not an object"):
            engine.intake(binary, tmp_path / "p", target="a")

    def test_a_refusal_names_the_engine_reason_and_its_diagnosis(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary = tmp_path / "a.exe"
        binary.write_bytes(BINARY_BYTES)

        def refuse(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args,
                2,
                stdout='{"error": "no functions discovered", "code": 2}',
                stderr=(
                    "INFO starting\n2026-09-23 16:50:55 UTC WARNING rebrew.discover:"
                    " Failed to parse binary (unknown format)"
                ),
            )

        monkeypatch.setattr(engines.subprocess, "run", refuse)
        with pytest.raises(engines.EngineError) as caught:
            engines.RebrewEngine(enabled=True).intake(binary, tmp_path / "p", target="a")
        assert str(caught.value) == (
            "rebrew intake failed: no functions discovered; Failed to parse binary (unknown format)"
        )


def _prototype_project(root: Path) -> Path:
    """A rebrew workspace whose coverage.db names came from prototype text.

    An older engine read the discovery inventory's name as the first token of
    the prototype, so ``int __declspec(naked) __stdcall Foo(void)`` was stored
    as ``__declspec``; the notepad project's ``ghidra_name`` and ``list_name``
    columns still carry exactly that.  The ``symbol`` column keeps the
    decorated linker name the real one comes back from.
    """
    project = root / "proto"
    (project / "db").mkdir(parents=True)
    (project / "rebrew-project.toml").write_text(
        '[project]\nname = "proto"\ndb_dir = "db"\n\n[targets.proto]\narch = "x86_32"\n',
        encoding="utf-8",
    )
    coverage = sqlite3.connect(project / "db" / "coverage.db")
    try:
        coverage.execute(
            "CREATE TABLE functions (target TEXT, va INTEGER, name TEXT, size INTEGER,"
            " status TEXT, markerType TEXT, symbol TEXT)"
        )
        coverage.executemany(
            "INSERT INTO functions VALUES ('proto', ?, ?, 16, 'STUB', 'FUNCTION', ?)",
            [
                (0x1000, "__declspec", "_ResizeEditControl@8"),
                (0x1010, "int __declspec(naked) __stdcall NakedEntry(int a)", ""),
                (0x1020, "static void __cdecl LocalHelper(void)", "_LocalHelper"),
                (0x1030, "__stdcall", ""),
                (0x1040, "WinMain", "_WinMain@16"),
                (0x1050, "", "_EmptyName@0"),
            ],
        )
        coverage.commit()
    finally:
        coverage.close()
    return project


class TestPrototypeNames:
    @pytest.mark.parametrize(
        ("raw", "symbol", "expected"),
        [
            ("WinMain", "", "WinMain"),
            ("__declspec", "_ResizeEditControl@8", "ResizeEditControl"),
            ("__declspec", "", "sub_1000"),
            ("__stdcall", "", "sub_1000"),
            ("static", "", "sub_1000"),
            ("int __declspec(naked) __stdcall NakedEntry(int a)", "", "NakedEntry"),
            ("static void __cdecl LocalHelper(void)", "", "LocalHelper"),
            (
                "__declspec(dllexport) LRESULT CALLBACK MainWndProc(HWND h, UINT m)",
                "",
                "MainWndProc",
            ),
            ("", "_EmptyName@0", "EmptyName"),
            ("", "", "sub_1000"),
            ("?Bar@CFoo@@QAEXXZ", "", "?Bar@CFoo@@QAEXXZ"),
        ],
    )
    def test_function_name_skips_declaration_tokens(
        self, raw: str, symbol: str, expected: str
    ) -> None:
        assert rebrew_import.function_name(raw, symbol=symbol, va=0x1000) == expected

    def test_import_stores_the_declarator_name(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        summary = rebrew_import.import_project(_prototype_project(tmp_path))
        binary_id = summary["targets"][0]["binary_id"]
        names = {
            int(row["va"]): str(row["name"])
            for row in store.list_functions(conn, binary_id=binary_id)
        }
        assert names == {
            0x1000: "ResizeEditControl",
            0x1010: "NakedEntry",
            0x1020: "LocalHelper",
            0x1030: "sub_1030",
            0x1040: "WinMain",
            0x1050: "EmptyName",
        }

    def test_coverage_functions_reads_one_target_in_va_order(self, tmp_path: Path) -> None:
        project = _prototype_project(tmp_path)
        rows = rebrew_import.coverage_functions(project / "db" / "coverage.db", "proto")
        assert [row["va"] for row in rows] == sorted(row["va"] for row in rows)
        assert rows[0]["name"] == "ResizeEditControl"

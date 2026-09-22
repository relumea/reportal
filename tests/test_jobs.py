"""Tests for the async operation workflow: the queue, the runner and its surfaces."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import (
    auth,
    behavior,
    cli,
    engines,
    jobs,
    journal,
    mcp_tools,
    pipeline,
    similarity,
    store,
)

HAS_SIMILARITY = similarity.available()
requires_similarity = pytest.mark.skipif(
    not HAS_SIMILARITY, reason="similarity extra not installed"
)

runner = CliRunner()


def _binary(conn: sqlite3.Connection, tmp_path: Path, name: str = "t.exe") -> int:
    path = tmp_path / name
    path.write_bytes(b"MZ" + b"\x00" * 64)
    return store.add_binary(conn, sha256=f"{name:0<64}"[:64], name=name, path=str(path), size=66)


def _submit(conn: sqlite3.Connection, tmp_path: Path, kind: str = "composition") -> dict[str, Any]:
    """A queued job of a kind that stores a scan with no engine call."""
    return jobs.submit(conn, kind=kind, binary_id=_binary(conn, tmp_path))


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


def _post(path: str, payload: dict[str, Any] | None = None) -> tuple[str, Any]:
    raw = b"" if payload is None else json.dumps(payload).encode()
    status, headers, body = wsgi_request("POST", path, body=raw)
    return status, json_body(body, headers)


class TestRegistry:
    def test_the_registry_holds_the_documented_kinds(self) -> None:
        assert set(jobs.JOB_KINDS) == {
            "ai-enrich",
            "behavior",
            "benchmark",
            "capabilities",
            "composition",
            "crypto",
            "debug",
            "detect",
            "filetype",
            "firmware",
            "flirt",
            "function-triage",
            "gobuildinfo",
            "hardening",
            "library",
            "lineage",
            "match",
            "pe-info",
            "protocols",
            "related",
            "remediation",
            "report",
            "report-pdf",
            "secrets",
            "security",
            "structs",
            "threat",
            "triage",
            "unpack",
            "unstrip",
        }

    def test_a_scan_kind_maps_onto_the_job_that_stores_it(self) -> None:
        assert jobs.job_kind_for_scan(store.SCAN_KIND_FILETYPE) == ("filetype", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_PE_INFO) == ("pe-info", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_TRIAGE) == ("triage", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_CRYPTO) == ("crypto", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_LIBRARY) == ("library", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_FLIRT) == ("flirt", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_FIRMWARE) == ("firmware", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_SECURITY) == ("security", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_THREAT) == ("threat", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_STRUCTS) == ("structs", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_DETECT) == ("detect", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_GOBUILDINFO) == ("gobuildinfo", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_REMEDIATION) == ("remediation", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_FUNCTION_TRIAGE) == (
            "function-triage",
            {},
        )
        assert jobs.job_kind_for_scan(store.SCAN_KIND_RELATED) == ("related", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_LINEAGE) == ("lineage", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_BENCHMARK) == ("benchmark", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_DEBUG_SESSION) == ("debug", {})
        assert jobs.job_kind_for_scan(store.SCAN_KIND_EXECUTION) == (
            "behavior",
            {"domain": behavior.DOMAIN_EXECUTION},
        )
        assert jobs.job_kind_for_scan(store.SCAN_KIND_UNPACK) is None

    def test_every_kind_names_its_label_and_its_write(self) -> None:
        for spec in jobs.JOB_KINDS.values():
            assert spec.label
            # A kind either stores one fixed scan kind, one scan kind per domain,
            # or journals a write of its own (`perform`) instead of a scan.
            params = dict.fromkeys(spec.params, "")
            params["domain"] = "execution" if spec.name == "behavior" else "obfuscation"
            assert (
                spec.scan_kind_for(params)
                or spec.perform is not None
                or spec.perform_progress is not None
            )

    def test_a_domain_kind_resolves_one_scan_kind_per_domain(self) -> None:
        hardening = jobs.JOB_KINDS["hardening"]
        obfuscation = hardening.scan_kind_for({"domain": "obfuscation"})
        anti_analysis = hardening.scan_kind_for({"domain": "anti-analysis"})

        assert obfuscation is not None and obfuscation.endswith("obfuscation")
        assert anti_analysis != obfuscation


class TestSubmit:
    def test_a_submitted_job_starts_queued(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        job = _submit(conn, tmp_path)

        assert job["status"] == jobs.STATUS_QUEUED
        assert job["progress"] == 0
        assert job["steps_total"] == 1
        assert job["live"] is True
        assert job["result"] is None
        assert job["label"]

    def test_an_unknown_kind_is_refused(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        try:
            jobs.submit(conn, kind="nope", binary_id=_binary(conn, tmp_path))
        except ValueError as exc:
            assert "unknown job kind" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown kind must be refused")

    def test_an_unknown_binary_is_refused(self, conn: sqlite3.Connection) -> None:
        try:
            jobs.submit(conn, kind="composition", binary_id=4242)
        except KeyError as exc:
            assert "4242" in str(exc.args[0])
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown binary must be refused")

    def test_a_parameter_the_kind_does_not_take_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        try:
            jobs.submit(
                conn, kind="composition", binary_id=_binary(conn, tmp_path), params={"domain": "x"}
            )
        except ValueError as exc:
            assert "takes no parameter" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unexpected parameter must be refused")

    def test_an_unknown_domain_is_refused_before_the_job_runs(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        try:
            jobs.submit(
                conn,
                kind="hardening",
                binary_id=_binary(conn, tmp_path),
                params={"domain": "nope"},
            )
        except ValueError as exc:
            assert "unknown hardening domain" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown domain must be refused on submit")

    def test_the_params_are_stored_with_the_job(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = jobs.submit(
            conn,
            kind="behavior",
            binary_id=_binary(conn, tmp_path),
            params={"domain": "networking"},
        )

        assert job["params"] == {"domain": "networking"}
        stored = jobs.get_job(conn, job["id"])
        assert stored is not None
        assert stored["params"] == {"domain": "networking"}

    def test_a_missing_domain_is_persisted_as_the_default(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = jobs.submit(conn, kind="behavior", binary_id=_binary(conn, tmp_path), params={})

        assert job["params"] == {"domain": behavior.BEHAVIOR_DOMAINS[0]}
        stored = jobs.get_job(conn, job["id"])
        assert stored is not None
        assert stored["params"] == {"domain": behavior.BEHAVIOR_DOMAINS[0]}

    def test_a_second_submit_of_the_same_work_reuses_the_queued_row(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        """A double-click must not queue a second metered or writing run."""
        binary_id = _binary(conn, tmp_path)
        first = jobs.submit(conn, kind="composition", binary_id=binary_id)
        second = jobs.submit(conn, kind="composition", binary_id=binary_id)

        assert second["id"] == first["id"]
        rows, total = jobs.list_jobs(conn, status=jobs.STATUS_QUEUED, binary_id=binary_id)
        assert total == 1
        assert rows[0]["id"] == first["id"]

    def test_a_second_submit_reuses_a_running_job(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        first = jobs.submit(conn, kind="ai-enrich", binary_id=binary_id)
        claimed = jobs._claim(conn)
        assert claimed is not None

        second = jobs.submit(conn, kind="ai-enrich", binary_id=binary_id)

        assert second == claimed
        assert second["id"] == first["id"]
        assert jobs.count_jobs(conn) == 1
        assert jobs.count_jobs(conn, status=jobs.STATUS_QUEUED) == 0

    def test_reclaim_orphaned_running_jobs_unblocks_resubmit(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        """A process exit leaves ``running``; reclaim must free the live slot."""
        binary_id = _binary(conn, tmp_path)
        first = jobs.submit(conn, kind="composition", binary_id=binary_id)
        claimed = jobs._claim(conn)
        assert claimed is not None
        assert claimed["status"] == jobs.STATUS_RUNNING
        assert jobs.reclaim_orphaned_running_jobs(conn) == 1
        orphan = jobs.get_job(conn, int(first["id"]))
        assert orphan is not None
        assert orphan["status"] == jobs.STATUS_FAILED
        second = jobs.submit(conn, kind="composition", binary_id=binary_id)
        assert second["id"] != first["id"]
        assert second["status"] == jobs.STATUS_QUEUED

    def test_concurrent_submits_reuse_one_job(
        self,
        conn: sqlite3.Connection,
        portal_db: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        jobs.ensure_schema(conn)
        ready = Barrier(2, timeout=10)
        ensure_schema = jobs.ensure_schema
        synchronized: set[sqlite3.Connection] = set()

        def synchronized_schema(connection: sqlite3.Connection) -> None:
            ensure_schema(connection)
            if connection not in synchronized:
                synchronized.add(connection)
                ready.wait()

        def submit() -> dict[str, Any]:
            with contextlib.closing(store.connect(portal_db)) as connection:
                return jobs.submit(connection, kind="ai-enrich", binary_id=binary_id)

        monkeypatch.setattr(jobs, "ensure_schema", synchronized_schema)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(submit)
            second = pool.submit(submit)
            assert first.result(timeout=15)["id"] == second.result(timeout=15)["id"]
        monkeypatch.setattr(jobs, "ensure_schema", ensure_schema)
        assert jobs.count_jobs(conn) == 1

    def test_concurrent_claims_take_distinct_jobs(
        self,
        conn: sqlite3.Connection,
        portal_db: Path,
        tmp_path: Path,
    ) -> None:
        """Two workers under BEGIN IMMEDIATE each claim a different queued row."""
        first = jobs.submit(conn, kind="ai-enrich", binary_id=_binary(conn, tmp_path, "a.exe"))
        second = jobs.submit(conn, kind="ai-enrich", binary_id=_binary(conn, tmp_path, "b.exe"))
        ready = Barrier(2, timeout=10)

        def claim() -> dict[str, Any] | None:
            with contextlib.closing(store.connect(portal_db)) as connection:
                jobs.ensure_schema(connection)
                ready.wait()
                return jobs._claim(connection)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (pool.submit(claim), pool.submit(claim))
            claimed = [future.result(timeout=15) for future in futures]
        ids = {job["id"] for job in claimed if job is not None}
        assert ids == {first["id"], second["id"]}
        assert jobs.count_jobs(conn, status=jobs.STATUS_QUEUED) == 0
        assert jobs.count_jobs(conn, status=jobs.STATUS_RUNNING) == 2

    def test_a_duplicate_is_reused_even_when_the_queue_is_full(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(jobs, "MAX_QUEUED_JOBS", 1)
        first = _submit(conn, tmp_path)

        assert jobs.submit(conn, kind="composition", binary_id=first["binary_id"]) == first
        with pytest.raises(ValueError, match="queue is full"):
            jobs.submit(conn, kind="report", binary_id=first["binary_id"])
        assert not conn.in_transaction
        assert jobs.count_jobs(conn) == 1

    def test_a_submit_after_the_first_finishes_queues_a_new_row(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        first = jobs.submit(conn, kind="composition", binary_id=binary_id)
        jobs.run_pending(conn, limit=1)
        again = jobs.submit(conn, kind="composition", binary_id=binary_id)

        assert again["id"] != first["id"]
        assert again["status"] == jobs.STATUS_QUEUED

    def test_ensure_schema_collapses_duplicate_live_jobs(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        jobs.ensure_schema(conn)
        conn.execute("DROP INDEX IF EXISTS idx_jobs_live_dedupe")
        stamp = store.now()
        params = "{}"
        first = conn.execute(
            f"INSERT INTO {jobs.TABLE} (kind, binary_id, status, params_json, created_at)"
            " VALUES ('composition', ?, ?, ?, ?)",
            (binary_id, jobs.STATUS_QUEUED, params, stamp),
        ).lastrowid
        second = conn.execute(
            f"INSERT INTO {jobs.TABLE} (kind, binary_id, status, params_json, created_at)"
            " VALUES ('composition', ?, ?, ?, ?)",
            (binary_id, jobs.STATUS_QUEUED, params, stamp),
        ).lastrowid
        conn.commit()
        jobs.ensure_schema(conn)
        rows = conn.execute(
            f"SELECT id, status FROM {jobs.TABLE} WHERE binary_id = ? ORDER BY id",
            (binary_id,),
        ).fetchall()
        by_id = {int(row["id"]): str(row["status"]) for row in rows}
        assert by_id[int(second or 0)] == jobs.STATUS_QUEUED
        assert by_id[int(first or 0)] == jobs.STATUS_CANCELLED
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                f"INSERT INTO {jobs.TABLE} (kind, binary_id, status, params_json, created_at)"
                " VALUES ('composition', ?, ?, ?, ?)",
                (binary_id, jobs.STATUS_QUEUED, params, stamp),
            )


class TestRun:
    def test_running_a_job_records_its_result(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)

        finished = jobs.run_pending(conn, limit=1)

        assert [row["id"] for row in finished] == [job["id"]]
        assert finished[0]["status"] == jobs.STATUS_DONE
        assert finished[0]["progress"] == 100
        assert finished[0]["result"] is not None
        assert finished[0]["finished_at"]

    def test_a_queued_job_runs_oldest_first(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        first = jobs.submit(
            conn, kind="composition", binary_id=_binary(conn, tmp_path, "first.exe")
        )
        second = jobs.submit(
            conn, kind="composition", binary_id=_binary(conn, tmp_path, "second.exe")
        )

        finished = jobs.run_pending(conn, limit=2)

        assert [row["id"] for row in finished] == [first["id"], second["id"]]

    def test_an_empty_queue_runs_nothing(self, conn: sqlite3.Connection) -> None:
        assert jobs.run_pending(conn, limit=3) == []

    def test_a_failing_operation_is_a_failed_job_not_a_crash(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        # The file is not a real executable, so the engine call refuses it; the
        # job records that rather than raising into the worker.
        job = jobs.submit(conn, kind="secrets", binary_id=_binary(conn, tmp_path))

        finished = jobs.run_pending(conn, limit=1)

        assert finished[0]["id"] == job["id"]
        assert finished[0]["status"] == jobs.STATUS_FAILED
        assert finished[0]["error"]
        assert finished[0]["result"] is None

    def test_a_failed_job_leaves_no_journal_entry(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path, kind="secrets")
        jobs.run_pending(conn, limit=1)

        assert journal.list_entries(conn) == []

    def test_a_queued_debug_probe_stores_the_session(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import debug

        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("lldb-dap", "lldb-dap"))
        monkeypatch.setattr(
            debug,
            "probe_binary",
            lambda sample, **kwargs: {
                "status": debug.STATUS_FINISHED,
                "backend": "lldb-dap",
                "argv": ["lldb-dap"],
                "caps": debug.requested_caps().as_payload(),
                "transcript": [{"request": "initialize", "success": True}],
                "notes": [],
            },
        )
        binary_id = _binary(conn, tmp_path)
        job = jobs.submit(conn, kind="debug", binary_id=binary_id)

        finished = jobs.run_pending(conn, limit=1)

        assert finished[0]["id"] == job["id"]
        assert finished[0]["status"] == jobs.STATUS_DONE
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert analysis_id is not None
        assert store.get_scan(conn, analysis_id, store.SCAN_KIND_DEBUG_SESSION) is not None

    def test_a_queued_debug_probe_refused_without_opt_in(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import debug

        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        job = jobs.submit(conn, kind="debug", binary_id=_binary(conn, tmp_path))

        finished = jobs.run_pending(conn, limit=1)

        assert finished[0]["id"] == job["id"]
        assert finished[0]["status"] == jobs.STATUS_FAILED
        assert "debug-disabled" in str(finished[0]["error"])

    def test_a_successful_job_is_journaled_like_its_route(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        entries = journal.list_entries(conn)
        assert entries, "the queued scan journals what it stored"
        assert any("composition" in entry["description"] for entry in entries)

    def test_a_finished_job_is_not_live(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        rows, total = jobs.list_jobs(conn)
        assert total == 1
        assert rows[0]["live"] is False


class TestMatchJob:
    """The one kind whose write is not a scan row: it journals its own rows."""

    def _seed(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        binary_id = _binary(conn, tmp_path, "match.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.add_function(
            conn,
            analysis_id=analysis_id,
            va=0x1000,
            name="sub_1000",
            size=16,
        )
        return binary_id

    def test_the_settings_are_validated_at_submit(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)

        try:
            jobs.submit(conn, kind="match", binary_id=binary_id, params={"min_similarity": 500.0})
        except ValueError as exc:
            assert "min_similarity" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an out-of-range setting must be refused at submit")

    def test_an_unknown_scope_id_is_refused_at_submit(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)

        try:
            jobs.submit(conn, kind="match", binary_id=binary_id, params={"binary_ids": [999]})
        except ValueError as exc:
            assert "999" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown scope id must be refused at submit")

    def test_a_parameter_the_kind_does_not_take_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)

        try:
            jobs.submit(conn, kind="match", binary_id=binary_id, params={"domain": "execution"})
        except ValueError as exc:
            assert "domain" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unexpected parameter must be refused")

    def test_the_progress_sink_writes_the_row_at_its_own_pace(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)
        job_id = int(job["id"])
        sink = jobs._progress_sink(conn, job_id)

        # Under the reporting interval nothing is written, so a long run does
        # not spend its time on the database.
        sink(1, 100)
        quiet = jobs.get_job(conn, job_id)
        assert quiet is not None
        assert quiet["progress"] == 0

        sink(25, 100)
        row = jobs.get_job(conn, job_id)
        assert row is not None
        assert row["progress"] == 25
        assert row["steps_total"] == 100
        assert row["message"] == "25 of 100 steps"

        # The last step always writes, whatever the interval.
        sink(100, 100)
        final = jobs.get_job(conn, job_id)
        assert final is not None
        assert final["progress"] == 100

    def test_the_kind_is_refused_without_the_scorer(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The route answers 503 before running; a queued job is refused at
        # submit for the same reason, rather than failing when it is picked up.
        binary_id = self._seed(conn, tmp_path)
        monkeypatch.setattr(similarity, "available", lambda: False)

        try:
            jobs.submit(conn, kind="match", binary_id=binary_id, params={})
        except ValueError as exc:
            assert "similarity" in str(exc)
            assert "uv sync --extra similarity" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a match job needs the scorer installed")

    @requires_similarity
    def test_a_queued_run_reports_its_steps(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _binary(conn, tmp_path, "steps.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        for index in range(3):
            store.add_function(
                conn,
                analysis_id=analysis_id,
                va=0x1000 + index * 0x10,
                name=f"sub_{index}",
                size=16,
            )
        job = jobs.submit(conn, kind="match", binary_id=binary_id, params={})

        finished = jobs.run_pending(conn, limit=1)

        assert finished[0]["status"] == jobs.STATUS_DONE, finished[0]["error"]
        # A finished run is complete, and the step total is the source count.
        assert finished[0]["progress"] == 100
        assert finished[0]["steps_total"] == 3
        stored = jobs.get_job(conn, int(job["id"]))
        assert stored is not None
        assert stored["message"] == "finished"

    @requires_similarity
    def test_a_queued_run_records_its_settings(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        jobs.submit(conn, kind="match", binary_id=binary_id, params={"min_similarity": 90.0})

        finished = jobs.run_pending(conn, limit=1)

        assert finished[0]["status"] == jobs.STATUS_DONE, finished[0]["error"]
        assert finished[0]["result"]["settings"]["min_similarity"] == 90.0
        assert finished[0]["result"]["functions"] == 1

    @requires_similarity
    def test_a_queued_run_is_revertible_through_its_journal_action(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        function_id = int(store.list_functions(conn)[0]["id"])
        other = _binary(conn, tmp_path, "other.exe")
        other_analysis = store.create_analysis(conn, binary_id=other, engine="manual")
        candidate = store.add_function(
            conn, analysis_id=other_analysis, va=0x2000, name="sub_2000", size=16
        )
        store.record_match(
            conn,
            function_id=function_id,
            candidate_function_id=candidate,
            similarity=95.0,
            confidence=1.0,
            settings={},
        )
        # A scope that admits no candidate still replaces prior rows with an
        # empty listing (see matching.match_binary).  Without a rebrew listing
        # the unscored path would leave the seed match in place, which is not
        # what this revert check exercises.
        jobs.submit(
            conn,
            kind="match",
            binary_id=binary_id,
            params={"binary_ids": [binary_id], "include_self": False},
        )

        finished = jobs.run_pending(conn, limit=1)
        action = finished[0]["result"]["journal_action"]

        # The run replaced the binary's matches, and its action puts them back.
        assert action
        assert store.list_matches(conn, function_id) == []
        journal.revert_action(conn, action)
        assert [
            int(row["candidate_function_id"]) for row in store.list_matches(conn, function_id)
        ] == [candidate]


class TestAiEnrichJob:
    """The whole-binary form of the pipeline: one run per function, queued."""

    def _seed(self, conn: sqlite3.Connection, tmp_path: Path) -> tuple[int, list[int]]:
        """A binary with a project context and two functions of distinct sizes."""
        binary_id = _binary(conn, tmp_path, "enrich.exe")
        store.set_rebrew_context(conn, binary_id, str(tmp_path))
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        ids = [
            store.add_function(
                conn,
                analysis_id=analysis_id,
                va=0x1000 + index * 0x100,
                name=f"sub_{index}",
                size=size,
            )
            for index, size in enumerate((0x20, 0x40))
        ]
        return binary_id, ids

    def test_a_queued_run_enriches_each_named_function(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: Any
    ) -> None:
        binary_id, ids = self._seed(conn, tmp_path)
        job = jobs.submit(conn, kind="ai-enrich", binary_id=binary_id, params={"function_ids": ids})

        finished = jobs.run_pending(conn, limit=1)[0]

        assert finished["status"] == jobs.STATUS_DONE, finished["error"]
        result = finished["result"]
        assert result["total"] == 2
        assert [row["function_id"] for row in result["runs"]] == ids
        assert result["done"] == 2
        assert [row["status"] for row in result["runs"]] == [pipeline.RUN_DONE] * 2
        # Every function's run is a stored row of its own, so one can be
        # reverted without touching the other's artifacts.
        for row in result["runs"]:
            assert store.get_pipeline_run(conn, int(row["run_id"])) is not None
        assert finished["progress"] == 100
        assert finished["steps_total"] == 2
        assert jobs.get_job(conn, int(job["id"])) is not None

    def test_the_default_limit_is_used_when_none_is_given(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: Any
    ) -> None:
        binary_id, ids = self._seed(conn, tmp_path)
        jobs.submit(conn, kind="ai-enrich", binary_id=binary_id, params={})

        finished = jobs.run_pending(conn, limit=1)[0]

        assert finished["status"] == jobs.STATUS_DONE, finished["error"]
        assert finished["result"]["total"] == len(ids)

    @pytest.mark.parametrize(
        "params",
        [{}, {"limit": None}, {"limit": str(pipeline.DEFAULT_BATCH_LIMIT)}],
    )
    def test_equivalent_limits_reuse_the_queued_job(
        self, conn: sqlite3.Connection, tmp_path: Path, params: dict[str, Any]
    ) -> None:
        binary_id, _ = self._seed(conn, tmp_path)
        job = jobs.submit(conn, kind="ai-enrich", binary_id=binary_id, params=params)
        repeated = jobs.submit(
            conn,
            kind="ai-enrich",
            binary_id=binary_id,
            params={"limit": pipeline.DEFAULT_BATCH_LIMIT},
        )

        assert repeated["id"] == job["id"]
        assert jobs.count_jobs(conn, status=jobs.STATUS_QUEUED) == 1
        stored = jobs.get_job(conn, int(job["id"]))
        assert stored is not None
        assert stored["params"] == {"limit": pipeline.DEFAULT_BATCH_LIMIT}

    def test_an_out_of_range_limit_is_refused_at_submit(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = self._seed(conn, tmp_path)
        for limit in (0, pipeline.MAX_BATCH_LIMIT + 1):
            with pytest.raises(ValueError):
                jobs.submit(conn, kind="ai-enrich", binary_id=binary_id, params={"limit": limit})
        with pytest.raises(ValueError):
            jobs.submit(conn, kind="ai-enrich", binary_id=binary_id, params={"limit": "many"})
        with pytest.raises(ValueError):
            jobs.submit(conn, kind="ai-enrich", binary_id=binary_id, params={"function_ids": "1"})
        with pytest.raises(ValueError):
            jobs.submit(conn, kind="ai-enrich", binary_id=binary_id, params={"function_ids": ["1"]})

    def test_a_parameter_the_kind_does_not_take_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = self._seed(conn, tmp_path)
        with pytest.raises(ValueError):
            jobs.submit(conn, kind="ai-enrich", binary_id=binary_id, params={"domain": "execution"})

    def test_the_route_queues_it(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, ids = self._seed(conn, tmp_path)

        status, payload = _post(
            "/api/jobs",
            {"kind": "ai-enrich", "binary_id": binary_id, "params": {"function_ids": ids}},
        )

        assert status.startswith("202")
        assert payload["kind"] == "ai-enrich"
        assert payload["params"] == {"function_ids": ids, "limit": pipeline.DEFAULT_BATCH_LIMIT}


class TestCancel:
    def test_a_queued_job_can_be_cancelled(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        job = _submit(conn, tmp_path)

        cancelled = jobs.cancel(conn, job["id"])

        assert cancelled is not None
        assert cancelled["status"] == jobs.STATUS_CANCELLED
        assert cancelled["finished_at"]
        assert jobs.run_pending(conn, limit=1) == []

    def test_cancelling_an_unknown_job_is_none(self, conn: sqlite3.Connection) -> None:
        assert jobs.cancel(conn, 4242) is None

    def test_cancelling_a_finished_job_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        try:
            jobs.cancel(conn, job["id"])
        except ValueError as exc:
            assert "cannot be cancelled" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a finished job must not be cancellable")

    def test_cancel_loses_to_a_claim_without_overwriting_running(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        """A claim that wins the row must leave cancel refusing, not rewriting."""
        job = _submit(conn, tmp_path)
        claimed = jobs._claim(conn)
        assert claimed is not None
        assert claimed["id"] == job["id"]
        assert claimed["status"] == jobs.STATUS_RUNNING

        try:
            jobs.cancel(conn, job["id"])
        except ValueError as exc:
            assert "cannot be cancelled" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a claimed job must not be cancellable")

        still = jobs.get_job(conn, job["id"])
        assert still is not None
        assert still["status"] == jobs.STATUS_RUNNING


class TestListing:
    def test_the_listing_filters_by_status_and_kind(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        first = _submit(conn, tmp_path)
        jobs.submit(conn, kind="unstrip", binary_id=first["binary_id"])
        jobs.run_pending(conn, limit=1)

        rows, total = jobs.list_jobs(conn, status=jobs.STATUS_QUEUED)

        assert total == 1
        assert rows[0]["kind"] == "unstrip"
        by_kind, kind_total = jobs.list_jobs(conn, kind="composition")
        assert kind_total == 1
        assert by_kind[0]["status"] == jobs.STATUS_DONE

    def test_a_corrupt_json_column_does_not_take_down_the_listing(
        self, conn: sqlite3.Connection, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        job = _submit(conn, tmp_path)
        conn.execute(
            f"UPDATE {jobs.TABLE} SET params_json = ?, result_json = ? WHERE id = ?",
            ("{not-json", "{also-broken", job["id"]),
        )
        conn.commit()

        with caplog.at_level("WARNING", logger="reportal.jobs"):
            rows, total = jobs.list_jobs(conn)
            stored = jobs.get_job(conn, int(job["id"]))

        assert total == 1
        assert rows[0]["params"] == {}
        assert rows[0]["result"] is None
        assert stored is not None
        assert stored["params"] == {}
        assert stored["result"] is None
        assert any("corrupt params_json" in record.message for record in caplog.records)
        assert any("corrupt result_json" in record.message for record in caplog.records)

    def test_an_unknown_status_or_kind_is_refused(self, conn: sqlite3.Connection) -> None:
        for kwargs in ({"status": "nope"}, {"kind": "nope"}):
            try:
                jobs.list_jobs(conn, **kwargs)  # type: ignore[arg-type]
            except ValueError:
                pass
            else:  # pragma: no cover - the assertion is the point
                raise AssertionError("an unknown filter must be refused")

    def test_an_out_of_range_limit_is_refused(self, conn: sqlite3.Connection) -> None:
        for bad in (0, jobs.MAX_JOB_LIMIT + 1):
            try:
                jobs.list_jobs(conn, limit=bad)
            except ValueError:
                pass
            else:  # pragma: no cover - the assertion is the point
                raise AssertionError("an out-of-range limit must be refused")

    def test_the_counts_report_what_is_waiting(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path)

        assert jobs.count_jobs(conn, status=jobs.STATUS_QUEUED) == 1
        assert jobs.count_jobs(conn, status=jobs.STATUS_DONE) == 0

    def test_a_non_member_does_not_list_or_read_a_team_job(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        job = _submit(conn, tmp_path, kind="composition")
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(
            conn, int(job["binary_id"]), visibility="team", owner_team_id=team_id
        )
        member = auth.find_user(conn, "ana")
        stranger = auth.find_user(conn, "bob")
        assert member is not None and stranger is not None
        assert jobs.visible_job(conn, int(job["id"]), member) is not None
        assert jobs.visible_job(conn, int(job["id"]), stranger) is None
        rows, total = jobs.list_jobs(conn, visible_to=stranger)
        assert (rows, total) == ([], 0)
        assert jobs.count_jobs(conn, visible_to=stranger) == 0

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, _, stranger_body = wsgi_request(
            "GET",
            f"/api/jobs/{int(job['id'])}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), stranger_body
        member_status, _, member_body = wsgi_request(
            "GET",
            f"/api/jobs/{int(job['id'])}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), member_body


class TestEvents:
    def test_the_stream_starts_with_the_current_state_and_ends_when_terminal(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        job = _submit(conn, tmp_path)
        clock = [0.0]
        monkeypatch.setattr(jobs, "_monotonic", lambda: clock[0])
        monkeypatch.setattr(jobs, "_sleep", lambda _seconds: clock.__setitem__(0, clock[0] + 0.1))

        frames = list(jobs.events(conn, job["id"], interval=0.1, max_seconds=0.05))

        assert frames, "a stream always sends the current state first"
        assert frames[0].startswith("event: job\ndata: ")
        assert f'"id": {job["id"]}' in frames[0]
        assert frames[-1].startswith("event: timeout")

    def test_a_terminal_job_streams_one_frame_and_closes(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        job = _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)
        monkeypatch.setattr(jobs, "_sleep", lambda _seconds: None)

        frames = list(jobs.events(conn, job["id"], interval=0.01, max_seconds=5.0))

        assert len(frames) == 1
        assert '"status": "done"' in frames[0]

    def test_an_unknown_job_streams_an_error_frame(self, conn: sqlite3.Connection) -> None:
        frames = list(jobs.events(conn, 4242, interval=0.01, max_seconds=0.01))

        assert frames == ['event: error\ndata: {"error": "job not found"}\n\n']


class TestRoute:
    def test_submitting_answers_the_queued_job(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)

        status, payload = _post("/api/jobs", {"kind": "composition", "binary_id": binary_id})

        assert status.startswith("202")
        assert payload["status"] == jobs.STATUS_QUEUED, "the pool is off, so nothing ran it"
        assert payload["kind"] == "composition"

    def test_submitting_for_a_team_binary_is_refused_for_a_non_member(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, binary_id, visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, _, stranger_body = wsgi_request(
            "POST",
            "/api/jobs",
            body=json.dumps({"kind": "composition", "binary_id": binary_id}).encode(),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("403"), stranger_body
        member_status, _, _ = wsgi_request(
            "POST",
            "/api/jobs",
            body=json.dumps({"kind": "composition", "binary_id": binary_id}).encode(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("202"), member_status

    def test_submitting_is_journaled_and_revertible(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)

        status, payload = _post("/api/jobs", {"kind": "composition", "binary_id": binary_id})

        assert status.startswith("202")
        assert payload["journal_action"], "the queued row is one journaled action"
        job_id = int(payload["id"])
        assert jobs.get_job(conn, job_id) is not None

        journal.revert_action(conn, payload["journal_action"])

        assert jobs.get_job(conn, job_id) is None

    def test_cancelling_is_journaled_and_revertible(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)

        status, payload = _post(f"/api/jobs/{job['id']}/cancel")

        assert status.startswith("200")
        assert payload["status"] == jobs.STATUS_CANCELLED
        assert payload["journal_action"]

        journal.revert_action(conn, payload["journal_action"])

        restored = jobs.get_job(conn, int(job["id"]))
        assert restored is not None
        assert restored["status"] == jobs.STATUS_QUEUED

    def test_an_unknown_kind_is_400(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        status, payload = _post("/api/jobs", {"kind": "nope", "binary_id": _binary(conn, tmp_path)})

        assert status.startswith("400")
        assert payload["error"] == "invalid job"

    def test_an_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _post("/api/jobs", {"kind": "composition", "binary_id": 4242})

        assert status.startswith("404")
        assert payload["error"] == "binary not found"

    def test_the_listing_carries_the_kinds_and_the_waiting_count(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path)

        status, payload = _get("/api/jobs")

        assert status.startswith("200")
        assert payload["queued"] >= 1
        assert any(entry["name"] == "composition" for entry in payload["kinds"])
        # Both closed vocabularies travel, so a client's controls cannot drift.
        assert list(payload["statuses"]) == list(jobs.STATUSES)
        assert "composition" in {entry["name"] for entry in payload["kinds"]}

    def test_an_unknown_status_filter_is_400(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/jobs?status=nope")

        assert status.startswith("400")
        assert payload["error"] == "invalid status"

    def test_one_job_is_404_when_it_does_not_exist(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/jobs/4242")

        assert status.startswith("404")
        assert payload["error"] == "job not found"

    def test_running_the_queue_inline_answers_what_finished(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        _submit(conn, tmp_path)

        status, payload = _post("/api/jobs/run")

        assert status.startswith("200")
        assert payload["count"] == 1
        assert payload["jobs"][0]["status"] == jobs.STATUS_DONE

    def test_cancelling_a_finished_job_is_409(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        status, payload = _post(f"/api/jobs/{job['id']}/cancel")

        assert status.startswith("409")
        assert payload["error"] == "job-not-cancellable"

    def test_cancelling_an_unknown_job_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _post("/api/jobs/4242/cancel")

        assert status.startswith("404")
        assert payload["error"] == "job not found"

    def test_the_events_route_streams_server_sent_events(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        job = _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        status, headers, body = wsgi_request("GET", f"/api/jobs/{job['id']}/events")

        assert status.startswith("200")
        assert headers["Content-Type"].startswith("text/event-stream")
        text = body.decode()
        assert text.startswith("event: job\n")
        assert '"status": "done"' in text

    def test_the_events_route_of_an_unknown_job_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/jobs/4242/events")

        assert status.startswith("404")
        assert payload["error"] == "job not found"


class TestCli:
    def test_job_submit_and_run(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)

        queued = runner.invoke(cli.app, ["job-submit", "composition", str(binary_id), "--json"])
        assert queued.exit_code == 0
        assert json.loads(queued.stdout)["status"] == jobs.STATUS_QUEUED

        ran = runner.invoke(cli.app, ["job-run", "--json"])
        assert ran.exit_code == 0
        assert json.loads(ran.stdout)["jobs"][0]["status"] == jobs.STATUS_DONE

        listed = runner.invoke(cli.app, ["jobs", "--json"])
        assert listed.exit_code == 0
        payload = json.loads(listed.stdout)
        assert payload["total"] == 1
        assert payload["queued"] == 0

        shown = runner.invoke(cli.app, ["job", "1", "--json"])
        assert shown.exit_code == 0
        assert json.loads(shown.stdout)["status"] == jobs.STATUS_DONE

        human = runner.invoke(cli.app, ["job", "1"])
        assert human.exit_code == 0
        assert human.stdout == ""
        assert "composition" in human.stderr
        assert '"binary_id"' in human.stderr

    def test_job_run_exits_nonzero_when_a_job_fails(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)

        queued = runner.invoke(cli.app, ["job-submit", "secrets", str(binary_id), "--json"])
        assert queued.exit_code == 0
        ran = runner.invoke(cli.app, ["job-run", "--json"])
        assert ran.exit_code == 1
        assert json.loads(ran.stdout)["jobs"][0]["status"] == jobs.STATUS_FAILED

        again = runner.invoke(cli.app, ["job-submit", "secrets", str(binary_id), "--run", "--json"])
        assert again.exit_code == 1
        assert json.loads(again.stdout)["status"] == jobs.STATUS_FAILED

    def test_job_submit_runs_it_when_asked(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)

        result = runner.invoke(
            cli.app, ["job-submit", "composition", str(binary_id), "--run", "--json"]
        )

        assert result.exit_code == 0
        assert json.loads(result.stdout)["status"] == jobs.STATUS_DONE

    def test_a_param_reaches_the_queued_job(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)

        result = runner.invoke(
            cli.app,
            [
                "job-submit",
                "match",
                str(binary_id),
                "--param",
                "min_similarity=90",
                "--param",
                'platforms=["windows"]',
                "--json",
            ],
        )

        assert result.exit_code == 0, result.output
        params = json.loads(result.stdout)["params"]
        assert params["min_similarity"] == 90.0
        assert params["platforms"] == ["windows"]

    def test_a_param_without_a_value_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)

        result = runner.invoke(
            cli.app, ["job-submit", "composition", "1", "--param", "min_similarity"]
        )

        assert result.exit_code == 1
        assert "KEY=VALUE" in result.output

    def test_an_unknown_kind_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)

        result = runner.invoke(cli.app, ["job-submit", "nope", "1"])

        assert result.exit_code == 1
        assert "unknown job kind" in result.output

    def test_an_unknown_job_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)

        assert runner.invoke(cli.app, ["job", "4242"]).exit_code == 1
        assert runner.invoke(cli.app, ["job-cancel", "4242"]).exit_code == 1

    def test_cancelling_a_queued_job_reports_it(self, tmp_path: Path, monkeypatch: Any) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv("REPORTAL_DB", str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _binary(conn, tmp_path)
        runner.invoke(cli.app, ["job-submit", "composition", str(binary_id), "--json"])

        result = runner.invoke(cli.app, ["job-cancel", "1", "--json"])

        assert result.exit_code == 0
        assert json.loads(result.stdout)["status"] == jobs.STATUS_CANCELLED


class TestMcp:
    def test_the_read_tools_are_read_only(self) -> None:
        for name in ("list_jobs", "get_job"):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.read_only_hint is True
        for name in ("submit_job", "cancel_job", "run_jobs"):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.destructive_hint is True

    def test_submit_run_and_read(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        submit = mcp_tools.get_tool("submit_job")
        run = mcp_tools.get_tool("run_jobs")
        get = mcp_tools.get_tool("get_job")
        listing = mcp_tools.get_tool("list_jobs")
        assert submit and run and get and listing

        queued = submit.handler({"kind": "composition", "binary_id": binary_id})
        assert queued["status"] == jobs.STATUS_QUEUED
        ran = run.handler({})
        assert ran["jobs"][0]["id"] == queued["id"]
        assert get.handler({"job_id": queued["id"]})["status"] == jobs.STATUS_DONE
        assert listing.handler({})["total"] == 1
        # The tool takes the same binary filter the route and the CLI do.
        assert listing.handler({"binary_id": binary_id})["count"] == 1
        assert listing.handler({"binary_id": 4242})["count"] == 0
        assert listing.handler({})["statuses"] == list(jobs.STATUSES)

    def test_an_unknown_kind_is_a_tool_error(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        submit = mcp_tools.get_tool("submit_job")
        assert submit is not None

        try:
            submit.handler({"kind": "nope", "binary_id": binary_id})
        except mcp_tools.ToolError as exc:
            assert exc.error == "invalid job"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown kind must be a tool error")

    def test_an_unknown_job_is_a_tool_error(self, portal_db: Path) -> None:
        get = mcp_tools.get_tool("get_job")
        assert get is not None

        try:
            get.handler({"job_id": 4242})
        except mcp_tools.ToolError as exc:
            assert exc.error == "job not found"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown job must be a tool error")


class TestPool:
    def test_the_pool_drains_a_queued_job(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: Any
    ) -> None:
        # The real pool, with its own connection: the one path a test cannot
        # drive through run_pending.  The wait is bounded and the job is one
        # stored-only scan, so it settles in well under the cap.
        monkeypatch.setenv(jobs.POOL_ENV, "1")
        monkeypatch.setattr(jobs, "POLL_SECONDS", 0.01)
        job = _submit(conn, tmp_path)

        worker = jobs.ensure_worker()
        try:
            assert worker is not None
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                stored = jobs.get_job(conn, job["id"])
                assert stored is not None
                if not stored["live"]:
                    break
                time.sleep(0.02)
            else:  # pragma: no cover - the pool would have to be wedged
                raise AssertionError("the pool did not pick the job up")
            assert stored["status"] == jobs.STATUS_DONE
        finally:
            jobs.stop_worker()

    def test_a_disabled_pool_starts_nothing(self, monkeypatch: Any) -> None:
        monkeypatch.setenv(jobs.POOL_ENV, "1")
        assert jobs.ensure_worker() is not None
        jobs.stop_worker()
        monkeypatch.setenv(jobs.POOL_ENV, "0")
        assert jobs.pool_disabled() is True
        assert jobs.ensure_worker() is None

    def test_the_application_shutdown_stops_the_pool(self, monkeypatch: Any) -> None:
        """A served process that started the pool must not leave it running."""
        import asyncio

        from reportal.webapp import app

        monkeypatch.setenv(jobs.POOL_ENV, "1")
        assert jobs.ensure_worker() is not None

        async def cycle() -> None:
            async with app.router.lifespan_context(app):
                pass

        asyncio.run(cycle())
        assert jobs._worker is None


class TestOffline:
    def test_running_a_job_makes_no_network_call(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: Any
    ) -> None:
        # The job runner reaches the engine the same way a route does, and the
        # engine is the stub; nothing here opens a socket.
        monkeypatch.setattr(engines, "get_engine", lambda: engines.RebrewEngine())

        _submit(conn, tmp_path)
        jobs.run_pending(conn, limit=1)

        assert jobs.count_jobs(conn) == 1


class TestSubmitterAttribution:
    def test_submit_records_the_submitter(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        from reportal import auth

        user, _ = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        job = jobs.submit(
            conn,
            kind="composition",
            binary_id=_binary(conn, tmp_path),
            submitted_by="ana",
            submitted_by_user_id=int(user["id"]),
        )

        assert job["submitted_by"] == "ana"
        assert job["submitted_by_user_id"] == int(user["id"])

    def test_execute_records_the_submitter_on_journal_entries(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        from reportal import auth, journal

        user, _ = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        job = jobs.submit(
            conn,
            kind="composition",
            binary_id=_binary(conn, tmp_path),
            submitted_by="ana",
            submitted_by_user_id=int(user["id"]),
        )

        stored = jobs.execute(conn, jobs.get_job(conn, int(job["id"])) or {})
        assert stored["status"] == jobs.STATUS_DONE
        entries = journal.list_entries(conn, limit=journal.MAX_LIST_LIMIT)
        assert entries
        assert {entry["actor"] for entry in entries} == {"ana"}
        assert {entry["actor_user_id"] for entry in entries} == {int(user["id"])}


class TestJobsSchemaAndRows:
    def test_upgrade_adds_missing_columns(self, tmp_path: Path) -> None:
        import sqlite3 as _sqlite

        db = tmp_path / "old-jobs.db"
        conn = _sqlite.connect(db)
        conn.row_factory = _sqlite.Row
        conn.execute(
            f"CREATE TABLE {jobs.TABLE} ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " kind TEXT NOT NULL,"
            " binary_id INTEGER,"
            " status TEXT NOT NULL,"
            " progress INTEGER NOT NULL DEFAULT 0,"
            " steps_total INTEGER NOT NULL DEFAULT 1,"
            " message TEXT NOT NULL DEFAULT '',"
            " params_json TEXT NOT NULL DEFAULT '{}',"
            " result_json TEXT NOT NULL DEFAULT '',"
            " error TEXT NOT NULL DEFAULT '',"
            " created_at TEXT NOT NULL,"
            " started_at TEXT NOT NULL DEFAULT '',"
            " finished_at TEXT NOT NULL DEFAULT '')"
        )
        conn.commit()
        jobs.ensure_schema(conn)
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({jobs.TABLE})")}
        assert "submitted_by" in columns
        assert "submitted_by_user_id" in columns
        assert "request_id" in columns
        conn.close()


class TestJobsRowParsing:
    def test_non_object_params_read_empty(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        job = jobs.submit(conn, kind="match", binary_id=_binary(conn, tmp_path))
        job_id = int(job["id"])
        conn.execute(f"UPDATE {jobs.TABLE} SET params_json = ? WHERE id = ?", ("[]", job_id))
        conn.commit()
        row = jobs.get_job(conn, job_id)
        assert row is not None
        assert row["params"] == {}


class _StubEngine(engines.RebrewEngine):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

    def available(self) -> bool:
        return True

    def pe_info(self, path: Any) -> dict[str, Any]:
        self.calls.append("pe_info")
        return {"machine": 0x14C, "sections": []}

    def analyze(self, path: Any) -> dict[str, Any]:
        self.calls.append("analyze")
        return {"meta": {}, "findings": []}

    def crypto_scan(self, path: Any) -> dict[str, Any]:
        self.calls.append("crypto_scan")
        return {"findings": [], "count": 0}

    def security_scan(self, project_dir: Any, min_severity: str = "") -> dict[str, Any]:
        self.calls.append("security_scan")
        return {"findings": [], "count": 0, "min_severity": min_severity}

    def structs(self, project_dir: Any, *, decompiler: str = "", limit: int = 0) -> dict[str, Any]:
        self.calls.append("structs")
        return {"structs": [], "count": 0, "decompiler": decompiler, "limit": limit}

    def strings(self, binary: Any) -> dict[str, Any]:
        self.calls.append("strings")
        return {"strings": [{"text": "http://c2.example/beacon", "kind": "ascii", "va": 0}]}

    def imports(self, binary: Any) -> dict[str, Any]:
        self.calls.append("imports")
        return {"imports": [{"dll": "KERNEL32.dll", "name": "CreateFileW", "iat_va": "0x0"}]}

    def fingerprint(self, binary: Any) -> dict[str, Any]:
        self.calls.append("fingerprint")
        return {"sha256": "ab" * 32, "imphash": "27abfd9cfda7519d5efb3f08a2a4f3ce"}


class TestPerformPeInfo:
    def test_pe_info_scan_is_stored(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="ab" * 32, name="demo.exe", path=str(target), size=2
        )
        stub = _StubEngine()
        engines.set_engine(stub)
        try:
            result = jobs._perform_pe_info(conn, binary_id, {})
        finally:
            engines.set_engine(engines.RebrewEngine(enabled=False))
        assert result["machine"] == 0x14C
        assert stub.calls == ["pe_info"]
        stored = store.get_scan(
            conn,
            store.latest_analysis_for_binary(conn, binary_id) or 0,
            store.SCAN_KIND_PE_INFO,
        )
        assert stored is not None

    def test_triage_scan_is_stored(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="cd" * 32, name="demo.exe", path=str(target), size=2
        )
        stub = _StubEngine()
        engines.set_engine(stub)
        try:
            result = jobs._perform_triage(conn, binary_id, {})
        finally:
            engines.set_engine(engines.RebrewEngine(enabled=False))
        assert result["meta"] == {}
        assert stub.calls == ["analyze"]

    def test_crypto_scan_is_stored(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="ef" * 32, name="demo.exe", path=str(target), size=2
        )
        stub = _StubEngine()
        engines.set_engine(stub)
        try:
            result = jobs._perform_crypto(conn, binary_id, {})
        finally:
            engines.set_engine(engines.RebrewEngine(enabled=False))
        assert result["count"] == 0
        assert stub.calls == ["crypto_scan"]

    def test_security_scan_is_stored(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="56" * 32, name="demo.exe", path=str(target), size=2
        )
        store.set_rebrew_context(conn, binary_id, str(tmp_path))
        stub = _StubEngine()
        engines.set_engine(stub)
        try:
            result = jobs._perform_security(conn, binary_id, {})
        finally:
            engines.set_engine(engines.RebrewEngine(enabled=False))
        assert result["count"] == 0
        assert stub.calls == ["security_scan"]

    def test_structs_scan_is_stored(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="78" * 32, name="demo.exe", path=str(target), size=2
        )
        store.set_rebrew_context(conn, binary_id, str(tmp_path))
        stub = _StubEngine()
        engines.set_engine(stub)
        try:
            result = jobs._perform_structs(conn, binary_id, {"limit": 5})
        finally:
            engines.set_engine(engines.RebrewEngine(enabled=False))
        assert result["limit"] == 5
        assert stub.calls == ["structs"]

    def test_remediation_is_stored(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="9a" * 32, name="demo.exe", path=str(target), size=2
        )
        stub = _StubEngine()
        engines.set_engine(stub)
        try:
            result = jobs._run_remediation(conn, binary_id, {})
        finally:
            engines.set_engine(engines.RebrewEngine(enabled=False))
        assert result["rule"]
        assert "strings" in stub.calls


class TestMorePerforms:
    def test_firmware_scan_is_stored(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        target = tmp_path / "demo.bin"
        target.write_bytes(b"\x00" * 128)
        binary_id = store.add_binary(
            conn, sha256="12" * 32, name="demo.bin", path=str(target), size=128
        )
        result = jobs._perform_firmware(conn, binary_id, {})
        assert result["regions"] == []
        stored = store.get_scan(
            conn,
            store.latest_analysis_for_binary(conn, binary_id) or 0,
            store.SCAN_KIND_FIRMWARE,
        )
        assert stored is not None

    def test_library_rejects_a_non_numeric_confidence(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="34" * 32, name="demo.exe", path=str(target), size=2
        )
        with pytest.raises(ValueError):
            jobs._run_library(conn, binary_id, {"min_confidence": "high"})


class TestDebugParamValidation:
    def _binary_id(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.bin"
        target.write_bytes(b"x")
        return store.add_binary(conn, sha256="bc" * 32, name="demo.bin", path=str(target), size=1)

    def test_non_numeric_timeout_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        binary_id = self._binary_id(conn, tmp_path)
        with pytest.raises(ValueError):
            jobs._perform_debug(conn, binary_id, {"timeout": "soon"})

    def test_non_list_breakpoints_are_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        binary_id = self._binary_id(conn, tmp_path)
        with pytest.raises(ValueError, match="breakpoints must be a list"):
            jobs._perform_debug(conn, binary_id, {"breakpoints": 0x1000})

    def test_empty_qemu_arch_is_rejected(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        binary_id = self._binary_id(conn, tmp_path)
        with pytest.raises(ValueError, match="qemu_arch must be a non-empty"):
            jobs._perform_debug(conn, binary_id, {"qemu_arch": "  "})


class TestRenderPdf:
    def test_pdf_report_is_written_and_journaled(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="de" * 32, name="demo.exe", path=str(target), size=2
        )
        result = jobs.render_pdf(conn, binary_id, {})
        assert result["path"].endswith(".pdf")
        from reportal import _paths

        written = _paths.reports_dir(binary_id) / "report.pdf"
        assert written.is_file()


class TestLatestJob:
    def test_unknown_kind_is_rejected(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError, match="unknown job kind"):
            jobs.latest_job(conn, kind="mystery")

    def test_newest_of_kind_is_returned(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        binary_id = _binary(conn, tmp_path)
        jobs.submit(conn, kind="pe-info", binary_id=binary_id)
        job = jobs.submit(conn, kind="pe-info", binary_id=binary_id)
        latest = jobs.latest_job(conn, kind="pe-info")
        assert latest is not None
        assert int(latest["id"]) == int(job["id"])

    def test_binary_filter_narrows(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        first = _binary(conn, tmp_path, name="a.exe")
        second = _binary(conn, tmp_path, name="b.exe")
        jobs.submit(conn, kind="pe-info", binary_id=first)
        jobs.submit(conn, kind="pe-info", binary_id=second)
        latest = jobs.latest_job(conn, kind="pe-info", binary_id=first)
        assert latest is not None
        assert int(latest["binary_id"]) == first


class TestQueueStoredScans:
    def test_unknown_analysis_queues_nothing(self, conn: sqlite3.Connection) -> None:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            assert jobs.queue_stored_scans(conn, log, 424242) == []

    def test_scans_with_a_job_kind_are_queued(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="fa" * 32, name="demo.exe", path=str(target), size=2
        )
        analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_PE_INFO,
            {"machine": 0x14C},
            params={"min_severity": "low"},
        )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            queued = jobs.queue_stored_scans(conn, log, analysis_id)
        assert len(queued) == 1
        assert queued[0]["kind"] == "pe-info"

    def test_unmapped_scans_are_skipped(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        binary_id = store.add_binary(
            conn, sha256="0b" * 32, name="demo.exe", path=str(target), size=2
        )
        analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
        store.set_scan(conn, analysis_id, "no-such-kind", {"x": 1})
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            assert jobs.queue_stored_scans(conn, log, analysis_id) == []


class TestSubmitRace:
    def test_duplicate_live_submit_reuses_the_row(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        first = jobs.submit(conn, kind="pe-info", binary_id=binary_id)
        second = jobs.submit(conn, kind="pe-info", binary_id=binary_id)
        assert int(second["id"]) == int(first["id"])


class TestRequestIdRestore:
    def test_stored_request_id_is_restored(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        from reportal import observability

        token = observability.set_request_id("req-abc")
        try:
            job = jobs.submit(conn, kind="pe-info", binary_id=_binary(conn, tmp_path))
        finally:
            observability.reset_request_id(token)
        assert job["request_id"] == "req-abc"
        stub = _StubEngine()
        engines.set_engine(stub)
        try:
            stored = jobs.execute(conn, jobs.get_job(conn, int(job["id"])) or {})
        finally:
            engines.set_engine(engines.RebrewEngine(enabled=False))
        assert stored["status"] == jobs.STATUS_DONE
        assert observability.current_request_id() in (None, "")


class TestLogSlow:
    def test_slow_job_logs_a_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        jobs._log_job_slow(job_id=1, kind="pe-info", binary_id=2, duration_ms=5000)
        assert any("job slow" in record.message for record in caplog.records)


class TestSlowJobCallSite:
    def test_slow_threshold_triggers_the_warning(
        self,
        tmp_path: Path,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from reportal import observability

        monkeypatch.setattr(observability, "SLOW_JOB_MS", 0)
        stub = _StubEngine()
        engines.set_engine(stub)
        try:
            job = jobs.submit(conn, kind="pe-info", binary_id=_binary(conn, tmp_path))
            jobs.execute(conn, jobs.get_job(conn, int(job["id"])) or {})
        finally:
            engines.set_engine(engines.RebrewEngine(enabled=False))
        assert any("job slow" in record.message for record in caplog.records)


class TestSubmitParamValidation:
    def test_non_numeric_min_confidence_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="min_confidence must be a number"):
            jobs.submit(
                conn,
                kind="library",
                binary_id=_binary(conn, tmp_path),
                params={"min_confidence": "high"},
            )

    def test_out_of_range_min_confidence_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="min_confidence must be between"):
            jobs.submit(
                conn,
                kind="library",
                binary_id=_binary(conn, tmp_path),
                params={"min_confidence": 1.5},
            )


class TestSecurityThreatParamValidation:
    def test_unsupported_severity_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="unsupported security severity"):
            jobs.submit(
                conn,
                kind="security",
                binary_id=_binary(conn, tmp_path),
                params={"min_severity": "cosmic"},
            )

    def test_non_boolean_narrative_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="narrative must be a boolean"):
            jobs.submit(
                conn,
                kind="threat",
                binary_id=_binary(conn, tmp_path),
                params={"narrative": "yes"},
            )


class TestStructsParamValidation:
    def test_unsupported_decompiler_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="unsupported decompiler backend"):
            jobs.submit(
                conn,
                kind="structs",
                binary_id=_binary(conn, tmp_path),
                params={"decompiler": "mystery"},
            )

    def test_non_integer_limit_is_rejected(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError, match="limit must be an integer"):
            jobs.submit(
                conn,
                kind="structs",
                binary_id=_binary(conn, tmp_path),
                params={"limit": "many"},
            )

    def test_negative_limit_is_rejected(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError, match="limit must not be negative"):
            jobs.submit(
                conn,
                kind="structs",
                binary_id=_binary(conn, tmp_path),
                params={"limit": -1},
            )


class TestFunctionTriageParamValidation:
    def test_non_integer_limit_is_rejected(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError, match="limit must be an integer"):
            jobs.submit(
                conn,
                kind="function-triage",
                binary_id=_binary(conn, tmp_path),
                params={"limit": "many"},
            )

    def test_out_of_range_limit_is_rejected(self, tmp_path: Path, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError, match="limit must be between"):
            jobs.submit(
                conn,
                kind="function-triage",
                binary_id=_binary(conn, tmp_path),
                params={"limit": 0},
            )

    def test_non_list_function_ids_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="function_ids must be a list"):
            jobs.submit(
                conn,
                kind="function-triage",
                binary_id=_binary(conn, tmp_path),
                params={"function_ids": 0x1000},
            )


class TestRelatedLineageBenchmarkUnpackValidation:
    def test_related_non_integer_limit_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="limit must be an integer"):
            jobs.submit(
                conn,
                kind="related",
                binary_id=_binary(conn, tmp_path),
                params={"limit": "many"},
            )

    def test_related_non_positive_limit_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="limit must be positive"):
            jobs.submit(
                conn,
                kind="related",
                binary_id=_binary(conn, tmp_path),
                params={"limit": 0},
            )

    def test_related_non_boolean_unrelated_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="include_unrelated must be a boolean"):
            jobs.submit(
                conn,
                kind="related",
                binary_id=_binary(conn, tmp_path),
                params={"include_unrelated": "yes"},
            )

    def test_lineage_non_integer_other_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="other_binary_id must be an integer"):
            jobs.submit(
                conn,
                kind="lineage",
                binary_id=_binary(conn, tmp_path),
                params={"other_binary_id": "abc"},
            )

    def test_lineage_self_comparison_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        with pytest.raises(ValueError, match="cannot be compared with itself"):
            jobs.submit(
                conn,
                kind="lineage",
                binary_id=binary_id,
                params={"other_binary_id": binary_id},
            )

    def test_lineage_non_boolean_refine_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="refine must be a boolean"):
            jobs.submit(
                conn,
                kind="lineage",
                binary_id=_binary(conn, tmp_path),
                params={"refine": "yes"},
            )

    def test_benchmark_missing_right_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="right_binary_id is required"):
            jobs.submit(
                conn,
                kind="benchmark",
                binary_id=_binary(conn, tmp_path),
            )

    def test_benchmark_self_comparison_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        binary_id = _binary(conn, tmp_path)
        with pytest.raises(ValueError, match="two different binaries"):
            jobs.submit(
                conn,
                kind="benchmark",
                binary_id=binary_id,
                params={"right_binary_id": binary_id},
            )

    def test_unpack_unknown_packer_is_rejected(
        self, tmp_path: Path, conn: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError, match="packer must be one of"):
            jobs.submit(
                conn,
                kind="unpack",
                binary_id=_binary(conn, tmp_path),
                params={"packer": "mystery"},
            )

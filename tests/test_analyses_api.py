"""Tests for the analysis lifecycle routes: read, update, status, params, map, logs, tags."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request

from reportal import analysis_log, auth, jobs, journal, store


def _seed(conn: sqlite3.Connection) -> dict[str, int]:
    binary_id = store.add_binary(
        conn, sha256="c" * 64, name="demo.exe", path="/tmp/demo.exe", size=128
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    first = store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=32)
    second = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16)
    return {"binary": binary_id, "analysis": analysis_id, "first": first, "second": second}


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


def _send(method: str, path: str, body: dict[str, Any] | None = None) -> tuple[str, Any]:
    raw = b"" if body is None else json.dumps(body).encode()
    status, headers, payload = wsgi_request(method, path, body=raw)
    return status, json_body(payload, headers)


class TestDetail:
    def test_it_carries_the_counts_the_scans_and_the_tags(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.set_scan(conn, ids["analysis"], store.SCAN_KIND_FILETYPE, {"count": 1})
        tag_id = store.create_tag(conn, "triage")
        store.add_binary_tag(conn, ids["binary"], tag_id)

        status, payload = _get(f"/api/analyses/{ids['analysis']}")

        assert status.startswith("200")
        assert payload["status"] == "done", "storing a scan finishes its analysis"
        assert payload["engine"] == "manual"
        assert payload["function_count"] == 2
        assert payload["scan_count"] == 1
        assert payload["scans"] == [{"kind": "filetype", "status": "done"}]
        assert payload["log_count"] >= 1
        assert payload["tags"] == ["triage"]

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/analyses/4242")

        assert status.startswith("404")
        assert payload["error"] == "analysis not found"


class TestStatus:
    def test_it_counts_by_severity_and_by_scan_status(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        analysis_log.append_entry(conn, ids["analysis"], message="warned", severity="warn")
        analysis_log.append_entry(conn, ids["analysis"], message="failed", severity="error")
        store.set_scan(conn, ids["analysis"], store.SCAN_KIND_FILETYPE, {"count": 1})

        status, payload = _get(f"/api/analyses/{ids['analysis']}/status")

        assert status.startswith("200")
        assert payload["status"] == "done", "storing a scan finishes its analysis"
        assert payload["terminal"] is True
        assert payload["scans"] == 1
        assert payload["scans_by_status"] == {"done": 1}
        assert payload["logs_by_severity"]["warn"] == 1
        assert payload["logs_by_severity"]["error"] == 1

    def test_a_finished_analysis_is_terminal(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.update_analysis_status(conn, ids["analysis"], status="done")

        status, payload = _get(f"/api/analyses/{ids['analysis']}/status")

        assert status.startswith("200")
        assert payload["terminal"] is True
        assert payload["finished_at"]

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/analyses/4242/status")

        assert status.startswith("404")
        assert payload["error"] == "analysis not found"


class TestParams:
    def test_it_records_what_a_rerun_needs(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.set_rebrew_context(conn, ids["binary"], "/tmp/rebrew-project")

        status, payload = _get(f"/api/analyses/{ids['analysis']}/params")

        assert status.startswith("200")
        assert payload["engine"] == "manual"
        assert payload["binary"]["sha256"] == "c" * 64
        assert payload["binary"]["path"] == "/tmp/demo.exe"
        assert payload["rebrew_project"] == "/tmp/rebrew-project"
        assert payload["scans"] == []

    def test_a_binary_without_a_project_reports_none(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _get(f"/api/analyses/{ids['analysis']}/params")

        assert status.startswith("200")
        assert payload["rebrew_project"] is None

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/analyses/4242/params")

        assert status.startswith("404")
        assert payload["error"] == "analysis not found"


class TestFuncMaps:
    def test_the_map_is_ordered_by_address(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _get(f"/api/analyses/{ids['analysis']}/func-maps")

        assert status.startswith("200")
        assert [row["va"] for row in payload["functions"]] == [0x1000, 0x2000]
        assert payload["count"] == 2
        assert payload["total"] == 2
        assert payload["functions"][0]["name"] == "sub_1000"
        assert payload["functions"][0]["size"] == 16

    def test_an_analysis_with_no_functions_answers_an_empty_map(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = store.add_binary(
            conn, sha256="d" * 64, name="bare.exe", path="/tmp/bare.exe", size=8
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")

        status, payload = _get(f"/api/analyses/{analysis_id}/func-maps")

        assert status.startswith("200")
        assert payload["functions"] == []
        assert payload["total"] == 0

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _get("/api/analyses/4242/func-maps")

        assert status.startswith("404")
        assert payload["error"] == "analysis not found"


class TestUpdate:
    def test_it_relabels_and_reverts(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _send("PATCH", f"/api/analyses/{ids['analysis']}", {"engine": "rebrew"})

        assert status.startswith("200")
        assert payload["engine"] == "rebrew"
        assert payload["journal_action"]
        journal.revert_action(conn, payload["journal_action"])
        restored = store.get_analysis(conn, ids["analysis"])
        assert restored is not None
        assert restored["engine"] == "manual"

    def test_an_empty_body_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _send("PATCH", f"/api/analyses/{ids['analysis']}", {})

        assert status.startswith("400")
        assert payload["error"] == "invalid body"

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("PATCH", "/api/analyses/4242", {"engine": "rebrew"})

        assert status.startswith("404")
        assert payload["error"] == "analysis not found"


class TestLogs:
    def test_it_appends_and_reverts(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _send(
            "POST",
            f"/api/analyses/{ids['analysis']}/logs",
            {"message": "looked at the entry point", "severity": "warn"},
        )

        assert status.startswith("201")
        assert payload["severity"] == "warn"
        entries, total = analysis_log.list_entries(conn, ids["analysis"])
        assert entries[0]["message"] == "looked at the entry point"
        journal.revert_action(conn, payload["journal_action"])
        _, after = analysis_log.list_entries(conn, ids["analysis"])
        assert after == total - 1

    def test_the_severity_defaults_to_info(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _send(
            "POST", f"/api/analyses/{ids['analysis']}/logs", {"message": "noted"}
        )

        assert status.startswith("201")
        assert payload["severity"] == "info"

    def test_an_unknown_severity_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _send(
            "POST",
            f"/api/analyses/{ids['analysis']}/logs",
            {"message": "noted", "severity": "loud"},
        )

        assert status.startswith("400")
        assert payload["error"] == "invalid severity"

    def test_a_blank_message_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _send("POST", f"/api/analyses/{ids['analysis']}/logs", {"message": "   "})

        assert status.startswith("400")
        assert payload["error"] == "message must be a non-empty string"

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("POST", "/api/analyses/4242/logs", {"message": "noted"})

        assert status.startswith("404")
        assert payload["error"] == "analysis not found"


class TestRequeue:
    def test_it_moves_a_finished_analysis_back_and_reverts(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.update_analysis_status(conn, ids["analysis"], status="failed")
        before = store.get_analysis(conn, ids["analysis"])
        assert before is not None
        assert before["finished_at"]

        status, payload = _send("POST", f"/api/analyses/{ids['analysis']}/requeue")

        assert status.startswith("200")
        assert payload["status"] == "pending"
        assert payload["finished_at"] is None
        assert payload["jobs"] == []
        entries, _ = analysis_log.list_entries(conn, ids["analysis"])
        assert "status changed to pending (was failed)" in str(entries[0]["message"])
        journal.revert_action(conn, payload["journal_action"])
        after = store.get_analysis(conn, ids["analysis"])
        assert after is not None
        assert after["status"] == "failed"
        assert after["finished_at"] == before["finished_at"]
        restored, _ = analysis_log.list_entries(conn, ids["analysis"])
        assert all("status changed to pending" not in str(entry["message"]) for entry in restored)

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _send("POST", "/api/analyses/4242/requeue")

        assert status.startswith("404")
        assert payload["error"] == "analysis not found"

    def test_it_queues_stored_scans_that_have_a_job_kind(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.set_scan(conn, ids["analysis"], store.SCAN_KIND_FILETYPE, {"count": 1})
        store.set_scan(conn, ids["analysis"], store.SCAN_KIND_TRIAGE, {"ok": True})
        store.set_scan(conn, ids["analysis"], store.SCAN_KIND_UNPACK, {"ok": True})
        store.update_analysis_status(conn, ids["analysis"], status="done")

        status, payload = _send("POST", f"/api/analyses/{ids['analysis']}/requeue")

        assert status.startswith("200")
        assert [job["kind"] for job in payload["jobs"]] == ["triage", "filetype"]
        listed, _ = jobs.list_jobs(conn, binary_id=ids["binary"])
        assert [job["kind"] for job in listed] == ["filetype", "triage"]
        journal.revert_action(conn, payload["journal_action"])
        leftover, _ = jobs.list_jobs(conn, binary_id=ids["binary"])
        assert leftover == []


class TestTags:
    def test_the_read_returns_the_binaries_tags(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        runner = _send("PATCH", f"/api/analyses/{ids['analysis']}/tags", {"tags": ["pe", "games"]})
        assert runner[0].startswith("200")

        status, payload = _get(f"/api/analyses/{ids['analysis']}/tags")

        assert status.startswith("200")
        assert [tag["name"] for tag in payload["tags"]] == ["games", "pe"]

    def test_the_replace_creates_removes_and_reverts(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        first = _send("PATCH", f"/api/analyses/{ids['analysis']}/tags", {"tags": ["pe"]})
        assert first[0].startswith("200")

        status, payload = _send(
            "PATCH", f"/api/analyses/{ids['analysis']}/tags", {"tags": ["games"]}
        )

        assert status.startswith("200")
        assert [tag["name"] for tag in payload["tags"]] == ["games"]
        journal.revert_action(conn, payload["journal_action"])
        restored = store.get_binary_tags(conn, ids["binary"])
        assert [tag["name"] for tag in restored] == ["pe"]

    def test_a_body_that_is_not_a_list_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _send("PATCH", f"/api/analyses/{ids['analysis']}/tags", {"tags": "pe"})

        assert status.startswith("400")
        assert payload["error"] == "invalid body"

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        assert _get("/api/analyses/4242/tags")[0].startswith("404")
        assert _send("PATCH", "/api/analyses/4242/tags", {"tags": []})[0].startswith("404")


def _seed_import(conn: sqlite3.Connection, ids: dict[str, int]) -> int:
    """One import stub, with the matching text in the first function's source."""
    stub = store.add_function(
        conn,
        analysis_id=ids["analysis"],
        va=0x3000,
        name="CreateFileW",
        size=6,
        status="THUNK",
        name_source=store.IMPORTED_NAME_SOURCE,
    )
    store.set_decompilation(
        conn, ids["first"], 'void sub_2000(void) { CreateFileW(L"x"); }', "kuna"
    )
    store.set_decompilation(conn, ids["second"], "void sub_1000(void) {}", "kuna")
    return stub


class TestImportedFunctions:
    def test_it_lists_the_stubs_with_their_text_derived_callers(
        self, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(conn)
        stub = _seed_import(conn, ids)

        status, payload = _get(f"/api/analyses/{ids['analysis']}/imported-functions")

        assert status.startswith("200")
        assert payload["analysis_id"] == ids["analysis"]
        assert payload["binary_id"] == ids["binary"]
        assert payload["caller_method"] == "decompilation-text"
        assert payload["total"] == 1
        assert payload["count"] == 1
        stub_row = payload["functions"][0]
        assert stub_row["id"] == stub
        assert stub_row["name"] == "CreateFileW"
        assert stub_row["name_source"] == store.IMPORTED_NAME_SOURCE
        assert stub_row["caller_count"] == 1, "only sub_2000 mentions it"
        assert [caller["id"] for caller in stub_row["callers"]] == [ids["first"]]

    def test_an_analysis_with_no_stubs_answers_empty(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _get(f"/api/analyses/{ids['analysis']}/imported-functions")

        assert status.startswith("200")
        assert payload["functions"] == []
        assert payload["total"] == 0

    def test_a_stub_with_no_name_has_no_callers(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        store.add_function(
            conn,
            analysis_id=ids["analysis"],
            va=0x3000,
            name="",
            size=6,
            name_source=store.IMPORTED_NAME_SOURCE,
        )

        _, payload = _get(f"/api/analyses/{ids['analysis']}/imported-functions")

        assert payload["functions"][0]["callers"] == []
        assert payload["functions"][0]["caller_count"] == 0

    def test_a_limit_outside_its_bound_is_400(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)

        status, payload = _get(f"/api/analyses/{ids['analysis']}/imported-functions?limit=0")

        assert status.startswith("400")
        assert payload["error"] == "invalid limit"

    def test_an_unknown_analysis_is_404(self, conn: sqlite3.Connection) -> None:
        assert _get("/api/analyses/4242/imported-functions")[0].startswith("404")


class TestBytes:
    def test_it_streams_the_analysiss_binary_bytes(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        path = tmp_path / "demo.bin"
        path.write_bytes(b"MZdemo-bytes")
        binary_id = store.add_binary(
            conn, sha256="d" * 64, name="demo.bin", path=str(path), size=12
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")

        status, headers, body = wsgi_request("GET", f"/api/analyses/{analysis_id}/bytes")

        assert status.startswith("200")
        assert body == b"MZdemo-bytes"
        assert headers["Content-Disposition"] == 'attachment; filename="demo.bin"'

    def test_an_unknown_analysis_is_404(self) -> None:
        assert wsgi_request("GET", "/api/analyses/4242/bytes")[0].startswith("404")

    def test_a_binary_missing_from_disk_is_404(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = store.add_binary(
            conn, sha256="e" * 64, name="gone.bin", path=str(tmp_path / "gone.bin"), size=4
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")

        status, headers, payload = wsgi_request("GET", f"/api/analyses/{analysis_id}/bytes")

        assert status.startswith("404")
        assert json_body(payload, headers)["error"] == "binary not on disk"


class TestWorkspaceFilter:
    def _analyse(self, conn: sqlite3.Connection, *, team: bool, index: int = 0) -> int:
        """One binary (optionally owned by a team) with an analysis.

        Each call registers its own binary, because the hash is the register's
        identity: two calls with one hash would be one binary.
        """
        team_id = 0
        if team:
            user, _token = auth.add_user(conn, name=f"owner{index}", role="admin")
            team_id = int(auth.create_team(conn, name=f"team{index}")["id"])
            auth.add_member(conn, team_id, int(user["id"]))
        binary_id = store.add_binary(conn, sha256=f"{index:02d}" * 32, name=f"demo{index}.exe")
        if team:
            store.set_binary_scope(conn, binary_id, visibility="team", owner_team_id=team_id)
        return store.create_analysis(conn, binary_id=binary_id, engine="manual")

    def test_the_listing_carries_the_binary_scope(self, conn: sqlite3.Connection) -> None:
        self._analyse(conn, team=True, index=5)
        status, headers, body = wsgi_request("GET", "/api/analyses")
        assert status.startswith("200"), body
        row = json_body(body, headers)["analyses"][0]
        assert row["visibility"] == "team"
        assert row["owner_team_name"] == "team5"

    def test_the_workspace_filter_selects_one_scope(self, conn: sqlite3.Connection) -> None:
        self._analyse(conn, team=False, index=1)
        self._analyse(conn, team=True, index=2)
        personal, headers, body = wsgi_request("GET", "/api/analyses?workspace=personal")
        assert personal.startswith("200"), body
        assert json_body(body, headers)["count"] == 1
        assert json_body(body, headers)["analyses"][0]["owner_team_id"] is None

        team, headers, body = wsgi_request("GET", "/api/analyses?workspace=team")
        assert json_body(body, headers)["count"] == 1
        assert json_body(body, headers)["analyses"][0]["owner_team_name"] == "team2"

        # A team-scoped object is not public, so the public filter keeps the other.
        public, headers, body = wsgi_request("GET", "/api/analyses?workspace=public")
        assert json_body(body, headers)["count"] == 1
        assert json_body(body, headers)["analyses"][0]["owner_team_id"] is None

    def test_an_unknown_workspace_is_400(self) -> None:
        status, headers, body = wsgi_request("GET", "/api/analyses?workspace=nonsense")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid workspace"

    def test_the_store_refuses_an_unknown_filter(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(ValueError):
            store.list_analyses(conn, workspace="nonsense")

    def test_a_non_member_does_not_list_a_team_analysis(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        binary_id = store.add_binary(conn, sha256="07" * 32, name="scoped.exe")
        store.set_binary_scope(conn, binary_id, visibility="team", owner_team_id=team_id)
        store.create_analysis(conn, binary_id=binary_id, engine="manual")

        member, headers, body = wsgi_request(
            "GET", "/api/analyses", headers={"Authorization": f"Bearer {token}"}
        )
        assert member.startswith("200"), body
        assert json_body(body, headers)["count"] == 1

        stranger, headers, body = wsgi_request(
            "GET", "/api/analyses", headers={"Authorization": f"Bearer {outsider}"}
        )
        assert stranger.startswith("200"), body
        assert json_body(body, headers)["count"] == 0
        assert json_body(body, headers)["total"] == 0

    def test_creating_an_analysis_on_a_hidden_binary_is_404(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn)
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, headers, body = wsgi_request(
            "POST",
            "/api/analyses",
            body=json.dumps({"binary_id": ids["binary"]}),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "binary not found"

        member_status, headers, body = wsgi_request(
            "POST",
            "/api/analyses",
            body=json.dumps({"binary_id": ids["binary"]}),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("201"), body

    def test_the_cli_and_the_tool(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from reportal import cli, mcp_server

        self._analyse(conn, team=False, index=1)
        self._analyse(conn, team=True, index=2)
        runner = CliRunner()
        payload = json.loads(
            runner.invoke(cli.app, ["analyses", "--workspace", "team", "--json"]).output
        )
        assert payload["count"] == 1
        assert payload["analyses"][0]["owner_team_name"] == "team2"

        listed = runner.invoke(cli.app, ["analyses"])
        assert listed.exit_code == 0, listed.output
        assert "personal" in listed.output

        bad = runner.invoke(cli.app, ["analyses", "--workspace", "nonsense"])
        assert bad.exit_code == 1
        assert "unknown workspace" in bad.output

        found, failed = mcp_server.call_tool("list_analyses", {"workspace": "team"})
        assert not failed, found
        assert found["count"] == 1

        refused, failed = mcp_server.call_tool("list_analyses", {"workspace": "nonsense"})
        assert failed
        assert refused["error"] == "invalid workspace"

        # The binary-scoped read `GET /api/analyses?binary_id=` already offered.
        binary_id = json.loads(runner.invoke(cli.app, ["analyses", "--json"]).output)["analyses"][
            0
        ]["binary_id"]
        scoped = json.loads(
            runner.invoke(cli.app, ["analyses", "--binary", str(binary_id), "--json"]).output
        )
        assert scoped["count"] == 1
        assert scoped["total"] == 1
        assert scoped["analyses"][0]["binary_id"] == binary_id

        missing = runner.invoke(cli.app, ["analyses", "--binary", "999999"])
        assert missing.exit_code == 1
        assert "no binary with id 999999" in missing.output

        one, failed = mcp_server.call_tool("list_analyses", {"binary_id": binary_id})
        assert not failed, one
        assert one["count"] == 1
        assert one["total"] == 1
        assert one["analyses"][0]["binary_id"] == binary_id


class TestAnalysisFilters:
    """The list's multi-status, platform and architecture filters (entry 10)."""

    def _analyse(
        self,
        conn: sqlite3.Connection,
        *,
        index: int,
        status: str = "pending",
        fmt: str = "",
        arch: str = "",
    ) -> int:
        binary_id = store.add_binary(
            conn, sha256=f"{index:02d}" * 32, name=f"demo{index}.exe", fmt=fmt, arch=arch
        )
        return store.create_analysis(conn, binary_id=binary_id, engine="manual", status=status)

    def test_several_statuses_are_any_of(self, conn: sqlite3.Connection) -> None:
        self._analyse(conn, index=1, status="pending")
        self._analyse(conn, index=2, status="done")
        self._analyse(conn, index=3, status="failed")

        status, headers, body = wsgi_request("GET", "/api/analyses?status=pending&status=done")
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["count"] == 2
        assert {row["status"] for row in payload["analyses"]} == {"pending", "done"}

    def test_one_status_still_answers(self, conn: sqlite3.Connection) -> None:
        self._analyse(conn, index=1, status="done")
        self._analyse(conn, index=2, status="failed")
        _status, headers, body = wsgi_request("GET", "/api/analyses?status=done")
        assert json_body(body, headers)["count"] == 1

    def test_an_unknown_status_is_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/analyses?status=sideways")
        assert status.startswith("400"), body
        assert json_body(body, headers)["error"] == "invalid status"

    def test_platform_and_architecture_filter_the_binary(self, conn: sqlite3.Connection) -> None:
        self._analyse(conn, index=1, fmt="pe", arch="x86_64")
        self._analyse(conn, index=2, fmt="elf", arch="aarch64")

        _status, headers, body = wsgi_request("GET", "/api/analyses?platform=pe&arch=x86_64")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["analyses"][0]["binary_format"] == "pe"
        # The payload names the values the register holds, for the controls.
        assert payload["platforms"] == ["elf", "pe"]
        assert payload["architectures"] == ["aarch64", "x86_64"]

    def test_an_override_answers_the_platform_filter_first(self, conn: sqlite3.Connection) -> None:
        self._analyse(conn, index=1, fmt="pe", arch="x86_64")
        binary_id = int(
            conn.execute("SELECT id FROM binaries WHERE sha256 = ?", ("01" * 32,)).fetchone()["id"]
        )
        store.set_binary_format_override(conn, binary_id, format_override="elf")

        _status, headers, body = wsgi_request("GET", "/api/analyses?platform=elf")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        row = payload["analyses"][0]
        assert row["binary_format"] == "elf"
        assert row["binary_format_override"] == "elf"
        # The filter controls offer the effective value the rows answer with.
        assert "elf" in payload["platforms"]

    def test_the_named_orders_sort_by_name_and_size(self, conn: sqlite3.Connection) -> None:
        self._analyse(conn, index=1)
        self._analyse(conn, index=2)
        _status, headers, body = wsgi_request("GET", "/api/analyses?order=name")
        names = [row["binary_name"] for row in json_body(body, headers)["analyses"]]
        assert names == sorted(names)
        _status, headers, body = wsgi_request("GET", "/api/analyses?order=name-desc")
        names = [row["binary_name"] for row in json_body(body, headers)["analyses"]]
        assert names == sorted(names, reverse=True)

    def test_an_unknown_order_is_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/analyses?order=sideways")
        assert status.startswith("400"), body
        assert json_body(body, headers)["error"] == "invalid order"

    def test_search_matches_the_name_the_engine_and_the_hash(
        self, conn: sqlite3.Connection
    ) -> None:
        self._analyse(conn, index=1)
        self._analyse(conn, index=2)

        # The name and the engine label, as they always were.
        _status, headers, body = wsgi_request("GET", "/api/analyses?search=demo1")
        assert [row["binary_name"] for row in json_body(body, headers)["analyses"]] == ["demo1.exe"]
        _status, headers, body = wsgi_request("GET", "/api/analyses?search=manual")
        assert json_body(body, headers)["count"] == 2

        # And the hash: a prefix is what an analyst has for a sample whose name
        # they do not know.
        _status, headers, body = wsgi_request("GET", "/api/analyses?search=0202")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["analyses"][0]["binary_name"] == "demo2.exe"

    def test_search_escapes_like_wildcards(self, conn: sqlite3.Connection) -> None:
        self._analyse(conn, index=1)

        status, headers, body = wsgi_request("GET", "/api/analyses?search=%25")

        assert status.startswith("200")
        assert json_body(body, headers)["count"] == 0

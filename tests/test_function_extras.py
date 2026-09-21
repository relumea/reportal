"""Tests for the per-function extras: call sites, capabilities, edges and names.

The derivations are asserted directly (they are pure text scans over stored
rows), and the routes, CLI commands and MCP tools are driven over the same
store, so the four surfaces cannot drift from what the module produces.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import auth, cli, function_extras, journal, mcp_server, store
from reportal._paths import DB_ENV

runner = CliRunner()

LISTING = """0000000000401000  push rbp
0000000000401001  mov rbp, rsp
0000000000401004  call 0x401200
0000000000401009  call rax
000000000040100b  call qword [rbx+0x10]
000000000040100f  jmp rdx
0000000000401011  ret
"""

CODE = """int sub_0(void) {
    char *path = "/etc/passwd";
    sub_1();
    return CreateFileA(path, 0, 0, 0, 0, 0, 0);
}
"""


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A portal DB with one binary, one analysis and three functions."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        ids = [
            store.add_function(
                conn, analysis_id=analysis_id, va=0x1000 + index * 0x10, name=f"sub_{index}"
            )
            for index in range(3)
        ]
        store.add_function(
            conn,
            analysis_id=analysis_id,
            va=0x2000,
            name="CreateFileA",
            name_source=store.IMPORTED_NAME_SOURCE,
        )
        store.set_disasm(conn, ids[0], LISTING)
        store.set_decompilation(conn, ids[0], CODE, "kuna")
    return {"binary": binary_id, "analysis": analysis_id, "functions": ids, "db": db}


class TestIndirectCallSites:
    def test_only_register_and_memory_targets_are_reported(self) -> None:
        sites = function_extras.indirect_call_sites(LISTING)
        assert [entry["target"] for entry in sites] == ["rax", "qword [rbx+0x10]", "rdx"]
        assert [entry["line"] for entry in sites] == [4, 5, 6]
        assert all(entry["kind"] == "indirect" for entry in sites)

    def test_a_direct_call_and_a_jump_to_a_symbol_are_left_out(self) -> None:
        assert function_extras.indirect_call_sites("0001  call sub_401000\n") == []
        assert function_extras.indirect_call_sites("") == []

    def test_the_scan_stops_at_the_limit(self) -> None:
        text = "\n".join(f"{index:04x}  call rax" for index in range(10))
        assert len(function_extras.indirect_call_sites(text, limit=3)) == 3


class TestCalleesFromText:
    def test_a_known_name_is_reported_and_the_exclusion_dropped(self) -> None:
        found = function_extras.callees_from_text(
            CODE, known={"sub_1": 2, "sub_2": 3, "CreateFileA": 4}, exclude="sub_0"
        )
        assert sorted(entry["name"] for entry in found) == ["CreateFileA", "sub_1"]
        assert all(entry["derivation"] == "decompilation-text" for entry in found)

    def test_an_unknown_name_is_not_a_callee(self) -> None:
        assert function_extras.callees_from_text(CODE, known={}, exclude="sub_0") == []


class TestCapabilities:
    def test_the_function_classification_reads_its_own_text(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = function_extras.function_capabilities(conn, ids["functions"][0])
        assert payload["function_id"] == ids["functions"][0]
        assert payload["has_decompilation"] is True
        assert payload["inputs"]["imports"] == 1
        assert "derivation" in payload

    def test_a_function_with_no_decompilation_classifies_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = function_extras.function_capabilities(conn, ids["functions"][1])
        assert payload["has_decompilation"] is False
        assert payload["capabilities"] == []

    def test_an_unknown_function_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(function_extras.UnknownEdgeError),
        ):
            function_extras.function_capabilities(conn, 999)


class TestEdges:
    def test_an_edge_is_recorded_listed_and_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            row = function_extras.add_edge(
                conn, function_id=ids["functions"][0], callee="dispatch", kind="indirect"
            )
            assert row["source"] == function_extras.EDGE_SOURCE_ANALYST
            assert function_extras.list_edges(conn, ids["functions"][0]) == [row]
            removed = function_extras.delete_edge(conn, ids["functions"][0], edge_id=int(row["id"]))
            assert removed["callee"] == "dispatch"
            assert function_extras.list_edges(conn, ids["functions"][0]) == []

    def test_re_declaring_an_edge_updates_it_in_place(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            first = function_extras.add_edge(conn, function_id=ids["functions"][0], callee="f")
            second = function_extras.add_edge(
                conn, function_id=ids["functions"][0], callee="f", note="why"
            )
        assert first["id"] == second["id"]
        assert second["note"] == "why"

    def test_duplicate_edge_tuple_is_rejected_by_the_schema(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            function_extras.ensure_schema(conn)
            function_extras.add_edge(conn, function_id=ids["functions"][0], callee="f")
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO function_edges"
                    " (function_id, callee_name, kind, note, source, created_at)"
                    " VALUES (?, 'f', 'call', '', 'analyst', ?)",
                    (ids["functions"][0], store.now()),
                )

    def test_a_blank_callee_and_a_bad_kind_are_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            for callee, kind in (("", None), ("x" * 200, None), ("f", "jump")):
                with pytest.raises(function_extras.InvalidEdgeError):
                    function_extras.add_edge(
                        conn, function_id=ids["functions"][0], callee=callee, kind=kind
                    )

    def test_callee_names_collapse_nfd_to_nfc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        nfc = "caf\u00e9"
        nfd = "cafe\u0301"
        assert nfc != nfd
        assert function_extras.normalize_callee(nfd) == nfc
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            first = function_extras.add_edge(conn, function_id=ids["functions"][0], callee=nfd)
            second = function_extras.add_edge(
                conn, function_id=ids["functions"][0], callee=nfc, note="same"
            )
            assert first["id"] == second["id"]
            assert second["callee"] == nfc

    def test_a_missing_edge_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(function_extras.UnknownEdgeError),
        ):
            function_extras.delete_edge(conn, ids["functions"][0], edge_id=99)

    def test_an_edge_of_another_function_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            row = function_extras.add_edge(conn, function_id=ids["functions"][1], callee="f")
            with pytest.raises(function_extras.UnknownEdgeError):
                function_extras.delete_edge(conn, ids["functions"][0], edge_id=int(row["id"]))

    def test_the_journaled_write_reverts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                function_extras.journaled_add_edge(
                    conn, log, function_id=ids["functions"][0], callee="f"
                )
            assert len(function_extras.list_edges(conn, ids["functions"][0])) == 1
            assert journal.revert_action(conn, action)["reverted"] > 0
            assert function_extras.list_edges(conn, ids["functions"][0]) == []


class TestCanonicalNames:
    def test_a_predicted_name_wins_over_a_rename(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.rename_function(
                conn, ids["functions"][0], new_name="renamed", actor="me", source="manual"
            )
            store.set_ai_artifact(
                conn,
                ids["functions"][0],
                "predicted-name",
                {"name": "predicted", "confidence": 0.9},
                "test-llm",
            )
            plan = function_extras.canonical_names(conn, [ids["functions"][0]])
        assert plan["planned"][0]["to"] == "predicted"
        assert plan["planned"][0]["source"] == "predicted-name"

    def test_a_function_with_no_candidate_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            plan = function_extras.canonical_names(conn, [ids["functions"][0], 999])
        assert plan["planned"] == []
        assert [entry["reason"] for entry in plan["skipped"]] == [
            "no canonical candidate recorded",
            "not found",
        ]

    def test_a_name_already_canonical_reports_no_change(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.rename_function(
                conn, ids["functions"][0], new_name="renamed", actor="me", source="manual"
            )
            store.rename_function(
                conn, ids["functions"][0], new_name="sub_0", actor="me", source="manual"
            )
            plan = function_extras.canonical_names(conn, [ids["functions"][0]])
        assert plan["planned"][0]["changed"] is False


class TestBatchReads:
    def test_callees_callers_carries_the_derived_and_declared_halves(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            function_extras.add_edge(conn, function_id=ids["functions"][0], callee="hook")
            payload = function_extras.callers_and_callees(conn, [ids["functions"][0], 999])
        first, second = payload["functions"]
        assert [entry["name"] for entry in first["callees"]] == ["sub_1", "CreateFileA"]
        assert [entry["name"] for entry in first["declared"]] == ["hook"]
        assert first["has_decompilation"] is True
        assert second["found"] is False
        assert payload["count"] == 2

    def test_a_caller_is_a_function_whose_text_mentions_the_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = function_extras.callers_and_callees(conn, [ids["functions"][1]])
        assert [entry["name"] for entry in payload["functions"][0]["callers"]] == ["sub_0"]

    def test_the_match_read_reports_recorded_rows_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.record_match(
                conn,
                function_id=ids["functions"][0],
                candidate_function_id=ids["functions"][1],
                similarity=0.91,
                confidence=0.8,
            )
            payload = function_extras.match_rows(conn, [ids["functions"][0], 999])
        assert payload["functions"][0]["count"] == 1
        assert payload["functions"][0]["matches"][0]["band"]
        assert payload["functions"][1]["found"] is False

    def test_a_function_of_a_hidden_binary_reads_as_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            owner, _token = auth.add_user(conn, name="owner", role="admin")
            team_id = int(auth.create_team(conn, name="blue")["id"])
            auth.add_member(conn, team_id, int(owner["id"]))
            _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
            ana = auth.find_user(conn, "ana")
            assert ana is not None
            auth.add_member(conn, team_id, int(ana["id"]))
            _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
            store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)
            member = auth.find_user(conn, "ana")
            stranger = auth.find_user(conn, "bob")
            assert member is not None and stranger is not None
            function_id = ids["functions"][0]
            assert (
                function_extras.match_rows(conn, [function_id], visible_to=member)["functions"][0][
                    "found"
                ]
                is True
            )
            assert (
                function_extras.match_rows(conn, [function_id], visible_to=stranger)["functions"][
                    0
                ]["found"]
                is False
            )
            assert (
                function_extras.callers_and_callees(conn, [function_id], visible_to=stranger)[
                    "functions"
                ][0]["found"]
                is False
            )

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, headers, body = wsgi_request(
            "GET",
            f"/api/functions/matches?ids={ids['functions'][0]}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("200"), body
        assert json_body(body, headers)["functions"][0]["found"] is False
        stranger_status, headers, body = wsgi_request(
            "GET",
            f"/api/functions/{ids['functions'][0]}/callees",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "function not found"
        member_status, headers, body = wsgi_request(
            "GET",
            f"/api/functions/matches?ids={ids['functions'][0]}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), body
        assert json_body(body, headers)["functions"][0]["found"] is True


class TestRoutes:
    def test_the_indirect_call_site_route(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['functions'][0]}/indirect-call-sites"
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["count"] == 3
        assert payload["has_disassembly"] is True

        empty, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['functions'][1]}/indirect-call-sites"
        )
        assert empty.startswith("200")
        assert json_body(body, headers)["has_disassembly"] is False

        missing, _, _ = wsgi_request("GET", "/api/functions/999/indirect-call-sites")
        assert missing.startswith("404")

    def test_the_capabilities_route(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['functions'][0]}/capabilities"
        )
        assert status.startswith("200"), body
        assert json_body(body, headers)["inputs"]["imports"] == 1
        missing, _, _ = wsgi_request("GET", "/api/functions/999/capabilities")
        assert missing.startswith("404")

    def test_the_function_string_routes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        url = f"/api/functions/{ids['functions'][0]}/strings"
        status, headers, body = wsgi_request(
            "POST", url, body=json.dumps({"value": "note", "note": "why"})
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["journal_action"]

        status, headers, body = wsgi_request("GET", url)
        payload = json_body(body, headers)
        assert payload["counts"]["analyst"] == 1
        assert "/etc/passwd" in [entry["value"] for entry in payload["derived"]]

        removed, headers, body = wsgi_request("DELETE", f"{url}/{payload['analyst'][0]['id']}")
        assert removed.startswith("200")
        assert json_body(body, headers)["journal_action"]

        gone, _, _ = wsgi_request("DELETE", f"{url}/999")
        assert gone.startswith("404")

        bad, headers, body = wsgi_request("POST", url, body=json.dumps({"value": ""}))
        assert bad.startswith("400")
        assert json_body(body, headers)["error"] == "invalid string"

    def test_the_callee_routes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        url = f"/api/functions/{ids['functions'][0]}/callees"
        status, headers, body = wsgi_request(
            "POST", url, body=json.dumps({"callee": "dispatch", "kind": "indirect"})
        )
        assert status.startswith("200"), body
        edge_id = json_body(body, headers)["id"]

        status, headers, body = wsgi_request("GET", url)
        payload = json_body(body, headers)
        assert payload["declared_count"] == 1
        assert payload["count"] == 2

        removed, _, _ = wsgi_request("DELETE", f"{url}/{edge_id}")
        assert removed.startswith("200")
        gone, _, _ = wsgi_request("DELETE", f"{url}/999")
        assert gone.startswith("404")

        bad, headers, body = wsgi_request("POST", url, body=json.dumps({"callee": ""}))
        assert bad.startswith("400")
        assert json_body(body, headers)["error"] == "invalid edge"

    def test_the_analysis_string_routes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        url = f"/api/analyses/{ids['analysis']}/strings"
        created, headers, body = wsgi_request("POST", url, body=json.dumps({"value": "a"}))
        assert created.startswith("200"), body
        assert json_body(body, headers)["journal_action"]

        status, headers, body = wsgi_request("GET", url)
        assert json_body(body, headers)["count"] == 1

        replaced, headers, body = wsgi_request("PUT", url, body=json.dumps({"strings": ["b", "c"]}))
        assert replaced.startswith("200"), body
        payload = json_body(body, headers)
        assert [entry["value"] for entry in payload["strings"]] == ["b", "c"]
        assert payload["removed"] == 1

        bad, headers, body = wsgi_request("PUT", url, body=json.dumps({"strings": "x"}))
        assert bad.startswith("400")
        assert json_body(body, headers)["error"] == "invalid string"

        missing, _, _ = wsgi_request("GET", "/api/analyses/999/strings")
        assert missing.startswith("404")

    def test_the_batch_routes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        query = f"ids={ids['functions'][0]},{ids['functions'][1]}"
        status, headers, body = wsgi_request("GET", f"/api/functions/callees-callers?{query}")
        assert status.startswith("200"), body
        assert json_body(body, headers)["count"] == 2

        status, headers, body = wsgi_request("GET", f"/api/functions/matches?{query}")
        assert status.startswith("200"), body
        assert json_body(body, headers)["functions"][0]["found"] is True

        status, headers, body = wsgi_request(
            "POST",
            "/api/functions/matches",
            body=json.dumps({"function_ids": [ids["functions"][0]]}),
        )
        assert status.startswith("200"), body
        assert json_body(body, headers)["count"] == 1

        for url in ("/api/functions/callees-callers?ids=", "/api/functions/matches?ids=x"):
            bad, _, _ = wsgi_request("GET", url)
            assert bad.startswith("400"), url

    def test_the_canonical_names_route_plans_applies_and_journals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.set_ai_artifact(
                conn,
                ids["functions"][0],
                "predicted-name",
                {"name": "handle_open", "confidence": 0.9},
                "test-llm",
            )
        planned, headers, body = wsgi_request(
            "POST",
            "/api/functions/canonical-names",
            body=json.dumps({"function_ids": [ids["functions"][0]], "apply": False}),
        )
        assert planned.startswith("200"), body
        assert json_body(body, headers)["dry_run"] is True

        status, headers, body = wsgi_request(
            "POST",
            "/api/functions/canonical-names",
            body=json.dumps({"function_ids": [ids["functions"][0]]}),
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["applied_count"] == 1
        assert payload["journal_action"]

        bad, headers, body = wsgi_request(
            "POST",
            "/api/functions/canonical-names",
            body=json.dumps({"function_ids": [ids["functions"][0]], "apply": "yes"}),
        )
        assert bad.startswith("400")
        assert json_body(body, headers)["error"] == "invalid apply"

    def test_a_hidden_function_plans_as_not_found_and_applies_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.set_ai_artifact(
                conn,
                ids["functions"][0],
                "predicted-name",
                {"name": "handle_open", "confidence": 0.9},
                "test-llm",
            )
            owner, _token = auth.add_user(conn, name="owner", role="admin")
            team_id = int(auth.create_team(conn, name="blue")["id"])
            auth.add_member(conn, team_id, int(owner["id"]))
            _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
            ana = auth.find_user(conn, "ana")
            assert ana is not None
            auth.add_member(conn, team_id, int(ana["id"]))
            _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
            stranger = auth.find_user(conn, "bob")
            assert stranger is not None
            store.set_binary_scope(conn, ids["binary"], visibility="team", owner_team_id=team_id)
            hidden = function_extras.canonical_names(
                conn, [ids["functions"][0]], visible_to=stranger
            )
            assert hidden["planned"] == []
            assert [entry["reason"] for entry in hidden["skipped"]] == ["not found"]

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, headers, body = wsgi_request(
            "POST",
            "/api/functions/canonical-names",
            body=json.dumps({"function_ids": [ids["functions"][0]]}),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("200"), body
        assert json_body(body, headers)["applied_count"] == 0
        member_status, headers, body = wsgi_request(
            "POST",
            "/api/functions/canonical-names",
            body=json.dumps({"function_ids": [ids["functions"][0]]}),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), body
        assert json_body(body, headers)["applied_count"] == 1


class TestCli:
    def test_the_read_commands(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        function_id = str(ids["functions"][0])
        indirect = runner.invoke(cli.app, ["indirect-calls", function_id, "--json"])
        assert indirect.exit_code == 0, indirect.output
        assert json.loads(indirect.output)["count"] == 3

        sites = runner.invoke(cli.app, ["indirect-calls", function_id])
        assert sites.exit_code == 0, sites.output
        assert "qword" in sites.output

        capabilities = runner.invoke(cli.app, ["function-capabilities", function_id, "--json"])
        assert capabilities.exit_code == 0, capabilities.output
        assert json.loads(capabilities.output)["function_id"] == ids["functions"][0]

        plain = runner.invoke(cli.app, ["function-capabilities", function_id])
        assert plain.exit_code == 0, plain.output

        strings = runner.invoke(cli.app, ["function-strings", function_id])
        assert strings.exit_code == 0, strings.output
        assert "/etc/passwd" in strings.output

        callers = runner.invoke(
            cli.app,
            ["callees-callers", function_id, str(ids["functions"][1]), "--json"],
        )
        assert callers.exit_code == 0, callers.output
        assert json.loads(callers.output)["count"] == 2

        matches = runner.invoke(cli.app, ["function-matches", function_id, "--json"])
        assert matches.exit_code == 0, matches.output
        assert json.loads(matches.output)["count"] == 1

    def test_the_analysis_string_commands(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        analysis_id = str(ids["analysis"])
        empty = runner.invoke(cli.app, ["analysis-strings", analysis_id])
        assert empty.exit_code == 0, empty.output
        assert "No strings recorded" in empty.output

        written = runner.invoke(
            cli.app, ["analysis-strings-set", analysis_id, "one", "two", "--json"]
        )
        assert written.exit_code == 0, written.output
        assert json.loads(written.output)["journal_action"]

        listed = runner.invoke(cli.app, ["analysis-strings", analysis_id, "--json"])
        assert [entry["value"] for entry in json.loads(listed.output)["strings"]] == [
            "one",
            "two",
        ]

        human = runner.invoke(cli.app, ["analysis-strings-set", analysis_id, "three"])
        assert human.exit_code == 0, human.output
        assert "3 string(s)" in human.output or "1 string(s)" in human.output

    def test_the_string_and_edge_commands(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        function_id = str(ids["functions"][0])
        added = runner.invoke(
            cli.app, ["user-string-add", function_id, "hello", "--note", "why", "--json"]
        )
        assert added.exit_code == 0, added.output
        string_id = json.loads(added.output)["id"]

        removed = runner.invoke(cli.app, ["user-string-rm", function_id, str(string_id), "--json"])
        assert removed.exit_code == 0, removed.output
        assert json.loads(removed.output)["journal_action"]

        edge = runner.invoke(
            cli.app, ["callee-add", function_id, "dispatch", "--kind", "indirect", "--json"]
        )
        assert edge.exit_code == 0, edge.output
        edge_id = json.loads(edge.output)["id"]

        human = runner.invoke(cli.app, ["callee-rm", function_id, str(edge_id)])
        assert human.exit_code == 0, human.output
        assert "Removed" in human.output

        bad = runner.invoke(cli.app, ["user-string-add", function_id, "", "--json"])
        assert bad.exit_code == 1, bad.output
        foreign = runner.invoke(cli.app, ["callee-add", "999", "x"])
        assert foreign.exit_code == 1

    def test_the_canonical_name_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        function_id = str(ids["functions"][0])
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.set_ai_artifact(
                conn,
                ids["functions"][0],
                "predicted-name",
                {"name": "handle_open", "confidence": 0.9},
                "test-llm",
            )
        planned = runner.invoke(cli.app, ["canonical-names", function_id, "--dry-run"])
        assert planned.exit_code == 0, planned.output
        assert "skipped" in planned.output or "->" in planned.output

        applied = runner.invoke(cli.app, ["canonical-names", function_id, "--json"])
        assert applied.exit_code == 0, applied.output
        assert json.loads(applied.output)["applied_count"] == 1

    def test_a_batch_over_the_limit_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        argv = ["callees-callers"] + [str(ids["functions"][0])] * (
            function_extras.MAX_FUNCTIONS_PER_QUERY + 1
        )
        result = runner.invoke(cli.app, argv)
        assert result.exit_code == 1
        assert "at most" in result.output

    def test_the_commands_fail_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        for argv in (
            ["indirect-calls", "1"],
            ["function-capabilities", "1"],
            ["function-strings", "1"],
            ["user-string-add", "1", "x"],
            ["user-string-rm", "1", "2"],
            ["analysis-strings", "1"],
            ["analysis-strings-set", "1", "x"],
            ["callee-add", "1", "x"],
            ["callee-rm", "1", "2"],
            ["callees-callers", "1"],
            ["canonical-names", "1"],
            ["function-matches", "1"],
        ):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no reportal database" in result.output


class TestMcp:
    def test_the_read_tools(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        function_id = ids["functions"][0]
        sites, failed = mcp_server.call_tool(
            "get_indirect_call_sites", {"function_id": function_id}
        )
        assert not failed, sites
        assert sites["count"] == 3

        capabilities, failed = mcp_server.call_tool(
            "get_function_capabilities", {"function_id": function_id}
        )
        assert not failed, capabilities
        assert capabilities["inputs"]["imports"] == 1

        strings, failed = mcp_server.call_tool("get_function_strings", {"function_id": function_id})
        assert not failed, strings
        assert strings["counts"]["analyst"] == 0

        edges, failed = mcp_server.call_tool("list_function_edges", {"function_id": function_id})
        assert not failed, edges
        assert edges["count"] == 0

        callers, failed = mcp_server.call_tool(
            "get_functions_callees_callers", {"function_ids": [function_id]}
        )
        assert not failed, callers
        assert callers["count"] == 1

        matches, failed = mcp_server.call_tool(
            "get_function_matches", {"function_ids": [function_id]}
        )
        assert not failed, matches
        assert matches["functions"][0]["found"] is True

        analysis, failed = mcp_server.call_tool(
            "list_analysis_strings", {"analysis_id": ids["analysis"]}
        )
        assert not failed, analysis
        assert analysis["count"] == 0

    def test_a_bad_batch_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed(tmp_path, monkeypatch)
        bad_batches: tuple[dict[str, Any], ...] = (
            {"function_ids": []},
            {"function_ids": ["x"]},
        )
        for arguments in bad_batches:
            payload, failed = mcp_server.call_tool("get_function_matches", arguments)
            assert failed, arguments
            assert payload["error"] == "invalid params"

    def test_the_write_tools(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        function_id = ids["functions"][0]
        added, failed = mcp_server.call_tool(
            "add_function_string", {"function_id": function_id, "value": "hello", "note": "why"}
        )
        assert not failed, added
        assert added["journal_action"]

        replaced, failed = mcp_server.call_tool(
            "replace_analysis_strings", {"analysis_id": ids["analysis"], "strings": ["a", "b"]}
        )
        assert not failed, replaced
        assert len(replaced["strings"]) == 2

        edge, failed = mcp_server.call_tool(
            "add_function_edge", {"function_id": function_id, "callee": "dispatch"}
        )
        assert not failed, edge
        edge_id = edge["id"]

        listed, failed = mcp_server.call_tool("list_function_edges", {"function_id": function_id})
        assert not failed, listed
        assert listed["count"] == 1

        removed, failed = mcp_server.call_tool(
            "delete_function_edge", {"function_id": function_id, "edge_id": edge_id}
        )
        assert not failed, removed
        assert removed["journal_action"]

        deleted, failed = mcp_server.call_tool(
            "delete_function_string", {"function_id": function_id, "string_id": added["id"]}
        )
        assert not failed, deleted
        assert deleted["journal_action"]

        missing, failed = mcp_server.call_tool(
            "delete_function_string", {"function_id": function_id, "string_id": added["id"]}
        )
        assert failed
        assert missing["error"] == "string not found"

        bad, failed = mcp_server.call_tool(
            "add_function_edge", {"function_id": function_id, "callee": " "}
        )
        assert failed
        assert bad["error"] == "invalid params"

        unknown, failed = mcp_server.call_tool("get_function_capabilities", {"function_id": 999})
        assert failed
        assert unknown["error"] == "edge not found"

    def test_the_canonical_name_tool(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.set_ai_artifact(
                conn,
                ids["functions"][0],
                "predicted-name",
                {"name": "handle_open", "confidence": 0.9},
                "test-llm",
            )
        planned, failed = mcp_server.call_tool(
            "canonicalize_function_names",
            {"function_ids": [ids["functions"][0]], "apply": False},
        )
        assert not failed, planned
        assert planned["dry_run"] is True

        applied, failed = mcp_server.call_tool(
            "canonicalize_function_names", {"function_ids": [ids["functions"][0]]}
        )
        assert not failed, applied
        assert applied["applied_count"] == 1
        assert applied["journal_action"]

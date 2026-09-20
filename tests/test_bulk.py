"""Tests for the bulk data-type and signature surfaces.

The module functions are asserted directly (they are the shared write path) and
the routes, CLI and MCP tools are driven over the same store, so the three
surfaces cannot drift from the report the module produces.
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

from reportal import auth, cli, data_types, journal, mcp_server, signatures, store, surface
from reportal._paths import DB_ENV

runner = CliRunner()

STRUCT = """typedef struct {
    int fd;
    char *path;
} file_handle;"""
STRUCT_EDITED = """typedef struct {
    int fd;
    char *path;
    int flags;
} file_handle;"""


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, functions: int = 3) -> dict[str, Any]:
    """A portal DB with one binary, one analysis and named functions."""
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
            for index in range(functions)
        ]
    return {"binary": binary_id, "analysis": analysis_id, "functions": ids, "db": db}


def _signature(conn: sqlite3.Connection, function_id: int) -> None:
    """Give one function a signature with one parameter."""
    signatures.ensure_signature(conn, function_id)
    signatures.add_parameter(conn, function_id, type_text="int", name="count")
    signatures.set_return_type(conn, function_id, return_type="char *")
    signatures.set_calling_convention(conn, function_id, calling_convention="stdcall")


class TestSignatureBatch:
    def test_the_order_is_the_callers_and_a_missing_one_is_null(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][1])
            rows = signatures.signatures_for(conn, [ids["functions"][1], ids["functions"][0]])
        assert [row["function_id"] for row in rows] == [ids["functions"][1], ids["functions"][0]]
        assert rows[0]["signature"] is not None
        assert rows[0]["signature"]["return_type"] == "char *"
        assert rows[1]["signature"] is None

    def test_an_unknown_function_is_reported_not_omitted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            rows = signatures.signatures_for(conn, [999])
        assert rows == [{"function_id": 999, "found": False, "signature": None}]


class TestSignatureCopy:
    def test_it_copies_the_return_type_convention_and_parameters(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
            report = signatures.copy_signature(
                conn, source_id=ids["functions"][0], targets=[ids["functions"][1]]
            )
            copied = signatures.get_signature(conn, ids["functions"][1])
        assert report["applied"] == [ids["functions"][1]]
        assert copied is not None
        assert copied["return_type"] == "char *"
        assert copied["calling_convention"] == "stdcall"
        assert [parameter["name"] for parameter in copied["parameters"]] == ["count"]

    def test_it_replaces_an_existing_signature_and_skips_the_rest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
            signatures.ensure_signature(conn, ids["functions"][1])
            signatures.set_return_type(conn, ids["functions"][1], return_type="void")
            report = signatures.copy_signature(
                conn,
                source_id=ids["functions"][0],
                targets=[ids["functions"][0], ids["functions"][1], 999],
            )
            target = signatures.get_signature(conn, ids["functions"][1])
        assert report["applied"] == [ids["functions"][1]]
        assert [entry["reason"] for entry in report["skipped"]] == [
            "the source function",
            "not found",
        ]
        assert target is not None
        assert target["return_type"] == "char *"
        assert len(target["parameters"]) == 1

    def test_a_source_without_a_signature_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(signatures.UnknownSignatureError),
        ):
            signatures.copy_signature(
                conn, source_id=ids["functions"][0], targets=[ids["functions"][1]]
            )


class TestTypeDefinitions:
    def test_a_definition_is_created_then_updated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            created = data_types.import_definitions(
                conn, binary_id=ids["binary"], definitions=[STRUCT]
            )
            updated = data_types.import_definitions(
                conn, binary_id=ids["binary"], definitions=[STRUCT_EDITED]
            )
            stored = store.find_data_type_by_name(conn, ids["binary"], "file_handle")
        assert created["created"] == 1
        assert created["updated"] == 0
        assert updated["created"] == 0
        assert updated["updated"] == 1
        assert stored is not None
        assert len(stored["members"]) == 3

    def test_an_unusable_definition_is_skipped_with_its_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = data_types.import_definitions(
                conn, binary_id=ids["binary"], definitions=["int x;", 42]
            )
        assert report["created"] == 0
        assert report["skipped"] == 2
        assert all(entry["reason"] for entry in report["skipped_types"])

    def test_update_only_refuses_a_new_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = data_types.import_definitions(
                conn, binary_id=ids["binary"], definitions=[STRUCT], create=False
            )
            assert report["created"] == 0
            assert report["skipped"] == 1
            assert "no stored type" in report["skipped_types"][0]["reason"]
            assert store.find_data_type_by_name(conn, ids["binary"], "file_handle") is None

    def test_a_scan_shaped_entry_is_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            report = data_types.import_definitions(
                conn,
                binary_id=ids["binary"],
                definitions=[{"name": "file_handle", "definition": STRUCT}],
            )
        assert report["created"] == 1


class TestDefinitionSplitting:
    def test_a_header_splits_on_top_level_semicolons(self) -> None:
        text = (
            "#include <x>\n// a comment\n"
            + STRUCT
            + "\n"
            + STRUCT_EDITED.replace("file_handle", "other_handle")
        )
        declarations = data_types.split_definitions(text)
        assert len(declarations) == 2
        assert declarations[0].startswith("typedef struct")
        assert declarations[0].rstrip().endswith("file_handle;")

    def test_a_block_comment_and_a_trailing_fragment_are_dropped(self) -> None:
        assert data_types.split_definitions("/* nothing here */\nint x") == []

    def test_an_enum_splits_as_one_declaration(self) -> None:
        declarations = data_types.split_definitions(
            "typedef enum {\n    RED = 1,\n    BLUE = 2\n} colour;\n"
        )
        assert len(declarations) == 1
        assert "BLUE" in declarations[0]


class TestBulkWritePath:
    def test_a_create_is_journaled_and_a_revert_removes_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                report = surface.bulk_data_type_definitions(
                    conn, log, binary_id=ids["binary"], definitions=[STRUCT]
                )
            assert report["created"] == 1
            assert store.find_data_type_by_name(conn, ids["binary"], "file_handle") is not None
            assert journal.revert_action(conn, action)["reverted"] > 0
            assert store.find_data_type_by_name(conn, ids["binary"], "file_handle") is None

    def test_an_update_is_journaled_and_a_revert_restores_the_previous_members(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            data_types.import_definitions(conn, binary_id=ids["binary"], definitions=[STRUCT])
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                report = surface.bulk_data_type_definitions(
                    conn, log, binary_id=ids["binary"], definitions=[STRUCT_EDITED]
                )
            assert report["updated"] == 1
            edited = store.find_data_type_by_name(conn, ids["binary"], "file_handle")
            assert edited is not None
            assert len(edited["members"]) == 3
            assert journal.revert_action(conn, action)["reverted"] > 0
            restored = store.find_data_type_by_name(conn, ids["binary"], "file_handle")
        assert restored is not None
        assert len(restored["members"]) == 2


class TestRoutes:
    def test_the_batch_signature_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
        query = f"{ids['functions'][0]},{ids['functions'][1]},999"
        status, headers, body = wsgi_request("GET", f"/api/functions/signatures?ids={query}")
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["count"] == 3
        assert payload["found"] == 2
        assert payload["signatures"][1]["signature"] is None
        assert payload["signatures"][2]["found"] is False

    def test_a_function_of_a_hidden_binary_reads_as_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
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
            visible = signatures.signatures_for(conn, ids["functions"], visible_to=member)
            assert [row["found"] for row in visible] == [True, True, True]
            hidden = signatures.signatures_for(conn, ids["functions"], visible_to=stranger)
            assert [row["found"] for row in hidden] == [False, False, False]

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        query = f"{ids['functions'][0]},{ids['functions'][1]}"
        stranger_status, headers, body = wsgi_request(
            "GET",
            f"/api/functions/signatures?ids={query}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["found"] == 0
        assert all(row["found"] is False for row in payload["signatures"])
        member_status, headers, body = wsgi_request(
            "GET",
            f"/api/functions/signatures?ids={query}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), body
        assert json_body(body, headers)["found"] == 2

    def test_a_bad_id_list_is_400(self) -> None:
        for query in ("ids=abc", "ids=", "ids=1,x", "ids=" + ",".join(str(n) for n in range(300))):
            status, headers, body = wsgi_request("GET", f"/api/functions/signatures?{query}")
            assert status.startswith("400"), query
            assert json_body(body, headers)["error"] == "invalid ids"

    def test_a_missing_id_parameter_is_400(self) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/signatures")
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid ids"
        assert "comma-separated" in payload["detail"]

    def test_the_copy_route_applies_and_journals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
        status, headers, body = wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/signatures/copy",
            body=json.dumps(
                {
                    "source_function_id": ids["functions"][0],
                    "targets": [ids["functions"][1], ids["functions"][2]],
                }
            ),
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["count"] == 2
        assert payload["journal_action"]

    def test_the_copy_route_refuses_a_foreign_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            other_analysis = store.create_analysis(conn, binary_id=ids["binary"], engine="manual")
            other = store.add_function(conn, analysis_id=other_analysis, va=0x9000, name="other")
        status, headers, body = wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/signatures/copy",
            body=json.dumps({"source_function_id": other, "targets": [ids["functions"][0]]}),
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_the_copy_route_validates_its_body(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        cases = (
            ({"source_function_id": "x", "targets": [1]}, "invalid source"),
            ({"source_function_id": 1}, "invalid targets"),
            ({"source_function_id": 1, "targets": []}, "invalid targets"),
            ({"source_function_id": 1, "targets": ["x"]}, "invalid targets"),
        )
        for body, error in cases:
            status, headers, response = wsgi_request(
                "POST",
                f"/api/analyses/{ids['analysis']}/signatures/copy",
                body=json.dumps(body),
            )
            assert status.startswith("400"), body
            assert json_body(response, headers)["error"] == error, body
        status, headers, response = wsgi_request(
            "POST",
            "/api/analyses/999/signatures/copy",
            body=json.dumps({"source_function_id": 1, "targets": [2]}),
        )
        assert status.startswith("404")
        assert json_body(response, headers)["error"] == "analysis not found"

    def test_the_bulk_create_route(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/data-types",
            body=json.dumps({"types": [STRUCT, "int x;"]}),
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["created"] == 1
        assert payload["skipped"] == 1
        assert payload["journal_action"]

    def test_the_bulk_update_route_does_not_create(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "PUT",
            f"/api/analyses/{ids['analysis']}/data-types",
            body=json.dumps({"types": [STRUCT]}),
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["created"] == 0
        assert payload["skipped"] == 1

        wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/data-types",
            body=json.dumps({"types": [STRUCT]}),
        )
        status, headers, body = wsgi_request(
            "PUT",
            f"/api/analyses/{ids['analysis']}/data-types",
            body=json.dumps({"types": [STRUCT_EDITED]}),
        )
        assert json_body(body, headers)["updated"] == 1

    def test_a_header_string_is_split_server_side(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        header = STRUCT + "\n" + STRUCT_EDITED.replace("file_handle", "other_handle")
        status, headers, body = wsgi_request(
            "POST",
            f"/api/analyses/{ids['analysis']}/data-types",
            body=json.dumps({"types": header}),
        )
        assert status.startswith("200"), body
        assert json_body(body, headers)["created"] == 2

    def test_a_bad_definition_list_is_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        bodies: list[dict[str, Any]] = [
            {},
            {"types": []},
            {"types": "x"},
            {"types": [1]},
            {"types": [{}] * 200},
        ]
        for body in bodies:
            for method in ("POST", "PUT"):
                status, headers, response = wsgi_request(
                    method,
                    f"/api/analyses/{ids['analysis']}/data-types",
                    body=json.dumps(body),
                )
                assert status.startswith("400"), (method, body)
                assert json_body(response, headers)["error"] == "invalid types"
        status, headers, response = wsgi_request(
            "POST", "/api/analyses/999/data-types", body=json.dumps({"types": [STRUCT]})
        )
        assert status.startswith("404")

    def test_the_type_functions_route(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            data_types.import_definitions(conn, binary_id=ids["binary"], definitions=[STRUCT])
            stored = store.find_data_type_by_name(conn, ids["binary"], "file_handle")
        assert stored is not None
        status, headers, body = wsgi_request(
            "GET", f"/api/analyses/{ids['analysis']}/data-types/{stored['id']}/functions"
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["data_type_id"] == stored["id"]
        assert "used_by_functions" in payload

    def test_the_type_functions_route_refuses_a_foreign_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            other_binary = store.add_binary(conn, sha256="bb" * 32, name="other.exe")
            other_type = store.add_data_type(
                conn, binary_id=other_binary, name="thing", size=4, members=[]
            )
        status, headers, body = wsgi_request(
            "GET", f"/api/analyses/{ids['analysis']}/data-types/{other_type}/functions"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "data type not found"


class TestCli:
    def test_the_batch_read(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
        result = runner.invoke(
            cli.app,
            ["signatures-batch", str(ids["functions"][0]), str(ids["functions"][1]), "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["signatures"][0]["signature"]["return_type"] == "char *"
        assert payload["signatures"][1]["signature"] is None

        human = runner.invoke(cli.app, ["signatures-batch", str(ids["functions"][0])])
        assert human.exit_code == 0, human.output
        assert "char *" in human.output

    def test_the_copy_command(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
        result = runner.invoke(
            cli.app,
            [
                "signature-copy",
                str(ids["analysis"]),
                str(ids["functions"][0]),
                str(ids["functions"][1]),
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["count"] == 1

        human = runner.invoke(
            cli.app,
            [
                "signature-copy",
                str(ids["analysis"]),
                str(ids["functions"][0]),
                str(ids["functions"][2]),
            ],
        )
        assert human.exit_code == 0, human.output
        assert "copied the signature" in human.output

    def test_the_copy_command_fails_for_a_foreign_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["signature-copy", str(ids["analysis"]), "999", str(ids["functions"][0])]
        )
        assert result.exit_code == 1
        assert "is not in analysis" in result.output
        result = runner.invoke(
            cli.app, ["signature-copy", str(ids["analysis"]), str(ids["functions"][0]), "999"]
        )
        assert result.exit_code == 1

    def test_the_import_command(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["data-types-import", str(ids["analysis"]), "--definition", STRUCT, "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["created"] == 1

        again = runner.invoke(
            cli.app,
            [
                "data-types-import",
                str(ids["analysis"]),
                "--definition",
                STRUCT,
                "--update-only",
            ],
        )
        assert again.exit_code == 0, again.output
        assert "1 updated" in again.output

    def test_the_import_reads_a_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        path = tmp_path / "types.h"
        path.write_text(f"# a comment\n{STRUCT}\n\n", encoding="utf-8")
        result = runner.invoke(
            cli.app, ["data-types-import", str(ids["analysis"]), "--file", str(path), "--json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["created"] == 1

    def test_the_import_needs_a_declaration(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["data-types-import", str(ids["analysis"])])
        assert result.exit_code == 1
        assert "at least one --definition" in result.output
        missing = runner.invoke(
            cli.app,
            ["data-types-import", str(ids["analysis"]), "--file", str(tmp_path / "nope.h")],
        )
        assert missing.exit_code == 1
        assert "cannot read" in missing.output

    def test_the_type_functions_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            data_types.import_definitions(conn, binary_id=ids["binary"], definitions=[STRUCT])
            stored = store.find_data_type_by_name(conn, ids["binary"], "file_handle")
        assert stored is not None
        result = runner.invoke(
            cli.app,
            ["data-type-functions", str(ids["analysis"]), str(stored["id"]), "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["data_type_id"] == stored["id"]

        human = runner.invoke(
            cli.app, ["data-type-functions", str(ids["analysis"]), str(stored["id"])]
        )
        assert human.exit_code == 0, human.output

        foreign = runner.invoke(cli.app, ["data-type-functions", str(ids["analysis"]), "999"])
        assert foreign.exit_code == 1

    def test_the_commands_fail_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        for argv in (
            ["signatures-batch", "1"],
            ["signature-copy", "1", "2", "3"],
            ["data-types-import", "1", "--definition", STRUCT],
            ["data-type-functions", "1", "2"],
        ):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no reportal database" in result.output


class TestMcp:
    def test_the_batch_read_tool(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
        payload, failed = mcp_server.call_tool(
            "get_signature_batch", {"function_ids": [ids["functions"][0], ids["functions"][1]]}
        )
        assert not failed, payload
        assert payload["signatures"][0]["signature"]["return_type"] == "char *"

        bad, failed = mcp_server.call_tool("get_signature_batch", {"function_ids": []})
        assert failed
        assert bad["error"] == "invalid params"

    def test_the_copy_tool(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
        payload, failed = mcp_server.call_tool(
            "copy_signature",
            {"source_function_id": ids["functions"][0], "targets": [ids["functions"][1]]},
        )
        assert not failed, payload
        assert payload["count"] == 1
        assert payload["journal_action"]

        bad, failed = mcp_server.call_tool(
            "copy_signature", {"source_function_id": ids["functions"][0], "targets": []}
        )
        assert failed
        assert bad["error"] == "invalid params"

        missing, failed = mcp_server.call_tool(
            "copy_signature", {"source_function_id": 999, "targets": [ids["functions"][0]]}
        )
        assert failed
        assert missing["error"] == "function not found"

    def test_the_foreign_target_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            _signature(conn, ids["functions"][0])
            other_analysis = store.create_analysis(conn, binary_id=ids["binary"], engine="manual")
            other = store.add_function(conn, analysis_id=other_analysis, va=0x9000, name="other")
        payload, failed = mcp_server.call_tool(
            "copy_signature",
            {"source_function_id": ids["functions"][0], "targets": [other]},
        )
        assert failed
        assert payload["error"] == "function not found"

    def test_the_import_tool(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        payload, failed = mcp_server.call_tool(
            "import_type_definitions",
            {"analysis_id": ids["analysis"], "definitions": [STRUCT]},
        )
        assert not failed, payload
        assert payload["created"] == 1
        assert payload["journal_action"]

        update_only, failed = mcp_server.call_tool(
            "import_type_definitions",
            {"analysis_id": ids["analysis"], "definitions": [STRUCT_EDITED], "update_only": True},
        )
        assert not failed, update_only
        assert update_only["updated"] == 1

        bad, failed = mcp_server.call_tool(
            "import_type_definitions", {"analysis_id": ids["analysis"], "definitions": []}
        )
        assert failed
        assert bad["error"] == "invalid params"

        missing, failed = mcp_server.call_tool(
            "import_type_definitions", {"analysis_id": 999, "definitions": [STRUCT]}
        )
        assert failed
        assert missing["error"] == "analysis not found"

    def test_the_type_functions_tool(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            data_types.import_definitions(conn, binary_id=ids["binary"], definitions=[STRUCT])
            stored = store.find_data_type_by_name(conn, ids["binary"], "file_handle")
        assert stored is not None
        payload, failed = mcp_server.call_tool(
            "get_data_type_functions",
            {"analysis_id": ids["analysis"], "data_type_id": stored["id"]},
        )
        assert not failed, payload
        assert payload["data_type_id"] == stored["id"]

        missing, failed = mcp_server.call_tool(
            "get_data_type_functions", {"analysis_id": ids["analysis"], "data_type_id": 999}
        )
        assert failed
        assert missing["error"] == "data type not found"

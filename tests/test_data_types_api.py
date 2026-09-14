"""Tests for the data-type JSON routes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, data_types, mcp_server, store

runner = CliRunner()

DEFINITION = (
    "typedef struct PlayerInfo_s {\n\tchar gap_0000[0x17];\n\tint field_C;\n} PlayerInfo;\n"
)


def _seed_binary(conn: sqlite3.Connection) -> int:
    return store.add_binary(conn, sha256="ab" * 32, name="demo.exe")


def _seed_scan(conn: sqlite3.Connection, binary_id: int, definition: str = DEFINITION) -> None:
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_STRUCTS,
        {
            "decompiled": 1,
            "skipped": 0,
            "structs": [{"name": "PlayerInfo", "va": 0x1000, "definition": definition}],
        },
    )


def _seed_type(conn: sqlite3.Connection, binary_id: int, definition: str = DEFINITION) -> int:
    parsed = data_types.parse_definition(definition)
    return store.add_data_type(
        conn,
        binary_id=binary_id,
        name=parsed["name"],
        size=parsed["size"],
        members=parsed["members"],
        source=data_types.SOURCE_SCAN,
    )


def _post(path: str, body: dict[str, object] | None = None) -> tuple[str, dict[str, str], bytes]:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    return wsgi_request("POST", path, body=payload)


def _patch(path: str, body: dict[str, object]) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("PATCH", path, body=json.dumps(body))


class TestListAndImport:
    def test_get_lists_the_model_with_sizes(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_type(conn, binary_id)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/data-types")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["types"][0]["name"] == "PlayerInfo"
        assert payload["types"][0]["size"] == 0x17 + 4
        assert payload["types"][0]["members"][0]["offset"] == 0

    def test_get_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/4242/data-types")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_import_seeds_from_the_stored_scan(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_scan(conn, binary_id)
        status, headers, body = _post(f"/api/binaries/{binary_id}/data-types/import")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["created"] == 1
        assert payload["updated"] == 0
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/data-types")
        assert json_body(body, headers)["types"][0]["name"] == "PlayerInfo"

    def test_import_without_a_scan_is_404_no_scan(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        status, headers, body = _post(f"/api/binaries/{binary_id}/data-types/import")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_import_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _post("/api/binaries/4242/data-types/import")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_unexpected_failure_is_a_sanitized_500(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed_binary(conn)

        def _explode(*args: object, **kwargs: object) -> list[object]:
            raise RuntimeError("internal detail that must not reach the client")

        monkeypatch.setattr(data_types, "list_types", _explode)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/data-types")
        assert status.startswith("500")
        assert json_body(body, headers)["error"] == "internal server error"
        assert "must not reach" not in body.decode("utf-8")


class TestTypeAndMemberEdits:
    def test_patch_renames_the_type(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(f"/api/data-types/{data_type_id}", {"name": "Player"})
        assert status.startswith("200")
        assert json_body(body, headers)["name"] == "Player"

    def test_patch_invalid_name_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(f"/api/data-types/{data_type_id}", {"name": "1bad"})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid name"

    def test_patch_without_an_operation_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(f"/api/data-types/{data_type_id}", {})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid request"

    def test_patch_rejects_name_and_member_together(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"name": "Player", "member": {"index": 0, "new_name": "x"}},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid request"

    def test_patch_unknown_type_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _patch("/api/data-types/4242", {"name": "Nope"})
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "data-type-not-found"

    def test_patch_unknown_member_is_404(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"member": {"name": "missing", "new_name": "x"}},
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "member-not-found"

    def test_patch_updates_a_member_and_recomputes(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"member": {"index": 1, "new_name": "count", "new_type": "short"}},
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["members"][1]["name"] == "count"
        assert payload["members"][1]["size"] == 2
        assert payload["size"] == 0x17 + 2

    def test_add_member_and_reject_a_duplicate(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members",
            {"name": "flags", "type": "unsigned int"},
        )
        assert status.startswith("200")
        assert json_body(body, headers)["members"][-1]["name"] == "flags"

        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members",
            {"name": "flags", "type": "int"},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "duplicate member"

    def test_add_member_without_a_type_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(f"/api/data-types/{data_type_id}/members", {"name": "x"})
        assert status.startswith("400")
        assert "type" in json_body(body, headers)["error"]

    def test_delete_member_by_name(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = wsgi_request(
            "DELETE", f"/api/data-types/{data_type_id}/members/gap_0000"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [member["name"] for member in payload["members"]] == ["field_C"]
        assert payload["members"][0]["offset"] == 0

    def test_delete_unknown_member_is_404(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = wsgi_request(
            "DELETE", f"/api/data-types/{data_type_id}/members/missing"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "member-not-found"

    def test_delete_the_last_member_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, "typedef struct One_s {\n\tint a;\n} One;\n")
        status, headers, body = wsgi_request("DELETE", f"/api/data-types/{data_type_id}/members/0")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid member"

    def test_delete_type_and_unknown_id(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = wsgi_request("DELETE", f"/api/data-types/{data_type_id}")
        assert status.startswith("200")
        assert json_body(body, headers)["deleted"] is True

        status, headers, body = wsgi_request("DELETE", f"/api/data-types/{data_type_id}")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "data-type-not-found"


class TestExport:
    def test_export_writes_the_header(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn)
        _seed_type(conn, binary_id)
        target = tmp_path / "out" / "types.h"
        status, headers, body = _post(
            f"/api/binaries/{binary_id}/data-types/export", {"path": str(target)}
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["types"] == 1
        assert payload["bytes"] > 0
        assert "PlayerInfo" in target.read_text(encoding="utf-8")

    def test_export_refuses_an_existing_target_without_force(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        _seed_type(conn, binary_id)
        target = tmp_path / "types.h"
        target.write_text("original", encoding="utf-8")
        status, headers, body = _post(
            f"/api/binaries/{binary_id}/data-types/export", {"path": str(target)}
        )
        assert status.startswith("409")
        assert json_body(body, headers)["error"] == "export-exists"

        status, headers, body = _post(
            f"/api/binaries/{binary_id}/data-types/export",
            {"path": str(target), "force": True},
        )
        assert status.startswith("200")
        assert "PlayerInfo" in target.read_text(encoding="utf-8")

    def test_export_refuses_a_missing_grandparent(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        _seed_type(conn, binary_id)
        target = tmp_path / "missing" / "nested" / "types.h"
        status, headers, body = _post(
            f"/api/binaries/{binary_id}/data-types/export", {"path": str(target)}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid path"
        assert not target.exists()

    def test_export_without_a_path_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        status, headers, body = _post(f"/api/binaries/{binary_id}/data-types/export", {})
        assert status.startswith("400")
        assert "path" in json_body(body, headers)["error"]

    def test_export_unknown_binary_is_404(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        status, headers, body = _post(
            "/api/binaries/4242/data-types/export", {"path": str(tmp_path / "types.h")}
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


def _add_typed(
    conn: sqlite3.Connection,
    binary_id: int,
    name: str,
    *,
    kind: str = data_types.KIND_STRUCT,
    namespace: str = "",
    members: list[dict[str, object]] | None = None,
    values: list[dict[str, object]] | None = None,
    target: str = "",
    element_count: int | None = None,
) -> int:
    normalized, size = data_types.recompute(kind, members or [], target, element_count)
    return store.add_data_type(
        conn,
        binary_id=binary_id,
        name=name,
        size=size,
        members=normalized,
        kind=kind,
        namespace=namespace,
        values=values or [],
        target=target,
        element_count=element_count,
        source=data_types.SOURCE_MANUAL,
    )


def _seed_filter_model(conn: sqlite3.Connection, binary_id: int) -> None:
    _add_typed(
        conn,
        binary_id,
        "NP_HEADER",
        members=[
            {"name": "magic", "type": "unsigned short", "pointer": False, "count": None},
        ],
    )
    _add_typed(
        conn,
        binary_id,
        "NP_FLAGS",
        kind=data_types.KIND_ENUM,
        values=[{"name": "NP_FLAG_A", "value": 0}],
    )
    _add_typed(
        conn,
        binary_id,
        "WIN_DWORD",
        kind=data_types.KIND_TYPEDEF,
        namespace="winnt",
        target="unsigned int",
    )


class TestSort:
    def test_size_orders_by_size_with_the_unknown_ones_last(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_filter_model(conn, binary_id)
        # A parameterless typedef is the model's unknown-size case (size 0).
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?sort=size"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["sort"] == "size"
        names = [data_type["name"] for data_type in payload["types"]]
        assert names[-1] == "WIN_DWORD"
        sizes = [data_type["size"] for data_type in payload["types"]]
        assert sizes == sorted(sizes, key=lambda size: (size == 0, size))

    def test_name_descending_is_the_reverse(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_filter_model(conn, binary_id)
        _, _, ascending = wsgi_request("GET", f"/api/binaries/{binary_id}/data-types")
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?direction=desc"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["direction"] == "desc"
        assert [row["name"] for row in payload["types"]] == [
            row["name"] for row in reversed(json_body(ascending, headers)["types"])
        ]

    def test_the_filter_and_the_sort_compose(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_filter_model(conn, binary_id)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?kind=struct&sort=size&direction=desc"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [row["name"] for row in payload["types"]] == ["NP_HEADER"]
        assert payload["total"] == 3

    def test_unknown_sort_and_direction_are_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        cases = (("sort=weight", "invalid sort"), ("direction=up", "invalid direction"))
        for query, error in cases:
            status, headers, body = wsgi_request(
                "GET", f"/api/binaries/{binary_id}/data-types?{query}"
            )
            assert status.startswith("400")
            assert json_body(body, headers)["error"] == error


class TestListFilters:
    def test_kind_filter_narrows_and_counts(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_filter_model(conn, binary_id)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?kind=enum"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["total"] == 3
        assert [data_type["name"] for data_type in payload["types"]] == ["NP_FLAGS"]
        assert payload["types"][0]["values"][0]["hex"] == "0x0"

    def test_unknown_kind_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?kind=widget"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid kind"

    def test_unknown_namespace_is_an_empty_list(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_filter_model(conn, binary_id)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?namespace=nope"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 0
        assert payload["types"] == []

    def test_namespace_filter_and_tree(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_filter_model(conn, binary_id)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?namespace=winnt"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [data_type["name"] for data_type in payload["types"]] == ["WIN_DWORD"]
        assert any(node["path"] == "winnt" for node in payload["namespaces"])

    def test_search_matches_an_enum_value_name(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_filter_model(conn, binary_id)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?search=NP_FLAG_A"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [data_type["name"] for data_type in payload["types"]] == ["NP_FLAGS"]

    def test_unfiltered_list_keeps_its_keys_and_adds_the_tree(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        _seed_type(conn, binary_id)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/data-types")
        payload = json_body(body, headers)
        assert status.startswith("200")
        assert payload["binary_id"] == binary_id
        assert payload["count"] == 1
        assert payload["total"] == 1
        assert payload["types"][0]["kind"] == data_types.KIND_STRUCT
        assert payload["namespaces"]


class TestReferencesRoute:
    def test_references_report_both_indices(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        player = _add_typed(
            conn,
            binary_id,
            "PlayerInfo",
            members=[{"name": "slot", "type": "int", "pointer": False, "count": None}],
        )
        _add_typed(
            conn,
            binary_id,
            "Holder",
            members=[{"name": "info", "type": "PlayerInfo", "pointer": False, "count": None}],
        )
        status, headers, body = wsgi_request("GET", f"/api/data-types/{player}/references")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["note"] == data_types.REFERENCES_NOTE
        assert [entry["name"] for entry in payload["referenced_by"]] == ["Holder"]
        assert payload["referenced_by"][0]["relationships"] == [data_types.RELATION_MEMBER]
        assert payload["used_by_functions"] == []

    def test_an_unreferenced_type_answers_empty_tables(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        lonely = _add_typed(
            conn,
            binary_id,
            "Lonely",
            members=[{"name": "a", "type": "int", "pointer": False, "count": None}],
        )
        status, headers, body = wsgi_request("GET", f"/api/data-types/{lonely}/references")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["referenced_by"] == []
        assert payload["used_by_functions"] == []

    def test_unknown_type_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/data-types/4242/references")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "data-type-not-found"


class TestProvenance:
    def test_the_labels_map_every_stored_source(self) -> None:
        assert data_types.source_label(data_types.SOURCE_SCAN) == data_types.SOURCE_SYSTEM
        assert data_types.source_label(data_types.SOURCE_SYMBOL) == data_types.SOURCE_SYSTEM
        assert data_types.source_label(data_types.SOURCE_MANUAL) == data_types.SOURCE_USER
        assert data_types.source_label(data_types.SOURCE_UNSTRIP) == data_types.SOURCE_AUTO_UNSTRIP
        assert data_types.source_label(data_types.SOURCE_AI) == data_types.SOURCE_AI_AGENT
        assert data_types.source_label("ai-renames") == data_types.SOURCE_AI_AGENT
        # A source nobody declared reads as a person's decision, never as absent.
        assert data_types.source_label("") == data_types.SOURCE_USER
        assert data_types.source_label("something-new") == data_types.SOURCE_USER

    def test_the_totals_name_every_label_in_order(self) -> None:
        totals = data_types.source_totals(
            [
                {"source": data_types.SOURCE_SCAN},
                {"source": data_types.SOURCE_SCAN},
                {"source": data_types.SOURCE_UNSTRIP},
            ]
        )
        assert list(totals) == list(data_types.SOURCE_LABELS)
        assert totals[data_types.SOURCE_SYSTEM] == 2
        assert totals[data_types.SOURCE_AUTO_UNSTRIP] == 1
        assert totals[data_types.SOURCE_AI_AGENT] == 0

    def test_the_filter_keeps_one_label(self) -> None:
        types = [
            {"name": "a", "kind": "struct", "namespace": "", "size": 4, "source": "scan"},
            {"name": "b", "kind": "struct", "namespace": "", "size": 4, "source": "manual"},
        ]
        kept = data_types.filter_types(types, source=data_types.SOURCE_SYSTEM)
        assert [entry["name"] for entry in kept] == ["a"]
        assert data_types.filter_types(types, source=None) == types

    def test_the_route_reports_the_strip_and_filters(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_type(conn, binary_id)
        store.add_data_type(
            conn,
            binary_id=binary_id,
            name="HandMade",
            size=4,
            members=[],
            source=data_types.SOURCE_MANUAL,
        )
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/data-types")
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["sources"] == {
            "System": 1,
            "User": 1,
            "Auto Unstrip": 0,
            "AI": 0,
        }

        filtered, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?source=User"
        )
        assert filtered.startswith("200"), body
        chosen = json_body(body, headers)
        assert [entry["name"] for entry in chosen["types"]] == ["HandMade"]
        assert chosen["count"] == 1 and chosen["total"] == 2
        assert chosen["sources"]["System"] == 1

    def test_an_unknown_label_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/data-types?source=Nonsense"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid source"

    def test_the_cli_and_the_tool_take_the_label(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_type(conn, binary_id)
        store.add_data_type(
            conn,
            binary_id=binary_id,
            name="HandMade",
            size=4,
            members=[],
            source=data_types.SOURCE_MANUAL,
        )
        payload = json.loads(
            runner.invoke(cli.app, ["types", str(binary_id), "--source", "User", "--json"]).output
        )
        assert [entry["name"] for entry in payload["types"]] == ["HandMade"]
        assert payload["sources"]["System"] == 1

        bad = runner.invoke(cli.app, ["types", str(binary_id), "--source", "Nope"])
        assert bad.exit_code == 1
        assert "invalid source" in bad.output

        listed, failed = mcp_server.call_tool(
            "list_data_types", {"binary_id": binary_id, "source": "User"}
        )
        assert not failed, listed
        assert [entry["name"] for entry in listed["types"]] == ["HandMade"]

        refused, failed = mcp_server.call_tool(
            "list_data_types", {"binary_id": binary_id, "source": "Nope"}
        )
        assert failed
        assert refused["error"] == "invalid source"

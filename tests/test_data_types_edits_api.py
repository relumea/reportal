"""Tests for the data-type routes added for the richer editor: the member shape
and position, the kind/namespace/size write, explicit padding and enum values.
"""

from __future__ import annotations

import json
import sqlite3

from conftest import json_body, wsgi_request

from reportal import data_types, store

DEFINITION = "typedef struct PlayerInfo_s {\n\tchar name[8];\n\tint field_C;\n} PlayerInfo;\n"
ENUM_DEFINITION = "typedef enum NPFlags_s {\n\tNP_FLAG_A = 0,\n\tNP_FLAG_B = 1\n} NPFlags;\n"


def _seed_binary(conn: sqlite3.Connection) -> int:
    return store.add_binary(conn, sha256="ab" * 32, name="demo.exe")


def _seed_type(conn: sqlite3.Connection, binary_id: int, definition: str = DEFINITION) -> int:
    parsed = data_types.parse_definition(definition)
    return store.add_data_type(
        conn,
        binary_id=binary_id,
        name=parsed["name"],
        size=parsed["size"],
        members=parsed["members"],
        kind=parsed["kind"],
        values=parsed["values"],
        target=parsed["target"],
        element_count=parsed["element_count"],
        source=data_types.SOURCE_SCAN,
    )


def _post(path: str, body: dict[str, object] | None = None) -> tuple[str, dict[str, str], bytes]:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    return wsgi_request("POST", path, body=payload)


def _patch(path: str, body: dict[str, object]) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("PATCH", path, body=json.dumps(body))


def _delete(path: str) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("DELETE", path)


class TestMemberShapeRoutes:
    def test_add_member_carries_bits_pointer_and_count(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members",
            {"name": "flags", "type": "unsigned int", "bits": 3},
        )
        assert status.startswith("200")
        member = json_body(body, headers)["members"][-1]
        assert (member["name"], member["bits"], member["is_gap"]) == ("flags", 3, False)

        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members",
            {"name": "rows", "type": "char", "count": 6, "pointer": False},
        )
        assert status.startswith("200")
        assert json_body(body, headers)["members"][-1]["count"] == 6

    def test_add_member_at_an_index_and_after_a_member(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members",
            {"name": "middle", "type": "short", "index": 1},
        )
        assert status.startswith("200")
        assert [m["name"] for m in json_body(body, headers)["members"]] == [
            "name",
            "middle",
            "field_C",
        ]

        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members",
            {"name": "last", "type": "char", "after": "field_C"},
        )
        assert status.startswith("200")
        assert [m["name"] for m in json_body(body, headers)["members"]] == [
            "name",
            "middle",
            "field_C",
            "last",
        ]

    def test_index_and_after_together_are_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members",
            {"name": "x", "type": "int", "index": 0, "after": "name"},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid member"

    def test_a_bad_bit_width_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members",
            {"name": "x", "type": "int", "bits": 0},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid member"

    def test_patch_sets_and_clears_a_bit_width(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"member": {"index": 1, "new_bits": 5}},
        )
        assert status.startswith("200")
        assert json_body(body, headers)["members"][1]["bits"] == 5

        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"member": {"index": 1, "new_bits": None}},
        )
        assert status.startswith("200")
        assert json_body(body, headers)["members"][1]["bits"] is None

    def test_patch_keeps_the_bit_width_across_a_retype(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        _patch(f"/api/data-types/{data_type_id}", {"member": {"index": 1, "new_bits": 3}})
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"member": {"index": 1, "new_type": "short"}},
        )
        assert status.startswith("200")
        member = json_body(body, headers)["members"][1]
        assert (member["type"], member["bits"]) == ("short", 3)


class TestGapRoutes:
    def test_convert_a_member_to_a_gap_and_back(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(f"/api/data-types/{data_type_id}/members/field_C/gap")
        assert status.startswith("200")
        gap = json_body(body, headers)["members"][1]
        assert (gap["name"], gap["is_gap"], gap["count"]) == ("gap_0008", True, 4)

        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members/gap_0008/ungap",
            {"name": "counter", "type": "int"},
        )
        assert status.startswith("200")
        member = json_body(body, headers)["members"][1]
        assert (member["name"], member["type"], member["is_gap"]) == ("counter", "int", False)

    def test_a_gap_size_is_taken_from_the_body(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members/name/gap", {"size": 16}
        )
        assert status.startswith("200")
        assert json_body(body, headers)["size"] == 20

    def test_ungap_needs_a_real_member(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/members/field_C/ungap",
            {"name": "counter", "type": "int"},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid member"

    def test_gap_on_a_union_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(
            conn, binary_id, "typedef union U_s {\n\tint a;\n\tchar b[4];\n} U;\n"
        )
        status, headers, body = _post(f"/api/data-types/{data_type_id}/members/a/gap")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid member"


class TestTypeFieldRoutes:
    def test_patch_sets_kind_namespace_and_size(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"kind": "union", "namespace": "winnt::kernel", "size": 32},
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["kind"] == "union"
        assert payload["namespace"] == "winnt::kernel"
        assert payload["size"] == 32
        assert payload["size_check"]["extent"] == 8
        assert payload["size_check"]["match"] is False

    def test_an_unknown_kind_is_400_listing_the_known_ones(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(f"/api/data-types/{data_type_id}", {"kind": "bitfield"})
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid kind"
        assert "struct" in payload["detail"]

    def test_a_negative_size_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(f"/api/data-types/{data_type_id}", {"size": -1})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid size"

    def test_member_is_exclusive_with_the_type_fields(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"kind": "union", "member": {"index": 0, "new_name": "x"}},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid request"

    def test_member_edit_needs_a_selector(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"member": {"new_name": "x"}},
        )
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid member"
        assert "name or an index" in payload["detail"]

    def test_member_name_and_index_are_exclusive(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}",
            {"member": {"name": "field_C", "index": 1, "new_name": "x"}},
        )
        assert status.startswith("400")
        payload = json_body(body, headers)
        assert payload["error"] == "invalid member"
        assert "exclusive" in payload["detail"]

    def test_the_kind_change_lands_in_history(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        _patch(f"/api/data-types/{data_type_id}", {"kind": "union"})
        status, headers, body = wsgi_request("GET", f"/api/data-types/{data_type_id}/history")
        entry = json_body(body, headers)["history"][0]
        changed = {change["field"]: change for change in entry["changes"]}
        assert set(changed) == {"kind", "size", "members"}
        assert changed["kind"]["before"] == "struct"
        assert changed["kind"]["after"] == "union"
        assert changed["size"]["after"] == 8

    def test_the_list_payload_carries_the_size_check(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id)
        _patch(f"/api/data-types/{data_type_id}", {"size": 16})
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/data-types")
        check = json_body(body, headers)["types"][0]["size_check"]
        assert check["declared"] == 16
        assert check["extent"] == 12
        assert "16" in check["warning"]


class TestValueRoutes:
    def test_add_value_auto_increments_and_notes_it(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, ENUM_DEFINITION)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/values", {"name": "NP_FLAG_C"}
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["values"][-1] == {"name": "NP_FLAG_C", "value": 2, "hex": "0x2"}
        assert "auto-incremented to 2" in payload["note"]

    def test_add_value_reads_a_hex_literal_and_echoes_both(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, ENUM_DEFINITION)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/values", {"name": "NP_FLAG_X", "value": "0x20"}
        )
        assert status.startswith("200")
        assert json_body(body, headers)["values"][-1] == {
            "name": "NP_FLAG_X",
            "value": 32,
            "hex": "0x20",
        }

    def test_add_value_refusals(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, ENUM_DEFINITION)
        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/values", {"name": "NP_FLAG_A"}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "duplicate member"

        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/values", {"name": "NP_FLAG_X", "value": 1}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "duplicate member"

        status, headers, body = _post(
            f"/api/data-types/{data_type_id}/values", {"name": "NP_FLAG_X", "value": "twenty"}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid member"

    def test_patch_value_renames_and_revalues(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, ENUM_DEFINITION)
        status, headers, body = _patch(
            f"/api/data-types/{data_type_id}/values/NP_FLAG_B",
            {"new_name": "NP_FLAG_BS", "new_value": "0x40"},
        )
        assert status.startswith("200")
        assert json_body(body, headers)["values"][1] == {
            "name": "NP_FLAG_BS",
            "value": 64,
            "hex": "0x40",
        }

    def test_patch_value_needs_an_edit(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, ENUM_DEFINITION)
        status, headers, body = _patch(f"/api/data-types/{data_type_id}/values/NP_FLAG_A", {})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid member"

    def test_delete_value_and_refuse_an_unknown_one(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, ENUM_DEFINITION)
        status, headers, body = _delete(f"/api/data-types/{data_type_id}/values/NP_FLAG_A")
        assert status.startswith("200")
        assert [value["name"] for value in json_body(body, headers)["values"]] == ["NP_FLAG_B"]

        status, headers, body = _delete(f"/api/data-types/{data_type_id}/values/NP_FLAG_Z")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "member-not-found"

    def test_removing_the_last_value_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, "typedef enum One_s {\n\tONE = 1\n} One;\n")
        status, headers, body = _delete(f"/api/data-types/{data_type_id}/values/ONE")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid member"

    def test_a_value_edit_lands_in_history(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _seed_type(conn, binary_id, ENUM_DEFINITION)
        _patch(
            f"/api/data-types/{data_type_id}/values/NP_FLAG_B",
            {"new_value": 5},
        )
        status, headers, body = wsgi_request("GET", f"/api/data-types/{data_type_id}/history")
        entry = json_body(body, headers)["history"][0]
        assert [change["field"] for change in entry["changes"]] == ["values"]
        assert entry["current"]["values"][1]["value"] == 5

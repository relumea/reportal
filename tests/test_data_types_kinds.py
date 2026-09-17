"""Tests for the data-type kinds: parsing, storage round trips and rendering.

One case per declaration shape the model carries, plus the padded "As C" form
and the legacy-row migration.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from reportal import data_types, store

UNION_DEFINITION = (
    "typedef union NPBlock_s {\n\tunsigned int as_int;\n\tunsigned char as_bytes[4];\n} NPBlock;\n"
)
ENUM_DEFINITION = (
    "typedef enum NPFlags_s {\n\tNP_FLAG_A = 0,\n\tNP_FLAG_B = 1,\n\tNP_FLAG_C\n} NPFlags;\n"
)
TYPEDEF_DEFINITION = "typedef unsigned int DWORD;\n"
POINTER_DEFINITION = "typedef void *HANDLE;\n"
ARRAY_DEFINITION = "typedef int Rows[4];\n"
FUNCTION_DEFINITION = "typedef void (*Callback)(int, char *value);\n"
BITFIELD_DEFINITION = (
    "typedef struct NPBits_s {\n\tunsigned int low : 3;\n\tunsigned int high : 5;\n} NPBits;\n"
)


def _seed_binary(conn: sqlite3.Connection, *, sha256: str = "ab" * 32) -> int:
    return store.add_binary(conn, sha256=sha256, name="demo.exe")


def _store_parsed(conn: sqlite3.Connection, binary_id: int, definition: str) -> int:
    """Parse *definition* and store it the way the scan import would."""
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


class TestParseKinds:
    def test_struct_keeps_its_kind(self) -> None:
        parsed = data_types.parse_definition("typedef struct S_s {\n\tint a;\n} S;\n")
        assert parsed["kind"] == data_types.KIND_STRUCT

    def test_union_members_all_sit_at_offset_zero(self) -> None:
        parsed = data_types.parse_definition(UNION_DEFINITION)
        assert parsed["kind"] == data_types.KIND_UNION
        assert [member["offset"] for member in parsed["members"]] == [0, 0]
        assert parsed["size"] == 4

    def test_enum_values_are_parsed_with_continuation(self) -> None:
        parsed = data_types.parse_definition(ENUM_DEFINITION)
        assert parsed["kind"] == data_types.KIND_ENUM
        assert parsed["members"] == []
        assert parsed["values"] == [
            {"name": "NP_FLAG_A", "value": 0},
            {"name": "NP_FLAG_B", "value": 1},
            {"name": "NP_FLAG_C", "value": 2},
        ]

    def test_hex_enum_values_are_parsed(self) -> None:
        parsed = data_types.parse_definition("typedef enum E_s {\n\tE_A = 0x10,\n\tE_B\n} E;\n")
        assert parsed["values"] == [{"name": "E_A", "value": 16}, {"name": "E_B", "value": 17}]

    def test_typedef_alias_keeps_its_target(self) -> None:
        parsed = data_types.parse_definition(TYPEDEF_DEFINITION)
        assert parsed["kind"] == data_types.KIND_TYPEDEF
        assert parsed["target"] == "unsigned int"
        assert parsed["size"] == 4

    def test_pointer_type(self) -> None:
        parsed = data_types.parse_definition(POINTER_DEFINITION)
        assert parsed["kind"] == data_types.KIND_POINTER
        assert parsed["target"] == "void"
        assert parsed["size"] == data_types.POINTER_SIZE

    def test_array_type(self) -> None:
        parsed = data_types.parse_definition(ARRAY_DEFINITION)
        assert parsed["kind"] == data_types.KIND_ARRAY
        assert parsed["target"] == "int"
        assert parsed["element_count"] == 4
        assert parsed["size"] == 16

    @pytest.mark.parametrize(
        ("target", "expected_size"),
        [
            ("char", 1),
            ("char[3]", 3),
            ("char *", 4),
            ("char *[0]", 0),
            ("char *[1]", 4),
            ("char *[3]", 12),
            ("Unknown *[3]", 12),
            ("Unknown[3]", 0),
        ],
    )
    def test_recompute_target_size(self, target: str, expected_size: int) -> None:
        members, size = data_types.recompute(data_types.KIND_TYPEDEF, [], target, None)
        assert members == []
        assert size == expected_size

    def test_function_type(self) -> None:
        parsed = data_types.parse_definition(FUNCTION_DEFINITION)
        assert parsed["kind"] == data_types.KIND_FUNCTION
        assert parsed["target"] == "void"
        members = parsed["members"]
        assert [(m["type"], m["pointer"], m["name"]) for m in members] == [
            ("int", False, ""),
            ("char", True, "value"),
        ]

    def test_bitfield_member_carries_its_width(self) -> None:
        parsed = data_types.parse_definition(BITFIELD_DEFINITION)
        assert [member["bits"] for member in parsed["members"]] == [3, 5]

    def test_a_plain_struct_is_still_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError):
            data_types.parse_definition("struct Foo { int a; };")


class TestStoreRoundTrips:
    def test_struct_round_trip(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, "typedef struct S_s {\n\tint a;\n} S;\n")
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert row["kind"] == data_types.KIND_STRUCT
        assert row["members"][0]["name"] == "a"

    def test_enum_values_survive_the_store(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert row["kind"] == data_types.KIND_ENUM
        assert [value["name"] for value in row["values"]] == ["NP_FLAG_A", "NP_FLAG_B", "NP_FLAG_C"]
        payload = data_types.encode_type(row)
        assert [value["hex"] for value in payload["values"]] == ["0x0", "0x1", "0x2"]

    def test_typedef_target_survives_the_store(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, TYPEDEF_DEFINITION)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert row["kind"] == data_types.KIND_TYPEDEF
        assert row["target"] == "unsigned int"

    def test_array_element_count_survives_the_store(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ARRAY_DEFINITION)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert row["element_count"] == 4
        assert row["size"] == 16

    def test_bitfield_round_trip(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, BITFIELD_DEFINITION)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert [member["bits"] for member in row["members"]] == [3, 5]
        header = data_types.render_header([row])
        assert "\tunsigned int low : 3;" in header
        assert "\tunsigned int high : 5;" in header

    def test_namespace_survives_an_edit(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, TYPEDEF_DEFINITION)
        row = data_types.set_namespace(conn, data_type_id, namespace="winnt")
        assert row["namespace"] == "winnt"


class TestRenderKinds:
    def test_union_renders_offsets_zero_and_overlap(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, UNION_DEFINITION)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        header = data_types.render_header([row])
        assert "typedef union NPBlock_s {" in header
        as_c = data_types.render_as_c(row)
        assert "/* all members overlap */" in as_c

    def test_typedef_renders_as_an_alias(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, TYPEDEF_DEFINITION)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert data_types.render_header([row]) == (
            "#pragma once\n\ntypedef unsigned int DWORD; /* size 4 */\n"
        )

    def test_pointer_and_array_render(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        pointer_id = _store_parsed(conn, binary_id, POINTER_DEFINITION)
        array_id = _store_parsed(conn, binary_id, ARRAY_DEFINITION)
        pointer = data_types.get_type(conn, pointer_id)
        array = data_types.get_type(conn, array_id)
        assert pointer is not None and array is not None
        assert "typedef void *HANDLE; /* size 4 */" in data_types.render_header([pointer])
        assert "typedef int Rows[4]; /* size 16 */" in data_types.render_header([array])

    def test_function_type_renders_its_parameters(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, FUNCTION_DEFINITION)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert (
            "typedef void (*Callback)(int, char *value); /* size 4 */"
            in data_types.render_header([row])
        )

    def test_enum_renders_named_values(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        header = data_types.render_header([row])
        assert "typedef enum NPFlags_s {" in header
        assert "\tNP_FLAG_A = 0," in header
        assert "\tNP_FLAG_C = 2" in header

    def test_padding_comments_match_the_real_offsets(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = store.add_data_type(
            conn,
            binary_id=binary_id,
            name="Gap",
            size=12,
            members=[
                {
                    "name": "a",
                    "type": "char",
                    "pointer": False,
                    "count": None,
                    "offset": 0,
                    "size": 1,
                },
                {
                    "name": "b",
                    "type": "int",
                    "pointer": False,
                    "count": None,
                    "offset": 4,
                    "size": 4,
                },
            ],
            kind=data_types.KIND_STRUCT,
        )
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert data_types.render_as_c(row) == (
            "typedef struct Gap_s {\n"
            "\tchar a;\n"
            "\t/* +0x3 padding */\n"
            "\tint b;\n"
            "\t/* +0x4 padding */\n"
            "} Gap;"
        )

    def test_struct_export_is_unchanged(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(
            conn,
            binary_id,
            "typedef struct PlayerInfo_s {\n"
            "\tchar gap_0000[0x17];\n"
            "\tint field_C;\n"
            "} PlayerInfo;\n",
        )
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert data_types.render_header([row]) == (
            "#pragma once\n"
            "\n"
            "typedef struct PlayerInfo_s {\n"
            "\tchar gap_0000[23];\n"
            "\tint field_C;\n"
            "} PlayerInfo; /* size 27 */\n"
        )


class TestLegacyMigration:
    def test_a_row_written_before_the_kind_column_reads_as_a_struct(self, tmp_path: Path) -> None:
        db_path = tmp_path / "legacy.db"
        raw = sqlite3.connect(db_path)
        raw.executescript(
            "CREATE TABLE binaries (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT,"
            " name TEXT, path TEXT, size INTEGER, format TEXT, arch TEXT);"
        )
        raw.executescript(
            "CREATE TABLE data_types (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " binary_id INTEGER NOT NULL, name TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0,"
            " members_json TEXT NOT NULL DEFAULT '[]', source TEXT NOT NULL DEFAULT '',"
            " created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE (binary_id, name));"
        )
        members = json.dumps(
            [
                {
                    "name": "a",
                    "type": "int",
                    "pointer": False,
                    "count": None,
                    "offset": 0,
                    "size": 4,
                    "note": "",
                }
            ]
        )
        raw.execute("INSERT INTO binaries (id, name) VALUES (1, 'demo.exe')")
        raw.execute(
            "INSERT INTO data_types (binary_id, name, size, members_json, source,"
            " created_at, updated_at) VALUES (1, 'Legacy', 4, ?, 'scan', '2020', '2020')",
            (members,),
        )
        raw.commit()
        raw.close()

        store.init_db(db_path)
        with sqlite3.connect(db_path) as upgraded:
            upgraded.row_factory = sqlite3.Row
            rows = data_types.list_types(upgraded, binary_id=1)
            assert rows[0]["kind"] == data_types.KIND_STRUCT
            assert rows[0]["namespace"] == ""
            assert data_types.render_header(rows) == (
                "#pragma once\n\ntypedef struct Legacy_s {\n\tint a;\n} Legacy; /* size 4 */\n"
            )

"""Tests for the data-type edit surface: the member shape and its position, the
kind/namespace/declared-size write, the size-vs-members check, explicit padding
and the enum value operations.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from reportal import data_types, store

DEFINITION = "typedef struct PlayerInfo_s {\n\tchar name[8];\n\tint field_C;\n} PlayerInfo;\n"
ENUM_DEFINITION = "typedef enum NPFlags_s {\n\tNP_FLAG_A = 0,\n\tNP_FLAG_B = 1\n} NPFlags;\n"


def _seed_binary(conn: sqlite3.Connection) -> int:
    return store.add_binary(conn, sha256="ab" * 32, name="demo.exe")


def _store_parsed(conn: sqlite3.Connection, binary_id: int, definition: str) -> int:
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


def _make_type(conn: sqlite3.Connection, binary_id: int, definition: str = DEFINITION) -> int:
    return _store_parsed(conn, binary_id, definition)


class TestMemberShape:
    def test_add_carries_pointer_count_and_bits(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.add_member(
            conn,
            data_type_id,
            name="flags",
            type_text="unsigned int",
            bits=3,
        )
        member = row["members"][-1]
        assert member["type"] == "unsigned int"
        assert member["bits"] == 3
        assert member["pointer"] is False
        assert member["size"] == 4
        assert row["size"] == 8 + 4 + 4

        row = data_types.add_member(conn, data_type_id, name="rows", type_text="char", count=6)
        assert row["members"][-1]["count"] == 6
        assert row["members"][-1]["size"] == 6

    def test_add_defaults_bits_to_none(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.add_member(conn, data_type_id, name="plain", type_text="int")
        assert row["members"][-1]["bits"] is None

    def test_add_rejects_a_bit_width_below_one(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.add_member(conn, data_type_id, name="x", type_text="int", bits=0)

    def test_add_rejects_a_non_integer_bit_width(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.add_member(conn, data_type_id, name="x", type_text="int", bits="3")  # type: ignore[arg-type]

    def test_update_sets_and_clears_a_bit_width(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.update_member(conn, data_type_id, index=1, new_bits=5)
        assert row["members"][1]["bits"] == 5
        assert "field_C : 5" in row["as_c"]

        row = data_types.update_member(conn, data_type_id, index=1, new_bits=None)
        assert row["members"][1]["bits"] is None
        assert " : " not in row["as_c"]

    def test_a_retype_leaves_a_hand_set_bit_width_alone(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        data_types.update_member(conn, data_type_id, index=1, new_bits=3)
        row = data_types.update_member(conn, data_type_id, index=1, new_type="short")
        assert row["members"][1]["type"] == "short"
        assert row["members"][1]["bits"] == 3
        assert row["members"][1]["size"] == 2

    def test_update_sets_the_pointer_flag_and_array_count(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.update_member(conn, data_type_id, index=1, new_pointer=True, new_count=2)
        assert row["members"][1]["pointer"] is True
        assert row["members"][1]["count"] == 2

    def test_update_without_an_edit_is_rejected(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.update_member(conn, data_type_id, index=1)


class TestMemberPosition:
    def test_index_inserts_at_that_position(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.add_member(conn, data_type_id, name="flags", type_text="short", index=1)
        assert [member["name"] for member in row["members"]] == ["name", "flags", "field_C"]
        assert [member["offset"] for member in row["members"]] == [0, 8, 10]

    def test_index_equal_to_the_length_appends(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.add_member(conn, data_type_id, name="tail", type_text="int", index=2)
        assert [member["name"] for member in row["members"]] == ["name", "field_C", "tail"]

    def test_after_inserts_after_the_named_member(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.add_member(
            conn, data_type_id, name="flags", type_text="short", after="name"
        )
        assert [member["name"] for member in row["members"]] == ["name", "flags", "field_C"]

    def test_after_an_unknown_member_is_rejected(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.UnknownMemberError):
            data_types.add_member(conn, data_type_id, name="flags", type_text="int", after="nope")

    def test_index_past_the_end_is_rejected(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.UnknownMemberError):
            data_types.add_member(conn, data_type_id, name="flags", type_text="int", index=9)

    def test_index_and_after_together_are_refused(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.add_member(
                conn, data_type_id, name="flags", type_text="int", index=0, after="name"
            )


class TestExplicitGaps:
    def test_convert_to_gap_names_the_offset_and_keeps_the_size(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.convert_to_gap(conn, data_type_id, name="field_C")
        gap = row["members"][1]
        assert gap["name"] == "gap_0008"
        assert gap["type"] == "char"
        assert gap["count"] == 4
        assert gap["size"] == 4
        assert gap["offset"] == 8
        assert row["size"] == 12
        assert data_types.is_gap_member(gap) is True

    def test_a_gap_with_a_different_size_shifts_what_follows(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.convert_to_gap(conn, data_type_id, name="name", size=16)
        assert [member["offset"] for member in row["members"]] == [0, 16]
        assert row["size"] == 20
        assert row["members"][0]["name"] == "gap_0000"

    def test_convert_to_gap_refuses_a_union(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(
            conn,
            binary_id,
            "typedef union U_s {\n\tint a;\n\tchar b[4];\n} U;\n",
        )
        with pytest.raises(data_types.InvalidMemberError):
            data_types.convert_to_gap(conn, data_type_id, name="a")

    def test_convert_to_gap_refuses_a_zero_sized_member(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(
            conn, binary_id, "typedef struct S_s {\n\tWindowInfo a;\n\tint b;\n} S;\n"
        )
        with pytest.raises(data_types.InvalidMemberError):
            data_types.convert_to_gap(conn, data_type_id, name="a")

    def test_convert_from_gap_needs_a_gap(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.convert_from_gap(
                conn, data_type_id, name="field_C", new_name="count", new_type="int"
            )

    def test_a_gap_round_trips_back_to_a_member(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        data_types.convert_to_gap(conn, data_type_id, name="field_C")
        row = data_types.convert_from_gap(
            conn, data_type_id, name="gap_0008", new_name="counter", new_type="int"
        )
        member = row["members"][1]
        assert (member["name"], member["type"], member["offset"], member["size"]) == (
            "counter",
            "int",
            8,
            4,
        )
        assert data_types.is_gap_member(member) is False

    def test_convert_from_gap_takes_the_shape_the_caller_names(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        data_types.convert_to_gap(conn, data_type_id, name="field_C")
        row = data_types.convert_from_gap(
            conn,
            data_type_id,
            name="gap_0008",
            new_name="flags",
            new_type="unsigned int",
            bits=5,
        )
        assert row["members"][1]["bits"] == 5
        assert "flags : 5" in row["as_c"]

    def test_is_gap_member_reads_the_naming_convention(self) -> None:
        assert data_types.gap_name(0x10) == "gap_0010"
        assert data_types.is_gap_member(
            {"name": "gap_0010", "type": "char", "pointer": False, "count": 4}
        )
        assert not data_types.is_gap_member(
            {"name": "gap_0010", "type": "char", "pointer": True, "count": 4}
        )
        assert not data_types.is_gap_member(
            {"name": "gap_buffer", "type": "char", "pointer": False, "count": 4}
        )
        assert not data_types.is_gap_member(
            {"name": "gap_0010", "type": "int", "pointer": False, "count": 4}
        )


class TestExplicitVersusImplicitRendering:
    def test_an_implicit_hole_renders_a_padding_comment(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = store.add_data_type(
            conn,
            binary_id=binary_id,
            name="Hole",
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
            "typedef struct Hole_s {\n"
            "\tchar a;\n"
            "\t/* +0x3 padding */\n"
            "\tint b;\n"
            "\t/* +0x4 padding */\n"
            "} Hole;"
        )

    def test_an_explicit_gap_renders_its_member_and_no_comment(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = store.add_data_type(
            conn,
            binary_id=binary_id,
            name="Gap",
            size=8,
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
                    "name": "gap_0001",
                    "type": "char",
                    "pointer": False,
                    "count": 3,
                    "offset": 1,
                    "size": 3,
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
        rendered = data_types.render_as_c(row)
        assert "\tchar gap_0001[3];" in rendered
        assert "padding */" not in rendered
        # The member wins: the header keeps every member and derives no gap text.
        assert data_types.render_header([row]) == (
            "#pragma once\n"
            "\n"
            "typedef struct Gap_s {\n"
            "\tchar a;\n"
            "\tchar gap_0001[3];\n"
            "\tint b;\n"
            "} Gap; /* size 8 */\n"
        )

    def test_a_struct_without_explicit_gaps_renders_what_it_always_did(
        self, conn: sqlite3.Connection
    ) -> None:
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


class TestSizeCheck:
    def test_a_matching_pair_reports_no_warning(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert data_types.size_check(row) == {
            "declared": 12,
            "extent": 12,
            "match": True,
            "warning": None,
        }

    def test_a_declared_size_past_the_members_warns(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.set_size(conn, data_type_id, size=16)
        assert row["size"] == 16
        assert row["size_check"]["declared"] == 16
        assert row["size_check"]["extent"] == 12
        assert row["size_check"]["match"] is False
        assert "16" in row["size_check"]["warning"]
        assert "12" in row["size_check"]["warning"]
        assert "trailing space" in row["size_check"]["warning"]

    def test_members_past_the_declared_size_warn(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.set_size(conn, data_type_id, size=4)
        assert row["size_check"]["extent"] == 12
        assert "past the declared size" in row["size_check"]["warning"]

    def test_setting_the_size_does_not_touch_the_members(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        data_types.set_size(conn, data_type_id, size=16)
        stored = data_types.get_type(conn, data_type_id)
        assert stored is not None
        assert [member["name"] for member in stored["members"]] == ["name", "field_C"]
        assert stored["members"][1]["size"] == 4

    def test_a_member_write_recomputes_the_declared_size(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        data_types.set_size(conn, data_type_id, size=16)
        row = data_types.add_member(conn, data_type_id, name="tail", type_text="char")
        assert row["size"] == 13
        assert row["size_check"]["match"] is True

    def test_a_negative_size_is_rejected(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidSizeError):
            data_types.set_size(conn, data_type_id, size=-1)

    def test_encode_type_carries_members_extent_and_flag(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        data_types.set_size(conn, data_type_id, size=16)
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        payload = data_types.encode_type(row)
        assert payload["size_check"]["declared"] == 16
        assert payload["size_check"]["extent"] == 12
        assert payload["members"][0]["is_gap"] is False
        assert payload["size"] == 16


class TestTypeFields:
    def test_set_kind_recomputes_the_shape(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.set_kind(conn, data_type_id, kind=data_types.KIND_UNION)
        assert row["kind"] == "union"
        assert [member["offset"] for member in row["members"]] == [0, 0]
        assert row["size"] == 8

    def test_an_unknown_kind_is_refused_listing_the_known_ones(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidKindError) as caught:
            data_types.set_kind(conn, data_type_id, kind="bitfield")
        for known in data_types.KNOWN_KINDS:
            assert known in str(caught.value)

    def test_validate_kind_returns_a_known_kind(self) -> None:
        assert data_types.validate_kind(" union ") == "union"

    def test_set_namespace_and_clear_it(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.set_namespace(conn, data_type_id, namespace=" winnt::kernel ")
        assert row["namespace"] == "winnt::kernel"
        row = data_types.set_namespace(conn, data_type_id, namespace="")
        assert row["namespace"] == ""

    def test_a_kind_change_lands_in_history_as_a_diffable_field(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        data_types.update_type(conn, data_type_id, kind="union", namespace="winnt")
        entry = data_types.list_history(conn, data_type_id)[0]
        changed = {change["field"] for change in entry["changes"]}
        assert {"kind", "namespace"} <= changed
        kind_change = next(c for c in entry["changes"] if c["field"] == "kind")
        assert kind_change["before"] == "struct"
        assert kind_change["after"] == "union"

    def test_update_type_applies_every_named_field_in_one_entry(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        data_types.update_type(conn, data_type_id, name="Player", kind="union", size=32)
        assert len(data_types.list_history(conn, data_type_id)) == 1
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert (row["name"], row["kind"], row["size"]) == ("Player", "union", 32)

    def test_update_type_needs_a_field(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.update_type(conn, data_type_id)

    def test_a_rename_still_refuses_a_duplicate(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id)
        other = _make_type(conn, binary_id, "typedef struct Other_s {\n\tint a;\n} Other;\n")
        with pytest.raises(data_types.DuplicateNameError):
            data_types.update_type(conn, other, name="PlayerInfo")

    def test_a_member_edit_on_a_kind_without_members_is_refused(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.add_member(conn, data_type_id, name="x", type_text="int")


class TestEnumValues:
    def test_add_auto_increments_and_notes_it(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        row = data_types.add_value(conn, data_type_id, name="NP_FLAG_C")
        assert row["values"][-1] == {"name": "NP_FLAG_C", "value": 2, "hex": "0x2"}
        assert "auto-incremented to 2" in row["note"]
        assert "NP_FLAG_B" in row["note"]

    def test_the_first_value_of_an_empty_enum_defaults_to_zero(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = store.add_data_type(
            conn, binary_id=binary_id, name="E", size=4, members=[], kind="enum", values=[]
        )
        row = data_types.add_value(conn, data_type_id, name="E_A")
        assert row["values"] == [{"name": "E_A", "value": 0, "hex": "0x0"}]
        assert "defaulted to 0" in row["note"]

    def test_add_reads_a_hex_literal(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        row = data_types.add_value(conn, data_type_id, name="NP_FLAG_X", value="0x20")
        assert row["values"][-1]["value"] == 32
        assert row["values"][-1]["hex"] == "0x20"

    def test_add_rejects_a_duplicate_name(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        with pytest.raises(data_types.DuplicateValueError):
            data_types.add_value(conn, data_type_id, name="NP_FLAG_A")

    def test_add_rejects_an_already_used_value(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        with pytest.raises(data_types.DuplicateValueError) as caught:
            data_types.add_value(conn, data_type_id, name="NP_FLAG_X", value=1)
        assert "NP_FLAG_B" in str(caught.value)

    def test_add_rejects_a_bad_literal(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        with pytest.raises(data_types.InvalidValueError):
            data_types.add_value(conn, data_type_id, name="NP_FLAG_X", value="twenty")

    def test_add_on_a_non_enum_is_refused(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidValueError):
            data_types.add_value(conn, data_type_id, name="X")

    def test_update_renames_and_revalues(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        row = data_types.update_value(
            conn, data_type_id, name="NP_FLAG_B", new_name="NP_FLAG_BS", new_value="0x40"
        )
        assert row["values"][1] == {"name": "NP_FLAG_BS", "value": 64, "hex": "0x40"}

    def test_update_by_index(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        row = data_types.update_value(conn, data_type_id, index=0, new_value=-1)
        assert row["values"][0]["value"] == -1
        assert row["values"][0]["hex"] == "-0x1"

    def test_update_refuses_a_duplicate_name_and_value(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        with pytest.raises(data_types.DuplicateValueError):
            data_types.update_value(conn, data_type_id, index=1, new_name="NP_FLAG_A")
        with pytest.raises(data_types.DuplicateValueError):
            data_types.update_value(conn, data_type_id, index=1, new_value=0)

    def test_update_needs_an_edit(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        with pytest.raises(data_types.InvalidValueError):
            data_types.update_value(conn, data_type_id, index=0)

    def test_remove_and_refuse_the_last_value(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        row = data_types.remove_value(conn, data_type_id, name="NP_FLAG_A")
        assert [value["name"] for value in row["values"]] == ["NP_FLAG_B"]
        with pytest.raises(data_types.EmptyStructError):
            data_types.remove_value(conn, data_type_id, index=0)

    def test_an_unknown_selector_is_refused(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        with pytest.raises(data_types.UnknownValueError):
            data_types.remove_value(conn, data_type_id, name="NP_FLAG_Z")
        with pytest.raises(data_types.UnknownValueError):
            data_types.remove_value(conn, data_type_id, index=9)

    def test_a_value_write_lands_in_history_as_a_diffable_field(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        data_types.add_value(conn, data_type_id, name="NP_FLAG_C")
        entry = data_types.list_history(conn, data_type_id)[0]
        assert [change["field"] for change in entry["changes"]] == ["values"]
        assert entry["previous"]["values"][-1]["name"] == "NP_FLAG_B"
        assert entry["current"]["values"][-1]["name"] == "NP_FLAG_C"

    def test_an_enum_value_edit_keeps_the_members_empty(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, ENUM_DEFINITION)
        row = data_types.add_value(conn, data_type_id, name="NP_FLAG_C")
        assert row["members"] == []
        assert row["size"] == data_types.ENUM_SIZE


class TestEditValidation:
    def test_a_non_integer_size_is_refused(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidSizeError):
            data_types.set_size(conn, data_type_id, size=True)

    def test_a_non_integer_count_is_refused(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.update_member(conn, data_type_id, index=1, new_count="4")  # type: ignore[arg-type]
        with pytest.raises(data_types.InvalidMemberError):
            data_types.update_member(conn, data_type_id, index=1, new_count=-1)

    def test_an_explicit_null_pointer_flag_clears_it(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        row = data_types.update_member(conn, data_type_id, index=1, new_pointer=True)
        assert row["members"][1]["pointer"] is True
        row = data_types.update_member(conn, data_type_id, index=1, new_pointer=None)
        assert row["members"][1]["pointer"] is False
        # An omitted flag leaves the field as it is.
        row = data_types.update_member(conn, data_type_id, index=1, new_name="count")
        assert row["members"][1]["pointer"] is False

    def test_value_edits_need_an_enum(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id)
        with pytest.raises(data_types.InvalidValueError):
            data_types.update_value(conn, data_type_id, index=0, new_value=1)
        with pytest.raises(data_types.InvalidValueError):
            data_types.remove_value(conn, data_type_id, index=0)

    def test_size_check_covers_a_non_struct_kind(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _store_parsed(conn, binary_id, "typedef int Rows[4];\n")
        row = data_types.get_type(conn, data_type_id)
        assert row is not None
        assert data_types.size_check(row)["warning"] is None
        assert data_types.member_extent(row) == row["size"] == 16


class TestParseValue:
    def test_reads_decimal_hex_and_integers(self) -> None:
        assert data_types.parse_value(31) == 31
        assert data_types.parse_value("31") == 31
        assert data_types.parse_value(" 0x1F ") == 31
        assert data_types.parse_value("-2") == -2

    def test_refuses_a_non_literal(self) -> None:
        with pytest.raises(data_types.InvalidValueError):
            data_types.parse_value("twenty")
        with pytest.raises(data_types.InvalidValueError):
            data_types.parse_value("")
        with pytest.raises(data_types.InvalidValueError):
            data_types.parse_value(True)
        with pytest.raises(data_types.InvalidValueError):
            data_types.parse_value(1.5)


def test_export_carries_an_explicit_gap(tmp_path: Path, conn: sqlite3.Connection) -> None:
    binary_id = _seed_binary(conn)
    data_type_id = _make_type(conn, binary_id)
    data_types.convert_to_gap(conn, data_type_id, name="field_C")
    target = tmp_path / "types.h"
    data_types.export_header(conn, binary_id=binary_id, path=target)
    header = target.read_text(encoding="utf-8")
    assert "\tchar gap_0008[4];" in header
    assert data_type_id > 0

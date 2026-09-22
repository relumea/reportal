"""Tests for reportal.data_types: parsing, editing, rendering and export."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from reportal import data_types, store

DEFINITION = (
    "typedef struct PlayerInfo_s {\n\tchar gap_0000[0x17];\n\tint field_C;\n} PlayerInfo;\n"
)


def _seed_binary(conn: sqlite3.Connection, *, sha256: str = "ab" * 32) -> int:
    return store.add_binary(conn, sha256=sha256, name="demo.exe")


def _seed_scan(conn: sqlite3.Connection, binary_id: int, structs: list[dict[str, object]]) -> None:
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_STRUCTS,
        {"decompiled": 1, "skipped": 0, "structs": structs},
    )


def _entry(name: str, definition: str) -> dict[str, object]:
    return {"name": name, "va": 0x1000, "definition": definition}


def _make_type(
    conn: sqlite3.Connection,
    binary_id: int,
    definition: str,
    *,
    source: str = data_types.SOURCE_SCAN,
) -> int:
    parsed = data_types.parse_definition(definition)
    return store.add_data_type(
        conn,
        binary_id=binary_id,
        name=parsed["name"],
        size=parsed["size"],
        members=parsed["members"],
        source=source,
    )


class TestParseDefinition:
    def test_parses_scalar_and_array_members(self) -> None:
        parsed = data_types.parse_definition(DEFINITION)
        assert parsed["name"] == "PlayerInfo"
        assert parsed["size"] == 0x17 + 4
        members = parsed["members"]
        assert [(m["name"], m["type"], m["offset"], m["size"]) for m in members] == [
            ("gap_0000", "char", 0, 0x17),
            ("field_C", "int", 0x17, 4),
        ]
        assert members[0]["count"] == 0x17
        assert members[1]["count"] is None

    def test_array_multiplies_the_element_size(self) -> None:
        parsed = data_types.parse_definition("typedef struct T_s {\n\tint rows[4];\n} T;\n")
        assert parsed["members"][0]["size"] == 16
        assert parsed["size"] == 16

    def test_pointer_member_is_four_bytes(self) -> None:
        parsed = data_types.parse_definition("typedef struct T_s {\n\tvoid *next;\n} T;\n")
        member = parsed["members"][0]
        assert member["pointer"] is True
        assert member["size"] == data_types.POINTER_SIZE

    def test_unknown_type_is_size_zero_with_a_note(self) -> None:
        parsed = data_types.parse_definition("typedef struct T_s {\n\tWindowInfo field_0;\n} T;\n")
        member = parsed["members"][0]
        assert member["size"] == 0
        assert "unknown type" in member["note"]

    def test_offsets_run_across_members(self) -> None:
        definition = "typedef struct T_s {\n\tchar a;\n\tshort b;\n\tint c;\n\tdouble d;\n} T;\n"
        parsed = data_types.parse_definition(definition)
        assert [member["offset"] for member in parsed["members"]] == [0, 1, 3, 7]
        assert parsed["size"] == 15

    def test_malformed_definition_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError):
            data_types.parse_definition("struct Foo { int a; };")

    def test_member_without_a_semicolon_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError):
            data_types.parse_definition("typedef struct T_s {\n\tint a\n} T;\n")

    def test_duplicate_member_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError):
            data_types.parse_definition("typedef struct T_s {\n\tint a;\n\tint a;\n} T;\n")

    def test_parse_member_type_reads_pointer_and_array(self) -> None:
        assert data_types.parse_member_type("unsigned int") == ("unsigned int", False, None)
        assert data_types.parse_member_type("void *") == ("void", True, None)
        assert data_types.parse_member_type("char[16]") == ("char", False, 16)

    def test_parse_member_type_rejects_a_non_type(self) -> None:
        with pytest.raises(data_types.InvalidMemberError):
            data_types.parse_member_type("1234")


class TestImportTypes:
    def test_creates_a_type_from_the_stored_scan(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_scan(conn, binary_id, [_entry("PlayerInfo", DEFINITION)])
        summary = data_types.import_types(conn, binary_id=binary_id)
        assert summary == {
            "binary_id": binary_id,
            "created": 1,
            "updated": 0,
            "skipped": 0,
            "skipped_types": [],
        }
        model = data_types.list_types(conn, binary_id=binary_id)
        assert [row["name"] for row in model] == ["PlayerInfo"]
        assert model[0]["size"] == 0x17 + 4
        assert model[0]["source"] == data_types.SOURCE_SCAN

    def test_updates_an_existing_type(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_scan(conn, binary_id, [_entry("PlayerInfo", DEFINITION)])
        data_types.import_types(conn, binary_id=binary_id)
        shorter = "typedef struct PlayerInfo_s {\n\tint field_0;\n} PlayerInfo;\n"
        _seed_scan(conn, binary_id, [_entry("PlayerInfo", shorter)])
        summary = data_types.import_types(conn, binary_id=binary_id)
        assert summary["created"] == 0
        assert summary["updated"] == 1
        assert data_types.list_types(conn, binary_id=binary_id)[0]["size"] == 4

    def test_skips_a_malformed_definition_with_a_reason(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _seed_scan(
            conn,
            binary_id,
            [
                _entry("Good", "typedef struct Good_s {\n\tint a;\n} Good;\n"),
                _entry("Bad", "int not_a_struct;"),
            ],
        )
        summary = data_types.import_types(conn, binary_id=binary_id)
        assert summary["created"] == 1
        assert summary["skipped"] == 1
        assert summary["skipped_types"][0]["name"] == "Bad"
        assert summary["skipped_types"][0]["reason"]

    def test_without_a_stored_scan_raises_no_scan(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        with pytest.raises(data_types.NoScanError):
            data_types.import_types(conn, binary_id=binary_id)


class TestEdits:
    def test_rename_type(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        row = data_types.rename_type(conn, data_type_id, name="Player")
        assert row["name"] == "Player"
        assert row["source"] == data_types.SOURCE_MANUAL

    def test_rename_rejects_a_bad_identifier(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        with pytest.raises(data_types.InvalidIdentifierError):
            data_types.rename_type(conn, data_type_id, name="9lives")

    def test_identifiers_collapse_nfd_to_nfc(self, conn: sqlite3.Connection) -> None:
        nfc = "caf\u00e9"
        nfd = "cafe\u0301"
        assert nfc != nfd
        assert data_types.validate_identifier(nfd) == nfc
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        row = data_types.rename_type(conn, data_type_id, name=nfd)
        assert row["name"] == nfc
        other = _make_type(conn, binary_id, "typedef struct Other_s {\n\tint a;\n} Other;\n")
        with pytest.raises(data_types.DuplicateNameError):
            data_types.rename_type(conn, other, name=nfc)

    def test_rename_rejects_a_duplicate_name(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id, DEFINITION)
        other = _make_type(conn, binary_id, "typedef struct Other_s {\n\tint a;\n} Other;\n")
        with pytest.raises(data_types.DuplicateNameError):
            data_types.rename_type(conn, other, name="PlayerInfo")

    def test_update_member_renames_and_recomputes(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        row = data_types.update_member(conn, data_type_id, name="field_C", new_name="count")
        assert [member["name"] for member in row["members"]] == ["gap_0000", "count"]
        assert [member["offset"] for member in row["members"]] == [0, 0x17]
        assert row["size"] == 0x17 + 4

    def test_update_member_retypes_and_recomputes_size(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        row = data_types.update_member(conn, data_type_id, name="field_C", new_type="short")
        assert row["members"][1]["type"] == "short"
        assert row["members"][1]["size"] == 2
        assert row["size"] == 0x17 + 2

    def test_update_member_by_index(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        row = data_types.update_member(conn, data_type_id, index=0, new_type="char[8]")
        assert row["members"][0]["size"] == 8
        assert row["members"][1]["offset"] == 8

    def test_update_member_rejects_a_duplicate_name(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        with pytest.raises(data_types.DuplicateMemberError):
            data_types.update_member(conn, data_type_id, index=1, new_name="gap_0000")

    def test_update_member_without_an_edit_is_rejected(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        with pytest.raises(data_types.InvalidMemberError):
            data_types.update_member(conn, data_type_id, name="field_C")

    def test_update_member_needs_exactly_one_selector(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        with pytest.raises(data_types.InvalidMemberError, match="no member selector"):
            data_types.update_member(conn, data_type_id, new_name="x")
        with pytest.raises(data_types.InvalidMemberError, match="exclusive"):
            data_types.update_member(conn, data_type_id, name="field_C", index=1, new_name="x")

    def test_add_member_appends_at_the_total_size(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        row = data_types.add_member(conn, data_type_id, name="flags", type_text="unsigned int")
        assert row["members"][-1]["name"] == "flags"
        assert row["members"][-1]["offset"] == 0x17 + 4
        assert row["size"] == 0x17 + 8

    def test_add_member_rejects_a_duplicate(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        with pytest.raises(data_types.DuplicateMemberError):
            data_types.add_member(conn, data_type_id, name="field_C", type_text="int")

    def test_remove_member_recomputes_offsets(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        row = data_types.remove_member(conn, data_type_id, name="gap_0000")
        assert [member["name"] for member in row["members"]] == ["field_C"]
        assert row["members"][0]["offset"] == 0
        assert row["size"] == 4

    def test_remove_last_member_is_rejected(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, "typedef struct One_s {\n\tint a;\n} One;\n")
        with pytest.raises(data_types.EmptyStructError):
            data_types.remove_member(conn, data_type_id, index=0)

    def test_unknown_id_and_member_raise(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        with pytest.raises(data_types.UnknownDataTypeError):
            data_types.rename_type(conn, 4242, name="Nope")
        with pytest.raises(data_types.UnknownMemberError):
            data_types.remove_member(conn, data_type_id, name="missing")

    def test_delete_type(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        assert data_types.delete_type(conn, data_type_id) is True
        assert data_types.delete_type(conn, data_type_id) is False


class TestRenderHeader:
    def test_renders_pragma_once_and_a_size_comment(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        data_type_id = _make_type(conn, binary_id, DEFINITION)
        header = data_types.render_header(data_types.list_types(conn, binary_id=binary_id))
        assert header.startswith("#pragma once\n")
        assert "typedef struct PlayerInfo_s {" in header
        assert "\tchar gap_0000[23];" in header
        assert "\tint field_C;" in header
        assert "} PlayerInfo; /* size 27 */" in header
        assert header.isascii()
        assert data_type_id > 0

    def test_is_deterministic_and_orders_by_name_and_offset(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id, "typedef struct Zed_s {\n\tint b;\n\tint a;\n} Zed;\n")
        _make_type(conn, binary_id, "typedef struct Alpha_s {\n\tint a;\n} Alpha;\n")
        model = data_types.list_types(conn, binary_id=binary_id)
        first = data_types.render_header(model)
        assert first == data_types.render_header(list(reversed(model)))
        assert first.index("Alpha_s") < first.index("Zed_s")
        assert first.index("} Zed;") > 0


class TestExportHeader:
    def test_writes_the_rendered_header(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id, DEFINITION)
        target = tmp_path / "types.h"
        summary = data_types.export_header(conn, binary_id=binary_id, path=target)
        assert summary["path"] == str(target)
        assert summary["types"] == 1
        written = target.read_text(encoding="utf-8")
        assert summary["bytes"] == len(written.encode("utf-8"))
        assert "PlayerInfo" in written

    def test_refuses_an_existing_target_without_force(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id, DEFINITION)
        target = tmp_path / "types.h"
        target.write_text("original", encoding="utf-8")
        with pytest.raises(data_types.ExportExistsError):
            data_types.export_header(conn, binary_id=binary_id, path=target)
        assert target.read_text(encoding="utf-8") == "original"

    def test_overwrites_with_force(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id, DEFINITION)
        target = tmp_path / "types.h"
        target.write_text("original", encoding="utf-8")
        data_types.export_header(conn, binary_id=binary_id, path=target, force=True)
        assert "PlayerInfo" in target.read_text(encoding="utf-8")

    def test_refuses_a_missing_parent_that_cannot_be_created(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id, DEFINITION)
        target = tmp_path / "missing" / "nested" / "types.h"
        with pytest.raises(data_types.ExportParentMissingError):
            data_types.export_header(conn, binary_id=binary_id, path=target)
        assert not target.exists()

    def test_creates_a_missing_parent_when_its_parent_exists(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id, DEFINITION)
        target = tmp_path / "out" / "types.h"
        summary = data_types.export_header(conn, binary_id=binary_id, path=target)
        assert Path(summary["path"]).is_file()

    def test_interrupt_during_write_removes_the_temp(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed_binary(conn)
        _make_type(conn, binary_id, DEFINITION)
        target = tmp_path / "types.h"
        real_fdopen = os.fdopen

        def boom(fd: int, *args: object, **kwargs: object) -> object:
            handle = real_fdopen(fd, *args, **kwargs)  # type: ignore[call-overload]

            def write(_data: object) -> int:
                raise KeyboardInterrupt

            handle.write = write
            return handle

        monkeypatch.setattr(os, "fdopen", boom)
        with pytest.raises(KeyboardInterrupt):
            data_types.export_header(conn, binary_id=binary_id, path=target)
        assert list(tmp_path.glob(".types-*")) == []
        assert not target.exists()


class TestDefinitionEdges:
    def test_bad_width_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="unsupported member"):
            data_types.parse_definition("typedef struct T_s {\n\tint:xx a;\n} T;\n")

    def test_bad_member_name_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="unsupported member"):
            data_types.parse_definition("typedef struct T_s {\n\tint 9lives;\n} T;\n")

    def test_bad_member_type_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="unsupported member"):
            data_types.parse_definition("typedef struct T_s {\n\tint! a;\n} T;\n")

    def test_double_array_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="unsupported member"):
            data_types.parse_definition("typedef struct T_s {\n\tint a[4][4];\n} T;\n")

    def test_bad_integer_literal_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="not an integer"):
            data_types.parse_definition("typedef enum E {\n\tA = xyz,\n} E;\n")

    def test_bad_enum_name_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="unsupported enum"):
            data_types.parse_definition("typedef enum E {\n\t9lives = 1,\n} E;\n")

    def test_duplicate_enum_name_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="duplicate enum"):
            data_types.parse_definition("typedef enum E {\n\tA = 1,\n\tA = 2,\n} E;\n")


class TestTypedefEdges:
    def test_bad_return_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="return"):
            data_types.parse_definition("typedef int! (*cb)(int);")

    def test_array_return_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="array"):
            data_types.parse_definition("typedef int[4] (*cb)(int);")

    def test_unsized_typedef_array_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="sized"):
            data_types.parse_definition("typedef int arr[];")

    def test_bad_typedef_type_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="not a type"):
            data_types.parse_definition("typedef int! myint;")

    def test_not_a_typedef_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="not a typedef"):
            data_types.parse_definition("int x;")


class TestMoreDefinitionEdges:
    def test_double_dimensioned_member_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="unsupported member"):
            data_types.parse_definition("typedef struct T_s {\n\tint[2] a[3];\n} T;\n")

    def test_empty_function_parameter_is_rejected(self) -> None:
        with pytest.raises(data_types.DefinitionError, match="empty function-type"):
            data_types.parse_definition("typedef void (*cb)(int,, char);")

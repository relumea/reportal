"""Tests for reportal.signatures: parsing, seeding, editing, rendering, export."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from reportal import signatures, store

PLAIN = "unsigned int sub_1005640(unsigned int a0, unsigned int a1)\n{\n  return 0;\n}\n"
STDCALL = "int __stdcall NpGetDefaultPrinterDC(void)\n{\n  return 0;\n}\n"
POINTER = "char *sub_1000(int count)\n{\n  return 0;\n}\n"
VOID = "void FUN_10006c00(void)\n{\n  return;\n}\n"
ARRAY = "void sub_1000(char buf[16])\n{\n  return;\n}\n"
UNPARSABLE = "// just a comment\n{ return; }\n"


def _seed_binary(conn: sqlite3.Connection, *, sha256: str = "ab" * 32) -> int:
    return store.add_binary(conn, sha256=sha256, name="demo.exe")


def _seed_function(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    va: int = 0x1000,
    name: str = "sub_1000",
    code: str | None = None,
) -> int:
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=va, name=name, size=16, status="STUB"
    )
    if code is not None:
        store.set_decompilation(conn, function_id, code, "kuna")
    return function_id


def _seeded(conn: sqlite3.Connection, code: str = PLAIN) -> tuple[int, int]:
    binary_id = _seed_binary(conn)
    function_id = _seed_function(conn, binary_id, code=code)
    signatures.seed_signatures(conn, binary_id=binary_id)
    return binary_id, function_id


class TestParseSignature:
    def test_parses_a_plain_declaration(self) -> None:
        parsed = signatures.parse_signature(PLAIN)
        assert parsed is not None
        assert parsed["name"] == "sub_1005640"
        assert parsed["return_type"] == "unsigned int"
        assert parsed["calling_convention"] == ""
        assert parsed["parameters"] == [
            {
                "index": 0,
                "type": "unsigned int",
                "name": "a0",
                "at": None,
                "kind": None,
                "bits": None,
            },
            {
                "index": 1,
                "type": "unsigned int",
                "name": "a1",
                "at": None,
                "kind": None,
                "bits": None,
            },
        ]

    def test_parses_a_stdcall_declaration(self) -> None:
        parsed = signatures.parse_signature(STDCALL)
        assert parsed is not None
        assert parsed["name"] == "NpGetDefaultPrinterDC"
        assert parsed["return_type"] == "int"
        assert parsed["calling_convention"] == "stdcall"
        assert parsed["parameters"] == []

    def test_parses_a_pointer_return(self) -> None:
        parsed = signatures.parse_signature(POINTER)
        assert parsed is not None
        assert parsed["return_type"] == "char *"
        assert parsed["parameters"] == [
            {"index": 0, "type": "int", "name": "count", "at": None, "kind": None, "bits": None}
        ]

    def test_void_parameter_means_none(self) -> None:
        parsed = signatures.parse_signature(VOID)
        assert parsed is not None
        assert parsed["parameters"] == []

    def test_parses_an_array_parameter(self) -> None:
        parsed = signatures.parse_signature(ARRAY)
        assert parsed is not None
        assert parsed["parameters"] == [
            {"index": 0, "type": "char[16]", "name": "buf", "at": None, "kind": None, "bits": None}
        ]

    def test_skips_leading_comment_lines(self) -> None:
        parsed = signatures.parse_signature("// note\n" + VOID)
        assert parsed is not None
        assert parsed["name"] == "FUN_10006c00"

    def test_a_malformed_line_returns_none(self) -> None:
        assert signatures.parse_signature("this is not a signature") is None
        assert signatures.parse_signature("if (x > 0) {\n  return;\n}") is None
        assert signatures.parse_signature("void sub_1000(void) trailing") is None
        assert signatures.parse_signature("") is None

    def test_an_unnamed_parameter_keeps_an_empty_name(self) -> None:
        parsed = signatures.parse_signature("void sub_1000(int, char *)")
        assert parsed is not None
        assert [(p["type"], p["name"]) for p in parsed["parameters"]] == [
            ("int", ""),
            ("char *", ""),
        ]


class TestSeedSignatures:
    def test_creates_a_signature_from_the_decompilation(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        function_id = _seed_function(conn, binary_id, code=PLAIN)
        summary = signatures.seed_signatures(conn, binary_id=binary_id)
        assert summary == {
            "binary_id": binary_id,
            "created": 1,
            "updated": 0,
            "skipped": 0,
            "skipped_functions": [],
        }
        row = signatures.get_signature(conn, function_id)
        assert row is not None
        assert row["name"] == "sub_1005640"
        assert row["source"] == signatures.SOURCE_DECOMPILATION

    def test_updates_an_existing_signature(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        function_id = _seed_function(conn, binary_id, code=PLAIN)
        signatures.seed_signatures(conn, binary_id=binary_id)
        store.set_decompilation(conn, function_id, VOID, "kuna")
        summary = signatures.seed_signatures(conn, binary_id=binary_id)
        assert summary["created"] == 0
        assert summary["updated"] == 1
        row = signatures.get_signature(conn, function_id)
        assert row is not None
        assert row["return_type"] == "void"

    def test_skips_an_unparsable_decompilation(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        good = _seed_function(conn, binary_id, va=0x1000, code=PLAIN)
        _seed_function(conn, binary_id, va=0x2000, name="bad", code=UNPARSABLE)
        summary = signatures.seed_signatures(conn, binary_id=binary_id)
        assert summary["created"] == 1
        assert summary["skipped"] == 1
        assert summary["skipped_functions"][0]["name"] == "bad"
        assert summary["skipped_functions"][0]["reason"]
        assert signatures.get_signature(conn, good) is not None

    def test_ignores_a_function_without_a_decompilation(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        function_id = _seed_function(conn, binary_id, code=None)
        summary = signatures.seed_signatures(conn, binary_id=binary_id)
        assert summary["created"] == 0
        assert summary["skipped"] == 0
        assert signatures.get_signature(conn, function_id) is None


class TestEdits:
    def test_set_return_type(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.set_return_type(conn, function_id, return_type="int")
        assert row["return_type"] == "int"
        assert row["source"] == signatures.SOURCE_MANUAL

    def test_set_return_type_rejects_an_empty_type(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.InvalidTypeError):
            signatures.set_return_type(conn, function_id, return_type="   ")
        with pytest.raises(signatures.InvalidTypeError):
            signatures.set_return_type(conn, function_id, return_type="1bad")

    def test_set_calling_convention(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.set_calling_convention(conn, function_id, calling_convention="__stdcall")
        assert row["calling_convention"] == "stdcall"
        assert signatures.render_prototype(row).startswith("unsigned int __stdcall")

    def test_set_calling_convention_rejects_an_unknown_one(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.InvalidTypeError):
            signatures.set_calling_convention(conn, function_id, calling_convention="pascal")

    def test_set_parameter_type_and_name(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.set_parameter(conn, function_id, index=0, type_text="char *", name="path")
        assert row["parameters"][0] == {
            "index": 0,
            "type": "char *",
            "name": "path",
            "at": None,
            "kind": None,
            "bits": None,
        }
        assert row["parameters"][1]["index"] == 1

    def test_set_parameter_rejects_a_bad_identifier(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.InvalidIdentifierError):
            signatures.set_parameter(conn, function_id, index=0, name="9lives")

    def test_set_parameter_rejects_an_empty_type(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.InvalidTypeError):
            signatures.set_parameter(conn, function_id, index=0, type_text="")

    def test_set_parameter_rejects_a_duplicate_name(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.DuplicateParameterError):
            signatures.set_parameter(conn, function_id, index=1, name="a0")

    def test_set_parameter_rejects_an_out_of_range_index(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.UnknownParameterError):
            signatures.set_parameter(conn, function_id, index=5, name="x")
        with pytest.raises(signatures.UnknownParameterError):
            signatures.set_parameter(conn, function_id, index=-1, name="x")

    def test_set_parameter_without_an_edit_is_rejected(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.InvalidParameterError):
            signatures.set_parameter(conn, function_id, index=0)

    def test_add_parameter_appends_and_reindexes(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.add_parameter(conn, function_id, type_text="char *", name="buffer")
        assert [p["index"] for p in row["parameters"]] == [0, 1, 2]
        assert row["parameters"][2] == {
            "index": 2,
            "type": "char *",
            "name": "buffer",
            "at": None,
            "kind": None,
            "bits": None,
        }

    def test_add_parameter_at_an_index_shifts_the_rest(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.add_parameter(conn, function_id, type_text="int", name="count", index=1)
        assert [p["name"] for p in row["parameters"]] == ["a0", "count", "a1"]
        assert [p["index"] for p in row["parameters"]] == [0, 1, 2]

    def test_add_parameter_rejects_a_duplicate_name(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.DuplicateParameterError):
            signatures.add_parameter(conn, function_id, type_text="int", name="a0")

    def test_add_parameter_rejects_an_out_of_range_index(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.UnknownParameterError):
            signatures.add_parameter(conn, function_id, type_text="int", index=9)

    def test_remove_parameter_reindexes(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.remove_parameter(conn, function_id, index=0)
        assert [p["name"] for p in row["parameters"]] == ["a1"]
        assert row["parameters"][0]["index"] == 0

    def test_remove_parameter_rejects_an_out_of_range_index(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.UnknownParameterError):
            signatures.remove_parameter(conn, function_id, index=2)

    def test_unknown_signature_raises(self, conn: sqlite3.Connection) -> None:
        binary_id = _seed_binary(conn)
        function_id = _seed_function(conn, binary_id, code=PLAIN)
        with pytest.raises(signatures.UnknownSignatureError):
            signatures.set_return_type(conn, function_id, return_type="int")

    def test_delete_signature(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        assert signatures.delete_signature(conn, function_id) is True
        assert signatures.delete_signature(conn, function_id) is False


class TestParameterFields:
    def test_fields_round_trip_through_store_and_payload(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.set_parameter(
            conn, function_id, index=0, at="ecx", kind="pointer", bits=32
        )
        parameter = row["parameters"][0]
        assert parameter["at"] == "ecx"
        assert parameter["kind"] == "pointer"
        assert parameter["bits"] == 32
        # The same values read back through the public getter.
        loaded = signatures.get_signature(conn, function_id)
        assert loaded is not None
        assert loaded["parameters"][0]["at"] == "ecx"
        assert loaded["parameters"][0]["kind"] == "pointer"
        assert loaded["parameters"][0]["bits"] == 32

    def test_absent_fields_stay_null(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.set_return_type(conn, function_id, return_type="int")
        parameter = row["parameters"][0]
        assert parameter["at"] is None
        assert parameter["kind"] is None
        assert parameter["bits"] is None
        # An absent arrival location is not claimed by the rendered prototype.
        assert "at " not in signatures.render_prototype(row)

    def test_a_field_can_be_cleared_with_an_explicit_none(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        signatures.set_parameter(conn, function_id, index=0, at="[esp+4]", kind="value")
        row = signatures.set_parameter(conn, function_id, index=0, at=None, kind=None)
        assert row["parameters"][0]["at"] is None
        assert row["parameters"][0]["kind"] is None

    def test_add_parameter_stores_the_fields(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        row = signatures.add_parameter(
            conn, function_id, type_text="char *", name="buffer", kind="pointer", bits=32
        )
        added = row["parameters"][2]
        assert added["kind"] == "pointer"
        assert added["bits"] == 32
        assert added["at"] is None

    def test_default_at_reads_the_convention_table(self) -> None:
        assert signatures.default_at("cdecl", 0) == "[esp+4]"
        assert signatures.default_at("stdcall", 1) == "[esp+8]"
        assert signatures.default_at("fastcall", 0) == "ecx"
        assert signatures.default_at("fastcall", 1) == "edx"
        assert signatures.default_at("fastcall", 2) == "[esp+4]"
        assert signatures.default_at("thiscall", 0) == "ecx"
        assert signatures.default_at("thiscall", 1) == "[esp+4]"
        # An unknown convention has no location to name.
        assert signatures.default_at("", 0) is None
        assert signatures.default_at("pascal", 0) is None

    def test_move_recomputes_the_arrival_locations(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        signatures.set_calling_convention(conn, function_id, calling_convention="cdecl")
        signatures.set_parameter(conn, function_id, index=0, at="[esp+4]")
        signatures.set_parameter(conn, function_id, index=1, at="[esp+8]")
        row = signatures.move_parameter(conn, function_id, index=1, to_index=0)
        # The moved parameter now sits first and its slot follows the order.
        assert [parameter["name"] for parameter in row["parameters"]] == ["a1", "a0"]
        assert [parameter["at"] for parameter in row["parameters"]] == ["[esp+4]", "[esp+8]"]

    def test_move_leaves_an_underivable_location_alone(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        # No calling convention, so the table cannot place the argument.
        signatures.set_parameter(conn, function_id, index=0, at="[ebp-8]")
        row = signatures.move_parameter(conn, function_id, index=0, to_index=1)
        assert row["parameters"][1]["at"] == "[ebp-8]"

    def test_move_keeps_an_absent_location_absent(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        signatures.set_calling_convention(conn, function_id, calling_convention="cdecl")
        row = signatures.move_parameter(conn, function_id, index=0, to_index=1)
        assert [parameter["at"] for parameter in row["parameters"]] == [None, None]

    def test_move_by_the_same_index_is_a_no_op(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        before = signatures.get_signature(conn, function_id)
        history = signatures.list_history(conn, function_id)
        row = signatures.move_parameter(conn, function_id, index=0, to_index=0)
        assert row == before
        assert signatures.list_history(conn, function_id) == history

    def test_move_rejects_an_out_of_range_index(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.UnknownParameterError):
            signatures.move_parameter(conn, function_id, index=0, to_index=5)

    def test_an_unparsable_location_is_rejected(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.InvalidTypeError):
            signatures.set_parameter(conn, function_id, index=0, at="the third thing")

    def test_an_unknown_kind_is_rejected(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.InvalidTypeError):
            signatures.set_parameter(conn, function_id, index=0, kind="quantum")

    def test_an_out_of_range_width_is_rejected(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seeded(conn)
        with pytest.raises(signatures.InvalidTypeError):
            signatures.set_parameter(conn, function_id, index=0, bits=0)
        with pytest.raises(signatures.InvalidTypeError):
            signatures.set_parameter(
                conn, function_id, index=0, bits=signatures.MAX_PARAMETER_BITS + 1
            )


class TestRenderAnnotations:
    def test_a_prototype_annotates_only_the_fields_it_has(self) -> None:
        signature = {
            "name": "read",
            "return_type": "int",
            "calling_convention": "stdcall",
            "parameters": [
                {
                    "index": 0,
                    "type": "char *",
                    "name": "path",
                    "at": "ecx",
                    "kind": "pointer",
                    "bits": 32,
                },
                {"index": 1, "type": "unsigned int", "name": "length"},
            ],
        }
        assert signatures.render_prototype(signature) == (
            "int __stdcall read(char * path /* at ecx, kind pointer, 32 bits */,"
            " unsigned int length);"
        )

    def test_render_prototypes_omits_an_absent_field(self) -> None:
        header = signatures.render_prototypes(
            [
                {
                    "function_id": 1,
                    "name": "one",
                    "return_type": "int",
                    "calling_convention": "",
                    "parameters": [{"index": 0, "type": "int", "name": "a", "kind": "value"}],
                },
                {
                    "function_id": 2,
                    "name": "two",
                    "return_type": "void",
                    "calling_convention": "",
                    "parameters": [{"index": 0, "type": "int", "name": "b"}],
                },
            ]
        )
        assert "int one(int a /* kind value */);" in header
        assert "void two(int b);" in header
        assert header.count("/*") == 1


class TestRender:
    def test_render_prototype_formats_head_convention_and_parameters(self) -> None:
        signature = {
            "name": "sub_1000",
            "return_type": "char *",
            "calling_convention": "stdcall",
            "parameters": [
                {"index": 0, "type": "unsigned int", "name": "a0"},
                {"index": 1, "type": "char *", "name": ""},
            ],
        }
        assert signatures.render_prototype(signature) == (
            "char * __stdcall sub_1000(unsigned int a0, char *);"
        )

    def test_render_prototype_void_and_array(self) -> None:
        empty = {
            "name": "reset",
            "return_type": "void",
            "calling_convention": "",
            "parameters": [],
        }
        assert signatures.render_prototype(empty) == "void reset(void);"
        array = {
            "name": "fill",
            "return_type": "void",
            "calling_convention": "",
            "parameters": [{"index": 0, "type": "char[16]", "name": "buf"}],
        }
        assert signatures.render_prototype(array) == "void fill(char buf[16]);"

    def test_render_prototypes_is_deterministic_and_orders_by_name(
        self, conn: sqlite3.Connection
    ) -> None:
        binary_id = _seed_binary(conn)
        _seed_function(conn, binary_id, va=0x1000, name="zeta", code=VOID)
        _seed_function(conn, binary_id, va=0x2000, name="alpha", code=PLAIN)
        signatures.seed_signatures(conn, binary_id=binary_id)
        model = signatures.list_signatures(conn, binary_id=binary_id)
        header = signatures.render_prototypes(model)
        assert header == signatures.render_prototypes(list(reversed(model)))
        assert header.startswith("#pragma once\n")
        assert header.index("FUN_10006c00") < header.index("sub_1005640")
        assert header.endswith(";\n")


class TestExportPrototypes:
    def test_writes_the_rendered_header(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, _ = _seeded(conn)
        target = tmp_path / "prototypes.h"
        summary = signatures.export_prototypes(conn, binary_id=binary_id, path=target)
        assert summary["path"] == str(target)
        assert summary["signatures"] == 1
        written = target.read_text(encoding="utf-8")
        assert summary["bytes"] == len(written.encode("utf-8"))
        assert "sub_1005640" in written

    def test_refuses_an_existing_target_without_force(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = _seeded(conn)
        target = tmp_path / "prototypes.h"
        target.write_text("original", encoding="utf-8")
        with pytest.raises(signatures.ExportExistsError):
            signatures.export_prototypes(conn, binary_id=binary_id, path=target)
        assert target.read_text(encoding="utf-8") == "original"

    def test_overwrites_with_force(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, _ = _seeded(conn)
        target = tmp_path / "prototypes.h"
        target.write_text("original", encoding="utf-8")
        signatures.export_prototypes(conn, binary_id=binary_id, path=target, force=True)
        assert "sub_1005640" in target.read_text(encoding="utf-8")

    def test_refuses_a_missing_parent_that_cannot_be_created(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = _seeded(conn)
        target = tmp_path / "missing" / "nested" / "prototypes.h"
        with pytest.raises(signatures.ExportParentMissingError):
            signatures.export_prototypes(conn, binary_id=binary_id, path=target)
        assert not target.exists()

    def test_creates_a_missing_parent_when_its_parent_exists(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = _seeded(conn)
        target = tmp_path / "out" / "prototypes.h"
        summary = signatures.export_prototypes(conn, binary_id=binary_id, path=target)
        assert Path(summary["path"]).is_file()

    def test_interrupt_during_write_removes_the_temp(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id, _ = _seeded(conn)
        target = tmp_path / "prototypes.h"
        real_fdopen = os.fdopen

        def boom(fd: int, *args: object, **kwargs: object) -> object:
            handle = real_fdopen(fd, *args, **kwargs)

            def write(_data: object) -> int:
                raise KeyboardInterrupt

            handle.write = write  # type: ignore[method-assign]
            return handle

        monkeypatch.setattr(os, "fdopen", boom)
        with pytest.raises(KeyboardInterrupt):
            signatures.export_prototypes(conn, binary_id=binary_id, path=target)
        assert list(tmp_path.glob(".signatures-*")) == []
        assert not target.exists()

"""Tests for the data-type CLI commands that edit the richer model: the member
shape and position, the kind/namespace/declared size, explicit padding and the
enum value operations.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from reportal import cli, store
from reportal._paths import DB_ENV

runner = CliRunner()

STRUCT_DEFINITION = (
    "typedef struct PlayerInfo_s {\n\tchar name[8];\n\tint field_C;\n} PlayerInfo;\n"
)
ENUM_DEFINITION = "typedef enum NPFlags_s {\n\tNP_FLAG_A = 0,\n\tNP_FLAG_B = 1\n} NPFlags;\n"


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, definition: str) -> int:
    """Create a portal DB with one binary and a stored structs scan."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_STRUCTS,
            {
                "decompiled": 1,
                "skipped": 0,
                "structs": [{"name": "x", "va": 0x1000, "definition": definition}],
            },
        )
    return binary_id


def _invoke(*args: str) -> Result:
    return runner.invoke(cli.app, list(args))


def _type_id(binary_id: int) -> int:
    result = _invoke("types", str(binary_id), "--json")
    return int(json.loads(result.stdout)["types"][0]["id"])


def _seed_struct(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    binary_id = _seed_portal(tmp_path, monkeypatch, STRUCT_DEFINITION)
    assert _invoke("types-import", str(binary_id)).exit_code == 0
    return _type_id(binary_id)


def _seed_enum(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    binary_id = _seed_portal(tmp_path, monkeypatch, ENUM_DEFINITION)
    assert _invoke("types-import", str(binary_id)).exit_code == 0
    return _type_id(binary_id)


class TestMemberCommand:
    def test_new_bits_makes_a_bitfield_and_clear_bits_drops_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke("type-member", str(data_type_id), "field_C", "--new-bits", "3", "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["members"][1]["bits"] == 3

        result = _invoke("type-member", str(data_type_id), "field_C", "--clear-bits", "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["members"][1]["bits"] is None

    def test_new_bits_and_clear_bits_are_exclusive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke(
            "type-member", str(data_type_id), "field_C", "--new-bits", "3", "--clear-bits", "--json"
        )
        assert result.exit_code == 1

    def test_pointer_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke("type-member", str(data_type_id), "field_C", "--pointer", "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["members"][1]["pointer"] is True


class TestMemberAddCommand:
    def test_add_at_an_index_and_after_a_member(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke(
            "type-member-add", str(data_type_id), "middle", "short", "--index", "1", "--json"
        )
        assert result.exit_code == 0
        assert [m["name"] for m in json.loads(result.stdout)["members"]] == [
            "name",
            "middle",
            "field_C",
        ]

        result = _invoke(
            "type-member-add", str(data_type_id), "last", "char", "--after", "field_C", "--json"
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout)["members"][-1]["name"] == "last"

    def test_add_with_bits_and_count(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke(
            "type-member-add", str(data_type_id), "flags", "unsigned int", "--bits", "3", "--json"
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout)["members"][-1]["bits"] == 3

    def test_index_and_after_together_fail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke(
            "type-member-add",
            str(data_type_id),
            "x",
            "int",
            "--index",
            "0",
            "--after",
            "name",
            "--json",
        )
        assert result.exit_code == 1


class TestGapCommands:
    def test_convert_to_a_gap_and_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke("type-member-gap", str(data_type_id), "field_C", "--json")
        assert result.exit_code == 0
        gap = json.loads(result.stdout)["members"][1]
        assert (gap["name"], gap["is_gap"]) == ("gap_0008", True)

        result = _invoke(
            "type-member-ungap", str(data_type_id), "gap_0008", "counter", "int", "--json"
        )
        assert result.exit_code == 0
        member = json.loads(result.stdout)["members"][1]
        assert (member["name"], member["type"], member["is_gap"]) == ("counter", "int", False)

    def test_a_gap_size_is_taken_from_the_option(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke("type-member-gap", str(data_type_id), "name", "--size", "16", "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["size"] == 20

    def test_ungap_needs_a_gap(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke(
            "type-member-ungap", str(data_type_id), "field_C", "counter", "int", "--json"
        )
        assert result.exit_code == 1


class TestTypeFieldCommands:
    def test_type_kind(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke("type-kind", str(data_type_id), "union", "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["kind"] == "union"

    def test_type_kind_refuses_an_unknown_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        assert _invoke("type-kind", str(data_type_id), "bitfield", "--json").exit_code == 1

    def test_type_namespace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke("type-namespace", str(data_type_id), "winnt::kernel", "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["namespace"] == "winnt::kernel"

    def test_type_size_reports_the_disagreement(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        result = _invoke("type-size", str(data_type_id), "16", "--json")
        assert result.exit_code == 0
        check = json.loads(result.stdout)["size_check"]
        assert check["declared"] == 16
        assert check["extent"] == 12
        assert "16" in check["warning"]

        result = _invoke("type-size", str(data_type_id), "16")
        assert result.exit_code == 0
        assert "disagrees" in result.output

    def test_types_prints_the_warning_and_carries_the_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_struct(tmp_path, monkeypatch)
        _invoke("type-size", str(data_type_id), "16", "--json")
        result = _invoke("types", str(_type_binary(tmp_path, monkeypatch)), "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["types"][0]["size_check"]["match"] is False


def _type_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    """The binary the seeded portal holds, for a `types` listing."""
    with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
        return int(store.list_binaries(conn)[0]["id"])


class TestValueCommands:
    def test_add_auto_increments(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_enum(tmp_path, monkeypatch)
        result = _invoke("type-value-add", str(data_type_id), "NP_FLAG_C", "--json")
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["values"][-1]["value"] == 2
        assert "auto-incremented" in payload["note"]

    def test_add_reads_a_hex_literal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_enum(tmp_path, monkeypatch)
        result = _invoke(
            "type-value-add", str(data_type_id), "NP_FLAG_X", "--value", "0x20", "--json"
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout)["values"][-1]["hex"] == "0x20"

    def test_edit_renames_and_revalues(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_enum(tmp_path, monkeypatch)
        result = _invoke(
            "type-value-edit",
            str(data_type_id),
            "NP_FLAG_B",
            "--new-name",
            "NP_FLAG_BS",
            "--new-value",
            "0x40",
            "--json",
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout)["values"][1] == {
            "name": "NP_FLAG_BS",
            "value": 64,
            "hex": "0x40",
        }

    def test_edit_needs_an_option(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_enum(tmp_path, monkeypatch)
        assert _invoke("type-value-edit", str(data_type_id), "NP_FLAG_B", "--json").exit_code == 1

    def test_remove(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data_type_id = _seed_enum(tmp_path, monkeypatch)
        result = _invoke("type-value-remove", str(data_type_id), "NP_FLAG_A", "--json")
        assert result.exit_code == 0
        assert [value["name"] for value in json.loads(result.stdout)["values"]] == ["NP_FLAG_B"]

    def test_a_duplicate_value_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data_type_id = _seed_enum(tmp_path, monkeypatch)
        result = _invoke("type-value-add", str(data_type_id), "NP_FLAG_X", "--value", "1", "--json")
        assert result.exit_code == 1

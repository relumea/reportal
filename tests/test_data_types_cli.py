"""Tests for the data-type CLI commands."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from reportal import cli, store
from reportal._paths import DB_ENV

runner = CliRunner()

DEFINITION = (
    "typedef struct PlayerInfo_s {\n\tchar gap_0000[0x17];\n\tint field_C;\n} PlayerInfo;\n"
)


def _seed_portal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_scan: bool = True
) -> dict[str, int]:
    """Create a portal DB with one binary and, optionally, a stored structs scan."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe")
        if with_scan:
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
            store.set_scan(
                conn,
                analysis_id,
                store.SCAN_KIND_STRUCTS,
                {
                    "decompiled": 1,
                    "skipped": 0,
                    "structs": [{"name": "PlayerInfo", "va": 0x1000, "definition": DEFINITION}],
                },
            )
    return {"binary": binary_id}


def _invoke(*args: str) -> Result:
    return runner.invoke(cli.app, list(args))


class TestTypesCommands:
    def test_types_lists_the_model_as_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        assert _invoke("types-import", str(ids["binary"])).exit_code == 0
        result = _invoke("types", str(ids["binary"]), "--json")
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["types"][0]["name"] == "PlayerInfo"
        assert payload["types"][0]["size"] == 0x17 + 4

    def test_types_human_output_names_the_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        _invoke("types-import", str(ids["binary"]))
        result = _invoke("types", str(ids["binary"]))
        assert result.exit_code == 0
        assert "PlayerInfo" in result.output

    def test_types_sort_by_size_puts_the_unknown_size_last(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        _invoke("types-import", str(ids["binary"]))
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.add_data_type(
                conn,
                binary_id=ids["binary"],
                name="NoSize",
                size=0,
                members=[],
                kind="typedef",
                target="unsigned int",
            )

        result = _invoke("types", str(ids["binary"]), "--sort", "size", "--json")

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["sort"] == "size"
        assert payload["direction"] == "asc"
        assert [row["name"] for row in payload["types"]] == ["PlayerInfo", "NoSize"]

    def test_types_refuses_an_unknown_sort(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)

        result = _invoke("types", str(ids["binary"]), "--sort", "weight", "--json")

        assert result.exit_code == 1
        assert "unknown type sort" in result.stdout

    def test_types_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed_portal(tmp_path, monkeypatch)
        assert _invoke("types", "4242", "--json").exit_code == 1

    def test_types_import_without_a_scan_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch, with_scan=False)
        result = _invoke("types-import", str(ids["binary"]), "--json")
        assert result.exit_code == 1

    def test_types_import_reports_counts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = _invoke("types-import", str(ids["binary"]), "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["created"] == 1


class TestTypeEditCommands:
    def test_type_rename(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        _invoke("types-import", str(ids["binary"]))
        result = _invoke("types", str(ids["binary"]), "--json")
        data_type_id = json.loads(result.stdout)["types"][0]["id"]
        result = _invoke("type-rename", str(data_type_id), "Player", "--json")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["name"] == "Player"

    def test_type_rename_rejects_a_bad_identifier(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        _invoke("types-import", str(ids["binary"]))
        result = _invoke("types", str(ids["binary"]), "--json")
        data_type_id = json.loads(result.stdout)["types"][0]["id"]
        assert _invoke("type-rename", str(data_type_id), "1bad", "--json").exit_code == 1

    def test_type_member_retypes_and_recomputes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        _invoke("types-import", str(ids["binary"]))
        result = _invoke("types", str(ids["binary"]), "--json")
        data_type_id = json.loads(result.stdout)["types"][0]["id"]
        result = _invoke(
            "type-member", str(data_type_id), "field_C", "--new-type", "short", "--json"
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["members"][1]["type"] == "short"
        assert payload["size"] == 0x17 + 2

    def test_type_member_needs_an_edit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        _invoke("types-import", str(ids["binary"]))
        result = _invoke("types", str(ids["binary"]), "--json")
        data_type_id = json.loads(result.stdout)["types"][0]["id"]
        assert _invoke("type-member", str(data_type_id), "field_C", "--json").exit_code == 1


class TestTypesExportCommand:
    def test_export_writes_the_header(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        _invoke("types-import", str(ids["binary"]))
        target = tmp_path / "out" / "types.h"
        result = _invoke("types-export", str(ids["binary"]), str(target), "--json")
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["path"] == str(target)
        assert "PlayerInfo" in target.read_text(encoding="utf-8")

    def test_export_refuses_to_overwrite_without_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        _invoke("types-import", str(ids["binary"]))
        target = tmp_path / "types.h"
        target.write_text("original", encoding="utf-8")
        assert _invoke("types-export", str(ids["binary"]), str(target), "--json").exit_code == 1
        assert (
            _invoke("types-export", str(ids["binary"]), str(target), "--force", "--json").exit_code
            == 0
        )
        assert "PlayerInfo" in target.read_text(encoding="utf-8")


class TestKindedTypesCommands:
    def _seed_enum(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        ids = _seed_portal(tmp_path, monkeypatch, with_scan=False)
        with contextlib.closing(store.connect(tmp_path / "portal.db")) as conn:
            store.add_data_type(
                conn,
                binary_id=ids["binary"],
                name="NPFlags",
                size=4,
                members=[],
                kind="enum",
                namespace="winnt",
                values=[{"name": "NP_FLAG_A", "value": 0}, {"name": "NP_FLAG_B", "value": 1}],
            )
        return ids["binary"]

    def test_types_shows_kind_namespace_and_enum_values(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed_enum(tmp_path, monkeypatch)
        result = _invoke("types", str(binary_id), "--json")
        assert result.exit_code == 0
        data_type = json.loads(result.stdout)["types"][0]
        assert data_type["kind"] == "enum"
        assert data_type["namespace"] == "winnt"
        assert [value["name"] for value in data_type["values"]] == ["NP_FLAG_A", "NP_FLAG_B"]

    def test_types_human_output_names_the_kind_and_namespace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed_enum(tmp_path, monkeypatch)
        result = _invoke("types", str(binary_id))
        assert result.exit_code == 0
        assert "NPFlags" in result.output
        assert "enum" in result.output
        assert "winnt" in result.output

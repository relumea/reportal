"""Tests for the function-signature CLI commands."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reportal import cli, store
from reportal._paths import DB_ENV

runner = CliRunner()

CODE = "char *sub_1000(unsigned int a0, int) {\n  return 0;\n}\n"


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16, status="STUB"
        )
        store.set_decompilation(conn, function_id, CODE, "kuna")
    return {"binary": binary_id, "function": function_id}


def _imported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    ids = _seed(tmp_path, monkeypatch)
    result = runner.invoke(cli.app, ["signatures-import", str(ids["binary"])])
    assert result.exit_code == 0
    return ids


class TestSignaturesImportAndList:
    def test_import_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signatures-import", str(ids["binary"]), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["created"] == 1
        assert payload["skipped"] == 0

    def test_list_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signatures", str(ids["binary"]), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["signatures"][0]["name"] == "sub_1000"

    def test_list_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signatures", "4242"])
        assert result.exit_code != 0

    def test_list_without_signatures_hints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signatures", str(ids["binary"])])
        assert result.exit_code == 0
        assert "No signatures yet" in result.output


class TestSignatureShowAndSet:
    def test_show_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature", str(ids["function"]), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["return_type"] == "char *"
        assert payload["parameters"][0]["name"] == "a0"

    def test_show_renders_the_prototype(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature", str(ids["function"])])
        assert result.exit_code == 0
        assert "char * sub_1000(unsigned int a0, int);" in result.output

    def test_show_unknown_function_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature", "4242"])
        assert result.exit_code != 0

    def test_set_return_type(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["signature-set", str(ids["function"]), "--return-type", "int", "--json"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["return_type"] == "int"
        assert payload["parameters"][0]["type"] == "unsigned int"

    def test_set_convention(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["signature-set", str(ids["function"]), "--convention", "stdcall", "--json"],
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout)["calling_convention"] == "stdcall"

    def test_set_without_an_option_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature-set", str(ids["function"])])
        assert result.exit_code != 0

    def test_set_empty_return_type_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["signature-set", str(ids["function"]), "--return-type", " "]
        )
        assert result.exit_code != 0


class TestParameterCommands:
    def test_param_sets_type_and_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "signature-param",
                str(ids["function"]),
                "0",
                "--type",
                "short",
                "--name",
                "count",
                "--json",
            ],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["parameters"][0] == {
            "index": 0,
            "type": "short",
            "name": "count",
            "at": None,
            "kind": None,
            "bits": None,
        }

    def test_param_without_an_option_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature-param", str(ids["function"]), "0"])
        assert result.exit_code != 0

    def test_param_add_appends(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["signature-param-add", str(ids["function"]), "--type", "char *", "--name", "buf"],
        )
        assert result.exit_code == 0
        result = runner.invoke(cli.app, ["signature", str(ids["function"]), "--json"])
        payload = json.loads(result.stdout)
        assert [p["name"] for p in payload["parameters"]] == ["a0", "", "buf"]

    def test_param_add_at_an_index(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "signature-param-add",
                str(ids["function"]),
                "--type",
                "int",
                "--name",
                "count",
                "--index",
                "0",
                "--json",
            ],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert [p["name"] for p in payload["parameters"]] == ["count", "a0", ""]

    def test_param_rm_reindexes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature-param-rm", str(ids["function"]), "0", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert [p["index"] for p in payload["parameters"]] == [0]

    def test_param_rm_bad_index_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature-param-rm", str(ids["function"]), "9"])
        assert result.exit_code != 0

    def test_param_sets_at_kind_and_bits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            [
                "signature-param",
                str(ids["function"]),
                "0",
                "--at",
                "ecx",
                "--kind",
                "pointer",
                "--bits",
                "32",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        parameter = json.loads(result.stdout)["parameters"][0]
        assert (parameter["at"], parameter["kind"], parameter["bits"]) == ("ecx", "pointer", 32)

    def test_param_clear_empties_a_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["signature-param", str(ids["function"]), "0", "--kind", "value"])
        result = runner.invoke(
            cli.app, ["signature-param", str(ids["function"]), "0", "--clear", "kind", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["parameters"][0]["kind"] is None

    def test_param_clear_rejects_an_unknown_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["signature-param", str(ids["function"]), "0", "--clear", "colour"]
        )
        assert result.exit_code != 0

    def test_param_move_reorders(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["signature-param-move", str(ids["function"]), "1", "0", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert [p["index"] for p in payload["parameters"]] == [0, 1]
        assert [p["name"] for p in payload["parameters"]] == ["", "a0"]

    def test_param_move_bad_index_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature-param-move", str(ids["function"]), "0", "9"])
        assert result.exit_code != 0

    def test_param_move_human(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["signature-param-move", str(ids["function"]), "0", "1"])
        assert result.exit_code == 0, result.output

    def test_param_sets_at_human(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["signature-param", str(ids["function"]), "0", "--at", "[esp+4]"]
        )
        assert result.exit_code == 0, result.output

    def test_param_rejects_a_bad_at(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _imported(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["signature-param", str(ids["function"]), "0", "--at", "the third thing"]
        )
        assert result.exit_code != 0


class TestSignaturesExport:
    def test_export_writes_the_header(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        target = tmp_path / "out" / "prototypes.h"
        result = runner.invoke(
            cli.app, ["signatures-export", str(ids["binary"]), str(target), "--json"]
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout)["signatures"] == 1
        assert "sub_1000" in target.read_text(encoding="utf-8")

    def test_export_refuses_without_force_and_overwrites_with_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _imported(tmp_path, monkeypatch)
        target = tmp_path / "prototypes.h"
        target.write_text("original", encoding="utf-8")
        refused = runner.invoke(cli.app, ["signatures-export", str(ids["binary"]), str(target)])
        assert refused.exit_code != 0
        assert target.read_text(encoding="utf-8") == "original"

        forced = runner.invoke(
            cli.app, ["signatures-export", str(ids["binary"]), str(target), "--force"]
        )
        assert forced.exit_code == 0
        assert "sub_1000" in target.read_text(encoding="utf-8")

    def test_export_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app, ["signatures-export", "4242", str(tmp_path / "prototypes.h")]
        )
        assert result.exit_code != 0


def test_signature_commands_are_registered() -> None:
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "signatures",
        "signatures-import",
        "signature",
        "signature-set",
        "signature-param",
        "signature-param-add",
        "signature-param-rm",
        "signature-param-move",
        "signatures-export",
    ):
        assert command in result.stdout


def test_db_connection_helper_is_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing database is reported rather than raising a raw error."""
    monkeypatch.setenv(DB_ENV, str(tmp_path / "absent.db"))
    result = runner.invoke(cli.app, ["signatures", "1"])
    assert result.exit_code != 0

"""Tests for the function-signature JSON routes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request

from reportal import signatures, store

CODE = "char *sub_1000(unsigned int a0, int) {\n  return 0;\n}\n"


def _seed_binary(conn: sqlite3.Connection) -> tuple[int, int]:
    binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16, status="STUB"
    )
    store.set_decompilation(conn, function_id, CODE, "kuna")
    return binary_id, function_id


def _post(path: str, body: dict[str, object] | None = None) -> tuple[str, dict[str, str], bytes]:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    return wsgi_request("POST", path, body=payload)


def _patch(path: str, body: dict[str, object]) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("PATCH", path, body=json.dumps(body))


class TestListAndImport:
    def test_get_lists_the_model_after_import(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/signatures")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["signatures"][0]["name"] == "sub_1000"
        assert payload["signatures"][0]["return_type"] == "char *"
        assert payload["signatures"][0]["parameters"][1]["type"] == "int"

    def test_get_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/4242/signatures")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_import_seeds_from_the_decompilations(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_binary(conn)
        status, headers, body = _post(f"/api/binaries/{binary_id}/signatures/import")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["created"] == 1
        assert payload["updated"] == 0
        assert payload["skipped"] == 0

    def test_import_without_decompilations_creates_nothing(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="cd" * 32, name="plain.exe")
        status, headers, body = _post(f"/api/binaries/{binary_id}/signatures/import")
        assert status.startswith("200")
        assert json_body(body, headers)["created"] == 0

    def test_import_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = _post("/api/binaries/4242/signatures/import")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


class TestGetAndPatchSignature:
    def test_get_signature(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = wsgi_request("GET", f"/api/functions/{function_id}/signature")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["function_id"] == function_id
        assert payload["parameters"][0]["name"] == "a0"
        assert payload["prototype"] == "char * sub_1000(unsigned int a0, int);"

    def test_get_signature_unknown_function_is_404(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/4242/signature")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_get_absent_signature_is_404(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seed_binary(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{function_id}/signature")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "signature-not-found"

    def test_patch_sets_return_type_and_convention(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature",
            {"return_type": "int", "calling_convention": "stdcall"},
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["return_type"] == "int"
        assert payload["calling_convention"] == "stdcall"

    def test_patch_empty_type_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature", {"return_type": ""}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid type"

    def test_patch_without_an_operation_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(f"/api/functions/{function_id}/signature", {})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid request"

    def test_patch_unknown_signature_is_404(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seed_binary(conn)
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature", {"return_type": "int"}
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "signature-not-found"


class TestParameterFieldsApi:
    def test_get_carries_the_derived_default(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        _patch(
            f"/api/functions/{function_id}/signature",
            {"calling_convention": "cdecl"},
        )
        status, headers, body = wsgi_request("GET", f"/api/functions/{function_id}/signature")
        assert status.startswith("200")
        payload = json_body(body, headers)
        # The staged default is derived; the model's own field stays null.
        assert [p["default_at"] for p in payload["parameters"]] == ["[esp+4]", "[esp+8]"]
        assert [p["at"] for p in payload["parameters"]] == [None, None]

    def test_patch_stores_at_kind_and_bits(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature/parameters/0",
            {"at": "ecx", "kind": "pointer", "bits": 32},
        )
        assert status.startswith("200")
        parameter = json_body(body, headers)["parameters"][0]
        assert parameter["at"] == "ecx"
        assert parameter["kind"] == "pointer"
        assert parameter["bits"] == 32

    def test_patch_null_clears_a_field(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        _patch(f"/api/functions/{function_id}/signature/parameters/0", {"kind": "value"})
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature/parameters/0", {"kind": None}
        )
        assert status.startswith("200")
        assert json_body(body, headers)["parameters"][0]["kind"] is None

    def test_patch_without_a_field_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(f"/api/functions/{function_id}/signature/parameters/0", {})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid parameter"

    def test_patch_an_unparsable_at_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature/parameters/0", {"at": "the third thing"}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid type"

    def test_patch_a_non_string_at_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature/parameters/0", {"at": 4}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid parameter"

    def test_add_parameter_with_the_fields(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _post(
            f"/api/functions/{function_id}/signature/parameters",
            {"type": "int", "name": "count", "kind": "value", "bits": 16},
        )
        assert status.startswith("200")
        added = json_body(body, headers)["parameters"][-1]
        assert added["kind"] == "value"
        assert added["bits"] == 16
        assert added["at"] is None

    def test_move_recomputes_the_slots(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        _patch(f"/api/functions/{function_id}/signature", {"calling_convention": "cdecl"})
        _patch(f"/api/functions/{function_id}/signature/parameters/0", {"at": "[esp+4]"})
        _patch(f"/api/functions/{function_id}/signature/parameters/1", {"at": "[esp+8]"})
        status, headers, body = _post(
            f"/api/functions/{function_id}/signature/parameters/1/move", {"to_index": 0}
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [p["name"] for p in payload["parameters"]] == ["", "a0"]
        assert [p["at"] for p in payload["parameters"]] == ["[esp+4]", "[esp+8]"]

    def test_move_without_an_index_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _post(
            f"/api/functions/{function_id}/signature/parameters/0/move", {}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid index"

    def test_move_out_of_range_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _post(
            f"/api/functions/{function_id}/signature/parameters/0/move", {"to_index": 9}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid index"


class TestParameterRoutes:
    def test_add_parameter(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _post(
            f"/api/functions/{function_id}/signature/parameters",
            {"type": "char *", "name": "buffer", "index": 0},
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [p["name"] for p in payload["parameters"]] == ["buffer", "a0", ""]
        assert [p["index"] for p in payload["parameters"]] == [0, 1, 2]

    def test_add_parameter_without_a_type_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _post(
            f"/api/functions/{function_id}/signature/parameters", {"name": "x"}
        )
        assert status.startswith("400")
        assert "type" in json_body(body, headers)["error"]

    def test_patch_parameter_type_and_name(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature/parameters/0",
            {"type": "short", "name": "count"},
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["parameters"][0]["type"] == "short"
        assert payload["parameters"][0]["name"] == "count"
        assert payload["parameters"][0]["at"] is None

    def test_patch_parameter_duplicate_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature/parameters/1", {"name": "a0"}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "duplicate parameter"

    def test_patch_parameter_bad_index_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = _patch(
            f"/api/functions/{function_id}/signature/parameters/5", {"name": "x"}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid index"

    def test_delete_parameter_reindexes(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = wsgi_request(
            "DELETE", f"/api/functions/{function_id}/signature/parameters/0"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [p["index"] for p in payload["parameters"]] == [0]

    def test_delete_parameter_bad_index_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = wsgi_request(
            "DELETE", f"/api/functions/{function_id}/signature/parameters/9"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid index"

    def test_delete_signature(self, conn: sqlite3.Connection) -> None:
        binary_id, function_id = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        status, headers, body = wsgi_request("DELETE", f"/api/functions/{function_id}/signature")
        assert status.startswith("200")
        assert json_body(body, headers)["deleted"] is True

    def test_delete_absent_signature_is_404(self, conn: sqlite3.Connection) -> None:
        _, function_id = _seed_binary(conn)
        status, headers, body = wsgi_request("DELETE", f"/api/functions/{function_id}/signature")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "signature-not-found"


class TestExport:
    def test_export_writes_the_header(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id, _ = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        target = tmp_path / "out" / "prototypes.h"
        status, headers, body = _post(
            f"/api/binaries/{binary_id}/signatures/export", {"path": str(target)}
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["signatures"] == 1
        assert payload["bytes"] > 0
        assert "sub_1000" in target.read_text(encoding="utf-8")

    def test_export_refuses_an_existing_target_without_force(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        target = tmp_path / "prototypes.h"
        target.write_text("original", encoding="utf-8")
        status, headers, body = _post(
            f"/api/binaries/{binary_id}/signatures/export", {"path": str(target)}
        )
        assert status.startswith("409")
        assert json_body(body, headers)["error"] == "export-exists"

        status, headers, body = _post(
            f"/api/binaries/{binary_id}/signatures/export",
            {"path": str(target), "force": True},
        )
        assert status.startswith("200")
        assert "sub_1000" in target.read_text(encoding="utf-8")

    def test_export_refuses_a_missing_grandparent(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id, _ = _seed_binary(conn)
        _post(f"/api/binaries/{binary_id}/signatures/import")
        target = tmp_path / "missing" / "nested" / "prototypes.h"
        status, headers, body = _post(
            f"/api/binaries/{binary_id}/signatures/export", {"path": str(target)}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid path"
        assert not target.exists()

    def test_export_without_a_path_is_400(self, conn: sqlite3.Connection) -> None:
        binary_id, _ = _seed_binary(conn)
        status, headers, body = _post(f"/api/binaries/{binary_id}/signatures/export", {})
        assert status.startswith("400")
        assert "path" in json_body(body, headers)["error"]

    def test_export_unknown_binary_is_404(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        status, headers, body = _post(
            "/api/binaries/4242/signatures/export", {"path": str(tmp_path / "prototypes.h")}
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_unexpected_failure_is_a_sanitized_500(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id, _ = _seed_binary(conn)

        def _explode(*args: object, **kwargs: object) -> list[object]:
            raise RuntimeError("internal detail that must not reach the client")

        monkeypatch.setattr(signatures, "list_signatures", _explode)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/signatures")
        assert status.startswith("500")
        assert json_body(body, headers)["error"] == "internal server error"
        assert "must not reach" not in body.decode("utf-8")

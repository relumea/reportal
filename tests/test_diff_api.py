"""Tests for the function diff route of the reportal JSON API."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from conftest import FakeEngine, json_body, wsgi_request

from reportal import engines, store

LEFT_CODE = "void sub_1000(void)\n{\n  return;\n}\n"
RIGHT_CODE = "void sub_2000(void)\n{\n  int x = 1;\n  return;\n}\n"

# Hex-style listings whose addresses and bytes differ on the two sides; the
# mnemonics are identical, so normalization collapses them to equal lines.
LEFT_HEX = "  0x00001000:  55                push ebp\n  0x00001001:  c3                ret\n"
RIGHT_HEX = "  0x00002000:  55                push ebp\n  0x00002001:  c3                ret\n"


def _seed(
    conn: sqlite3.Connection,
    *,
    context: bool = True,
    match: bool = True,
    decomp: bool = False,
) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe", path="/x/demo.exe")
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    left = store.add_function(conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=16)
    right = store.add_function(conn, analysis_id=analysis_id, va=0x2000, name="sub_2000", size=16)
    other = store.add_function(conn, analysis_id=analysis_id, va=0x3000, name="sub_3000", size=16)
    if context:
        store.set_rebrew_context(conn, binary_id, "/projects/notepad-rebrew")
    if match:
        store.record_match(
            conn,
            function_id=left,
            candidate_function_id=right,
            similarity=0.75,
            confidence=0.6,
        )
    if decomp:
        store.set_decompilation(conn, left, LEFT_CODE, "kuna")
        store.set_decompilation(conn, right, RIGHT_CODE, "kuna")
    return {
        "binary": binary_id,
        "analysis": analysis_id,
        "left": left,
        "right": right,
        "other": other,
    }


class TestDiffErrors:
    def test_unknown_function_404(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/functions/999/diff/1")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "function not found"

    def test_unknown_candidate_404(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['left']}/diff/999")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "candidate not found"

    def test_unrecorded_pair_400(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['other']}"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-such-match"

    def test_invalid_kind_400(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = _seed(conn, decomp=True)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=bytes"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid kind"

    def test_non_boolean_normalize_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, decomp=True)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?normalize=maybe"
        )
        assert status.startswith("400")
        assert "normalize" in json_body(body, headers)["error"]

    def test_without_context_400(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = _seed(conn, context=False)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=disasm"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"

    def test_without_engine_503(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=disasm"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_engine_error_500(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*args: object, **kwargs: object) -> str:
            raise engines.EngineError("rebrew asm exited with code 1: bad va")

        monkeypatch.setattr(fake_engine, "disassemble", boom)
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=disasm"
        )
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad va" in payload["detail"]


class TestDecompDiff:
    def test_stored_rows_serve_without_an_engine(self, conn: sqlite3.Connection) -> None:
        ids = _seed(conn, decomp=True)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=decomp"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["kind"] == "decomp"
        assert payload["normalized"] is True
        assert payload["left"]["function_id"] == ids["left"]
        assert payload["right"]["function_id"] == ids["right"]
        assert payload["similarity"] == 0.75
        assert payload["summary"]["insert"] > 0

    def test_live_compute_is_not_stored(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=decomp"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["entries"]
        assert fake_engine.calls == ["decompile", "decompile"]
        assert store.get_decompilation(conn, ids["left"]) is None

    def test_bare_route_uses_the_best_recorded_match(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, decomp=True)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['left']}/diff")
        assert status.startswith("200")
        assert json_body(body, headers)["right"]["function_id"] == ids["right"]

    def test_bare_route_without_a_match_404(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, match=False)
        status, headers, body = wsgi_request("GET", f"/api/functions/{ids['left']}/diff")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-match"


class TestDisasmDiff:
    def test_engine_lists_both_sides(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=disasm"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["kind"] == "disasm"
        assert fake_engine.calls == ["disassemble", "disassemble"]
        assert store.get_disasm(conn, ids["left"]) is not None

    def test_cached_listings_skip_the_engine(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        store.set_disasm(conn, ids["left"], LEFT_HEX)
        store.set_disasm(conn, ids["right"], RIGHT_HEX)
        status, _, _ = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=disasm"
        )
        assert status.startswith("200")
        assert fake_engine.calls == []

    def test_normalize_off_keeps_addresses(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        store.set_disasm(conn, ids["left"], LEFT_HEX)
        store.set_disasm(conn, ids["right"], RIGHT_HEX)
        status, headers, body = wsgi_request(
            "GET",
            f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=disasm&normalize=false",
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["normalized"] is False
        assert "0x00001000" in str(payload["entries"][0]["left"])

    def test_normalize_on_strips_addresses_and_bytes(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        store.set_disasm(conn, ids["left"], LEFT_HEX)
        store.set_disasm(conn, ids["right"], RIGHT_HEX)
        status, headers, body = wsgi_request(
            "GET",
            f"/api/functions/{ids['left']}/diff/{ids['right']}?kind=disasm&normalize=true",
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["normalized"] is True
        assert payload["entries"][0] == {
            "op": "equal",
            "left_line": 1,
            "right_line": 1,
            "left": "push ebp",
            "right": "push ebp",
        }
        assert payload["summary"] == {"equal": 2, "insert": 0, "delete": 0, "changed": 0}

    def test_json_is_a_stable_object(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, decomp=True)
        status, headers, body = wsgi_request(
            "GET", f"/api/functions/{ids['left']}/diff/{ids['right']}"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert set(payload) == {
            "left",
            "right",
            "kind",
            "normalized",
            "similarity",
            "entries",
            "summary",
        }

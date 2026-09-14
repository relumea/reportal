"""Tests for the strings route's server-side sort and the referrer filter.

The strings route orders the engine's entries by value or length; the
functions route's `refers_to` filter keeps the stored functions whose byte
range contains one of the address's cross-references, resolved through the
same engine call the xrefs route makes.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, engines, store
from reportal._paths import DB_ENV

runner = CliRunner()

PROJECT_DIR = "/projects/notepad-rebrew"

# Four engine string entries with a deliberate length tie (two 3-byte texts,
# two 5-byte texts) so the tie-break is testable.
STRING_PAYLOAD: dict[str, Any] = {
    "binary": "/x/demo.exe",
    "count": 4,
    "strings": [
        {"va": 0x402000, "section": ".rdata", "kind": "ascii", "size": 5, "text": "gamma"},
        {"va": 0x402010, "section": ".rdata", "kind": "ascii", "size": 3, "text": "abc"},
        {"va": 0x402020, "section": ".rdata", "kind": "ascii", "size": 3, "text": "abd"},
        {"va": 0x402030, "section": ".rdata", "kind": "ascii", "size": 5, "text": "delta"},
    ],
}


class _StringEngine(FakeEngine):
    """A fake whose strings payload carries VAs, sections and lengths."""

    def strings(self, binary: str | object) -> dict[str, Any]:
        self.calls.append("strings")
        return dict(STRING_PAYLOAD)


@pytest.fixture()
def fake_engine() -> _StringEngine:
    """The conftest fake, with the richer strings payload this module needs."""
    engine = _StringEngine()
    engines.set_engine(engine)
    return engine


def _seed(conn: sqlite3.Connection, *, context: bool = True) -> dict[str, int]:
    binary_id = store.add_binary(conn, sha256="ef" * 32, name="demo.exe", path="/x/demo.exe")
    if context:
        store.set_rebrew_context(conn, binary_id, PROJECT_DIR)
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    function_id = store.add_function(
        conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=0x300, status="STUB"
    )
    return {"binary": binary_id, "analysis": analysis_id, "function": function_id}


def _file_binary(conn: sqlite3.Connection, tmp_path: Path) -> int:
    """A binary whose row points at a real file, which the strings route reads."""
    path = tmp_path / "demo.exe"
    path.write_bytes(b"MZ" + b"\x00" * 62)
    return store.add_binary(
        conn, sha256="ef" * 32, name="demo.exe", path=str(path), size=path.stat().st_size
    )


class TestStringsSort:
    def test_value_ascending_is_the_default(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: _StringEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/strings")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["sort"] == "value"
        assert payload["order"] == "asc"
        assert [row["text"] for row in payload["strings"]] == ["abc", "abd", "delta", "gamma"]

    def test_value_descending(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: _StringEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/strings?sort=value&order=desc"
        )
        assert status.startswith("200")
        assert [row["text"] for row in json_body(body, headers)["strings"]] == [
            "gamma",
            "delta",
            "abd",
            "abc",
        ]

    def test_length_ascending_ties_break_on_the_text(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: _StringEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/strings?sort=length&order=asc"
        )
        assert status.startswith("200")
        rows = json_body(body, headers)["strings"]
        assert [row["size"] for row in rows] == [3, 3, 5, 5]
        # Equal lengths order by the text, so the tie is deterministic.
        assert [row["text"] for row in rows] == ["abc", "abd", "delta", "gamma"]

    def test_length_descending(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: _StringEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/strings?sort=length&order=desc"
        )
        assert status.startswith("200")
        assert [row["text"] for row in json_body(body, headers)["strings"]] == [
            "gamma",
            "delta",
            "abd",
            "abc",
        ]

    def test_a_row_carries_its_identity(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: _StringEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        _, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/strings?sort=value&order=asc"
        )
        row = json_body(body, headers)["strings"][0]
        assert row == {
            "va": 0x402010,
            "section": ".rdata",
            "kind": "ascii",
            "size": 3,
            "text": "abc",
        }

    def test_an_unknown_sort_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: _StringEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/strings?sort=entropy"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid sort"

    def test_an_unknown_order_is_refused(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: _StringEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/strings?order=sideways"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid order"


class TestNameAndAddressFilters:
    def test_name_matches_a_substring_and_va_one_address(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        store.add_function(
            conn,
            analysis_id=ids["analysis"],
            va=0x2000,
            name="NP_ENTRY",
            size=16,
            status="STUB",
        )

        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?name=np_"
        )
        payload = json_body(body, headers)
        assert status.startswith("200")
        assert [row["name"] for row in payload["functions"]] == ["NP_ENTRY"]
        assert payload["count"] == 1
        assert payload["total"] == 2

        _status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?va=0x1000"
        )
        payload = json_body(body, headers)
        assert [row["id"] for row in payload["functions"]] == [ids["function"]]

        # Decimal reads too, and both filters compose.
        _status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?va={0x2000}&name=NP"
        )
        payload = json_body(body, headers)
        assert [row["name"] for row in payload["functions"]] == ["NP_ENTRY"]

    def test_a_bad_address_is_400(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?va=somewhere"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid va"


class TestReferrerFilter:
    def test_keeps_the_containing_function(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?refers_to=0x401000"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        # The fake's refs are from 0x1100 and 0x1200, both inside the function
        # at 0x1000 (size 0x300), so exactly it is kept.
        assert payload["count"] == 1
        assert [row["id"] for row in payload["functions"]] == [ids["function"]]
        assert payload["total"] == 1
        # The referrer set is the xrefs route's own engine call.
        assert fake_engine.xrefs_args == (PROJECT_DIR, 0x401000, ())

    def test_an_address_nobody_references_is_an_empty_list(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="fe" * 32, name="plain.exe", path="/x/plain.exe")
        store.set_rebrew_context(conn, binary_id, PROJECT_DIR)
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.add_function(
            conn, analysis_id=analysis_id, va=0x5000, name="far", size=16, status="STUB"
        )
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/functions?refers_to=0x401000"
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 0
        assert payload["functions"] == []
        # The binary still has its function, so the empty list is the filter,
        # not an empty binary.
        assert payload["total"] == 1

    def test_a_non_integer_address_is_refused(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?refers_to=hello"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid refers_to"

    def test_without_a_project_context_is_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        ids = _seed(conn, context=False)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?refers_to=0x401000"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "no-engine-context"
        assert fake_engine.calls == []

    def test_without_an_engine_is_503(self, conn: sqlite3.Connection) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?refers_to=0x401000"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_an_engine_failure_is_500(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew xrefs exited with code 2")

        monkeypatch.setattr(fake_engine, "xrefs", boom)
        ids = _seed(conn)
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{ids['binary']}/functions?refers_to=0x401000"
        )
        assert status.startswith("500")
        assert json_body(body, headers)["error"] == "engine-error"

    def test_unknown_binary_is_404(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        _seed(conn)
        status, headers, body = wsgi_request(
            "GET", "/api/binaries/999/functions?refers_to=0x401000"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


class TestCli:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            return _file_binary(conn, tmp_path)

    def test_strings_command_sorts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: _StringEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["strings", str(binary_id), "--sort", "length", "--order", "desc", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert [row["text"] for row in payload["strings"]] == ["gamma", "delta", "abd", "abc"]

    def test_strings_command_rejects_an_unknown_sort(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: _StringEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["strings", str(binary_id), "--sort", "entropy"])
        assert result.exit_code != 0
        assert "--sort must be one of" in result.output

    def test_strings_command_rejects_an_unknown_order(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: _StringEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["strings", str(binary_id), "--order", "sideways"])
        assert result.exit_code != 0

    def test_strings_command_human(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: _StringEngine
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["strings", str(binary_id)])
        assert result.exit_code == 0, result.output

    def test_strings_command_unknown_binary_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: _StringEngine
    ) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["strings", "4242"])
        assert result.exit_code != 0

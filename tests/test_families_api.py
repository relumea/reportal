"""Tests for the family and detection JSON routes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from conftest import FINGERPRINT, FakeEngine, json_body, wsgi_request

from reportal import analysis_log, auth, engines, store

NAME = "DemoFamily"


def _assert_scan_failed(conn: sqlite3.Connection, binary_id: int, kind: str) -> None:
    """A failed scan leaves the analysis carrier `failed`, with an error entry."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    assert analysis_id is not None
    analysis = store.get_analysis(conn, analysis_id)
    assert analysis is not None
    assert analysis["status"] == store.ANALYSIS_STATUS_FAILED
    entries, _total = analysis_log.list_entries(conn, analysis_id)
    failed = [entry for entry in entries if entry["severity"] == analysis_log.SEVERITY_ERROR]
    assert any(kind in str(entry["message"]) for entry in failed)


def _file_binary(conn: sqlite3.Connection, tmp_path: Path, *, name: str = "demo.exe") -> int:
    target = tmp_path / name
    target.write_bytes(b"MZ" + b"\x00" * 30)
    sha = name.encode().hex().ljust(64, "0")
    return store.add_binary(conn, sha256=sha, name=name, path=str(target))


def _post(path: str, body: dict[str, object]) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("POST", path, body=json.dumps(body))


def _register(conn: sqlite3.Connection, binary_id: int, *, name: str = NAME) -> int:
    status, headers, body = _post("/api/families", {"name": name, "reference_binary_id": binary_id})
    assert status.startswith("201")
    return int(json_body(body, headers)["family_id"])


class TestFamiliesCrud:
    def test_post_creates_and_get_serves_stored(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = _post(
            "/api/families",
            {
                "name": NAME,
                "reference_binary_id": binary_id,
                "aliases": ["DEMO.A"],
                "notes": "first",
            },
        )
        assert status.startswith("201")
        payload = json_body(body, headers)
        assert payload["family_id"] > 0
        assert payload["name"] == NAME
        assert payload["aliases"] == ["DEMO.A"]
        assert payload["notes"] == "first"
        assert payload["reference_binary_id"] == binary_id
        assert payload["signatures"]["sha256"] == FINGERPRINT["sha256"]
        assert payload.pop("journal_action")
        assert fake_engine.calls == ["fingerprint", "imports", "strings"]

    def test_post_with_a_hidden_reference_is_404(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        owner, _token = auth.add_user(conn, name="owner", role="admin")
        team_id = int(auth.create_team(conn, name="blue")["id"])
        auth.add_member(conn, team_id, int(owner["id"]))
        _member, token = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        ana = auth.find_user(conn, "ana")
        assert ana is not None
        auth.add_member(conn, team_id, int(ana["id"]))
        _outsider, outsider = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        store.set_binary_scope(conn, binary_id, visibility="team", owner_team_id=team_id)

        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        stranger_status, headers, body = wsgi_request(
            "POST",
            "/api/families",
            body=json.dumps({"name": NAME, "reference_binary_id": binary_id}),
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), body
        assert json_body(body, headers)["error"] == "binary not found"

        member_status, headers, body = wsgi_request(
            "POST",
            "/api/families",
            body=json.dumps({"name": NAME, "reference_binary_id": binary_id}),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("201"), body

    def test_list_and_delete(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        family_id = _register(conn, binary_id)

        status, headers, body = wsgi_request("GET", "/api/families")
        assert status.startswith("200")
        families = json_body(body, headers)["families"]
        assert [row["family_id"] for row in families] == [family_id]

        status, headers, body = wsgi_request("DELETE", f"/api/families/{family_id}")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload.pop("journal_action")
        assert payload == {"family_id": family_id, "deleted": True}

        status, headers, body = wsgi_request("GET", f"/api/families/{family_id}")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "family not found"

    def test_blank_name_400(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = _post(
            "/api/families", {"name": "   ", "reference_binary_id": binary_id}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "name must be a non-empty string"
        assert fake_engine.calls == []

    def test_missing_name_400(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = _post("/api/families", {"reference_binary_id": binary_id})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "name must be a non-empty string"

    def test_duplicate_name_400_case_insensitively(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        _register(conn, binary_id)
        fake_engine.calls.clear()
        status, headers, body = _post(
            "/api/families", {"name": NAME.lower(), "reference_binary_id": binary_id}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "duplicate family"
        assert fake_engine.calls == []

    def test_aliases_must_be_a_list_of_strings(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = _post(
            "/api/families",
            {"name": NAME, "reference_binary_id": binary_id, "aliases": [1]},
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "aliases must be a list of strings"

    def test_unknown_reference_binary_404(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        status, headers, body = _post("/api/families", {"name": NAME, "reference_binary_id": 999})
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_reference_without_a_file_400(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="gone.exe", path="/nope/gone.exe")
        status, headers, body = _post(
            "/api/families", {"name": NAME, "reference_binary_id": binary_id}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"

    def test_without_engine_503(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = _post(
            "/api/families", {"name": NAME, "reference_binary_id": binary_id}
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_engine_error_500(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(binary: str | Path) -> dict[str, object]:
            raise engines.EngineError("rebrew fingerprints exited with code 1")

        monkeypatch.setattr(fake_engine, "fingerprint", boom)
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = _post(
            "/api/families", {"name": NAME, "reference_binary_id": binary_id}
        )
        assert status.startswith("500")
        assert json_body(body, headers)["error"] == "engine-error"

    def test_get_unknown_family_404(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/families/404")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "family not found"

    def test_delete_unknown_family_404(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("DELETE", "/api/families/404")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "family not found"

    def test_get_list_needs_no_engine(self, portal_db: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", "/api/families")
        assert status.startswith("200")
        assert json_body(body, headers) == {"families": []}


class TestDetectRoutes:
    def test_post_stores_and_get_serves_stored_without_engine(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        reference = _file_binary(conn, tmp_path, name="reference.exe")
        _register(conn, reference)
        target = _file_binary(conn, tmp_path, name="target.exe")

        status, headers, body = wsgi_request("POST", f"/api/binaries/{target}/detect")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == target
        assert payload["families_checked"] == 1
        assert payload["count"] == 1
        match = payload["matches"][0]
        assert match["name"] == NAME
        assert match["confidence"] == "high"
        assert match["signals"][0]["kind"] == "exact-binary"
        analysis_id = store.latest_analysis_for_binary(conn, target)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_DETECT) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{target}/detect")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan_and_no_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/detect")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no detect scan for binary {binary_id}" in payload["detail"]
        assert "/detect" in payload["detail"]
        assert fake_engine.calls == []

    def test_get_absent_404_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/detect")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_get_unknown_binary_404(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/detect")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_unknown_binary_404_and_no_engine_call(
        self, conn: sqlite3.Connection, fake_engine: FakeEngine
    ) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/detect")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_without_engine_503(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _file_binary(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/detect")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"

    def test_post_engine_error_500(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(binary: str | Path) -> dict[str, object]:
            raise engines.EngineError("rebrew imports exited with code 2")

        monkeypatch.setattr(fake_engine, "imports", boom)
        binary_id = _file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/detect")
        assert status.startswith("500")
        assert json_body(body, headers)["error"] == "engine-error"
        _assert_scan_failed(conn, binary_id, "detect")

    def test_post_no_match_is_200(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        reference = _file_binary(conn, tmp_path, name="reference.exe")
        _register(conn, reference)
        target = _file_binary(conn, tmp_path, name="target.exe")
        monkeypatch.setattr(
            fake_engine,
            "fingerprint",
            lambda binary: {
                "sha256": "00" * 32,
                "imphash": None,
                "rich_header_hash": None,
            },
        )
        monkeypatch.setattr(fake_engine, "imports", lambda binary: {"imports": []})
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": []})
        status, headers, body = wsgi_request("POST", f"/api/binaries/{target}/detect")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 0
        assert payload["matches"] == []
        assert payload["notes"]

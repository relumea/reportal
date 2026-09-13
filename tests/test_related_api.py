"""Tests for the `/api/binaries/<id>/related` routes."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from conftest import FakeEngine, json_body, wsgi_request

from reportal import engines, store

SHA = "aa" * 32


def _binary(
    conn: sqlite3.Connection, tmp_path: Path, *, name: str, sha: str, size: int = 1000
) -> int:
    path = tmp_path / name
    path.write_bytes(b"MZ" + name.encode())
    return store.add_binary(conn, sha256=sha, name=name, path=str(path), size=size, fmt="EXE")


def _store_fingerprint(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    sha256: str,
    imphash: str | None = None,
    fmt: str = "pe",
    arch: str = "x86_32",
    size: int = 1000,
) -> None:
    store.set_fingerprint(
        conn,
        binary_id,
        {
            "sha256": sha256,
            "imphash": imphash,
            "rich_header_hash": None,
            "format": fmt,
            "arch": arch,
            "size": size,
        },
    )


def _seed_pair(conn: sqlite3.Connection, tmp_path: Path) -> tuple[int, int]:
    target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
    other = _binary(conn, tmp_path, name="other.exe", sha="bb" * 32)
    _store_fingerprint(conn, target, sha256=SHA)
    _store_fingerprint(conn, other, sha256=SHA)
    return target, other


def _post(path: str, body: dict[str, object]) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request("POST", path, body=json.dumps(body))


class TestRelatedRoutes:
    def test_post_stores_and_get_serves_stored(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        target, other = _seed_pair(conn, tmp_path)
        status, headers, body = _post(f"/api/binaries/{target}/related", {})
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == target
        assert payload["candidates_considered"] == 1
        assert payload["count"] == 1
        assert payload["related"][0]["binary_id"] == other
        assert payload["related"][0]["classification"] == "identical"
        analysis_id = store.latest_analysis_for_binary(conn, target)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_RELATED) == payload

        status, headers, body = wsgi_request("GET", f"/api/binaries/{target}/related")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan_with_hint(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{target}/related")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no related scan for binary {target}" in payload["detail"]
        assert f"reportal related {target}" in payload["detail"]

    def test_get_unknown_binary_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/related")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_unknown_binary_404(self, portal_db: Path) -> None:
        status, headers, body = _post("/api/binaries/999/related", {})
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_invalid_limit_400(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        status, headers, body = _post(f"/api/binaries/{target}/related", {"limit": 0})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid limit"

    def test_post_non_integer_limit_400(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        status, headers, body = _post(f"/api/binaries/{target}/related", {"limit": "many"})
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "limit must be an integer"

    def test_post_invalid_include_unrelated_400(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        status, headers, body = _post(
            f"/api/binaries/{target}/related", {"include_unrelated": "yes"}
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "include_unrelated must be a boolean"

    def test_get_never_touches_the_engine(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        target, _other = _seed_pair(conn, tmp_path)
        status, _headers, _body = _post(f"/api/binaries/{target}/related", {})
        assert status.startswith("200")
        fake_engine.calls.clear()
        status, headers, body = wsgi_request("GET", f"/api/binaries/{target}/related")
        assert status.startswith("200")
        assert json_body(body, headers)["count"] == 1
        assert fake_engine.calls == []

    def test_post_degrades_without_an_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        target, _other = _seed_pair(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = _post(f"/api/binaries/{target}/related", {})
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert any("no rebrew engine" in note for note in payload["notes"])

    def test_post_include_unrelated_lists_it(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA, size=1)
        _store_fingerprint(conn, target, sha256=SHA, fmt="elf", arch="x86_64", size=1)
        other = _binary(conn, tmp_path, name="other.exe", sha="bb" * 32, size=999999)
        _store_fingerprint(conn, other, sha256="bb" * 32, fmt="elf", arch="x86_64", size=999999)
        status, headers, body = _post(
            f"/api/binaries/{target}/related", {"include_unrelated": True}
        )
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["count"] == 1
        assert payload["related"][0]["classification"] == "unrelated"

    def test_post_engine_error_500(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        target = _binary(conn, tmp_path, name="target.exe", sha=SHA)
        _binary(conn, tmp_path, name="other.exe", sha="bb" * 32)

        def boom(binary: str | Path) -> dict[str, object]:
            raise engines.EngineError("rebrew fingerprints exited with code 1")

        monkeypatch.setattr(fake_engine, "fingerprint", boom)
        status, headers, body = _post(f"/api/binaries/{target}/related", {})
        assert status.startswith("500")
        assert json_body(body, headers)["error"] == "engine-error"

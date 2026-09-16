"""Tests for the stored-binary download route, its helpers and the CLI command."""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import ResponseHeaders, on_request, wsgi_request
from typer.testing import CliRunner

from reportal import api, cli, store
from reportal._paths import DB_ENV

runner = CliRunner()

# A payload larger than the download chunk, so the streaming test sees more than
# one read without writing a file that slows the suite down.
PAYLOAD = bytes(range(256)) * (api.BINARY_DOWNLOAD_CHUNK_BYTES // 256) + b"tail"

PE_CONTENT_TYPE = "application/vnd.microsoft.portable-executable"


def _seed_file(path: Path, data: bytes = PAYLOAD) -> str:
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _seed_binary(
    conn: sqlite3.Connection,
    path: Path,
    *,
    sha256: str,
    name: str = "notepad.exe",
    size: int | None = None,
) -> int:
    return store.add_binary(
        conn,
        sha256=sha256,
        name=name,
        path=str(path),
        size=len(PAYLOAD) if size is None else size,
    )


def _stream_request(path: str) -> tuple[str, ResponseHeaders, list[bytes]]:
    """Issue a request and return the response body chunks, unjoined."""
    return on_request("GET", path)


class TestDownloadRoute:
    def test_round_trips_the_bytes_and_headers(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        source = tmp_path / "notepad.exe"
        sha256 = _seed_file(source)
        binary_id = _seed_binary(conn, source, sha256=sha256)

        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/download")

        assert status.startswith("200")
        assert headers["Content-Type"] == PE_CONTENT_TYPE
        assert headers["Content-Disposition"] == 'attachment; filename="notepad.exe"'
        assert headers["Content-Length"] == str(len(PAYLOAD))
        assert headers["Cache-Control"] == api.BINARY_DOWNLOAD_CACHE_CONTROL
        assert hashlib.sha256(body).hexdigest() == sha256
        assert body == PAYLOAD

    def test_a_binary_without_a_known_suffix_is_an_octet_stream(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        source = tmp_path / "blob.bin"
        sha256 = _seed_file(source)
        binary_id = _seed_binary(conn, source, sha256=sha256, name="blob.bin")

        status, headers, _body = wsgi_request("GET", f"/api/binaries/{binary_id}/download")

        assert status.startswith("200")
        assert headers["Content-Type"] == api.DEFAULT_BINARY_CONTENT_TYPE

    def test_the_filename_is_sanitized(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        source = tmp_path / "stored.exe"
        sha256 = _seed_file(source)
        binary_id = _seed_binary(conn, source, sha256=sha256, name='evil/dir"quote\\new\nline.exe')

        status, headers, _body = wsgi_request("GET", f"/api/binaries/{binary_id}/download")

        assert status.startswith("200")
        assert api.download_filename({"name": 'evil/dir"quote\\new\nline.exe', "path": ""}) == (
            "dir_quote_new_line.exe"
        )
        assert headers["Content-Disposition"] == 'attachment; filename="dir_quote_new_line.exe"'
        assert "\n" not in headers["Content-Disposition"]
        assert "/" not in headers["Content-Disposition"]

    def test_windows_reserved_device_names_are_prefixed(self) -> None:
        assert api.download_filename({"name": "AUX", "path": "", "id": 1}) == "_AUX"
        assert api.download_filename({"name": "nul.exe", "path": "", "id": 1}) == "_nul.exe"
        assert api.download_filename({"name": "COM1.bin", "path": "", "id": 1}) == "_COM1.bin"
        assert api.download_filename({"name": "notepad.exe", "path": "", "id": 1}) == "notepad.exe"

    def test_a_name_that_sanitizes_to_nothing_falls_back_to_the_stored_file(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        source = tmp_path / "abcdef.exe"
        sha256 = _seed_file(source)
        binary_id = _seed_binary(conn, source, sha256=sha256, name="..")

        status, headers, _body = wsgi_request("GET", f"/api/binaries/{binary_id}/download")

        assert status.startswith("200")
        assert headers["Content-Disposition"] == 'attachment; filename="abcdef.exe"'

    def test_a_missing_file_is_404_binary_not_on_disk(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        missing = tmp_path / "gone.exe"
        binary_id = _seed_binary(conn, missing, sha256="ab" * 32)

        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/download")

        assert status.startswith("404")
        payload = json.loads(body)
        assert payload["error"] == "binary not on disk"
        assert str(missing) in payload["detail"]

    def test_an_unknown_binary_is_404(self, conn: sqlite3.Connection) -> None:
        status, _headers, body = wsgi_request("GET", "/api/binaries/4242/download")

        assert status.startswith("404")
        assert json.loads(body)["error"] == "binary not found"

    def test_the_body_streams_in_bounded_chunks(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        source = tmp_path / "notepad.exe"
        sha256 = _seed_file(source)
        binary_id = _seed_binary(conn, source, sha256=sha256)

        status, _headers, chunks = _stream_request(f"/api/binaries/{binary_id}/download")

        assert not isinstance(chunks, (bytes, bytearray)), "the body must be streamed iterably"
        assert status.startswith("200")
        assert len(chunks) > 1, "a file past the chunk size must arrive in several reads"
        assert all(0 < len(chunk) <= api.BINARY_DOWNLOAD_CHUNK_BYTES for chunk in chunks)
        assert b"".join(chunks) == PAYLOAD


class TestCliDownload:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        source = tmp_path / "notepad.exe"
        sha256 = _seed_file(source)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = _seed_binary(conn, source, sha256=sha256)
        return {"db": db, "binary": binary_id, "source": source}

    def test_writes_the_exact_bytes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        target = tmp_path / "out" / "copy.exe"

        result = runner.invoke(
            cli.app, ["download", str(ids["binary"]), "--output", str(target), "--json"]
        )

        assert result.exit_code == 0
        assert json.loads(result.stdout)["bytes"] == len(PAYLOAD)
        assert target.read_bytes() == PAYLOAD

    def test_defaults_to_the_stored_name_in_the_current_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        out = tmp_path / "cwd"
        out.mkdir()
        monkeypatch.chdir(out)

        result = runner.invoke(cli.app, ["download", str(ids["binary"]), "--json"])

        assert result.exit_code == 0
        assert (out / "notepad.exe").read_bytes() == PAYLOAD

    def test_refuses_an_existing_target_without_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = self._seed(tmp_path, monkeypatch)
        target = tmp_path / "copy.exe"
        target.write_bytes(b"previous")

        result = runner.invoke(cli.app, ["download", str(ids["binary"]), "--output", str(target)])

        assert result.exit_code != 0
        assert "refusing to overwrite" in result.output
        assert "--force" in result.output
        assert target.read_bytes() == b"previous"

    def test_an_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["download", "999", "--output", str(tmp_path / "x.exe")])
        assert result.exit_code != 0
        assert "no binary with id 999" in result.output

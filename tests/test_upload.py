"""Tests for the multipart upload route, ``POST /api/binaries``."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request

from reportal import api, store

# Boundary used by the request builder; kept fixed so a failure is readable.
BOUNDARY = "----reportal-upload-test"

# Keys every upload response carries, duplicate or not.
RESPONSE_KEYS = {
    "id",
    "sha256",
    "name",
    "path",
    "size",
    "format",
    "arch",
    "created_at",
    "function_count",
    "duplicate",
}


def _multipart(
    content: bytes | None,
    *,
    filename: str | None = "demo.exe",
    name: str | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Build a multipart body with an optional ``file`` part and ``name`` field."""
    parts: list[bytes] = []
    if content is not None:
        disposition = 'Content-Disposition: form-data; name="file"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        parts.append(disposition.encode("utf-8") + b"\r\n\r\n" + content)
    if name is not None:
        parts.append(b'Content-Disposition: form-data; name="name"\r\n\r\n' + name.encode("utf-8"))
    body = b"".join(f"--{BOUNDARY}\r\n".encode() + part + b"\r\n" for part in parts)
    body += f"--{BOUNDARY}--\r\n".encode()
    headers = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}
    return body, headers


def _upload(
    content: bytes | None, *, filename: str | None = "demo.exe", name: str | None = None
) -> tuple[str, dict[str, str], bytes]:
    body, headers = _multipart(content, filename=filename, name=name)
    return wsgi_request("POST", "/api/binaries", body=body, headers=headers)


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A workspace marker in *tmp_path* with the working directory moved there."""
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestUploadSuccess:
    def test_writes_content_addressed_file_and_row(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        body = b"MZ uploaded payload"
        status, headers, raw = _upload(body, filename="demo.exe")
        assert status.startswith("200")
        payload = json_body(raw, headers)

        digest = hashlib.sha256(body).hexdigest()
        stored = workspace / "binaries" / f"{digest}.exe"
        assert stored.read_bytes() == body
        assert payload["sha256"] == digest
        assert payload["size"] == len(body)
        assert payload["path"] == str(stored)
        assert payload["format"] == "EXE"
        assert payload["name"] == "demo.exe"
        assert payload["duplicate"] is False
        assert len(store.list_binaries(conn)) == 1

    def test_creates_binaries_dir_on_demand(self, portal_db: Path, workspace: Path) -> None:
        assert not (workspace / "binaries").exists()
        status, _, _ = _upload(b"data")
        assert status.startswith("200")
        assert (workspace / "binaries").is_dir()

    def test_response_keys_are_stable(self, portal_db: Path, workspace: Path) -> None:
        _, headers, raw = _upload(b"stable")
        payload = json_body(raw, headers)
        assert payload.pop("journal_action")
        assert set(payload) == RESPONSE_KEYS


class TestUploadNaming:
    def test_client_filename_never_reaches_the_path(self, portal_db: Path, workspace: Path) -> None:
        body = b"traversal"
        status, headers, raw = _upload(body, filename="../../evil.exe")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        digest = hashlib.sha256(body).hexdigest()
        assert payload["path"] == str(workspace / "binaries" / f"{digest}.exe")
        assert "evil" not in Path(payload["path"]).name
        assert Path(payload["path"]).parent == workspace / "binaries"

    def test_long_extension_drops_the_suffix(self, portal_db: Path, workspace: Path) -> None:
        body = b"no suffix"
        status, headers, raw = _upload(body, filename="file.verylongextension")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        digest = hashlib.sha256(body).hexdigest()
        assert Path(payload["path"]).name == digest
        assert payload["format"] == ""

    def test_extensionless_filename_stores_without_suffix(
        self, portal_db: Path, workspace: Path
    ) -> None:
        body = b"extensionless"
        _, headers, raw = _upload(body, filename="payload")
        payload = json_body(raw, headers)
        assert Path(payload["path"]).name == hashlib.sha256(body).hexdigest()

    def test_name_field_overrides_the_stored_name(self, portal_db: Path, workspace: Path) -> None:
        _, headers, raw = _upload(b"named", filename="demo.exe", name="Custom Name")
        payload = json_body(raw, headers)
        assert payload["name"] == "Custom Name"

    def test_default_name_is_the_filename_basename(self, portal_db: Path, workspace: Path) -> None:
        _, headers, raw = _upload(b"basename", filename="C:/samples/tool.dll")
        payload = json_body(raw, headers)
        assert payload["name"] == "tool.dll"

    def test_empty_client_name_falls_back_to_hash(self, portal_db: Path, workspace: Path) -> None:
        body = b"nameless"
        _, headers, raw = _upload(body, filename="..")
        payload = json_body(raw, headers)
        assert payload["name"] == hashlib.sha256(body).hexdigest()


class TestUploadDedupe:
    def test_second_upload_returns_existing_row(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        body = b"same bytes"
        _, first_headers, first_raw = _upload(body, filename="demo.exe")
        first = json_body(first_raw, first_headers)

        status, headers, raw = _upload(body, filename="demo.exe")
        assert status.startswith("200")
        second = json_body(raw, headers)
        assert second["duplicate"] is True
        assert second["id"] == first["id"]
        assert second["path"] == first["path"]

        stored = list((workspace / "binaries").iterdir())
        assert [entry.name for entry in stored] == [f"{first['sha256']}.exe"]
        assert len(store.list_binaries(conn)) == 1

    def test_dedupe_ignores_the_client_suffix(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        body = b"cross suffix"
        first_status, first_headers, first_raw = _upload(body, filename="demo.exe")
        assert first_status.startswith("200")
        first = json_body(first_raw, first_headers)

        status, headers, raw = _upload(body, filename="demo.bin")
        assert status.startswith("200")
        second = json_body(raw, headers)
        assert second["duplicate"] is True
        assert second["id"] == first["id"]
        assert len(store.list_binaries(conn)) == 1
        assert [entry.name for entry in (workspace / "binaries").iterdir()] == [
            f"{first['sha256']}.exe"
        ]

    def test_duplicate_row_has_the_same_keys(self, portal_db: Path, workspace: Path) -> None:
        _upload(b"keys")
        _, headers, raw = _upload(b"keys")
        payload = json_body(raw, headers)
        assert payload["duplicate"] is True
        assert set(payload) == RESPONSE_KEYS


class TestUploadErrors:
    def test_missing_file_part_400_no_file(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = _upload(None, name="only a name")
        assert status.startswith("400")
        payload = json_body(raw, headers)
        assert payload["error"] == "no-file"
        assert set(payload) == {"error", "detail", "doc_url"}

    def test_zero_byte_upload_400_empty_file(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        status, headers, raw = _upload(b"", filename="empty.exe")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "empty-file"
        assert list((workspace / "binaries").iterdir()) == []
        assert store.list_binaries(conn) == []

    def test_oversized_upload_413_file_too_large(
        self,
        portal_db: Path,
        workspace: Path,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 8)
        status, headers, raw = _upload(b"0123456789abcdef", filename="big.exe")
        assert status.startswith("413")
        payload = json_body(raw, headers)
        assert payload["error"] == "file-too-large"
        assert set(payload) == {"error", "detail", "doc_url"}
        assert list((workspace / "binaries").iterdir()) == []
        assert store.list_binaries(conn) == []

    def test_malformed_multipart_body_400(self, portal_db: Path, workspace: Path) -> None:
        headers = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}
        status, response_headers, raw = wsgi_request(
            "POST", "/api/binaries", body=b"not a multipart body", headers=headers
        )
        assert status.startswith("400")
        payload = json_body(raw, response_headers)
        assert payload["error"] == "invalid-body"
        assert set(payload) == {"error", "detail", "doc_url"}

    def test_missing_boundary_400(self, portal_db: Path, workspace: Path) -> None:
        status, response_headers, raw = wsgi_request(
            "POST",
            "/api/binaries",
            body=b"--x\r\n",
            headers={"Content-Type": "multipart/form-data"},
        )
        assert status.startswith("400")
        assert json_body(raw, response_headers)["error"] == "invalid-body"

    def test_non_multipart_body_400_no_file(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = wsgi_request(
            "POST",
            "/api/binaries",
            body=b"file=@demo.exe",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "no-file"

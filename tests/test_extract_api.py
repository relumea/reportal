"""Tests for ``POST /api/binaries/<id>/extract``."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request
from test_archive import PASSWORD, _write_encrypted_zip, _write_zip

from reportal import store

ENTRY_ONE = b"first member bytes"
ENTRY_TWO = b"second member bytes"


def _register(conn: sqlite3.Connection, path: Path, name: str) -> int:
    """Register *path* as a stored binary row, the way an upload would."""
    return store.add_binary(
        conn,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        name=name,
        path=str(path),
        size=path.stat().st_size,
    )


def _extract(binary_id: int, **body: object) -> tuple[str, dict[str, str], bytes]:
    return wsgi_request(
        "POST",
        f"/api/binaries/{binary_id}/extract",
        body=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )


def _revert(action: str) -> str:
    status, _, _ = wsgi_request(
        "POST",
        "/api/journal/revert",
        body=json.dumps({"action": action}).encode(),
        headers={"Content-Type": "application/json"},
    )
    return status


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestExtraction:
    def test_registers_members_in_a_new_collection(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("one.bin", ENTRY_ONE), ("two.exe", ENTRY_TWO)])
        binary_id = _register(conn, archive, "bundle.zip")

        status, headers, raw = _extract(binary_id)
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["binary_id"] == binary_id
        assert payload["collection_name"] == "bundle.zip extraction"
        assert payload["kept"] == 2 and payload["skipped"] == 0
        names = {entry["name"]: entry for entry in payload["members"]}
        assert set(names) == {"one.bin", "two.exe"}
        assert names["one.bin"]["size"] == len(ENTRY_ONE)
        assert names["one.bin"]["duplicate"] is False
        assert names["one.bin"]["binary_id"] is not None

        stored = {int(row["id"]): row for row in store.list_binaries(conn)}
        assert len(stored) == 3  # the archive plus both members
        members = [row for row in stored.values() if row["name"] != "bundle.zip"]
        assert {row["name"] for row in members} == {"one.bin", "two.exe"}
        collections = {int(row["id"]): row for row in store.list_collections(conn)}
        assert collections[payload["collection_id"]]["binary_count"] == 2
        assert payload["journal_action"]

    def test_member_bytes_are_content_addressed(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("one.exe", ENTRY_ONE)])
        binary_id = _register(conn, archive, "bundle.zip")
        _, headers, raw = _extract(binary_id)
        payload = json_body(raw, headers)
        digest = hashlib.sha256(ENTRY_ONE).hexdigest()
        assert (workspace / "binaries" / f"{digest}.exe").read_bytes() == ENTRY_ONE
        assert payload["members"][0]["size"] == len(ENTRY_ONE)

    def test_named_collection_is_used(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        collection_id = store.create_collection(conn, name="firmware", scope="binary")
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("one.bin", ENTRY_ONE)])
        binary_id = _register(conn, archive, "bundle.zip")
        _, headers, raw = _extract(binary_id, collection_id=collection_id)
        payload = json_body(raw, headers)
        assert payload["collection_id"] == collection_id
        assert payload["collection_name"] == "firmware"
        assert len(store.list_collections(conn)) == 1

    def test_unknown_collection_is_404(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("one.bin", ENTRY_ONE)])
        binary_id = _register(conn, archive, "bundle.zip")
        status, headers, raw = _extract(binary_id, collection_id=99)
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "collection not found"

    def test_a_second_run_reports_the_members_as_duplicates(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("one.bin", ENTRY_ONE)])
        binary_id = _register(conn, archive, "bundle.zip")
        _, headers, first = _extract(binary_id)
        first_id = json_body(first, headers)["members"][0]["binary_id"]
        _, headers, raw = _extract(binary_id)
        payload = json_body(raw, headers)
        assert payload["members"][0]["duplicate"] is True
        assert payload["members"][0]["binary_id"] == first_id
        assert len(store.list_binaries(conn)) == 2

    def test_bad_members_are_skipped_and_good_ones_kept(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("../escape.bin", b"evil"), ("good.bin", ENTRY_TWO)])
        binary_id = _register(conn, archive, "bundle.zip")
        _, headers, raw = _extract(binary_id)
        payload = json_body(raw, headers)
        skipped = [entry for entry in payload["members"] if entry["skipped"]]
        assert [entry["name"] for entry in skipped] == ["../escape.bin"]
        assert "escapes" in skipped[0]["skipped"]
        assert payload["kept"] == 1
        assert not (workspace / "escape.bin").exists()

    def test_notes_carry_the_extraction_report(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("one.bin", ENTRY_ONE)])
        binary_id = _register(conn, archive, "bundle.zip")
        _, headers, raw = _extract(binary_id)
        payload = json_body(raw, headers)
        assert payload["notes"] and "compressed bytes" in payload["notes"][0]

    def test_extract_into_an_existing_collection(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("one.bin", ENTRY_ONE)])
        binary_id = _register(conn, archive, "bundle.zip")
        _extract(binary_id)
        _, headers, second = _extract(binary_id)
        # The default collection is found by name rather than created again.
        payload = json_body(second, headers)
        assert len(store.list_collections(conn)) == 1
        assert payload["collection_name"] == "bundle.zip extraction"


class TestRevert:
    def test_one_action_reverts_everything(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "bundle.zip"
        _write_zip(archive, [("one.bin", ENTRY_ONE), ("two.exe", ENTRY_TWO)])
        binary_id = _register(conn, archive, "bundle.zip")
        _, headers, raw = _extract(binary_id)
        action = json_body(raw, headers)["journal_action"]
        assert len(store.list_binaries(conn)) == 3
        assert len(store.list_collections(conn)) == 1

        assert _revert(action).startswith("200")
        assert [int(row["id"]) for row in store.list_binaries(conn)] == [binary_id]
        assert store.list_collections(conn) == []
        members = [
            path for path in (workspace / "binaries").iterdir() if not path.name.startswith(".")
        ]
        assert members == []


class TestRefusals:
    def test_unknown_binary_is_404(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = _extract(1234)
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"

    def test_rar_names_the_external_tool(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "sample.rar"
        archive.write_bytes(b"Rar!\x1a\x07\x00")
        binary_id = _register(conn, archive, "sample.rar")
        status, headers, raw = _extract(binary_id)
        assert status.startswith("400")
        payload = json_body(raw, headers)
        assert payload["error"] == "external-tool-required"
        assert "unrar" in payload["detail"]

    def test_seven_zip_names_the_external_tool(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "sample.7z"
        archive.write_bytes(b"7z\xbc\xaf\x27\x1c")
        binary_id = _register(conn, archive, "sample.7z")
        status, headers, raw = _extract(binary_id)
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "external-tool-required"

    def test_unsupported_extension_is_refused(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "sample.exe"
        archive.write_bytes(b"MZ not an archive")
        binary_id = _register(conn, archive, "sample.exe")
        status, headers, raw = _extract(binary_id)
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "unsupported-format"

    def test_row_without_a_file_is_400(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="ghost.zip")
        status, headers, raw = _extract(binary_id)
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "binary not on disk"


class TestPassword:
    def test_password_unlocks_the_archive(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "secret.zip"
        _write_encrypted_zip(archive, "secret.bin", ENTRY_ONE, PASSWORD.encode())
        binary_id = _register(conn, archive, "secret.zip")
        status, headers, raw = _extract(binary_id, password=PASSWORD)
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["kept"] == 1
        assert payload["members"][0]["name"] == "secret.bin"

    def test_missing_password_is_refused(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "secret.zip"
        _write_encrypted_zip(archive, "secret.bin", ENTRY_ONE, PASSWORD.encode())
        binary_id = _register(conn, archive, "secret.zip")
        status, headers, raw = _extract(binary_id)
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "password-required"

    def test_wrong_password_is_refused(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        archive = tmp_path / "secret.zip"
        _write_encrypted_zip(archive, "secret.bin", ENTRY_ONE, PASSWORD.encode())
        binary_id = _register(conn, archive, "secret.zip")
        status, headers, raw = _extract(binary_id, password="wrong")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "bad-password"


def test_workspace_keeps_no_temporary_directory(
    portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
) -> None:
    archive = tmp_path / "bundle.zip"
    _write_zip(archive, [("one.bin", ENTRY_ONE)])
    binary_id = _register(conn, archive, "bundle.zip")
    _extract(binary_id)
    leftovers = [
        path.name
        for path in (workspace / "binaries").iterdir()
        if path.name.startswith(".extract-")
    ]
    assert leftovers == []


def test_zip_with_no_members_answers_zero(
    portal_db: Path, workspace: Path, conn: sqlite3.Connection, tmp_path: Path
) -> None:
    archive = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("sub/", b"")
    binary_id = _register(conn, archive, "empty.zip")
    _, headers, raw = _extract(binary_id)
    payload = json_body(raw, headers)
    assert payload["members"] == []
    assert payload["kept"] == 0

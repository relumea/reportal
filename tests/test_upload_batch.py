"""Tests for the batch branch of ``POST /api/binaries``."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request

from reportal import api, store

# Boundary used by the request builder; kept fixed so a failure is readable.
BOUNDARY = "----reportal-batch-test"

# Keys the legacy single-file response carries; the batch branch must not
# change that shape.
LEGACY_RESPONSE_KEYS = {
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
    files: list[tuple[str, bytes]],
    *,
    files_json: str | None = None,
    name: str | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Build a multipart body with repeated ``file`` parts, in order."""
    parts: list[bytes] = []
    for filename, content in files:
        disposition = f'Content-Disposition: form-data; name="file"; filename="{filename}"'
        parts.append(disposition.encode("utf-8") + b"\r\n\r\n" + content)
    if name is not None:
        parts.append(b'Content-Disposition: form-data; name="name"\r\n\r\n' + name.encode("utf-8"))
    if files_json is not None:
        parts.append(
            b'Content-Disposition: form-data; name="files"\r\n\r\n' + files_json.encode("utf-8")
        )
    body = b"".join(f"--{BOUNDARY}\r\n".encode() + part + b"\r\n" for part in parts)
    body += f"--{BOUNDARY}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}


def _upload_batch(
    files: list[tuple[str, bytes]], *, files_json: str | None = None
) -> tuple[str, dict[str, str], bytes]:
    body, headers = _multipart(files, files_json=files_json)
    return wsgi_request("POST", "/api/binaries", body=body, headers=headers)


def _upload_single(
    content: bytes,
    *,
    filename: str = "demo.exe",
    name: str | None = None,
    files_json: str | None = None,
) -> tuple[str, dict[str, str], bytes]:
    body, headers = _multipart([(filename, content)], files_json=files_json, name=name)
    return wsgi_request("POST", "/api/binaries", body=body, headers=headers)


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A workspace marker in *tmp_path* with the working directory moved there."""
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestSingleFileUnchanged:
    def test_single_part_keeps_the_legacy_shape(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = _upload_single(b"legacy bytes")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload.pop("journal_action")
        assert set(payload) == LEGACY_RESPONSE_KEYS
        assert payload["duplicate"] is False

    def test_single_part_with_a_files_field_answers_the_batch_shape(
        self, portal_db: Path, workspace: Path
    ) -> None:
        status, headers, raw = _upload_single(
            b"one batch file", files_json='[{"name": "Named.exe"}]'
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert set(payload) >= {"files", "count", "duplicates", "errors"}
        assert payload["count"] == 1
        entry = payload["files"][0]
        assert entry["file"] == "Named.exe"
        assert entry["binary_id"] is not None
        assert entry["duplicate"] is False
        assert entry["error"] is None


class TestBatchResults:
    def test_mixed_duplicate_and_failure(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        # A first upload makes the second batch entry a duplicate.
        _, headers, raw = _upload_single(b"already here", filename="known.exe")
        known = json_body(raw, headers)

        json_options = json.dumps([{}, {}, {"name": "named"}])
        status, headers, raw = _upload_batch(
            [
                ("fresh.exe", b"fresh bytes"),
                ("known.exe", b"already here"),
                ("empty.bin", b""),
            ],
            files_json=json_options,
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["count"] == 3
        assert payload["duplicates"] == 1
        assert payload["errors"] == 1

        fresh, duplicate, failed = payload["files"]
        assert fresh["binary_id"] is not None and fresh["duplicate"] is False
        assert fresh["file"] == "fresh.exe"
        assert duplicate["binary_id"] == known["id"] and duplicate["duplicate"] is True
        assert failed["binary_id"] is None
        assert failed["error"]["error"] == "empty-file"
        assert len(store.list_binaries(conn)) == 2

    def test_response_names_the_successful_files(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = _upload_batch([("a.exe", b"aaa"), ("b.dll", b"bbb")])
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert [entry["file"] for entry in payload["files"]] == ["a.exe", "b.dll"]
        assert all(entry["error"] is None for entry in payload["files"])

    def test_format_and_arch_hints_are_stored(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"format": "pe", "arch": "x86_32"}])
        body, headers = _multipart([("hinted.bin", b"hinted")], files_json=options)
        _, _, raw = wsgi_request("POST", "/api/binaries", body=body, headers=headers)
        payload = json_body(raw, headers)
        binary = payload["files"][0]
        _, response_headers, raw_binary = wsgi_request(
            "GET", f"/api/binaries/{binary['binary_id']}"
        )
        row = json_body(raw_binary, response_headers)
        assert row["format"] == "pe"
        assert row["arch"] == "x86_32"

    def test_format_falls_back_to_the_suffix(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = _upload_batch([("code.exe", b"code")], files_json="[{}]")
        assert status.startswith("200")
        binary_id = json_body(raw, headers)["files"][0]["binary_id"]
        _, response_headers, raw_binary = wsgi_request("GET", f"/api/binaries/{binary_id}")
        assert json_body(raw_binary, response_headers)["format"] == "EXE"


class TestBatchTagsAndCollections:
    def test_tags_are_applied_per_file(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"tags": ["campaign"]}, {"tags": ["campaign", "second"]}])
        status, headers, raw = _upload_batch(
            [("one.exe", b"one"), ("two.exe", b"two")], files_json=options
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["files"][0]["tags"] == ["campaign"]
        assert payload["files"][1]["tags"] == ["campaign", "second"]
        for entry in payload["files"]:
            _, response_headers, raw_tags = wsgi_request(
                "GET", f"/api/binaries/{entry['binary_id']}/tags"
            )
            names = [tag["name"] for tag in json_body(raw_tags, response_headers)["tags"]]
            assert names == sorted(entry["tags"])

    def test_one_action_reverts_the_whole_request(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        options = json.dumps([{"tags": ["revert-me"]}, {"tags": ["revert-me"]}])
        _, headers, raw = _upload_batch(
            [("one.exe", b"one"), ("two.exe", b"two")], files_json=options
        )
        payload = json_body(raw, headers)
        action = payload["journal_action"]
        assert action
        assert len(store.list_binaries(conn)) == 2
        assert [tag["name"] for tag in store.list_tags(conn)] == ["revert-me"]

        status, _, _ = wsgi_request(
            "POST",
            "/api/journal/revert",
            body=json.dumps({"action": action}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert status.startswith("200")
        assert store.list_binaries(conn) == []
        assert store.list_tags(conn) == []
        stored = list((workspace / "binaries").iterdir())
        assert stored == []

    def test_collection_ids_are_applied(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        collection_id = store.create_collection(conn, name="batch collection", scope="binary")
        options = json.dumps([{"collection_ids": [collection_id]}])
        _, headers, raw = _upload_batch([("one.exe", b"one")], files_json=options)
        payload = json_body(raw, headers)
        assert payload["files"][0]["collections"] == [collection_id]
        collections = {int(row["id"]): row for row in store.list_collections(conn)}
        assert collections[collection_id]["binary_count"] == 1

    def test_unknown_collection_is_refused(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"collection_ids": [99]}])
        status, headers, raw = _upload_batch([("one.exe", b"one")], files_json=options)
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "collection not found"


class TestBatchRefusals:
    def test_missing_file_part_is_no_file(self, portal_db: Path, workspace: Path) -> None:
        body, headers = _multipart([], files_json="[]")
        status, response_headers, raw = wsgi_request(
            "POST", "/api/binaries", body=body, headers=headers
        )
        assert status.startswith("400")
        assert json_body(raw, response_headers)["error"] == "no-file"

    def test_oversized_part_is_reported_per_entry(
        self, portal_db: Path, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 8)
        status, headers, raw = _upload_batch(
            [("small.bin", b"1234"), ("big.bin", b"0123456789abcdef")]
        )
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["files"][0]["error"] is None
        assert payload["files"][1]["error"]["error"] == "file-too-large"
        assert payload["files"][1]["error"]["status"] == 413

    def test_too_many_files_is_refused(
        self, portal_db: Path, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(api, "MAX_UPLOAD_FILES", 1)
        status, headers, raw = _upload_batch([("a.exe", b"aaa"), ("b.exe", b"bbb")])
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "too-many-files"

    def test_mismatched_options_length_is_refused(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = _upload_batch([("a.exe", b"aaa")], files_json=json.dumps([{}, {}]))
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid-body"

    def test_non_array_options_is_refused(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = _upload_batch([("a.exe", b"aaa")], files_json='"nope"')
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid-body"

    def test_malformed_options_json_is_refused(self, portal_db: Path, workspace: Path) -> None:
        status, headers, raw = _upload_batch([("a.exe", b"aaa")], files_json="{not json")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid-body"

    def test_bad_option_type_is_refused(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"tags": [1]}])
        status, headers, raw = _upload_batch([("a.exe", b"aaa")], files_json=options)
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid-body"

    def test_unknown_format_hint_is_refused(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"format": "coff"}])
        status, headers, raw = _upload_batch([("a.exe", b"aaa")], files_json=options)
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid-body"

    def test_unknown_arch_hint_is_refused(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"arch": "mips"}])
        status, headers, raw = _upload_batch([("a.exe", b"aaa")], files_json=options)
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid-body"

    def test_top_level_name_in_a_batch_is_refused(self, portal_db: Path, workspace: Path) -> None:
        body, headers = _multipart([("a.exe", b"aaa"), ("b.exe", b"bbb")], name="not-in-a-batch")
        status, response_headers, raw = wsgi_request(
            "POST", "/api/binaries", body=body, headers=headers
        )
        assert status.startswith("400")
        assert json_body(raw, response_headers)["error"] == "invalid-body"


def test_batch_stores_each_file_by_content_hash(portal_db: Path, workspace: Path) -> None:
    status, headers, raw = _upload_batch([("one.exe", b"payload one"), ("two.exe", b"payload two")])
    assert status.startswith("200")
    payload = json_body(raw, headers)
    for content in (b"payload one", b"payload two"):
        digest = hashlib.sha256(content).hexdigest()
        assert (workspace / "binaries" / f"{digest}.exe").read_bytes() == content
    assert {entry["file"] for entry in payload["files"]} == {"one.exe", "two.exe"}

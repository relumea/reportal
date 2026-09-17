"""Tests for the batch branch of ``POST /api/binaries``."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from conftest import json_body, wsgi_request

from reportal import api, auth, store

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
    "language",
    "compiler",
    "notes",
    "created_at",
    "function_count",
    "duplicate",
    # The object scope a binary carries; public and ownerless until a team is set.
    "owner_team_id",
    "visibility",
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
    files: list[tuple[str, bytes]], *, files_json: str | None = None, token: str = ""
) -> tuple[str, dict[str, str], bytes]:
    body, headers = _multipart(files, files_json=files_json)
    if token:
        headers = {**headers, "Authorization": f"Bearer {token}"}
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

    def test_compiler_hint_stamps_an_empty_column(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"compiler": "MinGW GCC"}])
        body, headers = _multipart([("hinted.bin", b"hinted")], files_json=options)
        status, response_headers, raw = wsgi_request(
            "POST", "/api/binaries", body=body, headers=headers
        )
        assert status.startswith("200")
        binary_id = json_body(raw, response_headers)["files"][0]["binary_id"]
        _, get_headers, raw_binary = wsgi_request("GET", f"/api/binaries/{binary_id}")
        assert json_body(raw_binary, get_headers)["compiler"] == "MinGW GCC"

    def test_a_duplicate_upload_does_not_restamp_compiler(
        self, portal_db: Path, workspace: Path
    ) -> None:
        first = json.dumps([{"compiler": "MinGW GCC"}])
        body, headers = _multipart([("hinted.bin", b"same bytes")], files_json=first)
        status, response_headers, raw = wsgi_request(
            "POST", "/api/binaries", body=body, headers=headers
        )
        assert status.startswith("200")
        binary_id = json_body(raw, response_headers)["files"][0]["binary_id"]

        second = json.dumps([{"compiler": "Microsoft Visual C++"}])
        body, headers = _multipart([("hinted.bin", b"same bytes")], files_json=second)
        status, response_headers, raw = wsgi_request(
            "POST", "/api/binaries", body=body, headers=headers
        )
        assert status.startswith("200")
        payload = json_body(raw, response_headers)
        assert payload["files"][0]["duplicate"] is True
        assert payload["files"][0]["binary_id"] == binary_id
        _, get_headers, raw_binary = wsgi_request("GET", f"/api/binaries/{binary_id}")
        assert json_body(raw_binary, get_headers)["compiler"] == "MinGW GCC"

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


class TestBatchScope:
    """The scope a batch entry can register its binary into."""

    def test_an_entry_can_register_into_a_team_scope(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        team_id = int(auth.create_team(conn, name="Blue")["id"])
        options = json.dumps([{"visibility": "team", "team_id": team_id}])

        status, headers, raw = _upload_batch([("scoped.exe", b"scoped")], files_json=options)

        assert status.startswith("200")
        entry = json_body(raw, headers)["files"][0]
        assert entry["visibility"] == "team"
        assert entry["owner_team_id"] == team_id
        stored = store.get_binary(conn, entry["binary_id"])
        assert stored is not None
        assert stored["visibility"] == "team"
        assert int(stored["owner_team_id"]) == team_id

    def test_a_team_id_alone_means_team_visibility(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        team_id = int(auth.create_team(conn, name="Green")["id"])
        options = json.dumps([{"team_id": team_id}])

        _, headers, raw = _upload_batch([("green.exe", b"green")], files_json=options)

        entry = json_body(raw, headers)["files"][0]
        assert entry["visibility"] == "team"
        assert entry["owner_team_id"] == team_id

    def test_an_entry_that_names_no_scope_stays_public(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        _, headers, raw = _upload_batch([("plain.exe", b"plain")], files_json=json.dumps([{}]))

        entry = json_body(raw, headers)["files"][0]
        assert entry["visibility"] == "public"
        assert entry["owner_team_id"] is None

    def test_an_explicit_public_scope_ignores_a_team_id(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        team_id = int(auth.create_team(conn, name="Amber")["id"])
        options = json.dumps(
            [
                {"visibility": "team", "team_id": team_id},
                {"visibility": "public", "team_id": team_id},
            ]
        )

        status, headers, raw = _upload_batch(
            [("first.exe", b"first"), ("second.exe", b"second")], files_json=options
        )

        assert status.startswith("200")
        first, second = json_body(raw, headers)["files"]
        assert second["visibility"] == "public"
        assert second["owner_team_id"] is None

    def test_an_unknown_team_is_404(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"visibility": "team", "team_id": 99}])

        status, headers, raw = _upload_batch([("nope.exe", b"nope")], files_json=options)

        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == auth.ERROR_TEAM_NOT_FOUND

    def test_a_team_visibility_without_a_team_is_400(
        self, portal_db: Path, workspace: Path
    ) -> None:
        options = json.dumps([{"visibility": "team"}])

        status, headers, raw = _upload_batch([("nope.exe", b"nope")], files_json=options)

        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == auth.ERROR_INVALID_TEAM

    def test_an_unknown_visibility_is_400(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"visibility": "secret"}])

        status, headers, raw = _upload_batch([("nope.exe", b"nope")], files_json=options)

        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == auth.ERROR_INVALID_TEAM

    def test_a_non_integer_team_id_is_400(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"team_id": "5"}])

        status, headers, raw = _upload_batch([("nope.exe", b"nope")], files_json=options)

        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid-body"

    def test_a_non_member_cannot_scope_into_a_team(
        self,
        portal_db: Path,
        workspace: Path,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        team_id = int(auth.create_team(conn, name="Blue")["id"])
        _, ana = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        _, bob = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        ana_user = auth.find_user(conn, "ana")
        assert ana_user is not None
        auth.add_member(conn, team_id, int(ana_user["id"]))
        options = json.dumps([{"visibility": "team", "team_id": team_id}])

        refused = _upload_batch([("bob.exe", b"bob")], files_json=options, token=bob)
        allowed = _upload_batch([("ana.exe", b"ana")], files_json=options, token=ana)

        assert refused[0].startswith("403")
        assert json_body(refused[2], refused[1])["error"] == auth.ERROR_NOT_A_MEMBER
        assert allowed[0].startswith("200")
        assert json_body(allowed[2], allowed[1])["files"][0]["owner_team_id"] == team_id

    def test_a_duplicate_is_rescoped_and_the_revert_puts_it_back(
        self, portal_db: Path, workspace: Path, conn: sqlite3.Connection
    ) -> None:
        team_id = int(auth.create_team(conn, name="Blue")["id"])
        _, headers, raw = _upload_batch([("known.exe", b"known bytes")], files_json="[{}]")
        first = json_body(raw, headers)["files"][0]
        assert first["visibility"] == "public"

        options = json.dumps([{"visibility": "team", "team_id": team_id}])
        _, headers, raw = _upload_batch([("known.exe", b"known bytes")], files_json=options)
        payload = json_body(raw, headers)
        entry = payload["files"][0]
        assert entry["duplicate"] is True
        assert entry["binary_id"] == first["binary_id"]
        assert entry["owner_team_id"] == team_id
        stored = store.get_binary(conn, first["binary_id"])
        assert stored is not None and stored["visibility"] == "team"

        wsgi_request(
            "POST",
            "/api/journal/revert",
            body=json.dumps({"action": payload["journal_action"]}).encode(),
            headers={"Content-Type": "application/json"},
        )
        restored = store.get_binary(conn, first["binary_id"])
        assert restored is not None
        assert restored["visibility"] == "public"
        assert restored["owner_team_id"] is None

    def test_a_duplicate_in_a_foreign_team_is_reported_per_entry(
        self,
        portal_db: Path,
        workspace: Path,
        conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(auth.REQUIRED_ENV, "required")
        _, ana = auth.add_user(conn, name="ana", role=auth.ROLE_ANALYST)
        _, bob = auth.add_user(conn, name="bob", role=auth.ROLE_ANALYST)
        team_id = int(auth.create_team(conn, name="Blue")["id"])
        ana_user = auth.find_user(conn, "ana")
        assert ana_user is not None
        auth.add_member(conn, team_id, int(ana_user["id"]))
        _, headers, raw = _upload_batch([("ana.exe", b"ana bytes")], files_json="[{}]", token=ana)
        binary_id = json_body(raw, headers)["files"][0]["binary_id"]
        store.set_binary_scope(conn, binary_id, owner_team_id=team_id, visibility="team")

        options = json.dumps([{"visibility": "public"}])
        status, headers, raw = _upload_batch(
            [("ana.exe", b"ana bytes")], files_json=options, token=bob
        )

        assert status.startswith("200"), "the batch reports the refusal per entry"
        entry = json_body(raw, headers)["files"][0]
        assert entry["error"]["error"] == auth.ERROR_SCOPE_FORBIDDEN
        assert entry["binary_id"] is None


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

    def test_unknown_compiler_hint_is_refused(self, portal_db: Path, workspace: Path) -> None:
        options = json.dumps([{"compiler": "clang"}])
        status, headers, raw = _upload_batch([("a.exe", b"aaa")], files_json=options)
        assert status.startswith("400")
        payload = json_body(raw, headers)
        assert payload["error"] == "invalid-body"
        assert "compiler" in payload["detail"]

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

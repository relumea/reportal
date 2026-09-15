"""Tests for the knowledge HTTP routes: ``/api/documents`` and ``/api/knowledge/search``."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request

from reportal import auth, knowledge, llm, store

# Boundary of the multipart requests these tests build; fixed so a failure is
# readable.
BOUNDARY = "----reportal-knowledge-test"

NOTE_TEXT = "# Notes\n\nThe widget retry counter lives in the timer callback.\n"
FONT_TEXT = "Glyph metrics and kerning pairs for the outline font.\n"


@pytest.fixture(autouse=True)
def _no_endpoint() -> Iterator[None]:
    """Install an unconfigured client, so the search path never hits the network."""
    llm.set_client(llm.LlmClient(None))
    yield
    llm.set_client(None)


def _seed_binary(conn: sqlite3.Connection) -> int:
    """Create one binary in the isolated DB and return its id."""
    return store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path="/tmp/demo.exe")


def _post(body: dict[str, Any]) -> tuple[str, dict[str, str], bytes]:
    """POST *body* as JSON to ``/api/documents``."""
    return wsgi_request(
        "POST",
        "/api/documents",
        body=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _multipart(content: bytes | None, *, filename: str | None, title: str | None = None) -> bytes:
    """Build a multipart body holding an optional ``file`` part and ``title`` field."""
    parts: list[bytes] = []
    if content is not None:
        disposition = 'Content-Disposition: form-data; name="file"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        parts.append(disposition.encode("utf-8") + b"\r\n\r\n" + content)
    if title is not None:
        parts.append(
            b'Content-Disposition: form-data; name="title"\r\n\r\n' + title.encode("utf-8")
        )
    body = b"".join(f"--{BOUNDARY}\r\n".encode() + part + b"\r\n" for part in parts)
    return body + f"--{BOUNDARY}--\r\n".encode()


def _upload(
    binary_id: int,
    content: bytes | None,
    *,
    filename: str | None = "notes.md",
    title: str | None = None,
) -> tuple[str, dict[str, str], bytes]:
    """POST one multipart document upload to a binary's scope."""
    return wsgi_request(
        "POST",
        f"/api/binaries/{binary_id}/documents",
        body=_multipart(content, filename=filename, title=title),
        headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
    )


class TestCreateDocument:
    def test_pasted_note_is_created(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = _post(
            {
                "scope_kind": "binary",
                "scope_id": binary_id,
                "title": "notes",
                "source": "notes.md",
                "text": NOTE_TEXT,
            }
        )
        assert status.startswith("201")
        payload = json_body(raw, headers)
        assert payload["title"] == "notes"
        assert payload["scope_kind"] == "binary"
        assert payload["scope_id"] == binary_id
        assert payload["chunk_count"] == 1
        assert payload["duplicate"] is False
        assert payload["embedded"] is False
        assert "text" not in payload

    def test_duplicate_answers_200_with_the_flag(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        body = {"scope_kind": "binary", "scope_id": binary_id, "text": NOTE_TEXT}
        first_status, first_headers, first_raw = _post(body)
        assert first_status.startswith("201")
        first = json_body(first_raw, first_headers)

        status, headers, raw = _post(body)
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["duplicate"] is True
        assert payload["id"] == first["id"]
        assert len(store.list_documents(conn)) == 1

    def test_project_scope_is_accepted(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = _post(
            {"scope_kind": "project", "scope_id": 0, "title": "docs", "text": NOTE_TEXT}
        )
        assert status.startswith("201")
        assert json_body(raw, headers)["scope_kind"] == "project"

    def test_blank_text_is_400_empty_text(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = _post(
            {"scope_kind": "binary", "scope_id": binary_id, "text": "   \n"}
        )
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_EMPTY_TEXT

    def test_binary_text_is_400_binary_content(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = _post(
            {"scope_kind": "binary", "scope_id": binary_id, "text": "\u0000\u0001\u0002" * 20}
        )
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_BINARY_CONTENT

    def test_unknown_scope_kind_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = _post({"scope_kind": "collection", "scope_id": 1, "text": NOTE_TEXT})
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_INVALID_SCOPE

    def test_unknown_binary_is_404(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = _post({"scope_kind": "binary", "scope_id": 99, "text": NOTE_TEXT})
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"

    def test_negative_project_scope_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = _post({"scope_kind": "project", "scope_id": -1, "text": NOTE_TEXT})
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "invalid scope id"

    def test_oversized_text_is_413(
        self,
        conn: sqlite3.Connection,
        portal_db: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        binary_id = _seed_binary(conn)
        monkeypatch.setattr(knowledge, "MAX_DOCUMENT_BYTES", 16)
        status, headers, raw = _post(
            {"scope_kind": "binary", "scope_id": binary_id, "text": NOTE_TEXT}
        )
        assert status.startswith("413")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_FILE_TOO_LARGE

    def test_missing_scope_fields_are_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = _post({"text": NOTE_TEXT})
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "scope_kind must be a non-empty string"


class TestUploadDocument:
    def test_upload_creates_a_document(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = _upload(binary_id, NOTE_TEXT.encode(), title="uploaded")
        assert status.startswith("201")
        payload = json_body(raw, headers)
        assert payload["title"] == "uploaded"
        assert payload["source"] == "notes.md"
        assert payload["mime"] == ""
        assert payload["chunk_count"] == 1
        assert payload["duplicate"] is False

    def test_upload_without_a_title_uses_the_filename(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        _, headers, raw = _upload(binary_id, NOTE_TEXT.encode())
        assert json_body(raw, headers)["title"] == "notes.md"

    def test_unsupported_extension_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = _upload(binary_id, b"MZ data", filename="payload.bin")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_UNSUPPORTED_FORMAT
        assert store.list_documents(conn) == []

    def test_binary_content_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = _upload(binary_id, b"\x00\x01\x02" * 40, filename="blob.txt")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_BINARY_CONTENT

    def test_missing_file_part_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = _upload(binary_id, None, title="no file")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "no-file"

    def test_unknown_binary_is_404(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = _upload(1234, NOTE_TEXT.encode())
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"

    def test_oversized_upload_is_413(
        self,
        conn: sqlite3.Connection,
        portal_db: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        binary_id = _seed_binary(conn)
        monkeypatch.setattr(knowledge, "MAX_DOCUMENT_BYTES", 8)
        status, headers, raw = _upload(binary_id, b"far too many bytes for the cap")
        assert status.startswith("413")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_FILE_TOO_LARGE

    def test_rejected_upload_leaves_no_row(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _seed_binary(conn)
        _upload(binary_id, NOTE_TEXT.encode())
        status, headers, raw = _upload(binary_id, b"   ", filename="blank.txt")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_EMPTY_TEXT
        assert len(store.list_documents(conn)) == 1


class TestListAndGet:
    def _seed_two(self, conn: sqlite3.Connection, portal_db: Path) -> int:
        binary_id = _seed_binary(conn)
        _post({"scope_kind": "binary", "scope_id": binary_id, "title": "note", "text": NOTE_TEXT})
        _post({"scope_kind": "project", "scope_id": 0, "title": "font", "text": FONT_TEXT})
        return binary_id

    def test_binary_scope_lists_its_documents(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = self._seed_two(conn, portal_db)
        status, headers, raw = wsgi_request("GET", f"/api/binaries/{binary_id}/documents")
        assert status.startswith("200")
        documents = json_body(raw, headers)["documents"]
        assert [document["title"] for document in documents] == ["note"]
        assert documents[0]["chunk_count"] == 1
        assert "text" not in documents[0]

    def test_binary_scope_of_an_unknown_binary_is_404(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        status, headers, raw = wsgi_request("GET", "/api/binaries/77/documents")
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"

    def test_scope_filters_narrow_the_list(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        self._seed_two(conn, portal_db)
        status, headers, raw = wsgi_request("GET", "/api/documents")
        assert status.startswith("200")
        assert len(json_body(raw, headers)["documents"]) == 2

        _, headers, raw = wsgi_request("GET", "/api/documents?scope_kind=project&scope_id=0")
        documents = json_body(raw, headers)["documents"]
        assert [document["title"] for document in documents] == ["font"]

    def test_a_non_member_lists_only_unscoped_documents(
        self, conn: sqlite3.Connection, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed_two(conn, portal_db)
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
        _status, headers, raw = wsgi_request(
            "GET", "/api/documents", headers={"Authorization": f"Bearer {outsider}"}
        )
        assert [row["title"] for row in json_body(raw, headers)["documents"]] == ["font"]

        _status, headers, raw = wsgi_request(
            "GET", "/api/documents", headers={"Authorization": f"Bearer {token}"}
        )
        assert [row["title"] for row in json_body(raw, headers)["documents"]] == [
            "note",
            "font",
        ]

    def test_non_integer_scope_id_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = wsgi_request("GET", "/api/documents?scope_id=abc")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "scope_id must be an integer"

    def test_unknown_scope_kind_filter_is_400(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        status, headers, raw = wsgi_request("GET", "/api/documents?scope_kind=team")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == knowledge.ERROR_INVALID_SCOPE

    def test_get_without_text_omits_the_body(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = self._seed_two(conn, portal_db)
        document_id = store.list_documents(conn, scope_kind="binary", scope_id=binary_id)[0]["id"]
        status, headers, raw = wsgi_request("GET", f"/api/documents/{document_id}")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["chunk_count"] == 1
        assert "text" not in payload
        assert "chunks" not in payload

    def test_include_text_adds_the_body_and_chunks(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = self._seed_two(conn, portal_db)
        document_id = store.list_documents(conn, scope_kind="binary", scope_id=binary_id)[0]["id"]
        _, headers, raw = wsgi_request("GET", f"/api/documents/{document_id}?include_text=true")
        payload = json_body(raw, headers)
        assert payload["text"] == NOTE_TEXT.strip()
        assert payload["chunks"][0]["text"] == NOTE_TEXT.strip()
        assert payload["chunks"][0]["embedded"] is False

    def test_unknown_document_is_404(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = wsgi_request("GET", "/api/documents/4242")
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "document not found"


class TestDelete:
    def test_delete_removes_the_document_and_its_chunks(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        binary_id = _seed_binary(conn)
        _, headers, raw = _post({"scope_kind": "binary", "scope_id": binary_id, "text": NOTE_TEXT})
        document_id = int(json_body(raw, headers)["id"])
        assert store.list_chunks(conn, document_id)

        status, headers, raw = wsgi_request("DELETE", f"/api/documents/{document_id}")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload.pop("journal_action")
        assert payload == {"document_id": document_id, "deleted": True}
        assert store.get_document(conn, document_id) is None
        assert store.list_chunks(conn, document_id) == []
        assert store.counts(conn)["chunks"] == 0

    def test_delete_of_an_unknown_document_is_404(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        status, headers, raw = wsgi_request("DELETE", "/api/documents/4242")
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "document not found"

    def test_a_non_member_does_not_read_or_delete_a_team_document(
        self, conn: sqlite3.Connection, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed_binary(conn)
        _status, headers, raw = _post(
            {"scope_kind": "binary", "scope_id": binary_id, "text": NOTE_TEXT}
        )
        document_id = int(json_body(raw, headers)["id"])
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
        stranger_status, headers, raw = wsgi_request(
            "GET",
            f"/api/documents/{document_id}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("404"), raw
        assert json_body(raw, headers)["error"] == "document not found"

        stranger_status, headers, raw = wsgi_request(
            "DELETE",
            f"/api/documents/{document_id}",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert stranger_status.startswith("403"), raw
        assert json_body(raw, headers)["error"] == "scope-forbidden"

        member_status, headers, raw = wsgi_request(
            "GET",
            f"/api/documents/{document_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert member_status.startswith("200"), raw


class TestSearch:
    def _seed(self, conn: sqlite3.Connection) -> int:
        binary_id = _seed_binary(conn)
        _post({"scope_kind": "binary", "scope_id": binary_id, "title": "note", "text": NOTE_TEXT})
        _post({"scope_kind": "project", "scope_id": 0, "title": "font", "text": FONT_TEXT})
        return binary_id

    def test_search_ranks_the_matching_document_first(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        self._seed(conn)
        status, headers, raw = wsgi_request("GET", "/api/knowledge/search?q=retry+counter")
        assert status.startswith("200")
        payload = json_body(raw, headers)
        assert payload["query"] == "retry counter"
        assert payload["count"] == 1
        hit = payload["results"][0]
        assert hit["title"] == "note"
        assert hit["method"] == knowledge.METHOD_TFIDF
        assert hit["score"] > 0.0

    def test_binary_id_narrows_the_corpus(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = self._seed(conn)
        _, headers, raw = wsgi_request(
            "GET", f"/api/knowledge/search?q=glyph&binary_id={binary_id}"
        )
        assert json_body(raw, headers)["count"] == 0

        _, headers, raw = wsgi_request("GET", "/api/knowledge/search?q=glyph")
        assert json_body(raw, headers)["count"] == 1

    def test_empty_query_answers_an_empty_list(
        self, conn: sqlite3.Connection, portal_db: Path
    ) -> None:
        self._seed(conn)
        _, headers, raw = wsgi_request("GET", "/api/knowledge/search?q=")
        payload = json_body(raw, headers)
        assert payload["results"] == []
        assert payload["count"] == 0

    def test_limit_bounds_the_results(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        binary_id = _seed_binary(conn)
        for index in range(3):
            _post(
                {
                    "scope_kind": "binary",
                    "scope_id": binary_id,
                    "title": f"note {index}",
                    "text": f"widget timer note number {index}\n",
                }
            )
        _, headers, raw = wsgi_request("GET", "/api/knowledge/search?q=widget+timer&limit=2")
        assert len(json_body(raw, headers)["results"]) == 2

    def test_non_positive_limit_is_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = wsgi_request("GET", "/api/knowledge/search?q=x&limit=0")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "limit must be positive"

    def test_non_integer_queries_are_400(self, conn: sqlite3.Connection, portal_db: Path) -> None:
        status, headers, raw = wsgi_request("GET", "/api/knowledge/search?q=x&limit=abc")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "limit must be an integer"

        status, headers, raw = wsgi_request("GET", "/api/knowledge/search?q=x&binary_id=abc")
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "binary_id must be an integer"

    def test_a_non_member_does_not_search_a_team_binary_scope(
        self, conn: sqlite3.Connection, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed(conn)
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
        _status, headers, raw = wsgi_request(
            "GET",
            "/api/knowledge/search?q=retry+counter",
            headers={"Authorization": f"Bearer {outsider}"},
        )
        assert json_body(raw, headers)["count"] == 0

        _status, headers, raw = wsgi_request(
            "GET",
            "/api/knowledge/search?q=retry+counter",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert json_body(raw, headers)["count"] == 1

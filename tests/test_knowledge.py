"""Tests for document ingestion and semantic search (`reportal.knowledge`).

No test touches the network: the process client is an unconfigured
``LlmClient`` unless a test installs the deterministic embedding stub.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from typing import Any

import pytest

from reportal import knowledge, llm, store

# The stub's vocabulary; a fake vector counts these words, so a query that
# shares them ranks the document that carries them highest.
EMBED_VOCAB: tuple[str, ...] = ("retry", "counter", "timer", "widget", "glyph")

NOTE_TEXT = "# Notes\n\nThe widget retry counter lives in the timer callback of the dialog.\n"
FONT_TEXT = "Glyph metrics and kerning pairs for the outline font.\n"
LONG_TEXT = "paragraph text about the widget timer\n\n" * 120

# Leading characters of a chunk the next chunk must repeat; long enough to
# prove the overlap without depending on where the boundary landed.
_SAMPLE = 40


class FakeEmbeddingClient(llm.LlmClient):
    """Typed embeddings stub: bag-of-words vectors and a call log, no network."""

    def __init__(self, *, dim: int = len(EMBED_VOCAB)) -> None:
        super().__init__(llm.LlmConfig(endpoint="http://127.0.0.1:9/v1", model="fake-embed"))
        self.calls: list[list[str]] = []
        self.dim = dim

    def embeddings(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(list(texts))
        return [self._vector(text) for text in texts]

    def _vector(self, text: str) -> list[float]:
        lowered = text.lower()
        return [float(lowered.count(word)) for word in EMBED_VOCAB[: self.dim]]


@pytest.fixture(autouse=True)
def _no_endpoint() -> Iterator[None]:
    """Install an unconfigured client, so nothing here reaches the network."""
    llm.set_client(llm.LlmClient(None))
    yield
    llm.set_client(None)


@pytest.fixture()
def fake_embeddings() -> FakeEmbeddingClient:
    """A deterministic embeddings stub installed process-wide for one test."""
    client = FakeEmbeddingClient()
    llm.set_client(client)
    return client


def _ingest(
    conn: sqlite3.Connection,
    text: str,
    *,
    title: str = "notes",
    scope_kind: str = knowledge.SCOPE_KIND_BINARY,
    scope_id: int = 1,
    source: str = "notes.md",
) -> dict[str, Any]:
    """Ingest *text* as a document of one scope."""
    return knowledge.ingest_document(
        conn,
        scope_kind=scope_kind,
        scope_id=scope_id,
        title=title,
        source=source,
        mime="text/markdown",
        data=text.encode("utf-8"),
    )


class TestExtractText:
    def test_markdown_is_decoded_as_is(self) -> None:
        text = knowledge.extract_text(NOTE_TEXT.encode(), filename="notes.md")
        assert text is not None
        assert text.startswith("# Notes")
        assert "retry counter" in text

    def test_c_source_keeps_its_lines(self) -> None:
        source = "int add(int a, int b)\n{\n    return a + b;\n}\n"
        assert knowledge.extract_text(source.encode(), filename="add.c") == source.strip()

    def test_json_is_kept_verbatim(self) -> None:
        payload = '{"name": "demo", "flags": ["a", "b"]}'
        assert knowledge.extract_text(payload.encode(), filename="a.json") == payload

    def test_invalid_utf8_is_replaced(self) -> None:
        text = knowledge.extract_text(b"caf\xe9 ok", filename="a.txt")
        assert text is not None
        assert text.startswith("caf")
        assert text.endswith("ok")

    def test_utf8_signature_is_consumed(self) -> None:
        body = "# Café 東京 👩‍💻\n\nNotes"
        text = knowledge.extract_text(body.encode("utf-8-sig"), filename="notes.md")
        assert text == body
        assert knowledge.chunk_text(text) == [body]

    def test_utf8_signature_without_content_is_empty(self) -> None:
        assert knowledge.extract_text(b"\xef\xbb\xbf \n\t", filename="notes.md") is None
        assert knowledge.looks_binary(b"\xef\xbb\xbf \n\t") is False

    def test_embedded_bom_is_preserved(self) -> None:
        body = "Café\ufeff東京"
        assert knowledge.extract_text(body.encode("utf-8-sig"), filename="notes.txt") == body

    def test_binary_bytes_are_rejected(self) -> None:
        assert knowledge.extract_text(b"MZ\x00\x00\x01\x02\x00\x00", filename="a.txt") is None
        assert knowledge.looks_binary(b"MZ\x00\x00\x01\x02\x00\x00") is True

    def test_blank_text_is_rejected(self) -> None:
        assert knowledge.extract_text(b"   \n\t\n", filename="a.txt") is None
        assert knowledge.extract_text(b"", filename="a.txt") is None
        assert knowledge.looks_binary(b"   \n") is False

    def test_html_is_stripped_to_visible_text(self) -> None:
        page = (
            b"<html><head><style>p { color: red; }</style>"
            b"<script>alert('x')</script></head>"
            b"<body><h1>Title</h1><p>Body &amp; more</p><!-- note --></body></html>"
        )
        text = knowledge.extract_text(page, filename="page.html")
        assert text is not None
        assert "Title" in text
        assert "Body & more" in text
        assert "alert" not in text
        assert "color" not in text
        assert "<" not in text

    def test_supported_names_come_from_the_allowlist(self) -> None:
        assert knowledge.is_supported_name("README.md") is True
        assert knowledge.is_supported_name("LIB.H") is True
        assert knowledge.is_supported_name("payload.bin") is False
        assert knowledge.is_supported_name("no-extension") is False


class TestChunkText:
    def test_short_text_is_one_chunk(self) -> None:
        assert knowledge.chunk_text(NOTE_TEXT.strip()) == [NOTE_TEXT.strip()]

    def test_chunks_are_at_most_the_window(self) -> None:
        chunks = knowledge.chunk_text(LONG_TEXT)
        assert len(chunks) > 1
        assert all(len(chunk) <= knowledge.CHUNK_CHARS for chunk in chunks)
        assert all(chunk.strip() for chunk in chunks)

    def test_consecutive_chunks_overlap(self) -> None:
        body = "word " * 800
        chunks = knowledge.chunk_text(body)
        shared = chunks[0][-knowledge.CHUNK_OVERLAP :].strip()
        assert shared
        assert chunks[1].startswith(shared[:_SAMPLE])

    def test_paragraph_break_wins_over_the_window(self) -> None:
        body = "a" * 1100 + "\n\n" + "b" * 1100
        chunks = knowledge.chunk_text(body)
        assert chunks[0] == "a" * 1100

    def test_empty_text_yields_no_chunk(self) -> None:
        assert knowledge.chunk_text("   \n\n  ") == []

    def test_chunking_is_deterministic(self) -> None:
        assert knowledge.chunk_text(LONG_TEXT) == knowledge.chunk_text(LONG_TEXT)

    def test_chunk_count_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(knowledge, "MAX_CHUNKS_PER_DOCUMENT", 3)
        assert len(knowledge.chunk_text("z" * 6000)) == 3


class TestIngest:
    def test_stores_the_document_and_its_chunks(self, conn: sqlite3.Connection) -> None:
        payload = _ingest(conn, LONG_TEXT, title="long note")
        assert payload["duplicate"] is False
        assert payload["embedded"] is False
        assert payload["chunk_count"] == len(store.list_chunks(conn, int(payload["id"])))
        assert int(payload["chunk_count"]) > 1
        stored = store.get_document(conn, int(payload["id"]))
        assert stored is not None
        assert stored["title"] == "long note"
        assert stored["size"] == len(LONG_TEXT.encode("utf-8"))

    def test_same_bytes_in_one_scope_are_a_duplicate(self, conn: sqlite3.Connection) -> None:
        first = _ingest(conn, NOTE_TEXT)
        second = _ingest(conn, NOTE_TEXT, title="re-ingested")
        assert second["duplicate"] is True
        assert second["id"] == first["id"]
        assert len(store.list_documents(conn, scope_kind="binary", scope_id=1)) == 1

    def test_same_bytes_in_another_scope_are_a_new_document(self, conn: sqlite3.Connection) -> None:
        first = _ingest(conn, NOTE_TEXT, scope_id=1)
        second = _ingest(conn, NOTE_TEXT, scope_id=2)
        assert second["duplicate"] is False
        assert second["id"] != first["id"]

    def test_empty_text_is_rejected(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(knowledge.KnowledgeError) as excinfo:
            _ingest(conn, "   \n\n")
        assert excinfo.value.code == knowledge.ERROR_EMPTY_TEXT

    def test_binary_content_is_rejected(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(knowledge.KnowledgeError) as excinfo:
            knowledge.ingest_document(
                conn,
                scope_kind=knowledge.SCOPE_KIND_BINARY,
                scope_id=1,
                title="blob",
                source="blob.txt",
                mime="",
                data=b"\x00\x01\x02" * 40,
            )
        assert excinfo.value.code == knowledge.ERROR_BINARY_CONTENT

    def test_unknown_scope_kind_is_rejected(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(knowledge.KnowledgeError) as excinfo:
            _ingest(conn, NOTE_TEXT, scope_kind="collection")
        assert excinfo.value.code == knowledge.ERROR_INVALID_SCOPE

    def test_oversized_document_is_rejected(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(knowledge, "MAX_DOCUMENT_BYTES", 16)
        with pytest.raises(knowledge.KnowledgeError) as excinfo:
            _ingest(conn, NOTE_TEXT)
        assert excinfo.value.code == knowledge.ERROR_FILE_TOO_LARGE
        assert store.list_documents(conn) == []

    def test_document_count_per_scope_is_capped(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(knowledge, "MAX_DOCUMENTS_PER_SCOPE", 1)
        _ingest(conn, NOTE_TEXT)
        with pytest.raises(knowledge.KnowledgeError) as excinfo:
            _ingest(conn, FONT_TEXT, title="second")
        assert excinfo.value.code == knowledge.ERROR_TOO_MANY_DOCUMENTS

    def test_project_scope_accepts_any_non_negative_id(self, conn: sqlite3.Connection) -> None:
        payload = _ingest(conn, NOTE_TEXT, scope_kind=knowledge.SCOPE_KIND_PROJECT, scope_id=0)
        assert payload["scope_kind"] == "project"
        assert payload["scope_id"] == 0

    def test_document_with_embeddings_reports_them(
        self, conn: sqlite3.Connection, fake_embeddings: FakeEmbeddingClient
    ) -> None:
        payload = _ingest(conn, NOTE_TEXT)
        assert payload["embedded"] is True
        chunks = store.list_chunks(conn, int(payload["id"]))
        assert all(chunk["embedded"] for chunk in chunks)
        assert fake_embeddings.calls[0] == knowledge.chunk_text(NOTE_TEXT.strip())

    def test_document_without_embeddings_stays_readable(self, conn: sqlite3.Connection) -> None:
        payload = _ingest(conn, NOTE_TEXT)
        assert payload["embedded"] is False
        chunks = store.list_chunks(conn, int(payload["id"]))
        assert all(not chunk["embedded"] for chunk in chunks)
        assert chunks[0]["text"] == NOTE_TEXT.strip()

    def test_an_embedding_failure_does_not_fail_the_ingest(self, conn: sqlite3.Connection) -> None:
        llm.set_client(_FailingEmbeddingClient())
        payload = _ingest(conn, NOTE_TEXT)
        assert payload["embedded"] is False
        assert payload["chunk_count"] == 1


class _FailingEmbeddingClient(llm.LlmClient):
    """Embeddings stub raising the error a broken endpoint raises."""

    def __init__(self) -> None:
        super().__init__(llm.LlmConfig(endpoint="http://127.0.0.1:9/v1", model="broken"))

    def embeddings(self, texts: list[str]) -> list[list[float]]:
        raise llm.LlmError("embeddings endpoint is broken")


class TestSearch:
    def _corpus(self, conn: sqlite3.Connection) -> tuple[int, int]:
        note = _ingest(conn, NOTE_TEXT, title="widget note")
        font = _ingest(conn, FONT_TEXT, title="font note")
        return int(note["id"]), int(font["id"])

    def test_tfidf_ranks_the_matching_document_first(self, conn: sqlite3.Connection) -> None:
        note_id, _ = self._corpus(conn)
        hits = knowledge.search_knowledge(conn, query="retry counter")
        assert hits
        assert hits[0]["document_id"] == note_id
        assert hits[0]["method"] == knowledge.METHOD_TFIDF
        assert hits[0]["score"] > 0.0
        assert "retry counter" in hits[0]["text"]
        assert hits[0]["title"] == "widget note"

    def test_scope_filter_keeps_other_scopes_out(self, conn: sqlite3.Connection) -> None:
        note_id, _ = self._corpus(conn)
        other = _ingest(conn, NOTE_TEXT, title="other scope", scope_id=7)
        scoped = knowledge.search_knowledge(
            conn, query="retry counter", scope_kind="binary", scope_id=7
        )
        assert [hit["document_id"] for hit in scoped] == [int(other["id"])]
        assert int(other["id"]) != note_id

    def test_limit_bounds_the_result_list(self, conn: sqlite3.Connection) -> None:
        for index in range(3):
            _ingest(conn, f"widget timer note number {index}\n", title=f"note {index}")
        hits = knowledge.search_knowledge(conn, query="widget timer", limit=2)
        assert len(hits) == 2

    def test_empty_query_returns_nothing(self, conn: sqlite3.Connection) -> None:
        self._corpus(conn)
        assert knowledge.search_knowledge(conn, query="   ") == []
        assert knowledge.search_knowledge(conn, query="retry", limit=0) == []

    def test_query_without_a_corpus_term_returns_nothing(self, conn: sqlite3.Connection) -> None:
        self._corpus(conn)
        assert knowledge.search_knowledge(conn, query="zzzznotinthecorpus") == []

    def test_empty_corpus_returns_nothing(self, conn: sqlite3.Connection) -> None:
        assert knowledge.search_knowledge(conn, query="anything") == []

    def test_embeddings_path_scores_the_query(
        self, conn: sqlite3.Connection, fake_embeddings: FakeEmbeddingClient
    ) -> None:
        note_id, _ = self._corpus(conn)
        hits = knowledge.search_knowledge(conn, query="retry counter timer widget")
        assert hits
        assert hits[0]["document_id"] == note_id
        assert hits[0]["method"] == knowledge.METHOD_EMBEDDINGS
        assert hits[0]["score"] == pytest.approx(1.0)
        assert fake_embeddings.calls[-1] == ["retry counter timer widget"]

    def test_embeddings_path_falls_back_without_stored_vectors(
        self, conn: sqlite3.Connection, fake_embeddings: FakeEmbeddingClient
    ) -> None:
        document_id = store.add_document(
            conn,
            scope_kind="binary",
            scope_id=1,
            title="plain note",
            source="plain.md",
            mime="",
            sha256="cd" * 32,
            size=len(NOTE_TEXT),
            text=NOTE_TEXT.strip(),
        )
        store.add_chunk(conn, document_id=document_id, ordinal=0, text=NOTE_TEXT.strip())
        hits = knowledge.search_knowledge(conn, query="retry counter")
        assert hits
        assert hits[0]["document_id"] == document_id
        assert hits[0]["method"] == knowledge.METHOD_TFIDF


class TestStoreChunks:
    def test_delete_cascades_to_the_chunks(self, conn: sqlite3.Connection) -> None:
        payload = _ingest(conn, NOTE_TEXT)
        document_id = int(payload["id"])
        assert store.list_chunks(conn, document_id)
        assert store.delete_document(conn, document_id) is True
        assert store.list_chunks(conn, document_id) == []
        assert store.get_document(conn, document_id) is None

    def test_delete_of_an_unknown_id_is_false(self, conn: sqlite3.Connection) -> None:
        assert store.delete_document(conn, 4242) is False

    def test_chunk_iteration_carries_the_document_fields(self, conn: sqlite3.Connection) -> None:
        payload = _ingest(conn, NOTE_TEXT, title="carried")
        rows = store.iter_chunks_with_embeddings(conn, scope_kind="binary", scope_id=1)
        assert [row["document_id"] for row in rows] == [int(payload["id"])]
        assert rows[0]["title"] == "carried"
        assert rows[0]["source"] == "notes.md"
        assert rows[0]["embedding"] is None

    def test_unparsable_embedding_is_reported_as_absent(self, conn: sqlite3.Connection) -> None:
        payload = _ingest(conn, NOTE_TEXT)
        conn.execute(
            "UPDATE chunks SET embedding_json = ? WHERE document_id = ?",
            ("not json", int(payload["id"])),
        )
        conn.commit()
        rows = store.iter_chunks_with_embeddings(conn)
        assert rows[0]["embedding"] is None


class TestKnowledgeHelpers:
    def test_unusable_vectors_are_none(self) -> None:
        assert knowledge._usable_vector([]) is None
        assert knowledge._usable_vector([0.0] * (knowledge.EMBEDDING_DIM_SANITY + 1)) is None
        assert knowledge._usable_vector([0.1, 0.2]) == [0.1, 0.2]
        assert knowledge._usable_vectors(None, 1) is None
        assert knowledge._usable_vectors([[0.1]], 2) is None
        assert knowledge._usable_vectors([[0.1], []], 2) is None
        assert knowledge._usable_vectors([[0.1], [0.2]], 2) == [[0.1], [0.2]]

    def test_zero_norm_cosine_is_zero(self) -> None:
        assert knowledge._cosine_similarity([0.0, 0.0], [1.0, 2.0]) == 0.0
        assert knowledge._cosine_similarity([1.0], [1.0]) == 1.0

    def test_empty_query_ranks_nothing(self) -> None:
        chunks = [{"id": 1, "text": "hello world"}]
        assert knowledge._tfidf_scores(chunks, "") == []
        assert knowledge._tfidf_scores(chunks, "!!!") == []

    def test_sparse_cosine_swaps_to_the_shorter_side(self) -> None:
        left = {"a": 1.0, "b": 1.0, "c": 1.0}
        right = {"a": 1.0}
        assert knowledge._sparse_cosine(left, right) == knowledge._sparse_cosine(right, left)


class TestKnowledgeSearchEdges:
    def test_blank_query_answers_empty(self, conn: sqlite3.Connection) -> None:
        assert knowledge.retrieve(conn, query="  ") == []
        assert knowledge.retrieve(conn, query="x", limit=0) == []

    def test_snippet_truncates_long_text(self) -> None:
        long = "word " * 500
        snippet = knowledge._snippet(long)
        assert len(snippet) <= knowledge.RETRIEVAL_SNIPPET_CHARS
        assert snippet.endswith("…")
        assert knowledge._snippet("short") == "short"

    def test_hit_field_collapses_spaces(self) -> None:
        assert knowledge._hit_field({"title": "a  b\nc"}, "title") == "a b c"
        assert knowledge._hit_field({}, "missing") == ""

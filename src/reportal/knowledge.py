"""Document ingestion and semantic search over the local store.

A document (a markdown note, a source file, a pasted snippet) is scoped to one
binary or to the whole project.  Ingestion extracts its text, splits that text
into overlapping chunks, dedupes it by sha256 inside the scope and stores the
document with its chunks in the ``documents``/``chunks`` tables.

Ranking has two paths.  When an OpenAI-compatible embeddings endpoint is
configured, the query is embedded and compared to the stored chunk vectors by
cosine similarity.  Without one, and whenever a chunk was stored without a
vector, a local TF-IDF cosine ranks the same chunks: no configuration, no
extra dependency.

Nothing here fetches a URL or reads the network: the only request is the
optional embeddings call through :mod:`reportal.llm`, and an endpoint that is
absent or failing leaves the document searchable through the TF-IDF path.

A knowledge graph over these documents is built by :mod:`reportal.graph`,
which derives its nodes and edges from stored rows alone.  :func:`retrieve`
and :func:`as_context` are the retrieval half: a bounded list of hits for a
query and a bounded, citable block of them for a prompt.  Retrieved text is
untrusted input: a caller quotes it as context to reason about, never splices
it into a command, and never executes it.
"""

from __future__ import annotations

import hashlib
import math
import re
import sqlite3
from collections.abc import Mapping
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from reportal import llm, store

# Characters a chunk targets before the boundary search trims it, and the
# characters it shares with the following chunk.
CHUNK_CHARS = 1200
CHUNK_OVERLAP = 200

# Distance back from the chunk limit the boundary search may move a cut, so a
# preferred break never yields a short chunk.
BOUNDARY_SEARCH_CHARS = CHUNK_CHARS // 4

# Largest document accepted, in bytes, and the most documents one scope holds.
# Both are enforced at ingest so a runaway ingester cannot fill the store.
MAX_DOCUMENT_BYTES = 512 * 1024
MAX_DOCUMENTS_PER_SCOPE = 200

# Chunks stored per document; a longer document is truncated at this many.
MAX_CHUNKS_PER_DOCUMENT = 600

# Longest embedding vector accepted from an endpoint.  A longer one is a
# malformed response, not a model's output.
EMBEDDING_DIM_SANITY = 8192

# Suffixes a document file may carry.  A file with any other suffix is
# rejected as an unsupported format rather than decoded as text.
TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".md",
        ".txt",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".log",
        ".csv",
        ".ini",
        ".cfg",
        ".rs",
        ".py",
        ".js",
        ".ts",
        ".xml",
        ".html",
        ".htm",
    }
)

# Suffixes whose text is HTML and is reduced to its visible text before
# chunking.
HTML_EXTENSIONS: frozenset[str] = frozenset({".html", ".htm"})

# Elements whose content is not visible text, dropped before the tags are.
_SKIPPED_HTML_TAGS: frozenset[str] = frozenset({"script", "style"})

# Share of NUL and control characters above which bytes are read as binary
# rather than as text.  Tab, newline and carriage return count as text.
BINARY_CONTROL_RATIO = 0.05

# Characters that stay in text when the control-character share is measured.
_TEXT_WHITESPACE = "\t\n\r"

# Document scopes.  A binary scope names a stored binary id; a project scope is
# a workspace-level bucket with no table to validate against, the same loose
# reference the conversation scopes use; the docs scope holds the shipped
# manual, which `reportal.docs` ingests, and an id of zero.
SCOPE_KIND_BINARY = "binary"
SCOPE_KIND_PROJECT = "project"
SCOPE_KIND_DOCS = "docs"
SCOPE_KINDS: tuple[str, ...] = (SCOPE_KIND_BINARY, SCOPE_KIND_PROJECT, SCOPE_KIND_DOCS)

# Title a document carries when the caller supplies none.
DEFAULT_DOCUMENT_TITLE = "untitled"

# Results `search_knowledge` returns when the caller names no limit.
DEFAULT_SEARCH_LIMIT = 10

# Hits a retrieval returns by default, and the characters one snippet may take
# in a context block.  Both bound what a caller injects into a prompt.
RETRIEVAL_LIMIT = 5
RETRIEVAL_SNIPPET_CHARS = 400

# Largest `as_context` block, in characters.  The block is a prefix of the
# ranked hits, so a tight budget drops the lowest-ranked ones, never a high one.
RETRIEVAL_CONTEXT_CHARS = 2000

# Error names an unusable ingest reports; they are the API's error strings.
ERROR_UNSUPPORTED_FORMAT = "unsupported-format"
ERROR_EMPTY_TEXT = "empty-text"
ERROR_BINARY_CONTENT = "binary-content"
ERROR_FILE_TOO_LARGE = "file-too-large"
ERROR_TOO_MANY_DOCUMENTS = "too-many-documents"
ERROR_INVALID_SCOPE = "invalid scope kind"

# Ranking methods a search result reports.
METHOD_EMBEDDINGS = "embeddings"
METHOD_TFIDF = "tfidf"

# Break markers the chunker prefers, best first: a paragraph, then a line, then
# a sentence end.
_PARAGRAPH_BREAKS: tuple[str, ...] = ("\n\n", "\n")
_SENTENCE_BREAKS: tuple[str, ...] = (". ", "! ", "? ")

# Query tokens are word characters, which already include the underscore that
# dominates the identifiers in a reversing corpus.  Case is dropped so the
# ranking is not confused by it.
_TOKEN_RE = re.compile(r"\w+")

# Words dropped from the TF-IDF vocabulary.  Small on purpose: the corpus is
# technical prose, so a word carrying a document's subject (a function name,
# say) costs more to drop than the noise it removes.
STOPWORDS: frozenset[str] = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "but",
        "by",
        "for",
        "from",
        "has",
        "have",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "their",
        "then",
        "there",
        "these",
        "they",
        "this",
        "to",
        "was",
        "were",
        "which",
        "will",
        "with",
    }
)


class KnowledgeError(Exception):
    """A document cannot be ingested; ``code`` is the API's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class _HtmlTextExtractor(HTMLParser):
    """Collect the visible text of an HTML document, dropping script and style."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIPPED_HTML_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIPPED_HTML_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data.strip():
            self._parts.append(data.strip())

    def text(self) -> str:
        """Return the collected text, one space between its parts."""
        return " ".join(self._parts)


def html_to_text(text: str) -> str:
    """Return the visible text of *text*, with its tags removed."""
    parser = _HtmlTextExtractor()
    parser.feed(text)
    parser.close()
    return parser.text()


def is_supported_name(filename: str) -> bool:
    """True when *filename* carries a suffix on the :data:`TEXT_EXTENSIONS` list."""
    return Path(filename).suffix.lower() in TEXT_EXTENSIONS


def _decode(data: bytes) -> str:
    """Decode *data* as UTF-8, replacing invalid sequences."""
    return data.decode("utf-8", errors="replace")


def _control_ratio(text: str) -> float:
    """Share of *text* that is NUL or an unprintable control character."""
    if not text:
        return 0.0
    control = sum(
        1 for char in text if char not in _TEXT_WHITESPACE and (ord(char) < 32 or ord(char) == 127)
    )
    return control / len(text)


def looks_binary(data: bytes) -> bool:
    """True when *data* carries too many NUL and control bytes to be text."""
    return _control_ratio(_decode(data)) > BINARY_CONTROL_RATIO


def extract_text(data: bytes, *, filename: str) -> str | None:
    """Extract plain text from *data*, or None when it is unusable.

    The bytes are decoded as UTF-8 with invalid sequences replaced.  Content
    whose share of NUL and control characters passes
    :data:`BINARY_CONTROL_RATIO` is rejected as binary, HTML is reduced to its
    visible text, and content with no text left after trimming is rejected as
    empty.
    """
    text = _decode(data)
    if _control_ratio(text) > BINARY_CONTROL_RATIO:
        return None
    if Path(filename).suffix.lower() in HTML_EXTENSIONS:
        text = html_to_text(text)
    return text.strip() or None


def _break_offset(body: str, start: int, end: int) -> int:
    """Return how many characters a window takes, cut at its best break point.

    A paragraph break wins over a line break, a line break over a sentence end,
    a sentence end over a space; with none of them in the searched tail the
    window is taken whole.
    """
    floor = max(start + 1, end - BOUNDARY_SEARCH_CHARS)
    for markers in (_PARAGRAPH_BREAKS, _SENTENCE_BREAKS):
        for marker in markers:
            index = body.rfind(marker, floor, end)
            if index >= floor:
                return index + len(marker) - start
    space = body.rfind(" ", floor, end)
    if space >= floor:
        return space + 1 - start
    return end - start


def chunk_text(text: str) -> list[str]:
    """Split *text* into overlapping chunks of about :data:`CHUNK_CHARS`.

    A boundary prefers a paragraph break, then a sentence end, then a space,
    searched within :data:`BOUNDARY_SEARCH_CHARS` of the window's end, so a
    chunk is normally the full window.  Consecutive chunks share
    :data:`CHUNK_OVERLAP` characters.  The split is deterministic, holds no
    empty chunk and stops at :data:`MAX_CHUNKS_PER_DOCUMENT`.
    """
    body = text.strip()
    if not body:
        return []
    chunks: list[str] = []
    start = 0
    length = len(body)
    while start < length and len(chunks) < MAX_CHUNKS_PER_DOCUMENT:
        end = min(start + CHUNK_CHARS, length)
        if end < length:
            end = start + _break_offset(body, start, end)
        chunk = body[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= length:
            break
        start = max(end - CHUNK_OVERLAP, start + 1)
    return chunks


def _usable_vector(vector: list[float]) -> list[float] | None:
    """Return *vector*, or None when it is empty or implausibly wide."""
    if not vector or len(vector) > EMBEDDING_DIM_SANITY:
        return None
    return vector


def _usable_vectors(vectors: list[list[float]] | None, count: int) -> list[list[float]] | None:
    """Return one usable vector per chunk, or None when the batch does not fit."""
    if vectors is None or len(vectors) != count:
        return None
    if any(_usable_vector(vector) is None for vector in vectors):
        return None
    return vectors


def _embed_chunks(chunks: list[str]) -> list[list[float]] | None:
    """Embed *chunks* through the configured endpoint, or None.

    An endpoint that is absent, fails, or answers with a vector that does not
    fit the batch leaves the document to the TF-IDF path: storing the text is
    what makes it searchable at all, so an embeddings failure never fails an
    ingest.
    """
    try:
        return _usable_vectors(llm.embeddings(chunks), len(chunks))
    except llm.LlmError:
        return None


def _summary_row(document: dict[str, Any]) -> dict[str, Any]:
    """A stored document without its full text, for an ingest response."""
    return {key: value for key, value in document.items() if key != "text"}


def _unusable_reason(data: bytes) -> tuple[str, str]:
    """Return the error code and detail of data that extracts to no text."""
    if looks_binary(data):
        return ERROR_BINARY_CONTENT, "document carries no extractable text"
    return ERROR_EMPTY_TEXT, "document has no text"


def ingest_document(
    conn: sqlite3.Connection,
    *,
    scope_kind: str,
    scope_id: int,
    title: str,
    source: str,
    mime: str,
    data: bytes,
) -> dict[str, Any]:
    """Store one document and its chunks, deduped by content hash.

    ``scope_kind`` is validated against :data:`SCOPE_KINDS` and ``source``
    doubles as the filename hint that decides HTML handling, so a caller
    ingesting a file passes its name.  The same bytes twice in one scope return
    the stored row with ``duplicate: true``; the returned row carries the
    document's metadata, its chunk count and whether its chunks were embedded,
    never the whole text.

    Raises :class:`KnowledgeError` for an unknown scope kind, a document past
    :data:`MAX_DOCUMENT_BYTES`, a scope holding
    :data:`MAX_DOCUMENTS_PER_SCOPE` documents, or data that extracts to no
    text.
    """
    if scope_kind not in SCOPE_KINDS:
        raise KnowledgeError(ERROR_INVALID_SCOPE, f"unsupported scope kind: {scope_kind}")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise KnowledgeError(ERROR_FILE_TOO_LARGE, f"document exceeds {MAX_DOCUMENT_BYTES} bytes")
    sha256 = hashlib.sha256(data).hexdigest()
    existing = store.find_document_by_sha256(
        conn, scope_kind=scope_kind, scope_id=scope_id, sha256=sha256
    )
    if existing is not None:
        return {
            **_summary_row(existing),
            "duplicate": True,
            "embedded": _is_embedded(conn, existing),
        }
    if store.count_documents(conn, scope_kind=scope_kind, scope_id=scope_id) >= (
        MAX_DOCUMENTS_PER_SCOPE
    ):
        raise KnowledgeError(
            ERROR_TOO_MANY_DOCUMENTS,
            f"scope {scope_kind} {scope_id} holds {MAX_DOCUMENTS_PER_SCOPE} documents",
        )
    text = extract_text(data, filename=source)
    if text is None:
        raise KnowledgeError(*_unusable_reason(data))
    chunks = chunk_text(text)
    vectors = _embed_chunks(chunks)
    # Document and chunks share one commit: a crash between the row and its
    # ordinals would leave a document the search path cannot retrieve.
    document_id = store.add_document(
        conn,
        scope_kind=scope_kind,
        scope_id=scope_id,
        title=title.strip() or DEFAULT_DOCUMENT_TITLE,
        source=source,
        mime=mime,
        sha256=sha256,
        size=len(data),
        text=text,
        commit=False,
    )
    try:
        for ordinal, chunk in enumerate(chunks):
            store.add_chunk(
                conn,
                document_id=document_id,
                ordinal=ordinal,
                text=chunk,
                embedding=vectors[ordinal] if vectors is not None else None,
                commit=False,
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    stored = store.get_document(conn, document_id)
    return {**_summary_row(stored or {}), "duplicate": False, "embedded": vectors is not None}


def _is_embedded(conn: sqlite3.Connection, document: dict[str, Any]) -> bool:
    """True when any chunk of *document* carries a stored embedding."""
    return any(chunk["embedded"] for chunk in store.list_chunks(conn, int(document["id"])))


def _query_vector(text: str) -> list[float] | None:
    """Embed *text* through the configured endpoint, or None when unavailable."""
    try:
        vectors = llm.embeddings([text])
    except llm.LlmError:
        return None
    if not vectors or len(vectors) != 1:
        return None
    return _usable_vector(vectors[0])


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    """Cosine similarity of two equal-length dense vectors."""
    dot = 0.0
    left_norm = 0.0
    right_norm = 0.0
    for a, b in zip(left, right, strict=True):
        dot += a * b
        left_norm += a * a
        right_norm += b * b
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / math.sqrt(left_norm * right_norm)


def _embedding_scores(
    chunks: list[dict[str, Any]], vector: list[float]
) -> list[tuple[float, dict[str, Any]]]:
    """Cosine-rank the chunks carrying an embedding as wide as *vector*."""
    scored: list[tuple[float, dict[str, Any]]] = []
    for chunk in chunks:
        stored = chunk["embedding"]
        if stored is None or len(stored) != len(vector):
            continue
        score = _cosine_similarity(vector, stored)
        if score > 0.0:
            scored.append((score, chunk))
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored


def _tokens(text: str) -> list[str]:
    """Lower-cased word tokens of *text*, without the :data:`STOPWORDS`."""
    tokens = (match.group().lower() for match in _TOKEN_RE.finditer(text))
    return [token for token in tokens if token not in STOPWORDS]


def _inverse_document_frequency(documents: list[list[str]]) -> dict[str, float]:
    """Smoothed inverse document frequency over the chunk corpus."""
    total = len(documents)
    document_frequency: dict[str, int] = {}
    for tokens in documents:
        for token in set(tokens):
            document_frequency[token] = document_frequency.get(token, 0) + 1
    return {
        token: math.log((total + 1) / (count + 1)) + 1.0
        for token, count in document_frequency.items()
    }


def _tfidf_vector(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
    """L2-normalized TF-IDF vector of the tokens the corpus already knows."""
    counts: dict[str, int] = {}
    for token in tokens:
        if token in idf:
            counts[token] = counts.get(token, 0) + 1
    if not counts:
        return {}
    weighted = {token: count * idf[token] for token, count in counts.items()}
    norm = math.sqrt(sum(value * value for value in weighted.values()))
    if norm == 0.0:
        return {}
    return {token: value / norm for token, value in weighted.items()}


def _sparse_cosine(left: dict[str, float], right: dict[str, float]) -> float:
    """Cosine of two L2-normalized sparse vectors."""
    if len(left) > len(right):
        left, right = right, left
    return sum(value * right.get(token, 0.0) for token, value in left.items())


def _tfidf_scores(chunks: list[dict[str, Any]], query: str) -> list[tuple[float, dict[str, Any]]]:
    """Rank *chunks* against *query* with a local TF-IDF cosine."""
    documents = [_tokens(chunk["text"]) for chunk in chunks]
    query_tokens = _tokens(query)
    if not query_tokens:
        return []
    idf = _inverse_document_frequency(documents)
    query_vector = _tfidf_vector(query_tokens, idf)
    if not query_vector:
        return []
    scored: list[tuple[float, dict[str, Any]]] = []
    for chunk, tokens in zip(chunks, documents, strict=True):
        score = _sparse_cosine(query_vector, _tfidf_vector(tokens, idf))
        if score > 0.0:
            scored.append((score, chunk))
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored


def search_knowledge(
    conn: sqlite3.Connection,
    *,
    query: str,
    scope_kind: str | None = None,
    scope_id: int | None = None,
    limit: int = DEFAULT_SEARCH_LIMIT,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Rank stored chunks against *query*, best first.

    The query is embedded when an embeddings endpoint is configured and the
    stored chunks carry vectors, and the ranking is then a cosine similarity;
    otherwise the local TF-IDF cosine ranks the same chunks, so search works
    with zero configuration.  Every result reports the ``method`` that scored
    it.  An empty query, a non-positive limit or no stored chunk returns [].

    ``visible_to`` drops chunks of binary-scoped documents on binaries the
    caller may not see, like the other scoped reads; chunks of other scopes
    (project, docs) have no owning binary and stay.
    """
    from reportal import auth

    text = query.strip()
    if not text or limit < 1:
        return []
    chunks = store.iter_chunks_with_embeddings(conn, scope_kind=scope_kind, scope_id=scope_id)
    if not chunks:
        return []
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, params = scope
        visible_ids = {
            int(row["id"])
            for row in conn.execute(f"SELECT b.id AS id FROM binaries b WHERE {clause}", params)
        }
        chunks = [
            chunk
            for chunk in chunks
            if str(chunk.get("scope_kind")) != SCOPE_KIND_BINARY
            or int(chunk["scope_id"]) in visible_ids
        ]
        if not chunks:
            return []
    vector = _query_vector(text)
    method = METHOD_EMBEDDINGS
    scored: list[tuple[float, dict[str, Any]]] = []
    if vector is not None:
        scored = _embedding_scores(chunks, vector)
    if not scored:
        scored = _tfidf_scores(chunks, text)
        method = METHOD_TFIDF
    return [
        {
            "document_id": chunk["document_id"],
            "chunk_id": chunk["id"],
            "title": chunk["title"],
            "source": chunk["source"],
            "text": chunk["text"],
            "score": round(score, 6),
            "method": method,
        }
        for score, chunk in scored[:limit]
    ]


def retrieve(
    conn: sqlite3.Connection,
    *,
    query: str,
    scope_kind: str | None = None,
    scope_id: int | None = None,
    limit: int = RETRIEVAL_LIMIT,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Rank the stored chunks of one scope against *query*, best first.

    A thin wrapper over :func:`search_knowledge` with the retrieval default
    limit.  A blank query or a non-positive limit answers [] without touching
    the store, so a caller with no usable query injects nothing.
    """
    if not query.strip() or limit < 1:
        return []
    return search_knowledge(
        conn,
        query=query,
        scope_kind=scope_kind,
        scope_id=scope_id,
        limit=limit,
        visible_to=visible_to,
    )


def _hit_field(hit: dict[str, Any], key: str) -> str:
    """Return ``hit[key]`` as a string, with the spaces collapsed to one line."""
    return " ".join(str(hit.get(key, "")).split())


def _snippet(text: str) -> str:
    """One line of *text*, truncated to :data:`RETRIEVAL_SNIPPET_CHARS`."""
    collapsed = " ".join(text.split())
    if len(collapsed) <= RETRIEVAL_SNIPPET_CHARS:
        return collapsed
    return collapsed[: RETRIEVAL_SNIPPET_CHARS - 1] + "…"


def as_context(hits: list[dict[str, Any]], *, max_chars: int = RETRIEVAL_CONTEXT_CHARS) -> str:
    """Render *hits* as a bounded, citable block.

    One line per hit, ``[n] <title> (<source>): <text>``, with the snippet
    truncated to :data:`RETRIEVAL_SNIPPET_CHARS` and its whitespace collapsed.
    A hit whose line would push the block past *max_chars* is dropped, so the
    joined result never exceeds the budget; numbering stays contiguous over
    the lines kept, and no hits render as "".
    """
    lines: list[str] = []
    used = 0
    for hit in hits:
        line = (
            f"[{len(lines) + 1}] {_hit_field(hit, 'title')}"
            f" ({_hit_field(hit, 'source')}): {_snippet(_hit_field(hit, 'text'))}"
        )
        cost = len(line) + (1 if lines else 0)
        if used + cost > max_chars:
            continue
        lines.append(line)
        used += cost
    return "\n".join(lines)

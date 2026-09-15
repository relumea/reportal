"""Analyst comments: scope and body validation over the ``comments`` table.

The store accepts any scope kind and only checks that a body is non-empty.
This module is what decides which scopes exist and that the scope id resolves,
so the JSON API, the CLI and the MCP server report the same failure for the
same input: an unsupported scope kind or an unusable body is a bad request,
an unknown scope id or comment id is a not-found.

The author is free text with no identity behind it; :data:`DEFAULT_AUTHOR` is
recorded when the caller names none.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from reportal import store

SCOPE_BINARY = "binary"
SCOPE_FUNCTION = "function"
SCOPE_KINDS: tuple[str, ...] = (SCOPE_BINARY, SCOPE_FUNCTION)

# Longest comment body accepted, in characters.  A comment is a short analyst
# note, not a document, so a body past the cap is rejected rather than stored.
MAX_COMMENT_CHARS = 4000

# Author recorded on a comment whose creator names none.
DEFAULT_AUTHOR = "analyst"


class CommentError(Exception):
    """Base class for a rejected comment operation."""


class InvalidCommentError(CommentError, ValueError):
    """The scope kind or the body is unusable; the API answers 400."""


class UnknownScopeError(CommentError, KeyError):
    """No binary or function carries the requested scope id; the API answers 404."""

    def __init__(self, scope_kind: str, scope_id: int) -> None:
        super().__init__(f"no {scope_kind} with id {scope_id}")
        self.scope_kind = scope_kind
        self.scope_id = scope_id


class UnknownCommentError(CommentError, KeyError):
    """No comment carries the requested id; the API answers 404."""


def _scope_exists(conn: sqlite3.Connection, scope_kind: str, scope_id: int) -> bool:
    if scope_kind == SCOPE_BINARY:
        return store.get_binary(conn, scope_id) is not None
    if scope_kind == SCOPE_FUNCTION:
        return store.get_function(conn, scope_id) is not None
    return False


def check_scope(conn: sqlite3.Connection, *, scope_kind: str, scope_id: int) -> None:
    """Validate a scope kind and its id, raising a :class:`CommentError`."""
    if scope_kind not in SCOPE_KINDS:
        raise InvalidCommentError(f"unsupported scope kind: {scope_kind}")
    if not _scope_exists(conn, scope_kind, scope_id):
        raise UnknownScopeError(scope_kind, scope_id)


def normalize_body(body: str) -> str:
    """Trim and bound a comment body, raising :class:`InvalidCommentError`."""
    if not isinstance(body, str):
        raise InvalidCommentError("body must be a string")
    trimmed = body.strip()
    if not trimmed:
        raise InvalidCommentError("body must not be empty")
    if len(trimmed) > MAX_COMMENT_CHARS:
        raise InvalidCommentError(f"body exceeds {MAX_COMMENT_CHARS} characters")
    return trimmed


def normalize_author(author: str | None) -> str:
    """Return *author* trimmed, or :data:`DEFAULT_AUTHOR` when it is blank."""
    name = (author or "").strip()
    return name or DEFAULT_AUTHOR


def add_comment(
    conn: sqlite3.Connection,
    *,
    scope_kind: str,
    scope_id: int,
    body: str,
    author: str | None = None,
) -> dict[str, Any]:
    """Validate a scope and body, then store one comment and return its row."""
    check_scope(conn, scope_kind=scope_kind, scope_id=scope_id)
    return store.add_comment(
        conn,
        scope_kind=scope_kind,
        scope_id=scope_id,
        author=normalize_author(author),
        body=normalize_body(body),
    )


def list_comments(
    conn: sqlite3.Connection,
    *,
    scope_kind: str,
    scope_id: int,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Comments of one scope, oldest first; the scope must exist."""
    check_scope(conn, scope_kind=scope_kind, scope_id=scope_id)
    return store.list_comments(
        conn, scope_kind=scope_kind, scope_id=scope_id, visible_to=visible_to
    )


def get_comment(conn: sqlite3.Connection, comment_id: int) -> dict[str, Any]:
    """One comment by id, raising :class:`UnknownCommentError` when absent."""
    found = store.get_comment(conn, comment_id)
    if found is None:
        raise UnknownCommentError(f"no comment with id {comment_id}")
    return found


def update_comment(conn: sqlite3.Connection, comment_id: int, *, body: str) -> dict[str, Any]:
    """Replace a comment's body, raising for an unusable body or unknown id."""
    updated = store.update_comment(conn, comment_id, body=normalize_body(body))
    if updated is None:
        raise UnknownCommentError(f"no comment with id {comment_id}")
    return updated


def delete_comment(conn: sqlite3.Connection, comment_id: int) -> dict[str, Any]:
    """Delete one comment, raising :class:`UnknownCommentError` when absent."""
    found = get_comment(conn, comment_id)
    store.delete_comment(conn, comment_id)
    return found

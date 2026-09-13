"""The AI decompilation artifact: one rewritten function, its token map and rating.

reportal already stores the four flat AI artifacts (a summary, inline comments,
type suggestions and rename suggestions) over a decompilation rebrew produced.
This module is the hosted portal's richer first-class artifact: a complete
rewritten rendition of one function, the placeholder tokens it still carries
with the analyst overrides that rename them, per-line attribution of every line
against the decompilation the model read, an analyst rating, and per-line
inline comments beside it.

The artifact is an ``ai_artifacts`` row of kind :data:`KIND`, so it is journaled
and revertible through the same generic row-restore path as the other four
kinds and is snapshotted by the binary and analysis delete plans that already
name that table.  Nothing here runs an engine and nothing reaches the network
on its own: a rewrite needs a configured bridge, and every other operation is
local text work over the stored artifact.

Three derivations are local and deterministic, never model-reported, and the
response says so in ``derivation``:

* the token map is a regular-expression scan of the rewrite for the placeholder
  shapes the decompilers emit (``local_8``, ``param_1``, ``uVar2``, ``DAT_...``,
  ``FUN_...`` and friends);
* an attribution is a line diff between the rewrite and the stored
  decompilation: a line that matches one in the source is ``original``, a line
  whose counterpart differs is ``rewritten``, and a line with no counterpart is
  ``added``.  The model never reports provenance, so a derived attribution is
  what an analyst gets;
* the rendered text applies the overrides to the rewrite at read time and never
  mutates it, so clearing an override restores the model's own words by
  construction.

Line comments are keyed by line number, one per line, which is exactly the
hosted ``inline-comments/{line}`` contract and needs no id of its own.
"""

from __future__ import annotations

import difflib
import json
import re
import sqlite3
from collections.abc import Mapping
from typing import Any

from reportal import comments, journal, llm, renames, store

# Stored artifact kind.  It is deliberately not in `llm.AI_KINDS`: the four
# kinds there are flat payloads served verbatim, and this one carries a token
# map, attributions, overrides, a rating and per-line comments.
KIND = "ai-decompilation"

# Placeholder shapes the decompilers emit, in one scan.  Order matters only for
# the documentation; the classifier below names each match's kind.
TOKEN_RE = re.compile(
    r"\b(?:"
    r"local_[0-9a-fA-F]+"
    r"|param_\d+"
    r"|(?:field|var|arg|stack)_[0-9a-fA-Fx]+"
    r"|[a-z]Var\d+"
    r"|(?:DAT|FUN|LAB|SUB|sub|off|unk|byte|word|dword|qword|str|flt|dbl)_[0-9a-fA-F]+"
    r"|[A-Za-z_]*UNK[A-Za-z0-9_]*"
    r")\b"
)

# Per-token line list bound.  A token used on more lines than this keeps the
# first `MAX_TOKEN_LINES` numbers plus the true `line_count`, so one hot
# placeholder cannot bloat the artifact.
MAX_TOKEN_LINES = 40

# Longest override name accepted, in characters.
MAX_OVERRIDE_NAME = 128

# Longest per-line comment accepted, in characters (the analyst comment bound).
MAX_LINE_COMMENT_CHARS = comments.MAX_COMMENT_CHARS

# The rating vocabulary, the hosted analyst feedback field.
RATINGS: tuple[str, ...] = ("up", "down")

# What the response says about how a derived part was produced.
DERIVATION = (
    "tokens are a local scan of the rewrite for decompiler placeholder shapes;"
    " attributions are a local line diff against the stored decompilation, not"
    " model-reported provenance; the rendered code applies the stored overrides"
    " at read time and the model's rewrite is kept unchanged"
)

# An override name the compiler accepts.
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class AiDecompError(Exception):
    """Base class for a rejected AI-decompilation operation."""


class NoAiDecompilationError(AiDecompError, LookupError):
    """No artifact is stored for the function; the API answers 404."""


class InvalidOverrideError(AiDecompError, ValueError):
    """An override name is unusable; the API answers 400."""


class UnknownTokenError(AiDecompError, LookupError):
    """The artifact carries no such placeholder token; the API answers 404."""


class InvalidRatingError(AiDecompError, ValueError):
    """A rating is outside the vocabulary; the API answers 400."""


class InvalidLineCommentError(AiDecompError, ValueError):
    """A line number or comment body is unusable; the API answers 400."""


class UnknownLineCommentError(AiDecompError, LookupError):
    """No line comment is stored at that line; the API answers 404."""


# ── Derivations over the stored rewrite ────────────────────────────


def token_kind(token: str) -> str:
    """Classify one placeholder token by the decompiler shape it matches."""
    if token.startswith("param_"):
        return "parameter"
    if token.startswith(("local_", "field_", "var_", "arg_", "stack_")):
        return "local"
    if token.startswith(("FUN_", "sub_", "SUB_")):
        return "function"
    if token.startswith("LAB_"):
        return "label"
    if "UNK" in token:
        return "unknown"
    if re.fullmatch(r"[a-z]Var\d+", token):
        return "variable"
    return "global"


def tokens_of(code: str) -> list[dict[str, Any]]:
    """Scan *code* for placeholder tokens, first-seen order, with line numbers."""
    found: dict[str, dict[str, Any]] = {}
    for number, line in enumerate(code.splitlines(), start=1):
        for match in TOKEN_RE.finditer(line):
            token = match.group(0)
            entry = found.get(token)
            if entry is None:
                entry = {
                    "token": token,
                    "kind": token_kind(token),
                    "count": 0,
                    "lines": [],
                    "line_count": 0,
                    "name": None,
                }
                found[token] = entry
            entry["count"] += 1
            entry["line_count"] += 1
            if len(entry["lines"]) < MAX_TOKEN_LINES:
                entry["lines"].append(number)
    return list(found.values())


def attributions_of(rewritten: str, source: str) -> list[dict[str, Any]]:
    """Attribute each rewritten line to the decompilation the model read.

    A line whose text also occurs in the source at the aligned position is
    ``original``, an aligned line that differs is ``rewritten``, and a line with
    no aligned counterpart is ``added``.  ``source_lines`` carries the source
    line numbers the alignment paired with it, so a caller can open the original
    beside the rewrite.
    """
    left = source.splitlines()
    right = rewritten.splitlines()
    matcher = difflib.SequenceMatcher(a=left, b=right, autojunk=False)
    rows: list[dict[str, Any] | None] = [None] * len(right)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            origin = "original"
        elif tag == "insert":
            origin = "added"
        else:
            origin = "rewritten"
        paired = list(range(i1 + 1, i2 + 1)) if origin != "added" else []
        for index in range(j1, j2):
            rows[index] = {
                "line": index + 1,
                "origin": origin,
                "source_lines": paired,
            }
    return [row for row in rows if row is not None]


def apply_overrides(code: str, overrides: Mapping[str, str]) -> str:
    """Rewrite each overridden token in *code* to its analyst name.

    The whole-token replacement skips string literals and never rewrites a
    prefix of a longer identifier, and the keys are applied in sorted order so
    the same artifact and overrides always render the same text.
    """
    rendered = code
    for token in sorted(overrides):
        name = overrides[token]
        if token == name:
            continue
        rendered = renames.replace_identifier(rendered, token, name)[0]
    return rendered


# ── Payload construction and validation ────────────────────────────


def _payload(rewritten: str, source: str, model: str) -> dict[str, Any]:
    """Assemble a fresh artifact payload from a rewrite and the code it read."""
    return {
        "rewritten_code": rewritten,
        "model": model,
        "tokens": tokens_of(rewritten),
        "attributions": attributions_of(rewritten, source),
        "overrides": {},
        "rating": None,
        "rating_note": "",
        "line_comments": [],
    }


def normalize_override_name(name: Any) -> str:
    """Validate one override name, raising :class:`InvalidOverrideError`."""
    if not isinstance(name, str):
        raise InvalidOverrideError("override name must be a string")
    trimmed = name.strip()
    if not _IDENTIFIER_RE.fullmatch(trimmed):
        raise InvalidOverrideError(f"not a C identifier: {trimmed!r}")
    if len(trimmed) > MAX_OVERRIDE_NAME:
        raise InvalidOverrideError(f"override name exceeds {MAX_OVERRIDE_NAME} characters")
    if trimmed in renames.PROTECTED_IDENTIFIERS:
        raise InvalidOverrideError(f"override name is a C keyword: {trimmed}")
    return trimmed


def normalize_overrides(raw: Any, tokens: list[dict[str, Any]]) -> dict[str, str | None]:
    """Validate an overrides mapping against the artifact's token map.

    A value of ``None`` (or an empty string) clears the override for that token.
    A token the artifact does not carry is :class:`UnknownTokenError`, so a typo
    is reported rather than silently stored.
    """
    if not isinstance(raw, Mapping):
        raise InvalidOverrideError("overrides must be an object of token to name")
    known = {str(entry["token"]) for entry in tokens}
    normalized: dict[str, str | None] = {}
    for token, name in raw.items():
        if not isinstance(token, str) or token not in known:
            raise UnknownTokenError(f"no placeholder token {token!r} in the artifact")
        if name is None or (isinstance(name, str) and not name.strip()):
            normalized[token] = None
            continue
        normalized[token] = normalize_override_name(name)
    return normalized


def normalize_rating(rating: Any) -> str | None:
    """Validate a rating, raising :class:`InvalidRatingError`."""
    if rating is None or (isinstance(rating, str) and not rating.strip()):
        return None
    if not isinstance(rating, str) or rating.strip().lower() not in RATINGS:
        raise InvalidRatingError(f"rating must be one of {', '.join(RATINGS)}, or null")
    return rating.strip().lower()


def normalize_line(line: Any, line_count: int) -> int:
    """Validate a 1-based line number inside a rewrite of *line_count* lines."""
    if isinstance(line, bool) or not isinstance(line, int):
        raise InvalidLineCommentError("line must be an integer")
    if line < 1 or line > line_count:
        raise InvalidLineCommentError(f"line must be between 1 and {line_count}")
    return line


# ── Store access ───────────────────────────────────────────────────


def get(conn: sqlite3.Connection, function_id: int) -> dict[str, Any] | None:
    """Return the stored artifact row of *function_id*, or None."""
    artifact = store.get_ai_artifact(conn, function_id, KIND)
    if artifact is None:
        return None
    payload = artifact["payload"]
    if not isinstance(payload.get("rewritten_code"), str):
        return None
    payload.setdefault("tokens", [])
    payload.setdefault("attributions", [])
    payload.setdefault("overrides", {})
    payload.setdefault("rating", None)
    payload.setdefault("rating_note", "")
    payload.setdefault("line_comments", [])
    return artifact


def require(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """Return the stored artifact, raising :class:`NoAiDecompilationError` when absent."""
    artifact = get(conn, function_id)
    if artifact is None:
        raise NoAiDecompilationError(
            f"no AI decompilation for function {function_id};"
            f" run 'reportal ai-decompile {function_id}' first"
        )
    return artifact


def view(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Return the served artifact: rendered code, token map, attributions and feedback."""
    payload = artifact["payload"]
    overrides = payload.get("overrides") or {}
    tokens = [
        {**entry, "name": overrides.get(str(entry.get("token")))} for entry in payload["tokens"]
    ]
    return {
        "kind": KIND,
        "model": artifact["model"],
        "created_at": artifact["created_at"],
        "code": apply_overrides(str(payload["rewritten_code"]), overrides),
        "rewritten_code": payload["rewritten_code"],
        "tokens": tokens,
        "attributions": payload["attributions"],
        "overrides": overrides,
        "rating": payload.get("rating"),
        "rating_note": payload.get("rating_note", ""),
        "line_comments": payload.get("line_comments", []),
        "derivation": DERIVATION,
    }


def status(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """The workflow state of one stored artifact, without its text."""
    payload = artifact["payload"]
    counts: dict[str, int] = {"original": 0, "rewritten": 0, "added": 0}
    for row in payload["attributions"]:
        origin = str(row.get("origin"))
        if origin in counts:
            counts[origin] += 1
    overrides = payload.get("overrides") or {}
    tokens = payload["tokens"]
    return {
        "state": "ready",
        "model": artifact["model"],
        "created_at": artifact["created_at"],
        "line_count": len(str(payload["rewritten_code"]).splitlines()),
        "token_count": len(tokens),
        "overridden_count": sum(1 for entry in tokens if overrides.get(str(entry["token"]))),
        "attribution_counts": counts,
        "rating": payload.get("rating"),
        "line_comment_count": len(payload.get("line_comments", [])),
    }


def write_artifact(
    conn: sqlite3.Connection,
    log: journal.Journal,
    function_id: int,
    payload: Mapping[str, Any],
    *,
    description: str,
) -> None:
    """Persist one artifact payload inside the caller's journaled action.

    This is the single write path every mutator below shares, so all six of them
    journal the row they replace (or the row they create) identically.
    """
    before = journal.journaled_rows(
        conn,
        log,
        table="ai_artifacts",
        where="function_id = ? AND kind = ?",
        params=(function_id, KIND),
        description=description,
    )
    store.set_ai_artifact(conn, function_id, KIND, dict(payload), str(payload["model"]))
    if not before:
        journal.journaled_create(
            log,
            table="ai_artifacts",
            key={"function_id": function_id, "kind": KIND},
            description=description,
        )


# ── Mutations ──────────────────────────────────────────────────────


def rewrite(conn: sqlite3.Connection, function_id: int, *, client: llm.LlmClient) -> dict[str, Any]:
    """Ask the model for a rewritten function and return the new payload.

    The model's input is the function's stored decompilation and never a
    generated one, so a function without one raises
    :class:`reportal.renames.NoDecompilationError`.
    """
    stored = store.get_decompilation(conn, function_id)
    if stored is None:
        raise renames.NoDecompilationError(f"function {function_id} has no stored decompilation")
    source = str(stored["code"])
    result = llm.rewrite_decompilation(source, client=client)
    return _payload(str(result["code"]), source, client.model)


def set_overrides(
    conn: sqlite3.Connection, function_id: int, raw: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Merge an overrides mapping into the artifact.

    Returns the new payload and the ``changes`` the caller reports.  A ``None``
    value clears the override for that token.  The rewrite itself is never
    touched, so clearing one restores the model's own text.
    """
    artifact = require(conn, function_id)
    payload = dict(artifact["payload"])
    changes = normalize_overrides(raw, payload["tokens"])
    overrides = {str(key): str(value) for key, value in (payload.get("overrides") or {}).items()}
    for token, name in changes.items():
        if name is None:
            overrides.pop(token, None)
        else:
            overrides[token] = name
    payload["overrides"] = overrides
    return payload, {"changes": changes}


def rate(
    conn: sqlite3.Connection, function_id: int, *, rating: Any, note: Any = None
) -> dict[str, Any]:
    """Set the artifact's analyst rating (and free-text note)."""
    artifact = require(conn, function_id)
    payload = dict(artifact["payload"])
    payload["rating"] = normalize_rating(rating)
    if note is not None:
        if not isinstance(note, str):
            raise InvalidRatingError("note must be a string")
        payload["rating_note"] = note.strip()
    return payload


def _comment_body(body: Any) -> str:
    try:
        return comments.normalize_body(body)
    except comments.InvalidCommentError as exc:
        raise InvalidLineCommentError(str(exc)) from exc


def add_line_comment(
    conn: sqlite3.Connection,
    function_id: int,
    *,
    line: Any,
    body: Any,
    author: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Store one comment at *line*, replacing any comment already there."""
    artifact = require(conn, function_id)
    payload = dict(artifact["payload"])
    rows = [dict(entry) for entry in payload.get("line_comments", [])]
    text = str(payload["rewritten_code"])
    number = normalize_line(line, len(text.splitlines()))
    now = store.now()
    entry = {
        "line": number,
        "body": _comment_body(body),
        "author": comments.normalize_author(author),
        "created_at": now,
        "updated_at": now,
    }
    existing = next((row for row in rows if row["line"] == number), None)
    if existing is not None:
        entry["created_at"] = existing["created_at"]
        rows = [entry if row["line"] == number else row for row in rows]
    else:
        rows.append(entry)
    rows.sort(key=lambda row: int(row["line"]))
    payload["line_comments"] = rows
    return payload, entry


def update_line_comment(
    conn: sqlite3.Connection, function_id: int, *, line: Any, body: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replace the body of the comment stored at *line*."""
    artifact = require(conn, function_id)
    payload = dict(artifact["payload"])
    rows = [dict(entry) for entry in payload.get("line_comments", [])]
    text = str(payload["rewritten_code"])
    number = normalize_line(line, len(text.splitlines()))
    found = next((row for row in rows if row["line"] == number), None)
    if found is None:
        raise UnknownLineCommentError(f"no line comment at line {number}")
    found["body"] = _comment_body(body)
    found["updated_at"] = store.now()
    payload["line_comments"] = rows
    return payload, found


def delete_line_comment(
    conn: sqlite3.Connection, function_id: int, *, line: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Remove the comment stored at *line*."""
    artifact = require(conn, function_id)
    payload = dict(artifact["payload"])
    rows = [dict(entry) for entry in payload.get("line_comments", [])]
    text = str(payload["rewritten_code"])
    number = normalize_line(line, len(text.splitlines()))
    found = next((row for row in rows if row["line"] == number), None)
    if found is None:
        raise UnknownLineCommentError(f"no line comment at line {number}")
    payload["line_comments"] = [row for row in rows if row["line"] != number]
    return payload, found


def events(artifact: Mapping[str, Any]) -> list[str]:
    """The artifact's workflow as server-sent event frames.

    The workflow is one model call, so it is already over by the time the stream
    opens: the frames are the current state and its terminal marker, which is
    what a client that attaches after the call needs.  A stream that pretended
    to progress would be narrating a call that already returned.
    """
    state = status(artifact)
    return [
        f"event: ai-decompilation\ndata: {json.dumps(state)}\n\n",
        f"event: done\ndata: {json.dumps({'state': 'ready'})}\n\n",
    ]

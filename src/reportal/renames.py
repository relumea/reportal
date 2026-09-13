"""LLM identifier renaming over a function's stored decompilation.

The function-name half of the Agents/Reverse surface already exists: rebrew's
library identification proposes names and an apply records them.  This module
is the variable/parameter half.  It asks the configured OpenAI-compatible
bridge for renames on a decompilation reportal already stored, keeps the
suggestions as an ``ai_artifacts`` row of kind ``renames``, and applies a
chosen subset to that stored text with a journal, so an apply is reversible.

Nothing here calls a model unless an endpoint is configured: a suggest without
one raises :class:`reportal.llm.LlmUnavailable`, which the API and CLI report
as ``llm-unavailable``.  An apply is deterministic text work and needs no
endpoint; it never touches the rebrew project or the binary.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from typing import Any

from reportal import llm, store

# Stored artifact kinds: the suggestions the model produced and the journal a
# successful apply writes so `revert_renames` can put the text back.
RENAMES_KIND = "renames"
RENAMES_APPLIED_KIND = "renames-applied"

# Actor and name_history source an apply records.  A function-kind suggestion
# applied with `rename_function` lands under the same label as the panel.
RENAME_SOURCE = "renames"
DEFAULT_ACTOR = "renames"

# Shortest identifier an apply may rewrite or introduce.  A one- or two-character
# token (`a`, `n`, `sp`) occurs as a substring of unrelated identifiers, so a
# word-boundary rewrite of it is not safe.
MIN_IDENTIFIER_LENGTH = 3

# C keywords and predefined names a rename must never target or introduce.
PROTECTED_IDENTIFIERS = frozenset(
    {
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
        "NULL",
        "bool",
        "false",
        "size_t",
        "true",
    }
)

# C identifier shape: a rename writes only names the compiler accepts.
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# String literal openers an apply skips over, so a rename never rewrites text
# inside a literal.
_STRING_QUOTES = ('"', "'")


class NoDecompilationError(Exception):
    """The function has no stored decompilation to rename identifiers in."""


class NoSuggestionError(Exception):
    """No stored rename suggestion exists to apply."""


class NoRevertError(Exception):
    """No applied rename is journaled for the function."""


def identifier_pattern(name: str) -> re.Pattern[str]:
    """Return a word-boundary pattern matching the identifier *name* exactly."""
    return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])")


def identifier_present(text: str, name: str) -> bool:
    """True when *name* occurs in *text* as a whole token."""
    return identifier_pattern(name).search(text) is not None


def replace_identifier(text: str, old: str, new: str) -> tuple[str, int]:
    """Rewrite whole-token occurrences of *old* to *new*; returns (text, count).

    The scan tracks string literals, so an occurrence inside one is left alone,
    and the word-boundary pattern means a prefix or suffix of a longer token is
    never rewritten.
    """
    pattern = identifier_pattern(old)
    pieces: list[str] = []
    count = 0
    index = 0
    quote: str | None = None
    while index < len(text):
        char = text[index]
        if quote is not None:
            pieces.append(char)
            if char == "\\" and index + 1 < len(text):
                pieces.append(text[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in _STRING_QUOTES:
            quote = char
            pieces.append(char)
            index += 1
            continue
        match = pattern.match(text, index)
        if match is not None:
            pieces.append(new)
            count += 1
            index = match.end()
            continue
        pieces.append(char)
        index += 1
    return "".join(pieces), count


def _normalize_suggestion(entry: Any) -> dict[str, Any] | None:
    """Return one suggestion with its fields coerced, or None when unusable."""
    if not isinstance(entry, dict):
        return None
    from_name = entry.get("from")
    to_name = entry.get("to")
    if not isinstance(from_name, str) or not isinstance(to_name, str):
        return None
    if not from_name.strip() or not to_name.strip():
        return None
    kind = entry.get("kind")
    reason = entry.get("reason")
    return {
        "from": from_name.strip(),
        "to": to_name.strip(),
        "kind": kind.strip()
        if isinstance(kind, str) and kind.strip() in llm.RENAME_KINDS
        else llm.DEFAULT_RENAME_KIND,
        "reason": reason.strip() if isinstance(reason, str) else "",
        "confidence": llm.confidence(entry.get("confidence")),
    }


def _refusal(suggestion: dict[str, Any], text: str) -> str | None:
    """Return why *suggestion* cannot be applied to *text*, or None when it can."""
    from_name = suggestion["from"]
    to_name = suggestion["to"]
    if _IDENTIFIER_RE.fullmatch(from_name) is None or _IDENTIFIER_RE.fullmatch(to_name) is None:
        return "not a C identifier"
    if from_name in PROTECTED_IDENTIFIERS or to_name in PROTECTED_IDENTIFIERS:
        return "protected identifier"
    if len(from_name) < MIN_IDENTIFIER_LENGTH or len(to_name) < MIN_IDENTIFIER_LENGTH:
        return f"identifier shorter than {MIN_IDENTIFIER_LENGTH} characters"
    if from_name == to_name:
        return "name unchanged"
    if not identifier_present(text, from_name):
        return "from is not present in the decompilation"
    return None


def suggest_renames(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    client: llm.LlmClient | None = None,
    context: str = "",
) -> dict[str, Any]:
    """Ask the configured LLM for renames and store the suggestions.

    The model's input is the function's stored decompilation, which is never
    generated here.  Entries that are not ``from``/``to`` pairs, that repeat a
    ``from`` already kept, or whose ``from`` does not occur in the source are
    dropped.  Returns ``{"function_id", "model", "suggestions", "count"}``.
    Raises :class:`KeyError` for an unknown function,
    :class:`NoDecompilationError` without a stored decompilation and
    :class:`reportal.llm.LlmUnavailable` / :class:`reportal.llm.LlmError` from
    the bridge.
    """
    if store.get_function(conn, function_id) is None:
        raise KeyError(f"no function with id {function_id}")
    stored = store.get_decompilation(conn, function_id)
    if stored is None:
        raise NoDecompilationError(f"function {function_id} has no stored decompilation")
    code = str(stored["code"])
    active = client if client is not None else llm.get_client()
    if not active.available():
        raise llm.LlmUnavailable(llm.UNAVAILABLE_DETAIL)
    payload = llm.rename_suggestions(code, client=active, context=context)
    raw = payload.get("suggestions")
    entries = raw if isinstance(raw, list) else []
    suggestions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        suggestion = _normalize_suggestion(entry)
        if suggestion is None:
            continue
        from_name = suggestion["from"]
        if from_name in seen or not identifier_present(code, from_name):
            continue
        seen.add(from_name)
        suggestions.append(suggestion)
    store.set_ai_artifact(
        conn, function_id, RENAMES_KIND, {"suggestions": suggestions}, active.model
    )
    return {
        "function_id": function_id,
        "model": active.model,
        "suggestions": suggestions,
        "count": len(suggestions),
    }


def _apply_entries(
    conn: sqlite3.Connection, function_id: int, applied: Sequence[Any] | None
) -> Sequence[Any]:
    """Return the suggestions to apply: *applied*, else the stored ones.

    Raises :class:`NoSuggestionError` when the caller names none and nothing is
    stored.
    """
    if applied is not None:
        return applied
    artifact = store.get_ai_artifact(conn, function_id, RENAMES_KIND)
    suggestions = artifact["payload"].get("suggestions") if artifact is not None else None
    if not isinstance(suggestions, list) or not suggestions:
        raise NoSuggestionError(f"function {function_id} has no stored rename suggestions")
    return suggestions


def apply_renames(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    applied: Sequence[Any] | None = None,
    actor: str = DEFAULT_ACTOR,
    rename_function: bool = False,
) -> dict[str, Any]:
    """Apply rename suggestions to the function's stored decompilation.

    *applied* names the suggestions to apply; None applies every stored one.
    Each entry is validated against the running text: a malformed entry, a
    protected name, an identifier shorter than :data:`MIN_IDENTIFIER_LENGTH`, a
    no-op rename or a ``from`` that no longer occurs is skipped with a reason
    rather than failing the call.  A successful apply journals the previous text
    as an ``ai_artifacts`` row of kind ``renames-applied`` before replacing it,
    so :func:`revert_renames` can restore it.

    A ``function``-kind suggestion renames the function row too when
    *rename_function* is true, recording the change in ``name_history`` with
    source ``renames``; otherwise the row is left untouched.  Returns
    ``{"function_id", "applied", "skipped", "decompilation_updated"}``.
    """
    if store.get_function(conn, function_id) is None:
        raise KeyError(f"no function with id {function_id}")
    stored = store.get_decompilation(conn, function_id)
    if stored is None:
        raise NoDecompilationError(f"function {function_id} has no stored decompilation")
    source = str(stored["code"])
    backend = str(stored["backend"])
    entries = _apply_entries(conn, function_id, applied)
    working = source
    applied_list: list[dict[str, Any]] = []
    skipped_list: list[dict[str, Any]] = []
    for entry in entries:
        suggestion = _normalize_suggestion(entry)
        if suggestion is None:
            skipped_list.append({"suggestion": entry, "reason": "malformed suggestion"})
            continue
        refusal = _refusal(suggestion, working)
        if refusal is not None:
            skipped_list.append({**suggestion, "reason": refusal})
            continue
        working, count = replace_identifier(working, suggestion["from"], suggestion["to"])
        if count == 0:
            skipped_list.append({**suggestion, "reason": "no occurrence outside string literals"})
            continue
        applied_list.append(suggestion)
    updated = working != source
    if updated:
        store.set_ai_artifact(
            conn,
            function_id,
            RENAMES_APPLIED_KIND,
            {
                "previous_code": source,
                "previous_backend": backend,
                "applied": applied_list,
                "actor": actor,
            },
            "",
        )
        store.set_decompilation(conn, function_id, working, backend)
        if rename_function:
            for suggestion in applied_list:
                if suggestion["kind"] == "function":
                    store.rename_function(
                        conn,
                        function_id,
                        new_name=suggestion["to"],
                        actor=actor,
                        source=RENAME_SOURCE,
                    )
    return {
        "function_id": function_id,
        "applied": applied_list,
        "skipped": skipped_list,
        "decompilation_updated": updated,
    }


def revert_renames(conn: sqlite3.Connection, *, function_id: int) -> dict[str, Any]:
    """Restore the decompilation text the last apply journaled and drop it.

    Raises :class:`KeyError` for an unknown function and :class:`NoRevertError`
    when no apply is journaled for it.
    """
    if store.get_function(conn, function_id) is None:
        raise KeyError(f"no function with id {function_id}")
    artifact = store.get_ai_artifact(conn, function_id, RENAMES_APPLIED_KIND)
    payload = artifact["payload"] if artifact is not None else None
    previous = payload.get("previous_code") if isinstance(payload, dict) else None
    if not isinstance(previous, str):
        raise NoRevertError(f"function {function_id} has no applied renames to revert")
    backend = payload.get("previous_backend") if isinstance(payload, dict) else None
    store.set_decompilation(
        conn, function_id, previous, backend if isinstance(backend, str) else ""
    )
    store.clear_ai_artifact(conn, function_id, RENAMES_APPLIED_KIND)
    return {"function_id": function_id, "reverted": True, "code": previous}

"""Decompiler round-trip scripts: stored analysis as runnable tool scripts.

Zenyard's plugin story is "latest results applied" inside IDA, Ghidra and
Binary Ninja.  reportal already stores the results its own analysis produced
(the function rows, their ``name_history``, analyst comments, the signature
model and AI summaries), but nothing carries them into a decompiler: the
BinSync export lives in rebrew, needs the optional ``declib`` extra and the
shared state directory, and an analyst who only wants the names has no smaller
step.  This module is that step: a pure render of the stored rows as a
runnable script per tool, with no engine, no network and no state directory.

``include`` picks what a script carries, renames by default:

- ``renames``: one rename per stored function whose name is a real identity,
  never a decompiler placeholder (``sub_*``, ``fcn_*``, ``FUN_*``, ``FUNC_*``,
  empty) or a C declaration word (``__declspec``), because replaying either
  would overwrite the name the tool already shows.
- ``comments`` and ``summaries``: the function's analyst comments and its
  stored AI summary, joined into one function comment (a Ghidra plate
  comment, an IDA function comment, a Binja ``comment`` field).
- ``signatures``: the stored prototype, only when it is complete and plain
  C: a return type, a type on every parameter, no arrival-location
  annotations, a C identifier as the name and printable ASCII throughout.

The history an analyst can revert in reportal stays in reportal; the script is
the outbound half only.  ``collect`` gathers the rows, ``render`` writes one
tool's text, and the API, CLI and MCP tool share both.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from typing import Any

from reportal import lineage, llm, signatures, store

# Tools a script can be rendered for, in the order the CLI, API and SPA list
# them.  The names are the tools' own spellings.
FORMAT_GHIDRA = "ghidra"
FORMAT_IDA = "ida"
FORMAT_BINJA = "binja"
SCRIPT_FORMATS: tuple[str, ...] = (FORMAT_GHIDRA, FORMAT_IDA, FORMAT_BINJA)

# Media types the API answers per format: two runnable scripts and one JSON
# document, since Binary Ninja's rename API is the same call the JSON
# describes but the script form stays Python either way.
MEDIA_TYPES = {
    FORMAT_GHIDRA: "text/x-python",
    FORMAT_IDA: "text/x-python",
    FORMAT_BINJA: "application/json",
}

# Filenames the API and CLI suggest per format.
FILENAMES = {
    FORMAT_GHIDRA: "renames_ghidra.py",
    FORMAT_IDA: "renames_ida.py",
    FORMAT_BINJA: "renames_binja.json",
}

# What a script can carry, in the order a caller lists them.
INCLUDE_RENAMES = "renames"
INCLUDE_COMMENTS = "comments"
INCLUDE_SIGNATURES = "signatures"
INCLUDE_SUMMARIES = "summaries"
INCLUDE_KINDS: tuple[str, ...] = (
    INCLUDE_RENAMES,
    INCLUDE_COMMENTS,
    INCLUDE_SIGNATURES,
    INCLUDE_SUMMARIES,
)
DEFAULT_INCLUDE: tuple[str, ...] = (INCLUDE_RENAMES,)

# Shared with lineage / composition / unstrip so a placeholder is never
# replayed into a decompiler as if it were a real rename.
PLACEHOLDER_PREFIXES = lineage.PLACEHOLDER_PREFIXES

# Label the AI summary carries inside a function comment, so the tool shows
# which text a model wrote.
SUMMARY_LABEL = "AI summary"

# Separator between the parts of one function comment.
COMMENT_SEPARATOR = "\n\n"

# A C identifier: the only name a carried prototype may spell.
_C_IDENTIFIER = re.compile(r"\A[A-Za-z_]\w*\Z", re.ASCII)

# Characters a carried prototype's types may hold: the signature model's own
# type alphabet (words, spaces, pointers, array brackets).
_PROTOTYPE_TYPE = re.compile(r"\A[\w *\[\]]+\Z", re.ASCII)

# Characters a Python string literal carries as themselves; everything else
# is escaped, so a script is ASCII whatever the stored text holds.
_LITERAL_PLAIN = frozenset(chr(code) for code in range(0x20, 0x7F)) - {"\\", "'"}

# Escapes the literal writes for the control characters Python spells by name.
_LITERAL_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\\": "\\\\", "'": "\\'"}

# Code points above which a ``\\u`` escape no longer fits.
_BMP_LIMIT = 0x10000
_LATIN1_LIMIT = 0x100


class ScriptError(RuntimeError):
    """A round-trip script that cannot be rendered."""

    def __init__(self, detail: str, *, code: str = "binary not found") -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def parse_include(values: str | Iterable[str] | None) -> tuple[str, ...]:
    """The include kinds *values* names, in :data:`INCLUDE_KINDS` order.

    *values* is a comma-separated string (the query parameter and CLI form)
    or a list (the MCP form); empty or None means :data:`DEFAULT_INCLUDE`.
    Raises :class:`ScriptError` with code ``invalid include`` for an unknown
    kind.
    """
    if values is None:
        return DEFAULT_INCLUDE
    items = values.split(",") if isinstance(values, str) else list(values)
    wanted = {str(item).strip().lower() for item in items} - {""}
    if not wanted:
        return DEFAULT_INCLUDE
    unknown = sorted(wanted - set(INCLUDE_KINDS))
    if unknown:
        raise ScriptError(
            f"unknown include {', '.join(unknown)}; expected any of {', '.join(INCLUDE_KINDS)}",
            code="invalid include",
        )
    return tuple(kind for kind in INCLUDE_KINDS if kind in wanted)


def is_carried_name(name: str) -> bool:
    """True when *name* is a real identity: not a placeholder, not a declaration word."""
    stripped = name.strip()
    return lineage.is_function_name(stripped) and not stripped.startswith(PLACEHOLDER_PREFIXES)


def python_literal(text: str) -> str:
    """*text* as an ASCII ``u''`` literal that Jython 2.7 and Python 3 both read back.

    Quotes, backslashes and control characters are escaped, and every
    non-ASCII code point is a ``\\x``, ``\\u`` or ``\\U`` escape, so no stored
    text can end the literal, start a new line of code or depend on the
    script file's encoding.
    """
    parts: list[str] = []
    for char in text:
        code = ord(char)
        if char in _LITERAL_NAMED:
            parts.append(_LITERAL_NAMED[char])
        elif char in _LITERAL_PLAIN:
            parts.append(char)
        elif code < _LATIN1_LIMIT:
            parts.append(f"\\x{code:02x}")
        elif code < _BMP_LIMIT:
            parts.append(f"\\u{code:04x}")
        else:
            parts.append(f"\\U{code:08x}")
    return "u'" + "".join(parts) + "'"


def _optional_literal(text: str | None) -> str:
    return "None" if text is None else python_literal(text)


def safe_prototype(signature: dict[str, Any] | None, name: str) -> str | None:
    """The stored *signature* as a plain C prototype named *name*, or None when unsafe.

    Safe means a tool's C parser reads it as written: a C identifier as the
    name, a return type, a type on every parameter from the signature model's
    alphabet, identifier parameter names, and printable ASCII.  The
    arrival-location annotations (``at``, ``kind``, ``bits``) are not C and are
    left out; the result carries types, convention and names only.
    """
    if signature is None or not _C_IDENTIFIER.match(name):
        return None
    return_type = str(signature.get("return_type") or "").strip()
    if not return_type or not _PROTOTYPE_TYPE.match(return_type):
        return None
    parameters: list[dict[str, Any]] = []
    for parameter in signature.get("parameters") or []:
        type_text = str(parameter.get("type") or "").strip()
        parameter_name = str(parameter.get("name") or "")
        if not type_text or not _PROTOTYPE_TYPE.match(type_text):
            return None
        if parameter_name and not _C_IDENTIFIER.match(parameter_name):
            return None
        parameters.append({"type": type_text, "name": parameter_name})
    convention = str(signature.get("calling_convention") or "")
    if convention and not _C_IDENTIFIER.match(convention):
        return None
    prototype = signatures.render_prototype(
        {
            "name": name,
            "return_type": return_type,
            "calling_convention": convention,
            "parameters": parameters,
        }
    )
    return prototype if prototype.isascii() and prototype.isprintable() else None


def _comment(
    function_id: int,
    *,
    comments: dict[int, list[dict[str, Any]]],
    summaries: dict[int, dict[str, Any]],
) -> str | None:
    """One function's comment: its AI summary first, then its analyst comments."""
    parts: list[str] = []
    summary = summaries.get(function_id)
    if summary is not None:
        text = str(summary["payload"].get("summary") or "").strip()
        if text:
            parts.append(f"{SUMMARY_LABEL}: {text}")
    for row in comments.get(function_id, []):
        body = str(row.get("body") or "").strip()
        author = str(row.get("author") or "").strip()
        if body:
            parts.append(f"{author}: {body}" if author else body)
    return COMMENT_SEPARATOR.join(parts) or None


def _entries(
    conn: sqlite3.Connection,
    binary_id: int,
    functions: list[dict[str, Any]],
    include: tuple[str, ...],
) -> list[dict[str, Any]]:
    """One entry per function with something to carry, in VA order.

    Every entry has ``va``, ``name``, ``comment`` and ``prototype``; a field the
    include set leaves out, or the function has nothing for, is None.
    """
    comments = (
        store.function_comments_for_binary(conn, binary_id) if INCLUDE_COMMENTS in include else {}
    )
    summaries = (
        store.ai_artifacts_for_binary(conn, binary_id, llm.AI_KIND_SUMMARY)
        if INCLUDE_SUMMARIES in include
        else {}
    )
    stored_signatures = (
        {int(row["function_id"]): row for row in store.list_signatures(conn, binary_id=binary_id)}
        if INCLUDE_SIGNATURES in include
        else {}
    )
    found: list[dict[str, Any]] = []
    for function in functions:
        function_id = int(function["id"])
        stored_name = str(function.get("name") or "").strip()
        name = stored_name if INCLUDE_RENAMES in include and is_carried_name(stored_name) else None
        entry = {
            "va": int(function["va"]),
            "name": name,
            "comment": _comment(function_id, comments=comments, summaries=summaries),
            "prototype": safe_prototype(stored_signatures.get(function_id), stored_name),
        }
        if any(entry[field] is not None for field in ("name", "comment", "prototype")):
            found.append(entry)
    found.sort(key=lambda entry: int(entry["va"]))
    return found


def collect(
    conn: sqlite3.Connection, binary_id: int, *, include: tuple[str, ...] = DEFAULT_INCLUDE
) -> dict[str, Any]:
    """Gather what a binary's script carries under *include*.

    Raises :class:`ScriptError` for an unknown binary.  A binary with nothing
    to carry answers an empty entry list rather than an error, so a caller can
    tell "nothing to carry over" from "no such binary".
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise ScriptError(f"no binary with id {binary_id}")
    functions = store.list_functions(conn, binary_id=binary_id)
    return {
        "binary_id": binary_id,
        "binary_name": str(binary["name"]),
        "include": list(include),
        "entries": _entries(conn, binary_id, functions, include),
        "count": len(functions),
    }


def _python_entries(entries: list[dict[str, Any]]) -> list[str]:
    return [
        f"    (0x{entry['va']:x}, {_optional_literal(entry['name'])},"
        f" {_optional_literal(entry['comment'])}, {_optional_literal(entry['prototype'])}),"
        for entry in entries
    ]


def _header(tool: str, run: str, payload: dict[str, Any]) -> list[str]:
    entries: list[dict[str, Any]] = payload["entries"]
    carried = ", ".join(payload.get("include") or DEFAULT_INCLUDE)
    return [
        f"# reportal export for {tool}: {run}.",
        f"# binary: {python_literal(str(payload['binary_name']))}",
        f"# {len(entries)} function(s); carries {carried}.",
    ]


def _render_ghidra(payload: dict[str, Any]) -> str:
    entries: list[dict[str, Any]] = payload["entries"]
    with_prototypes = any(entry["prototype"] is not None for entry in entries)
    lines = [
        *_header("Ghidra", "run it in the Script Manager (Jython or PyGhidra)", payload),
        "from ghidra.program.model.symbol import SourceType",
    ]
    if with_prototypes:
        lines += [
            "from ghidra.app.cmd.function import ApplyFunctionSignatureCmd",
            "from ghidra.app.util.cparser.C import CParserUtils",
        ]
    lines += [
        "",
        "# (entry point, name, plate comment, C prototype); None leaves the field alone.",
        "FUNCTIONS = [",
        *_python_entries(entries),
        "]",
        "",
        "for va, name, comment, prototype in FUNCTIONS:",
        "    address = toAddr(va)",
        "    function = getFunctionAt(address)",
        "    if function is None:",
        "        print('no function at 0x%x' % va)",
        "        continue",
        "    if name is not None:",
        "        try:",
        "            function.setName(name, SourceType.USER_DEFINED)",
        "        except Exception as error:",
        "            print('rename failed at 0x%x: %s' % (va, error))",
        "    if comment is not None:",
        "        setPlateComment(address, comment)",
    ]
    if with_prototypes:
        lines += [
            "    if prototype is not None:",
            "        try:",
            "            signature = CParserUtils.parseSignature(None, currentProgram, prototype)",
            "            if signature is None:",
            "                print('prototype did not parse at 0x%x' % va)",
            "                continue",
            "            signature.setName(function.getName())",
            "            ApplyFunctionSignatureCmd(",
            "                address, signature, SourceType.USER_DEFINED",
            "            ).applyTo(currentProgram, monitor)",
            "        except Exception as error:",
            "            print('prototype not applied at 0x%x: %s' % (va, error))",
        ]
    return "\n".join(lines) + "\n"


def _render_ida(payload: dict[str, Any]) -> str:
    lines = [
        *_header("IDA", "File > Script file (IDAPython, IDA 7.4 or later)", payload),
        "import idc",
        "",
        "# (entry point, name, function comment, C prototype); None leaves the field alone.",
        "FUNCTIONS = [",
        *_python_entries(payload["entries"]),
        "]",
        "",
        "for va, name, comment, prototype in FUNCTIONS:",
        "    if name is not None and not idc.set_name(va, name, idc.SN_NOWARN | idc.SN_NOCHECK):",
        "        print('rename failed at 0x%x' % va)",
        "    if comment is not None and not idc.set_func_cmt(va, comment, 0):",
        "        print('comment failed at 0x%x' % va)",
        "    if prototype is not None and not idc.SetType(va, prototype):",
        "        print('prototype not applied at 0x%x' % va)",
    ]
    return "\n".join(lines) + "\n"


def _render_binja(payload: dict[str, Any]) -> str:
    functions: list[dict[str, Any]] = []
    for entry in payload["entries"]:
        row: dict[str, Any] = {"address": entry["va"]}
        for field in ("name", "comment", "prototype"):
            if entry[field] is not None:
                row[field] = entry[field]
        functions.append(row)
    return json.dumps(
        {
            "binary": payload["binary_name"],
            "include": list(payload.get("include") or DEFAULT_INCLUDE),
            "functions": functions,
        },
        indent=2,
    )


def render(payload: dict[str, Any], *, fmt: str) -> str:
    """Render *payload* (from :func:`collect`) as one tool's script text.

    Raises :class:`ValueError` for an unknown format.
    """
    if fmt == FORMAT_GHIDRA:
        return _render_ghidra(payload)
    if fmt == FORMAT_IDA:
        return _render_ida(payload)
    if fmt == FORMAT_BINJA:
        return _render_binja(payload)
    raise ValueError(f"unknown format: {fmt}; expected one of {', '.join(SCRIPT_FORMATS)}")


def script(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    fmt: str = FORMAT_GHIDRA,
    include: tuple[str, ...] = DEFAULT_INCLUDE,
) -> dict[str, Any]:
    """Collect and render a binary's stored analysis as one tool's script.

    Returns ``{"binary_id", "format", "include", "text", "renames", "comments",
    "prototypes", "functions"}``: the three counts are the carried fields and
    ``functions`` the binary's whole function set, so a caller can tell a small
    binary from a filtered one.
    """
    payload = collect(conn, binary_id, include=include)
    entries: list[dict[str, Any]] = payload["entries"]
    return {
        "binary_id": binary_id,
        "format": fmt,
        "include": list(include),
        "text": render(payload, fmt=fmt),
        "renames": sum(entry["name"] is not None for entry in entries),
        "comments": sum(entry["comment"] is not None for entry in entries),
        "prototypes": sum(entry["prototype"] is not None for entry in entries),
        "functions": payload["count"],
    }

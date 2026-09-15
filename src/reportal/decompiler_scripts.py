"""Decompiler round-trip scripts: stored renames as runnable tool scripts.

Zenyard's plugin story is "latest results applied" inside IDA, Ghidra and
Binary Ninja.  reportal already stores the results its own renames produced
(the function rows plus their ``name_history``), but nothing carries them
into a decompiler: the BinSync export lives in rebrew, needs the optional
``declib`` extra and the shared state directory, and an analyst who only
wants the names has no smaller step.  This module is that step: a pure
render of the stored renames as a runnable script per tool, with no engine,
no network and no state directory.

A script carries one rename per stored function whose name is a real
identity, never a decompiler placeholder (``sub_*``, ``fcn_*``, ``FUN_*``,
empty), because replaying a placeholder would overwrite the name the tool
already shows.  The history an analyst can revert in reportal stays in
reportal; the script is the outbound half only.  ``collect`` gathers the
rows, ``render`` writes one tool's text, and the API, CLI and MCP tool share
both.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from reportal import store

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

# Name prefixes a decompiler leaves on a function it could not name.  A
# function carrying one is unnamed even when a name_source was set.
PLACEHOLDER_PREFIXES = ("sub_", "fcn_", "FUN_")


class ScriptError(RuntimeError):
    """A round-trip script that cannot be rendered."""

    def __init__(self, detail: str, *, code: str = "binary not found") -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _is_named(name: str) -> bool:
    """True when *name* is a real identity, not a decompiler placeholder."""
    stripped = name.strip()
    return bool(stripped) and not stripped.startswith(PLACEHOLDER_PREFIXES)


def _literal(name: str) -> str:
    """*name* as a Python string literal, safe to splice into a script.

    ``repr`` already quotes and escapes, so a quote, a backslash or a newline
    in a stored rename renders as text rather than code; the one form it
    cannot express is a name holding both quote styles, which is refused
    rather than guessed at.  The Binja document needs no quoting at all
    (``json.dumps`` owns that boundary), so this is the two script formats
    only.
    """
    if "'" in name and '"' in name:
        raise ScriptError(f"rename is not a script-safe literal: {name!r}", code="unsafe name")
    return repr(name)


def _entries(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The renames a script carries: named functions as VA/name pairs."""
    found = [
        {"va": int(function["va"]), "name": str(function["name"])}
        for function in functions
        if _is_named(str(function.get("name") or ""))
    ]
    found.sort(key=lambda entry: int(str(entry["va"])))
    return found


def collect(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Gather a binary's stored renames for the script renderers.

    Raises :class:`ScriptError` for an unknown binary.  A binary with no
    named functions answers an empty entry list rather than an error, so a
    caller can tell "nothing to carry over" from "no such binary".
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise ScriptError(f"no binary with id {binary_id}")
    functions = store.list_functions(conn, binary_id=binary_id)
    return {
        "binary_id": binary_id,
        "binary_name": str(binary["name"]),
        "entries": _entries(functions),
        "count": len(functions),
    }


def render(payload: dict[str, Any], *, fmt: str) -> str:
    """Render *payload* (from :func:`collect`) as one tool's script text.

    Raises :class:`ValueError` for an unknown format.
    """
    if fmt not in SCRIPT_FORMATS:
        raise ValueError(f"unknown format: {fmt}; expected one of {', '.join(SCRIPT_FORMATS)}")
    entries: list[dict[str, Any]] = payload["entries"]
    if fmt == FORMAT_BINJA:
        import json

        return json.dumps(
            {
                "binary": payload["binary_name"],
                "renames": [{"address": entry["va"], "name": entry["name"]} for entry in entries],
            },
            indent=2,
        )
    if fmt == FORMAT_GHIDRA:
        lines = [
            "# reportal rename script for Ghidra: run in the Script Manager.",
            f"# binary: {payload['binary_name']} ({len(entries)} renames)",
            "from ghidra.program.model.symbol import SourceType",
            "",
            "RENAMES = [",
            *[f"    (0x{entry['va']:x}, {_literal(str(entry['name']))})," for entry in entries],
            "]",
            "",
            "for va, name in RENAMES:",
            "    for function in getFunctionsContaining(toAddr(va)):",
            "        if function.getEntryPoint().getOffset() == va:",
            "            function.setName(name, SourceType.USER_DEFINED)",
            "            break",
        ]
        return "\n".join(lines) + "\n"
    lines = [
        "; reportal rename script for IDA: File > Script file.",
        f"; binary: {payload['binary_name']} ({len(entries)} renames)",
        "",
    ]
    lines.extend(
        f"MakeName(0x{entry['va']:x}, {_literal(str(entry['name']))});" for entry in entries
    )
    return "\n".join(lines) + "\n"


def script(conn: sqlite3.Connection, binary_id: int, *, fmt: str = FORMAT_GHIDRA) -> dict[str, Any]:
    """Collect and render a binary's renames as one tool's script.

    Returns ``{"binary_id", "format", "text", "renames", "functions"}`` where
    ``renames`` is the carried count and ``functions`` the binary's whole
    function set, so a caller can tell a small binary from a filtered one.
    """
    payload = collect(conn, binary_id)
    return {
        "binary_id": binary_id,
        "format": fmt,
        "text": render(payload, fmt=fmt),
        "renames": len(payload["entries"]),
        "functions": payload["count"],
    }

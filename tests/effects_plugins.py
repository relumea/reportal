"""Plugin surface the effect-handler registry tests load through entry points."""

from __future__ import annotations

import sqlite3
from typing import Any

from reportal.effects import EFFECT_REVERTED


def mark_function(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """A single handler an entry point registers under its own name."""
    return {"kind": str(descriptor.get("kind", "")), "status": EFFECT_REVERTED}


def undo_note(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """One member of the kind-to-handler mapping."""
    return {"kind": str(descriptor.get("kind", "")), "note": str(descriptor.get("note", ""))}


def undo_tag(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """A second member of the kind-to-handler mapping."""
    return {"kind": str(descriptor.get("kind", ""))}


HANDLER_MAPPING: dict[str, Any] = {"plugin-note": undo_note, "plugin-tag": undo_tag}

# A mapping claiming a built-in kind: the registry must reject it.
BUILTIN_MAPPING: dict[str, Any] = {"disasm": undo_note}

# A mapping whose member is not callable, and a bare value that is not a handler.
BAD_MAPPING: dict[str, Any] = {"plugin-broken": 42}
NOT_A_HANDLER = 42

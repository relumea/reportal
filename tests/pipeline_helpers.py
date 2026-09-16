"""Shared seeding and stubs for the pipeline test modules."""

from __future__ import annotations

import contextlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    AI_COMMENTS_RESPONSE,
    AI_RENAMES_RESPONSE,
    AI_REWRITE_RESPONSE,
    AI_SUMMARY_RESPONSE,
    AI_TYPES_RESPONSE,
    FakeLlmClient,
)

from reportal import llm, store
from reportal._paths import DB_ENV
from reportal.components import Component, Context

# A NASM listing shaped like `rebrew asm --format nasm` output: two blocks, a
# conditional jump NASM could not encode (rebrew emits `db` plus the original
# instruction in the comment), a direct call and a backward jump.  The call
# target 0x2000 is the second function `seed_portal` stores, so the call trace
# has a name to read from stored metadata.
LISTING = """bits 32
org 0x00001000

func_00001000:
    push ebp                                 ; 00001000  55
    test eax, eax                            ; 00001001  85c0
    db 0x74, 0x03                            ; 00001003  je 0x1000b
    call 0x2000                              ; 00001005  e8f60f0000
    jmp 0x1000b                              ; 0000100a  e901000000
    mov eax, 1                               ; 0000100b  b801000000
    ret                                      ; 00001010  c3
"""


class ScriptedLlmClient(FakeLlmClient):
    """A fake LLM that answers each artifact prompt with its own canned payload."""

    def __init__(self) -> None:
        super().__init__(model="scripted-model")

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = llm.DEFAULT_TEMPERATURE,
        json_object: bool = False,
        max_tokens: int = llm.MAX_COMPLETION_TOKENS,
    ) -> str:
        self.calls.append(messages)
        self.temperatures.append(temperature)
        prompt = messages[-1]["content"] if messages else ""
        # Dispatch on a phrase only one prompt builder emits.  The order does
        # not matter for these, but the substrings must stay unique: the rename
        # prompt also says "parameters", so it is keyed on "unclear
        # identifiers" rather than on a word it shares with the type prompt.
        if "Rewrite this function" in prompt:
            return AI_REWRITE_RESPONSE
        if "Summarize" in prompt:
            return AI_SUMMARY_RESPONSE
        if "inline comment" in prompt:
            return AI_COMMENTS_RESPONSE
        if "unclear identifiers" in prompt:
            return AI_RENAMES_RESPONSE
        return AI_TYPES_RESPONSE


def seed_portal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    project: bool = True,
) -> dict[str, Any]:
    """Create a portal DB with a binary, two functions and (optionally) a project.

    The path matches the ``portal_db`` fixture (``tmp_path/reportal.db``), so a
    test can seed through this helper and read back through the ``conn`` fixture.
    """
    db = tmp_path / "reportal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(
            conn, sha256="cd" * 32, name="demo.exe", path=str(tmp_path / "demo.exe")
        )
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        function_id = store.add_function(
            conn, analysis_id=analysis_id, va=0x1000, name="sub_1000", size=0x20
        )
        second = store.add_function(
            conn, analysis_id=analysis_id, va=0x2000, name="DoThing", size=0x10
        )
        if project:
            store.set_rebrew_context(conn, binary_id, str(tmp_path))
    return {
        "db": str(db),
        "binary": binary_id,
        "analysis": analysis_id,
        "function": function_id,
        "second": second,
    }


def seed_unstrip_proposal(
    conn: sqlite3.Connection, *, analysis_id: int, function_id: int, name: str = "ChooseFontW"
) -> None:
    """Store an auto-unstrip proposal for one function."""
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_UNSTRIP,
        {
            "candidates": 1,
            "applied": False,
            "proposals": [
                {
                    "function_id": function_id,
                    "va": 0x1000,
                    "current_name": "sub_1000",
                    "proposed_name": name,
                    "module": "COMDLG32",
                    "kind": "import",
                    "confidence": 0.3,
                }
            ],
        },
    )


def spy(name: str, requires: set[str], captured: dict[str, Any]) -> Component:
    """A component that records what the run made available to it."""

    def effect(ctx: Context) -> None:
        for key in sorted(requires):
            captured[key] = ctx.get(key)

    return Component(
        name=name,
        requires=frozenset(requires),
        provides=frozenset(),
        effect=effect,
    )

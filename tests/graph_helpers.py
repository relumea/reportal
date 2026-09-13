"""Shared seeding for the knowledge-graph test modules."""

from __future__ import annotations

import sqlite3
from typing import Any

from reportal import knowledge, store

# The corpus every graph test builds from: one binary, two functions with a
# recorded match, a struct, a capability, a tag, an unstrip proposal, a triage
# library/FLIRT section and a document that names a function, a struct and a VA.
FUNCTION_NAME = "FreePrintSetup"
SECOND_FUNCTION_NAME = "sub_2000"
STRUCT_NAME = "PlayerInfo"
STRUCT_VA = 0x3000
CAPABILITY_NAME = "networking"
TAG_NAME = "notepad"
LIBRARY_MODULE = "COMDLG32"
FLIRT_NAME = "strlen"
DOCUMENT_TITLE = "Design note"
DOCUMENT_TEXT = (
    "# Design note\n\n"
    f"{FUNCTION_NAME} at 0x00001000 drives the dialog.\n\n"
    f"{STRUCT_NAME} is filled at 0x{STRUCT_VA:x}.\n"
)

UNSTRIP_CONFIDENCE = 0.3
TRIAGE_LIBRARY_CONFIDENCE = 0.9
MATCH_SIMILARITY = 91.5
MATCH_CONFIDENCE = 0.8


def seed_corpus(conn: sqlite3.Connection) -> dict[str, int]:
    """Seed the shared corpus and return the ids it produced."""
    binary_id = store.add_binary(
        conn, sha256="ab" * 32, name="demo.exe", size=1024, fmt="PE", arch="x86_32"
    )
    analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
    first = store.add_function(
        conn,
        analysis_id=analysis_id,
        va=0x1000,
        name=FUNCTION_NAME,
        size=64,
        status="STUB",
        name_source="rebrew",
    )
    second = store.add_function(
        conn,
        analysis_id=analysis_id,
        va=0x2000,
        name=SECOND_FUNCTION_NAME,
        size=32,
        status="STUB",
    )
    store.record_match(
        conn,
        function_id=first,
        candidate_function_id=second,
        similarity=MATCH_SIMILARITY,
        confidence=MATCH_CONFIDENCE,
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_STRUCTS,
        {
            "decompiled": 2,
            "skipped": 0,
            "structs": [
                {
                    "name": STRUCT_NAME,
                    "anonymous": False,
                    "semantic": True,
                    "var": "player",
                    "va": STRUCT_VA,
                    "evidence": 1,
                    "functions": 1,
                }
            ],
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_CAPABILITIES,
        {
            "binary_id": binary_id,
            "capabilities": [
                {
                    "name": CAPABILITY_NAME,
                    "description": "Opens or accepts network connections",
                    "confidence": "high",
                    "evidence": [{"kind": "import", "value": "WSAStartup"}],
                    "evidence_count": 2,
                }
            ],
            "count": 1,
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_UNSTRIP,
        {
            "candidates": 1,
            "proposals": [
                {
                    "function_id": first,
                    "va": 0x1000,
                    "current_name": FUNCTION_NAME,
                    "proposed_name": "ChooseFontW",
                    "module": LIBRARY_MODULE,
                    "kind": "import",
                    "confidence": UNSTRIP_CONFIDENCE,
                }
            ],
            "applied": False,
        },
    )
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_TRIAGE,
        {
            "library": [
                {
                    "va": "0x00001000",
                    "name": FUNCTION_NAME,
                    "module": LIBRARY_MODULE,
                    "kind": "flirt",
                    "confidence": TRIAGE_LIBRARY_CONFIDENCE,
                }
            ],
            "flirt": {
                "signature_count": 1,
                "matches": [{"va": "0x00002000", "size": 8, "name": FLIRT_NAME}],
            },
        },
    )
    tag_id = store.create_tag(conn, TAG_NAME)
    store.add_binary_tag(conn, binary_id, tag_id)
    document = knowledge.ingest_document(
        conn,
        scope_kind=knowledge.SCOPE_KIND_BINARY,
        scope_id=binary_id,
        title=DOCUMENT_TITLE,
        source="note.md",
        mime="text/markdown",
        data=DOCUMENT_TEXT.encode("utf-8"),
    )
    return {
        "binary": binary_id,
        "analysis": analysis_id,
        "first": first,
        "second": second,
        "tag": tag_id,
        "document": int(document["id"]),
    }


def node_id(binary_id: int, kind: str, key: str | int) -> str:
    """The graph node id the builder derives for one entity."""
    return f"b{binary_id}:{kind}:{key}"


def ordered(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows ordered by id, so two rebuilds compare equal whatever their order."""
    return sorted(rows, key=lambda row: str(row["id"]))


def relations(edges: list[dict[str, Any]]) -> set[str]:
    """The distinct relations an edge list carries."""
    return {str(edge["rel"]) for edge in edges}

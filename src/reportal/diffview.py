"""Resolve a match pair to two listings and align them for the diff view.

The API route, the `reportal diff` command and the `diff_functions` MCP tool
share :func:`function_diff`: it resolves a function and a candidate, assembles
each side's listing (``disasm`` through the engine and its cache, ``decomp``
from the stored row and only live, unstored, when there is none), normalizes
with :mod:`reportal.diffing` when asked, and returns the alignment, its
summary and the score.

A recorded match is not required here: any two stored functions can be aligned,
which is what the CLI and the MCP tool take.  The API route additionally
rejects a pair that is not a recorded match for the source function.

:class:`DiffError` carries the HTTP status and the stable error name the API
answers with; the MCP tool and the CLI report the same name and detail through
their own surfaces.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from reportal import diffing, engines, similarity, store

# Kinds the diff supports: `decomp` aligns stored C, `disasm` the engine's NASM
# listings.  Order matches DEFAULT_KIND and the SPA so the first entry is the
# default surface everywhere.
KIND_DISASM = "disasm"
KIND_DECOMP = "decomp"
DIFF_KINDS = (KIND_DECOMP, KIND_DISASM)
DEFAULT_KIND = KIND_DECOMP

# Normalization is on by default: an unnormalized disassembly diff is dominated
# by addresses and encoded bytes that say nothing about the code.
DEFAULT_NORMALIZE = True

# Format of the disassembly listing the diff holds; the cache key is the
# function id alone, so only this format may be cached.
LISTING_FORMAT = "nasm"


class DiffError(Exception):
    """A diff request that cannot be served, carrying its API status and name."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


def _require_engine(engine: engines.RebrewEngine) -> None:
    if not engine.available():
        raise DiffError(
            503,
            "engine-unavailable",
            engines.ENGINE_UNAVAILABLE_HINT,
        )


def _project_context(conn: sqlite3.Connection, function: dict[str, Any]) -> str:
    binary_id = int(function["binary_id"])
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise DiffError(
            400,
            "no-engine-context",
            f"binary {binary_id} has no analysis context yet",
        )
    return project_dir


def _disassembly(
    conn: sqlite3.Connection, engine: engines.RebrewEngine, function: dict[str, Any]
) -> str:
    """Return a function's NASM listing, from ``disasm_cache`` or the engine."""
    function_id = int(function["id"])
    cached = store.get_disasm(conn, function_id)
    if cached is not None:
        return cached
    project_dir = _project_context(conn, function)
    _require_engine(engine)
    try:
        listing, _filled = store.get_or_compute_disasm(
            conn,
            function_id,
            lambda: engine.disassemble(
                project_dir, int(function["va"]), int(function["size"]), LISTING_FORMAT
            ),
            extent_size=int(function["size"]),
            project_dir=project_dir,
        )
    except engines.EngineError as exc:
        raise DiffError(500, "engine-error", str(exc)) from exc
    return listing


def _decompilation(
    conn: sqlite3.Connection, engine: engines.RebrewEngine, function: dict[str, Any]
) -> str:
    """Return a function's stored decompilation, else a live unstored one."""
    stored = store.get_decompilation(conn, int(function["id"]))
    if stored is not None:
        return str(stored["code"])
    project_dir = _project_context(conn, function)
    _require_engine(engine)
    try:
        result = engine.decompile(
            project_dir, int(function["va"]), engines.DEFAULT_DECOMPILER_BACKEND, False
        )
    except engines.EngineError as exc:
        raise DiffError(500, "engine-error", str(exc)) from exc
    return str(result.get("code") or "")


def _stored_similarity(
    conn: sqlite3.Connection, function_id: int, candidate_id: int
) -> float | None:
    """The recorded similarity of the pair, or None when it is not recorded."""
    for row in store.list_matches(conn, function_id):
        if int(row["candidate_function_id"]) == candidate_id:
            return float(row["similarity"])
    return None


def _side(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "function_id": int(function["id"]),
        "name": str(function["name"]),
        "va": int(function["va"]),
        "binary_id": int(function["binary_id"]),
    }


def function_diff(
    conn: sqlite3.Connection,
    engine: engines.RebrewEngine,
    *,
    function_id: int,
    candidate_id: int | None = None,
    kind: str = DEFAULT_KIND,
    normalize: bool = DEFAULT_NORMALIZE,
) -> dict[str, Any]:
    """Align a function against a candidate (or its best recorded match).

    Raises :class:`DiffError` for an unknown function or candidate, an
    unsupported kind, a missing rebrew project context, an unavailable engine
    or an engine failure.  ``candidate_id`` None selects the source function's
    best recorded match and fails with ``no-match`` when it has none.
    """
    if kind not in DIFF_KINDS:
        raise DiffError(400, "invalid kind", f"unsupported diff kind: {kind}")
    left = store.get_function(conn, function_id)
    if left is None:
        raise DiffError(404, "function not found", f"no function with id {function_id}")
    if candidate_id is None:
        matches = store.list_matches(conn, function_id)
        if not matches:
            raise DiffError(404, "no-match", f"function {function_id} has no recorded match")
        candidate_id = int(matches[0]["candidate_function_id"])
        score: float | None = float(matches[0]["similarity"])
    else:
        score = _stored_similarity(conn, function_id, candidate_id)
    right = store.get_function(conn, candidate_id)
    if right is None:
        raise DiffError(404, "candidate not found", f"no function with id {candidate_id}")

    if kind == KIND_DISASM:
        left_text = _disassembly(conn, engine, left)
        right_text = _disassembly(conn, engine, right)
    else:
        left_text = _decompilation(conn, engine, left)
        right_text = _decompilation(conn, engine, right)

    if normalize:
        left_text = diffing.strip_addresses(left_text)
        right_text = diffing.strip_addresses(right_text)

    entries = diffing.align(left_text, right_text)
    if score is None and similarity.available():
        try:
            score = similarity.similarity(left_text, right_text)
        except similarity.SimilarityUnavailable:
            score = None

    return {
        "left": _side(left),
        "right": _side(right),
        "kind": kind,
        "normalized": normalize,
        "similarity": score,
        "entries": entries,
        "summary": diffing.summary(entries),
    }

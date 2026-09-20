"""Auto-unstrip: name library-identified functions from engine candidates.

The engine's library identification reports matches (FLIRT, CRT and IAT import
thunks) by VA, and reportal runs it as a dry run so it writes nothing.  reportal
joins those candidates to the functions it already stores and records rename
proposals without touching a function: an apply is a separate, explicit
request.  A name a person authored is never proposed for overwrite.

This module is pure proposal building plus the two orchestrators
(:func:`run_unstrip`, :func:`apply_proposal`); the engine call lives in
:mod:`reportal.engines`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from reportal import lineage, store
from reportal.engines import RebrewEngine

# Minimum engine confidence a proposal must reach when the caller names none.
# Import matches carry 0.3, the lowest the engine reports, so 0.0 keeps every
# candidate by default.
DEFAULT_MIN_CONFIDENCE = 0.0

# Name sources an engine produced rather than a person: rebrew's import names
# and a name a previous unstrip apply set.  Any other source (a hand rename, an
# applied match, a revert) is a person's decision, so unstrip leaves it alone.
# Placeholder names are handled separately.
AUTO_NAME_SOURCES = frozenset({"rebrew", "unstrip"})

# Shared with lineage / composition / decompiler scripts so a FUN_* or FUNC_*
# name is unnamed everywhere, not only in the unstrip eligibility check.
PLACEHOLDER_PREFIXES = lineage.PLACEHOLDER_PREFIXES

# Actor and rename source an unstrip apply records in the function's history.
# The value matches the stored scan kind so a proposal and the rename it caused
# share one label.
UNSTRIP_SOURCE = "unstrip"

IdentifyFn = Callable[[str | Path], dict[str, Any]]


class NoRebrewContextError(Exception):
    """The binary has no rebrew project context to identify library functions in."""


class NoProposalError(Exception):
    """The stored unstrip scan holds no proposal for the function."""


def _candidate_va(raw: Any) -> int | None:
    """Return a candidate's VA as an int: a hex string from the engine, or None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    try:
        return int(str(raw), 16)
    except (TypeError, ValueError):
        return None


def _is_unnamed(name: str) -> bool:
    """True when *name* is empty or a decompiler placeholder."""
    stripped = name.strip()
    return not stripped or stripped.startswith(PLACEHOLDER_PREFIXES)


def build_proposals(
    candidates: Sequence[dict[str, Any]], functions: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Join engine *candidates* to stored *functions* as rename proposals.

    A candidate carries a hex string ``va`` and a function an int ``va``; the
    join is on that address.  A candidate is dropped when no function has its
    VA, when the function already carries the proposed name, or when the
    function's name is user-authored (any source outside
    :data:`AUTO_NAME_SOURCES`, unless the name is a placeholder).  Proposals
    sort by confidence descending, then VA ascending.
    """
    by_va = {int(function["va"]): function for function in functions}
    proposals: list[dict[str, Any]] = []
    for candidate in candidates:
        va = _candidate_va(candidate.get("va"))
        if va is None:
            continue
        function = by_va.get(va)
        if function is None:
            continue
        proposed = str(candidate.get("name") or "").strip()
        if not proposed:
            continue
        current = str(function.get("name") or "")
        if current == proposed:
            continue
        source = str(function.get("name_source") or "")
        if not _is_unnamed(current) and source not in AUTO_NAME_SOURCES:
            continue
        confidence = candidate.get("confidence")
        proposals.append(
            {
                "function_id": int(function["id"]),
                "va": va,
                "current_name": current,
                "proposed_name": proposed,
                "module": str(candidate.get("module") or ""),
                "kind": str(candidate.get("kind") or ""),
                "confidence": float(confidence) if confidence is not None else 0.0,
            }
        )
    proposals.sort(key=lambda proposal: (-proposal["confidence"], proposal["va"]))
    return proposals


def _stored_proposal_name(
    conn: sqlite3.Connection, function: dict[str, Any], function_id: int
) -> str:
    """Return the stored unstrip proposal's name for *function_id*.

    Raises :class:`NoProposalError` when the function's binary has no stored unstrip
    scan or that scan holds no proposal for the function.
    """
    analysis_id = store.latest_analysis_for_binary(conn, int(function["binary_id"]))
    stored = (
        store.get_scan(conn, analysis_id, store.SCAN_KIND_UNSTRIP)
        if analysis_id is not None
        else None
    )
    proposals = stored.get("proposals") if isinstance(stored, dict) else None
    if isinstance(proposals, list):
        for proposal in proposals:
            if int(proposal.get("function_id", -1)) == function_id:
                return str(proposal.get("proposed_name") or "")
    raise NoProposalError(f"no stored unstrip proposal for function {function_id}")


def run_unstrip(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: RebrewEngine,
    ident: IdentifyFn | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
) -> dict[str, Any]:
    """Identify a binary's library functions and store the rename proposals.

    The engine runs in the binary's rebrew project context, which must exist.
    *ident* overrides the identification call and defaults to
    :meth:`RebrewEngine.identify_library`.  Proposals at or above
    *min_confidence* are stored as the ``unstrip`` scan; nothing is renamed.
    Raises :class:`NoRebrewContextError` without a stored project context and
    propagates an engine failure.
    """
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise NoRebrewContextError(f"binary {binary_id} has no rebrew project context")
    identify = ident or engine.identify_library
    result = identify(project_dir)
    raw_candidates = result.get("candidates")
    candidates = raw_candidates if isinstance(raw_candidates, list) else []
    functions = store.list_functions(conn, binary_id=binary_id)
    proposals = [
        proposal
        for proposal in build_proposals(candidates, functions)
        if proposal["confidence"] >= min_confidence
    ]
    payload = {"candidates": len(candidates), "proposals": proposals, "applied": False}
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_UNSTRIP,
        payload,
        params={"min_confidence": min_confidence},
    )
    return payload


def apply_proposal(
    conn: sqlite3.Connection, *, function_id: int, new_name: str | None = None
) -> dict[str, Any]:
    """Rename *function_id* to one of its stored unstrip proposals.

    *new_name* overrides the proposal's name; without it the name is read back
    from the function's stored ``unstrip`` scan.  Raises :class:`KeyError` for
    an unknown function, :class:`NoProposalError` when the scan holds none for it,
    and :class:`ValueError` for a blank name.
    """
    function = store.get_function(conn, function_id)
    if function is None:
        raise KeyError(f"no function with id {function_id}")
    resolved = (
        new_name if new_name is not None else _stored_proposal_name(conn, function, function_id)
    )
    if not resolved.strip():
        raise ValueError("name must not be empty")
    return store.rename_function(
        conn,
        function_id,
        new_name=resolved,
        actor=UNSTRIP_SOURCE,
        source=UNSTRIP_SOURCE,
    )

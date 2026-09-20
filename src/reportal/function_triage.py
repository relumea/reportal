"""Per-function triage: an LLM summary and a suspicion score per function.

The hosted portal's Agents/Triage surface marks the functions worth reading
("high-value function summaries").  ``threat.py`` already covers the binary
dossier that ``rebrew analyze`` returns; this module adds the per-function
layer reportal computes itself:

* :func:`score_candidates` ranks stored functions with a deterministic
  heuristic over cheap signals (size, a status that is not a byte match, a
  stored decompilation, a placeholder name and the number of recorded matches),
  returning a named ``heuristic_score`` in ``0..1`` and the reasons behind it.
* :func:`summarize_functions` selects the target functions (explicit ids, else
  the top ``limit`` candidates), builds each one's untrusted context (its
  stored decompilation, else a disassembly through the engine), asks the LLM
  bridge for ``{"summary", "score", "capabilities"}``, stores one ``ai_artifacts``
  row of kind :data:`FUNCTION_TRIAGE_KIND` per function and one aggregate scan
  of the same kind for the binary.

The feature degrades cleanly.  With no LLM endpoint configured every selected
function keeps the heuristic score and a deterministic one-line summary built
from its metadata, ``model`` is ``""`` and the payload's ``notes`` say so; the
run is stored either way, so the SPA and the API serve the same shape.

Context resolution is uniform and keeps the engine from being a hard
requirement: a function with a stored decompilation needs no engine call at
all, a function
without one is disassembled when the binary has a rebrew project context and
the engine is available, and a function with neither is recorded in the
payload's ``skipped`` list with a reason instead of failing the run.  The one
hard requirement is the LLM path: asking a model about a function whose
decompilation is not stored requires the engine, so that case raises
:class:`~reportal.engines.EngineUnavailable` (the API's 503) rather than
silently dropping the function.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from typing import Any

from reportal import engines, llm, store
from reportal.engines import RebrewEngine

# ai_artifacts kind of one function's triage row and scans kind of the
# aggregate payload.  Both are spelled the same on purpose: the artifact is the
# per-function half of the scan.
FUNCTION_TRIAGE_KIND = "function-triage"

# Functions summarized by a run when the caller names no limit, and the largest
# limit a caller may ask for.  Every function costs an engine call and a model
# call, so the ceiling is bounded rather than open-ended.
DEFAULT_LIMIT = 10
MAX_LIMIT = 50

# Longest context block sent per function.  A decompilation or listing can be
# far larger than a prompt needs, and the tail of a long function says least.
MAX_CONTEXT_CHARS = 20000

# Decimal places the heuristic score is rounded to, so the same inputs render
# the same number.
SCORE_DECIMALS = 4

# Heuristic weights, one share of the 0..1 score per signal.  They sum to 1.0,
# so a function with every signal scores 1.0.  The size and match-count signals
# saturate at their reference below rather than growing without bound.
WEIGHT_SIZE = 0.30
WEIGHT_STATUS = 0.25
WEIGHT_DECOMPILATION = 0.15
WEIGHT_NAME = 0.15
WEIGHT_MATCHES = 0.15

# Size at which the size signal is worth its full weight, and the number of
# recorded matches at which the match signal is.
SIZE_REFERENCE_BYTES = 4096
MATCH_REFERENCE = 3

# Method labels a summarized row carries, matching the payload's `by_method`.
METHOD_LLM = "llm"
METHOD_HEURISTIC = "heuristic"

# Prefixes that mark a compiler-generated or unnamed function.  Matched
# case-insensitively after lowercasing, so ``FUN_`` and ``FUNC_`` both land
# here (``fun_`` / ``func_``); keep both spellings so IDA and Hex-Rays dumps
# agree with lineage.PLACEHOLDER_PREFIXES.
PLACEHOLDER_NAME_PREFIXES: tuple[str, ...] = (
    "sub_",
    "fcn_",
    "fun_",
    "func_",
    "nullsub_",
    "loc_",
    "j_",
)

# Reasons a selected function is recorded as skipped instead of summarized.
NO_PROJECT_REASON = "no rebrew project context"
NO_SIZE_REASON = "function size is not positive"
NO_ENGINE_REASON = "no stored decompilation and no engine available"
EMPTY_DECOMPILATION_REASON = "stored decompilation is empty"

# Note a heuristic run records, so a caller can tell a model's row from a
# deterministic one without reading the model field.
HEURISTIC_NOTE = "llm-unavailable: scores and summaries are heuristic"

# Note a run with nothing to summarize records.
NO_FUNCTIONS_NOTE = "no functions selected for triage"

_VA_NAME = re.compile(r"^[0-9a-fA-F]+$")


def is_placeholder_name(name: str) -> bool:
    """True when *name* is empty or looks compiler-generated.

    A name is a placeholder when it is blank, when it starts with one of
    :data:`PLACEHOLDER_NAME_PREFIXES`, or when it is nothing but an address
    written without a prefix.
    """
    stripped = name.strip()
    if not stripped:
        return True
    lowered = stripped.lower()
    if lowered.startswith(PLACEHOLDER_NAME_PREFIXES):
        return True
    return bool(_VA_NAME.fullmatch(lowered))


def _int_field(row: dict[str, Any], key: str) -> int:
    """Return ``row[key]`` as an int, defaulting to 0 for a missing or bad value."""
    value = row.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def score_candidates(functions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank *functions* by a deterministic heuristic, best candidate first.

    Each input row is read for ``function_id``, ``name``, ``va``, ``size``,
    ``status``, ``has_decompilation`` and ``match_count``; the last two default
    to False and 0, so a caller that carries only the stored columns still gets
    a usable ranking.  :func:`candidate_rows` builds the full shape from the
    store.

    Returns one ``{"function_id", "name", "va", "size", "status",
    "has_decompilation", "match_count", "heuristic_score", "reasons"}`` row per
    input, sorted by score descending then VA then function id, so the order is
    stable for equal scores.  ``heuristic_score`` is the sum of the weighted
    signals (:data:`WEIGHT_SIZE`, :data:`WEIGHT_STATUS`,
    :data:`WEIGHT_DECOMPILATION`, :data:`WEIGHT_NAME`, :data:`WEIGHT_MATCHES`)
    rounded to :data:`SCORE_DECIMALS`, and ``reasons`` names every signal that
    contributed, in a fixed order.
    """
    ranked = [_score_function(row) for row in functions]
    ranked.sort(key=lambda row: (-row["heuristic_score"], row["va"], row["function_id"]))
    return ranked


def _score_function(row: dict[str, Any]) -> dict[str, Any]:
    """Score one candidate row and collect its contributing reasons."""
    size = _int_field(row, "size")
    status = str(row.get("status") or "")
    name = str(row.get("name") or "")
    matches = _int_field(row, "match_count")
    score = 0.0
    reasons: list[str] = []

    size_share = min(size / SIZE_REFERENCE_BYTES, 1.0) if size > 0 else 0.0
    if size_share > 0.0:
        score += WEIGHT_SIZE * size_share
        reasons.append(f"size {size} bytes")
    if status and status not in store.MATCHED_STATUSES:
        score += WEIGHT_STATUS
        reasons.append(f"status {status} is not a byte match")
    if bool(row.get("has_decompilation")):
        score += WEIGHT_DECOMPILATION
        reasons.append("stored decompilation")
    if is_placeholder_name(name):
        score += WEIGHT_NAME
        reasons.append(f"placeholder name {name!r}")
    if matches > 0:
        score += WEIGHT_MATCHES * min(matches / MATCH_REFERENCE, 1.0)
        reasons.append(f"{matches} stored matches")

    return {
        "function_id": _int_field(row, "function_id"),
        "name": name,
        "va": _int_field(row, "va"),
        "size": size,
        "status": status,
        "has_decompilation": bool(row.get("has_decompilation")),
        "match_count": matches,
        "heuristic_score": round(min(score, 1.0), SCORE_DECIMALS),
        "reasons": reasons,
    }


def candidate_rows(conn: sqlite3.Connection, *, binary_id: int) -> list[dict[str, Any]]:
    """Return a binary's functions with the cheap signals the heuristic reads."""
    functions = store.list_functions(conn, binary_id=binary_id)
    match_counts = store.match_counts_for_binary(conn, binary_id)
    decompiled = store.decompilation_ids_for_binary(conn, binary_id)
    rows: list[dict[str, Any]] = []
    for function in functions:
        function_id = int(function["id"])
        rows.append(
            {
                "function_id": function_id,
                "name": str(function.get("name") or ""),
                "va": int(function.get("va") or 0),
                "size": int(function.get("size") or 0),
                "status": str(function.get("status") or ""),
                "has_decompilation": function_id in decompiled,
                "match_count": match_counts.get(function_id, 0),
            }
        )
    return rows


def _heuristic_summary(row: dict[str, Any], reasons: Sequence[str]) -> str:
    """One deterministic line describing a function from its stored metadata."""
    name = str(row.get("name") or "") or f"sub_{_int_field(row, 'va'):x}"
    status = str(row.get("status") or "unknown")
    detail = "; ".join(reasons) or "no standout signal"
    return (
        f"{name} ({status}, {_int_field(row, 'size')} bytes,"
        f" {_int_field(row, 'match_count')} stored matches): {detail}"
    )


def _resolve_context(
    conn: sqlite3.Connection,
    row: dict[str, Any],
    *,
    project_dir: str | None,
    engine: RebrewEngine,
) -> tuple[str, str] | None:
    """Return ``(context, kind)`` for one function, or None when there is none.

    A stored decompilation is preferred and needs no engine.  Otherwise the
    function is disassembled through *engine* in the binary's rebrew project,
    which requires a project context, a positive size and an available engine.
    """
    stored = store.get_decompilation(conn, row["function_id"])
    if stored is not None and str(stored["code"]).strip():
        return str(stored["code"])[:MAX_CONTEXT_CHARS], llm.TRIAGE_CONTEXT_DECOMPILATION
    if project_dir is None or row["size"] <= 0 or not engine.available():
        return None
    listing = engine.disassemble(project_dir, row["va"], row["size"])
    return listing[:MAX_CONTEXT_CHARS], llm.TRIAGE_CONTEXT_DISASSEMBLY


def _no_context_reason(
    conn: sqlite3.Connection, row: dict[str, Any], *, project_dir: str | None
) -> str:
    """Name why :func:`_resolve_context` found nothing for one function."""
    stored = store.get_decompilation(conn, row["function_id"])
    if stored is not None and not str(stored["code"]).strip():
        return EMPTY_DECOMPILATION_REASON
    if project_dir is None:
        return NO_PROJECT_REASON
    if row["size"] <= 0:
        return NO_SIZE_REASON
    return NO_ENGINE_REASON


def summarize_functions(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    function_ids: Sequence[int] | None = None,
    limit: int = DEFAULT_LIMIT,
    client: llm.LlmClient | None = None,
    engine: RebrewEngine | None = None,
) -> dict[str, Any]:
    """Triage a binary's functions and store the results.

    An explicit *function_ids* list is used as given, in the order it names
    (capped at no length, since the caller asked for those); otherwise the top
    *limit* rows of :func:`score_candidates` are selected.  Each selected
    function with a resolvable context is summarized through the configured LLM
    bridge when one is available and through the heuristic otherwise, and
    stored as an ``ai_artifacts`` row of kind :data:`FUNCTION_TRIAGE_KIND`.  The
    aggregate payload is stored as the binary's ``function-triage`` scan.

    *engine* defaults to the process-wide engine, which the LLM path needs to
    disassemble a function with no stored decompilation.

    Returns ``{"binary_id", "model", "functions", "count", "by_method",
    "skipped", "notes"}``, where ``functions`` is sorted by score descending
    then VA.  Raises :class:`KeyError` for an unknown binary, :class:`ValueError`
    for an unknown function id, an out-of-range limit or a non-integer id, and
    :class:`~reportal.engines.EngineUnavailable` when the LLM path needs a
    disassembly and no engine is available.
    """
    if limit < 1 or limit > MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}, got {limit}")
    if store.get_binary(conn, binary_id) is None:
        raise KeyError(f"no binary with id {binary_id}")

    candidates = candidate_rows(conn, binary_id=binary_id)
    if function_ids is None:
        selected = score_candidates(candidates)[:limit]
    else:
        by_id = {row["function_id"]: row for row in candidates}
        wanted = [int(function_id) for function_id in function_ids]
        unknown = [function_id for function_id in wanted if function_id not in by_id]
        if unknown:
            raise ValueError(f"no function with id {unknown[0]} for binary {binary_id}")
        selected = [
            score_candidates([by_id[function_id]])[0] for function_id in dict.fromkeys(wanted)
        ]

    active = client if client is not None else llm.get_client()
    using_llm = active.available()
    source = engine if engine is not None else engines.get_engine()
    needs_engine = [row for row in selected if not row["has_decompilation"] and row["size"] > 0]
    if using_llm and needs_engine and not source.available():
        raise engines.EngineUnavailable(
            "the LLM path needs a disassembly and no rebrew engine is available"
        )
    project_dir = store.get_rebrew_context(conn, binary_id)

    entries: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    model = active.model if using_llm else ""
    for row in selected:
        resolved = _resolve_context(conn, row, project_dir=project_dir, engine=source)
        if resolved is None:
            skipped.append(
                {
                    "function_id": row["function_id"],
                    "name": row["name"],
                    "va": row["va"],
                    "reason": _no_context_reason(conn, row, project_dir=project_dir),
                }
            )
            continue
        context, context_kind = resolved
        if using_llm:
            answer = llm.function_triage(context, client=active, context_kind=context_kind)
            score = round(float(answer["score"]), SCORE_DECIMALS)
            summary = str(answer["summary"])
            capabilities = list(answer["capabilities"])
            method = METHOD_LLM
        else:
            score = row["heuristic_score"]
            summary = _heuristic_summary(row, row["reasons"])
            capabilities = []
            method = METHOD_HEURISTIC
        store.set_ai_artifact(
            conn,
            row["function_id"],
            FUNCTION_TRIAGE_KIND,
            {
                "summary": summary,
                "score": score,
                "capabilities": capabilities,
                "method": method,
            },
            model,
        )
        entries.append(
            {
                "function_id": row["function_id"],
                "name": row["name"],
                "va": row["va"],
                "size": row["size"],
                "status": row["status"],
                "score": score,
                "summary": summary,
                "capabilities": capabilities,
                "method": method,
            }
        )

    entries.sort(key=lambda entry: (-entry["score"], entry["va"]))
    by_method = {
        METHOD_LLM: sum(1 for entry in entries if entry["method"] == METHOD_LLM),
        METHOD_HEURISTIC: sum(1 for entry in entries if entry["method"] == METHOD_HEURISTIC),
    }
    notes: list[str] = []
    if not using_llm:
        notes.append(HEURISTIC_NOTE)
    if not selected:
        notes.append(NO_FUNCTIONS_NOTE)

    payload = {
        "binary_id": binary_id,
        "model": model,
        "functions": entries,
        "count": len(entries),
        "by_method": by_method,
        "skipped": skipped,
        "notes": notes,
    }
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_FUNCTION_TRIAGE,
        payload,
        params={"function_ids": list(function_ids or ()), "limit": limit},
    )
    return payload


def stored_function_triage(conn: sqlite3.Connection, *, binary_id: int) -> dict[str, Any] | None:
    """Return the binary's stored aggregate triage payload, or None."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, store.SCAN_KIND_FUNCTION_TRIAGE)

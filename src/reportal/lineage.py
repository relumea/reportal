"""Deterministic pairwise function lineage between two binaries.

:func:`compare_functions` pairs the functions of two listings without a model
and without disassembling anything itself.  An exact name match pairs first,
preferring the candidate whose size is closest; the unnamed/placeholder names
are then paired inside a size bucket with an injected structural scorer.  A
pairing whose names match at the same size, or whose structural score reaches
:data:`UNCHANGED_THRESHOLD`, is ``unchanged``; a name match at a different
size, or a score between :data:`CHANGED_THRESHOLD` and the unchanged
threshold, is ``changed``; everything left over is ``removed`` (left side
only) or ``added`` (right side only).  A named function whose name is absent
from the other side is never re-paired structurally: its name is the identity
signal, so a rename reads as one removal plus one addition.

:func:`compare_binaries` gathers both function lists from the store and builds
the scorer over the disassembly cache (``matching.cached_disassembler``, which
resolves each function's own rebrew project context) when the optional
``similarity`` extra and a rebrew engine are both available.  Without either it
runs the name/size pass alone and records ``refined: false`` instead of
failing: a structural score is an enrichment, not a requirement.

A finished comparison is stored as the ``lineage`` scan on the left binary's
analysis, keyed by the right binary id, so one left binary holds one stored
comparison per pair and a re-run refreshes just that pair.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from typing import Any

from reportal import engines, matching, similarity, store

# Statuses a lineage row carries.  The tuple is also the row sort order, so a
# reader sees the matched functions before the unmatched ones.
STATUS_UNCHANGED = "unchanged"
STATUS_CHANGED = "changed"
STATUS_REMOVED = "removed"
STATUS_ADDED = "added"
LINEAGE_STATUSES = (STATUS_UNCHANGED, STATUS_CHANGED, STATUS_REMOVED, STATUS_ADDED)

# Structural similarity (0-100) at or above which a scored pairing counts as
# the same function, and at or above which it counts as a changed one.  Below
# the second threshold the pair is not a match at all.
UNCHANGED_THRESHOLD = 95.0
CHANGED_THRESHOLD = 70.0

# Relative size difference two functions may differ by and still be candidates
# for a structural pairing, as a percentage of the larger size.
SIZE_TOLERANCE_PERCENT = 10.0

# Candidates scored per left function in the structural pass; only the nearest
# sizes are considered, so a huge binary cannot make the pass quadratic.
MAX_CANDIDATES = 20

# Rows a comparison returns.  The summary counts stay exact; only the row list
# is capped, since a large binary pair would otherwise return tens of thousands
# of rows.
MAX_ROWS = 500

# Name prefixes rebrew gives a function it could not name.  A name matching one
# of these (or an empty name) carries no identity, so it never pairs in the
# name pass.
PLACEHOLDER_PREFIXES = ("sub_", "fcn_", "FUNC_")

# Decimals `matched_percent` and `confidence` are rounded to.
METRIC_DECIMALS = 1

# Confidence a name-identical pairing carries: the names are the same string,
# so the pairing itself is not in doubt (the status still reports the size
# difference).
NAME_MATCH_CONFIDENCE = 1.0

# Payload key holding one left binary's stored comparisons, each keyed by the
# right binary id as a string.
COMPARISONS_KEY = "comparisons"


class LineageError(RuntimeError):
    """A lineage comparison that cannot be run."""


class SameBinaryError(LineageError):
    """A binary was compared with itself."""


# A structural scorer over two function rows: the similarity (0-100), or None
# when the pair cannot be scored (a missing listing, an unavailable engine).
FunctionScorer = Callable[[dict[str, Any], dict[str, Any]], float | None]


def is_placeholder_name(name: str) -> bool:
    """True when *name* carries no identity: empty or a rebrew placeholder."""
    stripped = name.strip()
    return not stripped or stripped.startswith(PLACEHOLDER_PREFIXES)


def _function_id(function: dict[str, Any]) -> int | None:
    value = function.get("id")
    return int(value) if isinstance(value, int) else None


def _name(function: dict[str, Any]) -> str:
    return str(function.get("name") or "")


def _va(function: dict[str, Any]) -> int | None:
    value = function.get("va")
    return int(value) if isinstance(value, int) else None


def _size(function: dict[str, Any]) -> int:
    value = function.get("size")
    return int(value) if isinstance(value, int) else 0


def _size_distance(left: dict[str, Any], right: dict[str, Any]) -> int:
    return abs(_size(left) - _size(right))


def _in_size_bucket(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """True when the two functions' sizes differ within the tolerance.

    Measured against the larger size, so the test is symmetric; two zero-size
    functions are in one bucket and a zero-size function pairs with nothing
    else.
    """
    larger = max(_size(left), _size(right))
    return _size_distance(left, right) <= larger * SIZE_TOLERANCE_PERCENT / 100


def _round(value: float) -> float:
    return round(value, METRIC_DECIMALS)


def _va_key(function: dict[str, Any]) -> int:
    va = _va(function)
    return va if va is not None else 0


def _row(
    status: str,
    left: dict[str, Any] | None,
    right: dict[str, Any] | None,
    *,
    similarity: float | None,
    confidence: float,
) -> dict[str, Any]:
    return {
        "status": status,
        "left_function_id": _function_id(left) if left is not None else None,
        "left_name": _name(left) if left is not None else None,
        "left_va": _va(left) if left is not None else None,
        "left_size": _size(left) if left is not None else None,
        "right_function_id": _function_id(right) if right is not None else None,
        "right_name": _name(right) if right is not None else None,
        "right_va": _va(right) if right is not None else None,
        "right_size": _size(right) if right is not None else None,
        "confidence": confidence,
        "similarity": similarity,
    }


def _summary(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Counts by status plus the paired share of both sides' functions."""
    counts = dict.fromkeys(LINEAGE_STATUSES, 0)
    for row in rows:
        status = str(row["status"])
        if status in counts:
            counts[status] += 1
    matched = counts[STATUS_UNCHANGED] + counts[STATUS_CHANGED]
    total = matched + counts[STATUS_ADDED] + counts[STATUS_REMOVED]
    return {
        **counts,
        "matched_percent": _round(100 * matched / total) if total else 0.0,
    }


def _sort_key(row: dict[str, Any]) -> tuple[int, int]:
    order = LINEAGE_STATUSES.index(str(row["status"]))
    anchor = row["left_va"] if row["left_va"] is not None else row["right_va"]
    return (order, int(anchor) if anchor is not None else 0)


def _name_pass(
    left: Sequence[dict[str, Any]], right: Sequence[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[int]]:
    """Pair exact non-placeholder names; returns rows, unmatched left, claimed right.

    A name with several candidates on either side takes the closest size, then
    the lowest VA, so the result does not depend on dictionary ordering.
    """
    right_by_name: dict[str, list[int]] = {}
    for index, function in enumerate(right):
        name = _name(function)
        if not is_placeholder_name(name):
            right_by_name.setdefault(name, []).append(index)

    rows: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    claimed: set[int] = set()
    for function in left:
        name = _name(function)
        if is_placeholder_name(name):
            unmatched.append(function)
            continue
        available = [index for index in right_by_name.get(name, []) if index not in claimed]
        if not available:
            unmatched.append(function)
            continue
        chosen = min(
            available,
            key=lambda index: (_size_distance(function, right[index]), _va_key(right[index])),
        )
        claimed.add(chosen)
        candidate = right[chosen]
        same_size = _size(function) == _size(candidate)
        rows.append(
            _row(
                STATUS_UNCHANGED if same_size else STATUS_CHANGED,
                function,
                candidate,
                similarity=None,
                confidence=NAME_MATCH_CONFIDENCE,
            )
        )
    return rows, unmatched, claimed


def _structural_pass(
    left: Sequence[dict[str, Any]],
    right: Sequence[dict[str, Any]],
    claimed: set[int],
    score: FunctionScorer,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Score each unmatched placeholder-named left function against its nearest sizes.

    Candidates come only from the left function's size bucket and never exceed
    :data:`MAX_CANDIDATES`, taken nearest size first.  The best candidate at or
    above :data:`CHANGED_THRESHOLD` wins; ties fall to the closer size, then the
    lower VA.
    """
    rows: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for function in left:
        available = [
            index
            for index in range(len(right))
            if index not in claimed and _in_size_bucket(function, right[index])
        ]
        available.sort(
            key=lambda index: (_size_distance(function, right[index]), _va_key(right[index]))
        )
        scored: list[tuple[float, int]] = []
        for index in available[:MAX_CANDIDATES]:
            value = score(function, right[index])
            if value is not None:
                scored.append((float(value), index))
        scored.sort(
            key=lambda item: (
                -item[0],
                _size_distance(function, right[item[1]]),
                _va_key(right[item[1]]),
            )
        )
        if not scored or scored[0][0] < CHANGED_THRESHOLD:
            unmatched.append(function)
            continue
        value, chosen = scored[0]
        claimed.add(chosen)
        rows.append(
            _row(
                STATUS_UNCHANGED if value >= UNCHANGED_THRESHOLD else STATUS_CHANGED,
                function,
                right[chosen],
                similarity=_round(value),
                confidence=_round(value / 100),
            )
        )
    return rows, unmatched


def compare_functions(
    left: Sequence[dict[str, Any]],
    right: Sequence[dict[str, Any]],
    *,
    score: FunctionScorer | None = None,
) -> dict[str, Any]:
    """Pair two function listings and classify every function of both sides.

    *score* is the structural scorer used by the second pass; without one only
    the exact-name pass runs, since there is no similarity to accept a
    placeholder pairing on.  Returns ``{"summary", "rows"}``: the exact status
    counts with ``matched_percent``, and the rows sorted status-first
    (unchanged, changed, removed, added) then by left VA, capped at
    :data:`MAX_ROWS`.  The summary always counts every function, cap or not.
    """
    rows, unmatched_left, claimed = _name_pass(left, right)
    if score is not None:
        placeholders = [row for row in unmatched_left if is_placeholder_name(_name(row))]
        named = [row for row in unmatched_left if not is_placeholder_name(_name(row))]
        scored_rows, still_unmatched = _structural_pass(placeholders, right, claimed, score)
        rows.extend(scored_rows)
        unmatched_left = named + still_unmatched
    rows.extend(
        _row(STATUS_REMOVED, function, None, similarity=None, confidence=0.0)
        for function in unmatched_left
    )
    rows.extend(
        _row(STATUS_ADDED, None, function, similarity=None, confidence=0.0)
        for index, function in enumerate(right)
        if index not in claimed
    )
    rows.sort(key=_sort_key)
    return {"summary": _summary(rows), "rows": rows[:MAX_ROWS]}


def _cache_scorer(disassembler: matching.Disassembler) -> FunctionScorer:
    """Wrap a disassembler into the structural scorer the second pass takes."""

    def score(left: dict[str, Any], right: dict[str, Any]) -> float | None:
        left_text = disassembler(left)
        right_text = disassembler(right)
        if not left_text or not right_text:
            return None
        try:
            return similarity.similarity(left_text, right_text)
        except similarity.SimilarityUnavailable:
            return None

    return score


def compare_binaries(
    conn: sqlite3.Connection,
    *,
    left_binary_id: int,
    right_binary_id: int,
    engine: engines.RebrewEngine | None = None,
    score: FunctionScorer | None = None,
    disassembler: matching.Disassembler | None = None,
    refine: bool = True,
) -> dict[str, Any]:
    """Compare the stored functions of two binaries.

    The structural pass runs when a scorer is injected, when a *disassembler*
    is injected, or when *refine* is true and the optional ``similarity`` extra
    and a rebrew engine are both available; otherwise the comparison is
    name/size only and ``refined`` is false.  A disassembler or engine that
    cannot resolve a function yields no score for that pair, never an error.

    Raises :class:`KeyError` for an unknown binary id and
    :class:`SameBinaryError` when both ids name the same binary.
    """
    if left_binary_id == right_binary_id:
        raise SameBinaryError(f"binary {left_binary_id} cannot be compared with itself")
    left_binary = store.get_binary(conn, left_binary_id)
    if left_binary is None:
        raise KeyError(f"no binary with id {left_binary_id}")
    right_binary = store.get_binary(conn, right_binary_id)
    if right_binary is None:
        raise KeyError(f"no binary with id {right_binary_id}")

    refined = False
    if score is not None:
        refined = True
    elif disassembler is not None:
        score = _cache_scorer(disassembler)
        refined = True
    elif refine and similarity.available():
        resolved = engine if engine is not None else engines.get_engine()
        if resolved.available():
            score = _cache_scorer(matching.cached_disassembler(conn, resolved))
            refined = True

    result = compare_functions(
        store.list_functions(conn, binary_id=left_binary_id),
        store.list_functions(conn, binary_id=right_binary_id),
        score=score,
    )
    return {
        "left_binary_id": left_binary_id,
        "right_binary_id": right_binary_id,
        "left_name": str(left_binary["name"]),
        "right_name": str(right_binary["name"]),
        "refined": refined,
        "summary": result["summary"],
        "rows": result["rows"],
    }


def _stored_comparisons(conn: sqlite3.Connection, left_binary_id: int) -> dict[str, dict[str, Any]]:
    """The left binary's stored comparison payload, empty when it has none.

    An entry is kept only when it is an object carrying the right binary id,
    which is the key the pair is stored under; anything else is not a
    comparison this module wrote and is skipped rather than served.
    """
    analysis_id = store.latest_analysis_for_binary(conn, left_binary_id)
    if analysis_id is None:
        return {}
    stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_LINEAGE)
    if not isinstance(stored, dict):
        return {}
    comparisons = stored.get(COMPARISONS_KEY)
    if not isinstance(comparisons, dict):
        return {}
    entries: dict[str, dict[str, Any]] = {}
    for key, value in comparisons.items():
        if not isinstance(value, dict):
            continue
        try:
            int(value["right_binary_id"])
        except (KeyError, TypeError, ValueError):
            continue
        entries[str(key)] = value
    return entries


def store_comparison(conn: sqlite3.Connection, comparison: dict[str, Any]) -> None:
    """Store *comparison* as the left binary's ``lineage`` scan entry for the pair.

    One scan row holds every pair of one left binary, keyed by the right binary
    id, so re-running one comparison refreshes that pair and leaves the others
    in place.
    """
    left_binary_id = int(comparison["left_binary_id"])
    right_binary_id = int(comparison["right_binary_id"])
    analysis_id = store.ensure_analysis_for_binary(conn, left_binary_id, engine=store.SCAN_ENGINE)
    comparisons = _stored_comparisons(conn, left_binary_id)
    comparisons[str(right_binary_id)] = comparison
    store.set_scan(conn, analysis_id, store.SCAN_KIND_LINEAGE, {COMPARISONS_KEY: comparisons})


def stored_comparison(
    conn: sqlite3.Connection, left_binary_id: int, right_binary_id: int
) -> dict[str, Any] | None:
    """The stored comparison of the pair, or None when it was never run."""
    return _stored_comparisons(conn, left_binary_id).get(str(right_binary_id))


def stored_comparisons(conn: sqlite3.Connection, left_binary_id: int) -> list[dict[str, Any]]:
    """Every stored comparison of *left_binary_id*, lowest other binary id first."""
    comparisons = _stored_comparisons(conn, left_binary_id)
    return sorted(comparisons.values(), key=lambda entry: int(entry["right_binary_id"]))

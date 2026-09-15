"""Composition analysis of one stored binary against its stored matches.

The hosted portal's binary detail page answers four questions about a binary's
place in the corpus: how many of its functions matched anything (``Matched: N /
M``), where its function names came from, how strong those matches are, and
which other binary each function matched.  :func:`compute_composition` answers
all four from the store alone.

Every input is already stored: this binary's functions come from
:func:`store.list_functions`, the match edges from
:func:`matching.binary_match_rows` (which reads ``matches`` joined to the
candidate functions), and the candidate's owning binary from
:func:`store.get_function` plus :func:`store.get_binary`.  The scan never runs
local function matching and never calls the engine, so a stored composition is
a reading of the ``matches`` table the ``reportal match`` command produced, not
a new computation.  A store with no match rows for the binary still succeeds:
``refined`` is false, a note names the command that fills the table, and every
function renders as ``No Match``.

A stored match whose candidate belongs to this same binary is not a
composition: reportal's corpus includes a binary's own functions, so an exact
duplicate can match itself, and the portal's composition block is about the
*other* binaries.  Those edges are counted and reported in the notes, and a
function whose every stored match is a self-match renders ``No Match``.

:data:`NAME_SOURCE_MAP` is the one explicit table mapping reportal's stored
``name_source`` vocabulary onto the portal's five labels, and an unrecognised
source falls to ``User`` because a person's decision is the safest reading of a
source nobody declared.

The per-binary list is not capped: it carries at most one row per other binary
in the store, so it is bounded by the binary count.  The per-function list is
capped at :data:`MAX_ROWS`, since a large binary has tens of thousands of
functions; every summary count stays exact when the list is capped.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any

from reportal import lineage, matching, renames, store, unstrip

# The five function-name-source labels the portal's breakdown carries, in the
# order the panel renders them.  ``No Debug Info`` is defined by the name (empty
# or a placeholder prefix), not by a source, so it is last.
NAME_SOURCE_SYSTEM = "System"
NAME_SOURCE_AUTO_UNSTRIP = "Auto Unstrip"
NAME_SOURCE_AI_AGENT = "AI Agent"
NAME_SOURCE_USER = "User"
NAME_SOURCE_NO_DEBUG_INFO = "No Debug Info"
NAME_SOURCE_LABELS = (
    NAME_SOURCE_SYSTEM,
    NAME_SOURCE_AUTO_UNSTRIP,
    NAME_SOURCE_AI_AGENT,
    NAME_SOURCE_USER,
    NAME_SOURCE_NO_DEBUG_INFO,
)

# One explicit table mapping reportal's stored ``name_source`` vocabulary onto
# the portal's five labels.  An unrecognised source falls to ``User`` because a
# person's decision is the safest reading of a source nobody declared; the
# ``ai`` prefix (the LLM bridge's own sources) also falls to ``AI Agent``.
# ``import`` is ``cli.THUNK_NAME_SOURCE`` (referenced as a literal because
# ``cli`` imports this module) and ``rebrew`` is rebrew's own library and CRT
# identification; both are the portal's ``System``.
NAME_SOURCE_MAP: dict[str, str] = {
    "import": NAME_SOURCE_SYSTEM,
    "rebrew": NAME_SOURCE_SYSTEM,
    "symbol": NAME_SOURCE_SYSTEM,
    unstrip.UNSTRIP_SOURCE: NAME_SOURCE_AUTO_UNSTRIP,
    renames.RENAME_SOURCE: NAME_SOURCE_AI_AGENT,
}
NAME_SOURCE_AI_PREFIX = "ai"

# Similarity cutoffs (matches.similarity, 0-100) that partition the quality
# bands, aligned with the floors the rest of reportal already uses:
# ``lineage.UNCHANGED_THRESHOLD`` (95.0) for a strong match,
# ``matching.DEFAULT_MIN_SIMILARITY`` (80.0) for a match, and
# ``lineage.CHANGED_THRESHOLD`` (70.0) for a partial one.  Anything below
# ``PARTIAL_MATCH_MIN_SIMILARITY`` that still has a stored match is weak; a
# function with no stored match is ``No Match``, never a similarity of zero.
STRONG_MATCH_MIN_SIMILARITY = 95.0
MATCH_MIN_SIMILARITY = 80.0
PARTIAL_MATCH_MIN_SIMILARITY = 70.0

# The five quality bands, strongest first, in the order the panel renders them.
BAND_STRONG_MATCH = "Strong Match"
BAND_MATCH = "Match"
BAND_PARTIAL_MATCH = "Partial Match"
BAND_WEAK_MATCH = "Weak Match"
BAND_NO_MATCH = "No Match"
QUALITY_BANDS = (
    BAND_STRONG_MATCH,
    BAND_MATCH,
    BAND_PARTIAL_MATCH,
    BAND_WEAK_MATCH,
    BAND_NO_MATCH,
)

# The hosted portal's composition categories, a second grouping beside the
# name-source buckets and the quality bands.  A function lands in exactly one:
# a name that says the toolchain produced it is ``library``, a function with no
# stored match is ``unique``, a function whose name came only from debug
# information is ``debug``, and every other function matched something, which is
# the malware signal this local corpus can support.  ``reportal`` matches by
# assembly similarity and holds no family feed, so ``malware`` is a matched
# function rather than a verdict, and the payload says so in ``category_notes``.
CATEGORY_MALWARE = "malware"
CATEGORY_DEBUG = "debug"
CATEGORY_UNIQUE = "unique"
CATEGORY_LIBRARY = "library"
CATEGORIES: tuple[str, ...] = (
    CATEGORY_MALWARE,
    CATEGORY_DEBUG,
    CATEGORY_UNIQUE,
    CATEGORY_LIBRARY,
)
CATEGORY_LABELS: dict[str, str] = {
    CATEGORY_MALWARE: "Malware",
    CATEGORY_DEBUG: "Debug",
    CATEGORY_UNIQUE: "Unique",
    CATEGORY_LIBRARY: "Library",
}
CATEGORY_NOTES: tuple[str, ...] = (
    (
        "a category is derived from the stored name source and the stored match edges;"
        " reportal matches by assembly similarity and holds no family feed, so"
        " 'malware' means a function matched another binary, not a verdict"
    ),
)

# The scope note a scoped payload carries in place of the whole-register one.
SCOPED_NOTE = "scoped to {}"

# Other binaries one category's top list names.
CATEGORY_TOP_BINARIES = 5

# Stored ``name_source`` values that mean the name came from a symbol file or
# the engine's own identification, which is what the hosted ``library`` category
# reads: an import stub, a rebrew-supplied name or an ingested symbol.
LIBRARY_NAME_SOURCES: frozenset[str] = frozenset({"import", "rebrew", "symbol"})

# Function rows the payload returns.  A binary can hold tens of thousands of
# functions; the summary counts stay exact and the note states the cap.
MAX_ROWS = 500

# Decimals every percentage is rounded to.
METRIC_DECIMALS = 1

# Scope note every payload carries, plus the two states a reader must be able
# to tell apart: no stored matches at all, and stored matches that only point
# back into this binary.
SCOPE_NOTE = "stored-only composition over the matches table; no engine and no matching run"
NO_MATCHES_NOTE = (
    "no stored matches for this binary; run 'reportal match <binary-id>'"
    " (or the Match button) before the composition analysis"
)
SELF_MATCH_NOTE = "{} functions matched only within this binary; a self-match is not a composition"


class NoCompositionError(KeyError):
    """The requested binary is not in the store.

    Subclasses ``KeyError``, the convention every sibling scan module raises for
    an unknown binary, so the route, CLI and MCP handlers already catch it.
    """


def _percent(part: int, total: int) -> float | None:
    """*part* as a percentage of *total*, one decimal; None when total is zero."""
    if total <= 0:
        return None
    return round(100 * part / total, METRIC_DECIMALS)


def name_source_label(function: dict[str, Any]) -> str:
    """The portal label one function's name and source fall into.

    A placeholder (or empty) name is ``No Debug Info`` whatever source it
    carries; otherwise see :data:`NAME_SOURCE_MAP`, then the ``ai`` prefix, then
    ``User`` for anything nobody declared.
    """
    if lineage.is_placeholder_name(str(function.get("name") or "")):
        return NAME_SOURCE_NO_DEBUG_INFO
    source = str(function.get("name_source") or "").strip().lower()
    label = NAME_SOURCE_MAP.get(source)
    if label is not None:
        return label
    if source.startswith(NAME_SOURCE_AI_PREFIX):
        return NAME_SOURCE_AI_AGENT
    return NAME_SOURCE_USER


def quality_band(similarity: float | None) -> str:
    """The quality band a stored match similarity falls into.

    ``None`` is ``No Match``: the band is the absence of a stored match, never a
    similarity of zero.
    """
    if similarity is None:
        return BAND_NO_MATCH
    if similarity >= STRONG_MATCH_MIN_SIMILARITY:
        return BAND_STRONG_MATCH
    if similarity >= MATCH_MIN_SIMILARITY:
        return BAND_MATCH
    if similarity >= PARTIAL_MATCH_MIN_SIMILARITY:
        return BAND_PARTIAL_MATCH
    return BAND_WEAK_MATCH


def _candidate_binary(
    conn: sqlite3.Connection, candidate_function_id: int, cache: dict[int, dict[str, Any] | None]
) -> dict[str, Any] | None:
    """The binary owning a candidate function, cached by candidate function id."""
    if candidate_function_id in cache:
        return cache[candidate_function_id]
    function = store.get_function(conn, candidate_function_id)
    binary = store.get_binary(conn, int(function["binary_id"])) if function is not None else None
    resolved = (
        None
        if binary is None
        else {
            "binary_id": int(binary["id"]),
            "name": str(binary["name"]),
            "sha256": binary.get("sha256"),
        }
    )
    cache[candidate_function_id] = resolved
    return resolved


def _best_matches(
    conn: sqlite3.Connection, *, binary_id: int, scope: frozenset[int] = frozenset()
) -> tuple[dict[int, dict[str, Any]], int, bool]:
    """The best other-binary match of each function, plus self-match and edge counts.

    ``matching.binary_match_rows`` returns every stored edge of this binary's
    functions, best similarity first, so the first non-self edge of a function
    is its best match against another binary.  Returns ``(best, self_only,
    has_edges)``: the best match per function id, how many functions matched
    only within this binary, and whether the store holds any edge at all.
    """
    cache: dict[int, dict[str, Any] | None] = {}
    best: dict[int, dict[str, Any]] = {}
    self_seen: set[int] = set()
    edges = matching.binary_match_rows(conn, binary_id)
    for edge in edges:
        source_id = int(edge["source_function_id"])
        candidate = _candidate_binary(conn, int(edge["candidate_function_id"]), cache)
        if candidate is None:
            continue
        if scope and int(candidate["binary_id"]) not in scope:
            continue
        if int(candidate["binary_id"]) == binary_id:
            self_seen.add(source_id)
            continue
        if source_id in best:
            continue
        best[source_id] = {
            "similarity": round(float(edge["similarity"]), METRIC_DECIMALS),
            "binary_id": int(candidate["binary_id"]),
            "binary_name": str(candidate["name"]),
        }
    return best, len(self_seen - set(best)), bool(edges)


def _function_rows(
    functions: list[dict[str, Any]], best: dict[int, dict[str, Any]]
) -> list[dict[str, Any]]:
    """One row per function, in VA order, with its best match or ``No Match``."""
    rows: list[dict[str, Any]] = []
    for function in functions:
        function_id = int(function["id"])
        matched = best.get(function_id)
        if matched is None:
            similarity: float | None = None
            matched_binary_id: int | None = None
            matched_binary_name: str | None = None
        else:
            similarity = float(matched["similarity"])
            matched_binary_id = int(matched["binary_id"])
            matched_binary_name = str(matched["binary_name"])
        rows.append(
            {
                "function_id": function_id,
                "name": str(function["name"]),
                "va": int(function["va"]),
                "size": int(function["size"]),
                "band": quality_band(similarity),
                "similarity": similarity,
                "matched_binary_id": matched_binary_id,
                "matched_binary_name": matched_binary_name,
            }
        )
    return rows


def _count_rows(
    labels: tuple[str, ...], counts: dict[str, int], total: int
) -> list[dict[str, Any]]:
    """One ``{label, count, percent}`` entry per label, in label order."""
    return [
        {
            "label": label,
            "count": counts.get(label, 0),
            "percent": _percent(counts.get(label, 0), total),
        }
        for label in labels
    ]


def category_of(name_source: str, matched: bool) -> str:
    """The hosted category one function falls into.

    Library wins over a match: a function whose name a symbol file or the engine
    supplied is a library function whatever else it looks like, which is the
    reading the hosted page takes.  A function with no stored match is debug,
    which is where a name the toolchain could not resolve belongs, and one that
    matched another binary is the local malware bucket.  ``unique`` is the two
    counts together: a function with no name and no match is the absence of
    evidence, and it is neither debug information nor a library.
    """
    if name_source in LIBRARY_NAME_SOURCES:
        return CATEGORY_LIBRARY
    if not matched:
        return CATEGORY_UNIQUE
    return CATEGORY_MALWARE


def _category_rows(
    functions: list[dict[str, Any]], rows: list[dict[str, Any]], total: int
) -> list[dict[str, Any]]:
    """One entry per hosted category, with its count, percent and top binaries.

    The top-binary list is the same per-other-binary rollup the payload carries,
    narrowed to the functions of this category, so the category view and the
    composition table cannot disagree about who a match came from.
    """
    sources = {int(function["id"]): function for function in functions}
    buckets: dict[str, list[dict[str, Any]]] = {label: [] for label in CATEGORIES}
    for row in rows:
        function = sources.get(int(row["function_id"]), {})
        source = str(function.get("name_source") or "").strip().lower()
        matched = row["matched_binary_id"] is not None
        # A placeholder name is the absence of debug information, so it is the
        # debug bucket's own reading of "the toolchain could not name this".
        if not matched and lineage.is_placeholder_name(str(row["name"])):
            buckets[CATEGORY_DEBUG].append(row)
            continue
        buckets[category_of(source, matched)].append(row)
    entries: list[dict[str, Any]] = []
    for category in CATEGORIES:
        members = buckets[category]
        rollup = _composition_rows(members, total)
        entries.append(
            {
                "category": category,
                "label": CATEGORY_LABELS[category],
                "count": len(members),
                "percent": _percent(len(members), total),
                "binaries": [
                    {
                        "binary_id": entry["binary_id"],
                        "name": entry["name"],
                        "count": entry["count"],
                    }
                    for entry in rollup[:CATEGORY_TOP_BINARIES]
                ],
            }
        )
    return entries


def _composition_rows(rows: list[dict[str, Any]], total: int) -> list[dict[str, Any]]:
    """Per other-binary rollup, count descending then binary id, with percentages."""
    rollup: dict[int, dict[str, Any]] = {}
    for row in rows:
        binary_id = row["matched_binary_id"]
        if binary_id is None:
            continue
        entry = rollup.setdefault(
            int(binary_id),
            {
                "binary_id": int(binary_id),
                "name": row["matched_binary_name"],
                "sha256": None,
                "count": 0,
            },
        )
        entry["count"] += 1
    for entry in rollup.values():
        entry["percent"] = _percent(int(entry["count"]), total)
    return sorted(
        rollup.values(), key=lambda entry: (-int(entry["count"]), int(entry["binary_id"]))
    )


def _binary_sha256(conn: sqlite3.Connection, binary_id: int) -> str | None:
    """The stored sha256 of one binary, or None when the row has none."""
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        return None
    value = binary.get("sha256")
    return str(value) if value else None


def compute_composition(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    binary_ids: Sequence[int] = (),
    collection_ids: Sequence[int] = (),
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one binary's composition payload from the store, without storing it.

    The payload carries the headline counts (``total_functions``,
    ``matched_functions``, ``matched_percent``), the five name-source buckets,
    the five quality bands, the four hosted ``categories``, one row per other
    binary this binary matched to, and one row per function capped at
    :data:`MAX_ROWS`.  ``refined`` is false when the store holds no match edge
    for the binary, and the notes name the command that fills the table.
    ``matched_percent`` and every percent is None when the binary has no
    functions at all, since a zero against no functions is not a reading the
    source gave.

    *binary_ids* and *collection_ids* narrow the candidates through
    :func:`reportal.matching.resolve_scope`, the same vocabulary the match
    settings sheet validates, so a scoped composition reads exactly the edges a
    scoped ``reportal match`` would have written.  An id no row carries raises
    :class:`reportal.matching.InvalidSettingsError`, which every surface maps to
    its own 400.

    Raises :class:`NoCompositionError` for an unknown binary.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise NoCompositionError(f"no binary with id {binary_id}")

    scope = matching.resolve_scope(
        conn,
        matching.MatchSettings(binary_ids=tuple(binary_ids), collection_ids=tuple(collection_ids)),
        visible_to=visible_to,
    )
    functions = store.list_functions(conn, binary_id=binary_id)
    total = len(functions)
    best, self_only, has_edges = _best_matches(conn, binary_id=binary_id, scope=scope)
    rows = _function_rows(functions, best)
    matched = sum(1 for row in rows if row["matched_binary_id"] is not None)

    name_counts = dict.fromkeys(NAME_SOURCE_LABELS, 0)
    for function in functions:
        name_counts[name_source_label(function)] += 1
    band_counts = dict.fromkeys(QUALITY_BANDS, 0)
    for row in rows:
        band_counts[str(row["band"])] += 1

    composition = _composition_rows(rows, total)
    for entry in composition:
        entry["sha256"] = _binary_sha256(conn, int(entry["binary_id"]))
    categories = _category_rows(functions, rows, total)

    notes = [SCOPE_NOTE]
    scope_payload = {
        "binary_ids": sorted(binary_ids),
        "collection_ids": sorted(collection_ids),
        "binaries": len(scope),
    }
    if scope:
        notes.append(
            SCOPED_NOTE.format(
                f"{len(scope)} candidate binaries"
                f" ({len(binary_ids)} named binary id(s), {len(collection_ids)} collection(s))"
            )
        )
    if not has_edges:
        notes.append(NO_MATCHES_NOTE)
    elif self_only:
        notes.append(SELF_MATCH_NOTE.format(self_only))
    if total > MAX_ROWS:
        notes.append(f"showing {MAX_ROWS} of {total} function rows")

    return {
        "binary_id": binary_id,
        "binary_name": str(binary["name"]),
        "sha256": binary.get("sha256"),
        "total_functions": total,
        "matched_functions": matched,
        "matched_percent": _percent(matched, total),
        "refined": has_edges,
        "name_sources": _count_rows(NAME_SOURCE_LABELS, name_counts, total),
        "match_quality": _count_rows(QUALITY_BANDS, band_counts, total),
        "categories": categories,
        "category_notes": list(CATEGORY_NOTES),
        "scope": scope_payload,
        "composition": composition,
        "functions": rows[:MAX_ROWS],
        "notes": notes,
    }


def run_composition(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    binary_ids: Sequence[int] = (),
    collection_ids: Sequence[int] = (),
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute one binary's composition and store it as the ``composition`` scan.

    The scan hangs off the binary's newest analysis, created when it has none,
    and replaces any earlier composition.  *binary_ids* and *collection_ids*
    narrow the candidates exactly as they do for
    :func:`compute_composition`, and the stored payload records the scope it was
    built under, so a later reader can tell a scoped scan from a whole-register
    one.  Raises :class:`NoCompositionError` for an unknown binary and
    :class:`reportal.matching.InvalidSettingsError` for an unknown scope id.
    """
    payload = compute_composition(
        conn,
        binary_id=binary_id,
        binary_ids=binary_ids,
        collection_ids=collection_ids,
        visible_to=visible_to,
    )
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, store.SCAN_KIND_COMPOSITION, payload)
    return payload


def stored_composition(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """The stored ``composition`` scan of a binary, or None before the first run."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, store.SCAN_KIND_COMPOSITION)

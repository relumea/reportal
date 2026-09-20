"""Deterministic relationship ranking of the stored binaries around one target.

The portal already holds cheap identity signals for every binary: the engine
fingerprint's ``sha256``, ``imphash`` and ``rich_header_hash``, the canonical
import-name set (:func:`families.import_names`) and the capability set
(:func:`families.capability_names`).  :func:`find_related` turns those into a
ranked list of related binaries for one target without a model and without a
network call: every other binary with a resolvable file is scored by
:func:`relationship`, the strongest matched signal names its classification,
and the result is stored as the ``related`` scan.

A relationship is the strongest signal two bundles share: an identical
``sha256`` is ``identical``, an identical ``imphash`` ``same-imports``, an
identical Rich-header hash ``same-toolchain``, an import-name Jaccard ratio at
or above :data:`IMPORT_OVERLAP_THRESHOLD` ``similar-lifecycle``, a
capability-set Jaccard ratio at or above :data:`CAPABILITY_OVERLAP_THRESHOLD`
``similar-capabilities`` and, only when nothing stronger matched, the same
format and architecture with a size within :data:`SIZE_TOLERANCE_PERCENT` of
the larger file ``similar-size``.  Every matched signal is returned with its
confidence and detail, so a caller reads why a candidate was ranked rather than
a bare score; a candidate that matches nothing is ``unrelated`` and is left out
unless the caller asks for it.

The target's bundle comes from the stored fingerprint when one exists, else
from the engine; imports and strings come from the engine when it is available
and from the store otherwise.  Candidate bundles follow the same rule.  A
missing engine is not an error: the scan degrades to whatever the store already
holds and records a note.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from reportal import engines, families, store

# Classifications a relationship carries, strongest first.  The tuple is also
# the ranking order, so the closest binaries sort before the weaker matches.
CLASSIFICATION_IDENTICAL = "identical"
CLASSIFICATION_SAME_IMPORTS = "same-imports"
CLASSIFICATION_SAME_TOOLCHAIN = "same-toolchain"
CLASSIFICATION_SIMILAR_LIFECYCLE = "similar-lifecycle"
CLASSIFICATION_SIMILAR_CAPABILITIES = "similar-capabilities"
CLASSIFICATION_SIMILAR_SIZE = "similar-size"
CLASSIFICATION_UNRELATED = "unrelated"

RELATED_CLASSIFICATIONS = (
    CLASSIFICATION_IDENTICAL,
    CLASSIFICATION_SAME_IMPORTS,
    CLASSIFICATION_SAME_TOOLCHAIN,
    CLASSIFICATION_SIMILAR_LIFECYCLE,
    CLASSIFICATION_SIMILAR_CAPABILITIES,
    CLASSIFICATION_SIMILAR_SIZE,
    CLASSIFICATION_UNRELATED,
)
CLASSIFICATION_RANK = {name: index for index, name in enumerate(RELATED_CLASSIFICATIONS)}

# Confidence a classification carries.  A signal's confidence is fixed by the
# signal kind; a relationship's confidence is the strongest matched signal's.
# An unrelated pair matches nothing, so it carries no confidence at all.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_NONE = "none"

# Signal kinds.  `identical` compares the engine fingerprint's sha256,
# `same-imports` the imphash, `same-toolchain` the Rich-header hash,
# `import-overlap` the Jaccard ratio of the canonical import-name sets,
# `capability-overlap` the Jaccard ratio of the capability-name sets and
# `size-window` the format/arch and file size.
SIGNAL_IDENTICAL = "identical"
SIGNAL_SAME_IMPORTS = "same-imports"
SIGNAL_SAME_TOOLCHAIN = "same-toolchain"
SIGNAL_IMPORT_OVERLAP = "import-overlap"
SIGNAL_CAPABILITY_OVERLAP = "capability-overlap"
SIGNAL_SIZE_WINDOW = "size-window"

SIGNAL_CLASSIFICATIONS = {
    SIGNAL_IDENTICAL: CLASSIFICATION_IDENTICAL,
    SIGNAL_SAME_IMPORTS: CLASSIFICATION_SAME_IMPORTS,
    SIGNAL_SAME_TOOLCHAIN: CLASSIFICATION_SAME_TOOLCHAIN,
    SIGNAL_IMPORT_OVERLAP: CLASSIFICATION_SIMILAR_LIFECYCLE,
    SIGNAL_CAPABILITY_OVERLAP: CLASSIFICATION_SIMILAR_CAPABILITIES,
    SIGNAL_SIZE_WINDOW: CLASSIFICATION_SIMILAR_SIZE,
}

SIGNAL_CONFIDENCES = {
    SIGNAL_IDENTICAL: CONFIDENCE_HIGH,
    SIGNAL_SAME_IMPORTS: CONFIDENCE_HIGH,
    SIGNAL_SAME_TOOLCHAIN: CONFIDENCE_MEDIUM,
    SIGNAL_IMPORT_OVERLAP: CONFIDENCE_MEDIUM,
    SIGNAL_CAPABILITY_OVERLAP: CONFIDENCE_LOW,
    SIGNAL_SIZE_WINDOW: CONFIDENCE_LOW,
}

# Jaccard ratio of two import-name sets, and of two capability-name sets, at or
# above which the overlap counts as a signal.  Both ride in every result's
# notes.
IMPORT_OVERLAP_THRESHOLD = 0.8
CAPABILITY_OVERLAP_THRESHOLD = 0.8

# Relative size difference two same-format binaries may differ by and still be
# `similar-size`, as a percentage of the larger file size.
SIZE_TOLERANCE_PERCENT = 10.0

# Candidates a scan returns when the caller names no limit, and the largest
# limit the API accepts.  A store of thousands of binaries still returns a
# bounded table.
DEFAULT_LIMIT = 20
MAX_LIMIT = 200

# Decimals a similarity ratio is rounded to, so the payload does not carry
# float noise from the Jaccard division.
SIMILARITY_DECIMALS = 6

# Scope and degradation notes every result carries.  The thresholds are stated
# because a reader cannot interpret the signals without them.
SCOPE_NOTE = (
    "local relationship ranking over hashes, imports, capabilities and size;"
    f" import overlap threshold {IMPORT_OVERLAP_THRESHOLD};"
    f" capability overlap threshold {CAPABILITY_OVERLAP_THRESHOLD};"
    f" size tolerance {SIZE_TOLERANCE_PERCENT}%"
)
NO_ENGINE_NOTE = "no rebrew engine; ranking from stored fingerprints and scans only"


class RelatedIO(Protocol):
    """The engine surface a related scan reads; all three calls are standalone."""

    def available(self) -> bool: ...

    def fingerprint(self, binary: str | Path) -> dict[str, Any]: ...

    def imports(self, binary: str | Path) -> dict[str, Any]: ...

    def strings(self, binary: str | Path) -> dict[str, Any]: ...


def _normalized(value: Any) -> str | None:
    """Return *value* as a trimmed, lowercased non-empty string, or None."""
    if not isinstance(value, str):
        return None
    stripped = value.strip().lower()
    return stripped or None


def _size(value: Any) -> int | None:
    """Return *value* as a non-negative int, or None when it is not a number."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def _string_set(value: Any) -> set[str]:
    """Return the string members of *value* as a set, ignoring any other shape."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return set()
    return {item for item in value if isinstance(item, str)}


def _jaccard(left: set[str], right: set[str]) -> float:
    """Jaccard ratio of two sets; 0.0 when either side is empty."""
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _equal_hash(left: dict[str, Any], right: dict[str, Any], key: str) -> str | None:
    """The shared value at *key*, or None when either side lacks one or they differ."""
    first = _normalized(left.get(key))
    second = _normalized(right.get(key))
    if first is not None and first == second:
        return first
    return None


def _overlap(left: dict[str, Any], right: dict[str, Any], key: str) -> tuple[float, int, int]:
    """The Jaccard ratio of the sets at *key* plus the shared and union counts."""
    first = _string_set(left.get(key))
    second = _string_set(right.get(key))
    union = first | second
    return (_jaccard(first, second), len(first & second), len(union))


def _signal(kind: str, detail: str) -> dict[str, Any]:
    """One matched signal with its fixed confidence and a human-readable detail."""
    return {"kind": kind, "confidence": SIGNAL_CONFIDENCES[kind], "detail": detail}


def _size_window(target: dict[str, Any], other: dict[str, Any]) -> tuple[bool, float, str] | None:
    """The size-window signal, or None when format, arch or size rules it out.

    The first element is whether the pair is inside the window, the second is
    its size similarity in 0..1 (1.0 for an equal size) and the third is the
    detail a signal carries.
    """
    target_format = _normalized(target.get("format"))
    target_arch = _normalized(target.get("arch"))
    other_format = _normalized(other.get("format"))
    other_arch = _normalized(other.get("arch"))
    if target_format is None or target_arch is None:
        return None
    if target_format != other_format or target_arch != other_arch:
        return None
    target_size = _size(target.get("size"))
    other_size = _size(other.get("size"))
    if target_size is None or other_size is None:
        return None
    larger = max(target_size, other_size)
    difference = abs(target_size - other_size)
    inside = difference <= larger * SIZE_TOLERANCE_PERCENT / 100
    similarity = 1.0 if larger == 0 else 1.0 - difference / larger
    detail = (
        f"format {target_format}/{target_arch}, size {target_size} within"
        f" {SIZE_TOLERANCE_PERCENT}% of {other_size}"
    )
    return (inside, similarity, detail)


def relationship(target: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
    """Classify the relationship between two binary bundles.

    Both bundles carry ``sha256``, ``imphash``, ``rich_header_hash``,
    ``import_names``, ``capabilities``, ``format``, ``arch`` and ``size``.  The
    classification is the strongest matched signal (see
    :data:`RELATED_CLASSIFICATIONS`) and every matched signal is listed, so a
    caller sees all the evidence rather than only the winner.  ``similarity`` is
    the strongest ratio the matched signals carry; an unrelated pair reports
    :data:`CONFIDENCE_NONE`, no signals and 0.0.
    """
    signals: list[dict[str, Any]] = []
    similarity = 0.0

    digest = _equal_hash(target, other, "sha256")
    if digest is not None:
        signals.append(_signal(SIGNAL_IDENTICAL, digest))
        similarity = 1.0
    imphash = _equal_hash(target, other, "imphash")
    if imphash is not None:
        signals.append(_signal(SIGNAL_SAME_IMPORTS, imphash))
        similarity = 1.0
    rich = _equal_hash(target, other, "rich_header_hash")
    if rich is not None:
        signals.append(_signal(SIGNAL_SAME_TOOLCHAIN, rich))
        similarity = 1.0

    ratio, shared, union = _overlap(target, other, "import_names")
    if ratio >= IMPORT_OVERLAP_THRESHOLD:
        signals.append(
            _signal(SIGNAL_IMPORT_OVERLAP, f"import jaccard {ratio:.3f} ({shared}/{union} names)")
        )
        similarity = max(similarity, ratio)
    ratio, shared, union = _overlap(target, other, "capabilities")
    if ratio >= CAPABILITY_OVERLAP_THRESHOLD:
        signals.append(
            _signal(
                SIGNAL_CAPABILITY_OVERLAP,
                f"capability jaccard {ratio:.3f} ({shared}/{union} categories)",
            )
        )
        similarity = max(similarity, ratio)

    if not signals:
        window = _size_window(target, other)
        if window is not None and window[0]:
            signals.append(_signal(SIGNAL_SIZE_WINDOW, window[2]))
            similarity = window[1]

    if not signals:
        return {
            "classification": CLASSIFICATION_UNRELATED,
            "confidence": CONFIDENCE_NONE,
            "signals": [],
            "similarity": 0.0,
        }
    strongest = signals[0]
    return {
        "classification": SIGNAL_CLASSIFICATIONS[str(strongest["kind"])],
        "confidence": str(strongest["confidence"]),
        "signals": signals,
        "similarity": round(similarity, SIMILARITY_DECIMALS),
    }


def _stored_capabilities(conn: sqlite3.Connection, binary_id: int) -> list[str]:
    """The capability names a stored ``capabilities`` scan carries, sorted."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return []
    scan = store.get_scan(conn, analysis_id, store.SCAN_KIND_CAPABILITIES)
    entries = scan.get("capabilities") if isinstance(scan, dict) else None
    if not isinstance(entries, list):
        return []
    return sorted(
        {str(entry["name"]) for entry in entries if isinstance(entry, dict) and entry.get("name")}
    )


def _entries(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return the dict entries under *payload[key]*, ignoring any other shape."""
    raw = payload.get(key)
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _bundle(
    conn: sqlite3.Connection, binary: dict[str, Any], *, io: RelatedIO | None
) -> dict[str, Any]:
    """Derive one binary's relationship bundle from the store and the engine.

    The stored fingerprint wins when one exists, else the engine computes it;
    the engine supplies imports and strings when it is usable, and a stored
    ``capabilities`` scan stands in for them when it is not.  None of these
    calls is required: whatever the store already holds is used and anything
    missing stays empty.
    """
    binary_id = int(binary["id"])
    path = Path(str(binary["path"]))
    usable = io is not None and io.available() and path.is_file()

    fingerprint = store.get_fingerprint(conn, binary_id)
    if fingerprint is None and usable and io is not None:
        fingerprint = io.fingerprint(path)
    resolved = fingerprint if isinstance(fingerprint, dict) else {}

    import_names: list[str] = []
    capability_names = _stored_capabilities(conn, binary_id)
    if usable and io is not None:
        imports_payload = io.imports(path)
        if isinstance(imports_payload, dict):
            import_names = families.import_names(imports_payload)
            if not capability_names:
                strings_payload = io.strings(path)
                raw_strings = (
                    strings_payload.get("strings") if isinstance(strings_payload, dict) else None
                )
                capability_names = families.capability_names(
                    _entries(imports_payload, "imports"),
                    [entry for entry in raw_strings if isinstance(entry, dict)]
                    if isinstance(raw_strings, list)
                    else [],
                )

    size = _size(resolved.get("size"))
    if size is None:
        size = _size(binary.get("size"))
    return {
        "sha256": _normalized(resolved.get("sha256")) or _normalized(binary.get("sha256")),
        "imphash": _normalized(resolved.get("imphash")),
        "rich_header_hash": _normalized(resolved.get("rich_header_hash")),
        "import_names": import_names,
        "capabilities": capability_names,
        "format": _normalized(resolved.get("format")) or _normalized(binary.get("format")),
        "arch": _normalized(resolved.get("arch")) or _normalized(binary.get("arch")),
        "size": size,
    }


def _candidate_key(candidate: dict[str, Any]) -> tuple[int, float, str]:
    return (
        CLASSIFICATION_RANK[str(candidate["classification"])],
        -float(candidate["similarity"]),
        str(candidate["name"]).casefold(),
    )


def find_related(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: RelatedIO | None = None,
    limit: int = DEFAULT_LIMIT,
    include_unrelated: bool = False,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Rank every other stored binary against *binary_id* and store the result.

    Each other binary with a resolvable file is bundled (the engine when it is
    available, else the store) and scored by :func:`relationship`.  The rows
    sort by classification rank, then similarity, then name, and are capped at
    *limit*; a binary that matches nothing is dropped unless *include_unrelated*
    is set.  The payload is stored as the ``related`` scan, replacing any
    earlier one, and returned as ``{"binary_id", "candidates_considered",
    "related", "count", "notes"}``.  A binary without a file on disk is skipped
    with a note, and a missing engine degrades to the stored data with a note
    rather than failing.

    Raises :class:`KeyError` for an unknown target binary and :class:`ValueError`
    for a non-positive or oversized *limit*.  ``visible_to`` narrows the
    candidates to binaries the caller may see, like the other scoped reads.
    """
    from reportal import auth

    if limit <= 0:
        raise ValueError(f"limit must be positive, got {limit}")
    if limit > MAX_LIMIT:
        raise ValueError(f"limit must be at most {MAX_LIMIT}, got {limit}")

    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")

    resolved = engine if engine is not None else engines.get_engine()
    notes: list[str] = [SCOPE_NOTE]
    if resolved is None or not resolved.available():
        notes.append(NO_ENGINE_NOTE)

    visible: set[int] | None = None
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, params = scope
        visible = {
            int(row["id"])
            for row in conn.execute(f"SELECT b.id AS id FROM binaries b WHERE {clause}", params)
        }

    target = _bundle(conn, binary, io=resolved)
    considered = 0
    missing_paths = 0
    results: list[dict[str, Any]] = []
    for candidate in store.list_binaries(conn):
        candidate_id = int(candidate["id"])
        if candidate_id == binary_id:
            continue
        if visible is not None and candidate_id not in visible:
            continue
        if not Path(str(candidate["path"])).is_file():
            missing_paths += 1
            continue
        considered += 1
        scored = relationship(target, _bundle(conn, candidate, io=resolved))
        if scored["classification"] == CLASSIFICATION_UNRELATED and not include_unrelated:
            continue
        results.append(
            {
                "binary_id": candidate_id,
                "name": str(candidate["name"]),
                "classification": scored["classification"],
                "confidence": scored["confidence"],
                "signals": scored["signals"],
                "similarity": scored["similarity"],
            }
        )

    results.sort(key=_candidate_key)
    matched = len(results)
    related = results[:limit]
    if matched > limit:
        notes.append(f"showing {limit} of {matched} matching binaries")
    if missing_paths:
        notes.append(f"{missing_paths} binaries with no file on disk were skipped")

    payload = {
        "binary_id": binary_id,
        "candidates_considered": considered,
        "related": related,
        "count": len(related),
        "notes": notes,
    }
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(
        conn,
        analysis_id,
        store.SCAN_KIND_RELATED,
        payload,
        params={"limit": limit, "include_unrelated": include_unrelated},
    )
    return payload


def stored_related(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """The stored ``related`` scan of a binary, or None before the first run."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, store.SCAN_KIND_RELATED)

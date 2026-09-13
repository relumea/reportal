"""Local malware-family matching against a user-curated signature store.

reportal bundles no external threat-intelligence feed and cannot: a malicious
family feed is a hosted, continuously updated service, and this is an offline
single-user tool.  Detect is therefore local family matching.  The analyst
registers a family with a reference binary, its optional aliases and its
notes; reportal derives that binary's signature bundle once (the engine
fingerprint's ``sha256``, ``imphash`` and ``rich_header_hash``, a locally
computed import hash, the canonical import-name set and the capability set
from :func:`capabilities.classify`) and stores it with the family.  A later
binary is scored against every registered family without re-running the engine
for the reference.

Each signal carries its own confidence: an ``exact-binary`` (sha256),
``import-fingerprint`` (imphash) or ``import-set`` (import hash) hit is
``high``, a ``toolchain-fingerprint`` (Rich header) or ``import-overlap`` hit
``medium``, and a ``capability-overlap`` hit ``low``.  A family's confidence
is the strongest signal it matched and every matched signal is returned as
evidence, so a caller reads why a family was proposed rather than a bare
score.  The import and capability overlap thresholds are stated in the result
(the payload carries the reportal scope and both thresholds in its notes).

A finished detection is stored as the ``detect`` scan on the binary's
analysis, so the ``GET`` route serves it without resolving the engine.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from reportal import capabilities, engines, store
from reportal.engines import RebrewEngine

# Confidences a family match carries, strongest first.  A signal's confidence
# is fixed by the signal kind (see :data:`SIGNAL_CONFIDENCES`); a match's
# confidence is the strongest of its signals.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_ORDER = {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_LOW: 2}

# Signal kinds.  `exact-binary` compares the engine fingerprint's sha256,
# `import-fingerprint` the imphash, `toolchain-fingerprint` the Rich header
# hash, `import-set` the locally computed import hash, `import-overlap` the
# Jaccard ratio of the canonical import-name sets and `capability-overlap` the
# Jaccard ratio of the capability-name sets.
SIGNAL_EXACT_BINARY = "exact-binary"
SIGNAL_IMPORT_FINGERPRINT = "import-fingerprint"
SIGNAL_TOOLCHAIN_FINGERPRINT = "toolchain-fingerprint"
SIGNAL_IMPORT_SET = "import-set"
SIGNAL_IMPORT_OVERLAP = "import-overlap"
SIGNAL_CAPABILITY_OVERLAP = "capability-overlap"

SIGNAL_CONFIDENCES = {
    SIGNAL_EXACT_BINARY: CONFIDENCE_HIGH,
    SIGNAL_IMPORT_FINGERPRINT: CONFIDENCE_HIGH,
    SIGNAL_TOOLCHAIN_FINGERPRINT: CONFIDENCE_MEDIUM,
    SIGNAL_IMPORT_SET: CONFIDENCE_HIGH,
    SIGNAL_IMPORT_OVERLAP: CONFIDENCE_MEDIUM,
    SIGNAL_CAPABILITY_OVERLAP: CONFIDENCE_LOW,
}

# Jaccard ratio of two import-name sets, and of two capability-name sets, at or
# above which the overlap counts as a signal.  Both are stated in the detection
# payload's notes.
IMPORT_OVERLAP_THRESHOLD = 0.8
CAPABILITY_OVERLAP_THRESHOLD = 0.8

# Separator between the sorted canonical import names the import hash covers.
IMPORT_HASH_SEPARATOR = "\n"

# Fingerprint fields the signature bundle keeps.
FINGERPRINT_SHA256 = "sha256"
FINGERPRINT_IMPHASH = "imphash"
FINGERPRINT_RICH_HEADER_HASH = "rich_header_hash"

# Strings a bundle derivation inspects; the engine can return tens of thousands
# and the classifier regexes every one.
MAX_STRINGS_INSPECTED = capabilities.MAX_STRINGS_INSPECTED

# Scope reportal can honestly claim, and the thresholds a reader needs to
# interpret the signals.  Both ride in every detection result's notes.
SCOPE_NOTE = (
    "local family matching against a user-curated signature store;"
    " reportal bundles no external threat-intelligence feed"
)
THRESHOLD_NOTE = (
    f"import overlap threshold {IMPORT_OVERLAP_THRESHOLD};"
    f" capability overlap threshold {CAPABILITY_OVERLAP_THRESHOLD}"
)


class FamilyError(RuntimeError):
    """A family operation that cannot be completed."""


class InvalidFamilyNameError(FamilyError):
    """A family name that is blank."""


class DuplicateFamilyError(FamilyError):
    """A family with the same name (case-insensitively) already exists."""


def _fingerprint_hash(fingerprint: dict[str, Any], key: str) -> str | None:
    """Return ``fingerprint[key]`` as a lowercased non-empty string, or None."""
    value = fingerprint.get(key)
    if not isinstance(value, str):
        return None
    stripped = value.strip().lower()
    return stripped or None


def canonical_import_name(entry: dict[str, Any]) -> str | None:
    """Return one import entry as its canonical ``dll:name``, or None.

    Both halves are lowercased and trimmed, so the import set (and therefore
    the import hash and the overlap ratio) is independent of the engine's
    ordering and casing.
    """
    name = str(entry.get("name") or "").strip().lower()
    if not name:
        return None
    dll = str(entry.get("dll") or "").strip().lower()
    return f"{dll}:{name}"


def import_names(payload: dict[str, Any]) -> list[str]:
    """The sorted, distinct canonical import names under ``payload["imports"]``."""
    raw = payload.get("imports")
    if not isinstance(raw, list):
        return []
    names = {
        canonical
        for entry in raw
        if isinstance(entry, dict) and (canonical := canonical_import_name(entry))
    }
    return sorted(names)


def import_hash(names: Sequence[str]) -> str:
    """The sha256 of *names* sorted and joined, the locally computed import hash."""
    joined = IMPORT_HASH_SEPARATOR.join(sorted(names))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def capability_names(
    imports: Sequence[dict[str, Any]], strings: Sequence[dict[str, Any]]
) -> list[str]:
    """The sorted capability names :func:`capabilities.classify` finds."""
    found = capabilities.classify(imports, strings[:MAX_STRINGS_INSPECTED])
    return sorted(str(entry["name"]) for entry in found)


def derive_bundle(
    conn: sqlite3.Connection, *, binary_id: int, engine: RebrewEngine | None = None
) -> dict[str, Any]:
    """Derive the signature bundle of a stored binary.

    Runs the engine's fingerprint, imports and strings for the binary's file
    and returns ``sha256``, ``imphash``, ``rich_header_hash``, ``import_hash``,
    ``import_names`` and ``capabilities``.  Raises :class:`KeyError` for an
    unknown binary, :class:`FileNotFoundError` when its row has no file, and
    :class:`engines.EngineUnavailable` without an engine.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")
    path = Path(str(binary["path"]))
    if not path.is_file():
        raise FileNotFoundError(f"binary {binary_id} has no file at {path}")
    source = engine or engines.get_engine()
    fingerprint = source.fingerprint(path)
    imports_payload = source.imports(path)
    strings_payload = source.strings(path)
    names = import_names(imports_payload)
    raw_imports = imports_payload.get("imports")
    raw_strings = strings_payload.get("strings")
    import_entries = (
        [entry for entry in raw_imports if isinstance(entry, dict)]
        if isinstance(raw_imports, list)
        else []
    )
    string_entries = (
        [entry for entry in raw_strings if isinstance(entry, dict)]
        if isinstance(raw_strings, list)
        else []
    )
    return {
        FINGERPRINT_SHA256: _fingerprint_hash(fingerprint, FINGERPRINT_SHA256),
        FINGERPRINT_IMPHASH: _fingerprint_hash(fingerprint, FINGERPRINT_IMPHASH),
        FINGERPRINT_RICH_HEADER_HASH: _fingerprint_hash(fingerprint, FINGERPRINT_RICH_HEADER_HASH),
        "import_hash": import_hash(names),
        "import_names": names,
        "capabilities": capability_names(import_entries, string_entries),
    }


def _family(record: dict[str, Any]) -> dict[str, Any]:
    """Reshape a store family row into the public family object."""
    return {
        "family_id": record["id"],
        "name": record["name"],
        "aliases": record["aliases"],
        "notes": record["notes"],
        "reference_binary_id": record["reference_binary_id"],
        "created_at": record["created_at"],
        "signatures": record["signatures"],
    }


def register_family(
    conn: sqlite3.Connection,
    *,
    name: str,
    reference_binary_id: int,
    aliases: Sequence[str] = (),
    notes: str = "",
    engine: RebrewEngine | None = None,
) -> dict[str, Any]:
    """Register a family from a reference binary and store its derived bundle.

    The name must be non-empty and unused (case-insensitively) and the
    reference binary must exist with a file the engine can fingerprint; the
    bundle is derived once and stored, so detection never re-runs the engine
    for the reference.  Raises :class:`InvalidFamilyNameError`,
    :class:`DuplicateFamilyError`, :class:`KeyError` for an unknown binary and
    :class:`engines.EngineUnavailable` without an engine.
    """
    cleaned = name.strip()
    if not cleaned:
        raise InvalidFamilyNameError("family name must not be empty")
    if store.find_family_by_name(conn, cleaned) is not None:
        raise DuplicateFamilyError(f"a family named {cleaned!r} already exists")
    bundle = derive_bundle(conn, binary_id=reference_binary_id, engine=engine)
    alias_list = [alias.strip() for alias in aliases if alias.strip()]
    family_id = store.add_family(
        conn,
        name=cleaned,
        aliases=alias_list,
        notes=notes,
        reference_binary_id=reference_binary_id,
        signatures=bundle,
    )
    stored = store.get_family(conn, family_id)
    if stored is None:
        raise FamilyError(f"family {family_id} vanished after insert")
    return _family(stored)


def list_families(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every registered family with its signature bundle, case-insensitive name order."""
    return [_family(record) for record in store.list_families(conn)]


def get_family(conn: sqlite3.Connection, family_id: int) -> dict[str, Any] | None:
    """One family with its signature bundle, or None for an unknown id."""
    record = store.get_family(conn, family_id)
    return _family(record) if record is not None else None


def delete_family(conn: sqlite3.Connection, family_id: int) -> bool:
    """Delete a family; False when the id is unknown."""
    return store.delete_family(conn, family_id)


def _jaccard(left: set[str], right: set[str]) -> float:
    """Jaccard ratio of two sets; 0.0 when either side is empty."""
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _equal_hash(signature: dict[str, Any], target: dict[str, Any], key: str) -> str | None:
    """The shared hash at *key*, or None when either side lacks one or they differ."""
    left = signature.get(key)
    right = target.get(key)
    if isinstance(left, str) and left and isinstance(right, str) and right and left == right:
        return left
    return None


def _signal(kind: str, detail: str) -> dict[str, Any]:
    """One matched signal with its fixed confidence and a human-readable detail."""
    return {"kind": kind, "confidence": SIGNAL_CONFIDENCES[kind], "detail": detail}


def _overlap(signature: dict[str, Any], target: dict[str, Any], key: str) -> tuple[float, int, int]:
    """The Jaccard ratio of the sets at *key* plus the shared and union counts."""
    left = {value for value in signature.get(key, []) if isinstance(value, str)}
    right = {value for value in target.get(key, []) if isinstance(value, str)}
    union = left | right
    return (_jaccard(left, right), len(left & right), len(union))


def evaluate(
    signature: dict[str, Any], target: dict[str, Any]
) -> tuple[list[dict[str, Any]], float]:
    """Score a stored signature bundle against a target bundle.

    Returns the matched signals in the order the signal kinds are defined
    above, plus the strongest similarity they carry (1.0 for an exact identity,
    else the best Jaccard ratio).  No matched signal means the family does not
    match.
    """
    signals: list[dict[str, Any]] = []
    similarity = 0.0

    digest = _equal_hash(signature, target, FINGERPRINT_SHA256)
    if digest is not None:
        signals.append(_signal(SIGNAL_EXACT_BINARY, digest))
        similarity = 1.0
    imphash = _equal_hash(signature, target, FINGERPRINT_IMPHASH)
    if imphash is not None:
        signals.append(_signal(SIGNAL_IMPORT_FINGERPRINT, imphash))
        similarity = 1.0
    rich = _equal_hash(signature, target, FINGERPRINT_RICH_HEADER_HASH)
    if rich is not None:
        signals.append(_signal(SIGNAL_TOOLCHAIN_FINGERPRINT, rich))
        similarity = 1.0
    digest = _equal_hash(signature, target, "import_hash")
    if digest is not None:
        signals.append(_signal(SIGNAL_IMPORT_SET, digest))
        similarity = 1.0

    ratio, shared, union = _overlap(signature, target, "import_names")
    if ratio >= IMPORT_OVERLAP_THRESHOLD:
        signals.append(
            _signal(SIGNAL_IMPORT_OVERLAP, f"import jaccard {ratio:.3f} ({shared}/{union} names)")
        )
        similarity = max(similarity, ratio)
    ratio, shared, union = _overlap(signature, target, "capabilities")
    if ratio >= CAPABILITY_OVERLAP_THRESHOLD:
        signals.append(
            _signal(
                SIGNAL_CAPABILITY_OVERLAP,
                f"capability jaccard {ratio:.3f} ({shared}/{union} categories)",
            )
        )
        similarity = max(similarity, ratio)

    return signals, similarity


def _match_key(match: dict[str, Any]) -> tuple[int, float, str]:
    return (
        CONFIDENCE_ORDER[str(match["confidence"])],
        -float(match["similarity"]),
        str(match["name"]).casefold(),
    )


def detect_binary(
    conn: sqlite3.Connection, *, binary_id: int, engine: RebrewEngine | None = None
) -> dict[str, Any]:
    """Match a stored binary against every registered family and store the result.

    Derives the target's bundle (fingerprint, imports, strings and
    capabilities), scores it against each family's stored signatures, keeps
    every family that matched at least one signal, and stores the payload as
    the ``detect`` scan.  Matches sort by confidence, then similarity, then
    name; no match at all is a valid result.  Raises :class:`KeyError` for an
    unknown binary, :class:`FileNotFoundError` when its row has no file, and
    :class:`engines.EngineUnavailable` without an engine.
    """
    target = derive_bundle(conn, binary_id=binary_id, engine=engine)
    records = store.list_families(conn)
    matches: list[dict[str, Any]] = []
    for record in records:
        signals, similarity = evaluate(record["signatures"], target)
        if not signals:
            continue
        confidence = min(
            (str(signal["confidence"]) for signal in signals),
            key=lambda level: CONFIDENCE_ORDER[level],
        )
        matches.append(
            {
                "family_id": record["id"],
                "name": record["name"],
                "aliases": record["aliases"],
                "confidence": confidence,
                "signals": signals,
                "similarity": similarity,
            }
        )
    matches.sort(key=_match_key)
    payload = {
        "binary_id": binary_id,
        "families_checked": len(records),
        "matches": matches,
        "count": len(matches),
        "notes": [SCOPE_NOTE, THRESHOLD_NOTE],
    }
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, store.SCAN_KIND_DETECT, payload)
    return payload


def stored_detection(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """The stored ``detect`` scan of a binary, or None before the first run."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, store.SCAN_KIND_DETECT)

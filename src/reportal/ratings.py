"""Analyst feedback on a stored agent artifact.

The hosted portal's agent cards each carry a regenerate control and a thumbs
up/down on the result.  reportal stores the artifacts themselves as `scans`
rows (triage, threat, capabilities, remediation, filetype and the rest) and
serves them from stored-only reads, but nothing recorded what an analyst thought
of one.  This module is that one small table.

A rating is keyed by `(binary_id, kind)`, where *kind* is one of
:data:`reportal.store.SCAN_KINDS`: the artifact is the binary's stored scan of
that kind, so a rating is one row per artifact rather than one per re-run, and a
scan that is re-run keeps its verdict.  The AI decompilation artifact carries
its own rating inside its payload (``ai_decomp.rate``); it is a function-scoped
artifact and is deliberately not duplicated here.

The rating is a judgement, not a measurement: ``up`` or ``down`` with an
optional note, and setting it again replaces it.  Every write is journaled, so a
revert restores the previous verdict and clearing one restores the absence.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from reportal import journal, store

# The table the ratings live in (created on first use).
TABLE = "artifact_ratings"

# The two verdicts, and the empty one that clears a rating.
RATINGS: tuple[str, ...] = ("up", "down")

# Every stored scan kind, read from the store's own constants so a kind added
# there is rateable the day it lands and this module cannot fall behind.  Sorted
# for a stable order in an error detail and a tool schema.
SCAN_KINDS: tuple[str, ...] = tuple(
    sorted(
        value
        for name, value in vars(store).items()
        if name.startswith("SCAN_KIND_") and isinstance(value, str)
    )
)

# Bounds on the note a rating may carry.
MAX_NOTE_CHARS = 500

# The error codes the surfaces report, shared by the API, CLI and MCP.
ERROR_INVALID = "invalid rating"
ERROR_NO_ARTIFACT = "no-artifact"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS artifact_ratings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id  INTEGER NOT NULL REFERENCES binaries(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    rating     TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (binary_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_artifact_ratings_binary ON artifact_ratings(binary_id);
"""


class RatingError(Exception):
    """Base class for a rejected rating operation."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


class InvalidRatingError(RatingError, ValueError):
    """A verdict, kind or note is unusable; the API answers 400."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_INVALID, detail)


class UnknownArtifactError(RatingError, LookupError):
    """No stored scan of that kind; the API answers 404."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_NO_ARTIFACT, detail)


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the ratings table when the database predates it."""
    conn.executescript(_SCHEMA)


def normalize_rating(rating: Any) -> str:
    """Validate a verdict, raising :class:`InvalidRatingError`.

    ``None`` or an empty string is the explicit "no rating", which is how a
    caller clears one; anything else must be a known verdict.
    """
    if rating is None:
        return ""
    if not isinstance(rating, str):
        raise InvalidRatingError("rating must be a string")
    value = rating.strip().lower()
    if not value:
        return ""
    if value not in RATINGS:
        raise InvalidRatingError(f"rating must be one of {', '.join(RATINGS)}, or empty to clear")
    return value


def normalize_note(note: Any) -> str:
    """Validate an optional note, raising :class:`InvalidRatingError`."""
    if note is None:
        return ""
    if not isinstance(note, str):
        raise InvalidRatingError("note must be a string")
    trimmed = note.strip()
    if len(trimmed) > MAX_NOTE_CHARS:
        raise InvalidRatingError(f"note exceeds {MAX_NOTE_CHARS} characters")
    return trimmed


def normalize_kind(kind: Any) -> str:
    """Validate a scan kind against the stored vocabulary."""
    if not isinstance(kind, str) or not kind.strip():
        raise InvalidRatingError("kind must be a non-empty scan kind")
    value = kind.strip()
    if value not in SCAN_KINDS:
        raise InvalidRatingError(f"kind must be one of {', '.join(SCAN_KINDS)}")
    return value


def require_artifact(conn: sqlite3.Connection, binary_id: int, kind: str) -> int:
    """The analysis id whose stored scan of *kind* is being rated.

    Resolves against the binary's latest analysis only, matching the scan GET
    routes: a newer empty analysis must not leave a stale scan rateable while
    the live read answers 404.  Raises :class:`UnknownArtifactError` for an
    unknown binary or a binary whose latest analysis has no stored scan of that
    kind: there is nothing to have an opinion about.
    """
    if store.get_binary(conn, binary_id) is None:
        raise UnknownArtifactError(f"no binary with id {binary_id}")
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None or store.get_scan(conn, analysis_id, kind) is None:
        raise UnknownArtifactError(f"binary {binary_id} has no stored {kind} scan")
    return analysis_id


def _row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """One stored rating as the surfaces report it."""
    return {
        "binary_id": int(row["binary_id"]),
        "kind": str(row["kind"]),
        "rating": str(row["rating"]),
        "note": str(row["note"]),
        "actor": str(row["actor"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def get_rating(conn: sqlite3.Connection, *, binary_id: int, kind: str) -> dict[str, Any] | None:
    """One stored rating, or None when the artifact is unrated."""
    ensure_schema(conn)
    row = conn.execute(
        f"SELECT * FROM {TABLE} WHERE binary_id = ? AND kind = ?", (int(binary_id), str(kind))
    ).fetchone()
    return None if row is None else _row(row)


def list_ratings(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """Every rating of one binary, newest first."""
    ensure_schema(conn)
    rows = conn.execute(
        f"SELECT * FROM {TABLE} WHERE binary_id = ? ORDER BY id DESC", (int(binary_id),)
    ).fetchall()
    return [_row(row) for row in rows]


def set_rating(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    kind: Any,
    rating: Any,
    note: Any = None,
    actor: str = "",
) -> dict[str, Any]:
    """Set or clear one artifact's rating, replacing any verdict already there.

    An empty verdict deletes the row, which is how a caller takes a rating back;
    the returned payload says whether a row is stored either way.
    """
    ensure_schema(conn)
    resolved_kind = normalize_kind(kind)
    resolved_rating = normalize_rating(rating)
    resolved_note = normalize_note(note)
    require_artifact(conn, int(binary_id), resolved_kind)
    if not resolved_rating:
        conn.execute(
            f"DELETE FROM {TABLE} WHERE binary_id = ? AND kind = ?",
            (int(binary_id), resolved_kind),
        )
        conn.commit()
        return {"binary_id": int(binary_id), "kind": resolved_kind, "rating": "", "note": ""}
    timestamp = store.now()
    conn.execute(
        f"INSERT INTO {TABLE} (binary_id, kind, rating, note, actor, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(binary_id, kind) DO UPDATE SET rating = excluded.rating,"
        " note = excluded.note, actor = excluded.actor, updated_at = excluded.updated_at",
        (
            int(binary_id),
            resolved_kind,
            resolved_rating,
            resolved_note,
            str(actor or ""),
            timestamp,
            timestamp,
        ),
    )
    conn.commit()
    stored = get_rating(conn, binary_id=int(binary_id), kind=resolved_kind)
    return stored if stored is not None else {}


def journaled_set(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    binary_id: int,
    kind: Any,
    rating: Any,
    note: Any = None,
    actor: str = "",
    description: str | None = None,
) -> dict[str, Any]:
    """Set or clear one rating inside the caller's journaled action.

    The row the write replaces is snapshotted first and the row it creates is
    journaled for deletion after, so a revert restores the previous verdict
    whether the artifact was rated or not.
    """
    resolved_kind = normalize_kind(kind)
    before = journal.snapshot_rows(
        conn,
        table=TABLE,
        where="binary_id = ? AND kind = ?",
        params=(int(binary_id), resolved_kind),
    )
    if before:
        journal.journaled_rows(
            conn,
            log,
            table=TABLE,
            where="binary_id = ? AND kind = ?",
            params=(int(binary_id), resolved_kind),
            description=description or f"replaced the {resolved_kind} rating",
        )
    result = set_rating(
        conn, binary_id=binary_id, kind=resolved_kind, rating=rating, note=note, actor=actor
    )
    if not before and result.get("rating"):
        journal.journaled_create(
            log,
            table=TABLE,
            key={"binary_id": int(binary_id), "kind": resolved_kind},
            description=description or f"rated the {resolved_kind} artifact",
        )
    return result


def describe(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The ratings of a binary beside every artifact kind it stores.

    Every stored scan kind appears, rated or not, so a reader can tell an
    unrated artifact from one that was never produced.
    """
    ratings = {row["kind"]: row for row in list_ratings(conn, binary_id)}
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    artifacts: list[dict[str, Any]] = []
    for kind in SCAN_KINDS:
        stored = store.get_scan(conn, analysis_id, kind) if analysis_id is not None else None
        if stored is None and kind not in ratings:
            continue
        artifacts.append({"kind": kind, "stored": stored is not None, "rating": ratings.get(kind)})
    return {
        "binary_id": int(binary_id),
        "artifacts": artifacts,
        "count": len(artifacts),
        "rated": sum(1 for entry in artifacts if entry["rating"]),
        "kinds": list(SCAN_KINDS),
    }


def kinds() -> tuple[str, ...]:
    """The rateable artifact kinds: every scan kind the store declares."""
    return SCAN_KINDS

"""The persisted LSH candidate index over function fingerprints.

Each indexed function's packed MinHash fingerprint
(:func:`reportal.similarity.fingerprint`) is cut into :data:`LSH_BANDS` bands of
:data:`LSH_ROWS` consecutive values, and each band's key is stored in
``lsh_buckets``.  ``lsh_fingerprints`` records the SHA-256 of the listing a row
was built from, so a changed listing is re-indexed instead of served.

The index is exact, not probabilistic, for a ``min_similarity`` above
:data:`LSH_PAIRWISE_MAX_SIMILARITY` (80.0).  The
bands partition the ``NUM_PERMUTATIONS`` positions, so a pair whose
fingerprints disagree at ``m`` positions spoils at most ``m`` bands and agrees
fully on at least ``LSH_BANDS - m`` of them.  A pair the Jaccard floor of
``min_similarity`` admits (:func:`reportal.similarity.jaccard_floor`) disagrees
at no more than ``NUM_PERMUTATIONS * (1 - floor)`` positions, so it shares at
least :func:`required_bands` buckets.  Asking for that many shared buckets
therefore drops only pairs the prefilter would have skipped, and the recorded
rows are the pairwise path's.  While ``required_bands`` is below one the bound
proves nothing and callers stay on the pairwise path.

The index is a derived cache: ``store`` drops a function's row whenever its
cached listing is replaced or cleared, :func:`index_listings` fills rows during a
match run, :func:`sync` indexes cached listings that have no row, and
:func:`rebuild` starts over from ``disasm_cache``.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from reportal import similarity, store

# Band count.  With LSH_ROWS values per band the bands cover every permutation,
# which the exactness argument in the module docstring needs.
LSH_BANDS = 64
LSH_ROWS = similarity.NUM_PERMUTATIONS // LSH_BANDS

# A pair agreeing on LSH_MIN_AGREEING = NUM_PERMUTATIONS - b + 1 = 65 positions
# disagrees on at most b - 1 = 63, so at least one band stays whole and the
# pair shares its bucket.
LSH_MIN_AGREEING = similarity.NUM_PERMUTATIONS - LSH_BANDS + 1

# The highest min_similarity still answered pairwise.  Agreement is counted in
# whole positions, so every Jaccard floor above (LSH_MIN_AGREEING - 1) / 128 =
# 0.5 already demands LSH_MIN_AGREEING positions; inverting jaccard_floor, that
# floor is (1 - w) * 100 + w * 100 * 0.5 = 60 + 40 * 0.5 = 80.0 for w = 0.4.
# The index serves every min_similarity strictly above it.
LSH_PAIRWISE_MAX_SIMILARITY = (
    1.0 - similarity.JACCARD_WEIGHT
) * similarity.SCORE_SCALE + similarity.JACCARD_WEIGHT * similarity.SCORE_SCALE * (
    LSH_MIN_AGREEING - 1
) / similarity.NUM_PERMUTATIONS

# Listings indexed per transaction by `rebuild` and `sync`, so a large cache is
# streamed rather than held in memory at once.
INDEX_BATCH = 500

# Ids per `IN (...)` lookup, under SQLite's default bound-parameter limit.
LOOKUP_CHUNK = 900

# A cached listing is served only while its recorded extent and project
# directory match the live function (`store.get_disasm`); the index reads the
# same set so it never indexes a listing a read would drop.
_VALID_LISTINGS = (
    "SELECT d.function_id AS function_id, d.text AS text"
    " FROM disasm_cache d"
    " JOIN functions f ON f.id = d.function_id"
    " JOIN analyses a ON a.id = f.analysis_id"
    " LEFT JOIN rebrew_contexts r ON r.binary_id = a.binary_id"
    " WHERE d.extent_size = f.size AND d.project_dir = COALESCE(r.project_dir, '')"
)
_UNINDEXED = (
    " AND NOT EXISTS (SELECT 1 FROM lsh_fingerprints l WHERE l.function_id = d.function_id)"
)


def required_bands(min_similarity: float) -> int:
    """How many buckets a pair reaching *min_similarity* shares at least.

    Zero or less means the bound proves nothing at this threshold, so the
    index cannot generate candidates for it.  The agreeing-position count is
    compared as ``count / NUM_PERMUTATIONS >= floor``, the division
    :func:`reportal.similarity.jaccard` makes, so a boundary pair is classified
    the same way on both paths.
    """
    floor = similarity.jaccard_floor(min_similarity)
    permutations = similarity.NUM_PERMUTATIONS
    agreeing = next(
        (count for count in range(permutations + 1) if count / permutations >= floor),
        permutations + 1,
    )
    return LSH_BANDS - (permutations - agreeing)


def uses_index(min_similarity: float) -> bool:
    """Whether candidates for *min_similarity* come from the index (exactly)."""
    return required_bands(min_similarity) >= 1


def listing_digest(text: str) -> str:
    """The SHA-256 a fingerprint row records for the listing it was built from."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _chunks(values: Sequence[int]) -> Iterator[Sequence[int]]:
    for start in range(0, len(values), LOOKUP_CHUNK):
        yield values[start : start + LOOKUP_CHUNK]


def _indexed_digests(conn: sqlite3.Connection, function_ids: Sequence[int]) -> dict[int, str]:
    digests: dict[int, str] = {}
    for chunk in _chunks(function_ids):
        placeholders = ", ".join("?" for _ in chunk)
        for row in conn.execute(
            "SELECT function_id, listing_sha256 FROM lsh_fingerprints"
            f" WHERE function_id IN ({placeholders})",
            tuple(chunk),
        ):
            digests[int(row["function_id"])] = str(row["listing_sha256"])
    return digests


def index_listings(conn: sqlite3.Connection, texts: Mapping[int, str | None]) -> int:
    """Index each function's listing whose row is missing or built from other text.

    An empty or missing listing is skipped: it has no fingerprint, and the
    match loop never scores it.  Returns how many functions were (re)indexed.
    Raises :class:`reportal.similarity.SimilarityUnavailable` without the extra.
    """
    listings = {function_id: text for function_id, text in texts.items() if text}
    if not listings:
        return 0
    known = _indexed_digests(conn, sorted(listings))
    # Fingerprints are computed before the first write, so the write lock is
    # held for the inserts alone, not for the tokenizing.
    pending: list[tuple[int, str, list[str]]] = []
    for function_id, text in listings.items():
        digest = listing_digest(text)
        if known.get(function_id) != digest:
            keys = similarity.band_keys(similarity.fingerprint(text), LSH_BANDS, LSH_ROWS)
            pending.append((function_id, digest, keys))
    if not pending:
        return 0
    stamp = store.now()
    for function_id, digest, keys in pending:
        conn.execute("DELETE FROM lsh_fingerprints WHERE function_id = ?", (function_id,))
        conn.execute(
            "INSERT INTO lsh_fingerprints (function_id, listing_sha256, created_at)"
            " VALUES (?, ?, ?)",
            (function_id, digest, stamp),
        )
        conn.executemany(
            "INSERT INTO lsh_buckets (function_id, band, bucket) VALUES (?, ?, ?)",
            [(function_id, band, key) for band, key in enumerate(keys)],
        )
    conn.commit()
    return len(pending)


def near(conn: sqlite3.Connection, text: str, min_bands: int) -> dict[int, int]:
    """Indexed functions sharing at least *min_bands* buckets with *text*'s fingerprint.

    Maps each function id to its shared-bucket count.  The probe listing need
    not be stored: its band keys are computed here and joined against
    ``idx_lsh_buckets_band_bucket``.
    """
    keys = similarity.band_keys(similarity.fingerprint(text), LSH_BANDS, LSH_ROWS)
    probe = ", ".join("(?, ?)" for _ in keys)
    params: list[Any] = []
    for band, key in enumerate(keys):
        params.extend((band, key))
    params.append(max(1, min_bands))
    cursor = conn.execute(
        f"WITH probe(band, bucket) AS (VALUES {probe})"
        " SELECT l.function_id AS function_id, COUNT(*) AS shared"
        " FROM probe p JOIN lsh_buckets l ON l.band = p.band AND l.bucket = p.bucket"
        " GROUP BY l.function_id HAVING COUNT(*) >= ?",
        params,
    )
    return {int(row["function_id"]): int(row["shared"]) for row in cursor}


def sync(conn: sqlite3.Connection) -> int:
    """Index every valid cached listing that has no index row yet.

    ``store`` drops a row whenever its listing changes, so a missing row is the
    only staleness a cached listing can have.  Listings are read and indexed
    :data:`INDEX_BATCH` at a time.  Returns how many were indexed.
    """
    missing = [
        int(row["function_id"])
        for row in conn.execute(_VALID_LISTINGS + _UNINDEXED + " ORDER BY d.function_id").fetchall()
    ]
    written = 0
    for start in range(0, len(missing), INDEX_BATCH):
        chunk = missing[start : start + INDEX_BATCH]
        placeholders = ", ".join("?" for _ in chunk)
        rows = conn.execute(
            _VALID_LISTINGS + f" AND d.function_id IN ({placeholders})", tuple(chunk)
        ).fetchall()
        written += index_listings(conn, {int(row["function_id"]): str(row["text"]) for row in rows})
    return written


def rebuild(conn: sqlite3.Connection) -> dict[str, Any]:
    """Drop the whole index and rebuild it from every valid cached listing.

    Returns :func:`status` after the rebuild, plus ``indexed``, the number of
    listings written.  Raises
    :class:`reportal.similarity.SimilarityUnavailable` without the extra.
    """
    if not similarity.available():
        raise similarity.SimilarityUnavailable(
            "the match index requires the optional 'similarity' extra (uv sync --extra similarity)"
        )
    conn.execute("DELETE FROM lsh_fingerprints")
    conn.commit()
    indexed = sync(conn)
    return {**status(conn), "indexed": indexed}


def status(conn: sqlite3.Connection) -> dict[str, Any]:
    """The index's counts and parameters; stored-only, it indexes nothing.

    ``unindexed`` counts valid cached listings with no index row, which the
    next :func:`sync` or :func:`rebuild` would index.
    """
    functions = int(conn.execute("SELECT COUNT(*) FROM lsh_fingerprints").fetchone()[0])
    buckets = int(conn.execute("SELECT COUNT(*) FROM lsh_buckets").fetchone()[0])
    listings = int(conn.execute(f"SELECT COUNT(*) FROM ({_VALID_LISTINGS})").fetchone()[0])
    unindexed = int(
        conn.execute(f"SELECT COUNT(*) FROM ({_VALID_LISTINGS}{_UNINDEXED})").fetchone()[0]
    )
    return {
        "functions": functions,
        "buckets": buckets,
        "cached_listings": listings,
        "unindexed": unindexed,
        "bands": LSH_BANDS,
        "rows_per_band": LSH_ROWS,
        "pairwise_max_similarity": LSH_PAIRWISE_MAX_SIMILARITY,
    }

"""Shared UTC clock for reportal writers and readers.

Timestamps that land in SQLite, journals and auth rows all go through here so
one process clock (and one test patch) covers every stored stamp.  Keeping the
helpers out of :mod:`reportal.store` lets auth, analysis_log and journal stamp
rows without importing the store package that depends on them for schema and
scope helpers.
"""

from __future__ import annotations

from datetime import UTC, datetime


def now() -> str:
    """Return the current UTC time as an ISO 8601 string (second resolution)."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def as_utc(value: str) -> datetime:
    """Parse an ISO stamp as an aware UTC datetime.

    Naive values are treated as UTC.  Callers that compare or store instants
    (invite expiry, feed ``since``, STIX timestamps) go through here so a ``Z``
    suffix or a non-UTC offset cannot shift a lexicographic or calendar read.
    Raises :class:`ValueError` when *value* is not ISO 8601.
    """
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def as_utc_iso(value: str) -> str:
    """Normalize *value* to UTC ``+00:00`` form (second resolution)."""
    return as_utc(value).isoformat(timespec="seconds")

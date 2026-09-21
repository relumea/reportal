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


def now_utc() -> datetime:
    """Return the current UTC time as an aware datetime, for calendar reads."""
    return datetime.now(UTC)


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


def relative_age(created_at: object) -> str:
    """A short relative reading of one stored timestamp.

    Blank when the stamp does not parse; the raw stamp still answers.
    """
    if not isinstance(created_at, str) or not created_at:
        return ""
    try:
        delta = now_utc() - as_utc(created_at)
    except ValueError:
        return ""
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return ""
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    if days < 30:
        return f"{days}d ago"
    months = days // 30
    if months < 12:
        return f"{months}mo ago"
    return f"{days // 365}y ago"

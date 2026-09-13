"""The notification feed, derived rather than stored.

The hosted portal carries a notification centre: a finished run, a failed
analysis and a reverted change each raise one item, and dismissing it is the
reader's business.  reportal already writes both sources such a feed needs, so
this module reads them instead of adding a table and a second writer that could
drift from them:

- the action journal (:mod:`reportal.journal`), one item per action, which is
  what tells a reader a write happened and whether it is still revertible; and
- the analysis log (:mod:`reportal.analysis_log`), one item per entry, whose
  severity is what makes a failure stand out.

:func:`feed` normalizes both into one item shape, newest first, bounded, with
the true total beside the page.  Nothing here writes, and nothing here polls:
the caller passes ``since`` to ask for what it has not seen, and dismissal
lives in the client, which is where the hosted portal keeps it too.  An item's
``id`` is stable for a given source row (or action), so a client can remember
what it dismissed without a server round trip.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any

from reportal import analysis_log, journal

# The two sources an item can come from, in the order :func:`feed` reads them.
SOURCE_JOURNAL = "action"
SOURCE_LOG = "log"
SOURCES: tuple[str, ...] = (SOURCE_JOURNAL, SOURCE_LOG)

# Items :func:`feed` returns when the caller names no bound, and the largest it
# accepts.  A feed is read as a page; ``total`` is the whole match.
DEFAULT_FEED_LIMIT = 50
MAX_FEED_LIMIT = 500

# Severity an action item carries: a journaled write is informational, whatever
# it wrote.  A log item carries its own severity from the closed set.
ACTION_SEVERITY = analysis_log.SEVERITY_INFO


def _item_from_action(row: dict[str, Any]) -> dict[str, Any]:
    """One feed item for a journaled action, from its newest entry."""
    return {
        "id": f"{SOURCE_JOURNAL}:{row['action']}",
        "seq": int(row["id"]),
        "kind": SOURCE_JOURNAL,
        "severity": ACTION_SEVERITY,
        "message": str(row["description"]),
        "at": str(row["created_at"]),
        "action": str(row["action"]),
        "status": str(row["status"]),
        "entries": int(row["entries"]),
        "revertible": int(row["active"]) > 0,
    }


def _item_from_log(row: dict[str, Any]) -> dict[str, Any]:
    """One feed item for an analysis-log entry, with its binary for linking."""
    return {
        "id": f"{SOURCE_LOG}:{row['id']}",
        "seq": int(row["id"]),
        "kind": SOURCE_LOG,
        "severity": str(row["severity"]),
        "message": str(row["message"]),
        "at": str(row["created_at"]),
        "analysis_id": int(row["analysis_id"]),
        "binary_id": int(row["binary_id"]) if row.get("binary_id") is not None else None,
        "binary_name": row.get("binary_name"),
    }


def parse_since(value: str) -> str:
    """Validate an ISO timestamp a caller wants the feed since.

    Returns it unchanged, which is the text form the rows are compared in, so a
    caller can pass back what a previous response carried.  Anything another
    format raises :class:`ValueError`, which the API answers as a 400.
    """
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"since must be an ISO timestamp: {value!r}") from exc
    return value


def latest(conn: sqlite3.Connection) -> str | None:
    """The time of the newest item either source holds, or None when empty.

    A client that polls passes this back as ``since``, which is one query per
    source and no page of items to read.
    """
    action = journal.list_actions(conn, limit=1)
    logs = analysis_log.list_recent(conn, limit=1)
    times = [str(row["created_at"]) for row in (*action, *logs)]
    return max(times) if times else None


def feed(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    limit: int = DEFAULT_FEED_LIMIT,
    sources: tuple[str, ...] = SOURCES,
) -> dict[str, Any]:
    """The notification feed, newest first, bounded, with its true total.

    *since* is an ISO timestamp (see :func:`parse_since`) and is inclusive, so
    an item written in the same second as the caller's watermark is returned
    again rather than lost; the caller de-duplicates by each item's ``id``.
    *limit* bounds the page (a global top-k is always inside the per-source
    top-k, so reading *limit* from each source is enough) and *sources* selects
    which of :data:`SOURCES` to read; ``total`` counts every matching item, not
    the page.  An unknown source or an out-of-range limit raises ``ValueError``.
    """
    unknown = [name for name in sources if name not in SOURCES]
    if unknown:
        raise ValueError(f"unknown notification source: {unknown[0]}")
    if limit < 1 or limit > MAX_FEED_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_FEED_LIMIT}")
    items: list[dict[str, Any]] = []
    total = 0
    if SOURCE_JOURNAL in sources:
        items.extend(
            _item_from_action(row) for row in journal.list_actions(conn, since=since, limit=limit)
        )
        total += journal.count_actions(conn, since=since)
    if SOURCE_LOG in sources:
        items.extend(
            _item_from_log(row) for row in analysis_log.list_recent(conn, since=since, limit=limit)
        )
        total += analysis_log.count_recent(conn, since=since)
    # Newest first.  Timestamps have second resolution, so the source row's own
    # id breaks a tie and keeps two items written in the same second in a
    # stable order between reads.
    items.sort(key=lambda item: (str(item["at"]), int(item["seq"])), reverse=True)
    page = items[:limit]
    return {
        "notifications": page,
        "count": len(page),
        "total": total,
        "since": since,
        "sources": list(sources),
    }

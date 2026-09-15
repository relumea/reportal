"""The activity feed, derived rather than stored.

``GET /v2/users/activity`` is the hosted portal's answer to "what has been done
here, and by whom".  Locally the answer is derived, the same way
:mod:`reportal.notifications` derives the notification feed: one item per
journaled action (the actor that made it, its newest description, when, and
whether it is still awaiting a revert) plus one item per analysis-log entry,
which is what reportal records about work done.  Nothing is written for the
feed, so reverting an action or pruning the journal is reflected at once rather
than leaving a stale copy behind.

The actor on a journal entry is the authenticated user the server recorded the
request for (`server.authenticate` + :func:`reportal.journal.acting_as`), the
literal ``local`` while token auth is off, and empty for a write no request
made (a CLI invocation or an MCP tool call).  :func:`actors` reports the names
that actually appear, so a client can offer a filter over what exists rather
than over what the user table happens to hold.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from reportal import analysis_log, journal, notifications

# Rows one feed returns when the caller names no limit, and the hard cap.
DEFAULT_ACTIVITY_LIMIT = 50
MAX_ACTIVITY_LIMIT = 500

# The item kinds the feed merges.
SOURCE_ACTION = "action"
SOURCE_LOG = "log"
SOURCES: tuple[str, ...] = (SOURCE_ACTION, SOURCE_LOG)


def _item_from_action(row: dict[str, Any]) -> dict[str, Any]:
    """One journaled action as a feed item."""
    return {
        "id": f"action:{row['action']}",
        "kind": SOURCE_ACTION,
        "actor": str(row.get("actor") or ""),
        "at": str(row["created_at"]),
        "action": str(row["action"]),
        "description": str(row["description"]),
        "status": str(row["status"]),
        "entries": int(row.get("entries") or 0),
    }


def _item_from_log(row: dict[str, Any]) -> dict[str, Any]:
    """One analysis-log entry as a feed item."""
    return {
        "id": f"log:{row['id']}",
        "kind": SOURCE_LOG,
        "actor": "",
        "at": str(row["created_at"]),
        "action": "",
        "description": f"analysis {row['analysis_id']}: {row['message']}",
        "status": str(row["severity"]),
        "entries": 1,
        "severity": str(row["severity"]),
    }


def feed(
    conn: sqlite3.Connection,
    *,
    actor: str | None = None,
    since: str | None = None,
    limit: int = DEFAULT_ACTIVITY_LIMIT,
    sources: tuple[str, ...] = SOURCES,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The merged activity feed, newest first, bounded, with the true total.

    *actor* narrows the feed to one name (the empty string means "the writes no
    request made").  *since* is an inclusive ISO timestamp, compared as text the
    way the rows are written.  An unknown source name raises ``ValueError``,
    which the callers map to their own error vocabulary.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    unknown = [name for name in sources if name not in SOURCES]
    if unknown:
        raise ValueError(f"unknown source: {unknown[0]}")
    bounded = min(limit, MAX_ACTIVITY_LIMIT)
    items: list[dict[str, Any]] = []
    total = 0
    if SOURCE_ACTION in sources:
        actions = journal.list_actions(conn, since=since, actor=actor, limit=journal.MAX_LIST_LIMIT)
        total += len(actions)
        items.extend(_item_from_action(row) for row in actions)
    if SOURCE_LOG in sources and actor is None:
        # An analysis-log entry carries no actor: the log records what the
        # engine or the analyst did, and only the journal knows who asked.
        entries = analysis_log.list_recent(
            conn, limit=analysis_log.MAX_LOG_LIMIT, since=since, visible_to=visible_to
        )
        items.extend(_item_from_log(row) for row in entries)
    items.sort(key=lambda item: (item["at"], item["id"]), reverse=True)
    return {
        "items": items[:bounded],
        "count": min(len(items), bounded),
        "total": len(items),
        "since": since,
        "actor": actor,
        "sources": list(sources),
        "latest": notifications.latest(conn),
    }


def actors(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every actor that appears in the journal, with how many actions it made.

    The empty name is reported as an empty string rather than hidden: "writes no
    request made" is a real group (a CLI invocation, an MCP tool call).
    """
    rows = conn.execute(
        f"SELECT actor, COUNT(DISTINCT action) AS actions, MAX(created_at) AS at"
        f" FROM {journal.TABLE} GROUP BY actor ORDER BY actor"
    ).fetchall()
    return [
        {
            "actor": str(row["actor"]),
            "actions": int(row["actions"]),
            "at": str(row["at"] or ""),
        }
        for row in rows
    ]

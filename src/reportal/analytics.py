"""Time series over the rows reportal already stores.

The hosted dashboard charts three things over the last 30 days: binaries
processed, software types detected and agents triggered, plus a credit count.
Billing has no local meaning, so the local analogue of the credit count is the
number of journaled actions in the period, and the three series are counted from
`analyses.created_at`, the software type each created analysis's binary derives
through :func:`reportal.threat.classify_binary`, and `auto_runs.created_at`.

Nothing here runs an engine or a model, and nothing is stored: every series is a
read over rows the workspace already holds, so the dashboard cannot drift from
the lists it summarizes.  A day with no activity is present with a zero rather
than missing, because a chart with holes reads as missing data.

The software-type series derives each analysis's type at read time, so it is
bounded by :data:`MAX_SERIES_ANALYSES` and a derivation is computed once per
binary; the payload's ``notes`` says when the bound bit.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from typing import Any

from reportal import journal, threat

# The window a caller gets without asking, its bound, and how many analyses the
# software-type derivation examines before it says it stopped.
DEFAULT_SERIES_DAYS = 30
MAX_SERIES_DAYS = 365
MAX_SERIES_ANALYSES = 2000

# The three counted series, in the order the dashboard renders them.
SERIES_KEYS: tuple[str, ...] = ("analyses", "auto_runs", "actions")


class SeriesError(ValueError):
    """A window outside the bounds this module accepts; the API answers 400."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


def normalize_days(days: int) -> int:
    """Validate a window length; raises :class:`SeriesError` outside the bounds."""
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_SERIES_DAYS:
        raise SeriesError(f"days must be between 1 and {MAX_SERIES_DAYS}")
    return days


def _day(value: str) -> str:
    """The ``YYYY-MM-DD`` part of a stored timestamp."""
    return str(value)[:10]


def window(days: int, *, today: date | None = None) -> list[str]:
    """The inclusive list of dates a series covers, oldest first."""
    end = today if today is not None else datetime.now(UTC).date()
    return [(end - timedelta(days=offset)).isoformat() for offset in range(days - 1, -1, -1)]


def _counts(conn: sqlite3.Connection, sql: str, *, since: str) -> dict[str, int]:
    """Rows per day for one ``substr(created_at, 1, 10)`` query.

    A table the schema has not created yet (an old database, or one where no
    action was ever journaled) counts as empty rather than failing the whole
    dashboard.
    """
    try:
        rows = conn.execute(sql, (since,)).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {_day(str(row["day"])): int(row["n"]) for row in rows}


def _scoped_daily_counts(
    conn: sqlite3.Connection,
    *,
    table: str,
    alias: str,
    binary_id_column: str,
    since: str,
    visible_to: Mapping[str, Any] | None,
) -> dict[str, int]:
    """Per-day row counts of *table* since *since*, on binaries the caller may see."""
    from reportal import auth

    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is None:
        return _counts(
            conn,
            f"SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS n FROM {table}"
            " WHERE created_at >= ? GROUP BY day",
            since=since,
        )
    clause, params = scope
    try:
        rows = conn.execute(
            f"SELECT substr({alias}.created_at, 1, 10) AS day, COUNT(*) AS n"
            f" FROM {table} {alias} JOIN binaries b ON b.id = {alias}.{binary_id_column}"
            f" WHERE {alias}.created_at >= ? AND {clause} GROUP BY day",
            [since, *params],
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {_day(str(row["day"])): int(row["n"]) for row in rows}


def _analyses(
    conn: sqlite3.Connection, since: str, visible_to: Mapping[str, Any] | None = None
) -> dict[str, int]:
    """Analyses created per day since *since*, on binaries the caller may see."""
    return _scoped_daily_counts(
        conn,
        table="analyses",
        alias="a",
        binary_id_column="binary_id",
        since=since,
        visible_to=visible_to,
    )


def _auto_runs(
    conn: sqlite3.Connection, since: str, visible_to: Mapping[str, Any] | None = None
) -> dict[str, int]:
    """Auto runs started per day since *since*, on binaries the caller may see."""
    return _scoped_daily_counts(
        conn,
        table="auto_runs",
        alias="r",
        binary_id_column="binary_id",
        since=since,
        visible_to=visible_to,
    )


def _actions(conn: sqlite3.Connection, since: str) -> dict[str, int]:
    """Journaled actions started per day since *since*, the local usage counter."""
    return _counts(
        conn,
        f"SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS n FROM {journal.TABLE}"
        " WHERE created_at >= ? GROUP BY day",
        since=since,
    )


def _software_types(
    conn: sqlite3.Connection,
    since: str,
    notes: list[str],
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, int]]:
    """Per-day, per-type counts of the software type each analysis's binary derives.

    One derivation per binary, reused for every analysis of it, and the list of
    analyses examined is capped: a workspace with a long history would otherwise
    read every scan of every binary behind a dashboard load.  Only analyses of
    binaries the caller may see are examined.
    """
    from reportal import auth

    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is None:
        rows = conn.execute(
            "SELECT id, binary_id, created_at FROM analyses WHERE created_at >= ?"
            " ORDER BY id DESC LIMIT ?",
            (since, MAX_SERIES_ANALYSES + 1),
        ).fetchall()
    else:
        clause, params = scope
        rows = conn.execute(
            "SELECT a.id, a.binary_id, a.created_at FROM analyses a"
            f" JOIN binaries b ON b.id = a.binary_id WHERE a.created_at >= ? AND {clause}"
            " ORDER BY a.id DESC LIMIT ?",
            [since, *params, MAX_SERIES_ANALYSES + 1],
        ).fetchall()
    if len(rows) > MAX_SERIES_ANALYSES:
        notes.append(f"the software-type series examines at most {MAX_SERIES_ANALYSES} analyses")
        rows = rows[:MAX_SERIES_ANALYSES]
    by_binary: dict[int, str] = {}
    series: dict[str, dict[str, int]] = {}
    for row in rows:
        binary_id = int(row["binary_id"])
        if binary_id not in by_binary:
            classified = threat.classify_binary(conn, binary_id)
            kind = classified.get("software_type")
            name = str(kind.get("type") or "") if isinstance(kind, dict) else ""
            by_binary[binary_id] = name or "unknown"
        day = _day(str(row["created_at"]))
        series.setdefault(day, {})
        name = by_binary[binary_id]
        series[day][name] = series[day].get(name, 0) + 1
    return series


def series(
    conn: sqlite3.Connection,
    *,
    days: int = DEFAULT_SERIES_DAYS,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The dashboard series over the last *days* days.

    Returns ``{"days", "range", "series", "software_types", "totals", "notes"}``:
    ``series`` carries one entry per counted key per day (a zero for a quiet
    day), ``software_types`` maps a day to its per-type counts, and ``totals``
    sums the window.  Raises :class:`SeriesError` for a window outside the
    bounds.  ``visible_to`` narrows the analyses, auto-run and software-type
    counts to binaries the caller may see; the journaled-actions count stays
    global, like the feed's journal half.
    """
    days = normalize_days(days)
    dates = window(days)
    # Full UTC midnight so the text compare matches store timestamps
    # (``...+00:00``) rather than relying on a bare date being a prefix.
    since = f"{dates[0]}T00:00:00+00:00"
    notes: list[str] = []

    per_day = {
        "analyses": _analyses(conn, since, visible_to),
        "auto_runs": _auto_runs(conn, since, visible_to),
        "actions": _actions(conn, since),
    }
    software = _software_types(conn, since, notes, visible_to)

    series_rows = [
        {"date": day, **{key: per_day[key].get(day, 0) for key in SERIES_KEYS}} for day in dates
    ]
    type_totals: dict[str, int] = {}
    for day in dates:
        for name, count in software.get(day, {}).items():
            type_totals[name] = type_totals.get(name, 0) + count
    return {
        "days": days,
        "range": {"from": dates[0], "to": dates[-1]},
        "series": series_rows,
        "software_types": [
            {"date": day, "counts": dict(sorted(software[day].items()))}
            for day in dates
            if software.get(day)
        ],
        "totals": {
            **{key: sum(row[key] for row in series_rows) for key in SERIES_KEYS},
            "software_types": dict(sorted(type_totals.items())),
        },
        "notes": notes,
    }

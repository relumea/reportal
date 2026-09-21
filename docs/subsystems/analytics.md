# Analytics, activity and notifications

Sources: src/reportal/analytics.py, src/reportal/activity.py, src/reportal/notifications.py

One computation and two derived feeds. `analytics.py` counts the dashboard series over rows the
workspace already holds; `activity.py` and `notifications.py` normalize the action journal and the
analysis log into feeds. Nothing here writes, runs an engine or calls a model, so a revert or a
prune shows on the next read instead of leaving a stale copy.

## Vocabulary

- `SERIES_KEYS`: `analyses`, `auto_runs` and `actions`. `DEFAULT_SERIES_DAYS` is 30,
  `MAX_SERIES_DAYS` 365, and `SeriesError` refuses a window outside the bounds.
- The `series` payload carries `days`, `range`, `series`, `software_types`, `totals` and `notes`.
  The software-type series derives each type through `threat.classify_binary` and is bounded by
  `MAX_SERIES_ANALYSES`.
- An activity item: `id`, `seq`, `kind`, `actor`, `at`, `action`, `description`, `status` and
  `entries`. `SOURCE_ACTION` and `SOURCE_LOG` are the two sources, and `DEFAULT_ACTIVITY_LIMIT`
  and `MAX_ACTIVITY_LIMIT` bound a page under the payload's `total`, `actor`, `sources` and
  `latest`.
- A notification item: `id`, `seq`, `kind`, `severity`, `message` and `at`, plus `action`,
  `status`, `entries` and `revertible` for an action or `analysis_id`, `binary_id` and
  `binary_name` for a log entry. `parse_since`, `latest` and `merge_page` are the shared helpers.

## Wiring

- Routes: `GET /api/stats/series`, `GET /api/users/activity` and `GET /api/notifications`.
- CLI: `stats --series --days`, `activity`, `notifications`.
- MCP: `get_stats_series`, `get_activity`, `list_notifications`.
- Tables read: `analyses`, `auto_runs`, `journal_entries`, `analysis_log` and `binaries`, through
  the store, journal and analysis-log readers.

## Invariants

- Every day in the window is present, a quiet one with a zero, so a chart cannot read as missing
  data (`tests/test_analytics.py`).
- The software-type bound is stated in the payload's `notes` when it bites, and a type that cannot
  be derived counts as `unknown` rather than being dropped (`tests/test_analytics.py`).
- The journaled-actions series stays global while the other series narrow to `visible_to`
  (`tests/test_analytics.py`).
- An activity item's `actor` is empty for a write no request made, and `actors` reports the empty
  name rather than hiding it (`tests/test_activity.py`).
- An unknown source name or an out-of-range limit raises `ValueError` (`tests/test_activity.py`,
  `tests/test_notifications.py`).
- `since` is inclusive, so the caller de-duplicates by each item's stable `id`
  (`tests/test_notifications.py`).

## See also

- [ARCHITECTURE.md: Analytics](../ARCHITECTURE.md#analytics)
- [ARCHITECTURE.md: Action journal](../ARCHITECTURE.md#action-journal)
- [API.md](../API.md)

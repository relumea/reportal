"""Tests for the dashboard time series.

The series is computed over stored rows only, so the tests write rows with
known timestamps and assert the buckets, the zero-filled quiet days and the
software-type derivation.
"""

from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import analytics, cli, mcp_server, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _stamp(days_ago: int) -> str:
    """An ISO timestamp *days_ago* days before today, in the store's format."""
    moment = datetime.now(UTC) - timedelta(days=days_ago)
    return moment.isoformat(timespec="seconds")


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A portal DB with one analysis today, one three days ago and one auto run."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="aa" * 32, name="demo.exe")
        first = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        second = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        conn.execute("UPDATE analyses SET created_at = ? WHERE id = ?", (_stamp(3), second))
        conn.execute(
            "INSERT INTO auto_runs (binary_id, status, config_json, stats_json,"
            " effects_json, created_at) VALUES (?, 'finished', '{}', '{}', '{}', ?)",
            (binary_id, _stamp(1)),
        )
        conn.commit()
    return {"binary": binary_id, "analysis": first, "older": second, "db": db}


class TestSeries:
    def test_the_window_is_continuous_and_zero_filled(self) -> None:
        dates = analytics.window(3, today=datetime(2026, 9, 13, tzinfo=UTC).date())
        assert dates == ["2026-09-11", "2026-09-12", "2026-09-13"]

    def test_a_day_outside_the_bounds_is_refused(self) -> None:
        assert analytics.normalize_days(1) == 1
        for days in (0, -1, analytics.MAX_SERIES_DAYS + 1, True):
            with pytest.raises(analytics.SeriesError):
                analytics.normalize_days(days)

    def test_the_rows_land_in_their_day(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = analytics.series(conn, days=7)
        assert payload["days"] == 7
        assert len(payload["series"]) == 7
        today = payload["series"][-1]
        assert today["analyses"] == 1
        assert payload["series"][-4]["analyses"] == 1
        assert payload["series"][-2]["auto_runs"] == 1
        assert payload["totals"]["analyses"] == 2
        assert payload["totals"]["auto_runs"] == 1
        assert all(row["actions"] >= 0 for row in payload["series"])

    def test_a_journaled_action_is_counted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            from reportal import journal

            with journal.journaled(conn, journal.new_action()) as log:
                journal.journaled_create(log, table="tags", key=1, description="a tag")
            payload = analytics.series(conn, days=1)
        assert payload["totals"]["actions"] >= 1

    def test_the_software_type_series_names_the_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            store.set_scan(
                conn,
                ids["analysis"],
                store.SCAN_KIND_CAPABILITIES,
                {"capabilities": [{"name": "process-injection", "confidence": "high"}]},
            )
            payload = analytics.series(conn, days=7)
        assert payload["totals"]["software_types"]
        assert payload["software_types"]
        named = payload["software_types"][0]["counts"]
        assert named
        assert all(isinstance(count, int) for count in named.values())

    def test_a_database_without_journal_entries_still_answers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            conn.execute("DROP TABLE IF EXISTS journal_entries")
            payload = analytics.series(conn, days=2)
        assert payload["totals"]["actions"] == 0


class TestSeriesRoutes:
    def test_the_route_answers_the_window(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", "/api/stats/series?days=7")
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["days"] == 7
        assert payload["range"]["to"] >= payload["range"]["from"]
        assert len(payload["series"]) == 7

        default, headers, body = wsgi_request("GET", "/api/stats/series")
        assert json_body(body, headers)["days"] == analytics.DEFAULT_SERIES_DAYS

    def test_a_window_outside_the_bounds_is_400(self) -> None:
        for query in ("days=0", f"days={analytics.MAX_SERIES_DAYS + 1}"):
            status, headers, body = wsgi_request("GET", f"/api/stats/series?{query}")
            assert status.startswith("400"), query
            assert json_body(body, headers)["error"] == "invalid days"


class TestSeriesCliAndMcp:
    def test_the_command_prints_the_series(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        payload = json.loads(
            runner.invoke(cli.app, ["stats", "--series", "--days", "7", "--json"]).output
        )
        assert payload["days"] == 7

        human = runner.invoke(cli.app, ["stats", "--series"])
        assert human.exit_code == 0, human.output
        assert "analyses" in human.output

        bad = runner.invoke(cli.app, ["stats", "--series", "--days", "0"])
        assert bad.exit_code == 1
        assert "invalid days" in bad.output

        counts = runner.invoke(cli.app, ["stats", "--json"])
        assert counts.exit_code == 0, counts.output
        assert "binaries" in json.loads(counts.output)

    def test_the_command_fails_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        result = runner.invoke(cli.app, ["stats", "--series"])
        assert result.exit_code == 1
        assert "no reportal database" in result.output

    def test_the_tool_answers_the_window(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        payload, failed = mcp_server.call_tool("get_stats_series", {"days": 7})
        assert not failed, payload
        assert payload["days"] == 7

        default, failed = mcp_server.call_tool("get_stats_series", {})
        assert not failed, default
        assert default["days"] == analytics.DEFAULT_SERIES_DAYS

        bad, failed = mcp_server.call_tool("get_stats_series", {"days": 0})
        assert failed
        assert bad["error"] == "invalid days"

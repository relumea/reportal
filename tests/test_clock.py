"""Tests for the shared UTC clock: parsing, normalization and relative age."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from reportal import clock


class TestAsUtc:
    def test_naive_is_utc(self) -> None:
        assert clock.as_utc("2026-09-22T10:00:00") == datetime(2026, 9, 22, 10, 0, tzinfo=UTC)

    def test_z_suffix_and_offsets_normalize(self) -> None:
        assert clock.as_utc("2026-09-22T10:00:00Z").utcoffset() == timedelta(0)
        assert clock.as_utc("2026-09-22T12:00:00+02:00") == datetime(2026, 9, 22, 10, 0, tzinfo=UTC)

    def test_garbage_raises(self) -> None:
        with pytest.raises(ValueError):
            clock.as_utc("not-a-stamp")

    def test_iso_normalizes_to_seconds(self) -> None:
        assert clock.as_utc_iso("2026-09-22T10:00:00Z") == "2026-09-22T10:00:00+00:00"


class TestRelativeAge:
    def test_blank_and_garbage_are_blank(self) -> None:
        assert clock.relative_age("") == ""
        assert clock.relative_age(None) == ""
        assert clock.relative_age("not-a-stamp") == ""

    def test_future_is_blank(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fixed = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
        monkeypatch.setattr(clock, "now_utc", lambda: fixed)
        assert clock.relative_age("2026-09-22T13:00:00+00:00") == ""

    def test_buckets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fixed = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
        monkeypatch.setattr(clock, "now_utc", lambda: fixed)

        def stamp(**kwargs: object) -> str:
            delta = timedelta(**kwargs)  # type: ignore[arg-type]
            return (fixed - delta).isoformat()

        assert clock.relative_age(stamp(seconds=30)) == "just now"
        assert clock.relative_age(stamp(minutes=5)) == "5m ago"
        assert clock.relative_age(stamp(hours=3)) == "3h ago"
        assert clock.relative_age(stamp(days=9)) == "9d ago"
        assert clock.relative_age(stamp(days=60)) == "2mo ago"
        assert clock.relative_age(stamp(days=400)) == "1y ago"

    def test_now_helpers(self) -> None:
        assert clock.now().endswith("+00:00")
        assert clock.now_utc().tzinfo == UTC

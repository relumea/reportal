"""The smoke's marker wait polls the live document.

``tools/smoke_spa.py`` used to dump the DOM once after a fixed virtual-time
budget, which is a cap on how far ahead the page's timers run rather than a wait
for a pending fetch: a route whose data arrived late was dumped without it and
``make check``'s smoke step flaked.  The wait now polls the document until every
marker group is satisfied or a deadline passes.  These tests pin that behaviour
without a browser, by driving the polling loop through the CDP seam and a fake
clock, so a regression to a single dump fails here instead of flaking later.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tools import smoke_spa


@contextlib.contextmanager
def _session(_browser: str, _profile: Path) -> Iterator[tuple[Any, str]]:
    yield object(), "session-1"


class _Clock:
    """A monotonic clock whose sleeps advance it, so a deadline can be reached."""

    def __init__(self) -> None:
        self._now = 0.0
        self.sleeps = 0

    def monotonic(self) -> float:
        return self._now

    def sleep(self, seconds: float) -> None:
        self._now += seconds
        self.sleeps += 1


def _install(monkeypatch: pytest.MonkeyPatch, doms: list[str]) -> tuple[_Clock, dict[str, int]]:
    """Wire the smoke's CDP seam to *doms*, one per document read."""
    clock = _Clock()
    reads = {"count": 0}

    def html(_pipe: Any, _session_id: str) -> str:
        index = min(reads["count"], len(doms) - 1)
        reads["count"] += 1
        return doms[index]

    monkeypatch.setattr(smoke_spa.cdp, "render", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(smoke_spa.cdp, "browser_session", _session)
    monkeypatch.setattr(smoke_spa.cdp, "document_html", html)
    monkeypatch.setattr(smoke_spa.cdp, "page_errors", lambda _pipe, _session_id: [])
    # The marker wait unfolds every collapsed panel before each read, so the
    # seam needs an expression evaluator even with no browser behind it.
    monkeypatch.setattr(smoke_spa.cdp, "evaluate", lambda _pipe, _session, _expr: 0)
    monkeypatch.setattr(smoke_spa.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(smoke_spa.time, "sleep", clock.sleep)
    return clock, reads


class TestRenderMarkers:
    def test_polls_until_every_marker_group_is_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock, reads = _install(
            monkeypatch,
            ["<html>shell</html>", "<html>shell</html>", "<html>shell MARKER</html>"],
        )

        dom, errors = smoke_spa.render_markers("chrome", "http://127.0.0.1:1/#/", (("MARKER",),))

        assert "MARKER" in dom
        assert errors == [], "a page with no error reports none"
        assert reads["count"] == 3, "the wait must re-read the document, not dump it once"
        assert clock.sleeps == 2, "it waits between reads rather than spinning"

    def test_a_marker_that_never_appears_stops_at_the_deadline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clock, reads = _install(monkeypatch, ["<html>shell</html>"])

        dom, _errors = smoke_spa.render_markers("chrome", "http://127.0.0.1:1/#/", (("MARKER",),))

        assert dom == "<html>shell</html>"
        # The deadline is bounded: the loop stops rather than polling forever.
        max_reads = int(smoke_spa.MARKER_DEADLINE_SECONDS / smoke_spa.MARKER_POLL_SECONDS) + 2
        assert reads["count"] <= max_reads

    def test_markers_missing_names_each_group_with_no_member(self) -> None:
        groups = (("alpha", "beta"), ("gamma",))
        assert smoke_spa.markers_missing("<html>beta</html>", groups) == [("gamma",)]
        assert smoke_spa.markers_missing("<html>beta gamma</html>", groups) == []


class TestCheckRoute:
    """The route check fails on a missing marker and on a page that logged an error."""

    def test_a_rendered_route_with_no_page_error_passes(self) -> None:
        assert smoke_spa.check_route("route", "<html>MARKER</html>", (("MARKER",),), [])

    def test_a_missing_marker_fails(self) -> None:
        assert not smoke_spa.check_route("route", "<html>shell</html>", (("MARKER",),), [])

    def test_a_page_error_fails_even_when_every_marker_rendered(self) -> None:
        errors = ["page error: TypeError: x is undefined"]
        assert not smoke_spa.check_route("route", "<html>MARKER</html>", (("MARKER",),), errors)

"""Shared stand-ins for ``importlib.metadata`` entry points in plugin tests."""

from __future__ import annotations

import pytest

from reportal import plugins


class EntryPoint:
    """Minimal stand-in for importlib.metadata.EntryPoint."""

    def __init__(self, name: str, value: str) -> None:
        self.name = name
        self.value = value


class EntryPoints:
    """Minimal stand-in for the EntryPoints collection."""

    def __init__(self, entries: list[EntryPoint]) -> None:
        self._entries = entries

    def select(self, *, group: str) -> list[EntryPoint]:
        return list(self._entries)


def patch_entry_points(monkeypatch: pytest.MonkeyPatch, *entries: EntryPoint) -> None:
    """Point :func:`reportal.plugins.entry_points` at *entries* for one test."""
    monkeypatch.setattr(plugins, "entry_points", lambda: EntryPoints(list(entries)))

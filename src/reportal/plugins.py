"""Shared entry-point discovery for reportal's plugin registries.

reportal is assembled from replaceable parts, and every kind of part registers
through its own entry-point group: pipeline components, auto-mode workers,
graph backends, effect handlers, MCP tools, external sources, models, sandbox
runners and debug backends.  This module is the one place that reads such a group and
turns a ``module:attr`` value into an object, so the nine seams differ only in
what they accept and where the result is registered.

Discovery never raises into the registry.  A malformed value, an unimportable
module, a missing attribute, a factory that raises and a factory returning the
wrong thing are all skipped with a warning, because a broken plugin must not
brick the process.  A *duplicate* name is the opposite case and is left to the
registry: two parts claiming one name is a composition error rather than a
broken plugin, so the registry raises :class:`RegistryError` naming the loser.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Callable, Iterator
from importlib.metadata import entry_points
from typing import Any

_log = logging.getLogger("reportal")

# Origin recorded for an in-tree registration, as opposed to a plugin's.
BUILTIN_ORIGIN = "builtin"

# A validator: the resolved value in, the value to register (or None) out.
Check = Callable[[str, str, str, Any], Any]


class RegistryError(RuntimeError):
    """A plugin registration is malformed, unusable, or a duplicate name."""


def items(group: str) -> list[tuple[str, str]]:
    """Return ``(name, value)`` of every entry point in *group*."""
    return [(str(ep.name), str(ep.value)) for ep in entry_points().select(group=group)]


def origin(name: str, value: str) -> str:
    """The origin string recorded for the entry point ``name`` at ``value``."""
    return f"entry point {name!r} ({value})"


def expects(expected: type[Any], label: str) -> Check:
    """A validator accepting an *expected* instance and warning about anything else."""

    def check(group: str, name: str, value: str, resolved: Any) -> Any:
        if isinstance(resolved, expected):
            return resolved
        _log.warning(
            "skipping bad %s registration %r (%s): expected a %s or a factory, got %s",
            group,
            name,
            value,
            label,
            type(resolved).__name__,
        )
        return None

    return check


def resolve(
    group: str, name: str, value: str, *, check: Check, expected: type[Any] | None = None
) -> Any:
    """Resolve one ``module:attr`` entry point and hand it to *check*, or None.

    *expected* is the type a callable value is called to produce and anything
    already an instance of it is used as it is.  Passing None means the value
    *is* the part rather than a factory for it, which is the effect-handler
    group's shape: a bare function there is a handler, not a factory.  The
    resolved object is checked before it reaches a registry, so a bad plugin is
    a warning rather than a failure at call time.
    """
    module_name, _, attr = value.partition(":")
    if not module_name:
        _log.warning(
            "skipping bad %s registration %r: value %r is not 'module' or 'module:attr'",
            group,
            name,
            value,
        )
        return None
    try:
        module = importlib.import_module(module_name)
        target = getattr(module, attr) if attr else module
        if expected is None:
            resolved = target
        else:
            resolved = target() if callable(target) and not isinstance(target, expected) else target
    except Exception as exc:  # any failure in a plugin module is a skipped plugin
        _log.warning("skipping broken %s registration %r (%s): %s", group, name, value, exc)
        return None
    return check(group, name, value, resolved)


def load(group: str, expected: type[Any], label: str) -> Iterator[tuple[str, str, Any]]:
    """Yield ``(name, value, plugin)`` for every usable entry point in *group*."""
    check = expects(expected, label)
    for name, value in items(group):
        resolved = resolve(group, name, value, expected=expected, check=check)
        if resolved is not None:
            yield name, value, resolved

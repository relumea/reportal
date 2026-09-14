"""reportal's component framework: everything in a pipeline run is a component.

A component declares the context values it ``requires`` and the values it
``provides``, plus the effect it performs.  Two properties of the model the
pipeline follows are implemented here:

* **Spatial composability**: a loader activates a component only when every
  name in ``requires`` is satisfiable, meaning a seeded value or a value an
  active component provides.  A component that is not activated is skipped
  together with everything that depends on it, each with a recorded reason.
  :meth:`Context.subscribe` reports every context change to a loader, so
  activation is re-evaluated while a run is in progress, not decided once.
* **Temporal composability**: every context transformation is journaled with
  its inverse.  A :meth:`Context.provide` and a :meth:`Context.revoke` restore
  the binding they replaced, and a persistent write a component performs
  records its inverse through :meth:`Context.record`; one
  :meth:`Context.revert` applies them all newest-first, so a revert undoes
  both what a run bound and what it wrote.

Built-in components live in :mod:`reportal.pipeline`.  Third parties declare an
entry point in the :data:`COMPONENT_ENTRY_POINT_GROUP` group whose value is
``module:attr`` naming a :class:`Component` or a zero-argument factory that
returns one.  Discovery mirrors ``rebrew.registry``: a broken registration is
skipped with a warning, and a duplicate name raises :class:`RegistryError`.

Every registration records where it came from: the declaring module and
whether the entry can be reloaded.  :func:`reload_component` re-imports that
module and swaps the registry entry in place, so the next composition reads the
new declaration while the rest of the registry and the declaration order are
untouched.  It is registry-level replacement, not a guarantee about a run
already in flight: a caller holding a registry snapshot or a live
:class:`Context` keeps it until it composes again.
"""

from __future__ import annotations

import importlib
import logging
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import CodeType
from typing import Any

from reportal import plugins
from reportal.plugins import RegistryError as RegistryError

# Entry-point group third-party components register in.
COMPONENT_ENTRY_POINT_GROUP = "reportal.components"

# Module declaring the in-tree components.  Imported lazily inside the registry
# because that module imports this one.
BUILTIN_MODULE = "reportal.pipeline"

# Value a component's ``name`` carries when a registration does not supply a
# usable one, and the origin label a built-in registration reports.
BUILTIN_ORIGIN = plugins.BUILTIN_ORIGIN

# Kinds of journal entry and of the change notification a subscriber sees: a
# binding made, a binding removed, and anything else a component recorded.
CHANGE_PROVIDE = "provide"
CHANGE_REVOKE = "revoke"
CHANGE_RECORD = "record"

# Status a revert reports for one applied inverse.
EFFECT_REVERTED = "reverted"
EFFECT_FAILED = "failed"

# Notification a subscriber receives: the changed name and the change kind.
ChangeCallback = Callable[[str, str], None]

# Sentinel distinguishing "no previous binding" from a binding whose value is
# None, so restoring an absent name removes it instead of rebinding None.
_NO_BINDING = object()

# Sentinel for "the module has no such attribute", so a declaration whose value
# is None still reads as present.
_NO_DECLARATION = object()

_log = logging.getLogger(__name__)


class RequirementError(LookupError):
    """A context value a component required is absent."""


class NotReloadableError(RuntimeError):
    """A component was registered in process and has no declaration to reload.

    ``reason`` names why: an in-process registration records no declaring module
    and no entry-point group, so there is nothing for :func:`reload_component`
    to re-import.  Built-in and entry-point registrations are reloadable.
    """

    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self.reason = reason
        super().__init__(f"component {name!r} is not reloadable: {reason}")


class ComponentMissingError(LookupError):
    """A reloaded declaration no longer declares the component."""

    def __init__(self, name: str, module_name: str) -> None:
        self.name = name
        self.module_name = module_name
        super().__init__(
            f"module {module_name!r} no longer declares component {name!r} after a reload"
        )


@dataclass(frozen=True)
class Effect:
    """One journaled transformation: what it did, how to undo it, and its record.

    ``inverse`` is the closure applied by :meth:`Context.revert` in the run's
    own process.  ``undo`` is the JSON-serializable descriptor a persisted run
    replays later, which is how a revert survives the process that ran the
    pipeline.  A binding and a write with no durable undo leave ``undo`` None.
    ``kind`` is :data:`CHANGE_PROVIDE`, :data:`CHANGE_REVOKE` or
    :data:`CHANGE_RECORD`, and a replay of a stored descriptor may carry the
    descriptor's own kind.  ``name`` is the context binding a provide or a
    revoke changed, and None for a recorded write.
    """

    description: str
    inverse: Callable[[], Any]
    undo: dict[str, Any] | None = None
    kind: str = CHANGE_RECORD
    name: str | None = None


class Context:
    """Named values plus the reversible journal of one pipeline run.

    Values are seeded by the runner (the function row, its binary, the rebrew
    project directory, the database connection, the engine and the LLM client)
    and written by components through :meth:`provide`; :meth:`revoke` withdraws
    one.  Every transformation journals its inverse, and every persistent write
    a component performs records its inverse through :meth:`record`.
    """

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        self._values: dict[str, Any] = dict(values or {})
        self._effects: list[Effect] = []
        self._subscribers: list[ChangeCallback] = []

    def subscribe(self, callback: ChangeCallback) -> None:
        """Register *callback*, called with ``(name, kind)`` on every change.

        A change is a :meth:`provide`, a :meth:`revoke`, or either's inverse
        applied by :meth:`revert`.  This is the surface a loader re-evaluates
        component activation from while a run is in progress.
        """
        self._subscribers.append(callback)

    def names(self) -> frozenset[str]:
        """Every name currently bound, which is what a requirement is checked against."""
        return frozenset(self._values)

    def _notify(self, name: str, kind: str) -> None:
        """Tell every subscriber that *name* changed in the *kind* direction."""
        for callback in self._subscribers:
            callback(name, kind)

    def _restore(self, name: str, previous: Any) -> None:
        """Put the binding of *name* back the way *previous* recorded it."""
        if previous is _NO_BINDING:
            self._values.pop(name, None)
            self._notify(name, CHANGE_REVOKE)
            return
        self._values[name] = previous
        self._notify(name, CHANGE_PROVIDE)

    def provide(self, name: str, value: Any) -> None:
        """Bind *name* to *value*, journaling the inverse that restores it.

        Overwriting a bound name journals the restore of the value it replaced,
        so a revert of two writes to one name walks back to the first value.
        """
        previous = self._values.get(name, _NO_BINDING)
        self._effects.append(
            Effect(
                description=f"provide {name}",
                inverse=lambda: self._restore(name, previous),
                kind=CHANGE_PROVIDE,
                name=name,
            )
        )
        self._values[name] = value
        self._notify(name, CHANGE_PROVIDE)

    def revoke(self, name: str) -> None:
        """Unbind *name*, journaling the inverse that restores its binding.

        Revoking a name that is not bound journals the same inverse, which is a
        no-op that still notifies subscribers (symmetric with :meth:`provide`).
        """
        previous = self._values.get(name, _NO_BINDING)
        self._effects.append(
            Effect(
                description=f"revoke {name}",
                inverse=lambda: self._restore(name, previous),
                kind=CHANGE_REVOKE,
                name=name,
            )
        )
        self._values.pop(name, None)
        self._notify(name, CHANGE_REVOKE)

    def require(self, name: str) -> Any:
        """Return the value bound to *name*.

        Raises :class:`RequirementError` when nothing bound it, which is what a
        component sees when a dependency it needs did not produce its value.
        """
        if name not in self._values:
            raise RequirementError(f"context has no value {name!r}")
        return self._values[name]

    def get(self, name: str, default: Any = None) -> Any:
        """Return the value bound to *name*, or *default* when there is none."""
        return self._values.get(name, default)

    def has(self, name: str) -> bool:
        """True when a value is bound to *name*."""
        return name in self._values

    def seed(self, name: str, value: Any) -> None:
        """Bind *name* outside the journal, the way the runner seeds a value.

        A seeded value is not an effect: it is what the context starts with, so
        it journals no inverse and a revert leaves it in place.  A live host
        re-seeds the database connection this way before each withdrawal, since
        the connection the process opened last is the one the component sees.
        """
        self._values[name] = value

    def record(
        self,
        description: str,
        inverse: Callable[[], Any],
        undo: dict[str, Any] | None = None,
        *,
        kind: str = CHANGE_RECORD,
    ) -> None:
        """Journal a write of *description* together with its *inverse*.

        *undo* is the descriptor a later process replays; a write that leaves
        nothing behind for a revert passes none.  *kind* labels the entry a
        revert reports; a stored descriptor replayed through this context
        passes the descriptor's own kind.
        """
        self._effects.append(Effect(description=description, inverse=inverse, undo=undo, kind=kind))

    def effects(self) -> tuple[Effect, ...]:
        """The journaled transformations in the order they happened."""
        return tuple(self._effects)

    def undo_plan(self) -> list[dict[str, Any]]:
        """The JSON-serializable undo descriptors, in journal order."""
        return [effect.undo for effect in self._effects if effect.undo is not None]

    def revert(self) -> list[dict[str, Any]]:
        """Apply the journaled inverses newest-first; returns what it undid.

        The journal is consumed by the call, so a second revert does nothing,
        and with it the context returns to the bindings it was seeded with: a
        name no component touched keeps its seeded value.  Every entry names
        its ``kind``, so a caller can see bindings and writes interleaved in
        the order the revert walked them.  An inverse that returns a mapping
        contributes its fields to the entry it reports.  One failing inverse
        does not stop the rest: it is reported with status ``failed`` and the
        remaining writes are still undone.
        """
        undone: list[dict[str, Any]] = []
        while self._effects:
            effect = self._effects.pop()
            try:
                outcome = effect.inverse()
            except Exception as exc:  # one bad inverse must not strand the rest
                undone.append(_revert_entry(effect, EFFECT_FAILED, str(exc)))
            else:
                undone.append(_revert_entry(effect, EFFECT_REVERTED, "", outcome))
        return undone

    def take_binding_change(self, change: str, name: str) -> bool:
        """Apply and remove the newest journaled binding change of *name*.

        *change* is :data:`CHANGE_PROVIDE` or :data:`CHANGE_REVOKE`.  This is
        how a revert that runs in the process that made a binding restores it
        for real: the effect is taken off the journal and its inverse applied,
        so it is not undone twice.  Returns False when this context never made
        that change, which is what a later process reports instead of claiming
        a restore it did not perform.
        """
        for index in range(len(self._effects) - 1, -1, -1):
            effect = self._effects[index]
            if effect.kind == change and effect.name == name:
                del self._effects[index]
                effect.inverse()
                return True
        return False


def _revert_entry(effect: Effect, status: str, detail: str, outcome: Any = None) -> dict[str, Any]:
    """One entry of a revert report, with the inverse's own fields merged in."""
    entry: dict[str, Any] = {
        "kind": effect.kind,
        "description": effect.description,
        "status": status,
        "detail": detail,
    }
    if isinstance(outcome, dict):
        entry.update(outcome)
    return entry


@dataclass(frozen=True)
class Component:
    """One unit of a pipeline run: what it needs, what it writes, and how.

    ``requires`` and ``provides`` are the coeffects and effects of the model;
    ``effect`` performs the work against a :class:`Context`.  ``revert`` is an
    optional component-level cleanup the loader calls when ``effect`` raises,
    for writes the journal does not cover.
    """

    name: str
    requires: frozenset[str]
    provides: frozenset[str]
    effect: Callable[[Context], None]
    revert: Callable[[Context], None] | None = None


@dataclass(frozen=True)
class Registration:
    """One registry entry: the component plus where its declaration came from.

    ``module_name`` is the module a reload re-imports and ``entry_point`` the
    entry-point key to re-resolve, both None/"" for an in-process registration.
    ``reloadable`` is what :func:`reload_component` checks before it touches the
    entry.
    """

    component: Component
    origin: str
    module_name: str | None
    reloadable: bool
    entry_point: str | None = None


_registry: dict[str, Registration] = {}
_builtins_loaded = False
_entry_points_loaded = False


def register_component(
    component: Component,
    *,
    origin: str = BUILTIN_ORIGIN,
    module_name: str | None = None,
    reloadable: bool = False,
    entry_point: str | None = None,
) -> None:
    """Register *component* under its own name.

    *origin* names the registration source in error messages.  *module_name*
    and *reloadable* record where a reload would re-read the declaration from;
    an in-process registration passes neither and is therefore not reloadable.
    Raises :class:`RegistryError` for a malformed value, a reloadable entry
    with no declaring module, or a name that is already taken, naming both
    origins (single-source discipline).
    """
    if reloadable and not module_name:
        raise RegistryError(
            f"bad component registration {component!r} from {origin}: reloadable entry"
            " names no declaring module"
        )
    if not isinstance(component, Component):
        raise RegistryError(
            f"bad component registration from {origin}: expected a Component,"
            f" got {type(component).__name__}"
        )
    if not component.name.strip():
        raise RegistryError(f"bad component registration from {origin}: empty name")
    if not callable(component.effect):
        raise RegistryError(
            f"bad component registration {component.name!r} from {origin}: effect is not callable"
        )
    if component.name in _registry:
        raise RegistryError(
            f"duplicate component registration {component.name!r}: {origin} conflicts"
            f" with an existing registration (single-source discipline)"
        )
    _registry[component.name] = Registration(
        component=component,
        origin=origin,
        module_name=module_name,
        reloadable=reloadable,
        entry_point=entry_point,
    )


def components() -> tuple[Component, ...]:
    """Every registered component, built-ins first, in declaration order."""
    _ensure_builtins()
    _ensure_entry_points()
    return tuple(entry.component for entry in _registry.values())


def assert_unique_providers(registered: Iterable[Component]) -> None:
    """Refuse two components that provide the same context name.

    The paper's coeffect context makes a second provision of an already bound
    key an error that produces no transition (Definitions 19 and 20), and one
    writer per key is what its independence property needs (Section 3.4.1):
    with two writers a revert walks back through both.  reportal held the
    single-source discipline for component *names* only, so a plugin claiming a
    name another component provides still ran and its binding outlived the
    provider's revert.  The caller passes the composition it is about to run,
    so a component the configuration disables is not a writer here.
    """
    provider: dict[str, str] = {}
    for component in registered:
        for name in sorted(component.provides):
            other = provider.setdefault(name, component.name)
            if other != component.name:
                raise RegistryError(
                    f"context name {name!r} is provided by both {other!r} and"
                    f" {component.name!r}; one writer per name is what makes the"
                    " two components' effects independent"
                )


def registrations() -> tuple[Registration, ...]:
    """Every registry entry with its origin and reloadability, in declaration order."""
    _ensure_builtins()
    _ensure_entry_points()
    return tuple(_registry.values())


def refresh_components() -> tuple[Component, ...]:
    """Discard discovered components and re-run discovery.

    Built-ins are re-declared and the entry-point group is scanned again, which
    is how a long-lived process picks up a plugin installed after startup.
    Unlike :func:`reload_component`, this drops in-process registrations and
    rebuilds the whole registry (and its declaration order) from scratch;
    reload swaps one live entry while leaving every other entry and the order
    of the registry untouched.
    """
    global _builtins_loaded, _entry_points_loaded
    _registry.clear()
    _builtins_loaded = False
    _entry_points_loaded = False
    return components()


def reload_component(name: str) -> dict[str, Any]:
    """Reload one registered component from its declaring module.

    Built-ins are re-read through :func:`reportal.pipeline.builtin_components`
    and entry-point components through a re-scan of the
    :data:`COMPONENT_ENTRY_POINT_GROUP` group, both after ``importlib.reload``
    of the declaring module, so module-level state is re-initialized.  The
    registry entry is replaced in place, which keeps declaration order.

    Returns the report ``{"name", "reloaded", "old_origin", "new_origin",
    "module", "changed"}``.  Raises :class:`KeyError` for an unknown name,
    :class:`NotReloadableError` for an in-process registration and
    :class:`ComponentMissingError` when the reloaded declaration no longer
    declares the component.
    """
    _ensure_builtins()
    _ensure_entry_points()
    entry = _registry.get(name)
    if entry is None:
        raise KeyError(name)
    return _reload_entry(name, entry, reloaded_modules=set())


def reload_all() -> dict[str, Any]:
    """Reload every reloadable component; report per-name results.

    Non-reloadable registrations are skipped with the reason
    :func:`reload_component` would raise, and a declaring module shared by
    several components is re-imported once per call.  Returns
    ``{"reloaded": [...], "skipped": [...], "count", "changed": [names]}``.
    """
    _ensure_builtins()
    _ensure_entry_points()
    reloaded: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    modules: set[str] = set()
    for name, entry in list(_registry.items()):
        if not entry.reloadable or entry.module_name is None:
            skipped.append({"name": name, "reason": _not_reloadable_reason(entry)})
            continue
        reloaded.append(_reload_entry(name, entry, reloaded_modules=modules))
    return {
        "reloaded": reloaded,
        "skipped": skipped,
        "count": len(reloaded),
        "changed": [report["name"] for report in reloaded if report["changed"]],
    }


def _reload_entry(name: str, entry: Registration, *, reloaded_modules: set[str]) -> dict[str, Any]:
    """Re-import one entry's declaration and swap it into the registry."""
    if not entry.reloadable or entry.module_name is None:
        raise NotReloadableError(name, _not_reloadable_reason(entry))
    value: str | None = None
    previous: Any = _NO_DECLARATION
    if entry.entry_point is not None:
        value = dict(plugins.items(COMPONENT_ENTRY_POINT_GROUP)).get(entry.entry_point)
        if value is None:
            raise ComponentMissingError(name, str(entry.module_name))
        # Captured before the reload: a module that no longer binds the
        # declaration leaves the old name in its namespace, since reload
        # re-executes in place and does not remove stale attributes.
        previous = _module_attribute(value)
    if entry.module_name not in reloaded_modules:
        importlib.reload(importlib.import_module(entry.module_name))
        reloaded_modules.add(entry.module_name)
    if entry.entry_point is None:
        component, origin = _builtin_declaration(name, entry)
    else:
        component, origin = _entry_point_declaration(name, entry, str(value), previous)
    old_component = entry.component
    _registry[name] = Registration(
        component=component,
        origin=origin,
        module_name=entry.module_name,
        reloadable=True,
        entry_point=entry.entry_point,
    )
    return {
        "name": name,
        "reloaded": True,
        "old_origin": entry.origin,
        "new_origin": origin,
        "module": entry.module_name,
        "changed": _change_fingerprint(old_component) != _change_fingerprint(component),
    }


def _builtin_declaration(name: str, entry: Registration) -> tuple[Component, str]:
    """Re-resolve *name* from the reloaded built-in declaration."""
    module = importlib.import_module(str(entry.module_name))
    component = next((item for item in module.builtin_components() if item.name == name), None)
    if component is None:
        raise ComponentMissingError(name, str(entry.module_name))
    return component, BUILTIN_ORIGIN


def _entry_point_declaration(
    name: str, entry: Registration, value: str, previous: Any
) -> tuple[Component, str]:
    """Re-resolve *name* from the reloaded entry point *value*."""
    if _module_attribute(value) is previous:
        raise ComponentMissingError(name, str(entry.module_name))
    component = plugins.resolve(
        COMPONENT_ENTRY_POINT_GROUP,
        str(entry.entry_point),
        value,
        expected=Component,
        check=plugins.expects(Component, "Component"),
    )
    if component is None or component.name != name:
        raise ComponentMissingError(name, str(entry.module_name))
    return component, plugins.origin(str(entry.entry_point), value)


def _module_attribute(value: str) -> Any:
    """The module attribute an entry-point value names, or the no-declaration sentinel."""
    module_name, _, attr = value.partition(":")
    if not module_name or not attr:
        return _NO_DECLARATION
    module = sys.modules.get(module_name)
    if module is None:
        return _NO_DECLARATION
    return getattr(module, attr, _NO_DECLARATION)


def _not_reloadable_reason(entry: Registration) -> str:
    """Why *entry* cannot be reloaded."""
    return (
        f"registered in process as {entry.origin!r} with no declaring module;"
        " only built-in and entry-point components are reloadable"
    )


def _code_fingerprint(code: CodeType) -> tuple[Any, ...]:
    """Identity-free description of a compiled body, nested comprehensions included.

    ``marshal`` is not usable here: two code objects for identical source do not
    always serialize to the same bytes, so a reload of unchanged source would
    report ``changed``.  Comparing the fields the compiler derives from the
    source keeps an unchanged declaration unchanged and a rewritten one changed.
    """
    return (
        code.co_code,
        tuple(
            _code_fingerprint(item) if isinstance(item, CodeType) else item
            for item in code.co_consts
        ),
        code.co_names,
        code.co_varnames,
        code.co_freevars,
        code.co_cellvars,
        code.co_flags,
    )


def _change_fingerprint(component: Component) -> tuple[Any, ...]:
    """What a reload compares: the declaration plus the effect's compiled body."""
    effect = component.effect
    code = getattr(effect, "__code__", None)
    return (
        component.name,
        tuple(sorted(component.requires)),
        tuple(sorted(component.provides)),
        str(getattr(effect, "__module__", "")),
        str(getattr(effect, "__qualname__", "")),
        _code_fingerprint(code) if code is not None else (),
    )


def _ensure_builtins() -> None:
    """Load the in-tree components once."""
    global _builtins_loaded
    if _builtins_loaded:
        return
    _builtins_loaded = True
    module = importlib.import_module(BUILTIN_MODULE)
    for component in module.builtin_components():
        register_component(
            component, origin=BUILTIN_ORIGIN, module_name=BUILTIN_MODULE, reloadable=True
        )


def _ensure_entry_points() -> None:
    """Load third-party components once, skipping a broken registration."""
    global _entry_points_loaded
    if _entry_points_loaded:
        return
    _entry_points_loaded = True
    for name, value, component in plugins.load(COMPONENT_ENTRY_POINT_GROUP, Component, "Component"):
        # A duplicate name is not skipped: two components claiming one name is a
        # composition error, and the RegistryError says which registration lost.
        register_component(
            component,
            origin=plugins.origin(name, value),
            module_name=value.partition(":")[0],
            reloadable=True,
            entry_point=name,
        )

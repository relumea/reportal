"""Tests for the component framework: context, journal and registry."""

from __future__ import annotations

import logging
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from plugin_helpers import EntryPoint as _EntryPoint
from plugin_helpers import patch_entry_points as _patch_entry_points

from reportal import components, pipeline
from reportal.components import (
    CHANGE_PROVIDE,
    CHANGE_REVOKE,
    Component,
    Context,
    RequirementError,
)

# Module the reload tests write under ``tmp_path`` and import through sys.path.
_HMR_MODULE = "reportal_hmr_probe"

# Source of that module.  ``__VERSION__`` is substituted with a string literal
# inside the effect, so rewriting the file changes the compiled body and not
# only a module-level constant the effect reads through its globals.
_HMR_TEMPLATE = '''\
"""A component module the reload tests rewrite between versions."""

from __future__ import annotations

from reportal.components import Component, Context

VALUE = "hmr.value"
LOG = "hmr.log"


def apply(ctx: Context) -> None:
    """Record this version and bind its marker."""
    ctx.require(LOG).append(__VERSION__)
    ctx.provide(VALUE, __VERSION__)


PROBE = Component(
    name="hmr-probe",
    requires=frozenset(),
    provides=frozenset({VALUE}),
    effect=apply,
)
'''


def _write_hmr_module(directory: Path, version: str, *, declared: bool = True) -> str:
    """Write the probe module at *version*; return its importable module name.

    The bytecode cache is dropped after the write: ``v1`` and ``v2`` compile to
    the same source size, so a rewrite inside one mtime tick would otherwise
    leave the cached bytecode valid and ``importlib.reload`` would re-execute
    the old version.
    """
    source = _HMR_TEMPLATE.replace("__VERSION__", f'"{version}"')
    if not declared:
        source = source.replace("PROBE = Component(", "_GONE = Component(")
    (directory / f"{_HMR_MODULE}.py").write_text(source, encoding="utf-8")
    for cache in directory.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
    return _HMR_MODULE


@pytest.fixture()
def hmr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Import the probe module from *tmp_path*, dropping its sys.modules entry after."""
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop(_HMR_MODULE, None)
    yield tmp_path
    sys.modules.pop(_HMR_MODULE, None)


@pytest.fixture(autouse=True)
def _isolate_components() -> Iterator[None]:
    """Reload the registry around each test, whatever a test registered."""
    components.refresh_components()
    yield
    components.refresh_components()


def _noop(ctx: Context) -> None:
    """An effect that does nothing."""


def _component(
    name: str,
    *,
    requires: set[str] | None = None,
    provides: set[str] | None = None,
    effect: Any = None,
) -> Component:
    """A component for the fiber tests: no work unless one is given."""
    return Component(
        name=name,
        requires=frozenset(requires or ()),
        provides=frozenset(provides or ()),
        effect=effect if effect is not None else _noop,
    )


def _providing(name: str, value: Any) -> Any:
    """An effect that binds *name* to *value* on the context it is given."""

    def effect(ctx: Context) -> None:
        ctx.provide(name, value)

    return effect


class TestContext:
    def test_provide_require_get_has(self) -> None:
        ctx = Context({"seed": 1})
        assert ctx.has("seed")
        assert ctx.require("seed") == 1
        assert ctx.get("seed") == 1
        assert not ctx.has("other")
        assert ctx.get("other", "fallback") == "fallback"
        ctx.provide("other", 2)
        assert ctx.require("other") == 2

    def test_require_unknown_raises(self) -> None:
        ctx = Context()
        with pytest.raises(RequirementError) as excinfo:
            ctx.require("missing")
        assert "missing" in str(excinfo.value)

    def test_revert_applies_inverses_newest_first(self) -> None:
        ctx = Context()
        order: list[str] = []
        ctx.record("first", lambda: order.append("first"))
        ctx.record("second", lambda: order.append("second"))
        undone = ctx.revert()
        assert order == ["second", "first"]
        assert [entry["description"] for entry in undone] == ["second", "first"]
        assert [entry["status"] for entry in undone] == ["reverted", "reverted"]

    def test_revert_consumes_the_journal(self) -> None:
        ctx = Context()
        ctx.record("one", lambda: None)
        assert len(ctx.revert()) == 1
        assert ctx.effects() == ()
        assert ctx.revert() == []

    def test_revert_reports_a_failing_inverse_and_continues(self) -> None:
        ctx = Context()
        order: list[str] = []

        def boom() -> None:
            raise RuntimeError("cannot undo")

        ctx.record("first", lambda: order.append("first"))
        ctx.record("second", boom)
        ctx.record("third", lambda: order.append("third"))
        undone = ctx.revert()
        assert order == ["third", "first"]
        assert [entry["status"] for entry in undone] == ["reverted", "failed", "reverted"]
        assert "cannot undo" in undone[1]["detail"]

    def test_undo_plan_keeps_only_durable_writes(self) -> None:
        ctx = Context()
        ctx.record("in memory", lambda: None)
        ctx.record("durable", lambda: None, {"kind": "disasm", "function_id": 1})
        ctx.provide("bound", 1)
        assert ctx.undo_plan() == [{"kind": "disasm", "function_id": 1}]

    def test_names_reports_the_bound_values(self) -> None:
        ctx = Context({"seed": 1})
        ctx.provide("other", 2)
        assert ctx.names() == frozenset({"seed", "other"})

    def test_provide_journals_an_inverse_that_removes_a_new_binding(self) -> None:
        ctx = Context()
        ctx.provide("late", 7)
        assert ctx.require("late") == 7
        ctx.revert()
        assert not ctx.has("late")

    def test_provide_revert_restores_the_previous_binding(self) -> None:
        ctx = Context({"seed": 1})
        ctx.provide("seed", 2)
        assert ctx.require("seed") == 2
        ctx.revert()
        assert ctx.require("seed") == 1

    def test_two_provides_of_one_name_revert_to_the_first_value(self) -> None:
        ctx = Context({"seed": 1})
        ctx.provide("seed", 2)
        ctx.provide("seed", 3)
        undone = ctx.revert()
        assert ctx.require("seed") == 1
        assert [entry["description"] for entry in undone] == ["provide seed", "provide seed"]

    def test_revoke_unbinds_and_revert_restores_the_binding(self) -> None:
        ctx = Context({"seed": 1})
        ctx.revoke("seed")
        assert not ctx.has("seed")
        ctx.revert()
        assert ctx.require("seed") == 1

    def test_revoke_of_an_absent_name_reverts_cleanly(self) -> None:
        ctx = Context()
        ctx.revoke("absent")
        assert not ctx.has("absent")
        undone = ctx.revert()
        assert undone[0]["kind"] == CHANGE_REVOKE
        assert undone[0]["status"] == "reverted"

    def test_revert_keeps_a_seeded_name_no_component_touched(self) -> None:
        ctx = Context({"seed": 1})
        ctx.provide("other", 2)
        ctx.revert()
        assert ctx.require("seed") == 1
        assert not ctx.has("other")

    def test_revert_reports_provides_and_records_interleaved_newest_first(self) -> None:
        ctx = Context()
        ctx.provide("one", 1)
        ctx.record("written", lambda: None, {"kind": "disasm", "function_id": 1})
        ctx.provide("two", 2)
        undone = ctx.revert()
        assert [entry["kind"] for entry in undone] == [CHANGE_PROVIDE, "record", CHANGE_PROVIDE]
        assert [entry["description"] for entry in undone] == [
            "provide two",
            "written",
            "provide one",
        ]

    def test_subscribe_is_notified_with_name_and_kind(self) -> None:
        ctx = Context()
        seen: list[tuple[str, str]] = []
        ctx.subscribe(lambda name, kind: seen.append((name, kind)))
        ctx.provide("a", 1)
        ctx.revoke("a")
        assert seen == [("a", CHANGE_PROVIDE), ("a", CHANGE_REVOKE)]

    def test_unsubscribe_stops_the_notifications(self) -> None:
        ctx = Context()
        seen: list[tuple[str, str]] = []
        unsubscribe = ctx.subscribe(lambda name, kind: seen.append((name, kind)))
        ctx.provide("a", 1)
        unsubscribe()
        unsubscribe()
        ctx.provide("b", 2)
        ctx.revert()
        assert seen == [("a", CHANGE_PROVIDE)]

    def test_revert_notifies_subscribers_with_the_restored_direction(self) -> None:
        ctx = Context({"seed": 1})
        seen: list[tuple[str, str]] = []
        ctx.subscribe(lambda name, kind: seen.append((name, kind)))
        ctx.provide("seed", 2)
        ctx.provide("other", 3)
        seen.clear()
        ctx.revert()
        assert seen == [("other", CHANGE_REVOKE), ("seed", CHANGE_PROVIDE)]


class TestRegistry:
    def test_builtins_register_in_tree(self) -> None:
        names = [component.name for component in components.components()]
        assert names == [
            pipeline.COMPONENT_PREPARE,
            pipeline.COMPONENT_READ_TRACE,
            pipeline.COMPONENT_DECOMPILE,
            pipeline.COMPONENT_SEARCH_FUNCTIONALITY,
            pipeline.COMPONENT_RESOLVE_NAMES,
            pipeline.COMPONENT_RETRIEVE_KNOWLEDGE,
            pipeline.COMPONENT_REWRITE,
            pipeline.COMPONENT_RENAME_VARIABLES,
            pipeline.COMPONENT_NAME_VARIABLES,
            pipeline.COMPONENT_SUMMARIZE,
            pipeline.COMPONENT_STORE,
        ]

    def test_register_component_adds_it(self) -> None:
        probe = Component("probe", frozenset(), frozenset(), _noop)
        components.register_component(probe)
        assert "probe" in [component.name for component in components.components()]

    def test_duplicate_name_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("probe", "pipeline_plugins:PROBE_COMPONENT"))
        components.refresh_components()
        with pytest.raises(components.RegistryError):
            components.register_component(
                Component("probe", frozenset(), frozenset(), _noop), origin="test"
            )

    def test_registering_a_non_component_raises(self) -> None:
        with pytest.raises(components.RegistryError):
            components.register_component("nope")  # type: ignore[arg-type]

    def test_unregister_withdraws_only_that_component(self) -> None:
        components.register_component(Component("probe", frozenset(), frozenset(), _noop))
        components.register_component(Component("other", frozenset(), frozenset(), _noop))
        components.unregister_component("probe")
        names = [component.name for component in components.components()]
        assert "probe" not in names
        assert "other" in names
        assert pipeline.COMPONENT_PREPARE in names

    def test_unregister_an_unknown_component_raises(self) -> None:
        with pytest.raises(components.RegistryError):
            components.unregister_component("nope")

    def test_refresh_drops_a_registered_extra(self) -> None:
        components.register_component(Component("probe", frozenset(), frozenset(), _noop))
        names = [component.name for component in components.refresh_components()]
        assert "probe" not in names
        assert pipeline.COMPONENT_PREPARE in names

    def test_entry_point_component_is_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("probe", "pipeline_plugins:PROBE_COMPONENT"))
        names = [component.name for component in components.refresh_components()]
        assert "probe" in names

    def test_entry_point_factory_is_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("made", "pipeline_plugins:make_component"))
        names = [component.name for component in components.refresh_components()]
        assert "factory-made" in names

    def test_entry_point_without_a_module_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", ""))
        assert pipeline.COMPONENT_PREPARE in [c.name for c in components.refresh_components()]

    def test_entry_point_with_an_unimportable_module_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "no_such_plugin_module:thing"))
        assert pipeline.COMPONENT_PREPARE in [c.name for c in components.refresh_components()]

    def test_entry_point_with_a_missing_attribute_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "pipeline_plugins:absent_attr"))
        assert pipeline.COMPONENT_PREPARE in [c.name for c in components.refresh_components()]

    def test_entry_point_that_is_not_a_component_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "pipeline_plugins:NOT_A_COMPONENT"))
        assert pipeline.COMPONENT_PREPARE in [c.name for c in components.refresh_components()]

    def test_entry_point_with_a_broken_factory_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "pipeline_plugins:broken_factory"))
        assert pipeline.COMPONENT_PREPARE in [c.name for c in components.refresh_components()]

    def test_entry_point_returning_the_wrong_type_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "pipeline_plugins:returns_wrong_type"))
        assert pipeline.COMPONENT_PREPARE in [c.name for c in components.refresh_components()]

    def test_a_broken_registration_is_skipped_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "no_such_plugin_module:thing"))
        with caplog.at_level(logging.WARNING):
            components.refresh_components()
        assert "skipping broken reportal.components registration" in caplog.text

    def test_entry_point_duplicating_a_builtin_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("dup", "pipeline_plugins:DUPLICATE_PREPARE"))
        with pytest.raises(components.RegistryError):
            components.refresh_components()


def _register_hmr(monkeypatch: pytest.MonkeyPatch, directory: Path, version: str) -> str:
    """Write the probe module at *version* and register it as an entry point."""
    module_name = _write_hmr_module(directory, version)
    _patch_entry_points(monkeypatch, _EntryPoint("hmr-probe", f"{module_name}:PROBE"))
    components.refresh_components()
    return module_name


def _entry(name: str) -> components.Registration:
    entry = next((item for item in components.registrations() if item.component.name == name), None)
    assert entry is not None
    return entry


class TestUniqueProviders:
    """The paper's precondition: one writer per context name."""

    def test_a_single_provider_is_accepted(self) -> None:
        components.assert_unique_providers(
            [
                components.Component("a", frozenset(), frozenset({"thing"}), lambda ctx: None),
                components.Component("b", frozenset({"thing"}), frozenset(), lambda ctx: None),
            ]
        )

    def test_two_providers_of_one_name_are_refused(self) -> None:
        first = components.Component("a", frozenset(), frozenset({"thing"}), lambda ctx: None)
        second = components.Component("b", frozenset(), frozenset({"thing"}), lambda ctx: None)
        try:
            components.assert_unique_providers([first, second])
        except components.RegistryError as exc:
            assert "thing" in str(exc)
            assert "'a'" in str(exc) and "'b'" in str(exc)
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("two providers of one name must be refused")

    def test_the_built_ins_are_a_valid_composition(self) -> None:
        # The guard is not vacuous: it accepts the composition reportal ships.
        from reportal import pipeline

        components.assert_unique_providers(pipeline.builtin_components())


class TestRegistration:
    def test_builtin_records_its_declaring_module(self) -> None:
        entry = _entry(pipeline.COMPONENT_PREPARE)
        assert entry.origin == "builtin"
        assert entry.module_name == components.BUILTIN_MODULE
        assert entry.reloadable is True
        assert entry.entry_point is None

    def test_in_process_registration_is_not_reloadable(self) -> None:
        components.register_component(Component("probe", frozenset(), frozenset(), _noop))
        entry = _entry("probe")
        assert entry.reloadable is False
        assert entry.module_name is None

    def test_entry_point_records_module_and_key(
        self, monkeypatch: pytest.MonkeyPatch, hmr: Path
    ) -> None:
        module_name = _register_hmr(monkeypatch, hmr, "v1")
        entry = _entry("hmr-probe")
        assert entry.module_name == module_name
        assert entry.entry_point == "hmr-probe"
        assert entry.reloadable is True
        assert entry.origin == f"entry point 'hmr-probe' ({module_name}:PROBE)"

    def test_reloadable_without_a_module_raises(self) -> None:
        with pytest.raises(components.RegistryError):
            components.register_component(
                Component("probe", frozenset(), frozenset(), _noop), reloadable=True
            )


class TestReload:
    def test_reload_picks_up_changed_code(self, monkeypatch: pytest.MonkeyPatch, hmr: Path) -> None:
        _register_hmr(monkeypatch, hmr, "v1")
        log: list[str] = []
        ctx = Context({"hmr.log": log})
        _entry("hmr-probe").component.effect(ctx)
        assert ctx.require("hmr.value") == "v1"

        _write_hmr_module(hmr, "v2")
        report = components.reload_component("hmr-probe")
        assert report["reloaded"] is True
        assert report["changed"] is True
        assert report["module"] == _HMR_MODULE
        assert report["new_origin"].startswith("entry point 'hmr-probe'")

        _entry("hmr-probe").component.effect(ctx)
        assert ctx.require("hmr.value") == "v2"
        assert log == ["v1", "v2"]

    def test_reload_of_unchanged_code_reports_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, hmr: Path
    ) -> None:
        _register_hmr(monkeypatch, hmr, "v1")
        _write_hmr_module(hmr, "v1")
        assert components.reload_component("hmr-probe")["changed"] is False

    def test_reload_of_a_builtin_reports_its_module(self, monkeypatch: pytest.MonkeyPatch) -> None:
        report = components.reload_component(pipeline.COMPONENT_PREPARE)
        assert report["old_origin"] == "builtin"
        assert report["new_origin"] == "builtin"
        assert report["module"] == components.BUILTIN_MODULE
        assert report["changed"] is False

    def test_reload_of_an_unknown_name_raises_key_error(self) -> None:
        with pytest.raises(KeyError):
            components.reload_component("no-such-component")

    def test_reload_of_a_non_reloadable_component_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        components.register_component(Component("probe", frozenset(), frozenset(), _noop))
        with pytest.raises(components.NotReloadableError) as excinfo:
            components.reload_component("probe")
        assert excinfo.value.name == "probe"
        assert "no declaring module" in excinfo.value.reason

    def test_reload_of_a_dropped_declaration_raises(
        self, monkeypatch: pytest.MonkeyPatch, hmr: Path
    ) -> None:
        _register_hmr(monkeypatch, hmr, "v1")
        _write_hmr_module(hmr, "v2", declared=False)
        with pytest.raises(components.ComponentMissingError) as excinfo:
            components.reload_component("hmr-probe")
        assert excinfo.value.name == "hmr-probe"
        assert excinfo.value.module_name == _HMR_MODULE

    def test_reload_keeps_declaration_order(
        self, monkeypatch: pytest.MonkeyPatch, hmr: Path
    ) -> None:
        _register_hmr(monkeypatch, hmr, "v1")
        components.register_component(Component("probe", frozenset(), frozenset(), _noop))
        before = [component.name for component in components.components()]
        components.reload_component("hmr-probe")
        components.reload_component(pipeline.COMPONENT_PREPARE)
        assert [component.name for component in components.components()] == before

    def test_reload_replaces_the_entry_in_place(
        self, monkeypatch: pytest.MonkeyPatch, hmr: Path
    ) -> None:
        _register_hmr(monkeypatch, hmr, "v1")
        previous = _entry("hmr-probe").component
        _write_hmr_module(hmr, "v2")
        components.reload_component("hmr-probe")
        assert _entry("hmr-probe").component is not previous

    def test_reload_all_reports_per_name_and_skips_non_reloadables(
        self, monkeypatch: pytest.MonkeyPatch, hmr: Path
    ) -> None:
        _register_hmr(monkeypatch, hmr, "v1")
        components.register_component(Component("probe", frozenset(), frozenset(), _noop))
        _write_hmr_module(hmr, "v2")
        report = components.reload_all()
        reloaded = {entry["name"]: entry for entry in report["reloaded"]}
        assert reloaded["hmr-probe"]["changed"] is True
        assert reloaded[pipeline.COMPONENT_PREPARE]["changed"] is False
        assert report["count"] == len(report["reloaded"])
        assert report["changed"] == ["hmr-probe"]
        skipped = {entry["name"]: entry["reason"] for entry in report["skipped"]}
        assert "probe" in skipped
        assert "no declaring module" in skipped["probe"]

    def test_reload_all_without_extras_changes_nothing(self) -> None:
        report = components.reload_all()
        assert report["changed"] == []
        assert report["skipped"] == []
        assert report["count"] == len(pipeline.builtin_components())


class TestNotifyReentrancy:
    def test_an_unsubscribe_inside_notify_keeps_every_subscriber(self) -> None:
        from collections.abc import Callable

        ctx = Context()
        seen: list[tuple[str, str]] = []
        stops: list[Callable[[], None]] = []

        def dropping(name: str, kind: str) -> None:
            seen.append((name, kind))
            for stop in list(stops):
                stop()

        stops.append(ctx.subscribe(dropping))
        ctx.subscribe(lambda name, kind: seen.append((name, kind)))
        ctx.provide("a", 1)

        assert seen == [("a", CHANGE_PROVIDE), ("a", CHANGE_PROVIDE)]


class TestDerivedRealm:
    def test_a_derived_context_reads_the_parent_and_writes_its_own(self) -> None:
        parent = Context({"seed": 1})
        child = parent.derive()
        assert child.parent is parent
        assert child.require("seed") == 1
        assert child.names() == frozenset({"seed"})
        child.provide("own", 2)
        assert child.require("own") == 2
        assert not parent.has("own")
        assert parent.names() == frozenset({"seed"})

    def test_two_derived_contexts_resolve_one_name_differently(self) -> None:
        parent = Context({"name": "outer"})
        first, second = parent.derive({"name": "first"}), parent.derive({"name": "second"})
        assert (first.require("name"), second.require("name")) == ("first", "second")
        assert parent.require("name") == "outer"

    def test_a_child_change_reaches_the_parent_subscriber(self) -> None:
        parent = Context()
        seen: list[tuple[str, str]] = []
        parent.subscribe(lambda name, kind: seen.append((name, kind)))
        parent.derive().provide("child", 1)
        assert seen == [("child", CHANGE_PROVIDE)]

    def test_dropping_a_derived_context_reverts_only_its_own_journal(self) -> None:
        parent = Context()
        child = parent.derive()
        child.provide("child", 1)
        parent.provide("parent", 2)
        undo = [entry["description"] for entry in child.drop()]
        assert undo == ["provide child"]
        assert child.dropped()
        assert not child.has("parent")
        assert parent.require("parent") == 2

    def test_dropping_twice_changes_nothing(self) -> None:
        child = Context().derive()
        child.provide("a", 1)
        assert len(child.drop()) == 1
        assert child.drop() == []


class TestInterception:
    def test_a_hook_wraps_every_read(self) -> None:
        ctx = Context({"count": 1})
        ctx.intercept("count", lambda value: value + 1)
        assert ctx.require("count") == 2
        assert ctx.get("count") == 2

    def test_hooks_apply_in_install_order(self) -> None:
        ctx = Context({"v": "x"})
        ctx.intercept("v", lambda value: value + "1")
        ctx.intercept("v", lambda value: value + "2")
        assert ctx.require("v") == "x12"

    def test_revert_uninstalls_the_hook(self) -> None:
        ctx = Context({"count": 1})
        ctx.intercept("count", lambda value: value + 1)
        ctx.revert()
        assert ctx.require("count") == 1
        assert ctx.effects() == ()

    def test_removing_the_hook_early_and_twice_is_a_noop(self) -> None:
        ctx = Context({"count": 1})
        remove = ctx.intercept("count", lambda value: value + 1)
        remove()
        remove()
        assert ctx.require("count") == 1

    def test_a_parent_hook_applies_to_a_derived_read(self) -> None:
        parent = Context({"count": 1})
        parent.intercept("count", lambda value: value * 10)
        assert parent.derive().require("count") == 10


class TestLoadSteps:
    def test_an_empty_context_loads_nothing(self) -> None:
        assert Context().load() is None

    def test_the_load_is_a_chain_that_ends_in_nothing(self) -> None:
        ctx = Context()
        ctx.provide("first", 1)
        ctx.provide("second", 2)
        step = ctx.load()
        assert step is not None
        assert [step.effect.description, step.rest.effect.description if step.rest else ""] == [
            "provide first",
            "provide second",
        ]
        assert step.rest is not None and step.rest.end()
        assert step.context is ctx

    def test_walking_the_load_applies_the_inverses_newest_first(self) -> None:
        ctx = Context()
        ctx.provide("first", 1)
        ctx.provide("second", 2)
        order: list[str] = []
        steps: list[components.EffectStep] = []
        step = ctx.load()
        while step is not None:
            steps.append(step)
            step = step.rest
        for item in reversed(steps):
            order.append(item.effect.description)
            item.inverse()
        assert order == ["provide second", "provide first"]
        assert ctx.names() == frozenset()


class TestFiber:
    def test_a_fiber_commits_the_names_it_provides(self) -> None:
        component = _component("fiber", provides={"fiber-out"}, effect=_providing("fiber-out", 1))
        fiber = components.Fiber(component)
        fiber.activate()
        assert fiber.state == components.FIBER_ACTIVE
        assert fiber.owner("fiber-out") is fiber
        assert fiber.provided() == {"fiber-out": fiber}
        assert fiber.context.require("fiber-out") == 1

    def test_a_child_fiber_reads_the_parent_realm_and_owns_its_value(self) -> None:
        parent = components.Fiber(
            _component("root", provides={"root-out"}, effect=_providing("root-out", 1))
        )
        parent.activate()
        child = parent.spawn(
            _component("child", provides={"child-out"}, effect=_providing("child-out", 2))
        )
        child.activate()
        assert child.context.parent is parent.context
        assert child.context.require("root-out") == 1
        assert child.owner("root-out") is parent
        assert child.owner("child-out") is child

    def test_retiring_a_fiber_reverts_its_realm_and_children(self) -> None:
        parent = components.Fiber(
            _component("root", provides={"root-out"}, effect=_providing("root-out", 1))
        )
        parent.activate()
        child = parent.spawn(
            _component("child", provides={"child-out"}, effect=_providing("child-out", 2))
        )
        child.activate()
        order: list[str] = []
        parent.component = Component(
            "root",
            frozenset(),
            frozenset({"root-out"}),
            parent.component.effect,
            revert=lambda ctx: order.append("root"),
        )
        child.component = Component(
            "child",
            frozenset(),
            frozenset({"child-out"}),
            child.component.effect,
            revert=lambda ctx: order.append("child"),
        )
        handle = parent.retire()
        assert order == ["child", "root"]
        assert handle.done()
        assert parent.state == components.FIBER_DISPOSED
        assert child.state == components.FIBER_DISPOSED
        assert parent.context.names() == frozenset()

    def test_retire_is_idempotent_and_returns_one_handle(self) -> None:
        fiber = components.Fiber(_component("one"))
        first = fiber.retire()
        second = fiber.retire()
        assert first is second
        assert first.result()["status"] == components.FIBER_DISPOSED

    def test_activating_twice_is_refused(self) -> None:
        fiber = components.Fiber(_component("one"))
        fiber.activate()
        with pytest.raises(components.FiberStateError):
            fiber.activate()

    def test_spawning_after_retirement_is_refused(self) -> None:
        fiber = components.Fiber(_component("one"))
        fiber.retire()
        with pytest.raises(components.FiberStateError):
            fiber.spawn(_component("child"))

    def test_a_failing_effect_reports_through_the_caller(self) -> None:
        def boom(_ctx: Context) -> None:
            raise RuntimeError("no")

        fiber = components.Fiber(_component("boom", effect=boom))
        with pytest.raises(RuntimeError):
            fiber.activate()
        assert fiber.state == components.FIBER_PENDING

    def test_the_inertia_handle_reports_a_revert_failure(self) -> None:
        def bad_revert(_ctx: Context) -> None:
            raise RuntimeError("cannot undo")

        fiber = components.Fiber(
            Component("one", frozenset(), frozenset(), lambda _ctx: None, revert=bad_revert)
        )
        fiber.activate()
        outcome = fiber.retire().result()
        assert outcome["reverted"] is False
        assert "cannot undo" in outcome["detail"]

    def test_context_spawn_derives_a_realm(self) -> None:
        ctx = Context({"seed": 1})
        fiber = ctx.spawn(_component("spawned", provides={"out"}, effect=_providing("out", 2)))
        assert fiber.context.parent is ctx
        fiber.activate()
        assert ctx.has("seed")
        assert not ctx.has("out")
        assert fiber.context.require("out") == 2
        assert fiber.retire().done()


class TestFiberEdges:
    def test_a_bound_none_is_a_value_not_a_default(self) -> None:
        ctx = Context({"none": None})
        assert ctx.has("none")
        assert ctx.get("none", "fallback") is None

    def test_an_unowned_name_has_no_owner_fiber(self) -> None:
        fiber = components.Fiber(_component("lonely"))
        assert fiber.owner("nothing") is None

    def test_a_pending_inertia_has_no_result_yet(self) -> None:
        fiber = components.Fiber(_component("one"))
        handle = components.Inertia(fiber)
        assert not handle.done()
        with pytest.raises(RuntimeError):
            handle.result()

    def test_retiring_a_fiber_that_never_activated_runs_nothing(self) -> None:
        fiber = components.Fiber(_component("one"))
        outcome = fiber.retire().result()
        assert outcome["reverted"] is None
        assert outcome["detail"] == ""

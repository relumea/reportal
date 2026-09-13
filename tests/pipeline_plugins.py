"""Plugin surface the component-registry tests load through entry points."""

from __future__ import annotations

from reportal.components import Component

# A well-formed component registered by value.
PROBE_COMPONENT = Component(
    name="probe",
    requires=frozenset(),
    provides=frozenset({"probe_value"}),
    effect=lambda ctx: ctx.provide("probe_value", 1),
)


def make_component() -> Component:
    """A factory an entry point may name instead of a component value."""
    return Component(
        name="factory-made",
        requires=frozenset(),
        provides=frozenset(),
        effect=lambda ctx: None,
    )


# A registration claiming a built-in name: the registry must reject it.
DUPLICATE_PREPARE = Component(
    name="prepare",
    requires=frozenset(),
    provides=frozenset(),
    effect=lambda ctx: None,
)


def broken_factory() -> Component:
    """A factory that raises while the registry resolves it."""
    raise RuntimeError("factory exploded")


def returns_wrong_type() -> str:
    """A factory that returns something that is not a component."""
    return "not a component"


NOT_A_COMPONENT = 42

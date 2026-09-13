"""Plugin surface the model-registry tests load through entry points."""

from __future__ import annotations

from reportal.models import KIND_LLM, Model


def _available() -> bool:
    return True


def probe_model() -> Model:
    """A registered model the entry-point tests resolve, directly or as a factory."""
    return Model(
        name="plugin-probe",
        kind=KIND_LLM,
        version="1.0",
        description="a plugin model",
        available=_available,
    )


PROBE_MODEL = probe_model()

# A factory named by an entry point; discovery calls it.
PROBE_FACTORY = probe_model

# A model claiming a built-in name: the registry must reject it.
IMPOSTOR_MODEL = Model(name="rebrew", kind=KIND_LLM, description="claims the built-in name")

# A bare value that is not a model.
NOT_A_MODEL = 42

"""The local model registry: which part produced a stored result.

The hosted portal runs every analysis under a named model (``binnet-0.7``,
``binnet-1.0``) and can re-run one on a newer model.  reportal has no single
model: a stored result comes from the ``rebrew`` engine, from one decompiler
backend, from the configured LLM model, or from the optional similarity extra.
This module names those parts as one registry, so an analysis records which one
produced it and a caller can re-run the LLM-backed artifacts under a different
model.

A model is a :class:`Model`: a name, a kind, a version, a description, an
``available()`` check and the reason it is not.  The built-ins are the engine
(kind ``engine``), each decompiler backend (``decompiler``), the configured
bridge model (``llm``, or the single :data:`UNCONFIGURED_MODEL` entry when no
endpoint is set) and the optional similarity extra (``similarity``).  The
registry mirrors :mod:`reportal.graph_backends`: built-ins are declared in-tree
by :func:`builtin_models`, a third party declares an entry point in the
:data:`MODEL_ENTRY_POINT_GROUP` group whose value is ``module:attr`` naming a
:class:`Model` or a zero-argument factory returning one, a broken registration
is skipped with a warning, and a duplicate name is a :class:`RegistryError`.

:func:`upgrade_analysis` is the one writer.  It re-runs the LLM-backed
artifacts an analysis already stored (a summary, inline comments, type
suggestions, identifier renames) under a named ``llm`` model, journals every
artifact it replaces and records the new model on the analysis row, so the
before/after pair is kept by the action journal and a revert puts the previous
payloads back.  A function whose re-run fails is reported in ``skipped`` with
its reason and leaves its stored artifact alone, so one bad response never
strands a half-upgraded analysis.
"""

from __future__ import annotations

import importlib.metadata
import sqlite3
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from reportal import engines, journal, llm, plugins, renames, similarity, store
from reportal.plugins import RegistryError as RegistryError

# Model kinds.  The kind decides what a caller may do with an entry: only an
# `llm` model can be the target of an upgrade, because it is the one that
# re-runs a stored artifact.
KIND_ENGINE = "engine"
KIND_DECOMPILER = "decompiler"
KIND_LLM = "llm"
KIND_SIMILARITY = "similarity"
KINDS: tuple[str, ...] = (KIND_ENGINE, KIND_DECOMPILER, KIND_LLM, KIND_SIMILARITY)

# Entry-point group third-party models register in.
MODEL_ENTRY_POINT_GROUP = "reportal.models"

# Origin label a built-in registration reports.
BUILTIN_ORIGIN = plugins.BUILTIN_ORIGIN

# Package names the engine and similarity entries report a version for.
ENGINE_PACKAGE = "rebrew"
SIMILARITY_PACKAGE = "resembl"

# The name the registry gives the bridge when no endpoint is configured.  It is
# listed so a caller can see that the AI extras have no model behind them, and
# it is never available.
UNCONFIGURED_MODEL = "unconfigured"

# The stored artifact kinds an upgrade re-runs, in the order it reports them.
UPGRADE_KINDS: tuple[str, ...] = (
    llm.AI_KIND_SUMMARY,
    llm.AI_KIND_COMMENTS,
    llm.AI_KIND_TYPES,
    renames.RENAMES_KIND,
)

# Longest model name accepted from a caller.
MAX_MODEL_NAME = 128

# How many functions one upgrade re-runs when the caller names no bound, and the
# hard cap on what it may ask for.
DEFAULT_UPGRADE_LIMIT = 25
MAX_UPGRADE_LIMIT = 200

# What the engine entry reports when the package is importable but has no
# distribution metadata to read a version from.
UNKNOWN_VERSION = "unknown"

_THRESHOLD_NOTE = "reportal re-runs the LLM-backed artifacts; it never re-analyses the binary"


class ModelError(Exception):
    """Base class for a rejected model operation."""


class UnknownModelError(ModelError, LookupError):
    """No model is registered under a requested name; the API answers 404."""


class InvalidModelError(ModelError, ValueError):
    """A model name or bound is unusable; the API answers 400."""


class NotUpgradeableError(ModelError, ValueError):
    """The named model is not an ``llm`` model, so it cannot re-run an artifact."""


def _never() -> bool:
    """The availability of an entry that is listed only to be named."""
    return False


def _always_available() -> bool:
    """The availability of a model that is always there."""
    return True


def _no_reason() -> str:
    """The reason an available model reports; it is never used."""
    return ""


@dataclass(frozen=True)
class Model:
    """One thing that can produce a stored result.

    ``available`` reports whether it can run right now and ``unavailable_reason``
    is the fixed, actionable detail a caller gets when it cannot.  A third-party
    model supplies both; the built-ins probe the engine, the bridge and the
    optional extra.
    """

    name: str
    kind: str
    version: str = ""
    description: str = ""
    available: Callable[[], bool] = _always_available
    unavailable_reason: Callable[[], str] = _no_reason

    def describe(self) -> dict[str, Any]:
        """The registry report: name, kind, version and availability."""
        is_available = self.available()
        return {
            "name": self.name,
            "kind": self.kind,
            "version": self.version,
            "available": is_available,
            "unavailable_reason": "" if is_available else self.unavailable_reason(),
            "description": self.description,
        }


# ── Built-in models ────────────────────────────────────────────────


def _distribution_version(package: str) -> str:
    """The installed distribution version of *package*, or ``unknown``."""
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return UNKNOWN_VERSION


def engine_model() -> Model:
    """The ``rebrew`` engine: what produces a fingerprint, disassembly or scan."""
    engine = engines.get_engine()

    def reason() -> str:
        return engines.ENGINE_UNAVAILABLE_HINT

    return Model(
        name=ENGINE_PACKAGE,
        kind=KIND_ENGINE,
        version=_distribution_version(ENGINE_PACKAGE),
        description="the in-process rebrew engine: fingerprints, disassembly, scans, decompilation",
        available=engine.available,
        unavailable_reason=reason,
    )


def decompiler_models() -> tuple[Model, ...]:
    """One entry per decompiler backend the engine accepts."""
    engine = engines.get_engine()

    def reason() -> str:
        return engines.ENGINE_UNAVAILABLE_HINT

    return tuple(
        Model(
            name=backend,
            kind=KIND_DECOMPILER,
            version=_distribution_version(ENGINE_PACKAGE),
            description=f"the {backend} decompiler backend, reached through rebrew",
            available=engine.available,
            unavailable_reason=reason,
        )
        for backend in sorted(engines.DECOMPILER_BACKENDS)
    )


def llm_model() -> Model:
    """The configured bridge model, or the single unconfigured placeholder."""
    client = llm.get_client()
    if not client.available():
        return Model(
            name=UNCONFIGURED_MODEL,
            kind=KIND_LLM,
            description=(
                "no chat-completions endpoint is configured, so no AI artifact can be produced"
            ),
            available=_never,
            unavailable_reason=lambda: llm.UNAVAILABLE_DETAIL,
        )
    return Model(
        name=client.model,
        kind=KIND_LLM,
        description="the configured OpenAI-compatible chat-completions model",
        available=client.available,
        unavailable_reason=lambda: llm.UNAVAILABLE_DETAIL,
    )


def similarity_model() -> Model:
    """The optional assembly-similarity extra behind local matching."""
    return Model(
        name=SIMILARITY_PACKAGE,
        kind=KIND_SIMILARITY,
        version=_distribution_version(SIMILARITY_PACKAGE),
        description="the optional similarity extra: assembly-similarity scoring for a match run",
        available=similarity.available,
        unavailable_reason=lambda: (
            "the optional similarity extra is not installed: uv sync --extra similarity"
        ),
    )


def builtin_models() -> tuple[Model, ...]:
    """The in-tree models: the engine, its backends, the bridge and the extra."""
    return (engine_model(), *decompiler_models(), llm_model(), similarity_model())


# ── Registry ───────────────────────────────────────────────────────

_registry: dict[str, Model] = {}
_origins: dict[str, str] = {}
_builtins_loaded = False
_entry_points_loaded = False
_registry_lock = threading.RLock()


def register_model(model: Model, *, origin: str = BUILTIN_ORIGIN) -> None:
    """Register *model* under its own name.

    Raises :class:`RegistryError` for a malformed value or a name that is
    already taken, naming both origins (single-source discipline).
    """
    if not isinstance(model, Model):
        raise RegistryError(
            f"bad model registration from {origin}: expected a Model, got {type(model).__name__}"
        )
    if not model.name.strip():
        raise RegistryError(f"bad model registration from {origin}: empty name")
    if model.kind not in KINDS:
        raise RegistryError(
            f"bad model registration {model.name!r} from {origin}:"
            f" unknown kind {model.kind!r}; known kinds: {', '.join(KINDS)}"
        )
    if not callable(model.available) or not callable(model.unavailable_reason):
        raise RegistryError(
            f"bad model registration {model.name!r} from {origin}:"
            " available and unavailable_reason must be callable"
        )
    with _registry_lock:
        if model.name in _registry:
            raise RegistryError(
                f"duplicate model registration {model.name!r}: {origin} conflicts with"
                f" {_origins[model.name]} (single-source discipline)"
            )
        _registry[model.name] = model
        _origins[model.name] = origin


def models() -> tuple[Model, ...]:
    """Every registered model, built-ins first, in registration order."""
    _ensure_builtins()
    _ensure_entry_points()
    with _registry_lock:
        return tuple(_registry.values())


def unregister_model(name: str) -> None:
    """Withdraw the model registered as *name*.

    Raises :class:`RegistryError` for a name nothing holds.  Withdrawing a
    built-in lasts until the next :func:`refresh_models`.
    """
    _ensure_builtins()
    _ensure_entry_points()
    with _registry_lock:
        if name not in _registry:
            raise RegistryError(f"no model registration {name!r} to withdraw")
        del _registry[name]
        _origins.pop(name, None)


def refresh_models() -> tuple[Model, ...]:
    """Discard discovered models and re-run discovery.

    Built-ins are re-declared, which is what picks up a bridge that was
    configured or an extra that was installed after startup, and the entry-point
    group is scanned again.
    """
    global _builtins_loaded, _entry_points_loaded
    with _registry_lock:
        _registry.clear()
        _origins.clear()
        _builtins_loaded = False
        _entry_points_loaded = False
    return models()


def get_model(name: str) -> Model:
    """The model registered under *name*; raises :class:`UnknownModelError`."""
    _ensure_builtins()
    _ensure_entry_points()
    with _registry_lock:
        model = _registry.get(name)
        known = ", ".join(sorted(_registry)) or "none"
    if model is None:
        raise UnknownModelError(f"unknown model {name!r}; known models: {known}")
    return model


def describe() -> dict[str, Any]:
    """The registry as a payload: every model, the kinds and the re-run note."""
    rows = [model.describe() for model in models()]
    return {
        "models": rows,
        "count": len(rows),
        "kinds": list(KINDS),
        "upgrade_kinds": list(UPGRADE_KINDS),
        "note": _THRESHOLD_NOTE,
    }


def normalize_model_name(name: Any) -> str:
    """Validate a requested model name, raising :class:`InvalidModelError`."""
    if not isinstance(name, str) or not name.strip():
        raise InvalidModelError("model must be a non-empty string")
    trimmed = name.strip()
    if len(trimmed) > MAX_MODEL_NAME:
        raise InvalidModelError(f"model exceeds {MAX_MODEL_NAME} characters")
    return trimmed


def upgradeable_model(name: Any) -> Model:
    """Resolve *name* to the ``llm`` model an upgrade may run under."""
    model = get_model(normalize_model_name(name))
    if model.kind != KIND_LLM:
        raise NotUpgradeableError(
            f"model {model.name!r} is a {model.kind} model; only an llm model re-runs an artifact"
        )
    if not model.available():
        raise llm.LlmUnavailable(model.unavailable_reason() or llm.UNAVAILABLE_DETAIL)
    return model


def _ensure_builtins() -> None:
    """Load the in-tree models once."""
    global _builtins_loaded
    with _registry_lock:
        if _builtins_loaded:
            return
        _builtins_loaded = True
        for model in builtin_models():
            register_model(model, origin=BUILTIN_ORIGIN)


def _ensure_entry_points() -> None:
    """Load third-party models once, skipping a broken registration."""
    global _entry_points_loaded
    with _registry_lock:
        if _entry_points_loaded:
            return
        _entry_points_loaded = True
        for name, value, model in plugins.load(MODEL_ENTRY_POINT_GROUP, Model, "Model"):
            register_model(model, origin=plugins.origin(name, value))


# ── The upgrade ────────────────────────────────────────────────────


def normalize_function_ids(functions: Any) -> list[int] | None:
    """Validate an explicit function id list, or None when none was named."""
    if functions is None:
        return None
    if not isinstance(functions, Sequence) or isinstance(functions, (str, bytes)):
        raise InvalidModelError("functions must be a list of function ids")
    ids: list[int] = []
    for entry in functions:
        if isinstance(entry, bool) or not isinstance(entry, int):
            raise InvalidModelError("functions must be a list of function ids")
        ids.append(entry)
    return ids


def normalize_limit(limit: Any) -> int:
    """Validate the function bound, raising :class:`InvalidModelError`."""
    if limit is None:
        return DEFAULT_UPGRADE_LIMIT
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise InvalidModelError("limit must be an integer")
    if limit < 1 or limit > MAX_UPGRADE_LIMIT:
        raise InvalidModelError(f"limit must be between 1 and {MAX_UPGRADE_LIMIT}")
    return limit


def candidate_functions(
    conn: sqlite3.Connection,
    analysis_id: int,
    *,
    functions: Sequence[int] | None = None,
    limit: int = DEFAULT_UPGRADE_LIMIT,
) -> list[dict[str, Any]]:
    """The functions of one analysis that carry at least one stored AI artifact.

    An explicit *functions* list keeps the order it was given and ignores
    *limit*; without one the analysis's functions are taken in id order, up to
    *limit* candidates that have something to re-run.
    """
    if functions is not None:
        by_id = store.functions_by_ids(conn, functions)
        rows: list[dict[str, Any]] = []
        for function_id in functions:
            function = by_id.get(int(function_id))
            if function is None or int(function["analysis_id"]) != analysis_id:
                continue
            if _stored_kinds(conn, function_id):
                rows.append(function)
        return rows
    rows = []
    for function in store.list_functions(conn, analysis_id=analysis_id):
        if not _stored_kinds(conn, function["id"]):
            continue
        rows.append(function)
        if len(rows) >= limit:
            break
    return rows


def _stored_kinds(conn: sqlite3.Connection, function_id: int) -> list[str]:
    """The upgrade kinds this function already has stored, in upgrade order."""
    return [
        kind for kind in UPGRADE_KINDS if store.get_ai_artifact(conn, function_id, kind) is not None
    ]


def _rerun(
    conn: sqlite3.Connection, function_id: int, kind: str, client: llm.LlmClient
) -> dict[str, Any]:
    """Produce one fresh artifact payload for *kind* through the bridge.

    The renames kind goes through :mod:`reportal.renames` because its payload is
    the suggestion list the apply path reads; every other kind is the bridge's
    own normalized payload.
    """
    if kind == renames.RENAMES_KIND:
        result = renames.suggest_renames(conn, function_id=function_id, client=client)
        return {"suggestions": result["suggestions"]}
    stored = store.get_decompilation(conn, function_id)
    if stored is None:
        raise renames.NoDecompilationError(f"function {function_id} has no stored decompilation")
    return llm.AI_RUNNERS[kind](str(stored["code"]), client=client)


def upgrade_analysis(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    analysis_id: int,
    model: Any,
    client: llm.LlmClient | None = None,
    functions: Any = None,
    limit: Any = None,
) -> dict[str, Any]:
    """Re-run an analysis's stored LLM artifacts under one model.

    Every artifact replaced is journaled, so the caller's action can put the
    previous payloads back, and the analysis row records the model it ran under.
    A function whose re-run fails is reported in ``skipped`` and keeps its
    stored artifacts, so a bad model response does not strand a half-upgraded
    analysis.  Raises :class:`UnknownModelError`, :class:`NotUpgradeableError`,
    :class:`InvalidModelError` or :class:`reportal.llm.LlmUnavailable`.
    """
    resolved = upgradeable_model(model)
    name = resolved.name
    function_ids = normalize_function_ids(functions)
    bound = normalize_limit(limit)
    if client is None:
        configured = llm.get_client()
        # A client that already sends the named model is used as it is, which
        # keeps an injected transport (and a test's stub) in place; only a
        # different name needs the model-overridden client.
        client = configured if configured.model == name else llm.with_model(configured, name)
    before = str((store.get_analysis(conn, analysis_id) or {}).get("model") or "")
    candidates = candidate_functions(conn, analysis_id, functions=function_ids, limit=bound)
    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for function in candidates:
        function_id = int(function["id"])
        kinds = _stored_kinds(conn, function_id)
        done: list[str] = []
        for kind in kinds:
            try:
                payload = _rerun(conn, function_id, kind, client)
            except (llm.LlmError, renames.NoDecompilationError) as exc:
                skipped.append({"function_id": function_id, "reason": str(exc)})
                break
            journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, kind),
                description=f"replaced the {kind} artifact of function {function_id}",
            )
            store.set_ai_artifact(conn, function_id, kind, payload, name)
            done.append(kind)
        if done:
            applied.append({"function_id": function_id, "kinds": done})
    journal.journaled_rows(
        conn,
        log,
        table="analyses",
        where="id = ?",
        params=(analysis_id,),
        description=f"recorded model {name} on analysis {analysis_id}",
    )
    store.update_analysis(conn, analysis_id, model=name)
    return {
        "analysis_id": analysis_id,
        "from": before,
        "to": name,
        "candidates": len(candidates),
        "applied": applied,
        "skipped": skipped,
        "upgraded": len(applied),
        "note": _THRESHOLD_NOTE,
    }

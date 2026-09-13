"""MCP tool registry for reportal.

Every capability the stdio MCP server exposes is a :class:`Tool`: a name, a
description, an input JSON Schema, MCP annotations and a handler.  Built-in
tools are declared in-tree by :func:`builtin_tools`; a third party declares an
entry point in the :data:`TOOL_ENTRY_POINT_GROUP` group whose value is
``module:attr`` naming a :class:`Tool` or a zero-argument factory returning one.
Discovery mirrors ``reportal.components``: a broken registration is skipped
with a warning, and a duplicate name raises :class:`RegistryError`.

A handler receives the decoded ``arguments`` object and calls reportal's
internal functions directly (store, engines, pipeline, llm); it never makes an
HTTP request back into reportal.  An expected failure raises :class:`ToolError`,
which the server reports as an MCP tool error; the handler never decides how
the failure reaches the wire.
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

from reportal import (
    auto_mode,
    auto_store,
    auto_workers,
    behavior,
    bulk_actions,
    capabilities,
    comments,
    components,
    composition,
    conversations,
    data_types,
    details,
    diffview,
    effects,
    engines,
    families,
    filetypes,
    function_triage,
    graph,
    graph_backends,
    hardening,
    instance,
    journal,
    knowledge,
    lineage,
    llm,
    matching,
    pdf,
    pipeline,
    plugins,
    protocols,
    related,
    remediation,
    remote_ingest,
    renames,
    secrets,
    signatures,
    similarity,
    store,
    surface,
    threat,
    unstrip,
    zipcrypto,
)
from reportal._paths import WorkspaceNotFound, reports_dir
from reportal.plugins import RegistryError as RegistryError
from reportal.server import db
from reportal.surface import classified as _classified
from reportal.surface import journaled_data_type_write as _journal_data_type_write
from reportal.surface import journaled_signature_write as _journal_signature_write
from reportal.surface import store_lineage as _store_lineage


def _fail(_status: int, error: str, detail: str) -> Exception:
    """The MCP answer to a shared-helper failure: a tool error.

    A tool error carries no HTTP status, so the status a shared check passes is
    accepted and dropped.
    """
    return ToolError(error, detail)


def _family_error(exc: families.FamilyError) -> ToolError:
    """Map a family validation failure to a tool error."""
    error, detail = surface.family_detail(exc)
    return ToolError(error, detail)


# The shared checks, bound to this surface's error channel.
_binary_file = partial(surface.binary_file, fail=_fail)
_engine = partial(surface.engine, fail=_fail)
_project_context = partial(surface.project_context, fail=_fail)
_require_binary = partial(surface.require_binary, fail=_fail)

# Entry-point group third-party tools register in.
TOOL_ENTRY_POINT_GROUP = "reportal.mcp_tools"

# Origin label a built-in registration reports.
BUILTIN_ORIGIN = plugins.BUILTIN_ORIGIN

# The only disassembly format `disasm_cache` holds, so only this format is
# cached; a `hex` request runs the engine and leaves the cache untouched.
CACHEABLE_DISASM_FORMAT = "nasm"

# Functions decompiled by a struct recovery run when the caller names no limit.
DEFAULT_STRUCT_LIMIT = 50

# Scope of the matches a binary's match run replaces: every function of the
# binary, reached through its analyses.
_BINARY_MATCHES_WHERE = (
    "function_id IN (SELECT f.id FROM functions f JOIN analyses a ON a.id = f.analysis_id"
    " WHERE a.binary_id = ?)"
)

# Scope of the signature rows a binary's seed run replaces: one row per function.
_BINARY_SIGNATURES_WHERE = (
    "function_id IN (SELECT f.id FROM functions f JOIN analyses a ON a.id = f.analysis_id"
    " WHERE a.binary_id = ?)"
)

# Scope of the signature-history rows a binary's seed run appends.
_BINARY_SIGNATURE_HISTORY_WHERE = _BINARY_SIGNATURES_WHERE

# Error name an MCP client sees per data-type failure of `edit_data_type`,
# `import_data_types` and `export_data_types`.
_DATA_TYPE_TOOL_ERRORS: tuple[tuple[type[data_types.DataTypeError], str], ...] = (
    (data_types.NoScanError, "no-scan"),
    (data_types.UnknownDataTypeError, "data type not found"),
    (data_types.UnknownHistoryError, "history not found"),
    (data_types.UnknownMemberError, "member not found"),
    # An enum's named constants are its member entries, so their selector
    # failure shares the member code the catalogue documents.
    (data_types.UnknownValueError, "member not found"),
    (data_types.ExportExistsError, "export exists"),
    (data_types.InvalidIdentifierError, "invalid name"),
    (data_types.InvalidKindError, "invalid kind"),
    (data_types.InvalidSizeError, "invalid size"),
    (data_types.DuplicateNameError, "duplicate name"),
    (data_types.DuplicateMemberError, "duplicate member"),
    (data_types.DuplicateValueError, "duplicate member"),
    (data_types.EmptyStructError, "invalid member"),
    (data_types.InvalidMemberError, "invalid member"),
    (data_types.InvalidValueError, "invalid member"),
    (data_types.DefinitionError, "invalid definition"),
    (data_types.ExportParentMissingError, "invalid path"),
)

# Error name an MCP client sees per signature failure of `run_signature_import`,
# `edit_signature` and `export_signatures`.
_SIGNATURE_TOOL_ERRORS: tuple[tuple[type[signatures.SignatureError], str], ...] = (
    (signatures.UnknownSignatureError, "signature not found"),
    (signatures.UnknownHistoryError, "history not found"),
    (signatures.UnknownParameterError, "invalid index"),
    (signatures.InvalidIdentifierError, "invalid name"),
    (signatures.DuplicateParameterError, "duplicate parameter"),
    (signatures.InvalidTypeError, "invalid type"),
    (signatures.InvalidParameterError, "invalid parameter"),
    (signatures.ExportExistsError, "export exists"),
    (signatures.ExportParentMissingError, "invalid path"),
)

_log = logging.getLogger(__name__)


class ToolError(Exception):
    """A tool could not produce a result.

    ``error`` is a fixed, sanitized string and ``detail`` is the context; the
    pair is what the server serializes into an MCP tool error.
    """

    def __init__(self, error: str, detail: str = "") -> None:
        super().__init__(f"{error}: {detail}" if detail else error)
        self.error = error
        self.detail = detail


@dataclass(frozen=True)
class ToolAnnotations:
    """MCP behavior hints: read-only versus destructive."""

    read_only_hint: bool
    destructive_hint: bool


ToolHandler = Callable[[dict[str, Any]], Any]


@dataclass(frozen=True)
class Tool:
    """One MCP tool: its wire metadata plus the handler that runs it."""

    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: ToolAnnotations
    handler: ToolHandler


_REGISTRY: dict[str, Tool] = {}
_builtins_loaded = False
_entry_points_loaded = False


def register_tool(tool: Tool, *, origin: str = BUILTIN_ORIGIN) -> None:
    """Register *tool* under its own name.

    Raises :class:`RegistryError` for a malformed value or a name that is
    already taken, naming both origins (single-source discipline).
    """
    if not isinstance(tool, Tool):
        raise RegistryError(
            f"bad tool registration from {origin}: expected a Tool, got {type(tool).__name__}"
        )
    if not tool.name.strip():
        raise RegistryError(f"bad tool registration from {origin}: empty name")
    if not isinstance(tool.description, str) or not tool.description.strip():
        raise RegistryError(f"bad tool registration {tool.name!r} from {origin}: empty description")
    if not isinstance(tool.input_schema, dict):
        raise RegistryError(
            f"bad tool registration {tool.name!r} from {origin}: input_schema is not a dict"
        )
    if not isinstance(tool.annotations, ToolAnnotations):
        raise RegistryError(
            f"bad tool registration {tool.name!r} from {origin}:"
            " annotations is not a ToolAnnotations"
        )
    if not callable(tool.handler):
        raise RegistryError(
            f"bad tool registration {tool.name!r} from {origin}: handler is not callable"
        )
    if tool.name in _REGISTRY:
        raise RegistryError(
            f"duplicate tool registration {tool.name!r}: {origin} conflicts"
            " with an existing registration (single-source discipline)"
        )
    _REGISTRY[tool.name] = tool


def tools() -> tuple[Tool, ...]:
    """Every registered tool, built-ins first, in declaration order."""
    _ensure_builtins()
    _ensure_entry_points()
    return tuple(_REGISTRY.values())


def get_tool(name: str) -> Tool | None:
    """The registered tool named *name*, or None."""
    return next((tool for tool in tools() if tool.name == name), None)


def refresh_tools() -> tuple[Tool, ...]:
    """Discard discovered tools and re-run discovery.

    Built-ins are re-declared and the entry-point group is scanned again, which
    is how a long-lived process picks up a plugin installed after startup.
    """
    global _builtins_loaded, _entry_points_loaded
    _REGISTRY.clear()
    _builtins_loaded = False
    _entry_points_loaded = False
    return tools()


def _ensure_builtins() -> None:
    """Load the in-tree tools once."""
    global _builtins_loaded
    if _builtins_loaded:
        return
    _builtins_loaded = True
    for tool in builtin_tools():
        register_tool(tool, origin=BUILTIN_ORIGIN)


def _ensure_entry_points() -> None:
    """Load third-party tools once, skipping a broken registration."""
    global _entry_points_loaded
    if _entry_points_loaded:
        return
    _entry_points_loaded = True
    for name, value, tool in plugins.load(TOOL_ENTRY_POINT_GROUP, Tool, "Tool"):
        # A duplicate name is not skipped: two tools claiming one name is a
        # registry error, and the RegistryError says which registration lost.
        register_tool(tool, origin=plugins.origin(name, value))


# ── Connection and error helpers ───────────────────────────────────


# The workspace connection is the server's opener, so one place creates the
# schema on first use.
_open = db


def _require_function(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    function = store.get_function(conn, function_id)
    if function is None:
        raise ToolError("function not found", f"no function with id {function_id}")
    return function


def _run_engine[T](call: Callable[[], T]) -> T:
    """Run one engine call, mapping an engine failure to a tool error."""
    try:
        return call()
    except engines.EngineError as exc:
        raise ToolError("engine-error", str(exc)) from exc


def _stored_scan(
    conn: sqlite3.Connection, binary_id: int, kind: str, run_tool: str
) -> dict[str, Any]:
    """Return the stored scan of *kind*, or raise the stored-only no-scan error."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is not None:
        stored = store.get_scan(conn, analysis_id, kind)
        if stored is not None:
            return stored
    raise ToolError(
        "no-scan",
        f"no {kind} scan for binary {binary_id}; call the {run_tool} tool first",
    )


def _ai_artifact(
    conn: sqlite3.Connection, function_id: int, kind: str, run_tool: str
) -> dict[str, Any]:
    artifact = store.get_ai_artifact(conn, function_id, kind)
    if artifact is None:
        raise ToolError(
            "no-artifact",
            f"no {kind} artifact for function {function_id}; call the {run_tool} tool first",
        )
    return {"function_id": function_id, "kind": kind, **artifact}


# ── Journal helpers ────────────────────────────────────────────────


def _journaled_scan_run(
    conn: sqlite3.Connection, binary_id: int, kind: str, run: Callable[[], dict[str, Any]]
) -> dict[str, Any]:
    """Run one scan that stores itself through a journal; returns the attached result."""
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        return log.attach(journal.journaled_scan(conn, log, binary_id, kind, run))


def _journaled_scan_store(
    conn: sqlite3.Connection, binary_id: int, kind: str, result: dict[str, Any]
) -> dict[str, Any]:
    """Store one computed scan through a journal; returns the attached result."""
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        journal.journaled_scan_result(conn, log, binary_id, kind, result)
        return log.attach(result)


def _store_ai_artifact(function_id: int, kind: str) -> dict[str, Any]:
    """Compute one AI artifact through the configured LLM and store it.

    The model input is the function's stored decompilation, which is never
    generated here; without a configured endpoint the failure is
    ``llm-unavailable``.
    """
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        client = llm.get_client()
        if not client.available():
            raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL)
        stored = store.get_decompilation(conn, function_id)
        if stored is None:
            raise ToolError(
                "no-decompilation",
                f"function {function_id} has no stored decompilation;"
                " call the run_pipeline tool first",
            )
        try:
            payload = llm.AI_RUNNERS[kind](str(stored["code"]), client=client)
        except llm.LlmUnavailable as exc:
            raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL) from exc
        except llm.LlmError as exc:
            raise ToolError("llm-error", str(exc)) from exc
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, kind),
                description=f"replaced the {kind} artifact of function {function_id}",
            )
            store.set_ai_artifact(conn, function_id, kind, payload, client.model)
            if not before:
                journal.journaled_create(
                    log,
                    table="ai_artifacts",
                    key={"function_id": function_id, "kind": kind},
                    description=f"stored the {kind} artifact of function {function_id}",
                )
            return log.attach(
                {
                    "function_id": function_id,
                    "kind": kind,
                    "payload": payload,
                    "model": client.model,
                }
            )


# ── Argument helpers ───────────────────────────────────────────────


def _arg_int(arguments: dict[str, Any], key: str) -> int:
    value = arguments.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolError("invalid params", f"{key} must be an integer")
    return value


def _arg_str(arguments: dict[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ToolError("invalid params", f"{key} must be a non-empty string")
    return value


def _arg_optional_int(arguments: dict[str, Any], key: str, default: int) -> int:
    if key not in arguments or arguments[key] is None:
        return default
    value = arguments[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolError("invalid params", f"{key} must be an integer")
    return value


def _arg_optional_str(arguments: dict[str, Any], key: str, default: str = "") -> str:
    if key not in arguments or arguments[key] is None:
        return default
    value = arguments[key]
    if not isinstance(value, str):
        raise ToolError("invalid params", f"{key} must be a string")
    return value


def _arg_optional_number(arguments: dict[str, Any], key: str, default: float) -> float:
    if key not in arguments or arguments[key] is None:
        return default
    value = arguments[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ToolError("invalid params", f"{key} must be a number")
    return float(value)


def _arg_optional_bool(arguments: dict[str, Any], key: str, default: bool) -> bool:
    if key not in arguments or arguments[key] is None:
        return default
    value = arguments[key]
    if not isinstance(value, bool):
        raise ToolError("invalid params", f"{key} must be a boolean")
    return value


def _arg_optional_int_list(arguments: dict[str, Any], key: str) -> list[int] | None:
    """Return ``arguments[key]`` as a list of ints, or None when absent."""
    if key not in arguments or arguments[key] is None:
        return None
    value = arguments[key]
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in value
    ):
        raise ToolError("invalid params", f"{key} must be a list of integers")
    return [int(item) for item in value]


def _arg_str_list(arguments: dict[str, Any], key: str) -> list[str]:
    """Return ``arguments[key]`` as a list of strings, defaulting to []."""
    if key not in arguments or arguments[key] is None:
        return []
    value = arguments[key]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ToolError("invalid params", f"{key} must be a list of strings")
    return value


def _arg_comment_body(arguments: dict[str, Any]) -> str:
    """Return a comment body untrimmed, so ``comments`` owns the validation."""
    value = arguments.get("body")
    if not isinstance(value, str):
        raise ToolError("invalid comment", "body must be a string")
    return value


# ── Read tools ─────────────────────────────────────────────────────


def _tool_list_binaries(arguments: dict[str, Any]) -> dict[str, Any]:
    with contextlib.closing(_open()) as conn:
        return {"binaries": store.list_binaries(conn)}


def _tool_get_binary(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        return _require_binary(conn, binary_id)


def _tool_list_functions(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_optional_int(arguments, "binary_id", 0)
    analysis_id = _arg_optional_int(arguments, "analysis_id", 0)
    with contextlib.closing(_open()) as conn:
        if binary_id:
            _require_binary(conn, binary_id)
        functions = store.list_functions(
            conn,
            binary_id=binary_id or None,
            analysis_id=analysis_id or None,
        )
    return {"functions": functions}


def _tool_get_function(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        return _require_function(conn, function_id)


def _tool_get_fingerprint(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = store.get_fingerprint(conn, binary_id)
        if stored is not None:
            return stored
        path = _binary_file(conn, binary_id)
    return _run_engine(lambda: _engine().fingerprint(path))


def _tool_get_imports(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
    return _run_engine(lambda: _engine().imports(path))


def _tool_get_strings(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
    return _run_engine(lambda: _engine().strings(path))


def _tool_get_tags(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_optional_int(arguments, "binary_id", 0)
    with contextlib.closing(_open()) as conn:
        if binary_id:
            _require_binary(conn, binary_id)
            return {"tags": store.get_binary_tags(conn, binary_id)}
        return {"tags": store.list_tags(conn)}


def _tool_get_triage(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = _stored_scan(conn, binary_id, store.SCAN_KIND_TRIAGE, "run_triage")
        return _classified(conn, binary_id, stored)


def _tool_get_function_triage(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_FUNCTION_TRIAGE, "run_function_triage")


def _tool_get_report(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_REPORT, "run_report")


def _pdf_path(binary_id: int) -> Path:
    """Return the PDF report path of *binary_id*, raising a tool error outside a workspace."""
    try:
        return reports_dir(binary_id) / pdf.REPORT_PDF_NAME
    except WorkspaceNotFound as exc:
        raise ToolError("no-workspace", str(exc)) from exc


def _tool_get_pdf_status(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
    target = _pdf_path(binary_id)
    if not target.is_file():
        return {
            "binary_id": binary_id,
            "exists": False,
            "path": str(target),
            "bytes": 0,
            "pages": 0,
        }
    data = target.read_bytes()
    return {
        "binary_id": binary_id,
        "exists": True,
        "path": str(target),
        "bytes": len(data),
        "pages": pdf.page_count(data),
    }


def _tool_generate_pdf_report(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        target = _pdf_path(binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            previous = journal.read_bounded(target) if target.is_file() else None
            result = pdf.write_report(conn, binary_id=binary_id, path=target, generated=store.now())
            journal.journaled_file(log, target, previous=previous)
            return log.attach(result)


def _tool_get_structs(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_STRUCTS, "run_structs")


def _tool_list_data_types(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        model = [
            data_types.encode_type(row) for row in data_types.list_types(conn, binary_id=binary_id)
        ]
    return {"binary_id": binary_id, "count": len(model), "types": model}


def _data_type_tool_error(exc: data_types.DataTypeError) -> ToolError:
    """Map a data-type failure to the tool error an MCP client sees."""
    for kind, code in _DATA_TYPE_TOOL_ERRORS:
        if isinstance(exc, kind):
            return ToolError(code, str(exc))
    return ToolError("invalid data type", str(exc))


def _tool_import_data_types(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="data_types",
                where="binary_id = ?",
                params=(binary_id,),
                description=f"replaced the data types of binary {binary_id}",
            )
            history_before = journal.snapshot_rows(
                conn,
                table="data_type_history",
                where="binary_id = ?",
                params=(binary_id,),
            )
            try:
                summary = data_types.import_types(
                    conn, binary_id=binary_id, engine=engines.get_engine()
                )
            except data_types.DataTypeError as exc:
                raise _data_type_tool_error(exc) from exc
            journal.journaled_new_rows(
                conn,
                log,
                table="data_types",
                where="binary_id = ?",
                params=(binary_id,),
                before=before,
                key=("id",),
                description=f"imported a data type for binary {binary_id}",
            )
            journal.journaled_new_rows(
                conn,
                log,
                table="data_type_history",
                where="binary_id = ?",
                params=(binary_id,),
                before=history_before,
                key=("id",),
                description=f"data type history of binary {binary_id}",
            )
            return log.attach(summary)


def _apply_data_type_edit(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    type_edit: dict[str, Any],
    member: Any,
    add: Any,
    remove: Any,
    to_gap: Any,
    from_gap: Any,
    add_value: Any,
    edit_value: Any,
    remove_value: Any,
    delete: Any,
) -> dict[str, Any]:
    """Apply the one operation ``edit_data_type``'s arguments name."""
    if delete:
        if not data_types.delete_type(conn, data_type_id):
            raise ToolError("data type not found", f"no data type with id {data_type_id}")
        return {"data_type_id": data_type_id, "deleted": True}
    if type_edit:
        return data_types.update_type(conn, data_type_id, **type_edit)
    if add is not None:
        return data_types.add_member(conn, data_type_id, **_member_addition(add))
    if remove is not None:
        return data_types.remove_member(conn, data_type_id, **_member_removal(remove))
    if member is not None:
        return data_types.update_member(conn, data_type_id, **_member_edit(member))
    if to_gap is not None:
        return data_types.convert_to_gap(conn, data_type_id, **_gap_conversion(to_gap))
    if from_gap is not None:
        return data_types.convert_from_gap(conn, data_type_id, **_gap_restore(from_gap))
    if add_value is not None:
        return data_types.add_value(conn, data_type_id, **_value_addition(add_value))
    if edit_value is not None:
        return data_types.update_value(conn, data_type_id, **_value_edit(edit_value))
    return data_types.remove_value(conn, data_type_id, **_value_removal(remove_value))


def _tool_edit_data_type(arguments: dict[str, Any]) -> dict[str, Any]:
    data_type_id = _arg_int(arguments, "data_type_id")
    type_edit = _type_edit(arguments)
    member = arguments.get("member")
    add = arguments.get("add_member")
    remove = arguments.get("remove_member")
    to_gap = arguments.get("to_gap")
    from_gap = arguments.get("from_gap")
    add_value = arguments.get("add_value")
    edit_value = arguments.get("edit_value")
    remove_value = arguments.get("remove_value")
    delete = arguments.get("delete")
    if delete is not None and not isinstance(delete, bool):
        raise ToolError("invalid params", "delete must be a boolean")
    operations = bool(type_edit) + bool(member is not None) + bool(add is not None)
    operations += bool(remove is not None) + bool(to_gap is not None)
    operations += bool(from_gap is not None) + bool(add_value is not None)
    operations += bool(edit_value is not None) + bool(remove_value is not None) + bool(delete)
    if operations != 1:
        raise ToolError(
            "invalid params",
            "exactly one of name/kind/namespace/size, member, add_member, remove_member,"
            " to_gap, from_gap, add_value, edit_value, remove_value or delete is required",
        )
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"edited data type {data_type_id}",
                    lambda: _apply_data_type_edit(
                        conn,
                        data_type_id,
                        type_edit=type_edit,
                        member=member,
                        add=add,
                        remove=remove,
                        to_gap=to_gap,
                        from_gap=from_gap,
                        add_value=add_value,
                        edit_value=edit_value,
                        remove_value=remove_value,
                        delete=delete,
                    ),
                )
            except data_types.DataTypeError as exc:
                raise _data_type_tool_error(exc) from exc
            return log.attach(row)


def _type_edit(arguments: dict[str, Any]) -> dict[str, Any]:
    """Decode the type-level fields of ``edit_data_type``, absent ones left out."""
    edit: dict[str, Any] = {}
    for key in ("name", "kind", "namespace"):
        value = arguments.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ToolError("invalid params", f"{key} must be a string")
        edit[key] = value
    size = arguments.get("size")
    if size is not None:
        if isinstance(size, bool) or not isinstance(size, int):
            raise ToolError("invalid params", "size must be an integer")
        edit["size"] = size
    return edit


def _member_selector(value: dict[str, Any], key: str) -> dict[str, Any]:
    """Decode a member or enum-value selector object's name/index."""
    name = value.get("name")
    index = value.get("index")
    if name is not None and not isinstance(name, str):
        raise ToolError("invalid params", f"{key}.name must be a string")
    if index is not None and (isinstance(index, bool) or not isinstance(index, int)):
        raise ToolError("invalid params", f"{key}.index must be an integer")
    if name is None and index is None:
        raise ToolError("invalid params", f"{key} needs a name or an index")
    return {"name": name, "index": index}


def _member_addition(value: Any) -> dict[str, Any]:
    """Decode the ``add_member`` object of ``edit_data_type``.

    The object carries the full member shape (``name``, ``type``, ``pointer``,
    ``count``, ``bits``) and the position the member takes (``index`` or
    ``after``); the domain refuses both position fields at once.
    """
    if not isinstance(value, dict):
        raise ToolError("invalid params", "add_member must be an object")
    name = value.get("name")
    type_text = value.get("type")
    if not isinstance(name, str) or not name.strip():
        raise ToolError("invalid params", "add_member.name must be a non-empty string")
    if not isinstance(type_text, str) or not type_text.strip():
        raise ToolError("invalid params", "add_member.type must be a non-empty string")
    addition: dict[str, Any] = {"name": name, "type_text": type_text}
    pointer = value.get("pointer")
    if pointer is not None:
        if not isinstance(pointer, bool):
            raise ToolError("invalid params", "add_member.pointer must be a boolean")
        addition["pointer"] = pointer
    for key in ("count", "bits", "index"):
        field = value.get(key)
        if field is None:
            continue
        if isinstance(field, bool) or not isinstance(field, int):
            raise ToolError("invalid params", f"add_member.{key} must be an integer")
        addition[key] = field
    after = value.get("after")
    if after is not None:
        if not isinstance(after, str) or not after.strip():
            raise ToolError("invalid params", "add_member.after must be a non-empty string")
        addition["after"] = after
    return addition


def _member_removal(value: Any) -> dict[str, Any]:
    """Decode the ``remove_member`` selector of ``edit_data_type``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "remove_member must be an object")
    return _member_selector(value, "remove_member")


def _member_edit(value: Any) -> dict[str, Any]:
    """Decode the ``member`` edit object of ``edit_data_type``.

    ``new_pointer``, ``new_count`` and ``new_bits`` are tri-state: an absent key
    leaves the field as it is, an explicit ``null`` clears it.
    """
    if not isinstance(value, dict):
        raise ToolError("invalid params", "member must be an object")
    edit = _member_selector(value, "member")
    new_name = value.get("new_name")
    new_type = value.get("new_type")
    if new_name is not None and not isinstance(new_name, str):
        raise ToolError("invalid params", "member.new_name must be a string")
    if new_type is not None and not isinstance(new_type, str):
        raise ToolError("invalid params", "member.new_type must be a string")
    edit["new_name"] = new_name
    edit["new_type"] = new_type
    if "new_pointer" in value:
        pointer = value["new_pointer"]
        if pointer is not None and not isinstance(pointer, bool):
            raise ToolError("invalid params", "member.new_pointer must be a boolean")
        edit["new_pointer"] = pointer
    for key in ("new_count", "new_bits"):
        if key in value:
            field = value[key]
            if field is not None and (isinstance(field, bool) or not isinstance(field, int)):
                raise ToolError("invalid params", f"member.{key} must be an integer")
            edit[key] = field
    return edit


def _member_shape(value: dict[str, Any], key: str) -> dict[str, Any]:
    """Decode an object's optional pointer/count/bits, absent ones left out."""
    shape: dict[str, Any] = {}
    if "pointer" in value:
        pointer = value["pointer"]
        if pointer is not None and not isinstance(pointer, bool):
            raise ToolError("invalid params", f"{key}.pointer must be a boolean")
        shape["pointer"] = pointer
    for field_key in ("count", "bits"):
        if field_key in value:
            field = value[field_key]
            if field is not None and (isinstance(field, bool) or not isinstance(field, int)):
                raise ToolError("invalid params", f"{key}.{field_key} must be an integer")
            shape[field_key] = field
    return shape


def _gap_conversion(value: Any) -> dict[str, Any]:
    """Decode the ``to_gap`` object of ``edit_data_type``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "to_gap must be an object")
    conversion = _member_selector(value, "to_gap")
    size = value.get("size")
    if size is not None:
        if isinstance(size, bool) or not isinstance(size, int):
            raise ToolError("invalid params", "to_gap.size must be an integer")
        conversion["size"] = size
    return conversion


def _gap_restore(value: Any) -> dict[str, Any]:
    """Decode the ``from_gap`` object of ``edit_data_type``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "from_gap must be an object")
    restore = _member_selector(value, "from_gap")
    new_name = value.get("new_name")
    new_type = value.get("new_type")
    if not isinstance(new_name, str) or not new_name.strip():
        raise ToolError("invalid params", "from_gap.new_name must be a non-empty string")
    if not isinstance(new_type, str) or not new_type.strip():
        raise ToolError("invalid params", "from_gap.new_type must be a non-empty string")
    restore["new_name"] = new_name
    restore["new_type"] = new_type
    restore.update(_member_shape(value, "from_gap"))
    return restore


def _value_addition(value: Any) -> dict[str, Any]:
    """Decode the ``add_value`` object of ``edit_data_type``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "add_value must be an object")
    name = value.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ToolError("invalid params", "add_value.name must be a non-empty string")
    addition: dict[str, Any] = {"name": name}
    if "value" in value:
        addition["value"] = value["value"]
    return addition


def _value_edit(value: Any) -> dict[str, Any]:
    """Decode the ``edit_value`` object of ``edit_data_type``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "edit_value must be an object")
    edit = _member_selector(value, "edit_value")
    new_name = value.get("new_name")
    if new_name is not None and not isinstance(new_name, str):
        raise ToolError("invalid params", "edit_value.new_name must be a string")
    edit["new_name"] = new_name
    edit["new_value"] = value.get("new_value")
    if edit["new_name"] is None and edit["new_value"] is None:
        raise ToolError("invalid params", "edit_value needs a new_name or a new_value")
    return edit


def _value_removal(value: Any) -> dict[str, Any]:
    """Decode the ``remove_value`` selector of ``edit_data_type``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "remove_value must be an object")
    return _member_selector(value, "remove_value")


def _tool_export_data_types(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    path = _arg_str(arguments, "path")
    force = _arg_optional_bool(arguments, "force", False)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        target = Path(path)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            previous = journal.read_bounded(target) if target.is_file() else None
            try:
                summary = data_types.export_header(
                    conn, binary_id=binary_id, path=path, force=force
                )
            except data_types.DataTypeError as exc:
                raise _data_type_tool_error(exc) from exc
            journal.journaled_file(log, target, previous=previous)
            return log.attach(summary)


def _tool_get_data_type_history(arguments: dict[str, Any]) -> dict[str, Any]:
    data_type_id = _arg_int(arguments, "data_type_id")
    with contextlib.closing(_open()) as conn:
        history = data_types.list_history(conn, data_type_id)
        row = store.get_data_type(conn, data_type_id)
    binary_id = (
        int(row["binary_id"])
        if row is not None
        else (int(history[0]["binary_id"]) if history else None)
    )
    return {
        "data_type_id": data_type_id,
        "binary_id": binary_id,
        "exists": row is not None,
        "count": len(history),
        "history": history,
    }


def _tool_revert_data_type_history(arguments: dict[str, Any]) -> dict[str, Any]:
    data_type_id = _arg_int(arguments, "data_type_id")
    history_id = _arg_int(arguments, "history_id")
    with contextlib.closing(_open()) as conn:
        entry = data_types.get_history(conn, history_id)
        if entry is None or int(entry["data_type_id"]) != data_type_id:
            raise ToolError(
                "history not found", f"no history {history_id} for data type {data_type_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"reverted data type {data_type_id}",
                    lambda: data_types.revert_history(conn, data_type_id, history_id),
                )
            except data_types.DataTypeError as exc:
                raise _data_type_tool_error(exc) from exc
            return log.attach(result)


def _signature_tool_error(exc: signatures.SignatureError) -> ToolError:
    """Map a signature failure to the tool error an MCP client sees."""
    for kind, code in _SIGNATURE_TOOL_ERRORS:
        if isinstance(exc, kind):
            return ToolError(code, str(exc))
    return ToolError("invalid signature", str(exc))


def _require_signature(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """Return a function's stored signature, raising when it has none."""
    row = signatures.get_signature(conn, function_id)
    if row is None:
        raise ToolError("signature not found", f"no signature for function {function_id}")
    return row


def _tool_get_signature(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        return _require_signature(conn, function_id)


def _tool_list_signatures(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        model = signatures.list_signatures(conn, binary_id=binary_id)
    return {"binary_id": binary_id, "count": len(model), "signatures": model}


def _tool_get_signature_history(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        history = signatures.list_history(conn, function_id)
    return {"function_id": function_id, "count": len(history), "history": history}


def _tool_revert_signature_history(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    history_id = _arg_int(arguments, "history_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        entry = signatures.get_history(conn, history_id)
        if entry is None or int(entry["function_id"]) != function_id:
            raise ToolError(
                "history not found", f"no history {history_id} for function {function_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = _journal_signature_write(
                conn,
                log,
                function_id,
                f"reverted signature of {function_id}",
                lambda: signatures.revert_history(conn, function_id, history_id),
            )
            return log.attach(result)


def _tool_read_memory(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    address = _arg_int(arguments, "address")
    length = _arg_optional_int(arguments, "length", engines.MEMORY_READ_DEFAULT)
    kind = (
        _arg_optional_str(arguments, "kind", engines.MEMORY_ADDRESS_KIND_VA)
        or engines.MEMORY_ADDRESS_KIND_VA
    )
    if length <= 0 or length > engines.MEMORY_READ_MAX:
        raise ToolError("invalid length", f"length must be between 1 and {engines.MEMORY_READ_MAX}")
    if kind not in engines.MEMORY_ADDRESS_KINDS:
        raise ToolError("invalid kind", f"unsupported address kind: {kind}")
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
    engine = _engine()
    try:
        window = engine.read_memory(path, address=address, length=length, kind=kind)
    except engines.UnmappedAddressError as exc:
        raise ToolError("unmapped address", str(exc)) from exc
    except engines.EngineError as exc:
        raise ToolError("engine-error", str(exc)) from exc
    return {"binary_id": binary_id, **window}


def _tool_run_signature_import(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="function_signatures",
                where=_BINARY_SIGNATURES_WHERE,
                params=(binary_id,),
                description=f"replaced the signatures of binary {binary_id}",
            )
            history_before = journal.snapshot_rows(
                conn,
                table="signature_history",
                where=_BINARY_SIGNATURE_HISTORY_WHERE,
                params=(binary_id,),
            )
            summary = signatures.seed_signatures(conn, binary_id=binary_id)
            journal.journaled_new_rows(
                conn,
                log,
                table="function_signatures",
                where=_BINARY_SIGNATURES_WHERE,
                params=(binary_id,),
                before=before,
                key=("function_id",),
                description=f"imported a signature for binary {binary_id}",
            )
            journal.journaled_new_rows(
                conn,
                log,
                table="signature_history",
                where=_BINARY_SIGNATURE_HISTORY_WHERE,
                params=(binary_id,),
                before=history_before,
                key=("id",),
                description=f"signature history of binary {binary_id}",
            )
            return log.attach(summary)


def _signature_optional(value: dict[str, Any], key: str) -> Any:
    """Return one optional signature field: :data:`signatures.UNSET` when absent."""
    return value.get(key, signatures.UNSET)


def _signature_parameter_edit(value: Any) -> dict[str, Any]:
    """Decode the ``parameter`` edit object of ``edit_signature``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "parameter must be an object")
    index = value.get("index")
    type_text = value.get("type")
    name = value.get("name")
    if isinstance(index, bool) or not isinstance(index, int):
        raise ToolError("invalid params", "parameter.index must be an integer")
    if type_text is not None and not isinstance(type_text, str):
        raise ToolError("invalid params", "parameter.type must be a string")
    if name is not None and not isinstance(name, str):
        raise ToolError("invalid params", "parameter.name must be a string")
    edit: dict[str, Any] = {"index": index, "type_text": type_text, "name": name}
    for key in ("at", "kind"):
        field = _signature_optional(value, key)
        if field is not signatures.UNSET and field is not None and not isinstance(field, str):
            raise ToolError("invalid params", f"parameter.{key} must be a string or null")
        edit[key] = field
    bits = _signature_optional(value, "bits")
    if (
        bits is not signatures.UNSET
        and bits is not None
        and (isinstance(bits, bool) or not isinstance(bits, int))
    ):
        raise ToolError("invalid params", "parameter.bits must be an integer or null")
    edit["bits"] = bits
    return edit


def _signature_parameter_addition(value: Any) -> dict[str, Any]:
    """Decode the ``add_parameter`` object of ``edit_signature``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "add_parameter must be an object")
    type_text = value.get("type")
    name = value.get("name", "")
    index = value.get("index")
    if not isinstance(type_text, str) or not type_text.strip():
        raise ToolError("invalid params", "add_parameter.type must be a non-empty string")
    if not isinstance(name, str):
        raise ToolError("invalid params", "add_parameter.name must be a string")
    if index is not None and (isinstance(index, bool) or not isinstance(index, int)):
        raise ToolError("invalid params", "add_parameter.index must be an integer")
    addition: dict[str, Any] = {"type_text": type_text, "name": name, "index": index}
    for key in ("at", "kind"):
        field = value.get(key)
        if field is not None and not isinstance(field, str):
            raise ToolError("invalid params", f"add_parameter.{key} must be a string or null")
        addition[key] = field
    bits = value.get("bits")
    if bits is not None and (isinstance(bits, bool) or not isinstance(bits, int)):
        raise ToolError("invalid params", "add_parameter.bits must be an integer or null")
    addition["bits"] = bits
    return addition


def _signature_parameter_move(value: Any) -> dict[str, Any]:
    """Decode the ``move_parameter`` object of ``edit_signature``."""
    if not isinstance(value, dict):
        raise ToolError("invalid params", "move_parameter must be an object")
    index = value.get("index")
    to_index = value.get("to_index")
    for key, field in (("index", index), ("to_index", to_index)):
        if isinstance(field, bool) or not isinstance(field, int):
            raise ToolError("invalid params", f"move_parameter.{key} must be an integer")
    return {"index": index, "to_index": to_index}


def _tool_edit_signature(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    return_type = arguments.get("return_type")
    convention = arguments.get("calling_convention")
    parameter = arguments.get("parameter")
    add = arguments.get("add_parameter")
    remove = arguments.get("remove_parameter")
    move = arguments.get("move_parameter")
    delete = arguments.get("delete")
    if delete is not None and not isinstance(delete, bool):
        raise ToolError("invalid params", "delete must be a boolean")
    operations = bool(return_type is not None) + bool(convention is not None)
    operations += bool(parameter is not None) + bool(add is not None)
    operations += bool(remove is not None) + bool(move is not None) + bool(delete)
    if operations != 1:
        raise ToolError(
            "invalid params",
            "exactly one of return_type, calling_convention, parameter, add_parameter,"
            " remove_parameter, move_parameter or delete is required",
        )
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row: dict[str, Any]
                if delete:
                    if signatures.get_signature(conn, function_id) is None:
                        raise ToolError(
                            "signature not found", f"no signature for function {function_id}"
                        )

                    def remove_signature() -> dict[str, Any]:
                        signatures.delete_signature(conn, function_id)
                        return {"function_id": function_id, "deleted": True}

                    row = _journal_signature_write(
                        conn,
                        log,
                        function_id,
                        f"edited signature of {function_id}",
                        remove_signature,
                    )
                else:
                    _require_signature(conn, function_id)
                    if return_type is not None:
                        if not isinstance(return_type, str):
                            raise ToolError("invalid params", "return_type must be a string")
                        row = _journal_signature_write(
                            conn,
                            log,
                            function_id,
                            f"edited signature of {function_id}",
                            lambda: signatures.set_return_type(
                                conn, function_id, return_type=return_type
                            ),
                        )
                    elif convention is not None:
                        if not isinstance(convention, str):
                            raise ToolError("invalid params", "calling_convention must be a string")
                        row = _journal_signature_write(
                            conn,
                            log,
                            function_id,
                            f"edited signature of {function_id}",
                            lambda: signatures.set_calling_convention(
                                conn, function_id, calling_convention=convention
                            ),
                        )
                    elif parameter is not None:
                        edit = _signature_parameter_edit(parameter)
                        row = _journal_signature_write(
                            conn,
                            log,
                            function_id,
                            f"edited signature of {function_id}",
                            lambda: signatures.set_parameter(conn, function_id, **edit),
                        )
                    elif add is not None:
                        addition = _signature_parameter_addition(add)
                        row = _journal_signature_write(
                            conn,
                            log,
                            function_id,
                            f"edited signature of {function_id}",
                            lambda: signatures.add_parameter(conn, function_id, **addition),
                        )
                    elif move is not None:
                        reorder = _signature_parameter_move(move)
                        row = _journal_signature_write(
                            conn,
                            log,
                            function_id,
                            f"reordered a parameter of signature {function_id}",
                            lambda: signatures.move_parameter(conn, function_id, **reorder),
                        )
                    else:
                        if isinstance(remove, bool) or not isinstance(remove, int):
                            raise ToolError(
                                "invalid params", "remove_parameter must be an integer index"
                            )
                        row = _journal_signature_write(
                            conn,
                            log,
                            function_id,
                            f"edited signature of {function_id}",
                            lambda: signatures.remove_parameter(conn, function_id, index=remove),
                        )
            except signatures.SignatureError as exc:
                raise _signature_tool_error(exc) from exc
            return log.attach(row)


def _tool_export_signatures(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    path = _arg_str(arguments, "path")
    force = _arg_optional_bool(arguments, "force", False)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        target = Path(path)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            previous = journal.read_bounded(target) if target.is_file() else None
            try:
                summary = signatures.export_prototypes(
                    conn, binary_id=binary_id, path=path, force=force
                )
            except signatures.SignatureError as exc:
                raise _signature_tool_error(exc) from exc
            journal.journaled_file(log, target, previous=previous)
            return log.attach(summary)


def _tool_get_crypto_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_CRYPTO, "run_crypto_scan")


def _tool_get_pe_info(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_PE_INFO, "run_pe_info")


def _tool_get_filetype(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_FILETYPE, "run_filetype")


def _tool_get_security_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_SECURITY, "run_security_scan")


def _tool_get_capabilities(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_CAPABILITIES, "run_capabilities")


def _tool_get_secrets_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_SECRETS, "run_secrets_scan")


def _tool_get_protocols_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_PROTOCOLS, "run_protocols_scan")


def _tool_get_threat_report(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = _stored_scan(conn, binary_id, store.SCAN_KIND_THREAT, "run_threat_report")
        return _classified(conn, binary_id, stored)


def _tool_get_remediation(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_REMEDIATION, "run_remediation")


def _behavior_domain(arguments: dict[str, Any]) -> str | None:
    """Return the requested behavior domain, or None when none was named."""
    raw = arguments.get("domain")
    if raw is None:
        return None
    if not isinstance(raw, str) or raw not in behavior.BEHAVIOR_DOMAINS:
        raise ToolError("invalid domain", f"unknown behavior domain: {raw}")
    return raw


def _tool_get_behavior_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    domain = _behavior_domain(arguments)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if domain is not None:
            return _stored_scan(
                conn, binary_id, behavior.DOMAIN_SCAN_KINDS[domain], "run_behavior_scan"
            )
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        return {
            name: store.get_scan(conn, analysis_id, behavior.DOMAIN_SCAN_KINDS[name])
            if analysis_id is not None
            else None
            for name in behavior.BEHAVIOR_DOMAINS
        }


def _hardening_domain(arguments: dict[str, Any]) -> str | None:
    """Return the requested hardening domain, or None when none was named."""
    raw = arguments.get("domain")
    if raw is None:
        return None
    if not isinstance(raw, str) or raw not in hardening.HARDENING_DOMAINS:
        raise ToolError("invalid domain", f"unknown hardening domain: {raw}")
    return raw


def _tool_get_hardening_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    domain = _hardening_domain(arguments)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if domain is not None:
            return _stored_scan(
                conn, binary_id, hardening.DOMAIN_SCAN_KINDS[domain], "run_hardening_scan"
            )
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        return {
            name: store.get_scan(conn, analysis_id, hardening.DOMAIN_SCAN_KINDS[name])
            if analysis_id is not None
            else None
            for name in hardening.HARDENING_DOMAINS
        }


def _tool_get_unstrip(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_UNSTRIP, "run_unstrip")


def _tool_get_matches(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        return {"matches": store.list_matches(conn, function_id)}


def _tool_get_lineage(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if "other_binary_id" not in arguments or arguments["other_binary_id"] is None:
            return {
                "binary_id": binary_id,
                "comparisons": lineage.stored_comparisons(conn, binary_id),
            }
        other_binary_id = _arg_int(arguments, "other_binary_id")
        stored = lineage.stored_comparison(conn, binary_id, other_binary_id)
        if stored is None:
            raise ToolError(
                "no-scan",
                f"no lineage comparison of binary {binary_id} with binary {other_binary_id};"
                " call the run_lineage tool first",
            )
        return stored


def _tool_get_related_binaries(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_RELATED, "run_related_binaries")


def _tool_get_composition(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_COMPOSITION, "run_composition")


def _tool_run_composition(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _journaled_scan_run(
            conn,
            binary_id,
            store.SCAN_KIND_COMPOSITION,
            lambda: composition.run_composition(conn, binary_id=binary_id),
        )


def _tool_run_lineage(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    other_binary_id = _arg_int(arguments, "other_binary_id")
    refine = _arg_optional_bool(arguments, "refine", True)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        _require_binary(conn, other_binary_id)
        try:
            comparison = lineage.compare_binaries(
                conn,
                left_binary_id=binary_id,
                right_binary_id=other_binary_id,
                engine=engines.get_engine(),
                refine=refine,
            )
        except lineage.SameBinaryError as exc:
            raise ToolError("same binary", str(exc)) from exc
        except KeyError as exc:
            raise ToolError("binary not found", str(exc.args[0])) from exc
        return _journaled_scan_run(
            conn,
            binary_id,
            store.SCAN_KIND_LINEAGE,
            lambda: _store_lineage(conn, comparison),
        )


def _tool_run_related_binaries(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    limit = _arg_optional_int(arguments, "limit", related.DEFAULT_LIMIT)
    include_unrelated = _arg_optional_bool(arguments, "include_unrelated", False)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_RELATED,
                lambda: related.find_related(
                    conn,
                    binary_id=binary_id,
                    engine=engines.get_engine(),
                    limit=limit,
                    include_unrelated=include_unrelated,
                ),
            )
        except ValueError as exc:
            raise ToolError("invalid params", str(exc)) from exc
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


def _tool_diff_functions(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    candidate_id = _arg_int(arguments, "candidate_function_id")
    kind = _arg_optional_str(arguments, "kind", diffview.DEFAULT_KIND) or diffview.DEFAULT_KIND
    normalize = _arg_optional_bool(arguments, "normalize", diffview.DEFAULT_NORMALIZE)
    with contextlib.closing(_open()) as conn:
        try:
            return diffview.function_diff(
                conn,
                engines.get_engine(),
                function_id=function_id,
                candidate_id=candidate_id,
                kind=kind,
                normalize=normalize,
            )
        except diffview.DiffError as exc:
            raise ToolError(exc.code, exc.detail) from exc


def _tool_get_disasm(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    fmt = _arg_optional_str(arguments, "format", "nasm") or "nasm"
    if fmt not in engines.DISASM_FORMATS:
        raise ToolError("invalid format", f"unsupported disassembly format: {fmt}")
    with contextlib.closing(_open()) as conn:
        function = _require_function(conn, function_id)
        binary_id = int(function["binary_id"])
        project_dir = _project_context(conn, binary_id)
        va = int(function["va"])
        size = int(function["size"])
        if fmt == CACHEABLE_DISASM_FORMAT:
            cached = store.get_disasm(conn, function_id)
            if cached is not None:
                return {"va": va, "size": size, "format": fmt, "disasm": cached}
        disasm = _run_engine(lambda: _engine().disassemble(project_dir, va, size, fmt))
        if fmt == CACHEABLE_DISASM_FORMAT:
            store.set_disasm(conn, function_id, str(disasm))
    return {"va": va, "size": size, "format": fmt, "disasm": disasm}


def _tool_get_decompilation(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    backend = _arg_optional_str(arguments, "backend", engines.DEFAULT_DECOMPILER_BACKEND)
    if backend not in engines.DECOMPILER_BACKENDS:
        raise ToolError("invalid backend", f"unsupported decompiler backend: {backend}")
    named = _arg_optional_bool(arguments, "named", False)
    with contextlib.closing(_open()) as conn:
        function = _require_function(conn, function_id)
        stored = store.get_decompilation(conn, function_id)
        if stored is not None:
            return {
                "va": int(function["va"]),
                "backend": str(stored["backend"]),
                "named": named,
                "code": str(stored["code"]),
            }
        binary_id = int(function["binary_id"])
        project_dir = _project_context(conn, binary_id)
        va = int(function["va"])
        result = _run_engine(lambda: _engine().decompile(project_dir, va, backend, named))
    return {
        "va": va,
        "backend": str(result.get("backend") or backend),
        "named": named,
        "code": str(result.get("code") or ""),
    }


def _tool_get_xrefs(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    raw_kinds = arguments.get("kinds", [])
    if not isinstance(raw_kinds, list) or any(not isinstance(kind, str) for kind in raw_kinds):
        raise ToolError("invalid params", "kinds must be a list of strings")
    kinds = [kind for kind in raw_kinds if kind.strip()]
    with contextlib.closing(_open()) as conn:
        function = _require_function(conn, function_id)
        project_dir = _project_context(conn, int(function["binary_id"]))
        va = int(function["va"])
    return _run_engine(lambda: _engine().xrefs(project_dir, va, kinds))


def _tool_get_history(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        return {"history": store.list_name_history(conn, function_id)}


def _tool_get_summary(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        return _ai_artifact(conn, function_id, llm.AI_KIND_SUMMARY, "run_summary")


def _tool_get_ai_comments(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        return _ai_artifact(conn, function_id, llm.AI_KIND_COMMENTS, "run_ai_comments")


def _tool_get_type_suggestions(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        return _ai_artifact(conn, function_id, llm.AI_KIND_TYPES, "run_type_suggestions")


def _tool_get_renames(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        artifact = store.get_ai_artifact(conn, function_id, renames.RENAMES_KIND)
    if artifact is None:
        raise ToolError(
            "no-artifact",
            f"no renames artifact for function {function_id}; call the suggest_renames tool first",
        )
    return {"function_id": function_id, "kind": renames.RENAMES_KIND, **artifact}


def _tool_list_conversations(arguments: dict[str, Any]) -> dict[str, Any]:
    scope_kind = _arg_optional_str(arguments, "scope_kind") or None
    if scope_kind is not None and scope_kind not in conversations.SCOPE_KINDS:
        raise ToolError("invalid scope kind", f"unsupported scope kind: {scope_kind}")
    scope_id = _arg_optional_int(arguments, "scope_id", 0)
    with contextlib.closing(_open()) as conn:
        rows = store.list_conversations(conn, scope_kind=scope_kind, scope_id=scope_id or None)
    return {"conversations": rows}


def _tool_get_conversation(arguments: dict[str, Any]) -> dict[str, Any]:
    conversation_id = _arg_int(arguments, "conversation_id")
    with contextlib.closing(_open()) as conn:
        conversation = store.get_conversation(conn, conversation_id)
        if conversation is None:
            raise ToolError("conversation not found", f"no conversation with id {conversation_id}")
        messages = store.list_messages(conn, conversation_id)
    return {**conversation, "messages": messages}


def _tool_get_pipeline(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        run = pipeline.latest_run(conn, function_id)
    if run is None:
        raise ToolError(
            "no-run",
            f"no pipeline run for function {function_id}; call the run_pipeline tool first",
        )
    return run


def _tool_list_documents(arguments: dict[str, Any]) -> dict[str, Any]:
    scope_kind = _arg_optional_str(arguments, "scope_kind") or None
    if scope_kind is not None and scope_kind not in knowledge.SCOPE_KINDS:
        raise ToolError("invalid scope kind", f"unsupported scope kind: {scope_kind}")
    scope_id = _arg_optional_int(arguments, "scope_id", 0)
    with contextlib.closing(_open()) as conn:
        rows = store.list_documents(conn, scope_kind=scope_kind, scope_id=scope_id or None)
    return {"documents": rows}


def _tool_search_knowledge(arguments: dict[str, Any]) -> dict[str, Any]:
    query = _arg_str(arguments, "query")
    limit = _arg_optional_int(arguments, "limit", knowledge.DEFAULT_SEARCH_LIMIT)
    if limit < 1:
        raise ToolError("invalid params", "limit must be positive")
    scope_kind = _arg_optional_str(arguments, "scope_kind") or None
    if scope_kind is not None and scope_kind not in knowledge.SCOPE_KINDS:
        raise ToolError("invalid scope kind", f"unsupported scope kind: {scope_kind}")
    scope_id = _arg_optional_int(arguments, "scope_id", 0)
    with contextlib.closing(_open()) as conn:
        results = knowledge.search_knowledge(
            conn,
            query=query,
            scope_kind=scope_kind,
            scope_id=scope_id or None,
            limit=limit,
        )
    return {"query": query, "count": len(results), "results": results}


def _tool_retrieve_knowledge(arguments: dict[str, Any]) -> dict[str, Any]:
    """Retrieve the best knowledge snippets for a query; read-only.

    ``function_id`` searches its binary's documents and ``binary_id`` that
    binary's; with neither the query runs over every document.  A function id
    wins over a binary id, since the function names its binary.
    """
    query = _arg_str(arguments, "query")
    limit = _arg_optional_int(arguments, "limit", knowledge.RETRIEVAL_LIMIT)
    if limit < 1:
        raise ToolError("invalid params", "limit must be positive")
    function_id = _arg_optional_int(arguments, "function_id", 0)
    binary_id = _arg_optional_int(arguments, "binary_id", 0)
    scope_kind: str | None = None
    scope_id: int | None = None
    with contextlib.closing(_open()) as conn:
        if function_id:
            function = _require_function(conn, function_id)
            binary_id = int(function["binary_id"])
        if binary_id:
            _require_binary(conn, binary_id)
            scope_kind = knowledge.SCOPE_KIND_BINARY
            scope_id = binary_id
        results = knowledge.retrieve(
            conn, query=query, scope_kind=scope_kind, scope_id=scope_id, limit=limit
        )
    return {"query": query, "count": len(results), "results": results}


def _tool_get_graph(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    kind = _arg_optional_str(arguments, "kind") or None
    if kind is not None and kind not in graph.GRAPH_NODE_KINDS:
        raise ToolError("invalid kind", f"unsupported node kind: {kind}")
    include_documents = _arg_optional_bool(arguments, "include_documents", False)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if store.count_graph_nodes(conn, binary_id) == 0:
            raise ToolError(
                "no-graph",
                f"no graph for binary {binary_id}; call the build_graph tool first",
            )
        return graph.graph_payload(
            conn, binary_id=binary_id, kind=kind, include_documents=include_documents
        )


def _tool_graph_neighbors(arguments: dict[str, Any]) -> dict[str, Any]:
    node_id = _arg_str(arguments, "node_id")
    with contextlib.closing(_open()) as conn:
        try:
            return graph.neighbors(conn, node_id=node_id)
        except KeyError as exc:
            raise ToolError("node not found", str(exc)) from exc


def _tool_list_graph_backends(arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "backends": [backend.describe() for backend in graph_backends.graph_backends()],
        "default": graph_backends.configured_backend_name(),
    }


def _comment_tool_error(exc: comments.CommentError) -> ToolError:
    """Map a comment validation failure onto its tool error."""
    detail = str(exc.args[0]) if exc.args else str(exc)
    if isinstance(exc, comments.InvalidCommentError):
        return ToolError("invalid comment", detail)
    if isinstance(exc, comments.UnknownScopeError):
        return ToolError(f"{exc.scope_kind} not found", detail)
    return ToolError("comment not found", detail)


def _tool_list_comments(arguments: dict[str, Any]) -> dict[str, Any]:
    scope_kind = _arg_str(arguments, "scope_kind")
    scope_id = _arg_int(arguments, "scope_id")
    with contextlib.closing(_open()) as conn:
        try:
            rows = comments.list_comments(conn, scope_kind=scope_kind, scope_id=scope_id)
        except comments.CommentError as exc:
            raise _comment_tool_error(exc) from exc
    return {"comments": rows}


# ── Destructive tools ──────────────────────────────────────────────


def _tool_run_fingerprint(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
        fingerprint = _run_engine(lambda: _engine().fingerprint(path))
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="binary_fingerprints",
                where="binary_id = ?",
                params=(binary_id,),
                description=f"replaced the fingerprint of binary {binary_id}",
            )
            store.set_fingerprint(conn, binary_id, fingerprint)
            if not before:
                journal.journaled_create(
                    log,
                    table="binary_fingerprints",
                    key={"binary_id": binary_id},
                    description=f"stored the fingerprint of binary {binary_id}",
                )
            return log.attach(fingerprint)


def _tool_rename_function(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    name = _arg_str(arguments, "name")
    actor = _arg_optional_str(arguments, "actor", "mcp") or "mcp"
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                change = journal.journaled_rename(
                    conn, log, function_id, new_name=name, actor=actor, source="manual"
                )
            except KeyError as exc:
                raise ToolError("function not found", f"no function with id {function_id}") from exc
            except ValueError as exc:
                raise ToolError("invalid name", str(exc)) from exc
            return log.attach(change)


def _tool_revert_name(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    history_id = _arg_int(arguments, "history_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        entry = store.get_name_history(conn, history_id)
        if entry is None or int(entry["function_id"]) != function_id:
            raise ToolError(
                "history not found",
                f"no history {history_id} for function {function_id}",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                journal.journaled_revert_name(conn, log, function_id, history_id)
            except ValueError as exc:
                raise ToolError("invalid name", str(exc)) from exc
            return log.attach(
                {
                    "function_id": function_id,
                    "history_id": history_id,
                    "name": str(entry["old_name"]),
                }
            )


def _tool_apply_match(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    candidate_id = _arg_int(arguments, "candidate_function_id")
    mode = (
        _arg_optional_str(arguments, "mode", matching.DEFAULT_TRANSFER_MODE)
        or matching.DEFAULT_TRANSFER_MODE
    )
    actor = _arg_optional_str(arguments, "actor", "mcp") or "mcp"
    with contextlib.closing(_open()) as conn:
        try:
            plan = matching.plan_transfer(
                conn, function_id=function_id, candidate_function_id=candidate_id, mode=mode
            )
        except matching.InvalidSettingsError as exc:
            raise ToolError(exc.error, exc.detail) from exc
        if plan.status == matching.TRANSFER_STATUS_FAILED:
            _, error = matching.TRANSFER_FAILURE_RESPONSE.get(plan.reason, (400, plan.reason))
            raise ToolError(error, plan.detail)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            if plan.status == matching.TRANSFER_STATUS_APPLIED:
                matching.apply_transfer(conn, log, plan, actor=actor)
            return log.attach(matching.plan_payload(plan))


def _tool_run_match(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    try:
        settings = matching.MatchSettings.from_request(
            {
                "min_similarity": _arg_optional_number(
                    arguments, "min_similarity", matching.DEFAULT_MIN_SIMILARITY
                ),
                "min_confidence": _arg_optional_number(
                    arguments, "min_confidence", matching.DEFAULT_MIN_CONFIDENCE
                ),
                "top": _arg_optional_int(arguments, "top", matching.DEFAULT_TOP),
                "include_self": _arg_optional_bool(
                    arguments, "include_self", matching.DEFAULT_INCLUDE_SELF
                ),
                "platforms": _arg_str_list(arguments, "platforms"),
                "architectures": _arg_str_list(arguments, "architectures"),
                "binary_ids": _arg_optional_int_list(arguments, "binary_ids") or [],
                "collection_ids": _arg_optional_int_list(arguments, "collection_ids") or [],
            }
        )
    except matching.InvalidSettingsError as exc:
        raise ToolError(exc.error, exc.detail) from exc
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if not similarity.available():
            raise ToolError(
                "similarity-unavailable",
                "install the optional extra: uv sync --extra similarity",
            )
        try:
            matching.resolve_scope(conn, settings)
        except matching.InvalidSettingsError as exc:
            raise ToolError(exc.error, exc.detail) from exc
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="matches",
                where=_BINARY_MATCHES_WHERE,
                params=(binary_id,),
                description=f"replaced the matches of binary {binary_id}",
            )
            try:
                summary = matching.match_binary(
                    conn, binary_id=binary_id, engine=_engine(), settings=settings
                )
            except engines.EngineUnavailable as exc:
                raise ToolError("engine-unavailable", str(exc)) from exc
            except engines.EngineError as exc:
                raise ToolError("engine-error", str(exc)) from exc
            except similarity.SimilarityUnavailable as exc:
                raise ToolError("similarity-unavailable", str(exc)) from exc
            except matching.InvalidSettingsError as exc:
                raise ToolError(exc.error, exc.detail) from exc
            journal.journaled_new_rows(
                conn,
                log,
                table="matches",
                where=_BINARY_MATCHES_WHERE,
                params=(binary_id,),
                before=before,
                key=("id",),
                description=f"recorded a match of binary {binary_id}",
            )
            return log.attach(
                {
                    **summary,
                    "binary_id": binary_id,
                    "settings": settings.payload(),
                    "notes": matching.scope_notes(settings),
                }
            )


def _tool_run_triage(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
        dossier = _run_engine(lambda: _engine().analyze(path))
        stored = _journaled_scan_store(conn, binary_id, store.SCAN_KIND_TRIAGE, dossier)
        return _classified(conn, binary_id, stored)


def _tool_run_function_triage(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    function_ids = _arg_optional_int_list(arguments, "function_ids")
    limit = _arg_optional_int(arguments, "limit", function_triage.DEFAULT_LIMIT)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_FUNCTION_TRIAGE,
                lambda: function_triage.summarize_functions(
                    conn,
                    binary_id=binary_id,
                    function_ids=function_ids,
                    limit=limit,
                    client=llm.get_client(),
                    engine=engines.get_engine(),
                ),
            )
        except ValueError as exc:
            raise ToolError("invalid params", str(exc)) from exc
        except engines.EngineUnavailable as exc:
            raise ToolError("engine-unavailable", str(exc)) from exc
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


def _tool_run_report(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        project_dir = _project_context(conn, binary_id)
        result = _run_engine(lambda: _engine().report(project_dir, reports_dir(binary_id)))
        return _journaled_scan_store(conn, binary_id, store.SCAN_KIND_REPORT, result)


def _tool_run_structs(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    decompiler = _arg_optional_str(arguments, "decompiler", engines.DEFAULT_DECOMPILER_BACKEND)
    if decompiler not in engines.DECOMPILER_BACKENDS:
        raise ToolError("invalid backend", f"unsupported decompiler backend: {decompiler}")
    limit = _arg_optional_int(arguments, "limit", DEFAULT_STRUCT_LIMIT)
    if limit < 0:
        raise ToolError("invalid limit", f"limit must not be negative: {limit}")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        project_dir = _project_context(conn, binary_id)
        result = _run_engine(
            lambda: _engine().structs(project_dir, decompiler=decompiler, limit=limit)
        )
        return _journaled_scan_store(conn, binary_id, store.SCAN_KIND_STRUCTS, result)


def _tool_run_crypto_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
        result = _run_engine(lambda: _engine().crypto_scan(path))
        return _journaled_scan_store(conn, binary_id, store.SCAN_KIND_CRYPTO, result)


def _tool_run_pe_info(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
        result = _run_engine(lambda: _engine().pe_info(path))
        return _journaled_scan_store(conn, binary_id, store.SCAN_KIND_PE_INFO, result)


def _tool_run_filetype(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_FILETYPE,
                lambda: filetypes.run_filetype(conn, binary_id=binary_id, engine=_engine()),
            )
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


def _tool_run_security_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    min_severity = _arg_optional_str(
        arguments, "min_severity", engines.DEFAULT_SECURITY_MIN_SEVERITY
    )
    if min_severity not in engines.SECURITY_SEVERITIES:
        raise ToolError("invalid severity", f"unsupported security severity: {min_severity}")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        project_dir = _project_context(conn, binary_id)
        result = _run_engine(lambda: _engine().security_scan(project_dir, min_severity))
        return _journaled_scan_store(conn, binary_id, store.SCAN_KIND_SECURITY, result)


def _tool_run_capabilities(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_CAPABILITIES,
                lambda: capabilities.run_capabilities(conn, binary_id=binary_id, engine=_engine()),
            )
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


def _tool_run_secrets_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_SECRETS,
                lambda: secrets.run_secrets(conn, binary_id=binary_id, engine=_engine()),
            )
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


def _tool_run_protocols_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_PROTOCOLS,
                lambda: protocols.scan_protocols(conn, binary_id=binary_id, engine=_engine()),
            )
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


def _tool_run_threat_report(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    narrative = _arg_optional_bool(arguments, "narrative", False)
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        try:
            stored = _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_THREAT,
                lambda: threat.build_threat_report(
                    conn,
                    binary_id=binary_id,
                    engine=_engine(),
                    llm_client=llm.get_client(),
                    narrative=narrative,
                ),
            )
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc
        return _classified(conn, binary_id, stored)


def _tool_run_remediation(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_REMEDIATION,
                lambda: remediation.build_remediation(conn, binary_id=binary_id, engine=_engine()),
            )
        except remediation.NoStringsError as exc:
            raise ToolError("no-strings", str(exc)) from exc
        except engines.EngineUnavailable as exc:
            raise ToolError("engine-unavailable", str(exc)) from exc
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


def _tool_run_behavior_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    domain = _behavior_domain(arguments)
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        names = (domain,) if domain is not None else behavior.BEHAVIOR_DOMAINS
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                results = {
                    name: journal.journaled_scan(
                        conn,
                        log,
                        binary_id,
                        behavior.DOMAIN_SCAN_KINDS[name],
                        partial(
                            behavior.scan_domain,
                            conn,
                            binary_id=binary_id,
                            domain=name,
                            engine=_engine(),
                        ),
                    )
                    for name in names
                }
            except engines.EngineError as exc:
                raise ToolError("engine-error", str(exc)) from exc
            return log.attach(results if domain is None else results[domain])


def _tool_run_hardening_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    domain = _hardening_domain(arguments)
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        names = (domain,) if domain is not None else hardening.HARDENING_DOMAINS
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                results = {
                    name: journal.journaled_scan(
                        conn,
                        log,
                        binary_id,
                        hardening.DOMAIN_SCAN_KINDS[name],
                        partial(
                            hardening.scan_hardening,
                            conn,
                            binary_id=binary_id,
                            domain=name,
                            engine=_engine(),
                        ),
                    )
                    for name in names
                }
            except engines.EngineError as exc:
                raise ToolError("engine-error", str(exc)) from exc
            return log.attach(results if domain is None else results[domain])


def _tool_run_unstrip(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    min_confidence = _arg_optional_number(
        arguments, "min_confidence", unstrip.DEFAULT_MIN_CONFIDENCE
    )
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        _project_context(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_UNSTRIP,
                lambda: unstrip.run_unstrip(
                    conn,
                    binary_id=binary_id,
                    engine=_engine(),
                    min_confidence=min_confidence,
                ),
            )
        except unstrip.NoRebrewContextError as exc:
            raise ToolError("no-engine-context", str(exc)) from exc
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


def _tool_apply_unstrip(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    override = arguments.get("name")
    if override is not None and not isinstance(override, str):
        raise ToolError("invalid params", "name must be a string")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                change = journal.journaled_name_change(
                    conn,
                    log,
                    function_id,
                    lambda: unstrip.apply_proposal(
                        conn, function_id=function_id, new_name=override
                    ),
                )
            except KeyError as exc:
                raise ToolError("function not found", f"no function with id {function_id}") from exc
            except unstrip.NoProposalError as exc:
                raise ToolError("no-proposal", str(exc)) from exc
            except ValueError as exc:
                raise ToolError("invalid name", str(exc)) from exc
            return log.attach(change)


def _tool_run_summary(arguments: dict[str, Any]) -> dict[str, Any]:
    return _store_ai_artifact(_arg_int(arguments, "function_id"), llm.AI_KIND_SUMMARY)


def _tool_run_ai_comments(arguments: dict[str, Any]) -> dict[str, Any]:
    return _store_ai_artifact(_arg_int(arguments, "function_id"), llm.AI_KIND_COMMENTS)


def _tool_run_type_suggestions(arguments: dict[str, Any]) -> dict[str, Any]:
    return _store_ai_artifact(_arg_int(arguments, "function_id"), llm.AI_KIND_TYPES)


def _tool_suggest_renames(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        client = llm.get_client()
        if not client.available():
            raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, renames.RENAMES_KIND),
                description=f"replaced the renames artifact of function {function_id}",
            )
            try:
                result = renames.suggest_renames(conn, function_id=function_id, client=client)
            except renames.NoDecompilationError as exc:
                raise ToolError("no-decompilation", str(exc)) from exc
            except llm.LlmError as exc:
                raise ToolError("llm-error", str(exc)) from exc
            if not before:
                journal.journaled_create(
                    log,
                    table="ai_artifacts",
                    key={"function_id": function_id, "kind": renames.RENAMES_KIND},
                    description=f"stored the renames artifact of function {function_id}",
                )
            return log.attach(result)


def _tool_apply_renames(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    raw = arguments.get("applied")
    if raw is not None and (
        not isinstance(raw, list) or any(not isinstance(entry, dict) for entry in raw)
    ):
        raise ToolError("invalid params", "applied must be a list of suggestion objects")
    applied = raw if isinstance(raw, list) else None
    rename_function = _arg_optional_bool(arguments, "rename_function", False)
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            artifact_before = journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, renames.RENAMES_APPLIED_KIND),
                description=f"replaced the applied renames of function {function_id}",
            )
            journal.journaled_rows(
                conn,
                log,
                table="decompilations",
                where="function_id = ?",
                params=(function_id,),
                description=f"rewrote the decompilation of function {function_id}",
            )
            try:
                result = journal.journaled_name_change(
                    conn,
                    log,
                    function_id,
                    lambda: renames.apply_renames(
                        conn,
                        function_id=function_id,
                        applied=applied,
                        actor="mcp",
                        rename_function=rename_function,
                    ),
                )
            except renames.NoDecompilationError as exc:
                raise ToolError("no-decompilation", str(exc)) from exc
            except renames.NoSuggestionError as exc:
                raise ToolError("no-artifact", str(exc)) from exc
            if result["decompilation_updated"] and not artifact_before:
                journal.journaled_create(
                    log,
                    table="ai_artifacts",
                    key={"function_id": function_id, "kind": renames.RENAMES_APPLIED_KIND},
                    description=f"journaled the applied renames of function {function_id}",
                )
            return log.attach(result)


def _tool_revert_renames(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, renames.RENAMES_APPLIED_KIND),
                description=f"reverted the applied renames of function {function_id}",
            )
            journal.journaled_rows(
                conn,
                log,
                table="decompilations",
                where="function_id = ?",
                params=(function_id,),
                description=f"restored the decompilation of function {function_id}",
            )
            try:
                result = renames.revert_renames(conn, function_id=function_id)
            except renames.NoRevertError as exc:
                raise ToolError("no-artifact", str(exc)) from exc
            return log.attach(result)


def _tool_create_conversation(arguments: dict[str, Any]) -> dict[str, Any]:
    scope_kind = _arg_str(arguments, "scope_kind")
    if scope_kind not in conversations.SCOPE_KINDS:
        raise ToolError("invalid scope kind", f"unsupported scope kind: {scope_kind}")
    scope_id = _arg_int(arguments, "scope_id")
    title = _arg_optional_str(arguments, "title")
    with contextlib.closing(_open()) as conn:
        if scope_kind == conversations.SCOPE_KIND_FUNCTION:
            if store.get_function(conn, scope_id) is None:
                raise ToolError("function not found", f"no function with id {scope_id}")
        elif store.get_binary(conn, scope_id) is None:
            raise ToolError("binary not found", f"no binary with id {scope_id}")
        resolved = title.strip() or conversations.default_title(
            conn, scope_kind=scope_kind, scope_id=scope_id
        )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            conversation_id = store.create_conversation(
                conn, scope_kind=scope_kind, scope_id=scope_id, title=resolved
            )
            journal.journaled_create(
                log,
                table="conversations",
                key=conversation_id,
                description=f"created conversation {conversation_id}",
            )
            return log.attach(store.get_conversation(conn, conversation_id) or {})


def _tool_send_conversation_message(arguments: dict[str, Any]) -> dict[str, Any]:
    conversation_id = _arg_int(arguments, "conversation_id")
    content = _arg_str(arguments, "content")
    with contextlib.closing(_open()) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            raise ToolError("conversation not found", f"no conversation with id {conversation_id}")
        client = llm.get_client()
        if not client.available():
            raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = {int(row["id"]) for row in store.list_messages(conn, conversation_id)}
            try:
                result = conversations.send_message(
                    conn, conversation_id=conversation_id, content=content, client=client
                )
            except llm.LlmUnavailable as exc:
                raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL) from exc
            except llm.LlmError as exc:
                raise ToolError("llm-error", str(exc)) from exc
            journal.journaled_messages(conn, log, conversation_id, before)
            return log.attach(result)


def _tool_delete_conversation(arguments: dict[str, Any]) -> dict[str, Any]:
    conversation_id = _arg_int(arguments, "conversation_id")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="messages",
                where="conversation_id = ?",
                params=(conversation_id,),
                description=f"deleted the messages of conversation {conversation_id}",
            )
            journal.journaled_rows(
                conn,
                log,
                table="conversations",
                where="id = ?",
                params=(conversation_id,),
                description=f"deleted conversation {conversation_id}",
            )
            if not store.delete_conversation(conn, conversation_id):
                raise ToolError(
                    "conversation not found", f"no conversation with id {conversation_id}"
                )
            return log.attach({"conversation_id": conversation_id, "deleted": True})


def _tool_run_pipeline(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    raw_disabled = arguments.get("disabled")
    disabled: frozenset[str] | None = None
    if raw_disabled is not None:
        if not isinstance(raw_disabled, list) or any(
            not isinstance(entry, str) for entry in raw_disabled
        ):
            raise ToolError("invalid params", "disabled must be a list of component names")
        disabled = frozenset(entry.strip() for entry in raw_disabled if entry.strip())
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            raise ToolError("function not found", f"no function with id {function_id}")
        try:
            return pipeline.run_pipeline(conn, function_id=function_id, disabled=disabled)
        except pipeline.PipelineUnavailable as exc:
            raise ToolError("pipeline-unavailable", str(exc)) from exc


def _tool_revert_pipeline_run(arguments: dict[str, Any]) -> dict[str, Any]:
    run_id = _arg_int(arguments, "run_id")
    with contextlib.closing(_open()) as conn:
        try:
            return pipeline.revert_run(conn, run_id)
        except KeyError as exc:
            raise ToolError("run not found", f"no pipeline run with id {run_id}") from exc


def _tool_list_integrations(arguments: dict[str, Any]) -> dict[str, Any]:
    # Imported here rather than at module scope: reportal.integrations reads this
    # module's registry (its own seam list names TOOL_ENTRY_POINT_GROUP and its
    # tool rows come from builtin_tools), so a module-level import would make the
    # two modules circular and break `from reportal import mcp_server` whenever
    # nothing else imported integrations first.  By the time a tool runs, both
    # modules are loaded.
    from reportal import integrations

    del arguments
    return integrations.inventory()


def _tool_list_components(arguments: dict[str, Any]) -> dict[str, Any]:
    rows = [
        {
            "name": entry.component.name,
            "requires": sorted(entry.component.requires),
            "provides": sorted(entry.component.provides),
            "origin": entry.origin,
            "reloadable": entry.reloadable,
            "withdrawable": pipeline.withdraw_refusal(entry.component) is None,
            "withdraw_reason": pipeline.withdraw_refusal(entry.component) or "",
        }
        for entry in components.registrations()
    ]
    return {"components": rows, "count": len(rows)}


def _tool_reload_components(arguments: dict[str, Any]) -> dict[str, Any]:
    all_components = _arg_optional_bool(arguments, "all", False)
    name = _arg_optional_str(arguments, "name")
    if all_components:
        if name:
            raise ToolError("invalid params", "provide a name or all, not both")
        try:
            return components.reload_all()
        except components.ComponentMissingError as exc:
            raise ToolError("component-missing", str(exc)) from exc
    if not name:
        raise ToolError("invalid params", "provide a name or all")
    try:
        return components.reload_component(name)
    except KeyError as exc:
        raise ToolError("component not found", f"no component named {name!r}") from exc
    except components.NotReloadableError as exc:
        raise ToolError("not-reloadable", str(exc)) from exc
    except components.ComponentMissingError as exc:
        raise ToolError("component-missing", str(exc)) from exc


def _tool_deactivate_components(arguments: dict[str, Any]) -> dict[str, Any]:
    name = _arg_str(arguments, "name")
    with contextlib.closing(_open()) as conn:
        try:
            return pipeline.withdraw_component(conn, name)
        except KeyError as exc:
            raise ToolError("component not found", f"no component named {name!r}") from exc
        except pipeline.NotWithdrawableError as exc:
            raise ToolError("not-withdrawable", str(exc)) from exc


def _tool_get_auto_run(arguments: dict[str, Any]) -> dict[str, Any]:
    run_id = arguments.get("run_id")
    binary_id = arguments.get("binary_id")
    if run_id is None and binary_id is None:
        raise ToolError("invalid params", "provide run_id or binary_id")
    with contextlib.closing(_open()) as conn:
        if run_id is not None:
            resolved = _arg_int(arguments, "run_id")
            if auto_store.get_auto_run(conn, resolved) is None:
                raise ToolError("run not found", f"no auto run with id {resolved}")
            return auto_mode.run_summary(conn, resolved)
        resolved_binary = _arg_int(arguments, "binary_id")
        _require_binary(conn, resolved_binary)
        run = auto_store.latest_auto_run(conn, resolved_binary)
        if run is None:
            raise ToolError(
                "no-run",
                f"no auto run for binary {resolved_binary}; call the run_auto tool first",
            )
        return auto_mode.run_summary(conn, int(run["id"]))


def _tool_run_auto(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    raw_disabled = arguments.get("disabled")
    disabled: frozenset[str] = frozenset()
    if raw_disabled is not None:
        if not isinstance(raw_disabled, list) or any(
            not isinstance(entry, str) for entry in raw_disabled
        ):
            raise ToolError("invalid params", "disabled must be a list of worker names")
        disabled = frozenset(entry.strip() for entry in raw_disabled if entry.strip())
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            return auto_mode.run_auto(
                conn,
                binary_id=binary_id,
                worker=_arg_optional_str(arguments, "worker", auto_workers.WORKER_OFFLINE),
                execute=_arg_optional_bool(arguments, "execute", False),
                concurrency=_arg_optional_int(
                    arguments, "concurrency", auto_mode.DEFAULT_CONCURRENCY
                ),
                functions_per_task=_arg_optional_int(
                    arguments, "functions_per_task", auto_mode.DEFAULT_FUNCTIONS_PER_TASK
                ),
                max_attempts=_arg_optional_int(
                    arguments, "max_attempts", auto_mode.DEFAULT_MAX_ATTEMPTS
                ),
                max_tasks=_arg_optional_int(arguments, "max_tasks", auto_mode.DEFAULT_MAX_TASKS),
                disabled=disabled,
            )
        except ValueError as exc:
            raise ToolError("invalid params", str(exc)) from exc


def _tool_revert_auto_run(arguments: dict[str, Any]) -> dict[str, Any]:
    run_id = _arg_int(arguments, "run_id")
    with contextlib.closing(_open()) as conn:
        try:
            return auto_mode.revert_auto_run(conn, run_id)
        except KeyError as exc:
            raise ToolError("run not found", f"no auto run with id {run_id}") from exc


def _tool_recover_auto_run(arguments: dict[str, Any]) -> dict[str, Any]:
    run_id = _arg_int(arguments, "run_id")
    with contextlib.closing(_open()) as conn:
        try:
            return auto_mode.recover_auto_run(conn, run_id)
        except KeyError as exc:
            raise ToolError("run not found", f"no auto run with id {run_id}") from exc


def _tool_create_tag(arguments: dict[str, Any]) -> dict[str, Any]:
    name = _arg_str(arguments, "name")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            created = store.find_tag(conn, name) is None
            try:
                tag_id = store.create_tag(conn, name)
            except ValueError as exc:
                raise ToolError("invalid name", str(exc)) from exc
            if created:
                journal.journaled_create(
                    log, table="tags", key=tag_id, description=f"created tag {tag_id}"
                )
            return log.attach({"tag_id": tag_id, "name": name})


def _tool_tag_binary(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    has_name = "name" in arguments
    has_tag_id = "tag_id" in arguments
    if has_name == has_tag_id:
        raise ToolError("invalid body", "provide exactly one of name or tag_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            if has_tag_id:
                tag_id = _arg_int(arguments, "tag_id")
                tag = store.get_tag(conn, tag_id)
                if tag is None:
                    raise ToolError("tag not found", f"no tag with id {tag_id}")
                name = str(tag["name"])
            else:
                name = _arg_str(arguments, "name")
                created = store.find_tag(conn, name) is None
                tag_id = store.create_tag(conn, name)
                if created:
                    journal.journaled_create(
                        log, table="tags", key=tag_id, description=f"created tag {tag_id}"
                    )
            if store.add_binary_tag(conn, binary_id, tag_id):
                journal.journaled_create(
                    log,
                    table="binary_tags",
                    key={"binary_id": binary_id, "tag_id": tag_id},
                    description=f"tagged binary {binary_id} with tag {tag_id}",
                )
            return log.attach({"binary_id": binary_id, "tag_id": tag_id, "name": name})


def _tool_untag_binary(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    tag_id = _arg_int(arguments, "tag_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="binary_tags",
                where="binary_id = ? AND tag_id = ?",
                params=(binary_id, tag_id),
                description=f"untagged binary {binary_id} from tag {tag_id}",
            )
            if not store.remove_binary_tag(conn, binary_id, tag_id):
                raise ToolError("tag not on binary", f"binary {binary_id} has no tag {tag_id}")
            return log.attach({"binary_id": binary_id, "tag_id": tag_id, "removed": True})


def _tool_export_zipped_binary(arguments: dict[str, Any]) -> dict[str, Any]:
    """Write a stored binary as a password-protected zip at the caller's path."""
    from reportal import api  # the filename sanitizer the routes use

    binary_id = _arg_int(arguments, "binary_id")
    path = _arg_str(arguments, "path")
    password = _arg_optional_str(arguments, "password", zipcrypto.DEFAULT_PASSWORD)
    if not password or len(password) > zipcrypto.MAX_PASSWORD_CHARS:
        raise ToolError(
            "invalid params",
            f"password must be 1 to {zipcrypto.MAX_PASSWORD_CHARS} characters",
        )
    with contextlib.closing(_open()) as conn:
        binary = _require_binary(conn, binary_id)
        source = Path(str(binary["path"]))
        if not source.is_file():
            raise ToolError(
                "binary not on disk", f"binary {binary_id} has no file at {binary['path']!r}"
            )
        target = Path(path).expanduser()
        member = f"{api.download_filename(binary)}.zip"
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            previous = journal.read_bounded(target) if target.is_file() else None
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as reader, target.open("wb") as writer:
                written = zipcrypto.write_protected_zip(writer, member, reader, password)
            journal.journaled_file(log, target, previous=previous)
            return log.attach(
                {
                    "binary_id": binary_id,
                    "path": str(target),
                    "member": member,
                    "password": password,
                    "bytes": written,
                }
            )


def _tool_get_die_info(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        payload = details.die_info(conn, binary_id)
    if not payload["available"]:
        raise ToolError(
            "no-scan",
            f"binary {binary_id} has no stored filetype or pe-info scan;"
            f" call run_filetype or run_pe_info first",
        )
    return payload


def _tool_get_additional_details(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if not details.source_present(conn, binary_id, store.SCAN_KIND_PE_INFO):
            raise ToolError(
                "no-scan",
                f"binary {binary_id} has no stored pe-info scan; call run_pe_info first",
            )
        return details.additional_details(conn, binary_id)


def _tool_get_details_status(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return details.status(conn, binary_id)


def _tool_get_config(_arguments: dict[str, Any]) -> dict[str, Any]:
    return instance.describe()


def _tool_list_collections(_arguments: dict[str, Any]) -> dict[str, Any]:
    with contextlib.closing(_open()) as conn:
        rows = store.list_collections(conn)
        for row in rows:
            row["tags"] = [tag["name"] for tag in store.collection_tags(conn, int(row["id"]))]
        return {"collections": rows, "count": len(rows)}


def _tool_get_collection(arguments: dict[str, Any]) -> dict[str, Any]:
    collection_id = _arg_int(arguments, "collection_id")
    with contextlib.closing(_open()) as conn:
        collection = store.get_collection(conn, collection_id)
        if collection is None:
            raise ToolError("collection not found", f"no collection with id {collection_id}")
        return collection


def _tool_create_collection(arguments: dict[str, Any]) -> dict[str, Any]:
    name = _arg_str(arguments, "name")
    description = _arg_optional_str(arguments, "description")
    scope = _arg_optional_str(arguments, "scope")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                collection_id = store.create_collection(
                    conn, name=name, description=description, scope=scope
                )
            except ValueError as exc:
                raise ToolError("invalid collection", str(exc)) from exc
            journal.journaled_create(
                log,
                table="collections",
                key=collection_id,
                description=f"created collection {collection_id}",
            )
            collection = store.get_collection(conn, collection_id) or {}
            return log.attach(collection)


def _tool_update_collection(arguments: dict[str, Any]) -> dict[str, Any]:
    collection_id = _arg_int(arguments, "collection_id")
    fields = {
        key: arguments[key]
        for key in ("name", "description", "scope")
        if key in arguments and arguments[key] is not None
    }
    if not fields:
        raise ToolError("invalid params", "provide name, description or scope")
    with contextlib.closing(_open()) as conn:
        if store.get_collection(conn, collection_id) is None:
            raise ToolError("collection not found", f"no collection with id {collection_id}")
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="collections",
                where="id = ?",
                params=(collection_id,),
                description=f"updated collection {collection_id}",
            )
            try:
                collection = store.update_collection(conn, collection_id, **fields)
            except ValueError as exc:
                raise ToolError("invalid collection", str(exc)) from exc
            return log.attach(collection or {})


def _tool_delete_collection(arguments: dict[str, Any]) -> dict[str, Any]:
    collection_id = _arg_int(arguments, "collection_id")
    with contextlib.closing(_open()) as conn:
        if store.get_collection(conn, collection_id) is None:
            raise ToolError("collection not found", f"no collection with id {collection_id}")
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            # Links first: a revert replays newest-first and a link restored
            # before its parent row exists trips the foreign key.
            for table in ("collection_binaries", "collection_tags"):
                links = journal.snapshot_rows(
                    conn, table=table, where="collection_id = ?", params=(collection_id,)
                )
                if links:
                    log.record(
                        effects.EFFECT_ROW_RESTORE,
                        f"links of collection {collection_id} in {table}",
                        journal.row_restore_descriptor(table, links),
                    )
            journal.journaled_rows(
                conn,
                log,
                table="collections",
                where="id = ?",
                params=(collection_id,),
                description=f"deleted collection {collection_id}",
            )
            store.delete_collection(conn, collection_id)
            return log.attach({"collection_id": collection_id, "deleted": True})


def _tool_set_collection_members(arguments: dict[str, Any]) -> dict[str, Any]:
    collection_id = _arg_int(arguments, "collection_id")
    binary_ids = _arg_optional_int_list(arguments, "binary_ids")
    if binary_ids is None:
        raise ToolError("invalid params", "binary_ids is required")
    with contextlib.closing(_open()) as conn:
        if store.get_collection(conn, collection_id) is None:
            raise ToolError("collection not found", f"no collection with id {collection_id}")
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn,
                table="collection_binaries",
                where="collection_id = ?",
                params=(collection_id,),
            )
            try:
                change = store.replace_collection_binaries(conn, collection_id, binary_ids)
            except (ValueError, KeyError) as exc:
                raise ToolError("binary not found", str(exc)) from exc
            log.record(
                effects.EFFECT_ROW_RESTORE,
                f"members of collection {collection_id}",
                journal.row_restore_descriptor("collection_binaries", before),
            )
            return log.attach({"collection_id": collection_id, **change})


def _tool_set_collection_tags(arguments: dict[str, Any]) -> dict[str, Any]:
    collection_id = _arg_int(arguments, "collection_id")
    if "tags" not in arguments:
        raise ToolError("invalid params", "tags is required")
    names = _arg_str_list(arguments, "tags")
    with contextlib.closing(_open()) as conn:
        if store.get_collection(conn, collection_id) is None:
            raise ToolError("collection not found", f"no collection with id {collection_id}")
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn,
                table="collection_tags",
                where="collection_id = ?",
                params=(collection_id,),
            )
            change = store.set_collection_tags(conn, collection_id, names)
            log.record(
                effects.EFFECT_ROW_RESTORE,
                f"tags of collection {collection_id}",
                journal.row_restore_descriptor("collection_tags", before),
            )
            return log.attach({"collection_id": collection_id, **change})


def _tool_add_comment(arguments: dict[str, Any]) -> dict[str, Any]:
    scope_kind = _arg_str(arguments, "scope_kind")
    scope_id = _arg_int(arguments, "scope_id")
    body = _arg_comment_body(arguments)
    author = _arg_optional_str(arguments, "author")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                created = comments.add_comment(
                    conn,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                    body=body,
                    author=author or None,
                )
            except comments.CommentError as exc:
                raise _comment_tool_error(exc) from exc
            journal.journaled_create(
                log,
                table="comments",
                key=int(created["id"]),
                description=f"stored comment {created['id']}",
            )
            return log.attach(created)


def _tool_update_comment(arguments: dict[str, Any]) -> dict[str, Any]:
    comment_id = _arg_int(arguments, "comment_id")
    body = _arg_comment_body(arguments)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="comments",
                where="id = ?",
                params=(comment_id,),
                description=f"edited comment {comment_id}",
            )
            try:
                updated = comments.update_comment(conn, comment_id, body=body)
            except comments.CommentError as exc:
                raise _comment_tool_error(exc) from exc
            return log.attach(updated)


def _tool_delete_comment(arguments: dict[str, Any]) -> dict[str, Any]:
    comment_id = _arg_int(arguments, "comment_id")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="comments",
                where="id = ?",
                params=(comment_id,),
                description=f"deleted comment {comment_id}",
            )
            try:
                deleted = comments.delete_comment(conn, comment_id)
            except comments.CommentError as exc:
                raise _comment_tool_error(exc) from exc
            return log.attach({"comment": deleted, "comment_id": comment_id, "deleted": True})


def _tool_bulk_binaries(arguments: dict[str, Any]) -> dict[str, Any]:
    action = _arg_str(arguments, "action")
    ids = _arg_optional_int_list(arguments, "binary_ids")
    if ids is None:
        raise ToolError("invalid params", "binary_ids must be a list of integers")
    tag = _arg_optional_str(arguments, "tag")
    with contextlib.closing(_open()) as conn:
        action_id = journal.new_action()
        with journal.journaled(conn, action_id) as log:
            try:
                result = bulk_actions.apply_binary_action(
                    conn, action=action, ids=ids, tag=tag, log=log
                )
            except bulk_actions.BulkError as exc:
                raise ToolError("invalid bulk request", str(exc)) from exc
            return log.attach(result)


def _tool_bulk_functions(arguments: dict[str, Any]) -> dict[str, Any]:
    action = _arg_str(arguments, "action")
    ids = _arg_optional_int_list(arguments, "function_ids")
    if ids is None:
        raise ToolError("invalid params", "function_ids must be a list of integers")
    prefix = _arg_optional_str(arguments, "prefix")
    replace = _arg_optional_bool(arguments, "replace", False)
    with contextlib.closing(_open()) as conn:
        action_id = journal.new_action()
        with journal.journaled(conn, action_id) as log:
            try:
                result = bulk_actions.apply_function_action(
                    conn, action=action, ids=ids, prefix=prefix, replace=replace, log=log
                )
            except bulk_actions.BulkError as exc:
                raise ToolError("invalid bulk request", str(exc)) from exc
            return log.attach(result)


def _tool_build_graph(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = journal.journaled_graph_rebuild(
                conn, log, binary_id, lambda: graph.build_graph(conn, binary_id=binary_id)
            )
            return log.attach(result)


def _tool_sync_graph_backend(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    name = _arg_optional_str(arguments, "backend") or None
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            return graph_backends.sync_graph(conn, binary_id=binary_id, backend_name=name)
        except graph_backends.UnknownBackendError as exc:
            raise ToolError("backend not found", str(exc)) from exc
        except graph_backends.GraphNotBuiltError as exc:
            raise ToolError("no-graph", str(exc)) from exc
        except graph_backends.BackendUnavailableError as exc:
            raise ToolError("backend-unavailable", exc.reason) from exc


def _tool_ingest_document(arguments: dict[str, Any]) -> dict[str, Any]:
    scope_kind = _arg_str(arguments, "scope_kind")
    if scope_kind not in knowledge.SCOPE_KINDS:
        raise ToolError(knowledge.ERROR_INVALID_SCOPE, f"unsupported scope kind: {scope_kind}")
    scope_id = _arg_int(arguments, "scope_id")
    if scope_id < 0:
        raise ToolError("invalid params", "scope_id must not be negative")
    title = _arg_optional_str(arguments, "title")
    source = _arg_optional_str(arguments, "source")
    text = _arg_optional_str(arguments, "text")
    with contextlib.closing(_open()) as conn:
        if scope_kind == knowledge.SCOPE_KIND_BINARY:
            _require_binary(conn, scope_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = knowledge.ingest_document(
                    conn,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                    title=title,
                    source=source,
                    mime="",
                    data=text.encode("utf-8"),
                )
            except knowledge.KnowledgeError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            journal.journaled_ingest(conn, log, payload)
            return log.attach(payload)


def _tool_ingest_url(arguments: dict[str, Any]) -> dict[str, Any]:
    """Fetch a URL and store it as a knowledge document; off by default."""
    if not remote_ingest.remote_enabled():
        raise ToolError(remote_ingest.ERROR_DISABLED, remote_ingest.DISABLED_DETAIL)
    scope_kind = _arg_str(arguments, "scope_kind")
    if scope_kind not in knowledge.SCOPE_KINDS:
        raise ToolError(knowledge.ERROR_INVALID_SCOPE, f"unsupported scope kind: {scope_kind}")
    scope_id = _arg_int(arguments, "scope_id")
    if scope_id < 0:
        raise ToolError("invalid params", "scope_id must not be negative")
    url = _arg_str(arguments, "url")
    title = _arg_optional_str(arguments, "title")
    with contextlib.closing(_open()) as conn:
        if scope_kind == knowledge.SCOPE_KIND_BINARY:
            _require_binary(conn, scope_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = remote_ingest.ingest_url(
                    conn,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                    url=url,
                    title=title,
                )
            except remote_ingest.RemoteIngestError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            except knowledge.KnowledgeError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            journal.journaled_ingest(conn, log, payload)
            return log.attach(payload)


def _tool_delete_document(arguments: dict[str, Any]) -> dict[str, Any]:
    document_id = _arg_int(arguments, "document_id")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="chunks",
                where="document_id = ?",
                params=(document_id,),
                description=f"deleted the chunks of document {document_id}",
            )
            journal.journaled_rows(
                conn,
                log,
                table="documents",
                where="id = ?",
                params=(document_id,),
                description=f"deleted document {document_id}",
            )
            if not store.delete_document(conn, document_id):
                raise ToolError("document not found", f"no document with id {document_id}")
            return log.attach({"document_id": document_id, "deleted": True})


def _tool_search(arguments: dict[str, Any]) -> dict[str, Any]:
    query = _arg_str(arguments, "query")
    limit = _arg_optional_int(arguments, "limit", store.DEFAULT_SEARCH_LIMIT)
    kind = _arg_optional_str(arguments, "kind", store.SEARCH_KIND_ALL)
    with contextlib.closing(_open()) as conn:
        try:
            results = store.search(conn, query, limit=limit, kind=kind)
        except store.SearchError as exc:
            raise ToolError(exc.code, exc.detail) from None
    return {"query": query, "kind": kind, **results}


def _tool_extract_archive(arguments: dict[str, Any]) -> dict[str, Any]:
    # Imported lazily: `reportal.api` imports `reportal.integrations`, which
    # imports this module, so a top-level import would be circular.
    from reportal.api import ExtractError, extract_archive_binary

    binary_id = _arg_int(arguments, "binary_id")
    password = _arg_optional_str(arguments, "password")
    collection_id = _arg_optional_int(arguments, "collection_id", 0)
    with contextlib.closing(_open()) as conn:
        try:
            return extract_archive_binary(
                conn, binary_id, password=password, collection_id=collection_id
            )
        except ExtractError as exc:
            raise ToolError(exc.code, exc.detail) from None


# ── Journal tools ──────────────────────────────────────────────────


def _journal_error_text(exc: Exception) -> str:
    """Return a journal failure's message without the KeyError quoting."""
    return str(exc.args[0]) if exc.args else str(exc)


def _tool_list_journal(arguments: dict[str, Any]) -> dict[str, Any]:
    limit = _arg_optional_int(arguments, "limit", journal.DEFAULT_LIST_LIMIT)
    action = _arg_optional_str(arguments, "action")
    with contextlib.closing(_open()) as conn:
        entries = journal.list_entries(conn, action=action or None, limit=limit)
    return {"entries": entries, "count": len(entries)}


def _tool_revert_journal_entry(arguments: dict[str, Any]) -> dict[str, Any]:
    has_action = "action" in arguments
    has_entry = "entry_id" in arguments
    if has_action == has_entry:
        raise ToolError("invalid body", "provide exactly one of action or entry_id")
    with contextlib.closing(_open()) as conn:
        try:
            if has_entry:
                return journal.revert_entry(conn, _arg_int(arguments, "entry_id"))
            return journal.revert_action(conn, _arg_str(arguments, "action"))
        except journal.UnknownActionError as exc:
            raise ToolError("action not found", _journal_error_text(exc)) from exc
        except journal.UnknownEntryError as exc:
            raise ToolError("entry not found", _journal_error_text(exc)) from exc
        except journal.EntryNotActiveError as exc:
            raise ToolError("not-active", str(exc)) from exc
        except journal.JournalError as exc:
            raise ToolError("journal-error", _journal_error_text(exc)) from exc


# ── Family tools ───────────────────────────────────────────────────


def _tool_list_families(arguments: dict[str, Any]) -> dict[str, Any]:
    with contextlib.closing(_open()) as conn:
        return {"families": families.list_families(conn)}


def _tool_get_detect_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return _stored_scan(conn, binary_id, store.SCAN_KIND_DETECT, "run_detect")


def _tool_register_family(arguments: dict[str, Any]) -> dict[str, Any]:
    name = _arg_str(arguments, "name")
    reference_binary_id = _arg_int(arguments, "reference_binary_id")
    aliases = _arg_str_list(arguments, "aliases")
    notes = _arg_optional_str(arguments, "notes")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                family = families.register_family(
                    conn,
                    name=name,
                    reference_binary_id=reference_binary_id,
                    aliases=aliases,
                    notes=notes,
                    engine=engines.get_engine(),
                )
            except families.FamilyError as exc:
                raise _family_error(exc) from exc
            except engines.EngineUnavailable as exc:
                raise ToolError("engine-unavailable", str(exc)) from exc
            except KeyError as exc:
                raise ToolError("binary not found", str(exc.args[0])) from exc
            except FileNotFoundError as exc:
                raise ToolError("binary not on disk", str(exc)) from exc
            except engines.EngineError as exc:
                raise ToolError("engine-error", str(exc)) from exc
            journal.journaled_create(
                log,
                table="families",
                key=int(family["family_id"]),
                description=f"registered family {family['family_id']}",
            )
            return log.attach(family)


def _tool_delete_family(arguments: dict[str, Any]) -> dict[str, Any]:
    family_id = _arg_int(arguments, "family_id")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="families",
                where="id = ?",
                params=(family_id,),
                description=f"deleted family {family_id}",
            )
            if not families.delete_family(conn, family_id):
                raise ToolError("family not found", f"no family with id {family_id}")
            return log.attach({"family_id": family_id, "deleted": True})


def _tool_run_detect(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            return _journaled_scan_run(
                conn,
                binary_id,
                store.SCAN_KIND_DETECT,
                lambda: families.detect_binary(
                    conn, binary_id=binary_id, engine=engines.get_engine()
                ),
            )
        except engines.EngineUnavailable as exc:
            raise ToolError("engine-unavailable", str(exc)) from exc
        except FileNotFoundError as exc:
            raise ToolError("binary not on disk", str(exc)) from exc
        except engines.EngineError as exc:
            raise ToolError("engine-error", str(exc)) from exc


# ── Schema helpers ─────────────────────────────────────────────────


def _int(description: str) -> dict[str, Any]:
    return {"type": "integer", "description": description}


def _str(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def _bool(description: str) -> dict[str, Any]:
    return {"type": "boolean", "description": description}


def _number(description: str) -> dict[str, Any]:
    return {"type": "number", "description": description}


def _enum(description: str, values: Sequence[str]) -> dict[str, Any]:
    return {"type": "string", "description": description, "enum": list(values)}


def _array(description: str, items: dict[str, Any]) -> dict[str, Any]:
    return {"type": "array", "description": description, "items": items}


def _object(properties: dict[str, Any], required: Sequence[str] = ()) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    return schema


_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False)
_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=True)

_FUNCTION_ID = _int("Function id.")
_BINARY_ID = _int("Binary id.")
_COLLECTION_ID = _int("Collection id.")


def builtin_tools() -> tuple[Tool, ...]:
    """The tools reportal ships in-tree, read tools first."""
    return (
        Tool(
            "list_binaries",
            "List every registered binary with its function count.",
            _object({}),
            _READ,
            _tool_list_binaries,
        ),
        Tool(
            "get_binary",
            "Return one binary by id.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_binary,
        ),
        Tool(
            "list_functions",
            "List function rows, optionally scoped to a binary or an analysis.",
            _object(
                {
                    "binary_id": _int("Limit to one binary's functions."),
                    "analysis_id": _int("Limit to one analysis's functions."),
                }
            ),
            _READ,
            _tool_list_functions,
        ),
        Tool(
            "get_function",
            "Return one function by id.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_function,
        ),
        Tool(
            "get_fingerprint",
            "Return a binary's stored fingerprint, else compute one live through"
            " rebrew without storing it.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_fingerprint,
        ),
        Tool(
            "get_imports",
            "Return a binary's live import table from rebrew (never stored).",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_imports,
        ),
        Tool(
            "get_strings",
            "Return a binary's live extracted strings from rebrew (never stored).",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_strings,
        ),
        Tool(
            "read_memory",
            "Read a window of a binary's bytes by address through the engine: an absolute"
            " virtual address, an RVA or a raw file offset.  Defaults to 64 bytes, capped at"
            " 1024, and refuses an address not backed by the image's raw bytes.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "address": _int("Address to read from."),
                    "length": _int(
                        f"Bytes to read (default {engines.MEMORY_READ_DEFAULT},"
                        f" max {engines.MEMORY_READ_MAX})."
                    ),
                    "kind": _enum(
                        "Address kind: an absolute VA, an RVA or a raw file offset.",
                        tuple(sorted(engines.MEMORY_ADDRESS_KINDS)),
                    ),
                },
                ("binary_id", "address"),
            ),
            _READ,
            _tool_read_memory,
        ),
        Tool(
            "get_tags",
            "List all tags with their binary counts; with binary_id, only that binary's tags.",
            _object({"binary_id": _int("Limit to one binary's tags.")}),
            _READ,
            _tool_get_tags,
        ),
        Tool(
            "get_triage",
            "Return a binary's stored triage dossier; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_triage,
        ),
        Tool(
            "get_function_triage",
            "Return a binary's stored per-function triage summaries and scores;"
            " fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_function_triage,
        ),
        Tool(
            "get_report",
            "Return a binary's stored report result; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_report,
        ),
        Tool(
            "get_pdf_status",
            "Report whether a binary's generated PDF report exists, with its path,"
            " size and page count.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_pdf_status,
        ),
        Tool(
            "get_structs",
            "Return a binary's stored struct recovery; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_structs,
        ),
        Tool(
            "list_data_types",
            "List a binary's editable type model with each type's size and members.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_list_data_types,
        ),
        Tool(
            "get_data_type_history",
            "List a data type's edit history, newest first, with each entry's per-field"
            " diff; a deleted type's history stays listed.",
            _object({"data_type_id": _int("Data type id.")}, ("data_type_id",)),
            _READ,
            _tool_get_data_type_history,
        ),
        Tool(
            "get_signature",
            "Return a function's stored signature with its return type and parameters.",
            _object({"function_id": _int("Function id.")}, ("function_id",)),
            _READ,
            _tool_get_signature,
        ),
        Tool(
            "list_signatures",
            "List a binary's stored function signatures, ordered by name.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_list_signatures,
        ),
        Tool(
            "get_signature_history",
            "List a function's signature-edit history, newest first.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_signature_history,
        ),
        Tool(
            "get_crypto_scan",
            "Return a binary's stored crypto scan; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_crypto_scan,
        ),
        Tool(
            "get_pe_info",
            "Return a binary's stored PE metadata; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_pe_info,
        ),
        Tool(
            "get_filetype",
            "Return a binary's stored file-type detection (packers, protectors, installers,"
            " runtimes and toolchains); fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_filetype,
        ),
        Tool(
            "get_security_scan",
            "Return a binary's stored security scan; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_security_scan,
        ),
        Tool(
            "get_capabilities",
            "Return a binary's stored capability scan; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_capabilities,
        ),
        Tool(
            "get_threat_report",
            "Return a binary's stored threat report; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_threat_report,
        ),
        Tool(
            "get_remediation",
            "Return a binary's stored YARA remediation rule; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_remediation,
        ),
        Tool(
            "get_secrets_scan",
            "Return a binary's stored secrets scan; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_secrets_scan,
        ),
        Tool(
            "get_protocols_scan",
            "Return a binary's stored protocol inference; fails when none was stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_protocols_scan,
        ),
        Tool(
            "get_behavior_scan",
            "Return a binary's stored behavior scan for one domain, or all three when no"
            " domain is named; fails when none was stored.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "domain": _enum(
                        "Behavior domain: execution, networking or filesystem.",
                        behavior.BEHAVIOR_DOMAINS,
                    ),
                },
                ("binary_id",),
            ),
            _READ,
            _tool_get_behavior_scan,
        ),
        Tool(
            "get_hardening_scan",
            "Return a binary's stored hardening scan for one domain (anti-analysis or"
            " obfuscation), or both when no domain is named; fails when none was stored.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "domain": _enum(
                        "Hardening domain: anti-analysis or obfuscation.",
                        hardening.HARDENING_DOMAINS,
                    ),
                },
                ("binary_id",),
            ),
            _READ,
            _tool_get_hardening_scan,
        ),
        Tool(
            "get_unstrip",
            "Return a binary's stored unstrip proposals; fails when none were stored.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_unstrip,
        ),
        Tool(
            "get_matches",
            "List the recorded match candidates of one function.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_matches,
        ),
        Tool(
            "get_lineage",
            "Return a stored lineage comparison of two binaries, or every comparison"
            " stored for one binary when no other binary id is given.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "other_binary_id": _int("The binary compared against."),
                },
                ("binary_id",),
            ),
            _READ,
            _tool_get_lineage,
        ),
        Tool(
            "get_related_binaries",
            "Return a binary's stored relationship ranking of the other binaries in"
            " the store; fails when none was run.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_related_binaries,
        ),
        Tool(
            "get_composition",
            "Return a binary's stored composition analysis: the matched counts, the"
            " name-source and quality breakdowns and the per-binary rollup; fails when"
            " none was run.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_composition,
        ),
        Tool(
            "list_families",
            "List the locally registered malware families with their stored signature"
            " bundles.  reportal bundles no external threat-intelligence feed.",
            _object({}),
            _READ,
            _tool_list_families,
        ),
        Tool(
            "get_detect_scan",
            "Return a binary's stored family detection; fails when none was run.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_detect_scan,
        ),
        Tool(
            "diff_functions",
            "Align two functions' disassembly or decompilation side by side, with the"
            " changed lines marked.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "candidate_function_id": _int("Candidate function id."),
                    "kind": _enum("Listing kind.", ("disasm", "decomp")),
                    "normalize": _bool(
                        "Strip addresses, encoded bytes and comments before comparing."
                    ),
                },
                ("function_id", "candidate_function_id"),
            ),
            _READ,
            _tool_diff_functions,
        ),
        Tool(
            "get_disasm",
            "Return a function's NASM or hex disassembly through its rebrew project.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "format": _enum("Output format.", ("nasm", "hex")),
                },
                ("function_id",),
            ),
            _READ,
            _tool_get_disasm,
        ),
        Tool(
            "get_decompilation",
            "Return a function's stored decompilation, else compute one live through"
            " rebrew without storing it.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "backend": _enum(
                        "Decompiler backend.",
                        ("auto", "kuna", "r2ghidra", "r2dec", "ghidra"),
                    ),
                    "named": _bool("Ask rebrew to apply known symbol names."),
                },
                ("function_id",),
            ),
            _READ,
            _tool_get_decompilation,
        ),
        Tool(
            "get_xrefs",
            "List live cross-references to a function through its rebrew project.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "kinds": _array("Keep only these reference kinds.", _str("A ref kind.")),
                },
                ("function_id",),
            ),
            _READ,
            _tool_get_xrefs,
        ),
        Tool(
            "get_history",
            "List a function's rename history, newest first.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_history,
        ),
        Tool(
            "get_summary",
            "Return the stored AI summary of a function; never calls the model.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_summary,
        ),
        Tool(
            "get_ai_comments",
            "Return the stored AI inline comments of a function; never calls the model.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_ai_comments,
        ),
        Tool(
            "list_comments",
            "List the analyst comments stored on a binary or function, oldest first.",
            _object(
                {
                    "scope_kind": _enum("Scope kind.", comments.SCOPE_KINDS),
                    "scope_id": _int("Scope id (a binary id or a function id)."),
                },
                ("scope_kind", "scope_id"),
            ),
            _READ,
            _tool_list_comments,
        ),
        Tool(
            "get_type_suggestions",
            "Return the stored AI type suggestions of a function; never calls the model.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_type_suggestions,
        ),
        Tool(
            "get_renames",
            "Return a function's stored identifier rename suggestions; never calls the model.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_renames,
        ),
        Tool(
            "list_conversations",
            "List conversations, optionally filtered by scope kind and id.",
            _object(
                {
                    "scope_kind": _enum("Scope kind.", ("function", "binary")),
                    "scope_id": _int("Scope id to filter on."),
                }
            ),
            _READ,
            _tool_list_conversations,
        ),
        Tool(
            "get_conversation",
            "Return one conversation with its messages.",
            _object({"conversation_id": _int("Conversation id.")}, ("conversation_id",)),
            _READ,
            _tool_get_conversation,
        ),
        Tool(
            "get_pipeline",
            "Return a function's latest AI decompilation run with its steps and artifacts.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_pipeline,
        ),
        Tool(
            "list_components",
            "List the pipeline component registry: each entry's name, coeffects,"
            " effects, origin and reloadability.",
            _object({}),
            _READ,
            _tool_list_components,
        ),
        Tool(
            "list_integrations",
            "List every plugin seam (pipeline components, auto-mode workers, graph"
            " backends, effect handlers, MCP tools) with the parts its registry holds.",
            _object({}),
            _READ,
            _tool_list_integrations,
        ),
        Tool(
            "get_auto_run",
            "Return an auto run with its task tree and coverage delta, by run id or as a"
            " binary's latest run.",
            _object(
                {
                    "run_id": _int("Auto run id."),
                    "binary_id": _int("Binary id, for its latest auto run."),
                }
            ),
            _READ,
            _tool_get_auto_run,
        ),
        Tool(
            "list_documents",
            "List knowledge documents, optionally filtered by scope kind and id,"
            " without their stored text.",
            _object(
                {
                    "scope_kind": _enum("Scope kind.", knowledge.SCOPE_KINDS),
                    "scope_id": _int("Scope id to filter on."),
                }
            ),
            _READ,
            _tool_list_documents,
        ),
        Tool(
            "search_knowledge",
            "Rank stored knowledge document chunks against a query and return the"
            " best snippets with their document and score.",
            _object(
                {
                    "query": _str("Search query."),
                    "scope_kind": _enum("Scope kind to search.", knowledge.SCOPE_KINDS),
                    "scope_id": _int("Scope id to search."),
                    "limit": _int("Maximum results (default 10)."),
                },
                ("query",),
            ),
            _READ,
            _tool_search_knowledge,
        ),
        Tool(
            "retrieve_knowledge",
            "Retrieve the best knowledge document snippets for a query, scoped to a"
            " binary or to the binary of a function; read-only.",
            _object(
                {
                    "query": _str("Search query."),
                    "binary_id": _int("Binary id to scope the search to."),
                    "function_id": _int("Function id; searches its binary's documents."),
                    "limit": _int(f"Maximum results (default {knowledge.RETRIEVAL_LIMIT})."),
                },
                ("query",),
            ),
            _READ,
            _tool_retrieve_knowledge,
        ),
        Tool(
            "get_graph",
            "Return a binary's stored knowledge graph with node degrees;"
            " document nodes are left out unless include_documents is true.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "kind": _enum("Keep one node kind.", graph.GRAPH_NODE_KINDS),
                    "include_documents": _bool("Include document nodes and their mention edges."),
                },
                ("binary_id",),
            ),
            _READ,
            _tool_get_graph,
        ),
        Tool(
            "graph_neighbors",
            "Return one graph node with its incoming and outgoing edges grouped by relation.",
            _object({"node_id": _str("Graph node id.")}, ("node_id",)),
            _READ,
            _tool_graph_neighbors,
        ),
        Tool(
            "list_graph_backends",
            "List the registered knowledge-graph backends with their availability"
            " and whether each supports querying.",
            _object({}),
            _READ,
            _tool_list_graph_backends,
        ),
        Tool(
            "run_fingerprint",
            "Compute and store a binary fingerprint through rebrew.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_fingerprint,
        ),
        Tool(
            "rename_function",
            "Rename a function and record it in the rename history.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "name": _str("New function name."),
                    "actor": _str("Who made the change (default: mcp)."),
                },
                ("function_id", "name"),
            ),
            _WRITE,
            _tool_rename_function,
        ),
        Tool(
            "revert_name",
            "Restore the name a rename-history row replaced.",
            _object(
                {"function_id": _FUNCTION_ID, "history_id": _int("Rename-history id.")},
                ("function_id", "history_id"),
            ),
            _WRITE,
            _tool_revert_name,
        ),
        Tool(
            "apply_match",
            "Copy a recorded match candidate's name, signature, or both onto a function."
            " A signature transfer refuses a differing non-empty calling convention"
            " (signature-conflict) and reports a referenced local type it cannot resolve.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "candidate_function_id": _int("Recorded candidate function id."),
                    "mode": _enum(
                        "What to copy: name, signature or both (default: name).",
                        matching.TRANSFER_MODES,
                    ),
                    "actor": _str("Who made the change (default: mcp)."),
                },
                ("function_id", "candidate_function_id"),
            ),
            _WRITE,
            _tool_apply_match,
        ),
        Tool(
            "run_match",
            "Rank a binary's functions against the local corpus under Match Settings and store"
            " the matches. The platform/architecture scope is a coarse filter over the stored"
            " fingerprint (else the suffix-derived format/arch columns), not a guarantee.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "min_similarity": _number("Minimum similarity percent for a candidate."),
                    "min_confidence": _number("Minimum softmax confidence for a candidate."),
                    "top": _int("Maximum candidates per function."),
                    "include_self": _bool("Allow the binary's own functions as candidates."),
                    "platforms": _array(
                        "Restrict candidates to these platforms.",
                        _enum("A platform.", matching.PLATFORMS),
                    ),
                    "architectures": _array(
                        "Restrict candidates to these architectures.",
                        _enum("An architecture.", matching.ARCHITECTURES),
                    ),
                    "binary_ids": _array(
                        "Restrict candidates to these binary ids.", _int("A binary id.")
                    ),
                    "collection_ids": _array(
                        "Restrict candidates to the binaries of these collections.",
                        _int("A collection id."),
                    ),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_match,
        ),
        Tool(
            "run_lineage",
            "Compare two binaries' functions and store the comparison on the left binary:"
            " what is unchanged, changed, added or removed.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "other_binary_id": _int("The binary compared against."),
                    "refine": _bool(
                        "Refine placeholder pairings with structural similarity when available."
                    ),
                },
                ("binary_id", "other_binary_id"),
            ),
            _WRITE,
            _tool_run_lineage,
        ),
        Tool(
            "run_related_binaries",
            "Rank the other binaries in the store against one binary by their hashes,"
            " imports, capabilities and size, and store the ranking.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "limit": _int("Maximum related binaries to return."),
                    "include_unrelated": _bool("Include binaries with no relationship."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_related_binaries,
        ),
        Tool(
            "run_composition",
            "Build a binary's composition analysis from the stored matches (matched"
            " counts, name-source and quality breakdowns, per-binary rollup) and store it."
            "  Stored-only: it runs no matching and no engine.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_composition,
        ),
        Tool(
            "register_family",
            "Register a malware family from a reference binary and store the signatures"
            " derived from it (hashes, import set and capabilities).",
            _object(
                {
                    "name": _str("Family name, unique case-insensitively."),
                    "reference_binary_id": _int("Reference binary the signatures come from."),
                    "aliases": _array("Alternative family names.", _str("An alias.")),
                    "notes": _str("Free-form notes about the family."),
                },
                ("name", "reference_binary_id"),
            ),
            _WRITE,
            _tool_register_family,
        ),
        Tool(
            "delete_family",
            "Delete a registered malware family.",
            _object({"family_id": _int("Family id.")}, ("family_id",)),
            _WRITE,
            _tool_delete_family,
        ),
        Tool(
            "run_detect",
            "Match a binary against the registered families and store the detection:"
            " every matched signal with its confidence and evidence.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_detect,
        ),
        Tool(
            "run_triage",
            "Run rebrew's one-shot dossier for a binary and store it.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_triage,
        ),
        Tool(
            "run_function_triage",
            "Summarize and score selected functions (the configured LLM when there"
            " is one, the deterministic heuristic otherwise) and store them.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "function_ids": _array(
                        "Explicit function ids (default: the top candidates).", _FUNCTION_ID
                    ),
                    "limit": _int("Candidate functions to triage (default 10)."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_function_triage,
        ),
        Tool(
            "run_report",
            "Generate rebrew's HTML report and store the coverage summary.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_report,
        ),
        Tool(
            "generate_pdf_report",
            "Render a binary's PDF summary from its stored scans into the workspace"
            " report directory.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_generate_pdf_report,
        ),
        Tool(
            "run_structs",
            "Recover struct definitions through rebrew and store them.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "decompiler": _enum(
                        "Decompiler backend.",
                        ("auto", "kuna", "r2ghidra", "r2dec", "ghidra"),
                    ),
                    "limit": _int("Maximum functions decompiled (default 50)."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_structs,
        ),
        Tool(
            "import_data_types",
            "Seed the binary's editable type model from its stored structs scan.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_import_data_types,
        ),
        Tool(
            "edit_data_type",
            "Edit a data type: set its name, kind, namespace or declared size; add, edit,"
            " reposition or remove a member; convert a member to explicit padding and back;"
            " add, rename, revalue or remove an enum constant; or delete the type.",
            _object(
                {
                    "data_type_id": _int("Data type id."),
                    "name": _str("New type name."),
                    "kind": _enum("New declaration kind.", tuple(data_types.KNOWN_KINDS)),
                    "namespace": _str(
                        "New namespace path; an empty string makes the type program-defined."
                    ),
                    "size": _int("Declared size in bytes."),
                    "member": _object(
                        {
                            "name": _str("Member to edit, by name."),
                            "index": _int("Member to edit, by index."),
                            "new_name": _str("New member name."),
                            "new_type": _str("New member type, e.g. 'unsigned int'."),
                            "new_pointer": _bool("Whether the member is a pointer."),
                            "new_count": _int("Array count; null clears it."),
                            "new_bits": _int("Bit width; null clears the bitfield."),
                        }
                    ),
                    "add_member": _object(
                        {
                            "name": _str("New member name."),
                            "type": _str("New member type."),
                            "pointer": _bool("Whether the member is a pointer."),
                            "count": _int("Array count."),
                            "bits": _int("Bit width, which makes the member a bitfield."),
                            "index": _int("Position the member takes."),
                            "after": _str("Insert the member after this member."),
                        },
                        ("name", "type"),
                    ),
                    "remove_member": _object(
                        {
                            "name": _str("Member to remove, by name."),
                            "index": _int("Member to remove, by index."),
                        }
                    ),
                    "to_gap": _object(
                        {
                            "name": _str("Member to convert, by name."),
                            "index": _int("Member to convert, by index."),
                            "size": _int("Bytes the gap covers (default: the member's own)."),
                        }
                    ),
                    "from_gap": _object(
                        {
                            "name": _str("Gap to convert, by name."),
                            "index": _int("Gap to convert, by index."),
                            "new_name": _str("Name the member takes."),
                            "new_type": _str("Type the member takes."),
                            "pointer": _bool("Whether the member is a pointer."),
                            "count": _int("Array count."),
                            "bits": _int("Bit width, which makes the member a bitfield."),
                        },
                        ("new_name", "new_type"),
                    ),
                    "add_value": _object(
                        {
                            "name": _str("New constant name."),
                            "value": _str(
                                "Value as a decimal or 0x hex literal; omitted, it"
                                " increments from the previous constant."
                            ),
                        },
                        ("name",),
                    ),
                    "edit_value": _object(
                        {
                            "name": _str("Constant to edit, by name."),
                            "index": _int("Constant to edit, by index."),
                            "new_name": _str("New constant name."),
                            "new_value": _str("New value, decimal or 0x hex."),
                        }
                    ),
                    "remove_value": _object(
                        {
                            "name": _str("Constant to remove, by name."),
                            "index": _int("Constant to remove, by index."),
                        }
                    ),
                    "delete": _bool("Delete the whole type."),
                },
                ("data_type_id",),
            ),
            _WRITE,
            _tool_edit_data_type,
        ),
        Tool(
            "export_data_types",
            "Render the type model as one C header at an explicit path.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "path": _str("Header path to write."),
                    "force": _bool("Overwrite an existing file."),
                },
                ("binary_id", "path"),
            ),
            _WRITE,
            _tool_export_data_types,
        ),
        Tool(
            "revert_data_type_history",
            "Restore the type state one history row recorded, undoing that edit; the"
            " revert is itself journaled and a repeat is a no-op.",
            _object(
                {
                    "data_type_id": _int("Data type id."),
                    "history_id": _int("Data-type history id."),
                },
                ("data_type_id", "history_id"),
            ),
            _WRITE,
            _tool_revert_data_type_history,
        ),
        Tool(
            "run_signature_import",
            "Parse the binary's stored decompilations and seed its signature model.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_signature_import,
        ),
        Tool(
            "edit_signature",
            "Set a signature's return type or convention, edit, add, move or remove a parameter,"
            " or delete it.",
            _object(
                {
                    "function_id": _int("Function id."),
                    "return_type": _str("New return type."),
                    "calling_convention": _str("New calling convention, e.g. 'stdcall'."),
                    "parameter": _object(
                        {
                            "index": _int("Parameter index to edit."),
                            "type": _str("New parameter type."),
                            "name": _str("New parameter name."),
                            "at": _str("Arrival location: a register or a stack slot."),
                            "kind": _str("Parameter kind: value, pointer, array or struct."),
                            "bits": _int("Parameter width in bits."),
                        },
                        ("index",),
                    ),
                    "add_parameter": _object(
                        {
                            "type": _str("New parameter type."),
                            "name": _str("New parameter name."),
                            "index": _int("Insert position (default appends)."),
                            "at": _str("Arrival location: a register or a stack slot."),
                            "kind": _str("Parameter kind: value, pointer, array or struct."),
                            "bits": _int("Parameter width in bits."),
                        },
                        ("type",),
                    ),
                    "move_parameter": _object(
                        {
                            "index": _int("Parameter index to move."),
                            "to_index": _int("Position to move it to."),
                        },
                        ("index", "to_index"),
                    ),
                    "remove_parameter": _int("Parameter index to remove."),
                    "delete": _bool("Delete the whole signature."),
                },
                ("function_id",),
            ),
            _WRITE,
            _tool_edit_signature,
        ),
        Tool(
            "export_signatures",
            "Render the signature model as one C prototype header at an explicit path.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "path": _str("Header path to write."),
                    "force": _bool("Overwrite an existing file."),
                },
                ("binary_id", "path"),
            ),
            _WRITE,
            _tool_export_signatures,
        ),
        Tool(
            "revert_signature_history",
            "Restore the signature state one history row recorded, undoing that edit; the"
            " revert is itself journaled and a repeat is a no-op.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "history_id": _int("Signature-history id."),
                },
                ("function_id", "history_id"),
            ),
            _WRITE,
            _tool_revert_signature_history,
        ),
        Tool(
            "run_crypto_scan",
            "Scan a binary for crypto constants and APIs and store the result.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_crypto_scan,
        ),
        Tool(
            "run_pe_info",
            "Inspect a binary's PE identity, sections and security metadata and store the result.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_pe_info,
        ),
        Tool(
            "run_filetype",
            "Detect a binary's file type, packer and protector signatures from the engine's"
            " pe-info, fingerprints, imports and strings, and store the result.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_filetype,
        ),
        Tool(
            "run_security_scan",
            "Scan a binary's rebrew reversed sources for unsafe API use and store the findings.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "min_severity": _enum("Minimum severity to report.", ("high", "medium", "low")),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_security_scan,
        ),
        Tool(
            "run_capabilities",
            "Classify a binary from its imports and strings and store the result.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_capabilities,
        ),
        Tool(
            "run_secrets_scan",
            "Scan a binary's strings for credentials and high-entropy values and store the"
            " findings; values are sensitive.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_secrets_scan,
        ),
        Tool(
            "run_protocols_scan",
            "Infer the network protocols a binary speaks from its imports and strings and"
            " store the result.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_protocols_scan,
        ),
        Tool(
            "run_threat_report",
            "Extract IOCs and map ATT&CK techniques for a binary, storing the report;"
            " the optional narrative asks the configured LLM.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "narrative": _bool("Ask the configured LLM for an analyst summary."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_threat_report,
        ),
        Tool(
            "run_remediation",
            "Generate a YARA rule from a binary's strings, validate it with yarac and store it.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_run_remediation,
        ),
        Tool(
            "run_behavior_scan",
            "Match a binary's imports and strings against the behavior rule table for one"
            " domain (all three when none is named) and store the result.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "domain": _enum(
                        "Behavior domain: execution, networking or filesystem.",
                        behavior.BEHAVIOR_DOMAINS,
                    ),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_behavior_scan,
        ),
        Tool(
            "run_hardening_scan",
            "Scan a binary's imports, strings, fingerprint and stored triage against the"
            " hardening heuristics for one domain (both when none is named) and store the"
            " result.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "domain": _enum(
                        "Hardening domain: anti-analysis or obfuscation.",
                        hardening.HARDENING_DOMAINS,
                    ),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_hardening_scan,
        ),
        Tool(
            "run_unstrip",
            "Identify a binary's library functions and store the rename proposals.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "min_confidence": _number("Minimum engine confidence a proposal must reach."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_unstrip,
        ),
        Tool(
            "build_graph",
            "Rebuild a binary's knowledge graph from the stored rows.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _WRITE,
            _tool_build_graph,
        ),
        Tool(
            "sync_graph_backend",
            "Push a binary's stored knowledge graph to a graph backend; the configured"
            " backend runs when none is named.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "backend": _str("Backend name; defaults to the configured backend."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_sync_graph_backend,
        ),
        Tool(
            "apply_unstrip",
            "Apply one stored unstrip proposal, recording the rename.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "name": _str("Override the proposed name."),
                },
                ("function_id",),
            ),
            _WRITE,
            _tool_apply_unstrip,
        ),
        Tool(
            "run_summary",
            "Summarize a function's stored decompilation with the configured LLM and store it.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _WRITE,
            _tool_run_summary,
        ),
        Tool(
            "run_ai_comments",
            "Write inline comments for a function's stored decompilation and store them.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _WRITE,
            _tool_run_ai_comments,
        ),
        Tool(
            "run_type_suggestions",
            "Suggest types for a function's stored decompilation and store them.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _WRITE,
            _tool_run_type_suggestions,
        ),
        Tool(
            "suggest_renames",
            "Suggest identifier renames for a function's stored decompilation and store them.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _WRITE,
            _tool_suggest_renames,
        ),
        Tool(
            "apply_renames",
            "Apply rename suggestions to a function's stored decompilation, journaling the"
            " previous text so the apply can be reverted; optionally renames the function.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "applied": _array(
                        "Suggestions to apply; every stored one when omitted.",
                        _object(
                            {
                                "from": _str("Identifier as written in the decompilation."),
                                "to": _str("New name for the identifier."),
                                "kind": _enum("Identifier kind.", llm.RENAME_KINDS),
                                "reason": _str("Why the name is better."),
                                "confidence": _number("Model confidence, 0 to 1."),
                            },
                            ("from", "to"),
                        ),
                    ),
                    "rename_function": _bool(
                        "Also rename the function row for a function-kind suggestion."
                    ),
                },
                ("function_id",),
            ),
            _WRITE,
            _tool_apply_renames,
        ),
        Tool(
            "revert_renames",
            "Restore the decompilation text the last apply renamed.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _WRITE,
            _tool_revert_renames,
        ),
        Tool(
            "create_conversation",
            "Create a conversation scoped to one stored function or binary.",
            _object(
                {
                    "scope_kind": _enum("Scope kind.", ("function", "binary")),
                    "scope_id": _int("Function or binary id to scope to."),
                    "title": _str("Conversation title (default: derived from the scope)."),
                },
                ("scope_kind", "scope_id"),
            ),
            _WRITE,
            _tool_create_conversation,
        ),
        Tool(
            "send_conversation_message",
            "Send one message to a conversation through the configured LLM.",
            _object(
                {
                    "conversation_id": _int("Conversation id."),
                    "content": _str("Message content."),
                },
                ("conversation_id", "content"),
            ),
            _WRITE,
            _tool_send_conversation_message,
        ),
        Tool(
            "delete_conversation",
            "Delete a conversation and its messages.",
            _object({"conversation_id": _int("Conversation id.")}, ("conversation_id",)),
            _WRITE,
            _tool_delete_conversation,
        ),
        Tool(
            "run_pipeline",
            "Run the AI decompilation pipeline over one function and store the run.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "disabled": _array("Component names to skip.", _str("A component name.")),
                },
                ("function_id",),
            ),
            _WRITE,
            _tool_run_pipeline,
        ),
        Tool(
            "revert_pipeline_run",
            "Undo the writes a stored pipeline run journaled.",
            _object({"run_id": _int("Pipeline run id.")}, ("run_id",)),
            _WRITE,
            _tool_revert_pipeline_run,
        ),
        Tool(
            "reload_components",
            "Reload one component's declaration from its module, or every reloadable"
            " one, swapping the live registry entry; an in-process registration is"
            " not reloadable.",
            _object(
                {
                    "name": _str("Component to reload."),
                    "all": _bool("Reload every reloadable component."),
                }
            ),
            _WRITE,
            _tool_reload_components,
        ),
        Tool(
            "deactivate_components",
            "Withdraw one component's contribution from the live composition: run its"
            " revert where declared and revoke the names it provided. A component that"
            " provides nothing and declares no revert cannot be withdrawn.",
            _object({"name": _str("Component to withdraw.")}, ("name",)),
            _WRITE,
            _tool_deactivate_components,
        ),
        Tool(
            "run_auto",
            "Decompose a binary's unmatched functions into batches, work them with a worker"
            " and return the run with its coverage delta. A dry run unless execute is true.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "worker": _str("Worker name (default offline)."),
                    "execute": _bool("Write C files into the rebrew project and compile them."),
                    "concurrency": _int("Maximum live worker calls."),
                    "functions_per_task": _int("Functions per leaf batch."),
                    "max_attempts": _int("Attempts per function."),
                    "max_tasks": _int("Maximum task rows the run creates."),
                    "disabled": _array("Worker names to refuse.", _str("A worker name.")),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_auto,
        ),
        Tool(
            "revert_auto_run",
            "Remove the files a stored auto run wrote, restore the statuses it changed and"
            " delete its rows.",
            _object({"run_id": _int("Auto run id.")}, ("run_id",)),
            _WRITE,
            _tool_revert_auto_run,
        ),
        Tool(
            "recover_auto_run",
            "Merge the writes a stale auto run's unfinished tasks recorded into its undo"
            " plan, mark those tasks interrupted and close the run.",
            _object({"run_id": _int("Auto run id.")}, ("run_id",)),
            _WRITE,
            _tool_recover_auto_run,
        ),
        Tool(
            "create_tag",
            "Create a tag by name, returning the existing one when it is already known.",
            _object({"name": _str("Tag name.")}, ("name",)),
            _WRITE,
            _tool_create_tag,
        ),
        Tool(
            "tag_binary",
            "Link a tag to a binary by name (created if needed) or by id.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "name": _str("Tag name to link, creating it when new."),
                    "tag_id": _int("Existing tag id to link."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_tag_binary,
        ),
        Tool(
            "untag_binary",
            "Unlink a tag from a binary.",
            _object(
                {"binary_id": _BINARY_ID, "tag_id": _int("Tag id to unlink.")},
                ("binary_id", "tag_id"),
            ),
            _WRITE,
            _tool_untag_binary,
        ),
        Tool(
            "export_zipped_binary",
            "Write a stored binary as a zip whose member is password protected.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "path": _str("Target path for the archive."),
                    "password": _str(f"Password; defaults to {zipcrypto.DEFAULT_PASSWORD!r}."),
                },
                ("binary_id", "path"),
            ),
            _WRITE,
            _tool_export_zipped_binary,
        ),
        Tool(
            "get_die_info",
            "Identify a binary the way Detect-It-Easy does, from the stored scans.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_die_info,
        ),
        Tool(
            "get_additional_details",
            "Read a binary's overlay, Rich header, debug entries and directory presence.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_additional_details,
        ),
        Tool(
            "get_details_status",
            "Report which scans the binary-detail reads have, and what fills a gap.",
            _object({"binary_id": _BINARY_ID}, ("binary_id",)),
            _READ,
            _tool_get_details_status,
        ),
        Tool(
            "get_config",
            "Read what this instance can do: versions, features, limits and tool counts.",
            _object({}),
            _READ,
            _tool_get_config,
        ),
        Tool(
            "list_collections",
            "List collections with their member and tag counts.",
            _object({}),
            _READ,
            _tool_list_collections,
        ),
        Tool(
            "get_collection",
            "Read one collection with its member binaries and tags.",
            _object({"collection_id": _COLLECTION_ID}, ("collection_id",)),
            _READ,
            _tool_get_collection,
        ),
        Tool(
            "create_collection",
            "Create a collection from a name, with an optional description and scope.",
            _object(
                {
                    "name": _str("Collection name, unique."),
                    "description": _str("Free-text description."),
                    "scope": _str("Scope label."),
                },
                ("name",),
            ),
            _WRITE,
            _tool_create_collection,
        ),
        Tool(
            "update_collection",
            "Rename a collection or set its description and scope; omitted fields stay.",
            _object(
                {
                    "collection_id": _COLLECTION_ID,
                    "name": _str("New name."),
                    "description": _str("New description."),
                    "scope": _str("New scope label."),
                },
                ("collection_id",),
            ),
            _WRITE,
            _tool_update_collection,
        ),
        Tool(
            "delete_collection",
            "Delete a collection with its membership and tag links.",
            _object({"collection_id": _COLLECTION_ID}, ("collection_id",)),
            _WRITE,
            _tool_delete_collection,
        ),
        Tool(
            "set_collection_members",
            "Make the given binary ids the exact members of a collection.",
            _object(
                {
                    "collection_id": _COLLECTION_ID,
                    "binary_ids": _array("The complete member list.", _BINARY_ID),
                },
                ("collection_id", "binary_ids"),
            ),
            _WRITE,
            _tool_set_collection_members,
        ),
        Tool(
            "set_collection_tags",
            "Replace a collection's tags with the names given (an empty list clears them).",
            _object(
                {
                    "collection_id": _COLLECTION_ID,
                    "tags": _array("The complete tag set.", _str("Tag name.")),
                },
                ("collection_id", "tags"),
            ),
            _WRITE,
            _tool_set_collection_tags,
        ),
        Tool(
            "add_comment",
            "Store one analyst comment on a binary or function.",
            _object(
                {
                    "scope_kind": _enum("Scope kind.", comments.SCOPE_KINDS),
                    "scope_id": _int("Scope id (a binary id or a function id)."),
                    "body": _str(f"Comment text, at most {comments.MAX_COMMENT_CHARS} characters."),
                    "author": _str(f"Author name (default {comments.DEFAULT_AUTHOR})."),
                },
                ("scope_kind", "scope_id", "body"),
            ),
            _WRITE,
            _tool_add_comment,
        ),
        Tool(
            "update_comment",
            "Replace an analyst comment's body.",
            _object(
                {
                    "comment_id": _int("Comment id."),
                    "body": _str(
                        f"New comment text, at most {comments.MAX_COMMENT_CHARS} characters."
                    ),
                },
                ("comment_id", "body"),
            ),
            _WRITE,
            _tool_update_comment,
        ),
        Tool(
            "delete_comment",
            "Delete one analyst comment by id.",
            _object({"comment_id": _int("Comment id.")}, ("comment_id",)),
            _WRITE,
            _tool_delete_comment,
        ),
        Tool(
            "bulk_binaries",
            "Apply one action (add_tag, remove_tag, delete) to many binaries and report"
            " the per-id result; an unknown id is skipped, not a batch failure.",
            _object(
                {
                    "action": _enum("Action to apply.", bulk_actions.BINARY_ACTIONS),
                    "binary_ids": _array("Binary ids.", _BINARY_ID),
                    "tag": _str("Tag name for add_tag and remove_tag."),
                },
                ("action", "binary_ids"),
            ),
            _WRITE,
            _tool_bulk_binaries,
        ),
        Tool(
            "bulk_functions",
            "Apply one action (rename, clear_matches) to many functions and report the"
            " per-id result; an unknown id is skipped, not a batch failure.",
            _object(
                {
                    "action": _enum("Action to apply.", bulk_actions.FUNCTION_ACTIONS),
                    "function_ids": _array("Function ids.", _FUNCTION_ID),
                    "prefix": _str("Prefix the rename adds to each function name."),
                    "replace": _bool("Drop the name's leading segment before adding the prefix."),
                },
                ("action", "function_ids"),
            ),
            _WRITE,
            _tool_bulk_functions,
        ),
        Tool(
            "ingest_document",
            "Store a document (or pasted note) in a binary's or the project's knowledge"
            " scope, chunking it and embedding it when an endpoint is configured.",
            _object(
                {
                    "scope_kind": _enum("Scope kind.", knowledge.SCOPE_KINDS),
                    "scope_id": _int("Scope id (a binary id for the binary scope)."),
                    "title": _str("Document title (default: untitled)."),
                    "source": _str("Where the text came from (a file name or label)."),
                    "text": _str("Document text."),
                },
                ("scope_kind", "scope_id", "text"),
            ),
            _WRITE,
            _tool_ingest_document,
        ),
        Tool(
            "ingest_url",
            "Fetch an http(s) URL and store its text as a knowledge document in a"
            " binary's or the project's scope; disabled unless reported enabled by"
            " GET /api/knowledge/config.",
            _object(
                {
                    "scope_kind": _enum("Scope kind.", knowledge.SCOPE_KINDS),
                    "scope_id": _int("Scope id (a binary id for the binary scope)."),
                    "url": _str("http(s) URL to fetch."),
                    "title": _str("Document title (default: untitled)."),
                },
                ("scope_kind", "scope_id", "url"),
            ),
            _WRITE,
            _tool_ingest_url,
        ),
        Tool(
            "delete_document",
            "Delete a knowledge document and, by cascade, its chunks.",
            _object({"document_id": _int("Document id.")}, ("document_id",)),
            _WRITE,
            _tool_delete_document,
        ),
        Tool(
            "search",
            "Search binaries, functions, collections and tags by substring, or by one"
            " typed query (sha256, binary, collection or tag).",
            _object(
                {
                    "query": _str("Substring or typed query to search for."),
                    "limit": _int(
                        f"Maximum rows per group (default {store.DEFAULT_SEARCH_LIMIT})."
                    ),
                    "kind": _enum(
                        "Query type (default all, the substring search).", store.SEARCH_KINDS
                    ),
                },
                ("query",),
            ),
            _READ,
            _tool_search,
        ),
        Tool(
            "extract_archive",
            "Unpack a stored archive and register the binaries it holds, reporting each"
            " member with the binary id it became or the reason it was skipped. The"
            " binaries join one collection as one journaled action.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "password": _str("Archive password, when the archive is encrypted."),
                    "collection_id": _int("Collection to add the members to (default: a new one)."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_extract_archive,
        ),
        Tool(
            "list_journal",
            "List recorded action-journal entries newest first, optionally narrowed to one"
            " action id; the descriptor payload is not returned.",
            _object(
                {
                    "action": _str("Only the entries of this action id."),
                    "limit": _int(f"Maximum entries (default {journal.DEFAULT_LIST_LIMIT})."),
                }
            ),
            _READ,
            _tool_list_journal,
        ),
        Tool(
            "revert_journal_entry",
            "Revert one recorded action (by action id) or one journal entry (by entry id),"
            " replaying its stored inverses newest-first.",
            _object(
                {
                    "action": _str("Action id to revert."),
                    "entry_id": _int("One journal entry id to revert."),
                }
            ),
            _WRITE,
            _tool_revert_journal_entry,
        ),
    )

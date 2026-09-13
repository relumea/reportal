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
    activity,
    agent,
    ai_decomp,
    analysis_log,
    auth,
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
    external,
    families,
    filetypes,
    firmware,
    function_extras,
    function_triage,
    graph,
    graph_backends,
    hardening,
    instance,
    jobs,
    journal,
    knowledge,
    lineage,
    llm,
    matching,
    models,
    notifications,
    pdf,
    pipeline,
    plugins,
    protocols,
    related,
    remediation,
    remote_ingest,
    renames,
    sandbox,
    secret_store,
    secrets,
    signatures,
    similarity,
    store,
    surface,
    symbols,
    threat,
    unstrip,
    user_strings,
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
        job = jobs.latest_job(conn, kind="report-pdf", binary_id=binary_id)
    target = _pdf_path(binary_id)
    if not target.is_file():
        return {
            "binary_id": binary_id,
            "exists": False,
            "path": str(target),
            "bytes": 0,
            "pages": 0,
            "job": job,
        }
    data = target.read_bytes()
    return {
        "binary_id": binary_id,
        "exists": True,
        "path": str(target),
        "bytes": len(data),
        "pages": pdf.page_count(data),
        "job": job,
    }


def _tool_generate_pdf_report(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        # Resolves the workspace and raises the same tool error the status read
        # does when there is none; the render computes the path itself.
        _pdf_path(binary_id)
        return jobs.render_pdf(conn, binary_id, {})


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


# ── AI decompilation artifact ──────────────────────────────────────


def _ai_decomp_error(exc: ai_decomp.AiDecompError) -> ToolError:
    """Map one artifact failure onto the tool error the MCP server answers."""
    if isinstance(exc, ai_decomp.NoAiDecompilationError):
        return ToolError("no-artifact", str(exc))
    if isinstance(exc, ai_decomp.UnknownTokenError):
        return ToolError("unknown token", str(exc))
    if isinstance(exc, ai_decomp.UnknownLineCommentError):
        return ToolError("no-line-comment", str(exc))
    if isinstance(exc, ai_decomp.InvalidOverrideError):
        return ToolError("invalid override", str(exc))
    if isinstance(exc, ai_decomp.InvalidRatingError):
        return ToolError("invalid rating", str(exc))
    return ToolError("invalid line-comment", str(exc))


def _require_ai_decomp(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """Return the stored artifact, mapping its absence onto a tool error."""
    try:
        return ai_decomp.require(conn, function_id)
    except ai_decomp.NoAiDecompilationError as exc:
        raise _ai_decomp_error(exc) from exc


def _ai_decomp_mutate(
    function_id: int,
    mutate: Callable[[sqlite3.Connection, int], tuple[dict[str, Any], dict[str, Any]]],
    *,
    description: str,
) -> dict[str, Any]:
    """Run one artifact mutation in a journaled action and return the new view."""
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload, extra = mutate(conn, function_id)
            except ai_decomp.AiDecompError as exc:
                raise _ai_decomp_error(exc) from exc
            ai_decomp.write_artifact(conn, log, function_id, payload, description=description)
            artifact = ai_decomp.require(conn, function_id)
        return log.attach({"function_id": function_id, **ai_decomp.view(artifact), **extra})


def _with_comment(
    result: tuple[dict[str, Any], dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Report the line comment a mutation touched beside the artifact view."""
    payload, entry = result
    return payload, {"comment": entry}


def _tool_run_ai_decompilation(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        client = llm.get_client()
        if not client.available():
            raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = ai_decomp.rewrite(conn, function_id, client=client)
            except renames.NoDecompilationError as exc:
                raise ToolError("no-decompilation", str(exc)) from exc
            except llm.LlmError as exc:
                raise ToolError("llm-error", str(exc)) from exc
            ai_decomp.write_artifact(
                conn,
                log,
                function_id,
                payload,
                description=f"replaced the AI decompilation of function {function_id}",
            )
            artifact = ai_decomp.require(conn, function_id)
        return log.attach({"function_id": function_id, **ai_decomp.view(artifact)})


def _tool_get_ai_decompilation(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        artifact = _require_ai_decomp(conn, function_id)
    return {"function_id": function_id, **ai_decomp.view(artifact)}


def _tool_get_ai_decompilation_status(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        artifact = _require_ai_decomp(conn, function_id)
    return {"function_id": function_id, **ai_decomp.status(artifact)}


def _tool_list_ai_decompilation_tokens(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        tokens = ai_decomp.view(_require_ai_decomp(conn, function_id))["tokens"]
    return {
        "function_id": function_id,
        "tokens": tokens,
        "count": len(tokens),
        "derivation": ai_decomp.DERIVATION,
    }


def _tool_get_ai_line_attributions(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        rows = ai_decomp.view(_require_ai_decomp(conn, function_id))["attributions"]
    return {"function_id": function_id, "attributions": rows, "derivation": ai_decomp.DERIVATION}


def _tool_set_ai_decompilation_overrides(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    raw = arguments.get("overrides")
    return _ai_decomp_mutate(
        function_id,
        lambda conn, fid: ai_decomp.set_overrides(conn, fid, raw),
        description=(
            f"replaced the token overrides of the AI decompilation of function {function_id}"
        ),
    )


def _tool_rate_ai_decompilation(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    raw = arguments.get("rating")
    note = arguments.get("note")
    if note is not None and not isinstance(note, str):
        raise ToolError("invalid params", "note must be a string")
    return _ai_decomp_mutate(
        function_id,
        lambda conn, fid: (ai_decomp.rate(conn, fid, rating=raw, note=note), {}),
        description=f"rated the AI decompilation of function {function_id}",
    )


def _tool_list_ai_line_comments(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        rows = _require_ai_decomp(conn, function_id)["payload"].get("line_comments", [])
    return {"function_id": function_id, "comments": rows, "count": len(rows)}


def _tool_add_ai_line_comment(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    line = _arg_int(arguments, "line")
    body = _arg_str(arguments, "body")
    author = _arg_optional_str(arguments, "author") or None
    return _ai_decomp_mutate(
        function_id,
        lambda conn, fid: _with_comment(
            ai_decomp.add_line_comment(conn, fid, line=line, body=body, author=author)
        ),
        description=f"stored an inline comment on the AI decompilation of function {function_id}",
    )


def _tool_update_ai_line_comment(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    line = _arg_int(arguments, "line")
    body = _arg_str(arguments, "body")
    return _ai_decomp_mutate(
        function_id,
        lambda conn, fid: _with_comment(
            ai_decomp.update_line_comment(conn, fid, line=line, body=body)
        ),
        description=f"edited an inline comment on the AI decompilation of function {function_id}",
    )


def _tool_delete_ai_line_comment(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    line = _arg_int(arguments, "line")
    return _ai_decomp_mutate(
        function_id,
        lambda conn, fid: _with_comment(ai_decomp.delete_line_comment(conn, fid, line=line)),
        description=f"removed an inline comment on the AI decompilation of function {function_id}",
    )


def _external_failure(exc: external.ExternalError) -> ToolError:
    """Map an external-source failure onto the tool error the MCP server answers."""
    return ToolError(exc.code, exc.detail)


def _tool_get_signature_batch(arguments: dict[str, Any]) -> dict[str, Any]:
    raw = arguments.get("function_ids")
    if (
        not isinstance(raw, list)
        or not raw
        or len(raw) > signatures.BATCH_LIMIT
        or any(isinstance(entry, bool) or not isinstance(entry, int) for entry in raw)
    ):
        raise ToolError(
            "invalid params",
            f"function_ids must be a non-empty list of at most {signatures.BATCH_LIMIT} ids",
        )
    ids = [int(entry) for entry in raw]
    with contextlib.closing(_open()) as conn:
        rows = signatures.signatures_for(conn, ids)
    return {"signatures": rows, "count": len(rows)}


def _tool_copy_signature(arguments: dict[str, Any]) -> dict[str, Any]:
    source_id = _arg_int(arguments, "source_function_id")
    raw = arguments.get("targets")
    if (
        not isinstance(raw, list)
        or not raw
        or len(raw) > signatures.BATCH_LIMIT
        or any(isinstance(entry, bool) or not isinstance(entry, int) for entry in raw)
    ):
        raise ToolError(
            "invalid params",
            f"targets must be a non-empty list of at most {signatures.BATCH_LIMIT} ids",
        )
    targets = [int(entry) for entry in raw]
    with contextlib.closing(_open()) as conn:
        source = _require_function(conn, source_id)
        analysis_id = int(source["analysis_id"])
        members = {int(row["id"]) for row in store.list_functions(conn, analysis_id=analysis_id)}
        outsiders = [target for target in targets if target not in members]
        if outsiders:
            raise ToolError(
                "function not found",
                f"function(s) {outsiders} are not in analysis {analysis_id}",
            )
        with journal.journaled(conn, journal.new_action()) as log:
            report: dict[str, Any] = {
                "source_function_id": source_id,
                "targets": targets,
                "applied": [],
                "skipped": [],
                "count": 0,
            }
            for target in targets:
                try:
                    result = surface.journaled_signature_write(
                        conn,
                        log,
                        target,
                        f"copied the signature of function {source_id} onto function {target}",
                        partial(
                            signatures.copy_signature,
                            conn,
                            source_id=source_id,
                            targets=[target],
                        ),
                    )
                except signatures.SignatureError as exc:
                    report["skipped"].append({"function_id": target, "reason": str(exc)})
                    continue
                if result["applied"]:
                    report["applied"].append(target)
                else:
                    report["skipped"].extend(result["skipped"])
            report["count"] = len(report["applied"])
            return log.attach(report)


def _tool_import_type_definitions(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    raw = arguments.get("definitions")
    if (
        not isinstance(raw, list)
        or not raw
        or len(raw) > data_types.MAX_BULK_DEFINITIONS
        or any(not isinstance(entry, str) for entry in raw)
    ):
        raise ToolError(
            "invalid params",
            f"definitions must be a non-empty list of at most"
            f" {data_types.MAX_BULK_DEFINITIONS} C declarations",
        )
    create = not _arg_optional_bool(arguments, "update_only", False)
    with contextlib.closing(_open()) as conn:
        analysis = _analysis_or_error(conn, analysis_id)
        binary_id = int(analysis["binary_id"])
        with journal.journaled(conn, journal.new_action()) as log:
            report = surface.bulk_data_type_definitions(
                conn, log, binary_id=binary_id, definitions=list(raw), create=create
            )
            return log.attach(report)


def _tool_get_data_type_functions(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    data_type_id = _arg_int(arguments, "data_type_id")
    with contextlib.closing(_open()) as conn:
        analysis = _analysis_or_error(conn, analysis_id)
        data_type = store.get_data_type(conn, data_type_id)
        if data_type is None or int(data_type["binary_id"]) != int(analysis["binary_id"]):
            raise ToolError(
                "data type not found",
                f"no data type {data_type_id} in analysis {analysis_id}",
            )
        return data_types.references(conn, data_type_id)


def _bounded_function_ids(arguments: dict[str, Any], key: str) -> list[int]:
    """A bounded, non-empty function-id list from the arguments."""
    ids = _arg_optional_int_list(arguments, key)
    limit = function_extras.MAX_FUNCTIONS_PER_QUERY
    if not ids or len(ids) > limit:
        raise ToolError("invalid params", f"{key} must be a non-empty list of at most {limit} ids")
    return ids


def _tool_list_conversation_runs(arguments: dict[str, Any]) -> dict[str, Any]:
    conversation_id = _arg_int(arguments, "conversation_id")
    with contextlib.closing(_open()) as conn:
        _conversation_or_error(conn, conversation_id)
        rows = agent.list_runs(conn, conversation_id)
    return {"conversation_id": conversation_id, "runs": rows, "count": len(rows)}


def _tool_get_conversation_run(arguments: dict[str, Any]) -> dict[str, Any]:
    conversation_id = _arg_int(arguments, "conversation_id")
    run_id = _arg_optional_int(arguments, "run_id", 0)
    with contextlib.closing(_open()) as conn:
        _conversation_or_error(conn, conversation_id)
        try:
            resolved = agent.resolve_run(conn, conversation_id, run_id or None)
        except agent.UnknownRunError as exc:
            raise ToolError(exc.code, exc.detail) from exc
    return resolved


def _tool_run_conversation_agent(arguments: dict[str, Any]) -> dict[str, Any]:
    conversation_id = _arg_int(arguments, "conversation_id")
    content = _arg_str(arguments, "content")
    with contextlib.closing(_open()) as conn:
        _conversation_or_error(conn, conversation_id)
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                payload = agent.start(
                    conn,
                    log,
                    conversation_id=conversation_id,
                    content=content,
                    client=_ai_client_or_error(),
                )
            except llm.LlmUnavailable as exc:
                raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL) from exc
            except llm.LlmError as exc:
                raise ToolError("llm-error", str(exc)) from exc
            return log.attach(payload)


def _tool_confirm_conversation_run(arguments: dict[str, Any]) -> dict[str, Any]:
    conversation_id = _arg_int(arguments, "conversation_id")
    run_id = _arg_optional_int(arguments, "run_id", 0)
    approve = _arg_optional_bool(arguments, "approve", True)
    with contextlib.closing(_open()) as conn:
        _conversation_or_error(conn, conversation_id)
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                payload = agent.confirm(
                    conn,
                    log,
                    conversation_id=conversation_id,
                    approve=approve,
                    run_id=run_id or None,
                    client=_ai_client_or_error(),
                )
            except agent.UnknownRunError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            except agent.NotWaitingError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            except llm.LlmUnavailable as exc:
                raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL) from exc
            except llm.LlmError as exc:
                raise ToolError("llm-error", str(exc)) from exc
            return log.attach(payload)


def _tool_cancel_conversation_run(arguments: dict[str, Any]) -> dict[str, Any]:
    conversation_id = _arg_int(arguments, "conversation_id")
    run_id = _arg_optional_int(arguments, "run_id", 0)
    with contextlib.closing(_open()) as conn:
        _conversation_or_error(conn, conversation_id)
        try:
            return agent.cancel(conn, conversation_id=conversation_id, run_id=run_id or None)
        except agent.UnknownRunError as exc:
            raise ToolError(exc.code, exc.detail) from exc
        except agent.NotCancellableError as exc:
            raise ToolError(exc.code, exc.detail) from exc


def _tool_get_indirect_call_sites(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        cached = store.get_disasm(conn, function_id)
        rows = function_extras.indirect_call_sites(cached or "")
    return {
        "function_id": function_id,
        "sites": rows,
        "count": len(rows),
        "has_disassembly": cached is not None,
        "derivation": function_extras.DERIVATION,
        "note": function_extras.CALL_SITE_NOTE,
    }


def _tool_get_function_capabilities(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        try:
            return function_extras.function_capabilities(conn, function_id)
        except function_extras.EdgeError as exc:
            raise ToolError(exc.code, exc.detail) from exc


def _tool_get_function_strings(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        try:
            return user_strings.function_strings(conn, function_id)
        except user_strings.UnknownStringError as exc:
            raise ToolError(exc.code, exc.detail) from exc


def _tool_list_analysis_strings(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        rows = user_strings.list_strings(
            conn, scope_kind=user_strings.SCOPE_ANALYSIS, scope_id=analysis_id
        )
    return {"analysis_id": analysis_id, "strings": rows, "count": len(rows)}


def _tool_list_function_edges(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        rows = function_extras.list_edges(conn, function_id)
    return {"function_id": function_id, "edges": rows, "count": len(rows)}


def _tool_get_functions_callees_callers(arguments: dict[str, Any]) -> dict[str, Any]:
    ids = _bounded_function_ids(arguments, "function_ids")
    with contextlib.closing(_open()) as conn:
        return function_extras.callers_and_callees(conn, ids)


def _tool_get_function_matches(arguments: dict[str, Any]) -> dict[str, Any]:
    ids = _bounded_function_ids(arguments, "function_ids")
    with contextlib.closing(_open()) as conn:
        return function_extras.match_rows(conn, ids)


def _tool_add_function_string(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    value = _arg_str(arguments, "value")
    kind = _arg_optional_str(arguments, "kind", user_strings.KIND_STRING)
    note = _arg_optional_str(arguments, "note")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                row = user_strings.journaled_add(
                    conn,
                    log,
                    scope_kind=user_strings.SCOPE_FUNCTION,
                    scope_id=function_id,
                    value=value,
                    kind=kind,
                    note=note,
                    actor=journal.current_actor(),
                    description=f"stored a string for function {function_id}",
                )
            except user_strings.UnknownStringError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            except user_strings.StringError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            return log.attach(row)


def _tool_delete_function_string(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    string_id = _arg_int(arguments, "string_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                row = user_strings.journaled_delete(
                    conn,
                    log,
                    scope_kind=user_strings.SCOPE_FUNCTION,
                    scope_id=function_id,
                    string_id=string_id,
                    description=f"removed string {string_id} from function {function_id}",
                )
            except user_strings.StringError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            return log.attach(row)


def _tool_replace_analysis_strings(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    values = _arg_str_list(arguments, "strings")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                report = user_strings.journaled_replace(
                    conn,
                    log,
                    scope_kind=user_strings.SCOPE_ANALYSIS,
                    scope_id=analysis_id,
                    values=values,
                    actor=journal.current_actor(),
                    description=f"replaced the strings of analysis {analysis_id}",
                )
            except user_strings.StringError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            return log.attach(report)


def _tool_add_function_edge(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    callee = _arg_str(arguments, "callee")
    kind = _arg_optional_str(arguments, "kind", function_extras.EDGE_CALL)
    note = _arg_optional_str(arguments, "note")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                row = function_extras.journaled_add_edge(
                    conn,
                    log,
                    function_id=function_id,
                    callee=callee,
                    kind=kind,
                    note=note,
                    description=f"recorded a callee of function {function_id}",
                )
            except function_extras.EdgeError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            return log.attach(row)


def _tool_delete_function_edge(arguments: dict[str, Any]) -> dict[str, Any]:
    function_id = _arg_int(arguments, "function_id")
    edge_id = _arg_int(arguments, "edge_id")
    with contextlib.closing(_open()) as conn:
        _require_function(conn, function_id)
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                row = function_extras.journaled_delete_edge(
                    conn,
                    log,
                    function_id=function_id,
                    edge_id=edge_id,
                    description=f"removed an edge of function {function_id}",
                )
            except function_extras.EdgeError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            return log.attach(row)


def _tool_canonicalize_function_names(arguments: dict[str, Any]) -> dict[str, Any]:
    ids = _bounded_function_ids(arguments, "function_ids")
    apply_renames = _arg_optional_bool(arguments, "apply", True)
    with contextlib.closing(_open()) as conn:
        plan = function_extras.canonical_names(conn, ids)
        if not apply_renames:
            return {**plan, "applied": [], "applied_count": 0, "dry_run": True}
        with journal.journaled(conn, journal.new_action()) as log:
            applied: list[dict[str, Any]] = []
            for entry in plan["planned"]:
                if not entry["changed"]:
                    continue
                result = journal.journaled_rename(
                    conn,
                    log,
                    int(entry["function_id"]),
                    new_name=str(entry["to"]),
                    actor=journal.current_actor(),
                    source="canonical-names",
                )
                applied.append({**entry, "result": result})
            return log.attach(
                {**plan, "applied": applied, "applied_count": len(applied), "dry_run": False}
            )


def _binary_or_error(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The binary row, or a tool error naming the id."""
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise ToolError("binary not found", f"no binary with id {binary_id}")
    return binary


def _tool_get_symbols(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    file_id = _arg_optional_int(arguments, "file_id", 0)
    with contextlib.closing(_open()) as conn:
        _binary_or_error(conn, binary_id)
        try:
            if file_id:
                return symbols.get_file(conn, binary_id=binary_id, file_id=file_id)
            rows = symbols.list_files(conn, binary_id)
        except symbols.UnknownSymbolFileError as exc:
            raise ToolError(exc.code, exc.detail) from exc
    if not rows:
        raise ToolError("no-symbols", f"binary {binary_id} has no ingested symbol file")
    return {"binary_id": binary_id, "symbol_files": rows, "count": len(rows)}


def _tool_import_symbols(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    path = _arg_str(arguments, "path")
    apply = _arg_optional_bool(arguments, "apply", True)
    try:
        data, parsed = symbols.parse_file(path)
    except symbols.UnreadableSymbolError as exc:
        raise ToolError(exc.code, exc.detail) from exc
    with contextlib.closing(_open()) as conn:
        _binary_or_error(conn, binary_id)
        directory = symbols.stored_path(symbols.digest(data)).parent
        try:
            directory.mkdir(parents=True, exist_ok=True)
            target = directory / symbols.digest(data)
            target.write_bytes(data)
        except OSError as exc:
            raise ToolError("write-failed", str(exc)) from exc
        with journal.journaled(conn, journal.new_action()) as log:
            report = symbols.import_symbols(
                conn,
                log,
                binary_id=binary_id,
                data=data,
                parsed=parsed,
                path=str(target),
                apply=apply,
            )
            return log.attach(report)


def _tool_export_symbols(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    path = _arg_str(arguments, "path")
    kind = _arg_optional_str(arguments, "format", "c").strip().lower() or "c"
    if kind not in ("c", "json"):
        raise ToolError("invalid format", "format must be c or json")
    file_id = _arg_optional_int(arguments, "file_id", 0)
    with contextlib.closing(_open()) as conn:
        _binary_or_error(conn, binary_id)
        try:
            row = symbols.get_file(conn, binary_id=binary_id, file_id=file_id or None)
        except symbols.UnknownSymbolFileError as exc:
            raise ToolError(exc.code, exc.detail) from exc
    text = symbols.render_symbols(row["parsed"], kind=kind)
    try:
        Path(path).write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ToolError("write-failed", f"cannot write {path}: {exc}") from exc
    return {"path": path, "format": kind, "bytes": len(text)}


def _tool_list_external_sources(arguments: dict[str, Any]) -> dict[str, Any]:
    return external.describe()


def _tool_get_external_report(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    source_name = _arg_str(arguments, "source")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        try:
            stored = external.stored(conn, analysis_id=analysis_id, source_name=source_name)
        except external.ExternalError as exc:
            raise _external_failure(exc) from exc
    if stored is None:
        raise ToolError(
            "no-scan",
            f"the {source_name} source has not run for analysis {analysis_id};"
            " call run_external_source first",
        )
    return stored


def _tool_run_external_source(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    source_name = _arg_str(arguments, "source")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                result = external.journaled_run(
                    conn,
                    log,
                    analysis_id=analysis_id,
                    source_name=source_name,
                    description=f"pulled the {source_name} external report",
                )
            except external.ExternalError as exc:
                raise _external_failure(exc) from exc
            return log.attach(result)


def _tool_get_external_status(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    source_name = _arg_str(arguments, "source")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        try:
            return external.status(conn, analysis_id=analysis_id, source_name=source_name)
        except external.ExternalError as exc:
            raise _external_failure(exc) from exc


def _tool_list_secrets(arguments: dict[str, Any]) -> dict[str, Any]:
    """Every stored secret, redacted: the value is never in a tool payload."""
    scope = _arg_optional_str(arguments, "scope") or None
    team_id = _arg_optional_int(arguments, "team_id", 0) or None
    try:
        with contextlib.closing(_open()) as conn:
            rows = secret_store.list_secrets(conn, scope=scope, team_id=team_id)
    except secret_store.SecretError as exc:
        raise ToolError(exc.code, exc.detail) from exc
    return {"secrets": rows, "count": len(rows)}


def _secret_scope(arguments: dict[str, Any]) -> tuple[str, int | None]:
    """The scope a secret tool named, validated."""
    scope = _arg_optional_str(arguments, "scope") or None
    team_id = _arg_optional_int(arguments, "team_id", 0) or None
    try:
        resolved_scope, resolved_team = secret_store.normalize_scope(scope, team_id)
    except secret_store.SecretError as exc:
        raise ToolError("invalid params", exc.detail) from exc
    return resolved_scope, resolved_team or None


def _tool_set_secret(arguments: dict[str, Any]) -> dict[str, Any]:
    name = _arg_str(arguments, "name")
    value = _arg_str(arguments, "value")
    scope, team_id = _secret_scope(arguments)
    with contextlib.closing(_open()) as conn:
        if team_id is not None and auth.get_team(conn, team_id) is None:
            raise ToolError("team not found", f"no team with id {team_id}")
        with journal.journaled(conn, journal.new_action()) as log:
            try:
                row = secret_store.journaled_set(
                    conn,
                    log,
                    name=name,
                    value=value,
                    scope=scope,
                    team_id=team_id,
                    description=f"stored the secret {name}",
                )
            except secret_store.SecretError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            return log.attach(row)


def _tool_delete_secret(arguments: dict[str, Any]) -> dict[str, Any]:
    name = _arg_str(arguments, "name")
    scope, team_id = _secret_scope(arguments)
    with (
        contextlib.closing(_open()) as conn,
        journal.journaled(conn, journal.new_action()) as log,
    ):
        try:
            row = secret_store.journaled_delete(
                conn,
                log,
                name=name,
                scope=scope,
                team_id=team_id,
                description=f"deleted the secret {name}",
            )
        except secret_store.SecretError as exc:
            raise ToolError(exc.code, exc.detail) from exc
        return log.attach(row)


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


def _tool_list_collections(arguments: dict[str, Any]) -> dict[str, Any]:
    order = _arg_optional_str(arguments, "order", store.DEFAULT_COLLECTION_ORDER)
    with contextlib.closing(_open()) as conn:
        try:
            rows = store.list_collections(conn, order=order)
        except ValueError as exc:
            raise ToolError("invalid order", str(exc)) from exc
        for row in rows:
            row["tags"] = [tag["name"] for tag in store.collection_tags(conn, int(row["id"]))]
        return {"collections": rows, "count": len(rows), "order": order}


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


def _tool_bulk_analyses(arguments: dict[str, Any]) -> dict[str, Any]:
    action = _arg_str(arguments, "action")
    ids = _arg_optional_int_list(arguments, "analysis_ids")
    if ids is None:
        raise ToolError("invalid params", "analysis_ids must be a list of integers")
    tag = _arg_optional_str(arguments, "tag")
    with contextlib.closing(_open()) as conn:
        action_id = journal.new_action()
        with journal.journaled(conn, action_id) as log:
            try:
                result = bulk_actions.apply_analysis_action(
                    conn, action=action, ids=ids, tag=tag, log=log
                )
            except bulk_actions.BulkError as exc:
                raise ToolError("invalid bulk request", str(exc)) from exc
            return log.attach(result)


def _tool_list_users(arguments: dict[str, Any]) -> dict[str, Any]:
    with contextlib.closing(_open()) as conn:
        users = auth.list_users(conn)
    return {"users": users, "count": len(users), "auth_required": auth.required()}


def _tool_add_user(arguments: dict[str, Any]) -> dict[str, Any]:
    name = _arg_str(arguments, "name")
    role = _arg_optional_str(arguments, "role", auth.ROLE_ANALYST)
    with (
        contextlib.closing(_open()) as conn,
        journal.journaled(conn, journal.new_action()) as log,
    ):
        try:
            user, token = auth.add_user(conn, name=name, role=role)
        except auth.AuthError as exc:
            raise ToolError(exc.code, exc.detail) from exc
        journal.journaled_create(
            log,
            table=auth.TABLE,
            key=int(user["id"]),
            description=f"created user {user['name']}",
        )
        return log.attach({**user, "token": token})


def _tool_rotate_user_token(arguments: dict[str, Any]) -> dict[str, Any]:
    user_id = _arg_int(arguments, "user_id")
    with contextlib.closing(_open()) as conn:
        if auth.get_user(conn, user_id) is None:
            raise ToolError(auth.ERROR_USER_NOT_FOUND, f"no user with id {user_id}")
        with journal.journaled(conn, journal.new_action()) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TABLE,
                where="id = ?",
                params=(user_id,),
                description=f"rotated the token of user {user_id}",
            )
            token = auth.rotate_token(conn, user_id)
            return log.attach({"id": user_id, "token": token})


def _tool_update_user(arguments: dict[str, Any]) -> dict[str, Any]:
    user_id = _arg_int(arguments, "user_id")
    role = _arg_optional_str(arguments, "role") or None
    disabled = arguments.get("disabled")
    if disabled is not None and not isinstance(disabled, bool):
        raise ToolError("invalid params", "disabled must be a boolean")
    if role is None and disabled is None:
        raise ToolError("invalid user", "provide role or disabled")
    with contextlib.closing(_open()) as conn:
        if auth.get_user(conn, user_id) is None:
            raise ToolError(auth.ERROR_USER_NOT_FOUND, f"no user with id {user_id}")
        with journal.journaled(conn, journal.new_action()) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TABLE,
                where="id = ?",
                params=(user_id,),
                description=f"updated user {user_id}",
            )
            try:
                updated = auth.update_user(conn, user_id, role=role, disabled=disabled)
            except auth.AuthError as exc:
                raise ToolError(exc.code, exc.detail) from exc
            assert updated is not None, "the row was just read"
            return log.attach(updated)


def _tool_delete_user(arguments: dict[str, Any]) -> dict[str, Any]:
    user_id = _arg_int(arguments, "user_id")
    with contextlib.closing(_open()) as conn:
        if auth.get_user(conn, user_id) is None:
            raise ToolError(auth.ERROR_USER_NOT_FOUND, f"no user with id {user_id}")
        with journal.journaled(conn, journal.new_action()) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TABLE,
                where="id = ?",
                params=(user_id,),
                description=f"deleted user {user_id}",
            )
            auth.delete_user(conn, user_id)
            return log.attach({"deleted": user_id})


def _tool_list_teams(arguments: dict[str, Any]) -> dict[str, Any]:
    with contextlib.closing(_open()) as conn:
        teams = auth.list_teams(conn)
    return {"teams": teams, "count": len(teams)}


def _tool_create_team(arguments: dict[str, Any]) -> dict[str, Any]:
    name = _arg_str(arguments, "name")
    description = _arg_optional_str(arguments, "description")
    with (
        contextlib.closing(_open()) as conn,
        journal.journaled(conn, journal.new_action()) as log,
    ):
        try:
            team = auth.create_team(conn, name=name, description=description)
        except auth.AuthError as exc:
            raise ToolError(exc.code, exc.detail) from exc
        journal.journaled_create(
            log,
            table=auth.TEAM_TABLE,
            key=int(team["id"]),
            description=f"created team {team['name']}",
        )
        return log.attach(team)


def _tool_delete_team(arguments: dict[str, Any]) -> dict[str, Any]:
    team_id = _arg_int(arguments, "team_id")
    with contextlib.closing(_open()) as conn:
        if auth.get_team(conn, team_id) is None:
            raise ToolError(auth.ERROR_TEAM_NOT_FOUND, f"no team with id {team_id}")
        with journal.journaled(conn, journal.new_action()) as log:
            for table, where in (
                (auth.TEAM_TABLE, "id = ?"),
                (auth.MEMBER_TABLE, "team_id = ?"),
                ("binaries", "owner_team_id = ?"),
                ("collections", "owner_team_id = ?"),
            ):
                journal.journaled_rows(
                    conn,
                    log,
                    table=table,
                    where=where,
                    params=(team_id,),
                    description=f"deleted team {team_id} ({table})",
                )
            auth.delete_team(conn, team_id)
            return log.attach({"deleted": team_id})


def _tool_add_team_member(arguments: dict[str, Any]) -> dict[str, Any]:
    team_id = _arg_int(arguments, "team_id")
    user_id = _arg_int(arguments, "user_id")
    with contextlib.closing(_open()) as conn:
        if auth.get_team(conn, team_id) is None:
            raise ToolError(auth.ERROR_TEAM_NOT_FOUND, f"no team with id {team_id}")
        with journal.journaled(conn, journal.new_action()) as log:
            if not auth.add_member(conn, team_id, user_id):
                raise ToolError(
                    auth.ERROR_INVALID_TEAM,
                    f"user {user_id} is unknown or already in team {team_id}",
                )
            journal.journaled_create(
                log,
                table=auth.MEMBER_TABLE,
                key={"team_id": team_id, "user_id": user_id},
                description=f"added user {user_id} to team {team_id}",
            )
            return log.attach(auth.get_team(conn, team_id) or {})


def _tool_remove_team_member(arguments: dict[str, Any]) -> dict[str, Any]:
    team_id = _arg_int(arguments, "team_id")
    user_id = _arg_int(arguments, "user_id")
    with (
        contextlib.closing(_open()) as conn,
        journal.journaled(conn, journal.new_action()) as log,
    ):
        snapshot = journal.journaled_rows(
            conn,
            log,
            table=auth.MEMBER_TABLE,
            where="team_id = ? AND user_id = ?",
            params=(team_id, user_id),
            description=f"removed user {user_id} from team {team_id}",
        )
        if not snapshot:
            raise ToolError(auth.ERROR_NOT_A_MEMBER, f"user {user_id} is not in team {team_id}")
        auth.remove_member(conn, team_id, user_id)
        return log.attach(auth.get_team(conn, team_id) or {})


def _set_object_scope(arguments: dict[str, Any], *, kind: str) -> dict[str, Any]:
    row_id = _arg_int(arguments, "binary_id" if kind == "binary" else "collection_id")
    visibility = _arg_optional_str(arguments, "visibility", auth.VISIBILITY_PUBLIC)
    team_id = _arg_optional_int(arguments, "team_id", 0) or None
    table = "binaries" if kind == "binary" else "collections"
    with contextlib.closing(_open()) as conn:
        current = (
            store.get_binary(conn, row_id)
            if kind == "binary"
            else store.get_collection(conn, row_id)
        )
        if current is None:
            raise ToolError(f"{kind} not found", f"no {kind} with id {row_id}")
        try:
            owner, resolved = auth.scope_of(conn, team_id=team_id, visibility=visibility)
        except auth.AuthError as exc:
            raise ToolError(exc.code, exc.detail) from exc
        with journal.journaled(conn, journal.new_action()) as log:
            journal.journaled_rows(
                conn,
                log,
                table=table,
                where="id = ?",
                params=(row_id,),
                description=f"scoped {kind} {row_id} to {resolved}",
            )
            if kind == "binary":
                updated = store.set_binary_scope(
                    conn, row_id, owner_team_id=owner, visibility=resolved
                )
            else:
                updated = store.set_collection_scope(
                    conn, row_id, owner_team_id=owner, visibility=resolved
                )
            assert updated is not None, "the row was just read"
            return log.attach(updated)


def _tool_set_binary_scope(arguments: dict[str, Any]) -> dict[str, Any]:
    return _set_object_scope(arguments, kind="binary")


def _tool_set_collection_scope(arguments: dict[str, Any]) -> dict[str, Any]:
    return _set_object_scope(arguments, kind="collection")


def _tool_run_firmware_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    from reportal import api

    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        try:
            return api.firmware_carve_binary(conn, binary_id)
        except api.ExtractError as exc:
            raise ToolError(exc.code, exc.detail) from exc


def _tool_get_firmware_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        payload = firmware.regions(conn, binary_id)
    if payload is None:
        raise ToolError(
            "no-scan",
            f"binary {binary_id} has no firmware scan; run 'reportal firmware {binary_id}'",
        )
    return payload


def _tool_extract_firmware_regions(arguments: dict[str, Any]) -> dict[str, Any]:
    from reportal import api

    binary_id = _arg_int(arguments, "binary_id")
    regions = _arg_optional_int_list(arguments, "regions")
    collection_id = _arg_optional_int(arguments, "collection_id", 0)
    with contextlib.closing(_open()) as conn:
        try:
            return api.firmware_extract_binary(
                conn,
                binary_id,
                region_indexes=regions,
                collection_id=collection_id,
            )
        except api.ExtractError as exc:
            raise ToolError(exc.code, exc.detail) from exc


def _tool_get_activity(arguments: dict[str, Any]) -> dict[str, Any]:
    actor = _arg_optional_str(arguments, "actor") or None
    since_raw = _arg_optional_str(arguments, "since")
    since = None
    if since_raw:
        try:
            since = notifications.parse_since(since_raw)
        except ValueError as exc:
            raise ToolError("invalid since", str(exc)) from exc
    limit = _arg_optional_int(arguments, "limit", activity.DEFAULT_ACTIVITY_LIMIT)
    if not 1 <= limit <= activity.MAX_ACTIVITY_LIMIT:
        raise ToolError(
            "invalid limit", f"limit must be between 1 and {activity.MAX_ACTIVITY_LIMIT}"
        )
    with contextlib.closing(_open()) as conn:
        payload = activity.feed(conn, actor=actor, since=since, limit=limit)
        payload["actors"] = activity.actors(conn)
    return payload


def _tool_list_feedback(arguments: dict[str, Any]) -> dict[str, Any]:
    limit = _arg_optional_int(arguments, "limit", 50)
    if limit < 1:
        raise ToolError("invalid limit", "limit must be positive")
    with contextlib.closing(_open()) as conn:
        notes = store.list_feedback(conn, limit=limit)
        total = store.count_feedback(conn)
    return {"feedback": notes, "count": len(notes), "total": total}


def _tool_add_feedback(arguments: dict[str, Any]) -> dict[str, Any]:
    message = _arg_str(arguments, "message")
    with (
        contextlib.closing(_open()) as conn,
        journal.journaled(conn, journal.new_action()) as log,
    ):
        try:
            feedback_id = store.add_feedback(
                conn, body=message, actor=journal.current_actor() or journal.LOCAL_ACTOR
            )
        except store.InvalidFeedbackError as exc:
            raise ToolError("invalid feedback", str(exc)) from exc
        journal.journaled_create(
            log,
            table="feedback",
            key=feedback_id,
            description=f"wrote feedback note {feedback_id}",
        )
        note = store.get_feedback(conn, feedback_id)
    return log.attach(note or {"id": feedback_id})


def _tool_run_sandbox_detonation(arguments: dict[str, Any]) -> dict[str, Any]:
    from reportal import api, sandbox

    binary_id = _arg_int(arguments, "binary_id")
    timeout = _arg_optional_int(arguments, "timeout", 0) or None
    memory_mb = _arg_optional_int(arguments, "memory_mb", 0) or None
    with contextlib.closing(_open()) as conn:
        try:
            return api.sandbox_detonate_binary(
                conn, binary_id, timeout=timeout, memory_mb=memory_mb
            )
        except sandbox.SandboxError as exc:
            raise ToolError(exc.code, exc.detail) from exc


def _tool_get_sandbox_report(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        report = None if analysis_id is None else sandbox.latest_run(conn, analysis_id)
        status = sandbox.status_payload(conn, analysis_id or 0)
    if report is None:
        raise ToolError(sandbox.ERROR_NO_RUN, f"binary {binary_id} has no detonation report")
    return {**report, "detonation": status}


def _tool_get_sandbox_status(arguments: dict[str, Any]) -> dict[str, Any]:
    binary_id = _arg_int(arguments, "binary_id")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id) or 0
        return sandbox.status_payload(conn, analysis_id)


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


def _tool_list_notifications(arguments: dict[str, Any]) -> dict[str, Any]:
    limit = _arg_optional_int(arguments, "limit", notifications.DEFAULT_FEED_LIMIT)
    since = _arg_optional_str(arguments, "since")
    with contextlib.closing(_open()) as conn:
        try:
            payload = notifications.feed(
                conn, since=notifications.parse_since(since) if since else None, limit=limit
            )
        except ValueError as exc:
            raise ToolError("invalid notification query", str(exc)) from exc
        payload["latest"] = notifications.latest(conn)
    return payload


def _conversation_or_error(conn: sqlite3.Connection, conversation_id: int) -> dict[str, Any]:
    """The conversation row, or a tool error naming the id."""
    conversation = store.get_conversation(conn, conversation_id)
    if conversation is None:
        raise ToolError("conversation not found", f"no conversation with id {conversation_id}")
    return conversation


def _ai_client_or_error() -> llm.LlmClient:
    """The configured bridge, or the tool error every AI path answers."""
    client = llm.get_client()
    if not client.available():
        raise ToolError("llm-unavailable", llm.UNAVAILABLE_DETAIL)
    return client


def _analysis_or_error(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any]:
    """The analysis row, or a tool error naming the id."""
    analysis = store.get_analysis(conn, analysis_id)
    if analysis is None:
        raise ToolError("analysis not found", f"no analysis with id {analysis_id}")
    return analysis


def _tool_get_analysis(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        detail = store.analysis_detail(conn, analysis_id)
        status = store.analysis_status(conn, analysis_id)
    assert detail is not None and status is not None, "the row was just read"
    return {**detail, "lifecycle": status}


def _tool_get_analysis_params(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        params = store.analysis_params(conn, analysis_id)
    assert params is not None, "the row was just read"
    return params


def _tool_get_analysis_func_maps(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        functions = store.list_functions(conn, analysis_id=analysis_id, sort="va", order="asc")
        total = store.count_functions(conn, analysis_id=analysis_id)
    return {
        "analysis_id": analysis_id,
        "functions": [
            {
                "id": int(row["id"]),
                "va": int(row["va"]),
                "name": str(row["name"]),
                "size": int(row["size"] or 0),
            }
            for row in functions
        ],
        "count": len(functions),
        "total": total,
    }


def _tool_get_imported_functions(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    limit = _arg_optional_int(arguments, "limit", store.DEFAULT_IMPORTED_LIMIT)
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        payload = store.imported_functions(conn, analysis_id, limit=limit)
    assert payload is not None, "the row was just read"
    return payload


def _tool_update_analysis(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    engine = _arg_str(arguments, "engine")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        with journal.journaled(conn, journal.new_action()) as log:
            journal.journaled_rows(
                conn,
                log,
                table="analyses",
                where="id = ?",
                params=(analysis_id,),
                description=f"relabelled analysis {analysis_id}",
            )
            updated = store.update_analysis(conn, analysis_id, engine=engine)
    assert updated is not None, "the row was just read"
    return log.attach(updated)


def _tool_append_analysis_log(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    message = _arg_str(arguments, "message")
    severity = _arg_optional_str(arguments, "severity", analysis_log.SEVERITY_INFO)
    if severity not in analysis_log.SEVERITIES:
        raise ToolError("invalid severity", f"unknown severity: {severity}")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        try:
            with journal.journaled(conn, journal.new_action()) as log:
                entry_id = analysis_log.append_entry(
                    conn, analysis_id, message=message, severity=severity
                )
                journal.journaled_create(
                    log,
                    table=analysis_log.TABLE,
                    key=entry_id,
                    description=f"logged an entry on analysis {analysis_id}",
                )
        except ValueError as exc:
            raise ToolError("invalid message", str(exc)) from exc
    return log.attach(
        {"id": entry_id, "analysis_id": analysis_id, "severity": severity, "message": message}
    )


def _tool_requeue_analysis(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        with journal.journaled(conn, journal.new_action()) as log:
            journal.journaled_rows(
                conn,
                log,
                table="analyses",
                where="id = ?",
                params=(analysis_id,),
                description=f"requeued analysis {analysis_id}",
            )
            logged_before = journal.snapshot_rows(
                conn, table=analysis_log.TABLE, where="analysis_id = ?", params=(analysis_id,)
            )
            updated = store.requeue_analysis(conn, analysis_id)
            journal.journaled_new_rows(
                conn,
                log,
                table=analysis_log.TABLE,
                where="analysis_id = ?",
                params=(analysis_id,),
                before=logged_before,
                key=["id"],
                description=f"logged the requeue of analysis {analysis_id}",
            )
    assert updated is not None, "the row was just read"
    return log.attach(updated)


def _tool_list_models(arguments: dict[str, Any]) -> dict[str, Any]:
    """Every registered model with its kind, version and availability."""
    return models.describe()


def _tool_upgrade_analysis_model(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    name = _arg_str(arguments, "model")
    raw_functions = arguments.get("functions")
    if raw_functions is not None and not isinstance(raw_functions, list):
        raise ToolError("invalid params", "functions must be a list of function ids")
    with contextlib.closing(_open()) as conn:
        _analysis_or_error(conn, analysis_id)
        try:
            target = models.upgradeable_model(name)
            functions = models.normalize_function_ids(raw_functions)
            limit = models.normalize_limit(arguments.get("limit"))
        except models.UnknownModelError as exc:
            raise ToolError("model not found", str(exc)) from exc
        except (models.NotUpgradeableError, models.InvalidModelError) as exc:
            raise ToolError("invalid model", str(exc)) from exc
        except llm.LlmUnavailable as exc:
            raise ToolError("llm-unavailable", str(exc)) from exc
        with journal.journaled(conn, journal.new_action()) as log:
            result = models.upgrade_analysis(
                conn,
                log,
                analysis_id=analysis_id,
                model=target.name,
                functions=functions,
                limit=limit,
            )
            return log.attach(result)


def _tool_set_analysis_tags(arguments: dict[str, Any]) -> dict[str, Any]:
    analysis_id = _arg_int(arguments, "analysis_id")
    names = _arg_str_list(arguments, "tags")
    with contextlib.closing(_open()) as conn:
        analysis = _analysis_or_error(conn, analysis_id)
        binary_id = int(analysis["binary_id"])
        with journal.journaled(conn, journal.new_action()) as log:
            current = {
                str(tag["name"]): int(tag["id"]) for tag in store.get_binary_tags(conn, binary_id)
            }
            for name in sorted(set(names) - set(current)):
                created = store.find_tag(conn, name) is None
                tag_id = store.create_tag(conn, name)
                if created:
                    log.record(
                        effects.EFFECT_ROW_DELETE,
                        f"created tag {tag_id}",
                        journal.row_delete_descriptor("tags", tag_id),
                    )
                if store.add_binary_tag(conn, binary_id, tag_id):
                    log.record(
                        effects.EFFECT_ROW_DELETE,
                        f"tagged binary {binary_id} with tag {tag_id}",
                        journal.row_delete_descriptor(
                            "binary_tags", {"binary_id": binary_id, "tag_id": tag_id}
                        ),
                    )
            for name in sorted(set(current) - set(names)):
                tag_id = current[name]
                link = journal.snapshot_rows(
                    conn,
                    table="binary_tags",
                    where="binary_id = ? AND tag_id = ?",
                    params=(binary_id, tag_id),
                )
                if store.remove_binary_tag(conn, binary_id, tag_id) and link:
                    log.record(
                        effects.EFFECT_ROW_RESTORE,
                        f"untagged binary {binary_id} from tag {tag_id}",
                        journal.row_restore_descriptor("binary_tags", link),
                    )
            tags = [str(tag["name"]) for tag in store.get_binary_tags(conn, binary_id)]
    return log.attach({"analysis_id": analysis_id, "binary_id": binary_id, "tags": tags})


def _tool_list_jobs(arguments: dict[str, Any]) -> dict[str, Any]:
    limit = _arg_optional_int(arguments, "limit", jobs.DEFAULT_JOB_LIMIT)
    status = _arg_optional_str(arguments, "status")
    kind = _arg_optional_str(arguments, "kind")
    with contextlib.closing(_open()) as conn:
        try:
            rows, total = jobs.list_jobs(
                conn, status=status or None, kind=kind or None, limit=limit
            )
        except ValueError as exc:
            raise ToolError("invalid job query", str(exc)) from exc
        queued = jobs.count_jobs(conn, status=jobs.STATUS_QUEUED)
    return {"jobs": rows, "count": len(rows), "total": total, "queued": queued}


def _tool_get_job(arguments: dict[str, Any]) -> dict[str, Any]:
    job_id = _arg_int(arguments, "job_id")
    with contextlib.closing(_open()) as conn:
        job = jobs.get_job(conn, job_id)
    if job is None:
        raise ToolError("job not found", f"no job with id {job_id}")
    return job


def _tool_submit_job(arguments: dict[str, Any]) -> dict[str, Any]:
    kind = _arg_str(arguments, "kind")
    binary_id = _arg_int(arguments, "binary_id")
    raw = arguments.get("params")
    params = raw if isinstance(raw, dict) else {}
    with (
        contextlib.closing(_open()) as conn,
        journal.journaled(conn, journal.new_action()) as log,
    ):
        try:
            job = jobs.submit(conn, kind=kind, binary_id=binary_id, params=params)
        except ValueError as exc:
            raise ToolError("invalid job", str(exc)) from exc
        except KeyError as exc:
            raise ToolError("binary not found", str(exc.args[0])) from exc
        journal.journaled_create(
            log,
            table=jobs.TABLE,
            key=int(job["id"]),
            description=f"queued {kind} job {job['id']} for binary {binary_id}",
        )
    jobs.ensure_worker()
    return log.attach(job)


def _tool_cancel_job(arguments: dict[str, Any]) -> dict[str, Any]:
    job_id = _arg_int(arguments, "job_id")
    with (
        contextlib.closing(_open()) as conn,
        journal.journaled(conn, journal.new_action()) as log,
    ):
        if jobs.get_job(conn, job_id) is None:
            raise ToolError("job not found", f"no job with id {job_id}")
        journal.journaled_rows(
            conn,
            log,
            table=jobs.TABLE,
            where="id = ?",
            params=(job_id,),
            description=f"cancelled job {job_id}",
        )
        try:
            job = jobs.cancel(conn, job_id)
        except ValueError as exc:
            raise ToolError("job-not-cancellable", str(exc)) from exc
    return log.attach(job or {})


def _tool_run_jobs(arguments: dict[str, Any]) -> dict[str, Any]:
    limit = _arg_optional_int(arguments, "limit", 1)
    with contextlib.closing(_open()) as conn:
        finished = jobs.run_pending(conn, limit=limit)
    return {"jobs": finished, "count": len(finished)}


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


def _string_map(description: str) -> dict[str, Any]:
    """A free-form object of string keys to string or null values."""
    return {
        "type": "object",
        "description": description,
        "additionalProperties": {"type": ["string", "null"]},
    }


_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False)
_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=True)

_FUNCTION_ID = _int("Function id.")
_BINARY_ID = _int("Binary id.")
_ANALYSIS_ID = _int("Analysis id.")
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
            "run_ai_decompilation",
            "Rewrite a function's stored decompilation with the configured LLM and store the"
            " artifact with its token map and per-line attributions.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _WRITE,
            _tool_run_ai_decompilation,
        ),
        Tool(
            "get_ai_decompilation",
            "The stored AI decompilation rendered with its token overrides, token map,"
            " attributions, rating and line comments.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_ai_decompilation,
        ),
        Tool(
            "get_ai_decompilation_status",
            "The stored AI decompilation's workflow state: line, token, override, attribution,"
            " rating and comment counts, without its text.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_ai_decompilation_status,
        ),
        Tool(
            "list_ai_decompilation_tokens",
            "The placeholder tokens of the rewrite with the analyst name each one carries.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_list_ai_decompilation_tokens,
        ),
        Tool(
            "get_ai_line_attributions",
            "Attribute each line of the rewrite to the decompilation the model read: original,"
            " rewritten or added, by a local line diff.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_ai_line_attributions,
        ),
        Tool(
            "set_ai_decompilation_overrides",
            "Set or clear analyst names for the rewrite's placeholder tokens; a null name clears"
            " that token's override.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "overrides": _string_map(
                        "Placeholder token to analyst name; a null clears the override."
                    ),
                },
                ("function_id", "overrides"),
            ),
            _WRITE,
            _tool_set_ai_decompilation_overrides,
        ),
        Tool(
            "rate_ai_decompilation",
            "Record analyst feedback on the rewrite: a rating of up or down, or null to clear it.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "rating": _enum("Analyst rating, or null to clear it.", ("up", "down")),
                    "note": _str("Free-text note stored beside the rating."),
                },
                ("function_id",),
            ),
            _WRITE,
            _tool_rate_ai_decompilation,
        ),
        Tool(
            "list_ai_line_comments",
            "The per-line inline comments stored beside the AI decompilation, ordered by line.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_list_ai_line_comments,
        ),
        Tool(
            "add_ai_line_comment",
            "Store one inline comment at a line of the rewrite, replacing any comment already"
            " there.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "line": _int("1-based line of the rewrite to comment."),
                    "body": _str("Comment body."),
                    "author": _str("Author to record; defaults to 'analyst'."),
                },
                ("function_id", "line", "body"),
            ),
            _WRITE,
            _tool_add_ai_line_comment,
        ),
        Tool(
            "update_ai_line_comment",
            "Replace the body of the inline comment stored at a line of the rewrite.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "line": _int("1-based line whose comment to replace."),
                    "body": _str("New comment body."),
                },
                ("function_id", "line", "body"),
            ),
            _WRITE,
            _tool_update_ai_line_comment,
        ),
        Tool(
            "delete_ai_line_comment",
            "Remove the inline comment stored at a line of the rewrite.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "line": _int("1-based line whose comment to remove."),
                },
                ("function_id", "line"),
            ),
            _WRITE,
            _tool_delete_ai_line_comment,
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
            "List collections with their member and tag counts, in the named order.",
            _object(
                {
                    "order": {
                        "type": "string",
                        "enum": sorted(store.COLLECTION_ORDERS),
                        "description": "id (default), name, size by member count, or updated",
                    }
                }
            ),
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
            "bulk_analyses",
            "Apply one action (add_tag, remove_tag, delete) to many analyses and report the"
            " per-id result; a tag action writes the binaries the analyses belong to, and an"
            " unknown or refused id is skipped, not a batch failure.",
            _object(
                {
                    "action": _enum("Action to apply.", bulk_actions.ANALYSIS_ACTIONS),
                    "analysis_ids": _array("Analysis ids.", _ANALYSIS_ID),
                    "tag": _str("Tag name the tag actions apply."),
                },
                ("action", "analysis_ids"),
            ),
            _WRITE,
            _tool_bulk_analyses,
        ),
        Tool(
            "list_users",
            "The local users with their roles and state, never their token digests; says whether"
            " token auth is required on this install.",
            _object({}),
            _READ,
            _tool_list_users,
        ),
        Tool(
            "add_user",
            "Create a user and return its bearer token once; only the token's digest is stored."
            " Journaled and revertible.",
            _object(
                {
                    "name": _str("User name."),
                    "role": _enum("Role the user carries.", auth.ROLES),
                },
                ("name",),
            ),
            _WRITE,
            _tool_add_user,
        ),
        Tool(
            "rotate_user_token",
            "Replace one user's bearer token and return the new one once; journaled and"
            " revertible.",
            _object({"user_id": _int("User id.")}, ("user_id",)),
            _WRITE,
            _tool_rotate_user_token,
        ),
        Tool(
            "update_user",
            "Set one user's role or disabled flag; journaled and revertible.",
            _object(
                {
                    "user_id": _int("User id."),
                    "role": _enum("New role.", auth.ROLES),
                    "disabled": _bool("Whether the user's token stops authenticating."),
                },
                ("user_id",),
            ),
            _WRITE,
            _tool_update_user,
        ),
        Tool(
            "delete_user",
            "Delete one user; journaled, so a revert puts the row back.",
            _object({"user_id": _int("User id.")}, ("user_id",)),
            _WRITE,
            _tool_delete_user,
        ),
        Tool(
            "list_teams",
            "The teams with their member counts; a team scopes the binaries and collections"
            " that carry its visibility.",
            _object({}),
            _READ,
            _tool_list_teams,
        ),
        Tool(
            "create_team",
            "Create a team; journaled and revertible.",
            _object(
                {"name": _str("Team name."), "description": _str("What the team works on.")},
                ("name",),
            ),
            _WRITE,
            _tool_create_team,
        ),
        Tool(
            "delete_team",
            "Delete a team; the binaries and collections it owned return to the whole"
            " workspace.  Journaled, so a revert restores the team, its members and the scope.",
            _object({"team_id": _int("Team id.")}, ("team_id",)),
            _WRITE,
            _tool_delete_team,
        ),
        Tool(
            "add_team_member",
            "Add a user to a team; journaled and revertible.",
            _object(
                {"team_id": _int("Team id."), "user_id": _int("User id to add.")},
                ("team_id", "user_id"),
            ),
            _WRITE,
            _tool_add_team_member,
        ),
        Tool(
            "remove_team_member",
            "Remove a user from a team; journaled and revertible.",
            _object(
                {"team_id": _int("Team id."), "user_id": _int("User id to remove.")},
                ("team_id", "user_id"),
            ),
            _WRITE,
            _tool_remove_team_member,
        ),
        Tool(
            "set_binary_scope",
            "Set a binary's visibility (public or team) and its owning team; journaled.",
            _object(
                {
                    "binary_id": _int("Binary id."),
                    "visibility": _enum("Who may see it.", auth.VISIBILITIES),
                    "team_id": _int("Owning team id, required for the team visibility."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_set_binary_scope,
        ),
        Tool(
            "set_collection_scope",
            "Set a collection's visibility (public or team) and its owning team; journaled.",
            _object(
                {
                    "collection_id": _int("Collection id."),
                    "visibility": _enum("Who may see it.", auth.VISIBILITIES),
                    "team_id": _int("Owning team id, required for the team visibility."),
                },
                ("collection_id",),
            ),
            _WRITE,
            _tool_set_collection_scope,
        ),
        Tool(
            "get_sandbox_report",
            "The newest detonation report of a binary: the runner, the caps, the exit status,"
            " the output tails and the files the sample wrote.  Read-only.",
            _object({"binary_id": _int("Binary id.")}, ("binary_id",)),
            _READ,
            _tool_get_sandbox_report,
        ),
        Tool(
            "get_sandbox_status",
            "Whether this install can detonate a binary (the opt-in and the installed runner)"
            " and when it last did.  Read-only.",
            _object({"binary_id": _int("Binary id.")}, ("binary_id",)),
            _READ,
            _tool_get_sandbox_status,
        ),
        Tool(
            "run_sandbox_detonation",
            "Run a stored sample under the sandbox runner and store the report.  Off by default:"
            " refused unless the workspace opts in and a runner is installed; the run has no"
            " network, a read-only root, capped memory and CPU and a wall-clock timeout.",
            _object(
                {
                    "binary_id": _int("Binary id."),
                    "timeout": _int("Wall-clock seconds (1 to 60)."),
                    "memory_mb": _int("Address space in MiB."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_run_sandbox_detonation,
        ),
        Tool(
            "get_activity",
            "What was done here and by whom: the journaled actions with the actor that made"
            " each, plus the analysis-log entries.  Derived, never stored.",
            _object(
                {
                    "actor": _str("Only this actor's actions; an empty value means no request."),
                    "since": _str("Only items at or after this ISO timestamp."),
                    "limit": _int(f"Maximum items (default {activity.DEFAULT_ACTIVITY_LIMIT})."),
                }
            ),
            _READ,
            _tool_get_activity,
        ),
        Tool(
            "list_feedback",
            "The local feedback notes about reportal itself, newest first.",
            _object({"limit": _int("Maximum notes (default 50).")}),
            _READ,
            _tool_list_feedback,
        ),
        Tool(
            "add_feedback",
            "Store one feedback note about reportal itself, attributed to the caller;"
            " journaled and revertible.",
            _object({"message": _str("What to record.")}, ("message",)),
            _WRITE,
            _tool_add_feedback,
        ),
        Tool(
            "get_firmware_scan",
            "A binary's stored firmware carve: its embedded regions (offset, size, kind,"
            " entropy, confidence) and the sampled entropy map.  Read-only, never runs a"
            " thing.",
            _object({"binary_id": _int("Binary id.")}, ("binary_id",)),
            _READ,
            _tool_get_firmware_scan,
        ),
        Tool(
            "run_firmware_scan",
            "Carve a stored firmware image and store the pass: magic-based region detection"
            " plus an entropy map, all offline byte work with nothing executed.",
            _object({"binary_id": _int("Binary id.")}, ("binary_id",)),
            _WRITE,
            _tool_run_firmware_scan,
        ),
        Tool(
            "extract_firmware_regions",
            "Carve the regions of a stored firmware scan out and register what they hold: a"
            " gzip, tar or zip region is unpacked with the archive reader, every other region"
            " is stored as a binary of its own.  One journaled action.",
            _object(
                {
                    "binary_id": _int("Binary id."),
                    "regions": _array(
                        "Region indexes to carve (default: every one).", _int("Index.")
                    ),
                    "collection_id": _int("Collection the carved binaries join."),
                },
                ("binary_id",),
            ),
            _WRITE,
            _tool_extract_firmware_regions,
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
            "list_notifications",
            "The notification feed derived from the action journal and the analysis log,"
            " newest first; dismissal is the client's, keyed by each item's id.",
            _object(
                {
                    "since": _str("Only items newer than this ISO timestamp."),
                    "limit": _int(f"Maximum items (default {notifications.DEFAULT_FEED_LIMIT})."),
                }
            ),
            _READ,
            _tool_list_notifications,
        ),
        Tool(
            "get_analysis",
            "One analysis with its counts, its scans, its binary's tags and its lifecycle counts.",
            _object({"analysis_id": _int("Analysis id.")}, ("analysis_id",)),
            _READ,
            _tool_get_analysis,
        ),
        Tool(
            "get_analysis_params",
            "What a re-run of one analysis would need: its engine, its binary's identity and"
            " content hash, its rebrew project context and the scans it already carries.",
            _object({"analysis_id": _int("Analysis id.")}, ("analysis_id",)),
            _READ,
            _tool_get_analysis_params,
        ),
        Tool(
            "get_analysis_func_maps",
            "One analysis's function map: every function's id, address, name and size, by address.",
            _object({"analysis_id": _int("Analysis id.")}, ("analysis_id",)),
            _READ,
            _tool_get_analysis_func_maps,
        ),
        Tool(
            "get_imported_functions",
            "One analysis's import stubs with the functions whose stored decompilation mentions"
            " each one; the callers are text derived, which the payload names.",
            _object(
                {
                    "analysis_id": _int("Analysis id."),
                    "limit": _int(f"Maximum stubs (default {store.DEFAULT_IMPORTED_LIMIT})."),
                },
                ("analysis_id",),
            ),
            _READ,
            _tool_get_imported_functions,
        ),
        Tool(
            "update_analysis",
            "Relabel one analysis's engine; journaled and revertible.",
            _object(
                {"analysis_id": _int("Analysis id."), "engine": _str("The engine label to set.")},
                ("analysis_id", "engine"),
            ),
            _WRITE,
            _tool_update_analysis,
        ),
        Tool(
            "append_analysis_log",
            "Append one log entry to an analysis; journaled and revertible.",
            _object(
                {
                    "analysis_id": _int("Analysis id."),
                    "message": _str("What to record."),
                    "severity": {
                        "type": "string",
                        "enum": list(analysis_log.SEVERITIES),
                        "description": "Defaults to info.",
                    },
                },
                ("analysis_id", "message"),
            ),
            _WRITE,
            _tool_append_analysis_log,
        ),
        Tool(
            "get_signature_batch",
            "Signatures for many functions in one read, in the order the ids were given; a"
            " function with none reports null.",
            _object(
                {
                    "function_ids": _array("Function ids to read.", _int("Function id.")),
                },
                ("function_ids",),
            ),
            _READ,
            _tool_get_signature_batch,
        ),
        Tool(
            "get_data_type_functions",
            "The functions that use one data type of an analysis's binary, from the stored"
            " reference index.",
            _object(
                {"analysis_id": _ANALYSIS_ID, "data_type_id": _int("Data type id.")},
                ("analysis_id", "data_type_id"),
            ),
            _READ,
            _tool_get_data_type_functions,
        ),
        Tool(
            "copy_signature",
            "Copy one function's signature onto others in the same analysis, journaling each"
            " target's previous signature and history.",
            _object(
                {
                    "source_function_id": _FUNCTION_ID,
                    "targets": _array("Function ids to copy it onto.", _int("Function id.")),
                },
                ("source_function_id", "targets"),
            ),
            _WRITE,
            _tool_copy_signature,
        ),
        Tool(
            "import_type_definitions",
            "Create or update data types for an analysis's binary from C declarations, parsing"
            " each with the structs-import parser; update_only refuses a new type.",
            _object(
                {
                    "analysis_id": _ANALYSIS_ID,
                    "definitions": _array("C declarations.", _str("A C declaration.")),
                    "update_only": _bool("Refuse a declaration whose type is not stored yet."),
                },
                ("analysis_id", "definitions"),
            ),
            _WRITE,
            _tool_import_type_definitions,
        ),
        Tool(
            "list_conversation_runs",
            "Every agent run of one conversation, newest first, with each run's status, tool"
            " calls and events.",
            _object({"conversation_id": _int("Conversation id.")}, ("conversation_id",)),
            _READ,
            _tool_list_conversation_runs,
        ),
        Tool(
            "get_conversation_run",
            "One agent run with its events, the tool call awaiting confirmation and the model's"
            " answer; without a run id, the conversation's newest run.",
            _object(
                {
                    "conversation_id": _int("Conversation id."),
                    "run_id": _int("Run id; the newest without one."),
                },
                ("conversation_id",),
            ),
            _READ,
            _tool_get_conversation_run,
        ),
        Tool(
            "run_conversation_agent",
            "Run one agent turn in a conversation: the model may call the local MCP tools and"
            " then answer.  A read-only tool runs at once; a destructive one pauses the run for"
            " confirm_conversation_run.",
            _object(
                {
                    "conversation_id": _int("Conversation id."),
                    "content": _str("The question to ask."),
                },
                ("conversation_id", "content"),
            ),
            _WRITE,
            _tool_run_conversation_agent,
        ),
        Tool(
            "confirm_conversation_run",
            "Approve or reject the tool call a paused agent run named and continue it; a"
            " rejection is fed back to the model as a refused call.",
            _object(
                {
                    "conversation_id": _int("Conversation id."),
                    "run_id": _int("Run id; the newest without one."),
                    "approve": _bool("False rejects the call."),
                },
                ("conversation_id",),
            ),
            _WRITE,
            _tool_confirm_conversation_run,
        ),
        Tool(
            "cancel_conversation_run",
            "Cancel a live agent run at its next step boundary; a run that already finished is"
            " refused.",
            _object(
                {
                    "conversation_id": _int("Conversation id."),
                    "run_id": _int("Run id; the newest without one."),
                },
                ("conversation_id",),
            ),
            _WRITE,
            _tool_cancel_conversation_run,
        ),
        Tool(
            "get_symbols",
            "The debug symbol files ingested for a binary (kind, counts, notes and the whole"
            " parse), or one of them by id.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "file_id": _int("One ingest; the newest without it."),
                },
                ("binary_id",),
            ),
            _READ,
            _tool_get_symbols,
        ),
        Tool(
            "import_symbols",
            "Ingest a debug symbol file: parse it with the stdlib readers, rename the functions"
            " whose VA matches a symbol and add the aggregate types it declares, as one"
            " journaled action.  apply=false stores the parse without changing anything.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "path": _str("The PDB or ELF/DWARF file to ingest."),
                    "apply": _bool("False stores the parse only."),
                },
                ("binary_id", "path"),
            ),
            _WRITE,
            _tool_import_symbols,
        ),
        Tool(
            "export_symbols",
            "Write one ingested parse to a path as a C header (reusing the type model's"
            " renderer) or as JSON.",
            _object(
                {
                    "binary_id": _BINARY_ID,
                    "path": _str("Where to write the export."),
                    "format": {
                        "type": "string",
                        "enum": ["c", "json"],
                        "description": "Defaults to c.",
                    },
                    "file_id": _int("One ingest; the newest without it."),
                },
                ("binary_id", "path"),
            ),
            _WRITE,
            _tool_export_symbols,
        ),
        Tool(
            "get_indirect_call_sites",
            "The indirect calls and jumps in a function's cached disassembly listing, with the"
            " line and operand of each; a function with no cached listing reports none rather"
            " than running the engine.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_indirect_call_sites,
        ),
        Tool(
            "get_function_capabilities",
            "Classify one function from the imports and string literals its stored decompilation"
            " mentions, with the same rule table the binary-level scan uses.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_function_capabilities,
        ),
        Tool(
            "get_function_strings",
            "A function's analyst-recorded strings and, beside them, the quoted literals its"
            " stored decompilation carries; the two halves are never merged.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_get_function_strings,
        ),
        Tool(
            "list_analysis_strings",
            "The analyst strings recorded at analysis scope.",
            _object({"analysis_id": _ANALYSIS_ID}, ("analysis_id",)),
            _READ,
            _tool_list_analysis_strings,
        ),
        Tool(
            "list_function_edges",
            "The callee edges an analyst declared for one function, with the kind, note and"
            " source.",
            _object({"function_id": _FUNCTION_ID}, ("function_id",)),
            _READ,
            _tool_list_function_edges,
        ),
        Tool(
            "get_functions_callees_callers",
            "The derived callers and callees of many functions in one read, plus the edges an"
            " analyst declared; a text derivation over stored decompilations, so it runs no"
            " engine.",
            _object(
                {"function_ids": _array("Function ids to read.", _int("Function id."))},
                ("function_ids",),
            ),
            _READ,
            _tool_get_functions_callees_callers,
        ),
        Tool(
            "get_function_matches",
            "The recorded match rows of many functions in one read, with the derived difference"
            " and band; it runs no scoring and no engine.",
            _object(
                {"function_ids": _array("Function ids to read.", _int("Function id."))},
                ("function_ids",),
            ),
            _READ,
            _tool_get_function_matches,
        ),
        Tool(
            "add_function_string",
            "Record one analyst string against a function, at function scope; journaled, and the"
            " value may not duplicate an entry already recorded there.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "value": _str("The string."),
                    "kind": {
                        "type": "string",
                        "enum": list(user_strings.KINDS),
                        "description": "Defaults to string.",
                    },
                    "note": _str("Why the string matters."),
                },
                ("function_id", "value"),
            ),
            _WRITE,
            _tool_add_function_string,
        ),
        Tool(
            "delete_function_string",
            "Remove one analyst string from a function, journaling the row it removed.",
            _object(
                {"function_id": _FUNCTION_ID, "string_id": _int("String id to remove.")},
                ("function_id", "string_id"),
            ),
            _WRITE,
            _tool_delete_function_string,
        ),
        Tool(
            "replace_analysis_strings",
            "Replace an analysis's whole analyst string list in one journaled action, so one"
            " revert puts the previous list back.",
            _object(
                {
                    "analysis_id": _ANALYSIS_ID,
                    "strings": _array("The complete list.", _str("A string.")),
                },
                ("analysis_id", "strings"),
            ),
            _WRITE,
            _tool_replace_analysis_strings,
        ),
        Tool(
            "add_function_edge",
            "Record one analyst-declared callee edge on a function, for a call the engine cannot"
            " resolve; journaled, and re-declaring the same edge updates it in place.",
            _object(
                {
                    "function_id": _FUNCTION_ID,
                    "callee": _str("Callee name the analyst asserts."),
                    "kind": {
                        "type": "string",
                        "enum": list(function_extras.EDGE_KINDS),
                        "description": "Defaults to call.",
                    },
                    "note": _str("Why the edge is claimed."),
                },
                ("function_id", "callee"),
            ),
            _WRITE,
            _tool_add_function_edge,
        ),
        Tool(
            "delete_function_edge",
            "Remove one analyst-declared callee edge, journaling the row it removed.",
            _object(
                {"function_id": _FUNCTION_ID, "edge_id": _int("Edge id to remove.")},
                ("function_id", "edge_id"),
            ),
            _WRITE,
            _tool_delete_function_edge,
        ),
        Tool(
            "canonicalize_function_names",
            "Rename many functions to the canonical name the store already recorded (a predicted"
            " name, else the newest rename), journaling every rename; apply=false only plans.",
            _object(
                {
                    "function_ids": _array("Function ids to rename.", _int("Function id.")),
                    "apply": _bool("False plans without writing."),
                },
                ("function_ids",),
            ),
            _WRITE,
            _tool_canonicalize_function_names,
        ),
        Tool(
            "list_external_sources",
            "The registered external sources with their kind, availability and the remote"
            " gate, plus whether a VirusTotal key resolves.",
            _object({}, ()),
            _READ,
            _tool_list_external_sources,
        ),
        Tool(
            "get_external_report",
            "The stored answer of one external source for an analysis; 404 no-scan before"
            " the first pull.",
            _object(
                {
                    "analysis_id": _ANALYSIS_ID,
                    "source": _str("Source name, e.g. local or virustotal."),
                },
                ("analysis_id", "source"),
            ),
            _READ,
            _tool_get_external_report,
        ),
        Tool(
            "get_external_status",
            "Whether one external source can run for an analysis and what is stored for it.",
            _object(
                {
                    "analysis_id": _ANALYSIS_ID,
                    "source": _str("Source name, e.g. local or virustotal."),
                },
                ("analysis_id", "source"),
            ),
            _READ,
            _tool_get_external_status,
        ),
        Tool(
            "run_external_source",
            "Run one external source for an analysis and store its answer; journaled.  The"
            " offline source reads stored rows, a remote one needs the workspace opt-in and a"
            " configured key.",
            _object(
                {
                    "analysis_id": _ANALYSIS_ID,
                    "source": _str("Source name, e.g. local or virustotal."),
                },
                ("analysis_id", "source"),
            ),
            _WRITE,
            _tool_run_external_source,
        ),
        Tool(
            "list_secrets",
            "Every stored credential the workspace or a team holds, redacted to its name,"
            " scope, byte length and a last-four hint; the value is never returned.",
            _object(
                {
                    "scope": _enum(
                        "Scope to list, or every scope when omitted.", secret_store.SCOPES
                    ),
                    "team_id": _int("Team id to filter a team scope."),
                }
            ),
            _READ,
            _tool_list_secrets,
        ),
        Tool(
            "set_secret",
            "Store or replace one named credential at workspace or team scope; journaled, so a"
            " revert restores the previous value.",
            _object(
                {
                    "name": _str("Secret name, e.g. virustotal.api_key."),
                    "value": _str("The credential value; it is never returned by a read."),
                    "scope": _enum("Scope to store at.", secret_store.SCOPES),
                    "team_id": _int("Team id for a team scope."),
                },
                ("name", "value"),
            ),
            _WRITE,
            _tool_set_secret,
        ),
        Tool(
            "delete_secret",
            "Remove one named credential; journaled, so a revert restores the row.",
            _object(
                {
                    "name": _str("Secret name to remove."),
                    "scope": _enum("Scope the secret lives at.", secret_store.SCOPES),
                    "team_id": _int("Team id for a team scope."),
                },
                ("name",),
            ),
            _WRITE,
            _tool_delete_secret,
        ),
        Tool(
            "list_models",
            "Every registered model that can produce a stored result, with its kind,"
            " version and availability.",
            _object({}, ()),
            _READ,
            _tool_list_models,
        ),
        Tool(
            "upgrade_analysis_model",
            "Re-run an analysis's stored LLM artifacts under a named llm model, journaling"
            " every artifact replaced; reportal never re-analyses the binary.",
            _object(
                {
                    "analysis_id": _ANALYSIS_ID,
                    "model": _str("The llm model to re-run the artifacts under."),
                    "functions": _array(
                        "Function ids to re-run; every candidate when omitted.",
                        _int("Function id."),
                    ),
                    "limit": _int(
                        f"Bound on the functions re-run (max {models.MAX_UPGRADE_LIMIT})."
                    ),
                },
                ("analysis_id", "model"),
            ),
            _WRITE,
            _tool_upgrade_analysis_model,
        ),
        Tool(
            "requeue_analysis",
            "Put an analysis back to pending and clear its finish time; journaled and revertible.",
            _object({"analysis_id": _int("Analysis id.")}, ("analysis_id",)),
            _WRITE,
            _tool_requeue_analysis,
        ),
        Tool(
            "set_analysis_tags",
            "Replace the tags on the analysis's binary, which is the scope reportal tags at;"
            " journaled and revertible.",
            _object(
                {
                    "analysis_id": _int("Analysis id."),
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "The tags the binary should carry.",
                    },
                },
                ("analysis_id", "tags"),
            ),
            _WRITE,
            _tool_set_analysis_tags,
        ),
        Tool(
            "list_jobs",
            "Queued and finished jobs, newest first, with the waiting count.",
            _object(
                {
                    "status": _str("Only jobs in this status."),
                    "kind": _str("Only jobs of this kind."),
                    "limit": _int(f"Maximum jobs (default {jobs.DEFAULT_JOB_LIMIT})."),
                }
            ),
            _READ,
            _tool_list_jobs,
        ),
        Tool(
            "get_job",
            "One job with its status, progress and result or error.",
            _object({"job_id": _int("Job id.")}, ("job_id",)),
            _READ,
            _tool_get_job,
        ),
        Tool(
            "submit_job",
            "Queue one operation (a scan kind) on a binary and answer its run id; the"
            " server's pool runs it, and list_jobs or get_job reports the outcome.",
            _object(
                {
                    "kind": _str(f"One of: {', '.join(jobs.JOB_KINDS)}."),
                    "binary_id": _int("Binary to run it on."),
                    "params": {"type": "object", "description": "Kind-specific parameters."},
                },
                ("kind", "binary_id"),
            ),
            _WRITE,
            _tool_submit_job,
        ),
        Tool(
            "cancel_job",
            "Cancel a job that has not started; a running one cannot be stopped.",
            _object({"job_id": _int("Job id.")}, ("job_id",)),
            _WRITE,
            _tool_cancel_job,
        ),
        Tool(
            "run_jobs",
            "Run the oldest waiting jobs inline and answer what finished.",
            _object({"limit": _int("How many waiting jobs to run (default 1).")}),
            _WRITE,
            _tool_run_jobs,
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

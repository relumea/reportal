"""The one effect dispatcher: what a run wrote, and how a revert takes it back.

A run of either kind records each write it made as a JSON undo descriptor: the
pipeline in ``pipeline_runs.effects_json``, auto mode in
``auto_runs.effects_json``.  A descriptor's ``kind`` selects its inverse from a
registry, so the two run kinds replay their plans through the same code instead
of each keeping its own reversal table, and a third party adds a kind without
editing this module.  Built-in kinds live in :func:`builtin_effect_handlers`;
a plugin declares an entry point in the :data:`EFFECT_ENTRY_POINT_GROUP` group
whose value is a handler or a mapping of kind to handler.  Discovery mirrors
``reportal.components``: a broken registration is skipped with a warning, and a
duplicate kind raises :class:`RegistryError`.

:func:`plan_context` rebuilds a run's journal from its descriptors as a
:class:`~reportal.components.Context`, which is what routes a stored revert
through ``Context.revert`` and therefore through one newest-first pass over
both in-process bindings and persisted writes.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import logging
import os
import re
import sqlite3
import tempfile
import threading
from collections.abc import Callable, Iterable, Mapping
from functools import partial
from pathlib import Path
from typing import Any

from reportal import auto_store, plugins, store
from reportal.components import EFFECT_FAILED, EFFECT_REVERTED, Context
from reportal.plugins import RegistryError as RegistryError

# Entry-point group third-party effect handlers register in.
EFFECT_ENTRY_POINT_GROUP = "reportal.effect_handlers"

# Origin label a built-in registration reports.
BUILTIN_ORIGIN = plugins.BUILTIN_ORIGIN

# Kinds of undo descriptor a run writes.  The first three are the pipeline's
# persistent writes; the last two are auto mode's.  The four `row-`/`file-`
# kinds are the action journal's (`reportal.journal`): a snapshot of table rows
# to re-insert, a row to delete, a file to delete, and a file to write back.
EFFECT_DISASM = "disasm"
EFFECT_DECOMPILATION = "decompilation"
EFFECT_AI_ARTIFACT = "ai-artifact"
EFFECT_FILE_WRITE = "file-write"
EFFECT_STATUS_CHANGE = "status-change"
EFFECT_ROW_RESTORE = "row-restore"
EFFECT_ROW_DELETE = "row-delete"
EFFECT_FILE_DELETE = "file-delete"
EFFECT_FILE_RESTORE = "file-restore"
# A context binding a run made.  It is informational: the binding lived in the
# process that made it, so a later process records it and applies nothing.
EFFECT_CONTEXT_CHANGE = "context-change"

# Status an auto-mode undo entry carries for a file the revert removed, and for
# one already gone.  A pipeline entry reports components.EFFECT_REVERTED, and a
# status restoration reports the status it put back instead.  A file-restore
# inverse reports EFFECT_RESTORED when it wrote the bytes back and
# EFFECT_PARTIAL when the descriptor carried no bytes to write.
EFFECT_REMOVED = "removed"
EFFECT_MISSING = "missing"
# A file inverse refused to remove a path: it no longer holds the bytes the run
# wrote, so deleting it would take another writer's file with it.
EFFECT_DIVERGED = "diverged"
EFFECT_RESTORED = "restored"
EFFECT_PARTIAL = "partial"

# An inverse action: it undoes one descriptor and returns the fields the revert
# entry carries, or None when it reports nothing beyond the reverting status.
EffectHandler = Callable[[sqlite3.Connection, dict[str, Any]], dict[str, Any] | None]

# A registered kind is an identifier-like string, which is what keeps a plugin
# kind and a descriptor's ``kind`` field usable as a mapping key.
_EFFECT_KIND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

_log = logging.getLogger(__name__)


def describe(descriptor: dict[str, Any]) -> str:
    """Human description of the write an undo descriptor reverses."""
    function_id = int(descriptor.get("function_id", 0))
    kind = str(descriptor.get("kind", ""))
    if kind == EFFECT_DISASM:
        return f"cached disassembly for function {function_id}"
    if kind == EFFECT_DECOMPILATION:
        return f"stored decompilation for function {function_id}"
    if kind == EFFECT_AI_ARTIFACT:
        return f"stored {descriptor.get('artifact_kind', '')} artifact for function {function_id}"
    if kind == EFFECT_FILE_WRITE:
        return f"wrote {descriptor.get('path', '')}"
    if kind == EFFECT_STATUS_CHANGE:
        return f"status of function {function_id}"
    if kind == EFFECT_ROW_RESTORE:
        return f"{len(descriptor.get('rows') or [])} row(s) of {descriptor.get('table', '')}"
    if kind == EFFECT_ROW_DELETE:
        return f"row of {descriptor.get('table', '')}"
    if kind == EFFECT_FILE_DELETE:
        return f"file {descriptor.get('path', '')}"
    if kind == EFFECT_FILE_RESTORE:
        return f"file {descriptor.get('path', '')}"
    if kind == EFFECT_CONTEXT_CHANGE:
        return f"{descriptor.get('change', '')} {descriptor.get('name', '')}"
    return f"effect {kind!r} on function {function_id}"


def _undo_disasm(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Drop the cached disassembly a run stored."""
    store.clear_disasm(conn, int(descriptor.get("function_id", 0)))
    return _pipeline_entry(descriptor)


def _undo_decompilation(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Restore the decompilation a run replaced, or drop the one it stored."""
    previous = descriptor.get("previous")
    function_id = int(descriptor.get("function_id", 0))
    if isinstance(previous, dict):
        store.set_decompilation(
            conn,
            function_id,
            str(previous.get("code") or ""),
            str(previous.get("backend") or ""),
            named=bool(previous.get("named")),
        )
    else:
        store.clear_decompilation(conn, function_id)
    return _pipeline_entry(descriptor)


def _undo_ai_artifact(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Restore the artifact a run replaced, or drop the one it stored."""
    previous = descriptor.get("previous")
    function_id = int(descriptor.get("function_id", 0))
    artifact_kind = str(descriptor.get("artifact_kind", ""))
    if isinstance(previous, dict):
        store.set_ai_artifact(
            conn,
            function_id,
            artifact_kind,
            dict(previous.get("payload") or {}),
            str(previous.get("model") or ""),
        )
    else:
        store.clear_ai_artifact(conn, function_id, artifact_kind)
    return _pipeline_entry(descriptor)


def file_digest(path: Path) -> str | None:
    """The SHA-256 of *path*'s bytes, or None when it cannot be read."""
    try:
        with path.open("rb") as handle:
            digest = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def file_write_descriptor(path: str | Path) -> dict[str, Any]:
    """The ``file-write`` descriptor for the file a run just wrote.

    It carries the digest of the bytes on disk now, which is what lets the
    inverse tell a file this run wrote from one another writer put there.  A
    path that cannot be read carries no digest, and a descriptor without one
    claims nothing (see :func:`_remove_written_file`).
    """
    target = str(path)
    descriptor: dict[str, Any] = {"kind": EFFECT_FILE_WRITE, "path": target}
    digest = file_digest(Path(target))
    if digest is not None:
        descriptor["sha256"] = digest
    return descriptor


def _remove_written_file(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Remove the file a run or an action wrote.

    A path that is gone reports :data:`EFFECT_MISSING`, one that still holds the
    bytes the descriptor recorded is removed, and one that no longer does
    reports :data:`EFFECT_DIVERGED` and is left alone, so a revert never deletes
    a file another writer re-created at the same path.  A descriptor with no
    digest is one persisted before the field existed or built for a write a
    crashed task never confirmed: it claims no bytes, so the path is removed as
    it always was.
    """
    raw = str(descriptor.get("path", ""))
    path = Path(raw) if raw else None
    if path is None or not path.is_file():
        return {"path": raw, "status": EFFECT_MISSING}
    recorded = str(descriptor.get("sha256") or "")
    if recorded and file_digest(path) != recorded:
        return {"path": raw, "status": EFFECT_DIVERGED}
    path.unlink(missing_ok=True)
    return {"path": raw, "status": EFFECT_REMOVED}


def _undo_file_write(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Remove the source file a run wrote, reporting one already gone as missing."""
    return _remove_written_file(conn, descriptor)


def _undo_status_change(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Restore the function status a run promoted."""
    function_id = int(descriptor.get("function_id", 0))
    before = str(descriptor.get("before", ""))
    auto_store.set_function_status(conn, function_id, before)
    return {"function_id": function_id, "status": before}


# A table or column name spliced into the row-restore SQL.  A descriptor is
# persisted, so the inverse re-validates every identifier it is handed.
_ROW_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _row_identifier(name: object) -> str:
    """Return *name* as a quoted SQL identifier, or raise :class:`ValueError`."""
    text = str(name)
    if _ROW_IDENTIFIER.match(text) is None:
        raise ValueError(f"not a table or column name: {text!r}")
    return f'"{text}"'


def _primary_key(conn: sqlite3.Connection, table: str) -> list[str]:
    """The primary-key columns of *table*, in key order."""
    quoted = _row_identifier(table)
    rows = conn.execute(f"PRAGMA table_info({quoted})").fetchall()
    keyed = [(int(row[5]), str(row[1])) for row in rows if int(row[5]) > 0]
    keyed.sort()
    return [name for _, name in keyed]


def _undo_row_restore(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Put the rows an action replaced or deleted back.

    An existing row is updated in place and a missing one inserted, never
    ``INSERT OR REPLACE``: a REPLACE deletes the conflicting row first, and with
    foreign keys on that cascades into every child row the restore is meant to
    keep.
    """
    table = str(descriptor.get("table", ""))
    rows = descriptor.get("rows") or []
    columns = [str(column) for column in (descriptor.get("columns") or [])]
    if not isinstance(rows, list):
        raise ValueError("row-restore descriptor carries no row list")
    if rows and not columns:
        raise ValueError("row-restore descriptor carries no columns")
    if columns:
        quoted = _row_identifier(table)
        names = ", ".join(_row_identifier(column) for column in columns)
        placeholders = ", ".join("?" for _ in columns)
        insert = f"INSERT INTO {quoted} ({names}) VALUES ({placeholders})"
        assignments = ", ".join(f"{_row_identifier(column)} = ?" for column in columns)
        key = _primary_key(conn, table)
        update = ""
        if key and all(column in columns for column in key):
            where = " AND ".join(f"{_row_identifier(column)} = ?" for column in key)
            update = f"UPDATE {quoted} SET {assignments} WHERE {where}"
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("row-restore descriptor carries a non-object row")
            values = tuple(row.get(column) for column in columns)
            if update and all(row.get(column) is not None for column in key):
                keyed = values + tuple(row.get(column) for column in key)
                if conn.execute(update, keyed).rowcount > 0:
                    continue
            conn.execute(insert, values)
        conn.commit()
    return {"table": table, "rows": len(rows), "status": EFFECT_REVERTED}


def _undo_row_delete(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Delete the row an action created."""
    table = str(descriptor.get("table", ""))
    keys = descriptor.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise ValueError("row-delete descriptor carries no key columns")
    where = " AND ".join(f"{_row_identifier(column)} = ?" for column in keys)
    cursor = conn.execute(
        f"DELETE FROM {_row_identifier(table)} WHERE {where}", tuple(keys.values())
    )
    conn.commit()
    return {"table": table, "deleted": cursor.rowcount, "status": EFFECT_REVERTED}


def _undo_file_delete(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Remove the file an action wrote, reporting one already gone as missing."""
    return _remove_written_file(conn, descriptor)


def _undo_file_restore(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Write back the file bytes an action deleted.

    A descriptor that carried no bytes (a file past the journal's size cap)
    reports :data:`EFFECT_PARTIAL` instead of writing a truncated file.
    The restore goes through a temp file and ``os.replace`` so a crash mid-write
    never leaves a half-restored path.
    """
    raw = str(descriptor.get("path", ""))
    encoded = descriptor.get("data_b64")
    if descriptor.get("partial") or not isinstance(encoded, str):
        return {"path": raw, "status": EFFECT_PARTIAL, "detail": "content not journaled"}
    data = base64.b64decode(encoded)
    path = Path(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=".reportal-", suffix=".tmp")
    owned = True
    try:
        with os.fdopen(handle, "wb") as stream:
            owned = False
            stream.write(data)
        os.replace(temp_name, path)
    except BaseException:
        if owned:
            with contextlib.suppress(OSError):
                os.close(handle)
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
    return {"path": raw, "bytes": len(data), "status": EFFECT_RESTORED}


def _undo_context_change(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Report a context binding change this process cannot apply.

    The binding lived in the process that made it, so a plan replayed later has
    nothing to revoke or restore.  The entry says so rather than claiming a
    restore: ``applied`` is false and the status is :data:`EFFECT_PARTIAL`.
    ``pipeline.revert_run`` handles the change against the run's live context
    before it reaches this handler.
    """
    name = str(descriptor.get("name", ""))
    change = str(descriptor.get("change", ""))
    return {
        "name": name,
        "change": change,
        "applied": False,
        "status": EFFECT_PARTIAL,
        "detail": "binding is process-local and the process that made it is gone",
    }


def _pipeline_entry(descriptor: dict[str, Any]) -> dict[str, Any]:
    """The report entry a pipeline write's inverse returns."""
    return {
        "kind": str(descriptor.get("kind", "")),
        "function_id": int(descriptor.get("function_id", 0)),
        "description": describe(descriptor),
        "status": EFFECT_REVERTED,
    }


def builtin_effect_handlers() -> dict[str, EffectHandler]:
    """The in-tree kinds and the inverse each one applies."""
    return {
        EFFECT_DISASM: _undo_disasm,
        EFFECT_DECOMPILATION: _undo_decompilation,
        EFFECT_AI_ARTIFACT: _undo_ai_artifact,
        EFFECT_FILE_WRITE: _undo_file_write,
        EFFECT_STATUS_CHANGE: _undo_status_change,
        EFFECT_ROW_RESTORE: _undo_row_restore,
        EFFECT_ROW_DELETE: _undo_row_delete,
        EFFECT_FILE_DELETE: _undo_file_delete,
        EFFECT_FILE_RESTORE: _undo_file_restore,
        EFFECT_CONTEXT_CHANGE: _undo_context_change,
    }


class UnknownEffectError(LookupError):
    """No handler is registered for a descriptor's kind."""

    def __init__(self, kind: str, known_kinds: Iterable[str]) -> None:
        self.kind = kind
        self.known_kinds = tuple(sorted(known_kinds))
        known = ", ".join(self.known_kinds) if self.known_kinds else "none"
        super().__init__(f"unknown effect kind {kind!r}; known kinds: {known}")


_registry: dict[str, EffectHandler] = {}
_origins: dict[str, str] = {}
_builtins_loaded = False
_entry_points_loaded = False
_registry_lock = threading.RLock()


def _valid_kind(kind: object) -> bool:
    """True when *kind* is a non-empty identifier-like string."""
    return isinstance(kind, str) and _EFFECT_KIND.match(kind) is not None


def register_effect_handler(
    kind: str, handler: EffectHandler, *, origin: str = BUILTIN_ORIGIN
) -> None:
    """Register *handler* as the inverse of descriptors of *kind*.

    Raises :class:`RegistryError` for a malformed kind, a non-callable handler,
    or a kind that is already taken, naming both origins (single-source
    discipline).
    """
    if not _valid_kind(kind):
        raise RegistryError(f"bad effect kind registration from {origin}: {kind!r}")
    if not callable(handler):
        raise RegistryError(
            f"bad effect handler registration {kind!r} from {origin}: handler is not callable"
        )
    with _registry_lock:
        if kind in _registry:
            raise RegistryError(
                f"duplicate effect handler registration {kind!r}: {origin} conflicts"
                f" with {_origins[kind]} (single-source discipline)"
            )
        _registry[kind] = handler
        _origins[kind] = origin


def effect_handlers() -> dict[str, EffectHandler]:
    """Every registered handler, built-ins first, in registration order."""
    _ensure_builtins()
    _ensure_entry_points()
    with _registry_lock:
        return dict(_registry)


def unregister_effect_handler(kind: str) -> None:
    """Withdraw the handler registered for descriptor *kind*.

    Raises :class:`RegistryError` for a kind nothing holds.  Withdrawing a
    built-in lasts until the next :func:`refresh_effect_handlers`.
    """
    _ensure_builtins()
    _ensure_entry_points()
    with _registry_lock:
        if kind not in _registry:
            raise RegistryError(f"no effect handler registration {kind!r} to withdraw")
        del _registry[kind]
        _origins.pop(kind, None)


def refresh_effect_handlers() -> dict[str, EffectHandler]:
    """Discard discovered handlers and re-run discovery.

    Built-ins are re-declared and the entry-point group is scanned again, which
    is how a long-lived process picks up a plugin installed after startup.
    """
    global _builtins_loaded, _entry_points_loaded
    with _registry_lock:
        _registry.clear()
        _origins.clear()
        _builtins_loaded = False
        _entry_points_loaded = False
    return effect_handlers()


def _ensure_builtins() -> None:
    """Load the in-tree handlers once."""
    global _builtins_loaded
    with _registry_lock:
        if _builtins_loaded:
            return
        _builtins_loaded = True
        for kind, handler in builtin_effect_handlers().items():
            register_effect_handler(kind, handler, origin=BUILTIN_ORIGIN)


def _ensure_entry_points() -> None:
    """Load third-party handlers once, skipping a broken registration."""
    global _entry_points_loaded
    with _registry_lock:
        if _entry_points_loaded:
            return
        _entry_points_loaded = True
        for name, value in plugins.items(EFFECT_ENTRY_POINT_GROUP):
            handlers = _load_entry_point(name, value)
            if handlers is None:
                continue
            # A duplicate kind is not skipped: two handlers claiming one kind is a
            # composition error, and the RegistryError says which registration lost.
            for kind, handler in handlers.items():
                register_effect_handler(kind, handler, origin=plugins.origin(name, value))


def _load_entry_point(name: str, value: str) -> dict[str, EffectHandler] | None:
    """Resolve one ``module:attr`` entry point into handlers, or None.

    A single callable registers under the entry-point *name* as its kind; a
    mapping registers every kind it names.  A malformed value, an unimportable
    module, a missing attribute, and a value that is neither are all skipped
    with a warning: a broken plugin must not brick the registry.

    The resolved value is not called: unlike the registries above, a callable
    here is the part rather than a factory for it, which is what omitting
    ``expected`` says.
    """
    target = plugins.resolve(EFFECT_ENTRY_POINT_GROUP, name, value, check=_validated_handlers)
    if target is None:
        return None
    if isinstance(target, Mapping):
        return {str(kind): handler for kind, handler in target.items()}
    return {name: target}


def _validated_handlers(group: str, name: str, value: str, resolved: Any) -> Any | None:
    """Accept a handler or a non-empty kind-to-callable mapping, else warn."""
    if isinstance(resolved, Mapping):
        if resolved and all(
            _valid_kind(kind) and callable(handler) for kind, handler in resolved.items()
        ):
            return resolved
        _log.warning(
            "skipping bad %s registration %r (%s): expected a non-empty mapping"
            " of kind to callable",
            group,
            name,
            value,
        )
        return None
    if callable(resolved):
        return resolved
    _log.warning(
        "skipping bad %s registration %r (%s): expected a handler or a mapping, got %s",
        group,
        name,
        value,
        type(resolved).__name__,
    )
    return None


def apply_descriptor(conn: sqlite3.Connection, descriptor: dict[str, Any]) -> dict[str, Any]:
    """Apply one descriptor's inverse and return the entry a revert reports.

    Raises :class:`UnknownEffectError` for a descriptor whose kind has no
    registered handler, which is a plan written by a newer reportal (or by a
    plugin this process does not have) than the one reading it.
    """
    kind = str(descriptor.get("kind", ""))
    handlers = effect_handlers()
    handler = handlers.get(kind)
    if handler is None:
        raise UnknownEffectError(kind, handlers)
    outcome = handler(conn, descriptor)
    return outcome if isinstance(outcome, dict) else {}


def apply_undo_plan(
    conn: sqlite3.Connection, descriptors: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Apply *descriptors* newest-first; returns an entry per descriptor.

    One failing inverse does not strand the rest: it is reported with status
    ``failed``, carrying the descriptor's identifying fields so a caller can
    still group it.
    """
    undone: list[dict[str, Any]] = []
    for descriptor in reversed(list(descriptors)):
        try:
            undone.append(apply_descriptor(conn, descriptor))
        except Exception as exc:  # one bad descriptor must not strand the rest
            entry = {
                **descriptor,
                "description": describe(descriptor),
                "status": EFFECT_FAILED,
                "detail": str(exc),
            }
            undone.append(entry)
    return undone


def plan_context(conn: sqlite3.Connection, descriptors: Iterable[dict[str, Any]]) -> Context:
    """A context whose journal is *descriptors*, so a revert replays the plan.

    Each descriptor is journaled with the dispatcher's inverse, in the run's
    original order; ``Context.revert`` then applies them newest-first alongside
    any binding the context itself carries.  ``undo_plan()`` on the result
    returns the same descriptors, which is how a run writes its plan through a
    context.
    """
    ctx = Context()
    for descriptor in descriptors:
        ctx.record(
            describe(descriptor),
            partial(apply_descriptor, conn, descriptor),
            dict(descriptor),
            kind=str(descriptor.get("kind", "")),
        )
    return ctx

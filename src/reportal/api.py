"""JSON API routes for reportal.

Every route lives under ``/api/`` and returns JSON.  POST bodies are JSON
objects; malformed input yields a 400 with a fixed message, unknown ids a
404.  The routes mount on :data:`router`, which :mod:`reportal.webapp`
includes in the application.

A handler that reads a JSON body declares it as ``body: dict[str, Any] =
Depends(json_body)``, or ``optional_json_body`` when an absent body is `{}`.
A handler that reads the query string takes ``request: Request`` and passes it
to the ``_query_*`` helpers, which read through ``request.query_params``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import re
import sqlite3
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from python_multipart.exceptions import MultipartParseError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException
from starlette.responses import Response, StreamingResponse

from reportal import (
    __version__,
    _paths,
    activity,
    agent,
    ai_decomp,
    analysis_log,
    analytics,
    attack_surface,
    auth,
    auto_mode,
    auto_store,
    auto_workers,
    behavior,
    benchmark,
    billing,
    bulk_actions,
    capabilities,
    comments,
    components,
    composition,
    conversations,
    data_types,
    decompiler_scripts,
    details,
    diffview,
    doctor,
    effects,
    engines,
    exploitability,
    external,
    families,
    filetypes,
    firmware,
    function_extras,
    function_triage,
    gobuildinfo,
    graph,
    graph_backends,
    hardening,
    instance,
    integrations,
    jobs,
    journal,
    knowledge,
    library,
    lineage,
    llm,
    matching,
    metering,
    models,
    notifications,
    observability,
    pdf,
    pipeline,
    protocols,
    ratings,
    related,
    remediation,
    remote_ingest,
    renames,
    sandbox,
    secret_store,
    secrets,
    settings,
    signatures,
    similarity,
    store,
    surface,
    symbols,
    threat,
    unpack,
    unstrip,
    user_strings,
    zipcrypto,
)
from reportal import (
    credits as credits_mod,
)
from reportal import (
    docs as docs_mod,
)
from reportal import (
    plans as plans_mod,
)
from reportal._paths import binaries_dir, db_path, reports_dir
from reportal.binary_actions import (
    ExtractError,
    download_filename,
    extract_archive_binary,
    firmware_carve_binary,
    firmware_extract_binary,
    unpack_binary,
)
from reportal.server import db, json_body, json_error, json_response, optional_json_body
from reportal.surface import classified as _classified
from reportal.surface import journaled_data_type_write as _journal_data_type_write
from reportal.surface import journaled_signature_write as _journal_signature_write
from reportal.surface import store_lineage as _store_lineage


def _fail(status: int, error: str, detail: str) -> Exception:
    """The HTTP answer to a shared-helper failure: the JSON error envelope."""
    return json_error(status, error=error, detail=detail)


def _family_error(exc: families.FamilyError) -> Response:
    """Map a family validation failure to its 400 response."""
    error, detail = surface.family_detail(exc)
    return json_error(400, error=error, detail=detail)


# The shared checks, bound to this surface's error channel.
_binary_file = partial(surface.binary_file, fail=_fail)
_engine = partial(surface.engine, fail=_fail)
_project_context = partial(surface.project_context, fail=_fail)
_require_binary = partial(surface.require_binary, fail=_fail)

router = APIRouter()
_log = logging.getLogger(__name__)

# The disassembly format `disasm_cache` holds.  The cache key is the function
# id alone, so only this format is cached; a `hex` request runs the engine and
# leaves the cache untouched rather than risk serving the wrong listing.
# Only the nasm listing is cached; the rule lives with the cache it names.
CACHEABLE_DISASM_FORMAT = store.CACHEABLE_DISASM_FORMAT

# Functions decompiled by a struct recovery run when the caller names no limit.
# `rebrew recover-structs` decompiles each function, so a live request needs a
# bound; the engine's own `--limit 0` means unlimited.
DEFAULT_STRUCT_LIMIT = 50

# Upload and function-size caps live on :mod:`reportal.instance` so the
# instance description can report them without importing this route module.
MAX_UPLOAD_BYTES = instance.MAX_UPLOAD_BYTES
MAX_UPLOAD_FILES = instance.MAX_UPLOAD_FILES
MAX_FUNCTION_SIZE = instance.MAX_FUNCTION_SIZE

# Most string needles one function-list filter may carry, combined as any-of.
MAX_FUNCTION_STRINGS = 16

# Explicit per-file upload hints the batch options accept.  They mirror the
# hosted portal's File Format and ISA pickers and the suffix-derived `format`/
# `arch` columns reportal already fills (the arch spellings are the engine's
# own, `matching.ARCHITECTURES`); an absent value leaves the stored one.
UPLOAD_FORMATS: tuple[str, ...] = ("pe", "elf", "blob")
UPLOAD_ARCHITECTURES: tuple[str, ...] = ("x86_32", "x86_64", "arm64")

# Read size while an upload streams to disk.
_UPLOAD_CHUNK_BYTES = 1024 * 1024

# Shape of the suffix kept from a client filename.  Anything else is dropped
# rather than passed through, so no client-supplied text reaches the stored
# file name.
_UPLOAD_SUFFIX = re.compile(r"^\.[A-Za-z0-9]{1,8}$")

# Accepted spellings of a boolean query parameter (`?named=`).  Anything else
# is a 400 rather than a silent false.  Truthy spellings match settings.FLAG_TRUTHY
# so env, workspace and query flags agree; false includes `off` (jobs pool).
_QUERY_TRUE = settings.FLAG_TRUTHY
_QUERY_FALSE = frozenset({"0", "false", "no", "off", ""})

# Scope of the matches a binary's match run replaces: every function of the
# binary owns the rows, and the run rewrites them.
# Scope of the signature rows a binary's seed run replaces: one row per function.
_BINARY_SIGNATURES_WHERE = (
    "function_id IN (SELECT f.id FROM functions f JOIN analyses a ON a.id = f.analysis_id"
    " WHERE a.binary_id = ?)"
)

# Scope of the signature-history rows a binary's seed run appends.
_BINARY_SIGNATURE_HISTORY_WHERE = _BINARY_SIGNATURES_WHERE

# Function-list filter vocabularies.  The name-source labels and the
# capability names come from the modules that classify them, so the route
# validates against the one definition instead of a copy that could drift.
FUNCTION_NAME_SOURCES: tuple[str, ...] = composition.NAME_SOURCE_LABELS
FUNCTION_CAPABILITIES: tuple[str, ...] = tuple(rule.name for rule in capabilities.CAPABILITIES)

# Access a global reference's engine kind names.  A kind the table does not
# carry is reported without an access rather than guessed at: an address load
# (`lea`, `mov`, `push`) references the address without reading its value, and
# a read-modify-write kind (`and_mem`, `inc_mem`) is neither one thing nor the
# other, so both stay null.
GLOBAL_ACCESS: dict[str, str] = {
    "mov_mem": "read",
    "push_mem": "read",
    "mov_mem_store": "write",
}


def _query_bool(request: Request, name: str, default: bool) -> bool:
    """Return boolean query parameter *name*, or *default* when absent."""
    raw = request.query_params.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _QUERY_TRUE:
        return True
    if value in _QUERY_FALSE:
        return False
    raise json_error(400, error=f"{name} must be a boolean")


def _query_int(request: Request, name: str) -> int | None:
    """Return integer query parameter *name*, or None when absent or blank."""
    raw = request.query_params.get(name)
    if raw is None or not str(raw).strip():
        return None
    try:
        return int(raw)
    except ValueError:
        raise json_error(400, error=f"{name} must be an integer") from None


def _query_list(request: Request, name: str, limit: int) -> tuple[list[str], Response | None]:
    """Return every value of a repeated query parameter, bounded.

    A filter that names several values at once (the function list's string
    needles) arrives as repeated parameters rather than one delimited string, so
    a value may contain the delimiter.  Returns ``(values, error)`` where a
    non-None error is the 400 to answer.
    """
    values = [value.strip() for value in request.query_params.getlist(name)]
    values = [value for value in values if value]
    if len(values) > limit:
        return [], json_error(
            400,
            error=f"invalid {name}",
            detail=f"at most {limit} {name} values are accepted",
        )
    return values, None


def _query_flag(request: Request, name: str) -> bool:
    """Return a boolean query parameter, defaulting to false when absent."""
    raw = request.query_params.get(name)
    if raw is None or not str(raw).strip():
        return False
    return str(raw).strip().lower() in _QUERY_TRUE


def _query_text(request: Request, name: str) -> str | None:
    """Return trimmed query parameter *name*, or None when absent or blank."""
    raw = request.query_params.get(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _invalid_query(name: str, value: str, allowed: Sequence[str]) -> Response:
    """The 400 for a query parameter outside its closed value set."""
    return json_error(
        400,
        error=f"invalid {name}",
        detail=f"unknown {name}: {value}; expected one of {', '.join(allowed)}",
    )


def _require_int(body: dict[str, Any], key: str) -> int:
    """Return ``body[key]`` as an int, or raise a 400 for a non-integer."""
    value = body.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise json_error(400, error=f"{key} must be an integer")
    return value


def _require_str(body: dict[str, Any], key: str) -> str:
    """Return ``body[key]`` as a non-empty string, or raise a 400."""
    value = body.get(key)
    if not isinstance(value, str) or not value.strip():
        raise json_error(400, error=f"{key} must be a non-empty string")
    return value


def _optional_str(body: dict[str, Any], key: str, default: str = "") -> str:
    """Return ``body[key]`` as a string, defaulting when absent."""
    value = body.get(key, default)
    if not isinstance(value, str):
        raise json_error(400, error=f"{key} must be a string")
    return value


def _optional_number(body: dict[str, Any], key: str, default: float) -> float:
    """Return ``body[key]`` as a float, defaulting when absent."""
    value = body.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise json_error(400, error=f"{key} must be a number")
    return float(value)


def _optional_int(body: dict[str, Any], key: str, default: int) -> int:
    """Return ``body[key]`` as an int, defaulting when absent."""
    value = body.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise json_error(400, error=f"{key} must be an integer")
    return value


def _optional_bool(body: dict[str, Any], key: str, default: bool) -> bool:
    """Return ``body[key]`` as a bool, defaulting when absent."""
    value = body.get(key, default)
    if not isinstance(value, bool):
        raise json_error(400, error=f"{key} must be a boolean")
    return value


def _optional_int_list(body: dict[str, Any], key: str) -> list[int] | None:
    """Return ``body[key]`` as a list of ints, or None when absent."""
    value = body.get(key)
    if value is None:
        return None
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in value
    ):
        raise json_error(400, error=f"{key} must be a list of integers")
    return [int(item) for item in value]


def _open() -> sqlite3.Connection:
    return db()


# ── Action journal helpers ─────────────────────────────────────────


# ── Health ─────────────────────────────────────────────────────────
#
# ``GET /api/health`` has moved to :mod:`reportal.rest`.


# ── Binaries ───────────────────────────────────────────────────────


@router.get("/api/binaries")
def list_binaries(request: Request) -> Response:
    """The binaries the caller may see, filtered and ordered.

    A team-scoped binary drops out for a non-member.  ``?search=`` matches the
    binary's name or its SHA-256 (a prefix is enough), ``?tag=`` keeps the ones
    carrying that exact tag name, ``?format=`` one stored format and
    ``?order=`` one of :data:`reportal.store.BINARY_ORDERS`; an unknown order is
    a 400.  The body echoes the filters it applied, carries ``count`` against
    ``total`` so a filter that matched nothing is distinguishable from an empty
    register, and names the ``formats`` the register holds, which is what the
    SPA's control is built from.
    """
    order = _query_text(request, "order") or store.DEFAULT_BINARY_ORDER
    if order not in store.BINARY_ORDERS:
        return _invalid_query("order", order, sorted(store.BINARY_ORDERS))
    search = _query_text(request, "search")
    tag = _query_text(request, "tag")
    fmt = _query_text(request, "format")
    with contextlib.closing(_open()) as conn:
        binaries = store.list_binaries(
            conn,
            search=search,
            tag=tag,
            fmt=fmt,
            order=order,
            visible_to=_caller(request),
        )
        total = store.count_binaries(conn, visible_to=_caller(request))
        formats = store.binary_filter_values(conn)["formats"]
    return json_response(
        {
            "binaries": binaries,
            "count": len(binaries),
            "total": total,
            "search": search,
            "tag": tag,
            "format": fmt,
            "order": order,
            "formats": formats,
        }
    )


def _upload_suffix(raw_filename: str) -> str:
    """Return the accepted suffix of a client filename, else ""."""
    suffix = Path(raw_filename).suffix
    return suffix if _UPLOAD_SUFFIX.match(suffix) else ""


def _client_name(raw_filename: str) -> str:
    """Return the display name a client filename suggests, else "".

    Only the basename is kept, and a name that survives as a path component
    (``.`` or ``..``) is dropped so the caller falls back to the content hash.
    """
    candidate = Path(raw_filename).name
    return "" if candidate in {"", ".", ".."} else candidate


class _PartError(Exception):
    """One multipart part reportal refuses; the route renders it as a JSON body."""

    def __init__(self, status: int, error: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.error = error
        self.detail = detail


def _stream_upload(upload: Any, directory: Path) -> tuple[Path, str, int]:
    """Stream one multipart part into *directory*, hashing as it goes.

    Returns ``(temporary path, sha256, size)``.  The write stops at
    :data:`MAX_UPLOAD_BYTES`; a part that passes the cap removes the temporary
    file and raises :class:`_PartError`, so no oversized upload reaches the
    disk.  The batch path catches that per file; the single-file path answers
    its 413 unchanged.
    """
    directory.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=directory, prefix=".upload-")
    temp = Path(temp_name)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            while True:
                chunk = upload.file.read(_UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise _PartError(
                        413,
                        "file-too-large",
                        f"upload exceeds {MAX_UPLOAD_BYTES} bytes",
                    )
                digest.update(chunk)
                handle.write(chunk)
    except BaseException:
        # fdopen takes ownership only on success; a failed open leaves the fd.
        with contextlib.suppress(OSError):
            os.close(fd)
        temp.unlink(missing_ok=True)
        raise
    return temp, digest.hexdigest(), size


def _read_upload(upload: Any, limit: int) -> bytes:
    """Read one multipart part into memory, raising a 413 past *limit*.

    A document is stored whole (its text is what search ranks), so unlike the
    binary upload it is buffered rather than streamed to a file; *limit* is
    what keeps the buffer bounded.
    """
    buffer = bytearray()
    while True:
        chunk = upload.file.read(_UPLOAD_CHUNK_BYTES)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > limit:
            raise json_error(413, error="file-too-large", detail=f"upload exceeds {limit} bytes")
    return bytes(buffer)


def _file_option_str(entry: Mapping[str, Any], key: str) -> str:
    """Return a per-file upload option as a trimmed string, or ""."""
    value = entry.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise json_error(400, error="invalid-body", detail=f"file option {key} must be a string")
    return value.strip()


def _file_option_str_list(entry: Mapping[str, Any], key: str) -> list[str]:
    """Return a per-file upload option as a list of trimmed strings."""
    value = entry.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise json_error(
            400, error="invalid-body", detail=f"file option {key} must be a list of strings"
        )
    return [item.strip() for item in value if item.strip()]


def _file_option_int_list(entry: Mapping[str, Any], key: str) -> list[int]:
    """Return a per-file upload option as a list of integers."""
    value = entry.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in value
    ):
        raise json_error(
            400, error="invalid-body", detail=f"file option {key} must be a list of integers"
        )
    return [int(item) for item in value]


def _file_options(raw: Any, count: int) -> list[dict[str, Any]]:
    """Parse the batch upload's per-file options, one entry per ``file`` part.

    The ``files`` field is a JSON array beside the repeated ``file`` parts,
    entry *i* describing part *i*.  An absent field means every file takes its
    defaults (the client filename and the suffix-derived format).
    """
    text = "" if raw is None else str(raw).strip()
    if not text:
        return [{} for _ in range(count)]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        raise json_error(
            400, error="invalid-body", detail="the 'files' field is not JSON"
        ) from None
    if not isinstance(parsed, list) or any(not isinstance(entry, dict) for entry in parsed):
        raise json_error(
            400, error="invalid-body", detail="the 'files' field must be a JSON array of objects"
        )
    if len(parsed) != count:
        raise json_error(
            400,
            error="invalid-body",
            detail=(
                f"the 'files' field describes {len(parsed)} files but the request carries {count}"
            ),
        )
    return [dict(entry) for entry in parsed]


def _apply_upload_tags(
    conn: sqlite3.Connection, log: journal.Journal, binary_id: int, tags: Sequence[str]
) -> list[str]:
    """Apply *tags* to a freshly uploaded binary, journaling every new row."""
    applied: list[str] = []
    for name in tags:
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
        applied.append(name)
    return applied


def _apply_upload_collections(
    conn: sqlite3.Connection, log: journal.Journal, binary_id: int, collection_ids: Sequence[int]
) -> list[int]:
    """Add a freshly uploaded binary to each named collection, journaling the links."""
    applied: list[int] = []
    for collection_id in collection_ids:
        if store.add_collection_binary(conn, collection_id, binary_id):
            log.record(
                effects.EFFECT_ROW_DELETE,
                f"added binary {binary_id} to collection {collection_id}",
                journal.row_delete_descriptor(
                    "collection_binaries",
                    {"collection_id": collection_id, "binary_id": binary_id},
                ),
            )
        applied.append(collection_id)
    return applied


def _upload_scope(
    request: Request, conn: sqlite3.Connection, entry: Mapping[str, Any]
) -> tuple[int | None, str] | None:
    """The scope one batch entry asks for, or None when it asks for nothing.

    Absent options keep the register's default (public, no owning team), so a
    client that names no scope behaves exactly as before.  A ``team_id`` without
    a ``visibility`` means team visibility, which is the shape the upload panel
    sends.  Naming a team the caller is not in is refused: the scope decides who
    may read and write the binary, and while auth is off there is no caller to
    hold to anything.
    """
    visibility = _file_option_str(entry, "visibility")
    raw_team = entry.get("team_id")
    if not visibility and raw_team is None:
        return None
    if raw_team is not None and (isinstance(raw_team, bool) or not isinstance(raw_team, int)):
        raise json_error(400, error="invalid-body", detail="file option team_id must be an integer")
    if not visibility:
        visibility = auth.VISIBILITY_TEAM
    owner, resolved = auth.scope_of(conn, team_id=raw_team, visibility=visibility)
    caller = _caller(request)
    member = owner is None or caller is None or str(caller.get("role")) == auth.ROLE_ADMIN
    if not member and owner not in set(_caller_team_ids(conn, request)):
        raise auth.NotAMemberError(auth.ERROR_NOT_A_MEMBER, f"you are not a member of team {owner}")
    return owner, resolved


def _upload_entry(
    conn: sqlite3.Connection,
    log: journal.Journal,
    request: Request,
    upload: Any,
    entry: Mapping[str, Any],
    directory: Path,
    scope: tuple[int | None, str] | None,
) -> dict[str, Any]:
    """Register one part of a batch upload and report its outcome.

    A refusal is reported in the entry instead of failing the request, so the
    files that succeeded stay registered.  *scope* is the resolved scope the
    entry asked for, or None to leave the binary where it was: a fresh binary
    carries it from the start, and a duplicate is re-scoped the way the scope
    route does it, journaled and refused when the caller may not write it.
    """
    raw_name = str(upload.filename or "")
    display = _file_option_str(entry, "name") or _client_name(raw_name) or raw_name
    try:
        temp, sha256, size = _stream_upload(upload, directory)
    except _PartError as exc:
        return _upload_error_entry(display, exc.error, exc.detail, exc.status)
    if size == 0:
        temp.unlink(missing_ok=True)
        return _upload_error_entry(display, "empty-file", "uploaded file is empty")
    tags = _file_option_str_list(entry, "tags")
    collection_ids = _file_option_int_list(entry, "collection_ids")
    existing = store.find_binary_by_sha256(conn, sha256)
    if existing is not None:
        temp.unlink(missing_ok=True)
        binary_id = int(existing["id"])
        duplicate = True
        if scope is not None:
            if not auth.may_write(
                _caller(request), existing, team_ids=_caller_team_ids(conn, request)
            ):
                return _upload_error_entry(
                    display,
                    auth.ERROR_SCOPE_FORBIDDEN,
                    f"binary {binary_id} belongs to a team you are not a member of",
                    403,
                )
            journal.journaled_rows(
                conn,
                log,
                table="binaries",
                where="id = ?",
                params=(binary_id,),
                description=f"scoped binary {binary_id} to {scope[1]}",
            )
            store.set_binary_scope(conn, binary_id, owner_team_id=scope[0], visibility=scope[1])
    else:
        suffix = _upload_suffix(raw_name)
        target = directory / f"{sha256}{suffix}"
        os.replace(temp, target)
        binary_id = store.add_binary(
            conn,
            sha256=sha256,
            name=display or sha256,
            path=str(target),
            size=size,
            fmt=_file_option_str(entry, "format") or suffix.lstrip(".").upper(),
            arch=_file_option_str(entry, "arch"),
        )
        duplicate = False
        if scope is not None:
            store.set_binary_scope(conn, binary_id, owner_team_id=scope[0], visibility=scope[1])
        log.record(
            effects.EFFECT_FILE_DELETE,
            f"stored uploaded file {target}",
            journal.file_delete_descriptor(str(target)),
        )
        log.record(
            effects.EFFECT_ROW_DELETE,
            f"registered binary {binary_id}",
            journal.row_delete_descriptor("binaries", binary_id),
        )
    applied_tags = _apply_upload_tags(conn, log, binary_id, tags)
    applied_collections = _apply_upload_collections(conn, log, binary_id, collection_ids)
    row = store.get_binary(conn, binary_id) or {}
    return {
        "file": display or sha256,
        "binary_id": binary_id,
        "duplicate": duplicate,
        "tags": applied_tags,
        "collections": applied_collections,
        "visibility": str(row.get("visibility") or auth.VISIBILITY_PUBLIC),
        "owner_team_id": row.get("owner_team_id"),
        "error": None,
    }


def _upload_error_entry(name: str, error: str, detail: str, status: int = 400) -> dict[str, Any]:
    """One batch entry for a part reportal refused; it never carries an id."""
    return {
        "file": name,
        "binary_id": None,
        "duplicate": False,
        "tags": [],
        "collections": [],
        "error": {"error": error, "detail": detail, "status": status},
    }


@router.get("/api/binaries/{binary_id}")
def get_binary(binary_id: int) -> Response:
    """One binary's row, plus the rebrew project the engine reads it through.

    ``rebrew_project`` is null for a binary imported without one, which is what
    every engine-backed read of the binary answers 400 ``no-engine-context``
    for; the route reports it so a client can say so before a read fails.
    """
    with contextlib.closing(_open()) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            return json_error(
                404, error="binary not found", detail=f"no binary with id {binary_id}"
            )
        project = store.get_rebrew_context(conn, binary_id)
    return json_response({**binary, "rebrew_project": project})


@router.post("/api/binaries/{binary_id}/firmware")
def firmware_scan(binary_id: int) -> Response:
    """Carve a stored firmware image: its embedded regions and their entropy.

    Pure byte work over the stored file: no engine call, no subprocess, nothing
    executed.  The pass is stored as the ``firmware`` scan, so a re-read costs
    nothing; 404 `binary not found`, 400 `binary not on disk`.
    """
    with contextlib.closing(_open()) as conn:
        try:
            payload = firmware_carve_binary(conn, binary_id)
        except ExtractError as exc:
            return json_error(exc.status, error=exc.code, detail=exc.detail)
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/firmware")
def firmware_regions(binary_id: int) -> Response:
    """The stored carve pass of a binary; 404 `no-scan` before the first run."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        payload = firmware.regions(conn, binary_id)
    if payload is None:
        return json_error(
            404,
            error="no-scan",
            detail=f"binary {binary_id} has no firmware scan; run 'reportal firmware {binary_id}'",
        )
    return json_response(payload)


@router.post("/api/binaries/{binary_id}/firmware/extract")
def firmware_extract(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Carve the stored firmware's regions out and register what they hold.

    Body ``{"regions": [index, ...]}`` selects the regions (every one when the
    key is absent) and ``{"collection_id": N}`` names the collection the carved
    binaries join (one named after the firmware when absent).  The whole request
    is one journal action, so its revert takes back every binary it created, the
    files it stored and the collection it joined.  A region the archive reader
    cannot unpack is carved as a binary of its own; 404 `no-scan` before the
    first carve.
    """
    raw = body.get("regions")
    if raw is not None and (
        not isinstance(raw, list)
        or any(isinstance(item, bool) or not isinstance(item, int) for item in raw)
    ):
        return json_error(400, error="invalid-region", detail="regions must be a list of indexes")
    collection_id = body.get("collection_id", 0)
    if isinstance(collection_id, bool) or not isinstance(collection_id, int):
        return json_error(
            400, error="invalid collection", detail="collection_id must be an integer"
        )
    with contextlib.closing(_open()) as conn:
        try:
            payload = firmware_extract_binary(
                conn,
                binary_id,
                region_indexes=None if raw is None else [int(item) for item in raw],
                collection_id=int(collection_id),
            )
        except ExtractError as exc:
            return json_error(exc.status, error=exc.code, detail=exc.detail)
    return json_response(payload, status=201)


@router.post("/api/binaries/{binary_id}/extract")
def extract_binary(binary_id: int, body: dict[str, Any] = Depends(optional_json_body)) -> Response:
    """Unpack a stored archive and register the binaries it holds.

    The archive is a stored binary; each member is reported with the id it
    became or the reason it was skipped, so a partially readable archive still
    registers what it could.  The whole request is **one journal action**:
    reverting its ``journal_action`` removes every binary it created, the file
    it stored and the collection it joined.  An archive reportal cannot read at
    all (an unsupported format, ``.rar``/``.7z`` without the external unpacker,
    a missing or wrong password) is 400 with the archive module's code.
    """
    password = _optional_str(body, "password")
    collection_id = _optional_int(body, "collection_id", 0)
    with contextlib.closing(_open()) as conn:
        try:
            payload = extract_archive_binary(
                conn, binary_id, password=password, collection_id=collection_id
            )
        except ExtractError as exc:
            return json_error(exc.status, error=exc.code, detail=exc.detail)
    return json_response(payload)


def _function_capabilities(function: dict[str, Any]) -> frozenset[str]:
    """Capability names a function's own name matches, through the rule table.

    A function name is an import name when the row is an import stub (a THUNK
    named after the API it forwards to), so the binary capability classifier
    answers the same question for one name: it is run with an empty string
    list, and only its import rules can match.
    """
    name = str(function.get("name") or "")
    if not name:
        return frozenset()
    found = capabilities.classify([{"name": name}], [])
    return frozenset(str(entry["name"]) for entry in found)


def _query_optional_address(request: Request, key: str) -> int | None:
    """Return one address query parameter, or None when it is absent.

    Decimal and `0x`-prefixed hex both read, which is how an analyst writes an
    address; anything else is a 400 naming the parameter.
    """
    raw = _query_text(request, key)
    if raw is None:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        raise json_error(
            400,
            error=f"invalid {key}",
            detail=f"{key} must be an integer or 0x-prefixed hex",
        ) from None


def _query_referrer_address(request: Request) -> int | None:
    """Return the `refers_to` query parameter as an address, or None when absent."""
    return _query_optional_address(request, "refers_to")


def _containing_function_ids(
    functions: Sequence[Mapping[str, Any]], addresses: Sequence[int]
) -> set[int]:
    """The ids of the stored functions whose byte range contains one of *addresses*.

    A function with no size contains nothing, and an address no stored function
    covers is simply not among the referrers: there is nowhere to navigate to.
    """
    covered: set[int] = set()
    for row in functions:
        start = int(row["va"])
        size = int(row["size"] or 0)
        if size <= 0:
            continue
        if any(start <= address < start + size for address in addresses):
            covered.add(int(row["id"]))
    return covered


@router.get("/api/binaries/{binary_id}/functions")
def list_binary_functions(request: Request, binary_id: int) -> Response:
    """Functions of one binary, filtered and sorted from the query string.

    Filters: ``name_source`` (one of :data:`FUNCTION_NAME_SOURCES`),
    ``capability`` (one of :data:`FUNCTION_CAPABILITIES`), ``min_size`` and
    ``max_size`` (inclusive byte bounds, at most :data:`MAX_FUNCTION_SIZE`),
    ``string`` (a literal the stored decompilation carries), ``match`` (one of
    :data:`reportal.store.FUNCTION_MATCH_VALUES`), ``name`` (a substring of the
    function's name), ``va`` (one exact address, decimal or ``0x`` hex) and
    ``refers_to`` (an address whose referrers the list keeps; the one
    engine-backed filter, resolved through the same ``rebrew xrefs`` call the
    xrefs route makes), ``sort``
    (one of :data:`reportal.store.FUNCTION_SORT_COLUMNS`) and ``order`` (one
    of :data:`reportal.store.FUNCTION_ORDERS`).  An unknown value is a 400.
    ``total`` counts the binary's functions before filtering, so a reader can
    tell a filter from a small binary.

    ``limit`` (bounded by :data:`reportal.store.MAX_FUNCTION_LIMIT`) and
    ``offset`` page the result, and ``matched`` reports how many rows the
    filters kept before the page was cut, so a client can tell a page from the
    whole answer.  The page is applied last, after the two filters this handler
    evaluates in Python (``name_source`` and ``capability``), so paging never
    drops a row a filter would have kept.
    """
    limit = _query_int(request, "limit")
    if limit is not None and not 1 <= limit <= store.MAX_FUNCTION_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {store.MAX_FUNCTION_LIMIT}",
        )
    offset = _query_int(request, "offset") or 0
    if offset < 0:
        return json_error(400, error="invalid offset", detail="offset must not be negative")
    min_size = _query_int(request, "min_size")
    max_size = _query_int(request, "max_size")
    for bound_name, bound in (("min_size", min_size), ("max_size", max_size)):
        if bound is not None and not 0 <= bound <= MAX_FUNCTION_SIZE:
            return json_error(
                400,
                error=f"invalid {bound_name}",
                detail=f"{bound_name} must be between 0 and {MAX_FUNCTION_SIZE}",
            )
    if min_size is not None and max_size is not None and min_size > max_size:
        return json_error(400, error="invalid size range", detail="min_size is above max_size")
    name_source = _query_text(request, "name_source")
    if name_source is not None and name_source not in FUNCTION_NAME_SOURCES:
        return _invalid_query("name_source", name_source, FUNCTION_NAME_SOURCES)
    capability = _query_text(request, "capability")
    if capability is not None and capability not in FUNCTION_CAPABILITIES:
        return _invalid_query("capability", capability, FUNCTION_CAPABILITIES)
    match = _query_text(request, "match")
    if match is not None and match not in store.FUNCTION_MATCH_VALUES:
        return _invalid_query("match", match, store.FUNCTION_MATCH_VALUES)
    refers_to = _query_referrer_address(request)
    name = _query_text(request, "name")
    va = _query_optional_address(request, "va")
    sort = _query_text(request, "sort") or store.DEFAULT_FUNCTION_SORT
    if sort not in store.FUNCTION_SORT_COLUMNS:
        return _invalid_query("sort", sort, tuple(store.FUNCTION_SORT_COLUMNS))
    order = _query_text(request, "order") or store.DEFAULT_FUNCTION_ORDER
    if order not in store.FUNCTION_ORDERS:
        return _invalid_query("order", order, store.FUNCTION_ORDERS)
    strings, strings_error = _query_list(request, "string", MAX_FUNCTION_STRINGS)
    if strings_error is not None:
        return strings_error
    regex = _query_flag(request, "regex")
    # The page goes to SQLite only when every filter is expressible there.  The
    # three this handler evaluates in Python (`refers_to`, `name_source`,
    # `capability`) each drop rows after the query, so a LIMIT pushed past them
    # would cut the page before they had a say; those requests read the matches
    # and are paged in Python below.
    post_filtered = refers_to is not None or name_source is not None or capability is not None
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            functions = store.list_functions(
                conn,
                binary_id=binary_id,
                min_size=min_size,
                max_size=max_size,
                strings=strings,
                regex=regex,
                match=match,
                name=name,
                va=va,
                sort=sort,
                order=order,
                limit=None if post_filtered else limit,
                offset=0 if post_filtered else offset,
            )
        except store.SearchError as exc:
            return json_error(400, error=exc.code, detail=exc.detail)
        total = store.count_functions(conn, binary_id=binary_id)
        # A SQL-paged request never holds every matching row, so its match count
        # is counted rather than measured off the page.  A post-filtered one is
        # counted below, after the Python filters have had their say.
        matched = (
            len(functions)
            if post_filtered
            else store.count_matching_functions(
                conn,
                binary_id=binary_id,
                min_size=min_size,
                max_size=max_size,
                strings=strings,
                regex=regex,
                match=match,
                name=name,
                va=va,
            )
        )
        referrers: set[int] | None = None
        if refers_to is not None:
            project_dir = _project_context(conn, binary_id)
            try:
                result = _engine().xrefs(project_dir, refers_to)
            except engines.EngineError as exc:
                return json_error(500, error="engine-error", detail=str(exc))
            refs = result.get("refs")
            from_vas = [
                int(ref["from_va"])
                for ref in (refs if isinstance(refs, list) else [])
                if isinstance(ref, Mapping) and isinstance(ref.get("from_va"), int)
            ]
            referrers = _containing_function_ids(functions, from_vas)
            functions = [row for row in functions if int(row["id"]) in referrers]
    if name_source is not None:
        label = composition.name_source_label
        functions = [row for row in functions if label(row) == name_source]
    if capability is not None:
        functions = [row for row in functions if capability in _function_capabilities(row)]
    if post_filtered:
        matched = len(functions)
        if limit is not None or offset:
            end = None if limit is None else offset + limit
            functions = functions[offset:end]
    return json_response(
        {
            "functions": functions,
            "count": len(functions),
            "matched": matched,
            "total": total,
        }
    )


@router.get("/api/binaries/{binary_id}/function-rollup")
def get_binary_function_rollup(binary_id: int) -> Response:
    """A binary's function totals and per-status breakdown, counted in SQLite.

    Stored-only and derived: the same three numbers a caller used to compute by
    reading the binary's whole function table, which is what a summary view
    wants and what makes that read unnecessary.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return json_response(store.function_rollup(conn, binary_id))


# ── Engine routes ──────────────────────────────────────────────────


@router.get("/api/binaries/{binary_id}/fingerprint")
def get_binary_fingerprint(binary_id: int) -> Response:
    """Stored fingerprint when one exists, else a live compute that is not stored."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = store.get_fingerprint(conn, binary_id)
        if stored is not None:
            return json_response(stored)
        path = _binary_file(conn, binary_id)
        fingerprint = _engine().fingerprint(path)
    return json_response(fingerprint)


@router.post("/api/binaries/{binary_id}/fingerprint")
def store_binary_fingerprint(binary_id: int) -> Response:
    """Compute and store a binary fingerprint through the rebrew engine."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            path = _binary_file(conn, binary_id)
            before = journal.journaled_rows(
                conn,
                log,
                table="binary_fingerprints",
                where="binary_id = ?",
                params=(binary_id,),
                description=f"replaced the fingerprint of binary {binary_id}",
            )
            fingerprint = _engine().fingerprint(path)
            store.set_fingerprint(conn, binary_id, fingerprint)
            if not before:
                journal.journaled_create(
                    log,
                    table="binary_fingerprints",
                    key={"binary_id": binary_id},
                    description=f"stored the fingerprint of binary {binary_id}",
                )
    return json_response(log.attach(fingerprint))


@router.get("/api/binaries/{binary_id}/imports")
def get_binary_imports(binary_id: int) -> Response:
    """Live pass-through of the engine's import table for a binary."""
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
        imports = _engine().imports(path)
    return json_response(imports)


@router.get("/api/binaries/{binary_id}/strings")
def get_binary_strings(request: Request, binary_id: int) -> Response:
    """Live strings from the engine, normalized and sorted server-side.

    ``?sort=`` orders by ``value`` (the text) or ``length`` and ``?order=`` by
    ``asc``/``desc``; an unknown value is 400.  Each string carries its VA when
    the engine reported one, which is what makes a click-through to the
    functions referencing it possible; an absent field stays ``null``.
    """
    sort = _query_text(request, "sort") or store.DEFAULT_STRING_SORT
    if sort not in store.STRING_SORTS:
        return _invalid_query("sort", sort, store.STRING_SORTS)
    order = _query_text(request, "order") or store.DEFAULT_FUNCTION_ORDER
    if order not in store.FUNCTION_ORDERS:
        return _invalid_query("order", order, store.FUNCTION_ORDERS)
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
        payload = _engine().strings(path)
    entries = store.normalize_string_entries(payload)
    return json_response(
        {
            "binary": payload.get("binary"),
            "count": len(entries),
            "strings": store.sort_string_entries(entries, sort=sort, order=order),
            "binary_id": binary_id,
            "sort": sort,
            "order": order,
        }
    )


def _match_view(row: Mapping[str, Any]) -> dict[str, Any]:
    """One stored match row with the derived metric fields the view renders.

    ``difference`` is the platform's Difference metric, the complement
    ``100 - similarity``, and it is derived here rather than stored; ``band``
    is the quality band the similarity falls into.
    """
    similarity_score = float(row.get("similarity") or 0.0)
    return {
        **row,
        "difference": matching.difference_of(similarity_score),
        "band": composition.quality_band(similarity_score),
    }


@router.post("/api/binaries/{binary_id}/match")
def match_binary(
    request: Request, binary_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Rank a binary's functions against the local corpus under Match Settings.

    The body carries the documented settings, each with a default that
    reproduces the run from before the settings existed: ``min_similarity``
    (80.0, a percentage floor), ``min_confidence`` (0.0, the softmax floor),
    ``include_self`` (true, whether the binary's own functions may be
    candidates), ``top`` (10), ``platforms`` (``windows``, ``linux``,
    ``android``), ``architectures`` (``x86_64``, ``x86_32``, ``arm64``),
    ``binary_ids`` and ``collection_ids``.  A value outside its range or its
    closed vocabulary is 400 with the repo's error vocabulary; an unknown
    binary or collection id is 400 too.

    The platform and architecture scope is best effort: it compares a
    binary's stored fingerprint when it has one, else its suffix-derived
    ``format``/``arch`` columns, so it is a coarse filter and not a guarantee.
    The response carries that caveat in ``notes``.

    The run records its settings on every row it writes, so a later ``GET``
    reports them back and a reader can tell two runs apart.
    """
    try:
        settings = matching.MatchSettings.from_request(body)
    except matching.InvalidSettingsError as exc:
        return json_error(400, error=exc.error, detail=exc.detail)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            matching.resolve_scope(conn, settings, visible_to=_caller(request))
        except matching.InvalidSettingsError as exc:
            return json_error(400, error=exc.error, detail=exc.detail)
        engine = _engine()
        if not similarity.available():
            return json_error(
                503,
                error="similarity-unavailable",
                detail="install the optional extra: uv sync --extra similarity",
            )
        try:
            payload = matching.journaled_match(
                conn,
                binary_id=binary_id,
                settings=settings,
                engine=engine,
                visible_to=_caller(request),
            )
        except engines.EngineUnavailable:
            return json_error(
                503, error="engine-unavailable", detail=engines.ENGINE_UNAVAILABLE_HINT
            )
        except engines.EngineError as exc:
            return json_error(500, error="engine-error", detail=str(exc))
        except similarity.SimilarityUnavailable:
            return json_error(
                503,
                error="similarity-unavailable",
                detail="install the optional extra: uv sync --extra similarity",
            )
        except matching.InvalidSettingsError as exc:
            return json_error(400, error=exc.error, detail=exc.detail)
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/matches")
def binary_matches(binary_id: int) -> Response:
    """The binary's recorded matches and the settings of the run that wrote them.

    Stored-only: it never scores and never touches the engine.  Each row
    carries the derived metric fields the matches view renders.  ``settings``
    is the run scope the rows were recorded under, or null for rows written
    outside a match run, and ``notes`` repeats the scope's caveats.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        rows = matching.binary_match_rows(conn, binary_id)
    settings = rows[0]["settings"] if rows else None
    if settings is None:
        notes = ["these rows were written outside a match run; no settings were recorded"]
    else:
        try:
            notes = matching.scope_notes(matching.MatchSettings.from_request(settings))
        except matching.InvalidSettingsError:
            # A stored payload the tool did not write is reported as unknown
            # rather than failing the read.
            notes = ["the recorded settings are not readable"]
    return json_response(
        {
            "binary_id": binary_id,
            "count": len(rows),
            "settings": settings,
            "notes": notes,
            "matches": [_match_view(row) for row in rows],
        }
    )


@router.post("/api/binaries/{binary_id}/matches/transfer")
def transfer_binary_matches(
    request: Request, binary_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Transfer candidate names and signatures for a list of matches at once.

    The body carries ``transfers`` (a non-empty list of objects with
    ``function_id``, ``candidate_function_id`` and ``mode``, the mode one of
    ``name``, ``signature`` or ``both`` and defaulting to ``name``), an
    optional boolean ``dry_run`` and an optional ``actor``.  Every row must
    name a function of this binary.

    One row's failure never abandons the rest: a row that cannot be applied is
    reported in ``transfers`` as ``failed`` with its reason, and the rows that
    succeeded keep their result.  The whole action is one journal entry, so
    ``journal_action`` reverts every row it wrote in one step.  ``dry_run``
    reports what would happen and writes nothing.

    Collision policy for a signature transfer: the target's return type,
    calling convention and parameters are replaced, but a target that already
    carries a different non-empty calling convention is refused with reason
    ``signature-conflict``, so an ABI-level mismatch is never overwritten
    silently.
    """
    try:
        requests = matching.parse_transfers(body)
    except matching.InvalidSettingsError as exc:
        return json_error(400, error=exc.error, detail=exc.detail)
    dry_run = _optional_bool(body, "dry_run", False)
    actor = _optional_str(body, "actor", "api")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            report = matching.transfer_matches(
                conn,
                None if dry_run else log,
                requests=requests,
                actor=actor,
                binary_id=binary_id,
                dry_run=dry_run,
                visible_to=_caller(request),
            )
    return json_response(log.attach(report))


# ── Triage, report and structs ─────────────────────────────────────


def _run_triage(path: Path) -> dict[str, Any]:
    """Run the engine's one-shot dossier for *path*, mapping a failure to a 500."""
    try:
        return _engine().analyze(path)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


def _run_report(project_dir: str, output_dir: Path) -> dict[str, Any]:
    """Run the engine's report into *output_dir*, mapping a failure to a 500."""
    try:
        return _engine().report(project_dir, output_dir)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


def _run_structs(project_dir: str, decompiler: str, limit: int) -> dict[str, Any]:
    """Run the engine's struct recovery, mapping a failure to a 500."""
    try:
        return _engine().structs(project_dir, decompiler=decompiler, limit=limit)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


def _run_crypto_scan(path: Path) -> dict[str, Any]:
    """Run the engine's crypto scan for *path*, mapping a failure to a 500."""
    try:
        return _engine().crypto_scan(path)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


def _run_pe_info(path: Path) -> dict[str, Any]:
    """Run the engine's PE metadata scan for *path*, mapping a failure to a 500."""
    try:
        return _engine().pe_info(path)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


def _run_security_scan(project_dir: str, min_severity: str) -> dict[str, Any]:
    """Run the engine's security scan in *project_dir*, mapping a failure to a 500."""
    try:
        return _engine().security_scan(project_dir, min_severity)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


def _no_scan(binary_id: int, kind: str, *, command: str | None = None) -> Response:
    """Return the stored-only 404 for a binary with no scan of *kind*.

    *command* overrides the route and CLI slug in the hint when it differs from
    the stored kind, as the crypto scan's ``crypto-scan`` does.
    """
    slug = command or kind
    return json_error(
        404,
        error="no-scan",
        detail=(
            f"no {kind} scan for binary {binary_id}; "
            f"run POST /api/binaries/{binary_id}/{slug} or 'reportal {slug} {binary_id}'"
        ),
    )


@contextlib.contextmanager
def _scan_span(conn: sqlite3.Connection, binary_id: int, kind: str) -> Iterator[None]:
    """Log a scan's start, and its failure, around a result route's engine call.

    The result-style scan routes run the engine before the journal helper
    stores the payload, so they cannot use `journal.journaled_scan` (which
    wraps the run itself).  This is the same span with
    ``ensure_analysis=False``: the analysis row stays the journal's to create
    and its revert's to remove when the scan succeeds, while a failure always
    leaves a log entry to blame.
    """
    with store.scan_span(conn, binary_id=binary_id, kind=kind, ensure_analysis=False):
        yield


@router.post("/api/binaries/{binary_id}/triage")
def store_binary_triage(binary_id: int) -> Response:
    """Run the engine's one-shot dossier for a binary and store it."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            with _scan_span(conn, binary_id, store.SCAN_KIND_TRIAGE):
                dossier = _run_triage(_binary_file(conn, binary_id))
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_TRIAGE, dossier)
        payload = _classified(conn, binary_id, dossier)
    return json_response(log.attach(payload))


@router.get("/api/binaries/{binary_id}/triage")
def get_binary_triage(binary_id: int) -> Response:
    """Stored triage dossier; a binary without one is a 404 no-scan.

    The response adds `software_type` and `threat_score`, derived at request
    time from the binary's stored evidence, so the stored dossier stays exactly
    what the engine returned.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE)
            if stored is not None:
                return json_response(_classified(conn, binary_id, stored))
    return _no_scan(binary_id, "triage")


@router.post("/api/binaries/{binary_id}/report")
def store_binary_report(binary_id: int) -> Response:
    """Run the engine's report into the workspace report directory and store the result."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        project_dir = _project_context(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            with _scan_span(conn, binary_id, store.SCAN_KIND_REPORT):
                result = _run_report(project_dir, reports_dir(binary_id))
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_REPORT, result)
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/report")
def get_binary_report(binary_id: int) -> Response:
    """Stored report result; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_REPORT)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "report")


@router.post("/api/binaries/{binary_id}/report/pdf")
def generate_binary_report_pdf(binary_id: int) -> Response:
    """Render the binary's PDF summary into its workspace report directory.

    The same call a queued ``report-pdf`` job makes, so the file is written and
    journaled once whether it is rendered here or by the pool; use
    ``POST /api/jobs`` to queue it instead of waiting for it.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        result = jobs.render_pdf(conn, binary_id, {})
    return json_response(
        {
            "path": result["path"],
            "bytes": result["bytes"],
            "pages": result["pages"],
            "download_url": f"/api/binaries/{binary_id}/report/pdf",
        }
        | {key: value for key, value in result.items() if key == "journal_action"}
    )


@router.get("/api/binaries/{binary_id}/report/pdf/status")
def get_binary_report_pdf_status(binary_id: int) -> Response:
    """Whether the PDF exists, what it holds, and the job that renders it.

    The hosted workflow answers its status route with the run; locally the file
    is the artifact, so this reports both: the file's path, size, page count and
    modification time when it is there, and the newest ``report-pdf`` job with
    its status, so a caller that queued one can watch it here or on
    ``GET /api/jobs/<id>``.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        job = jobs.latest_job(conn, kind="report-pdf", binary_id=binary_id)
    target = reports_dir(binary_id) / pdf.REPORT_PDF_NAME
    exists = target.is_file()
    return json_response(
        {
            "binary_id": binary_id,
            "exists": exists,
            "path": str(target),
            "bytes": target.stat().st_size if exists else 0,
            "pages": (job or {}).get("result", {}).get("pages", 0) if exists and job else 0,
            "generated_at": datetime.fromtimestamp(target.stat().st_mtime, UTC).isoformat(
                timespec="seconds"
            )
            if exists
            else None,
            "job": job,
            "download_url": f"/api/binaries/{binary_id}/report/pdf",
        }
    )


@router.get("/api/binaries/{binary_id}/report/pdf")
def get_binary_report_pdf(binary_id: int) -> Response:
    """Serve the generated PDF report; a binary without one is a 404 no-pdf."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
    target = reports_dir(binary_id) / pdf.REPORT_PDF_NAME
    if not target.is_file():
        return json_error(
            404,
            error="no-pdf",
            detail=(
                f"no PDF report for binary {binary_id}; run"
                f" 'reportal report-pdf {binary_id}' to generate it"
            ),
        )
    return Response(
        content=target.read_bytes(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{pdf.REPORT_PDF_NAME}"'},
    )


@router.post("/api/binaries/{binary_id}/structs")
def store_binary_structs(binary_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Recover a binary's struct definitions through the engine and store the result."""
    decompiler = _optional_str(body, "decompiler", engines.DEFAULT_DECOMPILER_BACKEND)
    limit = _optional_int(body, "limit", DEFAULT_STRUCT_LIMIT)
    if decompiler not in engines.DECOMPILER_BACKENDS:
        return json_error(
            400,
            error="invalid backend",
            detail=f"unsupported decompiler backend: {decompiler}",
        )
    if limit < 0:
        return json_error(400, error="invalid limit", detail=f"limit must not be negative: {limit}")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        project_dir = _project_context(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            with _scan_span(conn, binary_id, store.SCAN_KIND_STRUCTS):
                result = _run_structs(project_dir, decompiler, limit)
            journal.journaled_scan_result(
                conn,
                log,
                binary_id,
                store.SCAN_KIND_STRUCTS,
                result,
                params={"decompiler": decompiler, "limit": limit},
            )
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/structs")
def get_binary_structs(binary_id: int) -> Response:
    """Stored struct recovery; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "structs")


# ── Data types ─────────────────────────────────────────────────────


# HTTP status and stable error name per data-type failure, so the domain module
# carries no HTTP knowledge and every route answers the same codes.
_DATA_TYPE_ERRORS: tuple[tuple[type[data_types.DataTypeError], int, str], ...] = (
    (data_types.NoScanError, 404, "no-scan"),
    (data_types.UnknownDataTypeError, 404, "data-type-not-found"),
    (data_types.UnknownHistoryError, 404, "history not found"),
    (data_types.UnknownMemberError, 404, "member-not-found"),
    # An enum's named constants are its member entries, so their selector
    # failure shares the member code the catalogue documents.
    (data_types.UnknownValueError, 404, "member-not-found"),
    (data_types.ExportExistsError, 409, "export-exists"),
    (data_types.InvalidIdentifierError, 400, "invalid name"),
    (data_types.InvalidKindError, 400, "invalid kind"),
    (data_types.InvalidSizeError, 400, "invalid size"),
    (data_types.DuplicateNameError, 400, "duplicate name"),
    (data_types.DuplicateMemberError, 400, "duplicate member"),
    (data_types.DuplicateValueError, 400, "duplicate member"),
    (data_types.EmptyStructError, 400, "invalid member"),
    (data_types.InvalidMemberError, 400, "invalid member"),
    (data_types.InvalidValueError, 400, "invalid member"),
    (data_types.DefinitionError, 400, "invalid definition"),
    (data_types.ExportParentMissingError, 400, "invalid path"),
)


def _data_type_failure(exc: data_types.DataTypeError) -> Response:
    """Map a data-type failure to its JSON response."""
    for kind, status, error in _DATA_TYPE_ERRORS:
        if isinstance(exc, kind):
            return json_error(status, error=error, detail=str(exc))
    return json_error(400, error="invalid data type", detail=str(exc))


@router.get("/api/binaries/{binary_id}/data-types")
def list_binary_data_types(request: Request, binary_id: int) -> Response:
    """The binary's editable type model, optionally filtered and always counted.

    Without a filter the answer is the whole model, as it always was.  The
    namespace tree is built over the whole model either way, so the panel can
    offer a branch that the active filter excludes.

    ``?source=`` filters by provenance (`System`, `User`, `Auto Unstrip`, `AI`)
    and the payload always carries ``sources``: the count per label over the
    whole model, which is the strip the panel renders above the list.
    ``?sort=`` is one of :data:`reportal.data_types.TYPE_SORTS` (``name``, the
    default, or ``size``) and ``?direction=`` one of
    :data:`reportal.data_types.SORT_DIRECTIONS`; a type whose size the model
    states as zero (an unknown one) sorts last in either direction.  An unknown
    value of any of the four is a 400.
    """
    kind = _query_text(request, "kind") or ""
    if kind:
        try:
            kind = data_types.validate_kind(kind)
        except data_types.InvalidKindError as exc:
            return _data_type_failure(exc)
    namespace = _query_text(request, "namespace") or ""
    search = _query_text(request, "search") or ""
    source = _query_text(request, "source") or ""
    if source and source not in data_types.SOURCE_LABELS:
        return _invalid_query("source", source, data_types.SOURCE_LABELS)
    sort = _query_text(request, "sort") or data_types.DEFAULT_TYPE_SORT
    if sort not in data_types.TYPE_SORTS:
        return _invalid_query("sort", sort, data_types.TYPE_SORTS)
    direction = _query_text(request, "direction") or data_types.DEFAULT_SORT_DIRECTION
    if direction not in data_types.SORT_DIRECTIONS:
        return _invalid_query("direction", direction, data_types.SORT_DIRECTIONS)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        types = data_types.list_types(conn, binary_id=binary_id)
    selected = data_types.sort_types(
        data_types.filter_types(
            types,
            namespace=namespace or None,
            kind=kind or None,
            search=search or None,
            source=source or None,
        ),
        sort=sort,
        direction=direction,
    )
    return json_response(
        {
            "binary_id": binary_id,
            "count": len(selected),
            "total": len(types),
            "sort": sort,
            "direction": direction,
            "types": [data_types.encode_type(data_type) for data_type in selected],
            "namespaces": data_types.namespace_tree(types),
            "sources": data_types.source_totals(types),
        }
    )


@router.get("/api/data-types/{data_type_id}/references")
def data_type_references(data_type_id: int) -> Response:
    """The type's reverse indices: what references it and which functions use it."""
    with contextlib.closing(_open()) as conn:
        try:
            payload = data_types.references(conn, data_type_id)
        except data_types.DataTypeError as exc:
            return _data_type_failure(exc)
    return json_response(payload)


@router.post("/api/binaries/{binary_id}/data-types/import")
def import_binary_data_types(binary_id: int) -> Response:
    """Seed the type model from the binary's stored structs scan."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _require_binary(conn, binary_id)
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
                summary = data_types.import_types(
                    conn, binary_id=binary_id, engine=engines.get_engine()
                )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
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
    return json_response(log.attach(summary))


@router.post("/api/binaries/{binary_id}/data-types/export")
def export_binary_data_types(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Render the type model to the explicit path the caller names."""
    path = _require_str(body, "path")
    force = _optional_bool(body, "force", False)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _require_binary(conn, binary_id)
                target = Path(path)
                previous = journal.read_bounded(target) if target.is_file() else None
                summary = data_types.export_header(
                    conn, binary_id=binary_id, path=path, force=force
                )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
            journal.journaled_file(log, target, previous=previous)
    return json_response(log.attach(summary))


@router.patch("/api/data-types/{data_type_id}")
def update_data_type(
    data_type_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Edit a type's level fields and/or one of its members.

    The type-level fields (``name``, ``kind``, ``namespace``, ``size``) are one
    write and one history entry; the member edit is the exclusive alternative,
    so a request naming both is 400 ``invalid request``.  An unknown kind is 400
    `invalid kind` listing the known ones.
    """
    name = body.get("name")
    kind = body.get("kind")
    namespace = body.get("namespace")
    size = body.get("size")
    member = body.get("member")
    type_edit = {
        "name": name,
        "kind": kind,
        "namespace": namespace,
        "size": size,
    }
    named = {key: value for key, value in type_edit.items() if value is not None}
    if member is None and not named:
        return json_error(
            400,
            error="invalid request",
            detail="one of name, kind, namespace, size or member is required",
        )
    if member is not None and named:
        return json_error(
            400,
            error="invalid request",
            detail=f"member is exclusive with {', '.join(sorted(named))}",
        )
    for key in ("name", "kind", "namespace"):
        if type_edit[key] is not None and not isinstance(type_edit[key], str):
            return json_error(400, error=f"invalid {key}", detail=f"{key} must be a string")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int)):
        return json_error(400, error="invalid size", detail="size must be an integer")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                if member is None:
                    edit = _type_edit(body)
                    row = _journal_data_type_write(
                        conn,
                        log,
                        data_type_id,
                        f"edited data type {data_type_id}",
                        lambda: data_types.update_type(conn, data_type_id, **edit),
                    )
                else:
                    member_edit = _member_edit(member)
                    row = _journal_data_type_write(
                        conn,
                        log,
                        data_type_id,
                        f"edited data type {data_type_id}",
                        lambda: data_types.update_member(conn, data_type_id, **member_edit),
                    )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach(row))


def _type_edit(body: dict[str, Any]) -> dict[str, Any]:
    """Decode a PATCH body's type-level fields, absent ones left out."""
    return {
        key: body[key] for key in ("name", "kind", "namespace", "size") if body.get(key) is not None
    }


def _member_edit(member: Any) -> dict[str, Any]:
    """Decode a ``{"name"|"index", ...}`` member edit.

    ``new_pointer``, ``new_count`` and ``new_bits`` are tri-state: an absent key
    leaves the field as it is, an explicit ``null`` clears it.  The selector
    needs exactly one of ``name`` or ``index``; naming neither or both is 400
    ``invalid member``, matching the MCP tool and the domain.
    """
    if not isinstance(member, dict):
        raise json_error(400, error="invalid member", detail="member must be an object")
    selector_name = member.get("name")
    selector_index = member.get("index")
    if selector_name is not None and not isinstance(selector_name, str):
        raise json_error(400, error="invalid member", detail="member name must be a string")
    if selector_index is not None and (
        isinstance(selector_index, bool) or not isinstance(selector_index, int)
    ):
        raise json_error(400, error="invalid member", detail="member index must be an integer")
    if selector_name is None and selector_index is None:
        raise json_error(400, error="invalid member", detail="member needs a name or an index")
    if selector_name is not None and selector_index is not None:
        raise json_error(
            400,
            error="invalid member",
            detail="member name and index are exclusive",
        )
    new_name = member.get("new_name")
    new_type = member.get("new_type")
    if new_name is not None and not isinstance(new_name, str):
        raise json_error(400, error="invalid member", detail="new_name must be a string")
    if new_type is not None and not isinstance(new_type, str):
        raise json_error(400, error="invalid member", detail="new_type must be a string")
    edit: dict[str, Any] = {
        "name": selector_name,
        "index": selector_index,
        "new_name": new_name,
        "new_type": new_type,
    }
    if "new_pointer" in member:
        pointer = member["new_pointer"]
        if pointer is not None and not isinstance(pointer, bool):
            raise json_error(400, error="invalid member", detail="new_pointer must be a boolean")
        edit["new_pointer"] = pointer
    for key in ("new_count", "new_bits"):
        if key in member:
            value = member[key]
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise json_error(400, error="invalid member", detail=f"{key} must be an integer")
            edit[key] = value
    return edit


@router.post("/api/data-types/{data_type_id}/members")
def add_data_type_member(data_type_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Add one member to a type, appended or at a named position.

    ``index`` is the position the member takes and ``after`` names the member it
    follows; naming both is 400 `invalid member` rather than silently picking
    one.  The body's optional ``pointer``, ``count`` and ``bits`` carry the rest
    of the member shape.
    """
    name = _require_str(body, "name")
    type_text = _require_str(body, "type")
    addition = _member_addition(body)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"added a member to data type {data_type_id}",
                    lambda: data_types.add_member(
                        conn, data_type_id, name=name, type_text=type_text, **addition
                    ),
                )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach(row))


def _member_addition(body: dict[str, Any]) -> dict[str, Any]:
    """Decode the optional member shape and position an add names."""
    addition: dict[str, Any] = {}
    for key in ("index", "count", "bits"):
        if key in body:
            value = body[key]
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise json_error(400, error="invalid member", detail=f"{key} must be an integer")
            addition[key] = value
    if "pointer" in body:
        pointer = body["pointer"]
        if pointer is not None and not isinstance(pointer, bool):
            raise json_error(400, error="invalid member", detail="pointer must be a boolean")
        addition["pointer"] = pointer
    if "after" in body:
        after = body["after"]
        if not isinstance(after, str) or not after.strip():
            raise json_error(
                400, error="invalid member", detail="after must be a non-empty member name"
            )
        addition["after"] = after.strip()
    return addition


def _path_member_selector(segment: str) -> dict[str, Any]:
    """Select a member or enum value by path segment: digits are an index."""
    return {"index": int(segment)} if segment.isdigit() else {"name": segment}


@router.post("/api/data-types/{data_type_id}/members/{member}/gap")
def convert_data_type_member_to_gap(
    data_type_id: int, member: str, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Convert one member to explicit padding named after its offset."""
    size = body.get("size")
    if size is not None and (isinstance(size, bool) or not isinstance(size, int)):
        return json_error(400, error="invalid size", detail="size must be an integer")
    selector = _path_member_selector(member)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"converted a member of data type {data_type_id} to a gap",
                    lambda: data_types.convert_to_gap(conn, data_type_id, **selector, size=size),
                )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach(row))


@router.post("/api/data-types/{data_type_id}/members/{member}/ungap")
def convert_data_type_gap_to_member(
    data_type_id: int, member: str, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Turn one padding member back into a named, typed member."""
    new_name = _require_str(body, "name")
    new_type = _require_str(body, "type")
    conversion = _member_restore(body)
    selector = _path_member_selector(member)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"converted a gap of data type {data_type_id} to a member",
                    lambda: data_types.convert_from_gap(
                        conn,
                        data_type_id,
                        **selector,
                        new_name=new_name,
                        new_type=new_type,
                        **conversion,
                    ),
                )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach(row))


def _member_restore(body: dict[str, Any]) -> dict[str, Any]:
    """Decode an ungap body's optional pointer, count and bits, absent left out."""
    restore: dict[str, Any] = {}
    if "pointer" in body:
        pointer = body["pointer"]
        if pointer is not None and not isinstance(pointer, bool):
            raise json_error(400, error="invalid member", detail="pointer must be a boolean")
        restore["pointer"] = pointer
    for key in ("count", "bits"):
        if key in body:
            value = body[key]
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise json_error(400, error="invalid member", detail=f"{key} must be an integer")
            restore[key] = value
    return restore


@router.delete("/api/data-types/{data_type_id}/members/{member}")
def remove_data_type_member(data_type_id: int, member: str) -> Response:
    """Remove one member, selected by name or by a decimal index."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                if member.isdigit():
                    row = _journal_data_type_write(
                        conn,
                        log,
                        data_type_id,
                        f"removed a member from data type {data_type_id}",
                        lambda: data_types.remove_member(conn, data_type_id, index=int(member)),
                    )
                else:
                    row = _journal_data_type_write(
                        conn,
                        log,
                        data_type_id,
                        f"removed a member from data type {data_type_id}",
                        lambda: data_types.remove_member(conn, data_type_id, name=member),
                    )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach(row))


@router.post("/api/data-types/{data_type_id}/values")
def add_data_type_value(data_type_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Append one named enum constant.

    The body's ``value`` may be a JSON integer or a decimal/``0x`` literal
    string; omitting it continues from the last constant and the payload's
    ``note`` says which number was derived.
    """
    name = _require_str(body, "name")
    value = body.get("value")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"added an enum value to data type {data_type_id}",
                    lambda: data_types.add_value(conn, data_type_id, name=name, value=value),
                )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach(row))


@router.patch("/api/data-types/{data_type_id}/values/{value}")
def update_data_type_value(
    data_type_id: int, value: str, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Rename and/or revalue one enum constant, selected by name or index."""
    new_name = body.get("new_name")
    new_value = body.get("new_value")
    if new_name is None and new_value is None:
        return json_error(
            400, error="invalid member", detail="one of new_name or new_value is required"
        )
    if new_name is not None and not isinstance(new_name, str):
        return json_error(400, error="invalid member", detail="new_name must be a string")
    selector = _path_member_selector(value)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"edited an enum value of data type {data_type_id}",
                    lambda: data_types.update_value(
                        conn,
                        data_type_id,
                        **selector,
                        new_name=new_name,
                        new_value=new_value,
                    ),
                )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach(row))


@router.delete("/api/data-types/{data_type_id}/values/{value}")
def remove_data_type_value(data_type_id: int, value: str) -> Response:
    """Remove one enum constant, selected by name or index."""
    selector = _path_member_selector(value)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"removed an enum value from data type {data_type_id}",
                    lambda: data_types.remove_value(conn, data_type_id, **selector),
                )
            except data_types.DataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach(row))


@router.get("/api/data-types/{data_type_id}/history")
def data_type_history(data_type_id: int) -> Response:
    """A type's edit history, newest first, each entry carrying its per-field diff.

    Always answers.  The history rows are keyed by the type id and do not
    cascade with the row, so a deleted type's history is still readable here;
    a type written before the history table existed answers an empty list.
    """
    with contextlib.closing(_open()) as conn:
        history = data_types.list_history(conn, data_type_id)
        row = store.get_data_type(conn, data_type_id)
    binary_id = (
        int(row["binary_id"])
        if row is not None
        else (int(history[0]["binary_id"]) if history else None)
    )
    return json_response(
        {
            "data_type_id": data_type_id,
            "binary_id": binary_id,
            "exists": row is not None,
            "count": len(history),
            "history": history,
        }
    )


@router.post("/api/data-types/{data_type_id}/history/{history_id}/revert")
def revert_data_type_history(data_type_id: int, history_id: int) -> Response:
    """Restore the state one history row recorded, undoing that mutation.

    The revert is journaled (its ``journal_action`` reverts the revert) and
    reverting the same row twice is a no-op; a deleted type's revert puts the
    row back under its original id.  404 `history not found` for an unknown row
    or one of another type.
    """
    with contextlib.closing(_open()) as conn:
        entry = data_types.get_history(conn, history_id)
        if entry is None or int(entry["data_type_id"]) != data_type_id:
            return json_error(
                404,
                error="history not found",
                detail=f"no history {history_id} for data type {data_type_id}",
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
                return _data_type_failure(exc)
    return json_response(log.attach(result))


@router.delete("/api/data-types/{data_type_id}")
def delete_data_type(data_type_id: int) -> Response:
    """Delete one data type; 404 for an unknown id."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _journal_data_type_write(
                    conn,
                    log,
                    data_type_id,
                    f"deleted data type {data_type_id}",
                    lambda: _delete_data_type_or_raise(conn, data_type_id),
                )
            except data_types.UnknownDataTypeError as exc:
                return _data_type_failure(exc)
    return json_response(log.attach({"data_type_id": data_type_id, "deleted": True}))


def _delete_data_type_or_raise(conn: sqlite3.Connection, data_type_id: int) -> dict[str, Any]:
    """Delete one type, raising the domain error an unknown id maps to.

    The route answers 404 `data-type-not-found` from that single path, so the
    journaled and direct delete forms cannot drift apart.
    """
    if not data_types.delete_type(conn, data_type_id):
        raise data_types.UnknownDataTypeError(f"no data type with id {data_type_id}")
    return {"data_type_id": data_type_id, "deleted": True}


# HTTP status and stable error name per signature failure, so the domain module
# carries no HTTP knowledge and every route answers the same codes.
_SIGNATURE_ERRORS: tuple[tuple[type[signatures.SignatureError], int, str], ...] = (
    (signatures.UnknownSignatureError, 404, "signature-not-found"),
    (signatures.UnknownHistoryError, 404, "history not found"),
    (signatures.UnknownParameterError, 400, "invalid index"),
    (signatures.InvalidIdentifierError, 400, "invalid name"),
    (signatures.DuplicateParameterError, 400, "duplicate parameter"),
    (signatures.InvalidTypeError, 400, "invalid type"),
    (signatures.InvalidParameterError, 400, "invalid parameter"),
    (signatures.ExportExistsError, 409, "export-exists"),
    (signatures.ExportParentMissingError, 400, "invalid path"),
)


def _signature_failure(exc: signatures.SignatureError) -> Response:
    """Map a signature failure to its JSON response."""
    for kind, status, error in _SIGNATURE_ERRORS:
        if isinstance(exc, kind):
            return json_error(status, error=error, detail=str(exc))
    return json_error(400, error="invalid signature", detail=str(exc))


def _require_function_signature(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """Return the function's signature, raising 404 for an unknown function or row."""
    if store.get_function(conn, function_id) is None:
        raise json_error(
            404, error="function not found", detail=f"no function with id {function_id}"
        )
    row = signatures.get_signature(conn, function_id)
    if row is None:
        raise json_error(
            404, error="signature-not-found", detail=f"no signature for function {function_id}"
        )
    return row


def _signature_field(body: dict[str, Any], key: str) -> Any:
    """Return an optional signature field: :data:`signatures.UNSET` when absent."""
    if key not in body:
        return signatures.UNSET
    return body[key]


def _optional_signature_str(value: Any) -> str | None:
    """An optional string signature field, or None when the caller left it out."""
    return None if value is signatures.UNSET or value is None else str(value)


def _optional_signature_bits(value: Any) -> int | None:
    """An optional width signature field, or None when the caller left it out."""
    return None if value is signatures.UNSET or value is None else int(value)


def _signature_parameter_field_error(at: Any, kind: Any, bits: Any) -> Response | None:
    """Validate optional ``at``/``kind``/``bits`` for a parameter write, or None."""
    for key, value in (("at", at), ("kind", kind)):
        if value is not None and value is not signatures.UNSET and not isinstance(value, str):
            return json_error(400, error="invalid parameter", detail=f"{key} must be a string")
    if (
        bits is not None
        and bits is not signatures.UNSET
        and (isinstance(bits, bool) or not isinstance(bits, int))
    ):
        return json_error(400, error="invalid parameter", detail="bits must be an integer")
    return None


@router.get("/api/binaries/{binary_id}/signatures")
def list_binary_signatures(binary_id: int) -> Response:
    """The binary's parsed function signatures, ordered by name."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        model = signatures.list_signatures(conn, binary_id=binary_id)
    return json_response({"binary_id": binary_id, "count": len(model), "signatures": model})


@router.post("/api/binaries/{binary_id}/signatures/import")
def import_binary_signatures(binary_id: int) -> Response:
    """Seed the signature model from the binary's stored decompilations."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _require_binary(conn, binary_id)
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
            except signatures.SignatureError as exc:
                return _signature_failure(exc)
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
    return json_response(log.attach(summary))


@router.post("/api/binaries/{binary_id}/signatures/export")
def export_binary_signatures(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Render the signature model to the explicit path the caller names."""
    path = _require_str(body, "path")
    force = _optional_bool(body, "force", False)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _require_binary(conn, binary_id)
                target = Path(path)
                previous = journal.read_bounded(target) if target.is_file() else None
                summary = signatures.export_prototypes(
                    conn, binary_id=binary_id, path=path, force=force
                )
            except signatures.SignatureError as exc:
                return _signature_failure(exc)
            journal.journaled_file(log, target, previous=previous)
    return json_response(log.attach(summary))


@router.get("/api/functions/{function_id}/signature")
def get_function_signature(function_id: int) -> Response:
    """The parsed signature of one function plus its rendered prototype; 404 without one.

    Each parameter also carries ``default_at``: the arrival location its
    calling convention implies, offered beside the model rather than written
    into ``at``, so an absent ``at`` stays null.
    """
    with contextlib.closing(_open()) as conn:
        row = _require_function_signature(conn, function_id)
    model = {**row, "parameters": signatures.describe_parameters(row)}
    return json_response({**model, "prototype": signatures.render_prototype(row)})


@router.patch("/api/functions/{function_id}/signature")
def update_function_signature(
    function_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Set the return type and/or calling convention of one signature."""
    return_type = body.get("return_type")
    convention = body.get("calling_convention")
    if return_type is None and convention is None:
        return json_error(
            400, error="invalid request", detail="return_type or calling_convention is required"
        )
    if return_type is not None and not isinstance(return_type, str):
        return json_error(400, error="invalid type", detail="return_type must be a string")
    if convention is not None and not isinstance(convention, str):
        return json_error(400, error="invalid name", detail="calling_convention must be a string")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:

            def edit() -> dict[str, Any]:
                row = _require_function_signature(conn, function_id)
                if return_type is not None:
                    row = signatures.set_return_type(conn, function_id, return_type=return_type)
                if convention is not None:
                    row = signatures.set_calling_convention(
                        conn, function_id, calling_convention=convention
                    )
                return row

            try:
                row = _journal_signature_write(
                    conn, log, function_id, f"edited signature of {function_id}", edit
                )
            except signatures.SignatureError as exc:
                return _signature_failure(exc)
    return json_response(log.attach(row))


@router.post("/api/functions/{function_id}/signature/parameters")
def add_function_signature_parameter(
    function_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Add one parameter, appended or inserted at the named index.

    The body's optional ``at``, ``kind`` and ``bits`` are stored as given; an
    absent one stays null.
    """
    type_text = _require_str(body, "type")
    name = _optional_str(body, "name", "")
    index = body.get("index")
    if index is not None and (isinstance(index, bool) or not isinstance(index, int)):
        return json_error(400, error="invalid index", detail="index must be an integer")
    at = _signature_field(body, "at")
    kind = _signature_field(body, "kind")
    bits = _signature_field(body, "bits")
    field_error = _signature_parameter_field_error(at, kind, bits)
    if field_error is not None:
        return field_error
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _require_function_signature(conn, function_id)
                row = _journal_signature_write(
                    conn,
                    log,
                    function_id,
                    f"added a parameter to signature {function_id}",
                    lambda: signatures.add_parameter(
                        conn,
                        function_id,
                        type_text=type_text,
                        name=name,
                        index=index,
                        at=_optional_signature_str(at),
                        kind=_optional_signature_str(kind),
                        bits=_optional_signature_bits(bits),
                    ),
                )
            except signatures.SignatureError as exc:
                return _signature_failure(exc)
    return json_response(log.attach(row))


@router.patch("/api/functions/{function_id}/signature/parameters/{index}")
def update_function_signature_parameter(
    function_id: int, index: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Edit one parameter's type, name, arrival location, kind or width.

    ``at``, ``kind`` and ``bits`` are optional; an explicit ``null`` clears the
    field, an absent key leaves it as it is, and a request naming none of the
    fields is 400 ``invalid parameter``.
    """
    type_text = body.get("type")
    name = body.get("name")
    at = _signature_field(body, "at")
    kind = _signature_field(body, "kind")
    bits = _signature_field(body, "bits")
    if (
        type_text is None
        and name is None
        and at is signatures.UNSET
        and kind is signatures.UNSET
        and bits is signatures.UNSET
    ):
        return json_error(
            400,
            error="invalid parameter",
            detail="one of type, name, at, kind or bits is required",
        )
    if type_text is not None and not isinstance(type_text, str):
        return json_error(400, error="invalid type", detail="type must be a string")
    if name is not None and not isinstance(name, str):
        return json_error(400, error="invalid name", detail="name must be a string")
    field_error = _signature_parameter_field_error(at, kind, bits)
    if field_error is not None:
        return field_error
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _require_function_signature(conn, function_id)
                row = _journal_signature_write(
                    conn,
                    log,
                    function_id,
                    f"edited a parameter of signature {function_id}",
                    lambda: signatures.set_parameter(
                        conn,
                        function_id,
                        index=index,
                        type_text=type_text,
                        name=name,
                        at=at,
                        kind=kind,
                        bits=bits,
                    ),
                )
            except signatures.SignatureError as exc:
                return _signature_failure(exc)
    return json_response(log.attach(row))


@router.post("/api/functions/{function_id}/signature/parameters/{index}/move")
def move_function_signature_parameter(
    function_id: int, index: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Move one parameter to another position, recomputing the arrival locations."""
    to_index = body.get("to_index")
    if isinstance(to_index, bool) or not isinstance(to_index, int):
        return json_error(400, error="invalid index", detail="to_index must be an integer")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _require_function_signature(conn, function_id)
                row = _journal_signature_write(
                    conn,
                    log,
                    function_id,
                    f"reordered a parameter of signature {function_id}",
                    lambda: signatures.move_parameter(
                        conn, function_id, index=index, to_index=to_index
                    ),
                )
            except signatures.SignatureError as exc:
                return _signature_failure(exc)
    return json_response(log.attach(row))


@router.delete("/api/functions/{function_id}/signature/parameters/{index}")
def remove_function_signature_parameter(function_id: int, index: int) -> Response:
    """Remove one parameter, reindexing the rest."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                _require_function_signature(conn, function_id)
                row = _journal_signature_write(
                    conn,
                    log,
                    function_id,
                    f"removed a parameter of signature {function_id}",
                    lambda: signatures.remove_parameter(conn, function_id, index=index),
                )
            except signatures.SignatureError as exc:
                return _signature_failure(exc)
    return json_response(log.attach(row))


@router.delete("/api/functions/{function_id}/signature")
def delete_function_signature(function_id: int) -> Response:
    """Delete one function's signature; 404 for an unknown function or row."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        if signatures.get_signature(conn, function_id) is None:
            return json_error(
                404,
                error="signature-not-found",
                detail=f"no signature for function {function_id}",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:

            def remove() -> dict[str, Any]:
                signatures.delete_signature(conn, function_id)
                return {"function_id": function_id, "deleted": True}

            payload = _journal_signature_write(
                conn, log, function_id, f"deleted signature of {function_id}", remove
            )
    return json_response(log.attach(payload))


@router.get("/api/functions/{function_id}/signature/history")
def function_signature_history(function_id: int) -> Response:
    """A function's signature-edit history, newest first; always answers."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        history = signatures.list_history(conn, function_id)
    return json_response({"function_id": function_id, "count": len(history), "history": history})


@router.post("/api/functions/{function_id}/signature/history/{history_id}/revert")
def revert_function_signature(function_id: int, history_id: int) -> Response:
    """Restore the signature state recorded by one history row of a function."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        entry = signatures.get_history(conn, history_id)
        if entry is None or int(entry["function_id"]) != function_id:
            return json_error(
                404,
                error="history not found",
                detail=f"no history {history_id} for function {function_id}",
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
    return json_response(log.attach(result))


@router.post("/api/binaries/{binary_id}/crypto-scan")
def store_binary_crypto_scan(binary_id: int) -> Response:
    """Run the engine's crypto scan for a binary and store the result."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            with _scan_span(conn, binary_id, store.SCAN_KIND_CRYPTO):
                result = _run_crypto_scan(_binary_file(conn, binary_id))
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_CRYPTO, result)
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/crypto-scan")
def get_binary_crypto_scan(binary_id: int) -> Response:
    """Stored crypto scan; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_CRYPTO)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "crypto", command="crypto-scan")


@router.post("/api/binaries/{binary_id}/pe-info")
def store_binary_pe_info(binary_id: int) -> Response:
    """Run the engine's PE metadata scan for a binary and store the result."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            with _scan_span(conn, binary_id, store.SCAN_KIND_PE_INFO):
                result = _run_pe_info(_binary_file(conn, binary_id))
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_PE_INFO, result)
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/pe-info")
def get_binary_pe_info(binary_id: int) -> Response:
    """Stored PE metadata; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "pe-info")


@router.get("/api/binaries/{binary_id}/section-coverage")
def get_binary_section_coverage(binary_id: int) -> Response:
    """Per-section byte coverage over the stored pe-info sections and functions.

    Stored-only: it reads the binary's stored `pe-info` scan and its stored
    functions and never runs the engine.  A binary with no stored `pe-info`
    scan answers 404 `no-scan`; a binary with no stored functions reports
    `null` percentages and a note, never a fabricated 0%.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        coverage = store.section_byte_coverage(conn, binary_id)
    if coverage is None:
        return _no_scan(binary_id, "pe-info")
    return json_response(coverage)


def _query_address(
    request: Request,
) -> int:
    """Return the `va` query parameter as an int, raising a 400 otherwise."""
    raw = (request.query_params.get("va") or "").strip()
    if not raw:
        raise json_error(400, error="invalid address", detail="va is required")
    try:
        return int(raw, 0)
    except ValueError:
        raise json_error(
            400, error="invalid address", detail="va must be an integer or 0x-prefixed hex"
        ) from None


def _query_length(
    request: Request,
) -> int:
    """Return the bounded `length` query parameter, defaulting to the portal's 64."""
    raw = request.query_params.get("length")
    if raw is None or not raw.strip():
        return engines.MEMORY_READ_DEFAULT
    try:
        length = int(raw)
    except ValueError:
        raise json_error(400, error="invalid length", detail="length must be an integer") from None
    if length <= 0 or length > engines.MEMORY_READ_MAX:
        raise json_error(
            400,
            error="invalid length",
            detail=f"length must be between 1 and {engines.MEMORY_READ_MAX}",
        )
    return length


def _query_address_kind(
    request: Request,
) -> str:
    """Return the `kind` query parameter, defaulting to an absolute VA."""
    kind = _query_text(request, "kind") or engines.MEMORY_ADDRESS_KIND_VA
    if kind not in engines.MEMORY_ADDRESS_KINDS:
        raise json_error(
            400,
            error="invalid kind",
            detail=f"kind must be one of {', '.join(sorted(engines.MEMORY_ADDRESS_KINDS))}",
        )
    return kind


@router.get("/api/binaries/{binary_id}/memory")
def read_binary_memory(request: Request, binary_id: int) -> Response:
    """Read a window of the binary's bytes by address through the engine.

    `?va=` is the address, `?length=` the window size (default 64, cap 1024, the
    hosted portal's read_memory bounds) and `?kind=` the address kind (`va`,
    `rva` or `file`).  The engine's own `pe-info` section map locates the bytes;
    reportal never parses a PE.  An address not backed by the image's raw bytes
    answers 400 `unmapped address`, and an engine failure 500 `engine-error`.
    """
    address = _query_address(
        request,
    )
    length = _query_length(
        request,
    )
    kind = _query_address_kind(
        request,
    )
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
    try:
        window = _engine().read_memory(path, address=address, length=length, kind=kind)
    except engines.UnmappedAddressError as exc:
        return json_error(400, error="unmapped address", detail=str(exc))
    except engines.EngineError as exc:
        return json_error(500, error="engine-error", detail=str(exc))
    return json_response({"binary_id": binary_id, **window})


def _query_page_address(
    request: Request,
) -> int | None:
    """Return the `va` query parameter for a page read, or None for the start."""
    raw = (request.query_params.get("va") or "").strip()
    if not raw:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        raise json_error(
            400, error="invalid address", detail="va must be an integer or 0x-prefixed hex"
        ) from None


def _query_page_length(
    request: Request,
) -> int:
    """Return the bounded `length` query parameter of a page read."""
    raw = request.query_params.get("length")
    if raw is None or not raw.strip():
        return engines.MEMORY_PAGE_DEFAULT
    try:
        length = int(raw)
    except ValueError:
        raise json_error(400, error="invalid length", detail="length must be an integer") from None
    if length <= 0 or length > engines.MEMORY_PAGE_MAX:
        raise json_error(
            400,
            error="invalid length",
            detail=f"length must be between 1 and {engines.MEMORY_PAGE_MAX}",
        )
    return length


@router.get("/api/binaries/{binary_id}/memory/page")
def read_binary_memory_page(request: Request, binary_id: int) -> Response:
    """Read one page of the binary's bytes for the full-file hex view.

    The engine's own section map decides what is data and what is a gap: a run
    inside a section's raw bytes is read from the file, and every other byte in
    the page (a header, the gap between two sections, a section's uninitialized
    tail) is a `gap` row rather than zeros.  `?va=` is the page's first address
    (omitted starts at the first raw-backed section), `?length=` the page size
    (default 256, cap 4096) and `?kind=` the address kind (`va`, `rva` or
    `file`, so a jump is either virtual or an offset).  A start without backing
    bytes answers 400 `unmapped address`; an engine failure 500 `engine-error`.
    """
    length = _query_page_length(
        request,
    )
    kind = _query_address_kind(
        request,
    )
    address = _query_page_address(
        request,
    )
    with contextlib.closing(_open()) as conn:
        path = _binary_file(conn, binary_id)
    try:
        page = _engine().read_memory_page(path, address=address, length=length, kind=kind)
    except engines.UnmappedAddressError as exc:
        return json_error(400, error="unmapped address", detail=str(exc))
    except engines.EngineError as exc:
        return json_error(500, error="engine-error", detail=str(exc))
    return json_response({"binary_id": binary_id, **page})


def _run_capabilities(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Classify a binary's capabilities from its imports and strings, then store it."""
    engine = _engine()
    try:
        return capabilities.run_capabilities(conn, binary_id=binary_id, engine=engine)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


@router.post("/api/binaries/{binary_id}/capabilities")
def store_binary_capabilities(binary_id: int) -> Response:
    """Classify a binary from its imports and strings and store the result."""
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = journal.journaled_scan(
                conn,
                log,
                binary_id,
                store.SCAN_KIND_CAPABILITIES,
                lambda: _run_capabilities(conn, binary_id),
            )
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/capabilities")
def get_binary_capabilities(binary_id: int) -> Response:
    """Stored capability scan; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_CAPABILITIES)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "capabilities")


@router.post("/api/binaries/{binary_id}/security-scan")
def store_binary_security_scan(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Run the engine's security scan in the binary's rebrew project and store it."""
    min_severity = _optional_str(body, "min_severity", engines.DEFAULT_SECURITY_MIN_SEVERITY)
    if min_severity not in engines.SECURITY_SEVERITIES:
        return json_error(
            400,
            error="invalid severity",
            detail=f"unsupported security severity: {min_severity}",
        )
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        project_dir = _project_context(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            with _scan_span(conn, binary_id, store.SCAN_KIND_SECURITY):
                result = _run_security_scan(project_dir, min_severity)
            journal.journaled_scan_result(
                conn,
                log,
                binary_id,
                store.SCAN_KIND_SECURITY,
                result,
                params={"min_severity": min_severity},
            )
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/security-scan")
def get_binary_security_scan(binary_id: int) -> Response:
    """Stored security scan; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_SECURITY)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "security", command="security-scan")


@router.get("/api/binaries/{binary_id}/exploitability")
def get_binary_exploitability(binary_id: int) -> Response:
    """Rank the stored security findings by reachability.

    A stored-only read over the ``security`` and ``capabilities`` scans: a
    finding is ``reachable`` when another stored function's decompilation
    mentions its function (whole-token text derivation, stated as such) and
    ``network-adjacent`` when its function text mentions network imports or
    the binary carries the networking capability.  404 `no-scan` without a
    stored security scan.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            payload = exploitability.rank(conn, binary_id)
        except KeyError as exc:
            return json_error(404, error="binary not found", detail=str(exc))
    if not payload["available"]:
        return _no_scan(binary_id, "exploitability", command="security-scan")
    return json_response(payload)


@router.post("/api/binaries/{binary_id}/threat")
def store_binary_threat(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Build a binary's local threat report and store it as the `threat` scan."""
    narrative = _optional_bool(body, "narrative", False)
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        engine = _engine()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    store.SCAN_KIND_THREAT,
                    lambda: threat.build_threat_report(
                        conn,
                        binary_id=binary_id,
                        engine=engine,
                        llm_client=llm.get_client(),
                        narrative=narrative,
                    ),
                )
            except engines.EngineError as exc:
                raise json_error(500, error="engine-error", detail=str(exc)) from exc
            payload = _classified(conn, binary_id, result)
    return json_response(log.attach(payload))


@router.get("/api/binaries/{binary_id}/threat")
def get_binary_threat(binary_id: int) -> Response:
    """Stored threat report; a binary without one is a 404 no-scan.

    The response adds `software_type` and `threat_score`, derived at request
    time from the binary's stored evidence, so the stored scan stays the
    engine-independent payload `reportal threat` wrote.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_THREAT)
            if stored is not None:
                return json_response(_classified(conn, binary_id, stored))
    return _no_scan(binary_id, "threat")


@router.post("/api/binaries/{binary_id}/remediation")
def store_binary_remediation(binary_id: int) -> Response:
    """Generate the YARA, Snort and STIX artifacts for a binary and store them."""
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        engine = _engine()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    store.SCAN_KIND_REMEDIATION,
                    lambda: remediation.build_remediation(conn, binary_id=binary_id, engine=engine),
                )
            except remediation.NoStringsError as exc:
                raise json_error(404, error="no-strings", detail=str(exc)) from exc
            except engines.EngineUnavailable as exc:
                raise json_error(503, error="engine-unavailable", detail=str(exc)) from exc
            except engines.EngineError as exc:
                raise json_error(500, error="engine-error", detail=str(exc)) from exc
    return json_response(log.attach(result))


def _stored_remediation(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Return the stored remediation payload of *binary_id*, or None."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, store.SCAN_KIND_REMEDIATION)


def _no_remediation_scan(binary_id: int) -> Response:
    """Return the 404 for a binary with no stored remediation payload."""
    return json_error(
        404,
        error="no-scan",
        detail=(
            f"no remediation scan for binary {binary_id}; run"
            f" POST /api/binaries/{binary_id}/remediation or 'reportal yara {binary_id}'"
        ),
    )


@router.get("/api/binaries/{binary_id}/remediation")
def get_binary_remediation(binary_id: int) -> Response:
    """Stored remediation rule; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = _stored_remediation(conn, binary_id)
    if stored is not None:
        return json_response(stored)
    return _no_remediation_scan(binary_id)


def _no_remediation_artifact(binary_id: int, fmt: str) -> Response:
    """Return the 404 for a stored payload without the requested artifact."""
    return json_error(
        404,
        error="no-artifact",
        detail=(
            f"the stored remediation scan for binary {binary_id} carries no {fmt} artifact;"
            f" re-run 'reportal {fmt} {binary_id}' to rebuild it"
        ),
    )


@router.get("/api/binaries/{binary_id}/remediation/{fmt}")
def get_binary_remediation_artifact(binary_id: int, fmt: str) -> Response:
    """Serve one stored remediation artifact: YARA and Snort as text, STIX as JSON.

    An unknown format and a payload without that piece answer 404; a Snort
    artifact with no rules is served as an empty text body, which is its
    honest result when the threat scan names no network indicator.
    """
    if fmt not in remediation.REMEDIATION_FORMATS:
        return json_error(
            404,
            error="format-not-found",
            detail=(
                f"unknown remediation format: {fmt};"
                f" expected one of {', '.join(remediation.REMEDIATION_FORMATS)}"
            ),
        )
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = _stored_remediation(conn, binary_id)
        if stored is None:
            return _no_remediation_scan(binary_id)
        if fmt == "yara":
            text = stored.get("rule")
        elif fmt == "snort":
            snort = stored.get("snort")
            text = snort.get("text") if isinstance(snort, dict) else None
        else:
            bundle = stored.get("stix")
            if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
                return _no_remediation_artifact(binary_id, fmt)
            return json_response(bundle)
    if not isinstance(text, str):
        return _no_remediation_artifact(binary_id, fmt)
    return Response(content=text.encode("utf-8"), media_type="text/plain")


# ── Behavior scans (execution, networking, filesystem) ─────────────


def _behavior_domain_error(domain: str) -> Response | None:
    """Return the 404 for an unknown behavior domain, or None when it is valid."""
    if domain not in behavior.BEHAVIOR_DOMAINS:
        return json_error(
            404,
            error="domain not found",
            detail=f"unknown behavior domain: {domain}",
        )
    return None


def _stored_behavior(
    conn: sqlite3.Connection, binary_id: int, domain: str
) -> dict[str, Any] | None:
    """Return the stored scan of one behavior *domain*, or None."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, behavior.DOMAIN_SCAN_KINDS[domain])


@router.post("/api/binaries/{binary_id}/behavior/{domain}")
def store_binary_behavior(binary_id: int, domain: str) -> Response:
    """Run one behavior scan on a binary and store the result."""
    error = _behavior_domain_error(domain)
    if error is not None:
        return error
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        kind = behavior.DOMAIN_SCAN_KINDS[domain]
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    kind,
                    lambda: behavior.scan_domain(
                        conn, binary_id=binary_id, domain=domain, engine=_engine()
                    ),
                )
            except engines.EngineError as exc:
                raise json_error(500, error="engine-error", detail=str(exc)) from exc
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/behavior")
def get_binary_behavior(binary_id: int) -> Response:
    """All three stored behavior scans of a binary, null where one is absent."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        payload: dict[str, Any] = {
            domain: _stored_behavior(conn, binary_id, domain)
            for domain in behavior.BEHAVIOR_DOMAINS
        }
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/behavior/{domain}")
def get_binary_behavior_domain(binary_id: int, domain: str) -> Response:
    """Stored scan of one behavior domain; a binary without one is a 404 no-scan."""
    error = _behavior_domain_error(domain)
    if error is not None:
        return error
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = _stored_behavior(conn, binary_id, domain)
        if stored is not None:
            return json_response(stored)
    return json_error(
        404,
        error="no-scan",
        detail=(
            f"no {domain} scan for binary {binary_id}; run"
            f" POST /api/binaries/{binary_id}/behavior/{domain}"
            f" or 'reportal behavior {binary_id} {domain}'"
        ),
    )


# ── Hardening scans (anti-analysis, obfuscation) ───────────────────


def _hardening_domain_error(domain: str) -> Response | None:
    """Return the 404 for an unknown hardening domain, or None when it is valid."""
    if domain not in hardening.HARDENING_DOMAINS:
        return json_error(
            404,
            error="domain not found",
            detail=f"unknown hardening domain: {domain}",
        )
    return None


def _stored_hardening(
    conn: sqlite3.Connection, binary_id: int, domain: str
) -> dict[str, Any] | None:
    """Return the stored scan of one hardening *domain*, or None."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, hardening.DOMAIN_SCAN_KINDS[domain])


@router.post("/api/binaries/{binary_id}/hardening/{domain}")
def store_binary_hardening(binary_id: int, domain: str) -> Response:
    """Run one hardening scan on a binary and store the result."""
    error = _hardening_domain_error(domain)
    if error is not None:
        return error
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        kind = hardening.DOMAIN_SCAN_KINDS[domain]
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    kind,
                    lambda: hardening.scan_hardening(
                        conn, binary_id=binary_id, domain=domain, engine=_engine()
                    ),
                )
            except engines.EngineError as exc:
                raise json_error(500, error="engine-error", detail=str(exc)) from exc
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/hardening")
def get_binary_hardening(binary_id: int) -> Response:
    """Both stored hardening scans of a binary, null where one is absent."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        payload: dict[str, Any] = {
            domain: _stored_hardening(conn, binary_id, domain)
            for domain in hardening.HARDENING_DOMAINS
        }
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/hardening/{domain}")
def get_binary_hardening_domain(binary_id: int, domain: str) -> Response:
    """Stored scan of one hardening domain; a binary without one is a 404 no-scan."""
    error = _hardening_domain_error(domain)
    if error is not None:
        return error
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = _stored_hardening(conn, binary_id, domain)
        if stored is not None:
            return json_response(stored)
    return json_error(
        404,
        error="no-scan",
        detail=(
            f"no {domain} scan for binary {binary_id}; run"
            f" POST /api/binaries/{binary_id}/hardening/{domain}"
            f" or 'reportal hardening {binary_id} {domain}'"
        ),
    )


# ── Secrets scan ───────────────────────────────────────────────────


def _run_secrets(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Scan a binary's strings for secrets from the engine, then store the result."""
    engine = _engine()
    try:
        return secrets.run_secrets(conn, binary_id=binary_id, engine=engine)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


@router.post("/api/binaries/{binary_id}/secrets")
def store_binary_secrets(binary_id: int) -> Response:
    """Scan a binary's strings for credentials and high-entropy values and store them."""
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = journal.journaled_scan(
                conn,
                log,
                binary_id,
                store.SCAN_KIND_SECRETS,
                lambda: _run_secrets(conn, binary_id),
            )
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/secrets")
def get_binary_secrets(binary_id: int) -> Response:
    """Stored secrets scan; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_SECRETS)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "secrets")


# ── Protocols scan ─────────────────────────────────────────────────


def _run_protocols(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Infer a binary's protocols from the engine payloads, then store the result."""
    engine = _engine()
    try:
        return protocols.scan_protocols(conn, binary_id=binary_id, engine=engine)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


@router.post("/api/binaries/{binary_id}/protocols")
def store_binary_protocols(binary_id: int) -> Response:
    """Infer the network protocols a binary speaks and store the result."""
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = journal.journaled_scan(
                conn,
                log,
                binary_id,
                store.SCAN_KIND_PROTOCOLS,
                lambda: _run_protocols(conn, binary_id),
            )
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/protocols")
def get_binary_protocols(binary_id: int) -> Response:
    """Stored protocols scan; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_PROTOCOLS)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "protocols")


# ── Function triage ────────────────────────────────────────────────


def _run_function_triage(
    conn: sqlite3.Connection, binary_id: int, *, function_ids: list[int] | None, limit: int
) -> dict[str, Any]:
    """Summarize and score selected functions, then store the aggregate.

    A missing LLM endpoint is not an error: the run falls back to the
    deterministic heuristic and records that in its notes.  A missing engine is
    an error only on the LLM path, which needs a disassembly for a function
    whose decompilation is not stored.
    """
    try:
        return function_triage.summarize_functions(
            conn,
            binary_id=binary_id,
            function_ids=function_ids,
            limit=limit,
            client=llm.get_client(),
            engine=engines.get_engine(),
        )
    except ValueError as exc:
        raise json_error(400, error="invalid body", detail=str(exc)) from exc
    except engines.EngineUnavailable as exc:
        raise json_error(503, error="engine-unavailable", detail=str(exc)) from exc
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


@router.post("/api/binaries/{binary_id}/function-triage")
def store_binary_function_triage(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Summarize and score a binary's selected functions and store the result."""
    function_ids = _optional_int_list(body, "function_ids")
    limit = _optional_int(body, "limit", function_triage.DEFAULT_LIMIT)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = journal.journaled_scan(
                conn,
                log,
                binary_id,
                store.SCAN_KIND_FUNCTION_TRIAGE,
                lambda: _run_function_triage(
                    conn, binary_id, function_ids=function_ids, limit=limit
                ),
            )
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/function-triage")
def get_binary_function_triage(binary_id: int) -> Response:
    """Stored per-function triage; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = function_triage.stored_function_triage(conn, binary_id=binary_id)
        if stored is not None:
            return json_response(stored)
    return _no_scan(binary_id, "function-triage")


@router.post("/api/binaries/{binary_id}/library")
def store_binary_library(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Identify a binary's library functions and store the reading.

    The engine's own signature match runs in the binary's stored rebrew project
    context, so a binary without one answers 400 `no-engine-context`; 404
    `binary not found` for an unknown id and 500 `engine-error` when the
    identification fails.  The body's optional ``min_confidence`` drops the
    candidates below it before the components are derived, so the threshold and
    the module counts cannot disagree.
    """
    min_confidence = _optional_number(body, "min_confidence", library.DEFAULT_MIN_CONFIDENCE)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        _project_context(conn, binary_id)
        engine = _engine()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    library.SCAN_KIND,
                    lambda: library.run_library(
                        conn, binary_id=binary_id, engine=engine, min_confidence=min_confidence
                    ),
                )
            except engines.EngineError as exc:
                return json_error(500, error="engine-error", detail=str(exc))
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/library")
def get_binary_library(binary_id: int) -> Response:
    """The stored library reading, empty rather than 404 before the first run."""
    with contextlib.closing(_open()) as conn:
        try:
            payload = library.describe(conn, binary_id)
        except library.LibraryError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/sbom")
def get_binary_sbom(request: Request, binary_id: int) -> Response:
    """Render the stored library reading as a component list.

    ``?format=`` is one of :data:`reportal.library.SBOM_FORMATS` (`cyclonedx`,
    `spdx` or `csv`); JSON is answered for the two schema shapes and text for
    the CSV.  The reading comes from the stored scan, so exporting never runs
    the engine again, and a binary that was never identified answers an empty
    document rather than a 404 so an automated consumer gets a valid file.
    """
    fmt = (_query_text(request, "format") or library.FORMAT_CYCLONEDX).lower()
    if fmt not in library.SBOM_FORMATS:
        return json_error(
            400,
            error="invalid format",
            detail=f"format must be one of {', '.join(library.SBOM_FORMATS)}",
        )
    with contextlib.closing(_open()) as conn:
        try:
            payload = library.sbom(conn, binary_id, fmt=fmt)
        except library.LibraryError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)
    if fmt == library.FORMAT_CSV:
        return Response(
            content=library.render_csv(payload),
            media_type="text/csv",
            headers={"Content-Disposition": 'inline; filename="sbom.csv"'},
        )
    return json_response(payload)


@router.post("/api/binaries/{binary_id}/unpack")
def unpack_binary_route(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Rebuild a packed binary's image and register it as a new binary.

    The packer is the body's optional ``packer`` when it names one, else the one
    the source file's own stub identifies; the body's optional ``name`` is the
    new binary's display name.  The packed source is left untouched and the new
    binary carries the provenance as its ``unpack`` scan.  404 `binary not
    found`, 400 `binary not on disk`, 400 `no-packer` when nothing is packed,
    400 `unknown-packer` for a name that is not a known packer, 400
    `no-unpacker` for UPX without the external tool, and 503
    `engine-unavailable` for an LZEXE image without the engine.
    """
    packer = _optional_str(body, "packer").strip().lower()
    name = _optional_str(body, "name")
    with contextlib.closing(_open()) as conn:
        try:
            payload = unpack_binary(conn, binary_id, packer=packer, name=name)
        except ExtractError as exc:
            return json_error(exc.status, error=exc.code, detail=exc.detail)
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/unpack")
def get_binary_unpack(binary_id: int) -> Response:
    """The stored provenance of an unpacked binary, empty rather than 404.

    A binary reportal did not unpack answers ``stored: false`` and names the
    command that produces one, so a caller can tell "not unpacked" from "no such
    binary".
    """
    with contextlib.closing(_open()) as conn:
        try:
            payload = unpack.describe(conn, binary_id)
        except unpack.UnpackError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)
    return json_response(payload)


@router.post("/api/binaries/{binary_id}/unstrip")
def store_binary_unstrip(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Identify a binary's library functions and store the rename proposals."""
    min_confidence = _optional_number(body, "min_confidence", unstrip.DEFAULT_MIN_CONFIDENCE)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        _project_context(conn, binary_id)
        engine = _engine()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    store.SCAN_KIND_UNSTRIP,
                    lambda: unstrip.run_unstrip(
                        conn, binary_id=binary_id, engine=engine, min_confidence=min_confidence
                    ),
                )
            except engines.EngineError as exc:
                return json_error(500, error="engine-error", detail=str(exc))
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/unstrip")
def get_binary_unstrip(binary_id: int) -> Response:
    """Stored unstrip proposals; a binary without any is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_UNSTRIP)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, "unstrip")


@router.post("/api/binaries/{binary_id}/unstrip/apply")
def apply_binary_unstrip(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Apply one stored unstrip proposal, recording the rename."""
    function_id = _require_int(body, "function_id")
    override = body.get("name")
    if override is not None and not isinstance(override, str):
        return json_error(400, error="name must be a string")
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
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
            except KeyError:
                return json_error(
                    404, error="function not found", detail=f"no function with id {function_id}"
                )
            except unstrip.NoProposalError as exc:
                return json_error(404, error="no-proposal", detail=str(exc))
            except ValueError as exc:
                return json_error(400, error="invalid name", detail=str(exc))
            function = store.get_function(conn, function_id)
    return json_response(log.attach({**change, "function": function}))


# ── Lineage comparisons ────────────────────────────────────────────


def _lineage_other_id(body: dict[str, Any]) -> int:
    """Return the POST body's other binary id, or raise a 400."""
    value = body.get("other_binary_id")
    if isinstance(value, bool) or not isinstance(value, int):
        raise json_error(
            400,
            error="invalid other_binary_id",
            detail="other_binary_id must be an integer",
        )
    return value


@router.post("/api/binaries/{binary_id}/benchmark")
def store_binary_benchmark(
    request: Request, binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Score a match run against known counterpart addresses.

    The body names the partner binary with ``right_binary_id`` and the ground
    truth with an optional ``labels`` list of ``{"left_va", "right_va"}``
    objects; without one the labels are the two binaries' shared real function
    names, which the payload states because a shared name is the case a name
    transfer gets right for free.  ``min_similarity``, ``min_confidence`` and
    ``top`` come from the body as they do on the match route, while the
    candidate scope is always the partner binary: a benchmark is about one pair.
    404 `binary not found` for either id, 400 `invalid-labels` for the same
    binary twice or a malformed pair, 400 `no-labels` when nothing resolves to a
    stored function, 503 `similarity-unavailable` without the extra; the run is
    an ordinary match, so it replaces the left binary's recorded matches and is
    journaled as one action.
    """
    right_binary_id = _optional_int(body, "right_binary_id", 0)
    if right_binary_id <= 0:
        return json_error(
            400, error="invalid right_binary_id", detail="right_binary_id is required"
        )
    raw_labels = body.get("labels")
    if raw_labels is not None and not isinstance(raw_labels, list):
        return json_error(
            400,
            error="invalid labels",
            detail="labels must be a list of {left_va, right_va} objects",
        )
    try:
        settings = dataclasses.replace(
            matching.MatchSettings.from_request(body),
            binary_ids=(right_binary_id,),
            include_self=False,
        )
    except matching.InvalidSettingsError as exc:
        return json_error(400, error=exc.error, detail=exc.detail)
    with contextlib.closing(_open()) as conn:
        try:
            result = benchmark.run(
                conn,
                left_binary_id=binary_id,
                right_binary_id=right_binary_id,
                engine=_engine(),
                labels=raw_labels,
                settings=settings,
                visible_to=_caller(request),
            )
        except benchmark.BenchmarkError as exc:
            status = 404 if exc.code == "binary not found" else 400
            return json_error(status, error=exc.code, detail=exc.detail)
        except matching.InvalidSettingsError as exc:
            return json_error(400, error=exc.error, detail=exc.detail)
        except similarity.SimilarityUnavailable:
            return json_error(
                503,
                error="similarity-unavailable",
                detail="install the optional extra: uv sync --extra similarity",
            )
        except engines.EngineUnavailable:
            return json_error(
                503, error="engine-unavailable", detail=engines.ENGINE_UNAVAILABLE_HINT
            )
        except engines.EngineError as exc:
            return json_error(500, error="engine-error", detail=str(exc))
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(
                conn,
                log,
                binary_id,
                store.SCAN_KIND_BENCHMARK,
                result,
                params={"right_binary_id": right_binary_id, **settings.payload()},
            )
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/benchmark")
def get_binary_benchmark(binary_id: int) -> Response:
    """The stored benchmark of a binary, empty rather than 404 before the first run."""
    with contextlib.closing(_open()) as conn:
        try:
            payload = benchmark.describe(conn, binary_id)
        except benchmark.BenchmarkError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/rename-benchmark")
def get_binary_rename_benchmark(binary_id: int) -> Response:
    """Score the stored rename proposals against the names symbols supplied.

    A stored read: no engine runs and nothing is written.  The ground truth is
    the functions an ingested debug symbol file named, the proposals are the
    stored library reading (else the stored unstrip proposals), and the answer
    is precision, recall, F1 and every disagreement.  A binary with either input
    missing answers 200 with ``stored: false`` and the reason (``no-symbols`` or
    ``no-proposals``) rather than an error, so a panel names the missing input;
    only an unknown id is 404 `binary not found`.
    """
    with contextlib.closing(_open()) as conn:
        try:
            payload = benchmark.rename_report(conn, binary_id)
        except benchmark.BenchmarkError as exc:
            status = 404 if exc.code == "binary not found" else 400
            return json_error(status, error=exc.code, detail=exc.detail)
    return json_response(payload)


@router.post("/api/binaries/{binary_id}/lineage")
def store_binary_lineage(
    request: Request, binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Compare a binary with another and store the comparison on the left binary."""
    other_binary_id = _lineage_other_id(body)
    refine = _optional_bool(body, "refine", True)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if not _visible_binary(conn, other_binary_id, _caller(request)):
            return json_error(
                404, error="binary not found", detail=f"no binary with id {other_binary_id}"
            )
        if other_binary_id == binary_id:
            return json_error(
                400,
                error="same binary",
                detail=f"binary {binary_id} cannot be compared with itself",
            )
        try:
            comparison = lineage.compare_binaries(
                conn,
                left_binary_id=binary_id,
                right_binary_id=other_binary_id,
                engine=engines.get_engine(),
                refine=refine,
            )
        except lineage.SameBinaryError as exc:
            return json_error(400, error="same binary", detail=str(exc))
        except KeyError as exc:
            return json_error(404, error="binary not found", detail=str(exc.args[0]))
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan(
                conn,
                log,
                binary_id,
                store.SCAN_KIND_LINEAGE,
                lambda: _store_lineage(conn, comparison),
            )
    return json_response(log.attach(comparison))


@router.get("/api/binaries/{binary_id}/lineage")
def get_binary_lineage(request: Request, binary_id: int) -> Response:
    """One stored comparison of the pair, or every comparison stored for a binary."""
    raw_other = request.query_params.get("other_binary_id")
    if raw_other is not None:
        try:
            other_binary_id = int(raw_other)
        except ValueError:
            return json_error(
                400,
                error="invalid other_binary_id",
                detail="other_binary_id must be an integer",
            )
    else:
        other_binary_id = None
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if other_binary_id is None:
            return json_response(
                {
                    "binary_id": binary_id,
                    "comparisons": lineage.stored_comparisons(conn, binary_id),
                }
            )
        stored = lineage.stored_comparison(conn, binary_id, other_binary_id)
        if stored is not None:
            return json_response(stored)
    return json_error(
        404,
        error="no-scan",
        detail=(
            f"no lineage comparison of binary {binary_id} with binary {other_binary_id};"
            f" run POST /api/binaries/{binary_id}/lineage"
            f" or 'reportal lineage {binary_id} {other_binary_id}'"
        ),
    )


@router.get("/api/analyses/{analysis_id}/scans")
def list_analysis_scans(analysis_id: int) -> Response:
    """Stored scans of one analysis, newest first, without their result payloads."""
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        scans = store.list_scans(conn, analysis_id)
    return json_response({"scans": scans})


@router.get("/api/binaries/{binary_id}/scans")
def list_binary_scans(binary_id: int) -> Response:
    """Every stored scan of a binary's newest analysis, with the inputs each ran with.

    The result payload is left out (it can be large, and the route for that scan
    serves it); ``params`` is what the caller named when the scan ran, which is
    what a reader needs to run the scan again the same way.  A scan whose
    parameters predate that recording reports an empty object rather than a
    guessed one, and a binary with no analysis answers an empty list.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        scans = [] if analysis_id is None else store.list_scans(conn, analysis_id)
    return json_response(
        {
            "binary_id": binary_id,
            "analysis_id": analysis_id,
            "scans": scans,
            "count": len(scans),
        }
    )


# ── Malware families and detection ─────────────────────────────────


def _optional_str_list(body: dict[str, Any], key: str) -> list[str]:
    """Return ``body[key]`` as a list of strings, or raise a 400."""
    value = body.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise json_error(400, error=f"{key} must be a list of strings")
    return value


def _detect_error(exc: engines.EngineError | KeyError | FileNotFoundError) -> Response:
    """Map an engine or filesystem failure of a bundle derivation."""
    if isinstance(exc, engines.EngineUnavailable):
        return json_error(
            503,
            error="engine-unavailable",
            detail=engines.ENGINE_UNAVAILABLE_HINT,
        )
    if isinstance(exc, KeyError):
        return json_error(404, error="binary not found", detail=str(exc.args[0]))
    if isinstance(exc, FileNotFoundError):
        return json_error(400, error="binary not on disk", detail=str(exc))
    return json_error(500, error="engine-error", detail=str(exc))


@router.get("/api/families")
def list_families() -> Response:
    """Every registered family with its stored signature bundle."""
    with contextlib.closing(_open()) as conn:
        rows = families.list_families(conn)
    return json_response({"families": rows})


@router.post("/api/families")
def create_family(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Register a family from a reference binary and store its signature bundle."""
    name = _require_str(body, "name")
    reference_binary_id = _require_int(body, "reference_binary_id")
    aliases = _optional_str_list(body, "aliases")
    notes = _optional_str(body, "notes")
    with contextlib.closing(_open()) as conn:
        if not _visible_binary(conn, reference_binary_id, _caller(request)):
            return json_error(
                404,
                error="binary not found",
                detail=f"no binary with id {reference_binary_id}",
            )
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
                return _family_error(exc)
            except (engines.EngineError, KeyError, FileNotFoundError) as exc:
                return _detect_error(exc)
            journal.journaled_create(
                log,
                table="families",
                key=int(family["family_id"]),
                description=f"registered family {family['family_id']}",
            )
    return json_response(log.attach(family), status=201)


@router.get("/api/families/{family_id}")
def get_family(family_id: int) -> Response:
    """One registered family with its stored signature bundle."""
    with contextlib.closing(_open()) as conn:
        family = families.get_family(conn, family_id)
    if family is None:
        return json_error(404, error="family not found", detail=f"no family with id {family_id}")
    return json_response(family)


@router.delete("/api/families/{family_id}")
def delete_family(family_id: int) -> Response:
    """Delete a registered family; 404 for an unknown id."""
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
                return json_error(
                    404, error="family not found", detail=f"no family with id {family_id}"
                )
    return json_response(log.attach({"family_id": family_id, "deleted": True}))


@router.post("/api/binaries/{binary_id}/detect")
def store_binary_detect(binary_id: int) -> Response:
    """Match a binary against every registered family and store the result."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    store.SCAN_KIND_DETECT,
                    lambda: families.detect_binary(
                        conn, binary_id=binary_id, engine=engines.get_engine()
                    ),
                )
            except (engines.EngineError, KeyError, FileNotFoundError) as exc:
                return _detect_error(exc)
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/detect")
def get_binary_detect(binary_id: int) -> Response:
    """Stored family detection; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = families.stored_detection(conn, binary_id)
        if stored is not None:
            return json_response(stored)
    return _no_scan(binary_id, store.SCAN_KIND_DETECT)


# ── Related binaries ───────────────────────────────────────────────


@router.post("/api/binaries/{binary_id}/related")
def store_binary_related(
    request: Request, binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Rank the other stored binaries against this one and store the result."""
    limit = _optional_int(body, "limit", related.DEFAULT_LIMIT)
    include_unrelated = _optional_bool(body, "include_unrelated", False)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    store.SCAN_KIND_RELATED,
                    lambda: related.find_related(
                        conn,
                        binary_id=binary_id,
                        engine=engines.get_engine(),
                        limit=limit,
                        include_unrelated=include_unrelated,
                        visible_to=_caller(request),
                    ),
                )
            except ValueError as exc:
                return json_error(400, error="invalid limit", detail=str(exc))
            except KeyError as exc:
                return json_error(404, error="binary not found", detail=str(exc.args[0]))
            except engines.EngineError as exc:
                return json_error(500, error="engine-error", detail=str(exc))
    return json_response(log.attach(payload))


@router.get("/api/binaries/{binary_id}/related")
def get_binary_related(binary_id: int) -> Response:
    """Stored relationship ranking; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = related.stored_related(conn, binary_id)
        if stored is not None:
            return json_response(stored)
    return _no_scan(binary_id, store.SCAN_KIND_RELATED, command="related")


# ── Composition ────────────────────────────────────────────────────


@router.post("/api/binaries/{binary_id}/composition")
def store_binary_composition(
    request: Request, binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Build the binary's composition analysis from the store and store it.

    The body narrows the candidate corpus exactly as the match settings sheet
    does: ``{"binary_ids": [...], "collection_ids": [...]}`` goes through
    ``matching.resolve_scope``, so a scoped composition reads the edges a
    scoped match would have written, and the stored payload records the scope it
    was built under.  An id no row carries answers 400 with the scope module's
    own code (``unknown binary`` / ``unknown collection``).
    """
    binary_ids = _optional_int_list(body, "binary_ids") or []
    collection_ids = _optional_int_list(body, "collection_ids") or []
    with contextlib.closing(_open()) as conn:
        try:
            result = composition.compute_composition(
                conn,
                binary_id=binary_id,
                binary_ids=binary_ids,
                collection_ids=collection_ids,
                visible_to=_caller(request),
            )
        except composition.NoCompositionError as exc:
            return json_error(404, error="binary not found", detail=str(exc.args[0]))
        except matching.InvalidSettingsError as exc:
            return json_error(400, error=exc.error, detail=exc.detail)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_COMPOSITION, result)
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/composition")
def get_binary_composition(binary_id: int) -> Response:
    """Stored composition analysis; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        stored = composition.stored_composition(conn, binary_id)
        if stored is not None:
            return json_response(stored)
    return _no_scan(binary_id, store.SCAN_KIND_COMPOSITION, command="composition")


# ── File type ──────────────────────────────────────────────────────


@router.post("/api/binaries/{binary_id}/filetype")
def store_binary_filetype(binary_id: int) -> Response:
    """Detect a binary's file type and packer signatures and store the result."""
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        _engine()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    store.SCAN_KIND_FILETYPE,
                    lambda: filetypes.run_filetype(
                        conn, binary_id=binary_id, engine=engines.get_engine()
                    ),
                )
            except engines.EngineError as exc:
                return json_error(500, error="engine-error", detail=str(exc))
    return json_response(log.attach(payload))


@router.get("/api/binaries/{binary_id}/filetype")
def get_binary_filetype(binary_id: int) -> Response:
    """Stored file-type detection; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_FILETYPE)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, store.SCAN_KIND_FILETYPE)


@router.post("/api/binaries/{binary_id}/gobuildinfo")
def store_binary_gobuildinfo(binary_id: int) -> Response:
    """Recover a binary's Go build information and store it as a scan.

    Reads the stored file bytes for the ``go.buildinfo`` magic (version,
    module path, build settings); no engine and no project context.
    A file without the magic is 400 `not-go`.
    """
    with contextlib.closing(_open()) as conn:
        _binary_file(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = journal.journaled_scan(
                    conn,
                    log,
                    binary_id,
                    gobuildinfo.SCAN_KIND,
                    lambda: gobuildinfo.recover(conn, binary_id=binary_id),
                )
            except gobuildinfo.GobuildinfoError as exc:
                return json_error(400, error=exc.code, detail=exc.detail)
    return json_response(log.attach(payload))


@router.get("/api/binaries/{binary_id}/gobuildinfo")
def get_binary_gobuildinfo(binary_id: int) -> Response:
    """Stored Go build information; a binary without one is a 404 no-scan."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        if analysis_id is not None:
            stored = store.get_scan(conn, analysis_id, gobuildinfo.SCAN_KIND)
            if stored is not None:
                return json_response(stored)
    return _no_scan(binary_id, gobuildinfo.SCAN_KIND)


@router.get("/api/binaries/{binary_id}/die-info")
def get_binary_die_info(binary_id: int) -> Response:
    """Detect-It-Easy shaped identity, composed from the stored scans.

    The hosted portal answers this with a live detector; locally it is a read of
    the stored ``pe-info`` and ``filetype`` scans, so it runs no engine and
    writes nothing.  Each category lists what matched and why, and ``sources``
    names every input with the command that produces it, so an empty category is
    visibly "nothing matched" rather than "nothing ran".  A binary with neither
    source stored is 404 `no-scan`.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        payload = details.die_info(conn, binary_id)
    if not payload["available"]:
        return _no_scan(binary_id, store.SCAN_KIND_FILETYPE, command="filetype")
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/additional-details")
def get_binary_additional_details(binary_id: int) -> Response:
    """The overlay, Rich header, debug, presence and section shape of one binary.

    A read of the stored ``pe-info`` scan: the hosted portal fills the same
    fields in asynchronously, so its status route is here too, and both compose
    rather than run the engine.  404 `no-scan` without a stored ``pe-info``.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if not details.source_present(conn, binary_id, store.SCAN_KIND_PE_INFO):
            return _no_scan(binary_id, store.SCAN_KIND_PE_INFO, command="pe-info")
        return json_response(details.additional_details(conn, binary_id))


@router.get("/api/binaries/{binary_id}/additional-details/status")
def get_binary_additional_details_status(binary_id: int) -> Response:
    """Which sources the detail reads have, and which command fills a gap.

    Always answers 200 once the binary exists: the point of a status read is to
    report what is missing rather than to refuse, which is what the hosted
    portal's asynchronous status route is for.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        return json_response(details.status(conn, binary_id))


@router.get("/api/binaries/{binary_id}/attack-surface")
def get_binary_attack_surface(binary_id: int) -> Response:
    """The attack surface of one binary, composed from its stored scans.

    A stored-only read over the ``protocols``, ``behavior``, ``capabilities``,
    ``threat`` and ``crypto`` scans: the network-reachable entries, the local
    input handlers and the crypto usage, each with the evidence that named it
    and the scan it came from.  ``sources`` names every input with the command
    that fills it in.  404 `no-scan` when no source scan is stored.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            payload = attack_surface.attack_surface(conn, binary_id)
        except KeyError as exc:
            return json_error(404, error="binary not found", detail=str(exc))
    if not payload["available"]:
        return _no_scan(binary_id, "attack-surface", command="capabilities")
    return json_response(payload)


# ── Functions ──────────────────────────────────────────────────────


@router.get("/api/functions/callees-callers")
def get_functions_callees_callers(request: Request) -> Response:
    """The derived callers and callees of many functions in one read.

    The query is ``?ids=1,2,3`` (at most :data:`function_extras.MAX_FUNCTIONS_PER_QUERY`).
    A callee is a name the function's stored decompilation mentions that the
    binary also stores as a function or an import stub, plus every
    analyst-declared edge; a caller is a function whose text mentions this one.
    It is a text derivation over stored rows and the payload says so.
    """
    ids = _batch_ids(request)
    if ids is None:
        return _batch_error()
    with contextlib.closing(_open()) as conn:
        rows = function_extras.callers_and_callees(conn, ids, visible_to=_caller(request))
    return json_response(rows)


@router.get("/api/functions/matches")
def get_functions_matches(request: Request) -> Response:
    """The recorded match rows of many functions in one read.

    ``?ids=1,2,3``.  This reads what a previous match run stored; it runs no
    scoring and no engine, which the payload's note states.
    """
    ids = _batch_ids(request)
    if ids is None:
        return _batch_error()
    with contextlib.closing(_open()) as conn:
        rows = function_extras.match_rows(conn, ids, visible_to=_caller(request))
    return json_response(rows)


@router.post("/api/functions/matches")
def post_functions_matches(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """The same read as the GET, with the ids in the body: ``{"function_ids": [...]}``."""
    ids = _body_ids(body)
    if ids is None:
        return _batch_error()
    with contextlib.closing(_open()) as conn:
        rows = function_extras.match_rows(conn, ids, visible_to=_caller(request))
    return json_response(rows)


@router.post("/api/functions/canonical-names")
def canonicalize_function_names(
    request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Rename many functions to the canonical name the store already recorded.

    The body is ``{"function_ids": [...], "apply": bool}``; ``apply`` defaults to
    true and a false one is the dry run that only plans.  The candidate is a
    predicted name, else the newest recorded rename, and a function with neither
    is skipped rather than renamed to a guess; each rename is journaled, so one
    revert puts every name back.
    """
    ids = _body_ids(body)
    if ids is None:
        return _batch_error()
    apply_renames = body.get("apply")
    if apply_renames is not None and not isinstance(apply_renames, bool):
        return json_error(400, error="invalid apply", detail="apply must be a boolean")
    with contextlib.closing(_open()) as conn:
        plan = function_extras.canonical_names(conn, ids, visible_to=_caller(request))
        if apply_renames is False:
            return json_response({**plan, "applied": [], "applied_count": 0, "dry_run": True})
        allowed = _visible_binary_ids(conn, _caller(request))
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            applied: list[dict[str, Any]] = []
            for entry in plan["planned"]:
                if not entry["changed"]:
                    continue
                if allowed is not None:
                    owner = store.get_function(conn, int(entry["function_id"]))
                    if owner is None or int(owner["binary_id"]) not in allowed:
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
    return json_response(
        log.attach(
            {
                **plan,
                "applied": applied,
                "applied_count": len(applied),
                "count": len(applied) + len(plan["skipped"]),
                "dry_run": False,
            }
        )
    )


@router.get("/api/functions/signatures")
def get_function_signatures(request: Request) -> Response:
    """Signatures for many functions in one read, in the order the ids were given.

    The query is ``?ids=1,2,3`` (bounded by :data:`_BATCH_ID_LIMIT`).  A
    function with no signature yet reports ``null`` and one the store does not
    know reports ``found: false``, so a caller can tell the two apart; nothing
    is computed and no engine runs.
    """
    ids = _id_list(request, "ids")
    if ids is None:
        return json_error(
            400,
            error="invalid ids",
            detail=f"ids must be a comma-separated list of at most {_BATCH_ID_LIMIT} integers",
        )
    if not ids:
        return json_error(400, error="invalid ids", detail="ids must name at least one function")
    with contextlib.closing(_open()) as conn:
        rows = signatures.signatures_for(conn, ids, visible_to=_caller(request))
        seen = [row for row in rows if row["found"]]
    return json_response({"signatures": rows, "count": len(rows), "found": len(seen)})


@router.get("/api/functions/{function_id}")
def get_function(function_id: int) -> Response:
    with contextlib.closing(_open()) as conn:
        function = store.get_function(conn, function_id)
    if function is None:
        return json_error(
            404, error="function not found", detail=f"no function with id {function_id}"
        )
    return json_response(function)


@router.post("/api/functions/{function_id}/rename")
def rename_function(function_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    new_name = _require_str(body, "name")
    actor = _optional_str(body, "actor", "api")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                change = journal.journaled_rename(
                    conn, log, function_id, new_name=new_name, actor=actor, source="manual"
                )
            except KeyError:
                return json_error(
                    404, error="function not found", detail=f"no function with id {function_id}"
                )
            except ValueError as exc:
                return json_error(400, error="invalid name", detail=str(exc))
    return json_response(log.attach(change))


@router.get("/api/functions/{function_id}/history")
def function_history(function_id: int) -> Response:
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        history = store.list_name_history(conn, function_id)
    return json_response({"history": history})


@router.post("/api/functions/{function_id}/history/{history_id}/revert")
def revert_function_name(function_id: int, history_id: int) -> Response:
    """Restore the pre-rename name recorded by one history row of a function."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        entry = store.get_name_history(conn, history_id)
        if entry is None or int(entry["function_id"]) != function_id:
            return json_error(
                404,
                error="history not found",
                detail=f"no history {history_id} for function {function_id}",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                journal.journaled_revert_name(conn, log, function_id, history_id)
            except ValueError as exc:
                return json_error(400, error="invalid name", detail=str(exc))
    return json_response(
        log.attach(
            {"function_id": function_id, "history_id": history_id, "name": str(entry["old_name"])}
        )
    )


@router.get("/api/functions/{function_id}/matches")
def function_matches(function_id: int) -> Response:
    """The recorded match candidates of one function, with the derived metrics.

    Each row carries ``difference`` (the complement ``100 - similarity``) and
    the quality ``band`` beside the stored similarity and confidence.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        matches = store.list_matches(conn, function_id)
    return json_response({"matches": [_match_view(row) for row in matches]})


@router.post("/api/functions/{function_id}/apply-match")
def apply_match(function_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Apply one recorded match to a function: its name, signature, or both.

    ``mode`` defaults to ``name``, the behaviour from before the modes
    existed.  A ``signature`` transfer copies the candidate's return type,
    calling convention and parameters; the types those parameters name are
    resolved by the existing type model, and a referenced local type the
    target's binary has no row for is reported in ``missing_types`` rather
    than dropped.  A ``both`` transfer journals both writes, so one revert
    puts both back.

    Collision policy: a signature transfer refuses with 409
    ``signature-conflict`` when the target already carries a different
    non-empty calling convention, so an ABI-level mismatch is never
    overwritten silently.
    """
    candidate_id = _require_int(body, "candidate_function_id")
    mode = _optional_str(body, "mode", matching.DEFAULT_TRANSFER_MODE)
    actor = _optional_str(body, "actor", "api")
    with contextlib.closing(_open()) as conn:
        try:
            plan = matching.plan_transfer(
                conn,
                function_id=function_id,
                candidate_function_id=candidate_id,
                mode=mode,
            )
        except matching.InvalidSettingsError as exc:
            return json_error(400, error=exc.error, detail=exc.detail)
        if plan.status == matching.TRANSFER_STATUS_FAILED:
            status, error = matching.TRANSFER_FAILURE_RESPONSE.get(
                plan.reason, (400, "invalid transfer")
            )
            return json_error(status, error=error, detail=plan.detail)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            if plan.status == matching.TRANSFER_STATUS_APPLIED:
                matching.apply_transfer(conn, log, plan, actor=actor)
    return json_response(log.attach(matching.plan_payload(plan)))


@router.get("/api/functions/{function_id}/disasm")
def function_disasm(request: Request, function_id: int) -> Response:
    """NASM or hex listing of one function through its rebrew project context."""
    fmt = _query_text(request, "format") or "nasm"
    with contextlib.closing(_open()) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        binary_id = int(function["binary_id"])
        project_dir = store.get_rebrew_context(conn, binary_id)
        if project_dir is None:
            return json_error(
                400,
                error="no-engine-context",
                detail=f"binary {binary_id} has no rebrew project context",
            )
        if fmt not in engines.DISASM_FORMATS:
            return json_error(
                400, error="invalid format", detail=f"unsupported disassembly format: {fmt}"
            )
        va = int(function["va"])
        size = int(function["size"])
        if fmt == CACHEABLE_DISASM_FORMAT:
            cached = store.get_disasm(conn, function_id)
            if cached is not None:
                return json_response({"va": va, "size": size, "format": fmt, "disasm": cached})
        try:
            disasm = _engine().disassemble(project_dir, va, size, fmt)
        except engines.EngineError as exc:
            return json_error(500, error="engine-error", detail=str(exc))
        if fmt == CACHEABLE_DISASM_FORMAT:
            store.set_disasm(conn, function_id, disasm, extent_size=size, project_dir=project_dir)
    return json_response({"va": va, "size": size, "format": fmt, "disasm": disasm})


# ── Control-flow graph ─────────────────────────────────────────────


# Why the payload carries no blocks and no engine note.  The engine states its
# own reason whenever it segments nothing, so this is a fallback for a payload
# that somehow carries an empty block list and no note: the panel must never
# render an empty diagram with no explanation.
_CFG_EMPTY_NOTE = "the engine segmented no basic blocks for this function"


def _cfg_address(value: Any) -> int | None:
    """Parse one address the CFG payload carries, or None when it is unusable.

    ``rebrew asm --format cfg`` reports every address as a ``0x...`` string;
    the route converts them to ints so the SPA never parses hex.  A bool, a
    malformed string and a missing field all answer None, and the caller drops
    the row rather than inventing an address.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


def _cfg_count(value: Any) -> int:
    """A block count the CFG payload carries, or zero when it is unusable."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _cfg_block_rows(raw: Any) -> list[dict[str, Any]]:
    """Normalize the payload's blocks, dropping an entry with no address."""
    rows: list[dict[str, Any]] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, Mapping):
            continue
        address = _cfg_address(entry.get("va"))
        if address is None:
            continue
        rows.append(
            {
                "va": address,
                "size": _cfg_count(entry.get("size")),
                "instruction_count": _cfg_count(entry.get("instruction_count")),
                "first": str(entry.get("first") or ""),
                "last": str(entry.get("last") or ""),
            }
        )
    return rows


def _cfg_edge_rows(raw: Any) -> list[dict[str, Any]]:
    """Normalize the payload's edges, dropping one with an unusable endpoint."""
    rows: list[dict[str, Any]] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, Mapping):
            continue
        source = _cfg_address(entry.get("from"))
        target = _cfg_address(entry.get("to"))
        if source is None or target is None:
            continue
        rows.append({"from": source, "to": target, "back_edge": bool(entry.get("back_edge"))})
    return rows


@router.get("/api/functions/{function_id}/cfg")
def function_cfg(function_id: int) -> Response:
    """Basic-block control-flow graph of one function through its rebrew project.

    The graph is derived from the target binary on every request (there is no
    stored CFG): ``rebrew asm <hex-va> --size N --format cfg --json`` runs in
    the binary's stored rebrew project and the route converts the engine's hex
    addresses to ints.  ``block_count`` is what the payload returns,
    ``block_total`` the engine's true count and ``block_cap`` the engine's
    per-function cap, so a truncated graph states what it dropped; ``note``
    carries the engine's reason when it resolved no extent, and an empty
    payload always carries one.
    """
    with contextlib.closing(_open()) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        project_dir = _project_context(conn, int(function["binary_id"]))
        va = int(function["va"])
        try:
            payload = _engine().control_flow_graph(project_dir, va, int(function["size"]))
        except engines.EngineError as exc:
            return json_error(500, error="engine-error", detail=str(exc))
    blocks = _cfg_block_rows(payload.get("blocks"))
    edges = _cfg_edge_rows(payload.get("edges"))
    raw_note = payload.get("note")
    note = raw_note if isinstance(raw_note, str) and raw_note.strip() else None
    if not blocks and note is None:
        note = _CFG_EMPTY_NOTE
    engine_va = _cfg_address(payload.get("va"))
    return json_response(
        {
            "function_id": function_id,
            "va": engine_va if engine_va is not None else va,
            "size": _cfg_count(payload.get("size")),
            "blocks": blocks,
            "edges": edges,
            "block_count": len(blocks),
            "block_total": _cfg_count(payload.get("block_total")),
            "block_cap": _cfg_count(payload.get("block_cap")),
            "truncated": bool(payload.get("truncated")),
            "note": note,
        }
    )


# ── Decompilation ──────────────────────────────────────────────────


def _decompilation_context(conn: sqlite3.Connection, function: dict[str, Any]) -> tuple[int, str]:
    """Return the (*va*, rebrew project directory) a decompile call needs.

    Raises a 400 when the function's binary has no rebrew project context,
    since ``rebrew decompile`` resolves its target from that directory.
    """
    va = int(function["va"])
    binary_id = int(function["binary_id"])
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise json_error(
            400,
            error="no-engine-context",
            detail=f"binary {binary_id} has no rebrew project context",
        )
    return va, project_dir


def _run_decompiler(project_dir: str, va: int, backend: str, named: bool) -> dict[str, Any]:
    """Decompile through the engine, mapping an engine failure to a 500.

    :class:`~reportal.engines.EngineError` carries the bounded engine message;
    the response keeps the error name fixed and the text in ``detail``.
    """
    try:
        return _engine().decompile(project_dir, va, backend, named)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


@router.get("/api/functions/{function_id}/decompilation")
def function_decompilation(request: Request, function_id: int) -> Response:
    """Stored decompilation when one exists, else a live compute that is not stored."""
    backend = _query_text(request, "backend") or engines.DEFAULT_DECOMPILER_BACKEND
    named = _query_bool(request, "named", False)
    with contextlib.closing(_open()) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        if backend not in engines.DECOMPILER_BACKENDS:
            return json_error(
                400,
                error="invalid backend",
                detail=f"unsupported decompiler backend: {backend}",
            )
        stored = store.get_decompilation(conn, function_id)
        if stored is not None:
            return json_response(
                {
                    "va": int(function["va"]),
                    "backend": str(stored["backend"]),
                    "named": named,
                    "code": str(stored["code"]),
                }
            )
        va, project_dir = _decompilation_context(conn, function)
        result = _run_decompiler(project_dir, va, backend, named)
    return json_response(
        {
            "va": va,
            "backend": str(result.get("backend") or backend),
            "named": named,
            "code": str(result.get("code") or ""),
        }
    )


@router.post("/api/functions/{function_id}/decompilation")
def store_function_decompilation(
    function_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Compute a function's decompiled source through the engine and store it."""
    backend = _optional_str(body, "backend", engines.DEFAULT_DECOMPILER_BACKEND)
    named = _optional_bool(body, "named", False)
    with contextlib.closing(_open()) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        if backend not in engines.DECOMPILER_BACKENDS:
            return json_error(
                400,
                error="invalid backend",
                detail=f"unsupported decompiler backend: {backend}",
            )
        va, project_dir = _decompilation_context(conn, function)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.journaled_rows(
                conn,
                log,
                table="decompilations",
                where="function_id = ?",
                params=(function_id,),
                description=f"replaced the decompilation of function {function_id}",
            )
            result = _run_decompiler(project_dir, va, backend, named)
            code = str(result.get("code") or "")
            resolved = str(result.get("backend") or backend)
            store.set_decompilation(conn, function_id, code, resolved)
            if not before:
                journal.journaled_create(
                    log,
                    table="decompilations",
                    key={"function_id": function_id},
                    description=f"stored the decompilation of function {function_id}",
                )
    return json_response(log.attach({"va": va, "backend": resolved, "named": named, "code": code}))


# ── Diff view ──────────────────────────────────────────────────────


@router.get("/api/functions/{function_id}/diff")
@router.get("/api/functions/{function_id}/diff/{candidate_id}")
def function_diff(request: Request, function_id: int, candidate_id: int | None = None) -> Response:
    """Side-by-side alignment of a function against a recorded match candidate.

    Without a candidate the function's best recorded match is used (404
    ``no-match`` when it has none); with one, the pair must be a recorded match
    for the source function (400 ``no-such-match``), mirroring apply-match.
    """
    kind = _query_text(request, "kind") or diffview.DEFAULT_KIND
    normalize = _query_bool(request, "normalize", diffview.DEFAULT_NORMALIZE)
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        if candidate_id is not None:
            if store.get_function(conn, candidate_id) is None:
                return json_error(
                    404, error="candidate not found", detail=f"no function with id {candidate_id}"
                )
            if not store.has_match(conn, function_id, candidate_id):
                return json_error(
                    400,
                    error="no-such-match",
                    detail=f"no recorded match for {function_id} -> {candidate_id}",
                )
        try:
            payload = diffview.function_diff(
                conn,
                engines.get_engine(),
                function_id=function_id,
                candidate_id=candidate_id,
                kind=kind,
                normalize=normalize,
            )
        except diffview.DiffError as exc:
            return json_error(exc.status, error=exc.code, detail=exc.detail)
    return json_response(payload)


# ── Cross-references ───────────────────────────────────────────────


def _run_xrefs(project_dir: str, va: int, kinds: Sequence[str]) -> dict[str, Any]:
    """Run the engine's cross-reference lookup, mapping a failure to a 500."""
    try:
        return _engine().xrefs(project_dir, va, kinds)
    except engines.EngineError as exc:
        raise json_error(500, error="engine-error", detail=str(exc)) from exc


@router.get("/api/functions/{function_id}/xrefs")
def function_xrefs(request: Request, function_id: int) -> Response:
    """Live cross-references to a function through its rebrew project context.

    A repeated ``?kind=`` keeps only those reference kinds.
    """
    kinds = [kind for kind in request.query_params.getlist("kind") if kind.strip()]
    with contextlib.closing(_open()) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        project_dir = _project_context(conn, int(function["binary_id"]))
        result = _run_xrefs(project_dir, int(function["va"]), kinds)
    return json_response(result)


# ── Function references: globals, callers and callees ──────────────


# Callee kinds the engine reports for a call through an import slot: an
# indirect call whose target is the slot, not a function address.
_INDIRECT_CALL_KINDS = frozenset({"iat_call", "iat_jmp"})

_COUNT_NOTE = (
    "callers counts distinct call sites (from addresses); callees counts distinct"
    " (target, kind) pairs, so one target reached both directly and through its"
    " import slot appears twice"
)


def _stored_section_table(
    conn: sqlite3.Connection, binary_id: int
) -> tuple[list[Mapping[str, Any]], int]:
    """The binary's stored pe-info sections and image base, else empty and zero."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return [], 0
    stored = store.get_scan(conn, analysis_id, store.SCAN_KIND_PE_INFO)
    if not isinstance(stored, Mapping):
        return [], 0
    sections = stored.get("sections")
    rows = (
        [row for row in sections if isinstance(row, Mapping)] if isinstance(sections, list) else []
    )
    return rows, int(stored.get("image_base") or 0)


def _section_name_for(
    sections: Sequence[Mapping[str, Any]], image_base: int, address: int
) -> str | None:
    """The name of the section covering *address*, or None when none does."""
    for section in sections:
        start = image_base + int(section.get("virtual_address") or 0)
        size = int(section.get("virtual_size") or 0)
        if size > 0 and start <= address < start + size:
            return str(section.get("name") or "") or None
    return None


def _global_rows(
    raw: Any, sections: Sequence[Mapping[str, Any]], image_base: int
) -> list[dict[str, Any]]:
    """Normalize the dossier's globals into addressed access rows."""
    rows: list[dict[str, Any]] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, Mapping):
            continue
        address = entry.get("va")
        if isinstance(address, bool) or not isinstance(address, int):
            continue
        kind = str(entry.get("kind") or "")
        rows.append(
            {
                "address": address,
                "kind": kind,
                "access": GLOBAL_ACCESS.get(kind),
                "section": _section_name_for(sections, image_base, address),
            }
        )
    return rows


def _caller_rows(raw: Any) -> list[dict[str, Any]]:
    """Normalize the dossier's callers into one row per call site."""
    rows: list[dict[str, Any]] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, Mapping):
            continue
        address = entry.get("from_va")
        if isinstance(address, bool) or not isinstance(address, int):
            continue
        rows.append({"from_va": address, "name": str(entry.get("name") or "") or None})
    return rows


def _callee_rows(raw: Any) -> list[dict[str, Any]]:
    """Normalize the dossier's callees, marking an import-slot call indirect."""
    rows: list[dict[str, Any]] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, Mapping):
            continue
        address = entry.get("to_va")
        if isinstance(address, bool) or not isinstance(address, int):
            continue
        kind = str(entry.get("kind") or "")
        rows.append(
            {
                "to_va": address,
                "name": str(entry.get("name") or "") or None,
                "kind": kind,
                "indirect": kind in _INDIRECT_CALL_KINDS,
            }
        )
    return rows


@router.get("/api/functions/{function_id}/references")
def function_references(function_id: int) -> Response:
    """One function's globals, callers and callees from the engine's dossier.

    ``rebrew describe`` reports the data addresses the function touches, the
    call sites into it and the calls it makes.  A global carries the section
    that owns its address when the stored pe-info scan knows one and a read or
    a write when the instruction makes that clear; an address or an access the
    engine did not resolve stays null.  ``counts`` reports the row counts, and
    ``count_note`` states what each count means.
    """
    with contextlib.closing(_open()) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        binary_id = int(function["binary_id"])
        project_dir = _project_context(conn, binary_id)
        sections, image_base = _stored_section_table(conn, binary_id)
        try:
            dossier = _engine().describe(project_dir, int(function["va"]))
        except engines.EngineError as exc:
            return json_error(500, error="engine-error", detail=str(exc))
    globals_rows = _global_rows(dossier.get("globals"), sections, image_base)
    callers = _caller_rows(dossier.get("callers"))
    callees = _callee_rows(dossier.get("callees"))
    return json_response(
        {
            "function_id": function_id,
            "va": int(function["va"]),
            "globals": globals_rows,
            "callers": callers,
            "callees": callees,
            "counts": {
                "globals": len(globals_rows),
                "callers": len(callers),
                "callees": len(callees),
            },
            "count_note": _COUNT_NOTE,
        }
    )


# ── AI artifacts ───────────────────────────────────────────────────


def _ai_client() -> llm.LlmClient:
    """Return the process LLM client, or raise a 503 response when none is configured."""
    client = llm.get_client()
    if not client.available():
        raise json_error(503, error="llm-unavailable", detail=llm.UNAVAILABLE_DETAIL)
    return client


def _no_ai_decompilation(function_id: int) -> Response:
    """Return the 404 for a function with no stored decompilation to feed the model."""
    return json_error(
        404,
        error="no-decompilation",
        detail=(
            f"function {function_id} has no stored decompilation; "
            f"run POST /api/functions/{function_id}/decompilation or "
            f"'reportal decompile {function_id}' first"
        ),
    )


def _no_ai_artifact(function_id: int, kind: str) -> Response:
    """Return the stored-only 404 for a function with no artifact of *kind*."""
    command = llm.AI_CLI_COMMANDS.get(kind, kind)
    return json_error(
        404,
        error="no-artifact",
        detail=(
            f"no {kind} artifact for function {function_id}; "
            f"run POST /api/functions/{function_id}/{kind} or "
            f"'reportal {command} {function_id}'"
        ),
    )


def _store_ai_artifact(function_id: int, kind: str) -> Response:
    """Compute one AI artifact through the configured LLM and store it.

    A stored decompilation is required and is never generated here: the route
    reads the model's input from the ``decompilations`` table only.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        client = _ai_client()
        stored = store.get_decompilation(conn, function_id)
        if stored is None:
            return _no_ai_decompilation(function_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = llm.AI_RUNNERS[kind](str(stored["code"]), client=client)
            except llm.LlmUnavailable:
                return json_error(503, error="llm-unavailable", detail=llm.UNAVAILABLE_DETAIL)
            except llm.LlmError as exc:
                return json_error(502, error="llm-error", detail=str(exc))
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
    return json_response(
        log.attach(
            {"function_id": function_id, "kind": kind, "payload": payload, "model": client.model}
        )
    )


def _clear_ai_artifact(function_id: int, kind: str, *, missing: Response) -> Response:
    """Discard one stored AI artifact inside a journaled action.

    The row is snapshotted before it is dropped and its restore descriptor
    recorded, so the action's revert puts the artifact back (rating, overrides
    and line comments included: they live inside the payload).  *missing* is the
    stored-only 404 the caller's kind answers with when there is nothing to
    discard.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn,
                table="ai_artifacts",
                where="function_id = ? AND kind = ?",
                params=(function_id, kind),
            )
            if not before:
                return missing
            store.clear_ai_artifact(conn, function_id, kind)
            log.record(
                effects.EFFECT_ROW_RESTORE,
                f"discarded the {kind} artifact of function {function_id}",
                journal.row_restore_descriptor("ai_artifacts", before),
            )
    return json_response(log.attach({"function_id": function_id, "kind": kind, "discarded": True}))


def _get_ai_artifact(function_id: int, kind: str) -> Response:
    """Serve one stored AI artifact; never calls the LLM."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        artifact = store.get_ai_artifact(conn, function_id, kind)
    if artifact is None:
        return _no_ai_artifact(function_id, kind)
    return json_response({"function_id": function_id, "kind": kind, **artifact})


@router.post("/api/functions/{function_id}/summary")
def store_function_summary(function_id: int) -> bytes | Any:
    """Summarize a function's stored decompilation with the configured LLM."""
    return _store_ai_artifact(function_id, llm.AI_KIND_SUMMARY)


@router.delete("/api/functions/{function_id}/summary")
def discard_function_summary(function_id: int) -> bytes | Any:
    """Discard the stored artifact of this kind; journaled, so a revert restores it."""
    return _clear_ai_artifact(
        function_id, llm.AI_KIND_SUMMARY, missing=_no_ai_artifact(function_id, llm.AI_KIND_SUMMARY)
    )


@router.get("/api/functions/{function_id}/summary")
def get_function_summary(function_id: int) -> bytes | Any:
    """Stored AI summary; a function without one is a 404 no-artifact."""
    return _get_ai_artifact(function_id, llm.AI_KIND_SUMMARY)


@router.post("/api/functions/{function_id}/ai-comments")
def store_function_ai_comments(function_id: int) -> bytes | Any:
    """Ask the configured LLM for inline comments on a stored decompilation."""
    return _store_ai_artifact(function_id, llm.AI_KIND_COMMENTS)


@router.delete("/api/functions/{function_id}/ai-comments")
def discard_function_ai_comments(function_id: int) -> bytes | Any:
    """Discard the stored artifact of this kind; journaled, so a revert restores it."""
    return _clear_ai_artifact(
        function_id,
        llm.AI_KIND_COMMENTS,
        missing=_no_ai_artifact(function_id, llm.AI_KIND_COMMENTS),
    )


@router.get("/api/functions/{function_id}/ai-comments")
def get_function_ai_comments(function_id: int) -> bytes | Any:
    """Stored AI comments; a function without any is a 404 no-artifact."""
    return _get_ai_artifact(function_id, llm.AI_KIND_COMMENTS)


@router.post("/api/functions/{function_id}/type-suggestions")
def store_function_type_suggestions(function_id: int) -> bytes | Any:
    """Ask the configured LLM for type suggestions on a stored decompilation."""
    return _store_ai_artifact(function_id, llm.AI_KIND_TYPES)


@router.delete("/api/functions/{function_id}/type-suggestions")
def discard_function_type_suggestions(function_id: int) -> bytes | Any:
    """Discard the stored artifact of this kind; journaled, so a revert restores it."""
    return _clear_ai_artifact(
        function_id, llm.AI_KIND_TYPES, missing=_no_ai_artifact(function_id, llm.AI_KIND_TYPES)
    )


@router.get("/api/functions/{function_id}/type-suggestions")
def get_function_type_suggestions(function_id: int) -> bytes | Any:
    """Stored type suggestions; a function without any is a 404 no-artifact."""
    return _get_ai_artifact(function_id, llm.AI_KIND_TYPES)


# ── AI identifier renames ──────────────────────────────────────────


def _no_renames_artifact(function_id: int) -> Response:
    """Return the stored-only 404 for a function with no rename suggestions."""
    return json_error(
        404,
        error="no-artifact",
        detail=(
            f"no renames artifact for function {function_id}; "
            f"run POST /api/functions/{function_id}/renames or "
            f"'reportal suggest-renames {function_id}'"
        ),
    )


@router.post("/api/functions/{function_id}/renames")
def store_function_renames(function_id: int) -> Response:
    """Suggest identifier renames for a stored decompilation and store them."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        client = _ai_client()
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
            except renames.NoDecompilationError:
                return _no_ai_decompilation(function_id)
            except llm.LlmError as exc:
                return json_error(502, error="llm-error", detail=str(exc))
            if not before:
                journal.journaled_create(
                    log,
                    table="ai_artifacts",
                    key={"function_id": function_id, "kind": renames.RENAMES_KIND},
                    description=f"stored the renames artifact of function {function_id}",
                )
    return json_response(
        log.attach(
            {
                "function_id": function_id,
                "kind": renames.RENAMES_KIND,
                "payload": {"suggestions": result["suggestions"]},
                "model": result["model"],
                "count": result["count"],
            }
        )
    )


@router.get("/api/functions/{function_id}/renames")
def get_function_renames(function_id: int) -> Response:
    """Stored rename suggestions; a function without any is a 404 no-artifact."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        artifact = store.get_ai_artifact(conn, function_id, renames.RENAMES_KIND)
    if artifact is None:
        return _no_renames_artifact(function_id)
    return json_response({"function_id": function_id, "kind": renames.RENAMES_KIND, **artifact})


def _applied_entries(body: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Return the body's ``applied`` suggestions, or None to apply every stored one."""
    raw = body.get("applied")
    if raw is None:
        return None
    if not isinstance(raw, list) or any(not isinstance(entry, dict) for entry in raw):
        raise json_error(
            400,
            error="invalid applied",
            detail="applied must be a list of suggestion objects",
        )
    return raw


@router.post("/api/functions/{function_id}/renames/apply")
def apply_function_renames(
    function_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Apply rename suggestions to the function's stored decompilation.

    The body is ``{"applied": [...], "rename_function": bool}``; both are
    optional and an omitted ``applied`` applies every stored suggestion.  A
    ``function``-kind suggestion renames the function row only when
    ``rename_function`` is true.
    """
    applied = _applied_entries(body)
    rename_function = _optional_bool(body, "rename_function", False)
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
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
                        rename_function=rename_function,
                    ),
                )
            except renames.NoDecompilationError:
                return _no_ai_decompilation(function_id)
            except renames.NoSuggestionError:
                return _no_renames_artifact(function_id)
            if result["decompilation_updated"] and not artifact_before:
                journal.journaled_create(
                    log,
                    table="ai_artifacts",
                    key={"function_id": function_id, "kind": renames.RENAMES_APPLIED_KIND},
                    description=f"journaled the applied renames of function {function_id}",
                )
    return json_response(log.attach(result))


@router.post("/api/functions/{function_id}/renames/revert")
def revert_function_renames(function_id: int) -> Response:
    """Restore the decompilation text the last apply journaled."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
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
            except renames.NoRevertError:
                return json_error(
                    404,
                    error="no-artifact",
                    detail=f"no applied renames to revert for function {function_id}",
                )
    return json_response(log.attach(result))


# ── AI decompilation artifact ──────────────────────────────────────
#
# The hosted portal's richest AI artifact: one rewritten function, the
# placeholder tokens it still carries with the analyst overrides that rename
# them, per-line attribution against the decompilation the model read, an
# analyst rating and per-line inline comments.  It is one `ai_artifacts` row of
# kind `ai-decompilation`, so every write is journaled and revertible through
# the same generic row-restore path the other four AI artifacts use.


def _no_ai_decomp_artifact(function_id: int) -> Response:
    """Return the stored-only 404 for a function with no AI decompilation."""
    return json_error(
        404,
        error="no-artifact",
        detail=(
            f"no AI decompilation for function {function_id}; "
            f"run POST /api/functions/{function_id}/ai-decompilation or "
            f"'reportal ai-decompile {function_id}' first"
        ),
    )


def _ai_decomp_error(function_id: int, exc: ai_decomp.AiDecompError) -> Response:
    """Map one artifact failure onto the response the API answers with."""
    if isinstance(exc, ai_decomp.NoAiDecompilationError):
        return _no_ai_decomp_artifact(function_id)
    if isinstance(exc, ai_decomp.UnknownTokenError):
        return json_error(404, error="unknown token", detail=str(exc))
    if isinstance(exc, ai_decomp.UnknownLineCommentError):
        return json_error(404, error="no-line-comment", detail=str(exc))
    if isinstance(exc, ai_decomp.InvalidOverrideError):
        return json_error(400, error="invalid override", detail=str(exc))
    if isinstance(exc, ai_decomp.InvalidRatingError):
        return json_error(400, error="invalid rating", detail=str(exc))
    return json_error(400, error="invalid line-comment", detail=str(exc))


def _ai_decomp_view(conn: sqlite3.Connection, function_id: int) -> Response:
    """Serve the stored artifact of one function, or its 404."""
    try:
        artifact = ai_decomp.require(conn, function_id)
    except ai_decomp.NoAiDecompilationError:
        return _no_ai_decomp_artifact(function_id)
    return json_response({"function_id": function_id, **ai_decomp.view(artifact)})


def _ai_decomp_mutation(
    function_id: int,
    mutate: Callable[[sqlite3.Connection, int], tuple[dict[str, Any], dict[str, Any]]],
    *,
    description: str,
) -> Response:
    """Run one artifact mutation in a journaled action and serve the new view.

    *mutate* returns the new payload and the extra keys the route reports; the
    shared write path snapshots and journals the row either way.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload, extra = mutate(conn, function_id)
            except ai_decomp.AiDecompError as exc:
                return _ai_decomp_error(function_id, exc)
            ai_decomp.write_artifact(conn, log, function_id, payload, description=description)
            artifact = ai_decomp.require(conn, function_id)
    return json_response(
        log.attach({"function_id": function_id, **ai_decomp.view(artifact), **extra})
    )


@router.post("/api/functions/{function_id}/ai-decompilation")
def store_ai_decompilation(function_id: int) -> Response:
    """Rewrite a function's stored decompilation with the configured LLM.

    The model's input is the stored decompilation and never a generated one, so
    a function without one is the same 404 the other AI artifacts answer.  The
    token map and the per-line attributions in the response are derived locally
    and the response says so in ``derivation``.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        client = _ai_client()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = ai_decomp.rewrite(conn, function_id, client=client)
            except renames.NoDecompilationError:
                return _no_ai_decompilation(function_id)
            except llm.LlmUnavailable:
                return json_error(503, error="llm-unavailable", detail=llm.UNAVAILABLE_DETAIL)
            except llm.LlmError as exc:
                return json_error(502, error="llm-error", detail=str(exc))
            ai_decomp.write_artifact(
                conn,
                log,
                function_id,
                payload,
                description=f"replaced the AI decompilation of function {function_id}",
            )
            artifact = ai_decomp.require(conn, function_id)
    return json_response(log.attach({"function_id": function_id, **ai_decomp.view(artifact)}))


@router.get("/api/functions/{function_id}/ai-decompilation")
def get_ai_decompilation(function_id: int) -> Response:
    """The stored AI decompilation rendered with its overrides; never calls the LLM."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        return _ai_decomp_view(conn, function_id)


@router.delete("/api/functions/{function_id}/ai-decompilation")
def discard_ai_decompilation(function_id: int) -> bytes | Any:
    """Discard the stored AI decompilation; journaled, so a revert restores it."""
    return _clear_ai_artifact(
        function_id, ai_decomp.KIND, missing=_no_ai_decomp_artifact(function_id)
    )


@router.get("/api/functions/{function_id}/ai-decompilation/status")
def get_ai_decompilation_status(function_id: int) -> Response:
    """The artifact's workflow state: counts, rating and model, without its text."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        try:
            artifact = ai_decomp.require(conn, function_id)
        except ai_decomp.NoAiDecompilationError:
            return _no_ai_decomp_artifact(function_id)
    return json_response({"function_id": function_id, **ai_decomp.status(artifact)})


@router.get("/api/functions/{function_id}/ai-decompilation/events")
def get_ai_decompilation_events(function_id: int) -> Response:
    """The artifact's workflow as server-sent events.

    The workflow is one model call and is already over by the time a client can
    attach, so the stream reports the current state and its terminal marker
    rather than narrating a call that has returned.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        try:
            artifact = ai_decomp.require(conn, function_id)
        except ai_decomp.NoAiDecompilationError:
            return _no_ai_decomp_artifact(function_id)
        frames = ai_decomp.events(artifact)

    def stream() -> Any:
        yield from frames

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.get("/api/functions/{function_id}/ai-decompilation/tokens")
def get_ai_decompilation_tokens(function_id: int) -> Response:
    """The placeholder tokens of the rewrite with the name each one now carries."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        try:
            artifact = ai_decomp.require(conn, function_id)
        except ai_decomp.NoAiDecompilationError:
            return _no_ai_decomp_artifact(function_id)
    served = ai_decomp.view(artifact)
    return json_response(
        {
            "function_id": function_id,
            "tokens": served["tokens"],
            "count": len(served["tokens"]),
            "overridden_count": sum(1 for entry in served["tokens"] if entry["name"]),
            "derivation": ai_decomp.DERIVATION,
        }
    )


@router.patch("/api/functions/{function_id}/ai-decompilation/overrides")
def set_ai_decompilation_overrides(
    function_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Set or clear analyst overrides for the artifact's placeholder tokens.

    The body is ``{"overrides": {"<token>": "<name>"}}``; a null or empty name
    clears that token's override.  The model's rewrite is never rewritten in
    place, so a cleared override restores its own words.
    """
    raw = body.get("overrides")
    return _ai_decomp_mutation(
        function_id,
        lambda conn, fid: ai_decomp.set_overrides(conn, fid, raw),
        description=(
            f"replaced the token overrides of the AI decompilation of function {function_id}"
        ),
    )


@router.get("/api/functions/{function_id}/ai-decompilation/rating")
def get_ai_decompilation_rating(function_id: int) -> Response:
    """The analyst rating stored on the artifact, with its note."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        try:
            artifact = ai_decomp.require(conn, function_id)
        except ai_decomp.NoAiDecompilationError:
            return _no_ai_decomp_artifact(function_id)
        payload = artifact["payload"]
    return json_response(
        {
            "function_id": function_id,
            "rating": payload.get("rating"),
            "note": payload.get("rating_note", ""),
        }
    )


@router.patch("/api/functions/{function_id}/ai-decompilation/rating")
def set_ai_decompilation_rating(
    function_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Record analyst feedback on the rewrite: ``{"rating": "up"|"down"|null, "note": str}``."""
    note = body.get("note")
    return _ai_decomp_mutation(
        function_id,
        lambda conn, fid: (
            ai_decomp.rate(conn, fid, rating=body.get("rating"), note=note),
            {},
        ),
        description=f"rated the AI decompilation of function {function_id}",
    )


@router.get("/api/functions/{function_id}/ai-decompilation/inline-comments")
def list_ai_decompilation_comments(function_id: int) -> Response:
    """The per-line inline comments stored beside the artifact, ordered by line."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        try:
            artifact = ai_decomp.require(conn, function_id)
        except ai_decomp.NoAiDecompilationError:
            return _no_ai_decomp_artifact(function_id)
        rows = artifact["payload"].get("line_comments", [])
    return json_response({"function_id": function_id, "comments": rows, "count": len(rows)})


def _comment_fields(body: dict[str, Any]) -> tuple[Any, Any]:
    """Return the ``line`` and ``body`` a comment route reads from its request."""
    return body.get("line"), body.get("body")


def _with_comment(
    result: tuple[dict[str, Any], dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Report the line comment a mutation touched beside the artifact view."""
    payload, entry = result
    return payload, {"comment": entry}


@router.post("/api/functions/{function_id}/ai-decompilation/inline-comments")
def add_ai_decompilation_comment(
    function_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Store one inline comment at a line, replacing any comment already there."""
    line, text = _comment_fields(body)
    author = body.get("author")
    return _ai_decomp_mutation(
        function_id,
        lambda conn, fid: _with_comment(
            ai_decomp.add_line_comment(conn, fid, line=line, body=text, author=author)
        ),
        description=f"stored an inline comment on the AI decompilation of function {function_id}",
    )


@router.patch("/api/functions/{function_id}/ai-decompilation/inline-comments/{line}")
def update_ai_decompilation_comment(
    function_id: int, line: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Replace the body of the inline comment stored at *line*."""
    text = body.get("body")
    return _ai_decomp_mutation(
        function_id,
        lambda conn, fid: _with_comment(
            ai_decomp.update_line_comment(conn, fid, line=line, body=text)
        ),
        description=f"edited an inline comment on the AI decompilation of function {function_id}",
    )


@router.delete("/api/functions/{function_id}/ai-decompilation/inline-comments/{line}")
def delete_ai_decompilation_comment(function_id: int, line: int) -> Response:
    """Remove the inline comment stored at *line*."""
    return _ai_decomp_mutation(
        function_id,
        lambda conn, fid: _with_comment(ai_decomp.delete_line_comment(conn, fid, line=line)),
        description=f"removed an inline comment on the AI decompilation of function {function_id}",
    )


# ── AI decompilation pipeline ──────────────────────────────────────


def _disabled_components(body: dict[str, Any]) -> frozenset[str] | None:
    """Return the body's ``disabled`` component names, or None when it names none.

    None leaves the workspace ``[pipeline] disabled`` list in charge; an empty
    list overrides it with "nothing disabled".
    """
    raw = body.get("disabled")
    if raw is None:
        return None
    if not isinstance(raw, list) or any(not isinstance(entry, str) for entry in raw):
        raise json_error(
            400,
            error="invalid disabled",
            detail="disabled must be a list of component names",
        )
    return frozenset(entry.strip() for entry in raw if entry.strip())


def _no_pipeline_run(function_id: int) -> Response:
    """Return the stored-only 404 for a function no pipeline run covered."""
    return json_error(
        404,
        error="no-run",
        detail=(
            f"no pipeline run for function {function_id}; "
            f"run POST /api/functions/{function_id}/pipeline or "
            f"'reportal pipeline {function_id}'"
        ),
    )


@router.post("/api/functions/{function_id}/pipeline")
def run_function_pipeline(
    function_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Run the AI decompilation composition over one function and store the run.

    A component that cannot run is a skipped or failed step on the run, never a
    failed request: only a function that does not exist (404) or a composition
    that cannot be assembled at all (503) answers without a run.
    """
    disabled = _disabled_components(body)
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        try:
            run = pipeline.run_pipeline(conn, function_id=function_id, disabled=disabled)
        except pipeline.PipelineUnavailable as exc:
            return json_error(503, error="pipeline-unavailable", detail=str(exc))
    return json_response(run)


@router.get("/api/functions/{function_id}/pipeline")
def get_function_pipeline(function_id: int) -> Response:
    """Latest stored AI decompilation run of a function; 404 no-run without one."""
    with contextlib.closing(_open()) as conn:
        if store.get_function(conn, function_id) is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        run = pipeline.latest_run(conn, function_id)
    if run is None:
        return _no_pipeline_run(function_id)
    return json_response(run)


@router.get("/api/pipeline/runs/{run_id}")
def get_pipeline_run(run_id: int) -> Response:
    """One stored pipeline run with its steps and the function's artifacts."""
    with contextlib.closing(_open()) as conn:
        run = store.get_pipeline_run(conn, run_id)
        if run is None:
            return json_error(
                404, error="run not found", detail=f"no pipeline run with id {run_id}"
            )
        return json_response(pipeline.run_payload(conn, run))


@router.post("/api/pipeline/runs/{run_id}/revert")
def revert_pipeline_run(run_id: int) -> Response:
    """Undo the writes a stored pipeline run journaled; returns what was undone."""
    with contextlib.closing(_open()) as conn:
        try:
            result = pipeline.revert_run(conn, run_id)
        except KeyError:
            return json_error(
                404, error="run not found", detail=f"no pipeline run with id {run_id}"
            )
    return json_response(result)


# ── Components ─────────────────────────────────────────────────────


def _component_row(entry: components.Registration) -> dict[str, Any]:
    """One registry entry as the listing routes report it."""
    refusal = pipeline.withdraw_refusal(entry.component)
    return {
        "name": entry.component.name,
        "requires": sorted(entry.component.requires),
        "provides": sorted(entry.component.provides),
        "origin": entry.origin,
        "reloadable": entry.reloadable,
        "withdrawable": refusal is None,
        "withdraw_reason": refusal or "",
    }


@router.get("/api/components")
def list_components() -> Response:
    """The component registry: name, coeffects, effects, origin and reloadability."""
    rows = [_component_row(entry) for entry in components.registrations()]
    return json_response({"components": rows, "count": len(rows)})


@router.get("/api/integrations")
def list_integrations() -> Response:
    """Every plugin seam and the parts each registry currently holds.

    A read of the live registries: it starts nothing, changes nothing and keeps
    no state, so it is a plain GET with no journal entry.
    """
    return json_response(integrations.inventory())


@router.post("/api/components/reload")
def reload_components(
    request: Request, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Reload one component's declaration, or every reloadable one.

    The body is ``{"name": "..."}`` or ``{"all": true}``; the registry entry is
    swapped in place, so an already composed run keeps the snapshot it started
    with.  Destructive to the process-wide registry, so only a tenant admin
    (or auth-off local operator) may reshape it.
    """
    refused = _refuse_unless_tenant_admin(request)
    if refused is not None:
        return refused
    name = ""
    try:
        if _optional_bool(body, "all", False):
            if body.get("name") is not None:
                return json_error(400, error="provide a name or all, not both")
            return json_response(components.reload_all())
        if body.get("name") is None:
            return json_error(400, error="provide a component name or all")
        name = _require_str(body, "name")
        report = components.reload_component(name)
    except KeyError:
        return json_error(404, error="component not found", detail=f"no component named {name!r}")
    except components.NotReloadableError as exc:
        return json_error(409, error="not-reloadable", detail=str(exc))
    except components.ComponentMissingError as exc:
        return json_error(500, error="component-missing", detail=str(exc))
    return json_response(report)


@router.post("/api/components/{name}/deactivate")
def deactivate_components(name: str, request: Request) -> Response:
    """Withdraw one component's contribution from the live composition.

    The component's ``revert(ctx)`` runs where it declares one and the names it
    provided are revoked.  The response carries the ``deactivated`` entries and,
    when the withdrawal recorded a durable write, the action-journal id that
    reverts it; a withdrawal whose effect is a process-local binding reports
    ``journaled: false``.  Only a tenant admin (or auth-off local operator)
    may reshape the live composition.
    """
    refused = _refuse_unless_tenant_admin(request)
    if refused is not None:
        return refused
    with contextlib.closing(_open()) as conn:
        try:
            report = pipeline.withdraw_component(conn, name)
        except KeyError:
            return json_error(
                404, error="component not found", detail=f"no component named {name!r}"
            )
        except pipeline.NotWithdrawableError as exc:
            return json_error(409, error="not-withdrawable", detail=str(exc))
    return json_response(report)


# ── Auto mode ──────────────────────────────────────────────────────


def _auto_params(body: dict[str, Any]) -> auto_mode.AutoParams:
    """Build the validated params of an auto run, or raise a 400."""
    try:
        return auto_mode.build_params(
            worker=_optional_str(body, "worker", auto_workers.WORKER_OFFLINE),
            execute=_optional_bool(body, "execute", False),
            concurrency=_optional_int(body, "concurrency", auto_mode.DEFAULT_CONCURRENCY),
            functions_per_task=_optional_int(
                body, "functions_per_task", auto_mode.DEFAULT_FUNCTIONS_PER_TASK
            ),
            max_attempts=_optional_int(body, "max_attempts", auto_mode.DEFAULT_MAX_ATTEMPTS),
            max_tasks=_optional_int(body, "max_tasks", auto_mode.DEFAULT_MAX_TASKS),
        )
    except ValueError as exc:
        raise json_error(400, error="invalid params", detail=str(exc)) from exc


def _no_auto_run(binary_id: int) -> Response:
    """Return the stored-only 404 for a binary no auto run covered."""
    return json_error(
        404,
        error="no-run",
        detail=(
            f"no auto run for binary {binary_id}; "
            f"run POST /api/binaries/{binary_id}/auto or `reportal auto {binary_id}`"
        ),
    )


# Concurrent background auto runs started by the HTTP route.  Each POST
# otherwise starts an unbounded daemon thread; the semaphore is released when
# that thread finishes, so a hung run holds its slot and further starts answer
# 503 rather than growing the process.
MAX_BACKGROUND_AUTO_RUNS = 4
_auto_run_slots = threading.BoundedSemaphore(MAX_BACKGROUND_AUTO_RUNS)


def _execute_auto_run(run_id: int, params: auto_mode.AutoParams) -> None:
    """Run a planned auto run on its own connection in a background thread.

    A failure must not leave the run `running` forever: it is closed as failed
    so the polling client sees a terminal state instead of an eternal spinner.
    The background slot is released in ``finally`` so a crashed or finished run
    always frees capacity for the next start.
    """
    try:
        try:
            with contextlib.closing(_open()) as conn:
                auto_mode.execute_auto_run(conn, run_id=run_id, params=params)
        except Exception as exc:  # a crashed background run is a failed run, not a lost one
            failure = f"{type(exc).__name__}: {exc}"
            _log.warning(
                "auto run failed run_id=%s error=%s",
                run_id,
                failure[:200],
                exc_info=exc,
            )
            try:
                with contextlib.closing(_open()) as conn:
                    auto_mode.persist_undo_plan(conn, run_id)
                    auto_store.finish_auto_run(
                        conn,
                        run_id,
                        status=auto_store.AUTO_RUN_FAILED,
                        stats={"error": failure},
                    )
            except Exception:
                # A second failure must not die unobserved on a daemon thread:
                # the run would stay `running` with no log line to blame.
                _log.exception(
                    "could not mark auto run %s failed after %s",
                    run_id,
                    failure[:200],
                )
                raise
    finally:
        _auto_run_slots.release()


@router.post("/api/binaries/{binary_id}/auto")
def start_auto_run(binary_id: int, body: dict[str, Any] = Depends(optional_json_body)) -> Response:
    """Plan an auto run and execute it in the background; returns the run id.

    The request creates the run and its task tree, then returns 202 with the
    run id while a background thread works it, so the client polls
    ``GET /api/binaries/<id>/auto`` for live progress instead of blocking for
    minutes.  Body fields are all optional: ``worker`` (default the offline
    worker), ``execute`` (default false), ``concurrency``,
    ``functions_per_task``, ``max_attempts`` and ``max_tasks``.  At most
    :data:`MAX_BACKGROUND_AUTO_RUNS` runs execute at once; past that the route
    answers 503 without creating a run.
    """
    params = _auto_params(body)
    if not _auto_run_slots.acquire(blocking=False):
        return json_error(
            503,
            error="auto-busy",
            detail=(
                f"at most {MAX_BACKGROUND_AUTO_RUNS} auto runs may execute at once;"
                " wait for one to finish or poll an existing run"
            ),
        )
    try:
        with contextlib.closing(_open()) as conn:
            _require_binary(conn, binary_id)
            functions = auto_mode.select_functions(conn, binary_id)
            run_id = auto_mode.create_auto_run(
                conn, binary_id=binary_id, params=params, functions=functions
            )
        thread = threading.Thread(
            target=_execute_auto_run,
            args=(run_id, params),
            name=f"reportal-auto-{run_id}",
            daemon=True,
        )
        thread.start()
    except BaseException:
        _auto_run_slots.release()
        raise
    return json_response(
        {"run_id": run_id, "binary_id": binary_id, "status": auto_store.AUTO_RUN_RUNNING},
        status=202,
    )


@router.get("/api/binaries/{binary_id}/auto")
def get_binary_auto_run(binary_id: int) -> Response:
    """Latest auto run of a binary with its task tree; 404 no-run without one."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        run = auto_store.latest_auto_run(conn, binary_id)
        if run is None:
            return _no_auto_run(binary_id)
        return json_response(auto_mode.run_summary(conn, int(run["id"])))


@router.get("/api/auto/runs/{run_id}")
def get_auto_run(run_id: int) -> Response:
    """One auto run with its task tree and coverage; 404 run not found."""
    with contextlib.closing(_open()) as conn:
        if auto_store.get_auto_run(conn, run_id) is None:
            return json_error(404, error="run not found", detail=f"no auto run with id {run_id}")
        return json_response(auto_mode.run_summary(conn, run_id))


@router.post("/api/auto/runs/{run_id}/revert")
def revert_auto_run(run_id: int) -> Response:
    """Remove what a run wrote and delete its rows; returns what it undid."""
    with contextlib.closing(_open()) as conn:
        try:
            result = auto_mode.revert_auto_run(conn, run_id)
        except KeyError:
            return json_error(404, error="run not found", detail=f"no auto run with id {run_id}")
    return json_response(result)


@router.post("/api/auto/runs/{run_id}/recover")
def recover_auto_run(run_id: int) -> Response:
    """Recover a stale run: merge its unfinished tasks' writes and close it.

    There is no registry of live runs, so a `running` run is treated as stale
    (its worker died with a previous process); a run already closed is returned
    unchanged with zeroes.
    """
    with contextlib.closing(_open()) as conn:
        try:
            result = auto_mode.recover_auto_run(conn, run_id)
        except KeyError:
            return json_error(404, error="run not found", detail=f"no auto run with id {run_id}")
    return json_response(result)


# ── Conversations ──────────────────────────────────────────────────


def _conversation_scope_detail(
    conn: sqlite3.Connection, scope_kind: str, scope_id: int
) -> str | None:
    """Return the 404 detail for a scope id that does not exist, else None.

    The scope is a loose reference (functions and binaries live in different
    tables), so this is the only place an unknown scope id is rejected.
    """
    if scope_kind == conversations.SCOPE_KIND_FUNCTION:
        if store.get_function(conn, scope_id) is None:
            return f"no function with id {scope_id}"
        return None
    if scope_kind == conversations.SCOPE_KIND_DOCS:
        # The manual is one scope with no stored row, so every id names it; the
        # id is carried for the conversation row's sake and never matched.
        return None
    if store.get_binary(conn, scope_id) is None:
        return f"no binary with id {scope_id}"
    return None


def _no_conversation(conversation_id: int) -> Response:
    """Return the shared 404 for an unknown conversation id."""
    return json_error(
        404, error="conversation not found", detail=f"no conversation with id {conversation_id}"
    )


@router.get("/api/conversations")
def list_conversations(request: Request) -> Response:
    """Conversations, optionally filtered by ``?scope_kind=`` and ``?scope_id=``."""
    raw_kind = request.query_params.get("scope_kind")
    scope_kind = raw_kind.strip() if isinstance(raw_kind, str) and raw_kind.strip() else None
    raw_id = request.query_params.get("scope_id")
    scope_id: int | None = None
    if raw_id is not None:
        try:
            scope_id = int(raw_id)
        except ValueError:
            return json_error(400, error="scope_id must be an integer")
    with contextlib.closing(_open()) as conn:
        rows = store.list_conversations(
            conn, scope_kind=scope_kind, scope_id=scope_id, visible_to=_caller(request)
        )
    return json_response({"conversations": rows})


@router.post("/api/conversations")
def create_conversation(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Create a conversation for a function or binary scope."""
    scope_kind = _require_str(body, "scope_kind")
    scope_id = _require_int(body, "scope_id")
    if scope_kind not in conversations.SCOPE_KINDS:
        return json_error(
            400, error="invalid scope kind", detail=f"unsupported scope kind: {scope_kind}"
        )
    title = _optional_str(body, "title")
    with contextlib.closing(_open()) as conn:
        detail = _conversation_scope_detail(conn, scope_kind, scope_id)
        if detail is not None:
            return json_error(404, error=f"{scope_kind} not found", detail=detail)
        if scope_kind != conversations.SCOPE_KIND_DOCS:
            if scope_kind == conversations.SCOPE_KIND_FUNCTION:
                function = store.get_function(conn, scope_id)
                owner_id = None if function is None else int(function["binary_id"])
            else:
                owner_id = scope_id
            if owner_id is None or not _visible_binary(conn, owner_id, _caller(request)):
                return json_error(
                    404,
                    error=f"{scope_kind} not found",
                    detail=f"no {scope_kind} with id {scope_id}",
                )
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
            conversation = store.get_conversation(conn, conversation_id)
    return json_response(log.attach(conversation or {}), status=201)


@router.get("/api/conversations/{conversation_id}")
def get_conversation(conversation_id: int) -> Response:
    """One conversation with its messages in append order."""
    with contextlib.closing(_open()) as conn:
        conversation = store.get_conversation(conn, conversation_id)
        if conversation is None:
            return _no_conversation(conversation_id)
        messages = store.list_messages(conn, conversation_id)
    return json_response({**conversation, "messages": messages})


@router.delete("/api/conversations/{conversation_id}")
def delete_conversation(conversation_id: int) -> Response:
    """Delete a conversation and its messages."""
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
                return _no_conversation(conversation_id)
    return json_response(log.attach({"conversation_id": conversation_id, "deleted": True}))


@router.post("/api/conversations/{conversation_id}/messages")
def post_conversation_message(
    conversation_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Send one message to the configured LLM and store the exchange.

    The conversation must exist before the bridge is checked, so an unknown id
    is 404 whether or not an endpoint is configured.
    """
    content = _require_str(body, "content")
    with contextlib.closing(_open()) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            return _no_conversation(conversation_id)
        client = _ai_client()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = {int(row["id"]) for row in store.list_messages(conn, conversation_id)}
            try:
                result = conversations.send_message(
                    conn, conversation_id=conversation_id, content=content, client=client
                )
            except llm.LlmUnavailable:
                return json_error(503, error="llm-unavailable", detail=llm.UNAVAILABLE_DETAIL)
            except llm.LlmError as exc:
                journal.journaled_messages(conn, log, conversation_id, before)
                return json_error(502, error="llm-error", detail=str(exc))
            journal.journaled_messages(conn, log, conversation_id, before)
    return json_response(log.attach(result))


@router.post("/api/conversations/{conversation_id}/runs")
def start_conversation_run(
    conversation_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Run one agent turn: the model may call local MCP tools and answer.

    A read-only tool runs immediately; a tool that changes the workspace pauses
    the run with the exact call it wants to make, and `POST .../confirm` decides
    it.  The run row is journaled, and the messages the turn wrote with it, so a
    revert of the returned action removes both; a tool call the run made carries
    its own journal action, which this one does not cover.
    """
    content = _require_str(body, "content")
    with contextlib.closing(_open()) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            return _no_conversation(conversation_id)
        client = _ai_client()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = agent.start(
                    conn, log, conversation_id=conversation_id, content=content, client=client
                )
            except llm.LlmUnavailable:
                return json_error(503, error="llm-unavailable", detail=llm.UNAVAILABLE_DETAIL)
            except llm.LlmError as exc:
                return json_error(502, error="llm-error", detail=str(exc))
    return json_response(log.attach(result))


@router.get("/api/conversations/{conversation_id}/runs")
def list_conversation_runs(conversation_id: int) -> Response:
    """Every agent run of one conversation, newest first."""
    with contextlib.closing(_open()) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            return _no_conversation(conversation_id)
        rows = agent.list_runs(conn, conversation_id)
    return json_response({"runs": rows, "count": len(rows)})


@router.get("/api/conversations/{conversation_id}/runs/{run_id}")
def get_conversation_run(conversation_id: int, run_id: int) -> Response:
    """One agent run with its events, its pending call and its answer."""
    with contextlib.closing(_open()) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            return _no_conversation(conversation_id)
        try:
            return json_response(agent.payload(agent.get_run(conn, run_id)))
        except agent.UnknownRunError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)


@router.post("/api/conversations/{conversation_id}/confirm")
def confirm_conversation_run(
    conversation_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Approve or reject the tool call a paused run named, then continue it.

    The body is ``{"approve": bool, "run_id"?: int}``; without a run id the
    conversation's newest run is the one decided.  A rejection is fed back to
    the model as a refused tool result, so the run continues rather than
    failing, and the run's own messages are journaled with the returned action.
    """
    approve = body.get("approve")
    if not isinstance(approve, bool):
        return json_error(400, error="invalid approval", detail="approve must be a boolean")
    run_id = body.get("run_id")
    if run_id is not None and (isinstance(run_id, bool) or not isinstance(run_id, int)):
        return json_error(400, error="invalid run", detail="run_id must be an integer")
    with contextlib.closing(_open()) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            return _no_conversation(conversation_id)
        client = _ai_client()
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = agent.confirm(
                    conn,
                    log,
                    conversation_id=conversation_id,
                    approve=approve,
                    run_id=int(run_id) if run_id is not None else None,
                    client=client,
                )
            except agent.UnknownRunError as exc:
                return json_error(404, error=exc.code, detail=exc.detail)
            except agent.NotWaitingError as exc:
                return json_error(409, error=exc.code, detail=exc.detail)
            except llm.LlmUnavailable:
                return json_error(503, error="llm-unavailable", detail=llm.UNAVAILABLE_DETAIL)
            except llm.LlmError as exc:
                return json_error(502, error="llm-error", detail=str(exc))
    return json_response(log.attach(result))


@router.post("/api/conversations/{conversation_id}/cancel")
def cancel_conversation_run(
    conversation_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Cancel a live agent run; a run that already finished is refused.

    ``{"run_id"?: int}`` names one; without it the conversation's newest run is
    cancelled.  The run's loop re-reads its own status at each step boundary, so
    a call already in flight completes rather than being half-reported.
    """
    run_id = body.get("run_id")
    if run_id is not None and (isinstance(run_id, bool) or not isinstance(run_id, int)):
        return json_error(400, error="invalid run", detail="run_id must be an integer")
    with contextlib.closing(_open()) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            return _no_conversation(conversation_id)
        try:
            result = agent.cancel(
                conn,
                conversation_id=conversation_id,
                run_id=int(run_id) if run_id is not None else None,
            )
        except agent.UnknownRunError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)
        except agent.NotCancellableError as exc:
            return json_error(409, error=exc.code, detail=exc.detail)
    return json_response(result)


@router.get("/api/conversations/{conversation_id}/events")
def conversation_run_events(conversation_id: int, request: Request) -> Response:
    """The newest (or ``?run_id=``) run's state as server-sent events.

    The stream carries the run's state, not the model's tokens: a frame per
    observed change, the current state first, and a ``timeout`` frame at the
    cap so a client reconnects and reads the state again.
    """
    raw_run = request.query_params.get("run_id")
    run_id: int | None = None
    if raw_run is not None:
        try:
            run_id = int(raw_run)
        except ValueError:
            return json_error(400, error="invalid run", detail="run_id must be an integer")
    with contextlib.closing(_open()) as conn:
        if store.get_conversation(conn, conversation_id) is None:
            return _no_conversation(conversation_id)
        try:
            resolved = agent.resolve_run(conn, conversation_id, run_id)
        except agent.UnknownRunError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)

    def stream() -> Any:
        with contextlib.closing(_open()) as conn:
            yield from agent.events(conn, int(resolved["id"]))

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


# ── Analyses ───────────────────────────────────────────────────────


@router.get("/api/analyses")
def list_analyses(request: Request) -> Response:
    """Analyses with their binary and scope, filtered by status, search and workspace.

    ``?order=`` is one of :data:`reportal.store.ANALYSIS_ORDERS` and
    ``?limit=`` is bounded by :data:`reportal.store.MAX_ANALYSIS_LIMIT`; an
    unknown value is a 400.  ``total`` counts every analysis (or the binary's,
    with ``?binary_id=``) before the filters, so a filter that matched nothing
    says so instead of looking like an empty project.

    ``?status=`` repeats, and the values are combined as any-of, which is the
    hosted portal's multi-select Status control; a single value and the repeated
    form answer the same shape.  ``?platform=`` and ``?arch=`` match the stored
    binary's own `format` and `arch`, the two halves of that control.

    ``?workspace=`` is one of :data:`reportal.store.WORKSPACE_FILTERS` and reads
    the owning binary's scope the way the hosted portal's three controls do: an
    object no team owns (`personal`), one a team does (`team`), or one the whole
    workspace may see (`public`).  Each row carries its binary's `visibility`,
    `owner_team_id` and `owner_team_name`, and the scope is written through
    `PATCH /api/binaries/<id>/scope`, because the binary is the object reportal
    stores a team on.
    """
    status = _query_text(request, "status")
    repeated, status_error = _query_list(request, "status", len(store.ANALYSIS_STATUSES))
    if status_error is not None:
        return status_error
    for value in [status, *repeated]:
        if value is not None and value not in store.ANALYSIS_STATUSES:
            return _invalid_query("status", value, store.ANALYSIS_STATUSES)
    # The platform and architecture filters are free text against the stored
    # binary columns, which are what the crawler's own tags produced; the
    # payload answers the values the register actually holds so the control
    # offers only real choices.
    platform = _query_text(request, "platform")
    arch = _query_text(request, "arch")
    workspace = _query_text(request, "workspace")
    if workspace is not None and workspace not in store.WORKSPACE_FILTERS:
        return _invalid_query("workspace", workspace, store.WORKSPACE_FILTERS)
    order = _query_text(request, "order") or store.DEFAULT_ANALYSIS_ORDER
    if order not in store.ANALYSIS_ORDERS:
        return _invalid_query("order", order, store.ANALYSIS_ORDERS)
    limit = _query_int(request, "limit")
    if limit is not None and not 1 <= limit <= store.MAX_ANALYSIS_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {store.MAX_ANALYSIS_LIMIT}",
        )
    binary_id = _query_int(request, "binary_id")
    with contextlib.closing(_open()) as conn:
        analyses = store.list_analyses(
            conn,
            binary_id=binary_id,
            status=status,
            statuses=tuple(value for value in repeated if value is not None),
            search=_query_text(request, "search"),
            workspace=workspace,
            platform=platform,
            arch=arch,
            order=order,
            limit=limit,
            visible_to=_caller(request),
        )
        total = store.count_analyses(conn, binary_id=binary_id, visible_to=_caller(request))
        values = store.analysis_filter_values(conn)
    return json_response(
        {
            "analyses": analyses,
            "count": len(analyses),
            "total": total,
            "platforms": values["platforms"],
            "architectures": values["architectures"],
            "statuses": list(store.ANALYSIS_STATUSES),
        }
    )


@router.get("/api/analyses/{analysis_id}/logs")
def list_analysis_logs(request: Request, analysis_id: int) -> Response:
    """The analysis's log entries, newest first, bounded, with the true total.

    ``?limit=`` is bounded by :data:`reportal.analysis_log.MAX_LOG_LIMIT` and
    ``?offset=`` skips that many of the newest entries; an out-of-range value
    is a 400.  ``total`` is the whole log, not the page.
    """
    limit = _query_int(request, "limit")
    limit = analysis_log.DEFAULT_LOG_LIMIT if limit is None else limit
    if not 1 <= limit <= analysis_log.MAX_LOG_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {analysis_log.MAX_LOG_LIMIT}",
        )
    offset = _query_int(request, "offset") or 0
    if offset < 0:
        return json_error(400, error="invalid offset", detail="offset must not be negative")
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        entries, total = analysis_log.list_entries(conn, analysis_id, limit=limit, offset=offset)
    return json_response(
        {
            "logs": entries,
            "count": len(entries),
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    )


@router.delete("/api/analyses/{analysis_id}")
def delete_analysis(analysis_id: int) -> Response:
    """Delete one analysis with its functions, scans and log; journaled.

    A binary's only analysis is refused (409 ``last-analysis``) while it holds
    functions: the cascade would take them with it and leave the binary with a
    function table nothing carries.  Delete the binary instead.
    """
    with contextlib.closing(_open()) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        binary_id = int(analysis["binary_id"])
        functions = store.list_functions(conn, analysis_id=analysis_id)
        if store.is_last_analysis_with_functions(conn, analysis_id):
            return json_error(
                409,
                error="last-analysis",
                detail=(
                    f"analysis {analysis_id} is binary {binary_id}'s only analysis and holds"
                    f" {len(functions)} functions; deleting it would take them with it."
                    f" Delete binary {binary_id} instead."
                ),
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_analysis_delete(conn, log, analysis_id)
    return json_response(
        log.attach(
            {
                "deleted": analysis_id,
                "binary_id": binary_id,
                "functions_removed": len(functions),
            }
        )
    )


@router.post("/api/analyses")
def create_analysis(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    binary_id = _require_int(body, "binary_id")
    engine = _optional_str(body, "engine", "manual")
    with contextlib.closing(_open()) as conn:
        if not _visible_binary(conn, binary_id, _caller(request)):
            return json_error(
                404, error="binary not found", detail=f"no binary with id {binary_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine=engine)
            journal.journaled_create(
                log,
                table="analyses",
                key=analysis_id,
                description=f"created analysis {analysis_id} for binary {binary_id}",
            )
            analysis = store.get_analysis(conn, analysis_id)
    return json_response(log.attach(analysis or {}), status=201)


# ── Collections ────────────────────────────────────────────────────


@router.get("/api/collections")
def list_collections(request: Request) -> Response:
    """Collections with their member and tag counts, in ``?order=``.

    ``?order=`` is one of :data:`reportal.store.COLLECTION_ORDERS` (``id``, the
    default, then ``name``, ``size`` by member count, ``updated`` by the last
    membership, tag or field change and ``owner`` by the owning team's name); an
    unknown value is a 400.  ``?workspace=`` is one of
    :data:`reportal.store.WORKSPACE_FILTERS` and reads a collection's own scope:
    ``personal`` is one no team owns, ``team`` one a team does and ``public``
    one the whole workspace may see; an unknown value is a 400.  Every row
    carries ``visibility``, ``owner_team_id`` and ``owner_team_name``.  The
    response echoes the order and the workspace filter it applied, so a client
    rendering a sorted, filtered table does not have to assume either.
    """
    order = _query_text(request, "order") or store.DEFAULT_COLLECTION_ORDER
    if order not in store.COLLECTION_ORDERS:
        return _invalid_query("order", order, sorted(store.COLLECTION_ORDERS))
    workspace = _query_text(request, "workspace")
    if workspace is not None and workspace not in store.WORKSPACE_FILTERS:
        return _invalid_query("workspace", workspace, store.WORKSPACE_FILTERS)
    with contextlib.closing(_open()) as conn:
        return json_response(
            {
                "collections": store.list_collections(
                    conn,
                    order=order,
                    workspace=workspace,
                    visible_to=_caller(request),
                ),
                "order": order,
                "workspace": workspace,
            }
        )


@router.get("/api/binaries/{binary_id}/collections")
def list_binary_collections(request: Request, binary_id: int) -> Response:
    """The collections one binary is a member of, by name; read-only.

    A collection the caller may not see is left out, so a binary it can reach
    never discloses one it cannot.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        collections = store.collections_of_binary(conn, binary_id, visible_to=_caller(request))
    return json_response(
        {"binary_id": binary_id, "collections": collections, "count": len(collections)}
    )


@router.post("/api/collections")
def create_collection(body: dict[str, Any] = Depends(json_body)) -> Response:
    name = _require_str(body, "name")
    description = _optional_str(body, "description")
    scope = _optional_str(body, "scope")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                collection_id = store.create_collection(
                    conn, name=name, description=description, scope=scope
                )
            except ValueError as exc:
                return json_error(400, error="invalid collection", detail=str(exc))
            journal.journaled_create(
                log,
                table="collections",
                key=collection_id,
                description=f"created collection {collection_id}",
            )
            collections = store.list_collections(conn)
    created = next((c for c in collections if c["id"] == collection_id), {})
    return json_response(log.attach(created), status=201)


@router.post("/api/collections/{collection_id}/binaries")
def add_collection_binary(
    collection_id: int, request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    binary_id = _require_int(body, "binary_id")
    with contextlib.closing(_open()) as conn:
        known = {c["id"] for c in store.list_collections(conn)}
        if collection_id not in known:
            return json_error(
                404,
                error="collection not found",
                detail=f"no collection with id {collection_id}",
            )
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            return json_error(
                404, error="binary not found", detail=f"no binary with id {binary_id}"
            )
        if not auth.may_write(_caller(request), binary, team_ids=_caller_team_ids(conn, request)):
            return json_error(
                403,
                error=auth.ERROR_SCOPE_FORBIDDEN,
                detail=f"binary {binary_id} belongs to a team you are not a member of",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            added = store.add_collection_binary(conn, collection_id, binary_id)
            if added:
                journal.journaled_create(
                    log,
                    table="collection_binaries",
                    key={"collection_id": collection_id, "binary_id": binary_id},
                    description=f"added binary {binary_id} to collection {collection_id}",
                )
    return json_response(
        log.attach({"collection_id": collection_id, "binary_id": binary_id, "added": added})
    )


@router.get("/api/collections/{collection_id}")
def get_collection(collection_id: int) -> Response:
    """One collection with its members and tags; 404 for an unknown id."""
    with contextlib.closing(_open()) as conn:
        collection = store.get_collection(conn, collection_id)
        if collection is None:
            return _no_collection(collection_id)
    return json_response(collection)


@router.patch("/api/collections/{collection_id}")
def update_collection(collection_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Rename a collection or set its description and scope; absent fields stay."""
    name = _optional_str(body, "name") if "name" in body else None
    description = _optional_str(body, "description") if "description" in body else None
    scope = _optional_str(body, "scope") if "scope" in body else None
    if name is None and description is None and scope is None:
        return json_error(
            400,
            error="invalid collection",
            detail="name, description or scope is required",
        )
    with contextlib.closing(_open()) as conn:
        if store.get_collection(conn, collection_id) is None:
            return _no_collection(collection_id)
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
                collection = store.update_collection(
                    conn,
                    collection_id,
                    name=name,
                    description=description,
                    scope=scope,
                )
            except ValueError as exc:
                return json_error(400, error="invalid collection", detail=str(exc))
    return json_response(log.attach(collection or {}))


@router.delete("/api/collections/{collection_id}")
def delete_collection(collection_id: int) -> Response:
    """Delete one collection with its membership and tag links; 404 when unknown."""
    with contextlib.closing(_open()) as conn:
        if store.get_collection(conn, collection_id) is None:
            return _no_collection(collection_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            # The links are recorded before the collection row on purpose: a
            # revert replays newest-first, and a link restored before its parent
            # row exists trips the foreign key.
            for table, where in (
                ("collection_binaries", "collection_id = ?"),
                ("collection_tags", "collection_id = ?"),
            ):
                links = journal.snapshot_rows(
                    conn, table=table, where=where, params=(collection_id,)
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
    return json_response(log.attach({"collection_id": collection_id, "deleted": True}))


@router.patch("/api/collections/{collection_id}/binaries")
def replace_collection_binaries(
    request: Request, collection_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Make the body's ids the exact members of one collection; 404 for an unknown id."""
    binary_ids = _optional_int_list(body, "binary_ids")
    if binary_ids is None:
        return json_error(400, error="invalid collection", detail="binary_ids is required")
    with contextlib.closing(_open()) as conn:
        if store.get_collection(conn, collection_id) is None:
            return _no_collection(collection_id)
        for binary_id in binary_ids:
            binary = store.get_binary(conn, binary_id)
            if binary is None:
                return json_error(
                    404, error="binary not found", detail=f"no binary with id {binary_id}"
                )
            if not auth.may_write(
                _caller(request), binary, team_ids=_caller_team_ids(conn, request)
            ):
                return json_error(
                    403,
                    error=auth.ERROR_SCOPE_FORBIDDEN,
                    detail=f"binary {binary_id} belongs to a team you are not a member of",
                )
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
            except ValueError as exc:
                return json_error(404, error="binary not found", detail=str(exc))
            _record_link_change(log, "collection_binaries", before, collection_id)
    return json_response(log.attach({"collection_id": collection_id, **change}))


@router.delete("/api/collections/{collection_id}/binaries")
def remove_collection_binaries(
    request: Request, collection_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Remove the body's ids from one collection, keeping the rest of its members."""
    binary_ids = _optional_int_list(body, "binary_ids")
    if binary_ids is None:
        return json_error(400, error="invalid collection", detail="binary_ids is required")
    with contextlib.closing(_open()) as conn:
        collection = store.get_collection(conn, collection_id)
        if collection is None:
            return _no_collection(collection_id)
        for binary_id in binary_ids:
            binary = store.get_binary(conn, binary_id)
            if binary is None:
                return json_error(
                    404, error="binary not found", detail=f"no binary with id {binary_id}"
                )
            if not auth.may_write(
                _caller(request), binary, team_ids=_caller_team_ids(conn, request)
            ):
                return json_error(
                    403,
                    error=auth.ERROR_SCOPE_FORBIDDEN,
                    detail=f"binary {binary_id} belongs to a team you are not a member of",
                )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn,
                table="collection_binaries",
                where="collection_id = ?",
                params=(collection_id,),
            )
            kept = [
                int(row["id"])
                for row in collection["binaries"]
                if int(row["id"]) not in set(binary_ids)
            ]
            change = store.replace_collection_binaries(conn, collection_id, kept)
            _record_link_change(log, "collection_binaries", before, collection_id)
    return json_response(log.attach({"collection_id": collection_id, **change}))


@router.patch("/api/collections/{collection_id}/tags")
def replace_collection_tags(
    collection_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Replace the tags on one collection, creating the names that are new."""
    if "tags" not in body:
        return json_error(400, error="invalid collection", detail="tags is required")
    names = _optional_str_list(body, "tags")
    with contextlib.closing(_open()) as conn:
        if store.get_collection(conn, collection_id) is None:
            return _no_collection(collection_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn, table="collection_tags", where="collection_id = ?", params=(collection_id,)
            )
            change = store.set_collection_tags(conn, collection_id, names)
            _record_link_change(log, "collection_tags", before, collection_id)
    return json_response(log.attach({"collection_id": collection_id, **change}))


def _no_collection(collection_id: int) -> Response:
    """The 404 every collection route answers for an unknown id."""
    return json_error(
        404, error="collection not found", detail=f"no collection with id {collection_id}"
    )


def _record_link_change(
    log: journal.Journal, table: str, before: list[dict[str, Any]], collection_id: int
) -> None:
    """Journal a collection's links: what was there is restored on revert."""
    log.record(
        effects.EFFECT_ROW_RESTORE,
        f"links of collection {collection_id} in {table}",
        journal.row_restore_descriptor(table, before),
    )


# ── Tags ───────────────────────────────────────────────────────────


@router.get("/api/tags")
def list_tags() -> Response:
    with contextlib.closing(_open()) as conn:
        return json_response({"tags": store.list_tags(conn)})


@router.post("/api/tags")
def create_tag(body: dict[str, Any] = Depends(json_body)) -> Response:
    """Create a tag by name, returning the existing one when it is already known."""
    name = _require_str(body, "name")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            created = store.find_tag(conn, name) is None
            tag_id = store.create_tag(conn, name)
            if created:
                journal.journaled_create(
                    log, table="tags", key=tag_id, description=f"created tag {tag_id}"
                )
            tag = store.get_tag(conn, tag_id)
    stored_name = str(tag["name"]) if tag is not None else name.strip()
    return json_response(log.attach({"tag_id": tag_id, "name": stored_name}), status=201)


@router.patch("/api/tags/{tag_id}")
def rename_tag(tag_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Rename one tag by id; 404 when unknown, 400 for a blank or taken name."""
    name = _require_str(body, "name")
    with contextlib.closing(_open()) as conn:
        before = store.get_tag(conn, tag_id)
        if before is None:
            return json_error(404, error="tag not found", detail=f"no tag with id {tag_id}")
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            # The snapshot is taken before the write: a revert restores the row
            # as it was, so the old name has to be read first.
            journal.journaled_rows(
                conn,
                log,
                table="tags",
                where="id = ?",
                params=(tag_id,),
                description=f"renamed tag {tag_id}",
            )
            try:
                renamed = store.rename_tag(conn, tag_id, name)
            except ValueError as exc:
                return json_error(400, error="invalid tag", detail=str(exc))
    return json_response(log.attach(renamed or before))


@router.delete("/api/tags/{tag_id}")
def delete_tag(tag_id: int) -> Response:
    """Delete one tag with every link to it; 404 when unknown."""
    with contextlib.closing(_open()) as conn:
        if store.get_tag(conn, tag_id) is None:
            return json_error(404, error="tag not found", detail=f"no tag with id {tag_id}")
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            # The links are recorded before the tag row on purpose: a revert
            # replays newest-first, and a link restored before the tag it points
            # at exists trips the foreign key.
            for table, where in (
                ("binary_tags", "tag_id = ?"),
                ("collection_tags", "tag_id = ?"),
            ):
                links = journal.snapshot_rows(conn, table=table, where=where, params=(tag_id,))
                if links:
                    log.record(
                        effects.EFFECT_ROW_RESTORE,
                        f"links of tag {tag_id} in {table}",
                        journal.row_restore_descriptor(table, links),
                    )
            journal.journaled_rows(
                conn,
                log,
                table="tags",
                where="id = ?",
                params=(tag_id,),
                description=f"deleted tag {tag_id}",
            )
            store.delete_tag(conn, tag_id)
    return json_response(log.attach({"tag_id": tag_id, "deleted": True}))


@router.get("/api/binaries/{binary_id}/tags")
def list_binary_tags(binary_id: int) -> Response:
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        tags = store.get_binary_tags(conn, binary_id)
    return json_response({"tags": tags})


@router.post("/api/binaries/{binary_id}/tags")
def add_binary_tag(
    request: Request, binary_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Link a tag to a binary, addressed by ``name`` (created if needed) or ``tag_id``."""
    has_name = "name" in body
    has_tag_id = "tag_id" in body
    if has_name == has_tag_id:
        return json_error(400, error="invalid body", detail="provide exactly one of name or tag_id")
    with contextlib.closing(_open()) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            return json_error(
                404, error="binary not found", detail=f"no binary with id {binary_id}"
            )
        if not auth.may_write(_caller(request), binary, team_ids=_caller_team_ids(conn, request)):
            return json_error(
                403,
                error=auth.ERROR_SCOPE_FORBIDDEN,
                detail=f"binary {binary_id} belongs to a team you are not a member of",
            )
        if has_tag_id:
            tag_id = _require_int(body, "tag_id")
            tag = store.get_tag(conn, tag_id)
            if tag is None:
                return json_error(404, error="tag not found", detail=f"no tag with id {tag_id}")
            name = str(tag["name"])
            created_tag = False
        else:
            name = _require_str(body, "name")
            created_tag = store.find_tag(conn, name) is None
            tag_id = store.create_tag(conn, name)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            if created_tag:
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
    payload = {"binary_id": binary_id, "tag_id": tag_id, "name": name}
    return json_response(log.attach(payload))


@router.delete("/api/binaries/{binary_id}/tags/{tag_id}")
def remove_binary_tag(request: Request, binary_id: int, tag_id: int) -> Response:
    """Unlink a tag from a binary; the link must exist."""
    with contextlib.closing(_open()) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            return json_error(
                404, error="binary not found", detail=f"no binary with id {binary_id}"
            )
        if not auth.may_write(_caller(request), binary, team_ids=_caller_team_ids(conn, request)):
            return json_error(
                403,
                error=auth.ERROR_SCOPE_FORBIDDEN,
                detail=f"binary {binary_id} belongs to a team you are not a member of",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            link = journal.snapshot_rows(
                conn,
                table="binary_tags",
                where="binary_id = ? AND tag_id = ?",
                params=(binary_id, tag_id),
            )
            if not store.remove_binary_tag(conn, binary_id, tag_id):
                return json_error(
                    404,
                    error="tag not on binary",
                    detail=f"binary {binary_id} has no tag {tag_id}",
                )
            if link:
                log.record(
                    effects.EFFECT_ROW_RESTORE,
                    f"untagged binary {binary_id} from tag {tag_id}",
                    journal.row_restore_descriptor("binary_tags", link),
                )
    return json_response(log.attach({"binary_id": binary_id, "tag_id": tag_id, "removed": True}))


# The password a zipped download uses when the request names none, and the cap
# on one the request does name.  The value is a convention, not a secret: it
# defeats a scanner that opens every archive it sees, which is the only reason
# the hosted portal offers a protected download too.
ZIP_PASSWORD_DEFAULT = zipcrypto.DEFAULT_PASSWORD
ZIP_PASSWORD_MAX_CHARS = zipcrypto.MAX_PASSWORD_CHARS


@router.get("/api/binaries/{binary_id}/download-zipped")
def download_binary_zipped(binary_id: int, password: str = ZIP_PASSWORD_DEFAULT) -> Response:
    """Stream the stored bytes as a zip whose one member is password protected.

    The archive is assembled as it is streamed (:mod:`reportal.zipcrypto`): the
    member is deflated into a spooled temporary file so its CRC and compressed
    size precede it, then the spool is encrypted into the response, so neither
    the plaintext nor the archive is held whole for a binary up to
    :data:`MAX_UPLOAD_BYTES`.

    ``password`` is a query parameter with a shared default; it is **not a
    security measure** (ZipCrypto has no authentication and the password is
    echoed back in ``X-Reportal-Zip-Password``), it is what makes the archive
    survive a mail gateway or an upload form that refuses a raw sample.  The
    answer is not cacheable: the encryption header is drawn per request.
    """
    try:
        password = zipcrypto.validate_password(password)
    except ValueError as exc:
        return json_error(400, error="invalid password", detail=str(exc))
    with contextlib.closing(db()) as conn:
        binary = store.get_binary(conn, binary_id)
    if binary is None:
        return json_error(404, error="binary not found", detail=f"no binary with id {binary_id}")
    path = Path(str(binary["path"]))
    if not path.is_file():
        return json_error(
            404,
            error="binary not on disk",
            detail=f"binary {binary_id} has no file at {binary['path']!r}",
        )
    member = download_filename(binary)
    return StreamingResponse(
        _stream_protected_zip(path, f"{member}.zip", password),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{member}.zip"',
            "X-Reportal-Zip-Password": password,
            "Cache-Control": "no-store",
        },
    )


def _stream_protected_zip(path: Path, member: str, password: str) -> Iterator[bytes]:
    """Yield *path* as an encrypted zip member, closing the file when done."""
    with path.open("rb") as handle:
        yield from zipcrypto.stream_protected_zip(member, handle, password)


# ── Comments ───────────────────────────────────────────────────────
#
# The comment routes (``/api/binaries/<id>/comments``,
# ``/api/functions/<id>/comments`` and ``/api/comments/<id>``) have moved to
# :mod:`reportal.rest`.


# ── Bulk actions ───────────────────────────────────────────────────


def _bulk_failure(exc: bulk_actions.BulkError) -> Response:
    return json_error(400, error="invalid bulk request", detail=str(exc))


def _bulk_ids(body: dict[str, Any], key: str) -> list[int] | Response:
    value = body.get(key)
    if not isinstance(value, list):
        return json_error(400, error="invalid bulk request", detail=f"{key} must be a list")
    return value


@router.post("/api/binaries/bulk")
def bulk_binaries(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Apply one action (``add_tag``, ``remove_tag``, ``delete``) to many binaries."""
    action = body.get("action")
    if not isinstance(action, str):
        return json_error(400, error="invalid bulk request", detail="action must be a string")
    ids = _bulk_ids(body, "binary_ids")
    if not isinstance(ids, list):
        return ids
    tag = body.get("tag", "")
    if not isinstance(tag, str):
        return json_error(400, error="invalid bulk request", detail="tag must be a string")
    with contextlib.closing(_open()) as conn:
        caller = _caller(request)
        allowed = (
            None
            if caller is None
            else {int(row["id"]) for row in store.list_binaries(conn, visible_to=caller)}
        )
        action_id = journal.new_action()
        with journal.journaled(conn, action_id) as log:
            try:
                result = bulk_actions.apply_binary_action(
                    conn, action=action, ids=ids, tag=tag, log=log, allowed=allowed
                )
            except bulk_actions.BulkError as exc:
                return _bulk_failure(exc)
    return json_response(log.attach(result))


@router.post("/api/analyses/bulk")
def bulk_analyses(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Apply one action (``add_tag``, ``remove_tag``, ``delete``) to many analyses.

    A tag action writes each analysis's owning binary, the scope reportal tags
    at; a delete replays the same journaled snapshot ``DELETE
    /api/analyses/<id>`` uses, skipping a binary's only analysis while it holds
    functions with the reason ``only analysis with functions``.
    """
    action = body.get("action")
    if not isinstance(action, str):
        return json_error(400, error="invalid bulk request", detail="action must be a string")
    ids = _bulk_ids(body, "analysis_ids")
    if not isinstance(ids, list):
        return ids
    tag = body.get("tag", "")
    if not isinstance(tag, str):
        return json_error(400, error="invalid bulk request", detail="tag must be a string")
    with contextlib.closing(_open()) as conn:
        action_id = journal.new_action()
        with journal.journaled(conn, action_id) as log:
            try:
                result = bulk_actions.apply_analysis_action(
                    conn,
                    action=action,
                    ids=ids,
                    tag=tag,
                    log=log,
                    allowed=_visible_binary_ids(conn, _caller(request)),
                )
            except bulk_actions.BulkError as exc:
                return _bulk_failure(exc)
    return json_response(log.attach(result))


@router.post("/api/functions/bulk")
def bulk_functions(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Apply one action (``rename``, ``clear_matches``) to many functions."""
    action = body.get("action")
    if not isinstance(action, str):
        return json_error(400, error="invalid bulk request", detail="action must be a string")
    ids = _bulk_ids(body, "function_ids")
    if not isinstance(ids, list):
        return ids
    prefix = body.get("prefix", "")
    if not isinstance(prefix, str):
        return json_error(400, error="invalid bulk request", detail="prefix must be a string")
    replace = body.get("replace", False)
    if not isinstance(replace, bool):
        return json_error(400, error="invalid bulk request", detail="replace must be a boolean")
    with contextlib.closing(_open()) as conn:
        action_id = journal.new_action()
        with journal.journaled(conn, action_id) as log:
            try:
                result = bulk_actions.apply_function_action(
                    conn,
                    action=action,
                    ids=ids,
                    prefix=prefix,
                    replace=replace,
                    log=log,
                    allowed=_visible_binary_ids(conn, _caller(request)),
                )
            except bulk_actions.BulkError as exc:
                return _bulk_failure(exc)
    return json_response(log.attach(result))


# ── Journal ────────────────────────────────────────────────────────


@router.get("/api/notifications")
def list_notifications(request: Request) -> Response:
    """The notification feed, derived from the journal and the analysis log.

    ``?since=`` is an ISO timestamp (the ``since`` a previous response carried,
    usually) and ``?limit=`` is bounded by :data:`reportal.notifications.
    MAX_FEED_LIMIT`; either being unusable is a 400.  ``?sources=`` narrows the
    feed to ``action``, ``log`` or both.  Nothing is stored and nothing is
    written: dismissal lives in the client, keyed by each item's stable ``id``.
    """
    since_raw = _query_text(request, "since")
    since = None
    if since_raw is not None:
        try:
            since = notifications.parse_since(since_raw)
        except ValueError as exc:
            return json_error(400, error="invalid since", detail=str(exc))
    limit = _query_int(request, "limit")
    limit = notifications.DEFAULT_FEED_LIMIT if limit is None else limit
    if not 1 <= limit <= notifications.MAX_FEED_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {notifications.MAX_FEED_LIMIT}",
        )
    sources = notifications.SOURCES
    raw_sources = _query_text(request, "sources")
    if raw_sources is not None:
        sources = tuple(part.strip() for part in raw_sources.split(",") if part.strip())
    with contextlib.closing(_open()) as conn:
        try:
            payload = notifications.feed(
                conn, since=since, limit=limit, sources=sources, visible_to=_caller(request)
            )
        except ValueError as exc:
            return json_error(400, error="invalid sources", detail=str(exc))
        payload["latest"] = notifications.latest(conn)
    return json_response(payload)


@router.get("/api/journal")
def list_journal(request: Request) -> Response:
    """Recent journal entries, newest first, without their descriptor payload.

    ``?action=`` narrows to one action id and ``?actor=`` to the identity that
    wrote the entry (the name the server set around the request, ``local`` while
    auth is off and empty for a CLI or MCP write); ``?limit=`` bounds the page.
    The body echoes what it applied and names the ``actors`` the journal holds,
    which is what the SPA's control is built from.
    """
    raw_limit = request.query_params.get("limit")
    limit = journal.DEFAULT_LIST_LIMIT
    if raw_limit is not None:
        try:
            limit = int(raw_limit)
        except ValueError:
            return json_error(400, error="limit must be an integer")
    if limit < 1:
        return json_error(400, error="limit must be positive", detail="limit is at least 1")
    raw_action = request.query_params.get("action")
    action = raw_action.strip() if isinstance(raw_action, str) and raw_action.strip() else None
    raw_actor = request.query_params.get("actor")
    actor = raw_actor.strip() if isinstance(raw_actor, str) and raw_actor.strip() else None
    with contextlib.closing(_open()) as conn:
        entries = journal.list_entries(conn, action=action, actor=actor, limit=limit)
        actors = journal.list_actors(conn)
    return json_response(
        {
            "entries": entries,
            "count": len(entries),
            "limit": limit,
            "action": action,
            "actor": actor,
            "actors": actors,
        }
    )


@router.get("/api/journal/{action}")
def get_journal_action(action: str) -> Response:
    """Every entry of one action, newest first; 404 for an action never recorded."""
    with contextlib.closing(_open()) as conn:
        entries = journal.list_entries(conn, action=action, limit=journal.MAX_LIST_LIMIT)
    if not entries:
        return json_error(404, error="action not found", detail=f"no journal action {action!r}")
    return json_response({"action": action, "entries": entries, "count": len(entries)})


@router.post("/api/journal/revert")
def revert_journal(body: dict[str, Any] = Depends(json_body)) -> Response:
    """Revert one action (``{"action"}``) or one entry (``{"entry_id"}``)."""
    raw_action = body.get("action")
    raw_entry = body.get("entry_id")
    if (raw_action is None) == (raw_entry is None):
        return json_error(
            400, error="invalid body", detail="provide exactly one of action or entry_id"
        )
    with contextlib.closing(_open()) as conn:
        try:
            if raw_entry is not None:
                if isinstance(raw_entry, bool) or not isinstance(raw_entry, int):
                    return json_error(
                        400, error="invalid body", detail="entry_id must be an integer"
                    )
                return json_response(journal.revert_entry(conn, raw_entry))
            if not isinstance(raw_action, str) or not raw_action.strip():
                return json_error(
                    400, error="invalid body", detail="action must be a non-empty string"
                )
            return json_response(journal.revert_action(conn, raw_action))
        except journal.UnknownActionError as exc:
            return json_error(404, error="action not found", detail=str(exc))
        except journal.UnknownEntryError as exc:
            return json_error(404, error="entry not found", detail=str(exc))
        except journal.EntryNotActiveError as exc:
            return json_error(400, error="not-active", detail=str(exc))
        except ValueError as exc:
            return json_error(400, error="invalid body", detail=str(exc))
        except journal.JournalError:
            return json_error(
                500, error="journal-error", detail="the stored journal entry is unreadable"
            )


# ── Knowledge ──────────────────────────────────────────────────────


def _no_document(document_id: int) -> Response:
    """Return the shared 404 for an unknown document id."""
    return json_error(404, error="document not found", detail=f"no document with id {document_id}")


def _knowledge_error(exc: knowledge.KnowledgeError) -> Response:
    """Map an ingest failure to its JSON error response."""
    status = 413 if exc.code == knowledge.ERROR_FILE_TOO_LARGE else 400
    return json_error(status, error=exc.code, detail=exc.detail)


def _ingested(payload: dict[str, Any]) -> Response:
    """Answer an ingest: 201 for a new document, 200 for a duplicate."""
    return json_response(payload, status=200 if payload.get("duplicate") else 201)


# HTTP status per remote-ingest error name; an unlisted one is a bad target.
_REMOTE_STATUS: dict[str, int] = {
    remote_ingest.ERROR_DISABLED: 403,
    remote_ingest.ERROR_TOO_LARGE: 413,
    remote_ingest.ERROR_FETCH_FAILED: 502,
    remote_ingest.ERROR_TOO_MANY_REDIRECTS: 502,
}


def _remote_error(exc: remote_ingest.RemoteIngestError) -> Response:
    """Map a remote-ingest failure to its JSON error response."""
    return json_error(_REMOTE_STATUS.get(exc.code, 400), error=exc.code, detail=exc.detail)


def _check_document_scope(
    conn: sqlite3.Connection, scope_kind: str, scope_id: int
) -> Response | None:
    """Return a JSON error for a scope a document may not attach to, else None.

    A binary scope must name a stored binary.  A project scope is a
    workspace-level bucket no table holds, so it only rejects a negative id.
    """
    if scope_id < 0:
        return json_error(400, error="invalid scope id", detail="scope_id must not be negative")
    if scope_kind == knowledge.SCOPE_KIND_BINARY and store.get_binary(conn, scope_id) is None:
        return json_error(404, error="binary not found", detail=f"no binary with id {scope_id}")
    return None


@router.post("/api/documents")
def create_document(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Ingest a pasted note as a document.

    The body is ``{"scope_kind", "scope_id", "title", "text", "source"}``.  The
    text is encoded and ingested the way an uploaded file is, so the size cap,
    the binary and empty rejection and the per-scope dedupe all apply.
    """
    scope_kind = _require_str(body, "scope_kind")
    scope_id = _require_int(body, "scope_id")
    title = _optional_str(body, "title")
    source = _optional_str(body, "source")
    text = _optional_str(body, "text")
    if scope_kind not in knowledge.SCOPE_KINDS:
        return json_error(
            400, error=knowledge.ERROR_INVALID_SCOPE, detail=f"unsupported scope kind: {scope_kind}"
        )
    with contextlib.closing(_open()) as conn:
        failure = _check_document_scope(conn, scope_kind, scope_id)
        if failure is not None:
            return failure
        if scope_kind == knowledge.SCOPE_KIND_BINARY and not _visible_binary(
            conn, scope_id, _caller(request)
        ):
            return json_error(404, error="binary not found", detail=f"no binary with id {scope_id}")
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
                return _knowledge_error(exc)
            journal.journaled_ingest(conn, log, payload)
    return _ingested(log.attach(payload))


@router.get("/api/binaries/{binary_id}/documents")
def list_binary_documents(binary_id: int) -> Response:
    """Documents scoped to one binary, newest last, without their text."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        documents = store.list_documents(
            conn, scope_kind=knowledge.SCOPE_KIND_BINARY, scope_id=binary_id
        )
    return json_response({"documents": documents})


@router.get("/api/documents")
def list_documents(request: Request) -> Response:
    """Documents, optionally filtered by ``?scope_kind=`` and ``?scope_id=``."""
    raw_kind = request.query_params.get("scope_kind")
    scope_kind = raw_kind.strip() if isinstance(raw_kind, str) and raw_kind.strip() else None
    if scope_kind is not None and scope_kind not in knowledge.SCOPE_KINDS:
        return json_error(
            400, error=knowledge.ERROR_INVALID_SCOPE, detail=f"unsupported scope kind: {scope_kind}"
        )
    raw_id = request.query_params.get("scope_id")
    scope_id: int | None = None
    if raw_id is not None:
        try:
            scope_id = int(raw_id)
        except ValueError:
            return json_error(400, error="scope_id must be an integer")
    with contextlib.closing(_open()) as conn:
        documents = store.list_documents(
            conn, scope_kind=scope_kind, scope_id=scope_id, visible_to=_caller(request)
        )
    return json_response({"documents": documents})


@router.get("/api/documents/{document_id}")
def get_document(request: Request, document_id: int) -> Response:
    """One document: its metadata and chunk count, the text only on request.

    ``?include_text=true`` adds the extracted text and its chunks, which is
    what the ranking scores; without it the response stays metadata-sized.
    """
    include_text = _query_bool(request, "include_text", False)
    with contextlib.closing(_open()) as conn:
        document = store.get_document(conn, document_id)
        if document is None:
            return _no_document(document_id)
        chunks = store.list_chunks(conn, document_id)
    if not include_text:
        document.pop("text", None)
        return json_response(document)
    return json_response({**document, "chunks": chunks})


@router.delete("/api/documents/{document_id}")
def delete_document(document_id: int) -> Response:
    """Delete a document and, by cascade, its chunks."""
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            # Chunks first: a revert replays newest-first, so the document row
            # is back before its chunks are re-inserted.
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
                return _no_document(document_id)
    return json_response(log.attach({"document_id": document_id, "deleted": True}))


@router.get("/api/knowledge/config")
def knowledge_config() -> Response:
    """Report whether guarded remote ingestion is enabled; read-only."""
    return json_response({"allow_remote": remote_ingest.remote_enabled()})


@router.post("/api/knowledge/fetch")
def fetch_remote_document(body: dict[str, Any] = Depends(json_body)) -> Response:
    """Fetch one HTTP(S) URL and store its text as a knowledge document.

    The body is ``{"scope_kind", "scope_id", "url", "title"}``.  Remote
    ingestion is off by default: while it is disabled every request answers 403
    ``remote-ingest-disabled``.  A blocked or malformed target and an
    unsupported content type answer 400, a body past the size cap 413, a
    transport failure 502, an unknown binary scope 404, and a new document 201
    (a duplicate 200 with ``"duplicate": true``).
    """
    scope_kind = _require_str(body, "scope_kind")
    scope_id = _require_int(body, "scope_id")
    url = _require_str(body, "url")
    title = _optional_str(body, "title")
    if not remote_ingest.remote_enabled():
        return json_error(
            403, error=remote_ingest.ERROR_DISABLED, detail=remote_ingest.DISABLED_DETAIL
        )
    if scope_kind not in knowledge.SCOPE_KINDS:
        return json_error(
            400, error=knowledge.ERROR_INVALID_SCOPE, detail=f"unsupported scope kind: {scope_kind}"
        )
    with contextlib.closing(_open()) as conn:
        failure = _check_document_scope(conn, scope_kind, scope_id)
        if failure is not None:
            return failure
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
                return _remote_error(exc)
            except knowledge.KnowledgeError as exc:
                return _knowledge_error(exc)
            journal.journaled_ingest(conn, log, payload)
    return _ingested(log.attach(payload))


@router.get("/api/knowledge/search")
def search_knowledge(request: Request) -> Response:
    """Rank stored document chunks against ``?q=``; read-only.

    ``?binary_id=`` narrows the corpus to one binary and ``?limit=`` bounds the
    result list.  An absent or blank query answers an empty list rather than
    every chunk.
    """
    raw_query = request.query_params.get("q", "")
    query = raw_query if isinstance(raw_query, str) else ""
    limit = knowledge.DEFAULT_SEARCH_LIMIT
    raw_limit = request.query_params.get("limit")
    if raw_limit is not None:
        try:
            limit = int(raw_limit)
        except ValueError:
            return json_error(400, error="limit must be an integer")
    if limit < 1:
        return json_error(400, error="limit must be positive", detail="limit is at least 1")
    scope_kind: str | None = None
    scope_id: int | None = None
    raw_binary = request.query_params.get("binary_id")
    if raw_binary is not None:
        try:
            scope_id = int(raw_binary)
        except ValueError:
            return json_error(400, error="binary_id must be an integer")
        scope_kind = knowledge.SCOPE_KIND_BINARY
    with contextlib.closing(_open()) as conn:
        results = knowledge.search_knowledge(
            conn,
            query=query,
            scope_kind=scope_kind,
            scope_id=scope_id,
            limit=limit,
            visible_to=_caller(request),
        )
    return json_response({"query": query, "count": len(results), "results": results})


def _knowledge_query(
    request: Request,
) -> str:
    """The request's ``?q=`` value, "" when absent or not a string."""
    raw = request.query_params.get("q", "")
    return raw if isinstance(raw, str) else ""


def _knowledge_hits(
    query: str,
    scope_kind: str | None,
    scope_id: int | None,
    visible_to: dict[str, Any] | None = None,
) -> Response:
    """Retrieve bounded hits for one scope; returns the JSON response."""
    with contextlib.closing(_open()) as conn:
        results = knowledge.retrieve(
            conn, query=query, scope_kind=scope_kind, scope_id=scope_id, visible_to=visible_to
        )
    return json_response({"query": query, "count": len(results), "results": results})


@router.get("/api/functions/{function_id}/knowledge")
def function_knowledge(request: Request, function_id: int) -> Response:
    """Retrieve the function's binary documents against ``?q=``; read-only.

    ``?q=`` defaults to the function's name when absent or blank, so a plain
    GET gives the documents most about the function.  The corpus is the
    binary's knowledge scope.
    """
    query = _knowledge_query(
        request,
    )
    with contextlib.closing(_open()) as conn:
        function = store.get_function(conn, function_id)
        if function is None:
            return json_error(
                404, error="function not found", detail=f"no function with id {function_id}"
            )
        binary_id = int(function["binary_id"])
    resolved = query.strip() or str(function["name"])
    return _knowledge_hits(
        resolved, knowledge.SCOPE_KIND_BINARY, binary_id, visible_to=_caller(request)
    )


@router.get("/api/binaries/{binary_id}/knowledge")
def binary_knowledge(request: Request, binary_id: int) -> Response:
    """Retrieve the binary's documents against ``?q=``; read-only.

    An absent or blank query answers an empty list rather than every document.
    """
    query = _knowledge_query(
        request,
    )
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
    return _knowledge_hits(
        query, knowledge.SCOPE_KIND_BINARY, binary_id, visible_to=_caller(request)
    )


# ── Knowledge graph ────────────────────────────────────────────────


def _no_graph(binary_id: int) -> Response:
    """Return the stored-only 404 for a binary whose graph was never built."""
    return json_error(
        404,
        error="no-graph",
        detail=(
            f"no graph for binary {binary_id}; "
            f"run POST /api/binaries/{binary_id}/graph or 'reportal graph-build {binary_id}'"
        ),
    )


@router.post("/api/binaries/{binary_id}/graph")
def build_binary_graph(binary_id: int) -> Response:
    """Rebuild a binary's knowledge graph from the rows the store already holds."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = journal.journaled_graph_rebuild(
                conn, log, binary_id, lambda: graph.build_graph(conn, binary_id=binary_id)
            )
    return json_response(log.attach(result))


@router.get("/api/binaries/{binary_id}/graph")
def get_binary_graph(request: Request, binary_id: int) -> Response:
    """A binary's stored graph; 404 `no-graph` before the first build.

    ``?kind=`` keeps one node kind and ``?include_documents=true`` adds the
    document nodes and their mention edges, which are left out by default.
    """
    raw_kind = request.query_params.get("kind")
    kind = raw_kind.strip() if isinstance(raw_kind, str) and raw_kind.strip() else None
    if kind is not None and kind not in graph.GRAPH_NODE_KINDS:
        return json_error(
            400,
            error="invalid kind",
            detail=f"unsupported node kind: {kind}",
        )
    include_documents = _query_bool(request, "include_documents", False)
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        if store.count_graph_nodes(conn, binary_id) == 0:
            return _no_graph(binary_id)
        payload = graph.graph_payload(
            conn, binary_id=binary_id, kind=kind, include_documents=include_documents
        )
    return json_response(payload)


@router.get("/api/graph/nodes/{node_id}")
def get_graph_node(node_id: str) -> Response:
    """One graph node with its neighbors grouped by relation."""
    with contextlib.closing(_open()) as conn:
        try:
            detail = graph.neighbors(conn, node_id=node_id)
        except KeyError:
            return json_error(404, error="node not found", detail=f"no graph node {node_id}")
    return json_response(detail)


# ── Knowledge-graph backends ───────────────────────────────────────


def _backend_name(
    request: Request,
) -> str | None:
    """The ``?backend=`` query value, or None to use the configured backend."""
    raw = request.query_params.get("backend")
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip()


@router.get("/api/graph/backends")
def graph_backend_list() -> Response:
    """The registered graph backends and the configured default."""
    return json_response(
        {
            "backends": [backend.describe() for backend in graph_backends.graph_backends()],
            "default": graph_backends.configured_backend_name(),
        }
    )


@router.post("/api/binaries/{binary_id}/graph/sync")
def sync_binary_graph(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Push a binary's stored graph to a backend and return its report.

    The optional body is ``{"backend": "..."}``; without one the configured
    backend runs.  An unknown binary or backend is 404, a body that is not an
    object or names a non-string backend is 400 ``invalid body``, a binary
    without a stored graph is 404 ``no-graph``, and an uninstalled backend is
    503 ``backend-unavailable`` carrying its install hint.
    """
    raw = body.get("backend")
    if raw is not None and (not isinstance(raw, str) or not raw.strip()):
        return json_error(400, error="invalid body", detail="backend must be a non-empty string")
    name = raw.strip() if isinstance(raw, str) else None
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            report = graph_backends.sync_graph(conn, binary_id=binary_id, backend_name=name)
        except graph_backends.UnknownBackendError as exc:
            return json_error(404, error="backend not found", detail=str(exc))
        except graph_backends.GraphNotBuiltError:
            return _no_graph(binary_id)
        except graph_backends.BackendUnavailableError as exc:
            return json_error(503, error="backend-unavailable", detail=exc.reason)
    return json_response(report)


@router.get("/api/graph/query")
def graph_query(request: Request) -> Response:
    """Query a graph backend that supports it; ``?q=`` is the text.

    The configured backend runs when ``?backend=`` names none.  An unknown
    backend is 404, an unavailable backend 503 ``backend-unavailable``, and one
    without query support 400 ``query-unsupported``.
    """
    name = (
        _backend_name(
            request,
        )
        or graph_backends.configured_backend_name()
    )
    raw_query = request.query_params.get("q", "")
    text = raw_query if isinstance(raw_query, str) else ""
    with contextlib.closing(_open()) as conn:
        try:
            backend = graph_backends.get_graph_backend(name)
        except graph_backends.UnknownBackendError as exc:
            return json_error(404, error="backend not found", detail=str(exc))
        if not backend.available():
            return json_error(
                503,
                error="backend-unavailable",
                detail=backend.unavailable_reason(),
            )
        if not graph_backends.backend_supports_query(backend):
            return json_error(
                400,
                error="query-unsupported",
                detail=f"graph backend {backend.name!r} does not support query",
            )
        result = graph_backends.run_query(
            backend,
            conn,
            query=text,
            limit=graph_backends.DEFAULT_QUERY_LIMIT,
            visible_to=_caller(request),
        )
    return json_response(result)


# ── Artifact ratings ───────────────────────────────────────────────
#
# The hosted portal's agent cards each carry a thumbs up/down on the result.
# Locally an "agent artifact" is a stored scan: triage, threat, capabilities,
# remediation and the rest.  One small table records the analyst's verdict per
# stored artifact, so a re-run keeps it.


@router.get("/api/binaries/{binary_id}/ratings")
def list_artifact_ratings(binary_id: int) -> Response:
    """Every stored agent artifact of the binary with the analyst's verdict on it.

    An artifact that was never produced is left out; one that was produced but
    not rated carries `rating: null`, so the two are distinguishable.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        payload = ratings.describe(conn, binary_id)
    return json_response(payload)


@router.get("/api/binaries/{binary_id}/ratings/{kind}")
def get_artifact_rating(binary_id: int, kind: str) -> Response:
    """One artifact's rating, whether or not a verdict is stored."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        try:
            ratings.require_artifact(conn, binary_id, kind)
        except ratings.RatingError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)
        stored = ratings.get_rating(conn, binary_id=binary_id, kind=kind)
    return json_response({"binary_id": binary_id, "kind": kind, "rating": stored})


@router.put("/api/binaries/{binary_id}/ratings/{kind}")
def set_artifact_rating(
    binary_id: int, kind: str, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Record or clear the analyst's verdict on one stored artifact; journaled.

    The body is ``{"rating": "up"|"down"|null, "note"?: "..."}``; an empty
    rating clears the verdict rather than storing an empty one, and the write is
    journaled, so a revert restores what was there.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = ratings.journaled_set(
                    conn,
                    log,
                    binary_id=binary_id,
                    kind=kind,
                    rating=body.get("rating"),
                    note=body.get("note"),
                    actor=journal.current_actor(),
                )
            except ratings.RatingError as exc:
                return json_error(
                    400 if exc.code == ratings.ERROR_INVALID else 404,
                    error=exc.code,
                    detail=exc.detail,
                )
    return json_response(log.attach(result))


# ── Analytics ──────────────────────────────────────────────────────
#
# The dashboard's time series over rows the workspace already holds: analyses
# created, the software type each one's binary derives, auto runs started and
# journaled actions (the local analogue of the hosted portal's credit count).
# Nothing is stored, so a chart cannot drift from the lists it summarizes.


@router.get("/api/stats/series")
def stats_series(request: Request) -> Response:
    """The dashboard series over the last ``?days=`` days (30 by default).

    ``days`` is bounded by :data:`analytics.MAX_SERIES_DAYS`; every day in the
    window is present, a quiet one with a zero.  A binary whose software type
    cannot be derived counts as ``unknown`` rather than being dropped, and the
    payload's ``notes`` says when the derivation stopped at its bound.
    """
    requested = _query_int(request, "days")
    days = analytics.DEFAULT_SERIES_DAYS if requested is None else requested
    try:
        analytics.normalize_days(int(days))
    except analytics.SeriesError as exc:
        return json_error(400, error="invalid days", detail=exc.detail)
    with contextlib.closing(_open()) as conn:
        payload = analytics.series(conn, days=int(days), visible_to=_caller(request))
    return json_response(payload)


# ── Search ─────────────────────────────────────────────────────────


@router.get("/api/search")
def search(request: Request) -> Response:
    """Search the store by substring or by one typed query.

    ``?q=`` is the query and ``?kind=`` one of :data:`reportal.store.SEARCH_KINDS`
    (default ``all``, the substring behaviour the route always had).  ``sha256``
    matches a binary hash prefix, ``binary`` a binary name, ``collection`` a
    collection name and ``tag`` a tag name; each row carries the richer metadata
    the store holds (size, format, arch, created, tags) plus the ``match`` kind
    that made it hit, and ``counts`` reports each group's returned count against
    its matched total.  ``?limit=`` bounds each group.  A typed query the store
    refuses (an ambiguous or malformed hash prefix, an unknown kind) answers its
    own 400.

    ``?regex=true`` matches the query as a regular expression instead of a
    substring (bounded, cached, and 400 ``invalid regex`` when it does not
    compile), and a repeated ``?string=`` on the function list below is the
    any-of form of the same idea.
    """
    query = request.query_params.get("q", "")
    query = query if isinstance(query, str) else ""
    kind = request.query_params.get("kind", store.SEARCH_KIND_ALL)
    kind = kind if isinstance(kind, str) and kind.strip() else store.SEARCH_KIND_ALL
    regex = _query_flag(request, "regex")
    limit = _query_int(request, "limit")
    if limit is not None and not 1 <= limit <= store.MAX_SEARCH_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {store.MAX_SEARCH_LIMIT}",
        )
    with contextlib.closing(_open()) as conn:
        try:
            results = store.search(
                conn,
                query,
                kind=kind,
                limit=limit or store.DEFAULT_SEARCH_LIMIT,
                visible_to=_caller(request),
                regex=regex,
            )
        except store.SearchError as exc:
            return json_error(400, error=exc.code, detail=exc.detail)
    return json_response({"query": query, "kind": kind, "regex": regex, **results})


async def _request_form(request: Request) -> Any:
    """Parse a multipart or urlencoded body, or return the 400 for a bad one.

    The caller checks ``isinstance(result, Response)``.  A body the reader
    cannot follow is a 400 ``invalid-body``, the refusal the Bottle route
    answered: Starlette wraps most parse failures in a 400 of its own (which
    :mod:`reportal.server` maps), and this catches the ones it lets through.
    """
    try:
        return await request.form()
    except (MultiPartException, MultipartParseError):
        return json_error(400, error="invalid-body", detail="malformed multipart body")


def _form_text(value: object) -> str:
    """A non-file form field as text ("" for a missing field or a file part)."""
    return value if isinstance(value, str) else ""


# ── Uploads ────────────────────────────────────────────────────────
#
# The one group that is a behaviour port rather than a mechanical one: the
# parts arrive as ``UploadFile`` objects (Starlette has already parsed the
# multipart body and spooled each part), and the route streams the spool into
# its content-addressed home under ``MAX_UPLOAD_BYTES``.
#
# ``ponytail:`` the spool is Starlette's, so a part over 1 MiB lands in the
# system temp directory before the cap is checked -- the Bottle path streamed
# straight into ``binaries/``.  The cap still decides what is stored; if the
# transient temp usage ever matters, parse the body here with a bounded
# ``request.stream()`` reader instead of ``UploadFile``.


def _upload_batch(
    request: Request, files: Sequence[UploadFile], raw_options: Any, name: str
) -> Response:
    """Upload many files in one journaled action, reporting each one.

    A refusal or a duplicate is an entry on the result rather than a failed
    request, so the files that succeeded stay registered.  The whole request is
    one journal action: reverting its ``journal_action`` removes every binary
    the batch created, the tags it applied and the collections it joined.
    """
    if len(files) > MAX_UPLOAD_FILES:
        return json_error(
            400,
            error="too-many-files",
            detail=f"a batch upload carries at most {MAX_UPLOAD_FILES} files",
        )
    if name:
        return json_error(
            400,
            error="invalid-body",
            detail="name files through the 'files' field in a batch upload",
        )
    options = _file_options(raw_options, len(files))
    for entry in options:
        fmt = _file_option_str(entry, "format")
        if fmt and fmt not in UPLOAD_FORMATS:
            return json_error(
                400,
                error="invalid-body",
                detail=f"file option format must be one of {', '.join(UPLOAD_FORMATS)}",
            )
        arch = _file_option_str(entry, "arch")
        if arch and arch not in UPLOAD_ARCHITECTURES:
            return json_error(
                400,
                error="invalid-body",
                detail=f"file option arch must be one of {', '.join(UPLOAD_ARCHITECTURES)}",
            )
    directory = binaries_dir()
    with contextlib.closing(_open()) as conn:
        known = {int(row["id"]) for row in store.list_collections(conn)}
        for entry in options:
            unknown = [
                cid for cid in _file_option_int_list(entry, "collection_ids") if cid not in known
            ]
            if unknown:
                return json_error(
                    404, error="collection not found", detail=f"no collection with id {unknown[0]}"
                )
        scopes: list[tuple[int | None, str] | None] = []
        try:
            scopes = [_upload_scope(request, conn, entry) for entry in options]
        except auth.AuthError as exc:
            return _team_failure(exc)
        results: list[dict[str, Any]] = []
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            for upload, entry, scope in zip(files, options, scopes, strict=True):
                results.append(_upload_entry(conn, log, request, upload, entry, directory, scope))
        payload = log.attach(
            {
                "files": results,
                "count": len(results),
                "duplicates": sum(1 for row in results if row["duplicate"]),
                "errors": sum(1 for row in results if row["error"] is not None),
            }
        )
    return json_response(payload)


@router.post("/api/binaries")
async def upload_binary(request: Request) -> Response:
    """Register binaries from a multipart upload, deduped by content hash.

    One ``file`` part is the single-file upload and answers that binary's row
    with a ``duplicate`` flag, unchanged.  Repeated ``file`` parts (optionally
    described by a JSON ``files`` field, entry *i* per part, carrying a ``name``,
    ``tags``, ``collection_ids``, an explicit ``format``/``arch`` hint and the
    ``visibility``/``team_id`` scope the binary should carry) are a
    batch: every created binary, applied tag, collection link and scope change is
    recorded in **one** journal action, so reverting its ``journal_action`` takes
    the whole request back.  Each entry answers the same refusal vocabulary as the
    single-file path.  A compiler hint has no column in reportal's binary model
    (the hosted portal's Platform hint has no local meaning), so it is not stored;
    the scope does have one, and an entry that names none leaves the binary public
    and ownerless as before.

    The form is read here rather than declared as ``File``/``Form`` parameters
    so that a part which is not a file is a missing file (400 ``no-file``), as
    the Bottle route answered.  Storing the parts then runs on the threadpool:
    copying a spooled part into ``binaries/`` and hashing it blocks.

    The stored file is named by sha256 plus a suffix taken from the client
    filename only when it matches :data:`_UPLOAD_SUFFIX`, so the client name
    never becomes a path component.  The upload is streamed to a temporary file
    in the workspace `binaries/` directory and published with ``os.replace``,
    so a partial write is never visible as a finished binary.
    """
    form = await _request_form(request)
    if isinstance(form, Response):
        return form
    files = [part for part in form.getlist("file") if isinstance(part, UploadFile)]
    name = _form_text(form.get("name"))
    options = _form_text(form.get("files")) or None
    return await run_in_threadpool(_register_uploads, request, files, name, options)


def _register_uploads(
    request: Request, files: list[UploadFile], name: str, options: str | None
) -> Response:
    """Store the parts of one upload request (the blocking half of the route)."""
    if not files:
        return json_error(400, error="no-file", detail="multipart body needs a 'file' part")
    if len(files) > 1 or (options is not None and options.strip()):
        return _upload_batch(request, files, options, name)

    upload = files[0]
    raw_name = str(upload.filename or "")
    display = name or _client_name(raw_name)
    directory = binaries_dir()
    try:
        temp, sha256, size = _stream_upload(upload, directory)
    except _PartError as exc:
        return json_error(exc.status, error=exc.error, detail=exc.detail)
    if size == 0:
        temp.unlink(missing_ok=True)
        return json_error(400, error="empty-file", detail="uploaded file is empty")
    with contextlib.closing(_open()) as conn:
        existing = store.find_binary_by_sha256(conn, sha256)
        if existing is not None:
            temp.unlink(missing_ok=True)
            return json_response({**existing, "duplicate": True})
        suffix = _upload_suffix(raw_name)
        target = directory / f"{sha256}{suffix}"
        os.replace(temp, target)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            binary_id = store.add_binary(
                conn,
                sha256=sha256,
                name=display or sha256,
                path=str(target),
                size=size,
                fmt=suffix.lstrip(".").upper(),
            )
            log.record(
                effects.EFFECT_FILE_DELETE,
                f"stored uploaded file {target}",
                journal.file_delete_descriptor(str(target)),
            )
            log.record(
                effects.EFFECT_ROW_DELETE,
                f"registered binary {binary_id}",
                journal.row_delete_descriptor("binaries", binary_id),
            )
        row = store.get_binary(conn, binary_id)
        payload = log.attach({**(row or {}), "duplicate": False})
    return json_response(payload)


@router.post("/api/binaries/{binary_id}/documents")
async def ingest_binary_document(binary_id: int, request: Request) -> Response:
    """Ingest one document file scoped to a binary.

    The body is ``multipart/form-data`` with a ``file`` part and an optional
    ``title`` field, mirroring the binary upload: the part is read into a
    bounded buffer, its client filename supplies the source and the format, and
    the same bytes twice in the scope return the stored document with
    ``duplicate: true``.
    """
    form = await _request_form(request)
    if isinstance(form, Response):
        return form
    upload = form.get("file")
    if not isinstance(upload, UploadFile):
        return json_error(400, error="no-file", detail="multipart body needs a 'file' part")
    title = _form_text(form.get("title"))
    return await run_in_threadpool(_ingest_document, binary_id, upload, title)


def _ingest_document(binary_id: int, upload: UploadFile, title: str) -> Response:
    """Read one document part and store it (the blocking half of the route)."""
    filename = _client_name(str(upload.filename or ""))
    if not knowledge.is_supported_name(filename):
        return json_error(
            400,
            error=knowledge.ERROR_UNSUPPORTED_FORMAT,
            detail=f"{filename or 'upload'} is not a supported text format",
        )
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        data = _read_upload(upload, knowledge.MAX_DOCUMENT_BYTES)
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                payload = knowledge.ingest_document(
                    conn,
                    scope_kind=knowledge.SCOPE_KIND_BINARY,
                    scope_id=binary_id,
                    title=title or filename,
                    source=filename,
                    mime=str(upload.content_type or ""),
                    data=data,
                )
            except knowledge.KnowledgeError as exc:
                return _knowledge_error(exc)
            journal.journaled_ingest(conn, log, payload)
    return _ingested(log.attach(payload))


# ── Health, comments and the download ──────────────────────────────
#
# The first group ported here, kept together as it was written.

# ── Health ─────────────────────────────────────────────────────────


def _database_health(path: Path) -> dict[str, Any]:
    """Whether the SQLite file accepts a write, tested without writing.

    A permission check on the file and its directory, not a query and not a
    write: it takes no SQLite lock and cannot contend with a running auto run.
    A path with no write permission reports not writable, which is what the
    caller sees when the workspace is read-only or full.
    """
    try:
        writable = os.access(path, os.W_OK) and os.access(path.parent, os.W_OK)
    except OSError:
        writable = False
    detail = "" if writable else f"no write permission on {path} or its directory"
    return {"writable": writable, "detail": detail}


def _engine_health() -> dict[str, Any]:
    """Where the in-process rebrew engine comes from, and whether it is there.

    ``origin`` is the installed ``rebrew`` package's path, or null when the
    package is not importable; the probe never imports the engine or spawns
    anything.
    """
    engine = engines.get_engine()
    return {"available": engine.available(), "origin": engine.origin}


def _last_auto_run(conn: Any) -> dict[str, Any] | None:
    """The newest auto run as a summary, or None before the first one.

    One SELECT over ``auto_runs``; the run's task tree is not read.
    """
    runs = auto_store.list_auto_runs(conn)
    if not runs:
        return None
    run = runs[0]
    return {
        "run_id": int(run["id"]),
        "binary_id": int(run["binary_id"]),
        "status": str(run["status"]),
        "finished_at": run["finished_at"],
    }


def _jobs_health(conn: Any) -> dict[str, Any]:
    """Queue depth and whether this process will drain it.

    Two COUNT queries over ``jobs``; the process-local done/failed totals live
    under the top-level ``jobs`` key beside ``http``, not here.
    """
    return {
        "queued": jobs.count_jobs(conn, status=jobs.STATUS_QUEUED),
        "running": jobs.count_jobs(conn, status=jobs.STATUS_RUNNING),
        "pool": not jobs.pool_disabled(),
    }


@router.get("/api/doctor")
def doctor_report(request: Request) -> Response:
    """The pre-flight half of ``GET /api/health``, over HTTP.

    ``health`` answers from inside a running server; it cannot check the two
    things a start depends on, the SPA build and a free port.  This is
    ``doctor.report`` with an optional ``?port=`` (default 8002, 0 or blank
    skips the bind probe), so a remote caller gets the same readiness a unit
    file gates on.  Every check is a read: nothing is written and no database
    is created, and the answer is 200 with the same ``ok``/``degraded``
    vocabulary either way.
    """
    raw = request.query_params.get("port")
    if raw is None or not raw.strip():
        port = doctor.DEFAULT_PORT
    else:
        try:
            port = int(raw)
        except ValueError:
            return json_error(400, error="port must be an integer")
    return json_response(doctor.report(port=port))


@router.get("/api/health")
def health() -> Response:
    """Liveness plus dependency readiness: version, db path, counts, deps.

    The pre-existing keys (``status``, ``version``, ``db``, ``counts``) are
    unchanged, and a live server always answers 200: a degraded dependency is
    reported under ``dependencies`` and named in ``failures`` rather than
    turned into an error, because the process is still serving.  ``http`` is
    the process-local request counters since start (rate, 4xx/5xx, latency
    sum and max), and ``jobs`` is the matching done/failed/latency snapshot
    for background work, so an operator can read RED for both the request
    path and the queue without a separate metrics scrape.
    ``dependencies.jobs`` is the live queue depth (queued/running) and whether
    this process's pool is draining it.

    Every probe is cheap and side-effect free.  The database check is a
    permission test (no query, no write, no SQLite lock); the engine is read
    from the process-wide cached ``engines.get_engine()``, whose availability
    probe imports nothing and spawns nothing; the last auto run is a single
    SELECT.  The request adds no subprocess and no write.
    """
    path = db_path()
    # Open without init_db: health must not upgrade schema, and a read-only
    # database must still answer rather than 500 on ALTER TABLE.
    jobs_dep: dict[str, Any] = {
        "queued": 0,
        "running": 0,
        "pool": not jobs.pool_disabled(),
    }
    try:
        with contextlib.closing(store.connect(path)) as conn:
            counts = store.counts(conn)
            last_run = _last_auto_run(conn)
            jobs_dep = _jobs_health(conn)
    except (sqlite3.Error, OSError):
        counts = {
            "binaries": 0,
            "analyses": 0,
            "functions": 0,
            "matched": 0,
            "matches": 0,
            "comments": 0,
            "collections": 0,
            "families": 0,
            "documents": 0,
            "chunks": 0,
        }
        last_run = None
    database = _database_health(path)
    dependencies = {
        "database": database,
        "engine": _engine_health(),
        "auto": {"last_run": last_run},
        "jobs": jobs_dep,
    }
    failures = [] if database["writable"] else ["database"]
    return json_response(
        {
            "status": "ok",
            "version": __version__,
            "db": str(path),
            "counts": counts,
            "dependencies": dependencies,
            "failures": failures,
            "http": observability.http_snapshot(),
            "jobs": observability.job_snapshot(),
        }
    )


@router.get("/api/config")
def config() -> Response:
    """What this instance can do: versions, features, limits and counts.

    The hosted portal answers ``GET /v2/config`` with the same idea.  Every
    field is a read: no engine call runs, nothing is written and no network
    request is made, so a client can fetch this on start.  A feature that is
    off is reported as off rather than omitted, and the guarded paths (the AI
    bridge and URL ingestion) are off until the workspace opts in.
    """
    return json_response(instance.describe())


# ── Binaries ───────────────────────────────────────────────────────

# Content type a stored binary's suffix names, and the one every other suffix
# gets.  A fixed table rather than ``mimetypes``: the stdlib type map is read
# from the host's files, which makes the answer differ per machine.
BINARY_CONTENT_TYPES: dict[str, str] = {
    ".exe": "application/vnd.microsoft.portable-executable",
    ".dll": "application/vnd.microsoft.portable-executable",
    ".sys": "application/vnd.microsoft.portable-executable",
    ".ocx": "application/vnd.microsoft.portable-executable",
    ".elf": "application/x-elf",
    ".so": "application/x-sharedlib",
}
DEFAULT_BINARY_CONTENT_TYPE = "application/octet-stream"

# Bytes one read of a streaming download takes.  ``POST /api/binaries`` accepts
# up to MAX_UPLOAD_BYTES (256 MiB), so a stored binary can be large; reading it
# whole would hold all of it in memory for every concurrent download.
BINARY_DOWNLOAD_CHUNK_BYTES = 1024 * 1024

# A stored binary is content-addressed (``<sha256><suffix>``), so its bytes can
# never change under that name: a client may keep the answer indefinitely.
BINARY_DOWNLOAD_CACHE_CONTROL = "public, max-age=31536000, immutable"


def _binary_content_type(path: Path) -> str:
    """The content type of a stored binary, from its suffix or the default."""
    return BINARY_CONTENT_TYPES.get(path.suffix.lower(), DEFAULT_BINARY_CONTENT_TYPE)


def _stream_file(path: Path, chunk_bytes: int = BINARY_DOWNLOAD_CHUNK_BYTES) -> Iterator[bytes]:
    """Yield *path*'s bytes in bounded chunks, closing the file when done."""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_bytes)
            if not chunk:
                return
            yield chunk


def _streamed_binary(binary: Mapping[str, Any]) -> Response:
    """The streaming download response for a stored binary row.

    Shared by the binary download and the analysis ``bytes`` read, so both stream
    the same file the same way.  The row's own file is read in
    :data:`BINARY_DOWNLOAD_CHUNK_BYTES` chunks, named by
    :func:`reportal.binary_actions.download_filename` and cacheable
    indefinitely because the stored bytes are content-addressed.  A row whose
    file is gone is 404 `binary not on disk`.
    """
    binary_id = int(binary["id"])
    path = Path(str(binary["path"]))
    if not path.is_file():
        return json_error(
            404,
            error="binary not on disk",
            detail=f"binary {binary_id} has no file at {binary['path']!r}",
        )
    return StreamingResponse(
        _stream_file(path),
        media_type=_binary_content_type(path),
        headers={
            "Content-Disposition": f'attachment; filename="{download_filename(binary)}"',
            "Content-Length": str(path.stat().st_size),
            "Cache-Control": BINARY_DOWNLOAD_CACHE_CONTROL,
        },
    )


@router.get("/api/binaries/{binary_id}/download")
def download_binary(binary_id: int) -> Response:
    """Stream the stored bytes of one binary as a named attachment.

    The file is read in :data:`BINARY_DOWNLOAD_CHUNK_BYTES` chunks and yielded
    as it is read rather than returned as one body: ``POST /api/binaries``
    accepts up to :data:`MAX_UPLOAD_BYTES` (256 MiB), so a single ``read()``
    would hold the whole binary in the server's memory for every concurrent
    download.

    The filename comes from the stored name, never from the request, and is
    sanitized by :func:`download_filename`; ``Content-Length`` is the stored
    file's own byte count, the content type comes from its suffix, and the
    answer is cacheable indefinitely because the bytes are content-addressed.
    An unknown id is 404 `binary not found`; a row whose file is gone is 404
    `binary not on disk` with the path it looked for (the engine routes answer
    400 for that condition, but a download is of a representation that is gone,
    so it is a not-found here).
    """
    with contextlib.closing(db()) as conn:
        binary = store.get_binary(conn, binary_id)
    if binary is None:
        return json_error(404, error="binary not found", detail=f"no binary with id {binary_id}")
    return _streamed_binary(binary)


# ── Comments ───────────────────────────────────────────────────────


def _comment_failure(exc: comments.CommentError) -> Response:
    """Map a comment validation failure onto its JSON status and error name."""
    detail = str(exc.args[0]) if exc.args else str(exc)
    if isinstance(exc, comments.InvalidCommentError):
        return json_error(400, error="invalid comment", detail=detail)
    if isinstance(exc, comments.UnknownScopeError):
        return json_error(404, error=f"{exc.scope_kind} not found", detail=detail)
    return json_error(404, error="comment not found", detail=detail)


def _comment_text(body: dict[str, Any]) -> str:
    """Return the ``body`` field of a comment request, or a 400."""
    value = body.get("body")
    if not isinstance(value, str):
        raise json_error(400, error="invalid comment", detail="body must be a string")
    return value


def _list_scope_comments(
    scope_kind: str, scope_id: int, visible_to: dict[str, Any] | None = None
) -> Response:
    with contextlib.closing(db()) as conn:
        try:
            rows = comments.list_comments(
                conn, scope_kind=scope_kind, scope_id=scope_id, visible_to=visible_to
            )
        except comments.CommentError as exc:
            return _comment_failure(exc)
    return json_response({"comments": rows})


def _add_scope_comment(scope_kind: str, scope_id: int, body: dict[str, Any]) -> Response:
    text = _comment_text(body)
    author = body.get("author")
    if author is not None and not isinstance(author, str):
        return json_error(400, error="invalid comment", detail="author must be a string")
    with contextlib.closing(db()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                created = comments.add_comment(
                    conn,
                    scope_kind=scope_kind,
                    scope_id=scope_id,
                    body=text,
                    author=author,
                )
            except comments.CommentError as exc:
                return _comment_failure(exc)
            log.record(
                effects.EFFECT_ROW_DELETE,
                f"stored comment {created['id']}",
                journal.row_delete_descriptor("comments", int(created["id"])),
            )
    return json_response(log.attach(created), status=201)


@router.get("/api/binaries/{binary_id}/comments")
def list_binary_comments(request: Request, binary_id: int) -> Response:
    """Analyst comments stored on one binary, oldest first."""
    return _list_scope_comments(comments.SCOPE_BINARY, binary_id, visible_to=_caller(request))


@router.post("/api/binaries/{binary_id}/comments")
def add_binary_comment(binary_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Store one analyst comment on a binary; body ``{"body", "author"?}``."""
    return _add_scope_comment(comments.SCOPE_BINARY, binary_id, body)


@router.get("/api/functions/{function_id}/comments")
def list_function_comments(request: Request, function_id: int) -> Response:
    """Analyst comments stored on one function, oldest first."""
    return _list_scope_comments(comments.SCOPE_FUNCTION, function_id, visible_to=_caller(request))


@router.post("/api/functions/{function_id}/comments")
def add_function_comment(function_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Store one analyst comment on a function; body ``{"body", "author"?}``."""
    return _add_scope_comment(comments.SCOPE_FUNCTION, function_id, body)


@router.patch("/api/comments/{comment_id}")
def update_comment(comment_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Replace one comment's body; body ``{"body"}``."""
    text = _comment_text(body)
    with contextlib.closing(db()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn, table="comments", where="id = ?", params=(comment_id,)
            )
            try:
                updated = comments.update_comment(conn, comment_id, body=text)
            except comments.CommentError as exc:
                return _comment_failure(exc)
            if before:
                log.record(
                    effects.EFFECT_ROW_RESTORE,
                    f"edited comment {comment_id}",
                    journal.row_restore_descriptor("comments", before),
                )
    return json_response(log.attach(updated))


@router.delete("/api/comments/{comment_id}")
def delete_comment(comment_id: int) -> Response:
    """Delete one comment by id."""
    with contextlib.closing(db()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            before = journal.snapshot_rows(
                conn, table="comments", where="id = ?", params=(comment_id,)
            )
            try:
                deleted = comments.delete_comment(conn, comment_id)
            except comments.CommentError as exc:
                return _comment_failure(exc)
            if before:
                log.record(
                    effects.EFFECT_ROW_RESTORE,
                    f"deleted comment {comment_id}",
                    journal.row_restore_descriptor("comments", before),
                )
    payload = {"comment": deleted, "comment_id": comment_id, "deleted": True}
    return json_response(log.attach(payload))


# ── Jobs ───────────────────────────────────────────────────────────
#
# The asynchronous operation workflow: a queue, a status, a cancel and an
# event stream over the operations `jobs.JOB_KINDS` names.  The queued form of
# a scan is `POST /api/jobs` with its kind and binary rather than a flag on
# every scan route, so one route serves every operation the registry holds.


@router.get("/api/jobs")
def list_jobs(request: Request) -> Response:
    """Queued and finished jobs, newest first.

    ``?status=`` is one of :data:`reportal.jobs.STATUSES`, ``?kind=`` one of the
    registered job kinds and ``?limit=`` is bounded by
    :data:`reportal.jobs.MAX_JOB_LIMIT`; an unknown value is a 400.  ``total``
    counts every job matching the filters, so a bounded page never reads as the
    whole queue, and ``queued`` counts what is still waiting.
    """
    status = _query_text(request, "status")
    if status is not None and status not in jobs.STATUSES:
        return _invalid_query("status", status, jobs.STATUSES)
    kind = _query_text(request, "kind")
    if kind is not None and kind not in jobs.JOB_KINDS:
        return _invalid_query("kind", kind, sorted(jobs.JOB_KINDS))
    binary_id = _query_int(request, "binary_id")
    limit = _query_int(request, "limit")
    if limit is not None and not 1 <= limit <= jobs.MAX_JOB_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {jobs.MAX_JOB_LIMIT}",
        )
    with contextlib.closing(_open()) as conn:
        rows, total = jobs.list_jobs(
            conn,
            status=status,
            kind=kind,
            binary_id=binary_id,
            limit=limit or jobs.DEFAULT_JOB_LIMIT,
            visible_to=_caller(request),
        )
        queued = jobs.count_jobs(conn, status=jobs.STATUS_QUEUED, visible_to=_caller(request))
    return json_response(
        {
            "jobs": rows,
            "count": len(rows),
            "total": total,
            "queued": queued,
            # Both closed vocabularies the listing accepts, so the SPA's
            # controls are built from the registry rather than written twice.
            "statuses": list(jobs.STATUSES),
            "kinds": [
                {"name": spec.name, "label": spec.label, "params": list(spec.params)}
                for spec in jobs.JOB_KINDS.values()
            ],
        }
    )


@router.get("/api/jobs/{job_id}")
def get_job(request: Request, job_id: int) -> Response:
    """One job with its status, progress and result or error."""
    with contextlib.closing(_open()) as conn:
        job = jobs.visible_job(conn, job_id, _caller(request))
    if job is None:
        return json_error(404, error="job not found", detail=f"no job with id {job_id}")
    return json_response(job)


@router.post("/api/jobs")
def submit_job(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Queue one operation and answer it with its run id.

    The body is ``{"kind", "binary_id", "params"?}``; the response is the queued
    job, which a client polls on ``GET /api/jobs/<id>`` or follows on
    ``GET /api/jobs/<id>/events``.  The work runs in the bounded background pool
    the server starts on the first submit, so the request returns at once.
    """
    kind = _require_str(body, "kind")
    binary_id = _require_int(body, "binary_id")
    raw_params = body.get("params")
    if raw_params is not None and not isinstance(raw_params, dict):
        return json_error(400, error="invalid params", detail="params must be an object")
    with contextlib.closing(_open()) as conn:
        binary = store.get_binary(conn, binary_id)
        if binary is None:
            return json_error(
                404, error="binary not found", detail=f"no binary with id {binary_id}"
            )
        if not auth.may_write(_caller(request), binary, team_ids=_caller_team_ids(conn, request)):
            return json_error(
                403,
                error=auth.ERROR_SCOPE_FORBIDDEN,
                detail=f"binary {binary_id} belongs to a team you are not a member of",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                job = jobs.submit(conn, kind=kind, binary_id=binary_id, params=raw_params or {})
            except ValueError as exc:
                return json_error(400, error="invalid job", detail=str(exc))
            except KeyError as exc:
                return json_error(404, error="binary not found", detail=str(exc.args[0]))
            journal.journaled_create(
                log,
                table=jobs.TABLE,
                key=int(job["id"]),
                description=f"queued {kind} job {job['id']} for binary {binary_id}",
            )
        job = log.attach(job)
    if jobs.ensure_worker() is None and not jobs.pool_disabled():
        # No pool could start (the process has no workspace yet), so the job
        # would sit queued forever: run it now and answer the finished row
        # rather than a run id nothing will pick up.
        with contextlib.closing(_open()) as conn:
            job = jobs.run_pending(conn, limit=1)[0]
    return json_response(job, status=202)


@router.post("/api/jobs/{job_id}/cancel")
def cancel_job(request: Request, job_id: int) -> Response:
    """Cancel a job that has not started; 409 ``job-not-cancellable`` once it has.

    A running scan has already entered the engine, so the cancel refuses rather
    than reporting a stop that would not happen: the caller either waits for the
    result or leaves it running.
    """
    with contextlib.closing(_open()) as conn:
        if jobs.visible_job(conn, job_id, _caller(request)) is None:
            return json_error(404, error="job not found", detail=f"no job with id {job_id}")
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
                return json_error(409, error="job-not-cancellable", detail=str(exc))
    return json_response(log.attach(job or {}))


@router.post("/api/jobs/run")
def run_jobs(request: Request) -> Response:
    """Run the oldest waiting jobs inline and answer what finished.

    The server runs queued jobs in its own pool, so this is what a script, a
    test or a process without the pool uses to drain the queue deterministically;
    ``?limit=`` bounds how many run in the call.
    """
    limit = _query_int(request, "limit")
    if limit is not None and not 1 <= limit <= jobs.MAX_JOB_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {jobs.MAX_JOB_LIMIT}",
        )
    with contextlib.closing(_open()) as conn:
        finished = jobs.run_pending(conn, limit=limit or 1)
    return json_response({"jobs": finished, "count": len(finished)})


@router.get("/api/jobs/{job_id}/events")
def job_events(request: Request, job_id: int) -> Response:
    """The job's state as server-sent events, ending when the job is terminal.

    One ``event: job`` frame per observed change, the current state first so a
    client that attaches late is not left blank, and a ``timeout`` frame when
    the stream's cap is reached, which tells a client to reconnect and read the
    state again rather than hold a socket open.
    """
    with contextlib.closing(_open()) as conn:
        if jobs.visible_job(conn, job_id, _caller(request)) is None:
            return json_error(404, error="job not found", detail=f"no job with id {job_id}")

    def stream() -> Any:
        with contextlib.closing(_open()) as conn:
            yield from jobs.events(conn, job_id)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


# ── Data types and signatures, in bulk ─────────────────────────────
#
# The hosted bulk halves: copy one function's signature onto many, create or
# update an analysis's types from caller-supplied definitions, read many
# signatures at once and read the functions that use one type.  Each write is
# journaled through the shared surface helper, so one action covers the batch
# and a revert puts every row back.


# The bound every bulk read and write shares: a batch is a caller's list, not a
# corpus dump, so an id list or a definition list past this is a 400.
_BATCH_ID_LIMIT = 200


def _id_list(request: Request, name: str) -> list[int] | None:
    """Parse a comma-separated id query parameter, or None when it is unusable."""
    raw = request.query_params.get(name)
    if raw is None:
        return None
    text = raw.strip()
    if not text:
        return []
    parts = [part.strip() for part in text.split(",")]
    if len(parts) > _BATCH_ID_LIMIT:
        return None
    ids: list[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        ids.append(int(part))
    return ids


def _batch_ids(request: Request) -> list[int] | None:
    """The ids a batch read names (``?ids=``), or None when unusable.

    None means a 400: the list is empty, malformed, or longer than
    :data:`function_extras.MAX_FUNCTIONS_PER_QUERY`, so a caller cannot ask a
    single read to walk the corpus.
    """
    ids = _id_list(request, "ids")
    if ids is None or not ids or len(ids) > function_extras.MAX_FUNCTIONS_PER_QUERY:
        return None
    return ids


def _body_ids(body: dict[str, Any]) -> list[int] | None:
    """The function ids a batch body names (``{"function_ids": [...]}``), or None."""
    raw = body.get("function_ids")
    if not isinstance(raw, list) or not raw:
        return None
    if len(raw) > function_extras.MAX_FUNCTIONS_PER_QUERY:
        return None
    ids: list[int] = []
    for entry in raw:
        if isinstance(entry, bool) or not isinstance(entry, int):
            return None
        ids.append(entry)
    return ids


def _batch_error() -> Response:
    """The 400 every function batch read and write answers for an unusable list."""
    return json_error(
        400,
        error="invalid function_ids",
        detail=(
            "name between 1 and"
            f" {function_extras.MAX_FUNCTIONS_PER_QUERY} function ids (ids= or function_ids)"
        ),
    )


def _definition_list(body: dict[str, Any]) -> list[Any] | None:
    """The ``types`` a bulk data-type route carries, or None when unusable.

    A single string is accepted as a whole C header and split into its top-level
    declarations server-side, so a caller does not have to know where a struct
    ends; a list is taken as the declarations it is.
    """
    raw = body.get("types")
    if isinstance(raw, str):
        raw = data_types.split_definitions(raw)
    if not isinstance(raw, list) or not raw:
        return None
    if len(raw) > data_types.MAX_BULK_DEFINITIONS:
        return None
    if any(not isinstance(entry, (str, dict)) for entry in raw):
        return None
    return raw


@router.post("/api/analyses/{analysis_id}/signatures/copy")
def copy_analysis_signatures(
    analysis_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Copy one function's signature onto many in the same analysis; journaled.

    The body is ``{"source_function_id": int, "targets": [int, ...]}``.  A
    target that is the source, is unknown, or cannot take the copy is skipped
    with its reason and keeps its signature; the whole batch is one action.
    """
    raw_source = body.get("source_function_id")
    if isinstance(raw_source, bool) or not isinstance(raw_source, int):
        return json_error(
            400, error="invalid source", detail="source_function_id must be an integer"
        )
    raw_targets = body.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        return json_error(400, error="invalid targets", detail="targets must be a non-empty list")
    if len(raw_targets) > _BATCH_ID_LIMIT or any(
        isinstance(entry, bool) or not isinstance(entry, int) for entry in raw_targets
    ):
        return json_error(
            400,
            error="invalid targets",
            detail=f"targets must be at most {_BATCH_ID_LIMIT} function ids",
        )
    targets = [int(entry) for entry in raw_targets]
    with contextlib.closing(_open()) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        function_ids = {
            int(row["id"]) for row in store.list_functions(conn, analysis_id=analysis_id)
        }
        if int(raw_source) not in function_ids:
            return json_error(
                404,
                error="function not found",
                detail=f"function {raw_source} is not in analysis {analysis_id}",
            )
        outsiders = [target for target in targets if target not in function_ids]
        if outsiders:
            return json_error(
                404,
                error="function not found",
                detail=f"function(s) {outsiders} are not in analysis {analysis_id}",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            report: dict[str, Any] = {
                "source_function_id": int(raw_source),
                "targets": targets,
                "applied": [],
                "skipped": [],
                "count": 0,
            }

            def _copy(target: int) -> dict[str, Any]:
                return signatures.copy_signature(conn, source_id=int(raw_source), targets=[target])

            for target in targets:
                try:
                    result = _journal_signature_write(
                        conn,
                        log,
                        target,
                        f"copied the signature of function {raw_source} onto function {target}",
                        partial(_copy, target),
                    )
                except signatures.SignatureError as exc:
                    report["skipped"].append({"function_id": target, "reason": str(exc)})
                    continue
                if result["applied"]:
                    report["applied"].append(target)
                else:
                    report["skipped"].extend(result["skipped"])
            report["count"] = len(report["applied"])
    return json_response(log.attach(report))


@router.post("/api/analyses/{analysis_id}/data-types")
def create_analysis_data_types(
    analysis_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Create data types for an analysis's binary from C definitions; journaled.

    The body is ``{"types": ["typedef struct {...} Foo;", ...]}`` (an entry may
    also be an object carrying its declaration under ``definition``).  Each
    definition is parsed by the same parser the structs import uses; an
    unusable one is skipped with its reason rather than guessed at, and the
    batch is one journaled action, one entry per type.
    """
    return _bulk_analysis_data_types(analysis_id, body, create=True)


@router.put("/api/analyses/{analysis_id}/data-types")
def update_analysis_data_types(
    analysis_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Update an analysis's existing data types from C definitions; journaled.

    The same body as the bulk create, but a definition naming a type the binary
    does not carry is skipped ``no stored type named ...`` rather than created,
    which is what makes this the update half of the hosted pair.
    """
    return _bulk_analysis_data_types(analysis_id, body, create=False)


def _bulk_analysis_data_types(analysis_id: int, body: dict[str, Any], *, create: bool) -> Response:
    """Shared body of the bulk create and update data-type routes."""
    definitions = _definition_list(body)
    if definitions is None:
        return json_error(
            400,
            error="invalid types",
            detail=(
                "types must be a non-empty list of at most"
                f" {data_types.MAX_BULK_DEFINITIONS} definitions"
            ),
        )
    with contextlib.closing(_open()) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        binary_id = int(analysis["binary_id"])
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            report = surface.bulk_data_type_definitions(
                conn, log, binary_id=binary_id, definitions=definitions, create=create
            )
    return json_response(log.attach(report))


@router.get("/api/analyses/{analysis_id}/data-types/{data_type_id}/functions")
def get_data_type_functions(analysis_id: int, data_type_id: int) -> Response:
    """The functions that use one data type, from the stored reference index.

    The type must belong to the analysis's binary; the payload is the reference
    report the `/api/data-types/<id>/references` route serves, so the two cannot
    disagree about who uses a type.
    """
    with contextlib.closing(_open()) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        data_type = store.get_data_type(conn, data_type_id)
        if data_type is None or int(data_type["binary_id"]) != int(analysis["binary_id"]):
            return json_error(
                404,
                error="data type not found",
                detail=f"no data type {data_type_id} in analysis {analysis_id}",
            )
        report = data_types.references(conn, data_type_id)
    return json_response(report)


# ── Function-level extras ──────────────────────────────────────────
#
# The hosted function reads and writes that sit on top of a stored
# decompilation: indirect call sites, per-function capabilities, the function's
# strings (the analyst's and the derived literals), analyst-declared callee
# edges and the two batch reads.  Everything derived comes from rows reportal
# already holds and says so; the only writes are the analyst's own.


def _function_or_404(conn: sqlite3.Connection, function_id: int) -> Response | None:
    """The 404 a function-scoped route answers for an unknown id, or None."""
    if store.get_function(conn, function_id) is None:
        return json_error(
            404, error="function not found", detail=f"no function with id {function_id}"
        )
    return None


@router.get("/api/functions/{function_id}/indirect-call-sites")
def get_indirect_call_sites(function_id: int) -> Response:
    """The indirect calls and jumps in a function's cached listing.

    The listing is `disasm_cache`'s when the function has one; a function with
    no cached listing answers an empty list with a note saying the scan reads the
    cache rather than spawning the engine behind a read.
    """
    with contextlib.closing(_open()) as conn:
        missing = _function_or_404(conn, function_id)
        if missing is not None:
            return missing
        cached = store.get_disasm(conn, function_id)
        rows = function_extras.indirect_call_sites(cached or "")
    return json_response(
        {
            "function_id": function_id,
            "sites": rows,
            "count": len(rows),
            "has_disassembly": cached is not None,
            "derivation": function_extras.DERIVATION,
            "note": function_extras.CALL_SITE_NOTE,
        }
    )


@router.get("/api/functions/{function_id}/capabilities")
def get_function_capabilities(function_id: int) -> Response:
    """Classify one function from the imports and literals its decompilation mentions."""
    with contextlib.closing(_open()) as conn:
        missing = _function_or_404(conn, function_id)
        if missing is not None:
            return missing
        try:
            payload = function_extras.function_capabilities(conn, function_id)
        except function_extras.EdgeError as exc:
            return json_error(404, error="function not found", detail=exc.detail)
    return json_response(payload)


@router.get("/api/functions/{function_id}/strings")
def get_function_strings(request: Request, function_id: int) -> Response:
    """The analyst's strings for a function, and the literals its decompilation carries."""
    with contextlib.closing(_open()) as conn:
        missing = _function_or_404(conn, function_id)
        if missing is not None:
            return missing
        try:
            payload = user_strings.function_strings(conn, function_id, visible_to=_caller(request))
        except user_strings.UnknownStringError as exc:
            return json_error(404, error="function not found", detail=exc.detail)
    return json_response(payload)


@router.post("/api/functions/{function_id}/strings")
def add_function_string(function_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Record one analyst string for a function; journaled.

    The body is ``{"value": "...", "kind"?, "note"?}``; a value already recorded
    at the scope updates its note rather than adding a second row.
    """
    value = body.get("value")
    kind = body.get("kind")
    note = body.get("note")
    with contextlib.closing(_open()) as conn:
        missing = _function_or_404(conn, function_id)
        if missing is not None:
            return missing
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
            except user_strings.StringError as exc:
                return json_error(
                    400 if exc.code == user_strings.ERROR_INVALID else 404,
                    error=exc.code,
                    detail=exc.detail,
                )
    return json_response(log.attach(row))


@router.delete("/api/functions/{function_id}/strings/{string_id}")
def delete_function_string(function_id: int, string_id: int) -> Response:
    """Remove one analyst string from a function; journaled."""
    with contextlib.closing(_open()) as conn:
        missing = _function_or_404(conn, function_id)
        if missing is not None:
            return missing
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
                return json_error(404, error=exc.code, detail=exc.detail)
    return json_response(log.attach(row))


@router.get("/api/functions/{function_id}/callees")
def get_function_callees(request: Request, function_id: int) -> Response:
    """A function's derived callees and its analyst-declared edges.

    The derived half is a text scan of the stored decompilation against the
    binary's function names, and the declared half is what an analyst recorded;
    the two are reported separately rather than merged.
    """
    with contextlib.closing(_open()) as conn:
        missing = _function_or_404(conn, function_id)
        if missing is not None:
            return missing
        rows = function_extras.callers_and_callees(
            conn, [function_id], visible_to=_caller(request)
        )["functions"]
    payload: dict[str, Any] = (
        rows[0] if rows else {"function_id": function_id, "callees": [], "declared": []}
    )
    callees: list[Any] = list(payload.get("callees") or [])
    declared: list[Any] = list(payload.get("declared") or [])
    return json_response(
        {
            **payload,
            "count": len(callees),
            "declared_count": len(declared),
            "derivation": function_extras.DERIVATION,
        }
    )


@router.post("/api/functions/{function_id}/callees")
def add_function_callee(function_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Record one analyst-declared callee edge; journaled.

    The body is ``{"callee": "<name>", "kind"?: "call"|"indirect", "note"?}``.
    The edge is the analyst's claim, not a scan: it is stored with source
    ``analyst`` and reported beside the derived callees.
    """
    callee = body.get("callee")
    kind = body.get("kind")
    note = body.get("note")
    with contextlib.closing(_open()) as conn:
        missing = _function_or_404(conn, function_id)
        if missing is not None:
            return missing
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
                return json_error(
                    400 if exc.code == function_extras.ERROR_INVALID else 404,
                    error=exc.code,
                    detail=exc.detail,
                )
    return json_response(log.attach(row))


@router.delete("/api/functions/{function_id}/callees/{edge_id}")
def delete_function_callee(function_id: int, edge_id: int) -> Response:
    """Remove one analyst-declared callee edge; journaled."""
    with contextlib.closing(_open()) as conn:
        missing = _function_or_404(conn, function_id)
        if missing is not None:
            return missing
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = function_extras.journaled_delete_edge(
                    conn,
                    log,
                    function_id=function_id,
                    edge_id=edge_id,
                    description=f"removed an edge of function {function_id}",
                )
            except function_extras.EdgeError as exc:
                return json_error(404, error=exc.code, detail=exc.detail)
    return json_response(log.attach(row))


@router.post("/api/analyses/{analysis_id}/strings")
def add_analysis_string(analysis_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Record one analyst string at analysis scope; journaled."""
    value = body.get("value")
    kind = body.get("kind")
    note = body.get("note")
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                row = user_strings.journaled_add(
                    conn,
                    log,
                    scope_kind=user_strings.SCOPE_ANALYSIS,
                    scope_id=analysis_id,
                    value=value,
                    kind=kind,
                    note=note,
                    actor=journal.current_actor(),
                    description=f"stored a string for analysis {analysis_id}",
                )
            except user_strings.StringError as exc:
                return json_error(
                    400 if exc.code == user_strings.ERROR_INVALID else 404,
                    error=exc.code,
                    detail=exc.detail,
                )
    return json_response(log.attach(row))


@router.get("/api/analyses/{analysis_id}/strings")
def list_analysis_strings(request: Request, analysis_id: int) -> Response:
    """Every analyst string recorded at analysis scope."""
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        rows = user_strings.list_strings(
            conn,
            scope_kind=user_strings.SCOPE_ANALYSIS,
            scope_id=analysis_id,
            visible_to=_caller(request),
        )
    return json_response({"analysis_id": analysis_id, "strings": rows, "count": len(rows)})


@router.put("/api/analyses/{analysis_id}/strings")
def replace_analysis_strings(
    analysis_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Replace an analysis's whole analyst string list; journaled.

    The body is ``{"strings": ["...", ...]}``.  The hosted `PUT` is the whole
    list at once, so this removes what is there and writes what the body names,
    in order; every value is validated before anything is written.
    """
    raw_values = body.get("strings")
    if not isinstance(raw_values, list):
        return json_error(400, error="invalid string", detail="strings must be a list of values")
    values: list[Any] = raw_values
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
                return json_error(400, error=exc.code, detail=exc.detail)
    return json_response(log.attach(report))


# ── Debug symbols ──────────────────────────────────────────────────
#
# A symbol file is the one name source reportal cannot derive: the engine's
# annotations, library identification and the rename paths all guess, while a
# PDB or an ELF/DWARF table states what the toolchain knew.  The upload is
# content-addressed beside the workspace's `binaries/` directory, parsed by the
# stdlib readers in `symbols.py`, and applied as one journaled action.


def _symbol_or_404(conn: sqlite3.Connection, binary_id: int) -> Response | None:
    """The 404 a symbol route answers for an unknown binary, or None."""
    if store.get_binary(conn, binary_id) is None:
        return json_error(404, error="binary not found", detail=f"no binary with id {binary_id}")
    return None


@router.post("/api/binaries/{binary_id}/symbols")
async def upload_symbols(binary_id: int, request: Request) -> Response:
    """Ingest a debug symbol file: parse it, apply its names and store its types.

    The body is a multipart upload with one ``file`` part (a PDB or an ELF with
    DWARF) and an optional ``apply`` field, which is false to store the parse
    without touching a name or a type.  The file is streamed into the
    workspace's ``symbols/`` directory under its SHA-256, so a re-upload of the
    same bytes lands on the same path and is one more ingest row, and the parse
    is bounded and reported in full (its notes say what the reader did not do).
    The import is one journaled action.
    """
    form = await _request_form(request)
    if isinstance(form, Response):
        return form
    files = [part for part in form.getlist("file") if isinstance(part, UploadFile)]
    if not files:
        return json_error(400, error="no-file", detail="multipart body needs a 'file' part")
    if len(files) > 1:
        return json_error(400, error="too-many-files", detail="one symbol file per request")
    raw_apply = _form_text(form.get("apply")).strip().lower()
    apply = raw_apply not in {"false", "0", "no", "off"}
    return await run_in_threadpool(_ingest_symbols, binary_id, files[0], apply, request)


def _ingest_symbols(
    binary_id: int, upload: UploadFile, apply: bool, request: Request | None = None
) -> Response:
    """Store and parse one uploaded symbol file (the blocking half of the route)."""
    directory = _paths.project_root() / symbols.SYMBOLS_DIR
    try:
        directory.mkdir(parents=True, exist_ok=True)
        temp, _sha256, _size = _stream_upload(upload, directory)
    except _PartError as exc:
        return json_error(exc.status, error=exc.error, detail=exc.detail)
    except OSError as exc:
        return json_error(500, error="write-failed", detail=str(exc))
    try:
        data = temp.read_bytes()
    except OSError as exc:
        temp.unlink(missing_ok=True)
        return json_error(500, error="write-failed", detail=str(exc))
    if not data:
        temp.unlink(missing_ok=True)
        return json_error(400, error="empty-file", detail="uploaded file is empty")
    try:
        parsed = symbols.parse(data, filename=str(upload.filename or ""))
    except symbols.UnreadableSymbolError as exc:
        temp.unlink(missing_ok=True)
        return json_error(400, error=exc.code, detail=exc.detail)
    target = directory / symbols.digest(data)
    os.replace(temp, target)
    with contextlib.closing(_open()) as conn:
        if not _visible_binary(conn, binary_id, _caller(request) if request is not None else None):
            return json_error(
                404, error="binary not found", detail=f"no binary with id {binary_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            report = symbols.import_symbols(
                conn,
                log,
                binary_id=binary_id,
                data=data,
                parsed=parsed,
                path=str(target),
                apply=apply,
            )
    return json_response(log.attach(report))


@router.get("/api/binaries/{binary_id}/symbols")
def list_symbols(binary_id: int) -> Response:
    """Every symbol file ingested for one binary, newest first.

    Answers 404 ``no-symbols`` when none was ingested, which is the difference
    between "this binary has no symbols" and "the names came from elsewhere".
    """
    with contextlib.closing(_open()) as conn:
        missing = _symbol_or_404(conn, binary_id)
        if missing is not None:
            return missing
        rows = symbols.list_files(conn, binary_id)
    if not rows:
        return json_error(
            404, error="no-symbols", detail=f"binary {binary_id} has no ingested symbol file"
        )
    return json_response({"binary_id": binary_id, "symbol_files": rows, "count": len(rows)})


@router.get("/api/binaries/{binary_id}/symbols/export")
def export_symbols(binary_id: int, request: Request) -> Response:
    """Render one ingested parse as JSON or as a C header.

    ``?format=c`` (the default) reuses the type model's renderer, so the header
    and the editable model cannot disagree; ``?format=json`` answers the parse
    itself.  ``?file_id=`` names one ingest; without it the newest is exported.
    """
    kind = _query_text(request, "format") or "c"
    if kind not in ("c", "json"):
        return json_error(400, error="invalid format", detail="format must be c or json")
    file_id = _query_int(request, "file_id")
    with contextlib.closing(_open()) as conn:
        missing = _symbol_or_404(conn, binary_id)
        if missing is not None:
            return missing
        try:
            row = symbols.get_file(
                conn, binary_id=binary_id, file_id=int(file_id) if file_id else None
            )
        except symbols.UnknownSymbolFileError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)
    text = symbols.render_symbols(row["parsed"], kind=kind)
    return Response(
        content=text,
        media_type="application/json" if kind == "json" else "text/plain",
        headers={"Content-Disposition": f'inline; filename="symbols.{kind}"'},
    )


@router.get("/api/binaries/{binary_id}/decompiler-script")
def export_decompiler_script(binary_id: int, request: Request) -> Response:
    """Render the stored renames as a runnable decompiler script.

    ``?format=ghidra`` (the default) answers a Ghidra Python script,
    ``?format=ida`` an IDA script and ``?format=binja`` a JSON rename
    document.  Stored-only: placeholders are left out, so the script only
    carries names a decompiler would not already show.
    """
    fmt = (_query_text(request, "format") or decompiler_scripts.FORMAT_GHIDRA).lower()
    if fmt not in decompiler_scripts.SCRIPT_FORMATS:
        return json_error(
            400,
            error="invalid format",
            detail=f"format must be one of {', '.join(decompiler_scripts.SCRIPT_FORMATS)}",
        )
    with contextlib.closing(_open()) as conn:
        try:
            payload = decompiler_scripts.script(conn, binary_id, fmt=fmt)
        except decompiler_scripts.ScriptError as exc:
            return json_error(404, error=exc.code, detail=exc.detail)
    return Response(
        content=payload["text"],
        media_type=decompiler_scripts.MEDIA_TYPES[fmt],
        headers={"Content-Disposition": f'inline; filename="{decompiler_scripts.FILENAMES[fmt]}"'},
    )


# ── Documentation ──────────────────────────────────────────────────
#
# The portal ships its own manual: `docs/*.md` and `CHANGELOG.md` are read from
# the workspace, the checkout or an explicit `REPORTAL_DOCS` override and served
# as structured blocks, which the SPA renders without any markup injection.  A
# page's slug is its filename stem, so `GET /api/docs/errors` is `docs/ERRORS.md`.


@router.get("/api/docs")
def list_docs() -> Response:
    """Every shipped documentation page, in reading order."""
    try:
        listing = docs_mod.pages()
    except docs_mod.NoDocsError as exc:
        return json_error(404, error=exc.code, detail=exc.detail)
    return json_response({"pages": listing, "count": len(listing)})


@router.get("/api/docs/{slug}")
def get_doc(slug: str) -> Response:
    """One page's title, its on-this-page headings and its blocks."""
    try:
        payload = docs_mod.page(slug)
    except docs_mod.DocsError as exc:
        return json_error(404, error=exc.code, detail=exc.detail)
    return json_response(payload)


# ── Models ─────────────────────────────────────────────────────────
#
# The hosted portal runs an analysis under a named model and can upgrade it to a
# newer one.  Locally a stored result comes from the engine, one decompiler
# backend, the configured bridge model or the optional similarity extra, and the
# registry names all of them so an analysis can record which one produced it.


@router.get("/api/models")
def list_models() -> Response:
    """Every registered model with its kind, version and availability."""
    return json_response(models.describe())


@router.post("/api/analyses/{analysis_id}/upgrade")
def upgrade_analysis_model(analysis_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Re-run one analysis's stored LLM artifacts under a named model.

    The body is ``{"model": "<name>"}`` plus the optional ``functions`` id list
    and ``limit``.  reportal re-runs the artifacts the analysis already stored
    (a summary, inline comments, type suggestions, identifier renames); it never
    re-analyses the binary, which is the one thing the hosted upgrade does that
    has no local equivalent.  Every replaced artifact is journaled, so the
    previous payloads are what a revert of the returned action restores.
    """
    name = _require_str(body, "model")
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        try:
            functions = models.normalize_function_ids(body.get("functions"))
            limit = models.normalize_limit(body.get("limit"))
            target = models.upgradeable_model(name)
        except models.UnknownModelError as exc:
            return json_error(404, error="model not found", detail=str(exc))
        except (models.NotUpgradeableError, models.InvalidModelError) as exc:
            return json_error(400, error="invalid model", detail=str(exc))
        except llm.LlmUnavailable as exc:
            return json_error(503, error="llm-unavailable", detail=str(exc))
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            result = models.upgrade_analysis(
                conn,
                log,
                analysis_id=analysis_id,
                model=target.name,
                functions=functions,
                limit=limit,
            )
    return json_response(log.attach(result))


# ── External sources ───────────────────────────────────────────────
#
# What a third party says about a stored binary.  The offline source derives an
# answer from the rows reportal already holds; the remote one pulls a
# VirusTotal file report and is off unless the workspace opts in and a key
# resolves.  An answer is stored as the `external:<source>` scan on the
# analysis, so a re-pull replaces it and a revert removes it.


def _external_failure(exc: external.ExternalError) -> Response:
    """Map an external-source failure onto its JSON status and error name."""
    if isinstance(exc, external.UnknownSourceError):
        status = 404
    elif isinstance(exc, external.DisabledExternalError):
        status = 403
    elif isinstance(exc, external.UnavailableExternalError):
        status = 503
    elif isinstance(exc, external.NoContentHashError):
        status = 400
    elif exc.code == "analysis not found":
        status = 404
    else:
        status = 502
    return json_error(status, error=exc.code, detail=exc.detail)


@router.get("/api/external/sources")
def list_external_sources() -> Response:
    """The registered sources with their kind, availability and the remote gate."""
    return json_response(external.describe())


@router.post("/api/analyses/{analysis_id}/external/{source}")
def run_external_source(analysis_id: int, source: str) -> Response:
    """Run one source for an analysis and store its answer; journaled.

    The offline source never makes a request.  The remote one is refused 403
    `external-disabled` while the workspace has not opted in, 503
    `external-unavailable` when no key resolves, 400 `no-content-hash` when the
    binary has no SHA-256 to look up, and 502 `external-fetch-failed` when the
    call itself fails; nothing is stored on a failure.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                result = external.journaled_run(
                    conn,
                    log,
                    analysis_id=analysis_id,
                    source_name=source,
                    description=f"pulled the {source} external report",
                )
            except external.ExternalError as exc:
                return _external_failure(exc)
    return json_response(log.attach(result))


@router.get("/api/analyses/{analysis_id}/external/{source}")
def get_external_report(analysis_id: int, source: str) -> Response:
    """The stored answer of one source; 404 `no-scan` before the first pull."""
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        try:
            stored = external.stored(conn, analysis_id=analysis_id, source_name=source)
        except external.UnknownSourceError as exc:
            return _external_failure(exc)
    if stored is None:
        return json_error(
            404,
            error="no-scan",
            detail=(
                f"the {source} source has not run for analysis {analysis_id}; "
                f"run POST /api/analyses/{analysis_id}/external/{source}"
            ),
        )
    return json_response(stored)


@router.get("/api/analyses/{analysis_id}/external/{source}/status")
def get_external_status(analysis_id: int, source: str) -> Response:
    """Whether one source can run for an analysis and what is stored for it."""
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        try:
            payload = external.status(conn, analysis_id=analysis_id, source_name=source)
        except external.ExternalError as exc:
            return _external_failure(exc)
    return json_response(payload)


# ── Analysis lifecycle ─────────────────────────────────────────────
#
# The hosted analyses surface beyond list/create/delete: read one, its status
# and its recorded parameters, its function map, per-analysis tags (which are
# the owning binary's tags locally, the only scoping reportal has), an engine
# relabel, a log append and a requeue.  Every write is journaled and revertible
# like the rest of the portal.


@router.get("/api/analyses/{analysis_id}")
def get_analysis_detail(analysis_id: int) -> Response:
    """One analysis with its counts, its scans and its binary's tags.

    The hosted ``basic`` read.  ``scans`` names each stored scan kind and its
    status, ``function_count`` and ``log_count`` are the true totals and
    ``tags`` are the owning binary's, since that is the scope reportal tags at.
    """
    with contextlib.closing(_open()) as conn:
        detail = store.analysis_detail(conn, analysis_id)
    if detail is None:
        return json_error(
            404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
        )
    return json_response(detail)


@router.get("/api/analyses/{analysis_id}/status")
def get_analysis_status(analysis_id: int) -> Response:
    """The lifecycle read: status, times, scans and log counts by severity."""
    with contextlib.closing(_open()) as conn:
        status = store.analysis_status(conn, analysis_id)
    if status is None:
        return json_error(
            404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
        )
    return json_response(status)


@router.get("/api/analyses/{analysis_id}/params")
def get_analysis_params(analysis_id: int) -> Response:
    """What a re-run of this analysis would need, read from the stored rows.

    The engine label, the binary with its content hash and identity, the rebrew
    project context the engine calls resolve against, and the scan kinds already
    stored, so a re-run is reproducible and a missing input is visible.
    """
    with contextlib.closing(_open()) as conn:
        params = store.analysis_params(conn, analysis_id)
    if params is None:
        return json_error(
            404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
        )
    return json_response(params)


@router.get("/api/analyses/{analysis_id}/func-maps")
def get_analysis_func_maps(analysis_id: int) -> Response:
    """The analysis's function map: every function's address, name and size.

    Ordered by address, which is the order a reader walks a binary in.  An
    analysis with no functions answers an empty map rather than a 404.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        functions = store.list_functions(conn, analysis_id=analysis_id, sort="va", order="asc")
        total = store.count_functions(conn, analysis_id=analysis_id)
    return json_response(
        {
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
    )


@router.get("/api/analyses/{analysis_id}/imported-functions")
def get_analysis_imported_functions(analysis_id: int, request: Request) -> Response:
    """The analysis's import stubs, each with the functions that mention it.

    The hosted read groups the imported functions of an analysis and lists their
    callers.  reportal stores no call graph, so a caller is a function whose
    stored decompilation carries the stub's name and the payload names that
    method (``caller_method``) instead of passing a text match off as an edge the
    engine reported.  ``?limit=`` bounds the stubs returned; ``total`` is the
    true count.
    """
    limit = _query_int(request, "limit")
    limit = store.DEFAULT_IMPORTED_LIMIT if limit is None else limit
    if not 1 <= limit <= store.MAX_IMPORTED_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {store.MAX_IMPORTED_LIMIT}",
        )
    with contextlib.closing(_open()) as conn:
        payload = store.imported_functions(conn, analysis_id, limit=limit)
    if payload is None:
        return json_error(
            404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
        )
    return json_response(payload)


@router.get("/api/analyses/{analysis_id}/bytes")
def get_analysis_bytes(analysis_id: int) -> Response:
    """The bytes of the analysis's binary, streamed exactly as its download is.

    The hosted ``/bytes`` read is what the download route already serves for the
    binary; this resolves the analysis to its binary first so a caller that has
    only an analysis id does not need a second lookup.
    """
    with contextlib.closing(_open()) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        binary = None if analysis is None else store.get_binary(conn, int(analysis["binary_id"]))
    if analysis is None:
        return json_error(
            404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
        )
    if binary is None:
        return json_error(
            404,
            error="binary not found",
            detail=f"analysis {analysis_id} names binary {analysis['binary_id']}",
        )
    return _streamed_binary(binary)


@router.patch("/api/analyses/{analysis_id}")
def update_analysis(analysis_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Relabel one analysis's engine; journaled.

    The engine label is the one field the hosted update route carries that has a
    local meaning, and it is what tells two analyses of one binary apart.  An
    empty body is a 400, because an update that changes nothing is a mistake
    rather than a no-op.
    """
    if "engine" not in body:
        return json_error(400, error="invalid body", detail="provide engine")
    engine = _require_str(body, "engine")
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table="analyses",
                where="id = ?",
                params=(analysis_id,),
                description=f"relabelled analysis {analysis_id}",
            )
            updated = store.update_analysis(conn, analysis_id, engine=engine)
    return json_response(log.attach(updated or {}))


@router.post("/api/analyses/{analysis_id}/logs")
def append_analysis_log(analysis_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Append one log entry to an analysis; journaled.

    ``severity`` is one of :data:`reportal.analysis_log.SEVERITIES` and defaults
    to ``info``; the message must not be blank.  An analyst records what they
    did beside what the scans logged.
    """
    message = _require_str(body, "message")
    severity = _optional_str(body, "severity") or analysis_log.SEVERITY_INFO
    if severity not in analysis_log.SEVERITIES:
        return _invalid_query("severity", severity, analysis_log.SEVERITIES)
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            entry_id = analysis_log.append_entry(
                conn, analysis_id, message=message, severity=severity
            )
            journal.journaled_create(
                log,
                table=analysis_log.TABLE,
                key=entry_id,
                description=f"logged an entry on analysis {analysis_id}",
            )
    return json_response(
        log.attach(
            {"id": entry_id, "analysis_id": analysis_id, "severity": severity, "message": message}
        ),
        status=201,
    )


@router.post("/api/analyses/{analysis_id}/requeue")
def requeue_analysis(analysis_id: int) -> Response:
    """Put an analysis back to ``pending`` and clear its finish time; journaled.

    Locally the scans are the engine calls, so this moves the lifecycle row and
    leaves the caller to queue the work it wants (`POST /api/jobs` with a scan
    kind); the transition is logged.
    """
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
    return json_response(log.attach(updated or {}))


@router.get("/api/analyses/{analysis_id}/tags")
def list_analysis_tags(analysis_id: int) -> Response:
    """The tags on the analysis's binary, which is the scope reportal tags at."""
    with contextlib.closing(_open()) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        tags = store.get_binary_tags(conn, int(analysis["binary_id"]))
    return json_response({"analysis_id": analysis_id, "tags": tags})


@router.patch("/api/analyses/{analysis_id}/tags")
def set_analysis_tags(analysis_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Replace the tags on the analysis's binary, the scope reportal tags at.

    Body ``{"tags": ["name", ...]}``; a name that does not exist yet is created.
    Journaled tag by tag, so a revert puts the previous set back.
    """
    raw = body.get("tags")
    if not isinstance(raw, list) or any(not isinstance(name, str) for name in raw):
        return json_error(400, error="invalid body", detail="tags must be a list of names")
    wanted = [name.strip() for name in raw if name.strip()]
    with contextlib.closing(_open()) as conn:
        analysis = store.get_analysis(conn, analysis_id)
        if analysis is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        binary_id = int(analysis["binary_id"])
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            current = {
                str(tag["name"]): int(tag["id"]) for tag in store.get_binary_tags(conn, binary_id)
            }
            for name in sorted(set(wanted) - set(current)):
                created_tag = store.find_tag(conn, name) is None
                tag_id = store.create_tag(conn, name)
                if created_tag:
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
            for name in sorted(set(current) - set(wanted)):
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
            tags = store.get_binary_tags(conn, binary_id)
    return json_response(log.attach({"analysis_id": analysis_id, "tags": tags}))


# ── Identity and users ─────────────────────────────────────────────
#
# Token auth is off unless the environment or the workspace config turns it on,
# so a single-user loopback install keeps working unchanged.  When it is on,
# the middleware has already resolved the caller and every request below
# is authenticated; the user table itself needs the `admin` permission.  A user
# row's token digest never reaches a response: only the token a create or a
# rotation hands back once does.


def _auth_failure(exc: auth.AuthError) -> Response:
    """Map a user validation failure onto its JSON status and error name."""
    if isinstance(exc, auth.UserExistsError):
        status = 409
    elif isinstance(exc, auth.UnknownUserError):
        status = 404
    else:
        status = 400
    return json_error(status, error=exc.code, detail=exc.detail)


def _caller(request: Request) -> dict[str, Any] | None:
    """The authenticated caller, or None while auth is off."""
    user = getattr(request.state, "user", None)
    return user if isinstance(user, dict) else None


def _visible_binary_ids(conn: sqlite3.Connection, caller: dict[str, Any] | None) -> set[int] | None:
    """The binary ids *caller* may reach, or None for no restriction.

    None means auth is off or the caller is an admin; otherwise the shared
    `auth.visible_clause` lists the visible binaries once for the whole
    request, so a bulk action checks membership without a query per id.
    """
    scope = auth.visible_clause(conn, caller, prefix="b.")
    if scope is None:
        return None
    clause, params = scope
    return {
        int(row["id"])
        for row in conn.execute(f"SELECT b.id AS id FROM binaries b WHERE {clause}", params)
    }


def _visible_binary(
    conn: sqlite3.Connection, binary_id: int, caller: dict[str, Any] | None
) -> bool:
    """Whether *caller* may see *binary_id*: present and in the visible set."""
    if store.get_binary(conn, binary_id) is None:
        return False
    allowed = _visible_binary_ids(conn, caller)
    return allowed is None or binary_id in allowed


@router.get("/api/iam/me")
def iam_me(request: Request) -> Response:
    """Who the caller is and what it may do.

    With auth off the install is a single local user and the answer says so
    (``auth: "open"``, every permission); with it on the answer is the
    authenticated user with its role and the permissions that role carries.
    """
    user = _caller(request)
    if user is None:
        return json_response(
            {
                "auth": "open",
                "user": None,
                "role": None,
                "permissions": list(auth.ROLE_PERMISSIONS[auth.ROLE_ADMIN]),
                "teams": [],
            }
        )
    role = str(user["role"])
    with contextlib.closing(_open()) as conn:
        teams = auth.teams_of_user(conn, int(user["id"]))
    return json_response(
        {
            "auth": "required",
            "user": user,
            "role": role,
            "permissions": list(auth.permissions_for(role)),
            "teams": teams,
        }
    )


@router.get("/api/iam/me/permissions")
def iam_me_permissions(request: Request) -> Response:
    """The permission list the caller's role carries, nothing else."""
    user = _caller(request)
    role = None if user is None else str(user["role"])
    return json_response(
        {
            "role": role,
            "auth": "open" if user is None else "required",
            "permissions": list(
                auth.permissions_for(role) if role else auth.ROLE_PERMISSIONS[auth.ROLE_ADMIN]
            ),
            "roles": list(auth.ROLES),
        }
    )


@router.get("/api/users")
def list_users() -> Response:
    """Every user with its role and state; the token digest is never included."""
    with contextlib.closing(db()) as conn:
        users = auth.list_users(conn)
    return json_response({"users": users, "count": len(users)})


@router.post("/api/users")
def create_user(body: dict[str, Any] = Depends(json_body)) -> Response:
    """Create one user and return its token once; journaled and revertible."""
    name = _require_str(body, "name")
    role = _optional_str(body, "role", auth.ROLE_ANALYST)
    with contextlib.closing(db()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                user, token = auth.add_user(conn, name=name, role=role)
            except auth.AuthError as exc:
                return _auth_failure(exc)
            journal.journaled_create(
                log,
                table=auth.TABLE,
                key=int(user["id"]),
                description=f"created user {user['name']}",
            )
    return json_response(log.attach({**user, "token": token}), status=201)


@router.patch("/api/users/{user_id}")
def update_user(user_id: int, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Set one user's role or disabled flag; journaled and revertible."""
    if "role" not in body and "disabled" not in body:
        return json_error(400, error=auth.ERROR_INVALID_USER, detail="provide role or disabled")
    role = _optional_str(body, "role") if "role" in body else None
    if role is not None and role not in auth.ROLES:
        return _invalid_query("role", role, auth.ROLES)
    disabled = body.get("disabled")
    if disabled is not None and not isinstance(disabled, bool):
        return json_error(400, error=auth.ERROR_INVALID_USER, detail="disabled must be a boolean")
    with contextlib.closing(db()) as conn:
        if auth.get_user(conn, user_id) is None:
            return json_error(
                404, error=auth.ERROR_USER_NOT_FOUND, detail=f"no user with id {user_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
                return _auth_failure(exc)
    return json_response(log.attach(updated or {}))


@router.post("/api/users/{user_id}/token")
def rotate_user_token(user_id: int) -> Response:
    """Replace one user's token and return the new one once; journaled."""
    with contextlib.closing(db()) as conn:
        if auth.get_user(conn, user_id) is None:
            return json_error(
                404, error=auth.ERROR_USER_NOT_FOUND, detail=f"no user with id {user_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TABLE,
                where="id = ?",
                params=(user_id,),
                description=f"rotated the token of user {user_id}",
            )
            token = auth.rotate_token(conn, user_id)
    return json_response(log.attach({"id": user_id, "token": token}))


@router.delete("/api/users/{user_id}")
def delete_user(user_id: int) -> Response:
    """Delete one user; journaled, so a revert puts the row back."""
    with contextlib.closing(db()) as conn:
        if auth.get_user(conn, user_id) is None:
            return json_error(
                404, error=auth.ERROR_USER_NOT_FOUND, detail=f"no user with id {user_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TABLE,
                where="id = ?",
                params=(user_id,),
                description=f"deleted user {user_id}",
            )
            auth.delete_user(conn, user_id)
    return json_response(log.attach({"deleted": user_id}))


# ── Secret store ───────────────────────────────────────────────────
#
# Named credentials at workspace or team scope.  A read never returns the value:
# the routes serve the name, scope, byte length and a last-four hint, and the
# value itself is reachable only through `secret_store.value_of`, which an
# internal consumer calls on the caller's behalf.  A write is journaled, so a
# rotation is revertible and the previous value is what a revert restores.


def _secret_failure(exc: secret_store.SecretError) -> Response:
    """Map a secret-store failure onto its JSON status and error name."""
    if isinstance(exc, secret_store.UnknownSecretError):
        status = 404
    elif isinstance(exc, secret_store.ForbiddenSecretError):
        status = 403
    else:
        status = 400
    return json_error(status, error=exc.code, detail=exc.detail)


def _secret_scope(body: dict[str, Any]) -> tuple[str, int | None]:
    """Validate the scope a write names, and that the caller may use it."""
    scope = _optional_str(body, "scope") or None
    raw_team = body.get("team_id")
    if raw_team is not None and (isinstance(raw_team, bool) or not isinstance(raw_team, int)):
        raise secret_store.InvalidSecretError("team_id must be an integer")
    resolved_scope, resolved_team = secret_store.normalize_scope(scope, raw_team)
    return resolved_scope, resolved_team or None


@router.get("/api/secrets")
def list_secrets(request: Request) -> Response:
    """Every secret the caller may see, redacted; `?scope=`/`?team_id=` filter.

    The value is never in the payload: a row carries the name, the scope, the
    team, the byte length and a last-four hint.
    """
    scope = request.query_params.get("scope") or None
    raw_team = request.query_params.get("team_id") or None
    if raw_team is not None and not raw_team.isdigit():
        return json_error(
            400, error=secret_store.ERROR_INVALID, detail="team_id must be an integer"
        )
    try:
        with contextlib.closing(_open()) as conn:
            rows = secret_store.list_secrets(
                conn,
                scope=scope,
                team_id=int(raw_team) if raw_team else None,
            )
            user = _caller(request)
            team_ids = _caller_team_ids(conn, request)
    except secret_store.SecretError as exc:
        return _secret_failure(exc)
    visible = [row for row in rows if secret_store.may_read(user, row, team_ids=team_ids)]
    return json_response({"secrets": visible, "count": len(visible)})


@router.put("/api/secrets/{name}")
def set_secret(name: str, request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Store or replace one secret; journaled and revertible.

    The body is ``{"value": "...", "scope": "local"|"team", "team_id": int}``
    with the scope defaulting to `team` when a team id is given and to `local`
    otherwise.  A local secret needs an admin; a team secret needs that team's
    membership.  The response carries the redacted row, never the value.
    """
    try:
        value = secret_store.normalize_value(body.get("value"))
        with contextlib.closing(_open()) as conn:
            scope, team_id = _secret_scope(body)
            if team_id is not None and auth.get_team(conn, team_id) is None:
                return json_error(
                    404, error=auth.ERROR_TEAM_NOT_FOUND, detail=f"no team with id {team_id}"
                )
            user = _caller(request)
            if not secret_store.may_write(
                user,
                team_ids=_caller_team_ids(conn, request),
                scope=scope,
                team_id=team_id,
            ):
                return json_error(
                    403,
                    error=secret_store.ERROR_FORBIDDEN,
                    detail="a workspace secret needs an admin, a team secret its members",
                )
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
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
        return _secret_failure(exc)
    return json_response(log.attach(row))


@router.delete("/api/secrets/{name}")
def delete_secret(name: str, request: Request) -> Response:
    """Remove one secret; journaled and revertible (the row is restored on revert)."""
    team_id = _query_int(request, "team_id")
    scope = request.query_params.get("scope") or None
    try:
        with contextlib.closing(_open()) as conn:
            resolved_scope, resolved_team = secret_store.normalize_scope(scope, team_id)
            user = _caller(request)
            if not secret_store.may_write(
                user,
                team_ids=_caller_team_ids(conn, request),
                scope=resolved_scope,
                team_id=resolved_team or None,
            ):
                return json_error(
                    403,
                    error=secret_store.ERROR_FORBIDDEN,
                    detail="a workspace secret needs an admin, a team secret its members",
                )
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                row = secret_store.journaled_delete(
                    conn,
                    log,
                    name=name,
                    scope=resolved_scope,
                    team_id=resolved_team or None,
                    description=f"deleted the secret {name}",
                )
    except secret_store.SecretError as exc:
        return _secret_failure(exc)
    return json_response(log.attach(row))


# ── Teams and object scope ─────────────────────────────────────────
#
# A team is the identity side of the visibility model: `binaries` and
# `collections` carry an `owner_team_id` and a `visibility` (`public` to every
# authenticated user, `team` to the owners' members).  The gate
# (`server._enforce_scope`) reads the scope off the path, so a route added later
# is covered without repeating the check; these routes are the ones that set it.


def _team_failure(exc: auth.AuthError) -> Response:
    """Map a team or organisation failure onto its JSON status and error name."""
    if isinstance(exc, (auth.TeamExistsError, auth.AuthError)) and exc.code.endswith("-exists"):
        status = 409
    elif isinstance(
        exc,
        (auth.UnknownTeamError, auth.UnknownOrganisationError, auth.UnknownUserError),
    ):
        status = 404
    elif isinstance(exc, auth.NotAMemberError):
        status = 403
    else:
        status = 400
    return json_error(status, error=exc.code, detail=exc.detail)


def _caller_team_ids(conn: sqlite3.Connection, request: Request) -> list[int]:
    """The team ids the authenticated caller belongs to; empty while auth is off."""
    user = _caller(request)
    if user is None:
        return []
    return [int(team["id"]) for team in auth.teams_of_user(conn, int(user["id"]))]


def _refuse_unless_team_manager(
    conn: sqlite3.Connection, request: Request, team_id: int
) -> Response | None:
    """403 when the caller may not manage *team_id*; None when the write may proceed."""
    if auth.may_manage_team(conn, _caller(request), team_id):
        return None
    return json_error(
        403,
        error=auth.ERROR_NOT_A_TEAM_OWNER,
        detail=f"the caller does not own team {team_id}",
    )


def _refuse_unless_organisation_access(
    conn: sqlite3.Connection, request: Request, organisation_id: int
) -> Response | None:
    """403 when the caller may not reach this organisation's billing surface."""
    if auth.may_access_organisation(conn, _caller(request), organisation_id):
        return None
    return json_error(
        403,
        error=auth.ERROR_SCOPE_FORBIDDEN,
        detail=f"organisation {organisation_id} is outside the caller's teams",
    )


def _refuse_unless_tenant_admin(request: Request) -> Response | None:
    """403 when the caller may not reshape organisations or grant plans."""
    if auth.may_administer_tenants(_caller(request)):
        return None
    return json_error(
        403,
        error=auth.ERROR_FORBIDDEN,
        detail=auth.FORBIDDEN_DETAIL,
    )


@router.get("/api/organisations")
def list_organisations() -> Response:
    """Every organisation with the teams it holds; a structural read.

    An organisation is the hosted portal's one level above teams and is not
    access control: an object's team still decides who may read or write it.
    """
    with contextlib.closing(_open()) as conn:
        organisations = auth.list_organisations(conn)
    return json_response({"organisations": organisations, "count": len(organisations)})


@router.post("/api/organisations")
def create_organisation(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Create an organisation; journaled and revertible."""
    refused = _refuse_unless_tenant_admin(request)
    if refused is not None:
        return refused
    name = _require_str(body, "name")
    description = _optional_str(body, "description")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                organisation = auth.create_organisation(conn, name=name, description=description)
            except auth.AuthError as exc:
                return _team_failure(exc)
            journal.journaled_create(
                log,
                table=auth.ORG_TABLE,
                key=int(organisation["id"]),
                description=f"created organisation {organisation['name']}",
            )
    return json_response(log.attach(organisation), status=201)


@router.get("/api/organisations/{organisation_id}")
def get_organisation(organisation_id: int) -> Response:
    """One organisation with the teams it holds."""
    with contextlib.closing(_open()) as conn:
        organisation = auth.get_organisation(conn, organisation_id)
    if organisation is None:
        return json_error(
            404,
            error=auth.ERROR_ORGANISATION_NOT_FOUND,
            detail=f"no organisation with id {organisation_id}",
        )
    return json_response(organisation)


@router.delete("/api/organisations/{organisation_id}")
def delete_organisation(organisation_id: int, request: Request) -> Response:
    """Delete an organisation; its teams stay and simply stop being grouped."""
    refused = _refuse_unless_tenant_admin(request)
    if refused is not None:
        return refused
    with contextlib.closing(_open()) as conn:
        if auth.get_organisation(conn, organisation_id) is None:
            return json_error(
                404,
                error=auth.ERROR_ORGANISATION_NOT_FOUND,
                detail=f"no organisation with id {organisation_id}",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.ORG_TABLE,
                where="id = ?",
                params=(organisation_id,),
                description=f"deleted organisation {organisation_id}",
            )
            auth.delete_organisation(conn, organisation_id)
    return json_response(log.attach({"deleted": organisation_id}))


@router.put("/api/teams/{team_id}/organisation")
def set_team_organisation(
    team_id: int, request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Move a team into an organisation, or out of every one; journaled.

    The body is ``{"organisation_id": <id>|null}``.  Filing a team under an
    organisation grants its members that organisation's billing and usage
    surface, so only a tenant admin may reshape the hierarchy; a team owner
    alone cannot attach into another tenant by guessing an id.
    """
    refused = _refuse_unless_tenant_admin(request)
    if refused is not None:
        return refused
    raw = body.get("organisation_id")
    if raw is not None and (isinstance(raw, bool) or not isinstance(raw, int)):
        return json_error(
            400, error=auth.ERROR_INVALID_ORGANISATION, detail="organisation_id must be an integer"
        )
    with contextlib.closing(_open()) as conn:
        if auth.get_team(conn, team_id) is None:
            return json_error(
                404, error=auth.ERROR_TEAM_NOT_FOUND, detail=f"no team with id {team_id}"
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TEAM_TABLE,
                where="id = ?",
                params=(team_id,),
                description=f"moved team {team_id} to organisation {raw}",
            )
            try:
                auth.set_team_organisation(conn, team_id, raw)
            except auth.AuthError as exc:
                return _team_failure(exc)
            team = auth.get_team(conn, team_id)
    return json_response(log.attach(team or {}))


# ── Plans, metering and billing ────────────────────────────────────


def _billing_failure(exc: billing.BillingError) -> Response:
    """One mapping from the billing vocabulary to the JSON error envelope."""
    return json_error(exc.status, error="billing-error", detail=exc.detail)


def _organisation_or_404(
    conn: sqlite3.Connection, organisation_id: int
) -> dict[str, Any] | Response:
    """The organisation row, or the 404 every billing route answers with."""
    organisation = auth.get_organisation(conn, organisation_id)
    if organisation is None:
        return json_error(
            404,
            error=auth.ERROR_ORGANISATION_NOT_FOUND,
            detail=f"no organisation with id {organisation_id}",
        )
    return organisation


@router.get("/api/plans")
def list_plans() -> Response:
    """Every public plan, cheapest first, with the purchasable subset named.

    The catalog is code, so this read needs no database and never varies by
    caller: it is what a pricing page renders.
    """
    return json_response(
        {
            "plans": [plan.describe() for plan in plans_mod.public_plans()],
            "checkout_plans": [plan.id for plan in plans_mod.checkout_plans()],
            "default_plan_id": plans_mod.DEFAULT_PLAN_ID,
            "currency": "usd",
            "overage_usd_per_credit": credits_mod.OVERAGE_USD_PER_CREDIT,
            "tasks": credits_mod.catalog(),
            "billing": billing.public_billing_config(),
        }
    )


@router.get("/api/organisations/{organisation_id}/usage")
def get_organisation_usage(organisation_id: int, request: Request) -> Response:
    """Metered use in the organisation's open period, against its plan."""
    with contextlib.closing(_open()) as conn:
        found = _organisation_or_404(conn, organisation_id)
        if isinstance(found, Response):
            return found
        refused = _refuse_unless_organisation_access(conn, request, organisation_id)
        if refused is not None:
            return refused
        return json_response(metering.usage_summary(conn, organisation_id))


@router.get("/api/organisations/{organisation_id}/billing")
def get_organisation_billing(organisation_id: int, request: Request) -> Response:
    """The organisation's plan, quota state and subscription, if any."""
    with contextlib.closing(_open()) as conn:
        found = _organisation_or_404(conn, organisation_id)
        if isinstance(found, Response):
            return found
        refused = _refuse_unless_organisation_access(conn, request, organisation_id)
        if refused is not None:
            return refused
        summary = metering.usage_summary(conn, organisation_id)
        subscription = billing.subscription_of(conn, organisation_id)
    return json_response(
        {
            **summary,
            "organisation": found,
            "subscription": subscription,
            "billing": billing.public_billing_config(),
        }
    )


@router.put("/api/organisations/{organisation_id}/plan")
def set_organisation_plan(
    organisation_id: int, request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Assign the organisation a plan, restarting its period; journaled.

    This is the operator path (a grant, a migration, a support fix), not the
    customer one: a self-serve upgrade goes through checkout so there is a
    payment behind it.
    """
    refused = _refuse_unless_tenant_admin(request)
    if refused is not None:
        return refused
    plan_id = _require_str(body, "plan_id")
    if not plans_mod.plan_exists(plan_id):
        return json_error(400, error="invalid plan", detail=f"no plan named {plan_id}")
    with contextlib.closing(_open()) as conn:
        found = _organisation_or_404(conn, organisation_id)
        if isinstance(found, Response):
            return found
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.ORG_TABLE,
                where="id = ?",
                params=(organisation_id,),
                description=f"set organisation {organisation_id} to plan {plan_id}",
            )
            conn.execute(
                f"UPDATE {auth.ORG_TABLE} SET plan_id = ?, period_started_at = ? WHERE id = ?",
                (plan_id, auth.now(), organisation_id),
            )
        summary = metering.usage_summary(conn, organisation_id)
    return json_response(log.attach(summary))


@router.post("/api/organisations/{organisation_id}/billing/checkout")
def start_billing_checkout(
    organisation_id: int, request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Start a self-serve checkout for a paid plan."""
    plan_id = _require_str(body, "plan_id")
    with contextlib.closing(_open()) as conn:
        found = _organisation_or_404(conn, organisation_id)
        if isinstance(found, Response):
            return found
        refused = _refuse_unless_organisation_access(conn, request, organisation_id)
        if refused is not None:
            return refused
        try:
            session = billing.start_checkout(conn, found, plan_id)
        except billing.BillingError as exc:
            return _billing_failure(exc)
    return json_response(
        {"provider": session.provider, "session_id": session.session_id, "url": session.url}
    )


@router.post("/api/organisations/{organisation_id}/billing/portal")
def open_billing_portal(organisation_id: int, request: Request) -> Response:
    """Open the provider's self-service portal for the organisation."""
    with contextlib.closing(_open()) as conn:
        found = _organisation_or_404(conn, organisation_id)
        if isinstance(found, Response):
            return found
        refused = _refuse_unless_organisation_access(conn, request, organisation_id)
        if refused is not None:
            return refused
        try:
            session = billing.start_billing_portal(conn, organisation_id)
        except billing.BillingError as exc:
            return _billing_failure(exc)
    return json_response({"provider": session.provider, "url": session.url})


@router.post("/api/billing/manual/confirm")
def confirm_manual_checkout(
    request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Confirm a manual (development) checkout; grants the plan once."""
    refused = _refuse_unless_tenant_admin(request)
    if refused is not None:
        return refused
    token = _require_str(body, "token")
    organisation_id = _require_int(body, "organisation_id")
    with contextlib.closing(_open()) as conn:
        try:
            granted = billing.complete_manual_checkout(conn, token, organisation_id)
        except billing.BillingError as exc:
            return _billing_failure(exc)
        conn.commit()
    return json_response(granted)


@router.post("/api/organisations/{organisation_id}/billing/cancel-manual")
def cancel_manual_checkout(organisation_id: int, request: Request) -> Response:
    """Cancel a manual subscription, dropping the org to the fallback plan."""
    with contextlib.closing(_open()) as conn:
        found = _organisation_or_404(conn, organisation_id)
        if isinstance(found, Response):
            return found
        refused = _refuse_unless_organisation_access(conn, request, organisation_id)
        if refused is not None:
            return refused
        cancelled = billing.cancel_manual_subscription(conn, organisation_id)
        conn.commit()
    return json_response(cancelled)


@router.post("/api/billing/webhook")
async def apply_billing_webhook(request: Request) -> Response:
    """Apply a provider webhook: verify, claim, mirror, entitle.

    The raw body is read before anything parses it, because the signature covers
    the exact bytes the provider sent and a re-serialized body would not verify.
    A redelivery answers ``duplicate`` without touching the subscription.
    """
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    try:
        event = billing.verify_webhook(payload, signature)
    except billing.BillingError as exc:
        return _billing_failure(exc)
    normalized = billing.normalize_stripe_event(event)
    with contextlib.closing(_open()) as conn:
        try:
            result = billing.apply_event(conn, normalized)
        except billing.BillingError as exc:
            return _billing_failure(exc)
    return json_response(result)


@router.post("/api/organisations/{organisation_id}/billing/sync")
def sync_billing_subscription(organisation_id: int, request: Request) -> Response:
    """Re-read the organisation's subscription from the provider and mirror it.

    Webhooks are the primary path; this covers a lost delivery.  It only
    mirrors what the provider already says, so it cannot grant entitlement on
    its own, and it is rate limited because it calls out.
    """
    if not billing.reconcile_allowed(organisation_id):
        return json_error(
            429, error="rate-limited", detail="too many reconcile attempts; try again shortly"
        )
    with contextlib.closing(_open()) as conn:
        found = _organisation_or_404(conn, organisation_id)
        if isinstance(found, Response):
            return found
        refused = _refuse_unless_organisation_access(conn, request, organisation_id)
        if refused is not None:
            return refused
        try:
            result = billing.reconcile_account(conn, organisation_id)
        except billing.BillingError as exc:
            return _billing_failure(exc)
    return json_response(
        {
            "organisation_id": result.organisation_id,
            "provider": result.provider,
            "status": result.status,
            "plan_id": result.plan_id,
            "changed": result.changed,
        }
    )


@router.put("/api/iam/active-team")
def set_active_team(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Switch the team the caller has selected, or clear it with null.

    A view preference rather than a permission: the caller sees every team it
    belongs to either way, and the SPA filters its team lists to the active one
    when it is set.  Membership is still required, so a caller cannot select a
    team it is not in.
    """
    raw = body.get("team_id")
    if raw is not None and (isinstance(raw, bool) or not isinstance(raw, int)):
        return json_error(400, error="team_id must be an integer")
    with contextlib.closing(_open()) as conn:
        caller = _caller(request)
        if caller is None:
            return json_error(
                400,
                error="invalid-team",
                detail="an active team needs token auth; the local operator sees every team",
            )
        try:
            auth.set_active_team(conn, int(caller["id"]), raw)
        except auth.AuthError as exc:
            return _team_failure(exc)
        user = auth.get_user(conn, int(caller["id"]))
    return json_response({"active_team_id": None if user is None else user["active_team_id"]})


@router.get("/api/teams")
def list_teams() -> Response:
    """Every team with its member count; readable by any authenticated caller."""
    with contextlib.closing(_open()) as conn:
        teams = auth.list_teams(conn)
    return json_response({"teams": teams, "count": len(teams)})


@router.post("/api/teams")
def create_team(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Create a team; journaled and revertible.

    When auth is on the creator becomes the team's owner, so the team is
    manageable without a separate admin promotion; while auth is off the local
    operator creates an empty team the way the CLI always has.
    """
    name = _require_str(body, "name")
    description = _optional_str(body, "description")
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                team = auth.create_team(conn, name=name, description=description)
            except auth.AuthError as exc:
                return _team_failure(exc)
            journal.journaled_create(
                log,
                table=auth.TEAM_TABLE,
                key=int(team["id"]),
                description=f"created team {team['name']}",
            )
            caller = _caller(request)
            if caller is not None:
                user_id = int(caller["id"])
                team_id = int(team["id"])
                auth.add_member(conn, team_id, user_id)
                auth.set_member_role(conn, team_id, user_id, auth.TEAM_ROLE_OWNER)
                journal.journaled_create(
                    log,
                    table=auth.MEMBER_TABLE,
                    key={"team_id": team_id, "user_id": user_id},
                    description=f"added user {user_id} as owner of team {team_id}",
                )
                team = auth.get_team(conn, team_id) or team
    return json_response(log.attach(team), status=201)


@router.put("/api/teams/{team_id}/members/{user_id}/role")
def set_team_member_role(
    request: Request, team_id: int, user_id: int, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Set one membership's team role (owner or member); journaled.

    Only a team's own owner or an admin may promote or demote, which is the one
    place a team role is enforced; a member may still work on what the team
    owns.
    """
    role = _require_str(body, "role")
    with contextlib.closing(_open()) as conn:
        if auth.get_team(conn, team_id) is None:
            return json_error(
                404, error=auth.ERROR_TEAM_NOT_FOUND, detail=f"no team with id {team_id}"
            )
        refused = _refuse_unless_team_manager(conn, request, team_id)
        if refused is not None:
            return refused
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            snapshot = journal.journaled_rows(
                conn,
                log,
                table=auth.MEMBER_TABLE,
                where="team_id = ? AND user_id = ?",
                params=(team_id, user_id),
                description=f"set user {user_id}'s role in team {team_id}",
            )
            try:
                changed = auth.set_member_role(conn, team_id, user_id, role)
            except auth.AuthError as exc:
                return _team_failure(exc)
            team = auth.get_team(conn, team_id)
    if not snapshot or not changed:
        return json_error(
            404,
            error=auth.ERROR_NOT_A_MEMBER,
            detail=f"user {user_id} is not in team {team_id}",
        )
    return json_response(log.attach(team or {}))


@router.get("/api/teams/{team_id}")
def get_team(team_id: int) -> Response:
    """One team with its members."""
    with contextlib.closing(_open()) as conn:
        team = auth.get_team(conn, team_id)
    if team is None:
        return json_error(404, error=auth.ERROR_TEAM_NOT_FOUND, detail=f"no team with id {team_id}")
    return json_response(team)


@router.patch("/api/teams/{team_id}")
def update_team(
    team_id: int, request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Set a team's name or description; journaled and revertible."""
    if "name" not in body and "description" not in body:
        return json_error(400, error=auth.ERROR_INVALID_TEAM, detail="provide name or description")
    name = _optional_str(body, "name") if "name" in body else None
    description = _optional_str(body, "description") if "description" in body else None
    with contextlib.closing(_open()) as conn:
        if auth.get_team(conn, team_id) is None:
            return json_error(
                404, error=auth.ERROR_TEAM_NOT_FOUND, detail=f"no team with id {team_id}"
            )
        refused = _refuse_unless_team_manager(conn, request, team_id)
        if refused is not None:
            return refused
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            journal.journaled_rows(
                conn,
                log,
                table=auth.TEAM_TABLE,
                where="id = ?",
                params=(team_id,),
                description=f"updated team {team_id}",
            )
            try:
                updated = auth.update_team(conn, team_id, name=name, description=description)
            except auth.AuthError as exc:
                return _team_failure(exc)
    return json_response(log.attach(updated or {}))


@router.delete("/api/teams/{team_id}")
def delete_team(team_id: int, request: Request) -> Response:
    """Delete a team; journaled, including the objects that lose their scope.

    The binaries and collections the team owned return to the whole workspace,
    so the revert restores their scope as well as the team row and its members.
    """
    with contextlib.closing(_open()) as conn:
        if auth.get_team(conn, team_id) is None:
            return json_error(
                404, error=auth.ERROR_TEAM_NOT_FOUND, detail=f"no team with id {team_id}"
            )
        refused = _refuse_unless_team_manager(conn, request, team_id)
        if refused is not None:
            return refused
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
    return json_response(log.attach({"deleted": team_id}))


@router.post("/api/teams/{team_id}/members")
def add_team_member(
    team_id: int, request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Add a user to a team; journaled and revertible."""
    user_id = _require_int(body, "user_id")
    with contextlib.closing(_open()) as conn:
        if auth.get_team(conn, team_id) is None:
            return json_error(
                404, error=auth.ERROR_TEAM_NOT_FOUND, detail=f"no team with id {team_id}"
            )
        refused = _refuse_unless_team_manager(conn, request, team_id)
        if refused is not None:
            return refused
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            added = auth.add_member(conn, team_id, user_id)
            if added:
                journal.journaled_create(
                    log,
                    table=auth.MEMBER_TABLE,
                    key={"team_id": team_id, "user_id": user_id},
                    description=f"added user {user_id} to team {team_id}",
                )
            team = auth.get_team(conn, team_id)
    if not added:
        return json_error(
            400,
            error=auth.ERROR_INVALID_TEAM,
            detail=f"user {user_id} is unknown or already in team {team_id}",
        )
    return json_response(log.attach(team or {}), status=201)


@router.delete("/api/teams/{team_id}/members/{user_id}")
def remove_team_member(team_id: int, user_id: int, request: Request) -> Response:
    """Remove a user from a team; journaled, so a revert puts the row back."""
    with contextlib.closing(_open()) as conn:
        if auth.get_team(conn, team_id) is None:
            return json_error(
                404, error=auth.ERROR_TEAM_NOT_FOUND, detail=f"no team with id {team_id}"
            )
        refused = _refuse_unless_team_manager(conn, request, team_id)
        if refused is not None:
            return refused
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            snapshot = journal.journaled_rows(
                conn,
                log,
                table=auth.MEMBER_TABLE,
                where="team_id = ? AND user_id = ?",
                params=(team_id, user_id),
                description=f"removed user {user_id} from team {team_id}",
            )
            auth.remove_member(conn, team_id, user_id)
            team = auth.get_team(conn, team_id)
    if not snapshot:
        return json_error(
            404,
            error=auth.ERROR_NOT_A_MEMBER,
            detail=f"user {user_id} is not in team {team_id}",
        )
    return json_response(log.attach(team or {}))


def _set_scope(
    request: Request,
    body: dict[str, Any],
    *,
    kind: str,
    row_id: int,
) -> Response:
    """Set one object's visibility and owning team; journaled and revertible."""
    visibility = _optional_str(body, "visibility", auth.VISIBILITY_PUBLIC)
    raw_team = body.get("team_id")
    if raw_team is not None and (isinstance(raw_team, bool) or not isinstance(raw_team, int)):
        return json_error(400, error=auth.ERROR_INVALID_TEAM, detail="team_id must be an integer")
    table = "binaries" if kind == "binary" else "collections"
    with contextlib.closing(_open()) as conn:
        current = (
            store.get_binary(conn, row_id)
            if kind == "binary"
            else store.get_collection(conn, row_id)
        )
        if current is None:
            return json_error(404, error=f"{kind} not found", detail=f"no {kind} with id {row_id}")
        if not auth.may_write(_caller(request), current, team_ids=_caller_team_ids(conn, request)):
            return json_error(
                403,
                error=auth.ERROR_SCOPE_FORBIDDEN,
                detail=f"this {kind} belongs to a team you are not a member of",
            )
        try:
            owner, resolved = auth.scope_of(conn, team_id=raw_team, visibility=visibility)
        except auth.AuthError as exc:
            return _team_failure(exc)
        caller = _caller(request)
        if (
            owner is not None
            and caller is not None
            and str(caller.get("role")) != auth.ROLE_ADMIN
            and owner not in set(_caller_team_ids(conn, request))
        ):
            return json_error(
                403,
                error=auth.ERROR_NOT_A_MEMBER,
                detail=f"you are not a member of team {owner}",
            )
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
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
    return json_response(log.attach(updated or {}))


@router.patch("/api/binaries/{binary_id}/scope")
def set_binary_scope(
    binary_id: int, request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Set a binary's visibility and owning team (`public` or `team`)."""
    return _set_scope(request, body, kind="binary", row_id=binary_id)


@router.patch("/api/collections/{collection_id}/scope")
def set_collection_scope(
    collection_id: int, request: Request, body: dict[str, Any] = Depends(json_body)
) -> Response:
    """Set a collection's visibility and owning team (`public` or `team`)."""
    return _set_scope(request, body, kind="collection", row_id=collection_id)


# ── Activity and feedback ──────────────────────────────────────────
#
# The two hosted identity reads reportal had no local answer for: a feed of what
# was done and by whom, derived from the journal and the analysis log rather
# than stored, and a local feedback note, which is the one stored half.  Both
# are self-service paths (`auth._SELF_PATHS`), so an analyst needs no admin role
# to read its own activity or write a note.


def _invalid_feedback(detail: str) -> Response:
    return json_error(400, error="invalid feedback", detail=detail)


@router.get("/api/users/activity")
def user_activity(request: Request) -> Response:
    """The activity feed: journaled actions and analysis-log entries, newest first.

    ``?actor=`` narrows it to one name (the empty value means the writes no
    request made), ``?since=`` is an inclusive ISO timestamp and ``?limit=`` is
    bounded by :data:`activity.MAX_ACTIVITY_LIMIT`.  ``sources`` names the item
    kinds to merge.  Nothing is stored: the feed is derived, so a revert or a
    prune shows at once.

    Self-service while auth is on: a non-admin caller sees only its own
    journaled actions (plus analysis-log rows for binaries it may reach) and
    cannot name another actor.  An admin, or auth off, keeps the workspace feed.
    """
    actor = request.query_params.get("actor")
    since_raw = _query_text(request, "since")
    since = None
    if since_raw is not None:
        try:
            since = notifications.parse_since(since_raw)
        except ValueError as exc:
            return json_error(400, error="invalid since", detail=str(exc))
    limit = _query_int(request, "limit")
    limit = activity.DEFAULT_ACTIVITY_LIMIT if limit is None else limit
    if not 1 <= limit <= activity.MAX_ACTIVITY_LIMIT:
        return json_error(
            400,
            error="invalid limit",
            detail=f"limit must be between 1 and {activity.MAX_ACTIVITY_LIMIT}",
        )
    sources: tuple[str, ...] = activity.SOURCES
    raw_sources = _query_text(request, "sources")
    if raw_sources is not None:
        sources = tuple(part.strip() for part in raw_sources.split(",") if part.strip())
    caller = _caller(request)
    own_name: str | None = None
    if caller is not None and str(caller.get("role")) != auth.ROLE_ADMIN:
        own_name = str(caller["name"])
        if actor is not None and actor != own_name:
            return json_error(
                403,
                error=auth.ERROR_FORBIDDEN,
                detail="an analyst may only read its own activity",
            )
        actor = own_name
    with contextlib.closing(_open()) as conn:
        try:
            payload = activity.feed(
                conn,
                actor=actor,
                since=since,
                limit=limit,
                sources=sources,
                visible_to=caller,
            )
        except ValueError as exc:
            return json_error(400, error="invalid sources", detail=str(exc))
        if own_name is not None:
            payload["actors"] = [row for row in activity.actors(conn) if row["actor"] == own_name]
        else:
            payload["actors"] = activity.actors(conn)
    return json_response(payload)


@router.get("/api/users/feedback")
def list_feedback(request: Request) -> Response:
    """Stored feedback notes, newest first, bounded; read-only.

    Self-service while auth is on: a non-admin caller sees only the notes it
    wrote.  An admin, or auth off, keeps the full listing.
    """
    limit = _query_int(request, "limit")
    limit = 50 if limit is None else limit
    if not 1 <= limit <= 500:
        return json_error(400, error="invalid limit", detail="limit must be between 1 and 500")
    caller = _caller(request)
    owner_id: int | None = None
    if caller is not None and str(caller.get("role")) != auth.ROLE_ADMIN:
        owner_id = int(caller["id"])
    with contextlib.closing(_open()) as conn:
        notes = store.list_feedback(conn, limit=limit, user_id=owner_id)
        total = store.count_feedback(conn, user_id=owner_id)
    return json_response({"feedback": notes, "count": len(notes), "total": total})


@router.post("/api/users/feedback")
def add_feedback(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    """Store one feedback note about reportal itself; journaled and revertible.

    The note is attributed to the authenticated caller's name when there is one
    and to ``local`` while token auth is off, so it is never invented an owner.
    A blank body or one past :data:`reportal.store.MAX_FEEDBACK_CHARS` is 400
    ``invalid feedback``.
    """
    raw = body.get("message")
    if not isinstance(raw, str):
        return _invalid_feedback("message must be a string")
    caller = _caller(request)
    with contextlib.closing(_open()) as conn:
        action = journal.new_action()
        with journal.journaled(conn, action) as log:
            try:
                feedback_id = store.add_feedback(
                    conn,
                    body=raw,
                    actor=journal.current_actor(),
                    user_id=None if caller is None else int(caller["id"]),
                )
            except store.InvalidFeedbackError as exc:
                return _invalid_feedback(str(exc))
            journal.journaled_create(
                log,
                table="feedback",
                key=feedback_id,
                description=f"wrote feedback note {feedback_id}",
            )
    with contextlib.closing(_open()) as conn:
        stored = store.get_feedback(conn, feedback_id)
    return json_response(log.attach(stored or {"id": feedback_id}), status=201)


# ── Guarded sandbox detonation ─────────────────────────────────────
#
# The one route that executes a sample, and it is off by default: the workspace
# opts in, a runner must be installed, the run is capped and recorded, and the
# sample is bind-mounted read-only rather than executed from its stored path.
# Everything about the run (the command, the caps, the exit status, the output
# tails and the files it wrote) is stored and journaled, so a revert removes the
# record of a run whose effects the sandbox already contained.


def sandbox_failure(exc: sandbox.SandboxError) -> Response:
    """Map a sandbox refusal onto its status and error name."""
    if exc.code == sandbox.ERROR_DISABLED:
        return json_error(403, error=exc.code, detail=exc.detail)
    if exc.code == sandbox.ERROR_UNAVAILABLE:
        return json_error(503, error=exc.code, detail=exc.detail)
    if exc.code == sandbox.ERROR_NO_RUN or exc.code.endswith("not found"):
        return json_error(404, error=exc.code, detail=exc.detail)
    return json_error(400, error=exc.code, detail=exc.detail)


@router.post("/api/binaries/{binary_id}/dynamic-execution")
def run_binary_sandbox(
    binary_id: int, body: dict[str, Any] = Depends(optional_json_body)
) -> Response:
    """Detonate a stored sample under the sandbox runner and store the report.

    Body ``{"timeout": seconds, "memory_mb": megabytes}`` narrows the caps and
    can never raise them.  The run is refused unless the workspace opted in (403
    `sandbox-disabled`), a runner is installed (503 `sandbox-unavailable`) and
    the bounds are inside the caps (400 `invalid-sandbox`); 404 `binary not
    found`, 400 `binary not on disk`.  The report is one journaled row, so a
    revert removes the record.
    """
    raw_timeout = body.get("timeout")
    if raw_timeout is not None and (
        isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int)
    ):
        return json_error(400, error=sandbox.ERROR_INVALID, detail="timeout must be an integer")
    raw_memory = body.get("memory_mb")
    if raw_memory is not None and (isinstance(raw_memory, bool) or not isinstance(raw_memory, int)):
        return json_error(400, error=sandbox.ERROR_INVALID, detail="memory_mb must be an integer")
    with contextlib.closing(_open()) as conn:
        try:
            report = sandbox.detonate_binary(
                conn, binary_id, timeout=raw_timeout, memory_mb=raw_memory
            )
        except sandbox.SandboxError as exc:
            return sandbox_failure(exc)
    return json_response(report, status=201)


@router.get("/api/binaries/{binary_id}/dynamic-execution")
def get_binary_sandbox(binary_id: int) -> Response:
    """The newest detonation report of a binary's newest analysis; 404 `no-run`."""
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        report = None if analysis_id is None else sandbox.latest_run(conn, analysis_id)
        status = sandbox.status_payload(conn, analysis_id or 0)
    if report is None:
        return json_error(
            404,
            error=sandbox.ERROR_NO_RUN,
            detail=f"binary {binary_id} has no detonation report",
        )
    return json_response({**report, "detonation": status})


@router.get("/api/binaries/{binary_id}/dynamic-execution/status")
def get_binary_sandbox_status(binary_id: int) -> Response:
    """Whether this binary can be detonated, by which runner, and its last run.

    The binary-scoped spelling of the analysis status, for the binary detail's
    Sandbox panel, which knows the binary rather than a chosen analysis.  A
    binary with no analysis yet reports the install's opt-in state and no run.
    """
    with contextlib.closing(_open()) as conn:
        _require_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        payload = sandbox.status_payload(conn, analysis_id or 0)
    return json_response({"binary_id": binary_id, **payload})


@router.get("/api/analyses/{analysis_id}/dynamic-execution")
def get_analysis_sandbox(analysis_id: int) -> Response:
    """The newest detonation report of one analysis; the hosted report read."""
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        report = sandbox.latest_run(conn, analysis_id)
        status = sandbox.status_payload(conn, analysis_id)
    if report is None:
        return json_error(
            404,
            error=sandbox.ERROR_NO_RUN,
            detail=f"analysis {analysis_id} has no detonation report",
        )
    return json_response({**report, "detonation": status})


@router.get("/api/analyses/{analysis_id}/dynamic-execution/status")
def get_analysis_sandbox_status(analysis_id: int) -> Response:
    """Whether this analysis can be detonated, by which runner, and its last run."""
    with contextlib.closing(_open()) as conn:
        if store.get_analysis(conn, analysis_id) is None:
            return json_error(
                404, error="analysis not found", detail=f"no analysis with id {analysis_id}"
            )
        return json_response(sandbox.status_payload(conn, analysis_id))

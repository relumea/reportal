"""Editable per-function signatures: parse, model, edit, history and export.

The decompiled source reportal stores for a function opens with its
declaration.  This module parses that line into a local model (``function_signatures``,
one row per function), lets a caller edit the return type, the calling
convention and the ordered parameters, renders the model back as a C
prototype header, and keeps each mutation's previous state in
``signature_history`` so an edit can be reverted exactly.

A parameter carries more than its type and name.  ``at`` is where the target
convention passes the argument (a register or a stack slot), ``kind`` names
what the argument is (``value``, ``pointer``, ``array`` or ``struct``) and
``bits`` its width.  All three are optional and absent stays absent: the model
never fills a field nobody set, and :func:`render_prototype` annotates only
the fields it has.  :func:`default_at` is the convention table's answer for
"where would argument *i* arrive", exposed beside the model as ``default_at``
rather than written into it.

Reordering (``move_parameter``) recomputes ``at`` for the target convention.
Argument order decides where the 32-bit ABI passes each argument, so a reorder
that kept stale arrival locations would render a prototype that lies about the
ABI; the recompute is the one place the convention table is authoritative.
A parameter whose ``at`` the table cannot place (an unknown calling
convention) keeps the value it had, and an absent ``at`` stays absent, so the
recompute never invents a location for a field nobody set.

``store.py`` owns the table DDL and the row primitives; this module owns
parsing, validation, rendering, export and the history/revert logic, and is
what the API, the CLI and the MCP tools call.
"""

from __future__ import annotations

import contextlib
import os
import re
import sqlite3
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from reportal import store

# Calling conventions the parser recognizes and the model accepts, spelled the
# way a decompiler prints them minus the leading underscores.  An empty value
# means the source did not spell one and the prototype renders without a
# keyword.
CALLING_CONVENTIONS: frozenset[str] = frozenset(
    {"cdecl", "stdcall", "fastcall", "thiscall", "vectorcall"}
)
DEFAULT_CALLING_CONVENTION = ""

# What a parameter carries: the closed vocabulary of `kind`, the argument
# locations a stack slot or register can spell, and the widest bit width the
# model accepts.  A `kind` outside the set and an unparsable `at` are refused,
# so a field the model holds is one it understood.
PARAMETER_KINDS: frozenset[str] = frozenset({"value", "pointer", "array", "struct"})
MAX_PARAMETER_BITS = 512

# The x86-32 argument-passing table `default_at` reads, and the stack slot
# width it lays arguments out with.  The register tuple is the arguments the
# convention passes in registers, in order; every later argument goes on the
# stack.  Vectorcall is listed with no registers because rebrew's targets are
# 32-bit cdecl/stdcall/fastcall/thiscall, and an unknown convention has no
# entry: `default_at` answers None rather than guessing.
ARGUMENT_SLOT_BYTES = 4
_CONVENTION_REGISTERS: dict[str, tuple[str, ...]] = {
    "cdecl": (),
    "stdcall": (),
    "fastcall": ("ecx", "edx"),
    "thiscall": ("ecx",),
    "vectorcall": (),
}


class _Unset:
    """Sentinel: a parameter field the caller did not name.

    ``None`` on an edit clears a field, so an absent body key and an explicit
    null cannot share a value; the default argument is this sentinel instead.
    """


UNSET: _Unset = _Unset()

# An argument location: a register name (`ecx`, `r8d`), a stack slot
# (`[esp+4]`, `[ebp-8]`) or a bare offset (`+0x4`).
_REGISTER_RE = re.compile(r"\A[a-z]{2,5}\d{0,2}\Z", re.IGNORECASE)
_STACK_SLOT_RE = re.compile(r"\A\[(?:e|r)?(?:sp|bp)\s*[+-]\s*(?:0x[0-9a-fA-F]+|\d+)\]\Z")
_BARE_OFFSET_RE = re.compile(r"\A[+-]\s*(?:0x[0-9a-fA-F]+|\d+)\Z")

# Source recorded on a row seeded from a stored decompilation, and on a row a
# caller edited by hand.  A revert records the state it replaced under
# SOURCE_REVERT, the way a rename revert records itself in ``name_history``.
SOURCE_DECOMPILATION = "decompilation"
SOURCE_MANUAL = "manual"
SOURCE_REVERT = "revert"

# Actor recorded on a history row when the caller does not name one.
DEFAULT_ACTOR = "manual"

# Most function ids one batch read accepts, so a listing cannot ask for the corpus.
BATCH_LIMIT = 200

# A C identifier; the model rejects anything else as a function or parameter
# name.
_IDENTIFIER_RE = re.compile(r"\A[A-Za-z_]\w*\Z")

# Words that spell a type rather than a parameter name, so a declaration whose
# last token is one of these is an unnamed type.
_TYPE_KEYWORDS: frozenset[str] = frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "const",
        "volatile",
        "struct",
        "union",
        "enum",
        "bool",
        "size_t",
        "wchar_t",
        "wint_t",
        "_Bool",
        "__int8",
        "__int16",
        "__int32",
        "__int64",
    }
)

# A trailing array dimension, sized or not.
_ARRAY_SUFFIX_RE = re.compile(r"\[\s*[0-9]*\s*\]\s*\Z")

# A calling-convention keyword as the listing prints it, with any underscores.
_CONVENTION_RE = re.compile(r"\A_*(cdecl|stdcall|fastcall|thiscall|vectorcall)\Z")

# A declaration line: a head, a parenthesized parameter list, optionally closed
# by `{` or `;`.  A nested pair of parentheses (a function-pointer parameter) is
# not matched, so such a line does not parse.
_SIGNATURE_RE = re.compile(r"\A(?P<head>.+?)\((?P<params>[^()]*)\)\s*[;{]?\s*\Z")

# Punctuation that never occurs in a type the model carries.
_TYPE_PUNCTUATION_RE = re.compile(r"[^\w\s*\[\]]")


def default_at(convention: str, index: int) -> str | None:
    """The arrival location the target convention gives argument *index*, or None.

    The table is the x86-32 ABI rebrew's targets use.  cdecl and stdcall pass
    every argument on the stack, so argument *i* sits at ``[esp+4+4i]`` at
    function entry; fastcall passes the first two in ``ecx`` and ``edx`` and
    the rest on the stack from ``[esp+4]``; thiscall passes the ``this``
    pointer in ``ecx`` and the rest on the stack.  An empty or unknown
    convention, a convention without a table entry and a negative index answer
    None: the model has no location to name, and a caller must not be told one
    it does not know.
    """
    registers = _CONVENTION_REGISTERS.get((convention or "").strip().lower())
    if registers is None or index < 0:
        return None
    if index < len(registers):
        return registers[index]
    slot = index - len(registers)
    return f"[esp+{ARGUMENT_SLOT_BYTES * (slot + 1)}]"


def _validate_at(value: str | None) -> str | None:
    """Return a validated argument location, or None when the value clears it."""
    text = (value or "").strip()
    if not text:
        return None
    if _REGISTER_RE.match(text) or _STACK_SLOT_RE.match(text) or _BARE_OFFSET_RE.match(text):
        return text
    raise InvalidTypeError(f"not an argument location: {value!r}")


def _validate_kind(value: str | None) -> str | None:
    """Return a validated parameter kind, or None when the value clears it."""
    text = (value or "").strip().lower()
    if not text:
        return None
    if text not in PARAMETER_KINDS:
        raise InvalidTypeError(f"unknown parameter kind: {value!r}")
    return text


def _validate_bits(value: int | None) -> int | None:
    """Return a validated parameter width, or None when the value clears it."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidTypeError(f"bits must be an integer, got {value!r}")
    if not 1 <= value <= MAX_PARAMETER_BITS:
        raise InvalidTypeError(f"bits must be between 1 and {MAX_PARAMETER_BITS}, got {value}")
    return value


def _parameter_view(parameter: Mapping[str, Any]) -> dict[str, Any]:
    """One parameter with every model field present, absent ones as None."""
    bits = parameter.get("bits")
    return {
        "index": int(parameter["index"]),
        "type": str(parameter["type"]),
        "name": str(parameter.get("name") or ""),
        "at": str(parameter["at"]) if parameter.get("at") else None,
        "kind": str(parameter["kind"]) if parameter.get("kind") else None,
        "bits": int(bits) if isinstance(bits, int) and not isinstance(bits, bool) else None,
    }


def _parameters_view(parameters: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalize a stored parameter list, filling fields a legacy row predates."""
    return [_parameter_view(parameter) for parameter in parameters]


def _signature_view(row: Mapping[str, Any]) -> dict[str, Any]:
    """A signature row with its parameters normalized."""
    return {**row, "parameters": _parameters_view(row.get("parameters") or [])}


def _history_view(entry: Mapping[str, Any]) -> dict[str, Any]:
    """A history row whose recorded state has its parameters normalized.

    The recorded state also carries its rendered ``prototype``, through the same
    renderer the CLI, the header export and the function's own signature read
    use, so a reader (the SPA history panel) never re-implements the rendering.
    A row with no previous state created the signature, so its prototype is null.
    """
    previous = entry.get("previous")
    prototype: str | None = None
    if isinstance(previous, Mapping):
        previous = {
            **previous,
            "parameters": _parameters_view(previous.get("parameters") or []),
        }
        prototype = render_prototype(previous)
    return {**entry, "previous": previous, "prototype": prototype}


def describe_parameters(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The signature's parameters plus the arrival location its convention implies.

    ``default_at`` is a derived suggestion, not the model's ``at``: the panel
    can offer it while the stored field stays null until the analyst sets it.
    """
    convention = str(row.get("calling_convention") or "")
    return [
        {**parameter, "default_at": default_at(convention, int(parameter["index"]))}
        for parameter in _parameters_view(row.get("parameters") or [])
    ]


class SignatureError(ValueError):
    """Base class for a signature model failure."""


class InvalidIdentifierError(SignatureError):
    """A function or parameter name is not a C identifier."""


class InvalidTypeError(SignatureError):
    """A return or parameter type is empty or not a type declaration."""


class DuplicateParameterError(SignatureError):
    """Another parameter of the signature already carries the name."""


class UnknownSignatureError(SignatureError):
    """The function has no stored signature."""


class UnknownParameterError(SignatureError):
    """The parameter index is out of range."""


class UnknownHistoryError(SignatureError):
    """No signature-history row carries the id for this function."""


class InvalidParameterError(SignatureError):
    """A parameter edit is unusable (no operation named)."""


class ExportExistsError(SignatureError):
    """The export target exists and the caller did not pass ``force``."""


class ExportParentMissingError(SignatureError):
    """The export target's parent directory cannot be created."""


def _split_array(text: str) -> tuple[str, str]:
    """Split a trailing array dimension off *text*, returning ``(body, suffix)``."""
    match = _ARRAY_SUFFIX_RE.search(text)
    if match is None:
        return text.rstrip(), ""
    return text[: match.start()].rstrip(), match.group(0).replace(" ", "")


def _normalize_type(type_text: str) -> str:
    """Return the normalized type text, rejecting an empty or non-type one.

    Multi-word types (``unsigned int``) and pointer stars (``char *``) are kept;
    a token that is neither an identifier nor a run of stars is rejected.
    """
    tokens = (type_text or "").split()
    names: list[str] = []
    stars = 0
    for token in tokens:
        if token and set(token) <= {"*"}:
            stars += len(token)
            continue
        if not _IDENTIFIER_RE.match(token):
            raise InvalidTypeError(f"not a type: {type_text!r}")
        names.append(token)
    if not names:
        raise InvalidTypeError(f"not a type: {type_text!r}")
    text = " ".join(names)
    return f"{text} {'*' * stars}" if stars else text


def normalize_type(type_text: str) -> str:
    """Return a validated return-type text, rejecting an empty one."""
    text = (type_text or "").strip()
    if not text:
        raise InvalidTypeError("type is empty")
    if _TYPE_PUNCTUATION_RE.search(text):
        raise InvalidTypeError(f"not a type: {type_text!r}")
    return _normalize_type(text)


def parse_parameter(declaration: str) -> tuple[str, str]:
    """Return ``(type, name)`` for one parameter declaration.

    The name is optional, so ``char *`` yields an empty name and ``char *path``
    yields ``path``; a trailing array dimension stays with the type as
    ``char[16]``.
    """
    text = (declaration or "").strip()
    if not text:
        raise InvalidTypeError("type is empty")
    if _TYPE_PUNCTUATION_RE.search(text):
        raise InvalidTypeError(f"not a type: {declaration!r}")
    body, suffix = _split_array(text)
    if not body:
        raise InvalidTypeError(f"not a type: {declaration!r}")
    tokens = body.split()
    stars = 0
    last = tokens[-1]
    while last.startswith("*"):
        stars += 1
        last = last[1:]
    name = ""
    if last and _IDENTIFIER_RE.match(last) and last not in _TYPE_KEYWORDS and len(tokens) >= 2:
        name = last
        type_tokens = tokens[:-1]
        if stars:
            type_tokens = [*type_tokens, "*" * stars]
        base = _normalize_type(" ".join(type_tokens))
    else:
        base = _normalize_type(body)
    return (f"{base}{suffix}" if suffix else base), name


def normalize_parameter_type(type_text: str) -> str:
    """Return a validated parameter type text, rejecting an empty one."""
    normalized, _ = parse_parameter(type_text)
    return normalized


def _parse_name(head: str) -> tuple[str, str, str] | None:
    """Return ``(return_type, convention, name)`` for the text before ``(``."""
    tokens = head.split()
    if len(tokens) < 2:
        return None
    name_token = tokens[-1]
    stars = 0
    while name_token.startswith("*"):
        stars += 1
        name_token = name_token[1:]
    if not _IDENTIFIER_RE.match(name_token):
        return None
    return_tokens = tokens[:-1]
    convention = DEFAULT_CALLING_CONVENTION
    for position, token in enumerate(return_tokens):
        match = _CONVENTION_RE.match(token)
        if match is not None:
            convention = match.group(1)
            del return_tokens[position]
            break
    text = " ".join(return_tokens).strip()
    if stars:
        text = f"{text} {'*' * stars}"
    try:
        return_type = normalize_type(text)
    except InvalidTypeError:
        return None
    return return_type, convention, name_token


def _parse_parameters(text: str) -> list[dict[str, Any]]:
    """Return the ordered parameter list for a parameter text."""
    stripped = text.strip()
    if not stripped or stripped == "void":
        return []
    parameters: list[dict[str, Any]] = []
    for index, entry in enumerate(stripped.split(",")):
        type_text, name = parse_parameter(entry)
        if name and any(parameter["name"] == name for parameter in parameters):
            raise DuplicateParameterError(f"duplicate parameter: {name}")
        parameters.append(
            {
                "index": index,
                "type": type_text,
                "name": name,
                "at": None,
                "kind": None,
                "bits": None,
            }
        )
    return parameters


def _parse_line(line: str) -> dict[str, Any] | None:
    """Parse one candidate declaration line, or None when it is not one."""
    match = _SIGNATURE_RE.match(line)
    if match is None:
        return None
    split = _parse_name(match.group("head"))
    if split is None:
        return None
    return_type, convention, name = split
    try:
        parameters = _parse_parameters(match.group("params"))
    except SignatureError:
        return None
    return {
        "name": name,
        "return_type": return_type,
        "calling_convention": convention,
        "parameters": parameters,
    }


def parse_signature(code: str) -> dict[str, Any] | None:
    """Parse the signature line of a decompiler listing, or None.

    The first line that parses as a function declaration wins, so leading
    comments and blank lines are skipped.  A line that is not a declaration, or
    one whose parameter list does not parse, yields None without raising.
    """
    for raw in (code or "").splitlines():
        parsed = _parse_line(raw.strip())
        if parsed is not None:
            return parsed
    return None


def _load(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """Return the signature row, or raise :class:`UnknownSignatureError`.

    The row's parameters are normalized, so a character field a legacy row
    predates reads as None rather than a missing key.
    """
    row = store.get_signature(conn, function_id)
    if row is None:
        raise UnknownSignatureError(f"no signature for function {function_id}")
    return _signature_view(row)


def _reindex(parameters: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return the parameters with contiguous indices from 0."""
    return [{**parameter, "index": index} for index, parameter in enumerate(parameters)]


def _validate_identifier(name: str) -> str:
    """Return *name* when it is a C identifier, else raise."""
    candidate = (name or "").strip()
    if not _IDENTIFIER_RE.match(candidate):
        raise InvalidIdentifierError(f"not a C identifier: {name!r}")
    return candidate


def _state(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return the editable state of a signature row, for a history record."""
    return {
        "name": str(row["name"]),
        "return_type": str(row["return_type"]),
        "calling_convention": str(row["calling_convention"]),
        "parameters": _parameters_view(row["parameters"]),
        "source": str(row["source"]),
    }


def _record(
    conn: sqlite3.Connection,
    function_id: int,
    previous: Mapping[str, Any] | None,
    *,
    source: str,
    actor: str,
    actor_user_id: int | None = None,
) -> int:
    """Append one history row for the state a write replaced."""
    from reportal import journal

    current = journal.current_actor()
    return store.add_signature_history(
        conn,
        function_id=function_id,
        previous=previous,
        source=source,
        actor=current or actor,
        actor_user_id=actor_user_id or journal.current_actor_user_id(),
    )


def _save(
    conn: sqlite3.Connection,
    row: Mapping[str, Any],
    *,
    name: str | None = None,
    return_type: str | None = None,
    calling_convention: str | None = None,
    parameters: Sequence[Mapping[str, Any]] | None = None,
    source: str = SOURCE_MANUAL,
    actor: str = DEFAULT_ACTOR,
) -> dict[str, Any]:
    """Write back a signature with reindexed parameters, returning the new row.

    The state the write replaced is appended to the function's history first, so
    every mutation is revertible.
    """
    _record(conn, int(row["function_id"]), _state(row), source=source, actor=actor)
    store.upsert_signature(
        conn,
        function_id=int(row["function_id"]),
        name=str(row["name"]) if name is None else name,
        return_type=str(row["return_type"]) if return_type is None else return_type,
        calling_convention=(
            str(row["calling_convention"]) if calling_convention is None else calling_convention
        ),
        parameters=_reindex(list(row["parameters"]) if parameters is None else list(parameters)),
        source=source,
    )
    return _load(conn, int(row["function_id"]))


def list_signatures(conn: sqlite3.Connection, *, binary_id: int) -> list[dict[str, Any]]:
    """The signature model of one binary, ordered by name."""
    return [_signature_view(row) for row in store.list_signatures(conn, binary_id=binary_id)]


def ensure_signature(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """Return the function's signature row, creating an empty one when it has none.

    The setters need a row to edit; this is what a caller uses to start one, so
    a copy onto a function that had no signature creates it rather than failing.
    The empty row is not recorded as a history change: the first real edit
    records the change from empty, which is what a reader expects to see.
    """
    row = store.get_signature(conn, function_id)
    if row is not None:
        return _load(conn, function_id)
    function = store.get_function(conn, function_id)
    if function is None:
        raise UnknownSignatureError(f"no function with id {function_id}")
    store.upsert_signature(
        conn,
        function_id=function_id,
        name=str(function["name"]),
        return_type="",
        calling_convention="",
        parameters=[],
        source=SOURCE_MANUAL,
    )
    return _load(conn, function_id)


def get_signature(conn: sqlite3.Connection, function_id: int) -> dict[str, Any] | None:
    """One function signature by its function id, or None."""
    row = store.get_signature(conn, function_id)
    return _signature_view(row) if row is not None else None


def signatures_for(
    conn: sqlite3.Connection,
    function_ids: Sequence[int],
    *,
    visible_to: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """One row per requested function: its stored signature, or None for one.

    This is the batch read the hosted `GET /v3/functions/signatures` serves: the
    order is the caller's, a function with no signature yet reports ``null``,
    and a function the store does not know is reported with ``found: false``
    rather than omitted, so a caller can tell "no signature" from "no function".
    A function of a binary *visible_to* may not see reads as missing, like the
    per-object gate.
    """
    from reportal import auth

    visible: set[int] | None = None
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        clause, params = scope
        visible = {
            int(row["id"])
            for row in conn.execute(
                f"SELECT b.id AS id FROM binaries b WHERE {clause}", params
            ).fetchall()
        }
    functions = store.functions_by_ids(conn, function_ids)
    signatures = store.signatures_by_ids(conn, list(functions))
    rows: list[dict[str, Any]] = []
    for function_id in function_ids:
        function = functions.get(int(function_id))
        if function is None or (visible is not None and int(function["binary_id"]) not in visible):
            rows.append({"function_id": function_id, "found": False, "signature": None})
            continue
        stored = signatures.get(int(function_id))
        rows.append(
            {
                "function_id": function_id,
                "found": True,
                "name": str(function["name"]),
                "signature": _signature_view(stored) if stored is not None else None,
            }
        )
    return rows


def copy_signature(
    conn: sqlite3.Connection,
    *,
    source_id: int,
    targets: Sequence[int],
) -> dict[str, Any]:
    """Copy one function's signature onto each target; writes, journals nothing.

    The caller journaled the action (``surface.journaled_signature_write``), so
    this only writes.  A target that does not exist, is the source itself or
    refuses a write is reported in ``skipped`` with its reason and keeps its
    stored signature; a source with no signature is
    :class:`UnknownSignatureError`.
    """
    source = get_signature(conn, source_id)
    if source is None:
        raise UnknownSignatureError(f"function {source_id} has no stored signature")
    parameters = [
        {
            "type_text": str(parameter["type"]),
            "name": str(parameter.get("name") or ""),
            "at": parameter.get("at"),
            "kind": parameter.get("kind"),
            "bits": parameter.get("bits"),
        }
        for parameter in source["parameters"]
    ]
    applied: list[int] = []
    skipped: list[dict[str, Any]] = []
    for target in targets:
        if int(target) == int(source_id):
            skipped.append({"function_id": int(target), "reason": "the source function"})
            continue
        if store.get_function(conn, int(target)) is None:
            skipped.append({"function_id": int(target), "reason": "not found"})
            continue
        try:
            ensure_signature(conn, int(target))
            delete_signature(conn, int(target))
            ensure_signature(conn, int(target))
            for parameter in parameters:
                add_parameter(
                    conn,
                    int(target),
                    type_text=str(parameter["type_text"]),
                    name=str(parameter["name"]),
                    at=parameter["at"],
                    kind=parameter["kind"],
                    bits=parameter["bits"],
                )
            set_return_type(conn, int(target), return_type=str(source["return_type"]))
            set_calling_convention(
                conn, int(target), calling_convention=str(source["calling_convention"])
            )
        except SignatureError as exc:
            skipped.append({"function_id": int(target), "reason": str(exc)})
            continue
        applied.append(int(target))
    return {
        "source_function_id": int(source_id),
        "targets": [int(target) for target in targets],
        "applied": applied,
        "skipped": skipped,
        "count": len(applied),
    }


def set_return_type(
    conn: sqlite3.Connection, function_id: int, *, return_type: str
) -> dict[str, Any]:
    """Set one signature's return type, rejecting an empty one."""
    row = _load(conn, function_id)
    return _save(conn, row, return_type=normalize_type(return_type))


def set_calling_convention(
    conn: sqlite3.Connection, function_id: int, *, calling_convention: str
) -> dict[str, Any]:
    """Set one signature's calling convention, or clear it with an empty value."""
    row = _load(conn, function_id)
    candidate = (calling_convention or "").strip().lstrip("_")
    if candidate and candidate not in CALLING_CONVENTIONS:
        raise InvalidTypeError(f"unknown calling convention: {calling_convention!r}")
    return _save(conn, row, calling_convention=candidate)


def set_parameter(
    conn: sqlite3.Connection,
    function_id: int,
    *,
    index: int,
    type_text: str | None = None,
    name: str | None = None,
    at: str | None | _Unset = UNSET,
    kind: str | None | _Unset = UNSET,
    bits: int | None | _Unset = UNSET,
) -> dict[str, Any]:
    """Edit one parameter's type, name, arrival location, kind or width.

    ``type_text`` and ``name`` are ``None`` when the caller leaves them alone;
    ``at``, ``kind`` and ``bits`` default to :data:`UNSET` so an explicit
    ``None`` clears the field while an absent one leaves it as it is.
    """
    if (
        type_text is None
        and name is None
        and isinstance(at, _Unset)
        and isinstance(kind, _Unset)
        and isinstance(bits, _Unset)
    ):
        raise InvalidParameterError("one of type, name, at, kind or bits is required")
    row = _load(conn, function_id)
    parameters = list(row["parameters"])
    if not 0 <= index < len(parameters):
        raise UnknownParameterError(f"parameter index {index} is out of range")
    parameter = dict(parameters[index])
    if name is not None:
        candidate = _validate_identifier(name)
        if any(
            other["name"] == candidate
            for position, other in enumerate(parameters)
            if position != index
        ):
            raise DuplicateParameterError(f"parameter {candidate!r} already exists")
        parameter["name"] = candidate
    if type_text is not None:
        parameter["type"] = normalize_parameter_type(type_text)
    if not isinstance(at, _Unset):
        parameter["at"] = _validate_at(at)
    if not isinstance(kind, _Unset):
        parameter["kind"] = _validate_kind(kind)
    if not isinstance(bits, _Unset):
        parameter["bits"] = _validate_bits(bits)
    parameters[index] = parameter
    return _save(conn, row, parameters=parameters)


def add_parameter(
    conn: sqlite3.Connection,
    function_id: int,
    *,
    type_text: str,
    name: str = "",
    index: int | None = None,
    at: str | None = None,
    kind: str | None = None,
    bits: int | None = None,
) -> dict[str, Any]:
    """Add one parameter, appended or inserted at *index*.

    Every parameter is reindexed after the insert, so the stored indices stay
    contiguous from 0.  The optional ``at``, ``kind`` and ``bits`` are stored
    as given; an absent one stays null rather than being derived from the
    convention.
    """
    row = _load(conn, function_id)
    parameters = list(row["parameters"])
    if index is None:
        position = len(parameters)
    elif 0 <= index <= len(parameters):
        position = index
    else:
        raise UnknownParameterError(f"parameter index {index} is out of range")
    candidate = _validate_identifier(name) if (name or "").strip() else ""
    if candidate and any(parameter["name"] == candidate for parameter in parameters):
        raise DuplicateParameterError(f"parameter {candidate!r} already exists")
    parameters.insert(
        position,
        {
            "index": position,
            "type": normalize_parameter_type(type_text),
            "name": candidate,
            "at": _validate_at(at),
            "kind": _validate_kind(kind),
            "bits": _validate_bits(bits),
        },
    )
    return _save(conn, row, parameters=parameters)


def move_parameter(
    conn: sqlite3.Connection, function_id: int, *, index: int, to_index: int
) -> dict[str, Any]:
    """Move one parameter to *to_index*, recomputing the arrival locations.

    Argument order decides where the target convention passes each argument,
    so every parameter that carries an ``at`` is recomputed from its new index
    through :func:`default_at`; an ``at`` the convention table cannot place (an
    unknown calling convention) keeps its value, and an absent one stays
    absent.  A move to the same index is a no-op.
    """
    row = _load(conn, function_id)
    parameters = list(row["parameters"])
    if not 0 <= index < len(parameters):
        raise UnknownParameterError(f"parameter index {index} is out of range")
    if not 0 <= to_index < len(parameters):
        raise UnknownParameterError(f"parameter index {to_index} is out of range")
    if index == to_index:
        return row
    moved = parameters.pop(index)
    parameters.insert(to_index, moved)
    convention = str(row["calling_convention"] or "")
    reordered: list[dict[str, Any]] = []
    for position, parameter in enumerate(parameters):
        updated = dict(parameter)
        if updated.get("at"):
            derived = default_at(convention, position)
            if derived is not None:
                updated["at"] = derived
        reordered.append(updated)
    return _save(conn, row, parameters=reordered)


def remove_parameter(conn: sqlite3.Connection, function_id: int, *, index: int) -> dict[str, Any]:
    """Remove one parameter by index, reindexing the rest."""
    row = _load(conn, function_id)
    parameters = list(row["parameters"])
    if not 0 <= index < len(parameters):
        raise UnknownParameterError(f"parameter index {index} is out of range")
    del parameters[index]
    return _save(conn, row, parameters=parameters)


def delete_signature(conn: sqlite3.Connection, function_id: int) -> bool:
    """Delete one signature; False for an unknown function id.

    The deleted row's state is appended to the function's history first, so a
    revert can put the row back.
    """
    row = store.get_signature(conn, function_id)
    if row is None:
        return False
    _record(conn, function_id, _state(row), source=SOURCE_MANUAL, actor=DEFAULT_ACTOR)
    return store.delete_signature(conn, function_id)


def list_history(conn: sqlite3.Connection, function_id: int) -> list[dict[str, Any]]:
    """One function's signature history, newest first."""
    return [_history_view(entry) for entry in store.list_signature_history(conn, function_id)]


def get_history(conn: sqlite3.Connection, history_id: int) -> dict[str, Any] | None:
    """One signature-history row by id, or None."""
    entry = store.get_signature_history(conn, history_id)
    return _history_view(entry) if entry is not None else None


def revert_history(
    conn: sqlite3.Connection,
    function_id: int,
    history_id: int,
    *,
    actor: str = DEFAULT_ACTOR,
) -> dict[str, Any]:
    """Restore the state one history row recorded, undoing that mutation.

    The state the revert itself replaces is appended to the history (source
    ``revert``), so the revert is revertible in turn.  Reverting an entry whose
    state the signature already holds changes nothing, appends no history row
    and reports ``changed: false``: a second revert of the same row is a no-op,
    not a second restore.  Raises :class:`UnknownHistoryError` for a history id
    that names no row of *function_id*.
    """
    entry = get_history(conn, history_id)
    if entry is None or int(entry["function_id"]) != function_id:
        raise UnknownHistoryError(f"no history {history_id} for function {function_id}")
    previous = entry["previous"]
    current = store.get_signature(conn, function_id)
    if previous is None:
        if current is None:
            return {
                "function_id": function_id,
                "history_id": history_id,
                "changed": False,
                "signature": None,
            }
        _record(conn, function_id, _state(current), source=SOURCE_REVERT, actor=actor)
        store.delete_signature(conn, function_id)
        return {
            "function_id": function_id,
            "history_id": history_id,
            "changed": True,
            "signature": None,
        }
    if current is not None and _state(current) == previous:
        return {
            "function_id": function_id,
            "history_id": history_id,
            "changed": False,
            "signature": current,
        }
    _record(
        conn,
        function_id,
        None if current is None else _state(current),
        source=SOURCE_REVERT,
        actor=actor,
    )
    store.upsert_signature(
        conn,
        function_id=function_id,
        name=str(previous["name"]),
        return_type=str(previous["return_type"]),
        calling_convention=str(previous["calling_convention"]),
        parameters=list(previous["parameters"]),
        source=str(previous["source"]),
    )
    return {
        "function_id": function_id,
        "history_id": history_id,
        "changed": True,
        "signature": store.get_signature(conn, function_id),
    }


def seed_signatures(conn: sqlite3.Connection, *, binary_id: int) -> dict[str, Any]:
    """Seed the model from the binary's functions that carry a decompilation.

    Each stored decompilation's declaration line is parsed and upserted on the
    function id; a decompilation whose line does not parse is skipped with a
    reason.  A function with no stored decompilation is not touched.
    """
    created = 0
    updated = 0
    skipped: list[dict[str, Any]] = []
    for function in store.list_functions(conn, binary_id=binary_id):
        function_id = int(function["id"])
        stored = store.get_decompilation(conn, function_id)
        if stored is None:
            continue
        parsed = parse_signature(str(stored["code"]))
        if parsed is None:
            skipped.append(
                {
                    "function_id": function_id,
                    "name": str(function["name"] or ""),
                    "reason": "no function declaration line",
                }
            )
            continue
        existing = store.get_signature(conn, function_id)
        target = {
            "name": parsed["name"],
            "return_type": parsed["return_type"],
            "calling_convention": parsed["calling_convention"],
            "parameters": parsed["parameters"],
            "source": SOURCE_DECOMPILATION,
        }
        if existing is None or _state(existing) != target:
            _record(
                conn,
                function_id,
                None if existing is None else _state(existing),
                source=SOURCE_DECOMPILATION,
                actor=DEFAULT_ACTOR,
            )
        store.upsert_signature(
            conn,
            function_id=function_id,
            name=parsed["name"],
            return_type=parsed["return_type"],
            calling_convention=parsed["calling_convention"],
            parameters=parsed["parameters"],
            source=SOURCE_DECOMPILATION,
        )
        if existing is None:
            created += 1
        else:
            updated += 1
    return {
        "binary_id": binary_id,
        "created": created,
        "updated": updated,
        "skipped": len(skipped),
        "skipped_functions": skipped,
    }


def _parameter_annotation(parameter: Mapping[str, Any]) -> str:
    """The C comment one parameter's set fields render, or an empty string.

    Only the fields the model carries appear, so an absent arrival location is
    not claimed; ``at``, ``kind`` and ``bits`` render in that fixed order.
    """
    parts: list[str] = []
    at = parameter.get("at")
    if at:
        parts.append(f"at {at}")
    kind = parameter.get("kind")
    if kind:
        parts.append(f"kind {kind}")
    bits = parameter.get("bits")
    if isinstance(bits, int) and not isinstance(bits, bool):
        parts.append(f"{bits} bits")
    return f" /* {', '.join(parts)} */" if parts else ""


def _render_parameter(parameter: Mapping[str, Any]) -> str:
    """Render one parameter as a C declaration, with its set fields annotated."""
    body, suffix = _split_array(str(parameter["type"]))
    name = str(parameter.get("name") or "")
    declaration = f"{body} {name}".strip() if name else body
    return f"{declaration}{suffix}{_parameter_annotation(parameter)}"


def render_prototype(signature: Mapping[str, Any]) -> str:
    """Render one signature as a C prototype ending with ``;``."""
    head = str(signature["return_type"])
    convention = str(signature.get("calling_convention") or "")
    if convention:
        head = f"{head} __{convention}"
    parameters = list(signature.get("parameters") or [])
    rendered = ", ".join(_render_parameter(parameter) for parameter in parameters)
    return f"{head} {signature['name']}({rendered or 'void'});"


def render_prototypes(signatures: Sequence[Mapping[str, Any]]) -> str:
    """Render the model as one ``#pragma once`` prototype header.

    Prototypes are ordered by function name (then function id), so the same
    model always renders the same bytes.
    """
    ordered = sorted(signatures, key=lambda item: (str(item["name"]), int(item["function_id"])))
    lines = ["#pragma once", ""]
    lines.extend(render_prototype(signature) for signature in ordered)
    return "\n".join(lines).rstrip("\n") + "\n"


def export_prototypes(
    conn: sqlite3.Connection, *, binary_id: int, path: str | Path, force: bool = False
) -> dict[str, Any]:
    """Write the rendered prototypes to *path*, atomically.

    The target's parent directory is created only when its own parent already
    exists, so a typo cannot materialize a tree; an existing target is refused
    without ``force``.
    """
    signatures = list_signatures(conn, binary_id=binary_id)
    header = render_prototypes(signatures).encode("utf-8")
    target = Path(path).expanduser()
    parent = target.parent
    if not parent.is_dir():
        if parent.parent.is_dir():
            parent.mkdir()
        else:
            raise ExportParentMissingError(f"parent directory does not exist: {parent}")
    if target.exists() and not force:
        raise ExportExistsError(f"refusing to overwrite {target} without force")

    handle, temp_name = tempfile.mkstemp(dir=parent, prefix=".signatures-")
    # fdopen takes ownership only on success; close the raw fd only when it never did.
    owned = True
    try:
        with os.fdopen(handle, "wb") as stream:
            owned = False
            stream.write(header)
        os.replace(temp_name, target)
    except BaseException:
        if owned:
            with contextlib.suppress(OSError):
                os.close(handle)
        raise
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
    return {"path": str(target), "bytes": len(header), "signatures": len(signatures)}

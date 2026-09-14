"""Editable data types: the local type model, its C rendering and its indices.

Struct recovery (``rebrew recover-structs``) emits C typedefs that reportal
stores as a ``structs`` scan.  This module parses those definitions and the
edits made over them into a local model (``data_types``, one row per binary
and name) and renders it back as a C header.  Every mutation (an import that
creates a type, a rename, a namespace or kind change, a member add, edit or
remove, a delete) records the state it replaced and the state it wrote in
``data_type_history``, so an edit is revertible exactly and a reader can see
which field changed.

Model layout: the row carries the declaration *kind* (``struct``, ``union``,
``enum``, ``typedef``, ``pointer``, ``array``, ``function``), the optional
``namespace``, the *declared size*, and the kind-specific data a struct-shaped
row cannot hold: an enum's named values, a typedef or pointer's target, an
array's element type and count, a function type's return type and parameters.
A *bitfield* is not a type kind; it is a property of one member, so it lives on
the member as its width in bits and never forces the containing declaration
into another shape.  A member is one row of a struct or union (or one parameter
of a function type); an enum with named values is not a struct with offsets at
all, so its values live on the row.

A member carries the full shape a caller can set: ``name``, ``type``,
``pointer``, ``count`` and ``bits``.  A write can also name where the member
goes: ``index`` is the position it takes and ``after`` names the member it
follows, and the two are exclusive (a request naming both is refused).  The
offsets and the size are always derived from the member list through
:func:`recompute`, never accepted from the caller; a retype replaces the
member's ``type``/``pointer``/``count`` and leaves its hand-set ``bits`` alone,
and an explicit ``bits=None`` is what clears a bitfield.

The *declared size* is what the row stores; :func:`size_check` compares it with
the extent the member list implies and reports the disagreement it finds rather
than silently rewriting either number.  A caller can set the declared size
(``PATCH``/``type-size``) the way the platform's editor offers a Size field; a
member write then recomputes it from the members again.

Padding has two representations and the model keeps them distinct: an *implicit*
hole is a byte range no member covers, rendered as a ``/* +0xN padding */``
comment, and an *explicit* gap is an ordinary member named ``gap_XXXX`` over a
``char`` array of the gap's size, the convention ``rebrew recover-structs``
emits.  The explicit member wins: a member is model state, so the renderer emits
it, and the padding comment only marks bytes no member covers.  Rendering a gap
member as a comment would drop model state and stop the recovered definitions
from round-tripping, so a layout expressed with an explicit gap and one left as
a hole remain different models that render truthfully.

The recovery engine only ever emits ``typedef struct``, so an imported row is
always a struct.  A row written before the kind column existed is therefore a
struct by construction: the migration defaults it to ``struct`` and invents no
other kind for a row nobody declared.  The other kinds enter through the
parser when a definition names them, and through the model's own tests.

``store.py`` owns the table DDL and the row primitives; this module owns
parsing, validation, offset computation, rendering, filtering, the namespace
tree and the reverse indices, and is what the API, the CLI and the MCP tools
call.
"""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from reportal import store

# Declaration kinds the model carries.  These are reportal's own lower-case
# names for the shapes a recovered or hand-authored declaration can take; the
# hosted portal spells some of them differently (FUNCTION_DEFINITION, BASE),
# and its ``bitfield`` kind has no local source, so it is not modelled here.
KIND_STRUCT = "struct"
KIND_UNION = "union"
KIND_ENUM = "enum"
KIND_TYPEDEF = "typedef"
KIND_POINTER = "pointer"
KIND_ARRAY = "array"
KIND_FUNCTION = "function"
KINDS: frozenset[str] = frozenset(
    {KIND_STRUCT, KIND_UNION, KIND_ENUM, KIND_TYPEDEF, KIND_POINTER, KIND_ARRAY, KIND_FUNCTION}
)

# A row that was imported from the stored structs scan is a struct: that is the
# only shape ``rebrew recover-structs`` emits, and it is the default the
# migration applies to a row written before the kind column existed.
DEFAULT_KIND = KIND_STRUCT

# The namespace node a type with no namespace is grouped under.  The recovery
# engine names no namespace, so an empty namespace means the binary's own type;
# a non-empty one is a header namespace the decompiler inferred.
PROGRAM_NAMESPACE = "Binary"

# Byte widths of the primitives the recovery engine and hand edits use.  A
# type outside this table is recorded with size 0 and a note instead of
# failing the parse, so an unknown spelling never loses the member.
PRIMITIVE_SIZES: dict[str, int] = {
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "short": 2,
    "unsigned short": 2,
    "int": 4,
    "unsigned int": 4,
    "long": 4,
    "unsigned long": 4,
    "float": 4,
    "double": 8,
}

# A pointer is four bytes on the 32-bit targets reportal recovers types for,
# and so is a function type's pointer form.
POINTER_SIZE = 4

# A C enum is int-width on those same targets.  The recovery engine reports no
# enum size, so this is the model's declared width, not a measured one.
ENUM_SIZE = 4

# The gap member convention `rebrew recover-structs` emits for a hole it can
# name: a `char` array named after the offset it starts at, `char gap_0004[0x10];`.
# A caller converting a member to padding produces the same shape, and
# :func:`is_gap_member` recognizes it.
GAP_PREFIX = "gap_"
GAP_TYPE = "char"
_GAP_NAME_RE = re.compile(r"\Agap_[0-9A-Fa-f]+\Z")

# A bitfield carries at least one bit; C cannot represent a narrower width, so
# the model refuses it.
MIN_BITFIELD_BITS = 1

# The smallest padding run an explicit gap can carry.
MIN_GAP_BYTES = 1

# A type's declared size is a byte count and cannot be negative.
MIN_TYPE_SIZE = 0

# The known kinds, in the stable order an error detail and the tool schema list
# them, so a refusal always spells the same names in the same order.
KNOWN_KINDS: tuple[str, ...] = tuple(sorted(KINDS))

# Source recorded on a row imported from the stored structs scan, and on a row
# a caller created or edited by hand.
SOURCE_SCAN = "scan"
SOURCE_MANUAL = "manual"

# Source recorded on a row that came from a debug symbol file, and on one the
# hosted portal's own features would have produced (the local equivalents are
# library identification and the AI bridge).
SOURCE_SYMBOL = "symbol"
SOURCE_UNSTRIP = "unstrip"
SOURCE_AI = "ai"

# The four provenance labels the hosted portal shows, and the one explicit table
# mapping a stored source onto them.  A source nobody declared falls to ``User``
# (a person's decision is the safest reading), and the ``ai`` prefix covers the
# bridge's own source names.
SOURCE_SYSTEM = "System"
SOURCE_USER = "User"
SOURCE_AUTO_UNSTRIP = "Auto Unstrip"
SOURCE_AI_AGENT = "AI"
SOURCE_LABELS: tuple[str, ...] = (
    SOURCE_SYSTEM,
    SOURCE_USER,
    SOURCE_AUTO_UNSTRIP,
    SOURCE_AI_AGENT,
)
SOURCE_MAP: dict[str, str] = {
    SOURCE_SCAN: SOURCE_SYSTEM,
    SOURCE_SYMBOL: SOURCE_SYSTEM,
    SOURCE_MANUAL: SOURCE_USER,
    SOURCE_UNSTRIP: SOURCE_AUTO_UNSTRIP,
    SOURCE_AI: SOURCE_AI_AGENT,
}
SOURCE_AI_PREFIX = "ai"


def source_label(source: Any) -> str:
    """The provenance label of one stored ``source`` value."""
    value = str(source or "").strip().lower()
    if value in SOURCE_MAP:
        return SOURCE_MAP[value]
    if value.startswith(SOURCE_AI_PREFIX) and len(value) > len(SOURCE_AI_PREFIX):
        return SOURCE_AI_AGENT
    return SOURCE_USER


def source_totals(types: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """The count per provenance label, in :data:`SOURCE_LABELS` order.

    Every label is present, including a zero, so the strip a reader sees is
    stable and a missing source reads as zero rather than as absent.
    """
    totals: dict[str, int] = dict.fromkeys(SOURCE_LABELS, 0)
    for data_type in types:
        totals[source_label(data_type.get("source"))] += 1
    return totals


# Source recorded on the history entry a revert appends, the way a rename
# revert records itself in ``name_history``.
SOURCE_REVERT = "revert"

# Actor recorded on a history row when the caller does not name one.
DEFAULT_ACTOR = "manual"

# Most definitions one bulk create or update accepts in a single call.
MAX_BULK_DEFINITIONS = 100

# The model fields a history entry diffs, in the order a listing renders them.
# ``source`` is recorded in the state (a revert restores it) but is not a model
# field, so it is not part of the diff a reader sees.
HISTORY_FIELDS: tuple[str, ...] = (
    "name",
    "kind",
    "namespace",
    "size",
    "members",
    "values",
    "target",
    "element_count",
)

# A C identifier; the model rejects anything else as a type or member name.
_IDENTIFIER_RE = re.compile(r"\A[A-Za-z_]\w*\Z")

# Words that spell a type rather than a parameter name, so a function
# parameter declaration whose last token is one of these is unnamed.
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
    }
)

# ``typedef struct|union|enum [tag] { body } name;`` with the body one member
# (or, for an enum, one named value) per line or comma.
_TAGGED_RE = re.compile(
    r"\A\s*typedef\s+(?P<kind>struct|union|enum)\s+(?P<tag>[A-Za-z_]\w*)?\s*"
    r"\{(?P<body>.*)\}\s*(?P<name>[A-Za-z_]\w*)\s*;\s*\Z",
    re.DOTALL,
)

# ``typedef <return> (*name)(<params>);`` names a function type.
_FUNCTION_RE = re.compile(
    r"\A\s*typedef\s+(?P<return>.+?)\s*\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*"
    r"\((?P<params>[^()]*)\)\s*;\s*\Z",
    re.DOTALL,
)

# ``typedef <type> name;`` names an alias, a pointer or an array type.  The
# whole body is captured and split afterwards, since an array suffix rides on
# the alias name rather than the type.
_TYPEDEF_RE = re.compile(r"\A\s*typedef\s+(?P<body>.+?)\s*;\s*\Z", re.DOTALL)

# The alias name is the last identifier of a typedef body, with an optional
# array dimension after it.  The lookbehind keeps the greedy name from
# starting inside another identifier (``HANDLE`` is not ``HANDL`` + ``E``).
_TYPEDEF_ALIAS_RE = re.compile(
    r"\A(?P<decl>.*?)(?<![A-Za-z0-9_])(?P<name>[A-Za-z_]\w*)(?P<dim>\s*\[[^\]]*\])?\s*\Z",
    re.DOTALL,
)

# A trailing array dimension, optional on a member declaration and on the type
# text a caller writes when retyping one.
_ARRAY_SUFFIX_RE = re.compile(r"\[\s*(0[xX][0-9A-Fa-f]+|\d+)\s*\]\s*\Z")

# The relationship labels the reverse index reports, matching the hosted
# portal's wording so the panel reads the same either way.
RELATION_MEMBER = "as a member"
RELATION_TYPEDEF_TARGET = "as a typedef target"
RELATION_POINTEE = "as a pointee"
RELATION_ARRAY_ELEMENT = "as an array element"
RELATION_PARAMETER = "as a parameter"
RELATION_RETURN_TYPE = "as a return type"

# The reverse indices match a referenced name inside a member, target or
# signature type text.  It is a name match, not a resolved identity: a name
# that a namespace or a local declaration shadows is still reported.
REFERENCES_NOTE = (
    "Matching is by name: a namespaced or shadowed name is reported as an "
    "ordinary name match, not a proven identity."
)


class _Unset:
    """A field the caller did not name, distinct from one set to null.

    A member edit clears a field with an explicit ``None`` (a bitfield loses its
    width) and leaves it alone by omitting it, so the two cannot share a value.
    """


UNSET: _Unset = _Unset()


class DataTypeError(ValueError):
    """Base class for a data-type model failure."""


class DefinitionError(DataTypeError):
    """A recovered definition does not match a shape the model parses."""


class InvalidIdentifierError(DataTypeError):
    """A type or member name is not a C identifier."""


class DuplicateNameError(DataTypeError):
    """Another type of the same binary already carries the name."""


class DuplicateMemberError(DataTypeError):
    """Another member of the same type already carries the name."""


class UnknownDataTypeError(DataTypeError):
    """No data type row carries the id."""


class UnknownMemberError(DataTypeError):
    """A member selector matches no member of the type."""


class UnknownHistoryError(DataTypeError):
    """No data-type history row carries the id for this type."""


class NoScanError(DataTypeError):
    """The binary has no stored structs scan to import from."""


class InvalidMemberError(DataTypeError):
    """A member edit is unusable (no operation, an unparsable type or a kind without members)."""


class InvalidKindError(DataTypeError):
    """A kind change names a declaration shape the model does not carry."""


class InvalidSizeError(DataTypeError):
    """A declared size is not a byte count the model can store."""


class UnknownValueError(DataTypeError):
    """An enum value selector matches no named value of the type."""


class DuplicateValueError(DataTypeError):
    """Another enum value of the same type already carries the name or the value."""


class InvalidValueError(DataTypeError):
    """An enum value edit is unusable (a kind without values, a bad literal or no operation)."""


class EmptyStructError(DataTypeError):
    """Removing the member would leave the struct empty."""


class ExportExistsError(DataTypeError):
    """The export target exists and the caller did not pass ``force``."""


class ExportParentMissingError(DataTypeError):
    """The export target's parent directory cannot be created."""


def _resolve(type_text: str, pointer: bool, count: int | None) -> tuple[int, str]:
    """Return ``(size, note)`` for a member of *type_text*.

    A pointer is four bytes whatever its base; an array multiplies its element
    size by the count.  An unknown base is size 0 with a note naming it.
    """
    if pointer:
        element = POINTER_SIZE
        note = ""
    else:
        found = PRIMITIVE_SIZES.get(type_text)
        if found is None:
            return 0, f"unknown type: {type_text}"
        element = found
        note = ""
    return (element * count if count is not None else element), note


def _member(
    name: str, type_text: str, pointer: bool, count: int | None, bits: int | None = None
) -> dict[str, Any]:
    """Build one model member, deriving its size and note."""
    size, note = _resolve(type_text, pointer, count)
    return {
        "name": name,
        "type": type_text,
        "pointer": pointer,
        "count": count,
        "bits": bits,
        "offset": 0,
        "size": size,
        "note": note,
    }


def _split_array(text: str) -> tuple[str, int | None]:
    """Split a trailing ``[count]`` off *text*, returning the rest and the count."""
    match = _ARRAY_SUFFIX_RE.search(text)
    if match is None:
        return text.rstrip(), None
    return text[: match.start()].rstrip(), int(match.group(1), 0)


def _split_stars(text: str) -> tuple[str, int]:
    """Split a trailing run of ``*`` off *text*, returning the rest and the count."""
    body = text.rstrip()
    stars = 0
    while body.endswith("*"):
        stars += 1
        body = body[:-1].rstrip()
    return body, stars


def parse_member_type(type_text: str) -> tuple[str, bool, int | None]:
    """Return ``(base type, is pointer, array count)`` for a member type text.

    Raises :class:`InvalidMemberError` for a text that is not a type declaration.
    """
    body, count = _split_array((type_text or "").strip())
    body, stars = _split_stars(body)
    tokens = body.split()
    if not tokens or not all(_IDENTIFIER_RE.match(token) for token in tokens):
        raise InvalidMemberError(f"not a type: {type_text!r}")
    return " ".join(tokens), stars > 0, count


def _size_of_type_text(type_text: str) -> int:
    """Return the byte size of a target type text, 0 when it is not a known primitive."""
    body, count = _split_array((type_text or "").strip())
    body, stars = _split_stars(body)
    if stars:
        return POINTER_SIZE
    element = PRIMITIVE_SIZES.get(body, 0)
    return element * count if count is not None else element


def _parse_member_line(line: str) -> tuple[str, str, bool, int | None, int | None]:
    """Return ``(name, base type, pointer, array count, bit width)`` for a member line.

    The member name is the last token of the declaration, so a multi-word type
    (``unsigned int``) is never confused with it.  A ``: width`` suffix marks a
    bitfield and is carried as the member's bit width.
    """
    text = line.strip()
    if not text.endswith(";"):
        raise DefinitionError(f"unsupported member line: {line}")
    body = text[:-1].strip()
    bits: int | None = None
    if ":" in body:
        body, _, width_text = body.partition(":")
        body = body.strip()
        width_text = width_text.strip()
        if not width_text.isdigit():
            raise DefinitionError(f"unsupported member line: {line}")
        bits = int(width_text)
    body, count = _split_array(body)
    tokens = body.split()
    if len(tokens) < 2:
        raise DefinitionError(f"unsupported member line: {line}")
    name_token = tokens[-1]
    stars = 0
    while name_token.startswith("*"):
        stars += 1
        name_token = name_token[1:]
    if not _IDENTIFIER_RE.match(name_token):
        raise DefinitionError(f"unsupported member line: {line}")
    try:
        type_text, type_pointer, type_count = parse_member_type(" ".join(tokens[:-1]))
    except InvalidMemberError as exc:
        raise DefinitionError(f"unsupported member line: {line}") from exc
    if count is not None and type_count is not None:
        raise DefinitionError(f"unsupported member line: {line}")
    return (
        name_token,
        type_text,
        type_pointer or stars > 0,
        count if count is not None else type_count,
        bits,
    )


def _parse_literal(text: str) -> int:
    """Parse a C integer literal (decimal, hex or octal) or raise."""
    try:
        return int(text, 0)
    except ValueError as exc:
        raise DefinitionError(f"not an integer literal: {text!r}") from exc


def _parse_enum_body(body: str) -> list[dict[str, Any]]:
    """Return ``[{"name", "value"}]`` for an enum body.

    An entry without ``= value`` continues from the previous value, following
    C's own rule; the first one starts at 0.
    """
    values: list[dict[str, Any]] = []
    seen: set[str] = set()
    expected = 0
    for raw in body.replace("\n", ",").split(","):
        entry = raw.strip()
        if not entry:
            continue
        name_text, _, value_text = entry.partition("=")
        name = name_text.strip()
        if not _IDENTIFIER_RE.match(name):
            raise DefinitionError(f"unsupported enum value: {entry}")
        if name in seen:
            raise DefinitionError(f"duplicate enum value: {name}")
        seen.add(name)
        value = _parse_literal(value_text.strip()) if value_text.strip() else expected
        values.append({"name": name, "value": value})
        expected = value + 1
    return values


def _parse_function_parameters(params_text: str) -> list[dict[str, Any]]:
    """Return the ordered parameters of a function-type declaration."""
    stripped = (params_text or "").strip()
    if not stripped or stripped == "void":
        return []
    parameters: list[dict[str, Any]] = []
    for entry in stripped.split(","):
        declaration = entry.strip()
        if not declaration:
            raise DefinitionError("empty function-type parameter")
        tokens = declaration.split()
        name = ""
        type_tokens = tokens
        last = tokens[-1]
        stars = 0
        while last.startswith("*"):
            stars += 1
            last = last[1:]
        if last and _IDENTIFIER_RE.match(last) and last not in _TYPE_KEYWORDS and len(tokens) >= 2:
            name = last
            type_tokens = tokens[:-1]
            if stars:
                type_tokens = [*type_tokens, "*" * stars]
        try:
            type_text, pointer, count = parse_member_type(" ".join(type_tokens))
        except InvalidMemberError as exc:
            raise DefinitionError(f"unsupported function-type parameter: {declaration}") from exc
        parameters.append(_member(name, type_text, pointer, count))
    return parameters


def normalize_members(
    members: Sequence[Mapping[str, Any]], *, kind: str = KIND_STRUCT
) -> tuple[list[dict[str, Any]], int]:
    """Recompute every member's offset and size; return ``(members, size)``.

    A struct lays its members end to end from offset 0.  A union puts every
    member at offset 0 (they overlap) and its size is the widest member.  Order
    is otherwise preserved.
    """
    offset = 0
    widest = 0
    normalized: list[dict[str, Any]] = []
    for member in members:
        size, note = _resolve(str(member["type"]), bool(member.get("pointer")), member.get("count"))
        bits = member.get("bits")
        normalized.append(
            {
                "name": str(member["name"]),
                "type": str(member["type"]),
                "pointer": bool(member.get("pointer")),
                "count": member.get("count"),
                "bits": None if bits is None else int(bits),
                "offset": 0 if kind == KIND_UNION else offset,
                "size": size,
                "note": note,
            }
        )
        if kind == KIND_UNION:
            widest = max(widest, size)
        else:
            offset += size
    return normalized, widest if kind == KIND_UNION else offset


def parse_definition(definition: str) -> dict[str, Any]:
    """Parse one recovered declaration into its model fields.

    Recognizes the tagged forms (``typedef struct|union|enum`` with a body), a
    function type (``typedef <ret> (*name)(<params>);``) and a plain typedef
    (an alias, a pointer or an array).  Returns ``{"kind", "name", "members",
    "values", "target", "element_count", "size"}``.

    Raises :class:`DefinitionError` for a definition that is none of those
    shapes, for an unparsable member or value line, or for a duplicate name.
    """
    text = definition or ""
    tagged = _TAGGED_RE.match(text)
    if tagged is not None:
        return _parse_tagged(tagged)
    function = _FUNCTION_RE.match(text)
    if function is not None:
        return _parse_function_type(function)
    alias = _TYPEDEF_RE.match(text)
    if alias is not None:
        return _parse_typedef(alias)
    raise DefinitionError("definition is not a typedef declaration")


def _parse_tagged(match: re.Match[str]) -> dict[str, Any]:
    """Parse a ``typedef struct|union|enum`` match into the model fields."""
    kind = match.group("kind")
    name = match.group("name")
    validate_identifier(name)
    if kind == KIND_ENUM:
        values = _parse_enum_body(match.group("body"))
        return {
            "kind": KIND_ENUM,
            "name": name,
            "members": [],
            "values": values,
            "target": "",
            "element_count": None,
            "size": ENUM_SIZE,
        }
    members: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in match.group("body").splitlines():
        line = raw.strip()
        if not line:
            continue
        member_name, type_text, pointer, count, bits = _parse_member_line(line)
        if member_name in seen:
            raise DefinitionError(f"duplicate member: {member_name}")
        seen.add(member_name)
        members.append(_member(member_name, type_text, pointer, count, bits))
    normalized, size = normalize_members(members, kind=kind)
    return {
        "kind": kind,
        "name": name,
        "members": normalized,
        "values": [],
        "target": "",
        "element_count": None,
        "size": size,
    }


def _parse_function_type(match: re.Match[str]) -> dict[str, Any]:
    """Parse a ``typedef <ret> (*name)(<params>);`` match into the model fields."""
    name = match.group("name")
    validate_identifier(name)
    target, pointer, count = parse_member_type(match.group("return").strip())
    if count is not None:
        raise DefinitionError("a function type's return type cannot be an array")
    parameters = _parse_function_parameters(match.group("params"))
    return {
        "kind": KIND_FUNCTION,
        "name": name,
        "members": parameters,
        "values": [],
        "target": f"{target} *" if pointer else target,
        "element_count": None,
        "size": POINTER_SIZE,
    }


def _parse_typedef(match: re.Match[str]) -> dict[str, Any]:
    """Parse a ``typedef <type> name;`` match into an alias, pointer or array type."""
    alias = _TYPEDEF_ALIAS_RE.match(match.group("body").strip())
    if alias is None:
        raise DefinitionError("definition is not a typedef declaration")
    name = alias.group("name")
    validate_identifier(name)
    count: int | None = None
    dimension = alias.group("dim")
    if dimension is not None:
        inner = dimension.strip()[1:-1].strip()
        if not inner:
            raise DefinitionError("a typedef array dimension must be sized")
        count = _parse_literal(inner)
    body, stars = _split_stars(alias.group("decl").strip())
    tokens = body.split()
    if not tokens or not all(_IDENTIFIER_RE.match(token) for token in tokens):
        raise DefinitionError(f"not a type: {alias.group('decl').strip()!r}")
    base = " ".join(tokens)
    if count is not None:
        return {
            "kind": KIND_ARRAY,
            "name": name,
            "members": [],
            "values": [],
            "target": base,
            "element_count": count,
            "size": _size_of_type_text(base) * count,
        }
    if stars:
        return {
            "kind": KIND_POINTER,
            "name": name,
            "members": [],
            "values": [],
            "target": base,
            "element_count": None,
            "size": POINTER_SIZE,
        }
    return {
        "kind": KIND_TYPEDEF,
        "name": name,
        "members": [],
        "values": [],
        "target": base,
        "element_count": None,
        "size": _size_of_type_text(base),
    }


def validate_identifier(name: str) -> str:
    """Return *name* when it is a C identifier, else raise :class:`InvalidIdentifierError`."""
    candidate = (name or "").strip()
    if not _IDENTIFIER_RE.match(candidate):
        raise InvalidIdentifierError(f"not a C identifier: {name!r}")
    return candidate


def validate_kind(kind: str) -> str:
    """Return *kind* when the model carries it, else raise :class:`InvalidKindError`.

    The refusal spells every known kind, so a caller learns the vocabulary from
    the error rather than a second request.
    """
    candidate = (kind or "").strip()
    if candidate not in KINDS:
        raise InvalidKindError(f"unknown kind {kind!r}; known kinds: {', '.join(KNOWN_KINDS)}")
    return candidate


def _validated_bits(bits: int) -> int:
    """Return a bit width, refusing one no C declaration can carry."""
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise InvalidMemberError(f"bit width must be an integer, got {bits!r}")
    if bits < MIN_BITFIELD_BITS:
        raise InvalidMemberError(f"bit width must be at least {MIN_BITFIELD_BITS}, got {bits}")
    return bits


def _validated_count(count: int) -> int:
    """Return an array count, refusing a non-integer."""
    if isinstance(count, bool) or not isinstance(count, int):
        raise InvalidMemberError(f"array count must be an integer, got {count!r}")
    if count < 0:
        raise InvalidMemberError(f"array count must not be negative, got {count}")
    return count


def _validated_size(size: int) -> int:
    """Return a declared size, refusing a non-integer or a negative one."""
    if isinstance(size, bool) or not isinstance(size, int):
        raise InvalidSizeError(f"size must be an integer, got {size!r}")
    if size < MIN_TYPE_SIZE:
        raise InvalidSizeError(f"size must not be negative, got {size}")
    return size


def parse_value(value: Any) -> int:
    """Return an enum constant's integer value from a decimal or ``0x`` literal.

    An integer is taken as-is; a string is parsed the way C parses it (decimal,
    ``0x`` hex or a leading-zero octal) through one base-detecting call, so a
    value the caller typed as ``0x1F`` and one it sent as ``31`` agree.
    """
    if isinstance(value, bool):
        raise InvalidValueError(f"enum value must be an integer, got {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise InvalidValueError("enum value must not be empty")
        try:
            return int(text, 0)
        except ValueError as exc:
            raise InvalidValueError(f"not an integer literal: {value!r}") from exc
    raise InvalidValueError(f"enum value must be an integer or a literal string, got {value!r}")


def is_gap_member(member: Mapping[str, Any]) -> bool:
    """Whether *member* is the recovered padding convention ``char gap_XXXX[N]``.

    The test is the naming convention the recovery engine and
    :func:`convert_to_gap` share, not a stored flag: a member named ``gap_``
    followed by hex digits, of type ``char``, without a pointer and with an
    array count.
    """
    if bool(member.get("pointer")):
        return False
    if str(member.get("type") or "") != GAP_TYPE:
        return False
    if member.get("count") is None:
        return False
    return _GAP_NAME_RE.match(str(member.get("name") or "")) is not None


def gap_name(offset: int) -> str:
    """The padding member name for a hole starting at *offset*, as recovery emits it."""
    return f"{GAP_PREFIX}{offset:04X}"


def _member_view(member: Mapping[str, Any]) -> dict[str, Any]:
    """One member as the API payload carries it, with its derived gap flag."""
    return {**member, "is_gap": is_gap_member(member)}


def _load(conn: sqlite3.Connection, data_type_id: int) -> dict[str, Any]:
    """Return the type row, or raise :class:`UnknownDataTypeError`."""
    row = store.get_data_type(conn, data_type_id)
    if row is None:
        raise UnknownDataTypeError(f"no data type with id {data_type_id}")
    return row


def _member_index(row: Mapping[str, Any], *, name: str | None, index: int | None) -> int:
    """Return the position of the selected member, or raise :class:`UnknownMemberError`."""
    members = list(row["members"])
    if index is not None:
        if 0 <= index < len(members):
            return index
        raise UnknownMemberError(f"member index {index} is out of range")
    if name is None:
        raise UnknownMemberError("no member selector given")
    for position, member in enumerate(members):
        if str(member["name"]) == name:
            return position
    raise UnknownMemberError(f"no member named {name!r}")


def _require_member_kind(row: Mapping[str, Any]) -> None:
    """Reject a member edit on a kind whose data is not a member list."""
    if str(row.get("kind") or DEFAULT_KIND) not in (KIND_STRUCT, KIND_UNION, KIND_FUNCTION):
        raise InvalidMemberError(f"kind {row.get('kind')!r} has no editable member list")


def _require_value_kind(row: Mapping[str, Any]) -> None:
    """Reject an enum value edit on a kind whose data is not a value list."""
    if str(row.get("kind") or DEFAULT_KIND) != KIND_ENUM:
        raise InvalidValueError(f"kind {row.get('kind')!r} has no enum values")


def _insert_position(row: Mapping[str, Any], *, index: int | None, after: str | None) -> int:
    """Return where a new member goes, refusing both selectors at once.

    ``index`` is the position the member takes (``len(members)`` appends) and
    ``after`` names the member it follows; a request naming both is refused
    rather than silently picking one.
    """
    if index is not None and after is not None:
        raise InvalidMemberError(
            "index and after are exclusive; name the position with one of them"
        )
    members = list(row["members"])
    if index is None and after is None:
        return len(members)
    if index is not None:
        if 0 <= index <= len(members):
            return index
        raise UnknownMemberError(f"insert index {index} is out of range")
    for position, member in enumerate(members):
        if str(member["name"]) == after:
            return position + 1
    raise UnknownMemberError(f"no member named {after!r} to insert after")


def _value_index(row: Mapping[str, Any], *, name: str | None, index: int | None) -> int:
    """Return the position of the selected enum value, or raise."""
    values = list(row["values"])
    if index is not None:
        if 0 <= index < len(values):
            return index
        raise UnknownValueError(f"enum value index {index} is out of range")
    if name is None:
        raise UnknownValueError("no enum value selector given")
    for position, value in enumerate(values):
        if str(value["name"]) == name:
            return position
    raise UnknownValueError(f"no enum value named {name!r}")


def recompute(
    kind: str, members: Sequence[Mapping[str, Any]], target: str, element_count: int | None
) -> tuple[list[dict[str, Any]], int]:
    """Return the normalized members and the size for one kind.

    This is the one place the size rule per kind lives, so an edit, an import
    and a caller building a row by hand agree on it.
    """
    if kind in (KIND_STRUCT, KIND_UNION):
        return normalize_members(members, kind=kind)
    if kind == KIND_FUNCTION:
        normalized, _ = normalize_members(members)
        return normalized, POINTER_SIZE
    if kind == KIND_POINTER:
        return [dict(member) for member in members], POINTER_SIZE
    if kind == KIND_ARRAY:
        count = 0 if element_count is None else int(element_count)
        return [dict(member) for member in members], _size_of_type_text(target) * count
    if kind == KIND_ENUM:
        return [], ENUM_SIZE
    return [dict(member) for member in members], _size_of_type_text(target)


# ── History ────────────────────────────────────────────────────────


def _state(row: Mapping[str, Any]) -> dict[str, Any]:
    """The editable state of a type row, as one history entry records it.

    ``source`` is part of the recorded state so a revert restores it, but it is
    not one of :data:`HISTORY_FIELDS`, so it never shows up as a change.
    """
    count = row.get("element_count")
    return {
        "name": str(row["name"]),
        "kind": str(row.get("kind") or DEFAULT_KIND),
        "namespace": str(row.get("namespace") or ""),
        "size": int(row["size"]),
        "members": [dict(member) for member in row.get("members") or []],
        "values": [dict(value) for value in row.get("values") or []],
        "target": str(row.get("target") or ""),
        "element_count": None if count is None else int(count),
        "source": str(row.get("source") or ""),
    }


def _changed(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    """Whether two recorded states differ in a model field."""
    return any(previous.get(field) != current.get(field) for field in HISTORY_FIELDS)


def _changes(
    previous: Mapping[str, Any] | None, current: Mapping[str, Any] | None
) -> list[dict[str, Any]]:
    """The per-field diff two recorded states carry, in a fixed field order.

    A creation or a deletion has one side missing, so the entry itself (its
    ``previous`` or ``current`` null) is what states the shape of the change and
    the diff is empty; listing every field as added or removed would not.
    """
    if previous is None or current is None:
        return []
    return [
        {"field": field, "before": previous.get(field), "after": current.get(field)}
        for field in HISTORY_FIELDS
        if previous.get(field) != current.get(field)
    ]


def _history_view(entry: Mapping[str, Any]) -> dict[str, Any]:
    """A history row plus the per-field diff its two recorded states carry."""
    return {**entry, "changes": _changes(entry.get("previous"), entry.get("current"))}


def _record(
    conn: sqlite3.Connection,
    *,
    data_type_id: int,
    binary_id: int,
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any] | None,
    source: str,
    actor: str = DEFAULT_ACTOR,
) -> int:
    """Append one history row for the states a write replaced and wrote."""
    return store.add_data_type_history(
        conn,
        data_type_id=data_type_id,
        binary_id=binary_id,
        previous=previous,
        current=current,
        source=source,
        actor=actor,
    )


def _restore(
    conn: sqlite3.Connection,
    *,
    data_type_id: int,
    binary_id: int,
    state: Mapping[str, Any],
) -> None:
    """Write a recorded state back onto a type, refusing a name another row holds."""
    clash = store.find_data_type_by_name(conn, binary_id, str(state["name"]))
    if clash is not None and int(clash["id"]) != data_type_id:
        raise DuplicateNameError(
            f"type {state['name']!r} is held by data type {int(clash['id'])};"
            " rename or delete that row first"
        )
    store.restore_data_type(
        conn,
        data_type_id=data_type_id,
        binary_id=binary_id,
        name=str(state["name"]),
        kind=str(state["kind"]),
        namespace=str(state["namespace"]),
        size=int(state["size"]),
        members=list(state["members"]),
        values=list(state["values"]),
        target=str(state["target"]),
        element_count=state["element_count"],
        source=str(state["source"]),
    )


def _revert_result(
    data_type_id: int,
    history_id: int,
    *,
    changed: bool,
    reason: str,
    data_type: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """One revert's report: what it did and the row the type now holds (or null)."""
    return {
        "data_type_id": data_type_id,
        "history_id": history_id,
        "changed": changed,
        "reason": reason,
        "data_type": data_type,
    }


def _save(
    conn: sqlite3.Connection,
    row: Mapping[str, Any],
    *,
    name: str | None = None,
    kind: str | None = None,
    namespace: str | None = None,
    members: Sequence[Mapping[str, Any]] | None = None,
    values: Sequence[Mapping[str, Any]] | None = None,
    target: str | None = None,
    element_count: int | None = None,
    size: int | None = None,
    source: str = SOURCE_MANUAL,
    actor: str = DEFAULT_ACTOR,
) -> dict[str, Any]:
    """Write back a type, recomputing the offsets and size its kind implies.

    ``size`` is the declared size: omitted, it is recomputed from the members
    the way every member write does; given (a caller setting the Size field), it
    is stored as-is and :func:`size_check` reports any disagreement with the
    members rather than the write rewriting either number.

    The state the write replaces and the state it writes are appended to the
    type's history first, so every mutation is revertible; a write that changes
    none of :data:`HISTORY_FIELDS` (a re-import of the same definition) records
    nothing rather than a row whose diff is empty.  The returned payload is the
    encoded row, so a caller sees the same shape a read serves.
    """
    previous = _state(row)
    current_kind = str(kind if kind is not None else row.get("kind") or DEFAULT_KIND)
    current_members = list(row["members"]) if members is None else list(members)
    current_values = (
        [dict(value) for value in (row.get("values") or [])]
        if values is None
        else [dict(value) for value in values]
    )
    current_target = str(target if target is not None else row.get("target") or "")
    current_count = row.get("element_count") if element_count is None else int(element_count)
    normalized, computed = recompute(current_kind, current_members, current_target, current_count)
    store.update_data_type(
        conn,
        int(row["id"]),
        name=None if name is None else validate_identifier(name),
        kind=current_kind,
        namespace=(str(row.get("namespace") or "") if namespace is None else namespace),
        size=computed if size is None else _validated_size(size),
        members=normalized,
        values=current_values,
        target=current_target,
        element_count=None if current_count is None else int(current_count),
        source=source,
    )
    updated = _load(conn, int(row["id"]))
    current = _state(updated)
    if _changed(previous, current):
        _record(
            conn,
            data_type_id=int(updated["id"]),
            binary_id=int(updated["binary_id"]),
            previous=previous,
            current=current,
            source=source,
            actor=actor,
        )
    return encode_type(updated)


def list_types(conn: sqlite3.Connection, *, binary_id: int) -> list[dict[str, Any]]:
    """The model of one binary, ordered by name."""
    return store.list_data_types(conn, binary_id)


def get_type(conn: sqlite3.Connection, data_type_id: int) -> dict[str, Any] | None:
    """One model type by id, or None."""
    return store.get_data_type(conn, data_type_id)


def update_type(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str | None = None,
    kind: str | None = None,
    namespace: str | None = None,
    size: int | None = None,
) -> dict[str, Any]:
    """Apply the type-level fields the caller names in one write.

    The write is one row and one history entry whatever it changes, so a
    kind switch and a namespace land together and diff together; an unknown kind
    is refused listing the known ones, and a rename still rejects an identifier
    clash inside the same binary.
    """
    row = _load(conn, data_type_id)
    if name is not None:
        candidate = validate_identifier(name)
        other = store.find_data_type_by_name(conn, int(row["binary_id"]), candidate)
        if other is not None and int(other["id"]) != int(row["id"]):
            raise DuplicateNameError(f"type {candidate!r} already exists for this binary")
        name = candidate
    if kind is not None:
        kind = validate_kind(kind)
    if size is not None:
        size = _validated_size(size)
    if name is None and kind is None and namespace is None and size is None:
        raise InvalidMemberError("one of name, kind, namespace or size is required")
    return _save(
        conn,
        row,
        name=name,
        kind=kind,
        namespace=None if namespace is None else str(namespace).strip(),
        size=size,
    )


def rename_type(conn: sqlite3.Connection, data_type_id: int, *, name: str) -> dict[str, Any]:
    """Rename a type, rejecting an identifier clash inside the same binary."""
    return update_type(conn, data_type_id, name=name)


def set_kind(conn: sqlite3.Connection, data_type_id: int, *, kind: str) -> dict[str, Any]:
    """Switch a type's declaration kind, recomputing its size from the new shape."""
    return update_type(conn, data_type_id, kind=kind)


def set_namespace(conn: sqlite3.Connection, data_type_id: int, *, namespace: str) -> dict[str, Any]:
    """Set a type's namespace (an empty string makes it program-defined)."""
    return update_type(conn, data_type_id, namespace=namespace)


def set_size(conn: sqlite3.Connection, data_type_id: int, *, size: int) -> dict[str, Any]:
    """Set a type's declared size without touching its members.

    The member list's own extent stays what :func:`recompute` derives, so a
    disagreement between the two becomes visible through :func:`size_check`
    rather than being papered over by rewriting either number.
    """
    return update_type(conn, data_type_id, size=size)


def update_member(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str | None = None,
    index: int | None = None,
    new_name: str | None = None,
    new_type: str | None = None,
    new_pointer: bool | None | _Unset = UNSET,
    new_count: int | None | _Unset = UNSET,
    new_bits: int | None | _Unset = UNSET,
) -> dict[str, Any]:
    """Rename and/or retype one member, by name or index.

    ``new_name`` and ``new_type`` are ``None`` when the caller leaves them
    alone; ``new_pointer``, ``new_count`` and ``new_bits`` default to
    :data:`UNSET` so an explicit ``None`` clears the field while an omitted one
    keeps it.  A retype replaces the member's ``type``, ``pointer`` and
    ``count`` and leaves a hand-set ``bits`` alone: the width stays what the
    caller set, even when the new type is narrower, and only an explicit
    ``new_bits=None`` clears a bitfield.
    """
    if (
        new_name is None
        and new_type is None
        and isinstance(new_pointer, _Unset)
        and isinstance(new_count, _Unset)
        and isinstance(new_bits, _Unset)
    ):
        raise InvalidMemberError(
            "one of new_name, new_type, new_pointer, new_count or new_bits is required"
        )
    row = _load(conn, data_type_id)
    _require_member_kind(row)
    members = list(row["members"])
    position = _member_index(row, name=name, index=index)
    member = dict(members[position])
    if new_name is not None:
        candidate = validate_identifier(new_name)
        if any(str(m["name"]) == candidate for i, m in enumerate(members) if i != position):
            raise DuplicateMemberError(f"member {candidate!r} already exists")
        member["name"] = candidate
    if new_type is not None:
        type_text, pointer, count = parse_member_type(new_type)
        member["type"] = type_text
        member["pointer"] = pointer
        member["count"] = count
    if not isinstance(new_pointer, _Unset):
        member["pointer"] = bool(new_pointer)
    if not isinstance(new_count, _Unset):
        member["count"] = None if new_count is None else _validated_count(new_count)
    if not isinstance(new_bits, _Unset):
        member["bits"] = None if new_bits is None else _validated_bits(new_bits)
    members[position] = member
    return _save(conn, row, members=members)


def add_member(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str,
    type_text: str,
    pointer: bool | None = None,
    count: int | None = None,
    bits: int | None = None,
    index: int | None = None,
    after: str | None = None,
) -> dict[str, Any]:
    """Add one member (or function-type parameter), appended or at a position.

    ``index`` is the position the new member takes and ``after`` names the
    member it follows; a request naming both is refused rather than silently
    picking one, and naming neither appends.  An explicit ``pointer`` or
    ``count`` wins over what the type text carries, and ``bits`` makes the
    member a bitfield.
    """
    row = _load(conn, data_type_id)
    _require_member_kind(row)
    candidate = validate_identifier(name)
    members = list(row["members"])
    if any(str(member["name"]) == candidate for member in members):
        raise DuplicateMemberError(f"member {candidate!r} already exists")
    base_type, parsed_pointer, parsed_count = parse_member_type(type_text)
    member = _member(
        candidate,
        base_type,
        parsed_pointer if pointer is None else bool(pointer),
        parsed_count if count is None else _validated_count(count),
        None if bits is None else _validated_bits(bits),
    )
    members.insert(_insert_position(row, index=index, after=after), member)
    return _save(conn, row, members=members)


def remove_member(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str | None = None,
    index: int | None = None,
) -> dict[str, Any]:
    """Remove one member; refusing the last one keeps the declaration non-empty."""
    row = _load(conn, data_type_id)
    _require_member_kind(row)
    members = list(row["members"])
    position = _member_index(row, name=name, index=index)
    if len(members) == 1:
        raise EmptyStructError("removing the last member would leave the declaration empty")
    del members[position]
    return _save(conn, row, members=members)


def convert_to_gap(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str | None = None,
    index: int | None = None,
    size: int | None = None,
) -> dict[str, Any]:
    """Replace one struct member with explicit padding named after its offset.

    The gap is the recovered convention (``char gap_XXXX[N]``), so a struct that
    spells a hole out renders the gap as an ordinary member and no longer needs
    the derived ``/* +0xN padding */`` comment.  The size defaults to the
    member's own, which keeps every later offset where it was; a different size
    shifts them and is recomputed like any other member write.
    """
    row = _load(conn, data_type_id)
    _require_member_kind(row)
    if str(row.get("kind") or DEFAULT_KIND) != KIND_STRUCT:
        raise InvalidMemberError(
            "only a struct's members can become padding; a union's members overlap"
        )
    members = list(row["members"])
    position = _member_index(row, name=name, index=index)
    member = dict(members[position])
    gap_size = int(member["size"]) if size is None else _validated_size(size)
    if gap_size < MIN_GAP_BYTES:
        raise InvalidMemberError(f"a gap must cover at least {MIN_GAP_BYTES} byte")
    gap = gap_name(int(member["offset"]))
    if any(str(m["name"]) == gap for i, m in enumerate(members) if i != position):
        raise DuplicateMemberError(f"member {gap!r} already exists")
    members[position] = _member(gap, GAP_TYPE, False, gap_size)
    return _save(conn, row, members=members)


def convert_from_gap(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str | None = None,
    index: int | None = None,
    new_name: str,
    new_type: str,
    pointer: bool | None | _Unset = UNSET,
    count: int | None | _Unset = UNSET,
    bits: int | None | _Unset = UNSET,
) -> dict[str, Any]:
    """Turn one padding member back into a named, typed member.

    The selected member must be a gap (the recovered ``char gap_XXXX[N]``
    convention) so the operation cannot be aimed at a real member by mistake;
    the new member keeps the gap's position, and its size comes from the type
    the caller names, so naming a different size shifts the members after it the
    way any member write does.
    """
    row = _load(conn, data_type_id)
    _require_member_kind(row)
    members = list(row["members"])
    position = _member_index(row, name=name, index=index)
    member = members[position]
    if not is_gap_member(member):
        raise InvalidMemberError(f"member {member['name']!r} is not a gap")
    return update_member(
        conn,
        data_type_id,
        index=position,
        new_name=new_name,
        new_type=new_type,
        new_pointer=pointer,
        new_count=count,
        new_bits=bits,
    )


def _value_owner(values: Sequence[Mapping[str, Any]], resolved: int, *, skip: int) -> str | None:
    """The name of the value *resolved* already carries, or None."""
    for position, value in enumerate(values):
        if position != skip and int(value["value"]) == resolved:
            return str(value["name"])
    return None


def add_value(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str,
    value: Any | None = None,
) -> dict[str, Any]:
    """Append one named enum constant, auto-incrementing when no value is given.

    An omitted value continues from the last constant the way C does (the first
    constant of an empty enum starts at 0), and the payload's ``note`` says which
    number was derived so a caller that meant an explicit one can see the guess.
    A duplicate name or an already-used value is refused.
    """
    row = _load(conn, data_type_id)
    _require_value_kind(row)
    candidate = validate_identifier(name)
    values = list(row["values"])
    if any(str(entry["name"]) == candidate for entry in values):
        raise DuplicateValueError(f"enum value {candidate!r} already exists")
    auto = value is None
    resolved = (int(values[-1]["value"]) + 1 if values else 0) if auto else parse_value(value)
    owner = _value_owner(values, resolved, skip=-1)
    if owner is not None:
        raise DuplicateValueError(f"enum value {resolved} is already used by {owner}")
    values.append({"name": candidate, "value": resolved})
    payload = _save(conn, row, values=values)
    if auto:
        payload["note"] = (
            f"value auto-incremented to {resolved} from {values[-2]['name']}"
            if len(values) > 1
            else f"value defaulted to {resolved} for the first constant"
        )
    return payload


def update_value(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str | None = None,
    index: int | None = None,
    new_name: str | None = None,
    new_value: Any | None = None,
) -> dict[str, Any]:
    """Rename and/or revalue one enum constant, by name or index.

    ``new_value`` accepts an integer or a decimal/``0x`` literal string; the
    payload echoes every constant as a decimal and a hex value.  A rename or a
    revalue that collides with another constant is refused, naming the constant
    it collides with.
    """
    if new_name is None and new_value is None:
        raise InvalidValueError("one of new_name or new_value is required")
    row = _load(conn, data_type_id)
    _require_value_kind(row)
    values = list(row["values"])
    position = _value_index(row, name=name, index=index)
    entry = dict(values[position])
    if new_name is not None:
        candidate = validate_identifier(new_name)
        if any(
            str(other["name"]) == candidate
            for other in (v for i, v in enumerate(values) if i != position)
        ):
            raise DuplicateValueError(f"enum value {candidate!r} already exists")
        entry["name"] = candidate
    if new_value is not None:
        resolved = parse_value(new_value)
        owner = _value_owner(values, resolved, skip=position)
        if owner is not None:
            raise DuplicateValueError(f"enum value {resolved} is already used by {owner}")
        entry["value"] = resolved
    values[position] = entry
    return _save(conn, row, values=values)


def remove_value(
    conn: sqlite3.Connection,
    data_type_id: int,
    *,
    name: str | None = None,
    index: int | None = None,
) -> dict[str, Any]:
    """Remove one enum constant; refusing the last one keeps the enum non-empty."""
    row = _load(conn, data_type_id)
    _require_value_kind(row)
    values = list(row["values"])
    position = _value_index(row, name=name, index=index)
    if len(values) == 1:
        raise EmptyStructError("removing the last value would leave the enumeration empty")
    del values[position]
    return _save(conn, row, values=values)


def delete_type(conn: sqlite3.Connection, data_type_id: int) -> bool:
    """Delete one type; False for an unknown id.

    The deleted row's state is appended to the type's history first, so a
    revert can put it back even though the row itself is gone.
    """
    row = store.get_data_type(conn, data_type_id)
    if row is None:
        return False
    _record(
        conn,
        data_type_id=data_type_id,
        binary_id=int(row["binary_id"]),
        previous=_state(row),
        current=None,
        source=SOURCE_MANUAL,
    )
    return store.delete_data_type(conn, data_type_id)


def list_history(conn: sqlite3.Connection, data_type_id: int) -> list[dict[str, Any]]:
    """One type's edit history, newest first, each entry carrying its per-field diff.

    The rows are keyed by the type id and do not cascade with ``data_types``, so
    a deleted type's history is still listed here; a type with no history yet
    (a row written straight through ``store.add_data_type``) answers an empty
    list rather than an error.
    """
    return [_history_view(entry) for entry in store.list_data_type_history(conn, data_type_id)]


def get_history(conn: sqlite3.Connection, history_id: int) -> dict[str, Any] | None:
    """One data-type-history row by id, or None."""
    entry = store.get_data_type_history(conn, history_id)
    return _history_view(entry) if entry is not None else None


def revert_history(
    conn: sqlite3.Connection,
    data_type_id: int,
    history_id: int,
    *,
    actor: str = DEFAULT_ACTOR,
) -> dict[str, Any]:
    """Restore the state one history row recorded, undoing that mutation.

    The state the revert itself replaces is appended to the history (source
    ``revert``), so a revert is revertible in turn.  Three cases change nothing
    and answer ``changed: false`` with the reason stated: the entry recorded a
    creation whose type is already gone, the type already holds the recorded
    state (so reverting the same entry twice is a no-op), or the type row was
    deleted without a recorded state to put back.  A row still present is
    updated in place; one that was deleted is re-inserted under its original id.
    Raises :class:`UnknownHistoryError` for an id that names no row of
    *data_type_id*, and :class:`DuplicateNameError` when another type of the
    binary now holds the name the recorded state carries.
    """
    entry = get_history(conn, history_id)
    if entry is None or int(entry["data_type_id"]) != data_type_id:
        raise UnknownHistoryError(f"no history {history_id} for data type {data_type_id}")
    previous = entry["previous"]
    current_row = store.get_data_type(conn, data_type_id)
    if previous is None:
        if current_row is None:
            return _revert_result(
                data_type_id,
                history_id,
                changed=False,
                reason="the type this entry created is already gone",
                data_type=None,
            )
        _record(
            conn,
            data_type_id=data_type_id,
            binary_id=int(current_row["binary_id"]),
            previous=_state(current_row),
            current=None,
            source=SOURCE_REVERT,
            actor=actor,
        )
        store.delete_data_type(conn, data_type_id)
        return _revert_result(data_type_id, history_id, changed=True, reason="", data_type=None)
    if current_row is not None and _state(current_row) == previous:
        return _revert_result(
            data_type_id,
            history_id,
            changed=False,
            reason="the type already holds that state",
            data_type=current_row,
        )
    _record(
        conn,
        data_type_id=data_type_id,
        binary_id=int(entry["binary_id"]),
        previous=None if current_row is None else _state(current_row),
        current=previous,
        source=SOURCE_REVERT,
        actor=actor,
    )
    _restore(
        conn,
        data_type_id=data_type_id,
        binary_id=int(entry["binary_id"]),
        state=previous,
    )
    return _revert_result(
        data_type_id,
        history_id,
        changed=True,
        reason="",
        data_type=store.get_data_type(conn, data_type_id),
    )


def import_types(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: Any | None = None,
) -> dict[str, Any]:
    """Seed the model from the binary's stored structs scan.

    The import is stored-only: an absent scan raises :class:`NoScanError` and no
    engine call is made, so *engine* is accepted only so call sites pass the
    process-wide engine the way the other scan importers do.
    """
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    stored = (
        None if analysis_id is None else store.get_scan(conn, analysis_id, store.SCAN_KIND_STRUCTS)
    )
    if stored is None:
        raise NoScanError(f"no structs scan for binary {binary_id}; recover structs first")
    entries = stored.get("structs")
    entries = entries if isinstance(entries, list) else []

    report = import_definitions(conn, binary_id=binary_id, definitions=entries, source=SOURCE_SCAN)
    return {
        "binary_id": binary_id,
        "created": report["created"],
        "updated": report["updated"],
        "skipped": report["skipped"],
        "skipped_types": report["skipped_types"],
    }


def split_definitions(text: str) -> list[str]:
    """Split a C header into its top-level declarations.

    A semicolon inside braces belongs to a struct, union or enum member, so only
    a ``;`` at brace depth zero ends a declaration; a ``//`` or ``/* */``
    comment and a ``#`` preprocessor line are dropped, because neither is a
    declaration the parser can use.  A trailing fragment without its semicolon
    is dropped rather than guessed at.
    """
    declarations: list[str] = []
    buffer: list[str] = []
    depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]
        if pair == "//":
            end = text.find("\n", index)
            index = len(text) if end < 0 else end + 1
            continue
        if pair == "/*":
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        if char == "#" and not "".join(buffer).strip():
            end = text.find("\n", index)
            index = len(text) if end < 0 else end + 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        elif char == ";" and depth == 0:
            candidate = "".join(buffer).strip()
            if candidate:
                declarations.append(f"{candidate};")
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    return declarations


def apply_definition(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    definition: Any,
    name_hint: str = "",
    create: bool = True,
    source: str = SOURCE_MANUAL,
) -> tuple[str, str]:
    """Create or update one type from a C definition; returns (outcome, detail).

    The outcome is ``created``, ``updated`` or ``skipped`` and the detail names
    the type or the reason.  *create* False refuses a definition whose name is
    not stored yet, which is the bulk-update half of the hosted route.
    """
    if not isinstance(definition, str) or not definition.strip():
        return "skipped", "no definition"
    try:
        parsed = parse_definition(definition)
    except DefinitionError as exc:
        return "skipped", str(exc)
    name = str(parsed["name"])
    try:
        validate_identifier(name)
    except InvalidIdentifierError as exc:
        return "skipped", str(exc)
    existing = store.find_data_type_by_name(conn, binary_id, name)
    if existing is None:
        if not create:
            return "skipped", f"no stored type named {name!r}"
        data_type_id = store.add_data_type(
            conn,
            binary_id=binary_id,
            name=name,
            size=parsed["size"],
            members=parsed["members"],
            kind=parsed["kind"],
            values=parsed["values"],
            target=parsed["target"],
            element_count=parsed["element_count"],
            source=source,
        )
        created_row = store.get_data_type(conn, data_type_id)
        if created_row is not None:
            _record(
                conn,
                data_type_id=data_type_id,
                binary_id=binary_id,
                previous=None,
                current=_state(created_row),
                source=source,
            )
        return "created", name
    _save(
        conn,
        existing,
        members=parsed["members"],
        kind=parsed["kind"],
        values=parsed["values"],
        target=parsed["target"],
        element_count=parsed["element_count"],
        source=source,
    )
    return "updated", name


def import_definitions(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    definitions: Sequence[Any],
    create: bool = True,
    source: str = SOURCE_MANUAL,
) -> dict[str, Any]:
    """Create or update types from caller-supplied C definitions.

    This is the bulk half of the hosted `POST|PUT /v3/analyses/{id}/data-types`
    route: *definitions* is a list of C declaration strings (or scan-shaped
    objects carrying one under ``definition``), each applied in order, and the
    report counts what each one did.  Nothing is inferred: an unusable
    definition is skipped with its reason rather than guessed at.
    """
    created = 0
    updated = 0
    skipped: list[dict[str, str]] = []
    applied: list[dict[str, str]] = []
    for entry in definitions:
        if isinstance(entry, dict):
            definition = entry.get("definition")
            hint = str(entry.get("name") or "")
        else:
            definition = entry
            hint = ""
        outcome, detail = apply_definition(
            conn,
            binary_id=binary_id,
            definition=definition,
            name_hint=hint,
            create=create,
            source=source,
        )
        if outcome == "skipped":
            skipped.append({"name": hint or detail, "reason": detail})
            continue
        applied.append({"name": detail, "outcome": outcome})
        if outcome == "created":
            created += 1
        else:
            updated += 1
    return {
        "binary_id": binary_id,
        "created": created,
        "updated": updated,
        "skipped": len(skipped),
        "skipped_types": skipped,
        "applied": applied,
    }


# ── Filtering and the namespace tree ───────────────────────────────

# The orders the type list accepts and the two directions it reads in.  ``name``
# is the order the model has always been read in, so it stays the default.
TYPE_SORTS: tuple[str, ...] = ("name", "size")
DEFAULT_TYPE_SORT = "name"
SORT_DIRECTIONS: tuple[str, ...] = ("asc", "desc")
DEFAULT_SORT_DIRECTION = "asc"


def sort_types(
    types: Sequence[dict[str, Any]],
    *,
    sort: str = DEFAULT_TYPE_SORT,
    direction: str = DEFAULT_SORT_DIRECTION,
) -> list[dict[str, Any]]:
    """Order *types* by name or size, in *direction*.

    A size the model could not state is zero (:func:`recompute` records an
    unknown base that way), and such a type sorts last in either direction: a
    type whose size is unknown would otherwise claim the head of a descending
    list, which reads as "the largest thing in this binary".  The name and the
    id break ties, so the order is the same for two types of one size.

    An unknown sort or direction raises ``ValueError``, which the API, the CLI
    and the MCP tools map to their own error vocabulary.
    """
    if sort not in TYPE_SORTS:
        raise ValueError(f"unknown type sort: {sort}")
    if direction not in SORT_DIRECTIONS:
        raise ValueError(f"unknown sort direction: {direction}")
    reverse = direction == "desc"
    if sort == "size":
        known = [row for row in types if _stated_size(row) > 0]
        unknown = [row for row in types if _stated_size(row) <= 0]
        known.sort(
            key=lambda row: (_stated_size(row), str(row["name"]).lower(), int(row["id"])),
            reverse=reverse,
        )
        unknown.sort(key=lambda row: (str(row["name"]).lower(), int(row["id"])))
        return known + unknown
    return sorted(
        types,
        key=lambda row: (str(row["name"]).lower(), int(row["id"])),
        reverse=reverse,
    )


def _stated_size(data_type: Mapping[str, Any]) -> int:
    """The size a row states, which is zero for one the model could not compute."""
    return int(data_type.get("size") or 0)


def filter_types(
    types: Sequence[dict[str, Any]],
    *,
    namespace: str | None = None,
    kind: str | None = None,
    search: str | None = None,
    source: str | None = None,
) -> list[dict[str, Any]]:
    """Return the types that match every given filter.

    ``namespace`` matches the path exactly or any descendant (ticking a branch
    includes everything beneath it); ``PROGRAM_NAMESPACE`` selects the types
    with no namespace.  ``search`` is a case-insensitive substring over the
    type name, its member names and its enum value names.  ``source`` is one of
    :data:`SOURCE_LABELS` and matches the type's provenance, which
    :func:`source_label` derives from its stored source.
    """
    result = list(types)
    if kind:
        result = [data_type for data_type in result if str(data_type["kind"]) == kind]
    if source:
        result = [
            data_type for data_type in result if source_label(data_type.get("source")) == source
        ]
    if namespace:
        result = [data_type for data_type in result if _in_namespace(data_type, namespace)]
    if search and search.strip():
        needle = search.strip().lower()
        result = [data_type for data_type in result if _matches_search(data_type, needle)]
    return result


def _in_namespace(data_type: Mapping[str, Any], namespace: str) -> bool:
    """Whether a type sits in *namespace* or below it."""
    current = str(data_type.get("namespace") or "")
    if namespace == PROGRAM_NAMESPACE:
        return current == ""
    return current == namespace or current.startswith(f"{namespace}::")


def _matches_search(data_type: Mapping[str, Any], needle: str) -> bool:
    """Whether *needle* (lowercased) appears in the name, a member name or a value name."""
    if needle in str(data_type["name"]).lower():
        return True
    for member in data_type.get("members") or []:
        if needle in str(member.get("name") or "").lower():
            return True
    for value in data_type.get("values") or []:
        if needle in str(value.get("name") or "").lower():
            return True
    return False


def namespace_tree(types: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Build the namespace tree over *types*, with the program group.

    Namespaces are split on ``::``; a node's count includes every type at or
    below it.  Types with no namespace are grouped under
    ``PROGRAM_NAMESPACE``, which is the system/program split the platform's
    tree shows.
    """
    nodes: dict[str, dict[str, Any]] = {}
    children: dict[str, list[str]] = {}
    program = 0
    for data_type in types:
        raw = str(data_type.get("namespace") or "")
        if not raw:
            program += 1
            continue
        path = ""
        for part in raw.split("::"):
            path = part if not path else f"{path}::{part}"
            if path not in nodes:
                nodes[path] = {"name": part, "path": path, "count": 0, "children": []}
                parent = path.rsplit("::", 1)[0] if "::" in path else ""
                children.setdefault(parent, []).append(path)
            nodes[path]["count"] += 1

    def build(path: str) -> dict[str, Any]:
        node = nodes[path]
        kids = sorted(children.get(path, []), key=lambda item: nodes[item]["name"].lower())
        node["children"] = [build(kid) for kid in kids]
        return node

    roots = sorted(children.get("", []), key=lambda item: nodes[item]["name"].lower())
    tree = [build(root) for root in roots]
    if program:
        tree.append(
            {"name": PROGRAM_NAMESPACE, "path": PROGRAM_NAMESPACE, "count": program, "children": []}
        )
    return tree


# ── Reverse indices ────────────────────────────────────────────────


def _names_type(type_text: str, name: str) -> bool:
    """Whether a member or target type text names *name* exactly.

    A trailing array dimension and pointer stars are stripped, and a ``struct
    ``/``union ``/``enum `` tag is removed, so ``struct Foo *`` names ``Foo``.
    The comparison is exact after that, which keeps ``int`` from matching
    ``unsigned int``.
    """
    body, _ = _split_array((type_text or "").strip())
    body, _ = _split_stars(body)
    for prefix in ("struct ", "union ", "enum "):
        if body.startswith(prefix):
            body = body[len(prefix) :].strip()
            break
    return body == name


def _signature_names_type(type_text: str, name: str) -> bool:
    """Whether a signature type text names *name* (array, stars and qualifiers stripped)."""
    body, _ = _split_array((type_text or "").strip())
    body = re.sub(r"\b(const|volatile)\b", " ", body)
    body = re.sub(r"[*]+", " ", body)
    body = re.sub(r"\b(struct|union|enum)\b", " ", body)
    return body.strip() == name


def _relationships(data_type: Mapping[str, Any], name: str) -> list[str]:
    """The ways one type references *name*, in a stable order."""
    kind = str(data_type.get("kind") or DEFAULT_KIND)
    relationships: list[str] = []
    members = list(data_type.get("members") or [])
    has_member = any(_names_type(str(member.get("type") or ""), name) for member in members)
    if has_member and kind in (KIND_STRUCT, KIND_UNION):
        relationships.append(RELATION_MEMBER)
    target = str(data_type.get("target") or "")
    if kind == KIND_TYPEDEF and _names_type(target, name):
        relationships.append(RELATION_TYPEDEF_TARGET)
    if kind == KIND_POINTER and _names_type(target, name):
        relationships.append(RELATION_POINTEE)
    if kind == KIND_ARRAY and _names_type(target, name):
        relationships.append(RELATION_ARRAY_ELEMENT)
    if kind == KIND_FUNCTION:
        if _names_type(target, name):
            relationships.append(RELATION_RETURN_TYPE)
        if has_member:
            relationships.append(RELATION_PARAMETER)
    return relationships


def _functions_using(conn: sqlite3.Connection, binary_id: int, name: str) -> list[dict[str, Any]]:
    """The functions whose stored signature names *name*."""
    names = {
        int(function["id"]): str(function["name"] or "")
        for function in store.list_functions(conn, binary_id=binary_id)
    }
    result: list[dict[str, Any]] = []
    for signature in store.list_signatures(conn, binary_id=binary_id):
        usages: list[str] = []
        if _signature_names_type(str(signature["return_type"]), name):
            usages.append(RELATION_RETURN_TYPE)
        if any(
            _signature_names_type(str(parameter.get("type") or ""), name)
            for parameter in signature["parameters"]
        ):
            usages.append(RELATION_PARAMETER)
        if not usages:
            continue
        function_id = int(signature["function_id"])
        result.append(
            {
                "function_id": function_id,
                "name": names.get(function_id, str(signature["name"])),
                "usages": usages,
            }
        )
    result.sort(key=lambda row: row["function_id"])
    return result


def references(conn: sqlite3.Connection, data_type_id: int) -> dict[str, Any]:
    """The two reverse indices for one type: what mentions it and which functions use it."""
    selected = _load(conn, data_type_id)
    name = str(selected["name"])
    referenced_by: list[dict[str, Any]] = []
    for other in store.list_data_types(conn, int(selected["binary_id"])):
        if int(other["id"]) == int(selected["id"]):
            continue
        relationships = _relationships(other, name)
        if relationships:
            referenced_by.append(
                {
                    "id": int(other["id"]),
                    "name": str(other["name"]),
                    "namespace": str(other["namespace"]),
                    "kind": str(other["kind"]),
                    "relationships": relationships,
                }
            )
    referenced_by.sort(key=lambda row: (row["name"], row["namespace"], row["id"]))
    used_by = _functions_using(conn, int(selected["binary_id"]), name)
    return {
        "data_type_id": int(selected["id"]),
        "binary_id": int(selected["binary_id"]),
        "name": name,
        "namespace": str(selected["namespace"]),
        "referenced_by": referenced_by,
        "used_by_functions": used_by,
        "count": len(referenced_by),
        "function_count": len(used_by),
        "note": REFERENCES_NOTE,
    }


# ── Rendering ──────────────────────────────────────────────────────


def _declaration(member: Mapping[str, Any]) -> str:
    """Render one member (or function-type parameter) as a C declaration."""
    text = f"{member['type']} {'*' if member.get('pointer') else ''}{member['name']}"
    if member.get("count") is not None:
        text += f"[{member['count']}]"
    if member.get("bits") is not None:
        text += f" : {member['bits']}"
    return f"{text};"


def _render_parameter(member: Mapping[str, Any]) -> str:
    """Render one function-type parameter, where the name is optional."""
    text = str(member["type"])
    pointer = bool(member.get("pointer"))
    if pointer:
        text = f"{text} *"
    name = str(member.get("name") or "")
    if name:
        text = f"{text}{name}" if pointer else f"{text} {name}"
    if member.get("count") is not None:
        text += f"[{member['count']}]"
    return text


def _render_values(values: Iterable[Mapping[str, Any]]) -> list[str]:
    """Render enum values as ``NAME = value`` entries, in declaration order."""
    return [f"{value['name']} = {value['value']}" for value in values]


def _render_block(data_type: Mapping[str, Any], *, sized: bool) -> list[str]:
    """Render one type as the lines of its C declaration.

    ``sized`` appends the ``/* size N */`` comment the export carries; the
    padded As-C form leaves it to the panel's own size readout.
    """
    kind = str(data_type.get("kind") or DEFAULT_KIND)
    name = str(data_type["name"])
    suffix = f" /* size {int(data_type['size'])} */" if sized else ""
    if kind in (KIND_STRUCT, KIND_UNION):
        members = sorted(
            enumerate(data_type["members"]),
            key=lambda pair: (int(pair[1]["offset"]), pair[0]),
        )
        lines = [f"typedef {kind} {name}_s {{"]
        if kind == KIND_UNION:
            lines.append("\t/* all members overlap */")
        lines.extend(f"\t{_declaration(member)}" for _, member in members)
        lines.append(f"}} {name};{suffix}")
        return lines
    if kind == KIND_ENUM:
        entries = _render_values(data_type.get("values") or [])
        lines = [f"typedef enum {name}_s {{"]
        if entries:
            lines.append("\t" + ",\n\t".join(entries))
        lines.append(f"}} {name};{suffix}")
        return lines
    if kind == KIND_TYPEDEF:
        return [f"typedef {data_type.get('target') or 'void'} {name};{suffix}"]
    if kind == KIND_POINTER:
        return [f"typedef {data_type.get('target') or 'void'} *{name};{suffix}"]
    if kind == KIND_ARRAY:
        count = data_type.get("element_count")
        dimension = "" if count is None else f"[{int(count)}]"
        return [f"typedef {data_type.get('target') or 'void'} {name}{dimension};{suffix}"]
    if kind == KIND_FUNCTION:
        parameters = [_render_parameter(member) for member in data_type.get("members") or []]
        rendered = ", ".join(parameters) or "void"
        return [f"typedef {data_type.get('target') or 'void'} (*{name})({rendered});{suffix}"]
    raise DataTypeError(f"unknown kind: {kind!r}")


def render_header(types: Sequence[Mapping[str, Any]]) -> str:
    """Render the model as one ``#pragma once`` C header.

    Types are ordered by name and a struct's members by offset, so the same
    model always renders the same bytes.  A struct block keeps exactly the
    form it always had; the other kinds each render their own C shape.
    """
    lines = ["#pragma once", ""]
    for data_type in sorted(types, key=lambda item: str(item["name"])):
        lines.extend(_render_block(data_type, sized=True))
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def render_as_c(data_type: Mapping[str, Any]) -> str:
    """Render one type as the padded "As C" block the platform shows.

    A struct's holes are explicit: the gap between two members (and any
    trailing gap up to the declared size) is emitted as a ``/* +0xN padding
    */`` comment computed from the real offsets.  A union states that all its
    members overlap.  Kinds with no standalone C form are still rendered as
    the declaration the export would write, minus the size comment.

    A member converted to an explicit gap renders as its own declaration
    (``char gap_0004[0x10];``), so the comment marks only the bytes no member
    covers and a member is never dropped from the block: the explicit member
    wins over the derived comment.
    """
    kind = str(data_type.get("kind") or DEFAULT_KIND)
    if kind not in (KIND_STRUCT, KIND_UNION):
        return "\n".join(_render_block(data_type, sized=False))
    name = str(data_type["name"])
    members = sorted(
        enumerate(data_type["members"]),
        key=lambda pair: (int(pair[1]["offset"]), pair[0]),
    )
    lines = [f"typedef {kind} {name}_s {{"]
    if kind == KIND_UNION:
        lines.append("\t/* all members overlap */")
        lines.extend(f"\t{_declaration(member)}" for _, member in members)
    else:
        cursor = 0
        for _, member in members:
            offset = int(member["offset"])
            if offset > cursor:
                lines.append(f"\t/* +0x{offset - cursor:x} padding */")
            lines.append(f"\t{_declaration(member)}")
            cursor = max(cursor, offset + int(member["size"]))
        size = int(data_type["size"])
        if size > cursor:
            lines.append(f"\t/* +0x{size - cursor:x} padding */")
    lines.append(f"}} {name};")
    return "\n".join(lines)


def member_extent(data_type: Mapping[str, Any]) -> int:
    """The size the type's members imply, whatever the row's declared size says."""
    return recompute(
        str(data_type.get("kind") or DEFAULT_KIND),
        data_type.get("members") or [],
        str(data_type.get("target") or ""),
        data_type.get("element_count"),
    )[1]


def size_check(data_type: Mapping[str, Any]) -> dict[str, Any]:
    """Compare a type's declared size with its members' extent.

    The check is read-only: it reports the two numbers and the disagreement it
    finds, and never rewrites either one.  A match answers ``warning: null``.
    """
    declared = int(data_type["size"])
    extent = member_extent(data_type)
    if declared == extent:
        return {"declared": declared, "extent": extent, "match": True, "warning": None}
    direction = (
        "trailing space no member covers"
        if declared > extent
        else "members extending past the declared size"
    )
    return {
        "declared": declared,
        "extent": extent,
        "match": False,
        "warning": (
            f"declared size {declared} disagrees with the members' extent {extent}: {direction}"
        ),
    }


def encode_type(data_type: Mapping[str, Any]) -> dict[str, Any]:
    """Return one type row as the API payload.

    The payload carries what a reader needs without a second call: every enum
    value as a decimal and a hex echo, every member's derived gap flag, the
    padded As-C block and the size-vs-members check.
    """
    payload = dict(data_type)
    payload["members"] = [_member_view(member) for member in data_type.get("members") or []]
    payload["values"] = [
        {"name": str(value["name"]), "value": int(value["value"]), "hex": hex(int(value["value"]))}
        for value in data_type.get("values") or []
    ]
    payload["as_c"] = render_as_c(data_type)
    payload["size_check"] = size_check(data_type)
    return payload


def export_header(
    conn: sqlite3.Connection, *, binary_id: int, path: str | Path, force: bool = False
) -> dict[str, Any]:
    """Write the rendered model to *path*, atomically.

    The target's parent directory is created only when its own parent already
    exists, so a typo cannot materialize a tree; an existing target is refused
    without ``force``.
    """
    types = list_types(conn, binary_id=binary_id)
    header = render_header(types).encode("utf-8")
    target = Path(path).expanduser()
    parent = target.parent
    if not parent.is_dir():
        if parent.parent.is_dir():
            parent.mkdir()
        else:
            raise ExportParentMissingError(f"parent directory does not exist: {parent}")
    if target.exists() and not force:
        raise ExportExistsError(f"refusing to overwrite {target} without force")

    handle, temp_name = tempfile.mkstemp(dir=parent, prefix=".types-")
    temp = Path(temp_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(header)
        os.replace(temp, target)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return {"path": str(target), "bytes": len(header), "types": len(types)}

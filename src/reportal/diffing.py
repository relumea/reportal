"""Line-level alignment of two listings for the portal's Match / Diff surface.

The hosted portal pairs two functions and marks the differences between their
assembly and decompilation.  This module is the local alignment core: it is
pure and standard-library only, so it needs no store and no engine and the
alignment can be tested on strings alone.

:func:`align` runs :class:`difflib.SequenceMatcher` over the two texts line by
line and returns ordered entries, each naming the operation and the 1-based
line number on each side (``None`` where that side has no line).  A ``replace``
opcode is expanded into a delete run followed by an insert run, so the entries
only ever carry ``equal``, ``insert`` and ``delete``; :func:`summary` reports
those counts plus ``changed``, the number of replacement groups a delete run
followed by an insert run forms.

:func:`strip_addresses` normalizes a listing before comparison.  rebrew's NASM
output carries the absolute address and the encoded bytes in a trailing ``;``
comment, and its hex output leads with an address column and a byte column;
neither says anything about the code, so removing them keeps register and
layout-only noise from dominating the diff.  The mnemonic and its operands
are kept.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Mapping, Sequence

# Operations `align` emits.  `replace` is part of the wire contract even though
# the implementation expands it, so a consumer can style it if a future
# aligner emits it.
OP_EQUAL = "equal"
OP_INSERT = "insert"
OP_DELETE = "delete"
OP_REPLACE = "replace"

# One alignment entry: the operation, the 1-based line on each side (None when
# that side has no line) and the line text itself.
DiffEntry = dict[str, object]

# Trailing comment of a C-style listing (decompiled source), from `//` to the
# end of the line.
_C_COMMENT = re.compile(r"\s*//.*$")

# Trailing comment of a rebrew NASM listing: `; 00100000  55` (the address and
# the encoded bytes) or `; trailing data`.  Only the engine's own comment shape
# is stripped, so a `;` inside an operand is left alone.
_NASM_COMMENT = re.compile(r"\s*;\s*(?:[0-9A-Fa-f]{8}\b|trailing data\b).*$")

# Leading absolute-address column of a hex listing: `0x00401000:` or a bare
# eight-digit address, optionally with a colon.  Anchored and restricted to a
# `0x` prefix or a full eight digits so a mnemonic spelled with hex digits
# (`fadd`, `beef`) is not mistaken for an address.
_ADDRESS_COLUMN = re.compile(r"^(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]{8})\s*:?\s*")

# Encoded-byte column that follows the address in a hex listing, each byte a
# two-digit hex pair (`55 8b ec`).
_BYTE_COLUMN = re.compile(r"^(?:[0-9A-Fa-f]{2}\s+)+")


def _entry(
    op: str,
    left_line: int | None,
    right_line: int | None,
    left: str | None,
    right: str | None,
) -> DiffEntry:
    return {
        "op": op,
        "left_line": left_line,
        "right_line": right_line,
        "left": left,
        "right": right,
    }


def align(left: str, right: str) -> list[DiffEntry]:
    """Align two texts line by line, 1-based, with ``None`` for a missing side.

    A ``replace`` opcode becomes a delete run followed by an insert run, so
    every entry's ``op`` is ``equal``, ``insert`` or ``delete``.  An identical
    input yields one ``equal`` entry per line.
    """
    left_lines = left.splitlines()
    right_lines = right.splitlines()
    matcher = difflib.SequenceMatcher(a=left_lines, b=right_lines, autojunk=False)
    entries: list[DiffEntry] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == OP_EQUAL:
            for offset in range(i2 - i1):
                entries.append(
                    _entry(
                        OP_EQUAL,
                        i1 + offset + 1,
                        j1 + offset + 1,
                        left_lines[i1 + offset],
                        right_lines[j1 + offset],
                    )
                )
        elif tag == OP_DELETE:
            for index in range(i1, i2):
                entries.append(_entry(OP_DELETE, index + 1, None, left_lines[index], None))
        else:
            # `insert` and `replace` both emit their right-hand lines; a
            # replace opcode emits the left-hand lines first, as deletes.
            if tag == OP_REPLACE:
                for index in range(i1, i2):
                    entries.append(_entry(OP_DELETE, index + 1, None, left_lines[index], None))
            for index in range(j1, j2):
                entries.append(_entry(OP_INSERT, None, index + 1, None, right_lines[index]))
    return entries


def summary(entries: Sequence[Mapping[str, object]]) -> dict[str, int]:
    """Count the entries by operation plus the number of replacement groups.

    ``changed`` counts each delete run immediately followed by an insert run,
    which is how :func:`align` represents one ``replace`` opcode.
    """
    counts = {OP_EQUAL: 0, OP_INSERT: 0, OP_DELETE: 0, "changed": 0}
    pending_delete = False
    for entry in entries:
        op = str(entry["op"])
        if op == OP_REPLACE:
            counts["changed"] += 1
            pending_delete = False
        elif op == OP_DELETE:
            counts[OP_DELETE] += 1
            pending_delete = True
        elif op == OP_INSERT:
            counts[OP_INSERT] += 1
            if pending_delete:
                counts["changed"] += 1
                pending_delete = False
        else:
            counts[OP_EQUAL] += 1
            pending_delete = False
    return counts


def _normalize_line(line: str) -> str:
    """Strip one listing line's address, bytes and trailing comment."""
    text = _C_COMMENT.sub("", line)
    text = _NASM_COMMENT.sub("", text)
    text = text.strip()
    address = _ADDRESS_COLUMN.match(text)
    if address is not None:
        text = _BYTE_COLUMN.sub("", text[address.end() :]).strip()
    return " ".join(text.split())


def strip_addresses(listing: str) -> str:
    """Normalize a hex or NASM listing: no addresses, bytes or comments.

    rebrew's NASM listing keeps both the absolute address and the encoded
    bytes in a trailing ``;`` comment, and its hex listing leads with an
    address column and a byte column; both are removed.  The mnemonic and its
    operands survive, and whitespace is collapsed to single spaces.
    """
    return "\n".join(_normalize_line(line) for line in listing.splitlines())

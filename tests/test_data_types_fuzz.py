"""Property fuzz for the untrusted C typedef definition parser.

``data_types.parse_definition`` takes operator- and scan-supplied C typedef
text (API, CLI, MCP, structs-scan import).  These harnesses drive random and
structure-aware mutants through the grammar and assert: only
``DefinitionError`` / ``InvalidIdentifierError`` escape, and every successful
answer keeps the kind/name/members/values shape the store and renderers consume.
"""

from __future__ import annotations

import random
from typing import Any

from reportal import data_types

_ITERATIONS = 128
_MAX_RANDOM = 512
_MAX_MUTANT = 2048

_SEEDS = (
    "typedef struct S_s {\n\tint a;\n\tchar *next;\n} S;\n",
    "typedef union U_s {\n\tunsigned int as_int;\n\tunsigned char as_bytes[4];\n} U;\n",
    "typedef enum E_s {\n\tE_A = 0,\n\tE_B = 0x10,\n\tE_C\n} E;\n",
    "typedef unsigned int DWORD;\n",
    "typedef void *HANDLE;\n",
    "typedef int Rows[4];\n",
    "typedef void (*Callback)(int, char *value);\n",
    "typedef struct B_s {\n\tunsigned int low : 3;\n\tunsigned int high : 5;\n} B;\n",
)


def _mutate(rng: random.Random, seed: str) -> str:
    """One mutant: flips, overwrites, truncates, inserts or splices characters."""
    data = list(seed)
    if not data:
        return "".join(chr(rng.randint(0, 127)) for _ in range(rng.randint(1, 64)))
    choice = rng.randrange(5)
    if choice == 0:
        for _ in range(rng.randint(1, 8)):
            at = rng.randrange(len(data))
            data[at] = chr(ord(data[at]) ^ (1 << rng.randrange(7)))
    elif choice == 1:
        at = rng.randrange(len(data))
        length = min(rng.randint(1, 32), len(data) - at)
        data[at : at + length] = [chr(rng.randint(0, 127)) for _ in range(length)]
    elif choice == 2:
        data = data[: rng.randrange(len(data) + 1)]
    elif choice == 3:
        at = rng.randrange(len(data) + 1)
        blob = [chr(rng.randint(0, 127)) for _ in range(rng.randint(1, 64))]
        data[at:at] = blob
    else:
        start = rng.randrange(len(data))
        end = rng.randrange(start, len(data))
        if rng.random() < 0.5:
            data[start:end] = []
        else:
            data[end:end] = data[start:end]
    text = "".join(data)
    return text[:_MAX_MUTANT]


def _assert_parsed(parsed: dict[str, Any]) -> None:
    """Invariants every successful parse must keep for store and render."""
    assert parsed["kind"] in data_types.KINDS
    assert isinstance(parsed["name"], str) and parsed["name"]
    assert data_types.validate_identifier(parsed["name"]) == parsed["name"]
    assert isinstance(parsed["members"], list)
    assert isinstance(parsed["values"], list)
    assert isinstance(parsed["target"], str)
    assert parsed["element_count"] is None or isinstance(parsed["element_count"], int)
    assert isinstance(parsed["size"], int) and parsed["size"] >= 0
    if parsed["kind"] == data_types.KIND_ENUM:
        assert parsed["members"] == []
        for entry in parsed["values"]:
            assert isinstance(entry["name"], str) and entry["name"]
            assert isinstance(entry["value"], int)
    else:
        assert parsed["values"] == []
        for member in parsed["members"]:
            assert isinstance(member["name"], str)
            assert isinstance(member["type"], str) and member["type"]
            assert isinstance(member["pointer"], bool)
            assert member["count"] is None or isinstance(member["count"], int)
            assert member["bits"] is None or isinstance(member["bits"], int)
            assert isinstance(member["offset"], int) and member["offset"] >= 0
            assert isinstance(member["size"], int) and member["size"] >= 0


def _drive(rng: random.Random, corpus: list[str]) -> None:
    """Run *corpus* mutants through ``parse_definition`` with shape assertions."""
    for _ in range(_ITERATIONS):
        seed = corpus[rng.randrange(len(corpus))]
        text = _mutate(rng, seed) if rng.random() < 0.9 else seed
        try:
            parsed = data_types.parse_definition(text)
        except (data_types.DefinitionError, data_types.InvalidIdentifierError) as exc:
            assert isinstance(exc.args[0], str) and exc.args[0]
            continue
        _assert_parsed(parsed)


def test_parse_definition_random_text() -> None:
    """Pure random text, with and without a typedef prefix spliced in."""
    rng = random.Random(0xD47A)
    for _ in range(_ITERATIONS):
        size = rng.randint(0, _MAX_RANDOM)
        text = "".join(chr(rng.randint(0, 255)) for _ in range(size))
        if size and rng.random() < 0.4:
            at = rng.randrange(size)
            text = text[:at] + "typedef struct T { int a; } T;\n" + text[at:]
        text = text[:_MAX_MUTANT]
        try:
            parsed = data_types.parse_definition(text)
        except (data_types.DefinitionError, data_types.InvalidIdentifierError) as exc:
            assert isinstance(exc.args[0], str)
            continue
        _assert_parsed(parsed)


def test_parse_definition_mutates_valid_seeds() -> None:
    """Structure-aware mutants of every declaration kind the model parses."""
    for seed in _SEEDS:
        _assert_parsed(data_types.parse_definition(seed))
    corpus = list(_SEEDS) + ["", "typedef", "typedef struct {", "typedef int;\n"]
    _drive(random.Random(0x7A9E), corpus)

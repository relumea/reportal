"""Property fuzz for the untrusted decompiler-signature line parser.

``signatures.parse_signature`` takes the leading declaration of a stored
decompilation (and any operator paste that reaches seed/edit).  These
harnesses drive random and structure-aware mutants through the line grammar
and assert: the parser never raises, and every successful answer keeps the
name/return/convention/parameters shape the model and renderers consume.
"""

from __future__ import annotations

import random
from typing import Any

from reportal import signatures

_ITERATIONS = 128
_MAX_RANDOM = 512
_MAX_MUTANT = 2048

_SEEDS = (
    "unsigned int sub_1005640(unsigned int a0, unsigned int a1)\n{\n  return 0;\n}\n",
    "int __stdcall NpGetDefaultPrinterDC(void)\n{\n  return 0;\n}\n",
    "char *sub_1000(int count)\n{\n  return 0;\n}\n",
    "void FUN_10006c00(void)\n{\n  return;\n}\n",
    "void sub_1000(char buf[16])\n{\n  return;\n}\n",
    "void sub_1000(int, char *)\n{\n  return;\n}\n",
    "// note\nvoid helper(unsigned char *p, size_t n);\n",
)


def _mutate(rng: random.Random, seed: str) -> str:
    """One mutant: flips, overwrites, truncates, inserts or splices characters."""
    data = list(seed)
    if not data:
        return "".join(chr(rng.randint(0, 127)) for _ in range(rng.randint(1, 64)))
    choice = rng.randrange(6)
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
    elif choice == 4:
        start = rng.randrange(len(data))
        end = rng.randrange(start, len(data))
        if rng.random() < 0.5:
            data[start:end] = []
        else:
            data[end:end] = data[start:end]
    else:
        # Inject calling-convention tokens and short declaration fragments.
        at = rng.randrange(len(data) + 1)
        inject = rng.choice(
            [
                "__stdcall ",
                "__fastcall ",
                "()",
                "(int a, char *b)",
                "char buf[16]",
                "void (*fp)(int)",
            ]
        )
        data[at:at] = list(inject)
    return "".join(data)[:_MAX_MUTANT]


def _assert_parsed(parsed: dict[str, Any]) -> None:
    """Invariants every successful parse must keep for the signature model."""
    assert isinstance(parsed["name"], str) and parsed["name"]
    assert signatures._validate_identifier(parsed["name"]) == parsed["name"]
    assert isinstance(parsed["return_type"], str) and parsed["return_type"]
    convention = parsed["calling_convention"]
    assert convention == signatures.DEFAULT_CALLING_CONVENTION or convention in (
        signatures.CALLING_CONVENTIONS
    )
    assert isinstance(parsed["parameters"], list)
    seen: set[str] = set()
    for index, parameter in enumerate(parsed["parameters"]):
        assert parameter["index"] == index
        assert isinstance(parameter["type"], str) and parameter["type"]
        assert isinstance(parameter["name"], str)
        if parameter["name"]:
            assert parameter["name"] not in seen
            seen.add(parameter["name"])
            assert signatures._validate_identifier(parameter["name"]) == parameter["name"]
        assert parameter["at"] is None
        assert parameter["kind"] is None
        assert parameter["bits"] is None


def test_parse_signature_random_text() -> None:
    """Pure random text, with and without a declaration-shaped prefix."""
    rng = random.Random(0x516)
    for _ in range(_ITERATIONS):
        size = rng.randint(0, _MAX_RANDOM)
        text = "".join(chr(rng.randint(0, 255)) for _ in range(size))
        if size and rng.random() < 0.4:
            at = rng.randrange(size)
            text = text[:at] + "void sub_1000(int a)\n{\n}\n" + text[at:]
        text = text[:_MAX_MUTANT]
        parsed = signatures.parse_signature(text)
        if parsed is not None:
            _assert_parsed(parsed)


def test_parse_signature_mutates_valid_seeds() -> None:
    """Structure-aware mutants of known-good decompiler declaration lines."""
    for seed in _SEEDS:
        parsed = signatures.parse_signature(seed)
        assert parsed is not None
        _assert_parsed(parsed)
    rng = random.Random(0x516A)
    corpus = list(_SEEDS) + ["", "// only", "if (x) { return; }", "void f("]
    for _ in range(_ITERATIONS):
        seed = corpus[rng.randrange(len(corpus))]
        text = _mutate(rng, seed) if rng.random() < 0.9 else seed
        parsed = signatures.parse_signature(text)
        if parsed is not None:
            _assert_parsed(parsed)

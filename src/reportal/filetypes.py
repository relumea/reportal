"""Bundled file-type, packer and protector detection over data reportal fetches.

The hosted portal names a sample's file type and its packer.  The local engine
only reports that when an external ``diec`` happens to be installed, which is
not a dependency this project takes.  This module is the bundled alternative: a
curated table of signatures (:data:`SIGNATURES`) matched against evidence
reportal already fetches from the engine, the ``pe-info`` sections and entry
point, the ``fingerprints`` section entropies, the ``imports`` table and the
``strings`` table.  It is dependency-free, makes no network call and never
executes the sample.

A signature is a named :class:`FileSignature` with a category
(:data:`CATEGORY_PACKER`, :data:`CATEGORY_PROTECTOR`, :data:`CATEGORY_INSTALLER`,
:data:`CATEGORY_RUNTIME` or :data:`CATEGORY_TOOLCHAIN`) and a
:class:`SignatureMatch`, a record of the evidence it can fire on: a section-name
prefix, an entry-point byte prefix, a string marker, an import DLL name, a Rich
header, or an executable section at or above an entropy threshold.

Confidence is derived, never guessed per row.  Two independent signal kinds are
``high``; a single signal takes the weaker of the signature's declared
confidence and that signal kind's own ceiling, so a lone string marker or an
entropy heuristic never exceeds ``low`` while a section name, an import or an
entry-point prefix can carry ``medium``.  The rule and the scope are stated in
every result's notes.

:func:`detect` is pure and takes an evidence mapping, so a caller can run it
over payloads it already holds.  :func:`run_filetype` assembles the evidence
through the engine, detects, and stores the result as the ``filetype`` scan; a
missing evidence piece is recorded as a note instead of failing the run, while a
run whose every engine call failed assembles nothing and propagates its error
rather than storing an empty result over a real one.

What this cannot conclude: a missing signature is not proof a binary is
unpacked or unprotected (a packer that rewrites its own section names or a
protector that strips its markers leaves nothing to match), and a match is
static evidence, not proof of behavior.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from reportal import capabilities, engines, store

# Signature categories, in the order the CLI, the API and the SPA list them.
CATEGORY_PACKER = "packer"
CATEGORY_PROTECTOR = "protector"
CATEGORY_INSTALLER = "installer"
CATEGORY_RUNTIME = "runtime"
CATEGORY_TOOLCHAIN = "toolchain"

FILE_CATEGORIES: tuple[str, ...] = (
    CATEGORY_PACKER,
    CATEGORY_PROTECTOR,
    CATEGORY_INSTALLER,
    CATEGORY_RUNTIME,
    CATEGORY_TOOLCHAIN,
)

# Confidence labels a match carries, strongest first.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

_CONFIDENCE_RANK = {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 1, CONFIDENCE_LOW: 2}

# Signal kinds.  A signal's kind fixes the strongest confidence it can carry on
# its own; a section name, an import DLL or an entry-point prefix is a concrete
# artifact, a string marker, a byte constant or a numeric entropy heuristic
# merely suggests one.
SIGNAL_SECTION = "section"
SIGNAL_STRING = "string"
SIGNAL_IMPORT = "import"
SIGNAL_ENTRY_POINT = "entry-point"
SIGNAL_ENTROPY = "entropy"
SIGNAL_RICH_HEADER = "rich-header"
SIGNAL_CONSTANT = "constant"

SIGNAL_CONFIDENCES = {
    SIGNAL_SECTION: CONFIDENCE_MEDIUM,
    SIGNAL_IMPORT: CONFIDENCE_MEDIUM,
    SIGNAL_ENTRY_POINT: CONFIDENCE_MEDIUM,
    SIGNAL_RICH_HEADER: CONFIDENCE_MEDIUM,
    SIGNAL_STRING: CONFIDENCE_LOW,
    SIGNAL_ENTROPY: CONFIDENCE_LOW,
    SIGNAL_CONSTANT: CONFIDENCE_LOW,
}

# Independent signal kinds a match needs before its confidence is `high`.
MIN_HIGH_CONFIDENCE_KINDS = 2

# Matches kept in a payload and signals kept per match.  The full set is
# deduplicated first and `count` and `by_category` stay exact, so the caps only
# trim the rendered detail.
MAX_MATCHES = 50
MAX_SIGNALS_PER_MATCH = 10

# Strings inspected by one scan.  The engine can return tens of thousands and
# every signature regexes each one, so the tail is dropped.
MAX_STRINGS_INSPECTED = capabilities.MAX_STRINGS_INSPECTED

# Raw bytes read per executable section for constant matching.  Family
# constants are searched in executable sections only, so data blobs cannot
# fire them, and the per-section cap keeps a huge section bounded.
MAX_SECTION_BYTES = 16 * 1024 * 1024

# Engine calls one run makes (pe-info, fingerprints, imports, strings).  A run
# whose every call failed assembled nothing, so it fails instead of storing an
# empty detection over one an earlier run produced.
EVIDENCE_CALLS = 4

# An executable section at or above this Shannon entropy is compressed or
# encrypted code, the generic packed-image heuristic.
HIGH_ENTROPY_THRESHOLD = 7.0

# Characters of an entry-point prefix a signal keeps in its value.
ENTRY_PREFIX_CHARS = 16

# Scope, the confidence rule and the one evidence gap, all stated in every
# result's notes because a reader cannot interpret a match without them.
SCOPE_NOTE = (
    "local signature detection over the engine's pe-info, fingerprints, imports and strings;"
    " no diec, no network call and the binary is never executed"
)
CONFIDENCE_NOTE = (
    "confidence: two independent signal kinds are high; a single section name, import or"
    " entry-point prefix is medium; a lone string marker or entropy heuristic is low"
)
ENTRY_BYTES_NOTE = (
    "entry-point byte prefixes are unavailable (the engine's pe-info reported no bytes"
    " at the entry point, which is the case for a binary with no entry point, one whose"
    " entry point is outside the mapped image, or an engine older than the entry_bytes"
    " field)"
)
CAP_NOTE = "showing {shown} of {total} matches"


class FiletypeIO(Protocol):
    """The engine surface a file-type scan reads; every call is standalone."""

    def pe_info(self, binary: str | Path) -> dict[str, Any]: ...

    def fingerprint(self, binary: str | Path) -> dict[str, Any]: ...

    def imports(self, binary: str | Path) -> dict[str, Any]: ...

    def strings(self, binary: str | Path) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SignatureMatch:
    """The evidence one signature can fire on; every field is optional.

    ``section_prefixes`` are matched case-insensitively against a section name's
    start, ``imports`` against an import DLL name with a trailing ``.dll``
    ignored, and ``entry_prefixes`` against the lowercased hex of the bytes at
    the entry point.  ``constants`` are raw byte strings searched in the
    executable sections' bytes; a signature fires only when at least
    ``min_constants`` distinct constants hit (default 1), so a family row can
    require the coincidence its YARA rule requires.  ``rich_header`` fires
    when the binary carries a Rich header and ``executable_entropy`` when an
    executable section reaches that Shannon entropy.  ``exclude_formats``
    suppresses the signature outright for a named format, which keeps the
    DOS-only packers off a PE or ELF whose strings happen to carry their
    marker.
    """

    section_prefixes: tuple[str, ...] = ()
    strings: tuple[re.Pattern[str], ...] = ()
    imports: tuple[str, ...] = ()
    entry_prefixes: tuple[str, ...] = ()
    constants: tuple[bytes, ...] = ()
    min_constants: int = 1
    rich_header: bool = False
    executable_entropy: float | None = None
    exclude_formats: tuple[str, ...] = ()


@dataclass(frozen=True)
class FileSignature:
    """One named signature: its category, declared confidence and evidence.

    ``confidence`` is the signature's declared ceiling.  A match takes the
    weaker of it and the fired signal kind's own confidence, so a signature
    whose only matched signal is a string reports ``low`` whatever it declares.
    """

    name: str
    category: str
    confidence: str
    match: SignatureMatch = field(default_factory=SignatureMatch)


def _regex(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


# The signature table.  Names are unique; the detection deduplicates by
# ``(category, name)`` and sorts by confidence, then category, then name.
SIGNATURES: tuple[FileSignature, ...] = (
    # ── Packers ────────────────────────────────────────────────────────────
    FileSignature(
        "UPX",
        CATEGORY_PACKER,
        CONFIDENCE_MEDIUM,
        SignatureMatch(
            section_prefixes=("upx",),
            strings=_regex(r"UPX!", r"packed with the UPX"),
            entry_prefixes=("60be",),
        ),
    ),
    FileSignature(
        "ASPack",
        CATEGORY_PACKER,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=(".aspack", ".adata"), strings=_regex(r"\bASPack\b")),
    ),
    FileSignature(
        "MPRESS",
        CATEGORY_PACKER,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=(".mpress",), strings=_regex(r"\bMPRESS\b")),
    ),
    FileSignature(
        "PECompact",
        CATEGORY_PACKER,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=("pec2", "pecompact"), strings=_regex(r"\bPECompact\b")),
    ),
    FileSignature(
        "NsPack",
        CATEGORY_PACKER,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=("nsp0", "nsp1"), strings=_regex(r"\bNsPack\b")),
    ),
    FileSignature(
        "Petite",
        CATEGORY_PACKER,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=(".petite",), strings=_regex(r"\bPetite\b")),
    ),
    FileSignature(
        "tElock",
        CATEGORY_PACKER,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=(".telock",), strings=_regex(r"\btElock\b")),
    ),
    FileSignature(
        "FSG",
        CATEGORY_PACKER,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=("fsg",), strings=_regex(r"FSG!")),
    ),
    FileSignature(
        "PKLITE",
        CATEGORY_PACKER,
        CONFIDENCE_LOW,
        SignatureMatch(strings=_regex(r"PKLITE"), exclude_formats=("pe", "elf")),
    ),
    FileSignature(
        "LZEXE",
        CATEGORY_PACKER,
        CONFIDENCE_LOW,
        SignatureMatch(strings=_regex(r"LZ09", r"LZ91"), exclude_formats=("pe", "elf")),
    ),
    FileSignature(
        "high-entropy-executable",
        CATEGORY_PACKER,
        CONFIDENCE_LOW,
        SignatureMatch(executable_entropy=HIGH_ENTROPY_THRESHOLD),
    ),
    FileSignature(
        "BoxedApp",
        CATEGORY_PACKER,
        CONFIDENCE_LOW,
        SignatureMatch(strings=_regex(r"BoxedApp", r"bxilmerge", r"BxILMerge")),
    ),
    FileSignature(
        "Paranoiac-RAT-family",
        CATEGORY_PACKER,
        CONFIDENCE_LOW,
        SignatureMatch(
            constants=(
                bytes.fromhex("EA45F620"),
                bytes.fromhex("C2CA997F"),
                bytes.fromhex("97938F8B"),
                bytes.fromhex("4BCC8C47"),
            ),
            min_constants=3,
        ),
    ),
    FileSignature(
        "NeTiS-Gafgyt-family",
        CATEGORY_PACKER,
        CONFIDENCE_LOW,
        SignatureMatch(
            constants=(
                bytes.fromhex("730B6F0B"),
                bytes.fromhex("C073"),
                bytes.fromhex("C2D2536D3F917E4AD7652CB8E2449F1AF1C3AB8991725D3ED3A8B6C4961C2E7F"),
            ),
            min_constants=2,
        ),
    ),
    # ── Protectors ─────────────────────────────────────────────────────────
    FileSignature(
        "Themida/WinLicense",
        CATEGORY_PROTECTOR,
        CONFIDENCE_MEDIUM,
        SignatureMatch(
            section_prefixes=(".themida", ".winlice"),
            strings=_regex(r"Themida", r"WinLicense"),
        ),
    ),
    FileSignature(
        "VMProtect",
        CATEGORY_PROTECTOR,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=(".vmp0", ".vmp1"), strings=_regex(r"VMProtect")),
    ),
    FileSignature(
        "Enigma Protector",
        CATEGORY_PROTECTOR,
        CONFIDENCE_MEDIUM,
        SignatureMatch(section_prefixes=(".enigma",), strings=_regex(r"\bEnigma\b")),
    ),
    FileSignature(
        "Obsidium",
        CATEGORY_PROTECTOR,
        CONFIDENCE_LOW,
        SignatureMatch(strings=_regex(r"Obsidium")),
    ),
    FileSignature(
        "Armadillo",
        CATEGORY_PROTECTOR,
        CONFIDENCE_LOW,
        SignatureMatch(strings=_regex(r"Armadillo", r"Silicon Realms")),
    ),
    # ── Installers ─────────────────────────────────────────────────────────
    FileSignature(
        "NSIS",
        CATEGORY_INSTALLER,
        CONFIDENCE_LOW,
        SignatureMatch(
            strings=_regex(
                r"Nullsoft",
                r"NSIS Error",
                r"\$PLUGINSDIR",
                r"\.onGUIInit",
                r"InitPluginsDir",
            )
        ),
    ),
    FileSignature(
        "Inno Setup",
        CATEGORY_INSTALLER,
        CONFIDENCE_LOW,
        SignatureMatch(strings=_regex(r"Inno Setup")),
    ),
    FileSignature(
        "InstallShield",
        CATEGORY_INSTALLER,
        CONFIDENCE_LOW,
        SignatureMatch(strings=_regex(r"InstallShield")),
    ),
    # ── Runtimes ───────────────────────────────────────────────────────────
    FileSignature(
        ".NET",
        CATEGORY_RUNTIME,
        CONFIDENCE_MEDIUM,
        SignatureMatch(imports=("mscoree",), strings=_regex(r"BSJB")),
    ),
    FileSignature(
        "Visual Basic",
        CATEGORY_RUNTIME,
        CONFIDENCE_MEDIUM,
        SignatureMatch(imports=("msvbvm60", "msvbvm50")),
    ),
    FileSignature(
        "Delphi",
        CATEGORY_RUNTIME,
        CONFIDENCE_LOW,
        SignatureMatch(
            strings=_regex(r"@System@", r"\bBorland\b", r"\bEmbarcadero\b", r"\bDelphi\b")
        ),
    ),
    FileSignature(
        "Go",
        CATEGORY_RUNTIME,
        CONFIDENCE_MEDIUM,
        SignatureMatch(
            section_prefixes=(".gopclntab",),
            strings=_regex(r"gopclntab", r"runtime\.goexit", r"runtime\.gopanic", r"go\.buildid"),
        ),
    ),
    FileSignature(
        "Rust",
        CATEGORY_RUNTIME,
        CONFIDENCE_MEDIUM,
        SignatureMatch(
            section_prefixes=(".rustc",),
            strings=_regex(r"rust_begin_unwind", r"rust_panic", r"__rust_alloc", r"/rustc/"),
        ),
    ),
    FileSignature(
        "Swift",
        CATEGORY_RUNTIME,
        CONFIDENCE_MEDIUM,
        SignatureMatch(
            section_prefixes=("__swift",),
            strings=_regex(r"libswift", r"swift_allocObject", r"\bswift_once\b"),
        ),
    ),
    # ── Toolchains ─────────────────────────────────────────────────────────
    FileSignature(
        "Microsoft Visual C++",
        CATEGORY_TOOLCHAIN,
        CONFIDENCE_MEDIUM,
        SignatureMatch(imports=("msvcrt",), rich_header=True),
    ),
    FileSignature(
        "MinGW GCC",
        CATEGORY_TOOLCHAIN,
        CONFIDENCE_MEDIUM,
        SignatureMatch(
            section_prefixes=(".buildid",), strings=_regex(r"gcc2_compiled", r"__mingw")
        ),
    ),
)


def _signal(kind: str, value: str) -> dict[str, str]:
    return {"kind": kind, "value": value}


def _dedupe_signals(signals: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    """Collapse repeated ``(kind, value)`` signals, keeping the first."""
    seen: set[tuple[str, str]] = set()
    distinct: list[dict[str, str]] = []
    for signal in signals:
        key = (signal["kind"], signal["value"])
        if key in seen:
            continue
        seen.add(key)
        distinct.append(signal)
    return distinct


def _confidence(signature: FileSignature, signals: Sequence[dict[str, str]]) -> str:
    """Derive a match's confidence from its fired signal kinds.

    Two or more independent signal kinds are :data:`CONFIDENCE_HIGH`.  A single
    signal takes the weaker of the signature's declared confidence and that
    kind's own confidence, so a lone string marker never exceeds
    :data:`CONFIDENCE_LOW`.
    """
    kinds = {signal["kind"] for signal in signals}
    if len(kinds) >= MIN_HIGH_CONFIDENCE_KINDS:
        return CONFIDENCE_HIGH
    ceiling = SIGNAL_CONFIDENCES[signals[0]["kind"]]
    return max((signature.confidence, ceiling), key=lambda level: _CONFIDENCE_RANK[level])


def _section_entries(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """The section entries under ``evidence["sections"]``, ignoring other shapes."""
    raw = evidence.get("sections")
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _section_names(evidence: dict[str, Any]) -> list[str]:
    """The distinct section names the evidence carries, in order."""
    names: list[str] = []
    for entry in _section_entries(evidence):
        name = entry.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    return names


def _executable_sections(evidence: dict[str, Any]) -> list[str]:
    """The names of the sections the evidence marks executable."""
    return [
        str(entry["name"])
        for entry in _section_entries(evidence)
        if isinstance(entry.get("name"), str) and entry.get("execute")
    ]


def _entropies(evidence: dict[str, Any]) -> dict[str, float]:
    """The ``name -> entropy`` mapping the evidence carries, ignoring other shapes."""
    raw = evidence.get("entropies")
    if not isinstance(raw, dict):
        return {}
    values: dict[str, float] = {}
    for key, value in raw.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        values[str(key)] = float(value)
    return values


def _string_texts(evidence: dict[str, Any]) -> list[str]:
    """The string texts the evidence carries, capped at :data:`MAX_STRINGS_INSPECTED`.

    An entry is a mapping with its text under ``text`` (the engine's shape) or a
    plain string, which a caller may pass into :func:`detect` directly.
    """
    raw = evidence.get("strings")
    if not isinstance(raw, list):
        return []
    texts: list[str] = []
    for entry in raw[:MAX_STRINGS_INSPECTED]:
        if isinstance(entry, str):
            texts.append(entry)
        elif isinstance(entry, dict):
            text = entry.get("text")
            if isinstance(text, str) and text:
                texts.append(text)
    return texts


def _section_bytes(evidence: dict[str, Any]) -> bytes:
    """The raw bytes under ``evidence["section_bytes"]``, or empty."""
    raw = evidence.get("section_bytes")
    return raw if isinstance(raw, bytes) else b""


def read_section_bytes(path: Path, sections: Sequence[dict[str, Any]]) -> bytes:
    """Read executable sections' raw bytes from *path*, bounded.

    The section map comes from the engine's own pe-info payload and the bytes
    are read from the file exactly where that map says they live; reportal
    never parses a PE.  Only sections the map marks executable are read, each
    capped at :data:`MAX_SECTION_BYTES`.  An unreadable file answers empty
    rather than failing the scan.
    """
    chunks: list[bytes] = []
    try:
        with open(path, "rb") as handle:
            for entry in sections:
                if not isinstance(entry, dict) or not entry.get("execute"):
                    continue
                try:
                    offset = int(entry.get("raw_offset") or 0)
                    size = int(entry.get("raw_size") or 0)
                except (TypeError, ValueError):
                    continue
                if size <= 0:
                    continue
                try:
                    handle.seek(offset)
                    chunks.append(handle.read(min(size, MAX_SECTION_BYTES)))
                except OSError:
                    continue
    except OSError:
        return b""
    return b"".join(chunks)


def _import_dlls(evidence: dict[str, Any]) -> list[str]:
    """The distinct import DLL names the evidence carries, in order."""
    raw = evidence.get("imports")
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    for entry in raw:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict):
            dll = entry.get("dll")
            if isinstance(dll, str) and dll:
                names.append(dll)
    return names


def _entry_hex(evidence: dict[str, Any]) -> str | None:
    """The entry-point bytes as lowercased hex, or None when unusable."""
    raw = evidence.get("entry_bytes")
    if isinstance(raw, bytes):
        return raw.hex()
    if not isinstance(raw, str):
        return None
    cleaned = "".join(raw.split()).lower()
    if not cleaned or any(character not in "0123456789abcdef" for character in cleaned):
        return None
    return cleaned


def _rich_present(evidence: dict[str, Any]) -> bool:
    """True when the evidence carries a Rich header."""
    raw = evidence.get("rich_header")
    if isinstance(raw, dict):
        return bool(raw.get("present"))
    return bool(raw)


def _dll_matches(name: str, expected: str) -> bool:
    """True when DLL *name* is *expected*, ignoring case and a ``.dll`` suffix."""
    return _without_suffix(name) == _without_suffix(expected)


def _without_suffix(name: str) -> str:
    return name.strip().casefold().removesuffix(".dll")


def _entry_point_value(entry_point: Any, entry_hex: str) -> str:
    """Render an entry-point signal as ``<va> <hex prefix>`` when the VA is known."""
    prefix = entry_hex[:ENTRY_PREFIX_CHARS]
    if isinstance(entry_point, int) and not isinstance(entry_point, bool):
        return f"{hex(entry_point)} {prefix}"
    return prefix


def _format_name(evidence: dict[str, Any]) -> str | None:
    """The evidence's format, lowercased and trimmed, or None when absent."""
    raw = evidence.get("format")
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip().casefold()
    return cleaned or None


def _signals(
    signature: FileSignature,
    *,
    sections: Sequence[str],
    strings: Sequence[str],
    dlls: Sequence[str],
    entry_hex: str | None,
    entry_point: Any,
    rich_present: bool,
    entropies: dict[str, float],
    executable: Sequence[str],
    format_name: str | None,
    section_bytes: bytes = b"",
) -> list[dict[str, str]]:
    """The signals *signature* fires over one evidence set, deduplicated."""
    match = signature.match
    if format_name is not None and format_name in match.exclude_formats:
        return []
    signals: list[dict[str, str]] = []
    for name in sections:
        lowered = name.casefold()
        if any(lowered.startswith(prefix) for prefix in match.section_prefixes):
            signals.append(_signal(SIGNAL_SECTION, name))
    for text in strings:
        if any(pattern.search(text) for pattern in match.strings):
            signals.append(_signal(SIGNAL_STRING, text))
    for dll in dlls:
        if any(_dll_matches(dll, expected) for expected in match.imports):
            signals.append(_signal(SIGNAL_IMPORT, dll))
    if entry_hex is not None:
        for prefix in match.entry_prefixes:
            if entry_hex.startswith(prefix):
                signals.append(
                    _signal(SIGNAL_ENTRY_POINT, _entry_point_value(entry_point, entry_hex))
                )
                break
    if match.rich_header and rich_present:
        signals.append(_signal(SIGNAL_RICH_HEADER, "present"))
    if match.constants:
        hits = [needle for needle in dict.fromkeys(match.constants) if needle in section_bytes]
        if len(hits) >= match.min_constants:
            for needle in hits:
                signals.append(_signal(SIGNAL_CONSTANT, needle.hex()))
    if match.executable_entropy is not None:
        for name in executable:
            value = entropies.get(name)
            if value is not None and value >= match.executable_entropy:
                signals.append(
                    _signal(
                        SIGNAL_ENTROPY,
                        f"section {name} entropy {value:.4f} at or above"
                        f" {match.executable_entropy}",
                    )
                )
    return _dedupe_signals(signals)[:MAX_SIGNALS_PER_MATCH]


def _by_category(matches: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Count *matches* per category, every category present even at zero."""
    return {
        category: sum(1 for match in matches if match["category"] == category)
        for category in FILE_CATEGORIES
    }


def detect(evidence: dict[str, Any]) -> dict[str, Any]:
    """Match *evidence* against :data:`SIGNATURES` and return the matches.

    *evidence* carries ``format``, ``sections`` (entries with a ``name`` and an
    ``execute`` flag), ``entropies`` (a section-name to entropy mapping),
    ``imports``, ``strings``, ``rich_header`` and the optional ``entry_bytes``
    (the bytes at the entry point, as bytes or a hex string); any missing piece
    simply disables the signatures that need it, and the DOS-only packers are
    suppressed outright for a PE or ELF ``format``.  Returns ``{"matches",
    "count", "by_category", "notes"}``, where a match is ``{"name", "category",
    "confidence", "signals"}`` with each signal ``{"kind", "value"}``.  Matches
    deduplicate by ``(category, name)``, sort by confidence, then category, then
    name, and are capped at :data:`MAX_MATCHES` while ``count`` and
    ``by_category`` stay exact.  An empty ``matches`` list is valid.
    """
    sections = _section_names(evidence)
    executable = _executable_sections(evidence)
    entropies = _entropies(evidence)
    strings = _string_texts(evidence)
    dlls = _import_dlls(evidence)
    entry_hex = _entry_hex(evidence)
    entry_point = evidence.get("entry_point")
    rich_present = _rich_present(evidence)
    format_name = _format_name(evidence)
    section_bytes = _section_bytes(evidence)

    found: dict[tuple[str, str], dict[str, Any]] = {}
    for signature in SIGNATURES:
        signals = _signals(
            signature,
            sections=sections,
            strings=strings,
            dlls=dlls,
            entry_hex=entry_hex,
            entry_point=entry_point,
            rich_present=rich_present,
            entropies=entropies,
            executable=executable,
            format_name=format_name,
            section_bytes=section_bytes,
        )
        if not signals:
            continue
        key = (signature.category, signature.name.casefold())
        if key in found:
            continue
        found[key] = {
            "name": signature.name,
            "category": signature.category,
            "confidence": _confidence(signature, signals),
            "signals": signals,
        }

    ordered = sorted(
        found.values(),
        key=lambda match: (
            _CONFIDENCE_RANK[match["confidence"]],
            match["category"],
            match["name"],
        ),
    )
    notes: list[str] = []
    if len(ordered) > MAX_MATCHES:
        notes.append(CAP_NOTE.format(shown=MAX_MATCHES, total=len(ordered)))
    return {
        "matches": ordered[:MAX_MATCHES],
        "count": len(ordered),
        "by_category": _by_category(ordered),
        "notes": notes,
    }


def _entries(payload: dict[str, Any], key: str) -> list[Any]:
    """The list under ``payload[key]``, or an empty list for any other shape."""
    raw = payload.get(key)
    return raw if isinstance(raw, list) else []


def _entropy_map(fingerprint: dict[str, Any]) -> dict[str, float]:
    """The fingerprint's ``name -> entropy`` mapping, ignoring other shapes."""
    raw = fingerprint.get("section_entropies")
    if not isinstance(raw, list):
        return {}
    values: dict[str, float] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        value = entry.get("entropy")
        if (
            isinstance(name, str)
            and name
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
        ):
            values[name] = float(value)
    return values


def gather_evidence(io: FiletypeIO, path: Path) -> tuple[dict[str, Any], list[str]]:
    """Assemble the detection evidence for *path*, recording missing pieces.

    Every call is standalone.  A call that raises
    :class:`~reportal.engines.EngineError` leaves its evidence field empty and
    contributes a note, so one unusable piece degrades the detection instead of
    failing it.  A run whose every call failed assembled nothing at all, so the
    first error propagates: an empty detection would be meaningless and storing
    it would replace a real result with nothing.
    """
    evidence: dict[str, Any] = {
        "format": None,
        "sections": [],
        "entry_point": None,
        "entropies": {},
        "imports": [],
        "strings": [],
        "rich_header": None,
        "entry_bytes": None,
        "section_bytes": b"",
    }
    notes: list[str] = []
    failures: list[engines.EngineError] = []

    try:
        info = io.pe_info(path)
    except engines.EngineError as exc:
        failures.append(exc)
        notes.append(f"pe-info-error: {exc}")
    else:
        evidence["format"] = info.get("format")
        evidence["sections"] = _entries(info, "sections")
        evidence["entry_point"] = info.get("entry_point")
        evidence["entry_bytes"] = info.get("entry_bytes")
        evidence["rich_header"] = info.get("rich_header")
        evidence["section_bytes"] = read_section_bytes(path, evidence["sections"])

    try:
        fingerprint = io.fingerprint(path)
    except engines.EngineError as exc:
        failures.append(exc)
        notes.append(f"fingerprint-error: {exc}")
    else:
        evidence["entropies"] = _entropy_map(fingerprint)
        if not evidence["format"]:
            evidence["format"] = fingerprint.get("format")

    try:
        imports = io.imports(path)
    except engines.EngineError as exc:
        failures.append(exc)
        notes.append(f"imports-error: {exc}")
    else:
        evidence["imports"] = _entries(imports, "imports")

    try:
        strings = io.strings(path)
    except engines.EngineError as exc:
        failures.append(exc)
        notes.append(f"strings-error: {exc}")
    else:
        evidence["strings"] = _entries(strings, "strings")[:MAX_STRINGS_INSPECTED]

    if len(failures) == EVIDENCE_CALLS:
        raise failures[0]
    return evidence, notes


def run_filetype(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: FiletypeIO | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Detect a binary's file type and store the result as the ``filetype`` scan.

    The binary's file is resolved from the stored row.  *engine* (else the
    process-wide engine) supplies the standalone engine calls; *evidence*
    overrides the assembled evidence outright, which is how tests keep the run
    hermetic.  A missing evidence piece is recorded as a note instead of failing
    the run.

    Raises :class:`KeyError` for an unknown binary,
    :class:`FileNotFoundError` when its row has no file on disk and
    :class:`~reportal.engines.EngineError` when every engine call failed.
    Returns ``{"binary_id", "matches", "count", "by_category", "notes"}``.
    """
    _binary, path = capabilities.require_binary_file(conn, binary_id)

    notes = [SCOPE_NOTE, CONFIDENCE_NOTE]
    if evidence is None:
        source: FiletypeIO = engine if engine is not None else engines.get_engine()
        assembled, missing = gather_evidence(source, path)
        notes.extend(missing)
    else:
        assembled = dict(evidence)
    if _entry_hex(assembled) is None:
        notes.append(ENTRY_BYTES_NOTE)

    result = detect(assembled)
    payload = {
        "binary_id": binary_id,
        "matches": result["matches"],
        "count": result["count"],
        "by_category": result["by_category"],
        "notes": notes + result["notes"],
    }
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, store.SCAN_KIND_FILETYPE, payload)
    return payload

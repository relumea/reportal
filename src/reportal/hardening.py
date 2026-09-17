"""Deterministic hardening scans: anti-analysis and obfuscation heuristics.

The hosted RevEng.AI portal reports an anti-analysis and an obfuscation
surface per analysis.  reportal reproduces the static half locally and
deterministically over data it can already obtain: the engine's fingerprints,
imports and strings, plus the stored triage dossier when one exists.  No LLM
runs, no network call is made and the binary is never executed.

Two domains share one entry point (:func:`scan_hardening`):

* ``anti-analysis`` matches the import table and the extracted strings against
  the fixed rule table in :data:`ANTI_ANALYSIS_RULES`.  A matched import is
  :data:`CONFIDENCE_HIGH` (a concrete API family is present), string-only
  evidence :data:`CONFIDENCE_MEDIUM`.
* ``obfuscation`` applies numeric and structural heuristics with the named
  thresholds below (an executable section at or above
  :data:`HIGH_ENTROPY_THRESHOLD`, a weighted mean section entropy at or above
  :data:`HIGH_OVERALL_ENTROPY_THRESHOLD`, an import table or a string table
  that is sparse for the binary's size, and packer names or section
  conventions) and derives a :data:`PACKER_LIKELIHOOD_*` grade from how many
  fired.

Both domains store their result as the domain's own scan kind
(:data:`DOMAIN_SCAN_KINDS`), so the API and the SPA can serve one domain or
both.  A finding is ``{"category", "name", "detail", "confidence"}``; the list
is deduplicated, sorted and capped at :data:`MAX_FINDINGS` while ``count`` and
``by_confidence`` stay exact.  An empty ``findings`` list is a valid result.

What these scans cannot conclude: a missing finding is not proof the binary is
unprotected (a packer that rewrites its own import table or an anti-debug
check that resolves its API dynamically leaves no import to match), and a
firing heuristic is not proof of a packer (a legitimately compressed or
stripped binary fires the entropy and sparse-string rules).  They report
static evidence, nothing more.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from reportal import capabilities, engines, store
from reportal.capabilities import ImportRule
from reportal.engines import RebrewEngine

# Domain names, in the order the CLI, the API and the SPA list them.
DOMAIN_ANTI_ANALYSIS = "anti-analysis"
DOMAIN_OBFUSCATION = "obfuscation"

HARDENING_DOMAINS: tuple[str, ...] = (DOMAIN_ANTI_ANALYSIS, DOMAIN_OBFUSCATION)

# Stored scan kind per domain, so the store, the API and the SPA agree on where
# a domain's result lives.
DOMAIN_SCAN_KINDS: dict[str, str] = {
    DOMAIN_ANTI_ANALYSIS: store.SCAN_KIND_ANTI_ANALYSIS,
    DOMAIN_OBFUSCATION: store.SCAN_KIND_OBFUSCATION,
}

# Confidence labels, matching the other local scans: a matched import is a
# concrete API family, string-only evidence merely suggests intent.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"

# Findings kept in a payload.  The full set is deduplicated first and the exact
# counts (`count`, `by_confidence`) are computed over it, so the cap only trims
# the rendered detail.
MAX_FINDINGS = 50

# Strings inspected by one scan.  The engine can return tens of thousands and
# every rule regexes each one, so the tail is dropped.
MAX_STRINGS_INSPECTED = capabilities.MAX_STRINGS_INSPECTED

# Sort rank per confidence; lower sorts first so import hits lead the list.
_CONFIDENCE_RANK = {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 1}

# Packer likelihood grades and the finding counts that reach them.  The grade
# counts the deduplicated findings the obfuscation heuristics produced.
PACKER_LIKELIHOOD_HIGH = "high"
PACKER_LIKELIHOOD_MEDIUM = "medium"
PACKER_LIKELIHOOD_LOW = "low"
PACKER_HIGH_MIN_FINDINGS = 3
PACKER_MEDIUM_MIN_FINDINGS = 2

# Obfuscation thresholds.  An executable section at or above this Shannon
# entropy is compressed or encrypted code; the weighted mean across all
# sections at or above the second value marks a wholly packed image.
HIGH_ENTROPY_THRESHOLD = 7.0
HIGH_OVERALL_ENTROPY_THRESHOLD = 6.8

# A binary at or above this size with fewer than the threshold's imports has
# had its import table stripped; the same shape on the string table marks a
# packer that left few readable literals behind.
SPARSE_IMPORT_MIN_SIZE = 64 * 1024
SPARSE_IMPORT_THRESHOLD = 10
SPARSE_STRING_MIN_SIZE = 64 * 1024
SPARSE_STRING_THRESHOLD = 20

# Name a payload-level finding carries when its evidence is not one section.
ENTRY_IMPORTS = "imports"
ENTRY_STRINGS = "strings"
ENTRY_OVERALL_ENTROPY = "overall"

# Note recorded when the fingerprint carries no section entropies, so the two
# entropy thresholds are skipped instead of failing the scan.
SECTION_ENTROPY_NOTE = "fingerprint-unavailable: section entropy thresholds were skipped"


@dataclass(frozen=True)
class AntiAnalysisRule:
    """One anti-analysis category and its evidence matchers.

    ``imports`` are :class:`~reportal.capabilities.ImportRule` entries matched
    with the capabilities comparison; ``strings`` are case-insensitive regular
    expressions matched against a string entry's whole text.
    """

    category: str
    description: str
    imports: tuple[ImportRule, ...] = ()
    strings: tuple[re.Pattern[str], ...] = ()


def _regex(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


# String evidence: disassembly mnemonics, an exception-handling keyword, the
# SIGTRAP signal form, and the debugger literals a binary prints or checks.
_RDTSC = _regex(r"\brdtsc\b")
# I/O port probing: `in`/`out` mnemonics with an immediate port operand, the
# anti-emulation trick of reading non-standard ports (the SIDT-keyed RAT
# probed 0x4F, 0xEF, 0x93, 0x19, 0x3D, 0xA8 and 0xFD).  Ordinary user-space
# code never touches ports directly, so any hit is medium confidence.
_IO_PORT_PROBE = _regex(
    r"\b(?:in|out)\s+(?:al|ax|eax|dx)\s*,\s*(?:0x)?[0-9a-f]{1,4}\b",
    r"\b(?:in|out)\s+(?:0x)?[0-9a-f]{1,4}\s*,\s*(?:al|ax|eax)\b",
    r"\b(?:in|out)\s+(?:al|ax|eax)\s*,\s*dx\b",
    r"\bout\s+dx\s*,\s*(?:al|ax|eax)\b",
)
# Deliberate breakpoint and single-step traps: `int 3` with pushf/popf
# flag juggling, the fault-boundary trick where execution continues natively
# but diverges under a debugger.  Ordinary code never plants its own traps.
_INT3_TRAP = _regex(
    r"\bint\s+3\b",
    r"\bint3\b",
)
# CPU-state inspection: descriptor-table reads, the hypervisor leaf and
# FPU-state capture, the environment-sensitive key-derivation shape (SIDT
# feeding key material, FPU context saved around decrypt loops).  Ordinary
# user-space code reads none of these, so any hit is medium confidence.
_CPU_STATE_PROBE = _regex(
    r"\bsidt\b",
    r"\bsgdt\b",
    r"\bsldt\b",
    r"\bcpuid\b",
    r"\bfnstenv\b",
    r"\bfstenv\b",
    r"\bfxsave\b",
    r"\bfsave\b",
)
# LOCK-prefixed integrity probes: atomic write/check pairs around transient
# globals that abort when instrumentation alters read-back behavior.
_LOCK_CANARY = _regex(r"\block\s+(?:inc|dec|add|sub|xadd|xchg|cmpxchg)\b")
_VM_OR_SANDBOX = _regex(
    r"\b(?:VMware|VBOX|VirtualBox|QEMU|Xen|Sandboxie|SbieDll|wine|Wireshark|Procmon|Cuckoo)\b"
)
_EXCEPTION_STRING = _regex(r"\b__try\b|\b__except\b|\bsignal\s*\(\s*SIGTRAP\b")
_DEBUGGER_STRING = _regex(
    r"\bDebugger detected\b|\bdebugger\b|\bBeingDebugged\b|\bCheckRemoteDebugger\b"
)

# The anti-analysis rule table.  Categories overlap on purpose:
# ``SetUnhandledExceptionFilter`` is both an anti-debug API and exception
# tampering, and each is reported under both categories.
ANTI_ANALYSIS_RULES: tuple[AntiAnalysisRule, ...] = (
    AntiAnalysisRule(
        category="anti-debug-api",
        description="Calls an API a debugger intercepts or that reports a debugger",
        imports=capabilities._exact(
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "DebugActiveProcess",
            "SetUnhandledExceptionFilter",
            "AddVectoredExceptionHandler",
            "ptrace",
            "ptrace64",
        ),
    ),
    AntiAnalysisRule(
        category="timing-check",
        description="Reads a high-resolution clock, a sandbox timing tell",
        imports=capabilities._exact(
            "QueryPerformanceCounter",
            "GetTickCount",
            "timeGetTime",
        ),
        strings=_RDTSC,
    ),
    AntiAnalysisRule(
        category="vm-or-sandbox-artifact",
        description="Names a hypervisor, sandbox or analysis tool",
        strings=_VM_OR_SANDBOX,
    ),
    AntiAnalysisRule(
        category="exception-tampering",
        description="Installs or alters an exception handler",
        imports=capabilities._exact(
            "SetUnhandledExceptionFilter",
            "RtlAddVectoredExceptionHandler",
            "AddVectoredExceptionHandler",
            "SetErrorMode",
        ),
        strings=_EXCEPTION_STRING,
    ),
    AntiAnalysisRule(
        category="debugger-detection-string",
        description="Carries a debugger-detection literal",
        strings=_DEBUGGER_STRING,
    ),
    AntiAnalysisRule(
        category="io-port-probe",
        description="Reads or writes an I/O port directly, an anti-emulation probe",
        strings=_IO_PORT_PROBE,
    ),
    AntiAnalysisRule(
        category="cpu-state-probe",
        description="Reads CPU or FPU state user-space code never needs, an environment probe",
        strings=_CPU_STATE_PROBE,
    ),
    AntiAnalysisRule(
        category="int3-trap",
        description="Plants a breakpoint exception that diverges under a debugger",
        strings=_INT3_TRAP,
    ),
    AntiAnalysisRule(
        category="lock-canary",
        description="Guards globals with LOCK-prefixed writes that abort under instrumentation",
        strings=_LOCK_CANARY,
    ),
)

# Packer and protector names as string evidence, and the section-name
# conventions the same tools leave behind.
_PACKER_NAMES = re.compile(
    r"\b(?:UPX|MPRESS|Themida|VMProtect|ASPack|PECompact|Enigma|obsidium)\b", re.IGNORECASE
)
PACKER_SECTION_PREFIXES: tuple[str, ...] = ("upx", ".aspack", ".themida", ".mpress", ".packed")


class HardeningIO(Protocol):
    """The engine surface a hardening scan needs; every call is standalone."""

    def fingerprint(self, binary: str | Path) -> dict[str, Any]: ...

    def imports(self, binary: str | Path) -> dict[str, Any]: ...

    def strings(self, binary: str | Path) -> dict[str, Any]: ...


def _add(
    findings: dict[tuple[str, str], dict[str, Any]],
    *,
    category: str,
    name: str,
    detail: str,
    confidence: str,
) -> None:
    """Record one match, collapsing a repeat of the same ``(category, name)``."""
    key = (category, name.casefold())
    if key in findings:
        return
    findings[key] = {
        "category": category,
        "name": name,
        "detail": detail,
        "confidence": confidence,
    }


def _ordered(findings: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort deduplicated *findings* by confidence, then category, then name."""
    return sorted(
        findings.values(),
        key=lambda finding: (
            _CONFIDENCE_RANK[finding["confidence"]],
            finding["category"],
            finding["name"],
        ),
    )


def _by_confidence(ordered: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Count *ordered* findings per confidence label."""
    return {
        CONFIDENCE_HIGH: sum(1 for f in ordered if f["confidence"] == CONFIDENCE_HIGH),
        CONFIDENCE_MEDIUM: sum(1 for f in ordered if f["confidence"] == CONFIDENCE_MEDIUM),
    }


def classify_anti_analysis(
    imports: Sequence[dict[str, Any]], strings: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    """Match *imports* and *strings* against :data:`ANTI_ANALYSIS_RULES`.

    Returns ``{"findings", "count", "by_confidence"}``.  A finding is
    ``{"category", "name", "detail", "confidence"}``, where an import hit
    carries the import name and the rule's description, a string hit the
    matched string text and the rule's description.  Findings deduplicate by
    ``(category, name)``; the list sorts by confidence (import/high first),
    then category, then name; the list is capped at :data:`MAX_FINDINGS` while
    ``count`` and ``by_confidence`` stay exact.
    """
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    for rule in ANTI_ANALYSIS_RULES:
        for entry in imports:
            name = capabilities._import_name(entry)
            if not name:
                continue
            if any(capabilities._import_matches(pattern, name) for pattern in rule.imports):
                _add(
                    findings,
                    category=rule.category,
                    name=name,
                    detail=rule.description,
                    confidence=CONFIDENCE_HIGH,
                )
        for entry in strings:
            text = capabilities._string_text(entry)
            if not text:
                continue
            if any(pattern.search(text) for pattern in rule.strings):
                _add(
                    findings,
                    category=rule.category,
                    name=text,
                    detail=rule.description,
                    confidence=CONFIDENCE_MEDIUM,
                )

    ordered = _ordered(findings)
    return {
        "findings": ordered[:MAX_FINDINGS],
        "count": len(ordered),
        "by_confidence": _by_confidence(ordered),
    }


def _section_entries(fingerprint: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the fingerprint's section entries, ignoring any other shape."""
    raw = fingerprint.get("section_entropies")
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _section_entropy(entry: dict[str, Any]) -> float | None:
    """Return a section entry's entropy as a float, or None when unusable."""
    value = entry.get("entropy")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _section_weight(entry: dict[str, Any]) -> int:
    """Return a section's byte weight (raw size, else virtual size, else 1)."""
    for key in ("raw_size", "vsize"):
        value = entry.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return 1


def _weighted_mean_entropy(sections: Sequence[dict[str, Any]]) -> float | None:
    """Return the mean section entropy weighted by section size, or None."""
    graded = [(entry, _section_entropy(entry)) for entry in sections]
    graded = [(entry, entropy) for entry, entropy in graded if entropy is not None]
    if not graded:
        return None
    total = sum(_section_weight(entry) for entry, _ in graded)
    weighted = sum(_section_weight(entry) * cast(float, entropy) for entry, entropy in graded)
    return weighted / total


def _is_code_section(name: str) -> bool:
    """True when *name* is an executable or code-like section."""
    lowered = name.casefold()
    return "text" in lowered or "code" in lowered


def _triage_section_names(triage: dict[str, Any] | None) -> list[str]:
    """Return the section names a stored triage dossier carries, if any."""
    if not isinstance(triage, dict):
        return []
    meta = triage.get("meta")
    if not isinstance(meta, dict):
        return []
    sections = meta.get("sections")
    if not isinstance(sections, list):
        return []
    names: list[str] = []
    for entry in sections:
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str) and name:
                names.append(name)
    return names


def _section_names(fingerprint: dict[str, Any], triage: dict[str, Any] | None) -> list[str]:
    """Return the distinct section names from the triage dossier and fingerprint."""
    names = _triage_section_names(triage)
    names.extend(
        str(entry["name"])
        for entry in _section_entries(fingerprint)
        if isinstance(entry.get("name"), str) and entry["name"]
    )
    seen: set[str] = set()
    distinct: list[str] = []
    for name in names:
        key = name.casefold()
        if key not in seen:
            seen.add(key)
            distinct.append(name)
    return distinct


def _is_packer_section(name: str) -> bool:
    """True when *name* matches a packer's section-naming convention."""
    lowered = name.casefold()
    return any(lowered.startswith(prefix) for prefix in PACKER_SECTION_PREFIXES)


def classify_obfuscation(
    *,
    fingerprint: dict[str, Any],
    imports: Sequence[dict[str, Any]],
    strings: Sequence[dict[str, Any]],
    triage: dict[str, Any] | None = None,
    binary_size: int = 0,
    notes: Sequence[str] = (),
) -> dict[str, Any]:
    """Apply the obfuscation heuristics over *fingerprint*, *imports* and *strings*.

    Returns ``{"findings", "count", "by_confidence", "packer_likelihood",
    "notes"}``.  ``binary_size`` falls back to the fingerprint's ``size``.
    The two entropy thresholds are skipped with a note in ``notes`` when the
    fingerprint carries no section entropies; the sparse-table and packer-name
    heuristics still run.  ``packer_likelihood`` is
    :data:`PACKER_LIKELIHOOD_HIGH` from :data:`PACKER_HIGH_MIN_FINDINGS`
    findings, :data:`PACKER_LIKELIHOOD_MEDIUM` from
    :data:`PACKER_MEDIUM_MIN_FINDINGS`, else
    :data:`PACKER_LIKELIHOOD_LOW`.
    """
    recorded_notes = list(notes)
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    sections = _section_entries(fingerprint)

    if not sections:
        recorded_notes.append(SECTION_ENTROPY_NOTE)
    else:
        for entry in sections:
            name = entry.get("name")
            entropy = _section_entropy(entry)
            if not isinstance(name, str) or not name or entropy is None:
                continue
            if entropy >= HIGH_ENTROPY_THRESHOLD and _is_code_section(name):
                _add(
                    findings,
                    category="high-entropy-executable-section",
                    name=name,
                    detail=(
                        f"section {name} entropy {entropy:.4f} at or above {HIGH_ENTROPY_THRESHOLD}"
                    ),
                    confidence=CONFIDENCE_HIGH,
                )
        mean = _weighted_mean_entropy(sections)
        if mean is not None and mean >= HIGH_OVERALL_ENTROPY_THRESHOLD:
            _add(
                findings,
                category="high-overall-entropy",
                name=ENTRY_OVERALL_ENTROPY,
                detail=(
                    f"weighted mean section entropy {mean:.4f} at or above"
                    f" {HIGH_OVERALL_ENTROPY_THRESHOLD}"
                ),
                confidence=CONFIDENCE_MEDIUM,
            )

    size_value = fingerprint.get("size")
    size = size_value if isinstance(size_value, int) and not isinstance(size_value, bool) else 0
    if size <= 0:
        size = binary_size

    import_count = sum(1 for entry in imports if capabilities._import_name(entry))
    if size >= SPARSE_IMPORT_MIN_SIZE and import_count < SPARSE_IMPORT_THRESHOLD:
        _add(
            findings,
            category="sparse-imports",
            name=ENTRY_IMPORTS,
            detail=(
                f"{import_count} imports is below {SPARSE_IMPORT_THRESHOLD}"
                f" for a {size}-byte binary"
            ),
            confidence=CONFIDENCE_MEDIUM,
        )

    string_count = sum(1 for entry in strings if capabilities._string_text(entry))
    if size >= SPARSE_STRING_MIN_SIZE and string_count < SPARSE_STRING_THRESHOLD:
        _add(
            findings,
            category="sparse-strings",
            name=ENTRY_STRINGS,
            detail=(
                f"{string_count} strings is below {SPARSE_STRING_THRESHOLD}"
                f" for a {size}-byte binary"
            ),
            confidence=CONFIDENCE_MEDIUM,
        )

    for entry in strings:
        text = capabilities._string_text(entry)
        if not text:
            continue
        if _PACKER_NAMES.search(text):
            _add(
                findings,
                category="packer-name-artifact",
                name=text,
                detail="string names a known packer or protector",
                confidence=CONFIDENCE_HIGH,
            )
    for name in _section_names(fingerprint, triage):
        if _is_packer_section(name):
            _add(
                findings,
                category="packer-name-artifact",
                name=name,
                detail="section name matches a packer convention",
                confidence=CONFIDENCE_HIGH,
            )

    ordered = _ordered(findings)
    if len(ordered) >= PACKER_HIGH_MIN_FINDINGS:
        likelihood = PACKER_LIKELIHOOD_HIGH
    elif len(ordered) >= PACKER_MEDIUM_MIN_FINDINGS:
        likelihood = PACKER_LIKELIHOOD_MEDIUM
    else:
        likelihood = PACKER_LIKELIHOOD_LOW
    return {
        "findings": ordered[:MAX_FINDINGS],
        "count": len(ordered),
        "by_confidence": _by_confidence(ordered),
        "packer_likelihood": likelihood,
        "notes": recorded_notes,
    }


def _entries(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return the dict entries under *payload[key]*, ignoring any other shape."""
    raw = payload.get(key)
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _stored_triage(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any] | None:
    """Return the binary's stored triage dossier, or None when none exists."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    return store.get_scan(conn, analysis_id, store.SCAN_KIND_TRIAGE)


def _fingerprint_for(
    source: HardeningIO, path: Path, fingerprint: dict[str, Any] | None
) -> tuple[dict[str, Any], list[str]]:
    """Return ``(fingerprint, notes)``, recording an engine failure as a note.

    An injected *fingerprint* is returned untouched.  A missing or failed
    engine call yields an empty fingerprint and a note, so the entropy
    thresholds are skipped rather than failing the whole scan.
    """
    if fingerprint is not None:
        return fingerprint, []
    try:
        return source.fingerprint(path), []
    except engines.EngineError as exc:
        return {}, [f"fingerprint-error: {exc}"]


def scan_hardening(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    domain: str,
    engine: RebrewEngine | None = None,
    fingerprint: dict[str, Any] | None = None,
    imports: Sequence[dict[str, Any]] | None = None,
    strings: Sequence[dict[str, Any]] | None = None,
    triage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan one hardening *domain* of a binary and store the result.

    The binary's file is resolved from the stored row; *engine* (else the
    process-wide engine) supplies the standalone engine calls.  *imports*,
    *strings*, *fingerprint* and *triage* override the engine payloads and the
    stored triage dossier outright, which is how tests keep the run hermetic.
    Strings are capped at :data:`MAX_STRINGS_INSPECTED`.  The obfuscation scan
    records a note instead of failing when the fingerprint is unavailable.

    Raises :class:`ValueError` for an unknown domain, :class:`KeyError` for an
    unknown binary and :class:`FileNotFoundError` when its row has no file on
    disk; an engine failure from the imports or strings calls propagates.
    Returns ``{"binary_id", "domain", "findings", "count", "by_confidence",
    "packer_likelihood", "notes"}``, where ``packer_likelihood`` is null for
    ``anti-analysis``.
    """
    if domain not in HARDENING_DOMAINS:
        raise ValueError(f"unknown hardening domain: {domain}")
    binary, path = capabilities.require_binary_file(conn, binary_id)

    source: HardeningIO = engine or engines.get_engine()
    raw_imports, raw_strings = capabilities.load_imports_and_strings(
        path, source, imports=imports, strings=strings
    )

    if domain == DOMAIN_ANTI_ANALYSIS:
        result: dict[str, Any] = {
            **classify_anti_analysis(raw_imports, raw_strings),
            "packer_likelihood": None,
            "notes": [],
        }
    else:
        resolved, notes = _fingerprint_for(source, path, fingerprint)
        result = classify_obfuscation(
            fingerprint=resolved,
            imports=raw_imports,
            strings=raw_strings,
            triage=triage if triage is not None else _stored_triage(conn, binary_id),
            binary_size=int(binary["size"]) if isinstance(binary["size"], int) else 0,
            notes=notes,
        )

    payload = {"binary_id": binary_id, "domain": domain, **result}
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, DOMAIN_SCAN_KINDS[domain], payload)
    return payload

"""Remediation artifacts for a binary: YARA, Snort and STIX.

The hosted portal exposes an Agents/Remediation surface that turns an analysis
into detection content.  reportal renders all three formats locally:

* :func:`distinctive_strings` selects candidate literals from the entries
  ``rebrew strings`` returns, dropping the generic, the short and the
  format-specifier scaffolding that would make a noisy rule.
* :func:`distinctive_imports` does the same for the API names in the
  ``rebrew imports`` table, which are more discriminative than data literals.
* :func:`build_yara_rule` renders one complete rule: a sanitized name, a meta
  block, ``$sN`` string entries, ``$iN`` import entries and a single condition
  expression.  For a PE with an imphash the condition anchors on
  ``pe.imphash()`` and falls back to the strings and imports; otherwise it
  anchors on the file magic.  Every form bounds the filesize and clamps its
  match count to the literals carried.
* :func:`classify_specificity` grades the rule ``high`` (an exact fingerprint
  or at least :data:`MIN_SPECIFIC_STRINGS` literals), ``medium`` (some literals)
  or ``low``.
* :func:`validate_rule` compiles the rule with ``yarac`` when it is installed,
  writing the temporary source into the workspace ``.scratch/`` directory and
  removing it afterwards.  Without ``yarac`` the rule is stored unvalidated
  rather than treated as a failure.
* :func:`build_remediation` fetches the strings and imports through the engine,
  reads or builds the fingerprint for the rule metadata and the imphash anchor,
  generates the rule, validates it and stores the whole result as the
  ``remediation`` scan.  The same payload carries two further artifacts:
  :func:`build_snort_rule` renders one Snort 2 rule per network indicator from
  the stored ``threat`` scan, and :func:`build_stix_bundle` renders a STIX 2.1
  bundle over the same indicators.  The stored ``threat`` and ``protocols``
  scans are read, never re-run, and an absent threat scan is recorded in the
  Snort artifact's notes.

Nothing here is an engine call of its own: the strings, imports and fingerprint
all come from the ``rebrew`` adapter, and the artifacts are rendered locally.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from reportal import engines, protocols, store, threat
from reportal._paths import WorkspaceNotFound, db_path
from reportal.capabilities import require_binary_file
from reportal.engines import RebrewEngine

# Candidate strings kept per rule.  A string table can hold thousands of
# literals; a rule that carries every one of them is slow to match and no more
# precise than a bounded sample.
YARA_MAX_STRINGS = 20

# Candidate import names kept per rule.  Import names are more discriminative
# than data literals, but a rule that lists the whole import table is
# unreadable and no more precise than a bounded sample.
YARA_MAX_IMPORTS = 12

# Shortest literal a rule may use.  Shorter runs are common in machine code and
# match almost anything, so they are dropped rather than anchored.
YARA_MIN_STRING_LENGTH = 6

# Shortest import name a rule may use.  The two- and three-character CRT entry
# points appear in nearly every Microsoft binary and pin nothing.
YARA_MIN_IMPORT_LENGTH = 8

# Distinct literals (data strings plus import names) that make a rule specific
# on its own, without an exact fingerprint anchor.
MIN_SPECIFIC_STRINGS = 4

# Specificity grades :func:`classify_specificity` returns and the payload
# carries.
SPECIFICITY_HIGH = "high"
SPECIFICITY_MEDIUM = "medium"
SPECIFICITY_LOW = "low"

# A ``pe.imphash()`` condition needs the pe module imported ahead of the rule.
PE_MODULE_IMPORT = 'import "pe"'

# Longest literal a rule may use.  A very long string is unlikely to survive a
# recompile and adds little; the cap keeps the rule readable.
YARA_MAX_STRING_LENGTH = 200

# Matches a rule requires when the caller names no count.  It is clamped to the
# number of literals a rule actually carries, so a single-string rule is still
# satisfiable.
YARA_DEFAULT_MATCH_COUNT = 2

# Files larger than this are left to other tooling; the bound keeps a rule from
# matching a large, unrelated binary on a handful of short literals.
YARA_MAX_FILESIZE = 64 * 1024 * 1024

# Rule-name length cap, well under YARA's identifier limit.
YARA_RULE_NAME_MAX = 64

# Name used when the caller supplies nothing sanitizable.
YARA_RULE_NAME_FALLBACK = "reportal_rule"

# ``kind`` values ``rebrew strings`` reports for a UTF-16 run.  A rule for a
# wide literal keeps the ASCII form too, since a recompile may store it either
# way.
WIDE_STRING_KINDS: frozenset[str] = frozenset({"utf16", "wide", "unicode"})

# The compiled-rules checker and the magic-anchor table per fingerprint format.
YARAC_BIN = "yarac"
YARAC_TIMEOUT_SECONDS = 30
_MAGIC_EXPRESSIONS: dict[str, str] = {
    "pe": "uint16(0) == 0x5A4D",
    "elf": "uint32(0) == 0x464C457F",
    "macho": "(uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF)",
}

# Meta keys emitted in a fixed order.  ``author`` is always written by the
# builder; the rest come from the supplied metadata, and any extra key follows
# in sorted order so two builds of the same input are byte-identical.
YARA_AUTHOR = "reportal"
YARA_META_ORDER: tuple[str, ...] = ("date", "binary", "sha256", "imphash", "rich_header_hash")

# Keys accepted in the metadata block; used to keep the emitted order stable.
_AUTHOR_KEY = "author"

# Words a rule should not anchor on: common runtime, CRT, DLL and UI vocabulary
# shared by almost every Windows binary.  Compared case-insensitively against
# the whole literal.
YARA_STRING_DENYLIST: frozenset[str] = frozenset(
    {
        "error",
        "warning",
        "info",
        "debug",
        "true",
        "false",
        "null",
        "none",
        "yes",
        "no",
        "ok",
        "cancel",
        "untitled",
        "unknown",
        "invalid",
        "success",
        "succeeded",
        "failed",
        "failure",
        "please",
        "click",
        "press",
        "the",
        "and",
        "for",
        "this",
        "that",
        "with",
        "from",
        "string",
        "buffer",
        "memory",
        "file",
        "files",
        "path",
        "name",
        "value",
        "data",
        "type",
        "size",
        "count",
        "index",
        "result",
        "message",
        "text",
        "state",
        "flags",
        "mode",
        "open",
        "close",
        "read",
        "write",
        "delete",
        "create",
        "kernel32",
        "user32",
        "advapi32",
        "gdi32",
        "msvcrt",
        "ntdll",
        "shell32",
        "comdlg32",
        "ole32",
        "winmm",
        "kernel32.dll",
        "user32.dll",
        "advapi32.dll",
        "gdi32.dll",
        "msvcrt.dll",
        "ntdll.dll",
        "shell32.dll",
        "comdlg32.dll",
        "ole32.dll",
        "microsoft",
        "windows",
        "software",
        "system",
        "system32",
        "config",
        "settings",
        "program files",
    }
)

# Import names shared by nearly every Windows binary: the CRT startup set and
# the kernel32 loader, memory and error calls that only say "a C program".
# Dropped before ranking so a rule keeps the calls that describe this program.
# Compared case-insensitively against the whole import name.
YARA_GENERIC_API_DENYLIST: frozenset[str] = frozenset(
    {
        "__getmainargs",
        "__p__commode",
        "__p__fmode",
        "__set_app_type",
        "__setusermatherr",
        "_acmdln",
        "_adjust_fdiv",
        "_amsg_exit",
        "_cexit",
        "_controlfp",
        "_except_handler3",
        "_exit",
        "_initterm",
        "_onexit",
        "_wtol",
        "_xcptfilter",
        "abort",
        "atexit",
        "exit",
        "iswctype",
        "localtime",
        "time",
        "wcsncmp",
        "wcsncpy",
        "closehandle",
        "freelibrary",
        "getcurrentprocess",
        "getcurrentthreadid",
        "getlasterror",
        "getmodulehandlea",
        "getmodulehandlew",
        "getprocessheap",
        "getprocaddress",
        "gettickcount",
        "globalalloc",
        "globalfree",
        "globallock",
        "globalunlock",
        "heapalloc",
        "heapfree",
        "interlockeddecrement",
        "interlockedincrement",
        "loadlibrarya",
        "loadlibraryw",
        "localalloc",
        "localfree",
        "locallock",
        "localrealloc",
        "localsize",
        "localunlock",
        "multibytetowidechar",
        "setlasterror",
        "sleep",
        "virtualalloc",
        "virtualfree",
        "widechartomultibyte",
    }
)

# A printf conversion, used to detect a literal that is nothing but format
# scaffolding once the conversions are removed.
_FORMAT_SPECIFIER = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[hlLqjzt]*[diouxXeEfFgGaAcspn]")

# Characters allowed in a YARA identifier.
_IDENTIFIER = re.compile(r"[^0-9A-Za-z_]+")

# YARA keywords a rule name must not collide with.
_YARA_KEYWORDS: frozenset[str] = frozenset(
    {
        "all",
        "and",
        "any",
        "at",
        "condition",
        "contains",
        "entrypoint",
        "false",
        "filesize",
        "for",
        "global",
        "import",
        "in",
        "include",
        "matches",
        "meta",
        "not",
        "of",
        "or",
        "private",
        "rule",
        "strings",
        "them",
        "true",
    }
)

# Scratch subdirectory under the workspace that holds transient rule sources.
SCRATCH_DIR = ".scratch"
YARA_SCRATCH_SUBDIR = "yara"


class NoStringsError(ValueError):
    """The binary yielded no literal a rule can use."""


# A string entry is either the engine's ``{"text", "kind", ...}`` object or a
# bare literal the caller already selected.
YaraStringInput = str | dict[str, Any]


def _entry_text(entry: dict[str, Any]) -> str:
    """Return an engine string entry's text, or "" when it carries none."""
    return str(entry.get("text") or "").strip()


def _is_noise(text: str) -> bool:
    """True when *text* is only punctuation, digits or format scaffolding."""
    residual = _FORMAT_SPECIFIER.sub("", text)
    return not any(character.isalpha() for character in residual)


def distinctive_strings(
    strings: Sequence[dict[str, Any]],
    *,
    limit: int = YARA_MAX_STRINGS,
    min_length: int = YARA_MIN_STRING_LENGTH,
) -> list[str]:
    """Select rule literals from engine string entries.

    Candidates are the unique texts of at least *min_length* characters that
    are not in :data:`YARA_STRING_DENYLIST` and carry real letters beyond any
    format specifiers.  They are returned longest first (ties broken
    alphabetically, so the order is deterministic) and capped at *limit*.
    """
    candidates: dict[str, None] = {}
    for entry in strings:
        text = _entry_text(entry)
        if not text or text in candidates:
            continue
        if not min_length <= len(text) <= YARA_MAX_STRING_LENGTH:
            continue
        if text.casefold() in YARA_STRING_DENYLIST or _is_noise(text):
            continue
        candidates[text] = None
    ordered = sorted(candidates, key=lambda text: (-len(text), text))
    return ordered[:limit]


def distinctive_imports(
    names: Sequence[str],
    *,
    limit: int = YARA_MAX_IMPORTS,
    min_length: int = YARA_MIN_IMPORT_LENGTH,
) -> list[str]:
    """Select rule literals from import API names.

    Names shorter than *min_length* and names in
    :data:`YARA_GENERIC_API_DENYLIST` are dropped and duplicates collapse.
    The rest are ranked longest first with same-length ties reversed
    alphabetically, then capped at *limit*, so the selection is deterministic.
    """
    candidates: set[str] = set()
    for raw in names:
        name = str(raw).strip()
        if len(name) < min_length or name.casefold() in YARA_GENERIC_API_DENYLIST:
            continue
        candidates.add(name)
    return sorted(candidates, key=lambda name: (len(name), name), reverse=True)[:limit]


def _import_names(payload: Mapping[str, Any]) -> list[str]:
    """Return the unique import and stub names of an ``rebrew imports`` payload."""
    names: dict[str, None] = {}
    for key in ("imports", "stubs"):
        raw = payload.get(key)
        if not isinstance(raw, list):
            continue
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            if name:
                names[name] = None
    return list(names)


def classify_specificity(*, has_imphash: bool, string_count: int, import_count: int) -> str:
    """Return the specificity grade of a rule.

    ``high`` when the condition carries an exact fingerprint (imphash) or at
    least :data:`MIN_SPECIFIC_STRINGS` distinct literals, ``medium`` when it
    carries some but fewer than that floor, and ``low`` when it carries none.
    """
    total = max(string_count, 0) + max(import_count, 0)
    if has_imphash or total >= MIN_SPECIFIC_STRINGS:
        return SPECIFICITY_HIGH
    if total:
        return SPECIFICITY_MEDIUM
    return SPECIFICITY_LOW


def yara_escape(value: str) -> str:
    """Escape *value* for a double-quoted YARA string literal.

    Backslash and double quote are escaped, printable ASCII passes through and
    every other character is emitted as one ``\\xNN`` escape per UTF-8 byte, so
    the literal is byte-exact whatever the source encoding.
    """
    escaped: list[str] = []
    for byte in value.encode("utf-8"):
        if byte == 0x5C:
            escaped.append("\\\\")
        elif byte == 0x22:
            escaped.append('\\"')
        elif 0x20 <= byte <= 0x7E:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\x{byte:02x}")
    return "".join(escaped)


def sanitize_rule_name(name: str) -> str:
    """Return *name* as a valid, non-keyword YARA rule identifier."""
    cleaned = _IDENTIFIER.sub("_", name).strip("_")
    if not cleaned:
        cleaned = YARA_RULE_NAME_FALLBACK
    if cleaned[0].isdigit():
        cleaned = f"rule_{cleaned}"
    cleaned = cleaned[:YARA_RULE_NAME_MAX].strip("_") or YARA_RULE_NAME_FALLBACK
    if cleaned.casefold() in _YARA_KEYWORDS:
        cleaned = f"rule_{cleaned}"
    return cleaned


def _meta_value(value: Any) -> str:
    """Render one meta value: a bare number, a bare boolean, else a string."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return f'"{yara_escape(str(value))}"'


def _meta_lines(meta: Mapping[str, Any]) -> list[str]:
    """Render the meta block: author, the ordered known keys, then extras."""
    lines = [f"        {_AUTHOR_KEY} = {_meta_value(YARA_AUTHOR)}"]
    seen: set[str] = set()
    for key in YARA_META_ORDER:
        if key in meta and meta[key] not in (None, ""):
            seen.add(key)
            lines.append(f"        {sanitize_rule_name(key)} = {_meta_value(meta[key])}")
    for key in sorted(set(meta) - seen - {_AUTHOR_KEY}):
        if meta[key] not in (None, ""):
            lines.append(f"        {sanitize_rule_name(key)} = {_meta_value(meta[key])}")
    return lines


def _entries_by_text(entries: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map each entry's text to one entry, preferring a wide one.

    The same literal is often stored both as ASCII and as UTF-16; keeping the
    wide entry lets the rule carry the ``ascii wide`` modifier and match either.
    """
    by_text: dict[str, dict[str, Any]] = {}
    for entry in entries:
        text = _entry_text(entry)
        if not text:
            continue
        existing = by_text.get(text)
        wide = str(entry.get("kind") or "").casefold() in WIDE_STRING_KINDS
        if existing is None or wide:
            by_text[text] = entry
    return by_text


def _rule_entries(strings: Sequence[YaraStringInput]) -> list[tuple[str, bool]]:
    """Return deduplicated ``(text, wide)`` pairs from rule string inputs."""
    entries: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for item in strings:
        if isinstance(item, dict):
            text = _entry_text(item)
            wide = str(item.get("kind") or "").casefold() in WIDE_STRING_KINDS
        else:
            text = str(item).strip()
            wide = False
        if not text or text in seen:
            continue
        seen.add(text)
        entries.append((text, wide))
    return entries


def _condition(
    *,
    fmt: str,
    imphash: str | None,
    match_count: int,
    string_count: int,
    import_count: int,
) -> str:
    """Render the single condition expression of a rule.

    With *imphash* the fingerprint, string and import tests form one
    parenthesized alternative; without it the magic anchor and the ``them``
    clause stand alone.  Every form carries the filesize bound.
    """
    clauses: list[str] = []
    magic = _MAGIC_EXPRESSIONS.get(fmt)
    if magic is not None:
        clauses.append(magic)
    if imphash is not None:
        group = [
            f'pe.imphash() == "{yara_escape(imphash)}"',
            f"{min(match_count, string_count)} of ($s*)",
        ]
        if import_count:
            group.append(f"({min(match_count, import_count)} of ($i*))")
        clauses.append(f"({' or '.join(group)})")
    else:
        clauses.append(f"{min(match_count, string_count + import_count)} of them")
    clauses.append(f"filesize < {YARA_MAX_FILESIZE}")
    return " and ".join(clauses)


def build_yara_rule(
    *,
    name: str,
    strings: Sequence[YaraStringInput],
    meta: Mapping[str, Any],
    kind: str,
    match_count: int = YARA_DEFAULT_MATCH_COUNT,
    imports: Sequence[str] = (),
    imphash: str | None = None,
) -> str:
    """Render a complete YARA rule.

    *name* is sanitized into the rule identifier; *strings* become
    ``$s1..$sN`` (a literal whose engine kind is wide keeps the ASCII form too)
    and *imports* the ``$i1..$iN`` import-name entries; *meta* becomes the meta
    block with ``author`` and the ordered known keys.  When *imphash* is set on
    a PE the condition imports the ``pe`` module and anchors on
    ``pe.imphash()``, falling back to the string and import clauses; otherwise
    it anchors on the file magic for *kind*.  Every form bounds the filesize and
    clamps each match count to the literals carried.  The output is
    deterministic: only the caller-supplied meta, never a generated timestamp.

    Raises :class:`ValueError` when there is no literal to anchor on.
    """
    if match_count < 1:
        raise ValueError(f"match_count must be positive, got {match_count}")
    entries = _rule_entries(strings)
    if not entries:
        raise ValueError("a YARA rule needs at least one string")
    import_entries = _rule_entries(imports)
    fmt = kind.strip().lstrip(".").casefold()
    fingerprint = imphash if fmt == "pe" and imphash else None

    lines: list[str] = []
    if fingerprint is not None:
        lines.extend([PE_MODULE_IMPORT, ""])
    lines.extend([f"rule {sanitize_rule_name(name)}", "{", "    meta:"])
    lines.extend(_meta_lines(meta))
    lines.extend(["", "    strings:"])
    for index, (text, wide) in enumerate(entries, start=1):
        modifier = "ascii wide" if wide else "ascii"
        lines.append(f'        $s{index} = "{yara_escape(text)}" {modifier}')
    for index, (text, _wide) in enumerate(import_entries, start=1):
        lines.append(f'        $i{index} = "{yara_escape(text)}" ascii')

    condition = _condition(
        fmt=fmt,
        imphash=fingerprint,
        match_count=match_count,
        string_count=len(entries),
        import_count=len(import_entries),
    )
    lines.extend(["", "    condition:", f"        {condition}", "}", ""])
    return "\n".join(lines)


def _scratch_dir() -> Path:
    """Return the workspace ``.scratch/yara`` directory, creating it."""
    try:
        root = db_path().parent
    except WorkspaceNotFound:
        root = Path.cwd()
    directory = root / SCRATCH_DIR / YARA_SCRATCH_SUBDIR
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def validate_rule(rule: str) -> dict[str, Any]:
    """Compile *rule* with ``yarac`` and report the outcome.

    Returns ``{"validated", "validator", "error"}``.  Without ``yarac`` the
    result is ``validated: false`` with ``validator: null`` and an explanatory
    error, never an exception.  The temporary source is written under the
    workspace scratch directory and removed before returning.
    """
    yarac = shutil.which(YARAC_BIN)
    if yarac is None:
        return {
            "validated": False,
            "validator": None,
            "error": f"{YARAC_BIN} is not installed",
        }
    directory = _scratch_dir()
    handle, temp_name = tempfile.mkstemp(dir=directory, prefix="rule-", suffix=".yar")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(rule)
        try:
            proc = subprocess.run(
                [yarac, temp_name, os.devnull],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=YARAC_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"validated": False, "validator": YARAC_BIN, "error": str(exc)}
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(handle)
        raise
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)
    if proc.returncode == 0:
        return {"validated": True, "validator": YARAC_BIN, "error": None}
    message = " ".join(proc.stderr.split()) or f"{YARAC_BIN} rejected the rule"
    return {"validated": False, "validator": YARAC_BIN, "error": message}


def _fingerprint_meta(binary: Mapping[str, Any], fingerprint: Mapping[str, Any]) -> dict[str, Any]:
    """Build the rule meta block from the binary row and its fingerprint."""
    sha256 = str(fingerprint.get("sha256") or binary.get("sha256") or "")
    meta: dict[str, Any] = {
        "date": store.now()[:10],
        "binary": str(binary.get("name") or ""),
    }
    if sha256:
        meta["sha256"] = sha256
    for key in ("imphash", "rich_header_hash"):
        value = fingerprint.get(key)
        if value:
            meta[key] = str(value)
    return meta


# ── Snort ──────────────────────────────────────────────────────────

# Artifact names the format routes and the CLI commands accept.  ``yara`` is
# the rule payload's own text; ``snort`` and ``stix`` are the sub-objects the
# remediation payload carries.
REMEDIATION_FORMATS: tuple[str, ...] = ("yara", "snort", "stix")

# First SID of a generated rule set.  Snort reserves 1,000,000 and above for
# locally written rules, so a reportal set never collides with a vendor
# signature.
SNORT_SID_BASE = 1_000_000

# Indicator families a rule is built from, in emission order, paired with the
# family label the rule dict carries.  The threat report's categories name the
# same families; a rule is emitted per indicator, ordered by family then value.
SNORT_FAMILIES: tuple[tuple[str, str], ...] = (
    (threat.IOC_CATEGORY_URLS, "url"),
    (threat.IOC_CATEGORY_DOMAINS, "domain"),
    (threat.IOC_CATEGORY_IPV4, "ipv4"),
    (threat.IOC_CATEGORY_IPV6, "ipv6"),
)

# Protocol name a URL scheme names, so a scheme's port can be looked up in the
# stored protocol scan.
SNORT_SCHEME_PROTOCOLS: dict[str, str] = {
    "http": "http",
    "https": "https",
    "ftp": "ftp",
    "smtp": "smtp",
    "imap": "imap",
    "pop3": "pop3",
    "ssh": "ssh",
    "telnet": "telnet",
    "ldap": "ldap",
    "ldaps": "ldap",
    "mqtt": "mqtt",
    "mqtts": "mqtt",
    "irc": "irc",
    "ircs": "irc",
    "ws": "websocket",
    "wss": "websocket",
    "quic": "quic",
    "rdp": "rdp",
    "dns": "dns",
}

# Protocol preference for an indicator that names no scheme.  The first
# protocol present in the stored scan with a well-known port supplies it, so a
# domain or an address in an HTTPS-only binary still gets 443 rather than 53.
SNORT_PROTOCOL_PREFERENCE: tuple[str, ...] = (
    "https",
    "http",
    "tls",
    "ftp",
    "smtp",
    "dns",
    "tcp",
    "udp",
)

# Destination written when no port is inferable; ``any`` keeps the rule valid
# while saying the port is unknown.
SNORT_ANY_PORT = "any"

# Note a Snort artifact carries when the threat report names no host.
SNORT_NO_INDICATORS_NOTE = "no network indicators in the stored threat scan"

# Note the remediation payload's Snort artifact carries when no threat scan is
# stored; the artifact is then empty for want of indicators.
THREAT_SCAN_ABSENT_NOTE = (
    "threat-scan-unavailable: no stored threat scan, so no network indicators were available"
)


def snort_escape(value: str) -> str:
    """Escape *value* for a Snort double-quoted option value.

    Snort reads a backslash, a double quote and a vertical bar as its own
    syntax inside a quoted value, so each is backslash-escaped.
    """
    escaped: list[str] = []
    for character in value:
        if character in {"\\", '"', "|"}:
            escaped.append("\\" + character)
        else:
            escaped.append(character)
    return "".join(escaped)


def _url_host(value: str) -> str:
    """Return a URL's host without userinfo or port, else its netloc."""
    netloc = urlsplit(value).netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):
        return netloc
    return netloc.rsplit(":", 1)[0] if ":" in netloc else netloc


def _indicator_host(value: str, family: str) -> str:
    """Return the host a rule's ``content`` matches for one indicator."""
    return _url_host(value) if family == "url" else value


def _explicit_port(value: str, family: str) -> int | None:
    """Return the port an indicator names itself, else None.

    A URL's port comes from :func:`urllib.parse.urlsplit`; every other family
    is checked for a trailing ``:NNNN``.  A value outside 1..65535 (or a
    malformed URL port) yields None so the inferred port is used instead.
    """
    if family == "url":
        try:
            port = urlsplit(value).port
        except ValueError:
            return None
    else:
        match = re.search(r":(\d{1,5})$", value)
        port = int(match.group(1)) if match else None
    if port is None or not 1 <= port <= 65535:
        return None
    return port


def _protocol_ports(payload: Any) -> dict[str, list[int]]:
    """Map each protocol name in a stored protocols scan to its well-known ports."""
    entries = payload.get("protocols") if isinstance(payload, Mapping) else None
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        return {}
    ports: dict[str, list[int]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        name = str(entry.get("protocol") or "")
        raw = entry.get("ports")
        if not name or not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            continue
        known = [
            int(port)
            for port in raw
            if isinstance(port, int) and port in protocols.WELL_KNOWN_PORTS
        ]
        if known:
            ports[name] = sorted(known)
    return ports


def _inferred_port(value: str, family: str, protocol_ports: Mapping[str, list[int]]) -> int | None:
    """Return the port the stored protocol scan suggests, else None.

    A URL's scheme is tried first, then :data:`SNORT_PROTOCOL_PREFERENCE`, then
    any other protocol the scan reports; the smallest well-known port of the
    first protocol found wins.
    """
    if not protocol_ports:
        return None
    if family == "url":
        name = SNORT_SCHEME_PROTOCOLS.get(urlsplit(value).scheme.casefold())
        if name and protocol_ports.get(name):
            return min(protocol_ports[name])
    for name in SNORT_PROTOCOL_PREFERENCE:
        if protocol_ports.get(name):
            return min(protocol_ports[name])
    for name in sorted(protocol_ports):
        if protocol_ports[name]:
            return min(protocol_ports[name])
    return None


def _snort_rule(*, message: str, host: str, port: int | None, sid: int) -> str:
    """Render one Snort 2 rule for a host indicator."""
    destination = str(port) if port is not None else SNORT_ANY_PORT
    return (
        f"alert tcp $HOME_NET any -> $EXTERNAL_NET {destination} "
        f'(msg:"{snort_escape(message)}"; flow:established,to_server; '
        f'content:"{snort_escape(host)}"; http_header; sid:{sid}; rev:1;)'
    )


def _indicator_values(indicators: Mapping[str, Any], category: str) -> list[str]:
    """Return the unique, non-empty values of one IOC category, sorted."""
    findings = indicators.get(category)
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        return []
    values = {
        str(finding.get("value") or "").strip()
        for finding in findings
        if isinstance(finding, Mapping) and str(finding.get("value") or "").strip()
    }
    return sorted(values)


def build_snort_rule(
    *,
    name: str,
    indicators: Mapping[str, Any],
    meta: Mapping[str, Any],
) -> dict[str, Any]:
    """Render a Snort 2 rule set from a threat report's network indicators.

    *indicators* is the stored threat payload's ``iocs`` mapping; *meta* may
    carry the stored protocols scan under ``"protocols"``, which supplies the
    destination port when an indicator names none.  Returns ``{"rules",
    "text", "notes"}``: one rule per URL, domain and IPv4 indicator, ordered by
    family then value, with a SID counting up from :data:`SNORT_SID_BASE`, and
    every rule's text in ``text``.  A binary with no usable network indicator
    yields empty rules and text with :data:`SNORT_NO_INDICATORS_NOTE` rather
    than an invented rule.
    """
    protocol_ports = _protocol_ports(meta.get("protocols"))
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for category, family in SNORT_FAMILIES:
        for value in _indicator_values(indicators, category):
            if value in seen:
                continue
            seen.add(value)
            host = _indicator_host(value, family)
            if not host:
                continue
            port = _explicit_port(value, family) or _inferred_port(value, family, protocol_ports)
            sid = SNORT_SID_BASE + len(rules)
            message = f"{name} {family} {value}"
            rules.append(
                {
                    "sid": sid,
                    "family": family,
                    "value": value,
                    "host": host,
                    "port": port,
                    "text": _snort_rule(message=message, host=host, port=port, sid=sid),
                }
            )
    if not rules:
        return {"rules": [], "text": "", "notes": [SNORT_NO_INDICATORS_NOTE]}
    text = "".join(f"{rule['text']}\n" for rule in rules)
    return {"rules": rules, "text": text, "notes": []}


# ── STIX 2.1 ───────────────────────────────────────────────────────

# STIX version every emitted object declares.
STIX_SPEC_VERSION = "2.1"

# Namespace the deterministic object ids are derived in.  It is a fixed
# uuid5 of this project's URL, so the same pattern yields the same id on every
# machine and every build.
STIX_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/maci0/reportal")

# STIX hash property per IOC hash kind.
STIX_HASH_NAMES: dict[str, str] = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}

# IOC categories an indicator object is emitted for, in emission order.  A
# registry path or a file path has no faithful STIX pattern here, so those two
# categories are reported in a note instead of being coerced.
STIX_SUPPORTED_CATEGORIES: tuple[str, ...] = (
    threat.IOC_CATEGORY_URLS,
    threat.IOC_CATEGORY_DOMAINS,
    threat.IOC_CATEGORY_IPV4,
    threat.IOC_CATEGORY_IPV6,
    threat.IOC_CATEGORY_EMAILS,
    threat.IOC_CATEGORY_HASHES,
)

# Identity object reportal owns every emitted object through.
STIX_IDENTITY_NAME = "reportal"

# Content of the note object a bundle carries when it holds no indicator.
STIX_NO_INDICATORS_NOTE = "no indicators in the stored threat scan"


def stix_escape(value: str) -> str:
    """Escape *value* for a single-quoted STIX pattern string."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _stix_pattern(finding: Mapping[str, Any], category: str) -> str | None:
    """Return the STIX pattern for one finding, or None when it has none.

    The four network forms and the file-hash form are the whole map; a hash
    whose kind is not one of :data:`STIX_HASH_NAMES` is skipped.
    """
    value = str(finding.get("value") or "").strip()
    if not value:
        return None
    escaped = stix_escape(value)
    if category == threat.IOC_CATEGORY_URLS:
        return f"[url:value = '{escaped}']"
    if category == threat.IOC_CATEGORY_DOMAINS:
        return (
            f"[network-traffic:dst_ref.type = 'domain-name' AND "
            f"network-traffic:dst_ref.value = '{escaped}']"
        )
    if category == threat.IOC_CATEGORY_IPV4:
        return f"[ipv4-addr:value = '{escaped}']"
    if category == threat.IOC_CATEGORY_IPV6:
        return f"[ipv6-addr:value = '{escaped}']"
    if category == threat.IOC_CATEGORY_EMAILS:
        return f"[email-addr:value = '{escaped}']"
    if category == threat.IOC_CATEGORY_HASHES:
        name = STIX_HASH_NAMES.get(str(finding.get("kind") or "").casefold())
        return f"[file:hashes.'{name}' = '{escaped}']" if name else None
    return None


def _stix_timestamp(meta: Mapping[str, Any]) -> str:
    """Return the supplied date as a UTC ISO 8601 timestamp with a ``Z`` suffix.

    A bare date is midnight UTC; an aware value is converted to UTC; a naive
    clock time is treated as UTC (the same policy as :func:`reportal.store.now`
    and :func:`reportal.notifications.parse_since`).  An absent or unparseable
    date falls back to today's UTC date so a payload built without meta is still
    well-formed STIX.
    """
    raw = str(meta.get("date") or "").strip()
    if not raw:
        raw = store.now()[:10]
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        parsed = datetime.fromisoformat(store.now()[:10])
    parsed = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _stix_identity(timestamp: str) -> dict[str, Any]:
    """Return the identity object every bundle is owned by."""
    return {
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": f"identity--{uuid.uuid5(STIX_NAMESPACE, f'identity:{STIX_IDENTITY_NAME}')}",
        "created": timestamp,
        "modified": timestamp,
        "name": STIX_IDENTITY_NAME,
        "identity_class": "system",
    }


def _stix_note(*, key: str, timestamp: str, content: str, refs: list[str]) -> dict[str, Any]:
    """Return one note object with a deterministic id."""
    return {
        "type": "note",
        "spec_version": STIX_SPEC_VERSION,
        "id": f"note--{uuid.uuid5(STIX_NAMESPACE, f'note:{key}')}",
        "created": timestamp,
        "modified": timestamp,
        "content": content,
        "object_refs": refs,
    }


def build_stix_bundle(
    *,
    name: str,
    indicators: Mapping[str, Any],
    meta: Mapping[str, Any],
) -> dict[str, Any]:
    """Render a STIX 2.1 bundle over a threat report's indicators.

    *indicators* is the stored threat payload's ``iocs`` mapping and *meta* the
    rule metadata, whose ``date`` becomes ``created``, ``modified`` and
    ``valid_from``.  The bundle carries a reportal ``identity`` object, one
    ``indicator`` per IOC with a STIX pattern and ``pattern_type`` ``stix``, and
    a ``note`` when it holds no indicator.  Every id is a :func:`uuid.uuid5` of
    the object's pattern (or of its fixed key), so two builds of one input are
    byte-identical.

    Use :func:`as_json` to serialize the bundle.
    """
    timestamp = _stix_timestamp(meta)
    identity = _stix_identity(timestamp)
    objects: list[dict[str, Any]] = [identity]
    skipped: set[str] = set()
    for category in threat.IOC_CATEGORIES:
        findings = indicators.get(category)
        if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
            continue
        representable = category in STIX_SUPPORTED_CATEGORIES
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            if not representable:
                skipped.add(category)
                continue
            pattern = _stix_pattern(finding, category)
            if pattern is None:
                continue
            value = str(finding.get("value") or "").strip()
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": STIX_SPEC_VERSION,
                    "id": f"indicator--{uuid.uuid5(STIX_NAMESPACE, pattern)}",
                    "created": timestamp,
                    "modified": timestamp,
                    "name": f"{name} {category} {value}".strip(),
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": timestamp,
                }
            )
    has_indicator = any(obj["type"] == "indicator" for obj in objects)
    if not has_indicator:
        objects.append(
            _stix_note(
                key="no-indicators",
                timestamp=timestamp,
                content=STIX_NO_INDICATORS_NOTE,
                refs=[str(identity["id"])],
            )
        )
    if skipped:
        listed = ", ".join(sorted(skipped))
        objects.append(
            _stix_note(
                key=f"unsupported:{listed}",
                timestamp=timestamp,
                content=f"indicator categories with no STIX pattern here: {listed}",
                refs=[str(identity["id"])],
            )
        )
    bundle_id = f"bundle--{uuid.uuid5(STIX_NAMESPACE, '|'.join(str(obj['id']) for obj in objects))}"
    return {
        "type": "bundle",
        "spec_version": STIX_SPEC_VERSION,
        "id": bundle_id,
        "objects": objects,
    }


def as_json(bundle: Mapping[str, Any]) -> str:
    """Serialize a STIX bundle as indented, key-sorted JSON with a trailing newline."""
    return json.dumps(bundle, indent=2, sort_keys=True) + "\n"


def _threat_iocs(scan: Mapping[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    """Return the IOC mapping a stored threat scan carries, else {}."""
    raw = scan.get("iocs") if isinstance(scan, Mapping) else None
    if not isinstance(raw, Mapping):
        return {}
    iocs: dict[str, list[dict[str, Any]]] = {}
    for category in threat.IOC_CATEGORIES:
        findings = raw.get(category)
        if isinstance(findings, Sequence) and not isinstance(findings, (str, bytes)):
            selected = [dict(finding) for finding in findings if isinstance(finding, Mapping)]
            if selected:
                iocs[category] = selected
    return iocs


def build_remediation(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: RebrewEngine | None = None,
) -> dict[str, Any]:
    """Generate, validate and store a binary's remediation artifacts.

    The binary's file is resolved from the stored row; *engine* (else the
    process-wide engine) supplies ``rebrew strings``, ``rebrew imports`` and,
    when no fingerprint is stored, ``rebrew fingerprints``.  Literals come from
    the strings and from the import API names, the fingerprint's imphash
    anchors the PE condition, and the rule's specificity is graded and
    reported.  The stored ``threat`` scan supplies the IOC payload and the
    stored ``protocols`` scan the Snort destination ports; both are read, never
    run.  The payload carries the YARA rule plus the ``snort`` and ``stix``
    sub-objects and is stored as the ``remediation`` scan.  Its ``notes``
    describe the YARA validation only; an absent threat scan is recorded in the
    ``snort`` artifact's own notes.

    Raises :class:`KeyError` for an unknown binary, :class:`FileNotFoundError`
    when its row has no file, :class:`NoStringsError` when no literal survives
    selection, and :class:`~reportal.engines.EngineUnavailable` when no engine
    is configured.  An engine failure propagates as
    :class:`~reportal.engines.EngineError`.
    """
    binary, path = require_binary_file(conn, binary_id)

    source = engine if engine is not None else engines.get_engine()
    if source is None or not source.available():
        raise engines.EngineUnavailable("no rebrew engine is available for strings")

    notes: list[str] = []
    raw = source.strings(path).get("strings")
    entries = [entry for entry in raw if isinstance(entry, dict)] if isinstance(raw, list) else []
    selected = distinctive_strings(entries)
    if not selected:
        raise NoStringsError(
            f"binary {binary_id} has no distinctive strings;"
            f" the rule needs a printable literal of {YARA_MIN_STRING_LENGTH}+ characters"
        )

    by_text = _entries_by_text(entries)
    rule_strings = [by_text[text] for text in selected]
    import_names = _import_names(source.imports(path))
    selected_imports = distinctive_imports(import_names)

    fingerprint = store.get_fingerprint(conn, binary_id)
    if fingerprint is None:
        fingerprint = source.fingerprint(path)
    meta = _fingerprint_meta(binary, fingerprint)
    rule_name = f"{binary['name']}_{str(meta.get('sha256') or '')[:12]}"
    fmt = str(fingerprint.get("format") or binary.get("format") or "")
    imphash = str(fingerprint.get("imphash") or "") or None
    rule = build_yara_rule(
        name=rule_name,
        strings=rule_strings,
        meta=meta,
        kind=fmt,
        imports=selected_imports,
        imphash=imphash,
    )

    validation = validate_rule(rule)
    if validation["validator"] is None:
        notes.append(f"{YARAC_BIN}-unavailable: the rule was stored without validation")
    elif not validation["validated"]:
        notes.append(f"validation-error: {validation['error']}")

    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    stored_threat = store.get_scan(conn, analysis_id, store.SCAN_KIND_THREAT)
    stored_protocols = store.get_scan(conn, analysis_id, store.SCAN_KIND_PROTOCOLS)
    indicators = _threat_iocs(stored_threat)
    snort = build_snort_rule(
        name=rule_name,
        indicators=indicators,
        meta={"protocols": stored_protocols},
    )
    if stored_threat is None:
        snort["notes"] = [THREAT_SCAN_ABSENT_NOTE, *snort["notes"]]

    payload = {
        "binary_id": binary_id,
        "rule": rule,
        "rule_name": sanitize_rule_name(rule_name),
        "string_count": len(rule_strings),
        "import_count": len(selected_imports),
        "specificity": classify_specificity(
            has_imphash=fmt.strip().lstrip(".").casefold() == "pe" and imphash is not None,
            string_count=len(rule_strings),
            import_count=len(selected_imports),
        ),
        "validated": bool(validation["validated"]),
        "validator": validation["validator"],
        "meta": meta,
        "notes": notes,
        "snort": snort,
        "stix": build_stix_bundle(name=rule_name, indicators=indicators, meta=meta),
    }
    store.set_scan(conn, analysis_id, store.SCAN_KIND_REMEDIATION, payload)
    return payload

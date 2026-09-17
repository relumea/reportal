"""Behavioral scans: deterministic execution, networking and filesystem heuristics.

The hosted RevEng.AI portal runs an agent per analysis for execution,
networking and filesystem behavior.  reportal reproduces the static half
locally and deterministically: a binary's import table and extracted strings
are matched against a fixed rule table per domain, so a scan needs no LLM and
makes no network call.  Import evidence (a concrete API family) yields
:data:`~reportal.capabilities.CONFIDENCE_HIGH`, string-only evidence
:data:`~reportal.capabilities.CONFIDENCE_MEDIUM`.

Both engine calls are standalone: ``rebrew imports`` and ``rebrew strings``
read the binary file alone, so a scan needs no rebrew project context.  Each
domain's result is stored as its own scan kind (:data:`DOMAIN_SCAN_KINDS`).
Import-name matching reuses the :mod:`reportal.capabilities` rule primitives
rather than repeating the comparison.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from reportal import capabilities, engines, store
from reportal.capabilities import ImportRule
from reportal.engines import RebrewEngine

# Domain names, in the order the CLI, the API and the SPA list them.
DOMAIN_EXECUTION = "execution"
DOMAIN_NETWORKING = "networking"
DOMAIN_FILESYSTEM = "filesystem"

BEHAVIOR_DOMAINS: tuple[str, ...] = (DOMAIN_EXECUTION, DOMAIN_NETWORKING, DOMAIN_FILESYSTEM)

# Stored scan kind per domain, so `GET /api/binaries/<id>/behavior` and the
# store agree on where a domain's result lives.
DOMAIN_SCAN_KINDS: dict[str, str] = {
    DOMAIN_EXECUTION: store.SCAN_KIND_EXECUTION,
    DOMAIN_NETWORKING: store.SCAN_KIND_NETWORKING,
    DOMAIN_FILESYSTEM: store.SCAN_KIND_FILESYSTEM,
}

# Findings kept in a payload.  The full list is deduplicated first and the
# exact counts (`count`, `by_confidence`) are computed over it, so the cap only
# trims the rendered detail.
MAX_FINDINGS = 50

# Strings inspected by one scan.  The engine can return tens of thousands and
# every rule regexes each one, so the tail is dropped.
MAX_STRINGS_INSPECTED = capabilities.MAX_STRINGS_INSPECTED

# Sort rank per confidence; lower sorts first so import hits lead the list.
_CONFIDENCE_RANK = {
    capabilities.CONFIDENCE_HIGH: 0,
    capabilities.CONFIDENCE_MEDIUM: 1,
}


@dataclass(frozen=True)
class BehaviorRule:
    """One behavior rule: a label, a description and its matchers.

    ``imports`` are :class:`~reportal.capabilities.ImportRule` entries matched
    with the capabilities comparison; ``strings`` are case-insensitive regular
    expressions matched against a string entry's whole text.
    """

    name: str
    description: str
    imports: tuple[ImportRule, ...] = ()
    strings: tuple[re.Pattern[str], ...] = ()


def _regex(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


# String evidence.  A URL is scheme-anchored; an IPv4 literal validates every
# octet; a port is only accepted when labeled, since a bare number is too
# noisy to be evidence.  Filesystem strings are anchored on a drive letter or
# an UNC prefix and on a bounded set of file extensions.
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`\\{}\[\]|]+", re.IGNORECASE)
_IPV4 = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
)
_PORT = re.compile(r"\bport\s*[:=]?\s*\d{1,5}\b", re.IGNORECASE)
_DRIVE_PATH = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|*?]+")
_UNC_PATH = re.compile(r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+(?:\\[^\s\"'<>|*?]+)*")
_EXTENSION = re.compile(r"\.(?:exe|dll|sys|ini|cfg|dat|log|tmp|txt|bin)\b", re.IGNORECASE)


# The rule table, one tuple per domain.  Rules overlap on purpose: a process
# launch and a service start are different execution behaviors even when the
# same binary carries both.
BEHAVIOR_RULES: dict[str, tuple[BehaviorRule, ...]] = {
    DOMAIN_EXECUTION: (
        BehaviorRule(
            name="process-launch",
            description="Starts or spawns another process",
            imports=capabilities._prefix(
                "CreateProcess",
                "ShellExecute",
                "_spawn",
                "_exec",
                "posix_spawn",
            )
            + capabilities._exact(
                "WinExec",
                "system",
                "_system",
                "popen",
                "_popen",
                "execve",
                "execl",
                "execlp",
                "execvp",
                "fork",
                "vfork",
            ),
        ),
        BehaviorRule(
            name="service-control",
            description="Creates, starts or controls a service",
            imports=capabilities._prefix(
                "CreateService",
                "OpenSCManager",
                "StartService",
                "RegisterServiceCtrlHandler",
            ),
        ),
        BehaviorRule(
            name="iot-dropper",
            description="Carries IoT botnet staging markers",
            strings=_regex(
                r"\b(?:httpd|telnetd|dropbear)\b",
                r"/(?:data/local/tmp|root/dvr_gui|root/dvr_app|anko-app)/?",
                r"\b(?:ftpget|tftp|busybox)\b",
                r"main_(?:mipsel|mips|arm[567]?|x86(?:_64)?|ppc|m68k|sh4|spc)\b",
            ),
        ),
    ),
    DOMAIN_NETWORKING: (
        BehaviorRule(
            name="socket",
            description="Uses the socket API",
            imports=capabilities._prefix("WSA")
            + capabilities._exact(
                "socket",
                "connect",
                "bind",
                "listen",
                "accept",
                "send",
                "recv",
                "sendto",
                "recvfrom",
                "gethostbyname",
                "getaddrinfo",
            ),
        ),
        BehaviorRule(
            name="http-client",
            description="Speaks HTTP or downloads a URL",
            imports=capabilities._prefix(
                "WinHttp",
                "InternetOpen",
                "InternetConnect",
                "HttpOpenRequest",
                "HttpSendRequest",
                "URLDownloadToFile",
                "curl_easy_",
            ),
        ),
        BehaviorRule(
            name="url",
            description="Carries a URL literal",
            strings=(_URL,),
        ),
        BehaviorRule(
            name="ipv4",
            description="Carries an IPv4 literal",
            strings=(_IPV4,),
        ),
        BehaviorRule(
            name="port",
            description="Carries a labeled port literal",
            strings=(_PORT,),
        ),
        BehaviorRule(
            name="ddos-template",
            description="Carries a DDoS flood or amplification template literal",
            strings=_regex(
                r"Content-Length:\s*10485760",
                r"PRI \* HTTP/2\.0",
                r"M-SEARCH \* HTTP/1\.1",
                r"\bstats\r\n",
                r"port\s*11211\b",
            ),
        ),
    ),
    DOMAIN_FILESYSTEM: (
        BehaviorRule(
            name="file-io",
            description="Opens, reads, writes, deletes, moves or copies a file",
            imports=capabilities._prefix(
                "CreateFile",
                "ReadFile",
                "WriteFile",
                "DeleteFile",
                "MoveFile",
                "CopyFile",
            ),
        ),
        BehaviorRule(
            name="directory",
            description="Creates or removes a directory",
            imports=capabilities._prefix("CreateDirectory", "RemoveDirectory"),
        ),
        BehaviorRule(
            name="find-files",
            description="Enumerates files or directories",
            imports=capabilities._prefix("FindFirstFile", "FindNextFile"),
        ),
        BehaviorRule(
            name="temp-path",
            description="Resolves a temporary path",
            imports=capabilities._prefix("GetTempPath", "GetTempFileName"),
        ),
        BehaviorRule(
            name="shell-file-op",
            description="Runs a shell file operation",
            imports=capabilities._prefix("SHFileOperation"),
        ),
        BehaviorRule(
            name="posix-file",
            description="Uses the POSIX file API",
            imports=capabilities._exact(
                "open",
                "close",
                "read",
                "write",
                "lseek",
                "unlink",
                "rename",
                "remove",
                "opendir",
                "readdir",
                "closedir",
            ),
        ),
        BehaviorRule(
            name="drive-path",
            description="Carries a drive-letter path literal",
            strings=(_DRIVE_PATH,),
        ),
        BehaviorRule(
            name="unc-path",
            description="Carries a UNC path literal",
            strings=(_UNC_PATH,),
        ),
        BehaviorRule(
            name="file-extension",
            description="Carries a file-name extension literal",
            strings=(_EXTENSION,),
        ),
    ),
}


def _add(
    findings: dict[tuple[str, str], dict[str, Any]],
    key: tuple[str, str],
    *,
    kind: str,
    name: str,
    detail: str,
    confidence: str,
) -> None:
    """Record one match, counting a repeat of the same ``(name, detail)`` pair."""
    existing = findings.get(key)
    if existing is None:
        findings[key] = {
            "kind": kind,
            "name": name,
            "detail": detail,
            "confidence": confidence,
            "count": 1,
        }
        return
    existing["count"] += 1


def classify(
    domain: str, imports: Sequence[dict[str, Any]], strings: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    """Match *imports* and *strings* against *domain*'s rules.

    Returns ``{"findings", "count", "by_confidence"}``.  A finding is
    ``{"kind": "import"|"string", "name", "detail", "confidence", "count"}``,
    where an import hit carries the matched import name and the rule label as
    its detail, and a string hit the matched string text and the rule label.
    Findings deduplicate by ``(name, detail)``; the list sorts by confidence
    (import/high first), then name and rule label; ``count`` and
    ``by_confidence`` stay exact
    while the list itself is capped at :data:`MAX_FINDINGS`.

    Raises :class:`ValueError` for a domain outside :data:`BEHAVIOR_DOMAINS`.
    """
    rules = BEHAVIOR_RULES.get(domain)
    if rules is None:
        raise ValueError(f"unknown behavior domain: {domain}")

    findings: dict[tuple[str, str], dict[str, Any]] = {}
    for rule in rules:
        for entry in imports:
            name = capabilities._import_name(entry)
            if not name:
                continue
            if any(capabilities._import_matches(pattern, name) for pattern in rule.imports):
                _add(
                    findings,
                    (name.casefold(), rule.name),
                    kind="import",
                    name=name,
                    detail=rule.name,
                    confidence=capabilities.CONFIDENCE_HIGH,
                )
        for entry in strings:
            text = capabilities._string_text(entry)
            if not text:
                continue
            if any(pattern.search(text) for pattern in rule.strings):
                _add(
                    findings,
                    (text, rule.name),
                    kind="string",
                    name=text,
                    detail=rule.name,
                    confidence=capabilities.CONFIDENCE_MEDIUM,
                )

    ordered = sorted(
        findings.values(),
        key=lambda finding: (
            _CONFIDENCE_RANK[finding["confidence"]],
            finding["name"],
            finding["detail"],
        ),
    )
    by_confidence = {
        capabilities.CONFIDENCE_HIGH: sum(
            1 for finding in ordered if finding["confidence"] == capabilities.CONFIDENCE_HIGH
        ),
        capabilities.CONFIDENCE_MEDIUM: sum(
            1 for finding in ordered if finding["confidence"] == capabilities.CONFIDENCE_MEDIUM
        ),
    }
    return {
        "findings": ordered[:MAX_FINDINGS],
        "count": len(ordered),
        "by_confidence": by_confidence,
    }


def scan_domain(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    domain: str,
    engine: RebrewEngine | None = None,
    imports: Sequence[dict[str, Any]] | None = None,
    strings: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Scan one behavior *domain* of a binary and store the result.

    The binary's file is resolved from the stored row; *engine* (else the
    process-wide engine) supplies the two standalone engine calls.  *imports*
    and *strings* override the engine payloads outright, which is how tests
    keep the run hermetic.  Strings are capped at :data:`MAX_STRINGS_INSPECTED`.

    Raises :class:`ValueError` for an unknown domain, :class:`KeyError` for an
    unknown binary and :class:`FileNotFoundError` when its row has no file on
    disk; an engine failure propagates.  Returns ``{"binary_id", "domain",
    "findings", "count", "by_confidence"}``.
    """
    if domain not in BEHAVIOR_DOMAINS:
        raise ValueError(f"unknown behavior domain: {domain}")
    _binary, path = capabilities.require_binary_file(conn, binary_id)

    source: capabilities.CapabilityIO = engine or engines.get_engine()
    raw_imports, raw_strings = capabilities.load_imports_and_strings(
        path, source, imports=imports, strings=strings
    )
    result = classify(domain, raw_imports, raw_strings)
    payload = {"binary_id": binary_id, "domain": domain, **result}
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, DOMAIN_SCAN_KINDS[domain], payload)
    return payload

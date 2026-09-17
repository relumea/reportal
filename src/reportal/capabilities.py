"""Capability tagging: classify what a binary can do from its imports and strings.

The hosted RevEng.AI portal runs an agent that labels a binary's capabilities
(networking, crypto, file I/O, registry, process execution, and so on).
reportal reproduces that classification locally and deterministically: the
binary's import table and extracted strings are matched against the fixed rule
table in :data:`CAPABILITIES`, so a run needs no LLM and makes no network call.

Both engine calls the classifier consumes are standalone: ``rebrew imports``
and ``rebrew strings`` read the binary file alone, so a capabilities run needs
no rebrew project context.  A rule matches an import name by exact, prefix or
substring comparison and a string by a case-insensitive regular expression; an
import match (a concrete API family) yields ``high`` confidence, string-only
evidence ``medium``.  The result is stored as the ``capabilities`` scan.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from reportal import engines, store
from reportal.engines import RebrewEngine

# Confidence carried by a capability: an import match identifies a concrete API
# family, a string match only suggests intent.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"

# Import-name comparison a rule uses.  ``exact`` matches the whole name,
# ``prefix`` the leading run (``WSA*``), ``substring`` any occurrence.
ImportMode = Literal["exact", "prefix", "substring"]

IMPORT_EXACT: ImportMode = "exact"
IMPORT_PREFIX: ImportMode = "prefix"
IMPORT_SUBSTRING: ImportMode = "substring"

# Evidence entries kept per capability.  The list is a sample; ``evidence_count``
# always reports the exact number of distinct matches.
MAX_EVIDENCE_PER_CAPABILITY = 8

# Strings inspected by one run.  The engine can return tens of thousands and the
# classifier regexes every one, so the tail is dropped.
MAX_STRINGS_INSPECTED = 5000


@dataclass(frozen=True)
class ImportRule:
    """One import-name match: *mode* is :data:`IMPORT_EXACT`, prefix or substring."""

    mode: ImportMode
    value: str


@dataclass(frozen=True)
class Capability:
    """One capability category: a name, a description and its match rules."""

    name: str
    description: str
    imports: tuple[ImportRule, ...] = ()
    strings: tuple[re.Pattern[str], ...] = ()


def _exact(*values: str) -> tuple[ImportRule, ...]:
    return tuple(ImportRule(IMPORT_EXACT, value) for value in values)


def _prefix(*values: str) -> tuple[ImportRule, ...]:
    return tuple(ImportRule(IMPORT_PREFIX, value) for value in values)


def _substring(*values: str) -> tuple[ImportRule, ...]:
    return tuple(ImportRule(IMPORT_SUBSTRING, value) for value in values)


def _regex(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


# The rule table.  Win32/Winsock API families plus the string markers that carry
# the same intent (a URL, a Run key, a debugger name).  Categories overlap on
# purpose: persistence builds on registry writes, and a memory API is also an
# evasion indicator.
CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        name="networking",
        description="Opens or accepts network connections",
        imports=_prefix(
            "WSA",
            "WinHttp",
            "WinInet",
            "Internet",
            "Http",
            "Icmp",
            "Dns",
            "getaddrinfo",
            "gethostby",
        )
        + _exact(
            "connect",
            "recv",
            "send",
            "sendto",
            "recvfrom",
            "bind",
            "listen",
            "accept",
            "select",
            "htons",
            "ntohs",
            "inet_addr",
            "inet_ntoa",
            "URLDownloadToFile",
        )
        + _substring("socket"),
        strings=_regex(
            r"\bhttps?://",
            r"\bftp://",
            r"\b(?:GET|POST|PUT|DELETE|HEAD) \S* HTTP/",
        ),
    ),
    Capability(
        name="crypto",
        description="Uses cryptographic algorithms or APIs",
        imports=_prefix(
            "Crypt",
            "BCrypt",
            "NCrypt",
            "EVP_",
            "AES_",
            "DES_",
            "RC4_",
            "SHA1_",
            "SHA256_",
            "SHA512_",
            "MD5_",
            "RSA_",
            "SSL_",
        )
        + _exact(
            "RtlGenRandom",
            "SystemFunction036",
            "RtlEncryptMemory",
            "RtlDecryptMemory",
        ),
        strings=_regex(
            r"\b(?:AES|RSA|SHA-?(?:1|256|384|512)|MD5|RC4|3DES|DES|Blowfish|ChaCha20)\b"
        ),
    ),
    Capability(
        name="file-io",
        description="Reads or writes files",
        imports=_prefix(
            "CreateFile",
            "ReadFile",
            "WriteFile",
            "DeleteFile",
            "MoveFile",
            "CopyFile",
            "FindFirstFile",
            "FindNextFile",
            "GetFileAttributes",
            "SetFileAttributes",
            "GetFileSize",
            "GetFileTime",
            "SetFileTime",
            "GetTempPath",
            "GetTempFileName",
            "GetFullPathName",
            "CreateDirectory",
            "RemoveDirectory",
            "SetEndOfFile",
            "SHFileOperation",
        )
        + _exact(
            "OpenFile",
            "fopen",
            "fclose",
            "fread",
            "fwrite",
            "fseek",
            "ftell",
            "rewind",
            "fflush",
            "_open",
            "_close",
            "_read",
            "_write",
            "remove",
            "rename",
            "unlink",
            "chmod",
            "access",
        ),
        strings=_regex(r"[A-Za-z]:\\", r"\.(?:exe|dll|sys|ini|cfg|dat|log|tmp|txt|bin)\b"),
    ),
    Capability(
        name="registry",
        description="Reads or writes the Windows registry",
        imports=_prefix(
            "RegOpenKey",
            "RegCreateKey",
            "RegSetValue",
            "RegQueryValue",
            "RegQueryInfoKey",
            "RegDeleteKey",
            "RegDeleteValue",
            "RegEnumKey",
            "RegEnumValue",
            "RegCloseKey",
            "RegGetValue",
            "RegSaveKey",
            "RegLoadKey",
            "RegFlushKey",
            "RegConnectRegistry",
            "SHDeleteKey",
        ),
        strings=_regex(
            r"\bHKEY_LOCAL_MACHINE\b",
            r"\bHKEY_CURRENT_USER\b",
            r"\bHKLM\b",
            r"\bHKCU\b",
            r"Software\\Microsoft",
        ),
    ),
    Capability(
        name="process-execution",
        description="Starts or controls other processes",
        imports=_prefix(
            "CreateProcess",
            "ShellExecute",
            "OpenProcess",
            "TerminateProcess",
            "CreateRemoteThread",
            "NtCreateProcess",
            "ZwCreateProcess",
            "RtlCreateUserProcess",
            "_spawn",
            "_exec",
            "posix_spawn",
        )
        + _exact(
            "system",
            "_system",
            "popen",
            "_popen",
            "WinExec",
            "execve",
            "execl",
            "execlp",
            "execvp",
            "fork",
            "vfork",
        ),
        strings=_regex(
            r"\bcmd\.exe\b",
            r"\bpowershell(?:\.exe)?\b",
            r"\bwscript\.exe\b",
            r"\bcscript\.exe\b",
            r"\bmshta\.exe\b",
        ),
    ),
    Capability(
        name="threading",
        description="Creates or manages threads",
        imports=_prefix(
            "CreateThread",
            "CreateRemoteThread",
            "_beginthread",
            "_beginthreadex",
            "ResumeThread",
            "SuspendThread",
            "SetThread",
            "GetThread",
            "ExitThread",
            "TerminateThread",
            "OpenThread",
            "GetCurrentThread",
            "SwitchToThread",
            "TlsAlloc",
            "pthread_",
        )
        + _exact("pthread_create", "pthread_join", "pthread_exit"),
    ),
    Capability(
        name="memory",
        description="Allocates or changes executable memory",
        imports=_prefix(
            "VirtualAlloc",
            "VirtualProtect",
            "VirtualFree",
            "VirtualQuery",
            "HeapAlloc",
            "HeapCreate",
            "HeapFree",
            "HeapReAlloc",
            "HeapSize",
            "GlobalAlloc",
            "GlobalFree",
            "GlobalLock",
            "LocalAlloc",
            "LocalFree",
            "MapViewOfFile",
            "UnmapViewOfFile",
            "RtlMoveMemory",
            "RtlZeroMemory",
            "RtlFillMemory",
            "IsBadReadPtr",
            "IsBadWritePtr",
            "mprotect",
            "mmap",
        )
        + _exact("malloc", "calloc", "realloc", "free"),
    ),
    Capability(
        name="dynamic-loading",
        description="Loads libraries and resolves symbols at runtime",
        imports=_prefix(
            "LoadLibrary",
            "GetModuleHandle",
            "LoadModule",
            "LdrLoadDll",
            "LdrGetProcedureAddress",
            "dlopen",
            "dlsym",
        )
        + _exact("GetProcAddress", "FreeLibrary", "dlclose"),
    ),
    Capability(
        name="anti-debug",
        description="Detects or interferes with a debugger",
        imports=_prefix(
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
            "NtSetInformationThread",
            "NtQuerySystemInformation",
            "NtQueryObject",
            "OutputDebugString",
            "DebugBreak",
            "RtlCheckStack",
        )
        + _exact("IsDebuggerPresent", "DebugBreak", "OutputDebugString"),
        strings=_regex(
            r"\bOllyDbg\b",
            r"\bx64dbg\b",
            r"\bWinDbg\b",
            r"\bVirtualBox\b",
            r"\bVMware\b",
            r"\bVBox\b",
            r"\bProcmon\b",
            r"\bwireshark\b",
            r"\bSandboxie\b",
        ),
    ),
    Capability(
        name="persistence",
        description="Installs itself to run again later",
        imports=_prefix(
            "RegSetValue",
            "RegCreateKey",
            "CreateService",
            "OpenSCManager",
            "ChangeServiceConfig",
            "StartService",
            "WritePrivateProfileString",
            "SHSetValue",
        ),
        strings=_regex(
            r"\bCurrentVersion\\Run",
            r"\bSoftware\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"\bRunOnce\b",
            r"\bStartup\b",
            r"\.lnk\b",
        ),
    ),
    Capability(
        name="synchronization",
        description="Coordinates concurrent execution",
        imports=_prefix(
            "CreateMutex",
            "OpenMutex",
            "CreateEvent",
            "OpenEvent",
            "SetEvent",
            "ResetEvent",
            "PulseEvent",
            "WaitForSingleObject",
            "WaitForMultipleObjects",
            "CreateSemaphore",
            "OpenSemaphore",
            "ReleaseMutex",
            "ReleaseSemaphore",
            "EnterCriticalSection",
            "LeaveCriticalSection",
            "InitializeCriticalSection",
            "DeleteCriticalSection",
            "TryEnterCriticalSection",
            "CreateWaitableTimer",
            "SetWaitableTimer",
            "Interlocked",
            "pthread_mutex",
            "pthread_cond",
            "pthread_rwlock",
            "sem_",
        )
        + _exact("sem_wait", "sem_post"),
    ),
    Capability(
        name="compression",
        description="Compresses or decompresses data",
        imports=_prefix(
            "inflate",
            "deflate",
            "uncompress",
            "RtlDecompressBuffer",
            "RtlCompressBuffer",
            "LZOpenFile",
            "LZInit",
            "LZCopy",
            "LZRead",
            "LZClose",
            "BZ2_",
            "lzma_",
            "ZSTD_",
            "gzopen",
            "gzread",
            "gzwrite",
            "gzclose",
        )
        + _exact("compress", "uncompress"),
        strings=_regex(
            r"\bzlib\b",
            r"\bgzip\b",
            r"\bbzip2\b",
            r"\bLZMA\b",
            r"\.zip\b",
            r"\.gz\b",
            r"\.rar\b",
            r"\.7z\b",
        ),
    ),
    Capability(
        name="ui",
        description="Creates windows, dialogs or message boxes",
        imports=_prefix(
            "MessageBox",
            "CreateWindow",
            "RegisterClass",
            "RegisterWindowMessage",
            "DialogBox",
            "CreateDialog",
            "ShowWindow",
            "GetMessage",
            "SendMessage",
            "PostMessage",
            "FindWindow",
            "SetWindowText",
            "GetWindowText",
            "GetDlgItem",
            "SetDlgItem",
            "LoadMenu",
            "LoadString",
            "LoadIcon",
            "LoadCursor",
            "LoadBitmap",
            "DefWindowProc",
            "SetWindowLong",
            "GetWindowLong",
            "EnableWindow",
            "SetForegroundWindow",
            "SetWindowPos",
            "TranslateMessage",
            "DispatchMessage",
            "BeginPaint",
            "EndPaint",
            "GetDC",
            "ReleaseDC",
            "GetClientRect",
            "InvalidateRect",
            "UpdateWindow",
            "CreateMenu",
            "AppendMenu",
            "TrackPopupMenu",
            "Shell_NotifyIcon",
            "GetSystemMetrics",
            "SetTimer",
            "KillTimer",
        )
        + _exact("WinMain"),
    ),
    Capability(
        name="console",
        description="Reads or writes a console",
        imports=_prefix(
            "AllocConsole",
            "FreeConsole",
            "GetStdHandle",
            "SetStdHandle",
            "WriteConsole",
            "ReadConsole",
            "GetConsoleMode",
            "SetConsoleMode",
            "SetConsoleTitle",
            "SetConsoleCursorPosition",
            "GetConsoleScreenBufferInfo",
            "GetConsoleWindow",
        )
        + _exact(
            "printf",
            "fprintf",
            "sprintf",
            "snprintf",
            "wprintf",
            "puts",
            "fputs",
            "putchar",
            "putc",
            "scanf",
            "fscanf",
            "sscanf",
            "wscanf",
            "getchar",
            "fgets",
            "gets",
            "_printf",
            "_puts",
            "cout",
            "cerr",
            "cin",
            "stdin",
            "stdout",
            "stderr",
        ),
    ),
)


class StringsIO(Protocol):
    """The engine surface a strings-only scan needs; ``rebrew strings`` is standalone."""

    def strings(self, binary: str | Path) -> dict[str, Any]: ...


class CapabilityIO(StringsIO, Protocol):
    """The engine surface a capabilities run needs; both calls are standalone."""

    def imports(self, binary: str | Path) -> dict[str, Any]: ...


def _import_name(entry: dict[str, Any]) -> str:
    """Return an import entry's function name, or "" when it carries none."""
    return str(entry.get("name") or "").strip()


def _string_text(entry: dict[str, Any]) -> str:
    """Return a string entry's text, or "" when it carries none."""
    return str(entry.get("text") or "")


def _import_matches(rule: ImportRule, name: str) -> bool:
    """True when *name* matches *rule*, case-insensitively."""
    candidate = name.casefold()
    value = rule.value.casefold()
    if rule.mode == IMPORT_EXACT:
        return candidate == value
    if rule.mode == IMPORT_PREFIX:
        return candidate.startswith(value)
    if rule.mode == IMPORT_SUBSTRING:
        return value in candidate
    raise ValueError(f"unknown import match mode: {rule.mode}")


def classify(
    imports: Sequence[dict[str, Any]], strings: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Classify *imports* and *strings* into capability categories.

    Returns one entry per matched category with ``name``, ``description``,
    ``confidence``, ``evidence`` and ``evidence_count``.  Confidence is
    :data:`CONFIDENCE_HIGH` when an import rule matched and
    :data:`CONFIDENCE_MEDIUM` for string-only evidence.  Evidence entries are
    distinct ``(kind, value)`` pairs, the list is capped at
    :data:`MAX_EVIDENCE_PER_CAPABILITY` while ``evidence_count`` stays exact.
    Results sort by ``evidence_count`` descending, then name.
    """
    results: list[dict[str, Any]] = []
    for rule in CAPABILITIES:
        evidence: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        matched_import = False
        for entry in imports:
            name = _import_name(entry)
            if not name:
                continue
            if any(_import_matches(pattern, name) for pattern in rule.imports):
                matched_import = True
                marker = ("import", name.casefold())
                if marker not in seen:
                    seen.add(marker)
                    evidence.append({"kind": "import", "value": name})
        for entry in strings:
            text = _string_text(entry)
            if not text:
                continue
            if any(pattern.search(text) for pattern in rule.strings):
                marker = ("string", text)
                if marker not in seen:
                    seen.add(marker)
                    evidence.append({"kind": "string", "value": text})
        if not evidence:
            continue
        results.append(
            {
                "name": rule.name,
                "description": rule.description,
                "confidence": CONFIDENCE_HIGH if matched_import else CONFIDENCE_MEDIUM,
                "evidence": evidence[:MAX_EVIDENCE_PER_CAPABILITY],
                "evidence_count": len(evidence),
            }
        )
    results.sort(key=lambda entry: (-entry["evidence_count"], entry["name"]))
    return results


def _entries(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return the dict entries under *payload[key]*, ignoring any other shape."""
    raw = payload.get(key)
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def require_binary_file(conn: sqlite3.Connection, binary_id: int) -> tuple[dict[str, Any], Path]:
    """Return ``(binary_row, path)`` for a stored binary with bytes on disk.

    Raises :class:`KeyError` for an unknown id and :class:`FileNotFoundError`
    when the row's path is empty or no longer holds a file.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise KeyError(f"no binary with id {binary_id}")
    path = Path(str(binary["path"]))
    if not path.is_file():
        raise FileNotFoundError(f"binary {binary_id} has no file at {path}")
    return binary, path


def load_imports_and_strings(
    path: Path,
    source: CapabilityIO,
    *,
    imports: Sequence[dict[str, Any]] | None = None,
    strings: Sequence[dict[str, Any]] | None = None,
    max_strings: int = MAX_STRINGS_INSPECTED,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve import and string entries from overrides or *source*.

    An override of either side is taken as-is; otherwise the engine payload is
    parsed through :func:`_entries`.  Strings are truncated to *max_strings*.
    """
    raw_imports = (
        list(imports) if imports is not None else _entries(source.imports(path), "imports")
    )
    raw_strings = (
        list(strings) if strings is not None else _entries(source.strings(path), "strings")
    )
    return raw_imports, raw_strings[:max_strings]


def load_strings(
    path: Path,
    source: StringsIO,
    *,
    strings: Sequence[dict[str, Any]] | None = None,
    max_strings: int = MAX_STRINGS_INSPECTED,
) -> list[dict[str, Any]]:
    """Resolve string entries from an override or *source*, capped at *max_strings*."""
    raw_strings = (
        list(strings) if strings is not None else _entries(source.strings(path), "strings")
    )
    return raw_strings[:max_strings]


def run_capabilities(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: RebrewEngine | None = None,
    imports: Sequence[dict[str, Any]] | None = None,
    strings: Sequence[dict[str, Any]] | None = None,
    io: CapabilityIO | None = None,
) -> dict[str, Any]:
    """Classify a binary and store the result as the ``capabilities`` scan.

    The binary's file is resolved from the stored row; *io* (else *engine*, else
    the process-wide engine) supplies the two standalone engine calls.  *imports*
    and *strings* override the engine payloads outright, which is how tests keep
    the run hermetic.  Strings are capped at :data:`MAX_STRINGS_INSPECTED`.

    Raises :class:`KeyError` for an unknown binary and
    :class:`FileNotFoundError` when its row has no file on disk; an engine
    failure propagates.  Returns ``{"binary_id", "capabilities", "count"}``.
    """
    _binary, path = require_binary_file(conn, binary_id)
    source: CapabilityIO = io or engine or engines.get_engine()
    raw_imports, raw_strings = load_imports_and_strings(
        path, source, imports=imports, strings=strings
    )
    found = classify(raw_imports, raw_strings)
    payload = {"binary_id": binary_id, "capabilities": found, "count": len(found)}
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, store.SCAN_KIND_CAPABILITIES, payload)
    return payload

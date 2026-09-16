"""Shared fixtures for reportal tests: an isolated portal DB and an ASGI client."""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import sqlite3
from collections.abc import Iterator, Sequence
from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

from reportal import auto_workers, engines, jobs, llm, store
from reportal._paths import DB_ENV
from reportal.webapp import app

# Engine payloads a fake returns.  The values match the real rebrew output for
# a small PE fixture, so assertions read like the live CLI contract.
FINGERPRINT: dict[str, Any] = {
    "md5": "e6ff7c87f33650825f3a36454f4074fd",
    "sha1": "85343b66c57ecf075a75ea275d5ed1dc5080b794",
    "sha256": "bda21f387f7d53bd188a1fd91179efbd688723d18c26e78465c2ced8fb75463f",
    "crc32": "1f3f6484",
    "format": "pe",
    "arch": "x86_32",
    "size": 1024,
    "imphash": "27abfd9cfda7519d5efb3f08a2a4f3ce",
    "rich_header_hash": None,
    "section_entropies": [],
}

IMPORTS: dict[str, Any] = {
    "binary": "demo.exe",
    "imports": [{"dll": "KERNEL32.dll", "name": "GetTickCount", "iat_va": "0x0040104c"}],
    "stubs": [],
}

# Import stubs a fake engine reports, shaped like the live `rebrew imports`
# payload (a hex VA and the imported name).  `import-rebrew` ingests them as
# THUNK function rows.
IMPORT_STUBS: list[dict[str, str]] = [
    {"va": "0x010030c6", "name": "ChooseFontW"},
    {"va": "0x010030cc", "name": "ReplaceTextW"},
]

STRINGS: dict[str, Any] = {"binary": "demo.exe", "count": 1, "strings": ["hello"]}

# Engine payload for `rebrew decompile --json`; the shape matches the live
# contract (va/backend/named/applied/code).
DECOMPILATION: dict[str, Any] = {
    "va": "0x1000",
    "backend": "kuna",
    "named": False,
    "applied": [],
    "code": "void sub_1000(void)\n{\n  return;\n}\n",
}

# Engine payload for `rebrew analyze --json`, trimmed to the sections reportal
# surfaces (meta, toolchain and counts).
ANALYSIS: dict[str, Any] = {
    "binary": "demo.exe",
    "meta": {
        "format": "pe",
        "image_base": 0x400000,
        "text_va": 0x401000,
        "text_size": 4096,
        "sections": [{"name": ".text", "va": "0x00401000", "size": 4096}],
    },
    "toolchain": {"family": "msvc", "version_hint": "MSVC 6.0", "confidence": "high"},
    "strings": {"count": 3, "top": ["hello"]},
    "imports": {"count": 2, "dlls": ["KERNEL32.dll"]},
    "references": {"total": 5},
    "functions": {"total": 2, "covered": 1},
}

# Engine payload for `rebrew report --json`; `out` is filled per call.
REPORT: dict[str, Any] = {
    "out": "",
    "pages": ["index.html", "strings.html"],
    "summary": {
        "total_functions": 2,
        "covered_functions": 2,
        "coverage_pct": 100.0,
        "matched_pct": 50.0,
        "byte_coverage_pct": 25.0,
        "status_counts": {"EXACT": 1, "STUB": 1},
    },
}

# Engine payload for `rebrew xrefs <va> --json`; two callers of 0x1000.
XREFS: dict[str, Any] = {
    "target": 0x1000,
    "import_name": None,
    "count": 2,
    "refs": [
        {"kind": "call", "from_va": 0x1100, "instruction": "call 0x1000"},
        {"kind": "jmp", "from_va": 0x1200, "instruction": "jmp 0x1000"},
    ],
}

# Engine payload for `rebrew describe <va> --json`, shaped like the live
# contract: one direct caller, one direct callee, one indirect (import-slot)
# callee with no resolved name, and three globals (a data read, a data write
# and an address load).  The addresses land in the conftest PE_INFO `.data`
# section (image base 0x400000 + RVA 0x8000).
DESCRIBE: dict[str, Any] = {
    "va": 0x1000,
    "name": "sub_1000",
    "status": "STUB",
    "size": 32,
    "cflags": "",
    "pattern": None,
    "convention": "cdecl",
    "callers": [{"from_va": 0x1100, "name": "caller"}],
    "callees": [
        {"to_va": 0x1200, "name": "helper", "kind": "call"},
        {"to_va": 0x40104C, "name": None, "kind": "iat_call"},
    ],
    "strings": [],
    "globals": [
        {"va": 0x408000, "kind": "mov_mem"},
        {"va": 0x408004, "kind": "mov_mem_store"},
        {"va": 0x408008, "kind": "lea"},
    ],
    "imports": [],
}

# Engine payload for `rebrew recover-structs --json`, one recovered typedef.
STRUCTS: dict[str, Any] = {
    "decompiled": 12,
    "skipped": 1,
    "structs": [
        {
            "name": "PlayerInfo",
            "anonymous": False,
            "semantic": True,
            "var": "player",
            "va": 0x1000,
            "new": True,
            "definition": "typedef struct PlayerInfo_s {\n\tint field_0;\n} PlayerInfo;\n",
            "offsets": ["0x0"],
            "evidence": 1,
            "functions": 1,
        }
    ],
    "applied": None,
}

# Engine payload for `rebrew crypto-scan --json`, one constant and one API
# finding, matching the live contract (findings/count/by_confidence).
CRYPTO: dict[str, Any] = {
    "binary": "demo.exe",
    "findings": [
        {
            "kind": "constant",
            "name": "AES S-box",
            "va": 0x4F5F00,
            "section": ".rodata",
            "confidence": "high",
        },
        {
            "kind": "import",
            "name": "CryptEncrypt",
            "detail": "advapi32.dll",
            "va": 0x401020,
            "section": ".idata",
            "confidence": "medium",
        },
    ],
    "count": 2,
    "by_confidence": {"high": 1, "medium": 1},
}


# Engine payload for `rebrew pe-info --json`, shaped like the live contract for
# a small PE (identity, one executable and one writable section, security flags,
# Authenticode, debug and Rich-header blocks, presence and counts).
PE_INFO: dict[str, Any] = {
    "format": "pe",
    "arch": "x86_32",
    "bits": 32,
    "image_base": 0x400000,
    "entry_point": 0x401000,
    "subsystem": "WINDOWS_GUI",
    "timestamp": 938894716,
    "timestamp_iso": "1999-10-02T20:05:16Z",
    "checksum": 59572,
    "size": 50960,
    "sections": [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 26058,
            "raw_size": 26112,
            "raw_offset": 1536,
            "read": True,
            "write": False,
            "execute": True,
        },
        {
            "name": ".data",
            "virtual_address": 0x8000,
            "virtual_size": 6468,
            "raw_size": 1536,
            "raw_offset": 27648,
            "read": True,
            "write": True,
            "execute": False,
        },
    ],
    "security_flags": {
        "dll_characteristics": 0x8000,
        "aslr": False,
        "nx": False,
        "cfg": False,
        "gs": False,
        "safe_seh": False,
        "seh": True,
        "high_entropy_va": False,
        "force_integrity": False,
        "isolation": True,
        "certificate_table": False,
    },
    "flags_summary": ["SEH", "Isolation"],
    "authenticode": {"present": False, "signature_count": 0, "signers": []},
    "debug": [{"type": "MISC"}],
    "rich_header": {
        "present": True,
        "key": 1326957964,
        "entries": [{"id": 1, "build_id": 0, "count": 164}],
    },
    "presence": {
        "tls_directory": False,
        "load_config": False,
        "resources": True,
        "relocations": False,
        "exports": False,
        "imports": True,
    },
    "counts": {"exports": 0, "imports": 183, "import_dlls": 8, "relocations": 0},
}


# Engine payload for `rebrew security-scan --json`, one high and one low
# finding, matching the live contract (findings/count/by_severity).
SECURITY: dict[str, Any] = {
    "root": "/projects/notepad-rebrew",
    "files_scanned": 70,
    "findings": [
        {
            "rule": "unbounded-copy",
            "cwe": "CWE-120",
            "severity": "high",
            "confidence": "high",
            "file": "AddDefaultExtension.c",
            "line": 21,
            "function": "AddDefaultExtension",
            "snippet": "lstrcatW(lpPath, ...)",
            "message": "unbounded string copy",
        },
        {
            "rule": "unchecked-memcpy",
            "cwe": "CWE-787",
            "severity": "low",
            "confidence": "low",
            "file": "Files.c",
            "line": 5,
            "function": "Files",
            "snippet": "memcpy(dst, src, n)",
            "message": "unchecked memcpy size",
        },
    ],
    "count": 2,
    "by_severity": {"high": 1, "medium": 0, "low": 1},
}


# Engine payload for `rebrew identify-library --dry-run --json`, two IAT
# import candidates whose VAs match the functions the tests seed.
IDENTIFY: dict[str, Any] = {
    "sigs_written": 0,
    "identified": 2,
    "already_annotated": 0,
    "to_write": 2,
    "written": 0,
    "candidates": [
        {
            "va": "0x1000",
            "name": "ChooseFontW",
            "module": "COMDLG32",
            "kind": "import",
            "confidence": 0.3,
        },
        {
            "va": "0x2000",
            "name": "GetOpenFileNameW",
            "module": "COMDLG32",
            "kind": "import",
            "confidence": 0.3,
        },
    ],
}


class FakeEngine(engines.RebrewEngine):
    """Typed engine stub: fixed payloads and a call log, never an engine call.

    ``available`` is pinned True so a test using the stub never touches the
    installed rebrew package.
    """

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []
        self.xrefs_args: tuple[str, int, tuple[str, ...]] = ("", 0, ())
        self.describe_args: tuple[str, int] = ("", 0)
        self.structs_args: tuple[str, str, int] = ("", "", 0)
        self.security_scan_args: tuple[str, str] = ("", "")
        self.identify_arg = ""
        # The paths the stub reports as LZEXE-packed, and the bytes its rebuild
        # writes, so an unpack test drives both packers without a tool.
        self.lzexe_versions: dict[str, int] = {}
        self.unpack_bytes = b"MZ" + b"\x00" * 62

    def available(self) -> bool:
        return True

    @property
    def origin(self) -> str | None:
        return "/fake/bin/rebrew"

    def fingerprint(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("fingerprint")
        return dict(FINGERPRINT)

    def imports(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("imports")
        return {
            **IMPORTS,
            "binary": str(binary),
            "stubs": [dict(stub) for stub in IMPORT_STUBS],
        }

    def strings(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("strings")
        return {**STRINGS, "binary": str(binary)}

    def analyze(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("analyze")
        return {**ANALYSIS, "binary": str(binary)}

    def report(self, project_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
        self.calls.append("report")
        return {**REPORT, "out": str(output_dir)}

    def disassemble(self, project_dir: str | Path, va: int, size: int, fmt: str = "nasm") -> str:
        self.calls.append("disassemble")
        return f"bits 32\norg 0x{va:x}\n\nfunc_{va:x}:\n"

    def decompile(
        self,
        project_dir: str | Path,
        va: int,
        decompiler: str = engines.DEFAULT_DECOMPILER_BACKEND,
        named: bool = False,
    ) -> dict[str, Any]:
        self.calls.append("decompile")
        return {**DECOMPILATION, "va": hex(va), "backend": decompiler, "named": named}

    def xrefs(self, project_dir: str | Path, va: int, kinds: Sequence[str] = ()) -> dict[str, Any]:
        self.calls.append("xrefs")
        self.xrefs_args = (str(project_dir), va, tuple(kinds))
        refs = [ref for ref in XREFS["refs"] if not kinds or ref["kind"] in kinds]
        return {**XREFS, "count": len(refs), "refs": refs}

    def describe(self, project_dir: str | Path, va: int) -> dict[str, Any]:
        self.calls.append("describe")
        self.describe_args = (str(project_dir), va)
        return {**DESCRIBE, "va": va}

    def structs(
        self,
        project_dir: str | Path,
        *,
        decompiler: str = engines.DEFAULT_DECOMPILER_BACKEND,
        limit: int = 0,
    ) -> dict[str, Any]:
        self.calls.append("structs")
        self.structs_args = (str(project_dir), decompiler, limit)
        return dict(STRUCTS)

    def crypto_scan(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("crypto_scan")
        return {**CRYPTO, "binary": str(binary)}

    def pe_info(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("pe_info")
        return dict(PE_INFO)

    def security_scan(
        self,
        project_dir: str | Path,
        min_severity: str = engines.DEFAULT_SECURITY_MIN_SEVERITY,
    ) -> dict[str, Any]:
        self.calls.append("security_scan")
        self.security_scan_args = (str(project_dir), min_severity)
        return {**SECURITY, "root": str(project_dir)}

    def identify_library(self, project_dir: str | Path) -> dict[str, Any]:
        self.calls.append("identify_library")
        self.identify_arg = str(project_dir)
        return {**IDENTIFY, "candidates": [dict(candidate) for candidate in IDENTIFY["candidates"]]}

    def lzexe_version(self, binary: str | Path) -> int | None:
        self.calls.append("lzexe_version")
        return self.lzexe_versions.get(str(binary))

    def unpack_lzexe(self, binary: str | Path, output: str | Path) -> dict[str, Any]:
        self.calls.append("unpack_lzexe")
        target = Path(output)
        target.write_bytes(self.unpack_bytes)
        return {
            "version": self.lzexe_versions.get(str(binary), 91),
            "image_size": len(self.unpack_bytes),
            "file_size": len(self.unpack_bytes),
        }


@pytest.fixture(autouse=True)
def _no_job_pool() -> Iterator[None]:
    """Keep the job pool out of the tests: a thread picking a job up mid-assert is a race.

    The environment is patched with a local :class:`pytest.MonkeyPatch` rather
    than the ``monkeypatch`` fixture on purpose: requesting that fixture here
    would set it up before every test module's own autouse fixtures and tear it
    down after them, and ``tests/test_components.py`` relies on the opposite
    order (its entry-point patch has to be undone before the registry is
    refreshed again).
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv(jobs.POOL_ENV, "0")
        jobs.stop_worker()
        yield
    jobs.stop_worker()


@pytest.fixture(autouse=True)
def _isolate_engine() -> Iterator[None]:
    """Leave no engine installed between tests, whatever a test injected."""
    engines.set_engine(None)
    yield
    engines.set_engine(None)


# Assistant text a fake LLM returns per artifact kind.  The shapes match the
# prompts in `reportal.llm`, so assertions read like a real response.
AI_SUMMARY_RESPONSE = '{"summary": "Reads a file into a buffer and returns its length."}'
AI_COMMENTS_RESPONSE = (
    '[{"line": 3, "comment": "open the target file"},'
    ' {"line": 4, "comment": "read the whole file"}]'
)
AI_TYPES_RESPONSE = (
    '[{"name": "path", "kind": "parameter", "type": "const char *", "confidence": 0.9},'
    ' {"name": "result", "kind": "return", "type": "int", "confidence": 0.6}]'
)
AI_REWRITE_RESPONSE = '{"code": "int read_file(const char *path)\\n{\\n  return 0;\\n}\\n"}'
# Two renames over the decompilation the pipeline seeds, so an apply has
# something it can actually rewrite: `sub_1000` is the stored function name.
AI_RENAMES_RESPONSE = (
    '[{"from": "sub_1000", "to": "read_file", "kind": "function",'
    ' "reason": "reads a file", "confidence": 0.9},'
    ' {"from": "v1", "to": "length", "kind": "variable",'
    ' "reason": "holds a length", "confidence": 0.7}]'
)


class FakeLlmClient(llm.LlmClient):
    """Typed LLM stub: a canned response and a call log, never a network call."""

    def __init__(self, response: str = AI_SUMMARY_RESPONSE, model: str = "fake-model") -> None:
        super().__init__(llm.LlmConfig(endpoint="http://127.0.0.1:9/v1", model=model))
        self.response = response
        self.calls: list[list[dict[str, str]]] = []
        self.temperatures: list[float] = []

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = llm.DEFAULT_TEMPERATURE,
        json_object: bool = False,
    ) -> str:
        self.calls.append(messages)
        self.temperatures.append(temperature)
        return self.response


class FailingLlmClient(llm.LlmClient):
    """Typed LLM stub whose request always fails, never a network call."""

    def __init__(self, message: str = "model exploded") -> None:
        super().__init__(llm.LlmConfig(endpoint="http://127.0.0.1:9/v1", model="fake-model"))
        self.message = message

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = llm.DEFAULT_TEMPERATURE,
        json_object: bool = False,
    ) -> str:
        raise llm.LlmError(self.message)


@pytest.fixture(autouse=True)
def _isolate_llm() -> Iterator[None]:
    """Leave no LLM client installed between tests, whatever a test injected."""
    llm.set_client(None)
    yield
    llm.set_client(None)


@pytest.fixture(autouse=True)
def _isolate_auto_workers() -> Iterator[None]:
    """Leave only the built-in auto workers registered between tests."""
    auto_workers.refresh_workers()
    yield
    auto_workers.refresh_workers()


@pytest.fixture()
def fake_llm() -> FakeLlmClient:
    """A fake LLM client installed process-wide for one test."""
    client = FakeLlmClient()
    llm.set_client(client)
    return client


@pytest.fixture()
def fake_engine() -> FakeEngine:
    """A fake rebrew engine installed process-wide for one test."""
    engine = FakeEngine()
    engines.set_engine(engine)
    return engine


@pytest.fixture()
def portal_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point reportal at a fresh database in *tmp_path* and create the schema."""
    path = tmp_path / "reportal.db"
    monkeypatch.setenv(DB_ENV, str(path))
    store.init_db(path)
    return path


@pytest.fixture()
def conn(portal_db: Path) -> Iterator[sqlite3.Connection]:
    """A read-write connection to the isolated portal database."""
    with contextlib.closing(store.connect(portal_db)) as connection:
        yield connection


class ResponseHeaders(dict[str, str]):
    """Response headers looked up case-insensitively.

    ASGI carries header names lowercased; the WSGI client these tests were
    written against preserved the server's casing, so a lookup by the name in
    the reportal contract (``Content-Type``) has to keep working.
    """

    def __init__(self, items: list[tuple[str, str]]) -> None:
        super().__init__(items)
        self._lower = {key.lower(): value for key, value in items}

    def __getitem__(self, key: str) -> str:
        return self._lower[key.lower()]

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key.lower() in self._lower

    def get(self, key: str, default: Any = None) -> Any:
        return self._lower.get(key.lower(), default)


def _asgi_call(
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str] | None,
    host: str,
) -> tuple[str, ResponseHeaders, list[bytes]]:
    """Run one request through the ASGI application and collect its response."""
    url_path, _, query = path.partition("?")
    request_headers = {"host": host}
    for key, value in (headers or {}).items():
        request_headers[key.lower()] = value
    # Always declared, as the WSGI client these tests were written against did:
    # Bottle reads a missing Content-Length as -1, which the optional-body
    # routes distinguish from an empty body.
    request_headers.setdefault("content-length", str(len(body)))
    raw_headers = [
        (key.encode("latin-1"), value.encode("latin-1")) for key, value in request_headers.items()
    ]
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": url_path,
        "raw_path": url_path.encode("utf-8"),
        "query_string": query.encode("utf-8"),
        "root_path": "",
        "headers": raw_headers,
        "client": ("127.0.0.1", 34567),
        "server": (host, 80),
    }
    captured: dict[str, Any] = {"status": 0, "headers": ResponseHeaders([])}
    chunks: list[bytes] = []
    delivered = False
    # A streaming response listens for a client disconnect while it produces
    # its body and cancels the stream when it sees one, so the disconnect is
    # only reported once the response is complete.
    finished = asyncio.Event()

    async def receive() -> Any:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        await finished.wait()
        return {"type": "http.disconnect"}

    async def send(message: Any) -> None:
        if message["type"] == "http.response.start":
            captured["status"] = int(message["status"])
            captured["headers"] = ResponseHeaders(
                [
                    (key.decode("latin-1"), value.decode("latin-1"))
                    for key, value in message.get("headers", [])
                ]
            )
        elif message["type"] == "http.response.body":
            if message.get("body"):
                chunks.append(message["body"])
            if not message.get("more_body", False):
                finished.set()

    async def run() -> None:
        await app(scope, receive, send)

    try:
        asyncio.run(run())
    except Exception:
        # Starlette's 500 middleware sends the response and then re-raises so
        # the server can log it; the response already captured is the answer.
        if not captured["status"]:
            raise
    status = int(captured["status"])
    try:
        reason = HTTPStatus(status).phrase
    except ValueError:
        reason = ""
    return f"{status} {reason}".strip(), captured["headers"], chunks


def on_request(
    method: str,
    path: str,
    *,
    body: bytes | str = b"",
    headers: dict[str, str] | None = None,
    host: str = "127.0.0.1",
) -> tuple[str, ResponseHeaders, list[bytes]]:
    """Issue a request against the app; returns (status, headers, chunks)."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    return _asgi_call(method, path, body, headers, host)


def wsgi_request(
    method: str,
    path: str,
    *,
    body: bytes | str = b"",
    headers: dict[str, str] | None = None,
    host: str = "127.0.0.1",
) -> tuple[str, ResponseHeaders, bytes]:
    """Issue a request against the app; returns (status, headers, body)."""
    status, response_headers, chunks = on_request(
        method, path, body=body, headers=headers, host=host
    )
    return status, response_headers, b"".join(chunks)


def decode(body: bytes, headers: dict[str, str]) -> bytes:
    """Decompress a response body according to its Content-Encoding."""
    if headers.get("Content-Encoding") == "gzip":
        return gzip.decompress(body)
    return body


def json_body(body: bytes, headers: dict[str, str]) -> Any:
    """Decode and parse a JSON response body."""
    import json

    return json.loads(decode(body, headers))

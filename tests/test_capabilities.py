"""Tests for reportal.capabilities: rule matching and the scan orchestrator."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import capabilities, engines, store
from reportal.capabilities import MAX_EVIDENCE_PER_CAPABILITY, MAX_STRINGS_INSPECTED

EXPECTED_CATEGORIES = {
    "networking",
    "crypto",
    "file-io",
    "registry",
    "process-execution",
    "threading",
    "memory",
    "dynamic-loading",
    "anti-debug",
    "persistence",
    "synchronization",
    "compression",
    "ui",
    "console",
}


def _import(name: str, dll: str = "API.dll") -> dict[str, Any]:
    return {"dll": dll, "name": name, "iat_va": "0x401000"}


def _string(text: str) -> dict[str, Any]:
    return {"text": text, "va": "0x402000", "size": len(text), "kind": "ascii", "section": ".rdata"}


def _by_name(result: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {entry["name"]: entry for entry in result}


class _StubEngine:
    """Engine surface with fixed payloads and a call log."""

    def __init__(
        self,
        *,
        imports: dict[str, Any] | None = None,
        strings: dict[str, Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.calls: list[str] = []
        self._imports = imports if imports is not None else {"imports": []}
        self._strings = strings if strings is not None else {"strings": []}
        self._error = error

    def imports(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("imports")
        if self._error is not None:
            raise self._error
        return self._imports

    def strings(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("strings")
        if self._error is not None:
            raise self._error
        return self._strings


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, on_disk: bool = True) -> int:
    target = tmp_path / "demo.exe"
    if on_disk:
        target.write_bytes(b"MZ" + b"\x00" * 30)
    return store.add_binary(
        conn,
        sha256="ab" * 32,
        name="demo.exe",
        path=str(target) if on_disk else "",
    )


class TestClassify:
    def test_rule_table_covers_every_expected_category(self) -> None:
        assert {rule.name for rule in capabilities.CAPABILITIES} == EXPECTED_CATEGORIES

    @pytest.mark.parametrize(
        ("category", "name"),
        [
            ("networking", "WSAStartup"),
            ("crypto", "CryptEncrypt"),
            ("file-io", "CreateFileA"),
            ("registry", "RegOpenKeyExA"),
            ("process-execution", "CreateProcessA"),
            ("threading", "CreateThread"),
            ("memory", "VirtualAlloc"),
            ("dynamic-loading", "LoadLibraryA"),
            ("anti-debug", "IsDebuggerPresent"),
            ("synchronization", "CreateMutexA"),
            ("compression", "inflate"),
            ("ui", "MessageBoxA"),
            ("console", "GetStdHandle"),
        ],
    )
    def test_import_category_is_high_confidence(self, category: str, name: str) -> None:
        entry = _by_name(capabilities.classify([_import(name)], []))[category]
        assert entry["confidence"] == capabilities.CONFIDENCE_HIGH
        assert entry["evidence"] == [{"kind": "import", "value": name}]
        assert entry["evidence_count"] == 1

    def test_persistence_from_run_key_string(self) -> None:
        key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        entry = _by_name(capabilities.classify([], [_string(key)]))["persistence"]
        assert entry["confidence"] == capabilities.CONFIDENCE_MEDIUM
        assert entry["evidence"] == [{"kind": "string", "value": key}]

    def test_registry_from_hive_string(self) -> None:
        entry = _by_name(capabilities.classify([], [_string("HKEY_LOCAL_MACHINE\\Software")]))[
            "registry"
        ]
        assert entry["confidence"] == capabilities.CONFIDENCE_MEDIUM

    def test_url_string_is_medium_confidence(self) -> None:
        url = "https://c2.example/beacon"
        entry = _by_name(capabilities.classify([], [_string(url)]))["networking"]
        assert entry["confidence"] == capabilities.CONFIDENCE_MEDIUM
        assert entry["evidence"] == [{"kind": "string", "value": url}]

    def test_import_evidence_stays_high_beside_strings(self) -> None:
        result = capabilities.classify(
            [_import("WSAStartup")], [_string("https://c2.example/beacon")]
        )
        entry = _by_name(result)["networking"]
        assert entry["confidence"] == capabilities.CONFIDENCE_HIGH
        assert entry["evidence_count"] == 2
        assert {item["kind"] for item in entry["evidence"]} == {"import", "string"}

    def test_evidence_is_capped_while_count_is_exact(self) -> None:
        names = [
            "WSAStartup",
            "WSACleanup",
            "WSAGetLastError",
            "socket",
            "connect",
            "recv",
            "send",
            "bind",
            "listen",
            "accept",
            "gethostbyname",
            "inet_addr",
        ]
        entry = _by_name(capabilities.classify([_import(name) for name in names], []))["networking"]
        assert entry["evidence_count"] == len(names)
        assert len(entry["evidence"]) == MAX_EVIDENCE_PER_CAPABILITY

    def test_unrelated_imports_match_nothing(self) -> None:
        imports = [
            _import(name) for name in ("GetTickCount", "wsprintfA", "QueryPerformanceCounter")
        ]
        assert capabilities.classify(imports, []) == []

    def test_matching_is_case_insensitive(self) -> None:
        imports = [_import("wsaStartup"), _import("CRYPTENCRYPT"), _import("createfilea")]
        found = _by_name(capabilities.classify(imports, []))
        assert {"networking", "crypto", "file-io"} <= set(found)

    def test_duplicate_evidence_is_counted_once(self) -> None:
        entry = _by_name(capabilities.classify([_import("WSAStartup"), _import("wsaStartup")], []))[
            "networking"
        ]
        assert entry["evidence_count"] == 1
        assert entry["evidence"] == [{"kind": "import", "value": "WSAStartup"}]

    def test_results_sort_by_count_then_name(self) -> None:
        imports = [
            _import("WSAStartup"),
            _import("socket"),
            _import("CryptEncrypt"),
            _import("IsDebuggerPresent"),
        ]
        names = [entry["name"] for entry in capabilities.classify(imports, [])]
        assert names == ["networking", "anti-debug", "crypto"]

    def test_import_without_a_name_is_ignored(self) -> None:
        assert capabilities.classify([{"dll": "API.dll", "iat_va": "0x1"}], []) == []


class TestRunCapabilities:
    def test_stores_scan_and_returns_counts(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(
            imports={"imports": [_import("WSAStartup")]},
            strings={"strings": [_string("https://c2.example/beacon")]},
        )
        result = capabilities.run_capabilities(conn, binary_id=binary_id, io=stub)
        assert result["binary_id"] == binary_id
        assert result["count"] == 1
        assert result["capabilities"][0]["name"] == "networking"
        assert stub.calls == ["imports", "strings"]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_CAPABILITIES) == result

    def test_injected_payloads_skip_the_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("must not be called"))
        result = capabilities.run_capabilities(
            conn,
            binary_id=binary_id,
            io=stub,
            imports=[_import("CreateFileA")],
            strings=[_string("C:\\Windows\\temp.log")],
        )
        assert result["count"] == 1
        assert result["capabilities"][0]["name"] == "file-io"
        assert stub.calls == []

    def test_strings_inspected_are_capped(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        many = [
            _string(f"https://host{index}.example") for index in range(MAX_STRINGS_INSPECTED + 5)
        ]
        result = capabilities.run_capabilities(conn, binary_id=binary_id, imports=[], strings=many)
        assert result["capabilities"][0]["evidence_count"] == MAX_STRINGS_INSPECTED

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            capabilities.run_capabilities(conn, binary_id=4242)

    def test_missing_file_raises_file_not_found(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, on_disk=False)
        with pytest.raises(FileNotFoundError, match="has no file"):
            capabilities.run_capabilities(conn, binary_id=binary_id)

    def test_engine_unavailable_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            capabilities.run_capabilities(
                conn, binary_id=binary_id, engine=engines.RebrewEngine(enabled=False)
            )

    def test_engine_error_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("rebrew imports exited with code 3"))
        with pytest.raises(engines.EngineError, match="exited with code 3"):
            capabilities.run_capabilities(conn, binary_id=binary_id, io=stub)


class TestCapabilitiesEdges:
    def test_unknown_match_mode_raises(self) -> None:
        rule = capabilities.ImportRule("mystery", "x")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="unknown import match mode"):
            capabilities._import_matches(rule, "CreateFileW")

    def test_entries_ignore_non_list_shapes(self) -> None:
        assert capabilities._entries({}, "imports") == []
        assert capabilities._entries({"imports": "nope"}, "imports") == []
        assert capabilities._entries({"imports": ["nope", {"name": "x"}]}, "imports") == [
            {"name": "x"}
        ]

    def test_string_cap_respects_max(self) -> None:
        strings = [{"text": f"s{i}"} for i in range(10)]

        class _Source:
            def imports(self, binary: object) -> dict[str, object]:
                raise AssertionError("override wins")

            def strings(self, binary: object) -> dict[str, object]:
                raise AssertionError("override wins")

        _, resolved = capabilities.load_imports_and_strings(
            Path("/nope"),
            _Source(),
            imports=[],
            strings=strings,
            max_strings=3,
        )
        assert len(resolved) == 3


class TestLoadStrings:
    def test_engine_strings_are_parsed_and_capped(self) -> None:
        class _Source:
            def strings(self, binary: object) -> dict[str, object]:
                return {"strings": [{"text": "a"}, "nope", {"text": "b"}, {"text": "c"}]}

        resolved = capabilities.load_strings(
            Path("/nope"),
            _Source(),
            max_strings=2,
        )
        assert [entry["text"] for entry in resolved] == ["a", "b"]

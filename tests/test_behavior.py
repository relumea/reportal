"""Tests for reportal.behavior: the rule tables and the scan orchestrator."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import behavior, engines, store
from reportal.behavior import (
    BEHAVIOR_DOMAINS,
    DOMAIN_SCAN_KINDS,
    MAX_FINDINGS,
    MAX_STRINGS_INSPECTED,
)


def _import(name: str, dll: str = "API.dll") -> dict[str, Any]:
    return {"dll": dll, "name": name, "iat_va": "0x401000"}


def _string(text: str) -> dict[str, Any]:
    return {"text": text, "va": "0x402000", "size": len(text), "kind": "ascii", "section": ".rdata"}


class _StubEngine(engines.RebrewEngine):
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
        sha256="be" * 32,
        name="demo.exe",
        path=str(target) if on_disk else "",
    )


class TestClassify:
    def test_rule_table_covers_every_domain(self) -> None:
        assert set(behavior.BEHAVIOR_RULES) == set(BEHAVIOR_DOMAINS)

    @pytest.mark.parametrize(
        ("domain", "name", "rule"),
        [
            ("execution", "CreateProcessA", "process-launch"),
            ("execution", "ShellExecuteExW", "process-launch"),
            ("execution", "WinExec", "process-launch"),
            ("execution", "system", "process-launch"),
            ("execution", "OpenSCManagerA", "service-control"),
            ("execution", "RegisterServiceCtrlHandlerExW", "service-control"),
            ("networking", "WSAStartup", "socket"),
            ("networking", "getaddrinfo", "socket"),
            ("networking", "WinHttpOpen", "http-client"),
            ("networking", "InternetOpenUrlA", "http-client"),
            ("networking", "URLDownloadToFileA", "http-client"),
            ("filesystem", "CreateFileA", "file-io"),
            ("filesystem", "MoveFileExW", "file-io"),
            ("filesystem", "CreateDirectoryW", "directory"),
            ("filesystem", "FindFirstFileA", "find-files"),
            ("filesystem", "GetTempPathA", "temp-path"),
            ("filesystem", "SHFileOperationA", "shell-file-op"),
            ("filesystem", "unlink", "posix-file"),
        ],
    )
    def test_import_hit_is_high_confidence(self, domain: str, name: str, rule: str) -> None:
        result = behavior.classify(domain, [_import(name)], [])
        assert result["count"] == 1
        finding = result["findings"][0]
        assert finding["kind"] == "import"
        assert finding["name"] == name
        assert finding["detail"] == rule
        assert finding["confidence"] == "high"
        assert finding["count"] == 1

    @pytest.mark.parametrize("domain", ["execution", "networking", "filesystem"])
    def test_unrelated_imports_match_nothing(self, domain: str) -> None:
        imports = [
            _import(name) for name in ("GetTickCount", "wsprintfA", "QueryPerformanceCounter")
        ]
        result = behavior.classify(domain, imports, [])
        assert result["findings"] == []
        assert result["count"] == 0
        assert result["by_confidence"] == {"high": 0, "medium": 0}

    def test_url_string_is_medium_confidence(self) -> None:
        url = "https://c2.example/beacon"
        result = behavior.classify("networking", [], [_string(url)])
        finding = result["findings"][0]
        assert finding["kind"] == "string"
        assert finding["name"] == url
        assert finding["detail"] == "url"
        assert finding["confidence"] == "medium"

    def test_ipv4_string_is_medium_confidence(self) -> None:
        text = "connect to 203.0.113.9 now"
        result = behavior.classify("networking", [], [_string(text)])
        finding = result["findings"][0]
        assert finding["name"] == text
        assert finding["detail"] == "ipv4"
        assert finding["confidence"] == "medium"

    def test_labeled_port_string_is_medium_confidence(self) -> None:
        result = behavior.classify("networking", [], [_string("listening on port=4444")])
        finding = result["findings"][0]
        assert finding["detail"] == "port"
        assert finding["confidence"] == "medium"

    def test_invalid_ipv4_octet_is_not_a_finding(self) -> None:
        assert behavior.classify("networking", [], [_string("version 1.2.3.999")])["findings"] == []

    def test_drive_path_string_is_medium_confidence(self) -> None:
        path = "C:\\Windows\\Temp\\payload"
        result = behavior.classify("filesystem", [], [_string(path)])
        finding = result["findings"][0]
        assert finding["name"] == path
        assert finding["detail"] == "drive-path"
        assert finding["confidence"] == "medium"

    def test_unc_path_string_is_medium_confidence(self) -> None:
        path = "\\\\server\\share\\payload"
        result = behavior.classify("filesystem", [], [_string(path)])
        assert result["findings"][0]["detail"] == "unc-path"

    def test_file_extension_string_is_medium_confidence(self) -> None:
        result = behavior.classify("filesystem", [], [_string("dropped noop.dll")])
        assert result["findings"][0]["detail"] == "file-extension"

    def test_import_evidence_stays_high_beside_strings(self) -> None:
        result = behavior.classify(
            "networking", [_import("WSAStartup")], [_string("https://c2.example/beacon")]
        )
        assert result["by_confidence"] == {"high": 1, "medium": 1}
        assert [finding["confidence"] for finding in result["findings"]] == ["high", "medium"]

    def test_duplicate_evidence_counts_once(self) -> None:
        result = behavior.classify(
            "execution", [_import("CreateProcessA"), _import("createprocessa")], []
        )
        assert result["count"] == 1
        finding = result["findings"][0]
        assert finding["name"] == "CreateProcessA"
        assert finding["count"] == 2

    def test_findings_are_capped_while_count_is_exact(self) -> None:
        strings = [_string(f"C:\\dir{index}\\data") for index in range(MAX_FINDINGS + 5)]
        result = behavior.classify("filesystem", [], strings)
        assert result["count"] == MAX_FINDINGS + 5
        assert len(result["findings"]) == MAX_FINDINGS
        assert result["by_confidence"]["medium"] == MAX_FINDINGS + 5

    def test_findings_sort_by_confidence_then_name(self) -> None:
        imports = [_import("WriteFile"), _import("CreateFileA"), _import("DeleteFileA")]
        names = [
            finding["name"] for finding in behavior.classify("filesystem", imports, [])["findings"]
        ]
        assert names == ["CreateFileA", "DeleteFileA", "WriteFile"]

    def test_import_without_a_name_is_ignored(self) -> None:
        assert (
            behavior.classify("execution", [{"dll": "API.dll", "iat_va": "0x1"}], [])["findings"]
            == []
        )

    def test_unknown_domain_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="unknown behavior domain: registry"):
            behavior.classify("registry", [], [])


class TestScanDomain:
    def test_injected_payloads_skip_the_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("must not be called"))
        result = behavior.scan_domain(
            conn,
            binary_id=binary_id,
            domain="execution",
            imports=[_import("CreateProcessA")],
            strings=[],
        )
        assert result["binary_id"] == binary_id
        assert result["domain"] == "execution"
        assert result["count"] == 1
        assert stub.calls == []

    def test_stores_each_domain_under_its_own_kind(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payloads = {
            "execution": [_import("CreateProcessA")],
            "networking": [_import("WSAStartup")],
            "filesystem": [_import("CreateFileA")],
        }
        for domain, imports in payloads.items():
            result = behavior.scan_domain(
                conn, binary_id=binary_id, domain=domain, imports=imports, strings=[]
            )
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, DOMAIN_SCAN_KINDS[domain])
            assert stored == result
        for domain in BEHAVIOR_DOMAINS:
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            assert store.get_scan(conn, analysis_id or 0, DOMAIN_SCAN_KINDS[domain]) is not None

    def test_strings_inspected_are_capped(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        many = [_string(f"C:\\dir{index}\\data") for index in range(MAX_STRINGS_INSPECTED + 5)]
        result = behavior.scan_domain(
            conn, binary_id=binary_id, domain="filesystem", imports=[], strings=many
        )
        assert result["count"] == MAX_STRINGS_INSPECTED

    def test_unknown_domain_raises_value_error(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(ValueError, match="unknown behavior domain: registry"):
            behavior.scan_domain(conn, binary_id=binary_id, domain="registry")

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            behavior.scan_domain(conn, binary_id=4242, domain="execution")

    def test_missing_file_raises_file_not_found(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, on_disk=False)
        with pytest.raises(FileNotFoundError, match="has no file"):
            behavior.scan_domain(conn, binary_id=binary_id, domain="execution")

    def test_engine_unavailable_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            behavior.scan_domain(
                conn,
                binary_id=binary_id,
                domain="execution",
                engine=engines.RebrewEngine(enabled=False),
            )

    def test_engine_error_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("rebrew strings exited with code 3"))
        with pytest.raises(engines.EngineError, match="exited with code 3"):
            behavior.scan_domain(conn, binary_id=binary_id, domain="execution", engine=stub)

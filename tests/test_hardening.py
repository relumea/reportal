"""Tests for reportal.hardening: the anti-analysis rules and obfuscation heuristics."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import engines, hardening, store
from reportal.hardening import (
    DOMAIN_ANTI_ANALYSIS,
    DOMAIN_OBFUSCATION,
    DOMAIN_SCAN_KINDS,
    HARDENING_DOMAINS,
    HIGH_ENTROPY_THRESHOLD,
    HIGH_OVERALL_ENTROPY_THRESHOLD,
    MAX_FINDINGS,
    MAX_STRINGS_INSPECTED,
    SECTION_ENTROPY_NOTE,
    SPARSE_IMPORT_MIN_SIZE,
    SPARSE_IMPORT_THRESHOLD,
    SPARSE_STRING_MIN_SIZE,
    SPARSE_STRING_THRESHOLD,
)


def _import(name: str, dll: str = "API.dll") -> dict[str, Any]:
    return {"dll": dll, "name": name, "iat_va": "0x401000"}


def _string(text: str) -> dict[str, Any]:
    return {"text": text, "va": "0x402000", "size": len(text), "kind": "ascii", "section": ".rdata"}


def _section(name: str, entropy: float, raw_size: int = 1024) -> dict[str, Any]:
    return {"name": name, "entropy": entropy, "raw_size": raw_size, "vsize": raw_size}


def _fingerprint(sections: list[dict[str, Any]], size: int) -> dict[str, Any]:
    return {"size": size, "section_entropies": sections}


def _categories(findings: list[dict[str, Any]]) -> list[str]:
    return [finding["category"] for finding in findings]


class _StubEngine(engines.RebrewEngine):
    """Engine surface with fixed payloads and a call log."""

    def __init__(
        self,
        *,
        fingerprint: dict[str, Any] | None = None,
        imports: dict[str, Any] | None = None,
        strings: dict[str, Any] | None = None,
        error: Exception | None = None,
        fingerprint_error: Exception | None = None,
    ) -> None:
        self.calls: list[str] = []
        self._fingerprint = fingerprint if fingerprint is not None else {"section_entropies": []}
        self._imports = imports if imports is not None else {"imports": []}
        self._strings = strings if strings is not None else {"strings": []}
        self._error = error
        self._fingerprint_error = fingerprint_error

    def fingerprint(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("fingerprint")
        if self._fingerprint_error is not None:
            raise self._fingerprint_error
        return self._fingerprint

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
        sha256="ha" * 32,
        name="demo.exe",
        path=str(target) if on_disk else "",
        size=SPARSE_IMPORT_MIN_SIZE,
    )


class TestAntiAnalysisClassify:
    @pytest.mark.parametrize(
        ("name", "category"),
        [
            ("IsDebuggerPresent", "anti-debug-api"),
            ("CheckRemoteDebuggerPresent", "anti-debug-api"),
            ("NtQueryInformationProcess", "anti-debug-api"),
            ("NtSetInformationThread", "anti-debug-api"),
            ("OutputDebugStringA", "anti-debug-api"),
            ("OutputDebugStringW", "anti-debug-api"),
            ("DebugActiveProcess", "anti-debug-api"),
            ("ptrace", "anti-debug-api"),
            ("ptrace64", "anti-debug-api"),
            ("QueryPerformanceCounter", "timing-check"),
            ("GetTickCount", "timing-check"),
            ("timeGetTime", "timing-check"),
            ("RtlAddVectoredExceptionHandler", "exception-tampering"),
            ("SetErrorMode", "exception-tampering"),
        ],
    )
    def test_import_hit_is_high_confidence(self, name: str, category: str) -> None:
        result = hardening.classify_anti_analysis([_import(name)], [])
        finding = result["findings"][0]
        assert finding["category"] == category
        assert finding["name"] == name
        assert finding["confidence"] == "high"
        assert finding["detail"]
        assert result["count"] == 1

    def test_timing_string_rdtsc_is_medium(self) -> None:
        result = hardening.classify_anti_analysis([], [_string("rdtsc")])
        finding = result["findings"][0]
        assert finding["category"] == "timing-check"
        assert finding["confidence"] == "medium"

    @pytest.mark.parametrize(
        "text",
        ["in al, 0x4f", "out 0xef, al", "in eax, dx", "out dx, al", "IN AX, 0x93"],
    )
    def test_io_port_probes_are_medium(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(text)])
        finding = result["findings"][0]
        assert finding["category"] == "io-port-probe"
        assert finding["confidence"] == "medium"

    @pytest.mark.parametrize(
        "text",
        ["joined in autumn", "point out the door", "login", "out of memory"],
    )
    def test_prose_is_not_a_port_probe(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(text)])
        assert result["findings"] == []

    @pytest.mark.parametrize(
        "text",
        [
            "sidt [eax]",
            "SGDT [0x402000]",
            "sldt ax",
            "cpuid",
            "fnstenv [esp-0x1c]",
            "fstenv [ebx]",
            "fxsave [eax]",
            "fsave [ecx]",
        ],
    )
    def test_cpu_state_probes_are_medium(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(text)])
        finding = result["findings"][0]
        assert finding["category"] == "cpu-state-probe"
        assert finding["confidence"] == "medium"

    @pytest.mark.parametrize(
        "text",
        ["consider it done", "residue", "acid test", "CPUIDLE", "obsidian"],
    )
    def test_prose_is_not_a_cpu_state_probe(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(text)])
        assert result["findings"] == []

    @pytest.mark.parametrize("text", ["int 3", "INT3", "int3"])
    def test_breakpoint_traps_are_medium(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(text)])
        finding = result["findings"][0]
        assert finding["category"] == "int3-trap"
        assert finding["confidence"] == "medium"

    @pytest.mark.parametrize("text", ["point 3", "print 300", "hint 30", "internationalization"])
    def test_prose_is_not_a_trap(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(text)])
        assert result["findings"] == []

    @pytest.mark.parametrize(
        "text", ["lock inc [eax]", "LOCK XADD [ebx], ecx", "lock cmpxchg [edx], eax"]
    )
    def test_lock_canaries_are_medium(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(text)])
        finding = result["findings"][0]
        assert finding["category"] == "lock-canary"
        assert finding["confidence"] == "medium"

    @pytest.mark.parametrize("text", ["locksmith", "clockwork", "unlock the door"])
    def test_prose_is_not_a_canary(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(text)])
        assert result["findings"] == []

    @pytest.mark.parametrize(
        "text",
        ["VMware", "VBOX", "VirtualBox", "QEMU", "Xen", "Sandboxie", "SbieDll"],
    )
    def test_vm_or_sandbox_names_are_medium(self, text: str) -> None:
        result = hardening.classify_anti_analysis([], [_string(f"found {text} here")])
        assert _categories(result["findings"]) == ["vm-or-sandbox-artifact"]
        assert result["findings"][0]["confidence"] == "medium"

    def test_vm_artifact_matches_case_insensitively(self) -> None:
        result = hardening.classify_anti_analysis([], [_string("running under WINE")])
        assert result["findings"][0]["category"] == "vm-or-sandbox-artifact"

    def test_exception_strings_are_medium(self) -> None:
        result = hardening.classify_anti_analysis([], [_string("__try { __except (1) {} }")])
        assert _categories(result["findings"]) == ["exception-tampering"]

    def test_sigtrap_signal_string_is_medium(self) -> None:
        result = hardening.classify_anti_analysis([], [_string("signal(SIGTRAP, handler)")])
        assert _categories(result["findings"]) == ["exception-tampering"]

    def test_debugger_detection_string_is_medium(self) -> None:
        result = hardening.classify_anti_analysis([], [_string("Debugger detected!")])
        assert _categories(result["findings"]) == ["debugger-detection-string"]

    def test_unrelated_evidence_matches_nothing(self) -> None:
        imports = [_import(name) for name in ("LoadLibraryA", "WriteFile", "malloc")]
        strings = [_string("hello world"), _string("C:\\Temp\\out.txt")]
        result = hardening.classify_anti_analysis(imports, strings)
        assert result["findings"] == []
        assert result["count"] == 0
        assert result["by_confidence"] == {"high": 0, "medium": 0}

    def test_import_in_two_categories_reports_both(self) -> None:
        result = hardening.classify_anti_analysis([_import("SetUnhandledExceptionFilter")], [])
        assert _categories(result["findings"]) == ["anti-debug-api", "exception-tampering"]

    def test_duplicate_import_deduplicates_case_insensitively(self) -> None:
        result = hardening.classify_anti_analysis(
            [_import("IsDebuggerPresent"), _import("isdebuggerpresent")], []
        )
        assert result["count"] == 1
        assert result["findings"][0]["name"] == "IsDebuggerPresent"

    def test_findings_sort_by_confidence_then_category(self) -> None:
        imports = [_import("GetTickCount"), _import("IsDebuggerPresent")]
        strings = [_string("VMware")]
        result = hardening.classify_anti_analysis(imports, strings)
        assert result["findings"][0]["category"] == "anti-debug-api"
        assert result["findings"][1]["category"] == "timing-check"
        assert result["findings"][2]["confidence"] == "medium"

    def test_findings_are_capped_while_count_is_exact(self) -> None:
        strings = [_string(f"VMware {index}") for index in range(MAX_FINDINGS + 5)]
        result = hardening.classify_anti_analysis([], strings)
        assert result["count"] == MAX_FINDINGS + 5
        assert len(result["findings"]) == MAX_FINDINGS
        assert result["by_confidence"]["medium"] == MAX_FINDINGS + 5


class TestObfuscationEntropy:
    def test_high_entropy_code_section_fires(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(".text", 7.8)], 1024),
            imports=[],
            strings=[],
        )
        sections = [
            f for f in result["findings"] if f["category"] == "high-entropy-executable-section"
        ]
        assert len(sections) == 1
        assert sections[0]["name"] == ".text"
        assert "7.8" in sections[0]["detail"]
        assert sections[0]["confidence"] == "high"

    def test_entropy_at_the_threshold_fires(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(".text", HIGH_ENTROPY_THRESHOLD)], 1024),
            imports=[],
            strings=[],
        )
        assert "high-entropy-executable-section" in _categories(result["findings"])

    def test_entropy_below_the_threshold_does_not_fire(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(".text", 6.9)], 1024),
            imports=[],
            strings=[],
        )
        assert "high-entropy-executable-section" not in _categories(result["findings"])

    @pytest.mark.parametrize("name", [".code", "CODE", ".textbss", "mycode"])
    def test_code_like_section_names_fire(self, name: str) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(name, 7.5)], 1024),
            imports=[],
            strings=[],
        )
        assert "high-entropy-executable-section" in _categories(result["findings"])

    def test_high_entropy_data_section_does_not_fire(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(".rsrc", 7.9)], 1024),
            imports=[],
            strings=[],
        )
        assert "high-entropy-executable-section" not in _categories(result["findings"])

    def test_overall_entropy_at_the_threshold_fires(self) -> None:
        sections = [
            _section(".text", HIGH_OVERALL_ENTROPY_THRESHOLD),
            _section(".data", HIGH_OVERALL_ENTROPY_THRESHOLD),
        ]
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint(sections, 1024), imports=[], strings=[]
        )
        assert "high-overall-entropy" in _categories(result["findings"])

    def test_overall_entropy_below_the_threshold_does_not_fire(self) -> None:
        sections = [_section(".text", 6.5), _section(".data", 6.5)]
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint(sections, 1024), imports=[], strings=[]
        )
        assert "high-overall-entropy" not in _categories(result["findings"])

    def test_overall_entropy_weights_by_section_size(self) -> None:
        sections = [_section(".text", 7.9, raw_size=4096), _section(".data", 1.0, raw_size=64)]
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint(sections, 4160), imports=[], strings=[]
        )
        assert "high-overall-entropy" in _categories(result["findings"])

    def test_non_finite_section_entropy_does_not_poison_the_mean(self) -> None:
        """A NaN section used to make the weighted mean NaN and hide high entropy."""
        sections = [
            _section(".text", HIGH_OVERALL_ENTROPY_THRESHOLD),
            _section(".rdata", float("nan")),
        ]
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint(sections, 2048), imports=[], strings=[]
        )
        assert "high-overall-entropy" in _categories(result["findings"])
        assert "high-entropy-executable-section" not in _categories(result["findings"])


class TestObfuscationSparseAndPacker:
    def test_sparse_imports_fire_at_the_minimum_size(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], SPARSE_IMPORT_MIN_SIZE), imports=[], strings=[]
        )
        assert "sparse-imports" in _categories(result["findings"])

    def test_sparse_imports_below_the_minimum_size_do_not_fire(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], SPARSE_IMPORT_MIN_SIZE - 1), imports=[], strings=[]
        )
        assert "sparse-imports" not in _categories(result["findings"])

    def test_sparse_imports_at_the_threshold_do_not_fire(self) -> None:
        imports = [_import(f"Api{index}") for index in range(SPARSE_IMPORT_THRESHOLD)]
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], SPARSE_IMPORT_MIN_SIZE), imports=imports, strings=[]
        )
        assert "sparse-imports" not in _categories(result["findings"])

    def test_sparse_imports_one_below_the_threshold_fire(self) -> None:
        imports = [_import(f"Api{index}") for index in range(SPARSE_IMPORT_THRESHOLD - 1)]
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], SPARSE_IMPORT_MIN_SIZE), imports=imports, strings=[]
        )
        assert "sparse-imports" in _categories(result["findings"])

    def test_sparse_strings_fire_at_the_minimum_size(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], SPARSE_STRING_MIN_SIZE), imports=[], strings=[]
        )
        assert "sparse-strings" in _categories(result["findings"])

    def test_sparse_strings_below_the_minimum_size_do_not_fire(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], SPARSE_STRING_MIN_SIZE - 1), imports=[], strings=[]
        )
        assert "sparse-strings" not in _categories(result["findings"])

    def test_sparse_strings_at_the_threshold_do_not_fire(self) -> None:
        strings = [_string(f"literal {index}") for index in range(SPARSE_STRING_THRESHOLD)]
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], SPARSE_STRING_MIN_SIZE), imports=[], strings=strings
        )
        assert "sparse-strings" not in _categories(result["findings"])

    def test_packer_name_string_fires(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], 1024),
            imports=[],
            strings=[_string("$Info: This file is packed with the UPX executable packer")],
        )
        packer = [f for f in result["findings"] if f["category"] == "packer-name-artifact"]
        assert len(packer) == 1
        assert packer[0]["confidence"] == "high"

    def test_packer_section_name_from_triage_fires(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], 1024),
            imports=[],
            strings=[],
            triage={"meta": {"sections": [{"name": "UPX0"}, {"name": "UPX1"}]}},
        )
        names = [f["name"] for f in result["findings"] if f["category"] == "packer-name-artifact"]
        assert names == ["UPX0", "UPX1"]

    def test_packer_section_name_from_fingerprint_fires(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(".aspack", 6.0)], 1024),
            imports=[],
            strings=[],
        )
        assert any(
            f["category"] == "packer-name-artifact" and f["name"] == ".aspack"
            for f in result["findings"]
        )

    def test_no_packer_evidence_is_quiet(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(".text", 6.0)], 1024),
            imports=[_import("LoadLibraryA")],
            strings=[_string("just a normal literal")],
        )
        assert result["findings"] == []
        assert result["packer_likelihood"] == "low"


class TestPackerLikelihood:
    def test_low_with_no_findings(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], 1024), imports=[], strings=[]
        )
        assert result["packer_likelihood"] == "low"

    def test_medium_with_two_findings(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(".text", 7.8)], 1024), imports=[], strings=[]
        )
        assert result["count"] == 2
        assert result["packer_likelihood"] == "medium"

    def test_high_with_three_findings(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([_section(".text", 7.8)], 1024),
            imports=[],
            strings=[_string("UPX")],
        )
        assert result["packer_likelihood"] == "high"


class TestObfuscationNotes:
    def test_missing_section_entropies_record_a_note_and_skip_thresholds(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint={}, imports=[], strings=[], binary_size=SPARSE_IMPORT_MIN_SIZE
        )
        assert SECTION_ENTROPY_NOTE in result["notes"]
        assert "high-entropy-executable-section" not in _categories(result["findings"])
        assert "high-overall-entropy" not in _categories(result["findings"])

    def test_missing_fingerprint_still_runs_the_sparse_and_packer_heuristics(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint={},
            imports=[],
            strings=[_string("UPX")],
            binary_size=SPARSE_IMPORT_MIN_SIZE,
        )
        categories = _categories(result["findings"])
        assert "sparse-imports" in categories
        assert "packer-name-artifact" in categories

    def test_empty_section_list_records_the_note(self) -> None:
        result = hardening.classify_obfuscation(
            fingerprint=_fingerprint([], 1024), imports=[], strings=[]
        )
        assert SECTION_ENTROPY_NOTE in result["notes"]


class TestScanHardening:
    def test_anti_analysis_uses_injected_payloads_without_the_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("must not be called"))
        result = hardening.scan_hardening(
            conn,
            binary_id=binary_id,
            domain=DOMAIN_ANTI_ANALYSIS,
            imports=[_import("IsDebuggerPresent")],
            strings=[],
        )
        assert result["binary_id"] == binary_id
        assert result["domain"] == DOMAIN_ANTI_ANALYSIS
        assert result["count"] == 1
        assert result["packer_likelihood"] is None
        assert result["notes"] == []
        assert stub.calls == []

    def test_obfuscation_uses_injected_payloads_and_stores(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = hardening.scan_hardening(
            conn,
            binary_id=binary_id,
            domain=DOMAIN_OBFUSCATION,
            fingerprint=_fingerprint([_section(".text", 7.8)], 1024),
            imports=[],
            strings=[],
        )
        assert result["domain"] == DOMAIN_OBFUSCATION
        assert result["packer_likelihood"] == "medium"
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        stored = store.get_scan(conn, analysis_id or 0, DOMAIN_SCAN_KINDS[DOMAIN_OBFUSCATION])
        assert stored == result

    def test_each_domain_stores_under_its_own_kind(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        for domain in HARDENING_DOMAINS:
            hardening.scan_hardening(
                conn,
                binary_id=binary_id,
                domain=domain,
                fingerprint=_fingerprint([], 1024),
                imports=[],
                strings=[],
            )
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            stored = store.get_scan(conn, analysis_id or 0, DOMAIN_SCAN_KINDS[domain])
            assert stored is not None
            assert stored["domain"] == domain
        assert store.SCAN_KIND_ANTI_ANALYSIS == "anti-analysis"
        assert store.SCAN_KIND_OBFUSCATION == "obfuscation"

    def test_obfuscation_reads_the_stored_triage_section_names(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_TRIAGE,
            {"meta": {"sections": [{"name": "UPX0"}]}},
        )
        result = hardening.scan_hardening(
            conn,
            binary_id=binary_id,
            domain=DOMAIN_OBFUSCATION,
            fingerprint=_fingerprint([], 1024),
            imports=[],
            strings=[],
        )
        assert any(
            f["category"] == "packer-name-artifact" and f["name"] == "UPX0"
            for f in result["findings"]
        )

    def test_strings_inspected_are_capped(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        many = [_string(f"VMware {index}") for index in range(MAX_STRINGS_INSPECTED + 5)]
        result = hardening.scan_hardening(
            conn,
            binary_id=binary_id,
            domain=DOMAIN_ANTI_ANALYSIS,
            imports=[],
            strings=many,
        )
        assert result["count"] == MAX_STRINGS_INSPECTED

    def test_fingerprint_engine_error_is_notes_not_failure(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(fingerprint_error=engines.EngineError("rebrew fingerprints exited 1"))
        result = hardening.scan_hardening(
            conn,
            binary_id=binary_id,
            domain=DOMAIN_OBFUSCATION,
            engine=stub,
            imports=[],
            strings=[],
        )
        assert "high-entropy-executable-section" not in _categories(result["findings"])
        assert "high-overall-entropy" not in _categories(result["findings"])
        assert any(note.startswith("fingerprint-error") for note in result["notes"])
        assert SECTION_ENTROPY_NOTE in result["notes"]

    def test_engine_payloads_used_when_not_injected(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(
            imports={"imports": [_import("IsDebuggerPresent")]},
            strings={"strings": []},
        )
        result = hardening.scan_hardening(
            conn, binary_id=binary_id, domain=DOMAIN_ANTI_ANALYSIS, engine=stub
        )
        assert result["count"] == 1
        assert stub.calls == ["imports", "strings"]

    def test_unknown_domain_raises_value_error(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(ValueError, match="unknown hardening domain: packing"):
            hardening.scan_hardening(conn, binary_id=binary_id, domain="packing")

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            hardening.scan_hardening(conn, binary_id=4242, domain=DOMAIN_ANTI_ANALYSIS)

    def test_missing_file_raises_file_not_found(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, on_disk=False)
        with pytest.raises(FileNotFoundError, match="has no file"):
            hardening.scan_hardening(conn, binary_id=binary_id, domain=DOMAIN_ANTI_ANALYSIS)

    def test_engine_unavailable_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            hardening.scan_hardening(
                conn,
                binary_id=binary_id,
                domain=DOMAIN_ANTI_ANALYSIS,
                engine=engines.RebrewEngine(enabled=False),
            )

    def test_engine_error_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("rebrew strings exited with code 3"))
        with pytest.raises(engines.EngineError, match="exited with code 3"):
            hardening.scan_hardening(
                conn, binary_id=binary_id, domain=DOMAIN_ANTI_ANALYSIS, engine=stub
            )

    def test_binary_row_size_feeds_the_sparse_heuristics(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = hardening.scan_hardening(
            conn,
            binary_id=binary_id,
            domain=DOMAIN_OBFUSCATION,
            fingerprint={},
            imports=[],
            strings=[],
        )
        assert "sparse-imports" in _categories(result["findings"])


class TestHardeningHelpers:
    def test_entropy_rejects_non_numbers(self) -> None:
        assert hardening._section_entropy({"entropy": True}) is None
        assert hardening._section_entropy({"entropy": "high"}) is None
        assert hardening._section_entropy({"entropy": 7.5}) == 7.5

    def test_weight_defaults_to_one(self) -> None:
        assert hardening._section_weight({"raw_size": 0}) == 1
        assert hardening._section_weight({"raw_size": -5}) == 1
        assert hardening._section_weight({"raw_size": 100}) == 100

    def test_no_graded_sections_has_no_mean(self) -> None:
        assert hardening._weighted_mean_entropy([{"entropy": True}]) is None

    def test_triage_without_sections_is_empty(self) -> None:
        assert hardening._triage_section_names(None) == []
        assert hardening._triage_section_names({}) == []
        assert hardening._triage_section_names({"meta": "nope"}) == []
        assert hardening._triage_section_names({"meta": {}}) == []

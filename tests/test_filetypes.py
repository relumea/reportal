"""Tests for reportal.filetypes: the signature table, detection and the scan."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import engines, filetypes, store
from reportal.filetypes import (
    CAP_NOTE,
    CATEGORY_INSTALLER,
    CATEGORY_PACKER,
    CATEGORY_PROTECTOR,
    CATEGORY_RUNTIME,
    CATEGORY_TOOLCHAIN,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    ENTRY_BYTES_NOTE,
    FILE_CATEGORIES,
    HIGH_ENTROPY_THRESHOLD,
    MAX_MATCHES,
    MAX_SIGNALS_PER_MATCH,
    SIGNATURES,
    FileSignature,
    SignatureMatch,
)

_UPX_STRING = "UPX!"
_BSJB = "BSJB"


def _section(name: str, *, execute: bool = False) -> dict[str, Any]:
    return {"name": name, "execute": execute}


def _string(text: str) -> dict[str, Any]:
    return {"text": text, "va": "0x402000"}


def _import(dll: str, name: str = "SomeFunction") -> dict[str, Any]:
    return {"dll": dll, "name": name}


def _evidence(**overrides: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "format": "pe",
        "sections": [],
        "entry_point": None,
        "entropies": {},
        "imports": [],
        "strings": [],
        "rich_header": None,
    }
    evidence.update(overrides)
    return evidence


def _names(result: dict[str, Any]) -> list[str]:
    return [match["name"] for match in result["matches"]]


def _match(result: dict[str, Any], name: str) -> dict[str, Any]:
    return next(match for match in result["matches"] if match["name"] == name)


def _kinds(match: dict[str, Any]) -> set[str]:
    return {signal["kind"] for signal in match["signals"]}


class TestSignatureTable:
    def test_every_signature_is_well_formed(self) -> None:
        assert SIGNATURES
        for signature in SIGNATURES:
            assert signature.name.strip()
            assert signature.category in FILE_CATEGORIES
            assert signature.confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW)
            match = signature.match
            assert (
                match.section_prefixes
                or match.strings
                or match.imports
                or match.entry_prefixes
                or match.constants
                or match.rich_header
                or match.executable_entropy is not None
            )

    def test_signature_names_are_unique(self) -> None:
        names = [signature.name for signature in SIGNATURES]
        assert len(names) == len(set(names))

    def test_toolchain_names_match_the_signature_table(self) -> None:
        expected = tuple(
            signature.name for signature in SIGNATURES if signature.category == CATEGORY_TOOLCHAIN
        )
        assert filetypes.toolchain_names() == expected
        assert expected == ("Microsoft Visual C++", "MinGW GCC")

    def test_high_entropy_heuristic_uses_the_named_threshold(self) -> None:
        signature = next(s for s in SIGNATURES if s.name == "high-entropy-executable")
        assert signature.match.executable_entropy == HIGH_ENTROPY_THRESHOLD


class TestPackerSignatures:
    def test_upx_from_section_names(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("UPX1", execute=True)]))
        assert _match(result, "UPX")["category"] == CATEGORY_PACKER
        assert _match(result, "UPX")["confidence"] == CONFIDENCE_MEDIUM
        assert _kinds(_match(result, "UPX")) == {"section"}

    def test_upx_string_marker_alone_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string(_UPX_STRING)]))
        assert _match(result, "UPX")["confidence"] == CONFIDENCE_LOW

    def test_upx_entry_point_prefix(self) -> None:
        result = filetypes.detect(_evidence(entry_bytes="60BE 8D BE", entry_point=0x401000))
        match = _match(result, "UPX")
        assert _kinds(match) == {"entry-point"}
        assert match["signals"][0]["value"] == "0x401000 60be8dbe"
        assert match["confidence"] == CONFIDENCE_MEDIUM

    def test_upx_unrelated_entry_prefix_does_not_fire(self) -> None:
        result = filetypes.detect(_evidence(entry_bytes="e9", entry_point=0x401000))
        assert "UPX" not in _names(result)

    def test_aspack_from_adata_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".adata")]))
        assert _match(result, "ASPack")["category"] == CATEGORY_PACKER

    def test_mpress_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".MPRESS1")]))
        assert "MPRESS" in _names(result)

    def test_mpress_from_string_marker(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("MPRESS 1.27")]))
        assert _match(result, "MPRESS")["confidence"] == CONFIDENCE_LOW

    def test_pecompact_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("PEC2")]))
        assert "PECompact" in _names(result)

    def test_nspack_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("nsp0")]))
        assert "NsPack" in _names(result)

    def test_petite_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".petite")]))
        assert "Petite" in _names(result)

    def test_telock_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".tElock")]))
        assert "tElock" in _names(result)

    def test_fsg_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("FSG!")]))
        assert "FSG" in _names(result)

    def test_mew_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("MEW")]))
        assert "MEW" in _names(result)

    def test_upack_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("UPACK0")]))
        assert "Upack" in _names(result)

    def test_kkrunchy_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("kkrunchy 0.23a")]))
        assert _match(result, "kkrunchy")["confidence"] == CONFIDENCE_LOW

    def test_pklite_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(format="mz", strings=[_string("PKLITE Copr. 1990")]))
        assert _match(result, "PKLITE")["confidence"] == CONFIDENCE_LOW

    def test_lzexe_string_marker(self) -> None:
        result = filetypes.detect(_evidence(format="mz", strings=[_string("LZ91")]))
        assert _match(result, "LZEXE")["confidence"] == CONFIDENCE_LOW

    def test_dos_packer_markers_are_suppressed_on_a_pe(self) -> None:
        result = filetypes.detect(
            _evidence(format="pe", strings=[_string("PKLITE"), _string("LZ91")])
        )
        assert "PKLITE" not in _names(result)
        assert "LZEXE" not in _names(result)


class TestProtectorSignatures:
    def test_themida_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".themida")]))
        assert _match(result, "Themida/WinLicense")["category"] == CATEGORY_PROTECTOR

    def test_themida_from_string_marker(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("Themida 2.x")]))
        assert _match(result, "Themida/WinLicense")["confidence"] == CONFIDENCE_LOW

    def test_vmprotect_from_section_and_string(self) -> None:
        result = filetypes.detect(
            _evidence(sections=[_section(".vmp0")], strings=[_string("VMProtect")])
        )
        match = _match(result, "VMProtect")
        assert _kinds(match) == {"section", "string"}
        assert match["confidence"] == CONFIDENCE_HIGH

    def test_enigma_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".enigma1")]))
        assert "Enigma Protector" in _names(result)

    def test_obsidium_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("Obsidium")]))
        assert _match(result, "Obsidium")["confidence"] == CONFIDENCE_LOW

    def test_armadillo_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("Armadillo v1.71")]))
        assert _match(result, "Armadillo")["confidence"] == CONFIDENCE_LOW

    def test_asprotect_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".aspr1")]))
        assert "ASProtect" in _names(result)

    def test_confuserex_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("ConfuserEx v1.0")]))
        assert _match(result, "ConfuserEx")["confidence"] == CONFIDENCE_LOW

    def test_dotnet_reactor_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string(".NET Reactor")]))
        assert _match(result, ".NET Reactor")["confidence"] == CONFIDENCE_LOW

    def test_smartassembly_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("SmartAssembly")]))
        assert _match(result, "SmartAssembly")["confidence"] == CONFIDENCE_LOW

    def test_ilprotector_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("ILProtector")]))
        assert _match(result, "ILProtector")["confidence"] == CONFIDENCE_LOW


class TestInstallerSignatures:
    def test_nsis_string_markers(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("Nullsoft Install System")]))
        assert _match(result, "NSIS")["category"] == CATEGORY_INSTALLER
        assert _match(result, "NSIS")["confidence"] == CONFIDENCE_LOW

    def test_nsis_crypter_markers(self) -> None:
        result = filetypes.detect(
            _evidence(strings=[_string("$PLUGINSDIR"), _string("InitPluginsDir")])
        )
        assert _match(result, "NSIS")["category"] == CATEGORY_INSTALLER

    def test_boxedapp_string_markers(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("BoxedApp SDK")]))
        match = _match(result, "BoxedApp")
        assert match["category"] == CATEGORY_PACKER
        assert match["confidence"] == CONFIDENCE_LOW

    def test_paranoiac_rat_constants_need_three_hits(self) -> None:
        three = bytes.fromhex("EA45F620") + bytes.fromhex("C2CA997F") + bytes.fromhex("97938F8B")
        result = filetypes.detect(_evidence(section_bytes=three))
        match = _match(result, "Paranoiac-RAT-family")
        assert match["category"] == CATEGORY_PACKER
        assert match["confidence"] == CONFIDENCE_LOW
        assert _kinds(match) == {"constant"}

    def test_two_constants_are_not_enough(self) -> None:
        two = bytes.fromhex("EA45F620") + bytes.fromhex("C2CA997F")
        result = filetypes.detect(_evidence(section_bytes=two))
        assert "Paranoiac-RAT-family" not in _names(result)

    def test_no_section_bytes_fires_nothing_constant(self) -> None:
        result = filetypes.detect(_evidence())
        assert "Paranoiac-RAT-family" not in _names(result)

    def test_netis_gafgyt_constants_need_two_hits(self) -> None:
        two = bytes.fromhex("730B6F0B") + bytes.fromhex("C073")
        result = filetypes.detect(_evidence(section_bytes=two))
        match = _match(result, "NeTiS-Gafgyt-family")
        assert match["category"] == CATEGORY_PACKER
        assert match["confidence"] == CONFIDENCE_LOW
        assert _kinds(match) == {"constant"}

    def test_one_netis_constant_is_not_enough(self) -> None:
        result = filetypes.detect(_evidence(section_bytes=bytes.fromhex("C073")))
        assert "NeTiS-Gafgyt-family" not in _names(result)

    def test_inno_setup_string(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("Inno Setup Setup Data")]))
        assert "Inno Setup" in _names(result)

    def test_installshield_string(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("InstallShield (R)")]))
        assert "InstallShield" in _names(result)

    def test_sevenzip_sfx_string(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("7-Zip")]))
        assert "7-Zip SFX" in _names(result)

    def test_wix_string(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("Windows Installer XML")]))
        assert "WiX" in _names(result)


class TestRuntimeSignatures:
    def test_dotnet_from_import(self) -> None:
        result = filetypes.detect(_evidence(imports=[_import("MSCOREE.DLL", "_CorExeMain")]))
        match = _match(result, ".NET")
        assert match["category"] == CATEGORY_RUNTIME
        assert match["confidence"] == CONFIDENCE_MEDIUM
        assert _kinds(match) == {"import"}

    def test_dotnet_import_and_marker_is_high(self) -> None:
        result = filetypes.detect(_evidence(imports=[_import("mscoree")], strings=[_string(_BSJB)]))
        assert _match(result, ".NET")["confidence"] == CONFIDENCE_HIGH

    def test_dotnet_marker_alone_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string(_BSJB)]))
        assert _match(result, ".NET")["confidence"] == CONFIDENCE_LOW

    def test_visual_basic_from_import(self) -> None:
        result = filetypes.detect(_evidence(imports=[_import("MSVBVM60.DLL")]))
        assert _match(result, "Visual Basic")["category"] == CATEGORY_RUNTIME

    def test_delphi_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("@System@")]))
        assert _match(result, "Delphi")["confidence"] == CONFIDENCE_LOW

    def test_go_section_is_medium(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".gopclntab")]))
        match = _match(result, "Go")
        assert match["category"] == CATEGORY_RUNTIME
        assert match["confidence"] == CONFIDENCE_MEDIUM

    def test_go_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("runtime.gopanic")]))
        assert _match(result, "Go")["confidence"] == CONFIDENCE_LOW

    def test_go_section_and_marker_is_high(self) -> None:
        result = filetypes.detect(
            _evidence(sections=[_section(".gopclntab")], strings=[_string("runtime.goexit")])
        )
        assert _match(result, "Go")["confidence"] == CONFIDENCE_HIGH

    def test_rust_section_is_medium(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".rustc")]))
        match = _match(result, "Rust")
        assert match["category"] == CATEGORY_RUNTIME
        assert match["confidence"] == CONFIDENCE_MEDIUM

    def test_rust_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("rust_begin_unwind")]))
        assert _match(result, "Rust")["confidence"] == CONFIDENCE_LOW

    def test_swift_section_is_medium(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("__swift5_typeref")]))
        match = _match(result, "Swift")
        assert match["category"] == CATEGORY_RUNTIME
        assert match["confidence"] == CONFIDENCE_MEDIUM

    def test_swift_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("libswiftCore.dylib")]))
        assert _match(result, "Swift")["confidence"] == CONFIDENCE_LOW

    def test_pyinstaller_string(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("PyInstaller")]))
        match = _match(result, "PyInstaller")
        assert match["category"] == CATEGORY_RUNTIME
        assert match["confidence"] == CONFIDENCE_LOW

    def test_nuitka_string(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("Nuitka")]))
        assert _match(result, "Nuitka")["category"] == CATEGORY_RUNTIME

    def test_cx_freeze_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("cx_Freeze")]))
        assert _match(result, "cx_Freeze")["confidence"] == CONFIDENCE_LOW

    def test_autoit_magic_string(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("AU3!EA06")]))
        assert _match(result, "AutoIt")["category"] == CATEGORY_RUNTIME

    def test_electron_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("ELECTRON_RUN_AS_NODE")]))
        assert _match(result, "Electron")["confidence"] == CONFIDENCE_LOW

    def test_nim_string(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("NimMain")]))
        assert _match(result, "Nim")["category"] == CATEGORY_RUNTIME

    def test_zig_string_only_is_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("zig_probe_stack")]))
        assert _match(result, "Zig")["confidence"] == CONFIDENCE_LOW


class TestToolchainSignatures:
    def test_msvc_from_rich_header(self) -> None:
        result = filetypes.detect(_evidence(rich_header={"present": True}))
        assert _match(result, "Microsoft Visual C++")["category"] == CATEGORY_TOOLCHAIN

    def test_mingw_from_section(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section(".buildid")]))
        assert "MinGW GCC" in _names(result)

    def test_mingw_from_string_marker(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("gcc2_compiled.")]))
        assert _match(result, "MinGW GCC")["confidence"] == CONFIDENCE_LOW


class TestConfidenceRules:
    def test_single_section_signal_is_medium(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("UPX0")]))
        assert _match(result, "UPX")["confidence"] == CONFIDENCE_MEDIUM

    def test_two_independent_signal_kinds_are_high(self) -> None:
        result = filetypes.detect(
            _evidence(sections=[_section("UPX1")], strings=[_string(_UPX_STRING)])
        )
        assert _match(result, "UPX")["confidence"] == CONFIDENCE_HIGH

    def test_two_strings_are_one_kind_and_stay_low(self) -> None:
        result = filetypes.detect(_evidence(strings=[_string("Nullsoft"), _string("NSIS Error")]))
        match = _match(result, "NSIS")
        assert _kinds(match) == {"string"}
        assert match["confidence"] == CONFIDENCE_LOW

    def test_entropy_only_is_low(self) -> None:
        result = filetypes.detect(
            _evidence(sections=[_section(".text", execute=True)], entropies={".text": 7.5})
        )
        assert _match(result, "high-entropy-executable")["confidence"] == CONFIDENCE_LOW


class TestEntropyHeuristic:
    def test_executable_section_at_threshold_fires(self) -> None:
        result = filetypes.detect(
            _evidence(
                sections=[_section(".text", execute=True)],
                entropies={".text": HIGH_ENTROPY_THRESHOLD},
            )
        )
        assert "high-entropy-executable" in _names(result)

    def test_executable_section_below_threshold_does_not_fire(self) -> None:
        result = filetypes.detect(
            _evidence(
                sections=[_section(".text", execute=True)],
                entropies={".text": HIGH_ENTROPY_THRESHOLD - 0.0001},
            )
        )
        assert "high-entropy-executable" not in _names(result)

    def test_entropy_requires_an_executable_section(self) -> None:
        result = filetypes.detect(
            _evidence(sections=[_section(".rdata")], entropies={".rdata": 7.9})
        )
        assert "high-entropy-executable" not in _names(result)

    def test_entropy_signal_records_the_section(self) -> None:
        result = filetypes.detect(
            _evidence(sections=[_section(".text", execute=True)], entropies={".text": 7.9})
        )
        value = _match(result, "high-entropy-executable")["signals"][0]["value"]
        assert ".text" in value and "7.9" in value


class TestEvidence:
    def test_malformed_evidence_shapes_are_ignored(self) -> None:
        result = filetypes.detect(
            {
                "sections": "not a list",
                "imports": {"dll": "MSCOREE.DLL"},
                "strings": 7,
                "entropies": ["nope"],
                "rich_header": None,
            }
        )
        assert result["matches"] == []
        assert result["count"] == 0

    def test_plain_string_entries_are_accepted(self) -> None:
        result = filetypes.detect(_evidence(strings=[_UPX_STRING], imports=["mscoree"]))
        assert "UPX" in _names(result)
        assert ".NET" in _names(result)

    def test_unrelated_binary_yields_nothing(self) -> None:
        result = filetypes.detect(
            _evidence(
                sections=[_section(".text", execute=True), _section(".data")],
                entropies={".text": 6.2, ".data": 3.1},
                imports=[_import("KERNEL32.dll", "GetTickCount")],
                strings=[_string("hello")],
            )
        )
        assert result["matches"] == []
        assert result["count"] == 0
        assert result["by_category"] == dict.fromkeys(FILE_CATEGORIES, 0)

    def test_duplicate_signals_are_deduped(self) -> None:
        result = filetypes.detect(
            _evidence(
                sections=[_section("UPX1"), _section("UPX1")],
                strings=[_string(_UPX_STRING), _string(_UPX_STRING)],
            )
        )
        match = _match(result, "UPX")
        assert len(match["signals"]) == 2

    def test_matches_sort_by_confidence_then_category_then_name(self) -> None:
        result = filetypes.detect(
            _evidence(
                format="mz",
                sections=[_section("UPX1"), _section(".vmp1")],
                imports=[_import("mscoree")],
                strings=[
                    _string(_UPX_STRING),
                    _string("VMProtect"),
                    _string(_BSJB),
                    _string("PKLITE"),
                ],
                rich_header={"present": True},
            )
        )
        assert _names(result) == [
            "UPX",
            "VMProtect",
            ".NET",
            "Microsoft Visual C++",
            "PKLITE",
        ]

    def test_by_category_counts_every_category(self) -> None:
        result = filetypes.detect(_evidence(sections=[_section("UPX1")]))
        assert result["by_category"]["packer"] == 1
        assert set(result["by_category"]) == set(FILE_CATEGORIES)

    def test_signals_are_capped_per_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            filetypes,
            "SIGNATURES",
            (
                FileSignature(
                    "flood",
                    CATEGORY_PACKER,
                    CONFIDENCE_LOW,
                    SignatureMatch(strings=(filetypes.re.compile("flood"),)),
                ),
            ),
        )
        result = filetypes.detect(_evidence(strings=[_string(f"flood {i}") for i in range(50)]))
        assert len(result["matches"][0]["signals"]) == MAX_SIGNALS_PER_MATCH

    def test_matches_are_capped_with_a_note(self, monkeypatch: pytest.MonkeyPatch) -> None:
        table = tuple(
            FileSignature(
                f"sig-{index:02d}",
                CATEGORY_PACKER,
                CONFIDENCE_MEDIUM,
                SignatureMatch(section_prefixes=("upx",)),
            )
            for index in range(MAX_MATCHES + 5)
        )
        monkeypatch.setattr(filetypes, "SIGNATURES", table)
        result = filetypes.detect(_evidence(sections=[_section("UPX1")]))
        assert len(result["matches"]) == MAX_MATCHES
        assert result["count"] == MAX_MATCHES + 5
        assert result["notes"] == [CAP_NOTE.format(shown=MAX_MATCHES, total=MAX_MATCHES + 5)]


class _StubEngine:
    """Typed engine stub for filetype runs; raises only for the named calls."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.failing: set[str] = set()
        self.pe_info_payload: dict[str, Any] = {
            "format": "pe",
            "entry_point": 0x401000,
            "sections": [
                {"name": "UPX0", "execute": False},
                {"name": "UPX1", "execute": True},
            ],
            "rich_header": {"present": False},
        }
        self.fingerprint_payload: dict[str, Any] = {
            "format": "pe",
            "section_entropies": [{"name": "UPX1", "entropy": 7.8}],
        }
        self.imports_payload: dict[str, Any] = {"imports": [_import("KERNEL32.dll")]}
        self.strings_payload: dict[str, Any] = {"strings": [_string(_UPX_STRING)]}

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if name in self.failing:
            raise engines.EngineError(f"rebrew {name} failed")

    def pe_info(self, binary: str | Path) -> dict[str, Any]:
        self._call("pe_info")
        return dict(self.pe_info_payload)

    def fingerprint(self, binary: str | Path) -> dict[str, Any]:
        self._call("fingerprint")
        return dict(self.fingerprint_payload)

    def imports(self, binary: str | Path) -> dict[str, Any]:
        self._call("imports")
        return dict(self.imports_payload)

    def strings(self, binary: str | Path) -> dict[str, Any]:
        self._call("strings")
        return dict(self.strings_payload)


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, on_disk: bool = True) -> int:
    target = tmp_path / "demo.exe"
    if on_disk:
        target.write_bytes(b"MZ" + b"\x00" * 30)
    return store.add_binary(conn, sha256="fa" * 32, name="demo.exe", path=str(target))


class TestRunFiletype:
    def test_injected_evidence_round_trips_through_the_store(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        evidence = _evidence(sections=[_section("UPX1", execute=True)])
        payload = filetypes.run_filetype(conn, binary_id=binary_id, evidence=evidence)
        assert payload["binary_id"] == binary_id
        assert payload["count"] == 1
        assert payload["by_category"]["packer"] == 1
        assert payload["notes"][:2] == [filetypes.SCOPE_NOTE, filetypes.CONFIDENCE_NOTE]
        assert ENTRY_BYTES_NOTE in payload["notes"]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_FILETYPE) == payload
        binary = store.get_binary(conn, binary_id)
        assert binary is not None
        assert binary["language"] == ""

    def test_a_runtime_match_stamps_the_binary_language(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        filetypes.run_filetype(
            conn, binary_id=binary_id, evidence=_evidence(sections=[_section(".rustc")])
        )
        binary = store.get_binary(conn, binary_id)
        assert binary is not None
        assert binary["language"] == "Rust"
        assert binary["compiler"] == ""

    def test_a_toolchain_match_stamps_the_binary_compiler(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        filetypes.run_filetype(
            conn,
            binary_id=binary_id,
            evidence=_evidence(rich_header={"present": True}),
        )
        binary = store.get_binary(conn, binary_id)
        assert binary is not None
        assert binary["compiler"] == "Microsoft Visual C++"

    def test_unknown_binary_raises_keyerror(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError):
            filetypes.run_filetype(conn, binary_id=4242, evidence=_evidence())

    def test_missing_file_raises(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path, on_disk=False)
        with pytest.raises(FileNotFoundError):
            filetypes.run_filetype(conn, binary_id=binary_id, evidence=_evidence())

    def test_engine_evidence_is_assembled_and_stored(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        engine = _StubEngine()
        payload = filetypes.run_filetype(conn, binary_id=binary_id, engine=engine)
        assert engine.calls == ["pe_info", "fingerprint", "imports", "strings"]
        assert _match(payload, "UPX")["confidence"] == CONFIDENCE_HIGH
        assert "high-entropy-executable" in _names(payload)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_FILETYPE) == payload

    def test_injected_evidence_never_touches_the_engine(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        engine = _StubEngine()
        filetypes.run_filetype(
            conn, binary_id=binary_id, engine=engine, evidence=_evidence(strings=[_UPX_STRING])
        )
        assert engine.calls == []

    def test_read_section_bytes_reads_only_executable_sections(self, tmp_path: Path) -> None:
        target = tmp_path / "code.bin"
        target.write_bytes(b"\x00" * 64 + b"EXEC" + b"\x00" * 64 + b"DATA")
        sections = [
            {"name": ".text", "execute": True, "raw_offset": 64, "raw_size": 4},
            {"name": ".data", "execute": False, "raw_offset": 132, "raw_size": 4},
            {"name": ".bad", "execute": True, "raw_offset": 9999, "raw_size": 4},
        ]
        assert filetypes.read_section_bytes(target, sections) == b"EXEC"

    def test_read_section_bytes_of_missing_file_is_empty(self, tmp_path: Path) -> None:
        assert filetypes.read_section_bytes(tmp_path / "gone", []) == b""

    def test_missing_piece_degrades_with_a_note(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        engine = _StubEngine()
        engine.failing.add("pe_info")
        payload = filetypes.run_filetype(conn, binary_id=binary_id, engine=engine)
        assert any(note.startswith("pe-info-error") for note in payload["notes"])
        assert "UPX" in _names(payload)

    def test_without_an_engine_raises(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            filetypes.run_filetype(
                conn, binary_id=binary_id, engine=engines.RebrewEngine(enabled=False)
            )
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_injected_entry_bytes_suppresses_the_entry_note(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = filetypes.run_filetype(
            conn, binary_id=binary_id, evidence=_evidence(entry_bytes="60be")
        )
        assert ENTRY_BYTES_NOTE not in payload["notes"]

    def test_engine_entry_bytes_reach_the_detection(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        """pe-info's own entry bytes, not just the address, feed the signature."""
        binary_id = _seed(conn, tmp_path)
        engine = _StubEngine()
        engine.pe_info_payload["entry_bytes"] = "60be8dbe"
        payload = filetypes.run_filetype(conn, binary_id=binary_id, engine=engine)
        assert ENTRY_BYTES_NOTE not in payload["notes"]
        # The bytes carry through to the detection: the same evidence with the
        # field dropped loses the entry-point signal.
        without = dict(engine.pe_info_payload)
        del without["entry_bytes"]
        engine.pe_info_payload = without
        bare = filetypes.run_filetype(conn, binary_id=binary_id, engine=engine)
        assert ENTRY_BYTES_NOTE in bare["notes"]


class TestFiletypeHelpers:
    def test_entropies_skip_non_numbers(self) -> None:
        assert filetypes._entropy_map(
            {
                "section_entropies": [
                    {"name": "a", "entropy": True},
                    {"name": "b", "entropy": "high"},
                    {"name": "", "entropy": 1.0},
                    {"name": "c", "entropy": 7.5},
                    "nope",
                ]
            }
        ) == {"c": 7.5}
        assert filetypes._entropy_map({}) == {}

    def test_entry_hex_accepts_bytes_and_hex(self) -> None:
        assert filetypes._entry_hex({"entry_bytes": b"\x90\x90"}) == "9090"
        assert filetypes._entry_hex({"entry_bytes": "90 90"}) == "9090"
        assert filetypes._entry_hex({"entry_bytes": 42}) is None
        assert filetypes._entry_hex({"entry_bytes": "zz"}) is None
        assert filetypes._entry_hex({}) is None

    def test_section_bytes_skips_bad_entries(self, tmp_path: Path) -> None:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"0123456789abcdef")
        good = [{"raw_offset": "xx", "raw_size": 4}]
        assert filetypes.read_section_bytes(target, good) == b""
        missing: list[dict[str, object]] = [{"raw_offset": 100, "raw_size": 0}]
        assert filetypes.read_section_bytes(target, missing) == b""

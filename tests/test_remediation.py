"""Tests for reportal.remediation: string selection, rule rendering and the builder."""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FINGERPRINT, decode, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, engines, remediation, store
from reportal.remediation import (
    MIN_SPECIFIC_STRINGS,
    SNORT_ANY_PORT,
    SNORT_NO_INDICATORS_NOTE,
    SNORT_SID_BASE,
    STIX_NO_INDICATORS_NOTE,
    THREAT_SCAN_ABSENT_NOTE,
    YARA_DEFAULT_MATCH_COUNT,
    YARA_GENERIC_API_DENYLIST,
    YARA_MAX_FILESIZE,
    YARA_MAX_IMPORTS,
    YARA_MAX_STRINGS,
    YARA_MIN_IMPORT_LENGTH,
    YARA_MIN_STRING_LENGTH,
)

runner = CliRunner()

HAS_YARAC = shutil.which(remediation.YARAC_BIN) is not None
needs_yarac = pytest.mark.skipif(not HAS_YARAC, reason="yarac is not installed")

RULE_META: dict[str, Any] = {
    "date": "2026-09-12",
    "binary": "demo.exe",
    "sha256": "ab" * 32,
    "imphash": "27abfd9cfda7519d5efb3f08a2a4f3ce",
    "rich_header_hash": "deadbeefcafebabe",
}


class _StubEngine(engines.RebrewEngine):
    """Typed engine stub: fixed payloads and a call log, never a subprocess."""

    def __init__(
        self,
        *,
        strings: list[dict[str, Any]] | None = None,
        imports: list[str] | None = None,
        fingerprint: dict[str, Any] | None = None,
        error: Exception | None = None,
        available: bool = True,
    ) -> None:
        super().__init__()
        self.calls: list[str] = []
        self._strings = strings if strings is not None else []
        self._imports = imports if imports is not None else []
        self._fingerprint = fingerprint if fingerprint is not None else dict(FINGERPRINT)
        self._error = error
        self._available = available

    def available(self) -> bool:
        return self._available

    def strings(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("strings")
        if self._error is not None:
            raise self._error
        return {"strings": [dict(entry) for entry in self._strings]}

    def imports(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("imports")
        if self._error is not None:
            raise self._error
        return {
            "imports": [
                {"dll": "KERNEL32.dll", "name": name, "iat_va": "0x0"} for name in self._imports
            ]
        }

    def fingerprint(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("fingerprint")
        if self._error is not None:
            raise self._error
        return dict(self._fingerprint)


def _string(text: str, kind: str = "ascii", va: int = 0x402000) -> dict[str, Any]:
    return {"text": text, "kind": kind, "va": va, "size": len(text)}


def _seed(
    conn: sqlite3.Connection, tmp_path: Path, *, on_disk: bool = True, fingerprint: bool = False
) -> int:
    target = tmp_path / "demo.exe"
    if on_disk:
        target.write_bytes(b"MZ" + b"\x00" * 30)
    binary_id = store.add_binary(
        conn, sha256="ab" * 32, name="demo.exe", path=str(target) if on_disk else ""
    )
    if fingerprint:
        store.set_fingerprint(conn, binary_id, dict(FINGERPRINT))
    return binary_id


class TestYaraEscape:
    def test_quotes_and_backslashes_are_escaped(self) -> None:
        assert remediation.yara_escape('say "hi"') == 'say \\"hi\\"'
        assert remediation.yara_escape("a\\b") == "a\\\\b"

    def test_printable_ascii_passes_through(self) -> None:
        assert remediation.yara_escape("ABC 123 !?") == "ABC 123 !?"

    def test_non_printable_and_non_ascii_become_hex_escapes(self) -> None:
        assert remediation.yara_escape("\t") == "\\x09"
        assert remediation.yara_escape("café") == "caf\\xc3\\xa9"


class TestSanitizeRuleName:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("notepad.exe", "notepad_exe"),
            ("a b c", "a_b_c"),
            ("2fast", "rule_2fast"),
            ("rule", "rule_rule"),
            ("", "reportal_rule"),
            ("!!!", "reportal_rule"),
        ],
    )
    def test_names_are_sanitized(self, raw: str, expected: str) -> None:
        assert remediation.sanitize_rule_name(raw) == expected


class TestDistinctiveStrings:
    def test_long_unique_strings_are_selected_longest_first(self) -> None:
        entries = [
            _string("AAAAA"),
            _string("Cannot open file"),
            _string("Notepad"),
        ]
        assert remediation.distinctive_strings(entries) == ["Cannot open file", "Notepad"]

    def test_denylisted_runtime_words_are_dropped(self) -> None:
        entries = [_string("kernel32"), _string("Untitled"), _string("Distinctive marker")]
        assert remediation.distinctive_strings(entries) == ["Distinctive marker"]

    def test_short_strings_are_dropped_above_the_minimum(self) -> None:
        entries = [_string("abcde"), _string("abcdef")]
        assert remediation.distinctive_strings(entries) == ["abcdef"]

    def test_min_length_override_keeps_shorter_strings(self) -> None:
        entries = [_string("abcde")]
        assert remediation.distinctive_strings(entries, min_length=3) == ["abcde"]

    def test_duplicate_texts_collapse(self) -> None:
        entries = [_string("Distinctive marker", va=0x1000), _string("Distinctive marker")]
        assert remediation.distinctive_strings(entries) == ["Distinctive marker"]

    def test_format_specifier_junk_is_dropped(self) -> None:
        entries = [_string("%s"), _string("%d\\n"), _string("%08x: %s")]
        assert remediation.distinctive_strings(entries) == []

    def test_punctuation_and_digit_only_strings_are_dropped(self) -> None:
        entries = [_string("123456"), _string("......"), _string("Distinctive marker")]
        assert remediation.distinctive_strings(entries) == ["Distinctive marker"]

    def test_the_count_is_capped(self) -> None:
        entries = [_string(f"distinctive marker number {index}") for index in range(10)]
        assert len(remediation.distinctive_strings(entries, limit=3)) == 3

    def test_default_cap_is_the_named_constant(self) -> None:
        entries = [_string(f"distinctive marker number {index}") for index in range(40)]
        assert len(remediation.distinctive_strings(entries)) == YARA_MAX_STRINGS

    def test_entries_without_text_are_ignored(self) -> None:
        assert remediation.distinctive_strings([{"va": 0x1000}, _string("Distinctive marker")]) == [
            "Distinctive marker"
        ]


class TestDistinctiveImports:
    def test_names_are_ranked_longest_first_with_ties_reversed(self) -> None:
        names = ["Shortish", "AlphaWide", "BetaWideX", "AlphaWideXX"]
        assert remediation.distinctive_imports(names) == [
            "AlphaWideXX",
            "BetaWideX",
            "AlphaWide",
            "Shortish",
        ]

    def test_generic_api_denylist_is_dropped(self) -> None:
        names = ["GetLastError", "VirtualAlloc", "IsClipboardFormatAvailable"]
        assert remediation.distinctive_imports(names) == ["IsClipboardFormatAvailable"]

    def test_denylist_entries_are_lowercase_for_the_casefold_compare(self) -> None:
        assert YARA_GENERIC_API_DENYLIST
        assert all(name == name.casefold() for name in YARA_GENERIC_API_DENYLIST)

    def test_the_denylist_compare_is_case_insensitive(self) -> None:
        assert remediation.distinctive_imports(["GETLASTERROR", "IsClipboardFormatAvailable"]) == [
            "IsClipboardFormatAvailable"
        ]

    def test_short_names_are_dropped_below_the_minimum(self) -> None:
        names = ["MulDiv", "GetDC", "IsClipboardFormatAvailable"]
        assert remediation.distinctive_imports(names) == ["IsClipboardFormatAvailable"]

    def test_min_length_override_keeps_shorter_names(self) -> None:
        assert remediation.distinctive_imports(["MulDiv"], min_length=6) == ["MulDiv"]

    def test_duplicate_names_collapse(self) -> None:
        names = ["IsClipboardFormatAvailable", "IsClipboardFormatAvailable"]
        assert remediation.distinctive_imports(names) == ["IsClipboardFormatAvailable"]

    def test_import_count_is_capped_by_the_named_constant(self) -> None:
        names = [f"DistinctiveApiName{index:02d}" for index in range(40)]
        assert len(remediation.distinctive_imports(names)) == YARA_MAX_IMPORTS
        assert YARA_MIN_IMPORT_LENGTH > 0


class TestSpecificity:
    def test_high_with_an_imphash_and_one_string(self) -> None:
        grade = remediation.classify_specificity(has_imphash=True, string_count=1, import_count=0)
        assert grade == "high"

    def test_high_at_the_string_floor_without_an_imphash(self) -> None:
        grade = remediation.classify_specificity(
            has_imphash=False, string_count=MIN_SPECIFIC_STRINGS, import_count=0
        )
        assert grade == "high"

    def test_high_counts_strings_and_imports_together(self) -> None:
        grade = remediation.classify_specificity(
            has_imphash=False, string_count=1, import_count=MIN_SPECIFIC_STRINGS - 1
        )
        assert grade == "high"

    def test_medium_with_some_literals_below_the_floor(self) -> None:
        grade = remediation.classify_specificity(has_imphash=False, string_count=3, import_count=0)
        assert grade == "medium"

    def test_low_without_any_literal(self) -> None:
        grade = remediation.classify_specificity(has_imphash=False, string_count=0, import_count=0)
        assert grade == "low"


class TestBuildYaraRule:
    def _build(
        self, *, strings: Any, meta: Any = RULE_META, kind: str = "pe", **kwargs: Any
    ) -> str:
        return remediation.build_yara_rule(
            name="demo.exe", strings=strings, meta=meta, kind=kind, **kwargs
        )

    def test_rule_name_is_sanitized(self) -> None:
        rule = self._build(strings=[_string("Distinctive marker")])
        assert rule.startswith("rule demo_exe\n")

    def test_meta_carries_author_and_the_supplied_fields(self) -> None:
        rule = self._build(strings=[_string("Distinctive marker")])
        assert '        author = "reportal"' in rule
        for key, value in RULE_META.items():
            assert f'        {key} = "{value}"' in rule

    def test_meta_order_is_stable_with_extra_keys(self) -> None:
        meta = {**RULE_META, "extra": "1"}
        rule = self._build(strings=[_string("Distinctive marker")], meta=meta)
        assert rule.index("date =") < rule.index("binary =") < rule.index("extra =")

    def test_string_entries_are_numbered(self) -> None:
        rule = self._build(strings=[_string("First distinctive"), _string("Second distinctive")])
        assert '$s1 = "First distinctive" ascii' in rule
        assert '$s2 = "Second distinctive" ascii' in rule

    def test_wide_entries_keep_the_ascii_form_too(self) -> None:
        rule = self._build(strings=[_string("Wide literal here", kind="utf16")])
        assert '$s1 = "Wide literal here" ascii wide' in rule

    def test_pe_condition_is_anchored_on_the_mz_magic(self) -> None:
        rule = self._build(strings=[_string("Distinctive marker")], kind="pe")
        assert "uint16(0) == 0x5A4D" in rule

    def test_elf_condition_is_anchored_on_the_elf_magic(self) -> None:
        rule = self._build(strings=[_string("Distinctive marker")], kind="elf")
        assert "uint32(0) == 0x464C457F" in rule

    def test_unknown_kind_has_no_magic_anchor(self) -> None:
        rule = self._build(strings=[_string("Distinctive marker")], kind="coff")
        assert "uint16(0)" not in rule
        assert "filesize <" in rule

    def test_default_match_count_is_two(self) -> None:
        rule = self._build(strings=[_string("First distinctive"), _string("Second distinctive")])
        assert f"{YARA_DEFAULT_MATCH_COUNT} of them" in rule

    def test_match_count_is_clamped_to_the_strings_present(self) -> None:
        rule = self._build(strings=[_string("Distinctive marker")])
        assert "1 of them" in rule

    def test_match_count_can_be_raised(self) -> None:
        strings = [_string(f"distinctive marker number {index}") for index in range(3)]
        rule = self._build(strings=strings, match_count=3)
        assert "3 of them" in rule

    def test_match_count_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="match_count must be positive"):
            self._build(strings=[_string("Distinctive marker")], match_count=0)

    def test_filesize_is_bounded(self) -> None:
        rule = self._build(strings=[_string("Distinctive marker")])
        assert f"filesize < {YARA_MAX_FILESIZE}" in rule

    def test_no_strings_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one string"):
            self._build(strings=[])

    def test_output_is_deterministic(self) -> None:
        strings = [_string("First distinctive"), _string("Second distinctive")]
        assert self._build(strings=strings) == self._build(strings=strings)


class TestImphashCondition:
    def _build(self, **kwargs: Any) -> str:
        base: dict[str, Any] = {
            "name": "demo.exe",
            "strings": [_string("Distinctive marker")],
            "meta": RULE_META,
            "kind": "pe",
        }
        base.update(kwargs)
        return remediation.build_yara_rule(**base)

    def test_pe_with_imphash_imports_the_module_and_anchors_on_it(self) -> None:
        rule = self._build(imphash="deadbeef", imports=["IsClipboardFormatAvailable"])
        assert 'import "pe"' in rule
        assert 'pe.imphash() == "deadbeef"' in rule
        assert "uint16(0) == 0x5A4D" in rule

    def test_imphash_clauses_carry_the_strings_and_imports(self) -> None:
        rule = self._build(
            imphash="deadbeef",
            imports=["IsClipboardFormatAvailable", "RegisterWindowMessageW"],
        )
        assert '(pe.imphash() == "deadbeef" or 1 of ($s*) or (2 of ($i*)))' in rule

    def test_pe_with_imphash_and_no_imports_omits_the_import_clause(self) -> None:
        rule = self._build(imphash="deadbeef")
        assert "$i1" not in rule
        assert '(pe.imphash() == "deadbeef" or 1 of ($s*))' in rule

    def test_import_entries_are_numbered_after_the_strings(self) -> None:
        rule = self._build(
            imphash="deadbeef",
            imports=["IsClipboardFormatAvailable", "RegisterWindowMessageW"],
        )
        assert '$i1 = "IsClipboardFormatAvailable" ascii' in rule
        assert '$i2 = "RegisterWindowMessageW" ascii' in rule

    def test_non_pe_rule_omits_the_pe_condition(self) -> None:
        rule = self._build(kind="elf", imphash="deadbeef", imports=["IsClipboardFormatAvailable"])
        assert "pe.imphash()" not in rule
        assert 'import "pe"' not in rule
        assert "uint32(0) == 0x464C457F" in rule
        assert '$i1 = "IsClipboardFormatAvailable" ascii' in rule

    def test_pe_without_an_imphash_omits_the_pe_condition(self) -> None:
        rule = self._build(imports=["IsClipboardFormatAvailable"])
        assert "pe.imphash()" not in rule
        assert 'import "pe"' not in rule

    def test_each_match_count_is_clamped_to_its_own_literals(self) -> None:
        rule = self._build(
            imphash="deadbeef", match_count=5, imports=["IsClipboardFormatAvailable"]
        )
        assert "1 of ($s*)" in rule
        assert "(1 of ($i*))" in rule

    def test_filesize_bound_survives_the_imphash_condition(self) -> None:
        rule = self._build(imphash="deadbeef", imports=["IsClipboardFormatAvailable"])
        assert f"filesize < {YARA_MAX_FILESIZE}" in rule

    def test_the_condition_is_a_single_line(self) -> None:
        rule = self._build(imphash="deadbeef", imports=["IsClipboardFormatAvailable"])
        body = rule.split("condition:", 1)[1].strip()
        assert body.splitlines()[0].endswith(f"filesize < {YARA_MAX_FILESIZE}")

    @needs_yarac
    def test_an_imphash_rule_compiles_with_yarac(self) -> None:
        rule = self._build(
            imphash=RULE_META["imphash"],
            imports=["IsClipboardFormatAvailable", "RegisterWindowMessageW"],
        )
        assert remediation.validate_rule(rule) == {
            "validated": True,
            "validator": "yarac",
            "error": None,
        }


class TestValidateRule:
    @needs_yarac
    def test_a_good_rule_validates(self) -> None:
        rule = remediation.build_yara_rule(
            name="demo", strings=[_string("Distinctive marker")], meta=RULE_META, kind="pe"
        )
        result = remediation.validate_rule(rule)
        assert result == {"validated": True, "validator": "yarac", "error": None}

    @needs_yarac
    def test_a_broken_rule_reports_the_error(self) -> None:
        result = remediation.validate_rule("rule broken {\n condition:\n  $nope\n}\n")
        assert result["validated"] is False
        assert result["validator"] == "yarac"
        assert "nope" in str(result["error"])

    @needs_yarac
    def test_no_temporary_file_is_left_behind(self) -> None:
        rule = remediation.build_yara_rule(
            name="demo", strings=[_string("Distinctive marker")], meta=RULE_META, kind="pe"
        )
        remediation.validate_rule(rule)
        directory = remediation._scratch_dir()
        assert list(directory.glob("rule-*")) == []

    def test_without_yarac_the_rule_is_unvalidated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(remediation.shutil, "which", lambda name: None)
        result = remediation.validate_rule("rule x { condition: true }")
        assert result == {
            "validated": False,
            "validator": None,
            "error": f"{remediation.YARAC_BIN} is not installed",
        }


class TestBuildRemediation:
    def _strings(self) -> list[dict[str, Any]]:
        return [
            _string("Distinctive marker text", kind="utf16"),
            _string("error"),
            _string("short"),
        ]

    def test_rule_is_generated_from_engine_strings(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        stub = _StubEngine(strings=self._strings())
        result = remediation.build_remediation(conn, binary_id=binary_id, engine=stub)
        assert stub.calls == ["strings", "imports"]
        assert result["binary_id"] == binary_id
        assert result["rule"].startswith('import "pe"')
        assert "rule demo_exe_" in result["rule"]
        assert result["string_count"] == 1
        assert '$s1 = "Distinctive marker text" ascii wide' in result["rule"]

    def test_stored_fingerprint_is_used_without_a_fingerprint_call(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        stub = _StubEngine(strings=self._strings())
        result = remediation.build_remediation(conn, binary_id=binary_id, engine=stub)
        assert stub.calls == ["strings", "imports"]
        assert result["meta"]["sha256"] == FINGERPRINT["sha256"]
        assert result["meta"]["imphash"] == FINGERPRINT["imphash"]

    def test_fingerprint_is_built_when_absent(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(strings=self._strings())
        result = remediation.build_remediation(conn, binary_id=binary_id, engine=stub)
        assert stub.calls == ["strings", "imports", "fingerprint"]
        assert result["meta"]["sha256"] == FINGERPRINT["sha256"]

    def test_result_is_stored_as_the_remediation_scan(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        result = remediation.build_remediation(
            conn, binary_id=binary_id, engine=_StubEngine(strings=self._strings())
        )
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_REMEDIATION) == result

    def test_import_names_become_i_entries_and_are_counted(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        stub = _StubEngine(
            strings=self._strings(),
            imports=["IsClipboardFormatAvailable", "GetLastError", "MulDiv"],
        )
        result = remediation.build_remediation(conn, binary_id=binary_id, engine=stub)
        assert result["import_count"] == 1
        assert '$i1 = "IsClipboardFormatAvailable" ascii' in result["rule"]
        assert "GetLastError" not in result["rule"]
        assert "MulDiv" not in result["rule"]

    def test_imphash_anchors_the_pe_rule_and_grades_it_high(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        result = remediation.build_remediation(
            conn, binary_id=binary_id, engine=_StubEngine(strings=self._strings())
        )
        assert f'pe.imphash() == "{FINGERPRINT["imphash"]}"' in result["rule"]
        assert result["specificity"] == "high"

    def test_without_an_imphash_and_few_literals_the_rule_is_medium(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(strings=self._strings(), fingerprint={**FINGERPRINT, "imphash": None})
        result = remediation.build_remediation(conn, binary_id=binary_id, engine=stub)
        assert "pe.imphash()" not in result["rule"]
        assert result["specificity"] == "medium"

    def test_non_pe_rule_keeps_the_magic_and_omits_the_imphash(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(strings=self._strings(), fingerprint={**FINGERPRINT, "format": "elf"})
        result = remediation.build_remediation(conn, binary_id=binary_id, engine=stub)
        assert "pe.imphash()" not in result["rule"]
        assert "uint32(0) == 0x464C457F" in result["rule"]

    def test_no_usable_strings_raises_no_strings(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(strings=[_string("error"), _string("short")])
        with pytest.raises(remediation.NoStringsError, match="no distinctive strings"):
            remediation.build_remediation(conn, binary_id=binary_id, engine=stub)

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            remediation.build_remediation(
                conn, binary_id=4242, engine=_StubEngine(strings=self._strings())
            )

    def test_missing_file_raises_file_not_found(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, on_disk=False)
        with pytest.raises(FileNotFoundError, match="has no file"):
            remediation.build_remediation(
                conn, binary_id=binary_id, engine=_StubEngine(strings=self._strings())
            )

    def test_no_engine_raises_engine_unavailable(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            remediation.build_remediation(
                conn, binary_id=binary_id, engine=_StubEngine(available=False)
            )

    def test_engine_error_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("rebrew strings exited with code 3"))
        with pytest.raises(engines.EngineError, match="exited with code 3"):
            remediation.build_remediation(conn, binary_id=binary_id, engine=stub)

    def test_without_yarac_the_rule_is_stored_unvalidated(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        monkeypatch.setattr(remediation.shutil, "which", lambda name: None)
        result = remediation.build_remediation(
            conn, binary_id=binary_id, engine=_StubEngine(strings=self._strings())
        )
        assert result["validated"] is False
        assert result["validator"] is None
        assert result["notes"] == ["yarac-unavailable: the rule was stored without validation"]

    def test_payload_carries_every_key(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        result = remediation.build_remediation(
            conn, binary_id=binary_id, engine=_StubEngine(strings=self._strings())
        )
        assert set(result) == {
            "binary_id",
            "rule",
            "rule_name",
            "string_count",
            "import_count",
            "specificity",
            "validated",
            "validator",
            "meta",
            "notes",
            "snort",
            "stix",
        }


class TestRemediationRoutes:
    def _stub(self, monkeypatch: pytest.MonkeyPatch, fake_engine: engines.RebrewEngine) -> None:
        monkeypatch.setattr(
            fake_engine,
            "strings",
            lambda binary: {"strings": [_string("Distinctive marker text", kind="utf16")]},
        )
        monkeypatch.setattr(fake_engine, "fingerprint", lambda binary: dict(FINGERPRINT))

    def test_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: Any,
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        self._stub(monkeypatch, fake_engine)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/remediation")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert "rule demo_exe_" in payload["rule"]
        assert payload.pop("journal_action")
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_REMEDIATION) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/remediation")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan_makes_no_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: Any
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/remediation")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no remediation scan for binary {binary_id}" in payload["detail"]
        assert "reportal yara" in payload["detail"]
        assert fake_engine.calls == []
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: Any) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/remediation")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: Any) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/remediation")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: Any) -> None:
        binary_id = store.add_binary(conn, sha256="d2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/remediation")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/remediation")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        assert store.latest_analysis_for_binary(conn, binary_id) is None

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: Any,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew strings exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "strings", boom)
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/remediation")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]

    def test_post_404_no_strings(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: Any,
    ) -> None:
        monkeypatch.setattr(
            fake_engine, "strings", lambda binary: {"strings": [_string("error"), _string("abc")]}
        )
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/remediation")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-strings"
        assert str(YARA_MIN_STRING_LENGTH) in payload["detail"]


class TestYaraCommand:
    def _seed(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="cd" * 32, name="demo.exe", path=str(target))

    def _install(self, strings: list[dict[str, Any]] | None = None) -> _StubEngine:
        stub = _StubEngine(strings=strings or [_string("Distinctive marker text", kind="utf16")])
        engines.set_engine(stub)
        return stub

    def test_json_stores_and_prints(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install()
        result = runner.invoke(cli.app, ["yara", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert "rule demo_exe_" in payload["rule"]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        payload.pop("journal_action", None)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_REMEDIATION) == payload

    def test_json_carries_the_counts_and_specificity(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install()
        result = runner.invoke(cli.app, ["yara", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["import_count"] == 0
        assert payload["specificity"] == "high"

    def test_human_mode_prints_the_rule(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install()
        result = runner.invoke(cli.app, ["yara", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert result.stdout.startswith('import "pe"')
        assert "condition:" in result.stdout
        assert "pe.imphash()" in result.stdout

    def test_human_mode_reports_specificity_on_stderr(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install()
        result = runner.invoke(cli.app, ["yara", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "specificity: high" in result.stderr
        assert "1 strings, 0 imports" in result.stderr

    def test_output_writes_the_rule_atomically(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install()
        target = tmp_path / "out" / "demo.yar"
        result = runner.invoke(cli.app, ["yara", str(binary_id), "--output", str(target)])
        assert result.exit_code == 0, result.output
        assert str(target) in result.stderr
        assert result.stdout == ""
        assert target.is_file()
        text = target.read_text(encoding="utf-8")
        assert text.startswith('import "pe"')
        assert "condition:" in text
        if HAS_YARAC:
            assert remediation.validate_rule(text)["validated"] is True

    def test_without_engine_fails(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = self._seed(conn, tmp_path)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["yara", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "unavailable" in result.stdout

    def test_unknown_binary_fails(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        self._install()
        result = runner.invoke(cli.app, ["yara", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.stdout

    def test_no_strings_fails(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install(strings=[_string("error")])
        result = runner.invoke(cli.app, ["yara", str(binary_id), "--json"])
        assert result.exit_code == 1
        assert "no distinctive strings" in result.stdout


# ── Snort and STIX builders ────────────────────────────────────────


def _ioc(value: str, kind: str, va: int = 0x402000) -> dict[str, Any]:
    return {"value": value, "kind": kind, "source_va": va}


def _iocs(**categories: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return {name: list(entries) for name, entries in categories.items()}


def _protocols_scan(*pairs: tuple[str, list[int]]) -> dict[str, Any]:
    """A payload shaped like the stored `protocols` scan for the given families."""
    return {
        "protocols": [
            {
                "protocol": name,
                "description": name.upper(),
                "confidence": "high",
                "evidence": [],
                "ports": ports,
            }
            for name, ports in pairs
        ]
    }


def _seed_scan(
    conn: sqlite3.Connection, binary_id: int, kind: str, payload: dict[str, Any]
) -> None:
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, kind, payload)


def _seed_threat(
    conn: sqlite3.Connection, binary_id: int, iocs: dict[str, list[dict[str, Any]]]
) -> None:
    _seed_scan(conn, binary_id, store.SCAN_KIND_THREAT, {"binary_id": binary_id, "iocs": iocs})


class TestSnortEscape:
    def test_quotes_backslashes_and_pipes_are_escaped(self) -> None:
        assert remediation.snort_escape('say "hi"') == 'say \\"hi\\"'
        assert remediation.snort_escape("a\\b") == "a\\\\b"
        assert remediation.snort_escape("a|b") == "a\\|b"

    def test_plain_text_passes_through(self) -> None:
        assert remediation.snort_escape("evil.example.com") == "evil.example.com"


class TestBuildSnortRule:
    def test_a_url_rule_uses_the_scheme_port_from_the_protocol_scan(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("http://evil.example.com/x", "url")]),
            meta={"protocols": _protocols_scan(("http", [80]))},
        )
        assert len(result["rules"]) == 1
        rule = result["rules"][0]
        assert rule["sid"] == SNORT_SID_BASE
        assert rule["family"] == "url"
        assert rule["host"] == "evil.example.com"
        assert rule["port"] == 80
        assert "-> $EXTERNAL_NET 80 " in result["text"]

    def test_a_domain_without_a_protocol_scan_uses_any_port(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(domains=[_ioc("evil.example.com", "domain")]),
            meta={},
        )
        assert result["rules"][0]["port"] is None
        assert f"-> $EXTERNAL_NET {SNORT_ANY_PORT} " in result["text"]

    def test_an_ipv4_port_comes_from_the_protocol_scan(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(ipv4=[_ioc("1.2.3.4", "ipv4")]),
            meta={"protocols": _protocols_scan(("ssh", [22]))},
        )
        assert result["rules"][0]["port"] == 22

    def test_an_ipv6_finding_emits_a_rule(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(ipv6=[_ioc("2001:db8::1", "ipv6")]),
            meta={},
        )
        assert result["rules"][0]["family"] == "ipv6"
        assert 'content:"2001:db8::1"; http_header;' in result["text"]

    def test_an_explicit_url_port_wins_over_the_scan(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("http://evil.example.com:8080/x", "url")]),
            meta={"protocols": _protocols_scan(("http", [80]))},
        )
        assert result["rules"][0]["port"] == 8080

    def test_the_rule_carries_the_expected_shape(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("https://evil.example.com/p", "url")]),
            meta={},
        )
        text = result["text"]
        assert text.startswith("alert tcp $HOME_NET any -> $EXTERNAL_NET ")
        assert '(msg:"demo.exe url https://evil.example.com/p";' in text
        assert "flow:established,to_server;" in text
        assert 'content:"evil.example.com"; http_header;' in text
        assert f"sid:{SNORT_SID_BASE}; rev:1;)" in text
        assert text.endswith("\n")

    def test_sids_count_up_from_the_base_in_family_order(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(
                urls=[_ioc("http://b.example.com/", "url")],
                domains=[_ioc("a.example.com", "domain")],
                ipv4=[_ioc("1.2.3.4", "ipv4")],
            ),
            meta={},
        )
        assert [rule["family"] for rule in result["rules"]] == ["url", "domain", "ipv4"]
        assert [rule["sid"] for rule in result["rules"]] == [
            SNORT_SID_BASE,
            SNORT_SID_BASE + 1,
            SNORT_SID_BASE + 2,
        ]

    def test_values_are_sorted_within_a_family(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(
                domains=[_ioc("b.example.com", "domain"), _ioc("a.example.com", "domain")]
            ),
            meta={},
        )
        assert [rule["value"] for rule in result["rules"]] == [
            "a.example.com",
            "b.example.com",
        ]

    def test_two_builds_are_byte_identical(self) -> None:
        indicators = _iocs(
            urls=[_ioc("http://evil.example.com/x", "url")],
            ipv4=[_ioc("1.2.3.4", "ipv4")],
        )
        meta = {"protocols": _protocols_scan(("http", [80]))}
        first = remediation.build_snort_rule(name="demo.exe", indicators=indicators, meta=meta)
        second = remediation.build_snort_rule(name="demo.exe", indicators=indicators, meta=meta)
        assert first == second

    def test_no_network_indicators_returns_the_empty_result(self) -> None:
        result = remediation.build_snort_rule(
            name="demo.exe",
            indicators=_iocs(hashes=[_ioc("ab" * 32, "sha256")]),
            meta={},
        )
        assert result["rules"] == []
        assert result["text"] == ""
        assert result["notes"] == [SNORT_NO_INDICATORS_NOTE]
        assert result["notes"][0].startswith("no network indicators")


class TestBuildStixBundle:
    def _meta(self) -> dict[str, Any]:
        return {"date": "2026-09-12"}

    def test_a_missing_date_follows_store_now(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(store, "now", lambda: "2026-05-20T18:00:00+00:00")
        bundle = remediation.build_stix_bundle(name="demo.exe", indicators={}, meta={})
        identities = [obj for obj in bundle["objects"] if obj["type"] == "identity"]
        assert identities[0]["created"] == "2026-05-20T00:00:00Z"
        meta = remediation._fingerprint_meta({"name": "demo.exe"}, {})
        assert meta["date"] == "2026-05-20"

    @pytest.mark.parametrize(
        "date",
        [
            "2026-02-29",
            "2100-02-29",
            "2026-04-31",
            "01/02/03",
            "not-a-date",
            "2026-02-29T12:00:00Z",
        ],
    )
    def test_invalid_dates_fall_back_to_today_utc(
        self, date: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(store, "now", lambda: "2026-05-20T18:00:00+00:00")
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("http://evil.example.com/x", "url")]),
            meta={"date": date},
        )
        for obj in bundle["objects"]:
            assert obj["created"] == "2026-05-20T00:00:00Z"
            assert obj["modified"] == "2026-05-20T00:00:00Z"
            if obj["type"] == "indicator":
                assert obj["valid_from"] == "2026-05-20T00:00:00Z"

    @pytest.mark.parametrize("date", ["2000-02-29", "2024-02-29"])
    def test_valid_leap_days_are_preserved(self, date: str) -> None:
        bundle = remediation.build_stix_bundle(name="demo.exe", indicators={}, meta={"date": date})
        for obj in bundle["objects"]:
            assert obj["created"] == f"{date}T00:00:00Z"
            assert obj["modified"] == f"{date}T00:00:00Z"

    def test_the_bundle_wrapper_is_stix_21(self) -> None:
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("http://evil.example.com/x", "url")]),
            meta=self._meta(),
        )
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert str(bundle["id"]).startswith("bundle--")
        assert isinstance(bundle["objects"], list)

    def test_the_identity_object_names_reportal(self) -> None:
        bundle = remediation.build_stix_bundle(name="demo.exe", indicators={}, meta=self._meta())
        identities = [obj for obj in bundle["objects"] if obj["type"] == "identity"]
        assert len(identities) == 1
        assert identities[0]["name"] == "reportal"
        assert identities[0]["identity_class"] == "system"
        assert str(identities[0]["id"]).startswith("identity--")

    def test_one_indicator_object_per_ioc(self) -> None:
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(
                urls=[_ioc("http://evil.example.com/x", "url")],
                domains=[_ioc("evil.example.com", "domain")],
                ipv4=[_ioc("1.2.3.4", "ipv4")],
                emails=[_ioc("a@evil.example.com", "email")],
                hashes=[_ioc("ab" * 32, "sha256")],
            ),
            meta=self._meta(),
        )
        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert len(indicators) == 5
        assert all(obj["pattern_type"] == "stix" for obj in indicators)
        assert all(str(obj["id"]).startswith("indicator--") for obj in indicators)

    def test_patterns_match_their_category(self) -> None:
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(
                urls=[_ioc("http://evil.example.com/x", "url")],
                domains=[_ioc("evil.example.com", "domain")],
                ipv4=[_ioc("1.2.3.4", "ipv4")],
                hashes=[_ioc("ab" * 32, "sha256")],
            ),
            meta=self._meta(),
        )
        patterns = [str(obj["pattern"]) for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert "[url:value = 'http://evil.example.com/x']" in patterns
        assert (
            "[network-traffic:dst_ref.type = 'domain-name' AND "
            "network-traffic:dst_ref.value = 'evil.example.com']"
        ) in patterns
        assert "[ipv4-addr:value = '1.2.3.4']" in patterns
        assert "[file:hashes.'SHA-256' = '" + "ab" * 32 + "']" in patterns

    def test_an_ipv6_finding_emits_an_ipv6_pattern(self) -> None:
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(ipv6=[_ioc("2001:db8::1", "ipv6")]),
            meta=self._meta(),
        )
        patterns = [str(obj["pattern"]) for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert patterns == ["[ipv6-addr:value = '2001:db8::1']"]

    def test_the_hash_kind_selects_the_stix_property(self) -> None:
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(hashes=[_ioc("cd" * 16, "md5"), _ioc("ef" * 20, "sha1")]),
            meta=self._meta(),
        )
        patterns = [str(obj["pattern"]) for obj in bundle["objects"] if obj["type"] == "indicator"]
        assert "[file:hashes.'MD5' = '" + "cd" * 16 + "']" in patterns
        assert "[file:hashes.'SHA-1' = '" + "ef" * 20 + "']" in patterns

    def test_the_timestamps_come_from_the_supplied_date(self) -> None:
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("http://evil.example.com/x", "url")]),
            meta=self._meta(),
        )
        indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
        assert indicator["valid_from"] == "2026-09-12T00:00:00Z"
        assert indicator["created"] == "2026-09-12T00:00:00Z"
        assert indicator["modified"] == "2026-09-12T00:00:00Z"

    def test_aware_meta_dates_normalize_to_utc_z(self) -> None:
        # A US Eastern wall time must not freeze as -04:00 in the bundle: STIX
        # consumers that assume Z would shift the instant by four hours.
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("http://evil.example.com/x", "url")]),
            meta={"date": "2026-09-12T12:00:00-04:00"},
        )
        indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
        assert indicator["valid_from"] == "2026-09-12T16:00:00Z"
        assert indicator["created"] == "2026-09-12T16:00:00Z"
        # +00:00 and Z for the same instant must stay byte-identical to a bare date.
        via_offset = remediation.build_stix_bundle(
            name="demo.exe", indicators={}, meta={"date": "2026-09-12T00:00:00+00:00"}
        )
        via_date = remediation.build_stix_bundle(
            name="demo.exe", indicators={}, meta={"date": "2026-09-12"}
        )
        assert via_offset == via_date

    def test_ids_are_deterministic_across_builds(self) -> None:
        indicators = _iocs(urls=[_ioc("http://evil.example.com/x", "url")])
        first = remediation.build_stix_bundle(
            name="demo.exe", indicators=indicators, meta=self._meta()
        )
        second = remediation.build_stix_bundle(
            name="demo.exe", indicators=indicators, meta=self._meta()
        )
        assert first == second
        first_ids = sorted(str(obj["id"]) for obj in first["objects"])
        second_ids = sorted(str(obj["id"]) for obj in second["objects"])
        assert first_ids == second_ids

    def test_no_indicators_carries_a_note_object(self) -> None:
        bundle = remediation.build_stix_bundle(name="demo.exe", indicators={}, meta=self._meta())
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        assert len(notes) == 1
        assert notes[0]["content"] == STIX_NO_INDICATORS_NOTE

    def test_unsupported_categories_are_reported_in_a_note(self) -> None:
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(registry_paths=[_ioc("HKLM\\Software\\Run", "registry")]),
            meta=self._meta(),
        )
        assert not [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        assert any("registry_paths" in str(note["content"]) for note in notes)

    def test_as_json_round_trips_and_is_stable(self) -> None:
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("http://evil.example.com/x", "url")]),
            meta=self._meta(),
        )
        text = remediation.as_json(bundle)
        assert json.loads(text) == bundle
        assert text == remediation.as_json(bundle)
        assert text.endswith("\n")


class TestBuildRemediationArtifacts:
    def _strings(self) -> list[dict[str, Any]]:
        return [_string("Distinctive marker text", kind="utf16")]

    def test_the_rule_keys_survive_and_the_artifacts_are_added(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        result = remediation.build_remediation(
            conn, binary_id=binary_id, engine=_StubEngine(strings=self._strings())
        )
        assert result["rule"].startswith('import "pe"')
        assert result["specificity"] == "high"
        assert result["validated"] is False or isinstance(result["validated"], bool)
        assert isinstance(result["snort"], dict)
        assert isinstance(result["stix"], dict)
        assert result["stix"]["type"] == "bundle"

    def test_the_stored_threat_scan_drives_both_artifacts_without_an_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        _seed_threat(conn, binary_id, _iocs(urls=[_ioc("https://evil.example.com/x", "url")]))
        _seed_scan(
            conn,
            binary_id,
            store.SCAN_KIND_PROTOCOLS,
            _protocols_scan(("https", [443])),
        )
        stub = _StubEngine(strings=self._strings())
        result = remediation.build_remediation(conn, binary_id=binary_id, engine=stub)
        assert stub.calls == ["strings", "imports"]
        assert result["snort"]["rules"][0]["sid"] == SNORT_SID_BASE
        assert result["snort"]["rules"][0]["port"] == 443
        assert result["snort"]["notes"] == []
        patterns = [
            str(obj["pattern"]) for obj in result["stix"]["objects"] if obj["type"] == "indicator"
        ]
        assert "[url:value = 'https://evil.example.com/x']" in patterns

    def test_an_absent_threat_scan_is_noted_in_the_snort_artifact(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, fingerprint=True)
        result = remediation.build_remediation(
            conn, binary_id=binary_id, engine=_StubEngine(strings=self._strings())
        )
        assert result["snort"]["notes"] == [THREAT_SCAN_ABSENT_NOTE, SNORT_NO_INDICATORS_NOTE]
        assert result["snort"]["rules"] == []
        notes = [obj for obj in result["stix"]["objects"] if obj["type"] == "note"]
        assert notes and notes[0]["content"] == STIX_NO_INDICATORS_NOTE


class TestRemediationFormatRoutes:
    def test_get_yara_serves_the_rule_as_text(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        rule = "rule demo {\n    condition:\n        true\n}\n"
        _seed_scan(conn, binary_id, store.SCAN_KIND_REMEDIATION, {"rule": rule, "notes": []})
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/remediation/yara")
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("text/plain")
        assert decode(body, headers).decode("utf-8") == rule

    def test_get_snort_serves_the_rules_as_text(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        text = "alert tcp $HOME_NET any -> $EXTERNAL_NET any (sid:1000000; rev:1;)\n"
        _seed_scan(
            conn,
            binary_id,
            store.SCAN_KIND_REMEDIATION,
            {"snort": {"rules": [{"sid": 1000000}], "text": text, "notes": []}},
        )
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/remediation/snort")
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("text/plain")
        assert decode(body, headers).decode("utf-8") == text

    def test_get_stix_serves_the_bundle_as_json(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        bundle = remediation.build_stix_bundle(
            name="demo.exe",
            indicators=_iocs(urls=[_ioc("http://evil.example.com/x", "url")]),
            meta={"date": "2026-09-12"},
        )
        _seed_scan(conn, binary_id, store.SCAN_KIND_REMEDIATION, {"stix": bundle})
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/remediation/stix")
        assert status.startswith("200")
        assert headers["Content-Type"].startswith("application/json")
        assert json_body(body, headers) == bundle

    def test_a_snort_artifact_with_no_rules_serves_an_empty_body(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _seed_scan(
            conn,
            binary_id,
            store.SCAN_KIND_REMEDIATION,
            {"snort": {"rules": [], "text": "", "notes": [SNORT_NO_INDICATORS_NOTE]}},
        )
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/remediation/snort")
        assert status.startswith("200")
        assert decode(body, headers) == b""

    def test_a_payload_without_the_piece_404_no_artifact(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _seed_scan(conn, binary_id, store.SCAN_KIND_REMEDIATION, {"rule": "rule x {}"})
        for fmt in ("snort", "stix"):
            status, headers, body = wsgi_request(
                "GET", f"/api/binaries/{binary_id}/remediation/{fmt}"
            )
            assert status.startswith("404")
            assert json_body(body, headers)["error"] == "no-artifact"

    def test_an_unknown_format_404(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        _seed_scan(conn, binary_id, store.SCAN_KIND_REMEDIATION, {"rule": "rule x {}"})
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/remediation/car")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "format-not-found"
        assert "car" in payload["detail"]

    def test_an_absent_scan_404_no_scan(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/remediation/yara")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_an_unknown_binary_404(self, portal_db: Path) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/remediation/yara")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"


class TestSnortStixCommands:
    def _seed(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="ee" * 32, name="demo.exe", path=str(target))

    def _install(self) -> _StubEngine:
        stub = _StubEngine(strings=[_string("Distinctive marker text", kind="utf16")])
        engines.set_engine(stub)
        return stub

    def test_snort_prints_the_rules_and_stores_the_scan(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        _seed_threat(conn, binary_id, _iocs(urls=[_ioc("http://evil.example.com/x", "url")]))
        self._install()
        result = runner.invoke(cli.app, ["snort", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert result.stdout.startswith("alert tcp $HOME_NET any -> $EXTERNAL_NET ")
        assert f"sid:{SNORT_SID_BASE}" in result.stdout
        assert "1 Snort rules" in result.stderr
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        stored = store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_REMEDIATION)
        assert stored is not None
        assert stored["snort"]["rules"][0]["sid"] == SNORT_SID_BASE

    def test_snort_output_writes_the_rules_atomically(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        _seed_threat(conn, binary_id, _iocs(ipv4=[_ioc("1.2.3.4", "ipv4")]))
        self._install()
        target = tmp_path / "out" / "demo.rules"
        result = runner.invoke(cli.app, ["snort", str(binary_id), "--output", str(target)])
        assert result.exit_code == 0, result.output
        assert str(target) in result.stderr
        assert result.stdout == ""
        assert target.is_file()
        assert target.read_text(encoding="utf-8").startswith("alert tcp ")

    def test_stix_json_prints_the_bundle(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = self._seed(conn, tmp_path)
        _seed_threat(conn, binary_id, _iocs(urls=[_ioc("http://evil.example.com/x", "url")]))
        self._install()
        result = runner.invoke(cli.app, ["stix", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["stix"]["type"] == "bundle"
        indicators = [obj for obj in payload["stix"]["objects"] if obj["type"] == "indicator"]
        assert "[url:value = 'http://evil.example.com/x']" in [obj["pattern"] for obj in indicators]

    def test_stix_output_writes_the_bundle(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install()
        target = tmp_path / "out" / "demo.json"
        result = runner.invoke(cli.app, ["stix", str(binary_id), "--output", str(target)])
        assert result.exit_code == 0, result.output
        assert str(target) in result.stderr
        assert result.stdout == ""
        bundle = json.loads(target.read_text(encoding="utf-8"))
        assert bundle["type"] == "bundle"

    def test_snort_without_network_indicators_notes_the_empty_case(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install()
        result = runner.invoke(cli.app, ["snort", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert result.stdout == ""
        assert SNORT_NO_INDICATORS_NOTE in result.stderr
        assert THREAT_SCAN_ABSENT_NOTE in result.stderr
        assert "0 Snort rules" in result.stderr

    def test_stix_without_indicators_still_prints_a_bundle_with_a_note(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = self._seed(conn, tmp_path)
        self._install()
        result = runner.invoke(cli.app, ["stix", str(binary_id)])
        assert result.exit_code == 0, result.output
        bundle = json.loads(result.stdout)
        assert bundle["type"] == "bundle"
        notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
        assert notes and notes[0]["content"] == STIX_NO_INDICATORS_NOTE
        assert "0 STIX indicators" in result.stderr

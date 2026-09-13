"""Tests for threat's software-type classifier and analysis-level threat score."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from reportal import capabilities, store, threat
from reportal.threat import (
    MAX_EVIDENCE_PER_CONTRIBUTION,
    MAX_SIGNALS_PER_TYPE,
    SCORE_MAX,
)

# One constructed evidence set per software type, with the signal kinds the
# rule is expected to fire on.
TYPE_EVIDENCE: dict[str, tuple[dict[str, Any], set[str]]] = {
    threat.SOFTWARE_TYPE_RANSOMWARE: (
        {
            "imports": [{"dll": "advapi32.dll", "name": "CryptEncrypt"}],
            "capabilities": [{"name": "crypto"}, {"name": "file-io"}],
        },
        {threat.SIGNAL_IMPORT, threat.SIGNAL_CAPABILITY},
    ),
    threat.SOFTWARE_TYPE_KEYLOGGER: (
        {
            "imports": [
                {"dll": "user32.dll", "name": "SetWindowsHookExA"},
                {"dll": "user32.dll", "name": "GetAsyncKeyState"},
            ]
        },
        {threat.SIGNAL_IMPORT},
    ),
    threat.SOFTWARE_TYPE_COINMINER: (
        {"strings": [{"text": "stratum+tcp://pool.example.com:3333"}]},
        {threat.SIGNAL_STRING},
    ),
    threat.SOFTWARE_TYPE_DOWNLOADER: (
        {
            "imports": [
                {"dll": "urlmon.dll", "name": "URLDownloadToFileA"},
                {"dll": "wininet.dll", "name": "InternetReadFile"},
            ]
        },
        {threat.SIGNAL_IMPORT},
    ),
    threat.SOFTWARE_TYPE_INSTALLER: (
        {"filetype": {"matches": [{"name": "NSIS", "category": "installer", "confidence": "low"}]}},
        {threat.SIGNAL_FILETYPE},
    ),
    threat.SOFTWARE_TYPE_MANAGED: (
        {
            "filetype": {
                "matches": [{"name": ".NET", "category": "runtime", "confidence": "medium"}]
            },
            "dlls": ["mscoree.dll"],
        },
        {threat.SIGNAL_FILETYPE, threat.SIGNAL_DLL},
    ),
    threat.SOFTWARE_TYPE_PACKED: (
        {"filetype": {"matches": [{"name": "UPX", "category": "packer", "confidence": "high"}]}},
        {threat.SIGNAL_FILETYPE},
    ),
}


def _seed(conn: sqlite3.Connection, tmp_path: Path) -> int:
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ" + b"\x00" * 30)
    return store.add_binary(conn, sha256="cd" * 32, name="demo.exe", path=str(target))


def _scan(
    conn: sqlite3.Connection,
    binary_id: int,
    kind: str,
    payload: dict[str, Any],
) -> None:
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, kind, payload)


class TestClassifySoftware:
    def test_the_vocabulary_matches_the_rule_table(self) -> None:
        declared = [rule.software_type for rule in threat.SOFTWARE_TYPE_RULES]
        assert declared == list(threat.SOFTWARE_TYPES)
        assert len(declared) == len(set(declared))

    @pytest.mark.parametrize("software_type", list(TYPE_EVIDENCE))
    def test_each_type_fires_on_its_own_evidence(self, software_type: str) -> None:
        evidence, expected_kinds = TYPE_EVIDENCE[software_type]
        result = threat.classify_software(evidence)
        assert result["type"] == software_type
        assert result["description"]
        assert {signal["kind"] for signal in result["signals"]} == expected_kinds
        assert all(signal["value"] for signal in result["signals"])

    def test_two_independent_signal_kinds_are_high_confidence(self) -> None:
        result = threat.classify_software(TYPE_EVIDENCE[threat.SOFTWARE_TYPE_MANAGED][0])
        assert result["confidence"] == threat.CONFIDENCE_HIGH

    def test_a_lone_string_marker_is_low_confidence(self) -> None:
        result = threat.classify_software({"strings": [{"text": "Inno Setup Setup Data"}]})
        assert result["type"] == threat.SOFTWARE_TYPE_INSTALLER
        assert result["confidence"] == threat.CONFIDENCE_LOW

    def test_a_capability_tag_never_names_a_type_on_its_own(self) -> None:
        result = threat.classify_software(
            {"capabilities": [{"name": "crypto"}, {"name": "registry"}]}
        )
        assert result["type"] is None
        assert result["signals"] == []

    def test_a_capability_lifts_the_confidence_of_a_named_type(self) -> None:
        bare = threat.classify_software({"imports": [{"name": "URLDownloadToFileA"}]})
        assert bare["type"] is None
        supported = threat.classify_software(
            {
                "imports": [
                    {"name": "URLDownloadToFileA"},
                    {"name": "InternetReadFile"},
                ],
                "capabilities": [{"name": "networking"}],
            }
        )
        assert supported["type"] == threat.SOFTWARE_TYPE_DOWNLOADER
        assert supported["confidence"] == threat.CONFIDENCE_HIGH

    def test_min_signals_keeps_a_shared_api_from_naming_a_type(self) -> None:
        one_hook = threat.classify_software({"imports": [{"name": "SetWindowsHookExA"}]})
        assert one_hook["type"] is None

    def test_no_match_answers_none_with_the_reason(self) -> None:
        result = threat.classify_software({})
        assert result["type"] is None
        assert result["confidence"] is None
        assert result["signals"] == []
        assert threat.TYPE_EMPTY_NOTE in result["notes"]
        assert threat.TYPE_SCOPE_NOTE in result["notes"]

    def test_signals_deduplicate_and_stay_capped(self) -> None:
        evidence = {
            "imports": [
                {"name": "SetWindowsHookExA"},
                {"name": "SetWindowsHookExA"},
                {"name": "GetAsyncKeyState"},
            ]
        }
        result = threat.classify_software(evidence)
        values = [signal["value"] for signal in result["signals"]]
        assert values == ["SetWindowsHookExA", "GetAsyncKeyState"]
        assert len(result["signals"]) <= MAX_SIGNALS_PER_TYPE

    def test_the_triage_dossier_strings_are_read(self) -> None:
        result = threat.classify_software({"triage": {"strings": {"top": [{"text": "xmrig"}]}}})
        assert result["type"] == threat.SOFTWARE_TYPE_COINMINER
        assert result["signals"] == [{"kind": threat.SIGNAL_STRING, "value": "xmrig"}]

    def test_the_triage_dossier_dlls_are_read(self) -> None:
        result = threat.classify_software({"triage": {"imports": {"dlls": ["mscoree.dll"]}}})
        assert result["type"] == threat.SOFTWARE_TYPE_MANAGED
        assert result["signals"] == [{"kind": threat.SIGNAL_DLL, "value": "mscoree.dll"}]

    def test_evidence_sources_name_what_was_read(self) -> None:
        result = threat.classify_software(
            {
                "filetype": {"matches": [{"name": "UPX", "category": "packer"}]},
                "capabilities": [{"name": "crypto"}],
                "techniques": [{"id": "T1486"}],
            }
        )
        assert result["evidence_sources"] == ["filetype", "capabilities", "threat"]


class TestScoreThreat:
    def test_no_evidence_answers_null_with_the_reason(self) -> None:
        result = threat.score_threat({})
        assert result["score"] is None
        assert result["band"] is None
        assert result["contributions"] == []
        assert result["evidence_sources"] == []
        assert result["max"] == SCORE_MAX
        assert threat.SCORE_EMPTY_NOTE in result["notes"]
        assert threat.SCORE_SCOPE_NOTE in result["notes"]

    def test_contributions_are_named_and_sum_to_the_score(self) -> None:
        result = threat.score_threat(
            {
                "filetype": {"matches": [{"name": "UPX", "category": "packer"}]},
                "capabilities": [{"name": "networking"}, {"name": "persistence"}],
                "iocs": {threat.IOC_CATEGORY_URLS: [{"value": "https://c2"}], "domains": []},
                "techniques": [{"id": "T1071", "confidence": "medium"}],
            }
        )
        names = [entry["name"] for entry in result["contributions"]]
        assert names == [
            threat.CONTRIBUTION_PACKING,
            threat.CONTRIBUTION_CAPABILITIES,
            threat.CONTRIBUTION_INDICATORS,
            threat.CONTRIBUTION_TECHNIQUES,
        ]
        assert result["score"] == sum(entry["points"] for entry in result["contributions"])
        assert all(entry["evidence"] for entry in result["contributions"])
        assert result["band"] == threat.score_band(result["score"] or 0)

    def test_one_ioc_category_counts_once_whatever_its_size(self) -> None:
        small = threat.score_threat({"iocs": {threat.IOC_CATEGORY_URLS: [{"value": "a"}]}})
        large = threat.score_threat(
            {"iocs": {threat.IOC_CATEGORY_URLS: [{"value": str(index)} for index in range(50)]}}
        )
        assert small["score"] == large["score"]

    def test_the_score_is_bounded_by_the_maximum(self) -> None:
        result = threat.score_threat(
            {
                "filetype": {
                    "matches": [
                        {"name": "UPX", "category": "packer"},
                        {"name": "Themida", "category": "protector"},
                        {"name": "VMProtect", "category": "protector"},
                    ]
                },
                "capabilities": [{"name": name} for name in capabilities.CAPABILITIES],
                "iocs": {category: [{"value": "x"}] for category in threat.IOC_CATEGORIES},
                "techniques": [
                    {"id": "T1055", "confidence": "high"},
                    {"id": "T1059", "confidence": "high"},
                    {"id": "T1071", "confidence": "high"},
                    {"id": "T1041", "confidence": "high"},
                    {"id": "T1082", "confidence": "high"},
                ],
            }
        )
        assert result["score"] == SCORE_MAX
        assert result["band"] == threat.SCORE_BAND_CRITICAL

    def test_a_low_weight_source_still_scores_above_zero(self) -> None:
        result = threat.score_threat({"capabilities": [{"name": "console"}]})
        assert result["score"] == threat.CAPABILITY_POINTS["console"]
        assert result["evidence_sources"] == ["capabilities"]

    def test_an_unlisted_capability_takes_the_default(self) -> None:
        result = threat.score_threat({"capabilities": [{"name": "third-party-tag"}]})
        assert result["score"] == threat.DEFAULT_CAPABILITY_POINTS

    def test_an_empty_category_is_not_evidence(self) -> None:
        result = threat.score_threat({"iocs": {threat.IOC_CATEGORY_URLS: []}})
        assert result["score"] is None
        assert result["evidence_sources"] == []

    def test_an_unknown_indicator_category_takes_the_default(self) -> None:
        result = threat.score_threat({"iocs": {"third-party-category": [{"value": "x"}]}})
        assert result["score"] == threat.DEFAULT_IOC_POINTS
        assert result["contributions"][0]["evidence"] == ["third-party-category: 1"]

    @pytest.mark.parametrize(
        ("score", "band"),
        [
            (0, threat.SCORE_BAND_LOW),
            (24, threat.SCORE_BAND_LOW),
            (25, threat.SCORE_BAND_MODERATE),
            (49, threat.SCORE_BAND_MODERATE),
            (50, threat.SCORE_BAND_HIGH),
            (74, threat.SCORE_BAND_HIGH),
            (75, threat.SCORE_BAND_CRITICAL),
            (100, threat.SCORE_BAND_CRITICAL),
        ],
    )
    def test_the_band_floors_are_the_documented_scale(self, score: int, band: str) -> None:
        assert threat.score_band(score) == band

    def test_every_capability_tag_has_a_weight(self) -> None:
        assert {entry.name for entry in capabilities.CAPABILITIES} <= set(threat.CAPABILITY_POINTS)

    def test_every_ioc_category_has_a_weight(self) -> None:
        assert set(threat.IOC_CATEGORIES) == set(threat.IOC_POINTS)

    def test_contribution_evidence_is_capped(self) -> None:
        names = list(threat.CAPABILITY_POINTS) * 4
        result = threat.score_threat({"capabilities": [{"name": name} for name in names]})
        for entry in result["contributions"]:
            assert len(entry["evidence"]) <= MAX_EVIDENCE_PER_CONTRIBUTION


class TestClassifyBinary:
    def test_stored_scans_are_read_into_the_evidence(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _scan(
            conn,
            binary_id,
            store.SCAN_KIND_FILETYPE,
            {"matches": [{"name": "UPX", "category": "packer", "confidence": "high"}]},
        )
        _scan(
            conn,
            binary_id,
            store.SCAN_KIND_CAPABILITIES,
            {"capabilities": [{"name": "crypto"}]},
        )
        _scan(
            conn,
            binary_id,
            store.SCAN_KIND_THREAT,
            {"iocs": {threat.IOC_CATEGORY_URLS: [{"value": "https://c2"}]}, "techniques": []},
        )
        _scan(
            conn,
            binary_id,
            store.SCAN_KIND_TRIAGE,
            {"strings": {"top": [{"text": "xmrig"}]}},
        )
        evidence = threat.stored_evidence(conn, binary_id)
        assert threat.evidence_sources(evidence) == [
            "filetype",
            "capabilities",
            "threat",
            "triage",
        ]
        classified = threat.classify_binary(conn, binary_id)
        assert classified["software_type"]["type"] == threat.SOFTWARE_TYPE_COINMINER
        assert classified["threat_score"]["score"] is not None
        assert classified["threat_score"]["contributions"]

    def test_a_binary_without_an_analysis_has_empty_evidence(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        assert threat.stored_evidence(conn, binary_id) == {
            "filetype": {},
            "capabilities": [],
            "imports": [],
            "strings": [],
            "iocs": {},
            "techniques": [],
            "triage": {},
        }
        classified = threat.classify_binary(conn, binary_id)
        assert classified["software_type"]["type"] is None
        assert classified["threat_score"]["score"] is None

    def test_a_real_threat_report_feeds_the_classifier(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        engine = _StubEngine(
            imports=[{"dll": "advapi32.dll", "name": "CryptEncrypt"}],
            strings=[
                {"text": "Your files have been encrypted. Pay 1 bitcoin.", "va": 0x1000},
                {"text": "https://pay.example.com/unlock", "va": 0x2000},
            ],
        )
        threat.build_threat_report(conn, binary_id=binary_id, engine=engine)
        classified = threat.classify_binary(conn, binary_id)
        assert classified["software_type"]["type"] == threat.SOFTWARE_TYPE_RANSOMWARE
        # Only the stored scan is visible here: the technique the report mapped
        # plus the capability tags, not the raw string the report extracted.
        assert classified["software_type"]["confidence"] == threat.CONFIDENCE_MEDIUM
        names = [entry["name"] for entry in classified["threat_score"]["contributions"]]
        assert threat.CONTRIBUTION_TECHNIQUES in names
        assert threat.CONTRIBUTION_INDICATORS in names

    def test_the_stored_scan_is_not_rewritten(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        report = threat.build_threat_report(conn, binary_id=binary_id, engine=_StubEngine())
        threat.classify_binary(conn, binary_id)
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_THREAT) == report
        assert "software_type" not in report


class _StubEngine:
    """Engine surface with fixed payloads for the classifier's integration test."""

    def __init__(
        self,
        *,
        imports: list[dict[str, Any]] | None = None,
        strings: list[dict[str, Any]] | None = None,
    ) -> None:
        self._imports = imports or []
        self._strings = strings or []

    def available(self) -> bool:
        return True

    def imports(self, binary: str | Path) -> dict[str, Any]:
        return {"imports": self._imports, "stubs": []}

    def strings(self, binary: str | Path) -> dict[str, Any]:
        return {"strings": self._strings}

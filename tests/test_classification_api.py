"""Tests for the software type and threat score the threat and triage routes add."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, cast

from conftest import ANALYSIS, FakeEngine, json_body, wsgi_request

from reportal import mcp_server, store, threat

PACKER_MATCH: dict[str, Any] = {"name": "UPX", "category": "packer", "confidence": "high"}
CAPABILITIES: list[dict[str, Any]] = [{"name": "crypto"}, {"name": "file-io"}]
TECHNIQUE: dict[str, Any] = {
    "id": "T1486",
    "name": "Data Encrypted for Impact",
    "evidence": [{"kind": "import", "value": "CryptEncrypt"}],
    "confidence": "high",
}
IOC_URL = "https://pay.example.com/unlock"

# The weights the score adds for the seeded evidence: one packer match (10),
# crypto (5) and file-io (2) capabilities, one indicator category (8) and one
# high-confidence technique (10).
EXPECTED_SCORE = 35

THREAT_KEYS = ["binary_id", "iocs", "ioc_counts", "techniques", "narrative", "notes"]
# The engine dossier's own key order, which the added keys must follow.
TRIAGE_KEYS = list(ANALYSIS)


def _seed(conn: sqlite3.Connection, tmp_path: Path) -> int:
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ" + b"\x00" * 30)
    return store.add_binary(conn, sha256="ef" * 32, name="demo.exe", path=str(target))


def _scan(conn: sqlite3.Connection, binary_id: int, kind: str, payload: dict[str, Any]) -> None:
    analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine=store.SCAN_ENGINE)
    store.set_scan(conn, analysis_id, kind, payload)


def _seed_evidence(conn: sqlite3.Connection, binary_id: int) -> None:
    """Store the four scans the classification reads."""
    _scan(conn, binary_id, store.SCAN_KIND_FILETYPE, {"matches": [dict(PACKER_MATCH)]})
    _scan(conn, binary_id, store.SCAN_KIND_CAPABILITIES, {"capabilities": CAPABILITIES})
    _scan(
        conn,
        binary_id,
        store.SCAN_KIND_THREAT,
        {
            "binary_id": binary_id,
            "iocs": {threat.IOC_CATEGORY_URLS: [{"value": IOC_URL, "kind": "url", "source_va": 1}]},
            "ioc_counts": {threat.IOC_CATEGORY_URLS: 1},
            "techniques": [dict(TECHNIQUE)],
            "narrative": None,
            "notes": [],
        },
    )
    _scan(
        conn,
        binary_id,
        store.SCAN_KIND_TRIAGE,
        {
            "binary": "demo.exe",
            "meta": {"format": "pe"},
            "toolchain": {"family": "msvc"},
            "strings": {"count": 2, "top": [{"text": "Your files have been encrypted"}]},
            "imports": {"count": 1, "dlls": ["mscoree.dll"]},
            "references": {"total": 1},
            "functions": {"total": 1},
        },
    )


def _stored(conn: sqlite3.Connection, binary_id: int, kind: str) -> dict[str, Any]:
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    assert analysis_id is not None
    stored = store.get_scan(conn, analysis_id, kind)
    assert stored is not None
    return stored


def _mcp(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Run one tool through `tools/call` and return its JSON payload."""
    payload, is_error = mcp_server.call_tool(name, arguments)
    assert is_error is not True
    return cast(dict[str, Any], payload)


class TestThreatPayload:
    def test_the_post_appends_the_two_keys_after_the_stored_ones(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("200")
        payload = json_body(body, headers)
        stored = _stored(conn, binary_id, store.SCAN_KIND_THREAT)
        assert list(stored) == THREAT_KEYS
        assert list(payload) == [*THREAT_KEYS, "software_type", "threat_score", "journal_action"]

    def test_the_get_and_post_agree_on_the_derived_values(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _seed_evidence(conn, binary_id)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["software_type"]["type"] == threat.SOFTWARE_TYPE_RANSOMWARE
        assert payload["software_type"]["confidence"] == threat.CONFIDENCE_HIGH
        assert payload["threat_score"]["score"] == EXPECTED_SCORE
        assert payload["threat_score"]["band"] == threat.SCORE_BAND_MODERATE
        assert {entry["name"] for entry in payload["threat_score"]["contributions"]} == {
            threat.CONTRIBUTION_PACKING,
            threat.CONTRIBUTION_CAPABILITIES,
            threat.CONTRIBUTION_INDICATORS,
            threat.CONTRIBUTION_TECHNIQUES,
        }
        assert payload["threat_score"]["notes"][0] == threat.SCORE_SCOPE_NOTE

    def test_the_stored_scan_is_never_rewritten(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _seed_evidence(conn, binary_id)
        before = _stored(conn, binary_id, store.SCAN_KIND_THREAT)
        status, _headers, _body = wsgi_request("GET", f"/api/binaries/{binary_id}/threat")
        assert status.startswith("200")
        assert _stored(conn, binary_id, store.SCAN_KIND_THREAT) == before


class TestTriagePayload:
    def test_the_get_appends_the_derived_keys(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _seed_evidence(conn, binary_id)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert list(payload) == [*TRIAGE_KEYS, "software_type", "threat_score"]
        assert payload["software_type"]["type"] == threat.SOFTWARE_TYPE_RANSOMWARE
        assert payload["threat_score"]["score"] == EXPECTED_SCORE

    def test_the_post_derives_without_another_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert list(payload) == [*TRIAGE_KEYS, "software_type", "threat_score", "journal_action"]
        assert fake_engine.calls == ["analyze"]

    def test_both_surfaces_answer_the_same_values(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _seed_evidence(conn, binary_id)
        _status, threat_headers, threat_body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/threat"
        )
        _status, triage_headers, triage_body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/triage"
        )
        threat_payload = json_body(threat_body, threat_headers)
        triage_payload = json_body(triage_body, triage_headers)
        assert triage_payload["threat_score"] == threat_payload["threat_score"]
        assert triage_payload["software_type"] == threat_payload["software_type"]


class TestNoEvidence:
    def test_a_binary_with_evidence_free_scans_answers_null_with_the_reason(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _scan(
            conn,
            binary_id,
            store.SCAN_KIND_TRIAGE,
            {"meta": {"format": "pe"}, "toolchain": {"family": "msvc"}},
        )
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/triage")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["threat_score"]["score"] is None
        assert payload["threat_score"]["band"] is None
        assert payload["threat_score"]["contributions"] == []
        assert payload["threat_score"]["notes"][-1] == threat.SCORE_EMPTY_NOTE
        assert payload["software_type"]["type"] is None


class TestMcpTools:
    def test_the_stored_tools_carry_the_derived_keys(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _seed_evidence(conn, binary_id)
        for name in ("get_threat_report", "get_triage"):
            payload = _mcp(name, {"binary_id": binary_id})
            assert payload["software_type"]["type"] == threat.SOFTWARE_TYPE_RANSOMWARE
            assert payload["threat_score"]["score"] == EXPECTED_SCORE

    def test_the_run_tools_carry_the_derived_keys(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        _scan(conn, binary_id, store.SCAN_KIND_FILETYPE, {"matches": [dict(PACKER_MATCH)]})
        payload = _mcp("run_triage", {"binary_id": binary_id})
        assert payload["software_type"]["type"] == threat.SOFTWARE_TYPE_PACKED
        assert payload["threat_score"]["score"] == threat.PACKER_POINTS

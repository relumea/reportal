"""Tests for reportal.threat: IOC extraction, ATT&CK mapping and the report builder."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import AI_SUMMARY_RESPONSE, FailingLlmClient, FakeLlmClient

from reportal import engines, llm, store, threat
from reportal.threat import (
    MAX_EVIDENCE_PER_TECHNIQUE,
    MAX_IOCS_PER_CATEGORY,
    MAX_STRINGS_INSPECTED,
)

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class _StubEngine:
    """Engine surface with fixed payloads, a call log and an availability flag."""

    def __init__(
        self,
        *,
        imports: list[dict[str, Any]] | None = None,
        strings: list[dict[str, Any]] | None = None,
        error: Exception | None = None,
        available: bool = True,
    ) -> None:
        self.calls: list[str] = []
        self._imports = imports if imports is not None else []
        self._strings = strings if strings is not None else []
        self._error = error
        self._available = available

    def available(self) -> bool:
        return self._available

    def imports(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("imports")
        if self._error is not None:
            raise self._error
        return {"imports": self._imports, "stubs": []}

    def strings(self, binary: str | Path) -> dict[str, Any]:
        self.calls.append("strings")
        if self._error is not None:
            raise self._error
        return {"strings": self._strings}


def _string(text: str, va: int | str | None = 0x402000) -> dict[str, Any]:
    entry: dict[str, Any] = {"text": text, "size": len(text), "kind": "ascii"}
    if va is not None:
        entry["va"] = va
    return entry


def _import(name: str) -> dict[str, Any]:
    return {"dll": "API.dll", "name": name, "iat_va": "0x401000"}


def _values(iocs: dict[str, list[dict[str, Any]]], category: str) -> list[str]:
    return [finding["value"] for finding in iocs[category]]


def _seed(conn: sqlite3.Connection, tmp_path: Path, *, on_disk: bool = True) -> int:
    target = tmp_path / "demo.exe"
    if on_disk:
        target.write_bytes(b"MZ" + b"\x00" * 30)
    return store.add_binary(
        conn, sha256="ab" * 32, name="demo.exe", path=str(target) if on_disk else ""
    )


class TestExtractIocs:
    def test_every_category_is_always_present(self) -> None:
        iocs = threat.extract_iocs([])
        assert tuple(iocs) == threat.IOC_CATEGORIES

    def test_url_is_extracted_with_trailing_punctuation_trimmed(self) -> None:
        iocs = threat.extract_iocs([_string("see https://c2.example.com/beacon).")])
        assert _values(iocs, threat.IOC_CATEGORY_URLS) == ["https://c2.example.com/beacon"]
        assert iocs[threat.IOC_CATEGORY_URLS][0]["kind"] == "url"

    def test_url_without_a_host_does_not_match(self) -> None:
        iocs = threat.extract_iocs([_string("http://"), _string("https:///path")])
        assert iocs[threat.IOC_CATEGORY_URLS] == []

    def test_bare_domain_is_extracted(self) -> None:
        iocs = threat.extract_iocs([_string("callback evil.net nightly")])
        assert _values(iocs, threat.IOC_CATEGORY_DOMAINS) == ["evil.net"]

    def test_domain_with_an_implausible_tld_does_not_match(self) -> None:
        iocs = threat.extract_iocs([_string("image.png version.4.2 host.zzz")])
        assert iocs[threat.IOC_CATEGORY_DOMAINS] == []

    def test_public_ipv4_is_reported_public(self) -> None:
        iocs = threat.extract_iocs([_string("beacon 8.8.8.8:443")])
        assert iocs[threat.IOC_CATEGORY_IPV4][0] == {
            "value": "8.8.8.8",
            "kind": threat.KIND_IPV4,
            "source_va": 0x402000,
        }

    @pytest.mark.parametrize("address", ["10.0.0.5", "192.168.1.10", "172.16.4.4", "127.0.0.1"])
    def test_private_ipv4_is_kept_and_flagged(self, address: str) -> None:
        iocs = threat.extract_iocs([_string(f"callback {address} now")])
        assert iocs[threat.IOC_CATEGORY_IPV4][0]["value"] == address
        assert iocs[threat.IOC_CATEGORY_IPV4][0]["kind"] == threat.KIND_IPV4_PRIVATE

    def test_ipv4_with_an_out_of_range_octet_does_not_match(self) -> None:
        iocs = threat.extract_iocs([_string("999.1.2.3 and 1.2.3.999")])
        assert iocs[threat.IOC_CATEGORY_IPV4] == []

    def test_public_ipv6_is_extracted(self) -> None:
        iocs = threat.extract_iocs([_string("c2 at 2606:4700:4700::1111 now")])
        assert iocs[threat.IOC_CATEGORY_IPV6][0] == {
            "value": "2606:4700:4700::1111",
            "kind": threat.KIND_IPV6,
            "source_va": 0x402000,
        }

    def test_private_ipv6_is_kept_and_flagged(self) -> None:
        iocs = threat.extract_iocs([_string("link fe80::1 and loopback ::1 here")])
        assert {
            finding["value"]: finding["kind"] for finding in iocs[threat.IOC_CATEGORY_IPV6]
        } == {"fe80::1": threat.KIND_IPV6_PRIVATE, "::1": threat.KIND_IPV6_PRIVATE}

    def test_ipv4_mapped_stays_an_ipv4_finding(self) -> None:
        iocs = threat.extract_iocs([_string("mapped ::ffff:8.8.8.8 here")])
        assert iocs[threat.IOC_CATEGORY_IPV6] == []
        assert _values(iocs, threat.IOC_CATEGORY_IPV4) == ["8.8.8.8"]

    def test_zone_id_and_double_compression_are_not_findings(self) -> None:
        iocs = threat.extract_iocs([_string("zone fe80::1%eth0 and 1::2::3 here")])
        assert iocs[threat.IOC_CATEGORY_IPV6] == []

    def test_bracketed_url_is_extracted(self) -> None:
        iocs = threat.extract_iocs([_string("see http://[2001:db8::1]/beacon")])
        assert _values(iocs, threat.IOC_CATEGORY_URLS) == ["http://[2001:db8::1]/beacon"]

    @pytest.mark.parametrize(
        ("address", "kind"),
        [
            ("169.254.169.254", "cloud-aws"),
            ("169.254.170.2", "cloud-aws-ecs"),
            ("100.100.100.200", "cloud-alibaba"),
            ("169.254.0.23", "cloud-tencent"),
        ],
    )
    def test_cloud_metadata_ips_are_flagged_by_provider(self, address: str, kind: str) -> None:
        iocs = threat.extract_iocs([_string(f"curl http://{address}/latest/meta")])
        assert iocs[threat.IOC_CATEGORY_IPV4][0]["value"] == address
        assert iocs[threat.IOC_CATEGORY_IPV4][0]["kind"] == kind

    def test_cloud_metadata_hostname_is_flagged(self) -> None:
        iocs = threat.extract_iocs([_string("curl metadata.google.internal now")])
        assert iocs[threat.IOC_CATEGORY_DOMAINS][0] == {
            "value": "metadata.google.internal",
            "kind": "cloud-gcp",
            "source_va": 0x402000,
        }

    def test_email_is_extracted(self) -> None:
        iocs = threat.extract_iocs([_string("report to analyst@evil.com please")])
        assert _values(iocs, threat.IOC_CATEGORY_EMAILS) == ["analyst@evil.com"]

    def test_email_without_a_plausible_tld_does_not_match(self) -> None:
        iocs = threat.extract_iocs([_string("mail analyst@localhost")])
        assert iocs[threat.IOC_CATEGORY_EMAILS] == []

    def test_registry_path_is_extracted(self) -> None:
        key = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        iocs = threat.extract_iocs([_string(key)])
        assert _values(iocs, threat.IOC_CATEGORY_REGISTRY) == [key]
        assert iocs[threat.IOC_CATEGORY_REGISTRY][0]["kind"] == "registry"

    def test_registry_path_without_a_hive_prefix_does_not_match(self) -> None:
        iocs = threat.extract_iocs([_string("Software\\Microsoft\\Windows\\CurrentVersion")])
        assert iocs[threat.IOC_CATEGORY_REGISTRY] == []

    def test_absolute_drive_path_is_extracted(self) -> None:
        iocs = threat.extract_iocs([_string(r"C:\Windows\Temp\payload.dll")])
        assert iocs[threat.IOC_CATEGORY_FILES][0]["value"] == r"C:\Windows\Temp\payload.dll"
        assert iocs[threat.IOC_CATEGORY_FILES][0]["kind"] == "path"

    def test_unc_path_is_extracted(self) -> None:
        iocs = threat.extract_iocs([_string(r"\\fileserver\share\payload.exe")])
        assert iocs[threat.IOC_CATEGORY_FILES][0]["value"] == r"\\fileserver\share\payload.exe"
        assert iocs[threat.IOC_CATEGORY_FILES][0]["kind"] == "unc"

    def test_relative_path_does_not_match(self) -> None:
        iocs = threat.extract_iocs([_string(r"Windows\System32\cmd.exe")])
        assert iocs[threat.IOC_CATEGORY_FILES] == []

    def test_each_hash_length_maps_to_its_digest_kind(self) -> None:
        iocs = threat.extract_iocs([_string(f"{MD5} {SHA1} {SHA256}")])
        findings = {
            finding["value"]: finding["kind"] for finding in iocs[threat.IOC_CATEGORY_HASHES]
        }
        assert findings == {MD5: "md5", SHA1: "sha1", SHA256: "sha256"}

    def test_31_character_hex_does_not_match(self) -> None:
        iocs = threat.extract_iocs([_string(MD5[:-1])])
        assert iocs[threat.IOC_CATEGORY_HASHES] == []

    def test_format_strings_are_skipped_whole(self) -> None:
        iocs = threat.extract_iocs(
            [_string("http://%s/c2"), _string(r"C:\%s\payload.dll"), _string("%02x-%s")]
        )
        assert iocs[threat.IOC_CATEGORY_URLS] == []
        assert iocs[threat.IOC_CATEGORY_FILES] == []
        assert iocs[threat.IOC_CATEGORY_HASHES] == []

    def test_literal_percent_does_not_skip_a_string(self) -> None:
        iocs = threat.extract_iocs([_string("beacon c2.example.com (100%% up)")])
        assert _values(iocs, threat.IOC_CATEGORY_DOMAINS) == ["c2.example.com"]

    def test_duplicate_values_collapse_and_keep_the_first_va(self) -> None:
        iocs = threat.extract_iocs([_string("evil.net", va=0x1000), _string("evil.net", va=0x2000)])
        assert _values(iocs, threat.IOC_CATEGORY_DOMAINS) == ["evil.net"]
        assert iocs[threat.IOC_CATEGORY_DOMAINS][0]["source_va"] == 0x1000

    def test_category_is_capped_while_the_payload_reports_only_capped(self) -> None:
        entries = [
            _string(f"host{index}.example.com") for index in range(MAX_IOCS_PER_CATEGORY + 5)
        ]
        iocs = threat.extract_iocs(entries)
        assert len(iocs[threat.IOC_CATEGORY_DOMAINS]) == MAX_IOCS_PER_CATEGORY

    def test_strings_inspected_are_capped(self) -> None:
        entries = [
            _string(f"host{index}.example.com") for index in range(MAX_STRINGS_INSPECTED + 5)
        ]
        assert (
            len(threat.extract_iocs(entries)[threat.IOC_CATEGORY_DOMAINS]) == MAX_IOCS_PER_CATEGORY
        )

    def test_source_va_accepts_hex_strings_and_missing_values(self) -> None:
        iocs = threat.extract_iocs(
            [_string("evil.net", va="0x403000"), _string("bad.org", va=None)]
        )
        domains = {finding["value"]: finding["source_va"] for finding in iocs["domains"]}
        assert domains == {"evil.net": 0x403000, "bad.org": None}

    def test_entries_without_text_are_ignored(self) -> None:
        assert threat.extract_iocs([{"va": 0x1000}])[threat.IOC_CATEGORY_URLS] == []


class TestMapTechniques:
    def test_import_family_yields_high_confidence(self) -> None:
        found = threat.map_techniques([_import("CreateRemoteThread")], [], threat.extract_iocs([]))
        by_id = {item["id"]: item for item in found}
        assert by_id["T1055"]["confidence"] == threat.CONFIDENCE_HIGH
        assert by_id["T1055"]["evidence"] == [{"kind": "import", "value": "CreateRemoteThread"}]

    def test_capability_only_evidence_is_medium_confidence(self) -> None:
        found = threat.map_techniques([], [{"name": "crypto"}], threat.extract_iocs([]))
        by_id = {item["id"]: item for item in found}
        assert by_id["T1486"]["confidence"] == threat.CONFIDENCE_MEDIUM
        assert by_id["T1486"]["evidence"] == [{"kind": "capability", "value": "crypto"}]
        assert "T1027" in by_id and "T1140" in by_id

    def test_ioc_evidence_activates_the_protocol_technique(self) -> None:
        iocs = threat.extract_iocs([_string("https://c2.example.com/beacon")])
        found = threat.map_techniques([], [], iocs)
        by_id = {item["id"]: item for item in found}
        assert by_id["T1071"]["confidence"] == threat.CONFIDENCE_MEDIUM
        assert {"kind": "ioc", "value": "urls"} in by_id["T1071"]["evidence"]
        assert "T1041" in by_id

    def test_registry_ioc_activates_registry_and_autostart(self) -> None:
        iocs = threat.extract_iocs([_string("HKLM\\Software\\Run")])
        ids = {item["id"] for item in threat.map_techniques([], [], iocs)}
        assert {"T1112", "T1547"} <= ids

    def test_results_are_sorted_by_id(self) -> None:
        imports = [
            _import("RegSetValueExA"),
            _import("CreateRemoteThread"),
            _import("GetSystemInfo"),
        ]
        found = threat.map_techniques(imports, [], threat.extract_iocs([]))
        ids = [item["id"] for item in found]
        assert ids == sorted(ids)
        assert {"T1055", "T1082", "T1112"} <= set(ids)

    def test_unrelated_inputs_map_nothing(self) -> None:
        found = threat.map_techniques([_import("GetTickCount")], [], threat.extract_iocs([]))
        assert found == []

    def test_evidence_is_capped_while_confidence_stays_high(self) -> None:
        imports = [
            _import(name) for name in ("WSAStartup", "WSACleanup", "send", "recv", "connect")
        ]
        found = threat.map_techniques(imports, [], threat.extract_iocs([]))
        by_id = {item["id"]: item for item in found}
        assert by_id["T1071"]["confidence"] == threat.CONFIDENCE_HIGH
        assert len(by_id["T1071"]["evidence"]) <= MAX_EVIDENCE_PER_TECHNIQUE

    def test_the_table_covers_the_required_techniques(self) -> None:
        required = {
            "T1055",
            "T1059",
            "T1071",
            "T1041",
            "T1082",
            "T1112",
            "T1547",
            "T1027",
            "T1140",
            "T1485",
            "T1486",
            "T1105",
        }
        assert {technique.attack_id for technique in threat.TECHNIQUES} == required


class TestBuildThreatReport:
    def _build(
        self,
        conn: sqlite3.Connection,
        binary_id: int,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return threat.build_threat_report(conn, binary_id=binary_id, **kwargs)

    def test_engine_signals_build_iocs_and_techniques(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(
            imports=[_import("WSAStartup"), _import("CreateRemoteThread")],
            strings=[_string("https://c2.example.com/beacon")],
        )
        result = self._build(conn, binary_id, engine=stub)
        assert result["binary_id"] == binary_id
        assert stub.calls == ["strings", "imports"]
        assert (
            result["iocs"][threat.IOC_CATEGORY_URLS][0]["value"] == "https://c2.example.com/beacon"
        )
        assert result["ioc_counts"][threat.IOC_CATEGORY_URLS] == 1
        ids = {item["id"] for item in result["techniques"]}
        assert {"T1055", "T1071"} <= ids
        assert result["narrative"] is None

    def test_result_is_stored_as_the_threat_scan(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = self._build(conn, binary_id, engine=_StubEngine())
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_THREAT) == result

    def test_stored_capabilities_are_read_and_never_run(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.set_scan(
            conn,
            analysis_id,
            store.SCAN_KIND_CAPABILITIES,
            {"capabilities": [{"name": "persistence", "confidence": "medium"}]},
        )
        stub = _StubEngine()
        result = self._build(conn, binary_id, engine=stub)
        assert stub.calls == ["strings", "imports"]
        by_id = {item["id"]: item for item in result["techniques"]}
        assert by_id["T1547"]["confidence"] == threat.CONFIDENCE_MEDIUM
        assert by_id["T1547"]["evidence"] == [{"kind": "capability", "value": "persistence"}]

    def test_missing_engine_records_a_reason_instead_of_failing(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = self._build(conn, binary_id, engine=_StubEngine(available=False))
        assert result["notes"] == ["engine-unavailable: strings and imports were not read"]
        assert result["iocs"][threat.IOC_CATEGORY_URLS] == []
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_THREAT) == result

    def test_narrative_uses_the_llm_with_untrusted_context(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        client = FakeLlmClient()
        result = self._build(
            conn, binary_id, engine=_StubEngine(), llm_client=client, narrative=True
        )
        assert result["narrative"] == {
            "summary": "Reads a file into a buffer and returns its length."
        }
        assert client.calls
        assert "untrusted" in client.calls[0][1]["content"].casefold()

    def test_narrative_without_an_llm_records_a_reason(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = self._build(
            conn,
            binary_id,
            engine=_StubEngine(),
            llm_client=llm.LlmClient(None),
            narrative=True,
        )
        assert result["narrative"] is None
        assert result["notes"] == ["llm-unavailable: the narrative was not requested"]

    def test_narrative_is_not_requested_by_default(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        client = FakeLlmClient()
        result = self._build(conn, binary_id, engine=_StubEngine(), llm_client=client)
        assert result["narrative"] is None
        assert client.calls == []

    def test_llm_failure_omits_the_narrative_and_records_the_reason(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = self._build(
            conn,
            binary_id,
            engine=_StubEngine(),
            llm_client=FailingLlmClient("model exploded"),
            narrative=True,
        )
        assert result["narrative"] is None
        assert result["notes"] == ["llm-error: model exploded"]

    def test_payload_carries_every_category_and_key(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = self._build(conn, binary_id, engine=_StubEngine())
        assert set(result) == {
            "binary_id",
            "iocs",
            "ioc_counts",
            "techniques",
            "narrative",
            "notes",
        }
        assert tuple(result["iocs"]) == threat.IOC_CATEGORIES
        assert set(result["ioc_counts"]) == set(threat.IOC_CATEGORIES)

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            self._build(conn, 4242, engine=_StubEngine())

    def test_missing_file_raises_file_not_found(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, on_disk=False)
        with pytest.raises(FileNotFoundError, match="has no file"):
            self._build(conn, binary_id, engine=_StubEngine())

    def test_engine_error_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("rebrew strings exited with code 3"))
        with pytest.raises(engines.EngineError, match="exited with code 3"):
            self._build(conn, binary_id, engine=stub)

    def test_fake_engine_fixture_works_with_the_builder(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: Any
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        result = self._build(conn, binary_id, engine=fake_engine)
        assert result["binary_id"] == binary_id
        assert fake_engine.calls == ["strings", "imports"]


def test_narrative_response_constant_matches_the_fake() -> None:
    """The conftest summary response is the shape the narrative parser accepts."""
    assert AI_SUMMARY_RESPONSE.startswith('{"summary"')

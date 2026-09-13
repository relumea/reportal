"""Tests for reportal.protocols: the protocol table, inference and the scan."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import analysis_log, cli, engines, mcp_server, protocols, store
from reportal._paths import DB_ENV
from reportal.capabilities import CONFIDENCE_HIGH, CONFIDENCE_MEDIUM
from reportal.protocols import (
    MAX_STRINGS_INSPECTED,
    NO_EVIDENCE_NOTE,
    PROTOCOLS,
    WELL_KNOWN_PORTS,
    infer_protocols,
)

runner = CliRunner()


def _assert_scan_failed(conn: sqlite3.Connection, binary_id: int, kind: str) -> None:
    """A failed scan leaves the analysis carrier `failed`, with an error entry."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    assert analysis_id is not None
    analysis = store.get_analysis(conn, analysis_id)
    assert analysis is not None
    assert analysis["status"] == store.ANALYSIS_STATUS_FAILED
    entries, _total = analysis_log.list_entries(conn, analysis_id)
    failed = [entry for entry in entries if entry["severity"] == analysis_log.SEVERITY_ERROR]
    assert any(kind in str(entry["message"]) for entry in failed)


def _import(name: str, dll: str = "API.dll") -> dict[str, Any]:
    return {"dll": dll, "name": name, "iat_va": "0x401000"}


def _string(text: str, va: str = "0x402000") -> dict[str, Any]:
    return {"text": text, "va": va, "size": len(text), "kind": "ascii", "section": ".rdata"}


def _protocol(result: dict[str, Any], name: str) -> dict[str, Any]:
    return next(entry for entry in result["protocols"] if entry["protocol"] == name)


def _names(result: dict[str, Any]) -> list[str]:
    return [entry["protocol"] for entry in result["protocols"]]


def _evidence(result: dict[str, Any], name: str) -> list[tuple[str, str]]:
    return [(item["kind"], item["value"]) for item in _protocol(result, name)["evidence"]]


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

    def available(self) -> bool:
        return True

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
        sha256="5e" * 32,
        name="demo.exe",
        path=str(target) if on_disk else "",
    )


class TestProtocolTable:
    def test_protocol_names_are_unique(self) -> None:
        names = [spec.protocol for spec in PROTOCOLS]
        assert len(names) == len(set(names))

    def test_the_named_families_are_present(self) -> None:
        names = {spec.protocol for spec in PROTOCOLS}
        assert {
            "http",
            "https",
            "tls",
            "dns",
            "ftp",
            "smtp",
            "imap",
            "pop3",
            "irc",
            "telnet",
            "ssh",
            "smb",
            "rdp",
            "ldap",
            "snmp",
            "ntp",
            "quic",
            "mqtt",
            "websocket",
            "tcp",
            "udp",
        } <= names

    def test_every_import_confidence_is_known(self) -> None:
        for spec in PROTOCOLS:
            assert spec.import_confidence in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM)

    def test_every_well_known_port_owner_exists(self) -> None:
        names = {spec.protocol for spec in PROTOCOLS}
        for port, owners in WELL_KNOWN_PORTS.items():
            assert owners
            assert set(owners) <= names, port

    def test_a_well_known_port_may_have_several_owners(self) -> None:
        assert "https" in WELL_KNOWN_PORTS[443]

    def test_reported_ports_come_from_the_port_table(self) -> None:
        result = infer_protocols([_import("FtpGetFile")], [])
        assert _protocol(result, "ftp")["ports"] == [21]


class TestInferFromImport:
    def test_winhttp_names_http_and_https_at_high(self) -> None:
        result = infer_protocols([_import("WinHttpSendRequest")], [])
        assert _protocol(result, "http")["confidence"] == CONFIDENCE_HIGH
        assert _protocol(result, "https")["confidence"] == CONFIDENCE_HIGH
        assert _evidence(result, "http") == [("import", "WinHttpSendRequest")]

    def test_ldap_bind_names_ldap(self) -> None:
        result = infer_protocols([_import("ldap_bind")], [])
        assert _protocol(result, "ldap")["confidence"] == CONFIDENCE_HIGH

    def test_ftp_api_names_ftp(self) -> None:
        assert _protocol(infer_protocols([_import("FtpPutFile")], []), "ftp")

    def test_dns_api_names_dns(self) -> None:
        result = infer_protocols([_import("DnsQuery_A")], [])
        assert _protocol(result, "dns")["confidence"] == CONFIDENCE_HIGH

    def test_ssl_api_names_tls(self) -> None:
        result = infer_protocols([_import("SSL_new")], [])
        assert _protocol(result, "tls")["confidence"] == CONFIDENCE_HIGH

    def test_snmp_api_names_snmp(self) -> None:
        result = infer_protocols([_import("SnmpMgrRequest")], [])
        assert _protocol(result, "snmp")["confidence"] == CONFIDENCE_HIGH

    def test_a_lowercase_snmp_family_import_names_snmp(self) -> None:
        result = infer_protocols([_import("snmp_get")], [])
        assert _protocol(result, "snmp")["confidence"] == CONFIDENCE_HIGH

    def test_websocket_api_names_websocket(self) -> None:
        result = infer_protocols([_import("WinHttpWebSocketSend")], [])
        assert _protocol(result, "websocket")["confidence"] == CONFIDENCE_HIGH

    def test_mqtt_api_names_mqtt(self) -> None:
        result = infer_protocols([_import("mqtt_publish")], [])
        assert _protocol(result, "mqtt")["confidence"] == CONFIDENCE_HIGH

    def test_terminal_services_api_names_rdp(self) -> None:
        result = infer_protocols([_import("WTSQuerySessionInformationW")], [])
        assert _protocol(result, "rdp")["confidence"] == CONFIDENCE_HIGH

    def test_a_generic_socket_import_names_only_tcp_and_udp_at_medium(self) -> None:
        result = infer_protocols([_import("socket")], [])
        assert _names(result) == ["tcp", "udp"]
        assert _protocol(result, "tcp")["confidence"] == CONFIDENCE_MEDIUM
        assert _protocol(result, "udp")["confidence"] == CONFIDENCE_MEDIUM

    def test_winsock_prefix_names_tcp_and_udp_at_medium(self) -> None:
        result = infer_protocols([_import("WSAStartup")], [])
        assert _names(result) == ["tcp", "udp"]

    def test_an_import_without_a_name_is_skipped(self) -> None:
        assert infer_protocols([{"dll": "x.dll"}], [])["count"] == 0


class TestInferFromScheme:
    def test_ftp_scheme_names_ftp(self) -> None:
        result = infer_protocols([], [_string("ftp://files.example.com/pub")])
        assert _protocol(result, "ftp")["confidence"] == CONFIDENCE_HIGH
        assert ("scheme", "ftp") in _evidence(result, "ftp")

    def test_ws_scheme_names_websocket(self) -> None:
        result = infer_protocols([], [_string("ws://example.com/socket")])
        assert _protocol(result, "websocket")["confidence"] == CONFIDENCE_HIGH

    def test_ldap_scheme_names_ldap(self) -> None:
        result = infer_protocols([], [_string("ldap://dir.example.com/ou=people")])
        assert _protocol(result, "ldap")["confidence"] == CONFIDENCE_HIGH

    def test_https_scheme_names_https_and_not_http(self) -> None:
        result = infer_protocols([], [_string("https://example.com/index.html")])
        assert _protocol(result, "https")["confidence"] == CONFIDENCE_HIGH
        assert "http" not in _names(result)

    def test_the_scheme_is_case_insensitive(self) -> None:
        result = infer_protocols([], [_string("FTP://host/")])
        assert ("scheme", "ftp") in _evidence(result, "ftp")


class TestInferFromLiteral:
    def test_http_version_literal_names_http_at_medium(self) -> None:
        result = infer_protocols([], [_string("HTTP/1.1")])
        assert _protocol(result, "http")["confidence"] == CONFIDENCE_MEDIUM
        assert _evidence(result, "http") == [("string", "HTTP/1.1")]

    def test_smtp_greeting_literal_names_smtp(self) -> None:
        result = infer_protocols([], [_string("EHLO mail.example.com")])
        assert _protocol(result, "smtp")["confidence"] == CONFIDENCE_MEDIUM

    def test_smtp_helo_literal_names_smtp(self) -> None:
        result = infer_protocols([], [_string("HELO relay.example.com")])
        assert _protocol(result, "smtp")["confidence"] == CONFIDENCE_MEDIUM

    def test_smtp_banner_literal_names_smtp(self) -> None:
        result = infer_protocols([], [_string("220 mail.example.com ESMTP ready")])
        assert _protocol(result, "smtp")["confidence"] == CONFIDENCE_MEDIUM

    def test_ssh_banner_literal_names_ssh(self) -> None:
        result = infer_protocols([], [_string("SSH-2.0-OpenSSH_8.9")])
        assert _protocol(result, "ssh")["confidence"] == CONFIDENCE_MEDIUM

    def test_pop3_ok_literal_names_pop3(self) -> None:
        result = infer_protocols([], [_string("+OK POP3 server ready")])
        assert _protocol(result, "pop3")["confidence"] == CONFIDENCE_MEDIUM

    def test_ftp_user_literal_names_ftp(self) -> None:
        result = infer_protocols([], [_string("USER anonymous")])
        assert _protocol(result, "ftp")["confidence"] == CONFIDENCE_MEDIUM

    def test_tcp_literal_alone_names_tcp(self) -> None:
        result = infer_protocols([], [_string("SOCK_STREAM")])
        assert _protocol(result, "tcp")["confidence"] == CONFIDENCE_MEDIUM


class TestConfidenceRule:
    def test_an_import_plus_a_literal_is_high(self) -> None:
        result = infer_protocols([_import("socket")], [_string("TCP/IP stack")])
        assert _protocol(result, "tcp")["confidence"] == CONFIDENCE_HIGH
        assert _protocol(result, "udp")["confidence"] == CONFIDENCE_MEDIUM

    def test_an_import_plus_a_scheme_is_high(self) -> None:
        result = infer_protocols([_import("FtpGetFile")], [_string("ftp://host/pub")])
        ftp = _protocol(result, "ftp")
        assert ftp["confidence"] == CONFIDENCE_HIGH
        assert [kind for kind, _value in _evidence(result, "ftp")] == ["import", "scheme"]

    def test_a_scheme_alone_is_high(self) -> None:
        result = infer_protocols([], [_string("imap://mail.example.com/")])
        assert _protocol(result, "imap")["confidence"] == CONFIDENCE_HIGH

    def test_a_literal_alone_is_medium(self) -> None:
        result = infer_protocols([], [_string("EHLO")])
        assert _protocol(result, "smtp")["confidence"] == CONFIDENCE_MEDIUM


class TestFalsePositives:
    def test_the_word_http_in_a_sentence_matches_nothing(self) -> None:
        result = infer_protocols([], [_string("the HTTP protocol is documented here")])
        assert result["count"] == 0
        assert result["notes"] == [NO_EVIDENCE_NOTE]

    def test_a_lone_port_constant_matches_nothing(self) -> None:
        assert infer_protocols([], [_string("80")])["count"] == 0
        assert infer_protocols([], [_string("443")])["count"] == 0

    def test_a_port_in_a_parameter_list_matches_nothing(self) -> None:
        assert infer_protocols([], [_string("SetPort(443)")])["count"] == 0

    def test_a_dotted_host_without_a_port_matches_nothing(self) -> None:
        assert infer_protocols([], [_string("example.com")])["count"] == 0


class TestPortRule:
    def test_a_dotted_host_with_a_well_known_port_names_the_protocol(self) -> None:
        result = infer_protocols([], [_string("1.2.3.4:22")])
        assert _protocol(result, "ssh")["confidence"] == CONFIDENCE_MEDIUM
        assert ("string", "22") in _evidence(result, "ssh")

    def test_a_named_host_with_a_well_known_port_names_the_protocol(self) -> None:
        result = infer_protocols([], [_string("mail.example.com:25")])
        assert ("string", "25") in _evidence(result, "smtp")

    def test_an_unknown_port_number_adds_no_evidence(self) -> None:
        result = infer_protocols([], [_string("1.2.3.4:9999")])
        assert result["count"] == 0

    def test_a_scheme_and_host_port_agree(self) -> None:
        result = infer_protocols([], [_string("http://example.com:80/index.html")])
        assert _protocol(result, "http")["confidence"] == CONFIDENCE_HIGH
        assert ("scheme", "http") in _evidence(result, "http")


class TestShapeAndOrdering:
    def test_an_empty_scan_is_an_exact_empty_result(self) -> None:
        assert infer_protocols([], []) == {
            "protocols": [],
            "count": 0,
            "by_confidence": {CONFIDENCE_HIGH: 0, CONFIDENCE_MEDIUM: 0},
            "notes": [NO_EVIDENCE_NOTE],
        }

    def test_an_entry_without_text_is_skipped(self) -> None:
        assert infer_protocols([], [{"va": "0x1000", "size": 0}])["count"] == 0

    def test_protocols_sort_by_name(self) -> None:
        result = infer_protocols(
            [_import("socket")],
            [_string("HTTP/1.1"), _string("EHLO")],
        )
        assert _names(result) == ["http", "smtp", "tcp", "udp"]

    def test_evidence_deduplicates_and_sorts_by_kind(self) -> None:
        result = infer_protocols(
            [_import("WinHttpSendRequest"), _import("WinHttpSendRequest")],
            [_string("HTTP/1.1"), _string("GET /index.html")],
        )
        evidence = _evidence(result, "http")
        assert evidence[0] == ("import", "WinHttpSendRequest")
        assert ("string", "HTTP/1.1") in evidence
        assert len(evidence) == len(set(evidence))

    def test_a_repeated_scheme_collapses_to_one_evidence_entry(self) -> None:
        result = infer_protocols(
            [],
            [_string("ftp://a/p"), _string("ftp://b/q")],
        )
        assert _evidence(result, "ftp") == [("scheme", "ftp")]

    def test_by_confidence_counts_the_inferred_set(self) -> None:
        result = infer_protocols(
            [_import("WinHttpSendRequest"), _import("socket")],
            [_string("HTTP/1.1")],
        )
        assert result["by_confidence"] == {CONFIDENCE_HIGH: 2, CONFIDENCE_MEDIUM: 2}

    def test_every_entry_carries_the_named_fields(self) -> None:
        result = infer_protocols([_import("ldap_bind")], [])
        entry = _protocol(result, "ldap")
        assert set(entry) == {"protocol", "description", "confidence", "evidence", "ports"}
        assert entry["description"]

    def test_strings_beyond_the_cap_are_not_read(self) -> None:
        many = [
            _string("nothing here", va=hex(0x1000 + index))
            for index in range(MAX_STRINGS_INSPECTED)
        ]
        assert infer_protocols([], [*many, _string("HTTP/1.1")])["count"] == 0


class TestScanProtocols:
    def test_injected_payloads_skip_the_engine_and_store_the_round_trip(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("must not be called"))
        result = protocols.scan_protocols(
            conn,
            binary_id=binary_id,
            engine=stub,
            imports=[_import("WinHttpSendRequest")],
            strings=[_string("https://example.com/")],
        )
        assert result["binary_id"] == binary_id
        assert result["count"] == 2
        assert stub.calls == []
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_PROTOCOLS) == result

    def test_engine_payloads_are_used_when_none_are_injected(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(
            imports={"imports": [_import("ldap_bind")]},
            strings={"strings": [_string("ldap://dir.example.com/")]},
        )
        result = protocols.scan_protocols(conn, binary_id=binary_id, engine=stub)
        assert stub.calls == ["imports", "strings"]
        assert _protocol(result, "ldap")["confidence"] == CONFIDENCE_HIGH

    def test_an_empty_scan_is_stored(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        result = protocols.scan_protocols(
            conn, binary_id=binary_id, engine=_StubEngine(), imports=[], strings=[]
        )
        assert result["protocols"] == []
        assert result["notes"] == [NO_EVIDENCE_NOTE]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_PROTOCOLS) == result

    def test_unknown_binary_raises_key_error(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(KeyError, match="no binary with id 4242"):
            protocols.scan_protocols(conn, binary_id=4242, imports=[], strings=[])

    def test_missing_file_raises_file_not_found(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path, on_disk=False)
        with pytest.raises(FileNotFoundError, match="has no file"):
            protocols.scan_protocols(conn, binary_id=binary_id, imports=[], strings=[])

    def test_engine_unavailable_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        with pytest.raises(engines.EngineUnavailable):
            protocols.scan_protocols(
                conn, binary_id=binary_id, engine=engines.RebrewEngine(enabled=False)
            )

    def test_engine_error_propagates(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        binary_id = _seed(conn, tmp_path)
        stub = _StubEngine(error=engines.EngineError("rebrew strings exited with code 3"))
        with pytest.raises(engines.EngineError, match="exited with code 3"):
            protocols.scan_protocols(conn, binary_id=binary_id, engine=stub)


class TestProtocolsRoutes:
    """`POST`/`GET /api/binaries/<id>/protocols`."""

    def _file_binary(self, conn: sqlite3.Connection, tmp_path: Path) -> int:
        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ" + b"\x00" * 30)
        return store.add_binary(conn, sha256="e1" * 32, name="demo.exe", path=str(target))

    def _stub_engine(self, monkeypatch: pytest.MonkeyPatch, fake_engine: FakeEngine) -> None:
        monkeypatch.setattr(
            fake_engine, "imports", lambda binary: {"imports": [_import("WinHttpSendRequest")]}
        )
        monkeypatch.setattr(
            fake_engine, "strings", lambda binary: {"strings": [_string("HTTP/1.1")]}
        )

    def test_post_stores_then_get_serves_stored(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        self._stub_engine(monkeypatch, fake_engine)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/protocols")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["binary_id"] == binary_id
        assert _names(payload) == ["http", "https"]
        analysis_id = store.latest_analysis_for_binary(conn, binary_id)
        assert payload.pop("journal_action")
        assert store.get_scan(conn, analysis_id or 0, store.SCAN_KIND_PROTOCOLS) == payload

        engines.set_engine(engines.RebrewEngine(enabled=False))
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/protocols")
        assert status.startswith("200")
        assert json_body(body, headers) == payload

    def test_get_absent_404_no_scan_makes_no_engine_call(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("GET", f"/api/binaries/{binary_id}/protocols")
        assert status.startswith("404")
        payload = json_body(body, headers)
        assert payload["error"] == "no-scan"
        assert f"no protocols scan for binary {binary_id}" in payload["detail"]
        assert "reportal protocols" in payload["detail"]
        assert fake_engine.calls == []

    def test_get_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("GET", "/api/binaries/999/protocols")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_404_unknown_binary(self, portal_db: Path, fake_engine: FakeEngine) -> None:
        status, headers, body = wsgi_request("POST", "/api/binaries/999/protocols")
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"
        assert fake_engine.calls == []

    def test_post_400_without_path(self, conn: sqlite3.Connection, fake_engine: FakeEngine) -> None:
        binary_id = store.add_binary(conn, sha256="e2" * 32, name="ghost.exe")
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/protocols")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "binary not on disk"
        assert fake_engine.calls == []

    def test_post_503_without_engine(self, conn: sqlite3.Connection, tmp_path: Path) -> None:
        engines.set_engine(engines.RebrewEngine(enabled=False))
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/protocols")
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == "engine-unavailable"
        _assert_scan_failed(conn, binary_id, "protocols")

    def test_post_500_engine_error(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise engines.EngineError("rebrew imports exited with code 1: bad header")

        monkeypatch.setattr(fake_engine, "imports", boom)
        binary_id = self._file_binary(conn, tmp_path)
        status, headers, body = wsgi_request("POST", f"/api/binaries/{binary_id}/protocols")
        assert status.startswith("500")
        payload = json_body(body, headers)
        assert payload["error"] == "engine-error"
        assert "bad header" in payload["detail"]
        _assert_scan_failed(conn, binary_id, "protocols")


def _cli_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_engine: FakeEngine,
    *,
    imports: list[dict[str, Any]],
    strings: list[dict[str, Any]],
) -> int:
    """Seed a portal DB with one file-backed binary and the stub engine payloads."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    target = tmp_path / "demo.exe"
    target.write_bytes(b"MZ" + b"\x00" * 30)
    monkeypatch.setattr(fake_engine, "imports", lambda binary: {"imports": imports})
    monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": strings})
    engines.set_engine(fake_engine)
    with contextlib.closing(store.connect(db)) as conn:
        return store.add_binary(conn, sha256="e3" * 32, name="demo.exe", path=str(target))


class TestProtocolsCommand:
    def test_json_prints_the_payload(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _cli_seed(
            tmp_path,
            monkeypatch,
            fake_engine,
            imports=[_import("ldap_bind")],
            strings=[_string("ldap://dir.example.com/")],
        )
        result = runner.invoke(cli.app, ["protocols", str(binary_id), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["binary_id"] == binary_id
        assert _names(payload) == ["ldap"]

    def test_human_prints_the_table(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _cli_seed(
            tmp_path,
            monkeypatch,
            fake_engine,
            imports=[_import("WinHttpSendRequest")],
            strings=[_string("HTTP/1.1")],
        )
        result = runner.invoke(cli.app, ["protocols", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "2 protocols" in result.output
        assert "high 2" in result.output
        assert "http" in result.output
        assert "import: WinHttpSendRequest" in result.output

    def test_human_says_when_nothing_is_inferred(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _cli_seed(
            tmp_path, monkeypatch, fake_engine, imports=[], strings=[_string("hello")]
        )
        result = runner.invoke(cli.app, ["protocols", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "No protocols inferred." in result.output

    def test_an_unknown_binary_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        _cli_seed(tmp_path, monkeypatch, fake_engine, imports=[], strings=[])
        result = runner.invoke(cli.app, ["protocols", "4242", "--json"])
        assert result.exit_code == 1
        assert "no binary with id 4242" in result.output

    def test_a_missing_engine_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        engines.set_engine(engines.RebrewEngine(enabled=False))
        result = runner.invoke(cli.app, ["protocols", "1", "--json"])
        assert result.exit_code == 1
        assert "rebrew engine unavailable" in result.output


def _mcp_call(name: str, arguments: dict[str, Any]) -> tuple[Any, bool]:
    """Run one MCP tool through `tools/call`; returns (payload, is_error)."""
    return mcp_server.call_tool(name, arguments)


class TestProtocolsMcpTools:
    def test_get_without_a_scan_is_a_structured_error(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload, is_error = _mcp_call("get_protocols_scan", {"binary_id": binary_id})
        assert is_error is True
        assert payload["error"] == "no-scan"
        assert "run_protocols_scan" in payload["detail"]

    def test_run_then_get_serves_the_stored_scan(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        monkeypatch.setattr(
            fake_engine, "imports", lambda binary: {"imports": [_import("ssl_new")]}
        )
        monkeypatch.setattr(fake_engine, "strings", lambda binary: {"strings": []})
        payload, is_error = _mcp_call("run_protocols_scan", {"binary_id": binary_id})
        assert is_error is False
        assert payload["binary_id"] == binary_id
        assert _names(payload) == ["tls"]

        stored, is_error = _mcp_call("get_protocols_scan", {"binary_id": binary_id})
        assert is_error is False
        payload.pop("journal_action", None)
        assert stored == payload

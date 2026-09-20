"""Tests for the external-source registry and the two built-in sources.

No test touches the network: the local source reads stored rows, the remote one
drives an injected ``httpx.MockTransport``, and every gate (the opt-in, the key,
the size cap, a redirect) is asserted as its own case.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, external, journal, mcp_server, plugins, secret_store, store
from reportal._paths import DB_ENV

runner = CliRunner()

SHA256 = "ab" * 32
KEY = "vt-key-0123456789"

REPORT = {
    "data": {
        "id": SHA256,
        "type": "file",
        "attributes": {
            "sha256": SHA256,
            "meaningful_name": "demo.exe",
            "type_description": "Win32 EXE",
            "reputation": 12,
            "tags": ["peexe"],
            "last_analysis_stats": {"malicious": 2, "undetected": 68},
            "last_analysis_results": {
                "EngineB": {"category": "undetected", "result": None, "engine_version": "1"},
                "EngineA": {"category": "malicious", "result": "Trojan.X", "engine_version": "9"},
            },
            "links": {"self": "https://example.invalid/"},
        },
    }
}


class _EntryPoint:
    """Minimal stand-in for importlib.metadata.EntryPoint."""

    def __init__(self, name: str, value: str) -> None:
        self.name = name
        self.value = value


class _EntryPoints:
    """Minimal stand-in for the EntryPoints collection."""

    def __init__(self, entries: list[_EntryPoint]) -> None:
        self._entries = entries

    def select(self, *, group: str) -> list[_EntryPoint]:
        return list(self._entries)


def _patch_entry_points(monkeypatch: pytest.MonkeyPatch, *entries: _EntryPoint) -> None:
    monkeypatch.setattr(plugins, "entry_points", lambda: _EntryPoints(list(entries)))


def _transport(
    status: int = 200,
    body: Any = None,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Client:
    """A client whose one response is *status* with *body* as JSON."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{external.VIRUSTOTAL_URL_PREFIX}{SHA256}"
        assert request.headers.get(external.API_KEY_HEADER) == KEY
        payload = REPORT if body is None else body
        return httpx.Response(
            status,
            json=payload if isinstance(payload, (dict, list)) else None,
            content=None if isinstance(payload, (dict, list)) else payload,
            headers=headers or {},
        )

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


@pytest.fixture(autouse=True)
def _isolate_sources() -> Iterator[None]:
    """Reload the registry around each test, whatever a test registered.

    The closing refresh suppresses a duplicate-name error: a test that patches a
    built-in-claiming entry point leaves that patch live through the fixture's
    teardown, and the next test's setup reloads a clean registry anyway.
    """
    external.set_http_client(None)
    external.refresh_sources()
    yield
    external.set_http_client(None)
    with contextlib.suppress(plugins.RegistryError):
        external.refresh_sources()


@pytest.fixture(autouse=True)
def _clean_external_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gates are off unless a test turns one on."""
    monkeypatch.delenv(external.ALLOW_REMOTE_ENV, raising=False)
    monkeypatch.delenv(external.VIRUSTOTAL_KEY_ENV, raising=False)


def _seed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, scans: bool = True) -> dict[str, Any]:
    """A portal DB with one binary, its analysis, a fingerprint and its scans."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256=SHA256, name="demo.exe", size=1024, fmt="EXE")
        analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        store.set_fingerprint(
            conn, binary_id, {"sha256": SHA256, "format": "pe", "arch": "x86_32", "size": 1024}
        )
        if scans:
            store.set_scan(
                conn,
                analysis_id,
                store.SCAN_KIND_DETECT,
                {"matches": [{"name": "emotet", "confidence": "high"}], "count": 1},
            )
            store.set_scan(
                conn,
                analysis_id,
                store.SCAN_KIND_CAPABILITIES,
                {"capabilities": [{"name": "network", "evidence_count": 3}], "count": 1},
            )
            store.set_scan(
                conn,
                analysis_id,
                store.SCAN_KIND_THREAT,
                {"software_type": "trojan", "threat_score": 80},
            )
            store.set_scan(
                conn,
                analysis_id,
                store.SCAN_KIND_SECRETS,
                {"findings": [{"kind": "aws"}], "count": 1},
            )
    return {"binary": binary_id, "analysis": analysis_id, "db": db}


def _enable(monkeypatch: pytest.MonkeyPatch, *, key: str = KEY) -> None:
    monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
    if key:
        monkeypatch.setenv(external.VIRUSTOTAL_KEY_ENV, key)
    external.refresh_sources()


class TestRegistry:
    def test_the_built_ins_are_registered(self) -> None:
        found = {source.name: source.kind for source in external.sources()}
        assert found == {
            external.LOCAL_SOURCE: external.KIND_OFFLINE,
            external.VIRUSTOTAL_SOURCE: external.KIND_REMOTE,
        }

    def test_the_offline_source_is_always_available(self) -> None:
        source = external.get_source(external.LOCAL_SOURCE)
        assert source.available()
        assert source.describe()["unavailable_reason"] == ""

    def test_the_remote_source_is_unavailable_until_it_is_enabled(self) -> None:
        source = external.get_source(external.VIRUSTOTAL_SOURCE)
        assert not source.available()
        assert external.ALLOW_REMOTE_ENV in source.unavailable_reason()

    def test_a_key_without_the_gate_is_not_enough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.VIRUSTOTAL_KEY_ENV, KEY)
        external.refresh_sources()
        assert not external.get_source(external.VIRUSTOTAL_SOURCE).available()

    def test_the_gate_without_a_key_is_not_enough(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        external.refresh_sources()
        source = external.get_source(external.VIRUSTOTAL_SOURCE)
        assert not source.available()
        assert external.VIRUSTOTAL_KEY_SECRET in source.unavailable_reason()

    def test_both_switches_on_makes_it_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _enable(monkeypatch)
        assert external.get_source(external.VIRUSTOTAL_SOURCE).available()

    def test_an_unknown_name_names_the_known_ones(self) -> None:
        with pytest.raises(external.UnknownSourceError) as excinfo:
            external.get_source("nope")
        assert external.LOCAL_SOURCE in str(excinfo.value)

    def test_describe_reports_the_gate_and_the_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = external.describe()
        assert payload["count"] == len(payload["sources"])
        assert payload["remote_enabled"] is False
        assert payload["key_configured"] is False
        assert payload["note"]
        _enable(monkeypatch)
        assert external.describe()["remote_enabled"] is True
        assert external.describe()["key_configured"] is True

    def test_a_duplicate_name_is_a_registry_error(self) -> None:
        impostor = external.Source(
            name=external.LOCAL_SOURCE,
            kind=external.KIND_OFFLINE,
            description="claims the built-in name",
            retrieve=lambda context: {},
        )
        with pytest.raises(plugins.RegistryError):
            external.register_source(impostor, origin="test")

    def test_an_unknown_kind_is_a_registry_error(self) -> None:
        with pytest.raises(plugins.RegistryError):
            external.register_source(
                external.Source(
                    name="probe", kind="nonsense", description="", retrieve=lambda c: {}
                ),
                origin="test",
            )

    def test_a_non_source_is_a_registry_error(self) -> None:
        with pytest.raises(plugins.RegistryError):
            external.register_source(42, origin="test")  # type: ignore[arg-type]

    def test_a_registered_source_is_dropped_by_a_refresh(self) -> None:
        external.register_source(
            external.Source(
                name="probe",
                kind=external.KIND_OFFLINE,
                description="a local probe",
                retrieve=lambda context: {"found": True},
            ),
            origin="test",
        )
        assert "probe" in [source.name for source in external.sources()]
        assert "probe" not in [source.name for source in external.refresh_sources()]

    def test_unregister_withdraws_one_entry(self) -> None:
        external.register_source(
            external.Source(
                name="probe",
                kind=external.KIND_OFFLINE,
                description="a local probe",
                retrieve=lambda context: {"found": True},
            ),
            origin="test",
        )
        external.unregister_source("probe")
        names = [source.name for source in external.sources()]
        assert "probe" not in names
        assert external.LOCAL_SOURCE in names

    def test_unregister_unknown_name_raises(self) -> None:
        with pytest.raises(plugins.RegistryError):
            external.unregister_source("nope")

    def test_entry_point_sources_are_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(
            monkeypatch, _EntryPoint("plugin-probe", "external_plugins:PROBE_SOURCE")
        )
        assert "plugin-probe" in [source.name for source in external.refresh_sources()]

    def test_an_entry_point_factory_is_called(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("probe", "external_plugins:PROBE_FACTORY"))
        assert "plugin-probe" in [source.name for source in external.refresh_sources()]

    def test_a_broken_entry_point_is_skipped_with_a_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", "external_plugins:NOT_A_SOURCE"))
        with caplog.at_level(logging.WARNING):
            names = [source.name for source in external.refresh_sources()]
        assert "skipping bad reportal.external_sources registration" in caplog.text
        assert external.LOCAL_SOURCE in names

    def test_an_entry_point_with_no_module_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("bad", ""))
        assert external.LOCAL_SOURCE in [source.name for source in external.refresh_sources()]

    def test_an_entry_point_duplicating_a_builtin_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_entry_points(monkeypatch, _EntryPoint("dup", "external_plugins:IMPOSTOR_SOURCE"))
        with pytest.raises(plugins.RegistryError):
            external.refresh_sources()


class TestConfiguration:
    def test_the_gate_reads_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert external.remote_enabled() is False
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "yes")
        assert external.remote_enabled() is True

    def test_the_gate_reads_the_workspace_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "reportal.toml").write_text(
            f"[{external.CONFIG_TABLE}]\n{external.CONFIG_ALLOW_REMOTE} = true\n", encoding="utf-8"
        )
        monkeypatch.setattr(external, "project_root", lambda: tmp_path)
        monkeypatch.delenv(external.ALLOW_REMOTE_ENV, raising=False)
        assert external.remote_enabled() is True

    def test_env_falsey_forces_off_over_the_workspace_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "reportal.toml").write_text(
            f"[{external.CONFIG_TABLE}]\n{external.CONFIG_ALLOW_REMOTE} = true\n", encoding="utf-8"
        )
        monkeypatch.setattr(external, "project_root", lambda: tmp_path)
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "false")
        assert external.remote_enabled() is False

    def test_a_malformed_table_is_not_a_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        (tmp_path / "reportal.toml").write_text("this is not toml", encoding="utf-8")
        monkeypatch.setattr(external, "project_root", lambda: tmp_path)
        monkeypatch.delenv(external.ALLOW_REMOTE_ENV, raising=False)
        with caplog.at_level("WARNING", logger="reportal.external"):
            assert external.remote_enabled() is False
        assert any("remote sources fall back to off" in record.message for record in caplog.records)

    def test_the_key_reads_the_environment_first(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(external.VIRUSTOTAL_KEY_ENV, "env-key")
        assert external.virustotal_key() == "env-key"

    def test_the_key_reads_the_workspace_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "reportal.toml").write_text(
            f'[{external.CONFIG_TABLE}]\n{external.CONFIG_VIRUSTOTAL_KEY} = "table-key"\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(external, "project_root", lambda: tmp_path)
        assert external.virustotal_key() == "table-key"

    def test_the_key_falls_back_to_the_secret_store(self, conn: sqlite3.Connection) -> None:
        secret_store.set_secret(conn, name=external.VIRUSTOTAL_KEY_SECRET, value="store-key")
        assert external.virustotal_key() == "store-key"

    def test_no_key_anywhere_is_empty(self, conn: sqlite3.Connection) -> None:
        assert external.virustotal_key() == ""


class TestContext:
    def test_an_unknown_analysis_is_refused(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(external.ExternalError) as excinfo:
            external.binary_context(conn, 999)
        assert excinfo.value.code == "analysis not found"

    def test_the_context_assembles_the_stored_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            context = external.binary_context(conn, ids["analysis"])
        assert context["sha256"] == SHA256
        assert context["name"] == "demo.exe"
        assert context["stored"][store.SCAN_KIND_DETECT] is True
        assert context["scans"][store.SCAN_KIND_THREAT]["threat_score"] == 80


class TestLocalSource:
    def test_the_payload_reports_the_local_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            result = external.run(
                conn, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
            )
        payload = result["payload"]
        assert payload["found"] is True
        assert payload["families"] == ["emotet"]
        assert payload["capabilities"] == ["network"]
        assert payload["software_type"] == "trojan"
        assert payload["threat_score"] == 80
        assert payload["secrets"] == 1
        assert payload["sha256"] == SHA256
        assert payload["note"] == external.LOCAL_NOTE

    def test_missing_scans_are_reported_as_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch, scans=False)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            payload = external.run(
                conn, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
            )["payload"]
        assert payload["families"] == []
        assert payload["capabilities"] == []
        assert payload["software_type"] is None
        assert payload["secrets"] == 0
        assert payload["stored"][store.SCAN_KIND_DETECT] is False


class TestVirusTotalFetch:
    def test_a_file_report_is_normalized(self) -> None:
        external.set_http_client(_transport())
        payload = external.fetch_virustotal(SHA256, key=KEY)
        assert payload["found"] is True
        assert payload["sha256"] == SHA256
        assert payload["attributes"]["meaningful_name"] == "demo.exe"
        assert payload["attributes"]["last_analysis_stats"] == {"malicious": 2, "undetected": 68}
        assert list(payload["engines"]) == ["EngineA", "EngineB"]
        assert payload["engines"]["EngineA"]["result"] == "Trojan.X"
        assert payload["engine_count"] == 2
        assert "links" not in payload["attributes"], "the vendor links are not stored"
        assert "data" not in payload, "the raw document is not stored"
        assert payload["note"] == external.VIRUSTOTAL_NOTE

    def test_an_unknown_file_is_a_result_not_a_failure(self) -> None:
        external.set_http_client(_transport(404, {"error": {"code": "NotFoundError"}}))
        payload = external.fetch_virustotal(SHA256, key=KEY)
        assert payload["found"] is False
        assert payload["sha256"] == SHA256

    def test_a_redirect_is_refused(self) -> None:
        external.set_http_client(_transport(302, {}, headers={"location": "https://elsewhere/"}))
        with pytest.raises(external.ExternalFetchError) as excinfo:
            external.fetch_virustotal(SHA256, key=KEY)
        assert "redirect" in excinfo.value.detail

    def test_a_server_error_is_a_failure(self) -> None:
        external.set_http_client(_transport(500, {"error": {}}))
        with pytest.raises(external.ExternalFetchError):
            external.fetch_virustotal(SHA256, key=KEY)

    def test_a_non_json_body_is_a_failure(self) -> None:
        external.set_http_client(_transport(200, b"not json"))
        with pytest.raises(external.ExternalFetchError) as excinfo:
            external.fetch_virustotal(SHA256, key=KEY)
        assert excinfo.value.code == external.ERROR_FETCH_FAILED

    def test_a_body_past_the_cap_is_refused(self) -> None:
        huge = b"x" * (external.MAX_BYTES + 1)
        external.set_http_client(_transport(200, huge))
        with pytest.raises(external.ExternalFetchError) as excinfo:
            external.fetch_virustotal(SHA256, key=KEY)
        assert excinfo.value.code == external.ERROR_TOO_LARGE

    def test_a_response_without_a_data_object_is_a_failure(self) -> None:
        external.set_http_client(_transport(200, {"data": "nope"}))
        with pytest.raises(external.ExternalFetchError) as excinfo:
            external.fetch_virustotal(SHA256, key=KEY)
        assert excinfo.value.code == external.ERROR_BAD_RESPONSE

    def test_the_engine_results_are_capped(self) -> None:
        engines = {
            f"Engine{index:03d}": {"category": "undetected", "result": None}
            for index in range(external.MAX_ENGINE_RESULTS + 20)
        }
        body = {
            "data": {"id": SHA256, "type": "file", "attributes": {"last_analysis_results": engines}}
        }
        external.set_http_client(_transport(200, body))
        payload = external.fetch_virustotal(SHA256, key=KEY)
        assert len(payload["engines"]) == external.MAX_ENGINE_RESULTS
        assert payload["engine_count"] == external.MAX_ENGINE_RESULTS + 20
        assert payload["engine_cap"] == external.MAX_ENGINE_RESULTS


class TestRun:
    def test_the_remote_source_refuses_while_it_is_disabled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(external.DisabledExternalError) as excinfo,
        ):
            external.run(conn, analysis_id=ids["analysis"], source_name=external.VIRUSTOTAL_SOURCE)
        assert excinfo.value.code == external.ERROR_DISABLED

    def test_the_remote_source_refuses_without_a_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        external.refresh_sources()
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(external.UnavailableExternalError),
        ):
            external.run(conn, analysis_id=ids["analysis"], source_name=external.VIRUSTOTAL_SOURCE)

    def test_the_remote_source_runs_with_both_switches_on(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _enable(monkeypatch)
        external.set_http_client(_transport())
        with contextlib.closing(store.connect(ids["db"])) as conn:
            result = external.run(
                conn, analysis_id=ids["analysis"], source_name=external.VIRUSTOTAL_SOURCE
            )
        assert result["source"] == external.VIRUSTOTAL_SOURCE
        assert result["kind"] == external.KIND_REMOTE
        assert result["fetched_at"]
        assert result["payload"]["attributes"]["reputation"] == 12

    def test_a_binary_without_a_hash_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="", name="nameless", size=1)
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        _enable(monkeypatch)
        with (
            contextlib.closing(store.connect(db)) as conn,
            pytest.raises(external.NoContentHashError),
        ):
            external.run(conn, analysis_id=analysis_id, source_name=external.VIRUSTOTAL_SOURCE)

    def test_an_unknown_source_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with (
            contextlib.closing(store.connect(ids["db"])) as conn,
            pytest.raises(external.UnknownSourceError),
        ):
            external.run(conn, analysis_id=ids["analysis"], source_name="nope")


class TestStorage:
    def test_a_journaled_run_stores_the_scan_and_reverts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            action = journal.new_action()
            with journal.journaled(conn, action) as log:
                result = external.journaled_run(
                    conn, log, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
                )
            assert result["payload"]["found"] is True
            stored = external.stored(
                conn, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
            )
            assert stored is not None
            assert stored["payload"]["families"] == ["emotet"]
            assert journal.revert_action(conn, action)["reverted"] > 0
            assert (
                external.stored(
                    conn, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
                )
                is None
            )

    def test_a_second_run_replaces_the_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            for _ in range(2):
                with journal.journaled(conn, journal.new_action()) as log:
                    external.journaled_run(
                        conn, log, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
                    )
            stored = external.stored(
                conn, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
            )
        assert stored is not None
        assert stored["source"] == external.LOCAL_SOURCE

    def test_status_reports_the_gate_and_the_stored_answer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        with contextlib.closing(store.connect(ids["db"])) as conn:
            before = external.status(
                conn, analysis_id=ids["analysis"], source_name=external.VIRUSTOTAL_SOURCE
            )
            assert before["available"] is False
            assert before["stored"] is False
            assert before["remote_enabled"] is False
            assert before["fetched_at"] is None
            with journal.journaled(conn, journal.new_action()) as log:
                external.journaled_run(
                    conn, log, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
                )
            after = external.status(
                conn, analysis_id=ids["analysis"], source_name=external.LOCAL_SOURCE
            )
        assert after["stored"] is True
        assert after["fetched_at"]

    def test_the_scan_kind_names_the_source(self) -> None:
        assert external.scan_kind("virustotal") == "external:virustotal"


class TestRoutes:
    def test_the_registry_route_serves_the_sources(self) -> None:
        status, headers, body = wsgi_request("GET", "/api/external/sources")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert [entry["name"] for entry in payload["sources"]] == [
            external.LOCAL_SOURCE,
            external.VIRUSTOTAL_SOURCE,
        ]
        assert payload["remote_enabled"] is False

    def test_the_offline_source_runs_and_is_journalled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{ids['analysis']}/external/{external.LOCAL_SOURCE}"
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["payload"]["families"] == ["emotet"]
        assert payload["journal_action"]

        status, headers, body = wsgi_request(
            "GET", f"/api/analyses/{ids['analysis']}/external/{external.LOCAL_SOURCE}"
        )
        assert status.startswith("200")
        assert json_body(body, headers)["source"] == external.LOCAL_SOURCE

        status, headers, body = wsgi_request(
            "GET", f"/api/analyses/{ids['analysis']}/external/{external.LOCAL_SOURCE}/status"
        )
        assert status.startswith("200")
        state = json_body(body, headers)
        assert state["stored"] is True
        assert state["available"] is True

    def test_a_source_that_has_not_run_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "GET", f"/api/analyses/{ids['analysis']}/external/{external.LOCAL_SOURCE}"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "no-scan"

    def test_a_disabled_remote_source_is_403(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{ids['analysis']}/external/{external.VIRUSTOTAL_SOURCE}"
        )
        assert status.startswith("403")
        assert json_body(body, headers)["error"] == external.ERROR_DISABLED

    def test_an_enabled_source_without_a_key_is_503(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        monkeypatch.setenv(external.ALLOW_REMOTE_ENV, "1")
        external.refresh_sources()
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{ids['analysis']}/external/{external.VIRUSTOTAL_SOURCE}"
        )
        assert status.startswith("503")
        assert json_body(body, headers)["error"] == external.ERROR_UNAVAILABLE

    def test_a_remote_pull_is_stored(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _enable(monkeypatch)
        external.set_http_client(_transport())
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{ids['analysis']}/external/{external.VIRUSTOTAL_SOURCE}"
        )
        assert status.startswith("200"), body
        payload = json_body(body, headers)
        assert payload["payload"]["attributes"]["reputation"] == 12
        assert payload["journal_action"]

    def test_a_failed_remote_pull_is_502_and_stores_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        _enable(monkeypatch)
        external.set_http_client(_transport(500, {"error": {}}))
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{ids['analysis']}/external/{external.VIRUSTOTAL_SOURCE}"
        )
        assert status.startswith("502")
        assert json_body(body, headers)["error"] == external.ERROR_FETCH_FAILED
        with contextlib.closing(store.connect(ids["db"])) as conn:
            assert (
                external.stored(
                    conn, analysis_id=ids["analysis"], source_name=external.VIRUSTOTAL_SOURCE
                )
                is None
            )

    def test_an_unknown_source_is_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{ids['analysis']}/external/nope"
        )
        assert status.startswith("404")
        assert json_body(body, headers)["error"] == external.ERROR_UNKNOWN

    def test_an_unknown_analysis_is_404_on_every_route(self) -> None:
        for method, path in (
            ("POST", f"/api/analyses/999/external/{external.LOCAL_SOURCE}"),
            ("GET", f"/api/analyses/999/external/{external.LOCAL_SOURCE}"),
            ("GET", f"/api/analyses/999/external/{external.LOCAL_SOURCE}/status"),
        ):
            status, headers, body = wsgi_request(method, path)
            assert status.startswith("404"), path
            assert json_body(body, headers)["error"] == "analysis not found"

    def test_the_ask_for_a_hash_is_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            binary_id = store.add_binary(conn, sha256="", name="nameless", size=1)
            analysis_id = store.create_analysis(conn, binary_id=binary_id, engine="manual")
        _enable(monkeypatch)
        status, headers, body = wsgi_request(
            "POST", f"/api/analyses/{analysis_id}/external/{external.VIRUSTOTAL_SOURCE}"
        )
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == external.ERROR_NO_HASH


class TestCli:
    def test_sources_lists_the_registry(self) -> None:
        result = runner.invoke(cli.app, ["external-sources", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["count"] == 2

    def test_sources_human_output(self) -> None:
        result = runner.invoke(cli.app, ["external-sources"])
        assert result.exit_code == 0, result.output
        assert "virustotal" in result.output

    def test_the_offline_source_runs_and_prints(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["external", str(ids["analysis"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["payload"]["families"] == ["emotet"]
        assert payload["journal_action"]

        human = runner.invoke(cli.app, ["external", str(ids["analysis"])])
        assert human.exit_code == 0, human.output
        assert "emotet" in human.output
        assert "local" in human.output

    def test_status_prints_the_gate_and_the_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        runner.invoke(cli.app, ["external", str(ids["analysis"])])
        result = runner.invoke(
            cli.app,
            ["external-status", str(ids["analysis"]), "--source", external.LOCAL_SOURCE, "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["stored"] is True

        human = runner.invoke(
            cli.app, ["external-status", str(ids["analysis"]), "--source", external.LOCAL_SOURCE]
        )
        assert human.exit_code == 0, human.output
        assert "fetched_at" in human.output

    def test_a_disabled_remote_source_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        result = runner.invoke(
            cli.app,
            ["external", str(ids["analysis"]), "--source", external.VIRUSTOTAL_SOURCE],
        )
        assert result.exit_code == 1
        assert external.ERROR_DISABLED in result.output

    def test_an_unknown_source_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed(tmp_path, monkeypatch)
        for argv in (
            ["external", str(ids["analysis"]), "--source", "nope"],
            ["external-status", str(ids["analysis"]), "--source", "nope"],
        ):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert external.ERROR_UNKNOWN in result.output

    def test_an_unknown_analysis_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(tmp_path, monkeypatch)
        for argv in (["external", "999"], ["external-status", "999"]):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no analysis with id 999" in result.output

    def test_the_commands_fail_without_a_database(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(DB_ENV, str(tmp_path / "missing" / "portal.db"))
        for argv in (["external", "1"], ["external-status", "1"]):
            result = runner.invoke(cli.app, argv)
            assert result.exit_code == 1, argv
            assert "no reportal database" in result.output


class TestMcp:
    def test_the_registry_tool_lists_the_sources(self) -> None:
        payload, failed = mcp_server.call_tool("list_external_sources", {})
        assert not failed
        assert payload["count"] == 2

    def test_a_run_then_every_read_tool(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        payload, failed = mcp_server.call_tool(
            "run_external_source",
            {"analysis_id": ids["analysis"], "source": external.LOCAL_SOURCE},
        )
        assert not failed, payload
        assert payload["journal_action"]

        stored, failed = mcp_server.call_tool(
            "get_external_report",
            {"analysis_id": ids["analysis"], "source": external.LOCAL_SOURCE},
        )
        assert not failed
        assert stored["payload"]["families"] == ["emotet"]

        state, failed = mcp_server.call_tool(
            "get_external_status",
            {"analysis_id": ids["analysis"], "source": external.LOCAL_SOURCE},
        )
        assert not failed
        assert state["stored"] is True

    def test_the_tools_report_their_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        payload, failed = mcp_server.call_tool(
            "get_external_report",
            {"analysis_id": ids["analysis"], "source": external.LOCAL_SOURCE},
        )
        assert failed
        assert payload["error"] == "no-scan"

        payload, failed = mcp_server.call_tool(
            "run_external_source",
            {"analysis_id": ids["analysis"], "source": external.VIRUSTOTAL_SOURCE},
        )
        assert failed
        assert payload["error"] == external.ERROR_DISABLED

        payload, failed = mcp_server.call_tool(
            "run_external_source", {"analysis_id": 999, "source": external.LOCAL_SOURCE}
        )
        assert failed
        assert payload["error"] == "analysis not found"

        payload, failed = mcp_server.call_tool(
            "run_external_source", {"analysis_id": ids["analysis"], "source": "nope"}
        )
        assert failed
        assert payload["error"] == external.ERROR_UNKNOWN

        payload, failed = mcp_server.call_tool(
            "get_external_status", {"analysis_id": ids["analysis"], "source": "nope"}
        )
        assert failed
        assert payload["error"] == external.ERROR_UNKNOWN

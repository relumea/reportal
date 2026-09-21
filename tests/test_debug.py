"""Tests for the read-only debug sessions: the guards, the ledger and the surfaces."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request

from reportal import debug, journal, store


def _seed(conn: sqlite3.Connection, tmp_path: Path) -> int:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return store.add_binary(
        conn, sha256="b" * 64, name=path.name, path=str(path), size=path.stat().st_size
    )


def _db(tmp_path: Path, name: str = "t.db") -> Path:
    db = tmp_path / name
    store.init_db(db)
    return db


def _post(path: str, body: dict[str, Any] | None = None) -> tuple[str, Any]:
    raw = b"" if body is None else json.dumps(body).encode()
    status, headers, payload = wsgi_request("POST", path, body=raw)
    return status, json_body(payload, headers)


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


class TestGuards:
    def test_it_is_off_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)

        assert debug.enabled() is False
        with pytest.raises(debug.DebugError) as caught:
            debug.require_enabled()

        assert caught.value.code == debug.ERROR_DISABLED

    def test_the_environment_and_the_workspace_table_enable_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("[debug]\nenabled = true\n")
        monkeypatch.chdir(tmp_path)

        assert debug.enabled() is True

        monkeypatch.chdir(Path(__file__).resolve().parents[1])
        monkeypatch.setenv(debug.ENABLED_ENV, "yes")
        assert debug.enabled() is True
        monkeypatch.setenv(debug.ENABLED_ENV, "0")
        assert debug.enabled() is False

    def test_bad_bounds_are_refused(self) -> None:
        with pytest.raises(debug.DebugError) as caught:
            debug.requested_caps(timeout=0)
        assert caught.value.code == debug.ERROR_INVALID
        with pytest.raises(debug.DebugError) as caught:
            debug.requested_caps(timeout=debug.MAX_TIMEOUT_SECONDS + 1)
        assert caught.value.code == debug.ERROR_INVALID

    def test_both_backends_are_registered(self) -> None:
        names = {entry.name for entry in debug.registered_backends()}
        assert {"lldb-dap", "gdb"} <= names

    def test_unknown_backend_has_no_probe(self, tmp_path: Path) -> None:
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"\x7fELF")
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(sample, backend=debug.Backend("other", "other"))
        assert caught.value.code == debug.ERROR_UNAVAILABLE

    def test_mi_result_reads_the_last_response_line(self) -> None:
        ok, text = debug._mi_result(["*stopped", '^done,threads=[{id="1"}]'])
        assert ok is True
        assert text.startswith("^done")
        ok, _ = debug._mi_result(["*stopped", '^error,msg="x"'])
        assert ok is False


class TestLedger:
    def test_live_session_reuse(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        calls: list[str] = []

        def fake_probe(
            sample: Path,
            *,
            caps: debug.Caps | None = None,
            backend: debug.Backend | None = None,
            breakpoints: Any = None,
        ) -> dict[str, Any]:
            calls.append(str(sample))
            return {
                "status": debug.STATUS_FINISHED,
                "backend": "lldb-dap",
                "argv": ["lldb-dap"],
                "caps": (caps or debug.requested_caps()).as_payload(),
                "transcript": [{"request": "initialize", "success": True}],
                "notes": [],
            }

        monkeypatch.setattr(debug, "probe_binary", fake_probe)
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("lldb-dap", "lldb-dap"))
        db = _db(tmp_path)
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            first = debug.run_session(conn, binary_id)
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            assert analysis_id is not None
            scanned = store.get_scan(conn, analysis_id, debug.SCAN_KIND)
            assert scanned is not None
            assert scanned["session_id"] == first["id"]
            # A second probe for the same binary reuses the live row.
            conn.execute(
                f"UPDATE {debug.TABLE} SET status = ? WHERE id = ?",
                (debug.STATUS_RUNNING, first["id"]),
            )
            conn.commit()
            second = debug.run_session(conn, binary_id)
            assert second["id"] == first["id"]
            stored_binary = store.get_binary(conn, binary_id)
            assert stored_binary is not None
            assert calls == [str(Path(str(stored_binary["path"])))]

    def test_routes_refuse_when_off(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        db = _db(tmp_path)
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
        _ = binary_id

    def test_unregister_builtin_is_refused(self) -> None:
        from reportal.plugins import RegistryError

        with pytest.raises(RegistryError):
            debug.unregister_backend(debug.BUILTIN_BACKEND)
        with pytest.raises(RegistryError):
            debug.unregister_backend("no-such-backend")


class TestRoutes:
    def test_post_refuses_when_off(self, portal_db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from reportal._paths import DB_ENV

        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        monkeypatch.setenv(DB_ENV, str(portal_db))
        with store.connect(portal_db) as conn:
            binary_id = _seed(conn, portal_db.parent)
        status, payload = _post(f"/api/binaries/{binary_id}/debug-session", {})
        assert status.startswith("403")
        assert payload["error"] == debug.ERROR_DISABLED

    def test_get_reports_no_session(self, portal_db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from reportal._paths import DB_ENV

        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        monkeypatch.setenv(DB_ENV, str(portal_db))
        with store.connect(portal_db) as conn:
            binary_id = _seed(conn, portal_db.parent)
        status, payload = _get(f"/api/binaries/{binary_id}/debug-session")
        assert status.startswith("404")
        assert payload["error"] == debug.ERROR_NO_SESSION

    def test_status_reports_opt_in(self, portal_db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from reportal._paths import DB_ENV

        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        monkeypatch.setenv(DB_ENV, str(portal_db))
        with store.connect(portal_db) as conn:
            binary_id = _seed(conn, portal_db.parent)
        status, payload = _get(f"/api/binaries/{binary_id}/debug-session/status")
        assert status.startswith("200")
        assert payload["enabled"] is False

    def test_coverage_joins_addresses_to_functions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("lldb-dap", "lldb-dap"))
        monkeypatch.setattr(
            debug,
            "probe_binary",
            lambda sample, **kwargs: {
                "status": debug.STATUS_FINISHED,
                "backend": "lldb-dap",
                "argv": ["lldb-dap"],
                "caps": debug.requested_caps().as_payload(),
                "transcript": [
                    {
                        "request": "stackTrace",
                        "success": True,
                        "frames": [
                            {"name": "main", "instructionPointerReference": "0x1010"},
                        ],
                    },
                    {
                        "request": "readMemory",
                        "success": True,
                        "address": "0x2050",
                        "data": "",
                        "encoding": "hex",
                    },
                ],
                "notes": [],
            },
        )
        db = _db(tmp_path, "cov.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
            store.upsert_function(
                conn, analysis_id=analysis_id, va=0x1000, name="main", size=0x100, status="STUB"
            )
            store.upsert_function(
                conn, analysis_id=analysis_id, va=0x2000, name="far", size=0x100, status="STUB"
            )
            session = debug.run_session(conn, binary_id)
            coverage = debug.observed_coverage(conn, binary_id)
            assert coverage is not None
            assert coverage["session_id"] == session["id"]
            assert coverage["observed"] == 2
            assert coverage["total"] == 2
            assert [row["name"] for row in coverage["functions"]] == ["main", "far"]

    def test_coverage_reports_no_session(self, tmp_path: Path) -> None:
        db = _db(tmp_path, "none.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            assert debug.observed_coverage(conn, binary_id) is None

    def test_coverage_route_reports_no_session(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal._paths import DB_ENV

        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        monkeypatch.setenv(DB_ENV, str(portal_db))
        with store.connect(portal_db) as conn:
            binary_id = _seed(conn, portal_db.parent)
        status, payload = _get(f"/api/binaries/{binary_id}/debug-coverage")
        assert status.startswith("404")
        assert payload["error"] == debug.ERROR_NO_SESSION

    def test_scan_records_journal_revert(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("lldb-dap", "lldb-dap"))
        monkeypatch.setattr(
            debug,
            "probe_binary",
            lambda sample, **kwargs: {
                "status": debug.STATUS_FINISHED,
                "backend": "lldb-dap",
                "argv": ["lldb-dap"],
                "caps": debug.requested_caps().as_payload(),
                "transcript": [{"request": "initialize", "success": True}],
                "notes": [],
            },
        )
        db = _db(tmp_path, "revert.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            session = debug.run_session(conn, binary_id)
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            assert analysis_id is not None
            actions = journal.list_actions(conn, limit=5)
            assert actions
            journal.revert_action(conn, actions[0]["action"])
            assert debug.latest_session(conn, analysis_id) is None
            _ = session

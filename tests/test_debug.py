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
            qemu_arch: Any = None,
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

    def test_render_transcript_is_citable(self) -> None:
        text = debug.render_transcript(
            [
                {"request": "threads", "success": True, "threads": [{"id": 1, "name": "t"}]},
                {
                    "request": "stackTrace",
                    "success": True,
                    "frames": [{"name": "main", "instructionPointerReference": "0x1000"}],
                },
            ],
            backend="gdb",
        )
        assert "# Debug session (gdb)" in text
        assert "thread 1: t" in text
        assert "frame main @ 0x1000" in text
        assert "unobserved is not absent" in text

    def test_session_ingests_a_digest_document(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import knowledge

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
        db = _db(tmp_path, "digest.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            debug.run_session(conn, binary_id)
            documents = store.list_documents(
                conn, scope_kind=knowledge.SCOPE_KIND_BINARY, scope_id=binary_id
            )
            assert len(documents) == 1
            assert documents[0]["title"].startswith("Debug session")
            hits = knowledge.retrieve(
                conn,
                query="initialize",
                scope_kind=knowledge.SCOPE_KIND_BINARY,
                scope_id=binary_id,
            )
            assert hits

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


def _dap_frame(payload: dict[str, object]) -> bytes:
    import json as _json

    body = _json.dumps(payload).encode()
    return b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


class _FakePipe:
    """An os.read/select-compatible handle over canned bytes."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def fileno(self) -> int:
        return -1


class TestDapReader:
    def test_reads_batched_frames_without_loss(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import os as _os

        event = {"type": "event", "event": "initialized", "seq": 1}
        response = {"type": "response", "request_seq": 2, "command": "launch", "success": True}
        blob = _dap_frame(event) + _dap_frame(response)
        chunks = [blob[:10], blob[10:]]

        def fake_read(_fd: int, _n: int) -> bytes:
            return chunks.pop(0) if chunks else b""

        monkeypatch.setattr(_os, "read", fake_read)
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        reader = debug._DapReader(_FakePipe(b""), 65536, 5.0)
        assert reader.read_event("initialized") == event
        assert reader.read_response(2) == response

    def test_request_frame_carries_content_length(self) -> None:
        import json as _json

        raw = debug._dap_request(3, "threads", {})
        head, _, body = raw.partition(b"\r\n\r\n")
        assert head.lower().startswith(b"content-length:")
        assert _json.loads(body)["command"] == "threads"

    def test_garbage_frame_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import os as _os

        monkeypatch.setattr(_os, "read", lambda _fd, _n: b"no-headers-here")
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        reader = debug._DapReader(_FakePipe(b""), 65536, 5.0)
        with pytest.raises(debug.DebugError) as caught:
            reader.read_message()
        assert caught.value.code == debug.ERROR_INVALID


class TestRegistryAndLedger:
    def test_backend_registry_round_trip(self) -> None:
        backend = debug.Backend("probe-backend", "probe-backend")
        debug.register_backend(backend)
        try:
            assert debug.get_backend("probe-backend") is backend
            assert backend in debug.registered_backends()
        finally:
            from reportal.plugins import RegistryError

            debug.BACKENDS[:] = [b for b in debug.BACKENDS if b.name != "probe-backend"]
            with pytest.raises(RegistryError):
                debug.unregister_backend("probe-backend")

    def test_refresh_backends_returns_names(self) -> None:
        names = debug.refresh_backends()
        assert "lldb-dap" in names

    def test_unavailable_detail_names_the_missing_backend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        monkeypatch.setenv(debug.BACKEND_ENV, "no-such-backend")
        assert "no-such-backend" in debug.unavailable_detail()
        with pytest.raises(debug.DebugError) as caught:
            debug.require_backend()
        assert caught.value.code == debug.ERROR_UNAVAILABLE

    def test_configured_name_prefers_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "reportal.toml").write_text('[debug]\nbackend = "gdb"\n')
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv(debug.BACKEND_ENV, raising=False)
        assert debug.configured_backend_name() == "gdb"
        monkeypatch.setenv(debug.BACKEND_ENV, "lldb-dap")
        assert debug.configured_backend_name() == "lldb-dap"

    def test_session_lifecycle_helpers(self, tmp_path: Path) -> None:
        db = _db(tmp_path, "ledger.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
            assert debug.find_live_session(conn, binary_id) is None
            assert debug.get_session(conn, 4242) is None
            assert debug.latest_session(conn, analysis_id) is None
            assert debug.count_sessions(conn, analysis_id) == 0
            caps = debug.requested_caps()
            session_id, created = debug.start_session(
                conn,
                analysis_id=analysis_id,
                binary_id=binary_id,
                sha256="d" * 64,
                backend="lldb-dap",
                argv=["lldb-dap"],
                caps=caps,
            )
            assert created is True
            live = debug.find_live_session(conn, binary_id)
            assert live is not None and live["id"] == session_id
            again_id, again_created = debug.start_session(
                conn,
                analysis_id=analysis_id,
                binary_id=binary_id,
                sha256="d" * 64,
                backend="lldb-dap",
                argv=["lldb-dap"],
                caps=caps,
            )
            assert (again_id, again_created) == (session_id, False)
            debug.finish_session(conn, session_id, [{"request": "initialize", "success": True}])
            assert debug.find_live_session(conn, binary_id) is None
            assert debug.count_sessions(conn, analysis_id) == 1
            payload = debug.status_payload(conn, analysis_id)
            assert payload["sessions"] == 1
            assert payload["last"]["id"] == session_id

    def test_fail_session_closes_the_row(self, tmp_path: Path) -> None:
        db = _db(tmp_path, "fail.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
            session_id, _ = debug.start_session(
                conn,
                analysis_id=analysis_id,
                binary_id=binary_id,
                sha256="d" * 64,
                backend="gdb",
                argv=["gdb"],
                caps=debug.requested_caps(),
            )
            debug.fail_session(conn, session_id, "boom")
            row = debug.get_session(conn, session_id)
            assert row is not None and row["status"] == debug.STATUS_FAILED

    def test_parse_address_rejects_garbage(self) -> None:
        assert debug._parse_address(None) is None
        assert debug._parse_address("not-an-address") is None
        assert debug._parse_address("0x1000") == 0x1000
        assert debug._parse_address("") is None

    def test_transcript_addresses_skips_bad_rows(self) -> None:
        session = {
            "transcript": [
                {"request": "x", "address": "0x2000"},
                {"request": "y", "frames": [{"instructionPointerReference": "0x3000"}]},
                {"request": "z", "address": "garbage"},
                "not-a-dict",
                {"request": "w", "frames": ["not-a-dict"]},
            ]
        }
        assert debug._transcript_addresses(session) == [0x2000, 0x3000]
        assert debug._transcript_addresses({}) == []
        assert debug._transcript_addresses({"transcript": "nope"}) == []


class TestMiHelpers:
    def test_send_writes_a_line(self) -> None:
        import io as _io

        handle = _io.BytesIO()
        handle.flush = lambda: None  # type: ignore[method-assign]
        debug._mi_send(handle, "-thread-info")
        assert handle.getvalue() == b"-thread-info\n"

    def test_wait_for_stop_collects_through_the_prompt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os as _os

        blob = b'*stopped,reason="breakpoint-hit"\n(gdb)\n'
        chunks = [blob]

        def fake_read(_fd: int, _n: int) -> bytes:
            return chunks.pop(0) if chunks else b""

        monkeypatch.setattr(_os, "read", fake_read)
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        text = debug._mi_wait_for_stop(_FakePipe(b""), 65536, 5.0, marker="breakpoint-hit")
        assert text is not None and "breakpoint-hit" in text

    def test_wait_for_stop_times_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: ([], [], []))
        assert debug._mi_wait_for_stop(_FakePipe(b""), 65536, 0.01, marker="breakpoint-hit") is None

    def test_probe_run_session_refuses_without_backend(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("gdb", "nope"))
        monkeypatch.setattr(debug.Backend, "path", lambda self: None)
        db = _db(tmp_path, "noprobe.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            with pytest.raises(debug.DebugError) as caught:
                debug.run_session(conn, binary_id)
            assert caught.value.code == debug.ERROR_UNAVAILABLE


class TestProbeDispatch:
    def test_probe_binary_rejects_too_many_breakpoints(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(
                sample,
                backend=debug.Backend("lldb-dap", "lldb-dap"),
                breakpoints=list(range(debug.MAX_BREAKPOINTS + 1)),
            )
        assert caught.value.code == debug.ERROR_INVALID

    def test_probe_binary_needs_an_installed_executable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        monkeypatch.setattr(debug.Backend, "path", lambda self: None)
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(sample, backend=debug.Backend("lldb-dap", "lldb-dap"))
        assert caught.value.code == debug.ERROR_UNAVAILABLE
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(sample, backend=debug.Backend("gdb", "gdb"))
        assert caught.value.code == debug.ERROR_UNAVAILABLE

    def test_dap_probe_with_a_scripted_backend(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json as _json

        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")

        def frame(payload: dict[str, object]) -> bytes:
            body = _json.dumps(payload).encode()
            return b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

        responses = [
            {"type": "response", "request_seq": 1, "command": "initialize", "success": True},
            {"type": "event", "event": "initialized", "seq": 10},
            {"type": "response", "request_seq": 3, "command": "configurationDone", "success": True},
            {"type": "response", "request_seq": 2, "command": "launch", "success": True},
            {
                "type": "event",
                "event": "stopped",
                "seq": 11,
                "body": {"threadId": 7, "reason": "entry"},
            },
            {
                "type": "response",
                "request_seq": 4,
                "command": "threads",
                "success": True,
                "body": {"threads": [{"id": 7, "name": "t"}]},
            },
            {
                "type": "response",
                "request_seq": 5,
                "command": "stackTrace",
                "success": True,
                "body": {
                    "stackFrames": [
                        {"id": 9, "name": "main", "instructionPointerReference": "0x1000"}
                    ]
                },
            },
            {
                "type": "response",
                "request_seq": 6,
                "command": "scopes",
                "success": True,
                "body": {
                    "scopes": [
                        {
                            "name": "Registers",
                            "presentationHint": "registers",
                            "variablesReference": 3,
                        }
                    ]
                },
            },
            {
                "type": "response",
                "request_seq": 7,
                "command": "variables",
                "success": True,
                "body": {
                    "variables": [{"name": "General Purpose Registers", "variablesReference": 4}]
                },
            },
            {
                "type": "response",
                "request_seq": 8,
                "command": "variables",
                "success": True,
                "body": {"variables": [{"name": "rax", "value": "0x1"}]},
            },
            {
                "type": "response",
                "request_seq": 9,
                "command": "readMemory",
                "success": True,
                "body": {"data": "3q=="},
            },
            {"type": "response", "request_seq": 10, "command": "disconnect", "success": True},
        ]
        blob = b"".join(frame(payload) for payload in responses)
        chunks = [blob]

        class FakeStdin:
            def write(self, _data: bytes) -> None:
                return None

            def flush(self) -> None:
                return None

            def close(self) -> None:
                return None

        class FakeProcess:
            stdin: object = FakeStdin()
            stdout: object = _FakePipe(b"")

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def kill(self) -> None:
                return None

        import os as _os

        def fake_read(_fd: int, _n: int) -> bytes:
            return chunks.pop(0) if chunks else b""

        monkeypatch.setattr(_os, "read", fake_read)
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        monkeypatch.setattr(debug.Backend, "path", lambda self: "/usr/bin/lldb-dap")
        monkeypatch.setattr("subprocess.Popen", lambda *a, **k: FakeProcess())
        report = debug.probe_binary(sample, backend=debug.Backend("lldb-dap", "lldb-dap"))
        kinds = [entry["request"] for entry in report["transcript"]]
        assert kinds == [
            "initialize",
            "launch",
            "configurationDone",
            "stopped",
            "threads",
            "stackTrace",
            "registers",
            "readMemory",
            "disconnect",
        ]
        registers = next(e for e in report["transcript"] if e["request"] == "registers")
        assert registers["registers"] == [{"name": "rax", "value": "0x1"}]
        memory = next(e for e in report["transcript"] if e["request"] == "readMemory")
        assert memory["encoding"] == "base64"

    def test_mi_probe_with_a_scripted_gdb(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")

        class FakeStdin:
            def write(self, _data: bytes) -> None:
                return None

            def flush(self) -> None:
                return None

            def close(self) -> None:
                return None

        class FakeStdout:
            def __init__(self, lines: list[bytes]) -> None:
                self._chunks = lines

            def fileno(self) -> int:
                return -1

        script_lines = [
            b"(gdb)\n",
            b'^done,bkpt={number="1"}\n',
            b"(gdb)\n",
            b"^running\n",
            b'*stopped,reason="breakpoint-hit",thread-id="1"\n',
            b"(gdb)\n",
            b'^done,threads=[{id="1",name="t"}]\n',
            b"(gdb)\n",
            b'^done,stack=[frame={func="main",addr="0x1000"}]\n',
            b"(gdb)\n",
            b'^done,register-names=["rax","rbx"]\n',
            b"(gdb)\n",
            b'^done,memory=[{contents="ff"}]\n',
            b"(gdb)\n",
            b"^done\n",
            b"(gdb)\n",
        ]

        import os as _os

        holder: dict[str, FakeStdout] = {}

        def fake_read(_fd: int, _n: int) -> bytes:
            pipe = holder.get("pipe")
            if pipe is not None and pipe._chunks:
                return pipe._chunks.pop(0)
            return b""

        monkeypatch.setattr(_os, "read", fake_read)
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))

        class FakeProcess:
            stdin: object = FakeStdin()
            stdout: FakeStdout = FakeStdout(script_lines)

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def kill(self) -> None:
                return None

        holder["pipe"] = FakeProcess.stdout

        monkeypatch.setattr(debug.Backend, "path", lambda self: "/usr/bin/gdb")
        monkeypatch.setattr("subprocess.Popen", lambda *a, **k: FakeProcess())
        report = debug.probe_binary(
            sample, backend=debug.Backend("gdb", "gdb"), breakpoints=[0x1000]
        )
        kinds = [entry["request"] for entry in report["transcript"]]
        assert kinds == [
            "break-insert",
            "exec-run",
            "threads",
            "stackTrace",
            "registers",
            "readMemory",
            "setBreakpoints",
            "disconnect",
        ]
        point = next(e for e in report["transcript"] if e["request"] == "setBreakpoints")
        assert point["address"] == 0x1000
        memory = next(e for e in report["transcript"] if e["request"] == "readMemory")
        assert memory["encoding"] == "hex"

    def test_run_session_covers_missing_binary_and_missing_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("gdb", "gdb"))
        db = _db(tmp_path, "missing.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            with pytest.raises(debug.DebugError) as caught:
                debug.run_session(conn, 4242)
            assert caught.value.code == "binary not found"
            binary_id = store.add_binary(
                conn, sha256="e" * 64, name="gone.bin", path="/no/such/file", size=1
            )
            with pytest.raises(debug.DebugError) as caught:
                debug.run_session(conn, binary_id)
            assert caught.value.code == "binary not on disk"

    def test_run_session_records_a_failed_probe(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("gdb", "gdb"))

        def boom(*args: object, **kwargs: object) -> dict[str, object]:
            raise RuntimeError("backend exploded")

        monkeypatch.setattr(debug, "probe_binary", boom)
        db = _db(tmp_path, "boom.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            with pytest.raises(RuntimeError):
                debug.run_session(conn, binary_id)
            analysis_id = store.latest_analysis_for_binary(conn, binary_id)
            assert analysis_id is not None
            session = debug.latest_session(conn, analysis_id)
            assert session is not None and session["status"] == debug.STATUS_FAILED


class TestDebugErrorBranches:
    def test_unreadable_workspace_logs_and_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("this is not [toml\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level("WARNING", logger="reportal.debug"):
            assert debug.enabled() is False
        assert any("falls back to off" in r.message for r in caplog.records)

    def test_workspace_without_marker_disables(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(debug.ENABLED_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        assert debug.enabled() is False
        assert debug.configured_backend_name() == ""

    def test_unknown_backend_name_is_refused(self) -> None:
        from reportal.plugins import RegistryError

        with pytest.raises(RegistryError):
            debug.unregister_backend("no-such-backend")

    def test_configured_but_missing_backend_is_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.BACKEND_ENV, "no-such-backend")
        assert debug.available_backend() is None

    def test_first_installed_backend_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(debug.BACKEND_ENV, raising=False)
        monkeypatch.setattr(debug.Backend, "path", lambda self: "/usr/bin/x")
        assert debug.available_backend() is not None
        assert debug.require_backend() is not None

    def test_no_installed_backend_is_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(debug.BACKEND_ENV, raising=False)
        monkeypatch.setattr(debug.Backend, "path", lambda self: None)
        assert debug.available_backend() is None
        assert "no debug backend" in debug.unavailable_detail()

    def test_dap_reader_refuses_oversize_frame(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import os as _os

        body = b"x" * 10
        blob = b"Content-Length: 10\r\n\r\n" + body
        chunks = [blob]
        monkeypatch.setattr(_os, "read", lambda _f, _n: chunks.pop(0) if chunks else b"")
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        reader = debug._DapReader(_FakePipe(b""), 5, 5.0)
        with pytest.raises(debug.DebugError) as caught:
            reader.read_message()
        assert caught.value.code == debug.ERROR_INVALID

    def test_dap_reader_refuses_bad_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import os as _os

        body = b"not json!!"
        blob = b"Content-Length: 10\r\n\r\n" + body
        chunks = [blob]
        monkeypatch.setattr(_os, "read", lambda _f, _n: chunks.pop(0) if chunks else b"")
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        reader = debug._DapReader(_FakePipe(b""), 65536, 5.0)
        with pytest.raises(debug.DebugError) as caught:
            reader.read_message()
        assert caught.value.code == debug.ERROR_INVALID

    def test_dap_reader_times_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: ([], [], []))
        reader = debug._DapReader(_FakePipe(b""), 65536, 0.01)
        with pytest.raises(debug.DebugError) as caught:
            reader.read_message()
        assert caught.value.code == debug.ERROR_INVALID

    def test_dap_response_with_wrong_seq_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import os as _os

        def frame(payload: dict[str, object]) -> bytes:
            import json as _json

            body = _json.dumps(payload).encode()
            return b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

        blob = frame({"type": "response", "request_seq": 99, "success": True}) + frame(
            {"type": "response", "request_seq": 1, "success": True}
        )
        chunks = [blob]
        monkeypatch.setattr(_os, "read", lambda _f, _n: chunks.pop(0) if chunks else b"")
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        reader = debug._DapReader(_FakePipe(b""), 65536, 5.0)
        assert reader.read_response(1)["request_seq"] == 1

    def test_dap_response_with_bad_type_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import os as _os

        def frame(payload: dict[str, object]) -> bytes:
            import json as _json

            body = _json.dumps(payload).encode()
            return b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

        chunks = [frame({"type": "request", "command": "x"})]
        monkeypatch.setattr(_os, "read", lambda _f, _n: chunks.pop(0) if chunks else b"")
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        reader = debug._DapReader(_FakePipe(b""), 65536, 5.0)
        with pytest.raises(debug.DebugError):
            reader.read_response(1)

    def test_mi_result_with_no_response_line(self) -> None:
        ok, text = debug._mi_result(["~output only"])
        assert (ok, text) == (False, "")

    def test_mi_wait_rejects_an_oversized_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import os as _os

        blob = b'x\n*stopped,reason="breakpoint-hit"\n(gdb)\n'
        chunks = [blob]
        monkeypatch.setattr(_os, "read", lambda _f, _n: chunks.pop(0) if chunks else b"")
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        with pytest.raises(debug.DebugError):
            debug._mi_wait_for_stop(_FakePipe(b""), 1, 5.0, marker="breakpoint-hit")

    def test_run_session_reuses_a_live_row(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("lldb-dap", "lldb-dap"))
        db = _db(tmp_path, "live.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
            session_id, _ = debug.start_session(
                conn,
                analysis_id=analysis_id,
                binary_id=binary_id,
                sha256="d" * 64,
                backend="lldb-dap",
                argv=["lldb-dap"],
                caps=debug.requested_caps(),
            )
            assert debug.run_session(conn, binary_id)["id"] == session_id


class TestProbeFailureBranches:
    def test_dap_probe_refuses_an_invalid_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os as _os

        def frame(payload: dict[str, object]) -> bytes:
            import json as _json

            body = _json.dumps(payload).encode()
            return b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

        blob = frame({"type": "response", "request_seq": 1, "success": True}) + frame(
            {"type": "bogus"}
        )
        chunks = [blob]
        monkeypatch.setattr(_os, "read", lambda _f, _n: chunks.pop(0) if chunks else b"")
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))

        class FakeStdin:
            def write(self, _data: bytes) -> None:
                return None

            def flush(self) -> None:
                return None

            def close(self) -> None:
                return None

        class FakeProcess:
            stdin: object = FakeStdin()
            stdout: object = _FakePipe(b"")

            def wait(self, timeout: float | None = None) -> int:
                return 0

        monkeypatch.setattr(debug.Backend, "path", lambda self: "/usr/bin/lldb-dap")
        monkeypatch.setattr("subprocess.Popen", lambda *a, **k: FakeProcess())
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(sample, backend=debug.Backend("lldb-dap", "lldb-dap"))
        assert caught.value.code == debug.ERROR_INVALID

    def test_dap_probe_maps_oserror_to_invalid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*args: object, **kwargs: object) -> object:
            raise OSError("nope")

        monkeypatch.setattr("subprocess.Popen", boom)
        monkeypatch.setattr(debug.Backend, "path", lambda self: "/usr/bin/lldb-dap")
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(sample, backend=debug.Backend("lldb-dap", "lldb-dap"))
        assert caught.value.code == debug.ERROR_INVALID

    def test_mi_probe_maps_oserror_to_invalid(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*args: object, **kwargs: object) -> object:
            raise OSError("nope")

        monkeypatch.setattr("subprocess.Popen", boom)
        monkeypatch.setattr(debug.Backend, "path", lambda self: "/usr/bin/gdb")
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(sample, backend=debug.Backend("gdb", "gdb"))
        assert caught.value.code == debug.ERROR_INVALID

    def test_mi_probe_rejects_bad_breakpoints(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        with pytest.raises(debug.DebugError):
            debug.probe_binary(
                sample,
                backend=debug.Backend("gdb", "gdb"),
                breakpoints=["x"],  # type: ignore[list-item]
            )


class TestDebugFinalBranches:
    def test_configured_backend_returns_when_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.BACKEND_ENV, "lldb-dap")
        monkeypatch.setattr(debug.Backend, "path", lambda self: "/usr/bin/x")
        assert debug.available_backend() is not None

    def test_configured_but_uninstalled_backend_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.BACKEND_ENV, "lldb-dap")
        monkeypatch.setattr(debug.Backend, "path", lambda self: None)
        assert debug.available_backend() is None

    def test_start_session_reraises_without_a_live_row(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _db(tmp_path, "reraises.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
            monkeypatch.setattr(debug, "find_live_session", lambda conn, binary_id: None)
            import sqlite3 as _sqlite

            with pytest.raises(_sqlite.IntegrityError):
                debug.start_session(
                    conn,
                    analysis_id=999999,
                    binary_id=binary_id,
                    sha256="d" * 64,
                    backend="lldb-dap",
                    argv=["lldb-dap"],
                    caps=debug.requested_caps(),
                )
            _ = analysis_id

    def test_coverage_with_no_analysis_returns_none(self, tmp_path: Path) -> None:
        db = _db(tmp_path, "noanalysis.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            assert debug.observed_coverage(conn, binary_id) is None

    def test_coverage_counts_zero_size_exact_match_only(
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
                        "frames": [{"name": "f", "instructionPointerReference": "0x1001"}],
                    },
                ],
                "notes": [],
            },
        )
        db = _db(tmp_path, "exact.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
            store.upsert_function(
                conn, analysis_id=analysis_id, va=0x1000, name="f", size=0, status="STUB"
            )
            debug.run_session(conn, binary_id)
            coverage = debug.observed_coverage(conn, binary_id)
            assert coverage is not None
            assert coverage["observed"] == 0
            assert coverage["total"] == 1


class TestDapVariants:
    def _scripted_dap(
        self, monkeypatch: pytest.MonkeyPatch, responses: list[dict[str, object | None]]
    ) -> None:
        import os as _os

        def frame(payload: dict[str, object]) -> bytes:
            import json as _json

            body = _json.dumps(payload).encode()
            return b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

        blob = b"".join(frame(payload) for payload in responses)
        chunks = [blob]

        class FakeStdin:
            def write(self, _data: bytes) -> None:
                return None

            def flush(self) -> None:
                return None

            def close(self) -> None:
                return None

        class FakeProcess:
            stdin: object = FakeStdin()
            stdout: object = _FakePipe(b"")

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def kill(self) -> None:
                return None

        monkeypatch.setattr(_os, "read", lambda _f, _n: chunks.pop(0) if chunks else b"")
        monkeypatch.setattr("select.select", lambda r, _w, _x, _t=None: (r, [], []))
        monkeypatch.setattr(debug.Backend, "path", lambda self: "/usr/bin/lldb-dap")
        monkeypatch.setattr("subprocess.Popen", lambda *a, **k: FakeProcess())

    def _full_responses(self) -> list[dict[str, object]]:
        return [
            {"type": "response", "request_seq": 1, "command": "initialize", "success": True},
            {"type": "event", "event": "output", "seq": 20, "body": {"output": "hi"}},
            {"type": "event", "event": "initialized", "seq": 21},
            {"type": "response", "request_seq": 3, "command": "configurationDone", "success": True},
            {"type": "response", "request_seq": 2, "command": "launch", "success": True},
            {
                "type": "event",
                "event": "stopped",
                "seq": 22,
                "body": {"threadId": 1, "reason": "entry"},
            },
            {"type": "event", "event": "output", "seq": 23, "body": {"output": "x"}},
            {
                "type": "response",
                "request_seq": 4,
                "command": "threads",
                "success": True,
                "body": {"threads": []},
            },
            {
                "type": "response",
                "request_seq": 5,
                "command": "stackTrace",
                "success": True,
                "body": {"stackFrames": []},
            },
            {"type": "response", "request_seq": 6, "command": "disconnect", "success": True},
        ]

    def test_launch_loop_skips_non_stopped_events(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._scripted_dap(monkeypatch, self._full_responses())
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        report = debug.probe_binary(
            sample, backend=debug.Backend("lldb-dap", "lldb-dap"), breakpoints=[0x1000]
        )
        kinds = [entry["request"] for entry in report["transcript"]]
        assert "setBreakpoints" in kinds
        point = next(e for e in report["transcript"] if e["request"] == "setBreakpoints")
        assert point["address"] == 0x1000

    def test_launch_loop_refuses_an_invalid_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        responses: list[dict[str, object | None]] = [
            {"type": "response", "request_seq": 1, "command": "initialize", "success": True},
            {"type": "event", "event": "initialized", "seq": 21},
            {"type": "bogus"},
        ]
        self._scripted_dap(monkeypatch, responses)
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(sample, backend=debug.Backend("lldb-dap", "lldb-dap"))
        assert caught.value.code == debug.ERROR_INVALID


class TestQemuStub:
    def test_qemu_arch_needs_gdb(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(
                sample, backend=debug.Backend("lldb-dap", "lldb-dap"), qemu_arch="x86_64"
            )
        assert caught.value.code == debug.ERROR_INVALID

    def test_missing_qemu_is_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        monkeypatch.setattr(debug.shutil, "which", lambda name: None)
        with pytest.raises(debug.DebugError) as caught:
            debug.probe_binary(sample, backend=debug.Backend("gdb", "gdb"), qemu_arch="x86_64")
        assert caught.value.code == debug.ERROR_UNAVAILABLE

    def test_free_tcp_port_is_loopback(self) -> None:
        port = debug._free_tcp_port()
        assert 1 <= port <= 65535


class TestSessionProposals:
    def test_frames_become_proposals_for_placeholder_names(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("gdb", "gdb"))
        monkeypatch.setattr(
            debug,
            "probe_binary",
            lambda sample, **kwargs: {
                "status": debug.STATUS_FINISHED,
                "backend": "gdb",
                "argv": ["gdb"],
                "caps": debug.requested_caps().as_payload(),
                "transcript": [
                    {
                        "request": "stackTrace",
                        "success": True,
                        "frames": [{"name": "main", "instructionPointerReference": "0x1010"}],
                    },
                ],
                "notes": [],
            },
        )
        db = _db(tmp_path, "props.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
            function_id, _ = store.upsert_function(
                conn,
                analysis_id=analysis_id,
                va=0x1000,
                name="sub_1000",
                size=0x100,
                status="STUB",
            )
            debug.run_session(conn, binary_id)
            proposals = debug.session_proposals(conn, binary_id)
            assert proposals is not None
            assert proposals["count"] == 1
            row = proposals["proposals"][0]
            assert row["function_id"] == function_id
            assert row["proposed_name"] == "main"
            applied = debug.apply_session_proposal(conn, function_id=function_id)
            assert applied["new_name"] == "main"
            function = store.get_function(conn, function_id)
            assert function is not None and function["name_source"] == debug.SESSION_SOURCE

    def test_person_authored_names_are_never_proposed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(debug.ENABLED_ENV, "enabled")
        monkeypatch.setattr(debug, "require_backend", lambda: debug.Backend("gdb", "gdb"))
        monkeypatch.setattr(
            debug,
            "probe_binary",
            lambda sample, **kwargs: {
                "status": debug.STATUS_FINISHED,
                "backend": "gdb",
                "argv": ["gdb"],
                "caps": debug.requested_caps().as_payload(),
                "transcript": [
                    {
                        "request": "stackTrace",
                        "success": True,
                        "frames": [{"name": "main", "instructionPointerReference": "0x1010"}],
                    },
                ],
                "notes": [],
            },
        )
        db = _db(tmp_path, "guard.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            analysis_id = store.ensure_analysis_for_binary(conn, binary_id, engine="test")
            function_id, _ = store.upsert_function(
                conn,
                analysis_id=analysis_id,
                va=0x1000,
                name="mine",
                size=0x100,
                status="STUB",
                name_source="manual",
            )
            debug.run_session(conn, binary_id)
            proposals = debug.session_proposals(conn, binary_id)
            assert proposals is not None
            assert proposals["count"] == 0
            with pytest.raises(ValueError):
                debug.apply_session_proposal(conn, function_id=function_id)

    def test_proposals_need_a_session(self, tmp_path: Path) -> None:
        db = _db(tmp_path, "nop.db")
        with store.connect(db) as conn:
            debug.ensure_schema(conn)
            binary_id = _seed(conn, tmp_path)
            assert debug.session_proposals(conn, binary_id) is None
            with pytest.raises(KeyError):
                debug.apply_session_proposal(conn, function_id=4242)

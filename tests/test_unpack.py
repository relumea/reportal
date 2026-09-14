"""Tests for unpacking a packed executable and the provenance it produces.

The engine call and the external tool are both injected, so no test runs rebrew
or a real packer: the engine stub answers the LZEXE probe and writes canned
bytes, and the UPX path is driven by a throwaway ``upx`` script the module
resolves through its own lookup seam.  One test uses the sibling rebrew
checkout's real LZEXE fixture when it is present, and skips when it is not.
"""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeEngine, json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, engines, journal, mcp_server, store, unpack

runner = CliRunner()

# The real LZEXE fixture the sibling rebrew checkout ships: a Turbo C++ 3.1
# hello-world packed with the original LZEXE 0.91.  Used only when it exists.
REBREW_FIXTURES = Path(__file__).resolve().parents[2] / "rebrew" / "tests" / "fixtures"
PACKED = REBREW_FIXTURES / "tc16_hello_lzexe.exe"


def _get(path: str) -> Any:
    """Issue a GET and return its JSON body, asserting the 200."""
    status, headers, body = wsgi_request("GET", path)
    assert status.startswith("200"), body
    return json_body(body, headers)


def _post(path: str, body: str = "") -> tuple[str, Any]:
    """Issue a POST and return its status and JSON body."""
    raw = body.encode() if body else b""
    headers = {"Content-Type": "application/json"} if body else None
    status, response_headers, response = wsgi_request("POST", path, body=raw, headers=headers)
    return status, json_body(response, response_headers)


def _upx_script(tmp_path: Path, *, body: str = "") -> Path:
    """A stand-in ``upx`` that copies its input to its ``-o`` target."""
    tool = tmp_path / "upx"
    tool.write_text(
        body or '#!/bin/sh\n# -d -q -f -o <target> <source>\ncp "$6" "$5"\nexit 0\n',
        encoding="utf-8",
    )
    tool.chmod(0o755)
    return tool


def _seed(
    conn: sqlite3.Connection, tmp_path: Path, *, name: str = "packed.exe", body: bytes = b"MZpacked"
) -> int:
    """One stored binary whose file is on disk under *tmp_path*."""
    target = tmp_path / name
    target.write_bytes(body)
    return store.add_binary(
        conn,
        sha256=hashlib.sha256(body).hexdigest(),
        name=name,
        path=str(target),
        size=len(body),
        fmt="PE",
        arch="x86_32",
    )


def _workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make *tmp_path* the workspace, so the unpacked file lands inside it."""
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)


class TestDetection:
    def test_the_upx_marker_in_the_head_is_detected(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        target = tmp_path / "upx.exe"
        target.write_bytes(b"MZ" + b"\x00" * 16 + b"UPX!" + b"\x00" * 64)
        found = unpack.detect(target, engine=fake_engine)
        assert [entry["packer"] for entry in found] == ["upx"]
        assert found[0]["method"] == "upx"

    def test_the_upx_marker_at_the_end_of_a_large_file_is_detected(
        self, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        target = tmp_path / "big.exe"
        target.write_bytes(b"MZ" + b"\x00" * (unpack.UPX_MARKER_WINDOW * 3) + b"UPX!")
        assert [entry["packer"] for entry in unpack.detect(target, engine=fake_engine)] == ["upx"]

    def test_a_plain_file_detects_nothing(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        target = tmp_path / "plain.exe"
        target.write_bytes(b"MZ" + b"\x00" * 128)
        assert unpack.detect(target, engine=fake_engine) == []

    def test_the_lzexe_probe_asks_the_engine(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        target = tmp_path / "lz.exe"
        target.write_bytes(b"MZ" + b"\x00" * 64)
        fake_engine.lzexe_versions[str(target)] = 91
        found = unpack.detect(target, engine=fake_engine)
        assert found == [{"packer": "lzexe", "detail": "LZEXE 91 stub", "method": "engine"}]

    def test_an_unavailable_engine_still_names_upx(self, tmp_path: Path) -> None:
        target = tmp_path / "upx.exe"
        target.write_bytes(b"MZ" + b"UPX!" + b"\x00" * 64)
        found = unpack.detect(target, engine=engines.RebrewEngine(enabled=False))
        assert [entry["packer"] for entry in found] == ["upx"]

    def test_a_missing_file_detects_nothing(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        assert unpack.detect(tmp_path / "gone.exe", engine=fake_engine) == []


class TestUnpackTo:
    def test_lzexe_is_rebuilt_by_the_engine(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        source = tmp_path / "packed.exe"
        source.write_bytes(b"MZpacked")
        target = tmp_path / "out.exe"
        result = unpack.unpack_to(source, target, packer="lzexe", engine=fake_engine)
        assert result["method"] == "engine"
        assert result["version"] == 91
        assert target.read_bytes() == fake_engine.unpack_bytes
        assert fake_engine.calls == ["unpack_lzexe"]

    def test_an_unknown_packer_is_refused(self, tmp_path: Path, fake_engine: FakeEngine) -> None:
        with pytest.raises(unpack.UnpackError) as failure:
            unpack.unpack_to(
                tmp_path / "x.exe", tmp_path / "out.exe", packer="pkLite", engine=fake_engine
            )
        assert failure.value.code == "unknown-packer"

    def test_upx_without_the_tool_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(unpack, "_which", lambda _name: None)
        with pytest.raises(unpack.UnpackError) as failure:
            unpack.unpack_to(tmp_path / "x.exe", tmp_path / "out.exe", packer="upx")
        assert failure.value.code == "no-unpacker"
        assert "upx" in failure.value.detail

    def test_upx_runs_the_external_tool(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = tmp_path / "packed.exe"
        source.write_bytes(b"MZpayload")
        target = tmp_path / "out.exe"
        tool = _upx_script(tmp_path)
        monkeypatch.setattr(unpack, "_which", lambda _name: str(tool))
        result = unpack.unpack_to(source, target, packer="upx")
        assert result["method"] == "upx"
        assert result["tool"] == str(tool)
        assert result["file_size"] == len(b"MZpayload")
        assert target.read_bytes() == b"MZpayload"

    def test_a_failing_tool_reports_its_last_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = _upx_script(tmp_path, body='#!/bin/sh\necho "notPackedException" >&2\nexit 2\n')
        monkeypatch.setattr(unpack, "_which", lambda _name: str(tool))
        with pytest.raises(unpack.UnpackError) as failure:
            unpack.unpack_to(tmp_path / "x.exe", tmp_path / "out.exe", packer="upx")
        assert failure.value.code == "unpack-failed"
        assert "notPackedException" in failure.value.detail

    def test_a_tool_that_writes_nothing_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = _upx_script(tmp_path, body="#!/bin/sh\nexit 0\n")
        monkeypatch.setattr(unpack, "_which", lambda _name: str(tool))
        with pytest.raises(unpack.UnpackError) as failure:
            unpack.unpack_to(tmp_path / "x.exe", tmp_path / "out.exe", packer="upx")
        assert failure.value.code == "unpack-failed"


class TestRoutes:
    def test_post_registers_the_image_and_its_provenance(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        source = tmp_path / "packed.exe"
        source.write_bytes(b"MZpacked")
        fake_engine.lzexe_versions[str(source)] = 90
        binary_id = _seed(conn, tmp_path)
        status, payload = _post(f"/api/binaries/{binary_id}/unpack")
        assert status.startswith("200"), payload
        assert payload.pop("journal_action")
        new_id = payload["unpacked"]["binary_id"]
        assert new_id != binary_id
        assert payload["unpacked"]["name"] == "packed.unpacked.exe"
        assert payload["unpacked"]["sha256"] == hashlib.sha256(fake_engine.unpack_bytes).hexdigest()
        assert payload["packer"] == "lzexe"
        assert payload["method"] == "engine"
        assert payload["provenance"]["version"] == 90
        assert payload["provenance"]["source"]["binary_id"] == binary_id
        assert payload["provenance"]["stored"] is True
        assert source.read_bytes() == b"MZpacked"

        # The new binary is stored, on disk, and carries the provenance scan.
        row = store.get_binary(conn, int(new_id))
        assert row is not None
        assert Path(str(row["path"])).read_bytes() == fake_engine.unpack_bytes
        assert str(row["path"]).startswith(str(tmp_path))
        stored = _get(f"/api/binaries/{new_id}/unpack")
        assert stored["packer"] == "lzexe"
        assert stored["source"]["binary_id"] == binary_id

    def test_a_second_run_resolves_to_the_stored_binary(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        source = tmp_path / "packed.exe"
        source.write_bytes(b"MZpacked")
        fake_engine.lzexe_versions[str(source)] = 91
        binary_id = _seed(conn, tmp_path)
        _, first = _post(f"/api/binaries/{binary_id}/unpack")
        _, second = _post(f"/api/binaries/{binary_id}/unpack")
        assert second["unpacked"]["binary_id"] == first["unpacked"]["binary_id"]
        assert second["unpacked"]["duplicate"] is True
        assert second["provenance"]["stored"] is False
        assert any("already stored" in note for note in second["notes"])
        assert len(store.list_binaries(conn)) == 2

    def test_a_named_packer_and_name_are_honoured(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        tool = _upx_script(tmp_path)
        monkeypatch.setattr(unpack, "_which", lambda _name: str(tool))
        binary_id = _seed(conn, tmp_path, body=b"MZ" + b"UPX!" + b"\x00" * 32)
        status, payload = _post(
            f"/api/binaries/{binary_id}/unpack", '{"packer": "upx", "name": "renamed.exe"}'
        )
        assert status.startswith("200"), payload
        assert payload["packer"] == "upx"
        assert payload["unpacked"]["name"] == "renamed.exe"
        assert payload["unpacked"]["path"].endswith(".exe")

    def test_an_unpacked_binary_that_never_was_reports_stored_false(
        self, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        payload = _get(f"/api/binaries/{binary_id}/unpack")
        assert payload["stored"] is False
        assert payload["source"] is None
        assert "reportal unpack" in payload["notes"][0]

    def test_a_binary_with_nothing_packed_is_a_400(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path, body=b"MZ" + b"\x00" * 64)
        status, payload = _post(f"/api/binaries/{binary_id}/unpack")
        assert status.startswith("400")
        assert payload["error"] == "no-packer"
        assert "no known packer" in payload["detail"]

    def test_a_named_packer_that_does_not_match_is_a_400(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path, body=b"MZ" + b"\x00" * 64)
        status, payload = _post(f"/api/binaries/{binary_id}/unpack", '{"packer": "lzexe"}')
        assert status.startswith("400")
        assert payload["error"] == "no-packer"

    def test_an_unknown_packer_name_is_a_400(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path, body=b"MZ" + b"UPX!" + b"\x00" * 32)
        status, payload = _post(f"/api/binaries/{binary_id}/unpack", '{"packer": "pklite"}')
        assert status.startswith("400")
        assert payload["error"] == "unknown-packer"
        assert "lzexe" in payload["detail"]

    def test_an_unknown_binary_is_a_404(self, conn: sqlite3.Connection) -> None:
        status, payload = _post("/api/binaries/9999/unpack")
        assert status.startswith("404")
        assert payload["error"] == "binary not found"

    def test_a_row_without_a_file_is_a_400(self, conn: sqlite3.Connection) -> None:
        binary_id = store.add_binary(conn, sha256="11" * 32, name="ghost.exe", path="/nowhere")
        status, payload = _post(f"/api/binaries/{binary_id}/unpack")
        assert status.startswith("400")
        assert payload["error"] == "binary not on disk"


class TestJournal:
    def test_a_revert_removes_the_row_the_scan_and_the_file(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        source = tmp_path / "packed.exe"
        source.write_bytes(b"MZpacked")
        fake_engine.lzexe_versions[str(source)] = 91
        binary_id = _seed(conn, tmp_path)
        _, payload = _post(f"/api/binaries/{binary_id}/unpack")
        new_id = int(payload["unpacked"]["binary_id"])
        stored_path = Path(payload["unpacked"]["path"])
        assert stored_path.is_file()

        report = journal.revert_action(conn, payload["journal_action"])
        assert report["reverted"] >= 1
        assert store.get_binary(conn, new_id) is None
        assert not stored_path.exists()
        assert source.is_file()
        assert store.latest_analysis_for_binary(conn, new_id) is None


class TestMcp:
    def test_the_read_and_the_run_answer(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        source = tmp_path / "packed.exe"
        source.write_bytes(b"MZpacked")
        fake_engine.lzexe_versions[str(source)] = 91
        binary_id = _seed(conn, tmp_path)

        payload, failed = mcp_server.call_tool("get_unpack", {"binary_id": binary_id})
        assert failed is False
        assert payload["stored"] is False

        run, failed = mcp_server.call_tool("run_unpack", {"binary_id": binary_id})
        assert failed is False
        new_id = int(run["unpacked"]["binary_id"])

        stored, failed = mcp_server.call_tool("get_unpack", {"binary_id": new_id})
        assert failed is False
        assert stored["packer"] == "lzexe"
        assert stored["source"]["binary_id"] == binary_id

    def test_a_packed_binary_with_nothing_known_is_a_tool_error(
        self, conn: sqlite3.Connection, tmp_path: Path, fake_engine: FakeEngine
    ) -> None:
        binary_id = _seed(conn, tmp_path, body=b"MZ" + b"\x00" * 64)
        payload, failed = mcp_server.call_tool("run_unpack", {"binary_id": binary_id})
        assert failed is True
        assert payload["error"] == "no-packer"

    def test_an_unknown_binary_is_a_tool_error(self, conn: sqlite3.Connection) -> None:
        payload, failed = mcp_server.call_tool("get_unpack", {"binary_id": 9999})
        assert failed is True
        assert payload["error"] == "binary not found"


class TestCli:
    def test_the_unpack_command_prints_the_new_binary(
        self,
        portal_db: Path,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: FakeEngine,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        source = tmp_path / "packed.exe"
        source.write_bytes(b"MZpacked")
        fake_engine.lzexe_versions[str(source)] = 91
        binary_id = _seed(conn, tmp_path)
        conn.commit()
        result = runner.invoke(cli.app, ["unpack", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "lzexe" in result.output
        assert "packed.unpacked.exe" in result.output

        assert _get(f"/api/binaries/{binary_id}/unpack")["stored"] is False
        new_id = [row["id"] for row in store.list_binaries(conn) if row["id"] != binary_id][0]
        result = runner.invoke(cli.app, ["unpack-info", str(new_id)])
        assert result.exit_code == 0, result.output
        assert "source binary" in result.output

    def test_unpack_info_on_a_binary_that_was_not_unpacked(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        binary_id = _seed(conn, tmp_path)
        conn.commit()
        result = runner.invoke(cli.app, ["unpack-info", str(binary_id)])
        assert result.exit_code == 0, result.output
        assert "no stored unpack scan" in result.output

    def test_an_unknown_binary_fails_loud(
        self, portal_db: Path, conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        conn.commit()
        result = runner.invoke(cli.app, ["unpack-info", "9999"])
        assert result.exit_code == 1
        assert "binary not found" in result.output


@pytest.mark.skipif(not PACKED.is_file(), reason="the sibling rebrew LZEXE fixture is not present")
class TestRealEngine:
    def test_the_real_lzexe_fixture_unpacks(
        self,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The engine's own rebuild reaches disk, byte for byte."""
        from rebrew.lzexe import unpack_lzexe

        _workspace(tmp_path, monkeypatch)
        engines.set_engine(None)
        binary_id = _seed(conn, tmp_path, name="tc16_hello_lzexe.exe", body=PACKED.read_bytes())
        status, payload = _post(f"/api/binaries/{binary_id}/unpack")
        assert status.startswith("200"), payload
        expected = unpack_lzexe(PACKED).to_bytes()
        assert payload["packer"] == "lzexe"
        assert payload["provenance"]["version"] == 91
        assert payload["unpacked"]["sha256"] == hashlib.sha256(expected).hexdigest()
        assert Path(payload["unpacked"]["path"]).read_bytes() == expected
        assert expected[:2] == b"MZ"


def test_every_code_the_module_raises_is_documented() -> None:
    """The codes the unpack routes answer with are in the error catalogue."""
    from reportal import error_docs

    for code in (
        unpack.ERROR_UNKNOWN_PACKER,
        unpack.ERROR_NO_PACKER,
        unpack.ERROR_NO_UNPACKER,
        unpack.ERROR_UNPACK_FAILED,
        "engine-unavailable",
    ):
        assert error_docs.doc_anchor(code) is not None, code


def test_the_scan_kind_and_the_packer_vocabulary_agree() -> None:
    """The provenance scan kind is the store's, and every packer has a method note."""
    assert store.SCAN_KIND_UNPACK == unpack.SCAN_KIND
    assert set(unpack.PACKERS) == {"lzexe", "upx"}
    assert set(unpack.METHOD_NOTES) == set(unpack.PACKERS)

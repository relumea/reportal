"""Tests for the password-protected zip: the writer, the route, the CLI and the tool."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sqlite3
import struct
import zipfile
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, journal, mcp_tools, store, zipcrypto
from reportal._paths import DB_ENV

runner = CliRunner()

PAYLOAD = b"MZ" + bytes(range(256)) * 40
PASSWORD = "infected"
FIXED_HEADER = b"0123456789a"


def _read(blob: bytes, password: str = PASSWORD) -> bytes:
    """Read the single member of *blob* with stdlib ``zipfile``."""
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        name = archive.namelist()[0]
        archive.setpassword(password.encode())
        return archive.read(name)


def _seed(tmp_path: Path, monkeypatch: Any) -> dict[str, Any]:
    """A workspace with one stored binary whose file exists on disk."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    source = tmp_path / "notepad.exe"
    source.write_bytes(PAYLOAD)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(
            conn,
            sha256=hashlib.sha256(PAYLOAD).hexdigest(),
            name="notepad.exe",
            path=str(source),
            size=len(PAYLOAD),
        )
        missing = store.add_binary(
            conn,
            sha256="b" * 64,
            name="gone.exe",
            path=str(tmp_path / "gone.exe"),
            size=8,
        )
    return {"db": db, "binary": binary_id, "source": source, "missing": missing}


class TestWriter:
    def test_stdlib_zipfile_reads_the_member_back(self) -> None:
        blob = zipcrypto.build_protected_zip("sample.exe", PAYLOAD, PASSWORD, header=FIXED_HEADER)

        assert _read(blob) == PAYLOAD

    def test_default_header_entropy_uses_the_urandom_seam(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pinning ``_urandom`` makes two unprotected-header builds byte-identical."""
        monkeypatch.setattr(zipcrypto, "_urandom", lambda n: b"\xab" * n)
        first = zipcrypto.build_protected_zip("sample.exe", PAYLOAD, PASSWORD)
        second = zipcrypto.build_protected_zip("sample.exe", PAYLOAD, PASSWORD)
        assert first == second
        assert _read(first) == PAYLOAD

    def test_the_member_is_deflated_and_flagged_encrypted(self) -> None:
        blob = zipcrypto.build_protected_zip("sample.exe", PAYLOAD, PASSWORD, header=FIXED_HEADER)

        flags, method, _time, _date, crc, stored, size, name_len, _extra = struct.unpack(
            "<HHHHIIIHH", blob[6:30]
        )

        assert flags == zipcrypto._MEMBER_FLAGS
        assert method == zipfile.ZIP_DEFLATED
        assert crc == __import__("zlib").crc32(PAYLOAD)
        assert size == len(PAYLOAD)
        central = 46 + name_len
        assert stored == len(blob) - 30 - name_len - central - 22, (
            "the stored size counts the 12-byte encryption header"
        )
        assert blob[30 : 30 + name_len] == b"sample.exe"

    def test_a_non_ascii_member_name_round_trips(self) -> None:
        """UTF-8 bit 11 must be set or stdlib zipfile reads the name as CP437."""
        name = "café.bin"
        blob = zipcrypto.build_protected_zip(name, PAYLOAD, PASSWORD, header=FIXED_HEADER)

        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            assert archive.namelist() == [name]
            flags = struct.unpack_from("<H", blob, 6)[0]
            assert flags == zipcrypto._MEMBER_FLAGS
            archive.setpassword(PASSWORD.encode("utf-8"))
            assert archive.read(name) == PAYLOAD

    def test_the_wrong_password_is_refused(self) -> None:
        blob = zipcrypto.build_protected_zip("sample.exe", PAYLOAD, PASSWORD, header=FIXED_HEADER)

        with pytest.raises(RuntimeError):
            _read(blob, "not-the-password")

    def test_the_header_seam_is_what_makes_it_reproducible(self) -> None:
        first = zipcrypto.build_protected_zip("a.exe", PAYLOAD, PASSWORD, header=FIXED_HEADER)
        second = zipcrypto.build_protected_zip("a.exe", PAYLOAD, PASSWORD, header=FIXED_HEADER)
        random_one = zipcrypto.build_protected_zip("a.exe", PAYLOAD, PASSWORD)

        assert first == second
        assert random_one != first, "two downloads must not be byte-identical"

    def test_a_header_of_the_wrong_size_is_refused(self) -> None:
        with pytest.raises(ValueError):
            zipcrypto.build_protected_zip("a.exe", PAYLOAD, PASSWORD, header=b"short")

    def test_a_multi_chunk_member_round_trips(self) -> None:
        big = b"the quick brown fox\n" * (zipcrypto.READ_CHUNK_BYTES // 10)
        blob = zipcrypto.build_protected_zip("big.bin", big, PASSWORD, header=FIXED_HEADER)

        assert len(big) > zipcrypto.READ_CHUNK_BYTES
        assert _read(blob) == big

    def test_the_streaming_form_matches_the_in_memory_form(self) -> None:
        pieces = list(
            zipcrypto.stream_protected_zip(
                "a.exe", io.BytesIO(PAYLOAD), PASSWORD, header=FIXED_HEADER, chunk_bytes=64
            )
        )

        assert len(pieces) > 1, "the archive is handed out in pieces"
        assert b"".join(pieces) == zipcrypto.build_protected_zip(
            "a.exe", PAYLOAD, PASSWORD, header=FIXED_HEADER
        )

    def test_an_empty_member_round_trips(self) -> None:
        blob = zipcrypto.build_protected_zip("empty.bin", b"", PASSWORD, header=FIXED_HEADER)

        assert _read(blob) == b""


class TestRoute:
    def _zip(self, binary_id: int, **query: str) -> tuple[str, Any, bytes]:
        suffix = "?" + "&".join(f"{k}={v}" for k, v in query.items()) if query else ""
        status, headers, body = wsgi_request(
            "GET", f"/api/binaries/{binary_id}/download-zipped{suffix}"
        )
        return status, headers, body

    def test_it_serves_a_readable_zip(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        status, headers, body = self._zip(ids["binary"], password=PASSWORD)

        assert status.startswith("200")
        assert headers["Content-Type"] == "application/zip"
        assert headers["Content-Disposition"] == 'attachment; filename="notepad.exe.zip"'
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Reportal-Zip-Password"] == PASSWORD
        assert _read(body) == PAYLOAD

    def test_the_default_password_is_the_convention(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        _status, headers, body = self._zip(ids["binary"])

        assert headers["X-Reportal-Zip-Password"] == zipcrypto.DEFAULT_PASSWORD
        assert _read(body, zipcrypto.DEFAULT_PASSWORD) == PAYLOAD

    def test_a_named_password_is_honoured(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        _status, _headers, body = self._zip(ids["binary"], password="secret")

        assert _read(body, "secret") == PAYLOAD

    def test_an_empty_password_is_400(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        status, headers, body = self._zip(ids["binary"], password="")

        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid password"

    def test_an_overlong_password_is_400(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        status, headers, _body = self._zip(ids["binary"], password="x" * 200)

        assert status.startswith("400")
        assert json_body(_body, headers)["detail"] == zipcrypto.PASSWORD_LENGTH_DETAIL

    def test_a_password_with_a_control_character_is_400(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)

        status, headers, body = self._zip(ids["binary"], password="secret\r\nX-Evil: 1")

        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "invalid password"
        assert json_body(body, headers)["detail"] == zipcrypto.PASSWORD_CONTROL_DETAIL
        assert "x-evil" not in {key.lower() for key in headers}

        status, headers, body = self._zip(ids["binary"], password="secret\u200b")
        assert status.startswith("400")
        assert json_body(body, headers)["detail"] == zipcrypto.PASSWORD_CONTROL_DETAIL

    def test_an_unknown_binary_is_404(self, tmp_path: Path, monkeypatch: Any) -> None:
        _seed(tmp_path, monkeypatch)

        status, headers, body = self._zip(4242)

        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not found"

    def test_a_binary_whose_file_is_gone_is_404(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        status, headers, body = self._zip(ids["missing"])

        assert status.startswith("404")
        assert json_body(body, headers)["error"] == "binary not on disk"


class TestCli:
    def test_zip_writes_a_readable_archive(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        target = tmp_path / "out" / "sample.zip"

        result = runner.invoke(
            cli.app,
            ["download", str(ids["binary"]), "--zip", "--output", str(target), "--json"],
        )

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["zip"] is True
        assert payload["member"] == "notepad.exe.zip"
        assert payload["password"] == PASSWORD
        assert _read(target.read_bytes()) == PAYLOAD

    def test_zip_defaults_the_name_and_the_password(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(cli.app, ["download", str(ids["binary"]), "--zip", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["path"] == "notepad.exe.zip"
        assert _read((tmp_path / "notepad.exe.zip").read_bytes()) == PAYLOAD

    def test_a_named_password_is_used(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        target = tmp_path / "out.zip"

        result = runner.invoke(
            cli.app,
            [
                "download",
                str(ids["binary"]),
                "--zip",
                "--password",
                "chosen",
                "--output",
                str(target),
                "--json",
            ],
        )

        assert result.exit_code == 0
        assert _read(target.read_bytes(), "chosen") == PAYLOAD

    def test_an_empty_password_fails(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)

        result = runner.invoke(
            cli.app,
            [
                "download",
                str(ids["binary"]),
                "--zip",
                "--password",
                "",
                "--output",
                str(tmp_path / "x.zip"),
            ],
        )

        assert result.exit_code != 0
        assert "password must be 1 to" in result.output

    def test_an_existing_target_needs_force(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        target = tmp_path / "taken.zip"
        target.write_bytes(b"already here")

        result = runner.invoke(
            cli.app, ["download", str(ids["binary"]), "--zip", "--output", str(target)]
        )

        assert result.exit_code != 0
        assert "refusing to overwrite" in result.output
        assert target.read_bytes() == b"already here"


class TestMcp:
    def test_the_tool_is_registered_and_destructive(self) -> None:
        tool = mcp_tools.get_tool("export_zipped_binary")

        assert tool is not None
        assert tool.annotations.destructive_hint is True
        assert tool.annotations.read_only_hint is False

    def test_the_handler_writes_a_readable_archive(
        self, tmp_path: Path, monkeypatch: Any, portal_db: Path, conn: sqlite3.Connection
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        target = tmp_path / "tool.zip"
        tool = mcp_tools.get_tool("export_zipped_binary")
        assert tool is not None

        payload = tool.handler({"binary_id": ids["binary"], "path": str(target), "password": "pw"})

        assert payload["bytes"] == target.stat().st_size
        assert payload["password"] == "pw"
        assert _read(target.read_bytes(), "pw") == PAYLOAD

    def test_an_unknown_binary_is_a_tool_error(self, tmp_path: Path, monkeypatch: Any) -> None:
        _seed(tmp_path, monkeypatch)
        tool = mcp_tools.get_tool("export_zipped_binary")
        assert tool is not None

        try:
            tool.handler({"binary_id": 4242, "path": str(tmp_path / "x.zip")})
        except mcp_tools.ToolError as exc:
            assert exc.error == "binary not found"
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an unknown binary must be a tool error")

    def test_an_empty_password_is_a_tool_error(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        tool = mcp_tools.get_tool("export_zipped_binary")
        assert tool is not None

        try:
            tool.handler(
                {"binary_id": ids["binary"], "path": str(tmp_path / "x.zip"), "password": ""}
            )
        except mcp_tools.ToolError as exc:
            assert exc.detail.startswith("password must be 1 to")
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("an empty password must be a tool error")

    def test_a_password_with_a_control_character_is_a_tool_error(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        tool = mcp_tools.get_tool("export_zipped_binary")
        assert tool is not None

        try:
            tool.handler(
                {
                    "binary_id": ids["binary"],
                    "path": str(tmp_path / "x.zip"),
                    "password": "pw\r\nX-Evil: 1",
                }
            )
        except mcp_tools.ToolError as exc:
            assert exc.detail == zipcrypto.PASSWORD_CONTROL_DETAIL
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a control-character password must be a tool error")

    def test_a_path_outside_the_workspace_is_a_tool_error(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        ids = _seed(tmp_path, monkeypatch)
        outside = tmp_path.parent / f"outside-{tmp_path.name}" / "escaped.zip"
        tool = mcp_tools.get_tool("export_zipped_binary")
        assert tool is not None

        try:
            tool.handler({"binary_id": ids["binary"], "path": str(outside)})
        except mcp_tools.ToolError as exc:
            assert exc.error == "invalid path"
            assert "workspace" in exc.detail
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a path outside the workspace must be a tool error")
        assert not outside.exists()

    def test_the_write_is_revertible(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = _seed(tmp_path, monkeypatch)
        target = tmp_path / "revertible.zip"
        tool = mcp_tools.get_tool("export_zipped_binary")
        assert tool is not None

        payload = tool.handler({"binary_id": ids["binary"], "path": str(target)})
        assert target.is_file()
        with contextlib.closing(store.connect(ids["db"])) as conn:
            journal.revert_action(conn, payload["journal_action"])

        assert not target.is_file(), "the revert removes the file the tool wrote"

    def test_a_failed_write_leaves_the_previous_file_and_no_temp(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        source = tmp_path / "source.bin"
        source.write_bytes(b"payload")
        target = tmp_path / "target.zip"
        target.write_bytes(b"previous")

        def boom(*_args: Any, **_kwargs: Any) -> int:
            raise OSError("no space left")

        monkeypatch.setattr(zipcrypto, "write_protected_zip", boom)
        with pytest.raises(OSError):
            zipcrypto.write_protected_zip_file(source, target, "member.bin", "pw")

        assert target.read_bytes() == b"previous", "a failed write keeps the previous bytes"
        names = sorted(entry.name for entry in tmp_path.iterdir())
        assert names == ["source.bin", "target.zip"], "no half-written temp may survive"

"""The customer CLI is a thin platform client, never a workspace tool."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path
from typing import Any, Self

import pytest
from typer.testing import CliRunner

from reportal import customer_cli


class TestHelp:
    def test_help_lists_the_customer_path(self) -> None:
        result = CliRunner().invoke(customer_cli.app, ["--help"])
        assert result.exit_code == 0
        assert "upload" in result.stdout
        assert "binaries" in result.stdout
        assert "import-rebrew" not in result.stdout
        assert "rebrew" not in result.stdout.lower()

    def test_every_command_help_is_pipeable(self) -> None:
        for name in (
            "binaries",
            "binary",
            "upload",
            "functions",
            "function",
            "matches",
            "scans",
            "rename",
            "comment-add",
            "collections",
        ):
            result = CliRunner().invoke(customer_cli.app, [name, "--help"])
            assert result.exit_code == 0, name
            assert "Usage:" in result.stdout, name


class TestNoLocalState:
    def test_missing_token_fails_without_touching_a_workspace(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            customer_cli.app,
            ["binaries", "--server", "http://127.0.0.1:1", "--json"],
            env={},
        )
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert "token" in payload["error"]

    def test_unreachable_server_is_one_error(self) -> None:
        result = CliRunner().invoke(
            customer_cli.app,
            ["binary", "1", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert "error" in payload

    def test_module_imports_no_server_logic(self) -> None:
        import ast

        source = Path(customer_cli.__file__ or "").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for name in ("reportal.store", "reportal.engines", "reportal.server", "reportal.api"):
            assert name not in imported, name


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _raises_http(url: str, code: int, body: bytes) -> Any:
    from email.message import Message

    raise urllib.error.HTTPError(url, code, "err", Message(), io.BytesIO(body))


class TestCallErrors:
    def test_bad_scheme_is_a_customer_error(self) -> None:
        with pytest.raises(customer_cli.CustomerError, match="bad server URL"):
            customer_cli._call("GET", "/x", server="ftp://example.com", token="t", body=None)

    def test_http_error_carries_the_portal_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda request, timeout=60: _raises_http(
                str(request.full_url), 404, b'{"error": "nope", "detail": "d"}'
            ),
        )
        with pytest.raises(customer_cli.CustomerError, match="nope"):
            customer_cli._call("GET", "/x", server="http://127.0.0.1:1", token="t", body=None)

    def test_http_error_without_json_falls_back_to_status(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "urllib.request.urlopen",
            lambda request, timeout=60: _raises_http(str(request.full_url), 500, b"not json"),
        )
        with pytest.raises(customer_cli.CustomerError, match="HTTP 500"):
            customer_cli._call("GET", "/x", server="http://127.0.0.1:1", token="t", body={"a": 1})

    def test_os_error_is_unreachable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(request: Any, timeout: int = 60) -> Any:
            raise OSError("down")

        monkeypatch.setattr("urllib.request.urlopen", boom)
        with pytest.raises(customer_cli.CustomerError, match="cannot reach"):
            customer_cli._call("GET", "/x", server="http://127.0.0.1:1", token="t", body=None)

    def test_bad_json_is_a_customer_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "urllib.request.urlopen", lambda request, timeout=60: _FakeResponse(b"not json")
        )
        with pytest.raises(customer_cli.CustomerError, match="bad JSON"):
            customer_cli._call("GET", "/x", server="http://127.0.0.1:1", token="t", body=None)

    def test_empty_body_returns_an_empty_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "urllib.request.urlopen", lambda request, timeout=60: _FakeResponse(b"  ")
        )
        assert (
            customer_cli._call("GET", "/x", server="http://127.0.0.1:1", token="", body=None) == {}
        )


class TestCommandWiring:
    def test_binaries_lists_rows(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(
            customer_cli, "_call", lambda *a, **k: [{"id": 1, "name": "a", "sha256": "b" * 64}]
        )
        result = CliRunner().invoke(
            customer_cli.app,
            ["binaries", "--server", "http://127.0.0.1:1", "--token", "x"],
        )
        assert result.exit_code == 0, result.output

    def test_binaries_json_prints_the_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(customer_cli, "_call", lambda *a, **k: {"binaries": []})
        result = CliRunner().invoke(
            customer_cli.app,
            ["binaries", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout) == {"binaries": []}

    def test_engine_failure_is_one_error_line(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*args: object, **kwargs: object) -> object:
            raise customer_cli.CustomerError("down")

        monkeypatch.setattr(customer_cli, "_call", boom)
        result = CliRunner().invoke(
            customer_cli.app,
            ["binaries", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 1
        assert json.loads(result.stdout)["error"] == "down"


class TestShowCommands:
    def _ok(self, monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
        monkeypatch.setattr(customer_cli, "_call", lambda *a, **k: payload)

    def test_show_function_merges_decompilation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []

        def fake_call(
            method: str, path: str, *, server: str, token: str | None, body: object = None
        ) -> object:
            calls.append(path)
            return {"decompilation": "int f(){}"} if "decompilation" in path else {"id": 1}

        monkeypatch.setattr(customer_cli, "_call", fake_call)
        result = CliRunner().invoke(
            customer_cli.app,
            ["function", "1", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["decompilation"] == {"decompilation": "int f(){}"}
        assert len(calls) == 2

    def test_show_function_without_decompilation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_call(
            method: str, path: str, *, server: str, token: str | None, body: object = None
        ) -> object:
            if "decompilation" in path:
                raise customer_cli.CustomerError("gone")
            return {"id": 1}

        monkeypatch.setattr(customer_cli, "_call", fake_call)
        result = CliRunner().invoke(
            customer_cli.app,
            ["function", "1", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["decompilation"] is None

    def test_show_matches_and_scans(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._ok(monkeypatch, {"matches": []})
        for args in (
            ["matches", "1", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
            ["scans", "1", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        ):
            result = CliRunner().invoke(customer_cli.app, args)
            assert result.exit_code == 0, result.output


class TestWriteCommands:
    def test_rename_posts_the_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def fake_call(
            method: str, path: str, *, server: str, token: str | None, body: object = None
        ) -> object:
            seen.update(method=method, path=path, body=body or {})
            return {"ok": True}

        monkeypatch.setattr(customer_cli, "_call", fake_call)
        result = CliRunner().invoke(
            customer_cli.app,
            ["rename", "3", "main", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert seen == {
            "method": "POST",
            "path": "/api/functions/3/rename",
            "body": {"name": "main"},
        }

    def test_comment_posts_the_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def fake_call(
            method: str, path: str, *, server: str, token: str | None, body: object = None
        ) -> object:
            seen.update(method=method, path=path, body=body or {})
            return {"ok": True}

        monkeypatch.setattr(customer_cli, "_call", fake_call)
        result = CliRunner().invoke(
            customer_cli.app,
            [
                "comment-add",
                "4",
                "looks packed",
                "--server",
                "http://127.0.0.1:1",
                "--token",
                "x",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        assert seen["path"] == "/api/binaries/4/comments"

    def test_collections_lists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(customer_cli, "_call", lambda *a, **k: {"collections": [{"id": 1}]})
        result = CliRunner().invoke(
            customer_cli.app,
            ["collections", "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout) == {"collections": [{"id": 1}]}


class TestListAndEmit:
    def test_functions_list_with_name_filter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, object] = {}

        def fake_call(
            method: str, path: str, *, server: str, token: str | None, body: object = None
        ) -> object:
            seen["path"] = path
            return {"functions": []}

        monkeypatch.setattr(customer_cli, "_call", fake_call)
        result = CliRunner().invoke(
            customer_cli.app,
            [
                "functions",
                "5",
                "--name",
                "main",
                "--server",
                "http://127.0.0.1:1",
                "--token",
                "x",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        assert seen["path"] == "/api/binaries/5/functions?name=main"

    def test_emit_renders_tables_and_scalars(self, capsys: pytest.CaptureFixture[str]) -> None:
        customer_cli._emit([{"id": 1}], False)
        customer_cli._emit("plain", False)
        out = capsys.readouterr().out
        assert "plain" in out


class TestUpload:
    def test_missing_file_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            customer_cli, "_call", lambda *a, **k: (_ for _ in ()).throw(AssertionError())
        )
        result = CliRunner().invoke(
            customer_cli.app,
            [
                "upload",
                str(tmp_path / "gone.bin"),
                "--server",
                "http://127.0.0.1:1",
                "--token",
                "x",
                "--json",
            ],
        )
        assert result.exit_code == 1
        assert "not a file" in result.stdout

    def test_upload_posts_multipart(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import http.client as _http

        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")
        seen: dict[str, object] = {}

        class FakeResponse:
            status = 200

            def read(self) -> bytes:
                return b'{"id": 9}'

        class FakeConn:
            def __init__(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

            def request(
                self,
                method: str,
                path: str,
                body: bytes | None = None,
                headers: dict[str, str] | None = None,
            ) -> None:
                seen.update(method=method, path=path, body=body, headers=headers)

            def getresponse(self) -> FakeResponse:
                return FakeResponse()

        monkeypatch.setattr(_http, "HTTPConnection", FakeConn)
        result = CliRunner().invoke(
            customer_cli.app,
            [
                "upload",
                str(target),
                "--server",
                "http://127.0.0.1:1",
                "--token",
                "sekret",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        assert seen["method"] == "POST"
        assert seen["path"] == "/api/binaries"
        assert b"MZ" in bytes(seen["body"])  # type: ignore[arg-type]
        assert json.loads(result.stdout) == {"id": 9}

    def test_upload_server_error_names_the_problem(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import http.client as _http

        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")

        class FakeResponse:
            status = 413

            def read(self) -> bytes:
                return b'{"error": "file-too-large", "detail": "big"}'

        class FakeConn:
            def __init__(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

            def request(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

            def getresponse(self) -> FakeResponse:
                return FakeResponse()

        monkeypatch.setattr(_http, "HTTPConnection", FakeConn)
        result = CliRunner().invoke(
            customer_cli.app,
            ["upload", str(target), "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 1
        assert "file-too-large" in result.stdout


class TestHelpers:
    def test_version_flag(self) -> None:
        result = CliRunner().invoke(customer_cli.app, ["--version"])
        assert result.exit_code == 0
        assert "reportal-customer" in result.stdout

    def test_token_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(customer_cli.TOKEN_ENV, "env-token")
        assert customer_cli._token(None) == "env-token"
        assert customer_cli._token("explicit") == "explicit"

    def test_resolve_server_env_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(customer_cli.SERVER_ENV, "https://portal.example.com/")
        assert customer_cli._resolve_server("http://127.0.0.1:1") == "https://portal.example.com/"

    def test_fail_human_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        import typer as _typer

        with pytest.raises(_typer.Exit):
            customer_cli._fail("boom", False)


class TestUploadErrors:
    def test_plain_text_error_names_the_status(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import http.client as _http

        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")

        class FakeResponse:
            status = 500

            def read(self) -> bytes:
                return b"server exploded"

        class FakeConn:
            def __init__(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

            def request(self, *args: object, **kwargs: object) -> None:
                del args, kwargs

            def getresponse(self) -> FakeResponse:
                return FakeResponse()

        monkeypatch.setattr(_http, "HTTPConnection", FakeConn)
        result = CliRunner().invoke(
            customer_cli.app,
            ["upload", str(target), "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 1
        assert "HTTP 500" in result.stdout

    def test_connection_failure_is_one_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import http.client as _http

        target = tmp_path / "demo.exe"
        target.write_bytes(b"MZ")

        def boom(*args: object, **kwargs: object) -> object:
            raise OSError("down")

        monkeypatch.setattr(_http, "HTTPConnection", boom)
        result = CliRunner().invoke(
            customer_cli.app,
            ["upload", str(target), "--server", "http://127.0.0.1:1", "--token", "x", "--json"],
        )
        assert result.exit_code == 1
        assert "upload failed" in result.stdout


class TestHumanRenders:
    def test_binaries_table_lists_rows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            customer_cli,
            "_call",
            lambda *a, **k: [{"id": 1, "name": "a.exe", "sha256": "b" * 64, "function_count": 3}],
        )
        result = CliRunner().invoke(
            customer_cli.app,
            ["binaries", "--server", "http://127.0.0.1:1", "--token", "x"],
        )
        assert result.exit_code == 0, result.output
        assert "a.exe" in result.stderr

    def test_emit_dict_renders_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        customer_cli._emit({"id": 1}, False)
        assert json.loads(capsys.readouterr().out) == {"id": 1}

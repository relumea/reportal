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

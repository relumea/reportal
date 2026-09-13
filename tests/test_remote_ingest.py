"""Tests for guarded remote document ingestion.

Covers the address and port guards in :func:`remote_ingest.validate_target`, the
redirect and content-type contract of :func:`remote_ingest.fetch` against a
throwaway loopback ``http.server``, storage through
:func:`remote_ingest.ingest_url`, the enable gate (env and ``reportal.toml``),
and the HTTP and CLI surfaces.  The loopback seam and, for the surfaces that
cannot pass it, a patched ``validate_target`` keep every test offline.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import socket
import sqlite3
import threading
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, llm, remote_ingest, store
from reportal._paths import MARKER

runner = CliRunner()

NOTE_TEXT = "# Notes\n\nThe widget retry counter lives in the timer callback.\n"

# A public address the static resolver hands back, so no test resolves a name.
PUBLIC_ADDRESS = "93.184.216.34"


@pytest.fixture(autouse=True)
def _no_endpoint() -> Iterator[None]:
    """Install an unconfigured LLM client, so ingest never calls an embeddings endpoint."""
    llm.set_client(llm.LlmClient(None))
    yield
    llm.set_client(None)


@pytest.fixture()
def remote_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable remote ingestion through the environment variable."""
    monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, "1")


def _echo_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every host to itself, so a literal IP never touches the network."""

    def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def _static_resolver(monkeypatch: pytest.MonkeyPatch, *addresses: str) -> None:
    """Resolve every host to *addresses*, so a name maps to a chosen answer."""

    def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))
            for address in addresses
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def _admit_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the API and CLI surfaces reach a loopback ``http.server``.

    Those surfaces cannot pass the ``allow_loopback`` test seam, so the
    pre-flight check is replaced with an answer that admits the server and the
    peer check is told the transport exposes no peer address: the same
    unverifiable case an in-process transport produces, where the pre-flight
    answer stands.
    """
    monkeypatch.setattr(remote_ingest, "validate_target", lambda url, **kwargs: (url, "127.0.0.1"))
    monkeypatch.setattr(remote_ingest, "_peer_address", lambda response: None)


def _seed_binary(conn: sqlite3.Connection) -> int:
    """Create one binary in the isolated DB and return its id."""
    return store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path="/tmp/demo.exe")


def _ok(
    body: bytes, content_type: str | None = "text/markdown"
) -> tuple[int, dict[str, str], bytes]:
    """A 200 route carrying *body* and an optional content type."""
    headers: dict[str, str] = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    return 200, headers, body


def _redirect(location: str, status: int = 302) -> tuple[int, dict[str, str], bytes]:
    """A redirect route to *location*."""
    return status, {"Location": location}, b""


@contextlib.contextmanager
def _serve(
    routes: dict[str, tuple[int, dict[str, str], bytes]],
    *,
    records: dict[str, str] | None = None,
) -> Iterator[str]:
    """Serve *routes* on a loopback ephemeral port; yield the base URL.

    Each route is ``path -> (status, headers, body)``.  The server is shut down
    on exit, so a test never leaks a thread or a port.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if records is not None:
                records["user-agent"] = self.headers.get("User-Agent", "")
            entry = routes.get(self.path)
            if entry is None:
                self.send_error(404)
                return
            status, headers, body = entry
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class TestValidateTargetSchemes:
    @pytest.mark.parametrize(
        "url", ["ftp://example.com/x", "file:///etc/passwd", "data:text/plain,x"]
    )
    def test_non_http_schemes_are_rejected(self, url: str) -> None:
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target(url)
        assert excinfo.value.code == remote_ingest.ERROR_INVALID_URL

    def test_credentials_are_rejected(self) -> None:
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target("http://user:secret@example.com/notes.md")
        assert excinfo.value.code == remote_ingest.ERROR_INVALID_URL
        assert "credentials" in excinfo.value.detail

    @pytest.mark.parametrize("url", ["http://", "http:///notes.md", ""])
    def test_missing_host_is_rejected(self, url: str) -> None:
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target(url)
        assert excinfo.value.code == remote_ingest.ERROR_INVALID_URL

    def test_invalid_port_is_rejected(self) -> None:
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target("http://example.com:notaport/")
        assert excinfo.value.code == remote_ingest.ERROR_INVALID_URL


class TestValidateTargetAddresses:
    @pytest.mark.parametrize(
        "url",
        [
            "http://10.0.0.5/notes.md",
            "http://127.0.0.1/notes.md",
            "http://169.254.10.10/notes.md",
            "http://224.0.0.1/notes.md",
            "http://0.0.0.0/notes.md",
            "http://[::ffff:10.0.0.5]/notes.md",
        ],
    )
    def test_blocked_bare_addresses_are_rejected(
        self, url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _echo_resolver(monkeypatch)
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target(url)
        assert excinfo.value.code == remote_ingest.ERROR_BLOCKED_TARGET

    def test_a_hostname_resolving_private_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _static_resolver(monkeypatch, "10.1.2.3")
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target("http://intranet.example/notes.md")
        assert excinfo.value.code == remote_ingest.ERROR_BLOCKED_TARGET

    def test_any_private_answer_rejects_the_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _static_resolver(monkeypatch, PUBLIC_ADDRESS, "10.1.2.3")
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target("http://mixed.example/notes.md")
        assert excinfo.value.code == remote_ingest.ERROR_BLOCKED_TARGET

    def test_an_unresolvable_host_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
            raise socket.gaierror("no answer")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target("http://missing.example/notes.md")
        assert excinfo.value.code == remote_ingest.ERROR_UNRESOLVABLE

    def test_a_public_host_is_accepted_and_normalized(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _static_resolver(monkeypatch, PUBLIC_ADDRESS)
        normalized, address = remote_ingest.validate_target("HTTPS://Example.COM/notes.md?a=1#frag")
        assert normalized == "https://example.com/notes.md?a=1"
        assert address == PUBLIC_ADDRESS

    def test_the_loopback_seam_admits_a_loopback_target(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _echo_resolver(monkeypatch)
        normalized, address = remote_ingest.validate_target(
            "http://127.0.0.1:8123/notes.md", allow_loopback=True
        )
        assert normalized == "http://127.0.0.1:8123/notes.md"
        assert address == "127.0.0.1"

    def test_the_seam_never_admits_a_mapped_loopback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _echo_resolver(monkeypatch)
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target("http://[::ffff:127.0.0.1]/x", allow_loopback=True)
        assert excinfo.value.code == remote_ingest.ERROR_BLOCKED_TARGET


class TestValidateTargetPorts:
    def test_a_disallowed_port_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _static_resolver(monkeypatch, PUBLIC_ADDRESS)
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.validate_target("http://example.com:8080/notes.md")
        assert excinfo.value.code == remote_ingest.ERROR_INVALID_URL

    def test_the_scheme_default_port_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _static_resolver(monkeypatch, PUBLIC_ADDRESS)
        assert remote_ingest.validate_target("http://example.com:80/notes.md")[0] == (
            "http://example.com/notes.md"
        )
        assert remote_ingest.validate_target("https://example.com/notes.md")[0] == (
            "https://example.com/notes.md"
        )

    def test_the_seam_admits_a_loopback_ephemeral_port(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _echo_resolver(monkeypatch)
        normalized, _address = remote_ingest.validate_target(
            "http://127.0.0.1:49152/notes.md", allow_loopback=True
        )
        assert normalized == "http://127.0.0.1:49152/notes.md"


class TestFetch:
    def test_fetch_returns_the_body_and_metadata(self) -> None:
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}) as base:
            result = remote_ingest.fetch(
                f"{base}/notes.md", allow_loopback=True, max_bytes=4096, timeout=5
            )
        assert result["data"] == NOTE_TEXT.encode()
        assert result["bytes"] == len(NOTE_TEXT.encode())
        assert result["content_type"].startswith("text/markdown")
        assert result["url"] == f"{base}/notes.md"
        assert result["final_url"] == f"{base}/notes.md"

    def test_fetch_follows_and_revalidates_a_redirect_chain(self) -> None:
        routes = {
            "/a": _redirect("/b"),
            "/b": _redirect("/c"),
            "/c": _ok(NOTE_TEXT.encode()),
        }
        with _serve(routes) as base:
            result = remote_ingest.fetch(
                f"{base}/a", allow_loopback=True, max_bytes=4096, timeout=5
            )
        assert result["final_url"] == f"{base}/c"
        assert result["data"] == NOTE_TEXT.encode()

    def test_fetch_refuses_a_redirect_to_a_blocked_target(self) -> None:
        with (
            _serve({"/r": _redirect("http://10.0.0.1/notes.md")}) as base,
            pytest.raises(remote_ingest.RemoteIngestError) as excinfo,
        ):
            remote_ingest.fetch(f"{base}/r", allow_loopback=True, max_bytes=4096, timeout=5)
        assert excinfo.value.code == remote_ingest.ERROR_BLOCKED_TARGET

    def test_fetch_aborts_a_body_past_the_cap(self) -> None:
        with (
            _serve({"/big.md": _ok(b"x" * 500)}) as base,
            pytest.raises(remote_ingest.TooLargeError) as excinfo,
        ):
            remote_ingest.fetch(f"{base}/big.md", allow_loopback=True, max_bytes=16, timeout=5)
        assert excinfo.value.code == remote_ingest.ERROR_TOO_LARGE

    def test_fetch_refuses_an_unsupported_content_type(self) -> None:
        routes = {"/blob": _ok(b"\x00\x01", content_type="application/octet-stream")}
        with _serve(routes) as base, pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.fetch(f"{base}/blob", allow_loopback=True, max_bytes=4096, timeout=5)
        assert excinfo.value.code == remote_ingest.ERROR_UNSUPPORTED_CONTENT_TYPE

    def test_fetch_accepts_a_missing_content_type(self) -> None:
        with _serve({"/raw": _ok(NOTE_TEXT.encode(), content_type=None)}) as base:
            result = remote_ingest.fetch(
                f"{base}/raw", allow_loopback=True, max_bytes=4096, timeout=5
            )
        assert result["data"] == NOTE_TEXT.encode()

    def test_fetch_maps_a_connection_error(self) -> None:
        with _serve({"/x": _ok(b"x")}) as base:
            pass
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.fetch(f"{base}/x", allow_loopback=True, max_bytes=4096, timeout=5)
        assert excinfo.value.code == remote_ingest.ERROR_FETCH_FAILED

    def test_fetch_gives_up_after_max_redirects(self) -> None:
        with (
            _serve({"/loop": _redirect("/loop")}) as base,
            pytest.raises(remote_ingest.RemoteIngestError) as excinfo,
        ):
            remote_ingest.fetch(f"{base}/loop", allow_loopback=True, max_bytes=4096, timeout=5)
        assert excinfo.value.code == remote_ingest.ERROR_TOO_MANY_REDIRECTS

    def test_fetch_sends_the_reportal_user_agent(self) -> None:
        records: dict[str, str] = {}
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}, records=records) as base:
            remote_ingest.fetch(f"{base}/notes.md", allow_loopback=True, max_bytes=4096, timeout=5)
        assert records["user-agent"].startswith("reportal/")


class TestPeerAddress:
    def test_the_connected_peer_address_is_read_and_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str | None] = []
        real = remote_ingest._peer_address

        def spy(response: httpx.Response) -> str | None:
            value = real(response)
            calls.append(value)
            return value

        monkeypatch.setattr(remote_ingest, "_peer_address", spy)
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}) as base:
            result = remote_ingest.fetch(
                f"{base}/notes.md", allow_loopback=True, max_bytes=4096, timeout=5
            )
        assert calls == ["127.0.0.1"]
        assert result["peer_address"] == "127.0.0.1"
        assert result["data"] == NOTE_TEXT.encode()

    def test_a_blocked_peer_is_rejected_though_the_preflight_was_public(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The host resolves publicly, then the connection lands on loopback."""
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}) as base:
            port = urllib.parse.urlsplit(base).port
            monkeypatch.setattr(
                remote_ingest, "_resolved_addresses", lambda host, p: [PUBLIC_ADDRESS]
            )
            monkeypatch.setattr(remote_ingest, "ALLOWED_PORTS", frozenset({80, 443, port}))
            with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
                remote_ingest.fetch(f"{base}/notes.md", max_bytes=4096, timeout=5)
        assert excinfo.value.code == remote_ingest.ERROR_BLOCKED_TARGET
        assert "127.0.0.1" in excinfo.value.detail

    def test_a_transport_with_no_stream_is_marked_unverified(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _static_resolver(monkeypatch, PUBLIC_ADDRESS)
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers={"content-type": "text/markdown"}, content=NOTE_TEXT.encode()
            )
        )
        real_client = httpx.Client

        def factory(*args: Any, **kwargs: Any) -> httpx.Client:
            return real_client(*args, transport=transport, **kwargs)

        monkeypatch.setattr(httpx, "Client", factory)
        result = remote_ingest.fetch("http://example.com/notes.md", max_bytes=4096, timeout=5)
        assert result["peer_address"] == remote_ingest.PEER_UNVERIFIED
        assert result["data"] == NOTE_TEXT.encode()

    def test_each_redirect_hop_reads_its_own_peer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str | None] = []
        real = remote_ingest._peer_address

        def spy(response: httpx.Response) -> str | None:
            value = real(response)
            calls.append(value)
            if len(calls) > 1:
                return "10.1.2.3"
            return value

        monkeypatch.setattr(remote_ingest, "_peer_address", spy)
        routes = {"/a": _redirect("/b"), "/b": _ok(NOTE_TEXT.encode())}
        with _serve(routes) as base, pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.fetch(f"{base}/a", allow_loopback=True, max_bytes=4096, timeout=5)
        assert excinfo.value.code == remote_ingest.ERROR_BLOCKED_TARGET
        assert calls == ["127.0.0.1", "127.0.0.1"]
        assert "10.1.2.3" in excinfo.value.detail


class TestIngestUrl:
    def test_it_stores_the_document_with_the_final_url(
        self, conn: sqlite3.Connection, remote_on: None
    ) -> None:
        binary_id = _seed_binary(conn)
        routes = {"/a": _redirect("/notes.md"), "/notes.md": _ok(NOTE_TEXT.encode())}
        with _serve(routes) as base:
            payload = remote_ingest.ingest_url(
                conn,
                scope_kind="binary",
                scope_id=binary_id,
                url=f"{base}/a",
                allow_loopback=True,
            )
        assert payload["source"] == f"{base}/notes.md"
        assert payload["duplicate"] is False
        assert payload["chunk_count"] == 1

    def test_a_second_fetch_is_a_duplicate(self, conn: sqlite3.Connection, remote_on: None) -> None:
        binary_id = _seed_binary(conn)
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}) as base:
            first = remote_ingest.ingest_url(
                conn,
                scope_kind="binary",
                scope_id=binary_id,
                url=f"{base}/notes.md",
                allow_loopback=True,
            )
            second = remote_ingest.ingest_url(
                conn,
                scope_kind="binary",
                scope_id=binary_id,
                url=f"{base}/notes.md",
                allow_loopback=True,
            )
        assert second["duplicate"] is True
        assert second["id"] == first["id"]
        assert len(store.list_documents(conn, scope_kind="binary", scope_id=binary_id)) == 1

    def test_a_fetch_failure_leaves_no_document(
        self, conn: sqlite3.Connection, remote_on: None
    ) -> None:
        binary_id = _seed_binary(conn)
        with _serve({"/x": _ok(b"x")}) as base:
            pass
        with pytest.raises(remote_ingest.RemoteIngestError):
            remote_ingest.ingest_url(
                conn, scope_kind="binary", scope_id=binary_id, url=f"{base}/x", allow_loopback=True
            )
        assert store.list_documents(conn, scope_kind="binary", scope_id=binary_id) == []

    def test_a_rejected_case_never_writes(
        self, conn: sqlite3.Connection, remote_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed_binary(conn)
        monkeypatch.setattr(remote_ingest, "MAX_BYTES", 16)
        with (
            _serve({"/big.md": _ok(b"x" * 500)}) as base,
            pytest.raises(remote_ingest.TooLargeError),
        ):
            remote_ingest.ingest_url(
                conn,
                scope_kind="binary",
                scope_id=binary_id,
                url=f"{base}/big.md",
                allow_loopback=True,
            )
        assert store.list_documents(conn, scope_kind="binary", scope_id=binary_id) == []


class TestEnableGate:
    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        assert remote_ingest.remote_enabled() is False

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_env_truthy_spellings_enable(self, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, value)
        assert remote_ingest.remote_enabled() is True

    @pytest.mark.parametrize("value", ["0", "no", "false", "off", ""])
    def test_env_falsy_spellings_do_not_enable(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, value)
        assert remote_ingest.remote_enabled() is False

    def test_config_enables(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / MARKER).write_text("[knowledge]\nallow_remote = true\n", encoding="utf-8")
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        assert remote_ingest.remote_enabled() is True

    def test_config_false_does_not_enable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / MARKER).write_text("[knowledge]\nallow_remote = false\n", encoding="utf-8")
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        assert remote_ingest.remote_enabled() is False

    def test_ingest_url_refuses_while_disabled(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        with pytest.raises(remote_ingest.RemoteIngestError) as excinfo:
            remote_ingest.ingest_url(
                conn, scope_kind="binary", scope_id=0, url="http://example.com/notes.md"
            )
        assert excinfo.value.code == remote_ingest.ERROR_DISABLED
        assert excinfo.value.detail == remote_ingest.DISABLED_DETAIL


class TestApi:
    def _post(self, body: dict[str, Any]) -> tuple[str, dict[str, str], bytes]:
        return wsgi_request(
            "POST",
            "/api/knowledge/fetch",
            body=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

    def test_config_route_reports_disabled(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        status, headers, raw = wsgi_request("GET", "/api/knowledge/config")
        assert status.startswith("200")
        assert json_body(raw, headers) == {"allow_remote": False}

    def test_config_route_reports_enabled(
        self, portal_db: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, "1")
        status, headers, raw = wsgi_request("GET", "/api/knowledge/config")
        assert status.startswith("200")
        assert json_body(raw, headers) == {"allow_remote": True}

    def test_disabled_is_403(self, portal_db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        status, headers, raw = self._post(
            {"scope_kind": "project", "scope_id": 0, "url": "http://example.com/notes.md"}
        )
        assert status.startswith("403")
        payload = json_body(raw, headers)
        assert payload["error"] == remote_ingest.ERROR_DISABLED
        assert payload["detail"] == remote_ingest.DISABLED_DETAIL

    def test_blocked_target_is_400(self, conn: sqlite3.Connection, remote_on: None) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = self._post(
            {"scope_kind": "binary", "scope_id": binary_id, "url": "http://10.0.0.1/notes.md"}
        )
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == remote_ingest.ERROR_BLOCKED_TARGET

    def test_an_invalid_scheme_is_400(self, conn: sqlite3.Connection, remote_on: None) -> None:
        binary_id = _seed_binary(conn)
        status, headers, raw = self._post(
            {"scope_kind": "binary", "scope_id": binary_id, "url": "ftp://example.com/x"}
        )
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == remote_ingest.ERROR_INVALID_URL

    def test_unknown_scope_is_404(self, conn: sqlite3.Connection, remote_on: None) -> None:
        status, headers, raw = self._post(
            {"scope_kind": "binary", "scope_id": 99, "url": "http://example.com/notes.md"}
        )
        assert status.startswith("404")
        assert json_body(raw, headers)["error"] == "binary not found"

    def test_a_loopback_target_is_400_for_the_api(
        self, conn: sqlite3.Connection, remote_on: None
    ) -> None:
        """The production route never passes the seam, so a loopback URL is blocked."""
        binary_id = _seed_binary(conn)
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}) as base:
            status, headers, raw = self._post(
                {"scope_kind": "binary", "scope_id": binary_id, "url": f"{base}/notes.md"}
            )
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == remote_ingest.ERROR_BLOCKED_TARGET

    def test_the_success_path_stores_the_document(
        self,
        conn: sqlite3.Connection,
        remote_on: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        binary_id = _seed_binary(conn)
        _admit_loopback(monkeypatch)
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}) as base:
            status, headers, raw = self._post(
                {
                    "scope_kind": "binary",
                    "scope_id": binary_id,
                    "title": "Network notes",
                    "url": f"{base}/notes.md",
                }
            )
        assert status.startswith("201")
        payload = json_body(raw, headers)
        assert payload["title"] == "Network notes"
        assert payload["source"] == f"{base}/notes.md"
        assert payload["chunk_count"] == 1

    def test_an_oversized_body_is_413(
        self, conn: sqlite3.Connection, remote_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed_binary(conn)
        monkeypatch.setattr(remote_ingest, "MAX_BYTES", 16)
        _admit_loopback(monkeypatch)
        with _serve({"/big.md": _ok(b"x" * 500)}) as base:
            status, headers, raw = self._post(
                {"scope_kind": "binary", "scope_id": binary_id, "url": f"{base}/big.md"}
            )
        assert status.startswith("413")
        assert json_body(raw, headers)["error"] == remote_ingest.ERROR_TOO_LARGE

    def test_an_unsupported_content_type_is_400(
        self, conn: sqlite3.Connection, remote_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed_binary(conn)
        _admit_loopback(monkeypatch)
        with _serve({"/blob": _ok(b"x", content_type="application/octet-stream")}) as base:
            status, headers, raw = self._post(
                {"scope_kind": "binary", "scope_id": binary_id, "url": f"{base}/blob"}
            )
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == remote_ingest.ERROR_UNSUPPORTED_CONTENT_TYPE

    def test_a_fetch_failure_is_502(
        self, conn: sqlite3.Connection, remote_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed_binary(conn)
        _admit_loopback(monkeypatch)
        with _serve({"/x": _ok(b"x")}) as base:
            pass
        status, headers, raw = self._post(
            {"scope_kind": "binary", "scope_id": binary_id, "url": f"{base}/x"}
        )
        assert status.startswith("502")
        assert json_body(raw, headers)["error"] == remote_ingest.ERROR_FETCH_FAILED

    def test_missing_url_is_400(self, portal_db: Path, remote_on: None) -> None:
        status, headers, raw = self._post({"scope_kind": "project", "scope_id": 0})
        assert status.startswith("400")
        assert json_body(raw, headers)["error"] == "url must be a non-empty string"


class TestCli:
    def test_success_prints_the_document(
        self,
        conn: sqlite3.Connection,
        remote_on: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        binary_id = _seed_binary(conn)
        _admit_loopback(monkeypatch)
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}) as base:
            result = runner.invoke(
                cli.app, ["ingest-url", str(binary_id), f"{base}/notes.md", "--json"]
            )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["source"] == f"{base}/notes.md"
        assert payload["duplicate"] is False

    def test_disabled_exits_non_zero_with_the_api_message(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = _seed_binary(conn)
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        result = runner.invoke(
            cli.app, ["ingest-url", str(binary_id), "http://example.com/notes.md", "--json"]
        )
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert remote_ingest.ERROR_DISABLED in payload["error"]
        assert remote_ingest.DISABLED_DETAIL in payload["error"]

    def test_disabled_human_message_keeps_the_config_key(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The bracket in ``[knowledge]`` must survive Rich markup parsing."""
        binary_id = _seed_binary(conn)
        monkeypatch.delenv(remote_ingest.ALLOW_REMOTE_ENV, raising=False)
        result = runner.invoke(
            cli.app, ["ingest-url", str(binary_id), "http://example.com/notes.md"]
        )
        assert result.exit_code == 1
        assert "remote-ingest-disabled" in result.output
        assert "[knowledge]" in result.output
        assert "allow_remote = true" in result.output

    def test_a_blocked_target_exits_non_zero(
        self, conn: sqlite3.Connection, remote_on: None
    ) -> None:
        binary_id = _seed_binary(conn)
        result = runner.invoke(cli.app, ["ingest-url", str(binary_id), "http://10.0.0.1/x"])
        assert result.exit_code == 1
        assert remote_ingest.ERROR_BLOCKED_TARGET in result.output

    def test_project_flag_stores_a_project_document(
        self, conn: sqlite3.Connection, remote_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _admit_loopback(monkeypatch)
        with _serve({"/notes.md": _ok(NOTE_TEXT.encode())}) as base:
            result = runner.invoke(
                cli.app,
                ["ingest-url", "0", f"{base}/notes.md", "--project", "--json"],
            )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["scope_kind"] == "project"
        assert payload["scope_id"] == 0

    def test_an_unknown_binary_exits_non_zero(self, portal_db: Path, remote_on: None) -> None:
        result = runner.invoke(cli.app, ["ingest-url", "404", "http://example.com/notes.md"])
        assert result.exit_code == 1
        assert "no binary with id 404" in result.output

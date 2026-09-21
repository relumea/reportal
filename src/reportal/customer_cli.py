"""Customer CLI: the platform surface of reportal, over HTTP only.

The operator CLI (``reportal``) owns the workspace: it opens the database and
drives the analysis engine in process.  This CLI never touches either.  Every
command is a thin call against a running portal (``serve``), authenticated
with a token, so a customer install carries no server logic and names no
engine.

Commands are the coherent customer path: upload a binary, read its analyses,
functions, matches and scans, rename functions, leave notes, tag and
organize.  Operator work (imports, engine runs, user and secret management,
backups, serving) stays on ``reportal``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from reportal import __version__

app = typer.Typer(
    help="Customer CLI for the reportal platform (HTTP only, no local workspace).",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console(stderr=True)

DEFAULT_PORT = 8002


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"reportal-customer {__version__}")
        raise typer.Exit


@app.callback()
def _app_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


class CustomerError(Exception):
    """One failed platform call, already shaped for the user."""


def _base_url(server: str) -> str:
    base = (server or "").strip() or f"http://127.0.0.1:{DEFAULT_PORT}"
    return base.rstrip("/")


def _token(explicit: str | None) -> str:
    token = (explicit or "").strip() or os.environ.get("REPORTAL_TOKEN", "").strip()
    if not token:
        raise CustomerError("no token: pass --token or set REPORTAL_TOKEN")
    return token


def _call(
    method: str,
    path: str,
    *,
    server: str,
    token: str | None,
    body: dict[str, Any] | None = None,
) -> Any:
    """One JSON call against the platform, returning the decoded payload."""
    url = f"{_base_url(server)}{path}"
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme not in ("http", "https"):
        raise CustomerError(f"bad server URL: {url}")
    payload = json.dumps(body or {}).encode() if body is not None else None
    request = urllib.request.Request(url, data=payload, method=method)  # noqa: S310
    request.add_header("Accept", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        try:
            problem = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            problem = {}
        error = str(problem.get("error") or f"HTTP {exc.code}")
        detail = str(problem.get("detail") or "")
        raise CustomerError(f"{error}: {detail}" if detail else error) from None
    except OSError as exc:
        raise CustomerError(f"cannot reach {url}: {exc}") from None
    try:
        return json.loads(raw) if raw.strip() else {}
    except ValueError:
        raise CustomerError(f"bad JSON from {url}") from None


def _fail(message: str, json_output: bool) -> Any:
    if json_output:
        typer.echo(json.dumps({"error": message}))
    else:
        console.print(f"[red]{escape(message)}[/red]")
    raise typer.Exit(1)


def _emit(payload: Any, json_output: bool, render: Any = None) -> None:
    if json_output:
        typer.echo(json.dumps(payload))
        return
    if render is not None:
        render(payload)
    elif isinstance(payload, (dict, list)):
        typer.echo(json.dumps(payload, indent=2))
    else:
        typer.echo(str(payload))


def _server_option() -> Any:
    return typer.Option(
        f"http://127.0.0.1:{DEFAULT_PORT}",
        "--server",
        help="Portal base URL (REPORTAL_SERVER overrides the default).",
    )


def _token_option() -> Any:
    return typer.Option(None, "--token", help="API token (REPORTAL_TOKEN otherwise).")


def _json_option() -> Any:
    return typer.Option(False, "--json", help="Output results as JSON.")


def _resolve_server(server: str) -> str:
    return (os.environ.get("REPORTAL_SERVER", "").strip() or server).strip()


@app.command("binaries")
def list_binaries(
    server: str = _server_option(),
    token: str | None = _token_option(),
    search: str | None = typer.Option(None, "--search", help="Match name, hash or notes."),
    json_output: bool = _json_option(),
) -> None:
    """List binaries on the platform."""
    try:
        path = "/api/binaries"
        if search:
            path += f"?search={urllib.parse.quote(search)}"
        payload = _call("GET", path, server=_resolve_server(server), token=_token(token))
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    if json_output:
        typer.echo(json.dumps(payload))
        return
    rows = payload if isinstance(payload, list) else payload.get("binaries", payload)
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", justify="right")
    table.add_column("Name", style="cyan")
    table.add_column("SHA256")
    table.add_column("Functions", justify="right")
    for row in rows if isinstance(rows, list) else []:
        table.add_row(
            str(row.get("id")),
            str(row.get("name")),
            str(row.get("sha256", ""))[:16],
            str(row.get("function_count", "")),
        )
    console.print(table)


@app.command("binary")
def show_binary(
    binary_id: int = typer.Argument(..., help="Binary id."),
    server: str = _server_option(),
    token: str | None = _token_option(),
    json_output: bool = _json_option(),
) -> None:
    """Show one binary."""
    try:
        payload = _call(
            "GET", f"/api/binaries/{binary_id}", server=_resolve_server(server), token=_token(token)
        )
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    _emit(payload, json_output)


@app.command("upload")
def upload_binary(
    path: Path = typer.Argument(..., help="File to upload."),
    server: str = _server_option(),
    token: str | None = _token_option(),
    name: str | None = typer.Option(None, "--name", help="Display name."),
    json_output: bool = _json_option(),
) -> None:
    """Upload a binary to the platform for analysis."""
    import http.client
    import mimetypes
    import uuid

    source = path.expanduser()
    if not source.is_file():
        _fail(f"not a file: {path}", json_output)
        return
    boundary = uuid.uuid4().hex
    filename = name or source.name
    ctype, _ = mimetypes.guess_type(filename)
    body = bytearray()
    body += f"--{boundary}\r\n".encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += f"Content-Type: {ctype or 'application/octet-stream'}\r\n\r\n".encode()
    body += source.read_bytes()
    body += f"\r\n--{boundary}--\r\n".encode()
    parts = urllib.parse.urlsplit(f"{_base_url(_resolve_server(server))}/api/binaries")
    try:
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(parts.hostname or "", parts.port or 443, timeout=120)
        else:
            conn = http.client.HTTPConnection(parts.hostname or "", parts.port or 80, timeout=120)
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "application/json",
            "Authorization": f"Bearer {_token(token)}",
        }
        conn.request("POST", parts.path, body=bytes(body), headers=headers)
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        if response.status >= 400:
            try:
                problem = json.loads(raw)
                error = str(problem.get("error") or f"HTTP {response.status}")
                detail = str(problem.get("detail") or "")
                _fail(f"{error}: {detail}" if detail else error, json_output)
            except ValueError:
                _fail(f"HTTP {response.status}", json_output)
            return
        payload = json.loads(raw) if raw.strip() else {}
    except (OSError, ValueError) as exc:
        _fail(f"upload failed: {exc}", json_output)
        return
    _emit(payload, json_output)


@app.command("functions")
def list_functions(
    binary_id: int = typer.Argument(..., help="Binary id."),
    server: str = _server_option(),
    token: str | None = _token_option(),
    name: str | None = typer.Option(None, "--name", help="Filter by name substring."),
    json_output: bool = _json_option(),
) -> None:
    """List one binary's functions."""
    try:
        path = f"/api/binaries/{binary_id}/functions"
        if name:
            path += f"?name={urllib.parse.quote(name)}"
        payload = _call("GET", path, server=_resolve_server(server), token=_token(token))
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    _emit(payload, json_output)


@app.command("function")
def show_function(
    function_id: int = typer.Argument(..., help="Function id."),
    server: str = _server_option(),
    token: str | None = _token_option(),
    json_output: bool = _json_option(),
) -> None:
    """Show one function with its stored decompilation."""
    try:
        resolved = _resolve_server(server)
        auth = _token(token)
        function = _call("GET", f"/api/functions/{function_id}", server=resolved, token=auth)
        try:
            decomp = _call(
                "GET", f"/api/functions/{function_id}/decompilation", server=resolved, token=auth
            )
        except CustomerError:
            decomp = None
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    _emit({**function, "decompilation": decomp}, json_output)


@app.command("matches")
def show_matches(
    function_id: int = typer.Argument(..., help="Function id."),
    server: str = _server_option(),
    token: str | None = _token_option(),
    json_output: bool = _json_option(),
) -> None:
    """Show recorded matches of one function."""
    try:
        payload = _call(
            "GET",
            f"/api/functions/{function_id}/matches",
            server=_resolve_server(server),
            token=_token(token),
        )
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    _emit(payload, json_output)


@app.command("scans")
def show_scans(
    binary_id: int = typer.Argument(..., help="Binary id."),
    server: str = _server_option(),
    token: str | None = _token_option(),
    json_output: bool = _json_option(),
) -> None:
    """Show stored scans of one binary."""
    try:
        payload = _call(
            "GET",
            f"/api/binaries/{binary_id}/scans",
            server=_resolve_server(server),
            token=_token(token),
        )
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    _emit(payload, json_output)


@app.command("rename")
def rename_function(
    function_id: int = typer.Argument(..., help="Function id."),
    name: str = typer.Argument(..., help="New function name."),
    server: str = _server_option(),
    token: str | None = _token_option(),
    json_output: bool = _json_option(),
) -> None:
    """Rename one function."""
    try:
        payload = _call(
            "POST",
            f"/api/functions/{function_id}/rename",
            server=_resolve_server(server),
            token=_token(token),
            body={"name": name},
        )
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    _emit(payload, json_output)


@app.command("comment-add")
def add_comment(
    binary_id: int = typer.Argument(..., help="Binary id."),
    text: str = typer.Argument(..., help="Comment text."),
    server: str = _server_option(),
    token: str | None = _token_option(),
    json_output: bool = _json_option(),
) -> None:
    """Leave an analyst note on a binary."""
    try:
        payload = _call(
            "POST",
            f"/api/binaries/{binary_id}/comments",
            server=_resolve_server(server),
            token=_token(token),
            body={"body": text},
        )
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    _emit(payload, json_output)


@app.command("collections")
def list_collections(
    server: str = _server_option(),
    token: str | None = _token_option(),
    json_output: bool = _json_option(),
) -> None:
    """List collections."""
    try:
        payload = _call(
            "GET", "/api/collections", server=_resolve_server(server), token=_token(token)
        )
    except CustomerError as exc:
        _fail(str(exc), json_output)
        return
    _emit(payload, json_output)


def main() -> None:
    """Run the customer CLI."""
    app()


if __name__ == "__main__":
    main()

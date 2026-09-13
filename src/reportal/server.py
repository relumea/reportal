"""Shared FastAPI application for reportal.

Defines the ``app`` object every route module mounts on, the JSON response and
error helpers, the loopback Host validation and the database opener.  The route
modules mount on it through their own routers, which :mod:`reportal.webapp`
includes.

Every response keeps the contract the Bottle server established: the JSON error
envelope ``{"error", "detail", "doc_url"}``, the same status codes, the
``Vary``/``Content-Length`` headers, gzip for a client that asks for it, and the
same security headers.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
import re
import sqlite3
from collections.abc import Mapping
from contextvars import ContextVar, Token
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from reportal import __version__, auth, error_docs, store
from reportal._paths import WorkspaceNotFound, db_path

app = FastAPI(
    title="reportal",
    version=__version__,
    description="Self-hosted reverse-engineering portal over rebrew, resembl and recoverage.",
    # A trailing slash is not redirected onto the route without it: reportal's
    # contract is that a path it does not serve is a JSON 404, which is what
    # the Bottle router answered.
    redirect_slashes=False,
)

_log = logging.getLogger("reportal")

# Loopback hostnames accepted by the Host-header guard.  The guard defeats DNS
# rebinding (an attacker's domain resolving to 127.0.0.1) on loopback binds; a
# remote bind disables it by setting ALLOWED_HOSTS to None.
LOOPBACK_HOSTS: tuple[str, ...] = ("127.0.0.1", "::1", "localhost")
ALLOWED_HOSTS: set[str] | None = set(LOOPBACK_HOSTS)

# Headers every response carries (the Bottle server's ``after_request`` hook).
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
)

# The current request's ``Accept-Encoding``, so ``json_response`` can decide on
# gzip without every one of its callers taking a request argument.  The value
# is set per request by ``_reportal_headers``; outside a request it is empty and
# nothing is compressed.
_ACCEPT_ENCODING: ContextVar[str] = ContextVar("reportal_accept_encoding", default="")


def configure_hosts(allowed_hosts: set[str] | None) -> None:
    """Install the Host allowlist; call once at startup, before serving."""
    global ALLOWED_HOSTS
    ALLOWED_HOSTS = allowed_hosts


def _hostname_of(host_value: str) -> str:
    """Lowercased hostname of a Host header value ("" when unparsable).

    Values carrying userinfo or percent-encoding never come from a browser
    Host header, so they are rejected rather than parsed.
    """
    if any(ch in host_value for ch in ("@", "\\", "%")) or any(ord(c) < 32 for c in host_value):
        return ""
    try:
        parsed = urlsplit(host_value if "://" in host_value else f"//{host_value}")
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def db() -> sqlite3.Connection:
    """Open the reportal database, creating the schema on first use."""
    path = db_path()
    if not path.exists():
        store.init_db(path)
    return store.connect(path)


# The object a path names, so the team scope is enforced once for every route
# instead of in each handler.  An id that names no row is left to the route: the
# gate only refuses what it can see, and a missing object is the route's 404.
_SCOPED_PATHS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/api/binaries/(?P<id>\d+)"), "binary"),
    (re.compile(r"^/api/collections/(?P<id>\d+)"), "collection"),
    (re.compile(r"^/api/functions/(?P<id>\d+)"), "function"),
    (re.compile(r"^/api/analyses/(?P<id>\d+)"), "analysis"),
)

# The 404 each object reports when the caller may not see it.  A team-scoped
# object a non-member asks for is reported as missing rather than forbidden, so
# the answer does not disclose that it exists.
_NOT_FOUND_NAME: dict[str, str] = {
    "binary": "binary not found",
    "collection": "collection not found",
    "function": "function not found",
    "analysis": "analysis not found",
}


def _scoped_object(conn: sqlite3.Connection, path: str) -> tuple[str, Mapping[str, Any]] | None:
    """The binary or collection a path names, and the kind it is.

    A function or an analysis resolves to its owning binary, because that is the
    object a team scope attaches to: reportal has no per-function owner.
    """
    for pattern, kind in _SCOPED_PATHS:
        match = pattern.match(path)
        if match is None:
            continue
        row_id = int(match.group("id"))
        if kind == "binary":
            row = store.get_binary(conn, row_id)
        elif kind == "collection":
            row = store.get_collection(conn, row_id)
        elif kind == "function":
            function = store.get_function(conn, row_id)
            analysis = (
                None if function is None else store.get_analysis(conn, int(function["analysis_id"]))
            )
        else:
            analysis = store.get_analysis(conn, row_id)
        if kind != "binary" and kind != "collection":
            row = None if analysis is None else store.get_binary(conn, int(analysis["binary_id"]))
        if row is None:
            return None
        return kind, row
    return None


def _enforce_scope(
    conn: sqlite3.Connection,
    request: Request,
    user: Mapping[str, Any],
) -> None:
    """Refuse a request for a team-scoped object the caller may not reach.

    A read of an object the caller cannot see is a 404 for that object kind,
    because saying "forbidden" would disclose that it exists; a write is a 403
    ``scope-forbidden``, because the caller has already proven it is a member of
    the workspace and the object is not a secret at that point.
    """
    if str(user.get("role")) == auth.ROLE_ADMIN:
        return
    found = _scoped_object(conn, request.url.path)
    if found is None:
        return
    kind, row = found
    if str(row.get("visibility") or auth.VISIBILITY_PUBLIC) != auth.VISIBILITY_TEAM:
        return
    team_ids = [int(team["id"]) for team in auth.teams_of_user(conn, int(user["id"]))]
    if int(row.get("owner_team_id") or 0) in team_ids:
        return
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        raise json_error(404, error=_NOT_FOUND_NAME[kind], detail=f"no {kind} with that id")
    raise json_error(
        403,
        error=auth.ERROR_SCOPE_FORBIDDEN,
        detail=f"this {kind} belongs to a team you are not a member of",
    )


def require_auth(request: Request) -> None:
    """Refuse an API request that carries no acceptable token, when auth is on.

    Auth is off unless the environment or the workspace config turns it on, so
    the default single-user loopback install is unchanged and this check costs a
    configuration read.  When it is on, every ``/api`` request needs
    ``Authorization: Bearer <token>``: a missing or unknown token is 401
    ``unauthorized``, a disabled user is 401 as well, and a role that does not
    carry the permission the method and path imply is 403 ``forbidden``.  The
    authenticated user is left on ``request.state.user`` for the routes that
    report it.
    """
    if not auth.required():
        return
    token = auth.token_of(request.headers.get(auth.AUTHORIZATION_HEADER))
    with contextlib.closing(db()) as conn:
        user = auth.authenticate(conn, token)
    if user is None:
        raise json_error(401, error=auth.ERROR_UNAUTHORIZED, detail=auth.UNAUTHORIZED_DETAIL)
    needed = auth.required_permission(request.method, request.url.path)
    if needed not in auth.permissions_for(str(user["role"])):
        raise json_error(403, error=auth.ERROR_FORBIDDEN, detail=auth.FORBIDDEN_DETAIL)
    with contextlib.closing(db()) as conn:
        _enforce_scope(conn, request, user)
    request.state.user = user


def _accepts_gzip(accept_encoding: str) -> bool:
    """True when the client accepts gzip and has not refused it via q=0."""
    for token in accept_encoding.split(","):
        parts = [p.strip().lower() for p in token.split(";")]
        if not parts or parts[0] != "gzip":
            continue
        for param in parts[1:]:
            if param.startswith("q="):
                try:
                    return float(param[2:]) > 0
                except ValueError:
                    return False
        return True
    return False


def json_response(
    data: dict[str, Any] | list[Any], *, status: int = 200, **headers: str
) -> Response:
    """Serialize *data* as JSON, gzip-encoding it when the client allows."""
    body = json.dumps(data).encode("utf-8")
    response_headers = {"Vary": "Accept-Encoding"}
    if status < 400 and _accepts_gzip(_ACCEPT_ENCODING.get()):
        body = gzip.compress(body)
        response_headers["Content-Encoding"] = "gzip"
    for key, value in headers.items():
        response_headers[key.replace("_", "-")] = value
    return Response(
        content=body,
        status_code=status,
        media_type="application/json",
        headers=response_headers,
    )


class JsonError(Response, Exception):
    """The JSON error envelope, as a response *and* a raisable exception.

    Routes write ``return json_error(...)`` or ``raise json_error(...)``; the
    first is served directly by FastAPI, the second by the handler below.  One
    class covers both so the ported routes keep the call shape they had.
    """

    def __init__(self, status_code: int, *, error: str, detail: str = "") -> None:
        body = json.dumps(
            {"error": error, "detail": detail, "doc_url": error_docs.doc_url(error)}
        ).encode("utf-8")
        Response.__init__(
            self,
            content=body,
            status_code=status_code,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )
        Exception.__init__(self, error)
        self.error = error
        self.detail = detail


def json_error(status: int, *, error: str, detail: str = "") -> JsonError:
    """Build the JSON error response for *status*.

    *error* is a fixed, sanitized string so no exception text or request data
    reaches the response body, and *doc_url* points at the section of
    ``docs/ERRORS.md`` that documents the code.  A code the catalogue does not
    name carries ``null`` rather than a link to a section that does not exist.
    """
    return JsonError(status, error=error, detail=detail)


async def json_body(request: Request) -> dict[str, Any]:
    """Dependency: parse the request body as a JSON object.

    Raises 400 ``invalid JSON body`` for a non-UTF-8 body or invalid JSON, and
    400 ``request body must be a JSON object`` for any other JSON value.
    """
    raw = await request.body()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise json_error(400, error="invalid JSON body") from None
    if not isinstance(data, dict):
        raise json_error(400, error="request body must be a JSON object")
    return data


async def optional_json_body(request: Request) -> dict[str, Any]:
    """Dependency: parse the body as a JSON object, treating an absent body as {}.

    A request with no ``Content-Length`` or a zero one carries no body, which
    the routes that accept an empty body read as ``{}`` -- the same rule the
    Bottle server's ``request.content_length`` gave them.
    """
    raw_length = request.headers.get("content-length", "")
    try:
        length = int(raw_length or 0)
    except ValueError:
        length = 0
    if not length:
        return {}
    return await json_body(request)


@app.middleware("http")
async def _reportal_headers(request: Request, call_next: Any) -> Response:
    """Validate the Host header, carry the request to the helpers, add headers."""
    token: Token[str] = _ACCEPT_ENCODING.set(request.headers.get("accept-encoding", ""))
    try:
        if ALLOWED_HOSTS is not None:
            host = request.headers.get("host", "")
            if host and _hostname_of(host) not in ALLOWED_HOSTS:
                _log.warning("Rejected request with Host header %r", host)
                return json_error(400, error="unexpected Host header", detail="host not allowed")
        response: Response = await call_next(request)
    finally:
        _ACCEPT_ENCODING.reset(token)
    for key, value in SECURITY_HEADERS:
        response.headers[key] = value
    return response


@app.exception_handler(JsonError)
async def _handle_json_error(request: Request, exc: JsonError) -> Response:
    """Serve a raised :class:`JsonError` as its own response."""
    return exc


@app.exception_handler(WorkspaceNotFound)
async def _handle_workspace_not_found(request: Request, exc: WorkspaceNotFound) -> Response:
    """A missing workspace is a 500 naming the directory that was searched."""
    _log.error("No reportal workspace for %s", request.url.path)
    return json_error(500, error="no-workspace", detail=str(exc))


@app.exception_handler(RequestValidationError)
async def _handle_validation_error(request: Request, exc: RequestValidationError) -> Response:
    """A path or query parameter FastAPI could not coerce is a 404.

    Reportal declares only its path parameters to FastAPI; every body and query
    value is validated by hand and raises its own envelope.  A malformed path
    parameter is therefore an unknown endpoint, which is what the Bottle routes
    answered (their ``:int`` filter simply did not match).
    """
    return json_error(404, error="not found", detail=f"no such endpoint: {request.url.path}")


@app.exception_handler(StarletteHTTPException)
async def _handle_http_exception(request: Request, exc: StarletteHTTPException) -> Response:
    """Keep FastAPI's own refusals in the reportal envelope.

    A method FastAPI knows but the matched route does not allow is a 404 here,
    because that is what the Bottle catch-all answered.
    """
    if exc.status_code in {404, 405}:
        return json_error(404, error="not found", detail=f"no such endpoint: {request.url.path}")
    if exc.status_code == 400:
        # FastAPI's own refusal to parse the body; reportal answers a body it
        # cannot read with one fixed code, as the Bottle server did.
        return json_error(400, error="invalid-body", detail="malformed multipart body")
    detail = exc.detail if isinstance(exc.detail, str) else ""
    return json_error(exc.status_code, error="internal server error", detail=detail)


@app.exception_handler(Exception)
async def _handle_error(request: Request, exc: Exception) -> Response:
    """Log unhandled errors and keep the JSON contract for API routes."""
    _log.error("Unhandled error serving %s", request.url.path, exc_info=exc)
    if request.url.path.startswith("/api/"):
        return json_error(500, error="internal server error")
    return Response(
        content=b"<html><body><h1>500 Internal Server Error</h1></body></html>",
        status_code=500,
        media_type="text/html",
    )


def run(host: str, port: int) -> None:
    """Serve the application with uvicorn until interrupted."""
    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)

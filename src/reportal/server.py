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
from collections.abc import Callable, Mapping
from contextvars import ContextVar, Token
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response

from reportal import __version__, auth, disclosure, error_docs, journal, llm, metering, store
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

# The caller the current response is being serialized for, so `json_response`
# can apply `disclosure.redact_payload` without every route passing the request
# down to it.  Unset (outside a request, or before authentication) it reads as
# None, which `disclosure.is_operator` treats as the local operator: a CLI or a
# test sees the unredacted payload, exactly as it did before.
_CALLER: ContextVar[Mapping[str, Any] | None] = ContextVar("reportal_caller", default=None)


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
    (re.compile(r"^/api/data-types/(?P<id>\d+)"), "data-type"),
    (re.compile(r"^/api/comments/(?P<id>\d+)"), "comment"),
    (re.compile(r"^/api/documents/(?P<id>\d+)"), "document"),
    (re.compile(r"^/api/conversations/(?P<id>\d+)"), "conversation"),
    (re.compile(r"^/api/pipeline/runs/(?P<id>\d+)"), "pipeline-run"),
    (re.compile(r"^/api/auto/runs/(?P<id>\d+)"), "auto-run"),
    (re.compile(r"^/api/graph/nodes/(?P<id>.+)"), "graph-node"),
)

# The 404 each object reports when the caller may not see it.  A team-scoped
# object a non-member asks for is reported as missing rather than forbidden, so
# the answer does not disclose that it exists.
_NOT_FOUND_NAME: dict[str, str] = {
    "binary": "binary not found",
    "collection": "collection not found",
    "function": "function not found",
    "analysis": "analysis not found",
    "data-type": "data-type-not-found",
    "comment": "comment not found",
    "document": "document not found",
    "conversation": "conversation not found",
    "pipeline-run": "run not found",
    "auto-run": "run not found",
    "graph-node": "node not found",
}


def _scoped_object(conn: sqlite3.Connection, path: str) -> tuple[str, Mapping[str, Any]] | None:
    """The binary or collection a path names, and the kind it is.

    A function, an analysis, a data type, a comment, a binary-scoped document,
    a binary/function-scoped conversation, a pipeline run (through its
    function), an auto run (through its own binary) or a graph node (through
    its own binary) resolves to its owning binary, because that is the object
    a team scope attaches to: reportal has no per-function owner.  A comment's
    scope is its own row: a binary scope names the binary and a function scope
    names the function whose analysis names the binary.  A document or
    conversation of any other scope (project, docs) has no owning binary and
    is left to the route.
    """
    for pattern, kind in _SCOPED_PATHS:
        match = pattern.match(path)
        if match is None:
            continue
        raw_id = match.group("id")
        if kind == "graph-node":
            node = store.get_graph_node(conn, raw_id)
            analysis = None if node is None else {"binary_id": node["binary_id"]}
            row = None if analysis is None else store.get_binary(conn, int(analysis["binary_id"]))
            if row is None:
                return None
            return kind, row
        row_id = int(raw_id)
        if kind == "binary":
            row = store.get_binary(conn, row_id)
        elif kind == "collection":
            row = store.get_collection(conn, row_id)
        elif kind == "function":
            function = store.get_function(conn, row_id)
            analysis = (
                None if function is None else store.get_analysis(conn, int(function["analysis_id"]))
            )
        elif kind == "data-type":
            data_type = store.get_data_type(conn, row_id)
            analysis = None if data_type is None else {"binary_id": data_type["binary_id"]}
        elif kind == "comment":
            comment = store.get_comment(conn, row_id)
            analysis = None if comment is None else _comment_binary(conn, comment)
        elif kind == "document":
            document = store.get_document(conn, row_id)
            analysis = None if document is None else _document_binary(document)
        elif kind == "conversation":
            conversation = store.get_conversation(conn, row_id)
            analysis = None if conversation is None else _conversation_binary(conn, conversation)
        elif kind == "pipeline-run":
            run = store.get_pipeline_run(conn, row_id)
            analysis = None if run is None else _pipeline_run_binary(conn, run)
        elif kind == "auto-run":
            from reportal import auto_store

            run = auto_store.get_auto_run(conn, row_id)
            analysis = None if run is None else {"binary_id": run["binary_id"]}
        else:
            analysis = store.get_analysis(conn, row_id)
        if kind != "binary" and kind != "collection":
            row = None if analysis is None else store.get_binary(conn, int(analysis["binary_id"]))
        if row is None:
            return None
        return kind, row
    return None


def _pipeline_run_binary(conn: sqlite3.Connection, run: Mapping[str, Any]) -> dict[str, Any] | None:
    """The ``{"binary_id"}`` a pipeline run's function resolves to, or None."""
    function = store.get_function(conn, int(run["function_id"]))
    if function is None:
        return None
    return {"binary_id": int(function["binary_id"])}


def _conversation_binary(
    conn: sqlite3.Connection, conversation: Mapping[str, Any]
) -> dict[str, Any] | None:
    """The ``{"binary_id"}`` a binary/function-scoped conversation resolves to, or None."""
    from reportal import conversations

    if str(conversation.get("scope_kind")) == conversations.SCOPE_KIND_BINARY:
        return {"binary_id": int(conversation["scope_id"])}
    if str(conversation.get("scope_kind")) == conversations.SCOPE_KIND_FUNCTION:
        function = store.get_function(conn, int(conversation["scope_id"]))
        if function is None:
            return None
        return {"binary_id": int(function["binary_id"])}
    return None


def _document_binary(document: Mapping[str, Any]) -> dict[str, Any] | None:
    """The ``{"binary_id"}`` a binary-scoped document resolves to, or None."""
    from reportal import knowledge

    if str(document.get("scope_kind")) == knowledge.SCOPE_KIND_BINARY:
        return {"binary_id": int(document["scope_id"])}
    return None


def _comment_binary(conn: sqlite3.Connection, comment: Mapping[str, Any]) -> dict[str, Any] | None:
    """The ``{"binary_id"}`` the comment's scope resolves to, or None."""
    from reportal import comments

    if str(comment.get("scope_kind")) == comments.SCOPE_BINARY:
        return {"binary_id": int(comment["scope_id"])}
    if str(comment.get("scope_kind")) == comments.SCOPE_FUNCTION:
        function = store.get_function(conn, int(comment["scope_id"]))
        if function is None:
            return None
        return {"binary_id": int(function["binary_id"])}
    return None


def _enforce_scope(
    conn: sqlite3.Connection,
    request: Request,
    user: Mapping[str, Any],
) -> Response | None:
    """Refuse a request for a team-scoped object the caller may not reach.

    A read of an object the caller cannot see is a 404 for that object kind,
    because saying "forbidden" would disclose that it exists; a write is a 403
    ``scope-forbidden``, because the caller has already proven it is a member of
    the workspace and the object is not a secret at that point.  None means the
    request may proceed.
    """
    if str(user.get("role")) == auth.ROLE_ADMIN:
        return None
    found = _scoped_object(conn, request.url.path)
    if found is None:
        return None
    kind, row = found
    if str(row.get("visibility") or auth.VISIBILITY_PUBLIC) != auth.VISIBILITY_TEAM:
        return None
    team_ids = [int(team["id"]) for team in auth.teams_of_user(conn, int(user["id"]))]
    if int(row.get("owner_team_id") or 0) in team_ids:
        return None
    if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return json_error(404, error=_NOT_FOUND_NAME[kind], detail=f"no {kind} with that id")
    return json_error(
        403,
        error=auth.ERROR_SCOPE_FORBIDDEN,
        detail=f"this {kind} belongs to a team you are not a member of",
    )


def authenticate(request: Request) -> tuple[str, Response | None]:
    """Resolve the API caller, and the actor name its writes record.

    Auth is off unless the environment or the workspace config turns it on, so
    the default single-user loopback install is unchanged and this costs a
    configuration read.  When it is on, every ``/api`` request needs
    ``Authorization: Bearer <token>``: a missing or unknown token is 401
    ``unauthorized``, a disabled user is 401 as well, and a role that does not
    carry the permission the method and path imply is 403 ``forbidden``.  The
    authenticated user is left on ``request.state.user`` for the routes that
    report it, and the actor name is what :func:`reportal.journal.acting_as`
    records on the entries the request writes: the user's name, or ``local``
    while auth is off.

    It answers an ``(actor, refusal)`` pair rather than raising, because it runs
    inside a middleware: a raised :class:`JsonError` there would sit outside the
    app's exception handlers, while the response object it builds is served as
    is.
    """
    if not auth.required():
        return journal.LOCAL_ACTOR, None
    token = auth.token_of(request.headers.get(auth.AUTHORIZATION_HEADER))
    with contextlib.closing(db()) as conn:
        user = auth.authenticate(conn, token)
        if user is None:
            return "", json_error(
                401, error=auth.ERROR_UNAUTHORIZED, detail=auth.UNAUTHORIZED_DETAIL
            )
        needed = auth.required_permission(request.method, request.url.path)
        if needed not in auth.permissions_for(str(user["role"])):
            return "", json_error(403, error=auth.ERROR_FORBIDDEN, detail=auth.FORBIDDEN_DETAIL)
        refusal = _enforce_scope(conn, request, user)
    request.state.user = user
    if refusal is not None:
        return "", refusal
    return str(user["name"]), None


def caller_organisation(request: Request) -> int:
    """The organisation the request's writes meter against, or 0 for no tenant.

    The caller's active team names it.  Auth off, or a user with no active team,
    is a single-operator install: organisation 0, which
    :func:`reportal.metering.record_usage` records nothing for.
    """
    user = getattr(request.state, "user", None)
    if not isinstance(user, Mapping):
        return metering.NO_ORG
    team_id = user.get("active_team_id")
    if not isinstance(team_id, int):
        return metering.NO_ORG
    with contextlib.closing(db()) as conn:
        row = conn.execute(
            f"SELECT organisation_id FROM {auth.TEAM_TABLE} WHERE id = ?", (team_id,)
        ).fetchone()
    if row is None or row["organisation_id"] is None:
        return metering.NO_ORG
    return int(row["organisation_id"])


def _meter_tokens(organisation_id: int, path: str) -> Callable[[int, int, str], None]:
    """A usage sink that appends one token row per completion for a tenant."""

    def sink(prompt_tokens: int, completion_tokens: int, model: str) -> None:
        with contextlib.closing(db()) as conn:
            metering.record_usage(
                conn,
                organisation_id,
                metering.KIND_TOKENS,
                prompt_tokens + completion_tokens,
                model=model,
                detail=path,
            )

    return sink


def _charge_credits(organisation_id: int, path: str) -> Callable[[str, int], None]:
    """A charge sink that debits a tenant's credits once per billable task."""

    def sink(task: str, input_tokens: int) -> None:
        with contextlib.closing(db()) as conn:
            metering.charge_task(
                conn,
                organisation_id,
                task,
                input_tokens=input_tokens,
                detail=path,
            )

    return sink


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
    """Serialize *data* as JSON, gzip-encoding it when the client allows.

    Every response passes through `disclosure.redact_payload` first, so the
    machinery behind an answer (which model, how many tokens, what it thought)
    never reaches a tenant.  Doing it here rather than in each producer is what
    makes a new AI route private by construction: a field nobody remembered to
    strip is stripped anyway.  An operator's payload is returned unchanged.
    """
    data = disclosure.redact_payload(data, caller=_CALLER.get())
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
    caller_token: Token[Mapping[str, Any] | None] = _CALLER.set(None)
    try:
        if ALLOWED_HOSTS is not None:
            host = request.headers.get("host", "")
            if host and _hostname_of(host) not in ALLOWED_HOSTS:
                _log.warning("Rejected request with Host header %r", host)
                return json_error(400, error="unexpected Host header", detail="host not allowed")
        actor = journal.LOCAL_ACTOR
        if request.url.path.startswith("/api"):
            actor, refusal = authenticate(request)
            if refusal is not None:
                return refusal
            # Set after authentication, because that is what resolves the role
            # `disclosure` branches on.  A refusal returns before this, so an
            # error body is serialized with no caller and is redacted.
            user = getattr(request.state, "user", None)
            _CALLER.set(user if isinstance(user, Mapping) else None)
        # The actor is set here, in the async middleware, so the worker thread
        # the route runs on inherits it; a value set inside a sync dependency
        # would not reach the handler.  Both meters ride the same scope: a
        # tenant request gets a credit charger (what it is billed) and a token
        # sink (what it cost us), so every AI route is metered without knowing
        # billing exists, and a request with no tenant gets neither, so a
        # self-hosted install records nothing.
        organisation_id = metering.NO_ORG
        if request.url.path.startswith("/api"):
            organisation_id = caller_organisation(request)
        with journal.acting_as(actor), contextlib.ExitStack() as stack:
            if organisation_id != metering.NO_ORG:
                stack.enter_context(
                    llm.recording_usage(_meter_tokens(organisation_id, request.url.path))
                )
                stack.enter_context(
                    llm.charging(_charge_credits(organisation_id, request.url.path))
                )
            response: Response = await call_next(request)
    finally:
        _ACCEPT_ENCODING.reset(token)
        _CALLER.reset(caller_token)
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

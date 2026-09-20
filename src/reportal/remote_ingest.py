"""Guarded remote (URL) document ingestion for reportal.

A knowledge document usually comes from a local file, pasted text or an HTTP
upload.  This module adds one more source, a URL, and that source is off by
default: remote ingestion is enabled only when ``REPORTAL_ALLOW_REMOTE_INGEST``
holds a truthy value or the workspace ``reportal.toml`` carries
``[knowledge] allow_remote = true``.  While it is disabled every remote path
answers the fixed 403 ``remote-ingest-disabled`` and no request leaves the
process.

Enabling it turns reportal into a fetch client, which is an SSRF surface when a
caller chooses the URL.  The guards live in :func:`validate_target`: only
``http``/``https``, a host is required, credentials in the URL are rejected,
every address the host resolves to is checked against the loopback, private,
link-local, multicast, unspecified and reserved ranges (an IPv4-mapped IPv6
form included) and any one blocked address rejects the target, and the port is
restricted to the named allowlist.
:func:`fetch` follows redirects manually and re-validates each hop before
requesting it, streams the body and aborts past :data:`MAX_BYTES`, and accepts
only a named content-type allowlist.  No auth header and no cookie is sent, and
the environment's proxy variables are ignored.

``allow_loopback`` is a test-only seam: it admits a loopback target on its
ephemeral port so a local ``http.server`` can be exercised end to end.  It is
unsafe for production, no production caller passes it, and it must never be
exposed as a request field.

A DNS answer can change between validation and the connection (TOCTOU), so the
pre-flight check alone does not cover the address actually connected to.
:func:`fetch` closes that on the established connection: after the stream opens
and before the body is read, it reads the peer address the transport carries
(``network_stream`` -> ``get_extra_info("server_addr")``) and rejects a blocked
peer exactly as the pre-flight check does.  The pre-flight check stays as the
cheap early exit that fails before any request is sent; the peer check is what
covers the connection.  A transport that exposes no stream or no peer address is
unverifiable: production callers refuse that case rather than trusting the
pre-flight DNS alone (a DNS answer can change between resolution and connect).
The test-only ``allow_loopback`` seam still admits an unverifiable peer so an
in-process mock transport can exercise the rest of the path, and the returned
payload reports :data:`PEER_UNVERIFIED` so a reader can tell a verified
connection from an unverified one.

What the peer check still cannot cover: the request has already been sent by the
time the peer is known, so only the body is withheld; an HTTPS connection has
already exchanged handshake bytes with a blocked peer; and a network namespace
with no private routes would isolate the process more strongly than any
address check can.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import tomllib
import urllib.parse
from typing import Any

import httpx2 as httpx

from reportal import __version__, knowledge
from reportal._paths import MARKER, WorkspaceNotFound, project_root

# Environment variable that enables remote ingestion; any truthy spelling works.
ALLOW_REMOTE_ENV = "REPORTAL_ALLOW_REMOTE_INGEST"
# Keep in sync with ``settings.FLAG_TRUTHY`` (and the other flag readers).
_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled", "required"})

# Workspace reportal.toml table and key that also enable it.
CONFIG_TABLE = "knowledge"
CONFIG_ALLOW_REMOTE = "allow_remote"

# Schemes a remote target may use.
ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Port a scheme uses when the URL carries none.
DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

# Ports a remote target may use.  The scheme default is always allowed; the
# test seam admits a loopback host on its ephemeral port as well.
ALLOWED_PORTS: frozenset[int] = frozenset({80, 443})

# Redirect hops followed before a fetch fails, and the largest body accepted.
MAX_REDIRECTS = 5
MAX_BYTES = knowledge.MAX_DOCUMENT_BYTES

# Wall-clock budget for one request in a redirect chain.
FETCH_TIMEOUT_SECONDS = 30

# User-Agent identifying reportal to the remote server.
USER_AGENT = f"reportal/{__version__} remote-ingest"

# Peer address :func:`fetch` reports for a transport with no stream or no
# ``server_addr``.  The connection is unverifiable, so the pre-flight answer
# stands and this marker is how a reader tells that path from a verified one.
PEER_UNVERIFIED = "unverified"

# Content types accepted.  A missing content type is accepted, since not every
# static file server sets one; anything else is refused before the body is read.
CONTENT_TYPE_TEXT_PREFIX = "text/"
ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset(
    {"application/json", "application/xml", "application/x-yaml", "text/markdown"}
)

# Error names the API, CLI and MCP surfaces report.
ERROR_DISABLED = "remote-ingest-disabled"
ERROR_INVALID_URL = "invalid-url"
ERROR_BLOCKED_TARGET = "blocked-target"
ERROR_UNRESOLVABLE = "unresolvable-host"
ERROR_UNSUPPORTED_CONTENT_TYPE = "unsupported-content-type"
ERROR_FETCH_FAILED = "fetch-failed"
ERROR_TOO_MANY_REDIRECTS = "too-many-redirects"
ERROR_TOO_LARGE = knowledge.ERROR_FILE_TOO_LARGE

# Fixed detail every disabled remote path reports.
DISABLED_DETAIL = (
    "set REPORTAL_ALLOW_REMOTE_INGEST=1 or [knowledge] allow_remote = true to enable URL ingestion"
)


class RemoteIngestError(Exception):
    """A remote document cannot be ingested; ``code`` is the API's error name."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class TooLargeError(RemoteIngestError):
    """The fetched body passed :data:`MAX_BYTES`."""


def _truthy(value: str) -> bool:
    """True when *value* is a truthy env spelling."""
    return value.strip().lower() in _TRUTHY


def _workspace_allow_remote() -> bool:
    """True when the workspace ``reportal.toml`` sets ``[knowledge] allow_remote``."""
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return False
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return False
    table = document.get(CONFIG_TABLE)
    if not isinstance(table, dict):
        return False
    return table.get(CONFIG_ALLOW_REMOTE) is True


def remote_enabled() -> bool:
    """True when the environment or the workspace config enables URL ingestion."""
    if _truthy(os.environ.get(ALLOW_REMOTE_ENV, "")):
        return True
    return _workspace_allow_remote()


def require_enabled() -> None:
    """Raise the disabled error when remote ingestion is off."""
    if not remote_enabled():
        raise RemoteIngestError(ERROR_DISABLED, DISABLED_DETAIL)


def _resolved_addresses(host: str, port: int) -> list[str]:
    """Return every address *host* resolves to, or raise an unresolvable error."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RemoteIngestError(ERROR_UNRESOLVABLE, f"host {host!r} did not resolve") from exc
    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        value = str(sockaddr[0]).split("%", 1)[0]
        if value and value not in addresses:
            addresses.append(value)
    if not addresses:
        raise RemoteIngestError(ERROR_UNRESOLVABLE, f"host {host!r} resolved to no address")
    return addresses


def _is_mapped(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when *address* is an IPv4-mapped IPv6 form."""
    return isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None


def _blocked_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when *address* is in a range a remote target may not reach."""
    return (
        not address.is_global
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def _all_loopback(values: list[str]) -> bool:
    """True when every address in *values* is a loopback address."""
    return all(ipaddress.ip_address(value).is_loopback for value in values)


def _normalized(parsed: urllib.parse.SplitResult, port: int) -> str:
    """Rebuild *parsed* with a lower-cased scheme and host and an explicit port."""
    host = parsed.hostname or ""
    netloc = f"[{host}]" if ":" in host else host
    if port != DEFAULT_PORTS[parsed.scheme.lower()]:
        netloc = f"{netloc}:{port}"
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )


def validate_target(url: str, *, allow_loopback: bool = False) -> tuple[str, str]:
    """Return the normalized *url* and one resolved address it may reach.

    Raises :class:`RemoteIngestError` for a non-http(s) scheme, a missing host,
    credentials in the URL, an unparsable port, a host that does not resolve, a
    port outside :data:`ALLOWED_PORTS`, or a target with any address in a
    blocked range.  ``allow_loopback`` is the test-only seam described in the
    module docstring; production callers never pass it.
    """
    candidate = url.strip()
    if not candidate:
        raise RemoteIngestError(ERROR_INVALID_URL, "url must not be empty")
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError as exc:
        raise RemoteIngestError(ERROR_INVALID_URL, "url is not parseable") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise RemoteIngestError(
            ERROR_INVALID_URL, f"scheme {scheme or '(none)'} is not http or https"
        )
    host = parsed.hostname or ""
    if not host:
        raise RemoteIngestError(ERROR_INVALID_URL, "url must carry a host")
    if parsed.username or parsed.password:
        raise RemoteIngestError(ERROR_INVALID_URL, "credentials in the url are not allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise RemoteIngestError(ERROR_INVALID_URL, "url carries an invalid port") from exc
    if port is None:
        port = DEFAULT_PORTS[scheme]
    allowed: list[str] = []
    for value in _resolved_addresses(host, port):
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise RemoteIngestError(ERROR_UNRESOLVABLE, f"host resolved to {value!r}") from exc
        if _is_mapped(address):
            raise RemoteIngestError(
                ERROR_BLOCKED_TARGET, f"target {host!r} resolves to the mapped address {value}"
            )
        if allow_loopback and address.is_loopback:
            allowed.append(value)
            continue
        if _blocked_address(address):
            raise RemoteIngestError(
                ERROR_BLOCKED_TARGET, f"target {host!r} resolves to the blocked address {value}"
            )
        allowed.append(value)
    if not allowed:
        raise RemoteIngestError(
            ERROR_BLOCKED_TARGET, f"target {host!r} resolved to no usable address"
        )
    if port not in ALLOWED_PORTS and not (allow_loopback and _all_loopback(allowed)):
        raise RemoteIngestError(ERROR_INVALID_URL, f"port {port} is not allowed")
    return _normalized(parsed, port), allowed[0]


def _content_type_allowed(content_type: str) -> bool:
    """True when *content_type* is on the allowlist, or is missing."""
    value = content_type.split(";", 1)[0].strip().lower()
    if not value:
        return True
    return value.startswith(CONTENT_TYPE_TEXT_PREFIX) or value in ALLOWED_CONTENT_TYPES


def _read_bounded(response: httpx.Response, max_bytes: int) -> bytes:
    """Read *response* as bytes, raising :class:`TooLargeError` past *max_bytes*."""
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise TooLargeError(ERROR_TOO_LARGE, f"remote document exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _peer_address(response: httpx.Response) -> str | None:
    """The address of the connection *response* arrived on, or None.

    httpx2 exposes the raw transport stream as ``extensions["network_stream"]``
    (httpcore sets it) and httpcore's stream answers
    ``get_extra_info("server_addr")`` with the connected ``(ip, port)``.  A
    transport that exposes neither (httpx2's ``MockTransport``, an in-process
    ASGI transport) returns None, which is the unverifiable case the module
    docstring describes.
    """
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    extra = getattr(stream, "get_extra_info", None)
    if extra is None:
        return None
    sockaddr = extra("server_addr")
    if not sockaddr:
        return None
    address = str(sockaddr[0]).split("%", 1)[0]
    return address or None


def _peer_blocked_detail(host: str, address: str, *, allow_loopback: bool) -> str | None:
    """The blocked-target detail when *address* is a blocked peer, else None.

    The ranges and the loopback seam are the ones the pre-flight check applies,
    so every address the pre-flight admits is admitted here and the same target
    is rejected wherever the check runs.  An IPv4-mapped form and an unparsable
    answer are both rejected, the same as the pre-flight check.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return f"target {host!r} connected to the unparsable address {address}"
    if _is_mapped(parsed):
        return f"target {host!r} connected to the mapped address {address}"
    if allow_loopback and parsed.is_loopback:
        return None
    if _blocked_address(parsed):
        return f"target {host!r} connected to the blocked address {address}"
    return None


def fetch(
    url: str, *, allow_loopback: bool = False, max_bytes: int, timeout: float
) -> dict[str, Any]:
    """Fetch *url*, re-validating every redirect hop before requesting it.

    Returns ``{"url", "final_url", "content_type", "data", "bytes",
    "peer_address"}``, where ``peer_address`` is the connected peer's address or
    :data:`PEER_UNVERIFIED` when the transport exposes none and the loopback
    seam admitted that case.  Raises :class:`TooLargeError` for a body past
    *max_bytes*, a :class:`RemoteIngestError` for a blocked or unverifiable
    target or an unsupported content type, and the fetch-failed error for a
    transport failure or too many redirects.

    Each hop runs the pre-flight check first: it is the cheap early exit that
    fails before a request is sent.  The connection's own peer address is then
    read before the body is consumed, which is what closes the gap between the
    resolution and the connection the pre-flight check cannot see.  Without a
    peer address the body is refused unless ``allow_loopback`` is set, so a
    production fetch cannot fall through on pre-flight DNS alone.
    """
    current = url
    with httpx.Client(follow_redirects=False, timeout=timeout, trust_env=False) as client:
        for _hop in range(MAX_REDIRECTS + 1):
            normalized, _address = validate_target(current, allow_loopback=allow_loopback)
            try:
                with client.stream(
                    "GET", normalized, headers={"User-Agent": USER_AGENT}
                ) as response:
                    peer_address = _peer_address(response)
                    if peer_address is None:
                        if not allow_loopback:
                            host = urllib.parse.urlsplit(normalized).hostname or ""
                            raise RemoteIngestError(
                                ERROR_BLOCKED_TARGET,
                                f"target {host!r} connected with no verifiable peer address",
                            )
                        peer_address = PEER_UNVERIFIED
                    else:
                        host = urllib.parse.urlsplit(normalized).hostname or ""
                        blocked = _peer_blocked_detail(
                            host, peer_address, allow_loopback=allow_loopback
                        )
                        if blocked is not None:
                            raise RemoteIngestError(ERROR_BLOCKED_TARGET, blocked)
                    if response.is_redirect:
                        location = response.headers.get("location", "")
                        if not location:
                            raise RemoteIngestError(
                                ERROR_FETCH_FAILED, "redirect carried no Location header"
                            )
                        current = urllib.parse.urljoin(normalized, location)
                        continue
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "")
                    if not _content_type_allowed(content_type):
                        raise RemoteIngestError(
                            ERROR_UNSUPPORTED_CONTENT_TYPE,
                            f"content type {content_type!r} is not supported",
                        )
                    data = _read_bounded(response, max_bytes)
                    return {
                        "url": url,
                        "final_url": str(response.url),
                        "content_type": content_type,
                        "data": data,
                        "bytes": len(data),
                        "peer_address": peer_address,
                    }
            except httpx.HTTPError as exc:
                raise RemoteIngestError(ERROR_FETCH_FAILED, f"fetch failed: {exc}") from exc
    raise RemoteIngestError(ERROR_TOO_MANY_REDIRECTS, f"more than {MAX_REDIRECTS} redirects")


def ingest_url(
    conn: Any,
    *,
    scope_kind: str,
    scope_id: int,
    url: str,
    allow_loopback: bool = False,
    title: str | None = None,
) -> dict[str, Any]:
    """Fetch *url* and store its text in one knowledge scope.

    The document's ``source`` is the final URL of the redirect chain, so a
    re-fetch of the same content is deduped by sha256 inside the scope.  A
    fetch, size or content-type failure raises before anything is written, so a
    failed ingest never leaves a partial document.  ``allow_loopback`` is the
    test-only seam; production callers never pass it.
    """
    if scope_kind not in knowledge.SCOPE_KINDS:
        raise knowledge.KnowledgeError(
            knowledge.ERROR_INVALID_SCOPE, f"unsupported scope kind: {scope_kind}"
        )
    require_enabled()
    normalized, _address = validate_target(url, allow_loopback=allow_loopback)
    result = fetch(
        normalized,
        allow_loopback=allow_loopback,
        max_bytes=MAX_BYTES,
        timeout=FETCH_TIMEOUT_SECONDS,
    )
    final_url = str(result["final_url"])
    data = result["data"]
    if knowledge.extract_text(data, filename=final_url) is None:
        if knowledge.looks_binary(data):
            raise RemoteIngestError(
                knowledge.ERROR_BINARY_CONTENT, "fetched document carries no extractable text"
            )
        raise RemoteIngestError(knowledge.ERROR_EMPTY_TEXT, "fetched document has no text")
    return knowledge.ingest_document(
        conn,
        scope_kind=scope_kind,
        scope_id=scope_id,
        title=title or "",
        source=final_url,
        mime=str(result["content_type"]),
        data=data,
    )

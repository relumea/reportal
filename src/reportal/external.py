"""External sources: what a third party says about a stored binary.

The hosted portal pulls VirusTotal data for an analysis (`POST
/v2/analysis/{id}/external/vt`, `GET .../vt`, `GET .../vt/status`).  reportal
makes no network call unless the user configures one, so the local form is a
registry of *sources* with two built-ins:

* ``local`` (kind ``offline``) derives an answer from the rows reportal already
  holds: the fingerprint, the stored detection families, the capability tags,
  the threat report and the secrets-scan counts, each reported as present or
  absent rather than invented.  It is always available and makes no request, so
  the hosted feature has a local meaning on an air-gapped install.
* ``virustotal`` (kind ``remote``) pulls the file report the VirusTotal API v3
  serves for the binary's SHA-256.  It is off unless the workspace opts in
  (``REPORTAL_ALLOW_EXTERNAL`` or ``[external] allow_remote = true``, the same
  gate shape ``remote_ingest.py`` uses) **and** a key resolves, first match
  wins: ``REPORTAL_VIRUSTOTAL_KEY``, then ``[external] virustotal_api_key``,
  then the secret store under :data:`VIRUSTOTAL_KEY_SECRET`.  The request goes
  to one fixed https host with the key in the ``x-apikey`` header, follows no
  redirect (`follow_redirects=False`, so a 3xx is a failure rather than a hop to
  somewhere else), is bounded by :data:`MAX_BYTES`, times out at
  :data:`FETCH_TIMEOUT_SECONDS`, and stores a normalized subset of the answer
  (the per-engine results capped at :data:`MAX_ENGINE_RESULTS`) with the source
  and the fetch time; the response is never stored whole.

The answer is a scan: `set_scan(conn, analysis_id, f"external:{source}", ...)`
is an upsert, so a re-pull replaces the previous one, and
:func:`journaled_run` is the one write path the routes, the CLI and the MCP
tools share, so all three journal it identically.

A source is a :class:`Source`: a name, a kind, a description, an
``available()`` check, the reason it is not, and a ``retrieve(context)`` call
that returns the payload to store.  The registry mirrors
:mod:`reportal.graph_backends`: built-ins are declared in-tree by
:func:`builtin_sources`, a third party registers an entry point in the
:data:`SOURCE_ENTRY_POINT_GROUP` group whose value is ``module:attr`` naming a
:class:`Source` or a zero-argument factory returning one, a broken registration
is skipped with a warning, and a duplicate name is a :class:`RegistryError`.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx2 as httpx

from reportal import journal, plugins, secret_store, store
from reportal._paths import MARKER, WorkspaceNotFound, project_root

# Source kinds.  The kind tells a caller what the source can do: an `offline`
# one reads stored rows, a `remote` one makes a request that has to be enabled.
KIND_OFFLINE = "offline"
KIND_REMOTE = "remote"
KINDS: tuple[str, ...] = (KIND_OFFLINE, KIND_REMOTE)

# Entry-point group third-party sources register in.
SOURCE_ENTRY_POINT_GROUP = "reportal.external_sources"

# Origin label a built-in registration reports.
BUILTIN_ORIGIN = plugins.BUILTIN_ORIGIN

# The sources reportal ships in-tree.
LOCAL_SOURCE = "local"
VIRUSTOTAL_SOURCE = "virustotal"

# Workspace reportal.toml table that carries the settings, and the keys in it.
CONFIG_TABLE = "external"
CONFIG_ALLOW_REMOTE = "allow_remote"
CONFIG_VIRUSTOTAL_KEY = "virustotal_api_key"

# Environment variables: the remote gate and the VirusTotal key.
ALLOW_REMOTE_ENV = "REPORTAL_ALLOW_EXTERNAL"
VIRUSTOTAL_KEY_ENV = "REPORTAL_VIRUSTOTAL_KEY"

# The secret-store name the VirusTotal key is read from when neither the
# environment nor the workspace table carries one.
VIRUSTOTAL_KEY_SECRET = "virustotal.api_key"

_TRUTHY = frozenset({"1", "true", "yes", "on"})

# The one host a remote source calls, and the path its file report lives at.
VIRUSTOTAL_HOST = "www.virustotal.com"
VIRUSTOTAL_FILE_PATH = "/api/v3/files/"
VIRUSTOTAL_URL_PREFIX = f"https://{VIRUSTOTAL_HOST}{VIRUSTOTAL_FILE_PATH}"

# Request bounds: the key travels as a header, the body is capped and the call
# is given a wall-clock limit.
API_KEY_HEADER = "x-apikey"
MAX_BYTES = 512 * 1024
FETCH_TIMEOUT_SECONDS = 20
USER_AGENT = "reportal external-source"

# How many per-engine results are kept, and the fields of the file report the
# normalized payload carries.  The raw response also carries every engine's
# verbose record and the vendor links; nothing here stores it whole.
MAX_ENGINE_RESULTS = 100
VIRUSTOTAL_FIELDS: tuple[str, ...] = (
    "sha256",
    "sha1",
    "md5",
    "magic",
    "size",
    "type_tag",
    "type_description",
    "meaningful_name",
    "names",
    "reputation",
    "tags",
    "total_votes",
    "times_submitted",
    "unique_sources",
    "first_submission_date",
    "last_submission_date",
    "last_analysis_date",
    "last_analysis_stats",
    "popular_threat_classification",
    "signature_info",
)

# The scale a payload carries: the local one is reportal's own derivation, the
# remote one is a third party's, and a reader must be able to tell them apart.
LOCAL_NOTE = (
    "reportal's own derivation over the rows it already stored; no engine run and no network call"
)
VIRUSTOTAL_NOTE = (
    "the VirusTotal API v3 file report, normalized: the per-engine results are"
    f" capped at {MAX_ENGINE_RESULTS} entries and the vendor links are not stored"
)

# Error codes the surface reports, shared by the API, CLI and MCP.
ERROR_DISABLED = "external-disabled"
ERROR_UNAVAILABLE = "external-unavailable"
ERROR_UNKNOWN = "unknown source"
ERROR_NO_HASH = "no-content-hash"
ERROR_FETCH_FAILED = "external-fetch-failed"
ERROR_TOO_LARGE = "external-too-large"
ERROR_BAD_RESPONSE = "external-bad-response"

DISABLED_DETAIL = (
    f"external sources are off: set {ALLOW_REMOTE_ENV}=1 or [external]"
    f" {CONFIG_ALLOW_REMOTE} = true in reportal.toml to enable the remote ones"
)


class ExternalError(Exception):
    """Base class for a rejected external-source operation."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


class DisabledExternalError(ExternalError, PermissionError):
    """Remote sources are not enabled; the API answers 403."""

    def __init__(self, detail: str = DISABLED_DETAIL) -> None:
        super().__init__(ERROR_DISABLED, detail)


class UnavailableExternalError(ExternalError, RuntimeError):
    """A source is registered but cannot run (no key, no response); 503."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_UNAVAILABLE, detail)


class UnknownSourceError(ExternalError, LookupError):
    """No source is registered under a requested name; the API answers 404."""

    def __init__(self, name: str, known: tuple[str, ...]) -> None:
        self.name = name
        self.known = known
        known_text = ", ".join(known) if known else "none"
        super().__init__(ERROR_UNKNOWN, f"unknown source {name!r}; known sources: {known_text}")


class NoContentHashError(ExternalError, ValueError):
    """The binary has no SHA-256 to look up; the API answers 400."""

    def __init__(self, detail: str) -> None:
        super().__init__(ERROR_NO_HASH, detail)


class ExternalFetchError(ExternalError, RuntimeError):
    """A remote call failed; the API answers 502."""

    def __init__(self, detail: str, code: str = ERROR_FETCH_FAILED) -> None:
        super().__init__(code, detail)


# ── Configuration ──────────────────────────────────────────────────


def _truthy(value: str) -> bool:
    return value.strip().lower() in _TRUTHY


def _workspace_table() -> dict[str, Any]:
    """The workspace ``reportal.toml`` ``[external]`` table, or an empty object."""
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return {}
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    table = document.get(CONFIG_TABLE)
    return table if isinstance(table, dict) else {}


def remote_enabled() -> bool:
    """Whether the remote sources are enabled: the environment, then the config."""
    if _truthy(os.environ.get(ALLOW_REMOTE_ENV, "")):
        return True
    value = _workspace_table().get(CONFIG_ALLOW_REMOTE)
    return value is True or (isinstance(value, str) and _truthy(value))


def require_enabled() -> None:
    """Raise :class:`DisabledExternalError` unless the remote sources are enabled."""
    if not remote_enabled():
        raise DisabledExternalError()


def virustotal_key() -> str:
    """The VirusTotal key: the environment, the workspace table, then the store."""
    value = os.environ.get(VIRUSTOTAL_KEY_ENV, "").strip()
    if value:
        return value
    table = _workspace_table().get(CONFIG_VIRUSTOTAL_KEY)
    if isinstance(table, str) and table.strip():
        return table.strip()
    return (secret_store.resolve_from_workspace(VIRUSTOTAL_KEY_SECRET) or "").strip()


# ── The transport seam ─────────────────────────────────────────────

_http: httpx.Client | None = None


def set_http_client(client: httpx.Client | None) -> None:
    """Install the process-wide HTTP client; None builds one per call.

    The seam exists so a test drives :func:`fetch_virustotal` over an
    ``httpx.MockTransport`` instead of the network, the way ``llm.set_client``
    does for the bridge.
    """
    global _http
    _http = client


def _open_client(timeout: float) -> tuple[httpx.Client, bool]:
    """The client for one call, and whether the caller owns (must close) it.

    An injected client is reused as it is and never closed, which is what lets a
    test drive several calls over one ``MockTransport``; a client built here is
    closed by the caller.
    """
    if _http is not None:
        return _http, False
    return httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False), True


# ── The source shape ───────────────────────────────────────────────


def _always_available() -> bool:
    """The availability of a source that is always usable."""
    return True


def _no_reason() -> str:
    """The reason an available source reports; it is never used."""
    return ""


@dataclass(frozen=True)
class Source:
    """One external source: how to check it, describe it and retrieve an answer.

    ``retrieve`` takes the context :func:`binary_context` assembled and returns
    the payload to store as the scan.  It may raise
    :class:`ExternalError` (a refusal) or any exception a caller maps.
    """

    name: str
    kind: str
    description: str
    retrieve: Callable[[dict[str, Any]], dict[str, Any]]
    available: Callable[[], bool] = _always_available
    unavailable_reason: Callable[[], str] = _no_reason

    def describe(self) -> dict[str, Any]:
        """The registry report: name, kind, availability and description."""
        is_available = self.available()
        return {
            "name": self.name,
            "kind": self.kind,
            "available": is_available,
            "unavailable_reason": "" if is_available else self.unavailable_reason(),
            "description": self.description,
        }


# ── The stored context an offline source reads ─────────────────────


def binary_context(conn: sqlite3.Connection, analysis_id: int) -> dict[str, Any]:
    """Everything a source may read about one analysis, assembled once.

    Raises :class:`UnknownSourceError` for an unknown analysis id so every
    caller reports the same not-found; the payload's ``stored`` block names
    which scans are present, so an offline answer can say "no threat report"
    rather than an empty result.
    """
    analysis = store.get_analysis(conn, analysis_id)
    if analysis is None:
        raise ExternalError("analysis not found", f"no analysis with id {analysis_id}")
    binary_id = int(analysis["binary_id"])
    binary = store.get_binary(conn, binary_id)
    kinds = (
        store.SCAN_KIND_DETECT,
        store.SCAN_KIND_CAPABILITIES,
        store.SCAN_KIND_THREAT,
        store.SCAN_KIND_SECRETS,
    )
    scans: dict[str, Any] = {}
    stored: dict[str, bool] = {}
    for kind in kinds:
        found = store.get_scan(conn, analysis_id, kind)
        stored[kind] = found is not None
        if found is not None:
            scans[kind] = found
    fingerprint = store.get_fingerprint(conn, binary_id) if binary is not None else None
    context: dict[str, Any] = {
        "analysis_id": analysis_id,
        "analysis": analysis,
        "binary_id": binary_id,
        "binary": binary or {},
        "fingerprint": fingerprint or {},
        "stored": stored,
        "scans": scans,
    }
    context["sha256"] = str((fingerprint or {}).get("sha256") or (binary or {}).get("sha256") or "")
    context["name"] = str((binary or {}).get("name") or "")
    return context


def local_payload(context: Mapping[str, Any]) -> dict[str, Any]:
    """The offline answer: the local evidence about one binary, or its absence.

    Nothing is inferred: a scan that is not stored is reported as absent, and
    the payload says which fields came from where, the same honesty
    ``details.py`` applies to a composed read.
    """
    scans = context.get("scans") or {}
    fingerprint = context.get("fingerprint") or {}
    detect = scans.get(store.SCAN_KIND_DETECT) or {}
    capabilities = scans.get(store.SCAN_KIND_CAPABILITIES) or {}
    threat = scans.get(store.SCAN_KIND_THREAT) or {}
    secrets = scans.get(store.SCAN_KIND_SECRETS) or {}
    families = [str(entry["name"]) for entry in (detect.get("matches") or []) if entry.get("name")]
    tag_names = [
        str(entry["name"])
        for entry in (capabilities.get("capabilities") or [])
        if isinstance(entry, dict) and entry.get("name")
    ]
    return {
        "found": True,
        "name": context.get("name") or "",
        "sha256": context.get("sha256") or "",
        "format": fingerprint.get("format") or "",
        "arch": fingerprint.get("arch") or "",
        "size": fingerprint.get("size"),
        "families": sorted(families),
        "capabilities": sorted(tag_names),
        "software_type": threat.get("software_type"),
        "threat_score": threat.get("threat_score"),
        "secrets": len(secrets.get("findings") or []),
        "stored": dict(context.get("stored") or {}),
        "note": LOCAL_NOTE,
    }


def local_source() -> Source:
    """The offline source: reportal's own evidence, no request, always usable."""
    return Source(
        name=LOCAL_SOURCE,
        kind=KIND_OFFLINE,
        description="the local evidence reportal already stored for the binary",
        retrieve=local_payload,
    )


# ── The VirusTotal source ──────────────────────────────────────────


def _read_bounded(response: httpx.Response, max_bytes: int) -> bytes:
    """Read at most *max_bytes* of a response, raising when it is past the cap."""
    data = response.read()
    if len(data) > max_bytes:
        raise ExternalFetchError(f"the response is larger than {max_bytes} bytes", ERROR_TOO_LARGE)
    return data


def _normalized_file_report(data: Any) -> dict[str, Any]:
    """The stored subset of a VirusTotal file report, bounded and normalized."""
    if not isinstance(data, dict):
        raise ExternalFetchError("the response was not a JSON object", ERROR_BAD_RESPONSE)
    document = data.get("data")
    if not isinstance(document, dict):
        raise ExternalFetchError("the response carried no data object", ERROR_BAD_RESPONSE)
    attributes = document.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    engines: dict[str, Any] = {}
    raw_engines = attributes.get("last_analysis_results")
    if isinstance(raw_engines, dict):
        for engine in sorted(raw_engines)[:MAX_ENGINE_RESULTS]:
            entry = raw_engines[engine]
            if isinstance(entry, dict):
                engines[engine] = {
                    "category": entry.get("category"),
                    "result": entry.get("result"),
                    "engine_version": entry.get("engine_version"),
                }
    return {
        "found": True,
        "id": document.get("id"),
        "type": document.get("type"),
        "attributes": {key: attributes[key] for key in VIRUSTOTAL_FIELDS if key in attributes},
        "engines": engines,
        "engine_count": len(raw_engines) if isinstance(raw_engines, dict) else 0,
        "engine_cap": MAX_ENGINE_RESULTS,
        "note": VIRUSTOTAL_NOTE,
    }


def fetch_virustotal(
    sha256: str, *, key: str, timeout: float = FETCH_TIMEOUT_SECONDS
) -> dict[str, Any]:
    """Fetch one VirusTotal file report and return the normalized payload.

    The URL is built from a fixed host and the hash, so a caller cannot point it
    anywhere else; the key travels in the ``x-apikey`` header.  A 404 is a
    *result* (the file is unknown to VirusTotal) and is stored as ``found:
    false``; any other non-2xx is a failure.  Not enabled, no key and a failed
    call all raise rather than storing a partial answer.
    """
    url = f"{VIRUSTOTAL_URL_PREFIX}{sha256}"
    client, owned = _open_client(timeout)
    try:
        response = client.get(
            url,
            headers={
                API_KEY_HEADER: key,
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
            },
        )
        if response.status_code == 404:
            return {
                "found": False,
                "sha256": sha256,
                "url": url,
                "note": "VirusTotal does not know this file",
            }
        if response.is_redirect:
            raise ExternalFetchError(
                f"the API answered a redirect ({response.status_code}); it is not followed"
            )
        response.raise_for_status()
        payload = _normalized_file_report(json.loads(_read_bounded(response, MAX_BYTES)))
    except ExternalError:
        raise
    except (httpx.HTTPError, ValueError) as exc:
        raise ExternalFetchError(f"the VirusTotal request failed: {exc}") from exc
    finally:
        if owned:
            client.close()
    payload["sha256"] = payload.get("sha256") or sha256
    payload["url"] = url
    return payload


def virustotal_source() -> Source:
    """The remote source: the VirusTotal file report, off unless opted in."""

    def reason() -> str:
        if not remote_enabled():
            return DISABLED_DETAIL
        return (
            f"no VirusTotal key is configured: set {VIRUSTOTAL_KEY_ENV},"
            f" [external] {CONFIG_VIRUSTOTAL_KEY}, or the {VIRUSTOTAL_KEY_SECRET}"
            " entry in the secret store"
        )

    def available() -> bool:
        return remote_enabled() and bool(virustotal_key())

    def retrieve(context: dict[str, Any]) -> dict[str, Any]:
        require_enabled()
        sha256 = str(context.get("sha256") or "")
        if not sha256:
            raise NoContentHashError(
                "the binary has no stored sha256 to look up; store a fingerprint first"
            )
        key = virustotal_key()
        if not key:
            raise UnavailableExternalError(reason())
        return fetch_virustotal(sha256, key=key)

    return Source(
        name=VIRUSTOTAL_SOURCE,
        kind=KIND_REMOTE,
        description="the VirusTotal API v3 file report for the binary's sha256",
        retrieve=retrieve,
        available=available,
        unavailable_reason=reason,
    )


def builtin_sources() -> tuple[Source, ...]:
    """The in-tree sources: the offline one first, then the remote."""
    return (local_source(), virustotal_source())


# ── Registry ───────────────────────────────────────────────────────

_registry: dict[str, Source] = {}
_origins: dict[str, str] = {}
_builtins_loaded = False
_entry_points_loaded = False


def register_source(source: Source, *, origin: str = BUILTIN_ORIGIN) -> None:
    """Register *source* under its own name.

    Raises :class:`RegistryError` for a malformed value or a name already taken,
    naming both origins (single-source discipline).
    """
    if not isinstance(source, Source):
        raise plugins.RegistryError(
            f"bad external source registration from {origin}: expected a Source,"
            f" got {type(source).__name__}"
        )
    if not source.name.strip():
        raise plugins.RegistryError(f"bad external source registration from {origin}: empty name")
    if source.kind not in KINDS:
        raise plugins.RegistryError(
            f"bad external source registration {source.name!r} from {origin}:"
            f" unknown kind {source.kind!r}; known kinds: {', '.join(KINDS)}"
        )
    if not callable(source.retrieve):
        raise plugins.RegistryError(
            f"bad external source registration {source.name!r} from {origin}:"
            " retrieve must be callable"
        )
    if source.name in _registry:
        raise plugins.RegistryError(
            f"duplicate external source registration {source.name!r}: {origin} conflicts"
            f" with {_origins[source.name]} (single-source discipline)"
        )
    _registry[source.name] = source
    _origins[source.name] = origin


def sources() -> tuple[Source, ...]:
    """Every registered source, built-ins first, in registration order."""
    _ensure_builtins()
    _ensure_entry_points()
    return tuple(_registry.values())


def unregister_source(name: str) -> None:
    """Withdraw the external source registered as *name*.

    Raises :class:`RegistryError` for a name nothing holds.  Withdrawing a
    built-in lasts until the next :func:`refresh_sources`.
    """
    _ensure_builtins()
    _ensure_entry_points()
    if name not in _registry:
        raise plugins.RegistryError(f"no source registration {name!r} to withdraw")
    del _registry[name]


def refresh_sources() -> tuple[Source, ...]:
    """Discard discovered sources and re-run discovery.

    Built-ins are re-declared, which is what picks up a key or a gate that was
    configured after startup, and the entry-point group is scanned again.
    """
    global _builtins_loaded, _entry_points_loaded
    _registry.clear()
    _origins.clear()
    _builtins_loaded = False
    _entry_points_loaded = False
    return sources()


def get_source(name: str) -> Source:
    """The source registered under *name*; raises :class:`UnknownSourceError`."""
    _ensure_builtins()
    _ensure_entry_points()
    source = _registry.get(name)
    if source is None:
        raise UnknownSourceError(name, tuple(sorted(_registry)))
    return source


def describe() -> dict[str, Any]:
    """The registry as a payload: every source, the remote gate and the note."""
    rows = [source.describe() for source in sources()]
    return {
        "sources": rows,
        "count": len(rows),
        "remote_enabled": remote_enabled(),
        "key_configured": bool(virustotal_key()),
        "note": DISABLED_DETAIL,
    }


def _ensure_builtins() -> None:
    """Load the in-tree sources once."""
    global _builtins_loaded
    if _builtins_loaded:
        return
    _builtins_loaded = True
    for source in builtin_sources():
        register_source(source, origin=BUILTIN_ORIGIN)


def _ensure_entry_points() -> None:
    """Load third-party sources once, skipping a broken registration."""
    global _entry_points_loaded
    if _entry_points_loaded:
        return
    _entry_points_loaded = True
    for name, value, source in plugins.load(SOURCE_ENTRY_POINT_GROUP, Source, "Source"):
        register_source(source, origin=plugins.origin(name, value))


# ── Running one source ─────────────────────────────────────────────


def scan_kind(source_name: str) -> str:
    """The `scans.kind` one source's answer is stored under."""
    return f"external:{source_name}"


def status(conn: sqlite3.Connection, *, analysis_id: int, source_name: str) -> dict[str, Any]:
    """Whether one source can run for an analysis and what is stored for it."""
    source = get_source(source_name)
    context = binary_context(conn, analysis_id)
    stored = store.get_scan(conn, analysis_id, scan_kind(source.name))
    return {
        "analysis_id": analysis_id,
        "binary_id": context["binary_id"],
        "source": source.name,
        "kind": source.kind,
        "available": source.available(),
        "unavailable_reason": "" if source.available() else source.unavailable_reason(),
        "stored": stored is not None,
        "fetched_at": (stored or {}).get("fetched_at"),
        "remote_enabled": remote_enabled(),
    }


def stored(
    conn: sqlite3.Connection, *, analysis_id: int, source_name: str
) -> dict[str, Any] | None:
    """The stored answer of one source, or None; never runs it."""
    source = get_source(source_name)
    return store.get_scan(conn, analysis_id, scan_kind(source.name))


def run(conn: sqlite3.Connection, *, analysis_id: int, source_name: str) -> dict[str, Any]:
    """Run one source and return the payload to store; writes nothing.

    The caller stores it, so a failure leaves no scan behind and the write is
    journaled where the caller wants it.  Raises :class:`ExternalError` for a
    disabled, unavailable or failing source.
    """
    source = get_source(source_name)
    context = binary_context(conn, analysis_id)
    if not source.available():
        if source.kind == KIND_REMOTE and not remote_enabled():
            raise DisabledExternalError()
        raise UnavailableExternalError(source.unavailable_reason())
    payload = source.retrieve(context)
    return {
        "analysis_id": analysis_id,
        "binary_id": context["binary_id"],
        "source": source.name,
        "kind": source.kind,
        "fetched_at": store.now(),
        "payload": payload,
    }


def journaled_run(
    conn: sqlite3.Connection,
    log: journal.Journal,
    *,
    analysis_id: int,
    source_name: str,
    description: str | None = None,
) -> dict[str, Any]:
    """Run one source inside the caller's journaled action and store the answer.

    This is the one write path the routes, the CLI and the MCP tools share: the
    scan row it replaces is snapshotted, or the row it creates is journaled, and
    the answer replaces any earlier one for the same source.
    """
    kind = scan_kind(source_name)
    result = run(conn, analysis_id=analysis_id, source_name=source_name)
    replaced = journal.journaled_rows(
        conn,
        log,
        table="scans",
        where="analysis_id = ? AND kind = ?",
        params=(analysis_id, kind),
        description=description or f"replaced the {source_name} external report",
    )
    store.set_scan(conn, analysis_id, kind, result)
    if not replaced:
        journal.journaled_create(
            log,
            table="scans",
            key={"analysis_id": analysis_id, "kind": kind},
            description=description or f"stored the {source_name} external report",
        )
    return result
